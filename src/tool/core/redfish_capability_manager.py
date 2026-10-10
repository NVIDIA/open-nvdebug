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
Run-scoped discovery for Redfish System diagnostic dump capabilities.

The static collector catalog describes how a collector is implemented and which
platform families it is safe on. A System's ``CollectDiagnosticDataActionInfo``
resource describes which OEM payloads the running firmware accepts. This module
keeps those responsibilities separate and exposes a small, deterministic
capability cache that can be consulted before collector selection and again at
request time.

Capability discovery distinguishes an advertised request failure from an
authoritative absence. Systems that do not advertise the required Dump topology
are unsupported, while failures encountered after following advertised links
remain unavailable and therefore fail open for legacy collector behavior. Once
every discovered System is either available or unsupported, absence of an exact
value is authoritative and can safely gate a collector or payload.
"""

from __future__ import annotations

import asyncio
import copy
import json
import math
from collections import deque
from dataclasses import dataclass
from typing import Any, Optional

from ..utils.redfish_limits import (
    MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS,
    bound_redfish_collection_members,
)
from ..utils.redfish_topology_profile import (
    RedfishTopologyProfileError,
    validate_redfish_uri_path,
)

SYSTEMS_COLLECTION_URI = "/redfish/v1/Systems"
SYSTEM_DUMP_CAPABILITY_SOURCE = "system_dump_action_info"
OEM_DIAGNOSTIC_DATA_TYPE = "OEMDiagnosticDataType"


@dataclass
class _RequestBudget:
    """
    Run-local request counter shared by bounded System workers.

    The coherent record keeps ``maximum`` and ``used`` together so consumers
    observe one request budget state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        maximum: Numeric maximum retained by this record.
        used: Numeric used retained by this record.
    """

    maximum: int
    used: int = 0

    def reserve(self) -> bool:
        # This method contains no await, so one event loop cannot interleave the
        # check and increment performed by concurrent discovery workers.
        """
        Reserve capacity under the configured budget.

        The implementation uses current instance state to reserve capacity under
        the configured budget. It updates ``used`` on the instance as part of
        that state transition.

        Returns:
            Whether the reserve capacity under the configured budget operation
            succeeds.
        """
        if self.used >= self.maximum:
            return False
        self.used += 1
        return True


class SystemDumpCapabilityManager:
    """
    Discover and cache System Dump ActionInfo once per DUT and run.

    The type coordinates ``_log``, ``_normalize_uri``, ``_system_member``,
    ``_canonical_action_info``, and ``_parameter_values`` and retains the state
    those operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    MAX_FOLLOWED_SYSTEMS = min(MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS, 128)
    MAX_FOLLOWED_LOG_SERVICES = min(MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS, 128)
    MAX_CONCURRENT_SYSTEM_PROBES = 8
    MAX_CONCURRENT_DUT_DISCOVERIES = 8
    # ActionInfo responses already cross the Redfish structured-response byte
    # boundary, but the capability cache survives for the run and is copied for
    # callers. Bound both retained object count and UTF-8 text so a valid JSON
    # response cannot turn into an unbounded per-System cache amplifier. The
    # ceilings are intentionally far above every governed platform fixture
    # (currently two parameters and single-digit OEM values).
    MAX_ACTION_INFO_PARAMETERS = 64
    MAX_ACTION_INFO_ALLOWABLE_VALUES_PER_PARAMETER = 512
    MAX_ACTION_INFO_TEXT_BYTES = 4 * 1024
    MAX_ACTION_INFO_RETAINED_TEXT_BYTES = 64 * 1024
    MAX_ACTION_INFO_RETAINED_DOCUMENT_BYTES = 128 * 1024
    MAX_ACTION_INFO_RETAINED_NODES = 2_048
    MAX_ACTION_INFO_RETAINED_DEPTH = 32
    # One Systems collection request plus at most one System, one LogServices
    # collection, one advertised Dump service, and one advertised ActionInfo
    # request for every admitted System.
    MAX_DISCOVERY_REQUESTS = 1 + (4 * MAX_FOLLOWED_SYSTEMS)

    def __init__(self, orchestrator: Any) -> None:
        """
        Initialize a ``SystemDumpCapabilityManager`` instance.

        The initializer records ``_cache``, ``_locks``, and ``orchestrator`` for
        later operations and establishes the instance invariants before any
        public method runs.

        Args:
            orchestrator: Orchestrator consumed while the function attempts to
                initialize a ``SystemDumpCapabilityManager`` instance.
        """
        self.orchestrator = orchestrator
        self._cache: dict[str, dict[str, Any]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def _log(self, level: str, message: str, dut_id: str | None = None) -> None:
        """
        Log one sanitized runtime event.

        The implementation uses ``level``, ``message``, and ``dut_id`` to log
        one sanitized runtime event. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        logger = getattr(self.orchestrator, "logger", None)
        if not logger:
            return
        if dut_id and hasattr(logger, "write_to_dut_runtime_log"):
            await logger.write_to_dut_runtime_log(
                dut_id, level, "SystemDumpCapabilities", message
            )
            return
        if hasattr(logger, "log_runtime"):
            await logger.log_runtime(level, "SystemDumpCapabilities", message)

    @staticmethod
    def _normalize_uri(uri: Any) -> str:
        """
        Return a validated path-only Redfish URI, or an empty sentinel.

        The implementation uses ``uri`` to produce a validated path-only Redfish
        URI, or an empty sentinel.

        Args:
            uri: Validated remote resource identifier used for URI.

        Returns:
            The canonical URI text.
        """
        try:
            return validate_redfish_uri_path(
                uri,
                context="System capability URI",
            )
        except (RedfishTopologyProfileError, TypeError, ValueError):
            return ""

    @classmethod
    def _system_member(
        cls, member: Any, collection_uri: str = SYSTEMS_COLLECTION_URI
    ) -> tuple[str, str] | None:
        """
        Return the system member.

        The implementation uses ``member`` to produce the system member.

        Args:
            member: Member object whose ``get`` state is read while performing
                system member.
            collection_uri: Configured Systems collection that must directly
                contain the advertised member.

        Returns:
            A tuple containing ``relative`` and ``URI`` in that order.
        """
        if not isinstance(member, dict):
            return None
        raw_uri = member.get("@odata.id")

        try:
            uri = validate_redfish_uri_path(
                raw_uri,
                context="System capability member URI",
                service_root=collection_uri,
            )
        except (RedfishTopologyProfileError, TypeError, ValueError):
            return None
        prefix = f"{collection_uri}/"
        if not uri.startswith(prefix):
            return None
        relative = uri[len(prefix) :]
        if not relative or "/" in relative:
            return None
        return relative, uri

    def _configured_systems_uri(self, dut_id: str, *, hmc: bool = False) -> str:
        """
        Resolve the catalog Systems collection in the selected DUT namespace.

        Resolve per-resource overrides before the namespace so explicit custom
        collection paths remain authoritative. Supply the DUT's baseboard and
        platform selectors so their resource overrides participate in the same
        precedence as ordinary collectors. A selected HMC collection retains its
        namespace even when the caller does not explicitly request HMC routing.
        Missing URI policy stops discovery instead of probing an assumed endpoint.

        Args:
            dut_id: DUT whose configured resource overrides must be honored.
            hmc: Whether to require the HMC namespace; otherwise infer it from
                the collection selected by resource override policy.

        Returns:
            A validated Systems collection URI from runtime configuration.

        Raises:
            ValueError: If the runtime URI manager or its collection is invalid.
        """

        dut_manager = getattr(self.orchestrator, "dut_manager", None)
        uri_manager = getattr(dut_manager, "uri_config_manager", None)
        if uri_manager is None:
            raise ValueError("System capability discovery requires URI configuration")
        dut_config = dut_manager.get_dut_config(dut_id) or {}
        try:
            uri = uri_manager.get_uri(
                dut_id,
                "Systems",
                baseboard=dut_config.get("baseboard"),
                platform=dut_config.get("platform"),
            )
        except KeyError as error:
            raise ValueError(
                "System capability URI policy has no Systems resource"
            ) from error
        selected_hmc = hmc or uri_manager._is_hmc_uri(uri, dut_id)
        return validate_redfish_uri_path(
            uri_manager.normalize_response_uri(dut_id, uri, hmc=selected_hmc),
            context="Configured capability Systems collection",
        )

    def _configured_link(
        self, dut_id: str, uri: Any, *, hmc: bool | None = None
    ) -> str:
        """
        Normalize a path-only capability link before comparing resource identity.

        Validate the original advertised path before rebasing. Invalid authorities,
        queries and traversal remain invalid even if a suffix resembles a known
        catalog resource.

        Args:
            dut_id: DUT whose BMC and HMC roots interpret the advertised path.
            uri: Untrusted response link; authorities and queries remain invalid.
            hmc: Parent namespace for descendant links, or ``None`` to infer it
                when resolving a top-level System member.

        Returns:
            The configured path, or an empty sentinel for an invalid link.
        """

        validated = self._normalize_uri(uri)
        if not validated:
            return ""
        uri_manager = self.orchestrator.dut_manager.uri_config_manager
        try:
            return uri_manager.normalize_response_uri(dut_id, validated, hmc=hmc)
        except (RedfishTopologyProfileError, TypeError, ValueError):
            return ""

    def _configured_system_member(
        self, dut_id: str, member: Any, *, hmc: bool | None = None
    ) -> tuple[str, str] | None:
        """
        Validate a System member against its configured BMC or HMC collection.

        Use the same namespace for the collection and member ancestry check. This
        admits configured HMC members without accepting unrelated collections or
        nested descendants as ComputerSystem identities. An unresolved collection
        policy invalidates this member without discarding other discovered Systems.

        Args:
            dut_id: DUT owning the collection and the advertised member.
            member: Untrusted member object returned by Systems discovery.
            hmc: Resolved parent namespace, or ``None`` to infer member routing
                when a BMC collection may advertise independent HMC Systems.

        Returns:
            The exact case-sensitive System ID and URI, or ``None`` if invalid.
        """

        if not isinstance(member, dict):
            return None
        uri = self._configured_link(dut_id, member.get("@odata.id"), hmc=hmc)
        if not uri:
            return None
        uri_manager = self.orchestrator.dut_manager.uri_config_manager
        try:
            systems_collection_uri = self._configured_systems_uri(
                dut_id, hmc=uri_manager._is_hmc_uri(uri, dut_id)
            )
        except (AttributeError, TypeError, ValueError):
            return None
        return self._system_member({"@odata.id": uri}, systems_collection_uri)

    @classmethod
    def _canonical_action_info(
        cls,
        response: Any,
        requested_uri: str,
        system_uri: str,
    ) -> tuple[bool, str]:
        """
        Return the canonical action info.

        The implementation uses ``response``, ``requested_uri``, and
        ``system_uri`` to produce the canonical action info. Remote I/O uses the
        configured transport policy and returns only after its response or
        failure has been observed.

        Args:
            response: Transport response governed by the configured
                authentication and trust policy.
            requested_uri: Validated remote resource identifier used for
                requested URI.
            system_uri: Validated remote resource identifier used for system
                URI.

        Returns:
            A tuple containing ``success flag`` and ``status text`` in that
            order.
        """
        if not isinstance(response, dict):
            return False, "ActionInfo response is not a JSON object"

        requested = cls._normalize_uri(requested_uri)
        response_uri = cls._normalize_uri(response.get("@odata.id"))
        if not response_uri:
            return False, "ActionInfo response has a missing or invalid @odata.id"
        if response_uri != requested:
            return False, "ActionInfo @odata.id mismatch with the requested URI"

        canonical_system_uri = cls._normalize_uri(system_uri)
        if not canonical_system_uri or not requested.startswith(
            f"{canonical_system_uri}/"
        ):
            return False, "ActionInfo URI does not belong to the discovered System"

        odata_type = response.get("@odata.type")
        if not isinstance(odata_type, str) or "ActionInfo" not in odata_type:
            return False, "ActionInfo response has an invalid @odata.type"
        if not isinstance(response.get("Parameters"), list):
            return False, "ActionInfo response is missing Parameters"
        return True, ""

    @classmethod
    def _parameter_values(cls, action_info: dict[str, Any]) -> dict[str, list[str]]:
        """
        Extract bounded string-valued ActionInfo capability evidence.

        Non-mapping parameters and non-string allowable values retain the
        established compatibility behavior and are ignored. Structurally valid
        collections are rejected when their entry count, individual UTF-8 text,
        or aggregate retained UTF-8 text exceeds the run-cache ceilings. A
        caller must treat that rejection as unavailable capability evidence,
        never as an authoritative truncated capability list.

        Args:
            action_info: Mapping supplying fields for parameter values.

        Returns:
            A new mapping of parameter names to retained allowable strings.

        Raises:
            ValueError: If a parameter/value count or retained UTF-8 byte limit
                is exceeded, or a retained string is not valid UTF-8 text.
        """
        parameters = action_info.get("Parameters", [])
        if len(parameters) > cls.MAX_ACTION_INFO_PARAMETERS:
            raise ValueError("ActionInfo has too many Parameters to retain safely")

        values: dict[str, list[str]] = {}
        seen_parameter_names: set[str] = set()
        retained_text_bytes = 0
        for parameter in parameters:
            if not isinstance(parameter, dict):
                continue
            name = parameter.get("Name")
            allowable = parameter.get("AllowableValues")
            if not isinstance(name, str):
                continue
            if name in seen_parameter_names:
                raise ValueError("ActionInfo contains a duplicate parameter name")
            seen_parameter_names.add(name)
            if not isinstance(allowable, list):
                continue
            if len(allowable) > cls.MAX_ACTION_INFO_ALLOWABLE_VALUES_PER_PARAMETER:
                raise ValueError(
                    "ActionInfo parameter has too many AllowableValues to retain safely"
                )
            try:
                name_bytes = len(name.encode("utf-8"))
            except UnicodeEncodeError as error:
                raise ValueError(
                    "ActionInfo parameter text is not valid UTF-8"
                ) from error
            if name_bytes > cls.MAX_ACTION_INFO_TEXT_BYTES:
                raise ValueError("ActionInfo parameter text exceeds retention limit")
            retained_text_bytes += name_bytes

            retained_values: list[str] = []
            for value in allowable:
                if not isinstance(value, str):
                    continue
                try:
                    value_bytes = len(value.encode("utf-8"))
                except UnicodeEncodeError as error:
                    raise ValueError(
                        "ActionInfo parameter text is not valid UTF-8"
                    ) from error
                if value_bytes > cls.MAX_ACTION_INFO_TEXT_BYTES:
                    raise ValueError(
                        "ActionInfo parameter text exceeds retention limit"
                    )
                retained_text_bytes += value_bytes
                if retained_text_bytes > cls.MAX_ACTION_INFO_RETAINED_TEXT_BYTES:
                    raise ValueError(
                        "ActionInfo parameter values exceed aggregate retention limit"
                    )
                retained_values.append(value)
            if retained_text_bytes > cls.MAX_ACTION_INFO_RETAINED_TEXT_BYTES:
                raise ValueError(
                    "ActionInfo parameter values exceed aggregate retention limit"
                )
            values[name] = retained_values
        return values

    @classmethod
    def _retained_action_info(cls, action_info: dict[str, Any]) -> dict[str, Any]:
        """
        Return an owned exact copy of one bounded ActionInfo document.

        R46 publishes this evidence, so a successful canonical response must
        remain available as the complete JSON document rather than only as a
        derived parameter list. The iterative preflight bounds nesting, node
        count, individual and aggregate UTF-8 text, and canonical encoded size
        before ``deepcopy`` retains the device-controlled object. Across the
        fixed System limit, these per-document ceilings also bound aggregate
        cache and per-access copy amplification.

        Args:
            action_info: Canonical JSON object returned by the advertised
                System Dump ActionInfo URI.

        Returns:
            A defensive copy with the same JSON mapping, sequence, scalar, and
            null values as the validated ActionInfo response.

        Raises:
            ValueError: If the document exceeds a retention limit, contains a
                non-string mapping key, a non-JSON value, non-finite numeric
                data, or text that cannot be represented as UTF-8.
        """
        stack: list[tuple[Any, int]] = [(action_info, 1)]
        nodes = 0
        retained_text_bytes = 0

        while stack:
            value, depth = stack.pop()
            nodes += 1
            if nodes > cls.MAX_ACTION_INFO_RETAINED_NODES:
                raise ValueError("ActionInfo document exceeds retention node limit")
            if depth > cls.MAX_ACTION_INFO_RETAINED_DEPTH:
                raise ValueError("ActionInfo document exceeds retention depth limit")

            if isinstance(value, dict):
                for key, child in value.items():
                    if not isinstance(key, str):
                        raise ValueError(
                            "ActionInfo document contains a non-string mapping key"
                        )
                    try:
                        key_bytes = len(key.encode("utf-8"))
                    except UnicodeEncodeError as error:
                        raise ValueError(
                            "ActionInfo document text is not valid UTF-8"
                        ) from error
                    if key_bytes > cls.MAX_ACTION_INFO_TEXT_BYTES:
                        raise ValueError(
                            "ActionInfo document text exceeds retention limit"
                        )
                    retained_text_bytes += key_bytes
                    stack.append((child, depth + 1))
            elif isinstance(value, list):
                stack.extend((child, depth + 1) for child in value)
            elif isinstance(value, str):
                try:
                    value_bytes = len(value.encode("utf-8"))
                except UnicodeEncodeError as error:
                    raise ValueError(
                        "ActionInfo document text is not valid UTF-8"
                    ) from error
                if value_bytes > cls.MAX_ACTION_INFO_TEXT_BYTES:
                    raise ValueError("ActionInfo document text exceeds retention limit")
                retained_text_bytes += value_bytes
            elif value is None or isinstance(value, (bool, int)):
                pass
            elif isinstance(value, float):
                if not math.isfinite(value):
                    raise ValueError("ActionInfo document contains a non-finite number")
            else:
                raise ValueError("ActionInfo document contains a non-JSON value")

            if retained_text_bytes > cls.MAX_ACTION_INFO_RETAINED_TEXT_BYTES:
                raise ValueError(
                    "ActionInfo document text exceeds aggregate retention limit"
                )

        try:
            encoded = json.dumps(
                action_info,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (
            OverflowError,
            RecursionError,
            TypeError,
            UnicodeEncodeError,
            ValueError,
        ) as error:
            raise ValueError("ActionInfo document is not bounded JSON") from error
        if len(encoded) > cls.MAX_ACTION_INFO_RETAINED_DOCUMENT_BYTES:
            raise ValueError("ActionInfo document exceeds retained byte limit")
        return copy.deepcopy(action_info)

    @staticmethod
    def _redfish_preflight_failed(
        dut_id: str, preflight_results: Optional[dict[str, Any]]
    ) -> bool:
        """
        Return the Redfish preflight failed.

        The implementation uses ``dut_id`` and ``preflight_results`` to produce
        the Redfish preflight failed.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            preflight_results: Mapping supplying fields for redfish preflight
                failed.

        Returns:
            Whether the redfish preflight failed operation succeeds.
        """
        if not isinstance(preflight_results, dict):
            return False
        dut_result = preflight_results.get(dut_id, {})
        if not isinstance(dut_result, dict):
            return False
        services = dut_result.get("services", {})
        if not isinstance(services, dict):
            return False
        redfish = services.get("redfish", {})
        return isinstance(redfish, dict) and redfish.get("status") == "fail"

    @staticmethod
    def _empty_result(dut_id: str) -> dict[str, Any]:
        """
        Return the empty result.

        The implementation uses ``dut_id`` to produce the empty result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing the ``source``, ``dut_id``, ``status``,
            ``authoritative``, and ``systems_collection_uri`` fields.
        """
        return {
            "source": SYSTEM_DUMP_CAPABILITY_SOURCE,
            "dut_id": dut_id,
            "status": "unavailable",
            "authoritative": False,
            "systems_collection_uri": SYSTEMS_COLLECTION_URI,
            "systems": {},
            "oem_diagnostic_data_types": [],
            "errors": [],
            "systems_member_count": 0,
            "systems_followed_count": 0,
            "systems_members_truncated": False,
            "invalid_system_members": 0,
            "duplicate_system_members": 0,
            "systems_available_count": 0,
            "systems_unsupported_count": 0,
            "systems_unavailable_count": 0,
            "requests_made": 0,
        }

    @staticmethod
    def _system_result(
        system_uri: str,
        *,
        status: str,
        action_target_uri: str = "",
        action_target_state: str = "unknown",
        action_info_uri: str = "",
        parameter_values: Optional[dict[str, list[str]]] = None,
        action_info: Optional[dict[str, Any]] = None,
        error: str = "",
        reason: str = "",
    ) -> dict[str, Any]:
        """
        Build one stable per-System capability result.

        Unsupported results carry a non-error ``reason`` because they represent
        authoritative negative capability evidence. Unavailable results carry an
        ``error`` because advertised topology could not be characterized. The
        function copies mutable values into a new result and has no side effects.

        Args:
            system_uri: Validated URI of the discovered ComputerSystem resource.
            status: Capability state: ``available``, ``unsupported``, or
                ``unavailable``.
            action_target_uri: Validated target advertised for the System Dump
                ``CollectDiagnosticData`` action, or an empty value when no
                callable action was advertised.
            action_target_state: Discovery state for the advertised action
                target: ``available``, ``unsupported``, ``invalid``, or
                ``unknown`` when discovery did not reach that field.
            action_info_uri: Advertised ActionInfo URI, or an empty value when no
                such link was advertised.
            parameter_values: Validated ActionInfo allowable values by parameter.
            action_info: Exact device ActionInfo response retained as evidence.
            error: Failure reason for unavailable advertised topology.
            reason: Non-error reason for an unsupported System.

        Returns:
            A serializable mapping with a stable per-System capability shape.
        """
        normalized_values = dict(parameter_values or {})
        return {
            "system_uri": system_uri,
            "action_target_uri": action_target_uri,
            "action_target_state": action_target_state,
            "action_info_uri": action_info_uri,
            "status": status,
            "parameter_values": normalized_values,
            "oem_diagnostic_data_types": list(
                normalized_values.get(OEM_DIAGNOSTIC_DATA_TYPE, [])
            ),
            "action_info": action_info,
            "error": error,
            "reason": reason,
        }

    async def discover_many(
        self,
        dut_ids: list[str],
        preflight_results: Optional[dict[str, Any]] = None,
        force: bool = False,
    ) -> dict[str, dict[str, Any]]:
        """
        Discover capabilities with a fixed number of owned worker tasks.

        The implementation uses ``dut_ids``, ``preflight_results``, and
        ``force`` to discover capabilities with a fixed number of owned worker
        tasks. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.
            force: Whether force is enabled or required for this operation.

        Returns:
            The validated ``results``.
        """
        pending = deque(enumerate(dut_ids))
        discoveries: list[dict[str, Any] | Exception | None] = [None] * len(dut_ids)

        async def worker() -> None:
            """
            Process one capability-discovery request in the bounded worker pool.

            The implementation uses current instance state to process one
            capability-discovery request in the bounded worker pool. Terminal
            status is emitted only after one capability-discovery request in the
            bounded worker pool and its owned cleanup have completed. Owned
            asynchronous work is awaited before return, so completion does not
            leave an unobserved task behind.
            """
            while pending:
                index, dut_id = pending.popleft()
                try:
                    discoveries[index] = await self.discover(
                        dut_id, preflight_results, force=force
                    )
                except Exception as error:  # keep other DUT discoveries independent
                    discoveries[index] = error

        worker_count = min(len(dut_ids), self.MAX_CONCURRENT_DUT_DISCOVERIES)
        async with asyncio.TaskGroup() as task_group:
            for _ in range(worker_count):
                task_group.create_task(worker())

        results: dict[str, dict[str, Any]] = {}
        for dut_id, discovery in zip(dut_ids, discoveries):
            if isinstance(discovery, Exception):
                result = self._empty_result(dut_id)
                result["errors"].append(str(discovery))
                self._cache[dut_id] = result
                results[dut_id] = copy.deepcopy(result)
                await self._log(
                    "WARNING",
                    f"Capability discovery failed unexpectedly: {discovery}",
                    dut_id,
                )
            else:
                assert discovery is not None
                results[dut_id] = discovery
        return results

    async def discover(
        self,
        dut_id: str,
        preflight_results: Optional[dict[str, Any]] = None,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Discover canonical System Dump ActionInfo for one DUT.

        ``force=True`` bypasses both this manager's run-scoped snapshot and the
        DUT's HTTP GET cache so safety-sensitive consumers receive live
        evidence.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.
            force: Whether force is enabled or required for this operation.

        Returns:
            A mapping containing discover.
        """
        if not force and dut_id in self._cache:
            return self.get(dut_id)

        lock = self._locks.setdefault(dut_id, asyncio.Lock())
        async with lock:
            if not force and dut_id in self._cache:
                return self.get(dut_id)

            result = self._empty_result(dut_id)
            dut_manager = getattr(self.orchestrator, "dut_manager", None)
            if dut_manager is None:
                result["errors"].append("DUT manager is not initialized")
                self._cache[dut_id] = result
                return copy.deepcopy(result)

            if self._redfish_preflight_failed(dut_id, preflight_results):
                result["errors"].append(
                    "Redfish preflight failed; live dump capabilities were not queried"
                )
                self._cache[dut_id] = result
                await self._log(
                    "INFO",
                    "Skipping capability discovery because Redfish preflight failed",
                    dut_id,
                )
                return copy.deepcopy(result)

            try:
                systems_collection_uri = self._configured_systems_uri(dut_id)
                collection_hmc = dut_manager.uri_config_manager._is_hmc_uri(
                    systems_collection_uri, dut_id
                )
            except (AttributeError, TypeError, ValueError):
                result["errors"].append(
                    "System capability URI configuration is invalid"
                )
                self._cache[dut_id] = result
                return copy.deepcopy(result)
            result["systems_collection_uri"] = systems_collection_uri

            request_budget = _RequestBudget(self.MAX_DISCOVERY_REQUESTS)
            if not request_budget.reserve():
                result["errors"].append(
                    "System capability request budget was exhausted before discovery"
                )
                self._cache[dut_id] = result
                return copy.deepcopy(result)
            success, response, _, _ = await dut_manager.execute_redfish_request(
                dut_id,
                "GET",
                systems_collection_uri,
                timeout=30,
                bypass_cache=force,
                retry_count=0,
            )
            if not success or not isinstance(response, dict):
                result["requests_made"] = request_budget.used
                result["errors"].append(
                    f"Failed to query {systems_collection_uri}: transport failed "
                    "or response was not a JSON object"
                )
                self._cache[dut_id] = result
                await self._log("WARNING", result["errors"][-1], dut_id)
                return copy.deepcopy(result)

            members = response.get("Members")
            if not isinstance(members, list):
                result["requests_made"] = request_budget.used
                result["errors"].append("Systems collection is missing Members")
                self._cache[dut_id] = result
                return copy.deepcopy(result)

            bounded_members, source_count, truncated = bound_redfish_collection_members(
                members,
                field_name="Systems Members",
                limit=self.MAX_FOLLOWED_SYSTEMS,
            )
            result["systems_member_count"] = source_count
            result["systems_members_truncated"] = truncated
            collection_complete = not truncated
            if truncated:
                result["errors"].append(
                    f"Systems collection returned {source_count} members; only "
                    f"{self.MAX_FOLLOWED_SYSTEMS} may be followed"
                )

            next_link = response.get("Members@odata.nextLink") or response.get(
                "@odata.nextLink"
            )
            if next_link:
                collection_complete = False
                result["errors"].append(
                    "Systems collection is paginated; capability discovery did not "
                    "receive the complete member set"
                )
            advertised_count = response.get("Members@odata.count")
            if advertised_count is not None:
                if (
                    isinstance(advertised_count, bool)
                    or not isinstance(advertised_count, int)
                    or advertised_count < 0
                ):
                    collection_complete = False
                    result["errors"].append(
                        "Systems collection has an invalid Members@odata.count"
                    )
                elif advertised_count != source_count:
                    collection_complete = False
                    result["errors"].append(
                        "Systems collection member list does not match "
                        "Members@odata.count"
                    )

            systems: list[tuple[str, str]] = []
            seen_system_uris: set[str] = set()
            invalid_members = 0
            duplicate_members = 0
            for member in bounded_members:
                parsed = self._configured_system_member(
                    dut_id, member, hmc=True if collection_hmc else None
                )
                if parsed is None:
                    invalid_members += 1
                    continue
                _, system_uri = parsed
                if system_uri in seen_system_uris:
                    duplicate_members += 1
                    continue
                seen_system_uris.add(system_uri)
                systems.append(parsed)

            result["invalid_system_members"] = invalid_members
            result["duplicate_system_members"] = duplicate_members
            result["systems_followed_count"] = len(systems)
            if invalid_members:
                collection_complete = False
                result["errors"].append(
                    f"Systems collection contains {invalid_members} invalid member(s)"
                )

            if not systems:
                result["requests_made"] = request_budget.used
                result["errors"].append("Systems collection contains no valid members")
                self._cache[dut_id] = result
                return copy.deepcopy(result)

            pending_systems = deque(enumerate(systems))
            system_results: list[dict[str, Any] | Exception | None] = [None] * len(
                systems
            )

            async def system_worker() -> None:
                """
                Discover one system's dump capabilities in the bounded worker pool.

                The implementation uses current instance state to discover one
                system's dump capabilities in the bounded worker pool. Owned
                asynchronous work is awaited before return, so completion does
                not leave an unobserved task behind.
                """
                while pending_systems:
                    index, (system_id, uri) = pending_systems.popleft()
                    try:
                        system_results[index] = await self._discover_system(
                            dut_id,
                            system_id,
                            uri,
                            bypass_cache=force,
                            request_budget=request_budget,
                        )
                    except Exception as error:
                        system_results[index] = error

            worker_count = min(len(systems), self.MAX_CONCURRENT_SYSTEM_PROBES)
            async with asyncio.TaskGroup() as task_group:
                for _ in range(worker_count):
                    task_group.create_task(system_worker())

            all_values: list[str] = []
            complete = collection_complete
            for (system_id, system_uri), system_result in zip(systems, system_results):
                if isinstance(system_result, Exception):
                    system_result = self._system_result(
                        system_uri,
                        status="unavailable",
                        error=str(system_result),
                    )
                assert system_result is not None
                result["systems"][system_id] = system_result
                system_status = system_result["status"]
                if system_status == "available":
                    result["systems_available_count"] += 1
                elif system_status == "unsupported":
                    result["systems_unsupported_count"] += 1
                else:
                    result["systems_unavailable_count"] += 1
                    complete = False
                    if system_result.get("error"):
                        result["errors"].append(
                            f"System {system_id}: {system_result['error']}"
                        )
                for value in system_result.get("oem_diagnostic_data_types", []):
                    if value not in all_values:
                        all_values.append(value)

            result["oem_diagnostic_data_types"] = all_values
            result["requests_made"] = request_budget.used
            result["authoritative"] = complete
            if complete:
                result["status"] = (
                    "available" if result["systems_available_count"] else "unsupported"
                )
            elif (
                result["systems_available_count"] or result["systems_unsupported_count"]
            ):
                result["status"] = "partial"

            self._cache[dut_id] = result
            await self._log(
                "INFO",
                f"Discovered {len(all_values)} System dump payload(s) across "
                f"{len(result['systems'])} System(s) "
                f"({result['systems_available_count']} available, "
                f"{result['systems_unsupported_count']} unsupported, "
                f"{result['systems_unavailable_count']} unavailable); "
                f"status={result['status']}, "
                f"authoritative={result['authoritative']}",
                dut_id,
            )
            return copy.deepcopy(result)

    async def _discover_system(
        self,
        dut_id: str,
        system_id: str,
        system_uri: str,
        bypass_cache: bool = False,
        request_budget: _RequestBudget | None = None,
    ) -> dict[str, Any]:
        """
        Discover bounded diagnostic capabilities beneath one resolved System.

        Follow advertised LogServices, Dump actions and ActionInfo while retaining
        the System's resolved BMC or HMC namespace across proxy-rewritten child
        links. Validate each descendant's ancestry and retain the original bounded
        ActionInfo response separately from its normalized request identity.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            system_id: Exact case-sensitive ComputerSystem identity to validate.
            system_uri: Advertised System URI to resolve under configured roots.
            bypass_cache: Whether to bypass the owned Redfish response cache.
            request_budget: Shared discovery request budget, or ``None`` to allow
                the four requests needed for this System's capability traversal.

        Returns:
            A mapping containing the ``system_uri``, ``action_target_uri``,
            ``action_info_uri``, ``status``, ``parameter_values``, and
            ``oem_diagnostic_data_types`` fields.

        Side Effects:
            Issues bounded GET requests through the DUT manager and consumes the
            supplied request budget; no diagnostic action is executed.
        """
        dut_manager = getattr(self.orchestrator, "dut_manager", None)
        if dut_manager is None:
            return self._system_result(
                self._normalize_uri(system_uri),
                status="unavailable",
                error="dut_manager unavailable",
            )
        parsed_system = self._configured_system_member(
            dut_id, {"@odata.id": system_uri}
        )
        if parsed_system is None or parsed_system[0] != system_id:
            return self._system_result(
                "",
                status="unavailable",
                error="System capability URI or identifier is invalid",
            )
        system_uri = parsed_system[1]
        system_hmc = dut_manager.uri_config_manager._is_hmc_uri(system_uri, dut_id)

        if request_budget is None:
            request_budget = _RequestBudget(4)

        if not request_budget.reserve():
            return self._system_result(
                system_uri,
                status="unavailable",
                error="System capability request budget exhausted",
            )

        system_success, system_response, _, _ = (
            await dut_manager.execute_redfish_request(
                dut_id,
                "GET",
                system_uri,
                timeout=30,
                bypass_cache=bypass_cache,
                retry_count=0,
            )
        )
        if not system_success or not isinstance(system_response, dict):
            return self._system_result(
                system_uri,
                status="unavailable",
                error="Failed to query advertised System resource",
            )
        response_system_uri = self._configured_link(
            dut_id, system_response.get("@odata.id"), hmc=system_hmc
        )
        if response_system_uri != system_uri:
            return self._system_result(
                system_uri,
                status="unavailable",
                error="System response has a missing or mismatched @odata.id",
            )

        log_services_link = system_response.get("LogServices")
        if log_services_link is None:
            return self._system_result(
                system_uri,
                status="unsupported",
                reason="System does not advertise a LogServices collection",
            )
        if not isinstance(log_services_link, dict):
            return self._system_result(
                system_uri,
                status="unavailable",
                error="Advertised LogServices link is malformed",
            )
        try:
            log_services_uri = validate_redfish_uri_path(
                self._configured_link(
                    dut_id, log_services_link.get("@odata.id"), hmc=system_hmc
                ),
                context="Advertised System LogServices URI",
                service_root=system_uri,
            )
        except (RedfishTopologyProfileError, TypeError, ValueError):
            return self._system_result(
                system_uri,
                status="unavailable",
                error="Advertised LogServices URI is invalid",
            )

        if not request_budget.reserve():
            return self._system_result(
                system_uri,
                status="unavailable",
                error="System capability request budget exhausted",
            )
        log_services_success, log_services_response, _, _ = (
            await dut_manager.execute_redfish_request(
                dut_id,
                "GET",
                log_services_uri,
                timeout=30,
                bypass_cache=bypass_cache,
                retry_count=0,
            )
        )
        if not log_services_success or not isinstance(log_services_response, dict):
            return self._system_result(
                system_uri,
                status="unavailable",
                error="Failed to query advertised LogServices collection",
            )
        log_service_members = log_services_response.get("Members")
        if not isinstance(log_service_members, list):
            return self._system_result(
                system_uri,
                status="unavailable",
                error="Advertised LogServices collection is missing Members",
            )

        bounded_log_services, source_count, truncated = (
            bound_redfish_collection_members(
                log_service_members,
                field_name="LogServices Members",
                limit=self.MAX_FOLLOWED_LOG_SERVICES,
            )
        )
        collection_complete = not truncated
        if log_services_response.get(
            "Members@odata.nextLink"
        ) or log_services_response.get("@odata.nextLink"):
            collection_complete = False
        advertised_count = log_services_response.get("Members@odata.count")
        if advertised_count is not None:
            if (
                isinstance(advertised_count, bool)
                or not isinstance(advertised_count, int)
                or advertised_count < 0
                or advertised_count != source_count
            ):
                collection_complete = False

        dump_uris: list[str] = []
        invalid_members = 0
        log_services_prefix = f"{log_services_uri.rstrip('/')}/"
        for member in bounded_log_services:
            if not isinstance(member, dict):
                invalid_members += 1
                continue
            try:
                member_uri = validate_redfish_uri_path(
                    self._configured_link(
                        dut_id, member.get("@odata.id"), hmc=system_hmc
                    ),
                    context="Advertised LogService member URI",
                    service_root=log_services_uri,
                )
            except (RedfishTopologyProfileError, TypeError, ValueError):
                invalid_members += 1
                continue
            if not member_uri.startswith(log_services_prefix):
                invalid_members += 1
                continue
            relative_member = member_uri[len(log_services_prefix) :]
            if not relative_member or "/" in relative_member:
                invalid_members += 1
                continue
            if member.get("Id") == "Dump" or relative_member == "Dump":
                if member_uri not in dump_uris:
                    dump_uris.append(member_uri)

        if invalid_members:
            collection_complete = False
        if not collection_complete:
            return self._system_result(
                system_uri,
                status="unavailable",
                error=(
                    "LogServices collection is incomplete or malformed; Dump "
                    "support cannot be determined"
                ),
            )
        if not dump_uris:
            return self._system_result(
                system_uri,
                status="unsupported",
                reason="System LogServices collection does not advertise Dump",
            )
        if len(dump_uris) != 1:
            return self._system_result(
                system_uri,
                status="unavailable",
                error="LogServices collection advertises multiple Dump services",
            )
        dump_uri = dump_uris[0]

        if not request_budget.reserve():
            return self._system_result(
                system_uri,
                status="unavailable",
                error="System capability request budget exhausted",
            )
        dump_success, dump_response, _, _ = await dut_manager.execute_redfish_request(
            dut_id,
            "GET",
            dump_uri,
            timeout=30,
            bypass_cache=bypass_cache,
            retry_count=0,
        )
        if not dump_success or not isinstance(dump_response, dict):
            return self._system_result(
                system_uri,
                status="unavailable",
                error="Failed to query advertised Dump LogService",
            )
        actions = dump_response.get("Actions")
        if not isinstance(actions, dict):
            if actions is None:
                return self._system_result(
                    system_uri,
                    status="unsupported",
                    reason="Dump LogService does not advertise diagnostic actions",
                )
            return self._system_result(
                system_uri,
                status="unavailable",
                error="Advertised Dump LogService Actions value is malformed",
            )
        action = actions.get("#LogService.CollectDiagnosticData")
        if action is None:
            return self._system_result(
                system_uri,
                status="unsupported",
                reason="Dump LogService does not advertise CollectDiagnosticData",
            )
        if not isinstance(action, dict):
            return self._system_result(
                system_uri,
                status="unavailable",
                error="Advertised CollectDiagnosticData action is malformed",
            )
        if "target" not in action:
            return self._system_result(
                system_uri,
                status="unsupported",
                action_target_state="unsupported",
                reason="CollectDiagnosticData does not advertise an action target",
            )
        try:
            action_target_uri = validate_redfish_uri_path(
                self._configured_link(dut_id, action["target"], hmc=system_hmc),
                context="Advertised System Dump action target",
                service_root=dump_uri,
            )
        except (RedfishTopologyProfileError, TypeError, ValueError):
            return self._system_result(
                system_uri,
                status="unavailable",
                action_target_state="invalid",
                error="Advertised CollectDiagnosticData action target is invalid",
            )
        if "@Redfish.ActionInfo" not in action:
            return self._system_result(
                system_uri,
                status="unsupported",
                action_target_uri=action_target_uri,
                action_target_state="available",
                reason="CollectDiagnosticData does not advertise ActionInfo",
            )
        try:
            action_info_uri = validate_redfish_uri_path(
                self._configured_link(
                    dut_id, action["@Redfish.ActionInfo"], hmc=system_hmc
                ),
                context="Advertised System ActionInfo URI",
                service_root=system_uri,
            )
        except (RedfishTopologyProfileError, TypeError, ValueError):
            return self._system_result(
                system_uri,
                status="unavailable",
                action_target_uri=action_target_uri,
                action_target_state="available",
                error="Advertised ActionInfo URI is invalid",
            )

        if not request_budget.reserve():
            return self._system_result(
                system_uri,
                status="unavailable",
                action_target_uri=action_target_uri,
                action_target_state="available",
                action_info_uri=action_info_uri,
                error="System capability request budget exhausted",
            )
        success, action_info, _, _ = await dut_manager.execute_redfish_request(
            dut_id,
            "GET",
            action_info_uri,
            timeout=30,
            bypass_cache=bypass_cache,
            retry_count=0,
        )
        if not success:
            return self._system_result(
                system_uri,
                status="unavailable",
                action_target_uri=action_target_uri,
                action_target_state="available",
                action_info_uri=action_info_uri,
                error="Failed to query advertised ActionInfo",
            )

        # Rebase identity only for validation. R46 must retain the exact bounded
        # device response, including any catalog-root @odata.id advertised behind
        # a proxy; action_info_uri separately records the configured request path.
        canonical_response = action_info
        if isinstance(action_info, dict):
            canonical_response = {
                **action_info,
                "@odata.id": self._configured_link(
                    dut_id, action_info.get("@odata.id"), hmc=system_hmc
                ),
            }
        canonical, error = self._canonical_action_info(
            canonical_response, action_info_uri, system_uri
        )
        if not canonical:
            return self._system_result(
                system_uri,
                status="unavailable",
                action_target_uri=action_target_uri,
                action_target_state="available",
                action_info_uri=action_info_uri,
                error=error,
            )

        try:
            parameter_values = self._parameter_values(action_info)
        except ValueError as parameter_error:
            return self._system_result(
                system_uri,
                status="unavailable",
                action_target_uri=action_target_uri,
                action_target_state="available",
                action_info_uri=action_info_uri,
                error=str(parameter_error),
            )
        if OEM_DIAGNOSTIC_DATA_TYPE not in parameter_values:
            return self._system_result(
                system_uri,
                status="unavailable",
                action_target_uri=action_target_uri,
                action_target_state="available",
                action_info_uri=action_info_uri,
                parameter_values=parameter_values,
                error=f"ActionInfo has no {OEM_DIAGNOSTIC_DATA_TYPE} parameter",
            )

        try:
            retained_action_info = self._retained_action_info(action_info)
        except ValueError as retention_error:
            return self._system_result(
                system_uri,
                status="unavailable",
                action_target_uri=action_target_uri,
                action_target_state="available",
                action_info_uri=action_info_uri,
                error=str(retention_error),
            )

        return self._system_result(
            system_uri,
            status="available",
            action_target_uri=action_target_uri,
            action_target_state="available",
            action_info_uri=action_info_uri,
            parameter_values=parameter_values,
            action_info=retained_action_info,
        )

    def get(self, dut_id: str) -> dict[str, Any]:
        """
        Return a defensive, stable snapshot for R46 and other consumers.

        After applying local validation, the function forwards ``dut_id`` to
        ``copy.deepcopy`` and preserves its return and exception contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing the values assembled by this operation.
        """
        return copy.deepcopy(self._cache.get(dut_id, self._empty_result(dut_id)))

    def supports(
        self, dut_id: str, value: str, system_id: str | None = None
    ) -> Optional[bool]:
        """
        Return True, False, or None when support is not authoritative.

        The implementation uses ``dut_id``, ``value``, and ``system_id`` to
        produce True, False, or None when support is not authoritative.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            value: Text supplied as value in the format accepted by this
                function.
            system_id: Stable system identifier used to correlate configuration,
                logs, and results.

        Returns:
            Whether the true, False, or None when support is not authoritative
            operation succeeds.
        """
        cached = self._cache.get(dut_id)
        if not cached:
            return None

        if system_id is not None:
            system = cached.get("systems", {}).get(system_id)
            if not isinstance(system, dict):
                return None
            if system.get("status") == "unsupported":
                return False
            if system.get("status") != "available":
                return None
            return value in system.get("oem_diagnostic_data_types", [])

        if value in cached.get("oem_diagnostic_data_types", []):
            return True
        if cached.get("authoritative"):
            return False
        return None

    def filter_payloads(
        self,
        dut_id: str,
        payloads: list[Any],
        system_id: str | None = None,
    ) -> list[Any]:
        """
        Keep advertised payloads; preserve unknown payloads for legacy BMCs.

        The implementation uses ``dut_id``, ``payloads``, and ``system_id`` to
        keep advertised payloads; preserve unknown payloads for legacy BMCs.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            payloads: Entries supplied as ``payloads`` without transferring
                container ownership.
            system_id: Stable system identifier used to correlate configuration,
                logs, and results.

        Returns:
            The validated ``filtered``.
        """
        filtered: list[Any] = []
        for payload in payloads:
            if isinstance(payload, dict):
                value = payload.get(OEM_DIAGNOSTIC_DATA_TYPE)
            else:
                value = payload
            if not isinstance(value, str):
                filtered.append(payload)
                continue
            supported = self.supports(dut_id, value, system_id=system_id)
            if supported is not False:
                filtered.append(payload)
        return filtered

    def clear(self, dut_id: str | None = None) -> None:
        """
        Clear state retained by the current owner.

        The implementation uses ``dut_id`` to clear state retained by the
        current owner.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        if dut_id is None:
            self._cache.clear()
            self._locks.clear()
        else:
            self._cache.pop(dut_id, None)
            self._locks.pop(dut_id, None)
