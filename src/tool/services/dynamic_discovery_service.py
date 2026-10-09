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
Dynamic Discovery Service.

Discovers and caches Redfish endpoints for dynamic resource discovery with
support for iterating over systems, chassis, and managers.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlsplit

from ..utils.enums import ResourceType
from ..utils.redfish_limits import (
    MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS,
    bound_redfish_collection_members,
)
from ..utils.redfish_topology_profile import (
    RedfishTopologyProfileError,
    validate_redfish_request_uri,
    validate_redfish_uri_path,
)
from ..utils.uri_config_manager import URIConfigManager

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryConfig:
    """
    Configuration for dynamic discovery.

    The coherent record keeps ``core_endpoints``, ``optional_endpoints``,
    ``sub_resource_endpoints``, ``manager_types``, and ``cache_enabled``
    together so consumers observe one discovery config state. Consumers receive
    the fields as one unit instead of assembling partial state.

    Attributes:
        core_endpoints: Collection of core endpoints entries retained by this
            record.
        optional_endpoints: Collection of optional endpoints entries retained by
            this record.
        sub_resource_endpoints: Collection of sub resource endpoints entries
            retained by this record.
        manager_types: Collection of manager types entries retained by this
            record.
        cache_enabled: Whether cache enabled applies to this record.
        verbose_logging: Whether verbose logging applies to this record.
        discover_sub_resources: Whether discover sub resources applies to this
            record.
        discover_firmware_inventory: Whether discover firmware inventory applies
            to this record.
    """

    # Core Redfish endpoints to discover
    core_endpoints: Optional[List[ResourceType]] = None

    # Optional endpoints to discover
    optional_endpoints: Optional[List[ResourceType]] = None

    # Sub-resource endpoints to discover (collections under singleton services)
    # Note: Excluding endpoints that commonly cause 403 errors or are slow
    sub_resource_endpoints: List[ResourceType] = field(
        default_factory=lambda: [
            # UpdateService sub-resources - Only include if needed
            # ResourceType.FIRMWARE_INVENTORY,  # SLOW: 60+ members, often not needed for basic discovery
            # ResourceType.SOFTWARE_INVENTORY,  # Often empty or slow
            # TaskService sub-resources
            # ResourceType.TASKS,  # Often causes 403 errors
            # EventService sub-resources
            # ResourceType.SUBSCRIPTIONS,  # Often causes 403 errors
            # SessionService sub-resources
            # ResourceType.SESSIONS,  # Often causes 403 errors
            # AccountService sub-resources - Often cause 403 errors
            # ResourceType.ACCOUNTS,  # Often causes 403 errors
            # ResourceType.ROLES,  # Often causes 403 errors
            # ResourceType.EXTERNAL_ACCOUNT_PROVIDERS,  # Often causes 403 errors
        ]
    )

    # Manager types to filter for (e.g., "BMC", "EnclosureManager")
    manager_types: List[str] = field(
        default_factory=lambda: ["BMC", "EnclosureManager"]
    )

    # Whether to cache discovery results
    cache_enabled: bool = True

    # Whether to log discovery details
    verbose_logging: bool = False

    # Whether to discover sub-resources (can be slow and cause 403 errors)
    discover_sub_resources: bool = False

    # Whether to discover firmware inventory (enabled dynamically based on collector requirements)
    discover_firmware_inventory: bool = False


class DynamicDiscoveryService:
    """
    Service for discovering and caching Redfish endpoints dynamically.

    This service discovers available Redfish resources and caches them in memory
    for use by collectors. It implements the same functionality as the legacy
    base_collector.py but natively without external dependencies.
    """

    MAX_DISCOVERY_MEMBERS = MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS
    MAX_DISCOVERY_PAGE_REQUESTS = 64
    DISCOVERY_DEADLINE_SECONDS = 120.0

    def __init__(
        self, dut_manager, logger, uri_config_manager: Optional[URIConfigManager] = None
    ):
        """
        Initialize the Dynamic Discovery service.

        The initializer records ``_discovery_cache``, ``_resource_details``,
        ``_resource_members``, ``_resource_metadata``, and ``_resource_uris``
        for later operations and establishes the instance invariants before any
        public method runs. If the function cannot initialize the Dynamic
        Discovery service, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            dut_manager: DUT manager consumed while the function attempts to
                initialize the Dynamic Discovery service.
            logger: Sanitized logger used for operator-visible diagnostics.
            uri_config_manager: Validated remote resource identifier used for
                URI config manager.

        Raises:
            ValueError: If dynamicdiscoveryservice lacks a URI configuration
                manager.
        """
        self.dut_manager = dut_manager
        self.logger = logger
        if uri_config_manager is None:
            raise ValueError(
                "DynamicDiscoveryService requires a URI configuration manager"
            )
        self.uri_config_manager = uri_config_manager
        self.config = self._resolve_config(DiscoveryConfig())

        # Cache for discovered resources
        self._discovery_cache: Dict[str, Any] = {}
        self._resource_members: Dict[str, List[str]] = {}
        self._resource_details: Dict[str, Dict[str, Any]] = {}
        self._resource_metadata: Dict[str, Dict[str, Any]] = {}

        # Core resource mappings (will be populated dynamically using URI config manager)
        self._resource_uris = {}

    def _sanitize_diagnostic(self, text: str) -> str:
        """
        Route exception text through the run sanitizer or withhold it.

        The implementation uses ``text`` to route exception text through the run
        sanitizer or withhold it.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical diagnostic text.
        """

        sanitize = getattr(self.logger, "_sanitize_text", None)
        if callable(sanitize):
            sanitized = sanitize(text)
            if isinstance(sanitized, str):
                return sanitized
        return "Discovery failure details withheld: run sanitizer unavailable"

    def set_config(self, config: DiscoveryConfig) -> None:
        """
        Set discovery configuration.

        The implementation uses ``config`` to set discovery configuration. It
        updates ``config`` on the instance as part of that state transition.

        Args:
            config: Config governing set discovery configuration.
        """
        self.config = self._resolve_config(config)

    def _resolve_config(self, config: DiscoveryConfig) -> DiscoveryConfig:
        """
        Fill topology-owned discovery categories without a local fallback.

        The implementation uses ``config`` to fill topology-owned discovery
        categories without a local fallback.

        Args:
            config: Config governing fill topology-owned discovery categories
                without a local fallback.

        Returns:
            The validated ``config``.
        """

        if config.core_endpoints is None:
            config.core_endpoints = (
                self.uri_config_manager.get_discovery_resource_types("core")
            )
        if config.optional_endpoints is None:
            config.optional_endpoints = (
                self.uri_config_manager.get_discovery_resource_types("optional")
            )
        return config

    def _get_resource_uri(self, dut_id: str, resource_type: ResourceType) -> str:
        """
        Get the catalog-owned URI for a resource type.

        After applying local validation, the function forwards ``dut_id`` and
        ``resource_type`` to ``self.uri_config_manager.get_uri`` and preserves
        its return and exception contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            resource_type: Resource type consumed while the function attempts to
                get the catalog-owned URI for a resource type.

        Returns:
            The canonical resource URI text.
        """
        return self.uri_config_manager.get_uri(dut_id, resource_type)

    def _get_firmware_inventory_resource_types(self) -> List[ResourceType]:
        """
        Return the catalog-owned ordered firmware inventory candidates.

        The implementation uses current instance state to produce the
        catalog-owned ordered firmware inventory candidates. If the function
        cannot produce the catalog-owned ordered firmware inventory candidates,
        its exception reaches the caller instead of being converted into a
        successful result.

        Returns:
            The validated ``resource_types``.

        Raises:
            ValueError: If catalog Redfish topology must define a non-empty
                discovery.firmware_inventory_candidates list; or catalog Redfish
                topology firmware inventory candidate ``index`` is not a
                supported resource: ``resource_type``.
        """

        resource_types = self.uri_config_manager.get_discovery_resource_types(
            "firmware_inventory_candidates"
        )
        if not isinstance(resource_types, list) or not resource_types:
            raise ValueError(
                "Catalog Redfish topology must define a non-empty "
                "discovery.firmware_inventory_candidates list"
            )
        for index, resource_type in enumerate(resource_types):
            if not isinstance(resource_type, ResourceType):
                raise ValueError(
                    "Catalog Redfish topology firmware inventory candidate "
                    f"{index} is not a supported resource: {resource_type!r}"
                )
        return resource_types

    def _create_standardized_collector_result(
        self,
        successful_operations: int = 0,
        total_operations: int = 0,
        output_files: List[str] = None,
        error_messages: List[str] = None,
        operation_name: str = "dynamic_discovery",
        additional_context: Dict[str, Any] = None,
        dut_id: str = None,
        collector_id: str = None,
    ) -> Dict[str, Any]:
        """
        Create a standardized collector result dictionary.

        This method provides a consistent result format for all collector
        operations. Now aligned with BaseService signature for consistency.

        Args:
            successful_operations: Numeric successful operations used while the
                operation performs bounded accounting.
            total_operations: Numeric total operations used while the operation
                performs bounded accounting.
            output_files: Optional output files; ``None`` selects the function's
                default behavior.
            error_messages: Optional error messages; ``None`` selects the
                function's default behavior.
            operation_name: Stable operation name used for lookup and
                operator-facing diagnostics.
            additional_context: Optional additional context; ``None`` selects
                the function's default behavior.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            A mapping containing the ``success``, ``successful_operations``,
            ``total_operations``, ``output_files``, and ``error_messages``
            fields.
        """
        if output_files is None:
            output_files = []
        if error_messages is None:
            error_messages = []
        if additional_context is None:
            additional_context = {}

        # Add dut_id and collector_id to additional_context if provided
        if dut_id:
            additional_context["dut_id"] = dut_id
        if collector_id:
            additional_context["collector_id"] = collector_id

        return {
            "success": successful_operations > 0 and len(error_messages) == 0,
            "successful_operations": successful_operations,
            "total_operations": total_operations,
            "output_files": output_files,
            "error_messages": error_messages,
            "operation_name": operation_name,
            "additional_context": additional_context,
        }

    async def discover_all_resources(
        self, dut_id: str, preflight_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Discover all configured Redfish resources for a DUT.

        The implementation uses ``dut_id`` and ``preflight_results`` to discover
        all configured Redfish resources for a DUT. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.

        Returns:
            A mapping containing discover all resources.
        """
        await self.logger.write_to_dut_runtime_log(
            dut_id, "INFO", "DynamicDiscovery", "Starting Redfish dynamic discovery..."
        )

        # Check if Redfish is available
        if preflight_results:
            redfish_status = preflight_results.get("redfish", {}).get("status")
            if redfish_status != "pass":
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "DynamicDiscovery",
                    f"Redfish preflight failed ({redfish_status}) - skipping discovery",
                )
                return self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[f"Redfish preflight failed: {redfish_status}"],
                    operation_name="dynamic_discovery",
                    additional_context={"preflight_status": redfish_status},
                    dut_id=dut_id,
                    collector_id="dynamic_discovery",
                )

        discovery_results = {
            "success": True,
            "partial": False,
            "dut_id": dut_id,
            "discovered_resources": {},
            "raw_response_data": {},
            "metadata": {
                "discovery_timestamp": None,
                "total_resources": 0,
                "cache_enabled": self.config.cache_enabled,
                "truncated_resources": [],
            },
        }

        try:
            # Combine all endpoints for parallel discovery
            all_endpoints = []

            # Add core endpoints
            for resource_type in self.config.core_endpoints:
                all_endpoints.append(("core", resource_type))

            # Add optional endpoints
            for resource_type in self.config.optional_endpoints:
                all_endpoints.append(("optional", resource_type))

            # Add sub-resource endpoints only if enabled
            if self.config.discover_sub_resources:
                for resource_type in self.config.sub_resource_endpoints:
                    all_endpoints.append(("sub-resource", resource_type))

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DynamicDiscovery",
                f"Starting parallel discovery of {len(all_endpoints)} endpoints: {[f'{category}({rt.value})' for category, rt in all_endpoints]}",
            )

            # Create async tasks for parallel execution
            async def discover_endpoint(
                category: str, resource_type: ResourceType
            ) -> tuple:
                """
                Discover a single endpoint and return (category, resource_type, result).

                The implementation uses ``category`` and ``resource_type`` to
                discover a single endpoint and return (category, resource_type,
                result). Owned asynchronous work is awaited before return, so
                completion does not leave an unobserved task behind.

                Args:
                    category: Text supplied as category in the format accepted
                        by this function.
                    resource_type: Resource type object whose ``value`` state is
                        read while performing discover a single endpoint and
                        return (category, resource_type, result).

                Returns:
                    A tuple containing ``category``, ``resource type``, and
                    ``discover endpoint value 3`` in that order.
                """
                try:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DynamicDiscovery",
                        f"Discovering {category} {resource_type.value}...",
                    )

                    result = await self._discover_resource(dut_id, resource_type)
                    return (category, resource_type, result)
                except Exception as e:
                    return (
                        category,
                        resource_type,
                        {"success": False, "error": str(e)},
                    )

            # Execute all discovery requests in parallel
            discovery_tasks = [
                discover_endpoint(category, resource_type)
                for category, resource_type in all_endpoints
            ]

            # Wait for all tasks to complete
            discovery_results_list = await asyncio.gather(
                *discovery_tasks, return_exceptions=True
            )

            # Process results
            for result_item in discovery_results_list:
                if isinstance(result_item, BaseException):
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "DynamicDiscovery",
                        f"Discovery task failed with exception: {str(result_item)}",
                    )
                    continue

                category, resource_type, result = result_item

                if result["success"]:
                    resource_result = {
                        "success": True,
                        "members": result["members"],
                        "total_count": result.get(
                            "total_count", len(result["members"])
                        ),
                    }
                    for metadata_key in (
                        "complete",
                        "partial",
                        "truncated",
                        "pagination_complete",
                        "source_member_count",
                        "advertised_member_count",
                        "advertised_count_mismatch",
                        "member_limit",
                        "page_count",
                        "request_count",
                        "rejected_member_count",
                        "duplicate_member_count",
                        "incomplete_reasons",
                    ):
                        if metadata_key in result:
                            resource_result[metadata_key] = result[metadata_key]
                    discovery_results["discovered_resources"][
                        resource_type.value
                    ] = resource_result
                    if result.get("partial"):
                        discovery_results["partial"] = True
                        discovery_results["metadata"].setdefault(
                            "incomplete_resources", []
                        ).append(resource_type.value)
                    if result.get("truncated"):
                        discovery_results["metadata"]["truncated_resources"].append(
                            resource_type.value
                        )
                    discovery_results["raw_response_data"][resource_type.value] = (
                        result.get("member_details", {})
                    )
                    discovery_results["metadata"]["total_resources"] += len(
                        result["members"]
                    )

                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DynamicDiscovery",
                        f"{category.capitalize()} {resource_type.value} discovered: {len(result['members'])} members (raw data stored)",
                    )
                else:
                    error_msg = result.get("error", "Not found")
                    if category == "core":
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARN",
                            "DynamicDiscovery",
                            f"Failed to discover core {resource_type.value}: {error_msg}",
                        )
                    else:
                        # Optional and sub-resource endpoints can fail silently
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DynamicDiscovery",
                            f"{category.capitalize()} {resource_type.value} not available: {error_msg}",
                        )

            # Cache results if enabled
            if self.config.cache_enabled:
                cache_key = f"{dut_id}_discovery"
                self._discovery_cache[cache_key] = discovery_results

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DynamicDiscovery",
                f"Discovery complete - found {discovery_results['metadata']['total_resources']} total resources",
            )

            return discovery_results

        except Exception as e:
            import traceback

            error_details = self._sanitize_diagnostic(
                f"Discovery failed: {e}\nTraceback:\n{traceback.format_exc()}"
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DynamicDiscovery",
                error_details,
            )
            return self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[error_details],
                operation_name="dynamic_discovery",
                additional_context={"error_traceback": error_details},
                dut_id=dut_id,
                collector_id="dynamic_discovery",
            )

    def _normalize_collection_link(
        self, dut_id: str, uri: str, *, context: str, hmc: bool
    ) -> str:
        """
        Rebase a response link before checking its collection membership.

        Proxies may advertise the catalog root inside a response fetched through
        a custom root. Validate the original path first, then translate that root
        without granting a link permission to escape its collection. Keep both
        pagination and member comparisons in the resolved collection namespace.
        BMC collections may still advertise independently routed HMC members.

        Args:
            dut_id: DUT whose effective collection root anchors the response.
            uri: Path-only response link, optionally containing a page query.
            context: Diagnostic name of the resource or pagination link.
            hmc: Resolved namespace of the collection whose links are validated.

        Returns:
            A validated request path in the effective collection namespace.

        Raises:
            RedfishTopologyProfileError: If the original or rebased URI is unsafe.
        """

        validated = validate_redfish_request_uri(uri, context=context)
        return self.uri_config_manager.normalize_response_uri(
            dut_id, validated, hmc=hmc
        )

    async def _discover_resource(
        self, dut_id: str, resource_type: ResourceType
    ) -> Dict[str, Any]:
        """
        Discover a specific Redfish resource type.

        The implementation uses ``dut_id`` and ``resource_type`` to discover a
        specific Redfish resource type. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        If the function cannot discover a specific Redfish resource type, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            resource_type: Resource type object whose ``value`` state is read
                while performing discover a specific Redfish resource type.

        Returns:
            A mapping containing discover resource.

        Raises:
            RedfishTopologyProfileError: If nextLink escaped its collection; or
                nextLink repeated a page.
        """
        # Get URI from config manager if available, otherwise use fallback
        if self.uri_config_manager:
            # Get DUT config for baseboard/platform info
            dut_config = self.dut_manager.get_dut_config(dut_id)
            baseboard = dut_config.get("baseboard")
            platform = dut_config.get("platform")

            # Map ResourceType enum to URI key
            uri_key = resource_type.value
            uri = self.uri_config_manager.get_uri(dut_id, uri_key, baseboard, platform)

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DynamicDiscovery",
                f"_discover_resource: using URI config manager for {resource_type.value}, baseboard={baseboard}, platform={platform}, uri_key={uri_key}, uri={uri}",
            )
        else:
            uri = self._get_resource_uri(dut_id, resource_type)
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DynamicDiscovery",
                f"_discover_resource: using fallback URI for {resource_type.value}: {uri}",
            )

        if not uri:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DynamicDiscovery",
                f"_discover_resource: no URI found for resource type {resource_type}",
            )
            return {
                "success": False,
                "error": f"Unknown resource type: {resource_type}",
            }

        try:
            discovery_started = time.monotonic()
            try:
                collection_request_uri = validate_redfish_request_uri(
                    uri,
                    context=f"{resource_type.value} collection URI",
                )
            except (RedfishTopologyProfileError, TypeError, ValueError):
                return {
                    "success": False,
                    "error": f"Invalid {resource_type.value} collection URI",
                }

            # Get the resource collection
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DynamicDiscovery",
                f"_discover_resource: making Redfish request GET {collection_request_uri}",
            )

            success, collection, error_info, _ = (
                await self.dut_manager.execute_redfish_request(
                    dut_id, "GET", collection_request_uri, timeout=10
                )
            )
            request_count = 1

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DynamicDiscovery",
                f"_discover_resource: Redfish request result - success={success}, collection_keys={list(collection.keys()) if (collection and isinstance(collection, dict)) else 'None'}",
            )

            # Accept response if it's a valid dict, even if success is False (e.g., HTTP 500 with valid JSON)
            if not collection or not isinstance(collection, dict):
                # Log the actual error details
                http_status = (
                    error_info.get("http_status")
                    if error_info and isinstance(error_info, dict)
                    else "unknown"
                )
                error_message = (
                    error_info.get("error_message", "No details")
                    if error_info and isinstance(error_info, dict)
                    else "No details"
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DynamicDiscovery",
                    f"_discover_resource: failed to get valid {resource_type.value} collection from {collection_request_uri} (HTTP {http_status}): {str(error_message)[:200]}",
                )
                return {
                    "success": False,
                    "error": f"Failed to get {resource_type.value} collection",
                }

            # If we got a valid dict but success=False, log a warning
            if not success:
                http_status = (
                    error_info.get("http_status")
                    if error_info and isinstance(error_info, dict)
                    else "unknown"
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "DynamicDiscovery",
                    f"_discover_resource: got valid JSON for {resource_type.value} despite HTTP error {http_status}, proceeding with discovery",
                )

            members: List[Any] = []
            source_member_count = 0
            members_truncated = False
            pagination_complete = bool(success)
            pagination_errors: List[str] = []
            page_count = 0
            collection_path = unquote(urlsplit(collection_request_uri).path)
            collection_hmc = self.uri_config_manager._is_hmc_uri(
                collection_request_uri, dut_id
            )
            seen_page_uris = {collection_request_uri}
            current_page = collection

            while True:
                page_count += 1
                try:
                    page_members, page_source_count, page_truncated = (
                        bound_redfish_collection_members(
                            current_page.get("Members", []),
                            field_name=f"{resource_type.value} Members",
                            limit=self.MAX_DISCOVERY_MEMBERS,
                        )
                    )
                except ValueError:
                    if page_count == 1:
                        return {
                            "success": False,
                            "error": f"Invalid {resource_type.value} Members collection",
                        }
                    pagination_complete = False
                    pagination_errors.append("paginated Members value was malformed")
                    break

                source_member_count += page_source_count
                remaining_capacity = self.MAX_DISCOVERY_MEMBERS - len(members)
                members.extend(page_members[: max(0, remaining_capacity)])
                if page_truncated or page_source_count > remaining_capacity:
                    members_truncated = True
                    pagination_complete = False
                    pagination_errors.append("member follow limit was reached")
                    break

                next_link = current_page.get(
                    "Members@odata.nextLink"
                ) or current_page.get("@odata.nextLink")
                if not next_link:
                    break
                if len(members) >= self.MAX_DISCOVERY_MEMBERS:
                    members_truncated = True
                    pagination_complete = False
                    pagination_errors.append(
                        "member follow limit was reached before the next page"
                    )
                    break

                try:
                    next_page_uri = self._normalize_collection_link(
                        dut_id,
                        next_link,
                        context=f"{resource_type.value} Members nextLink",
                        hmc=collection_hmc,
                    )
                    next_page_parts = urlsplit(next_page_uri)
                    if unquote(next_page_parts.path) != collection_path:
                        raise RedfishTopologyProfileError(
                            "nextLink escaped its collection"
                        )
                    canonical_page_uri = unquote(next_page_parts.path) + (
                        f"?{next_page_parts.query}" if next_page_parts.query else ""
                    )
                    if canonical_page_uri in seen_page_uris:
                        raise RedfishTopologyProfileError("nextLink repeated a page")
                except (RedfishTopologyProfileError, TypeError, ValueError) as error:
                    pagination_complete = False
                    pagination_errors.append(str(error))
                    break

                elapsed = time.monotonic() - discovery_started
                if request_count >= self.MAX_DISCOVERY_PAGE_REQUESTS:
                    pagination_complete = False
                    pagination_errors.append("pagination request budget was exhausted")
                    break
                if elapsed >= self.DISCOVERY_DEADLINE_SECONDS:
                    pagination_complete = False
                    pagination_errors.append("pagination deadline was exceeded")
                    break

                seen_page_uris.add(canonical_page_uri)
                request_count += 1
                page_success, page_payload, _, _ = (
                    await self.dut_manager.execute_redfish_request(
                        dut_id,
                        "GET",
                        next_page_uri,
                        timeout=max(
                            1,
                            min(
                                10,
                                int(self.DISCOVERY_DEADLINE_SECONDS - elapsed),
                            ),
                        ),
                    )
                )
                if not isinstance(page_payload, dict):
                    pagination_complete = False
                    pagination_errors.append("next page was not a JSON object")
                    break
                if not page_success:
                    pagination_complete = False
                    pagination_errors.append("next page request was unsuccessful")
                current_page = page_payload

            raw_advertised_count = collection.get("Members@odata.count")
            advertised_count_valid = raw_advertised_count is None or (
                type(raw_advertised_count) is int and raw_advertised_count >= 0
            )
            advertised_member_count = (
                raw_advertised_count if advertised_count_valid else None
            )
            advertised_count_mismatch = bool(
                raw_advertised_count is not None
                and (
                    not advertised_count_valid
                    or raw_advertised_count != source_member_count
                )
            )
            if advertised_count_mismatch:
                pagination_complete = False
                pagination_errors.append(
                    "Members@odata.count did not match the observed member count"
                )
            if members_truncated:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "DynamicDiscovery",
                    f"_discover_resource: limiting {resource_type.value} members "
                    f"from {source_member_count} to {self.MAX_DISCOVERY_MEMBERS}",
                )
            member_ids = []
            member_details = {}
            rejected_member_count = 0
            duplicate_member_count = 0
            seen_member_ids = set()
            is_singleton_service = len(members) == 0

            # Log the type of resource discovered
            if is_singleton_service:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"_discover_resource: discovered singleton service {resource_type.value} (no Members array)",
                )
            else:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"_discover_resource: processing {len(members)} members for {resource_type.value} collection",
                )

            # Handle singleton services (no Members array)
            if is_singleton_service:
                # For singleton services, treat the service itself as the "member"
                service_id = collection.get("Id", resource_type.value)
                member_ids = [service_id]
                member_details = {service_id: collection}

                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"_discover_resource: treating singleton service {resource_type.value} as member with ID: {service_id}",
                )

                # Log service capabilities and important metadata
                service_enabled = collection.get("ServiceEnabled", "unknown")
                service_status = collection.get("Status", {})
                service_state = service_status.get("State", "unknown")
                service_health = service_status.get("Health", "unknown")

                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"_discover_resource: singleton service {resource_type.value} - Enabled: {service_enabled}, State: {service_state}, Health: {service_health}",
                )

                # Log important sub-resource URIs for singleton services
                sub_resources = []
                for key, value in collection.items():
                    if isinstance(value, dict) and "@odata.id" in value:
                        sub_resources.append(f"{key}: {value['@odata.id']}")

                if sub_resources:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DynamicDiscovery",
                        f"_discover_resource: singleton service {resource_type.value} sub-resources: {', '.join(sub_resources)}",
                    )
            else:
                # Handle collection resources (with Members array)
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"_discover_resource: processing collection {resource_type.value} with {len(members)} members",
                )

            # Process each member (for collections) or handle singleton special cases
            for member in members:
                member_uri = (
                    member.get("@odata.id") if isinstance(member, dict) else None
                )
                if not member_uri:
                    rejected_member_count += 1
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "DynamicDiscovery",
                        f"_discover_resource: member missing @odata.id: {member}",
                    )
                    continue

                try:
                    request_member_uri = member_uri
                    member_uri = self._normalize_collection_link(
                        dut_id,
                        member_uri,
                        context=f"{resource_type.value} member URI",
                        hmc=collection_hmc,
                    )
                    member_uri = validate_redfish_uri_path(
                        member_uri,
                        context=f"{resource_type.value} member URI",
                        service_root=collection_path,
                    )
                except (RedfishTopologyProfileError, TypeError, ValueError):
                    rejected_member_count += 1
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "DynamicDiscovery",
                        f"_discover_resource: rejected invalid {resource_type.value} member URI",
                    )
                    continue

                if collection_hmc:
                    request_member_uri = member_uri

                # The path validator proves that decoding cannot introduce a
                # separator or traversal segment. Decode safe aliases before
                # deduplication so ``System_0`` and ``%53ystem_0`` cannot cause
                # repeated detail requests or state-changing work downstream.
                member_uri = unquote(member_uri)
                member_id = member_uri.rsplit("/", 1)[-1]
                if member_id in seen_member_ids:
                    duplicate_member_count += 1
                    continue
                seen_member_ids.add(member_id)
                member_ids.append(member_id)

                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"_discover_resource: processed collection member {member_id} from {member_uri}",
                )

                # Get detailed information for the member
                if self.config.verbose_logging:
                    detail_success, detail_data, _, _ = (
                        await self.dut_manager.execute_redfish_request(
                            dut_id, "GET", request_member_uri, timeout=10
                        )
                    )
                    if detail_success and detail_data:
                        member_details[member_id] = detail_data

                # Apply type filtering for managers
                if resource_type == ResourceType.MANAGERS and self.config.manager_types:
                    if self.config.verbose_logging and member_id in member_details:
                        manager_type = member_details[member_id].get("ManagerType")
                        if (
                            manager_type
                            and manager_type not in self.config.manager_types
                        ):
                            member_ids.remove(member_id)
                            if member_id in member_details:
                                del member_details[member_id]

            # Special handling for UpdateService - discover firmware inventory (if enabled)
            # Fixed: This now works for both singleton and collection services
            if (
                resource_type == ResourceType.UPDATE_SERVICE
                and self.config.discover_firmware_inventory
            ):
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"_discover_resource: discovering firmware inventory for UpdateService (singleton: {is_singleton_service})",
                )
                try:
                    firmware_inventory = await self._discover_firmware_inventory(
                        dut_id, uri
                    )
                    if firmware_inventory:
                        # For singleton services, add to the service details
                        if is_singleton_service:
                            service_id = (
                                member_ids[0] if member_ids else "UpdateService"
                            )
                            member_details[service_id][
                                "firmware_inventory"
                            ] = firmware_inventory
                        else:
                            member_details["firmware_inventory"] = firmware_inventory

                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DynamicDiscovery",
                            f"_discover_resource: discovered firmware inventory with {len(firmware_inventory.get('Members', []))} components",
                        )
                    else:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARN",
                            "DynamicDiscovery",
                            "_discover_resource: firmware inventory discovery returned None for UpdateService",
                        )
                except Exception as fw_error:
                    import traceback

                    error_traceback = self._sanitize_diagnostic(
                        "_discover_resource: firmware inventory discovery failed: "
                        f"{fw_error}\nTraceback:\n{traceback.format_exc()}"
                    )
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "DynamicDiscovery",
                        error_traceback,
                    )
            elif (
                resource_type == ResourceType.UPDATE_SERVICE
                and not self.config.discover_firmware_inventory
            ):
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    "_discover_resource: skipping firmware inventory discovery for UpdateService (disabled in config)",
                )

            discovery_complete = bool(
                pagination_complete
                and not members_truncated
                and not advertised_count_mismatch
                and rejected_member_count == 0
                and duplicate_member_count == 0
            )
            if rejected_member_count:
                pagination_errors.append(
                    f"{rejected_member_count} collection members were rejected"
                )
            if duplicate_member_count:
                pagination_errors.append(
                    f"{duplicate_member_count} duplicate collection members were ignored"
                )

            # Cache the results and their completeness as one snapshot. Bare
            # member lists remain available for compatibility, while safety-
            # sensitive consumers use get_resource_member_snapshot().
            cache_key = f"{dut_id}_{resource_type.value}"
            self._resource_members[cache_key] = member_ids
            resource_metadata = {
                "complete": discovery_complete,
                "partial": not discovery_complete,
                "truncated": members_truncated,
                "pagination_complete": pagination_complete,
                "source_member_count": source_member_count,
                "advertised_member_count": advertised_member_count,
                "advertised_count_mismatch": advertised_count_mismatch,
                "member_limit": self.MAX_DISCOVERY_MEMBERS,
                "page_count": page_count,
                "request_count": request_count,
                "rejected_member_count": rejected_member_count,
                "duplicate_member_count": duplicate_member_count,
                "incomplete_reasons": list(dict.fromkeys(pagination_errors)),
            }
            self._resource_metadata[cache_key] = resource_metadata
            if member_details:
                self._resource_details[cache_key] = member_details

            # Log what was discovered and cached with improved messaging
            if is_singleton_service:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DynamicDiscovery",
                    f"Discovered singleton service {resource_type.value}: {member_ids[0] if member_ids else 'unknown'} (service metadata preserved)",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"Cached singleton service {resource_type.value} with key '{cache_key}': {member_ids}",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"Cached singleton service {resource_type.value} details with key '{cache_key}': {len(member_details)} detail entries (includes service metadata)",
                )
            else:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DynamicDiscovery",
                    f"Discovered {len(member_ids)} {resource_type.value} collection members: {member_ids}",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"Cached {resource_type.value} collection members with key '{cache_key}': {member_ids}",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"Cached {resource_type.value} collection details with key '{cache_key}': {len(member_details)} detail entries",
                )

            return {
                "success": True,
                "members": member_ids,
                "member_details": member_details,
                "total_count": len(member_ids),
                **resource_metadata,
            }

        except Exception as e:
            import traceback

            error_details = self._sanitize_diagnostic(
                f"Failed to discover {resource_type.value}: {e}\n"
                f"Traceback:\n{traceback.format_exc()}"
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DynamicDiscovery",
                error_details,
            )
            return self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[error_details],
                operation_name=f"discover_{resource_type.value}",
                additional_context={
                    "resource_type": resource_type.value,
                    "error_traceback": error_details,
                },
                dut_id=dut_id,
                collector_id=f"dynamic_discovery_{resource_type.value}",
            )

    async def _discover_firmware_inventory(
        self, dut_id: str, update_service_uri: str
    ) -> Optional[Dict[str, Any]]:
        """
        Discover firmware inventory from UpdateService.

        ``update_service_uri`` remains in the signature for compatibility with
        the discovery callback. Candidate paths are resolved from catalog
        resources instead of being constructed from this value.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            update_service_uri: Validated remote resource identifier used for
                update service URI.

        Returns:
            A mapping containing the ``uri``, ``total_components``,
            ``components``, ``inventory_data``, and ``partial`` fields.
        """
        try:
            # ``update_service_uri`` remains in the signature for compatibility
            # with the discovery callback. Candidate paths are resolved from
            # catalog resources instead of being constructed from this value.
            del update_service_uri
            dut_config = self.dut_manager.get_dut_config(dut_id) or {}
            baseboard = dut_config.get("baseboard")
            platform = dut_config.get("platform")
            legacy_uri = dut_config.get("firmware_inventory_uri")

            def iter_candidate_uris():
                """
                Yield candidate firmware-inventory URIs in selection order.

                The implementation uses current instance state to yield
                candidate firmware-inventory URIs in selection order.

                Yields:
                    Each candidate URIs admitted by the operation, in
                    deterministic iteration order.
                """
                seen_uris = set()
                if legacy_uri is not None:
                    normalized_legacy_uri = validate_redfish_uri_path(
                        legacy_uri,
                        context="DUT firmware_inventory_uri",
                    )
                    seen_uris.add(normalized_legacy_uri)
                    yield "DUT firmware_inventory_uri", normalized_legacy_uri

                for resource_type in self._get_firmware_inventory_resource_types():
                    candidate_uri = self.uri_config_manager.get_uri(
                        dut_id,
                        resource_type,
                        baseboard,
                        platform,
                    )
                    normalized_candidate_uri = validate_redfish_uri_path(
                        candidate_uri,
                        context=f"Catalog {resource_type.value} URI",
                    )
                    if normalized_candidate_uri not in seen_uris:
                        seen_uris.add(normalized_candidate_uri)
                        yield (
                            f"catalog {resource_type.value}",
                            normalized_candidate_uri,
                        )

            firmware_inventory = None
            firmware_inventory_uri = None
            for candidate_source, candidate_uri in iter_candidate_uris():
                success, inventory, _, _ = (
                    await self.dut_manager.execute_redfish_request(
                        dut_id, "GET", candidate_uri
                    )
                )
                if success and inventory:
                    firmware_inventory = inventory
                    firmware_inventory_uri = candidate_uri
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "DynamicDiscovery",
                        "Using firmware inventory URI from "
                        f"{candidate_source}: {candidate_uri}",
                    )
                    break

                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "DynamicDiscovery",
                    f"Firmware inventory URI failed ({candidate_source}): "
                    f"{candidate_uri}",
                )

            if firmware_inventory is None or firmware_inventory_uri is None:
                return None

            if firmware_inventory:
                try:
                    members, source_member_count, members_truncated = (
                        bound_redfish_collection_members(
                            firmware_inventory.get("Members", []),
                            field_name="FirmwareInventory Members",
                            limit=self.MAX_DISCOVERY_MEMBERS,
                        )
                    )
                except ValueError:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "DynamicDiscovery",
                        "Firmware inventory returned an invalid Members collection",
                    )
                    return None
                if not members:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "DynamicDiscovery",
                        "Firmware inventory returned no members",
                    )
                    return None
                if members_truncated:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DynamicDiscovery",
                        "Firmware inventory member walk was truncated from "
                        f"{source_member_count} to {self.MAX_DISCOVERY_MEMBERS}",
                    )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DynamicDiscovery",
                    f"Discovered firmware inventory with {len(members)} components",
                )

                # Get detailed information for each firmware component
                firmware_details = {}
                rejected_members = 0

                for member in members:
                    member_uri = (
                        member.get("@odata.id") if isinstance(member, dict) else None
                    )
                    if not member_uri:
                        rejected_members += 1
                        continue

                    try:
                        member_uri = validate_redfish_uri_path(
                            member_uri,
                            context="FirmwareInventory member URI",
                            service_root=firmware_inventory_uri,
                        )
                    except (RedfishTopologyProfileError, TypeError, ValueError):
                        rejected_members += 1
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARN",
                            "DynamicDiscovery",
                            "Rejected invalid firmware inventory member URI",
                        )
                        continue

                    # Extract component ID from URI
                    component_id = member_uri.split("/")[-1]

                    # Get detailed firmware information
                    detail_success, detail_data, _, _ = (
                        await self.dut_manager.execute_redfish_request(
                            dut_id, "GET", member_uri
                        )
                    )
                    if detail_success and detail_data:
                        firmware_details[component_id] = detail_data

                return {
                    "uri": firmware_inventory_uri,
                    "total_components": len(members),
                    "components": firmware_details,
                    "inventory_data": firmware_inventory,
                    "partial": members_truncated or rejected_members > 0,
                    "truncated": members_truncated,
                    "source_member_count": source_member_count,
                    "member_limit": self.MAX_DISCOVERY_MEMBERS,
                    "rejected_member_count": rejected_members,
                }

            return None

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARN",
                "DynamicDiscovery",
                f"Failed to discover firmware inventory: {str(e)}",
            )
            return None

    async def get_resource_members(self, dut_id: str, resource_type: str) -> List[str]:
        """
        Get cached resource members for a specific resource type.

        Log what's being retrieved from cache using async logging.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            resource_type: Text supplied as resource type in the format accepted
                by this function.

        Returns:
            The validated ``members``.
        """
        cache_key = f"{dut_id}_{resource_type}"
        members = self._resource_members.get(cache_key, [])

        # Log what's being retrieved from cache using async logging
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "DynamicDiscovery",
            f"get_resource_members: cache_key='{cache_key}', found {len(members)} members: {members}",
        )

        return members

    async def get_resource_member_snapshot(
        self, dut_id: str, resource_type: str
    ) -> Dict[str, Any]:
        """
        Return cached members together with completeness metadata.

        State-changing consumers must not infer completeness from a bounded
        list. An absent metadata record is deliberately incomplete.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            resource_type: Text supplied as resource type in the format accepted
                by this function.

        Returns:
            The validated ``snapshot``.
        """

        cache_key = f"{dut_id}_{resource_type}"
        members = list(self._resource_members.get(cache_key, []))
        metadata = dict(self._resource_metadata.get(cache_key, {}))
        snapshot = {
            "members": members,
            "complete": bool(metadata.get("complete", False)),
            "partial": not bool(metadata.get("complete", False)),
            **metadata,
        }
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "DynamicDiscovery",
            (
                f"get_resource_member_snapshot: cache_key='{cache_key}', "
                f"members={len(members)}, complete={snapshot['complete']}"
            ),
        )
        return snapshot

    async def get_resource_details(
        self, dut_id: str, resource_type: str
    ) -> Dict[str, Any]:
        """
        Get cached resource details for a specific resource type.

        Log what's being retrieved from cache using async logging.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            resource_type: Text supplied as resource type in the format accepted
                by this function.

        Returns:
            The validated ``details``.
        """
        cache_key = f"{dut_id}_{resource_type}"
        details = self._resource_details.get(cache_key, {})

        # Log what's being retrieved from cache using async logging
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "DynamicDiscovery",
            f"get_resource_details: cache_key='{cache_key}', found {len(details)} detail entries",
        )

        return details

    async def get_discovery_results(self, dut_id: str) -> Optional[Dict[str, Any]]:
        """
        Get cached discovery results for a DUT.

        Log what's being retrieved from cache using async logging.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``results``, or ``None`` when no value qualifies.
        """
        cache_key = f"{dut_id}_discovery"
        results = self._discovery_cache.get(cache_key)

        # Log what's being retrieved from cache using async logging
        if results:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DynamicDiscovery",
                f"get_discovery_results: cache_key='{cache_key}', found results with {results.get('metadata', {}).get('total_resources', 0)} total resources",
            )
        else:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DynamicDiscovery",
                f"get_discovery_results: cache_key='{cache_key}', no results found",
            )

        return results

    async def get_firmware_inventory(self, dut_id: str) -> Optional[Dict[str, Any]]:
        """
        Get cached firmware inventory for a DUT.

        The implementation uses ``dut_id`` to get cached firmware inventory for
        a DUT. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``firmware_inventory``, or ``None`` when no value
            qualifies.
        """
        cache_key = f"{dut_id}_UpdateService"
        update_service_details = self._resource_details.get(cache_key, {})

        # Firmware inventory can be stored in two ways:
        # 1. Directly as update_service_details["firmware_inventory"] (old way)
        # 2. Nested under a service ID for singleton services (new way)
        firmware_inventory = update_service_details.get("firmware_inventory")

        # If not found at top level, try looking in nested service IDs
        if not firmware_inventory:
            # For singleton services, firmware inventory is stored under the service ID
            for service_id, service_details in update_service_details.items():
                if (
                    isinstance(service_details, dict)
                    and "firmware_inventory" in service_details
                ):
                    firmware_inventory = service_details["firmware_inventory"]
                    break

        # Log what's being retrieved from cache using async logging
        if firmware_inventory:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DynamicDiscovery",
                f"get_firmware_inventory: cache_key='{cache_key}', found firmware inventory with {len(firmware_inventory) if firmware_inventory and isinstance(firmware_inventory, dict) else 0} components",
            )
        else:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DynamicDiscovery",
                f"get_firmware_inventory: cache_key='{cache_key}', no firmware inventory found in cache. Cache contents: {list(update_service_details.keys())}",
            )

        return firmware_inventory

    async def clear_cache(self, dut_id: Optional[str] = None) -> None:
        """
        Clear discovery cache.

        The implementation uses ``dut_id`` to clear discovery cache. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        if dut_id:
            # Clear specific DUT cache
            cache_key = f"{dut_id}_discovery"
            if cache_key in self._discovery_cache:
                del self._discovery_cache[cache_key]
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"clear_cache: cleared discovery cache for DUT '{dut_id}'",
                )

            # Clear resource members and details for this DUT
            keys_to_remove = [
                f"{dut_id}_{resource_type.value}"
                for resource_type in ResourceType
                if f"{dut_id}_{resource_type.value}" in self._resource_members
            ]
            for key in keys_to_remove:
                del self._resource_members[key]
                if key in self._resource_details:
                    del self._resource_details[key]
                self._resource_metadata.pop(key, None)

            if keys_to_remove:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"clear_cache: cleared {len(keys_to_remove)} resource cache entries for DUT '{dut_id}'",
                )
        else:
            # Clear all cache
            discovery_cache_size = len(self._discovery_cache)
            resource_members_size = len(self._resource_members)
            resource_details_size = len(self._resource_details)
            resource_metadata_size = len(self._resource_metadata)

            self._discovery_cache.clear()
            self._resource_members.clear()
            self._resource_details.clear()
            self._resource_metadata.clear()

            await self.logger.write_to_dut_runtime_log(
                "system",
                "DEBUG",
                "DynamicDiscovery",
                f"clear_cache: cleared all cache - discovery: {discovery_cache_size}, members: {resource_members_size}, details: {resource_details_size}, metadata: {resource_metadata_size}",
            )

    async def get_cache_stats(self, dut_id: str = "system") -> Dict[str, Any]:
        """
        Get cache statistics.

        The implementation uses ``dut_id`` to get cache statistics. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``stats``.
        """
        stats = {
            "discovery_cache_size": len(self._discovery_cache),
            "resource_members_cache_size": len(self._resource_members),
            "resource_details_cache_size": len(self._resource_details),
            "resource_metadata_cache_size": len(self._resource_metadata),
            "cached_duts": list(
                set([k.split("_")[0] for k in self._resource_members.keys()])
            ),
        }

        # Log cache statistics using async logging
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "DynamicDiscovery",
            f"get_cache_stats: discovery_cache={stats['discovery_cache_size']}, members_cache={stats['resource_members_cache_size']}, details_cache={stats['resource_details_cache_size']}, cached_duts={stats['cached_duts']}",
        )

        return stats
