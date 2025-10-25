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
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..utils.enums import ResourceType
from ..utils.uri_config_manager import URIConfigManager

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryConfig:
    """
    Configuration for dynamic discovery.
    """

    # Core Redfish endpoints to discover
    core_endpoints: List[ResourceType] = field(
        default_factory=lambda: [
            ResourceType.SYSTEMS,
            ResourceType.CHASSIS,
            ResourceType.MANAGERS,
            ResourceType.UPDATE_SERVICE,
        ]
    )

    # Optional endpoints to discover
    optional_endpoints: List[ResourceType] = field(
        default_factory=lambda: [
            ResourceType.TASK_SERVICE,
            ResourceType.EVENT_SERVICE,
            ResourceType.SESSION_SERVICE,
            ResourceType.ACCOUNT_SERVICE,
        ]
    )

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

    # Whether to discover firmware inventory (can be very slow with 60+ members)
    discover_firmware_inventory: bool = False


class DynamicDiscoveryService:
    """
    Service for discovering and caching Redfish endpoints dynamically.

    This service discovers available Redfish resources and caches them in memory
    for use by collectors. It implements the same functionality as the legacy
    base_collector.py but natively without external dependencies.
    """

    def __init__(
        self, dut_manager, logger, uri_config_manager: Optional[URIConfigManager] = None
    ):
        """
        Initialize the Dynamic Discovery service.

        Args:
            dut_manager: DUT manager instance.
            logger: Logger instance.
            uri_config_manager: URI config manager instance.
        """
        self.dut_manager = dut_manager
        self.logger = logger
        self.config = DiscoveryConfig()
        self.uri_config_manager = uri_config_manager

        # Cache for discovered resources
        self._discovery_cache: Dict[str, Any] = {}
        self._resource_members: Dict[str, List[str]] = {}
        self._resource_details: Dict[str, Dict[str, Any]] = {}

        # Core resource mappings (will be populated dynamically using URI config manager)
        self._resource_uris = {}

    def set_config(self, config: DiscoveryConfig) -> None:
        """
        Set discovery configuration.

        Args:
            config: Discovery configuration.
        """
        self.config = config

    def _get_resource_uri(self, dut_id: str, resource_type: ResourceType) -> str:
        """
        Get URI for a resource type using URI config manager or fallback.

        Args:
            dut_id: DUT ID.
            resource_type: Resource type.
        """
        if self.uri_config_manager:
            return self.uri_config_manager.get_uri(dut_id, resource_type)
        else:
            # Fallback to hardcoded URI if no URI config manager
            return f"/redfish/v1/{resource_type.value}"

    def _create_standardized_collector_result(
        self,
        successful_operations: int = 0,
        total_operations: int = 0,
        output_files: List[str] = None,
        error_messages: List[str] = None,
        operation_name: str = "dynamic_discovery",
        additional_context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Create a standardized collector result dictionary.

        This method provides a consistent result format for all collector operations.

        Args:
            successful_operations: Number of successful operations
            total_operations: Total number of operations attempted
            output_files: List of output file paths
            error_messages: List of error messages
            operation_name: Name of the operation performed
            additional_context: Additional context information

        Returns:
            Standardized result dictionary
        """
        if output_files is None:
            output_files = []
        if error_messages is None:
            error_messages = []
        if additional_context is None:
            additional_context = {}

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

        Args:
            dut_id: The DUT identifier
            preflight_results: Optional preflight results to check Redfish status

        Returns:
            dict: Discovery results with resource members and metadata
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
                    error_messages=["Redfish preflight failed"],
                    operation_name="dynamic_discovery",
                    additional_context={},
                )

        discovery_results = {
            "success": True,
            "dut_id": dut_id,
            "discovered_resources": {},
            "raw_response_data": {},
            "metadata": {
                "discovery_timestamp": None,
                "total_resources": 0,
                "cache_enabled": self.config.cache_enabled,
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

                Args:
                    category: Category of the resource.
                    resource_type: Resource type.
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
                if isinstance(result_item, Exception):
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "DynamicDiscovery",
                        f"Discovery task failed with exception: {str(result_item)}",
                    )
                    continue

                category, resource_type, result = result_item

                if result["success"]:
                    discovery_results["discovered_resources"][resource_type.value] = {
                        "success": True,
                        "members": result["members"],
                        "total_count": result.get(
                            "total_count", len(result["members"])
                        ),
                    }
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
            await self.logger.write_to_dut_runtime_log(
                dut_id, "ERROR", "DynamicDiscovery", f"Discovery failed: {str(e)}"
            )
            return self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="dynamic_discovery",
                additional_context={},
                dut_id=dut_id,
                collector_id="dynamic_discovery",
            )

    async def _discover_resource(
        self, dut_id: str, resource_type: ResourceType
    ) -> Dict[str, Any]:
        """
        Discover a specific Redfish resource type.

        Args:
            dut_id: The DUT identifier
            resource_type: The resource type to discover

        Returns:
            dict: Discovery result with members and metadata
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
            # Get the resource collection
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DynamicDiscovery",
                f"_discover_resource: making Redfish request GET {uri}",
            )

            success, collection, _, _ = await self.dut_manager.execute_redfish_request(
                dut_id, "GET", uri, timeout=10
            )

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DynamicDiscovery",
                f"_discover_resource: Redfish request result - success={success}, collection_keys={list(collection.keys()) if collection else 'None'}",
            )

            if not success or not collection:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DynamicDiscovery",
                    f"_discover_resource: failed to get {resource_type.value} collection from {uri}",
                )
                return {
                    "success": False,
                    "error": f"Failed to get {resource_type.value} collection",
                }

            members = collection.get("Members", [])
            member_ids = []
            member_details = {}
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
                member_uri = member.get("@odata.id")
                if not member_uri:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "DynamicDiscovery",
                        f"_discover_resource: member missing @odata.id: {member}",
                    )
                    continue

                # Extract member ID from URI
                member_id = member_uri.split("/")[-1]
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
                            dut_id, "GET", member_uri, timeout=10
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
                firmware_inventory = await self._discover_firmware_inventory(
                    dut_id, uri
                )
                if firmware_inventory:
                    # For singleton services, add to the service details
                    if is_singleton_service:
                        service_id = member_ids[0] if member_ids else "UpdateService"
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
            elif (
                resource_type == ResourceType.UPDATE_SERVICE
                and not self.config.discover_firmware_inventory
            ):
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DynamicDiscovery",
                    f"_discover_resource: skipping firmware inventory discovery for UpdateService (disabled in config)",
                )

            # Cache the results
            cache_key = f"{dut_id}_{resource_type.value}"
            self._resource_members[cache_key] = member_ids
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
            }

        except Exception as e:
            return self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="dynamic_discovery",
                additional_context={},
                dut_id=dut_id,
                collector_id="dynamic_discovery",
            )

    async def _discover_firmware_inventory(
        self, dut_id: str, update_service_uri: str
    ) -> Optional[Dict[str, Any]]:
        """
        Discover firmware inventory from UpdateService.

        Args:
            dut_id: The DUT identifier
            update_service_uri: The UpdateService URI

        Returns:
            dict: Firmware inventory data or None if not available
        """
        try:
            # Get firmware inventory URI from config manager if available
            if self.uri_config_manager:
                dut_config = self.dut_manager.get_dut_config(dut_id)
                baseboard = dut_config.get("baseboard")
                platform = dut_config.get("platform")

                firmware_uri = self.uri_config_manager.get_uri(
                    dut_id, "firmware_inventory", baseboard, platform
                )
            else:
                # Fallback to DUT config or default
                dut_config = self.dut_manager.get_dut_config(dut_id)
                firmware_uri = dut_config.get(
                    "firmware_inventory_uri", f"{update_service_uri}/FirmwareInventory"
                )

            # Try the configured firmware inventory URI
            success, firmware_inventory, _, _ = (
                await self.dut_manager.execute_redfish_request(
                    dut_id, "GET", firmware_uri
                )
            )

            if success and firmware_inventory:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DynamicDiscovery",
                    f"Using configured firmware inventory URI: {firmware_uri}",
                )
            else:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "DynamicDiscovery",
                    f"Configured firmware inventory URI failed: {firmware_uri}",
                )
                firmware_inventory = None

            # If no custom URI or custom URI failed, try standard URIs
            if not firmware_inventory:
                # Standard firmware inventory URI
                firmware_inventory_uri = f"{update_service_uri}/FirmwareInventory"

                success, firmware_inventory, _, _ = (
                    await self.dut_manager.execute_redfish_request(
                        dut_id, "GET", firmware_inventory_uri
                    )
                )

                if not success or not firmware_inventory:
                    # Try alternative URI patterns
                    alternative_uris = [
                        f"{update_service_uri}/SoftwareInventory",
                        f"{update_service_uri}/Inventory",
                        f"{update_service_uri}/Firmware",
                    ]

                    for alt_uri in alternative_uris:
                        success, inventory, _, _ = (
                            await self.dut_manager.execute_redfish_request(
                                dut_id, "GET", alt_uri
                            )
                        )
                        if success and inventory:
                            firmware_inventory = inventory
                            firmware_inventory_uri = alt_uri
                            break
                else:
                    firmware_inventory_uri = f"{update_service_uri}/FirmwareInventory"

            if firmware_inventory:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DynamicDiscovery",
                    f"Discovered firmware inventory with {len(firmware_inventory.get('Members', []))} components",
                )

                # Get detailed information for each firmware component
                firmware_details = {}
                members = firmware_inventory.get("Members", [])

                for member in members:
                    member_uri = member.get("@odata.id")
                    if not member_uri:
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

        Args:
            dut_id: The DUT identifier
            resource_type: The resource type (e.g., "Systems", "Chassis", "Managers")

        Returns:
            list: List of resource member IDs
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

    async def get_resource_details(
        self, dut_id: str, resource_type: str
    ) -> Dict[str, Any]:
        """
        Get cached resource details for a specific resource type.

        Args:
            dut_id: The DUT identifier
            resource_type: The resource type

        Returns:
            dict: Resource details by member ID
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

        Args:
            dut_id: The DUT identifier

        Returns:
            dict: Cached discovery results or None if not found
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

        Args:
            dut_id: The DUT identifier

        Returns:
            dict: Firmware inventory data or None if not found
        """
        cache_key = f"{dut_id}_UpdateService"
        update_service_details = self._resource_details.get(cache_key, {})
        firmware_inventory = update_service_details.get("firmware_inventory")

        # Log what's being retrieved from cache using async logging
        if firmware_inventory:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DynamicDiscovery",
                f"get_firmware_inventory: cache_key='{cache_key}', found firmware inventory with {firmware_inventory.get('total_components', 0)} components",
            )
        else:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DynamicDiscovery",
                f"get_firmware_inventory: cache_key='{cache_key}', no firmware inventory found",
            )

        return firmware_inventory

    async def clear_cache(self, dut_id: Optional[str] = None) -> None:
        """
        Clear discovery cache.

        Args:
            dut_id: Optional DUT ID to clear specific cache, or None to clear all
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
                k for k in self._resource_members.keys() if k.startswith(f"{dut_id}_")
            ]
            for key in keys_to_remove:
                del self._resource_members[key]
                if key in self._resource_details:
                    del self._resource_details[key]

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

            self._discovery_cache.clear()
            self._resource_members.clear()
            self._resource_details.clear()

            await self.logger.write_to_dut_runtime_log(
                "system",
                "DEBUG",
                "DynamicDiscovery",
                f"clear_cache: cleared all cache - discovery: {discovery_cache_size}, members: {resource_members_size}, details: {resource_details_size}",
            )

    async def get_cache_stats(self, dut_id: str = "system") -> Dict[str, Any]:
        """
        Get cache statistics.

        Args:
            dut_id: DUT ID for logging purposes (defaults to "system")

        Returns:
            dict: Cache statistics
        """
        stats = {
            "discovery_cache_size": len(self._discovery_cache),
            "resource_members_cache_size": len(self._resource_members),
            "resource_details_cache_size": len(self._resource_details),
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
