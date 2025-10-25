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
Redfish Service - Handles all Redfish-related collector operations.

Provides comprehensive Redfish API collectors for BMC access including resource
enumeration, telemetry collection, and system management data via REST API.
"""

import asyncio
import json
import logging
import os
import random
import re
import time
import traceback
from asyncio import Semaphore
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from tabulate import tabulate

from ..utils.enums import ENTITY_URI_TO_PLACEHOLDER
from ..utils.id_filtering import filter_ids, log_filtered_ids, should_skip_id
from ..utils.temp_dir_config import create_temp_directory, get_bmc_temp_dir
from ..utils.timeout_config import (
    get_collector_sleep_duration,
    get_collector_timeout,
    get_expand_level,
    get_nvos_tech_dump_timeout,
)
from .base_service import BaseService

logger = logging.getLogger(__name__)


class RedfishService(BaseService):
    """
    Service for Redfish operations

    This service is organized into logical sections:
    1. Helper Methods
    2. Handles
    3. Collector Public API
    """

    # Configuration for concurrent processing
    DEFAULT_MAX_CONCURRENT_ENTITIES = 10  # Per-DUT limit (was global, now per-DUT)
    DEFAULT_MAX_CONCURRENT_REQUESTS = 10  # Per-DUT limit (was global, now per-DUT)
    DEFAULT_MAX_CONCURRENT_DUMPS = 3  # Per-DUT limit (was global, now per-DUT)

    def __init__(self, service_name: str, orchestrator: Any) -> None:
        """
        Initialize Redfish service.

        Args:
            service_name: Name of the service.
            orchestrator: Orchestrator instance.
        """
        super().__init__(service_name, orchestrator)

        # Per-DUT semaphores for limiting concurrent operations
        self._dut_semaphores = {}

    def _get_dut_semaphore(
        self, dut_id: str, semaphore_type: str = "requests"
    ) -> asyncio.Semaphore:
        """
        Get or create a semaphore for a specific DUT and operation type (thread-safe).

        Args:
            dut_id: DUT ID.
            semaphore_type: Type of semaphore.
        """
        key = f"{dut_id}_{semaphore_type}"

        # Use dict.get() with default creation - this is thread-safe for simple operations
        if key not in self._dut_semaphores:
            # Create per-DUT semaphores with appropriate limits
            if semaphore_type == "requests":
                limit = self.DEFAULT_MAX_CONCURRENT_REQUESTS
            elif semaphore_type == "entities":
                limit = self.DEFAULT_MAX_CONCURRENT_ENTITIES
            elif semaphore_type == "dumps":
                limit = self.DEFAULT_MAX_CONCURRENT_DUMPS
            else:
                limit = 3  # Default limit

            self._dut_semaphores[key] = asyncio.Semaphore(limit)

        return self._dut_semaphores[key]

    """
    Validation
    """

    async def _validate_entities_consolidated(
        self,
        dut_id: str,
        entity_type: str,
        check_hgx_prefix: bool = True,
        filter_mode: str = "hgx_only",
        baseboard_aware: bool = True,
        entity_id_patterns: List[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Consolidated entity validation method that replaces _validate_systems, _validate_managers, _validate_chassis.

        Args:
            dut_id: Device under test ID
            entity_type: Type of entity ("Systems", "Managers", "Chassis")
            check_hgx_prefix: Whether to check for HGX prefix in entity names
            filter_mode: Filtering mode - "hgx_only", "all_platforms", or "non_hgx_only"
            baseboard_aware: Whether to apply baseboard-specific filtering logic
            entity_id_patterns: List of entity ID patterns to include
        """
        # Get collector context for better logging
        collector_id = kwargs.get("collector_id", "unknown")

        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"[{collector_id}] Starting {entity_type} validation with patterns: {entity_id_patterns or 'default'}",
            dut_id,
        )

        # Check if we should use pattern-based filtering or traditional filtering
        baseboard_patterns = kwargs.get("baseboard_patterns", {})

        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"[{collector_id}] Validation config: entity_id_patterns={entity_id_patterns}, baseboard_patterns={baseboard_patterns}",
            dut_id,
        )

        if entity_id_patterns or baseboard_patterns:
            # Use the new pattern-based filtering system
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"[{collector_id}] Resolving patterns for baseboard: entity_type={entity_type}, default_patterns={entity_id_patterns}, baseboard_patterns={baseboard_patterns}",
                dut_id,
            )

            patterns_to_use = await self._resolve_patterns_for_baseboard(
                dut_id=dut_id,
                entity_type=entity_type,
                default_patterns=entity_id_patterns,
                baseboard_patterns=baseboard_patterns,
                collector_id=collector_id,
                baseboard=kwargs.get("baseboard", "default"),
                baseboard_manager=kwargs.get("baseboard_manager"),
            )

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"[{collector_id}] Resolved patterns: {patterns_to_use}",
                dut_id,
            )

            # Remove collector_id from kwargs to avoid duplicate argument error
            kwargs_without_collector = {
                k: v for k, v in kwargs.items() if k != "collector_id"
            }
            return await self._validate_entities_with_patterns(
                dut_id,
                entity_type,
                patterns_to_use,
                collector_id,
                **kwargs_without_collector,
            )

        return await self._validate_entities_generic(
            dut_id,
            entity_type,
            check_hgx_prefix,
            filter_mode,
            baseboard_aware,
            **kwargs,
        )

    async def validate_connection(self, dut_id: str) -> Tuple[bool, str]:
        """
        Validate Redfish connection.

        Args:
            dut_id: DUT ID.
        """
        try:
            return await self.dut_manager.get_dut(dut_id).test_redfish_connection()
        except Exception as e:
            return False, f"Redfish connection validation failed: {str(e)}"

    async def _validate_redfish_connection(
        self, dut_id: str, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Validate Redfish connection.

        Args:
            dut_id: DUT ID.
        """
        # First check if we have preflight results
        dut = self.dut_manager.get_dut(dut_id)
        preflight_results = getattr(dut, "preflight_results", {})

        if preflight_results:
            redfish_service_result = preflight_results.get("services", {}).get(
                "redfish", {}
            )
            if redfish_service_result:
                preflight_status = redfish_service_result.get("status", "unknown")
                preflight_message = redfish_service_result.get("message", "")

                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Found preflight results for Redfish connection: status={preflight_status}, message={preflight_message}",
                    dut_id,
                )

                if preflight_status == "pass":
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Using preflight results for Redfish validation - connection already verified",
                        dut_id,
                    )
                    return {
                        "success": True,
                        "reason": f"Preflight verified: {preflight_message}",
                        "context": {
                            "redfish_available": True,
                            "preflight_used": True,
                            "successful_operations": 1,
                            "total_operations": 1,
                        },
                    }
                elif preflight_status == "fail":
                    await self._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"Preflight failed for Redfish connection: {preflight_message}",
                        dut_id,
                    )
                    return {
                        "success": False,
                        "reason": f"Preflight failed: {preflight_message}",
                        "context": {
                            "redfish_available": False,
                            "preflight_used": True,
                            "successful_operations": 0,
                            "total_operations": 1,
                        },
                    }

        # No preflight results or unknown status - run connection test
        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            "No preflight results found or unknown status - running Redfish connection test",
            dut_id,
        )

        success, message = await self.validate_connection(dut_id)

        # Log the validation result
        if success:
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Redfish connection validation passed: {message}",
                dut_id,
            )
        else:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Redfish connection validation failed: {message}",
                dut_id,
            )

        return {
            "success": success,
            "reason": message,
            "context": {
                "redfish_available": success,
                "preflight_used": False,
                "successful_operations": 1 if success else 0,
                "total_operations": 1,
            },
        }

    async def _validate_entities_generic(
        self,
        dut_id: str,
        entity_type: str,
        check_hgx_prefix: bool = True,
        filter_mode: str = "hgx_only",
        baseboard_aware: bool = True,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generic entity validation method that can be used for Systems, Managers, Chassis, etc.

        Args:
            dut_id: Device under test ID
            entity_type: Type of entity ("Systems", "Managers", "Chassis")
            check_hgx_prefix: Whether to check for HGX prefix in entity names
            filter_mode: Filtering mode - "hgx_only", "all_platforms", or "non_hgx_only"
            baseboard_aware: Whether to apply baseboard-specific filtering logic
        """
        try:
            # Log validation start
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Starting {entity_type} validation with filter_mode={filter_mode}, baseboard_aware={baseboard_aware}",
                dut_id,
            )

            # Log baseboard filtering configuration if present
            if baseboard_aware and kwargs.get("baseboard_filtering"):
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Baseboard filtering configuration: {kwargs.get('baseboard_filtering')}",
                    dut_id,
                )
            # Map entity type to discovery method and config keys
            entity_config = {
                "Systems": {
                    "discovery_method": self.get_discovered_systems,
                    "uri_key": "Systems",
                    "config_prefix": "HGX_SYSTEM_ID_PREFIX",
                    "context_key": "filtered_systems",
                    "count_key": "system_count",
                },
                "Managers": {
                    "discovery_method": self.get_discovered_managers,
                    "uri_key": "Managers",
                    "config_prefix": "HGX_MANAGER_ID_PREFIX",
                    "context_key": "filtered_managers",
                    "count_key": "manager_count",
                },
                "Chassis": {
                    "discovery_method": self.get_discovered_chassis,
                    "uri_key": "Chassis",
                    "config_prefix": "HGX_CHASSIS_ID_PREFIX",
                    "context_key": "filtered_chassis",
                    "count_key": "chassis_count",
                },
            }

            if entity_type not in entity_config:
                return {
                    "success": False,
                    "reason": f"Unsupported entity type: {entity_type}",
                    "context": {"filtered_entities": []},
                }

            config = entity_config[entity_type]

            # Try to use dynamic discovery results first
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Attempting dynamic discovery for {entity_type}",
                dut_id,
            )

            discovered_entities = await config["discovery_method"](dut_id)

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Dynamic discovery result for {entity_type}: {discovered_entities}",
                dut_id,
            )

            if discovered_entities:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using dynamic discovery results for {entity_type} validation: {discovered_entities}",
                    dut_id,
                )
                filtered_entities = []

                for entity_id in discovered_entities:
                    # Use configured URI for entity type
                    entity_uri = self.get_configured_uri(dut_id, config["uri_key"])
                    entity_uri_full = f"{entity_uri}/{entity_id}"

                    success, entity_data, _ = await self.dispatch_request(
                        dut_id, "GET", entity_uri_full, bypass_cache=True
                    )

                    if success:
                        model = entity_data.get("Model", "")
                        # Get HGX prefix from config, fallback to "HGX"
                        dut_config = self.dut_manager.get_dut_config(dut_id)
                        hgx_prefix = dut_config.get(config["config_prefix"], "HGX")
                        # Check if HGX prefix is in the entity_id (system/manager/chassis ID), not the model
                        is_hgx = hgx_prefix in entity_id

                        # Apply filtering based on filter_mode and baseboard awareness
                        include_entity = False

                        if baseboard_aware and kwargs.get("baseboard_filtering"):
                            # Get DUT config to check baseboard type
                            dut_config = self.dut_manager.get_dut_config(dut_id)
                            dut_baseboard = dut_config.get("baseboard", "")

                            # Get baseboard filtering rules from params
                            baseboard_filtering = kwargs.get("baseboard_filtering", {})

                            await self._log_runtime(
                                "DEBUG",
                                "RedfishService",
                                f"Baseboard-aware filtering: dut_baseboard='{dut_baseboard}', baseboard_filtering={baseboard_filtering}, original_filter_mode='{filter_mode}'",
                                dut_id,
                            )

                            # Use BaseboardManager to apply filtering rules
                            baseboard_manager = (
                                self.dut_manager._get_baseboard_manager()
                            )

                            # Log baseboard info for debugging
                            await baseboard_manager.log_baseboard_info(dut_id)

                            # When baseboard_aware=True, we should use the YAML configuration
                            # The BaseboardManager will handle the "default" key from baseboard_filtering
                            effective_filter_mode = await baseboard_manager.apply_baseboard_filtering(
                                dut_id,
                                dut_baseboard,
                                baseboard_filtering,
                                "all_platforms",  # This should only be used if no "default" in YAML
                            )

                            # Log baseboard detection
                            await self._log_runtime(
                                "DEBUG",
                                "RedfishService",
                                f"Entity {entity_id} (model={model}, is_hgx={is_hgx}): dut_baseboard={dut_baseboard}, effective_filter_mode={effective_filter_mode}",
                                dut_id,
                            )

                            # Apply the effective filter mode
                            if effective_filter_mode == "hgx_only":
                                include_entity = is_hgx or not check_hgx_prefix
                            elif effective_filter_mode == "all_platforms":
                                include_entity = True
                            elif effective_filter_mode == "non_hgx_only":
                                include_entity = not is_hgx
                            else:
                                # Fallback to original filter_mode
                                if filter_mode == "hgx_only":
                                    include_entity = is_hgx or not check_hgx_prefix
                                elif filter_mode == "all_platforms":
                                    include_entity = True
                                elif filter_mode == "non_hgx_only":
                                    include_entity = not is_hgx
                                else:
                                    include_entity = is_hgx or not check_hgx_prefix
                        else:
                            # Non-baseboard-aware filtering (original logic)
                            if filter_mode == "hgx_only":
                                include_entity = is_hgx or not check_hgx_prefix
                            elif filter_mode == "all_platforms":
                                include_entity = True
                            elif filter_mode == "non_hgx_only":
                                include_entity = not is_hgx
                            else:
                                # Default to hgx_only for backward compatibility
                                include_entity = is_hgx or not check_hgx_prefix

                        # Log filtering decision
                        effective_filter_mode_used = (
                            effective_filter_mode
                            if "effective_filter_mode" in locals()
                            else filter_mode
                        )
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"Entity {entity_id}: include_entity={include_entity} (effective_filter_mode='{effective_filter_mode_used}')",
                            dut_id,
                        )

                        if include_entity:
                            filtered_entities.append(
                                {
                                    "id": entity_id,
                                    "model": model,
                                    "name": entity_data.get("Name", ""),
                                    "discovery_source": "dynamic_discovery",
                                    "is_hgx": is_hgx,
                                }
                            )

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Filtered {entity_type} using mode '{filter_mode}': {len(filtered_entities)} entities found",
                    dut_id,
                )

                # Log the filtered entities
                if filtered_entities:
                    entity_ids = [entity["id"] for entity in filtered_entities]
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Filtered {entity_type} entities: {entity_ids}",
                        dut_id,
                    )

                return {
                    "success": True,
                    "context": {
                        config["context_key"]: filtered_entities,
                        config["count_key"]: len(filtered_entities),
                        "filter_mode": filter_mode,
                        "discovery_method": "dynamic_discovery",
                    },
                }
            else:
                # Fallback to direct Redfish query
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Dynamic discovery failed for {entity_type}, falling back to direct Redfish query",
                    dut_id,
                )

            # Fallback to direct Redfish request if no discovery results
            await self._log_runtime(
                "INFO",
                "RedfishService",
                "No dynamic discovery results, using direct Redfish request",
                dut_id,
            )
            entity_uri = self.get_configured_uri(dut_id, config["uri_key"])
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Fallback: trying direct Redfish request to {entity_uri}",
                dut_id,
            )
            success, response, _ = await self.dispatch_request(
                dut_id, "GET", entity_uri
            )

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Fallback: direct Redfish request result - success={success}, response_keys={list(response.keys()) if isinstance(response, dict) else 'not_dict'}",
                dut_id,
            )

            if not success:
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"Fallback: direct Redfish request failed for {entity_type}: {response}",
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[f"Failed to get {entity_type}: {response}"],
                    operation_name="entity_discovery",
                    additional_context={config["context_key"]: []},
                )

            entities_list = response.get("Members", [])
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Fallback: found {len(entities_list)} entities in response",
                dut_id,
            )
            filtered_entities = []

            for entity in entities_list:
                entity_id = entity.get("@odata.id", "").split("/")[-1]
                entity_uri_full = f"{entity_uri}/{entity_id}"
                success, entity_data, _ = await self.dispatch_request(
                    dut_id, "GET", entity_uri_full
                )

                if success:
                    model = entity_data.get("Model", "")
                    # Get HGX prefix from config, fallback to "HGX"
                    dut_config = self.dut_manager.get_dut_config(dut_id)
                    hgx_prefix = dut_config.get(config["config_prefix"], "HGX")
                    is_hgx = hgx_prefix in model

                    # Apply filtering based on filter_mode and baseboard awareness
                    include_entity = False

                    if baseboard_aware and kwargs.get("baseboard_filtering"):
                        # Get DUT config to check baseboard type
                        dut_config = self.dut_manager.get_dut_config(dut_id)
                        target_baseboard = dut_config.get("TargetBaseboard", "")

                        # Get baseboard filtering rules from params
                        baseboard_filtering = kwargs.get("baseboard_filtering", {})

                        # Determine which filter mode to use based on baseboard
                        effective_filter_mode = filter_mode  # Default fallback

                        # Check for exact baseboard match first (highest priority)
                        if target_baseboard in baseboard_filtering:
                            effective_filter_mode = baseboard_filtering[
                                target_baseboard
                            ]
                        else:
                            # Check for baseboard type/group match (e.g., "HGX", "NVL", "GH200")
                            matched_group = None
                            for (
                                baseboard_type,
                                filter_rule,
                            ) in baseboard_filtering.items():
                                if baseboard_type in target_baseboard:
                                    matched_group = baseboard_type
                                    effective_filter_mode = filter_rule
                                    break

                            # If no match found, keep the original filter_mode (code default)
                            # No need for explicit "default" in YAML

                        # Apply the effective filter mode
                        if effective_filter_mode == "hgx_only":
                            include_entity = is_hgx or not check_hgx_prefix
                        elif effective_filter_mode == "all_platforms":
                            include_entity = True
                        elif effective_filter_mode == "non_hgx_only":
                            include_entity = not is_hgx
                        else:
                            # Fallback to original filter_mode
                            if filter_mode == "hgx_only":
                                include_entity = is_hgx or not check_hgx_prefix
                            elif filter_mode == "all_platforms":
                                include_entity = True
                            elif filter_mode == "non_hgx_only":
                                include_entity = not is_hgx
                            else:
                                include_entity = is_hgx or not check_hgx_prefix
                    else:
                        # Non-baseboard-aware filtering (original logic)
                        if filter_mode == "hgx_only":
                            include_entity = is_hgx or not check_hgx_prefix
                        elif filter_mode == "all_platforms":
                            include_entity = True
                        elif filter_mode == "non_hgx_only":
                            include_entity = not is_hgx
                        else:
                            # Default to hgx_only for backward compatibility
                            include_entity = is_hgx or not check_hgx_prefix

                    if include_entity:
                        filtered_entities.append(
                            {
                                "id": entity_id,
                                "model": model,
                                "name": entity_data.get("Name", ""),
                                "discovery_source": "direct_request",
                                "is_hgx": is_hgx,
                            }
                        )

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Filtered {entity_type} using mode '{filter_mode}': {len(filtered_entities)} entities found",
                dut_id,
            )

            return {
                "success": True,
                "context": {
                    config["context_key"]: filtered_entities,
                    config["count_key"]: len(filtered_entities),
                    "filter_mode": filter_mode,
                    "discovery_method": "direct_request",
                },
            }

        except Exception as e:
            return {
                "success": False,
                "reason": str(e),
                "context": {"filtered_entities": []},
            }

    async def _validate_systems(
        self,
        dut_id: str,
        check_hgx_prefix: bool = True,
        filter_mode: str = "hgx_only",
        baseboard_aware: bool = True,
        system_id_patterns: List[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Validate systems using consolidated validation approach.

        Args:
            dut_id: DUT ID.
            check_hgx_prefix: Whether to check for HGX prefix.
            filter_mode: Filter mode.
            baseboard_aware: Whether to use baseboard awareness.
            system_id_patterns: System ID patterns.
        """
        return await self._validate_entities_consolidated(
            dut_id,
            "Systems",
            check_hgx_prefix,
            filter_mode,
            baseboard_aware,
            system_id_patterns,
            **kwargs,
        )

    async def _validate_managers(
        self,
        dut_id: str,
        check_hgx_prefix: bool = False,
        filter_mode: str = "hgx_only",
        baseboard_aware: bool = True,
        manager_id_patterns: List[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Validate managers using consolidated validation approach.

        Args:
            dut_id: DUT ID.
            check_hgx_prefix: Whether to check for HGX prefix.
            filter_mode: Filter mode.
            baseboard_aware: Whether to use baseboard awareness.
            manager_id_patterns: Manager ID patterns.
        """
        return await self._validate_entities_consolidated(
            dut_id,
            "Managers",
            check_hgx_prefix,
            filter_mode,
            baseboard_aware,
            manager_id_patterns,
            **kwargs,
        )

    async def _log_filter_summary_table(
        self,
        dut_id: str,
        entity_type: str,
        discovered_entities: List[str],
        filtered_entities: List[Dict[str, Any]],
        patterns_used: List[str],
        collector_id: str,
        **kwargs,
    ) -> None:
        """
        Log a comprehensive filter summary table showing what was discovered, filtered, and kept.

        Args:
            dut_id: DUT ID.
            entity_type: Type of entity.
            discovered_entities: Discovered entities.
            filtered_entities: Filtered entities.
            patterns_used: Patterns used.
            collector_id: Collector ID.
        """

        # Calculate statistics
        total_discovered = len(discovered_entities)
        total_filtered = len(filtered_entities)
        total_excluded = total_discovered - total_filtered

        # Create filter summary table
        summary_lines = []
        summary_lines.append("=" * 80)
        summary_lines.append(
            f"FILTER SUMMARY - {entity_type} - Collector {collector_id}"
        )
        summary_lines.append("=" * 80)
        summary_lines.append(f"Patterns Used: {patterns_used}")
        summary_lines.append(f"Total Discovered: {total_discovered}")
        summary_lines.append(f"Total Kept: {total_filtered}")
        summary_lines.append(f"Total Excluded: {total_excluded}")
        summary_lines.append("")

        # Table header
        summary_lines.append(f"{'Entity ID':<30} {'Status':<10} {'Reason':<35}")
        summary_lines.append("-" * 80)

        # Process each discovered entity
        for entity_id in discovered_entities:
            # Check if this entity was kept
            kept_entity = next(
                (e for e in filtered_entities if e["id"] == entity_id), None
            )

            if kept_entity:
                status = "KEPT"
                reason = f"Matches pattern(s): {patterns_used}"
            else:
                status = "EXCLUDED"
                reason = f"No pattern match: {patterns_used}"

            summary_lines.append(f"{entity_id:<30} {status:<10} {reason:<35}")

        summary_lines.append("-" * 80)
        summary_lines.append("")

        # Log the summary
        for line in summary_lines:
            await self._log_runtime(
                "INFO", "RedfishService", line, dut_id, collector_id
            )

    async def _validate_entities_with_patterns(
        self,
        dut_id: str,
        entity_type: str,
        id_patterns: List[str],
        collector_id: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Validate entities using specific ID patterns.

        Args:
            dut_id: Device under test ID
            entity_type: Type of entity ("Systems", "Managers", "Chassis")
            id_patterns: List of ID patterns to match (supports wildcards like "HGX_*")
            collector_id: Collector ID for logging
        """
        try:
            # Get all discovered entities of the specified type
            if entity_type == "Systems":
                discovered_entities = await self.get_discovered_systems(dut_id)
            elif entity_type == "Managers":
                discovered_entities = await self.get_discovered_managers(dut_id)
            elif entity_type == "Chassis":
                discovered_entities = await self.get_discovered_chassis(dut_id)
            else:
                return {
                    "success": False,
                    "reason": f"Unsupported entity type: {entity_type}",
                    "context": {"filtered_entities": []},
                }

            # Log discovered entities for debugging
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"DISCOVERED_ENTITIES_{entity_type}: {discovered_entities}",
                dut_id,
            )

            if not discovered_entities:
                await self._log_runtime(
                    "WARNING",
                    "RedfishService",
                    f"[{collector_id}] No {entity_type} found for validation",
                    dut_id,
                )
                return {
                    "success": False,
                    "reason": f"No {entity_type} found",
                    "context": {"filtered_entities": []},
                }

            # Get configured URI for the entity type
            entity_uri = self.get_configured_uri(dut_id, entity_type)
            filtered_entities = []

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"[{collector_id}] Filtering {len(discovered_entities)} {entity_type} with patterns: {id_patterns}",
                dut_id,
            )

            for entity_id in discovered_entities:
                # Check if this entity matches any of the specified patterns
                if self._matches_pattern(entity_id, id_patterns):
                    entity_uri_full = f"{entity_uri}/{entity_id}"
                    success, entity_data, _ = await self.dispatch_request(
                        dut_id, "GET", entity_uri_full
                    )

                    if success:
                        filtered_entities.append(
                            {
                                "id": entity_id,
                                "model": entity_data.get("Model", ""),
                                "name": entity_data.get("Name", ""),
                                "discovery_source": "pattern_filtering",
                            }
                        )
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"[{collector_id}] Matched {entity_type} {entity_id} (model: {entity_data.get('Model', 'N/A')})",
                            dut_id,
                        )

            # Log comprehensive filter summary table
            await self._log_filter_summary_table(
                dut_id,
                entity_type,
                discovered_entities,
                filtered_entities,
                id_patterns,
                collector_id,
                **kwargs,
            )

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"[{collector_id}] Pattern filtering found {len(filtered_entities)} {entity_type}: {[e['id'] for e in filtered_entities]}",
                dut_id,
            )

            return {
                "success": True,
                "context": {
                    f"filtered_{entity_type.lower()}": filtered_entities,
                    f"{entity_type.lower()}_count": len(filtered_entities),
                    "filter_mode": "pattern_based",
                    "patterns_used": id_patterns,
                    "discovery_method": "pattern_filtering",
                },
            }

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"[{collector_id}] Error in pattern-based {entity_type} validation: {str(e)}",
                dut_id,
            )
            return {
                "success": False,
                "reason": str(e),
                "context": {"filtered_entities": []},
            }

    def _matches_pattern(self, entity_id: str, patterns: List[str]) -> bool:
        """
        Check if entity ID matches any of the provided patterns

        Args:
            entity_id: The entity ID to check
            patterns: List of patterns (supports wildcards like "HGX_*")

        Returns:
            True if entity_id matches any pattern
        """
        import fnmatch

        for pattern in patterns:
            if fnmatch.fnmatch(entity_id, pattern):
                return True
        return False

    async def _resolve_patterns_for_baseboard(
        self,
        dut_id: str,
        entity_type: str,
        default_patterns: List[str],
        baseboard_patterns: Dict[str, List[str]],
        collector_id: str,
        baseboard: str = "default",
        baseboard_manager=None,
    ) -> List[str]:
        """
        Generalized method to resolve patterns based on baseboard and baseboard groups

        Args:
            dut_id: Device under test ID
            entity_type: Type of entity ("Systems", "Managers", "Chassis")
            default_patterns: Default patterns to use if no specific patterns match
            baseboard_patterns: Dictionary of baseboard/group -> patterns mappings
            collector_id: Collector ID for logging
            baseboard: Target baseboard name (fallback if not found in DUT config)
            baseboard_manager: BaseboardManager instance

        Returns:
            List of patterns to use for filtering
        """
        # Get the actual baseboard from DUT config, not from kwargs
        dut_config = self.dut_manager.get_dut_config(dut_id)
        target_baseboard = (
            dut_config.get("baseboard")
            or dut_config.get("TargetBaseboard", "")
            or baseboard
        )

        if baseboard_manager is None:
            baseboard_manager = self.dut_manager._get_baseboard_manager()

        patterns_to_use = None

        # Log the baseboard resolution process
        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"Baseboard resolution: dut_config.baseboard='{dut_config.get('baseboard')}', dut_config.TargetBaseboard='{dut_config.get('TargetBaseboard')}', fallback='{baseboard}', resolved='{target_baseboard}'",
            dut_id,
        )

        # First, check for exact baseboard match
        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"Checking baseboard patterns: target_baseboard='{target_baseboard}', available_patterns={list(baseboard_patterns.keys()) if baseboard_patterns else 'None'}",
            dut_id,
        )

        if baseboard_patterns and target_baseboard in baseboard_patterns:
            patterns_to_use = baseboard_patterns[target_baseboard]
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Using exact baseboard patterns for {target_baseboard}: {patterns_to_use}",
                dut_id,
            )
        # Then check for baseboard group match
        elif baseboard_manager and baseboard_patterns:
            baseboard_group = baseboard_manager.get_baseboard_group(target_baseboard)
            if baseboard_group and baseboard_group in baseboard_patterns:
                patterns_to_use = baseboard_patterns[baseboard_group]
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using baseboard group patterns for {target_baseboard} (group: {baseboard_group}): {patterns_to_use}",
                    dut_id,
                )

        # Fall back to default patterns if no specific patterns found
        if patterns_to_use is None:
            patterns_to_use = default_patterns or [
                "*"
            ]  # Default to all if no patterns specified
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Using fallback patterns: {patterns_to_use}",
                dut_id,
            )
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Using default patterns: {patterns_to_use}",
                dut_id,
            )

        return patterns_to_use

    async def _validate_chassis(
        self,
        dut_id: str,
        check_hgx_prefix: bool = True,
        filter_mode: str = "hgx_only",
        baseboard_aware: bool = True,
        chassis_id_patterns: List[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Validate chassis using consolidated validation approach.

        Args:
            dut_id: DUT ID.
            check_hgx_prefix: Whether to check HGX prefix.
            filter_mode: Filter mode to apply.
            baseboard_aware: Whether to use baseboard-aware filtering.
            chassis_id_patterns: Optional chassis ID patterns.
            **kwargs: Additional arguments.

        Returns:
            Validation result dictionary.
        """
        return await self._validate_entities_consolidated(
            dut_id,
            "Chassis",
            check_hgx_prefix,
            filter_mode,
            baseboard_aware,
            chassis_id_patterns,
            **kwargs,
        )

    async def _validate_specific_entities(
        self, dut_id: str, entity_type: str, entity_names: List[str], **kwargs
    ) -> Dict[str, Any]:
        """
        Validate specific entities by name.

        Args:
            dut_id: Device under test ID
            entity_type: Type of entity ("Systems", "Managers", "Chassis")
            entity_names: List of specific entity names to validate
        """
        try:
            # Get all discovered entities of the specified type
            if entity_type == "Systems":
                discovered_entities = await self.get_discovered_systems(dut_id)
            elif entity_type == "Managers":
                discovered_entities = await self.get_discovered_managers(dut_id)
            elif entity_type == "Chassis":
                discovered_entities = await self.get_discovered_chassis(dut_id)
            else:
                return {
                    "success": False,
                    "reason": f"Unsupported entity type: {entity_type}",
                    "context": {"filtered_entities": []},
                }

            if not discovered_entities:
                return {
                    "success": False,
                    "reason": f"No {entity_type} found",
                    "context": {"filtered_entities": []},
                }

            # Get configured URI for the entity type
            entity_uri = self.get_configured_uri(dut_id, entity_type)
            filtered_entities = []

            for entity_id in discovered_entities:
                # Check if this entity matches any of the specified names
                if entity_id in entity_names:
                    entity_uri_full = f"{entity_uri}/{entity_id}"
                    success, entity_data, _ = await self.dispatch_request(
                        dut_id, "GET", entity_uri_full
                    )

                    if success:
                        filtered_entities.append(
                            {
                                "id": entity_id,
                                "model": entity_data.get("Model", ""),
                                "name": entity_data.get("Name", ""),
                                "discovery_source": "specific_selection",
                            }
                        )

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Validated {len(filtered_entities)} specific {entity_type}: {[e['id'] for e in filtered_entities]}",
                dut_id,
            )

            return {
                "success": True,
                "context": {
                    "filtered_entities": filtered_entities,
                    "entity_count": len(filtered_entities),
                    "entity_type": entity_type,
                    "discovery_method": "specific_selection",
                },
            }

        except Exception as e:
            return {
                "success": False,
                "reason": str(e),
                "context": {"filtered_entities": []},
            }

    async def _validate_by_baseboard(
        self, dut_id: str, entity_type: str, baseboard_filter: str = None, **kwargs
    ) -> Dict[str, Any]:
        """
        Validate entities based on baseboard configuration.

        Args:
            dut_id: Device under test ID
            entity_type: Type of entity ("Systems", "Managers", "Chassis")
            baseboard_filter: Baseboard filter to apply (e.g., "HGX", "non-HGX", "all")
        """
        try:
            # Get DUT config to check baseboard type
            dut_config = self.dut_manager.get_dut_config(dut_id)
            target_baseboard = dut_config.get("TargetBaseboard", "")

            # Get all discovered entities of the specified type
            if entity_type == "Systems":
                discovered_entities = await self.get_discovered_systems(dut_id)
            elif entity_type == "Managers":
                discovered_entities = await self.get_discovered_managers(dut_id)
            elif entity_type == "Chassis":
                discovered_entities = await self.get_discovered_chassis(dut_id)
            else:
                return {
                    "success": False,
                    "reason": f"Unsupported entity type: {entity_type}",
                    "context": {"filtered_entities": []},
                }

            if not discovered_entities:
                return {
                    "success": False,
                    "reason": f"No {entity_type} found",
                    "context": {"filtered_entities": []},
                }

            # Get configured URI for the entity type
            entity_uri = self.get_configured_uri(dut_id, entity_type)
            filtered_entities = []

            # Get HGX prefix from config
            if entity_type == "Systems":
                hgx_prefix = dut_config.get("HGX_SYSTEM_ID_PREFIX", "HGX")
            elif entity_type == "Managers":
                hgx_prefix = dut_config.get("HGX_MANAGER_ID_PREFIX", "HGX")
            else:
                hgx_prefix = "HGX"  # Default for chassis

            for entity_id in discovered_entities:
                entity_uri_full = f"{entity_uri}/{entity_id}"
                success, entity_data, _ = await self.dispatch_request(
                    dut_id, "GET", entity_uri_full
                )

                if success:
                    model = entity_data.get("Model", "")
                    is_hgx = hgx_prefix in model

                    # Apply baseboard filtering
                    include_entity = False
                    if baseboard_filter == "HGX" or baseboard_filter == "hgx":
                        include_entity = is_hgx
                    elif baseboard_filter == "non-HGX" or baseboard_filter == "non_hgx":
                        include_entity = not is_hgx
                    elif baseboard_filter == "all" or baseboard_filter is None:
                        include_entity = True
                    else:
                        # Check if baseboard filter matches target baseboard
                        include_entity = (
                            baseboard_filter.lower() in target_baseboard.lower()
                        )

                    if include_entity:
                        filtered_entities.append(
                            {
                                "id": entity_id,
                                "model": model,
                                "name": entity_data.get("Name", ""),
                                "discovery_source": "baseboard_filter",
                                "is_hgx": is_hgx,
                                "target_baseboard": target_baseboard,
                            }
                        )

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Filtered {entity_type} by baseboard '{baseboard_filter}': {len(filtered_entities)} entities found",
                dut_id,
            )

            return {
                "success": True,
                "context": {
                    "filtered_entities": filtered_entities,
                    "entity_count": len(filtered_entities),
                    "entity_type": entity_type,
                    "baseboard_filter": baseboard_filter,
                    "target_baseboard": target_baseboard,
                },
            }

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Error in _validate_by_baseboard: {str(e)}",
                dut_id,
            )
            return {
                "success": False,
                "reason": f"Validation error: {str(e)}",
                "context": {"filtered_entities": []},
            }

    async def _validate_entities_dynamic(
        self,
        dut_id: str,
        entity_type: str = "Chassis",
        filter_criteria: Dict[str, Any] = None,
        output_variable: str = None,
        baseboard_aware: bool = False,
        baseboard_filtering: Dict[str, str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generic validation method for all entity types with dynamic filtering.

        Args:
            dut_id: Device under test ID
            entity_type: Type of entity ("Systems", "Managers", "Chassis")
            filter_criteria: Dict containing filter configuration:
                - check_path: Path to check in entity data (e.g., "ThermalSubsystem")
                - target_uri: URI pattern to use if found (e.g., "/redfish/v1/Chassis/{chassis_id}/ThermalSubsystem/ThermalMetrics")
                - oem_path: List path to OEM data (e.g., ["Nvidia"])
                - oem_keywords: Keywords to search for in OEM data (e.g., ["rot", "root", "trust"])
                - id_pattern: Pattern to match in entity ID (e.g., "RoT")
                - model_keywords: Keywords to search for in model names
                - name_keywords: Keywords to search for in entity names
            output_variable: Variable name to store the filtered URIs
            baseboard_aware: Whether to apply baseboard-specific filtering
            baseboard_filtering: Dict mapping baseboard patterns to filter modes (e.g., {"NVL": "hgx_only", "HGX": "hgx_only"})
        """
        try:
            # Entity configuration mapping
            entity_config = {
                "Systems": {
                    "discovery_method": self.get_discovered_systems,
                    "uri_base": self.get_configured_uri(dut_id, "Systems"),
                    "id_placeholder": "system_id",
                },
                "Managers": {
                    "discovery_method": self.get_discovered_managers,
                    "uri_base": self.get_configured_uri(dut_id, "Managers"),
                    "id_placeholder": "manager_id",
                },
                "Chassis": {
                    "discovery_method": self.get_discovered_chassis,
                    "uri_base": self.get_configured_uri(dut_id, "Chassis"),
                    "id_placeholder": "chassis_id",
                },
            }

            if entity_type not in entity_config:
                return {
                    "success": False,
                    "reason": f"Unsupported entity type: {entity_type}",
                    "context": {output_variable: []},
                }

            config = entity_config[entity_type]

            # Get all discovered entities
            discovered_entities = await config["discovery_method"](dut_id)

            if not discovered_entities:
                return {
                    "success": False,
                    "reason": f"No {entity_type} found",
                    "context": {output_variable: []},
                }

            filtered_uris = []
            filter_criteria = filter_criteria or {}

            # Get DUT baseboard for filtering if baseboard_aware is enabled
            dut_baseboard = None
            effective_filter_mode = "hgx_only"  # Default
            if baseboard_aware and baseboard_filtering:
                dut_config = self.dut_manager.get_dut_config(dut_id)
                dut_baseboard = dut_config.get("baseboard", "")

                # Determine effective filter mode based on baseboard
                for baseboard_pattern, filter_mode in baseboard_filtering.items():
                    if baseboard_pattern.upper() in dut_baseboard.upper():
                        effective_filter_mode = filter_mode
                        break

                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Baseboard filtering enabled for {entity_type}: baseboard={dut_baseboard}, filter_mode={effective_filter_mode}",
                    dut_id,
                )

            # If id_pattern is specified but no matching entities found in discovery,
            # try to enumerate based on the pattern (common for nested GPU chassis)
            if "id_pattern" in filter_criteria:
                id_pattern = filter_criteria["id_pattern"]
                # Check if any discovered entities match the pattern
                matching_discovered = [
                    e for e in discovered_entities if id_pattern.lower() in e.lower()
                ]

                if not matching_discovered:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"No {entity_type.lower()} matching pattern '{id_pattern}' found in standard discovery. Attempting enumeration...",
                        dut_id,
                    )

                    # Try common enumeration patterns for the id_pattern
                    # For "HGX_GPU", try HGX_GPU_0, HGX_GPU_1, HGX_GPU_2, HGX_GPU_3, etc.
                    enumeration_attempts = []
                    for i in range(8):  # Try 0-7 for common GPU counts
                        enumeration_attempts.append(f"{id_pattern}_{i}")

                    # Also try SXM variants for GPU chassis
                    if "GPU" in id_pattern.upper():
                        for i in range(8):
                            enumeration_attempts.append(f"{id_pattern}_SXM_{i}")

                    # Probe each potential entity to see if it exists
                    enumerated_entities = []
                    for potential_id in enumeration_attempts:
                        entity_uri = f"{config['uri_base']}/{potential_id}"
                        success, _, _ = await self.dispatch_request(
                            dut_id, "GET", entity_uri
                        )
                        if success:
                            enumerated_entities.append(potential_id)
                            await self._log_runtime(
                                "INFO",
                                "RedfishService",
                                f"Enumerated {entity_type.lower()}: {potential_id}",
                                dut_id,
                            )

                    if enumerated_entities:
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Found {len(enumerated_entities)} {entity_type.lower()} via enumeration: {enumerated_entities}",
                            dut_id,
                        )
                        # Add enumerated entities to the discovered list for processing
                        discovered_entities = (
                            list(discovered_entities) + enumerated_entities
                        )

            for entity_id in discovered_entities:
                # Apply baseboard filtering first if enabled
                if baseboard_aware and baseboard_filtering:
                    # Check if entity matches HGX pattern
                    is_hgx = entity_id.upper().startswith("HGX_")

                    # Apply filter mode
                    should_skip = False
                    if effective_filter_mode == "hgx_only" and not is_hgx:
                        should_skip = True
                    elif effective_filter_mode == "non_hgx_only" and is_hgx:
                        should_skip = True
                    # "all_platforms" mode doesn't skip anything

                    if should_skip:
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"Skipping {entity_type.lower()} {entity_id} due to baseboard filter (mode={effective_filter_mode}, is_hgx={is_hgx})",
                            dut_id,
                        )
                        continue

                entity_uri = f"{config['uri_base']}/{entity_id}"

                success, entity_data, _ = await self.dispatch_request(
                    dut_id, "GET", entity_uri
                )

                if not success:
                    continue

                include_entity = False

                # Check ID pattern first (if specified)
                if "id_pattern" in filter_criteria:
                    id_pattern = filter_criteria["id_pattern"]
                    if id_pattern.lower() in entity_id.lower():
                        # Use custom target URI if specified, otherwise use default entity URI
                        if "target_uri" in filter_criteria:
                            target_uri = filter_criteria["target_uri"].format(
                                **{config["id_placeholder"]: entity_id}
                            )
                            filtered_uris.append(target_uri)
                        else:
                            filtered_uris.append(entity_uri)
                        include_entity = True
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Found {entity_type.lower()} matching ID pattern '{id_pattern}': {entity_id}",
                            dut_id,
                        )
                        continue

                # Check for specific path in entity data
                if "check_path" in filter_criteria:
                    check_path = filter_criteria["check_path"]
                    if check_path in entity_data:
                        # Use custom target URI if specified, otherwise use default entity URI
                        if "target_uri" in filter_criteria:
                            target_uri = filter_criteria["target_uri"].format(
                                **{config["id_placeholder"]: entity_id}
                            )
                            filtered_uris.append(target_uri)
                        else:
                            filtered_uris.append(entity_uri)
                        include_entity = True
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Found {entity_type.lower()} with {check_path}: {entity_id}",
                            dut_id,
                        )
                    else:
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"{entity_type} {entity_id} does not have {check_path}, skipping",
                            dut_id,
                        )

                # Check OEM data for keywords
                elif "oem_keywords" in filter_criteria:
                    oem_keywords = filter_criteria["oem_keywords"]
                    oem_path = filter_criteria.get("oem_path", [])

                    # Navigate to OEM data
                    oem_data = entity_data.get("Oem", {})
                    for path_part in oem_path:
                        oem_data = oem_data.get(path_part, {})

                    # Check for keywords in OEM data
                    oem_data_str = str(oem_data).lower()
                    if any(keyword.lower() in oem_data_str for keyword in oem_keywords):
                        filtered_uris.append(entity_uri)
                        include_entity = True
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Found {entity_type.lower()} with OEM keywords {oem_keywords}: {entity_id}",
                            dut_id,
                        )
                    else:
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"{entity_type} {entity_id} does not contain OEM keywords {oem_keywords}, skipping",
                            dut_id,
                        )

                # Check model keywords
                elif "model_keywords" in filter_criteria:
                    model_keywords = filter_criteria["model_keywords"]
                    model = entity_data.get("Model", "").lower()
                    if any(keyword.lower() in model for keyword in model_keywords):
                        filtered_uris.append(entity_uri)
                        include_entity = True
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Found {entity_type.lower()} with model keywords {model_keywords}: {entity_id}",
                            dut_id,
                        )
                    else:
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"{entity_type} {entity_id} model '{model}' does not match keywords {model_keywords}, skipping",
                            dut_id,
                        )

                # Check name keywords
                elif "name_keywords" in filter_criteria:
                    name_keywords = filter_criteria["name_keywords"]
                    name = entity_data.get("Name", "").lower()
                    if any(keyword.lower() in name for keyword in name_keywords):
                        filtered_uris.append(entity_uri)
                        include_entity = True
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Found {entity_type.lower()} with name keywords {name_keywords}: {entity_id}",
                            dut_id,
                        )
                    else:
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"{entity_type} {entity_id} name '{name}' does not match keywords {name_keywords}, skipping",
                            dut_id,
                        )

                elif not filter_criteria:
                    # No filters provided at all, include all entities
                    filtered_uris.append(entity_uri)
                    include_entity = True
                else:
                    # Filters were provided but none matched; skip this entity
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"{entity_type} {entity_id} did not match filter criteria {filter_criteria}, skipping",
                        dut_id,
                    )

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Found {len(filtered_uris)} {entity_type.lower()} with filter criteria: {filter_criteria}",
                dut_id,
            )

            return {
                "success": True,
                "context": {
                    output_variable: filtered_uris,
                    f"{entity_type.lower()}_count": len(filtered_uris),
                    "filter_criteria": filter_criteria,
                },
            }

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Error in _validate_entities_dynamic: {str(e)}",
                dut_id,
            )
            return {
                "success": False,
                "reason": f"Validation error: {str(e)}",
                "context": {output_variable: []},
            }

    async def _validate_chassis_dynamic(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Backward compatibility wrapper for chassis dynamic validation.

        Args:
            dut_id: DUT ID.
            kwargs: Keyword arguments.
        """
        return await self._validate_entities_dynamic(
            dut_id, entity_type="Chassis", **kwargs
        )

    async def _validate_systems_dynamic(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Wrapper for systems dynamic validation with baseboard filtering support.

        Args:
            dut_id: DUT ID.
            kwargs: Keyword arguments.
        """
        return await self._validate_entities_dynamic(
            dut_id, entity_type="Systems", **kwargs
        )

    async def _validate_managers_dynamic(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Wrapper for managers dynamic validation with baseboard filtering support.

        Args:
            dut_id: DUT ID.
            kwargs: Keyword arguments.
        """
        return await self._validate_entities_dynamic(
            dut_id, entity_type="Managers", **kwargs
        )

    """
    Discovery
    """

    async def get_discovered_systems(self, dut_id: str) -> List[str]:
        """
        Get discovered system IDs from dynamic discovery.

        Args:
            dut_id: DUT ID.
        """
        if not self.dut_manager:
            return []

        systems = await self.dut_manager.get_resource_members(dut_id, "Systems")

        # Log what systems were found
        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"get_discovered_systems for {dut_id}: found {len(systems)} systems: {systems}",
            dut_id,
        )

        return systems

    async def get_discovered_chassis(self, dut_id: str) -> List[str]:
        """
        Get discovered chassis IDs from dynamic discovery.

        Args:
            dut_id: DUT ID.
        """
        if not self.dut_manager:
            return []
        chassis = await self.dut_manager.get_resource_members(dut_id, "Chassis")

        # Log what chassis were found
        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"get_discovered_chassis for {dut_id}: found {len(chassis)} chassis: {chassis}",
            dut_id,
        )

        return chassis

    async def get_discovered_managers(self, dut_id: str) -> List[str]:
        """
        Get discovered manager IDs from dynamic discovery.

        Args:
            dut_id: DUT ID.
        """
        if not self.dut_manager:
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"get_discovered_managers for {dut_id}: no dut_manager available",
                dut_id,
            )
            return []

        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"get_discovered_managers for {dut_id}: calling get_resource_members",
            dut_id,
        )

        managers = await self.dut_manager.get_resource_members(dut_id, "Managers")

        # Log what managers were found
        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"get_discovered_managers for {dut_id}: found {len(managers)} managers: {managers}",
            dut_id,
        )

        return managers

    async def get_discovered_firmware_inventory(
        self, dut_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get discovered firmware inventory from dynamic discovery.

        Args:
            dut_id: DUT ID.
        """
        if not self.dut_manager:
            return None
        firmware_inventory = await self.dut_manager.get_firmware_inventory(dut_id)

        # Log what firmware inventory was found
        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"get_discovered_firmware_inventory for {dut_id}: found {len(firmware_inventory) if firmware_inventory else 0} firmware inventory: {firmware_inventory}",
            dut_id,
        )

        return firmware_inventory

    async def get_discovery_results(self, dut_id: str) -> Optional[Dict[str, Any]]:
        """
        Get complete discovery results for a DUT.

        Args:
            dut_id: DUT ID.
        """
        if not self.dut_manager:
            return None
        discovery_results = await self.dut_manager.get_discovery_results(dut_id)

        # Log what discovery results were found
        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"get_discovery_results for {dut_id}: found {len(discovery_results) if discovery_results else 0} discovery results: {discovery_results}",
            dut_id,
        )

        return discovery_results

    async def get_resource_details(
        self, dut_id: str, resource_type: str
    ) -> Dict[str, Any]:
        """
        Get detailed information about discovered resources.

        Args:
            dut_id: DUT ID.
            resource_type: Resource type.
        """
        if not self.dut_manager:
            return {}
        resource_details = await self.dut_manager.get_resource_details(
            dut_id, resource_type
        )

        # Log what resource details were found
        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"get_resource_details for {dut_id}: found {len(resource_details)} resource details: {resource_details}",
            dut_id,
        )

        return resource_details

    def get_configured_uri(self, dut_id: str, uri_key: str) -> str:
        """
        Get configured URI for a specific key using URI config manager.

        Args:
            dut_id: DUT ID.
            uri_key: URI key.
        """
        if not self.dut_manager or not self.dut_manager.uri_config_manager:
            # Fallback to constructed URI if no URI config manager available
            return f"/redfish/v1/{uri_key}"

        # Get DUT config for baseboard/platform info
        dut_config = self.dut_manager.get_dut_config(dut_id)
        baseboard = dut_config.get("baseboard")
        platform = dut_config.get("platform")

        return self.dut_manager.uri_config_manager.get_uri(
            dut_id, uri_key, baseboard, platform
        )

    async def _discover_chassis_devices(
        self,
        dut_id: str,
        device_types: List[str] = None,
        device_patterns: Dict[str, List[str]] = None,
        use_firmware_inventory: Union[bool, Dict[str, bool]] = True,
        baseboard_specific_config: Dict[str, Dict[str, Any]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generic device discovery method for chassis-based devices

        Args:
            dut_id: Device under test ID
            device_types: List of device types to discover (e.g., ["network", "nvswitch", "gpu", "sma"])
            device_patterns: Dict of regex patterns for each device type
            use_firmware_inventory: Whether to use firmware inventory (bool or dict per baseboard)
            baseboard_specific_config: Baseboard-specific configuration overrides

        Returns:
            Dict with discovered devices by type and context for execution stage
        """
        try:
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"=== Starting generic chassis device discovery for types: {device_types} ===",
                dut_id,
            )

            # Get DUT config for baseboard-specific logic
            dut_config = self.dut_manager.get_dut_config(dut_id)
            target_baseboard = dut_config.get(
                "TargetBaseboard", dut_config.get("baseboard", "")
            )

            # Determine firmware inventory usage based on baseboard
            if isinstance(use_firmware_inventory, dict):
                # First try to get the specific baseboard setting
                if target_baseboard in use_firmware_inventory:
                    use_fw_inventory = use_firmware_inventory[target_baseboard]
                # If not found, check for "default" setting
                elif "default" in use_firmware_inventory:
                    use_fw_inventory = use_firmware_inventory["default"]
                # If no default specified, fall back to True
                else:
                    use_fw_inventory = True
            else:
                use_fw_inventory = use_firmware_inventory

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Target baseboard: {target_baseboard}, using firmware inventory: {use_fw_inventory}",
                dut_id,
            )

            # Get baseboard-specific configuration
            baseboard_config = {}
            if (
                baseboard_specific_config
                and target_baseboard in baseboard_specific_config
            ):
                baseboard_config = baseboard_specific_config[target_baseboard]
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Using baseboard-specific config for {target_baseboard}: {baseboard_config}",
                dut_id,
            )

            discovered_devices = {}

            # Default device types if not specified
            if device_types is None:
                device_types = ["network", "nvswitch", "gpu", "sma"]

            # Default patterns if not specified
            if device_patterns is None:
                device_patterns = {
                    "nvlink_nic_patterns": [r"HGX_.*NVLinkManagementNIC_(\d+)"],
                    "connectx_nic_patterns": [r"HGX_FW_ConnectX_(\d+)"],
                    "nvswitch_patterns": [r"HGX_.*NVSwitch_(\d+)"],
                    "gpu_patterns": [r"HGX_.*GPU_.*(\d+)", r"HGX_FW_GPU_(\d+)"],
                    "sma_patterns": [r"HGX_.*SMA_(\d+)", r"HGX_.*MCU_(\d+)"],
                }

            # Get chassis data
            chassis_uri = self.get_configured_uri(dut_id, "Chassis")
            success, chassis_response, _ = await self.dispatch_request(
                dut_id, "GET", chassis_uri
            )

            if not success:
                return {
                    "success": False,
                    "reason": f"Failed to fetch chassis data: {chassis_response}",
                    "context": {"discovered_devices": {}},
                }

            chassis_members = chassis_response.get("Members", [])
            chassis_ids = [
                member.get("@odata.id", "").split("/")[-1] for member in chassis_members
            ]

            # Apply ID filtering based on DUT configuration
            dut_config = self.dut_manager.get_dut_config(dut_id)
            original_chassis_ids = chassis_ids.copy()
            chassis_ids = filter_ids(chassis_ids, "chassis", dut_config)

            # Log filtered IDs if any were filtered
            if len(chassis_ids) != len(original_chassis_ids):
                log_filtered_ids(
                    original_chassis_ids, chassis_ids, "chassis", self.logger, dut_id
                )

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Found {len(chassis_ids)} chassis members: {chassis_ids}",
                dut_id,
            )

            # Process each device type
            for device_type in device_types:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Discovering devices for type: {device_type}",
                    dut_id,
                )

                device_ids = set()

                # Try firmware inventory first if enabled
                if use_fw_inventory:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Attempting firmware inventory discovery for {device_type}",
                        dut_id,
                    )
                    # TODO: Implement firmware inventory discovery
                    # For now, we'll use chassis-based discovery

                # Chassis-based discovery - generic pattern lookup
                patterns_for_type = []
                # Look for patterns with the device_type as a key
                if device_type in device_patterns:
                    patterns_for_type = device_patterns[device_type]
                # Also look for patterns with device_type + "_patterns" suffix for backward compatibility
                elif f"{device_type}_patterns" in device_patterns:
                    patterns_for_type = device_patterns[f"{device_type}_patterns"]
                else:
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        f"No patterns found for device type {device_type} in device_patterns: {list(device_patterns.keys())}",
                        dut_id,
                    )

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using patterns for {device_type}: {patterns_for_type}",
                    dut_id,
                )

                # Apply patterns to chassis IDs
                for chassis_id in chassis_ids:
                    for pattern_str in patterns_for_type:
                        try:
                            pattern = re.compile(pattern_str)
                            match = pattern.match(chassis_id)
                            if match:
                                device_id = int(match.group(1))
                                device_ids.add(device_id)
                                await self._log_runtime(
                                    "INFO",
                                    "RedfishService",
                                    f"Found {device_type} device ID {device_id} from chassis {chassis_id}",
                                    dut_id,
                                )
                                break  # Found match, move to next chassis
                        except (ValueError, IndexError, re.error) as e:
                            await self._log_runtime(
                                "WARNING",
                                "RedfishService",
                                f"Error processing pattern {pattern_str} for chassis {chassis_id}: {e}",
                                dut_id,
                            )

                # Store discovered devices for this type
                device_ids_list = sorted(list(device_ids))
                discovered_devices[device_type] = device_ids_list

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Discovered {len(device_ids_list)} {device_type} devices: {device_ids_list}",
                    dut_id,
                )

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"=== Device discovery complete. Total discovered: {discovered_devices} ===",
                dut_id,
            )

            return {
                "success": True,
                "context": {
                    "discovered_devices": discovered_devices,
                    "target_baseboard": target_baseboard,
                    "use_firmware_inventory": use_fw_inventory,
                    "baseboard_config": baseboard_config,
                    "device_types": device_types,
                    "discovery_method": "chassis_device_discovery",
                },
            }

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Error in chassis device discovery: {str(e)}",
                dut_id,
            )
            return {
                "success": False,
                "reason": f"Device discovery failed: {str(e)}",
                "context": {"discovered_devices": {}},
            }

    async def _get_diagnostic_data_action_info(
        self, dut_id: str, entity_type: str, entity_id: str, log_service: str = "Dump"
    ) -> Dict[str, Any]:
        """
        Get diagnostic data action info for an entity.

        Args:
            dut_id: DUT ID.
            entity_type: Entity type.
            entity_id: Entity ID.
            log_service: Log service.
        """
        try:
            # Try to get action info from the diagnostic data endpoint
            action_uri = f"{entity_type}/{entity_id}/LogServices/{log_service}/Actions/LogService.CollectDiagnosticData"
            success, response, _ = await self.dispatch_request(
                dut_id, "GET", action_uri
            )

            if success:
                return {
                    "success": True,
                    "exists": True,
                    "data": response,
                }
            else:
                return {
                    "success": True,
                    "exists": False,
                    "data": {},
                }
        except Exception as e:
            return {
                "success": False,
                "exists": False,
                "data": {},
                "error": str(e),
            }

    """ 
    Common Helpers 
    """

    async def _log_collector_start(self, dut_id: str, collector_name: str, **kwargs):
        """
        Common logging for collector start (DRY pattern).

        Args:
            dut_id: DUT ID.
            collector_name: Collector name.
            kwargs: Keyword arguments.
        """
        await self._log_runtime(
            "INFO", "RedfishService", f"Starting {collector_name} collection", dut_id
        )

    async def _log_collector_success(
        self, dut_id: str, collector_name: str, context: Dict[str, Any], **kwargs
    ):
        """
        Common logging for collector success (DRY pattern).

        Args:
            dut_id: DUT ID.
            collector_name: Collector name.
            context: Context.
        """
        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"Completed {collector_name} collection successfully: {context}",
            dut_id,
        )

    async def _log_collector_failure(
        self, dut_id: str, collector_name: str, reason: str, **kwargs
    ):
        """
        Common logging for collector failure (DRY pattern).

        Args:
            dut_id: DUT ID.
            collector_name: Collector name.
            reason: Reason.
        """
        await self._log_runtime(
            "ERROR",
            "RedfishService",
            f"Failed {collector_name} collection: {reason}",
            dut_id,
        )

        # Also create detailed error log file for better debugging
        try:
            # Extract collector_id from collector_name or kwargs
            collector_id = kwargs.get("collector_id", collector_name)

            # Create error log file with context
            error_log_path = await self._create_error_log_file(
                dut_id=dut_id,
                collector_id=collector_id,
                error_message=f"Failed {collector_name} collection: {reason}",
                context={
                    "collector_name": collector_name,
                    "reason": reason,
                    "operation": "collection_failure",
                    "additional_context": kwargs,
                },
            )

            if error_log_path:
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Created error log file: {error_log_path}",
                    dut_id,
                )
        except Exception as e:
            # Don't let error log creation failure break the main flow
            await self._log_runtime(
                "WARN",
                "RedfishService",
                f"Failed to create error log file for {collector_name}: {str(e)}",
                dut_id,
            )

    async def _process_entities_with_common_logic(
        self,
        dut_id: str,
        entity_type: str,
        processor_func,
        collector_name: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Common entity processing logic (DRY pattern).

        Args:
            dut_id: DUT ID.
            entity_type: Entity type.
            processor_func: Processor function.
            collector_name: Collector name.
            kwargs: Keyword arguments.
        """
        try:
            await self._log_collector_start(dut_id, collector_name)

            # Get entities
            success, entities, _ = await self.dispatch_request(
                dut_id, "GET", entity_type
            )

            if not success:
                return await self._handle_collector_error(
                    dut_id, collector_name, f"Failed to get {entity_type}: {entities}"
                )

            output_files = []
            status_list = []
            entities_processed = 0

            # Process each entity
            for entity in entities.get("Members", []):
                entity_id = entity.get("@odata.id", "").split("/")[-1]

                # Call the provided processor function
                result = await processor_func(dut_id, entity_id, **kwargs)

                # Process result using common function
                await self._process_collector_result(
                    result=result,
                    all_output_files=output_files,
                    all_status_list=status_list,
                    error_messages=[],  # This method doesn't use error_messages
                    entity_type=entity_type,
                    entity_id=entity_id,
                )

                if result.get("success", False):
                    entities_processed += 1

            result = {
                "success": any(status_list),
                "output_files": output_files,
                "context": {
                    "entity_type": entity_type,
                    "entities_processed": entities_processed,
                    "successful_collections": len([s for s in status_list if s]),
                    "total_files": len(output_files),
                },
            }

            if result["success"]:
                await self._log_collector_success(
                    dut_id, collector_name, result["context"]
                )
            else:
                await self._log_collector_failure(
                    dut_id, collector_name, "No successful collections"
                )

            return result

        except Exception as e:
            await self._log_collector_failure(dut_id, collector_name, str(e))
            return await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=collector_name,
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="collection",
                additional_context={"collector_name": collector_name},
            )

    async def _save_data_to_file_with_pattern(
        self, dut_id: str, data: Any, function_tag: str, **kwargs
    ) -> Optional[str]:
        """
        Common file saving logic with pattern substitution (DRY pattern)

        Handles parameters that may come from YAML framework as kwargs:
        - output_pattern: File pattern for output
        - substitutions: Dictionary of pattern substitutions
        - collector_id: Collector identifier
        - filename: Alternative filename parameter
        - entries_pattern: Pattern for entries files
        - additional_data_pattern: Pattern for additional data files
        """
        # Extract parameters from kwargs (framework passes these from YAML)
        output_pattern = kwargs.get("output_pattern", "")
        substitutions = kwargs.get("substitutions", {})
        collector_id = kwargs.get("collector_id", "")
        filename = kwargs.get("filename", "")
        entries_pattern = kwargs.get("entries_pattern", "")
        additional_data_pattern = kwargs.get("additional_data_pattern", "")
        try:
            # Handle binary data (bytes) vs JSON/text data
            if isinstance(data, bytes):
                # Binary data - write directly
                content = data
                is_binary = True
            elif isinstance(data, (dict, list)):
                content = json.dumps(data, indent=2)
                is_binary = False
            else:
                content = str(data)
                is_binary = False

            # For JSON files, let write_output_with_generalization handle the filename generation
            # For binary files, we need to handle it ourselves since we bypass the text system
            if not is_binary:
                # Don't pre-process filename for JSON files - let write_output_with_generalization do it
                filename = function_tag
            else:
                # For binary files, we need to handle filename generation ourselves
                # Use additional_data_pattern if available, otherwise fall back to output_pattern
                effective_pattern = (
                    additional_data_pattern
                    if additional_data_pattern
                    else output_pattern
                )
                if effective_pattern and substitutions:
                    # Use substitute_output_pattern_variables directly to preserve original extension
                    filename = self.substitute_output_pattern_variables(
                        effective_pattern, substitutions
                    )

                    # Debug logging
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Generated filename: {filename} from pattern: {effective_pattern} with substitutions: {substitutions}",
                        dut_id,
                    )
                else:
                    filename = f"{function_tag}.bin"

            if is_binary:
                # For binary data, write directly to file bypassing the text-based file system
                # Use the filename that was already generated above
                final_filename = filename

                # Get the full file path using the logger's directory structure
                # Use the actual collector_id (like "R3") for proper directory structure
                group = self._get_collector_group(collector_id)
                if self.logger:
                    # Use the logger's create_collector_log_file to get the proper directory structure
                    temp_file_path = await self.logger.create_collector_log_file(
                        dut_id, group, collector_id, final_filename
                    )
                    file_path = temp_file_path.parent / final_filename

                    # Write binary data directly
                    with open(file_path, "wb") as f:
                        f.write(content)

                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Written binary file: {file_path} ({len(content)} bytes)",
                        dut_id,
                    )
                    file_path = str(file_path)
                else:
                    # Fallback if logger not available
                    file_path = final_filename
            else:
                # For text/JSON data, write normally
                # Use additional_data_pattern if available, otherwise fall back to output_pattern
                effective_pattern = (
                    additional_data_pattern
                    if additional_data_pattern
                    else output_pattern
                )

                # Debug logging to see what's being passed
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Calling write_output_with_generalization with effective_pattern='{effective_pattern}', function_tag='{function_tag}', substitutions={substitutions}",
                    dut_id,
                )
                file_path = await self.write_output_with_generalization(
                    dut_id,
                    collector_id,
                    content,
                    output_pattern=effective_pattern,
                    function_tag=function_tag,  # Use original function_tag, not processed filename
                    substitutions=substitutions,
                )
            return file_path
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Failed to save data to file: {str(e)}",
                dut_id,
            )
            # Log the full exception details for debugging
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Full traceback for file save failure: {traceback.format_exc()}",
                dut_id,
            )
            return None

    async def _execute_with_error_handling(
        self, dut_id: str, operation_name: str, operation_func, *args, **kwargs
    ) -> Dict[str, Any]:
        """
        Common error handling wrapper (DRY pattern).

        Args:
            dut_id: DUT ID.
            operation_name: Operation name.
            operation_func: Operation function.
        """
        try:
            await self._log_runtime(
                "INFO", "RedfishService", f"Starting {operation_name}", dut_id
            )

            result = await operation_func(*args, **kwargs)

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Completed {operation_name} successfully",
                dut_id,
            )

            return result
        except Exception as e:
            await self._log_runtime(
                "ERROR", "RedfishService", f"Failed {operation_name}: {str(e)}", dut_id
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name=operation_name,
                additional_context={"operation_name": operation_name},
            )

    def _is_404_error(self, response: Any) -> bool:
        """
        Check if response indicates a 404 error.

        Args:
            response: Response to check.

        Returns:
            True if response indicates a 404 error.
        """
        if isinstance(response, dict):
            if not response:  # Empty dict {}
                return True
            else:
                error_info = response.get("error", {})
                error_code = error_info.get("code", "")
                error_message = error_info.get("message", "")

                # Check for various 404 error codes and patterns
                return (
                    error_code == "Base.1.12.ResourceMissingAtURI"
                    or error_code == "Base.1.12.ResourceNotFound"
                    or error_code == "Base.1.12.ResourceAtUriUnauthorized"
                    or "404" in str(error_code)
                    or "not found" in error_message.lower()
                    or "missing" in error_message.lower()
                    or "unauthorized" in error_message.lower()
                )
        elif isinstance(response, str):
            # Handle string responses (like "HTTP 404: {...}")
            response_lower = response.lower()

            # First check if it's a server error (5xx) - these are NOT 404s
            if any(
                f"http {code}" in response_lower
                for code in [
                    "500",
                    "501",
                    "502",
                    "503",
                    "504",
                    "505",
                    "520",
                    "521",
                    "522",
                    "523",
                    "524",
                ]
            ):
                return False

            # Then check for actual 404 patterns
            return (
                "http 404" in response_lower
                or "not found" in response_lower
                or "missing" in response_lower
                or "unauthorized" in response_lower
                or "resourcemissingaturi" in response_lower
            )
        return False

    def _matches_filter(
        self, data: Dict[str, Any], filter_criteria: Dict[str, Any]
    ) -> bool:
        """
        Check if data matches filter criteria.

        Args:
            data: Data to check.
            filter_criteria: Filter criteria dictionary.

        Returns:
            True if data matches all filter criteria.
        """
        for key, expected_value in filter_criteria.items():
            if key not in data:
                return False
            if data[key] != expected_value:
                return False
        return True

    def _find_pattern_matches(self, data: Dict[str, Any], pattern: str) -> List[str]:
        """
        Find pattern matches in data.

        Args:
            data: Data to search.
            pattern: Pattern to match.

        Returns:
            List of matching paths.
        """
        matches = []

        def search_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    search_recursive(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]"
                    search_recursive(item, current_path)
            elif isinstance(obj, str):
                if re.search(pattern, obj, re.IGNORECASE):
                    matches.append(f"{path}: {obj}")

        search_recursive(data)
        return matches

    async def _get_platform_info(self, dut_id: str) -> Dict[str, Any]:
        """
        Get platform information.

        Args:
            dut_id: DUT ID.

        Returns:
            Platform information dictionary.
        """
        try:
            # First check DUT config for baseboard type
            dut = self.dut_manager.get_dut(dut_id)
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Platform detection: DUT object type: {type(dut)}",
                dut_id,
            )

            if dut and hasattr(dut, "config"):
                baseboard = dut.config.get("baseboard", "")
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Platform detection: found baseboard '{baseboard}' in DUT config",
                    dut_id,
                )

                if baseboard:
                    # Check if this is a legacy platform
                    legacy_platforms = ["GH200", "Hopper-HGX-8-GPU"]
                    if any(legacy in baseboard for legacy in legacy_platforms):
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"Platform detection: baseboard '{baseboard}' detected as legacy platform",
                            dut_id,
                        )
                        return {"platform_type": baseboard}

                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Platform detection: baseboard '{baseboard}' not in legacy list",
                        dut_id,
                    )
            else:
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Platform detection: DUT config not accessible",
                    dut_id,
                )

            # Fallback: Get root to determine platform
            success, root_data, _ = await self.dispatch_request(dut_id, "GET", "")

            if success:
                # Try to determine platform from root data
                if "Oem" in root_data:
                    return {"platform_type": "OEM"}
                elif "Systems" in root_data:
                    return {"platform_type": "Standard"}
                else:
                    return {"platform_type": "Unknown"}
            else:
                return {"platform_type": "Unknown"}
        except Exception as e:
            await self._log_runtime(
                "ERROR", "RedfishService", f"Failed to get platform info: {e}", dut_id
            )
            return {"platform_type": "Unknown"}

    """
    Task Management 
    """

    async def _append_to_diagnostic_json_array(
        self,
        dut_id: str,
        data: Dict[str, Any],
        function_tag: str,
        file_type: str,  # "diagnostic_responses", "diagnostic_errors", "task_completions"
        collector_id: str,
    ) -> str:
        """
        Append data to a JSON array file, creating the file if it doesn't exist.

        Args:
            dut_id: DUT ID.
            function_tag: Function tag for naming.
            data: Data to append.
            file_type: Type of file (diagnostic_responses, diagnostic_errors, task_completions).
            collector_id: Collector ID.

        Returns:
            Path to the created file.
        """
        try:
            # Generate filename
            filename = f"{file_type}_{function_tag}.json"

            # Use the existing logger infrastructure to get the proper DUT directory
            # This ensures we're in the correct collector folder structure
            # CRITICAL FIX: Use original collector ID for file path determination to prevent cross-contamination
            original_collector_id = await self._get_original_collector_id(
                dut_id, collector_id
            )
            file_collector_id = (
                original_collector_id
                if original_collector_id != "unknown"
                else collector_id
            )

            group = self._get_collector_group(file_collector_id)
            if self.logger:
                # Get the proper file path using the logger's directory structure
                temp_file_path = await self.logger.create_collector_log_file(
                    dut_id, group, file_collector_id, filename
                )
                file_path = temp_file_path.parent / filename
            else:
                # Fallback if logger not available
                file_path = Path(filename)

            # Load existing data or create new array
            existing_data = []
            if file_path.exists():
                try:
                    with open(file_path, "r") as f:
                        existing_data = json.load(f)
                        if not isinstance(existing_data, list):
                            existing_data = []  # Reset if not an array
                except (json.JSONDecodeError, IOError):
                    existing_data = []  # Reset on any read error

            # Append new data
            existing_data.append(data)

            # Save updated array
            with open(file_path, "w") as f:
                json.dump(existing_data, f, indent=2, default=str)

            return str(file_path)

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Failed to append to {file_type} array: {str(e)}",
                dut_id,
            )
            # Fallback to individual file using existing infrastructure
            return await self._save_data_to_file_with_pattern(
                dut_id,
                data,
                function_tag,
                output_pattern=f"{file_type}_{function_tag}_fallback.json",
                substitutions={},
                collector_id=collector_id,
            )

    async def _wait_for_task_completion(
        self,
        dut_id: str,
        task_id: str,
        max_retries: int = 50,
        function_tag: str = "",
        entity_context: Dict[str, Any] = None,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        """
        Wait for a Redfish task to complete.

        Args:
            dut_id: DUT ID.
            task_id: Task ID.
            max_retries: Maximum retry attempts.
            entity_context: Optional entity context.
            **kwargs: Additional arguments.

        Returns:
            Task completion data or None if failed.
        """
        # Get collector context for better logging
        collector_id = kwargs.get("collector_id", "unknown")
        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"[{collector_id}] === ENTERING _wait_for_task_completion for task {task_id} with max_retries={max_retries} ===",
            dut_id,
        )

        try:
            task_service_uri = self.get_configured_uri(dut_id, "TaskService")
            task_uri = f"{task_service_uri}/Tasks/{task_id}"

            # Calculate timeout
            retry_interval = 30  # seconds
            total_timeout = max_retries * retry_interval

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"[{collector_id}] Starting task monitoring for {task_id} with {max_retries} retries ({total_timeout}s total)",
                dut_id,
            )

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Task monitoring parameters: task_id={task_id}, task_uri={task_uri}, max_retries={max_retries}, retry_interval={retry_interval}",
                dut_id,
            )

            # Initial wait for quick tasks
            await asyncio.sleep(2)

            # Test the task URI first to make sure it's accessible
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Testing task URI accessibility: {task_uri}",
                dut_id,
            )

            test_success, test_response, _ = await self.dispatch_request(
                dut_id, "GET", task_uri, bypass_cache=True
            )

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Task URI test result: success={test_success}, response_type={type(test_response)}",
                dut_id,
            )

            if not test_success:
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"Task URI {task_uri} is not accessible: {test_response}",
                    dut_id,
                )
                return None

            for attempt in range(max_retries):
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"=== STARTING Task monitoring attempt {attempt + 1}/{max_retries} for task {task_id} ===",
                    dut_id,
                )

                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"About to make dispatch_request for task {task_id}, attempt {attempt + 1}",
                    dut_id,
                )

                try:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"=== DISPATCH REQUEST DEBUG START for task {task_id}, attempt {attempt + 1} ===",
                        dut_id,
                    )
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Request details: method=GET, uri={task_uri}, bypass_cache=True",
                        dut_id,
                    )

                    success, response, _ = await self.dispatch_request(
                        dut_id, "GET", task_uri, bypass_cache=True
                    )

                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Dispatch request completed: success={success}, response_type={type(response)}",
                        dut_id,
                    )

                    if success and response:
                        # Safely log response content, avoiding binary data
                        try:
                            if isinstance(response, bytes):
                                response_log = f"Task {task_id} response content: <binary data, {len(response)} bytes>"
                            else:
                                response_log = f"Task {task_id} response content: {json.dumps(response, indent=2)}"
                        except (TypeError, ValueError) as e:
                            response_log = f"Task {task_id} response content: <unable to serialize: {type(response)}, error: {e}>"

                        await self._log_runtime(
                            "INFO", "RedfishService", response_log, dut_id
                        )

                        # Check if we have TaskState in the response
                        task_state = response.get("TaskState", "NOT_FOUND")
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Task {task_id} TaskState: {task_state}",
                            dut_id,
                        )
                    else:
                        await self._log_runtime(
                            "ERROR",
                            "RedfishService",
                            f"Dispatch request failed for task {task_id}, attempt {attempt + 1}: response={response}",
                            dut_id,
                        )

                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"=== DISPATCH REQUEST DEBUG END for task {task_id}, attempt {attempt + 1} ===",
                        dut_id,
                    )
                except Exception as e:
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Exception in dispatch_request for task {task_id}, attempt {attempt + 1}: {str(e)}",
                        dut_id,
                    )
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Exception type: {type(e).__name__}, Exception args: {e.args}",
                        dut_id,
                    )
                    success = False
                    response = None

                if not success:
                    await self._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"Failed to fetch task {task_id} status (attempt {attempt + 1}/{max_retries})",
                        dut_id,
                    )

                    # Check for critical failures that should cause early exit
                    if isinstance(response, str) and any(
                        keyword in response.lower()
                        for keyword in [
                            "unauthorized",
                            "forbidden",
                            "not found",
                            "connection refused",
                            "timeout",
                        ]
                    ):
                        await self._log_runtime(
                            "ERROR",
                            "RedfishService",
                            f"Critical failure detected for task {task_id}: {response}. Exiting task monitoring.",
                            dut_id,
                        )
                        return None

                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Sleeping {retry_interval}s before next attempt for task {task_id}",
                        dut_id,
                    )
                    await asyncio.sleep(retry_interval)
                    continue

                # Log the first response to see what we're getting
                if attempt == 0:
                    # Safely log initial task response, avoiding binary data
                    try:
                        if isinstance(response, bytes):
                            response_log = f"Initial task response for {task_id}: <binary data, {len(response)} bytes>"
                        else:
                            response_log = f"Initial task response for {task_id}: {json.dumps(response, indent=2)}"
                    except (TypeError, ValueError) as e:
                        response_log = f"Initial task response for {task_id}: <unable to serialize: {type(response)}, error: {e}>"

                    await self._log_runtime(
                        "DEBUG", "RedfishService", response_log, dut_id
                    )

                # Save intermediate task status for monitoring progress
                if function_tag and entity_context and success and response:
                    status_data = {
                        "task_id": task_id,
                        "attempt": attempt + 1,
                        "max_retries": max_retries,
                        "task_state": response.get("TaskState", "UNKNOWN"),
                        "task_status": response.get("TaskStatus", ""),
                        "percent_complete": response.get("PercentComplete", ""),
                        "response_data": response,
                        "entity_type": entity_context.get("entity_type", "unknown"),
                        "entity_id": entity_context.get("entity_id", "unknown"),
                        "log_service": entity_context.get("log_service", "unknown"),
                        "timestamp": datetime.now().isoformat(),
                    }
                    await self._append_to_diagnostic_json_array(
                        dut_id,
                        status_data,
                        function_tag,
                        "task_status_updates",
                        kwargs.get("collector_id", "unknown"),
                    )

                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Validating response for task {task_id}, attempt {attempt + 1}: type={type(response)}",
                    dut_id,
                )

                # Validate response
                if not isinstance(response, dict) or "TaskState" not in response:
                    await self._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"Received malformed task response: {response}",
                        dut_id,
                    )
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Sleeping {retry_interval}s before next attempt for task {task_id}",
                        dut_id,
                    )
                    await asyncio.sleep(retry_interval)
                    continue

                try:
                    task_state = response.get("TaskState", "")
                    task_status = response.get("TaskStatus", "")
                    percent_complete = response.get("PercentComplete", "")

                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Task {task_id}, attempt {attempt + 1}: TaskState='{task_state}', TaskStatus='{task_status}', PercentComplete='{percent_complete}'",
                        dut_id,
                    )

                    # Log task state changes as INFO for better visibility
                    if (
                        attempt == 0
                        or task_state != "Running"
                        or percent_complete != "0"
                    ):
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Task {task_id}, attempt {attempt + 1}: TaskState='{task_state}', TaskStatus='{task_status}', PercentComplete='{percent_complete}'",
                            dut_id,
                        )
                except Exception as e:
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Error parsing task state for task {task_id}, attempt {attempt + 1}: {str(e)}",
                        dut_id,
                    )
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Task state parsing error details: type={type(e).__name__}, args={e.args}",
                        dut_id,
                    )
                    # Continue with next attempt
                    await asyncio.sleep(retry_interval)
                    continue

                # Log detailed task information
                task_info = f"TaskState: {task_state}"
                if task_status:
                    task_info += f", TaskStatus: {task_status}"
                if percent_complete:
                    task_info += f", PercentComplete: {percent_complete}%"

                # Log progress every 10 attempts (every 5 minutes)
                if (attempt + 1) % 10 == 0:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Task {task_id} still running - attempt {attempt + 1}/{max_retries} ({task_info})",
                        dut_id,
                    )

                # Also log every 5 attempts for better visibility
                if (attempt + 1) % 5 == 0:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Task {task_id} progress - attempt {attempt + 1}/{max_retries} ({task_info})",
                        dut_id,
                    )

                # Check for completion states
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Checking completion states for task {task_id}, attempt {attempt + 1}: TaskState='{task_state}'",
                    dut_id,
                )

                if task_state == "Completed":
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Task {task_id} completed successfully after {attempt + 1} attempts ({task_info})",
                        dut_id,
                    )
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"EXITING _wait_for_task_completion for task {task_id} - COMPLETED",
                        dut_id,
                    )

                    # Save task completion to array-based file
                    if function_tag and entity_context:
                        completion_data = {
                            "task_id": task_id,
                            "final_state": task_state,
                            "total_attempts": attempt + 1,
                            "max_retries": max_retries,
                            "completion_response": response,
                            "entity_type": entity_context.get("entity_type", "unknown"),
                            "entity_id": entity_context.get("entity_id", "unknown"),
                            "log_service": entity_context.get("log_service", "unknown"),
                            "timestamp": datetime.now().isoformat(),
                        }
                        await self._append_to_diagnostic_json_array(
                            dut_id,
                            completion_data,
                            function_tag,
                            "task_completions",
                            kwargs.get("collector_id", "unknown"),
                        )

                    return response
                elif task_state in [
                    "Succeeded",
                    "Done",
                ]:  # Additional success states
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Task completed with alternate success state: {task_state} after {attempt + 1} attempts ({task_info})",
                        dut_id,
                    )
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"EXITING _wait_for_task_completion for task {task_id} - SUCCEEDED/DONE",
                        dut_id,
                    )

                    # Save task completion to array-based file
                    if function_tag and entity_context:
                        completion_data = {
                            "task_id": task_id,
                            "final_state": task_state,
                            "total_attempts": attempt + 1,
                            "max_retries": max_retries,
                            "completion_response": response,
                            "entity_type": entity_context.get("entity_type", "unknown"),
                            "entity_id": entity_context.get("entity_id", "unknown"),
                            "log_service": entity_context.get("log_service", "unknown"),
                            "timestamp": datetime.now().isoformat(),
                        }
                        await self._append_to_diagnostic_json_array(
                            dut_id,
                            completion_data,
                            function_tag,
                            "task_completions",
                            kwargs.get("collector_id", "unknown"),
                        )

                    return response
                elif task_state in ["Completed with Warnings"]:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Task {task_id} completed with warnings after {attempt + 1} attempts ({task_info})",
                        dut_id,
                    )
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"EXITING _wait_for_task_completion for task {task_id} - COMPLETED WITH WARNINGS",
                        dut_id,
                    )

                    # Save task completion to array-based file
                    if function_tag and entity_context:
                        completion_data = {
                            "task_id": task_id,
                            "final_state": task_state,
                            "total_attempts": attempt + 1,
                            "max_retries": max_retries,
                            "completion_response": response,
                            "entity_type": entity_context.get("entity_type", "unknown"),
                            "entity_id": entity_context.get("entity_id", "unknown"),
                            "log_service": entity_context.get("log_service", "unknown"),
                            "timestamp": datetime.now().isoformat(),
                        }
                        await self._append_to_diagnostic_json_array(
                            dut_id,
                            completion_data,
                            function_tag,
                            "task_completions",
                            kwargs.get("collector_id", "unknown"),
                        )

                    return response

                # Check for terminal failure states
                if task_state in ["Failed", "Cancelled", "Exception", "Aborted"]:
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Task {task_id} in terminal failure state: {task_state}",
                        dut_id,
                    )
                    # Log detailed error information
                    error_details = []
                    if "Messages" in response:
                        try:
                            messages = response["Messages"]
                            if isinstance(messages, bytes):
                                error_details.append(
                                    f"Messages: <binary data, {len(messages)} bytes>"
                                )
                            else:
                                error_details.append(
                                    f"Messages: {json.dumps(messages, indent=2)}"
                                )
                        except Exception:
                            error_details.append(
                                "Messages: [Error serializing messages]"
                            )
                    if task_status:
                        error_details.append(f"TaskStatus: {task_status}")
                    if percent_complete:
                        error_details.append(f"PercentComplete: {percent_complete}%")

                    error_msg = (
                        "\n".join(error_details)
                        if error_details
                        else "No additional details"
                    )
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Task {task_id} failed with state: {task_state}\nDetails: {error_msg}",
                        dut_id,
                    )
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"EXITING _wait_for_task_completion for task {task_id} - FAILED",
                        dut_id,
                    )
                    return None

                # Still running, wait 30 seconds
                if attempt < max_retries - 1:  # Don't sleep on last attempt
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Task {task_id} still running, sleeping {retry_interval}s before next attempt (attempt {attempt + 1}/{max_retries})",
                        dut_id,
                    )
                    await asyncio.sleep(retry_interval)
                else:
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Task {task_id} last attempt ({attempt + 1}/{max_retries}), not sleeping",
                        dut_id,
                    )

            # Timeout after max retries
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Task {task_id} loop completed, checking for timeout",
                dut_id,
            )
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Task {task_id} timed out after {total_timeout} seconds ({max_retries} retries)",
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"EXITING _wait_for_task_completion for task {task_id} - TIMEOUT",
                dut_id,
            )
            return None

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception in task monitoring: {str(e)}",
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"EXITING _wait_for_task_completion for task {task_id} - EXCEPTION",
                dut_id,
            )
            return None

    async def _get_dump_location(
        self, task_response: Dict[str, Any], dut_id: str = None, attachment: bool = True
    ) -> Optional[str]:
        """
        Get the log dump location for a redfish task.

        Args:
            task_response: Task response data.
            dut_id: Optional DUT ID.
            attachment: Whether to append attachment path.

        Returns:
            Dump location URI or None if not found.
        """
        try:
            # Get location from HttpHeaders
            resp_headers = task_response.get("Payload", {}).get("HttpHeaders", [])
            dump_location = ""

            for header in resp_headers:
                if header.startswith("Location:"):
                    dump_location = header.lstrip("Location:").strip()
                    if attachment:
                        # Fetch the URI to get AdditionalDataURI
                        success, resp, _ = await self.dispatch_request(
                            dut_id, "GET", dump_location, bypass_cache=True
                        )
                        if success and resp.get("AdditionalDataURI"):
                            dump_location = resp.get("AdditionalDataURI")
                        else:
                            await self._log_runtime(
                                "WARN",
                                "RedfishService",
                                "Could not fetch attachment URI. Returning default value",
                                dut_id,
                            )
                            # Fall back to previous default
                            if not dump_location.endswith("/attachment"):
                                dump_location = dump_location + "/attachment"
                    break

            return dump_location if dump_location else None
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception getting dump location: {str(e)}",
                dut_id,
            )
            return None

    async def _try_fallback_payloads(
        self,
        dut_id: str,
        entity_type: str,
        entity_id: str,
        log_service: str,
        default_payload: Dict[str, Any],
        fallback_payloads: Optional[List[Dict[str, Any]]],
        function_tag: str,
        output_pattern: str,
        status_list: List[bool],
        output_files: List[str],
        collector_id: str = "",
        diagnostic_type: str = None,
        fallback_index: int = None,
        collection_level: str = "L3",
        **kwargs,
    ) -> bool:
        """
        Try fallback payloads in order until one succeeds.

        Args:
            dut_id: DUT ID.
            entity_id: Entity ID.
            entity_type: Entity type.
            uri_template: URI template.
            fallback_payloads: List of fallback payloads to try.
            **kwargs: Additional arguments.

        Returns:
            True if any fallback succeeded.
        """
        try:
            # Try fallback payloads first if provided
            if fallback_payloads:
                for i, fallback_payload in enumerate(fallback_payloads):
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Trying fallback payload {i+1}/{len(fallback_payloads)} for {entity_type} {entity_id}",
                        dut_id,
                    )

                    status, output_file = await self._execute_redfish_dump_task(
                        dut_id=dut_id,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        log_service=log_service,
                        payload=fallback_payload,
                        function_tag=function_tag,
                        fallback_index=i,
                        **kwargs,
                    )
                    status_list.append(status)
                    if output_file:
                        output_files.append(output_file)

                    if status:
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Fallback payload {i+1} succeeded for {entity_type} {entity_id}",
                            dut_id,
                        )
                        return True

            # If no fallback payloads or all failed, try default payload
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Trying default payload for {entity_type} {entity_id}",
                dut_id,
            )

            status, output_file = await self._execute_redfish_dump_task(
                dut_id=dut_id,
                entity_type=entity_type,
                entity_id=entity_id,
                log_service=log_service,
                payload=default_payload,
                function_tag=function_tag,
                **kwargs,
            )
            status_list.append(status)
            if output_file:
                output_files.append(output_file)

            return status

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception in fallback payload execution: {str(e)}",
                dut_id,
            )
            return False

    """
    Utility Functions 
    """

    def _extract_output_pattern_params(
        self, kwargs: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        """Extract output_pattern and substitutions from kwargs, return filtered kwargs

        Args:
            kwargs: Original kwargs dictionary

        Returns:
            Tuple of (output_pattern, substitutions, filtered_kwargs)
        """
        output_pattern = kwargs.get("output_pattern")
        substitutions = kwargs.get("substitutions", {})

        # Remove output_pattern and substitutions from kwargs to avoid conflicts
        filtered_kwargs = {
            k: v
            for k, v in kwargs.items()
            if k not in ["output_pattern", "substitutions"]
        }

        return output_pattern, substitutions, filtered_kwargs

    async def _save_data_with_common_pattern(
        self,
        dut_id: str,
        data: Any,
        function_tag: str,
        output_pattern: str = None,
        substitutions: Dict[str, Any] = None,
        **kwargs,
    ) -> Optional[str]:
        """Common data saving function with pattern handling

        Args:
            dut_id: DUT identifier
            data: Data to save
            function_tag: Function tag for file naming
            output_pattern: Output pattern for filename
            substitutions: Variable substitutions for pattern
            **kwargs: Additional parameters for _save_data_to_file_with_pattern

        Returns:
            File path if successful, None otherwise
        """
        try:
            file_path = await self._save_data_to_file_with_pattern(
                dut_id,
                data,
                function_tag,
                output_pattern=output_pattern,
                substitutions=substitutions or {},
                **kwargs,
            )
            return file_path
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Failed to save data for {function_tag}: {str(e)}",
                dut_id,
            )
            return None

    def _extract_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """
        Extract nested value from dictionary using dot notation path.

        Args:
            data: Dictionary to search.
            path: Dot-notation path to value.

        Returns:
            Extracted value or None if not found.
        """
        # Handle special case for @odata.id pattern - this is a common Redfish pattern
        if ".@odata.id" in path:
            # Split on ".@odata.id" to get the parent path
            parts = path.split(".@odata.id")
            if len(parts) == 2:
                parent_key = parts[0]
                parent_data = self._extract_nested_value(data, parent_key)
                if isinstance(parent_data, dict):
                    return parent_data.get("@odata.id")
            return None

        # For other cases, use the original dot notation approach
        keys = path.split(".")
        current = data

        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None

        return current

    async def _get_dut_config(self, dut_id: str) -> Dict[str, Any]:
        """
        Get DUT configuration from the DUT manager.

        Args:
            dut_id: DUT ID.

        Returns:
            DUT configuration dictionary.
        """
        try:
            if hasattr(self, "dut_manager") and self.dut_manager:
                return self.dut_manager.get_dut_config(dut_id)
            return {}
        except Exception as e:
            await self._log_runtime(
                "WARN", "RedfishService", f"Failed to get DUT config: {str(e)}", dut_id
            )
            return {}

    def _extract_entity_id_from_uri(
        self, uri: str, entity_type: Optional[str] = None
    ) -> Union[Dict[str, str], str]:
        """
        Extract entity identifiers from a Redfish URI.

        Behavior:
        - If entity_type is provided, return a single ID string for that entity type
          (e.g., "Chassis" -> chassis_id string). Falls back to "unknown" if not found.
        - If entity_type is None, return a dict mapping known entity placeholders
          to IDs using ENTITY_URI_TO_PLACEHOLDER.

        Args:
            uri: Redfish URI (e.g., /redfish/v1/Chassis/HGX_GPU_0/LogServices/XID/Entries)
            entity_type: Optional entity type name (e.g., "Chassis", "Systems", "Managers")

        Returns:
            Union of:
            - str: Extracted entity ID when entity_type is provided
            - Dict[str, str]: Mapping of entity placeholders to IDs when entity_type is None
        """
        # When a specific entity type is requested, return a single ID string
        if entity_type:
            # Handle common Redfish entity collections explicitly
            if entity_type in ("Chassis", "Systems", "Managers"):
                token = f"/{entity_type}/"
                if token in uri:
                    parts = uri.split(token)
                    if len(parts) > 1:
                        entity_id = parts[1].split("/")[0]
                        if entity_id:
                            return entity_id

            # Generic fallback: find the segment after the entity type
            uri_parts = uri.split("/")
            for i, part in enumerate(uri_parts):
                if part.lower() == entity_type.lower() and i + 1 < len(uri_parts):
                    return uri_parts[i + 1]

            # If all else fails, return a default string
            return "unknown"

        # No entity_type: return a dict mapping placeholders to IDs
        entity_ids: Dict[str, str] = {}

        for entity_path, entity_var in ENTITY_URI_TO_PLACEHOLDER.items():
            if entity_path in uri:
                # Extract ID from URI (e.g., /Chassis/HGX_GPU_0/... -> HGX_GPU_0)
                parts = uri.split(entity_path)
                if len(parts) > 1:
                    # Get the part after entity_path and extract the ID
                    remaining = parts[1]
                    entity_id = remaining.split("/")[0]
                    if entity_id:
                        entity_ids[entity_var] = entity_id

        return entity_ids

    async def _log_collection_start(self, dut_id: str, collection_type: str, uri: str):
        """Log collection start

        Args:
            dut_id: DUT identifier
            collection_type: Type of collection
            uri: URI being collected from
        """
        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"Starting {collection_type} collection from: {uri}",
            dut_id,
        )

    async def _log_collection_success(
        self, dut_id: str, collection_type: str, uri: str, file_path: str
    ):
        """Log successful collection

        Args:
            dut_id: DUT identifier
            collection_type: Type of collection
            uri: URI that was collected from
            file_path: Path of saved file
        """
        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"Successfully collected {collection_type} from {uri} -> {file_path}",
            dut_id,
        )

    async def _log_collection_failure(
        self, dut_id: str, collection_type: str, uri: str, error: str
    ):
        """Log collection failure

        Args:
            dut_id: DUT identifier
            collection_type: Type of collection
            uri: URI that failed
            error: Error message
        """
        await self._log_runtime(
            "ERROR",
            "RedfishService",
            f"Failed {collection_type} collection from {uri}: {error}",
            dut_id,
        )

    async def _get_log_service_uris_legacy(
        self, dut_id: str, entity_type: str, log_service_filter: Dict[str, Any]
    ) -> List[str]:
        """
        Get log service URIs for legacy platforms.

        Args:
            dut_id: DUT ID.
            entity_type: Type of entity (Systems, Chassis, etc).
            log_service_filter: Filter criteria for log services.

        Returns:
            List of log service URIs.
        """
        try:
            # Get entities first
            entity_uri = self.get_configured_uri(dut_id, entity_type)
            success, entities_response, _ = await self.dispatch_request(
                dut_id, "GET", entity_uri
            )

            if not success:
                return []

            entities = entities_response.get("Members", [])
            log_service_uris = []

            for entity in entities:
                entity_id = entity.get("@odata.id", "").split("/")[-1]

                # Get log services for this entity
                entity_base_uri = self.get_configured_uri(dut_id, entity_type)
                log_services_uri = f"{entity_base_uri}/{entity_id}/LogServices"
                success, log_services_response, _ = await self.dispatch_request(
                    dut_id, "GET", log_services_uri
                )

                if success:
                    log_services = log_services_response.get("Members", [])

                    for log_service in log_services:
                        service_id = log_service.get("@odata.id", "").split("/")[-1]

                        # Check if this service matches the filter
                        id_contains = log_service_filter.get("id_contains", [])
                        if isinstance(id_contains, dict):
                            id_contains = id_contains.get("anyOf", [])

                        if any(contains in service_id for contains in id_contains):
                            entity_base_uri = self.get_configured_uri(
                                dut_id, entity_type
                            )
                            entries_uri = f"{entity_base_uri}/{entity_id}/LogServices/{service_id}/Entries"
                            log_service_uris.append(entries_uri)

            return log_service_uris

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Failed to get legacy log service URIs: {str(e)}",
                dut_id,
            )
            return []

    async def _find_filtered_entries_in_source_logs(
        self,
        dut_id: str,
        source_logs: str,
        entry_filter: Dict[str, Any],
        processing_config: Dict[str, Any] = None,
    ) -> List[Dict[str, Any]]:
        """
        Find filtered entries in source log files.

        Args:
            dut_id: DUT ID.
            source_logs: Source log file pattern.
            entry_filter: Filter criteria for entries.
            processing_config: Optional processing configuration.

        Returns:
            List of filtered log entries.
        """
        try:
            # Get the current output directory from the logger
            output_dir = await self._get_output_directory(dut_id)

            if not output_dir or output_dir == "/tmp":
                await self._log_runtime(
                    "WARN",
                    "RedfishService",
                    "Using fallback output directory, may not find expected files",
                    dut_id,
                )

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Current working directory: {os.getcwd()}, output_dir: {output_dir}",
                dut_id,
            )

            # Get possible source directories from processing config
            possible_source_dirs = []
            if processing_config and "possible_source_directories" in processing_config:
                possible_source_dirs = processing_config["possible_source_directories"]
            else:
                # Fallback to default patterns
                possible_source_dirs = [
                    f"Redfish_{source_logs}",
                    f"Redfish_{source_logs.replace('_', '')}",
                ]

            # Build full paths
            full_source_dirs = [
                os.path.join(output_dir, dut_id, "redfish", source_dir)
                for source_dir in possible_source_dirs
            ]

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Looking for source logs in directories: {full_source_dirs}",
                dut_id,
            )

            source_log_dir = None
            for full_dir in full_source_dirs:
                if os.path.exists(full_dir):
                    source_log_dir = full_dir
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Found source log directory: {source_log_dir}",
                        dut_id,
                    )
                    break

            if not source_log_dir:
                await self._log_runtime(
                    "WARN",
                    "RedfishService",
                    f"Source log directory not found. Tried: {possible_source_dirs}",
                    dut_id,
                )
                return []

            all_filtered_entries = []

            # List all files in source log directory
            try:
                source_files = os.listdir(source_log_dir)
            except Exception as e:
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"Error listing source log directory: {str(e)}",
                    dut_id,
                )
                return []

            # Process each JSON file that looks like a log file
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Found {len(source_files)} source files to process",
                dut_id,
            )

            for filename in source_files:
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Processing source file: {filename}",
                    dut_id,
                )

                if not filename.endswith(".json") or "_additional_data" in filename:
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Skipping {filename}: not a JSON file or is additional data file",
                        dut_id,
                    )
                    continue

                if "eventlog" not in filename.lower():
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Skipping {filename}: does not contain 'eventlog'",
                        dut_id,
                    )
                    continue

                file_path = os.path.join(source_log_dir, filename)

                try:
                    with open(file_path, "r") as f:
                        log_data = json.load(f)

                    # Validate basic JSON structure
                    if not isinstance(log_data, dict) or "Members" not in log_data:
                        continue

                    if not isinstance(log_data["Members"], list):
                        continue

                    # Filter entries based on criteria
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Processing {len(log_data['Members'])} entries from {filename}",
                        dut_id,
                    )

                    for entry in log_data["Members"]:
                        if self._entry_matches_filter(entry, entry_filter):
                            all_filtered_entries.append(entry)
                            await self._log_runtime(
                                "DEBUG",
                                "RedfishService",
                                f"Found matching entry with ID: {entry.get('Id', 'unknown')}",
                                dut_id,
                            )

                except Exception as e:
                    await self._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"Error processing source log file {filename}: {str(e)}",
                        dut_id,
                    )
                    continue

            return all_filtered_entries

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Failed to find filtered entries in source logs: {str(e)}",
                dut_id,
            )
            return []

    def _entry_matches_filter(
        self, entry: Dict[str, Any], entry_filter: Dict[str, Any]
    ) -> bool:
        """Check if an entry matches the filter criteria

        Supports multiple filter types:
        - "exists": Check if field exists and is not None/empty
        - "equals": Exact value match (default)
        - "contains": String contains match
        - "regex": Regular expression match
        - "in": Value is in list
        - "not_in": Value is not in list
        - "greater_than": Numeric comparison
        - "less_than": Numeric comparison
        - "greater_than_equal": Numeric comparison
        - "less_than_equal": Numeric comparison
        """
        try:
            for filter_key, filter_config in entry_filter.items():
                entry_value = entry.get(filter_key)

                # Handle simple string value (backward compatibility)
                if isinstance(filter_config, str):
                    if filter_config == "exists":
                        # Check if the field exists and is not None/empty
                        if entry_value is None or entry_value == "":
                            return False
                    else:
                        # Exact value match (default behavior)
                        if entry_value != filter_config:
                            return False
                    continue

                # Handle filter object with operator
                if isinstance(filter_config, dict):
                    operator = filter_config.get("operator", "equals")
                    value = filter_config.get("value")

                    if operator == "exists":
                        if entry_value is None or entry_value == "":
                            return False
                    elif operator == "equals":
                        if entry_value != value:
                            return False
                    elif operator == "contains":
                        if not isinstance(entry_value, str) or value not in entry_value:
                            return False
                    elif operator == "regex":
                        if not isinstance(entry_value, str) or not re.search(
                            value, entry_value
                        ):
                            return False
                    elif operator == "in":
                        if entry_value not in value:
                            return False
                    elif operator == "not_in":
                        if entry_value in value:
                            return False
                    elif operator == "greater_than":
                        if (
                            not isinstance(entry_value, (int, float))
                            or entry_value <= value
                        ):
                            return False
                    elif operator == "less_than":
                        if (
                            not isinstance(entry_value, (int, float))
                            or entry_value >= value
                        ):
                            return False
                    elif operator == "greater_than_equal":
                        if (
                            not isinstance(entry_value, (int, float))
                            or entry_value < value
                        ):
                            return False
                    elif operator == "less_than_equal":
                        if (
                            not isinstance(entry_value, (int, float))
                            or entry_value > value
                        ):
                            return False
                    else:
                        # Unknown operator, default to exact match
                        if entry_value != value:
                            return False
                else:
                    # Fallback to exact match
                    if entry_value != filter_config:
                        return False

            return True

        except Exception:
            return False

    async def _execute_fallback_collection(
        self,
        dut_id: str,
        fallback_config: Dict[str, Any],
        function_tag: str,
        processing_config: Dict[str, Any] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Execute fallback collection when source logs are not found.

        Args:
            dut_id: DUT ID.
            fallback_config: Fallback configuration.
            function_tag: Function tag.
            processing_config: Optional processing configuration.
            **kwargs: Additional arguments.

        Returns:
            Collection result dictionary.
        """
        try:
            # Get collector context for better logging
            collector_id = kwargs.get("collector_id", function_tag)

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Executing fallback collection: {fallback_config.get('collection_type', 'unknown')}",
                dut_id,
            )

            # Extract fallback configuration
            collection_type = fallback_config.get("collection_type", "paginated")
            entity_type = fallback_config.get("entity_type", "Systems")
            log_service = fallback_config.get("log_service", "EventLog")
            fallback_function_tag = fallback_config.get(
                "function_tag", "fallback_collection"
            )
            additional_data_callback = fallback_config.get(
                "additional_data_callback", False
            )
            additional_data_pattern = fallback_config.get("additional_data_pattern", "")
            collection_level_handling = fallback_config.get(
                "collection_level_handling", {}
            )
            output_pattern = fallback_config.get("output_pattern", "")

            # Execute the fallback collection using the unified function
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Fallback collection: function_tag='{fallback_function_tag}', entity_type='{entity_type}', log_service='{log_service}'",
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Fallback collection config: {fallback_config}",
                dut_id,
            )
            # Add collector_id to the fallback config so the logger can create the correct directory
            # Use the source_collector from the processing_config as the collector_id
            fallback_config_with_id = fallback_config.copy()
            fallback_config_with_id["collector_id"] = processing_config.get(
                "source_collector", "R1"
            )

            return await self.collect_redfish_unified(dut_id, **fallback_config_with_id)

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Fallback collection failed: {str(e)}",
                dut_id,
            )
            return {
                "success": False,
                "reason": f"Fallback collection failed: {str(e)}",
                "output_files": [],
            }

    async def _execute_redfish_dump_task_direct(
        self,
        dut_id: str,
        uri: str,
        payload: Dict[str, Any],
        function_tag: str,
        **kwargs,
    ) -> Tuple[bool, Optional[str]]:
        """
        Execute a Redfish dump task using direct URI (more flexible).

        Args:
            dut_id: DUT ID.
            uri: Direct URI for the dump task.
            payload: Payload for the POST request.
            function_tag: Function tag for naming.
            **kwargs: Additional arguments.

        Returns:
            Tuple of (success, output_file_path).
        """
        try:
            # Extract parameters from kwargs
            output_pattern = kwargs.get("output_pattern", "")
            diagnostic_type = kwargs.get("diagnostic_type")
            max_retries = kwargs.get("max_retries", 50)

            # Use the URI directly without parsing
            dump_uri = uri

            # Get DUT for full URI logging
            dut = self.dut_manager.get_dut(dut_id)
            full_dump_uri = dut.normalize_redfish_uri(dump_uri)

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Executing direct URI dump task: POST {full_dump_uri}",
                dut_id,
            )

            # Save the initial request payload
            diagnostic_responses = []

            # Initiate the dump task using direct URI
            success, response, status_code = await self.dispatch_request(
                dut_id, "POST", dump_uri, payload, bypass_cache=True
            )

            if success and response:
                diagnostic_responses.append(
                    {
                        "uri": dump_uri,
                        "payload": payload,
                        "response": response,
                        "status_code": status_code,
                        "timestamp": datetime.now().isoformat(),
                    }
                )

                # Handle the response similar to the original method
                if isinstance(response, dict) and "@odata.id" in response:
                    task_id = response["@odata.id"].split("/")[-1]
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Direct URI dump task initiated successfully: {task_id}",
                        dut_id,
                    )

                    # Save diagnostic responses using the same method as original
                    output_file = await self._append_to_diagnostic_json_array(
                        dut_id,
                        diagnostic_responses[0],  # Use the first response
                        function_tag,
                        "diagnostic_responses",
                        kwargs.get("collector_id", "R40"),
                    )

                    return True, output_file
                else:
                    error_response = {
                        "success": False,
                        "reason": f"Direct URI dump task response missing @odata.id: {response}",
                        "context": {
                            "request_uri": dump_uri,
                            "request_payload": payload,
                            "response_data": response,
                            "status_code": status_code,
                        },
                    }
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        f"{error_response}",
                        dut_id,
                    )

                    return False, None
            else:
                # Include request details in the error response for better debugging
                error_response = {
                    "success": False,
                    "reason": f"Failed to initiate direct URI dump task: {response}",
                    "context": {
                        "request_uri": dump_uri,
                        "request_payload": payload,
                        "response_data": response,
                        "status_code": status_code,
                    },
                }
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return False, None

        except Exception as e:
            # Include request details in the error response for better debugging
            error_response = {
                "success": False,
                "reason": f"Exception in direct URI dump task: {str(e)}",
                "context": {
                    "request_uri": dump_uri,
                    "request_payload": payload,
                    "exception": str(e),
                },
            }
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"{error_response}",
                dut_id,
            )
            return False, None

    async def _execute_redfish_dump_task(
        self,
        dut_id: str,
        entity_type: str,
        entity_id: str,
        log_service: str,
        payload: Dict[str, Any],
        function_tag: str,
        **kwargs,
    ) -> Tuple[bool, Optional[str]]:
        """
        Execute a Redfish dump task and collect the result.

        Args:
            dut_id: DUT ID.
            entity_type: Type of entity (Systems, Chassis, etc).
            entity_id: Entity ID.
            log_service: Log service name.
            payload: Payload for the POST request.
            function_tag: Function tag for naming.
            **kwargs: Additional arguments.

        Returns:
            Tuple of (success, output_file_path).
        """
        try:
            # Extract parameters from kwargs
            output_pattern = kwargs.get("output_pattern", "")
            diagnostic_type = kwargs.get("diagnostic_type")
            collector_id = kwargs.get(
                "collector_id", "R3"
            )  # Default to R3 for R3 collector
            fallback_index = kwargs.get("fallback_index")
            device_id = kwargs.get("device_id")
            device_type_name = kwargs.get("device_type_name")

            # Get timeout from collector definition and DUT config
            collector_def = kwargs.get("collector_def", {})
            dut_config = self.dut_manager.get_dut_config(dut_id)
            tool_config = self.orchestrator.config_manager.get_tool_config()
            timeout_seconds = get_collector_timeout(
                collector_id, collector_def, dut_config, 1500, tool_config
            )

            # Calculate retries based on timeout
            retry_interval = 30  # seconds, default value
            max_retries = int((timeout_seconds + 28) / retry_interval)

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Using timeout of {timeout_seconds} seconds ({max_retries} retries at {retry_interval}s intervals) for {entity_type} {entity_id}",
                dut_id,
            )

            # Initiate the dump task
            # Some implementations require the Actions segment; others (e.g., R43) do not.
            use_actions_segment = kwargs.get("use_actions_segment", True)
            if use_actions_segment:
                dump_uri = f"{entity_type}/{entity_id}/LogServices/{log_service}/Actions/LogService.CollectDiagnosticData"
            else:
                dump_uri = f"{entity_type}/{entity_id}/LogServices/{log_service}/LogService.CollectDiagnosticData"

            # Get DUT for full URI logging
            dut = self.dut_manager.get_dut(dut_id)
            full_dump_uri = dut.normalize_redfish_uri(dump_uri)

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Initiating diagnostic data collection: POST {full_dump_uri}",
                dut_id,
            )

            # Save the initial request payload
            # Save the diagnostic request to array-based file
            request_data = {
                "request_uri": dump_uri,
                "full_uri": full_dump_uri,
                "payload": payload,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "log_service": log_service,
                "step": "request",
                "timestamp": datetime.now().isoformat(),
            }
            request_file_path = await self._append_to_diagnostic_json_array(
                dut_id,
                request_data,
                function_tag,
                "diagnostic_requests",
                collector_id,
            )

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Saved diagnostic request to: {request_file_path}",
                dut_id,
            )

            success, response, _ = await self.dispatch_request(
                dut_id, "POST", dump_uri, payload, bypass_cache=True
            )

            # Create a properly structured JSON response object
            # Handle response data - if it's already a dict, use it directly; otherwise try to parse it
            response_data = response
            if not isinstance(response, dict):
                try:
                    # Try to parse as JSON if it's a string
                    if isinstance(response, str):
                        response_data = json.loads(response)
                    else:
                        response_data = {"raw_response": str(response)}
                except (json.JSONDecodeError, TypeError):
                    response_data = {"raw_response": str(response)}

            structured_response = {
                "request_uri": dump_uri,
                "request_payload": payload,
                "response_status": "success" if success else "failure",
                "response_data": response_data,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "log_service": log_service,
                "step": "initial_response",
                "timestamp": datetime.now().isoformat(),
            }

            # Save the structured response to array-based file
            response_file_path = await self._append_to_diagnostic_json_array(
                dut_id,
                structured_response,
                function_tag,
                "diagnostic_responses",
                collector_id,
            )

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Saved initial response to: {response_file_path}",
                dut_id,
            )

            if not success:
                error_details = await self._extract_error_details_async(
                    response,
                    dut_id,
                    f"Failed to initiate dump task for {entity_type} {entity_id} (URI: {full_dump_uri}): ",
                )

                # Include request details in the error response for better debugging
                error_response = {
                    "success": False,
                    "reason": error_details,
                    "context": {
                        "request_uri": dump_uri,
                        "full_uri": full_dump_uri,
                        "request_payload": payload,
                        "response_data": response_data,
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "log_service": log_service,
                    },
                }
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return False, error_details

            task_id = response.get("Id", "")

            # Apply TASK_ID_PREFIX if configured
            if task_id:
                tool_config = await self.orchestrator.get_dut_specific_tool_config(
                    dut_id
                )
                task_prefix = tool_config.get("TASK_ID_PREFIX", "")
                if task_prefix:
                    task_id = f"{task_prefix}_{task_id}"
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Applied task ID prefix '{task_prefix}' to task ID: {task_id}",
                        dut_id,
                    )

            if not task_id:
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"No task ID returned for {entity_type} {entity_id}",
                    dut_id,
                )

                # Create structured error response for no task ID
                # Handle response data - if it's already a dict, use it directly; otherwise try to parse it
                response_data = response
                if not isinstance(response, dict):
                    try:
                        # Try to parse as JSON if it's a string
                        if isinstance(response, str):
                            response_data = json.loads(response)
                        else:
                            response_data = {"raw_response": str(response)}
                    except (json.JSONDecodeError, TypeError):
                        response_data = {"raw_response": str(response)}

                error_response = {
                    "request_uri": dump_uri,
                    "request_payload": payload,
                    "response_status": "failure",
                    "error_type": "no_task_id",
                    "error_message": "Response did not contain a task ID",
                    "response_data": response_data,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "log_service": log_service,
                    "timestamp": datetime.now().isoformat(),
                }

                # Save the structured error response to array-based file
                error_file_path = await self._append_to_diagnostic_json_array(
                    dut_id,
                    error_response,
                    function_tag,
                    "diagnostic_errors",
                    collector_id,
                )

                # Include request details in the error response for better debugging
                error_response = {
                    "success": False,
                    "reason": "Response did not contain a task ID",
                    "context": {
                        "request_uri": dump_uri,
                        "request_payload": payload,
                        "response_data": response_data,
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "log_service": log_service,
                    },
                }
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return False, "Response did not contain a task ID"

            # Wait for task completion
            entity_context = {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "log_service": log_service,
            }
            task_completed = await self._wait_for_task_completion(
                dut_id,
                task_id,
                max_retries=max_retries,
                function_tag=function_tag,
                entity_context=entity_context,
                collector_id=collector_id,
            )
            if not task_completed:
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"Task {task_id} did not complete for {entity_type} {entity_id}",
                    dut_id,
                )

                # Save the task timeout error to array-based file
                error_data = {
                    "task_id": task_id,
                    "status": "timeout",
                    "max_retries": max_retries,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "log_service": log_service,
                    "error_type": "task_timeout",
                    "timestamp": datetime.now().isoformat(),
                }
                error_file_path = await self._append_to_diagnostic_json_array(
                    dut_id,
                    error_data,
                    function_tag,
                    "diagnostic_errors",
                    collector_id,
                )

                # Include request details in the error response for better debugging
                error_response = {
                    "success": False,
                    "reason": f"Task {task_id} did not complete within timeout",
                    "context": {
                        "request_uri": dump_uri,
                        "request_payload": payload,
                        "task_id": task_id,
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "log_service": log_service,
                        "max_retries": max_retries,
                    },
                }
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return False, "Task {task_id} did not complete within timeout"

            # Task completion is already saved in _wait_for_task_completion method
            # No need to save it again here

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Task completion saved to array-based file",
                dut_id,
            )

            # Get dump location
            dump_location = await self._get_dump_location(task_completed, dut_id)
            if not dump_location:
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"Failed to get dump location for task {task_id}",
                    dut_id,
                )

                # Save the no dump location error to array-based file
                error_data = {
                    "task_completion": task_completed,
                    "error": "no_dump_location",
                    "task_id": task_id,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "log_service": log_service,
                    "error_type": "no_dump_location",
                    "timestamp": datetime.now().isoformat(),
                }
                error_file_path = await self._append_to_diagnostic_json_array(
                    dut_id,
                    error_data,
                    function_tag,
                    "diagnostic_errors",
                    collector_id,
                )

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Saved task completion without dump location to: {error_file_path}",
                    dut_id,
                )

                # Include request details in the error response for better debugging
                error_response = {
                    "success": False,
                    "reason": "Task completed but no dump location found in response",
                    "context": {
                        "request_uri": dump_uri,
                        "request_payload": payload,
                        "task_id": task_id,
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "log_service": log_service,
                        "task_response": task_response,
                    },
                }
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return False, "Task completed but no dump location found in response"

            # Generate output filename with task_id substitution
            if "$task_id" in output_pattern:
                final_output_pattern = output_pattern.replace("$task_id", str(task_id))
            else:
                final_output_pattern = output_pattern

            # Download the dump
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Attempting to download dump from: {dump_location}",
                dut_id,
            )

            success, dump_data, _ = await self.dispatch_request(
                dut_id, "GET", dump_location, get_raw_content=True, bypass_cache=True
            )

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Download attempt result: success={success}, data_size={len(dump_data) if success and isinstance(dump_data, bytes) else 'N/A'}",
                dut_id,
            )

            # Save the dump download response metadata to array-based file
            dump_metadata = {
                "dump_location": dump_location,
                "success": success,
                "data_type": "binary" if success else "error",
                "data_size": (
                    len(dump_data) if success and isinstance(dump_data, bytes) else 0
                ),
                "task_id": task_id,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "log_service": log_service,
                "step": "dump_download",
                "timestamp": datetime.now().isoformat(),
            }
            dump_metadata_file_path = await self._append_to_diagnostic_json_array(
                dut_id,
                dump_metadata,
                function_tag,
                "diagnostic_responses",
                collector_id,
            )

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Saved dump metadata to: {dump_metadata_file_path}",
                dut_id,
            )

            if success:
                # Get device-specific substitutions from kwargs and merge with standard ones
                device_substitutions = kwargs.get("substitutions", {})
                standard_substitutions = {
                    self._get_entity_id_key(
                        entity_type
                    ): entity_id,  # Use correct ID key based on entity_type
                    "task_id": task_id,
                    "diagnostic_type": diagnostic_type or "default",
                }
                # Merge device substitutions with standard ones (device takes precedence)
                merged_substitutions = {
                    **standard_substitutions,
                    **device_substitutions,
                }

                # Write binary data to file
                file_path = await self._save_data_to_file_with_pattern(
                    dut_id,
                    dump_data,
                    function_tag,
                    output_pattern=final_output_pattern,
                    substitutions=merged_substitutions,
                    collector_id=collector_id,
                    is_binary=True,
                )
                return True, file_path
            else:
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"Failed to download dump from {dump_location}",
                    dut_id,
                )

                # Save the dump download error response to array-based file
                error_data = {
                    "dump_data": (
                        dump_data
                        if not isinstance(dump_data, bytes)
                        else {"error": "binary_error_response"}
                    ),
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "log_service": log_service,
                    "error_type": "dump_download_failed",
                    "task_id": task_id,
                    "dump_location": dump_location,
                    "timestamp": datetime.now().isoformat(),
                }
                error_file_path = await self._append_to_diagnostic_json_array(
                    dut_id,
                    error_data,
                    function_tag,
                    "diagnostic_errors",
                    collector_id,
                )

                # Include request details in the error response for better debugging
                error_response = {
                    "success": False,
                    "reason": f"Failed to download dump from {dump_location}",
                    "context": {
                        "request_uri": dump_uri,
                        "request_payload": payload,
                        "task_id": task_id,
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "log_service": log_service,
                        "dump_location": dump_location,
                        "download_success": success,
                    },
                }
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return False, "Failed to download dump from {dump_location}"

        except Exception as e:
            # Include request details in the error response for better debugging
            error_response = {
                "success": False,
                "reason": f"Exception in dump task execution: {str(e)}",
                "context": {
                    "request_uri": dump_uri,
                    "request_payload": payload,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "log_service": log_service,
                    "exception": str(e),
                },
            }
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"{error_response}",
                dut_id,
            )
            return False, "Exception in dump task execution: {str(e)}"

    async def _process_entities_common(
        self, dut_id: str, entities: Dict[str, Any], processor_func, **kwargs
    ) -> List[Any]:
        """
        Common entity processing loop (DRY pattern).

        Args:
            dut_id: DUT ID.
            entities: Entities dictionary with Members list.
            processor_func: Function to process each entity.
            **kwargs: Additional arguments.

        Returns:
            List of processed results.
        """
        results = []
        for entity in entities.get("Members", []):
            entity_id = entity.get("@odata.id", "").split("/")[-1]
            result = await processor_func(dut_id, entity_id, **kwargs)
            results.append(result)
        return results

    def _get_skip_amount(
        self,
        collection_level: str,
        collection_level_handling: Optional[Dict[str, Any]] = None,
    ) -> int:
        """
        Common collection level skip amount calculator (DRY pattern).

        Args:
            collection_level: Collection level (L1, L2, L3).
            collection_level_handling: Optional custom handling configuration.

        Returns:
            Number of entries to skip.
        """
        if collection_level_handling and collection_level in collection_level_handling:
            return collection_level_handling[collection_level]

        defaults = {"L1": 10000, "L2": 15000, "L3": 30000}
        return defaults.get(collection_level, 30000)

    def _get_entity_id_key(self, entity_type: str) -> str:
        """
        Get the correct ID key for variable substitution based on entity_type (DRY pattern).

        Args:
            entity_type: Type of entity (Systems, Managers, etc).

        Returns:
            ID key name for substitutions.
        """
        return "system_id" if entity_type == "Systems" else "manager_id"

    async def dispatch_request(
        self,
        dut_id: str,
        method: str = "GET",
        uri: str = "",
        body: Any = None,
        get_raw_content: bool = False,
        error_context: str = "",
        timeout: int = 300,
        bypass_cache: bool = False,
        retry_count: int = 3,  # Default retry count, can be overridden by collector definition
    ) -> Tuple[bool, Union[dict, str, bytes], dict]:
        """Dispatch Redfish API request to BMC server

        Args:
            dut_id: DUT identifier
            method: HTTP method (GET, POST, etc.)
            uri: Request URI
            body: Request body (for POST/PUT)
            get_raw_content: If True, return raw bytes; if False, return JSON/text
            error_context: Context for error logging
            timeout: Request timeout in seconds
            bypass_cache: If True, bypass caching for this request

        Returns:
            Tuple of (success, response_data, metadata)
        """
        try:
            # Get DUT for URI normalization (for logging full URIs)
            dut = self.dut_manager.get_dut(dut_id)
            full_uri = dut.normalize_redfish_uri(uri)

            # Log request start for better debugging of concurrent requests
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Starting {method} request to {full_uri} (timeout={timeout}s, max_retries={retry_count})",
                dut_id,
            )

            # Use the DUT manager for all Redfish requests (handles URI normalization, auth, retry, etc.)
            success, response, error_details, retry_info = (
                await self.dut_manager.execute_redfish_request(
                    dut_id,
                    method,
                    uri,
                    body,
                    timeout,
                    get_raw_content,
                    bypass_cache,
                    retry_count,
                )
            )

            if not success:
                # Use the detailed error information from DUT manager
                # Include request body/payload in error logs for POST/PUT/PATCH requests
                body_log = ""
                if body and method.upper() in ["POST", "PUT", "PATCH"]:
                    try:
                        body_str = (
                            json.dumps(body, indent=2)
                            if isinstance(body, dict)
                            else str(body)
                        )
                        body_log = f" | Request body: {body_str}"
                    except Exception:
                        body_log = f" | Request body: {body}"

                if error_details:
                    # error_details already contains 'uri' field from DUT manager (normalized)
                    error_uri = error_details.get("uri", full_uri)
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Failed to {error_context} ({method} {error_uri}): HTTP {error_details.get('http_status', 'Unknown')} - {error_details.get('error_message', response)}{body_log}",
                        dut_id,
                    )
                else:
                    error_details = await self._extract_error_details_async(
                        response,
                        dut_id,
                        f"Failed to {error_context} ({method} {full_uri}): {body_log}",
                    )
                return False, response, error_details

            # Log successful binary downloads
            if get_raw_content and isinstance(response, bytes):
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Successfully downloaded {len(response)} bytes for {error_context}",
                    dut_id,
                )

            return True, response, {}

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception in {error_context}: {str(e)}",
                dut_id,
            )
            return False, str(e), {"error": "exception", "message": str(e)}

    async def _concurrent_redfish_requests(
        self,
        dut_id: str,
        requests: List[Tuple[str, str]],  # List of (uri, error_context) tuples
        max_concurrent: int = None,
    ) -> List[Tuple[bool, Any]]:
        """
        Execute multiple Redfish requests concurrently with rate limiting.

        Args:
            dut_id: DUT ID.
            requests: List of (uri, error_context) tuples.
            max_concurrent: Maximum concurrent requests.

        Returns:
            List of (success, response) tuples.
        """
        if max_concurrent is None:
            max_concurrent = self.DEFAULT_MAX_CONCURRENT_REQUESTS

        semaphore = Semaphore(max_concurrent)

        async def _make_request(uri: str, error_context: str) -> Tuple[bool, Any]:
            async with semaphore:
                return await self.dispatch_request(
                    dut_id, "GET", uri, error_context=error_context, bypass_cache=True
                )

        # Create tasks for all requests
        tasks = [_make_request(uri, error_context) for uri, error_context in requests]

        # Execute all requests concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle any exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"Request {i+1} failed: {str(result)}",
                    dut_id,
                )
                processed_results.append((False, {"error": str(result)}))
            else:
                processed_results.append(result)

        return processed_results

    async def _concurrent_entity_processing(
        self,
        dut_id: str,
        entities: List[Dict[str, Any]],
        processor_func,
        max_concurrent: int = None,
        **kwargs,
    ) -> List[Any]:
        """
        Process multiple entities concurrently.

        Args:
            dut_id: DUT ID.
            entities: List of entities to process.
            processor_func: Function to process each entity.
            max_concurrent: Maximum concurrent processing tasks.
            **kwargs: Additional arguments.

        Returns:
            List of processed results.
        """
        if max_concurrent is None:
            max_concurrent = self.DEFAULT_MAX_CONCURRENT_ENTITIES
        from time import time

        start_time = time()
        entity_count = len(entities)

        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"Starting concurrent processing of {entity_count} entities with max_concurrent={max_concurrent}",
            dut_id,
        )

        semaphore = Semaphore(max_concurrent)

        async def _process_entity(entity: Dict[str, Any]) -> Any:
            async with semaphore:
                entity_id = entity.get("@odata.id", "").split("/")[-1]
                return await processor_func(dut_id, entity_id, **kwargs)

        # Create tasks for all entities
        tasks = [_process_entity(entity) for entity in entities]

        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle any exceptions
        processed_results = []
        successful_count = 0
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"Entity processing {i+1} failed: {str(result)}",
                    dut_id,
                )
                processed_results.append(None)
            else:
                processed_results.append(result)
                successful_count += 1

        end_time = time()
        duration = end_time - start_time

        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"Concurrent processing completed: {successful_count}/{entity_count} successful in {duration:.2f}s",
            dut_id,
        )

        return processed_results

    async def _log_redfish_request(
        self,
        dut_id: str,
        method: str,
        url: str,
        body: Any = None,
        headers: Dict[str, str] = None,
        timeout: int = 60,
    ) -> None:
        """
        Log Redfish request details.

        Args:
            dut_id: DUT ID.
            method: HTTP method.
            url: Request URL.
            body: Request body.
            headers: Request headers.
            timeout: Request timeout.
        """
        try:
            # Truncate large request bodies
            body_str = str(body) if body else "None"
            max_body_length = 1000
            if len(body_str) > max_body_length:
                body_str = body_str[:max_body_length] + "... [truncated]"

            # Don't log repetitive task polling
            if "/TaskService/Tasks/" in url:
                return

            request_log = f"Redfish request: {method} {url} | Body: {body_str} | Headers: {headers} | Timeout: {timeout}s"
            await self._log_runtime("INFO", "RedfishService", request_log, dut_id)

        except Exception as e:
            # Best effort logging
            await self._log_runtime(
                "WARN", "RedfishService", f"Failed to log request details: {e}", dut_id
            )

    async def _log_redfish_response(
        self,
        dut_id: str,
        method: str,
        url: str,
        success: bool,
        response_data: Any = None,
        status_code: int = None,
        error_message: str = None,
    ) -> None:
        """
        Log Redfish response details.

        Args:
            dut_id: DUT ID.
            method: HTTP method.
            url: Request URL.
            success: Whether the request succeeded.
            response_data: Response data.
            status_code: HTTP status code.
            error_message: Error message if failed.
        """
        try:
            # Don't log repetitive task polling
            if "/TaskService/Tasks/" in url:
                return

            if success:
                if status_code and status_code >= 200 and status_code < 300:
                    # Success case - log minimal info since content is saved to file
                    response_log = f"Redfish response: {method} {url} | Status: {status_code} | Success"

                    # For task responses, log task state
                    if isinstance(response_data, dict) and "TaskState" in response_data:
                        task_id = response_data.get("Id", "Unknown")
                        task_state = response_data.get("TaskState", "Unknown")
                        percent_complete = response_data.get("PercentComplete", 0)
                        response_log += (
                            f" | Task {task_id}: {task_state} ({percent_complete}%)"
                        )

                    await self._log_runtime(
                        "INFO", "RedfishService", response_log, dut_id
                    )
                else:
                    # Non-2xx status - log more details
                    response_log = f"Redfish response: {method} {url} | Status: {status_code} | Error"
                    if response_data:
                        # Truncate response data
                        response_str = str(response_data)
                        if len(response_str) > 1000:
                            response_str = response_str[:1000] + "... [truncated]"
                        response_log += f" | Response: {response_str}"
                    await self._log_runtime(
                        "ERROR", "RedfishService", response_log, dut_id
                    )
            else:
                # Failed request - log error details
                error_log = f"Redfish response: {method} {url} | Failed"
                if error_message:
                    error_log += f" | Error: {error_message}"
                if response_data:
                    # Truncate error response
                    error_str = str(response_data)
                    if len(error_str) > 1000:
                        error_str = error_str[:1000] + "... [truncated]"
                    error_log += f" | Response: {error_str}"
                await self._log_runtime("ERROR", "RedfishService", error_log, dut_id)

        except Exception as e:
            # Best effort logging
            await self._log_runtime(
                "WARN", "RedfishService", f"Failed to log response details: {e}", dut_id
            )

    def _get_diagnostic_type_for_device(self, device_type: str) -> str:
        """
        Get diagnostic type for device type.

        Args:
            device_type: Device type.

        Returns:
            Diagnostic type string.
        """
        diagnostic_type_mapping = {
            "network": "Net_NVLinkManagementNIC",
            "nvswitch": "Net_NVSwitch",
            "gpu": "Net_GPU_SXM",
            "sma": "SMA",
            "mcu": "MCU",
        }
        return diagnostic_type_mapping.get(device_type, device_type)

    def _get_max_retries_for_device_type(self, device_type: str) -> int:
        """
        Get max retries for device type.

        Args:
            device_type: Device type.

        Returns:
            Maximum retry count.
        """
        if device_type == "nvswitch":
            return 300  # 2.5 hours
        elif device_type in ["sma", "mcu"]:
            return 150  # 75 minutes
        else:
            return 100  # 50 minutes

    def _get_device_type_name(self, diagnostic_type: str, device_id: int) -> str:
        """
        Get device type name for logging.

        Args:
            diagnostic_type: Diagnostic type.
            device_id: Device ID.

        Returns:
            Device type name.
        """
        device_type_mapping = {
            "Net_NVLinkManagementNIC": "NVLinkNIC",
            "Net_NVSwitch": "NVSwitch",
            "Net_GPU_SXM": "GPU",
            "SMA": "SMA",
            "MCU": "MCU",
        }
        return device_type_mapping.get(diagnostic_type, diagnostic_type)

    """
    Handles 
    """

    async def _handle_get_collection(
        self, dut_id: str, uri_list: List[str], function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle simple GET request collections.

        Args:
            dut_id: DUT ID.
            uri_list: List of URIs to collect.
            function_tag: Function tag for naming.
            **kwargs: Additional arguments.

        Returns:
            Collector result dictionary.
        """

        async def _get_collection_and_save():
            output_files = []

            for uri in uri_list:
                await self._log_collection_start(dut_id, "GET", uri)

                success, data, _ = await self.dispatch_request(
                    dut_id, "GET", uri, bypass_cache=True
                )

                if success:
                    # Extract output pattern parameters using common function
                    output_pattern, substitutions, filtered_kwargs = (
                        self._extract_output_pattern_params(kwargs)
                    )

                    # Extract entity IDs from URI for placeholder substitution
                    extracted_ids = self._extract_entity_id_from_uri(uri)
                    substitutions.update(extracted_ids)

                    if extracted_ids:
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"Extracted entity IDs from URI: {extracted_ids}",
                            dut_id,
                        )

                    # Use common data saving function
                    file_path = await self._save_data_with_common_pattern(
                        dut_id,
                        data,
                        f"{function_tag}_response",
                        output_pattern=output_pattern,
                        substitutions=substitutions,
                        **filtered_kwargs,
                    )

                    if file_path:
                        output_files.append(file_path)
                        await self._log_collection_success(
                            dut_id, "GET", uri, file_path
                        )
                else:
                    await self._log_collection_failure(dut_id, "GET", uri, str(data))
                    # Return error immediately with the actual error message
                    return await self._create_standardized_collector_result(
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id", function_tag),
                        successful_operations=len(output_files),
                        total_operations=len(uri_list),
                        output_files=output_files,
                        error_messages=[f"GET request failed: {uri} - {data}"],
                        operation_name="get_collection",
                        additional_context={
                            "uris_processed": uri_list,
                            "successful_count": len(output_files),
                        },
                    )

            return await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=kwargs.get("collector_id", function_tag),
                successful_operations=len(output_files),
                total_operations=len(uri_list),
                output_files=output_files,
                error_messages=[],
                operation_name="get_collection",
                additional_context={
                    "uris_processed": uri_list,
                    "successful_count": len(output_files),
                },
            )

        return await self._execute_with_error_handling(
            dut_id, f"GET collection for {function_tag}", _get_collection_and_save
        )

    async def _handle_paginated_collection(
        self,
        dut_id: str,
        entity_type: str,
        log_service: str,
        function_tag: str,
        additional_data_callback: bool,
        collection_level_handling: Optional[Dict[str, Any]],
        uri_list: List[str],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Handle paginated log collections.

        Args:
            dut_id: DUT ID.
            entity_type: Type of entity.
            log_service: Log service name.
            function_tag: Function tag for naming.
            additional_data_callback: Whether to use additional data callback.
            collection_level_handling: Collection level configuration.
            uri_list: List of URIs.
            **kwargs: Additional arguments.

        Returns:
            Collector result dictionary.
        """
        await self._log_collection_start(
            dut_id, "paginated", f"{entity_type}/{log_service}"
        )

        try:
            # Check if uri_pattern is provided in kwargs (for R32 case)
            uri_pattern = kwargs.get("uri_pattern")

            # Use existing paginated logic but make it work with URI patterns
            if uri_list:
                # Custom URI patterns provided
                return await self._collect_paginated_from_uris(
                    dut_id,
                    uri_list,
                    function_tag,
                    additional_data_callback,
                    collection_level_handling,
                    **kwargs,
                )
            elif uri_pattern:
                # URI pattern provided (like R32) - pass it to entity-based collection
                kwargs["uri_pattern"] = uri_pattern
                return await self._collect_paginated_from_entities(
                    dut_id,
                    entity_type,
                    log_service,
                    function_tag,
                    additional_data_callback,
                    collection_level_handling,
                    **kwargs,
                )
            else:
                # Standard entity-based collection
                return await self._collect_paginated_from_entities(
                    dut_id,
                    entity_type,
                    log_service,
                    function_tag,
                    additional_data_callback,
                    collection_level_handling,
                    **kwargs,
                )
        except Exception as e:
            await self._log_collection_failure(
                dut_id, "paginated", f"{entity_type}/{log_service}", str(e)
            )
            return await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=kwargs.get("collector_id", f"{entity_type}_{log_service}"),
                successful_operations=0,
                total_operations=0,
                output_files=[],
                error_messages=[f"Exception in paginated collection: {str(e)}"],
                operation_name="paginated_collection",
                additional_context={
                    "entity_type": entity_type,
                    "log_service": log_service,
                    "error_type": type(e).__name__,
                },
            )

    async def _collect_paginated_from_uris(
        self,
        dut_id: str,
        uri_list: List[str],
        function_tag: str,
        additional_data_callback: bool,
        collection_level_handling: Optional[Dict[str, Any]],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Collect paginated data from custom URI patterns.

        Args:
            dut_id: DUT ID.
            uri_list: List of URIs.
            function_tag: Function tag for naming.
            additional_data_callback: Whether to use additional data callback.
            collection_level_handling: Collection level configuration.
            **kwargs: Additional arguments.

        Returns:
            Collector result dictionary.
        """
        output_files = []
        failed_uris = []
        successful_uris = []

        for uri in uri_list:
            await self._log_collection_start(dut_id, "paginated_uri", uri)

            # Extract entity info from URI for compatibility
            uri_parts = uri.split("/")
            entity_id = "unknown"
            for i, part in enumerate(uri_parts):
                if part in ["Systems", "Managers", "Chassis"] and i + 1 < len(
                    uri_parts
                ):
                    entity_id = uri_parts[i + 1]
                    break

            # Use existing optimized pagination logic
            result = await self._collect_optimized_paginated_logs(
                dut_id,
                "Custom",
                entity_id,
                "Logs",
                function_tag,
                additional_data_callback,
                collection_level_handling,
                uri_pattern=uri,
                retry_count=kwargs.get("retry_count", 3),
                **kwargs,
            )

            # Extract files from standardized result
            collected_files = result.get("output_files", [])

            if collected_files:
                output_files.extend(collected_files)
                successful_uris.append(uri)
                await self._log_collection_success(
                    dut_id, "paginated_uri", uri, f"{len(collected_files)} files"
                )
            else:
                failed_uris.append(uri)
                await self._log_collection_failure(
                    dut_id, "paginated_uri", uri, "No files collected"
                )

        # Determine overall success based on results
        successful_operations = len(successful_uris)
        total_operations = len(uri_list)
        error_messages = [f"Failed URI: {uri}" for uri in failed_uris]

        return await self._create_standardized_collector_result(
            dut_id=dut_id,
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name="paginated_uri_collection",
            additional_context={
                "custom_uris_processed": len(uri_list),
                "successful_uris": successful_uris,
                "failed_uris": failed_uris,
            },
        )

    async def _collect_paginated_from_entities(
        self,
        dut_id: str,
        entity_type: str,
        log_service: str,
        function_tag: str,
        additional_data_callback: bool,
        collection_level_handling: Optional[Dict[str, Any]],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Collect paginated data from standard entity-based approach.

        Args:
            dut_id: DUT ID.
            entity_type: Type of entity.
            log_service: Log service name.
            function_tag: Function tag for naming.
            additional_data_callback: Whether to use additional data callback.
            collection_level_handling: Collection level configuration.
            **kwargs: Additional arguments.

        Returns:
            Collector result dictionary.
        """
        # Use the original collect_redfish_paginated_logs method to ensure all logic is preserved
        # This maintains backward compatibility and ensures additional_data_callback works correctly
        result = await self._collect_redfish_paginated_logs(
            dut_id,
            entity_type,
            log_service,
            function_tag,
            additional_data_callback,
            collection_level_handling,
            **kwargs,
        )

        # Add logging for the result
        if result.get("success"):
            await self._log_collection_success(
                dut_id,
                "paginated_entities",
                f"{entity_type}/{log_service}",
                f"{len(result.get('output_files', []))} files",
            )
        else:
            reason = result.get("reason")
            if not reason:
                reason = f"Paginated entities collection failed for {entity_type}/{log_service} - no specific error reason provided in result"
            await self._log_collection_failure(
                dut_id,
                "paginated_entities",
                f"{entity_type}/{log_service}",
                reason,
            )

        return result

    async def _get_custom_uris_from_config(
        self, dut_id: str, entity_id: str, uri_key: str, entity_type: str = None
    ) -> List[str]:
        """
        Get custom URIs from configuration with entity_id substitution.
        This is a generic approach that works for any URI configuration key.

        Args:
            dut_id: DUT identifier
            entity_id: Entity ID for substitution (e.g., system_id, manager_id)
            uri_key: Configuration key for the URI list (e.g., "POST_CODES_URI")
            entity_type: Entity type for smart substitution (e.g., Systems, Managers, Chassis)

        Returns:
            List of custom URIs with entity_id substituted, or empty list if none configured
        """
        try:
            # Check DUT-level configuration first (highest priority)
            dut_config = self.dut_manager.get_dut_config(dut_id)
            dut_uris = dut_config.get(uri_key, None)

            if dut_uris:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using DUT-level custom URIs for {entity_id} from {uri_key}: {dut_uris}",
                    dut_id,
                )
                return self._process_user_defined_uris(dut_uris, entity_id, entity_type)

            # Check tool-level configuration (medium priority)
            orchestrator = getattr(self, "orchestrator", None)
            if orchestrator and hasattr(orchestrator, "config_manager"):
                tool_config = orchestrator.config_manager.get_tool_config()
            else:
                tool_config = self.dut_manager.tool_config
            tool_uris = tool_config.get(uri_key, None)

            if tool_uris:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using tool-level custom URIs for {entity_id} from {uri_key}: {tool_uris}",
                    dut_id,
                )
                return self._process_user_defined_uris(
                    tool_uris, entity_id, entity_type
                )

            return []

        except Exception as e:
            await self._log_runtime(
                "WARNING",
                "RedfishService",
                f"Could not load custom URI configuration for {uri_key}: {e}",
                dut_id,
            )
            return []

    def _process_user_defined_uris(
        self, uris_config, entity_id: str, entity_type: str = None
    ) -> List[str]:
        """
        Process user-defined URIs, handling both string and list formats with entity_id substitution.

        Args:
            uris_config: String or list of strings containing URIs
            entity_id: The entity ID to substitute in URIs (e.g., system_id, manager_id)
            entity_type: Entity type to determine the appropriate substitution pattern

        Returns:
            List of processed URIs with entity_id substituted
        """
        if not uris_config:
            return []

        # Convert single string to list
        if isinstance(uris_config, str):
            uris_config = [uris_config]

        # Filter out empty strings and process each URI
        processed_uris = []
        for uri in uris_config:
            if uri and isinstance(uri, str):
                processed_uri = uri

                # Smart substitution based on entity type
                if entity_type:
                    # Use entity-type specific substitution
                    if entity_type.lower() == "systems":
                        processed_uri = processed_uri.replace("{system_id}", entity_id)
                    elif entity_type.lower() == "managers":
                        processed_uri = processed_uri.replace("{manager_id}", entity_id)
                    elif entity_type.lower() == "chassis":
                        processed_uri = processed_uri.replace("{chassis_id}", entity_id)

                # Always support generic {entity_id} substitution
                processed_uri = processed_uri.replace("{entity_id}", entity_id)

                # Backward compatibility support
                processed_uri = processed_uri.replace("{system_id}", entity_id)
                processed_uri = processed_uri.replace("{manager_id}", entity_id)
                processed_uri = processed_uri.replace("{chassis_id}", entity_id)

                processed_uris.append(processed_uri)

        return processed_uris

    async def _collect_custom_uris(
        self,
        dut_id: str,
        entity_type: str,
        entity_id: str,
        custom_uris: List[str],
        function_tag: str,
        log_service: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Collect data from custom URIs using paginated collection logic.

        Args:
            dut_id: DUT identifier
            entity_type: Entity type from collector definition (e.g., Systems, Managers, Chassis)
            entity_id: Entity ID
            custom_uris: List of custom URIs to collect from
            function_tag: Function tag for file naming
            log_service: Log service name for context
            **kwargs: Additional parameters

        Returns:
            Standardized collector result
        """
        output_files = []
        error_messages = []
        successful_operations = 0
        total_operations = len(custom_uris)

        for i, uri in enumerate(custom_uris):
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Collecting {log_service} from custom URI {i+1}/{total_operations}: {uri}",
                dut_id,
            )

            # Generate filename based on URI
            uri_safe = (
                "_".join(uri.split("/")[-3:-1]).replace("?", "_").replace("&", "_")
            )
            output_file = f"{function_tag}_{log_service.lower()}_{entity_id}_uri_{i}_{uri_safe}.json"

            # Use the existing paginated collection logic for each custom URI
            # Pass the entity_type from collector definition and use custom URI as pattern
            # Set _processing_custom_uris flag to prevent infinite recursion
            custom_kwargs = kwargs.copy()
            custom_kwargs["_processing_custom_uris"] = True
            result = await self._collect_optimized_paginated_logs(
                dut_id=dut_id,
                entity_type=entity_type,  # Use entity_type from collector definition
                entity_id=entity_id,
                log_service=log_service,
                function_tag=function_tag,
                uri_pattern=uri,  # Use custom URI as pattern
                retry_count=kwargs.get("retry_count", 3),
                **custom_kwargs,
            )

            # Extract results from standardized response
            if result.get("status") in ["success", "partial"]:
                successful_operations += 1
                output_files.extend(result.get("output_files", []))
            else:
                error_messages.append(
                    f"Failed to collect from custom URI {uri}: {result.get('reason', 'Unknown error')}"
                )

        # Create standardized result
        return await self._create_standardized_collector_result(
            dut_id=dut_id,
            collector_id=kwargs.get(
                "collector_id", f"custom_{log_service.lower()}_{entity_id}"
            ),
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name="custom_uri_collection",
            additional_context={
                "entity_type": entity_type,
                "entity_id": entity_id,
                "log_service": log_service,
                "custom_uris": custom_uris,
                "status": "success" if successful_operations > 0 else "error",
            },
        )

    async def _create_collection_table(
        self,
        dut_id: str,
        collection_data: Dict[str, Any],
        function_tag: str,
        table_properties: List[str],
        output_pattern: str,
        substitutions: Dict[str, str],
        collector_id: str = "",
        table_title: str = "Collection Table",
        **kwargs,
    ) -> List[str]:
        """
        Create a table from collection data with specified properties.
        This is a generalized method that can be used by any collector that wants table output.
        Uses the existing v2.0 file creation infrastructure.

        Args:
            dut_id: DUT identifier
            collection_data: Collection data containing Members
            function_tag: Function tag for file naming
            table_properties: List of properties to include in the table
            output_pattern: Output pattern for filename
            substitutions: Variable substitutions for pattern
            collector_id: Collector ID for directory structure
            table_title: Title for the table
            **kwargs: Additional parameters for _save_data_with_common_pattern

        Returns:
            List of output files created
        """
        output_files = []

        try:
            # Import tabulate for table formatting
            from tabulate import tabulate

            inventory_members = collection_data.get("Members", [])
            if not isinstance(inventory_members, list):
                inventory_members = []

            # Define property list (Id and Version are always included for firmware, customizable for others)
            if not table_properties:
                prop_list = ["Id", "Version"]  # Default properties
            else:
                # Remove duplicates and ensure Id is first if present
                unique_props = list(dict.fromkeys(table_properties))
                if "Id" in unique_props:
                    unique_props.remove("Id")
                    prop_list = ["Id"] + unique_props
                else:
                    prop_list = unique_props

            table_data = []
            table_data_json = []

            # Process each member to get detailed properties
            for component in inventory_members:
                component_uri = component.get("@odata.id", "")
                if not component_uri:
                    continue

                # Get detailed component data
                success, response, _ = await self.dispatch_request(
                    dut_id,
                    "GET",
                    component_uri,
                    error_context=f"get component {component_uri}",
                )

                if not success:
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        f"Could not fetch component {component_uri}: {response}",
                        dut_id,
                    )
                    continue

                # Extract properties
                entry = {}
                for prop in prop_list:
                    entry[prop] = response.get(prop, "")

                table_data_json.append(entry)
                table_data.append(list(entry.values()))

            if not table_data:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"No {table_title.lower()} data found to create table",
                    dut_id,
                )
                return output_files

            # Create text table content
            table_content = f"{table_title}:\n\n"
            table_content += tabulate(table_data, prop_list, tablefmt="outline") + "\n"

            text_file = await self._save_data_with_common_pattern(
                dut_id,
                table_content,
                f"{function_tag}_table",
                output_pattern=f"{function_tag}.txt",
                substitutions=substitutions,
                collector_id=collector_id,
                **kwargs,
            )
            if text_file:
                output_files.append(text_file)

            json_file = await self._save_data_with_common_pattern(
                dut_id,
                table_data_json,
                f"{function_tag}_table",
                output_pattern=f"{function_tag}.json",
                substitutions=substitutions,
                collector_id=collector_id,
                **kwargs,
            )
            if json_file:
                output_files.append(json_file)

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Created {table_title.lower()} with {len(table_data)} entries",
                dut_id,
            )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Error creating {table_title.lower()}: {e}",
                dut_id,
            )

        return output_files

    async def _handle_collection_with_members(
        self, dut_id: str, uri_list: List[str], function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle collection with members.

        Args:
            dut_id: DUT ID.
            uri_list: List of collection URIs.
            function_tag: Function tag for naming.
            **kwargs: Additional arguments including format_output, table_properties, etc.

        Returns:
            Collector result dictionary.
        """
        output_files = []
        failed_collections = []
        successful_collections = []

        # Define collection name for summary generation (matching host service pattern)
        collection_name = f"{function_tag} Collection"

        # Check if this is a table format request (for firmware inventory)
        format_output = kwargs.get("format_output", "")
        is_table_format = format_output == "table"

        # Get table properties from collector definition with DUT config override
        table_properties = []
        if is_table_format:
            # Start with default properties from collector definition
            table_properties = kwargs.get("table_properties", [])
            if not isinstance(table_properties, list):
                table_properties = []

            # Check for DUT-level and tool-level configuration override
            config_key = kwargs.get("table_config_key", "")
            if config_key:
                try:
                    dut_config = self.dut_manager.get_dut_config(dut_id)
                    dut_override_props = dut_config.get(config_key, [])

                    # Check DUT-level configuration first (highest priority)
                    if isinstance(dut_override_props, list) and dut_override_props:
                        # Use DUT-level configuration if available
                        table_properties = dut_override_props
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Using DUT-level table properties from {config_key}: {table_properties}",
                            dut_id,
                        )
                    else:
                        # Fall back to tool-level configuration (medium priority)
                        # Get tool config from the orchestrator's configuration manager
                        orchestrator = getattr(self, "orchestrator", None)
                        if orchestrator and hasattr(orchestrator, "config_manager"):
                            tool_config = orchestrator.config_manager.get_tool_config()
                        else:
                            tool_config = self.dut_manager.tool_config
                        tool_override_props = tool_config.get(config_key, [])
                        if (
                            isinstance(tool_override_props, list)
                            and tool_override_props
                        ):
                            table_properties = tool_override_props
                            await self._log_runtime(
                                "INFO",
                                "RedfishService",
                                f"Using tool-level table properties from {config_key}: {table_properties}",
                                dut_id,
                            )
                        else:
                            await self._log_runtime(
                                "DEBUG",
                                "RedfishService",
                                f"No override found for {config_key}, using collector defaults: {table_properties}",
                                dut_id,
                            )
                except Exception as e:
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        f"Could not load config for table properties override: {e}",
                        dut_id,
                    )

        # Retry configuration
        max_retries = kwargs.get(
            "retry_count", 2
        )  # Default 2 retries for failed collections
        retry_delay = 5  # 5 seconds between retries

        for collection_uri in uri_list:
            await self._log_collection_start(dut_id, "collection", collection_uri)

            # Add small delay between requests to prevent BMC overload
            if len(successful_collections) > 0 or len(failed_collections) > 0:
                await asyncio.sleep(1)  # 1000ms delay between requests

            # Try collection with retries
            success = False
            collection_data = None
            last_error = None

            for retry_attempt in range(max_retries + 1):
                if retry_attempt > 0:
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        f"Retrying collection for {collection_uri} (attempt {retry_attempt + 1}/{max_retries + 1})",
                        dut_id,
                    )
                    await asyncio.sleep(retry_delay)

                success, collection_data, _ = await self.dispatch_request(
                    dut_id,
                    "GET",
                    collection_uri,
                    error_context=f"get collection from {collection_uri}",
                )

                if success:
                    break
                else:
                    last_error = collection_data
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        f"Collection attempt {retry_attempt + 1} failed for {collection_uri}: {collection_data}",
                        dut_id,
                    )

            if not success:
                error_msg = f"Collection failed for {collection_uri} after {max_retries + 1} attempts: {last_error}"
                failed_collections.append(error_msg)
                await self._log_collection_failure(
                    dut_id, "collection", collection_uri, str(last_error)
                )
                continue

            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            # Extract entity IDs from the collection_uri for substitutions
            # URI formats:
            #   /redfish/v1/Chassis/{chassis_id}/LogServices/XID/Entries
            #   /redfish/v1/Systems/{system_id}/LogServices/EventLog/Entries
            #   /redfish/v1/Managers/{manager_id}/LogServices/Journal/Entries
            # Extract entity IDs from collection URI for placeholder substitution
            extracted_ids = self._extract_entity_id_from_uri(collection_uri)
            substitutions.update(extracted_ids)

            if extracted_ids:
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Extracted entity IDs from collection URI: {extracted_ids}",
                    dut_id,
                )

            # Handle table format for any collection
            if is_table_format:
                # Create collection table instead of individual member files
                collector_id = kwargs.get("collector_id", "")
                table_title = kwargs.get(
                    "table_title", f"{function_tag.replace('_', ' ').title()} Table"
                )
                table_files = await self._create_collection_table(
                    dut_id,
                    collection_data,
                    function_tag,
                    table_properties,
                    output_pattern,
                    substitutions,
                    collector_id,
                    table_title,
                )
                output_files.extend(table_files)
                if table_files:
                    successful_collections.append(collection_uri)
                    await self._log_collection_success(
                        dut_id,
                        "collection",
                        collection_uri,
                        f"Created {len(table_files)} table files",
                    )
            else:
                # Save collection summary using common function (original behavior)
                collection_file = await self._save_data_with_common_pattern(
                    dut_id,
                    collection_data,
                    function_tag,
                    output_pattern=output_pattern,
                    substitutions={
                        **substitutions,
                        "member_id": "root",
                        "task_id": "root",
                        "index": "root",
                        "report_id": "collection_summary",
                    },
                    **filtered_kwargs,
                )
                if collection_file:
                    output_files.append(collection_file)
                    successful_collections.append(collection_uri)
                    await self._log_collection_success(
                        dut_id, "collection", collection_uri, collection_file
                    )

            # Process members (skip for table format as members are processed in table creation)
            if not is_table_format:
                members = collection_data.get("Members", [])
                for i, member in enumerate(members):
                    # Add small delay between member requests to prevent BMC overload
                    if i > 0:
                        await asyncio.sleep(1)  # 1000ms delay between member requests

                    # Use member_uri_pattern if provided, otherwise use the member's @odata.id
                    member_uri_pattern = kwargs.get("member_uri_pattern", "")
                    if member_uri_pattern:
                        # Extract member ID from the member's @odata.id (this is the chassis ID)
                        member_odata_id = member.get("@odata.id", "")
                        chassis_id = (
                            member_odata_id.split("/")[-1]
                            if member_odata_id
                            else f"member_{i}"
                        )

                        # Build URI using the pattern and chassis ID
                        member_uri = member_uri_pattern.replace(
                            "{chassis_id}", chassis_id
                        )
                        # Use chassis_id as member_id for file naming
                        member_id = chassis_id
                    else:
                        member_uri = member.get("@odata.id", "")
                        member_id = (
                            member_uri.split("/")[-1] if member_uri else f"member_{i}"
                        )

                    if member_uri:
                        # Try member collection with retries
                        member_success = False
                        member_data = None
                        member_last_error = None

                        for member_retry_attempt in range(max_retries + 1):
                            if member_retry_attempt > 0:
                                await self._log_runtime(
                                    "WARNING",
                                    "RedfishService",
                                    f"Retrying member collection for {member_uri} (attempt {member_retry_attempt + 1}/{max_retries + 1})",
                                    dut_id,
                                )
                                await asyncio.sleep(retry_delay)

                            member_success, member_data, _ = (
                                await self.dispatch_request(
                                    dut_id,
                                    "GET",
                                    member_uri,
                                    error_context=f"get member {member_uri}",
                                )
                            )

                            if member_success:
                                break
                            else:
                                member_last_error = member_data
                                await self._log_runtime(
                                    "WARNING",
                                    "RedfishService",
                                    f"Member collection attempt {member_retry_attempt + 1} failed for {member_uri}: {member_data}",
                                    dut_id,
                                )

                        if member_success:
                            # member_id was already set correctly above when building the URI
                            # Extract report_id from the member data if available (like original implementation)
                            report_id = member_data.get("Id", member_id)

                            # Check if member_uri_pattern is provided and extract variable name
                            member_uri_pattern = kwargs.get("member_uri_pattern", "")
                            if (
                                member_uri_pattern
                                and "{chassis_id}" in member_uri_pattern
                            ):
                                # Use chassis_id for substitutions when member_uri_pattern contains {chassis_id}
                                member_substitutions = {
                                    **substitutions,
                                    "chassis_id": member_id,
                                    "member_id": member_id,
                                    "task_id": member_id,
                                    "index": str(i),
                                    "report_id": report_id,
                                }
                            else:
                                # Default substitutions
                                member_substitutions = {
                                    **substitutions,
                                    "member_id": member_id,
                                    "task_id": member_id,
                                    "index": str(i),
                                    "report_id": report_id,
                                }

                            member_file = await self._save_data_with_common_pattern(
                                dut_id,
                                member_data,
                                function_tag,
                                output_pattern=output_pattern,
                                substitutions=member_substitutions,
                                **filtered_kwargs,
                            )
                            if member_file:
                                output_files.append(member_file)
                                successful_collections.append(member_uri)
                                await self._log_collection_success(
                                    dut_id, "member", member_uri, member_file
                                )

                            # Handle additional member collections (e.g., CertChain for certificates)
                            additional_collections = kwargs.get(
                                "additional_member_collections", []
                            )
                            if additional_collections and isinstance(
                                additional_collections, list
                            ):
                                await self._log_runtime(
                                    "DEBUG",
                                    "RedfishService",
                                    f"Processing {len(additional_collections)} additional member collections for {member_uri}",
                                    dut_id,
                                )

                                # Smart filtering: Check if this member actually has certificate data
                                # before trying to collect additional certificate endpoints
                                should_collect_additional = True
                                if "Certificates" in member_uri and "CertChain" in str(
                                    additional_collections
                                ):
                                    # Check if the member data indicates certificates are available
                                    members_count = member_data.get(
                                        "Members@odata.count", 0
                                    )
                                    if members_count == 0:
                                        await self._log_runtime(
                                            "DEBUG",
                                            "RedfishService",
                                            f"Skipping additional certificate collection for {member_uri} - no certificate members (count: {members_count})",
                                            dut_id,
                                        )
                                        should_collect_additional = False

                                if should_collect_additional:
                                    for additional_config in additional_collections:
                                        if not isinstance(additional_config, dict):
                                            continue

                                        additional_uri_pattern = additional_config.get(
                                            "uri_pattern", ""
                                        )
                                        additional_suffix = additional_config.get(
                                            "output_suffix", ""
                                        )

                                        if not additional_uri_pattern:
                                            continue

                                        # Build the additional URI using the same substitutions
                                        additional_uri = additional_uri_pattern
                                        for key, value in member_substitutions.items():
                                            additional_uri = additional_uri.replace(
                                                f"{{{key}}}", str(value)
                                            )

                                        await self._log_runtime(
                                            "DEBUG",
                                            "RedfishService",
                                            f"Collecting additional member data from: {additional_uri}",
                                            dut_id,
                                        )

                                    # Try to collect additional member data with retries
                                    additional_success = False
                                    additional_data = None
                                    additional_last_error = None

                                    # Use reduced retries for certificate endpoints that often fail
                                    additional_max_retries = max_retries
                                    if "CertChain" in additional_uri:
                                        additional_max_retries = min(
                                            1, max_retries
                                        )  # Only 1 retry for CertChain
                                        await self._log_runtime(
                                            "DEBUG",
                                            "RedfishService",
                                            f"Using reduced retries ({additional_max_retries}) for certificate endpoint: {additional_uri}",
                                            dut_id,
                                        )

                                    for additional_retry_attempt in range(
                                        additional_max_retries + 1
                                    ):
                                        if additional_retry_attempt > 0:
                                            await self._log_runtime(
                                                "WARNING",
                                                "RedfishService",
                                                f"Retrying additional collection for {additional_uri} (attempt {additional_retry_attempt + 1}/{additional_max_retries + 1})",
                                                dut_id,
                                            )
                                            await asyncio.sleep(retry_delay)

                                        additional_success, additional_data, _ = (
                                            await self.dispatch_request(
                                                dut_id,
                                                "GET",
                                                additional_uri,
                                                error_context=f"get additional member data {additional_uri}",
                                            )
                                        )

                                        if additional_success:
                                            break
                                        else:
                                            additional_last_error = additional_data
                                            await self._log_runtime(
                                                "WARNING",
                                                "RedfishService",
                                                f"Additional collection attempt {additional_retry_attempt + 1} failed for {additional_uri}: {additional_data}",
                                                dut_id,
                                            )

                                    if additional_success:
                                        # Create output pattern with suffix
                                        additional_output_pattern = output_pattern
                                        if additional_suffix:
                                            # Add suffix before the file extension
                                            if additional_output_pattern.endswith(
                                                ".json"
                                            ):
                                                additional_output_pattern = (
                                                    additional_output_pattern.replace(
                                                        ".json",
                                                        f"{additional_suffix}.json",
                                                    )
                                                )
                                            else:
                                                additional_output_pattern = f"{additional_output_pattern}{additional_suffix}"

                                        additional_file = await self._save_data_with_common_pattern(
                                            dut_id,
                                            additional_data,
                                            function_tag,
                                            output_pattern=additional_output_pattern,
                                            substitutions=member_substitutions,
                                            **filtered_kwargs,
                                        )
                                        if additional_file:
                                            output_files.append(additional_file)
                                            successful_collections.append(
                                                additional_uri
                                            )
                                            await self._log_collection_success(
                                                dut_id,
                                                "additional_member",
                                                additional_uri,
                                                additional_file,
                                            )
                                    else:
                                        # Log additional collection failure but don't fail the main collection
                                        error_msg = f"Additional member collection failed for {additional_uri} after {additional_max_retries + 1} attempts: {additional_last_error}"
                                        await self._log_runtime(
                                            "WARNING",
                                            "RedfishService",
                                            error_msg,
                                            dut_id,
                                        )
                                else:
                                    await self._log_runtime(
                                        "DEBUG",
                                        "RedfishService",
                                        f"Skipped additional member collections for {member_uri} due to smart filtering",
                                        dut_id,
                                    )
                        else:
                            # Add specific error message for member collection failure
                            error_msg = f"Member collection failed for {member_uri} after {max_retries + 1} attempts: {member_last_error}"
                            failed_collections.append(error_msg)
                            await self._log_collection_failure(
                                dut_id, "member", member_uri, str(member_last_error)
                            )

        # Determine overall success based on results
        # Count successful operations: collections that succeeded + members that succeeded
        successful_operations = len(successful_collections)
        total_operations = len(uri_list)
        error_messages = (
            failed_collections  # failed_collections already contains error messages
        )

        # If no collections succeeded and no specific error messages, add a generic one
        if successful_operations == 0 and not error_messages:
            error_messages = [
                f"All collection operations failed for {len(uri_list)} URIs"
            ]

        # Calculate certificate-specific statistics if this is a certificate collection
        cert_successful = 0
        cert_failed = 0
        cert_skipped = 0
        additional_details = {}

        if "certificates" in function_tag.lower() or "cert" in function_tag.lower():
            cert_successful = len([f for f in output_files if "_certchain.json" in f])
            cert_failed = len([f for f in failed_collections if "CertChain" in f])
            cert_skipped = len(
                [f for f in failed_collections if "no certificate members" in f]
            )

            additional_details = {
                "Certificate chains collected": cert_successful,
                "Certificate chains failed": cert_failed,
                "Certificate chains skipped (no certificates)": cert_skipped,
            }

        # Check if summary generation is enabled
        generate_summary = kwargs.get("generate_summary", True)
        summary_format = kwargs.get("summary_format", "both")
        collector_config = kwargs.get("collector_config", {})
        summary_messages = collector_config.get("summary_messages", {})

        if generate_summary:

            # Add custom summary message based on results
            if summary_messages:
                if successful_operations == 0 and total_operations > 0:
                    custom_message = summary_messages.get(
                        "failure", "Collection failed"
                    )
                elif successful_operations == total_operations and total_operations > 0:
                    custom_message = summary_messages.get(
                        "success", "Collection completed successfully"
                    )
                elif (
                    successful_operations > 0
                    and successful_operations < total_operations
                ):
                    custom_message = summary_messages.get(
                        "partial_success", "Collection completed with some failures"
                    )
                elif total_operations == 0:
                    custom_message = summary_messages.get(
                        "empty_results", "No operations performed"
                    )
                else:
                    custom_message = summary_messages.get(
                        "no_certificates", "No certificates found"
                    )

                additional_details["Summary"] = custom_message

            # Handle summary generation using helper function
            output_files = await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=function_tag,
                collection_name=collection_name,
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=len(error_messages),
                output_files=output_files,
                additional_details=additional_details,
                kwargs=kwargs,
                collection_type="collection_with_members",
                ignore_empty_results=True,
            )

        # Prepare additional context with certificate-specific details
        additional_context = {
            "collections_processed": len(uri_list),
            "successful_collections": successful_collections,
            "failed_collections": failed_collections,
        }

        # Add certificate-specific details if this is a certificate collection
        if "certificates" in function_tag.lower() or "cert" in function_tag.lower():
            additional_context.update(
                {
                    "certificate_chains_collected": cert_successful,
                    "certificate_chains_failed": cert_failed,
                    "certificate_chains_skipped": cert_skipped,
                }
            )

        return await self._create_standardized_collector_result(
            dut_id=dut_id,
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name="collection_with_members",
            additional_context=additional_context,
        )

    async def _handle_existing_dumps_collection(
        self,
        dut_id: str,
        entity_type: str,
        log_service: str,
        function_tag: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Handle existing dumps collection.

        Args:
            dut_id: DUT ID.
            entity_type: Type of entity.
            log_service: Log service name.
            function_tag: Function tag for naming.
            **kwargs: Additional arguments including filtered entities.

        Returns:
            Collector result dictionary.
        """
        try:
            output_files = []
            failed_entities = []
            successful_entities = []

            entity_uri = self.get_configured_uri(dut_id, entity_type)
            await self._log_collection_start(dut_id, "existing_dumps", entity_uri)

            # Check if we have validation results with filtered entities
            filtered_systems = kwargs.get("filtered_systems", [])
            filtered_managers = kwargs.get("filtered_managers", [])
            filtered_chassis = kwargs.get("filtered_chassis", [])

            if filtered_systems and entity_type == "Systems":
                # Use filtered systems from validation
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using {len(filtered_systems)} filtered systems from validation: {[sys['id'] for sys in filtered_systems]}",
                    dut_id,
                )
                entity_ids = [sys["id"] for sys in filtered_systems]
            elif filtered_managers and entity_type == "Managers":
                # Use filtered managers from validation
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using {len(filtered_managers)} filtered managers from validation: {[mgr['id'] for mgr in filtered_managers]}",
                    dut_id,
                )
                entity_ids = [mgr["id"] for mgr in filtered_managers]
            elif filtered_chassis and entity_type == "Chassis":
                # Use filtered chassis from validation
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using {len(filtered_chassis)} filtered chassis from validation: {[chassis['id'] for chassis in filtered_chassis]}",
                    dut_id,
                )
                entity_ids = [chassis["id"] for chassis in filtered_chassis]
            else:
                # Get entities - fallback to fetching all entities
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"No filtered {entity_type.lower()} found in context, fetching all {entity_type}",
                    dut_id,
                )
                success, entities, _ = await self.dispatch_request(
                    dut_id,
                    "GET",
                    entity_uri,
                    error_context=f"get {entity_type}",
                )

                if not success:
                    return await self._create_standardized_collector_result(
                        successful_operations=0,
                        total_operations=1,
                        output_files=[],
                        error_messages=[f"Failed to get {entity_type}: {entities}"],
                        operation_name="entity_discovery",
                        additional_context={"entity_type": entity_type},
                    )

                entity_ids = [
                    entity.get("@odata.id", "").split("/")[-1]
                    for entity in entities.get("Members", [])
                ]

            if not entity_ids:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[f"No {entity_type} found"],
                    operation_name="existing_dumps_collection",
                    additional_context={"entity_type": entity_type},
                )

            # Process entities concurrently for better performance
            async def _process_entity_dumps(
                dut_id: str, entity_id: str, **kwargs
            ) -> List[str]:
                entity_output_files = []

                await self._log_collection_start(
                    dut_id, "entity_dumps", f"{entity_type}/{entity_id}"
                )

                # Get dump service
                entity_base_uri = self.get_configured_uri(dut_id, entity_type)
                success, dump_service, _ = await self.dispatch_request(
                    dut_id,
                    "GET",
                    f"{entity_base_uri}/{entity_id}/LogServices/{log_service}",
                    error_context=f"get dump service for {entity_type} {entity_id}",
                )

                if not success:
                    await self._log_collection_failure(
                        dut_id,
                        "entity_dumps",
                        f"{entity_type}/{entity_id}",
                        f"Dump service not found",
                    )
                    return []

                # Add small delay between dump service and entries requests
                await asyncio.sleep(
                    1
                )  # 1000ms delay between dump service and entries requests

                # Get dump entries
                success, dump_entries, _ = await self.dispatch_request(
                    dut_id,
                    "GET",
                    f"{entity_base_uri}/{entity_id}/LogServices/{log_service}/Entries",
                    error_context=f"get dump entries for {entity_type} {entity_id}",
                )

                if success:
                    # Extract output pattern parameters using common function
                    output_pattern, substitutions, filtered_kwargs = (
                        self._extract_output_pattern_params(kwargs)
                    )

                    # Save entries list using entries_pattern
                    entries_file = await self._save_data_with_common_pattern(
                        dut_id,
                        dump_entries,
                        "entries",
                        output_pattern=kwargs.get("entries_pattern", ""),
                        substitutions={**substitutions, "manager_id": entity_id},
                        **filtered_kwargs,
                    )
                    if entries_file:
                        entity_output_files.append(entries_file)
                        await self._log_collection_success(
                            dut_id,
                            "entries",
                            f"{entity_type}/{entity_id}",
                            entries_file,
                        )

                    # Collect all dump entries with AdditionalDataURI for binary download
                    dump_entries_with_attachments = []
                    for member in dump_entries.get("Members", []):
                        additional_data_uri = member.get("AdditionalDataURI")
                        if additional_data_uri:
                            dump_entries_with_attachments.append(
                                {
                                    "entry_id": member.get("Id", "unknown"),
                                    "attachment_uri": additional_data_uri,
                                    "entry_data": member,
                                }
                            )

                    if dump_entries_with_attachments:
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Found {len(dump_entries_with_attachments)} dump entries with attachments for {entity_type} {entity_id}",
                            dut_id,
                        )

                        # Make concurrent requests for binary dump attachments
                        attachment_tasks = []
                        for entry in dump_entries_with_attachments:
                            task = self.dispatch_request(
                                dut_id,
                                "GET",
                                entry["attachment_uri"],
                                get_raw_content=True,
                                error_context=f"get binary dump from {entry['attachment_uri']}",
                            )
                            attachment_tasks.append(task)

                        # Execute all attachment requests concurrently with limited concurrency
                        # Use per-DUT semaphore to limit concurrent requests to prevent BMC overload
                        semaphore = self._get_dut_semaphore(dut_id, "requests")

                        async def limited_request(task):
                            async with semaphore:
                                return await task

                        limited_tasks = [
                            limited_request(task) for task in attachment_tasks
                        ]
                        attachment_results = await asyncio.gather(
                            *limited_tasks, return_exceptions=True
                        )

                        # Process results and save binary files
                        for i, result in enumerate(attachment_results):
                            # Handle exceptions from asyncio.gather with return_exceptions=True
                            if isinstance(result, Exception):
                                entry = dump_entries_with_attachments[i]
                                entry_id = entry["entry_id"]
                                await self._log_runtime(
                                    "WARN",
                                    "RedfishService",
                                    f"Failed to download binary dump for {entity_type}/{entity_id}/{entry_id}: {str(result)}",
                                    dut_id,
                                )
                                continue

                            # Unpack successful results
                            try:
                                success, binary_data, metadata = result
                                if success and isinstance(binary_data, bytes):
                                    entry = dump_entries_with_attachments[i]
                                    entry_id = entry["entry_id"]

                                    # Save binary dump file using common function
                                    dump_file = (
                                        await self._save_data_with_common_pattern(
                                            dut_id,
                                            binary_data,
                                            f"dump_{entry_id}",
                                            output_pattern=output_pattern,
                                            substitutions={
                                                **substitutions,
                                                "entry_id": entry_id,
                                                "manager_id": entity_id,
                                            },
                                            **filtered_kwargs,
                                        )
                                    )
                                    if dump_file:
                                        entity_output_files.append(dump_file)
                                        await self._log_collection_success(
                                            dut_id,
                                            "binary_dump",
                                            f"{entity_type}/{entity_id}/{entry_id}",
                                            dump_file,
                                        )
                            except (ValueError, TypeError) as e:
                                entry = dump_entries_with_attachments[i]
                                entry_id = entry["entry_id"]
                                await self._log_runtime(
                                    "WARN",
                                    "RedfishService",
                                    f"Failed to unpack result for {entity_type}/{entity_id}/{entry_id}: {str(e)}",
                                    dut_id,
                                )

                return entity_output_files

            # Process each entity
            for i, entity_id in enumerate(entity_ids):
                # Add delay between entity processing to prevent BMC overload
                if i > 0:
                    await asyncio.sleep(1)  # 1000ms delay between entities

                entity_files = await _process_entity_dumps(dut_id, entity_id, **kwargs)
                if entity_files:
                    output_files.extend(entity_files)
                    successful_entities.append(entity_id)
                else:
                    failed_entities.append(entity_id)

            # Use the base collector's standardized result function
            successful_operations = len(successful_entities)
            total_operations = len(entity_ids)
            error_messages = [
                f"Entity {entity_id} failed" for entity_id in failed_entities
            ]

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="entities",
                additional_context={
                    "entity_type": entity_type,
                    "entities_processed": len(entity_ids),
                    "successful_entities": successful_entities,
                    "failed_entities": failed_entities,
                },
            )

        except Exception as e:
            entity_uri = self.get_configured_uri(dut_id, entity_type)
            await self._log_collection_failure(
                dut_id, "existing_dumps", entity_uri, str(e)
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=0,
                output_files=[],
                error_messages=[f"Exception in existing dumps collection: {str(e)}"],
                operation_name="existing_dumps_collection",
                additional_context={"entity_type": entity_type},
            )

    async def _handle_sequential_collection(
        self, dut_id: str, uri_list: List[str], function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle sequential data collection.

        Args:
            dut_id: DUT ID.
            uri_list: List of URIs to collect sequentially.
            function_tag: Function tag for naming.
            **kwargs: Additional arguments.

        Returns:
            Collector result dictionary.
        """
        output_files = []
        failed_uris = []
        successful_uris = []

        for i, uri in enumerate(uri_list):
            await self._log_collection_start(dut_id, "sequential", uri)

            success, data, _ = await self.dispatch_request(dut_id, "GET", uri)

            if success:
                # Extract output pattern parameters using common function
                output_pattern, substitutions, filtered_kwargs = (
                    self._extract_output_pattern_params(kwargs)
                )

                # Use common data saving function with sequence-specific substitutions
                file_path = await self._save_data_with_common_pattern(
                    dut_id,
                    data,
                    function_tag,
                    output_pattern=output_pattern,
                    substitutions={
                        **substitutions,
                        "sequence": str(i + 1),
                        "index": str(i),
                    },
                    **filtered_kwargs,
                )

                if file_path:
                    output_files.append(file_path)
                    successful_uris.append(uri)
                    await self._log_collection_success(
                        dut_id, "sequential", uri, file_path
                    )
                else:
                    failed_uris.append(f"Failed to save data for {uri}")
                    await self._log_collection_failure(
                        dut_id, "sequential", uri, "Failed to save data"
                    )
            else:
                failed_uris.append(f"GET request failed for {uri}: {data}")
                await self._log_collection_failure(dut_id, "sequential", uri, str(data))

        # Determine overall success based on results
        successful_operations = len(successful_uris)
        total_operations = len(uri_list)
        error_messages = failed_uris  # failed_uris already contains error messages

        return await self._create_standardized_collector_result(
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name="sequential_collection",
            additional_context={
                "sequence_count": len(uri_list),
                "successful_uris": successful_uris,
                "failed_uris": failed_uris,
            },
        )

    async def _handle_uri_list_collection(
        self,
        dut_id: str,
        entity_type: str,
        uri_list: List[str],
        function_tag: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Handle URI list collection.

        Args:
            dut_id: DUT ID.
            entity_type: Type of entity.
            uri_list: List of URIs.
            function_tag: Function tag for naming.
            **kwargs: Additional arguments.

        Returns:
            Collector result dictionary.
        """
        output_files = []
        failed_uris = []
        successful_uris = []

        for i, uri in enumerate(uri_list):
            await self._log_collection_start(dut_id, "uri_list", uri)

            success, data, _ = await self.dispatch_request(dut_id, "GET", uri)

            if success:
                # Extract output pattern parameters using common function
                output_pattern, substitutions, filtered_kwargs = (
                    self._extract_output_pattern_params(kwargs)
                )

                # Extract entity ID from URI for substitutions
                entity_id = self._extract_entity_id_from_uri(uri, entity_type)

                # Use common data saving function with URI-specific substitutions
                # Create substitutions dict with null check for entity_type
                uri_substitutions = {
                    **substitutions,
                    "log_id": str(i),
                    "index": str(i),
                    "uri": uri,
                }

                # Only add entity_type-based substitution if entity_type is not None
                if entity_type:
                    uri_substitutions[f"{entity_type.lower()}_id"] = entity_id

                file_path = await self._save_data_with_common_pattern(
                    dut_id,
                    data,
                    function_tag,
                    output_pattern=output_pattern,
                    substitutions=uri_substitutions,
                    **filtered_kwargs,
                )

                if file_path:
                    output_files.append(file_path)
                    successful_uris.append(uri)
                    await self._log_collection_success(
                        dut_id, "uri_list", uri, file_path
                    )
                else:
                    failed_uris.append(f"Failed to save data for {uri}")
                    await self._log_collection_failure(
                        dut_id, "uri_list", uri, "Failed to save data"
                    )
            else:
                failed_uris.append(f"GET request failed for {uri}: {data}")
                await self._log_collection_failure(dut_id, "uri_list", uri, str(data))

        # Handle empty URI list case - this should be treated as "skipped" not "error"
        if not uri_list:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=0,
                output_files=[],
                error_messages=[],
                operation_name="uri_list_collection",
                additional_context={
                    "entity_type": entity_type,
                    "uri_count": 0,
                    "status": "skipped",
                    "reason": "No URIs provided in configuration - collector skipped",
                },
            )

        # Determine overall success based on results
        successful_operations = len(successful_uris)
        total_operations = len(uri_list)
        error_messages = failed_uris  # failed_uris already contains error messages

        return await self._create_standardized_collector_result(
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name="uri_list_collection",
            additional_context={
                "entity_type": entity_type,
                "uri_count": len(uri_list),
                "successful_uris": successful_uris,
                "failed_uris": failed_uris,
            },
        )

    async def _handle_expand_collection(
        self,
        dut_id: str,
        uri_list: List[str],
        expand_level: int,
        function_tag: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Handle expand with traversal collection.

        Args:
            dut_id: DUT ID.
            uri_list: List of base URIs.
            expand_level: Expansion level for traversal.
            function_tag: Function tag for naming.
            **kwargs: Additional arguments.

        Returns:
            Collector result dictionary.
        """
        output_files = []
        failed_uris = []
        successful_uris = []

        for base_uri in uri_list:
            await self._log_collection_start(dut_id, "expand", base_uri)

            # Get base collection
            success, collection_data, _ = await self.dispatch_request(
                dut_id,
                "GET",
                base_uri,
                error_context=f"get base collection from {base_uri}",
            )

            if not success:
                failed_uris.append(
                    f"Base collection failed for {base_uri}: {collection_data}"
                )
                await self._log_collection_failure(
                    dut_id, "expand", base_uri, str(collection_data)
                )
                continue

            # Build expand query
            expand_query = f"$expand=*($levels={expand_level})"

            # Get expanded data
            success, expanded_data, _ = await self.dispatch_request(
                dut_id,
                "GET",
                f"{base_uri}?{expand_query}",
                error_context=f"get expanded data from {base_uri}",
            )

            if success:
                # Extract output pattern parameters using common function
                output_pattern, substitutions, filtered_kwargs = (
                    self._extract_output_pattern_params(kwargs)
                )

                # Use common data saving function
                file_path = await self._save_data_with_common_pattern(
                    dut_id,
                    expanded_data,
                    function_tag,
                    output_pattern=output_pattern,
                    substitutions={**substitutions, "expand_level": str(expand_level)},
                    **filtered_kwargs,
                )

                if file_path:
                    output_files.append(file_path)
                    successful_uris.append(base_uri)
                    await self._log_collection_success(
                        dut_id, "expand", base_uri, file_path
                    )
            else:
                failed_uris.append(f"Expand failed for {base_uri}: {expanded_data}")
                await self._log_collection_failure(
                    dut_id, "expand", base_uri, str(expanded_data)
                )

        # Determine overall success based on results
        successful_operations = len(successful_uris)
        total_operations = len(uri_list)
        error_messages = failed_uris  # failed_uris already contains error messages

        return await self._create_standardized_collector_result(
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name="expand_collection",
            additional_context={
                "expand_level": expand_level,
                "base_uris": len(uri_list),
                "successful_uris": successful_uris,
                "failed_uris": failed_uris,
            },
        )

    async def _handle_chassis_with_filter_collection(
        self, dut_id: str, uri_list: List[str], function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle chassis with filter collection.

        Args:
            dut_id: DUT ID.
            uri_list: List of chassis collection URIs.
            function_tag: Function tag for naming.
            **kwargs: Additional arguments including filter_criteria.

        Returns:
            Collector result dictionary.
        """
        output_files = []
        failed_chassis = []
        successful_chassis = []

        filter_criteria = kwargs.get("filter_criteria", {})

        for collection_uri in uri_list:
            await self._log_collection_start(dut_id, "chassis_filter", collection_uri)

            # Get chassis collection
            success, collection_data, _ = await self.dispatch_request(
                dut_id,
                "GET",
                collection_uri,
                error_context=f"get chassis collection from {collection_uri}",
            )

            if not success:
                failed_chassis.append(
                    f"Chassis collection failed for {collection_uri}: {collection_data}"
                )
                await self._log_collection_failure(
                    dut_id, "chassis_filter", collection_uri, str(collection_data)
                )
                continue

            # Process individual chassis
            members = collection_data.get("Members", [])
            for member in members:
                chassis_uri = member.get("@odata.id", "")
                if chassis_uri:
                    chassis_id = chassis_uri.split("/")[-1]

                    # Get individual chassis data
                    chassis_success, chassis_data, _ = await self.dispatch_request(
                        dut_id,
                        "GET",
                        chassis_uri,
                        error_context=f"get chassis data from {chassis_uri}",
                    )

                    if chassis_success:
                        # Apply filter criteria if provided
                        if filter_criteria:
                            # Filter the data based on criteria
                            filtered_data = self._apply_chassis_filter(
                                chassis_data, filter_criteria
                            )
                        else:
                            filtered_data = chassis_data

                        if filtered_data:
                            # Extract output pattern parameters using common function
                            output_pattern, substitutions, filtered_kwargs = (
                                self._extract_output_pattern_params(kwargs)
                            )

                            # Use common data saving function with chassis_id substitution
                            file_path = await self._save_data_with_common_pattern(
                                dut_id,
                                filtered_data,
                                function_tag,
                                output_pattern=output_pattern,
                                substitutions={
                                    **substitutions,
                                    "chassis_id": chassis_id,
                                },
                                **filtered_kwargs,
                            )

                            if file_path:
                                output_files.append(file_path)
                                successful_chassis.append(chassis_id)
                                await self._log_collection_success(
                                    dut_id, "chassis_filter", chassis_uri, file_path
                                )
                    else:
                        failed_chassis.append(
                            f"Chassis data failed for {chassis_uri}: {chassis_data}"
                        )
                        await self._log_collection_failure(
                            dut_id, "chassis_filter", chassis_uri, str(chassis_data)
                        )

        # Determine overall success based on results
        successful_operations = len(successful_chassis)
        total_operations = len(uri_list)
        error_messages = (
            failed_chassis  # failed_chassis already contains error messages
        )

        return await self._create_standardized_collector_result(
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name="chassis_filter_collection",
            additional_context={
                "filter_criteria": filter_criteria,
                "chassis_processed": len(uri_list),
                "successful_chassis": successful_chassis,
                "failed_chassis": failed_chassis,
            },
        )

    def _apply_chassis_filter(
        self, data: Dict[str, Any], filter_criteria: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Apply filter criteria to chassis data.

        Args:
            data: Chassis data to filter.
            filter_criteria: Filter criteria dictionary.

        Returns:
            Filtered chassis data.
        """
        # Simple filter implementation - can be enhanced based on specific needs
        if not data or not filter_criteria:
            return data

        # For now, return the data as-is
        # This can be enhanced with specific filtering logic based on requirements
        return data

    async def _handle_log_processing_collection(
        self,
        dut_id: str,
        entity_type: str,
        log_service: str,
        function_tag: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Handle log processing collection (e.g., CPER logs from SEL logs).

        Args:
            dut_id: DUT ID.
            entity_type: Type of entity.
            log_service: Log service name.
            function_tag: Function tag for naming.
            **kwargs: Additional arguments including processing_config.

        Returns:
            Collector result dictionary.
        """
        try:
            output_files = []
            status_list = []

            processing_config = kwargs.get("processing_config", {})
            source_logs = processing_config.get("source_logs")
            entry_filter = processing_config.get("entry_filter", {})
            legacy_platforms = processing_config.get("legacy_platforms", [])
            legacy_collection = processing_config.get("legacy_collection", {})
            collector_id = kwargs.get(
                "collector_id", ""
            )  # Extract collector_id from kwargs

            # Check if this is a legacy platform
            platform_info = await self._get_platform_info(dut_id)
            platform_type = platform_info.get("platform_type", "unknown")

            # Use legacy_platforms from processing_config if available, otherwise use default
            if processing_config and "legacy_platforms" in processing_config:
                legacy_platforms = processing_config["legacy_platforms"]

            is_legacy = any(legacy in platform_type for legacy in legacy_platforms)

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Platform detection: platform_type='{platform_type}', legacy_platforms={legacy_platforms}, is_legacy={is_legacy}",
                dut_id,
            )

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Log processing: platform_type='{platform_type}', is_legacy={is_legacy}",
                dut_id,
            )

            if is_legacy:
                # For legacy platforms, collect directly from fault logs
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    "Legacy platform detected. Collecting logs directly from fault logs.",
                    dut_id,
                )

                # Use legacy collection configuration from processing_config
                legacy_collection_config = (
                    processing_config.get("legacy_collection", {})
                    if processing_config
                    else {}
                )
                uri_pattern = legacy_collection_config.get("uri_pattern", "")
                log_service_filter = legacy_collection_config.get(
                    "log_service_filter", {}
                )

                # Get log service URIs
                log_service_uris = await self._get_log_service_uris_legacy(
                    dut_id, entity_type, log_service_filter
                )

                if not log_service_uris:
                    await self._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"No {log_service} log URIs found for legacy platform",
                        dut_id,
                    )
                    return await self._create_standardized_collector_result(
                        successful_operations=0,
                        total_operations=0,
                        output_files=[],
                        error_messages=[f"No {log_service} log URIs found"],
                        operation_name="log_processing_collection",
                        additional_context={
                            "log_service": log_service,
                            "platform_type": platform_type,
                        },
                    )

                # Process each log service URI
                for log_uri in log_service_uris:
                    success, response, _ = await self.dispatch_request(
                        dut_id, "GET", log_uri
                    )

                    if success:
                        # Extract entity IDs from URI
                        uri_parts = log_uri.split("/")
                        entity_id = uri_parts[4] if len(uri_parts) > 4 else "unknown"
                        service_id = uri_parts[6] if len(uri_parts) > 6 else "unknown"

                        # Save the log entries
                        json_filename = f"{function_tag}_{log_service.lower()}_logs_{entity_id}_{service_id}.json"
                        json_file = await self._save_data_with_common_pattern(
                            dut_id,
                            response,
                            function_tag,
                            output_pattern=json_filename,
                            substitutions={
                                "entity_id": entity_id,
                                "service_id": service_id,
                            },
                            collector_id=collector_id,
                        )

                        if json_file:
                            output_files.append(json_file)
                            status_list.append(True)

                            # Process individual log entries
                            entries = response.get("Members", [])
                            for entry in entries:
                                entry_type = entry.get("DiagnosticDataType", "")
                                if entry_type == log_service:
                                    entry_id = entry.get("Id")
                                    entry_uri = entry.get("AdditionalDataURI")

                                    if entry_uri and entry_id:
                                        # Fetch binary log data
                                        entry_success, entry_data, _ = (
                                            await self.dispatch_request(
                                                dut_id, "GET", entry_uri
                                            )
                                        )

                                        if entry_success:
                                            binary_filename = f"{function_tag}_{log_service.lower()}_logs_{entity_id}_{service_id}_{entry_id}.tar.xz"
                                            binary_file = await self._save_data_with_common_pattern(
                                                dut_id,
                                                entry_data,
                                                function_tag,
                                                output_pattern=binary_filename,
                                                substitutions={
                                                    "entity_id": entity_id,
                                                    "service_id": service_id,
                                                    "entry_id": entry_id,
                                                },
                                            )

                                            if binary_file:
                                                output_files.append(binary_file)
                                                status_list.append(True)
                    else:
                        status_list.append(False)

                        # Create error log file for failed log service URI
                        error_log_path = await self._create_error_log_file(
                            dut_id=dut_id,
                            collector_id=kwargs.get("collector_id"),
                            error_message=f"Failed to get log service URI: {log_uri}",
                            context={
                                "log_uri": log_uri,
                                "log_service": log_service,
                                "entity_type": entity_type,
                                "operation": "log_service_uri_request",
                            },
                        )

                        # Add error log file to output files
                        if error_log_path:
                            output_files.append(error_log_path)

            else:
                # For non-legacy platforms, process from source logs
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Non-legacy platform detected. Processing {log_service} entries from {source_logs}.",
                    dut_id,
                )

                # Find source log files
                source_entries = await self._find_filtered_entries_in_source_logs(
                    dut_id, source_logs, entry_filter, processing_config
                )

                if source_entries:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Found {len(source_entries)} {log_service} entries in source logs",
                        dut_id,
                    )

                    # Create consolidated log file
                    entity_base_uri = self.get_configured_uri(dut_id, entity_type)
                    consolidated_response = {
                        "@odata.id": f"{entity_base_uri}/System/LogServices/{log_service}/Entries",
                        "@odata.type": "#LogEntryCollection.LogEntryCollection",
                        "Description": f"Collection of {log_service} Log Entries",
                        "Members": source_entries,
                        "Members@odata.count": len(source_entries),
                        "Name": f"{log_service} Log Entries",
                    }

                    # Save consolidated log file
                    json_filename = f"{function_tag}_{log_service.lower()}_logs.json"
                    json_file = await self._save_data_with_common_pattern(
                        dut_id,
                        consolidated_response,
                        function_tag,
                        output_pattern=json_filename,
                    )

                    if json_file:
                        output_files.append(json_file)
                        status_list.append(True)

                        # Process individual entries for binary data
                        for entry in source_entries:
                            entry_id = entry.get("Id")
                            entry_uri = entry.get("AdditionalDataURI")

                            if entry_uri and entry_id:
                                # Fetch binary log data
                                entry_success, entry_data, _ = (
                                    await self.dispatch_request(
                                        dut_id, "GET", entry_uri
                                    )
                                )

                                if entry_success:
                                    binary_filename = f"{function_tag}_{log_service.lower()}_logs_{entry_id}.tar.xz"
                                    binary_file = (
                                        await self._save_data_with_common_pattern(
                                            dut_id,
                                            entry_data,
                                            function_tag,
                                            output_pattern=binary_filename,
                                            substitutions={"entry_id": entry_id},
                                        )
                                    )

                                    if binary_file:
                                        output_files.append(binary_file)
                                        status_list.append(True)
                else:
                    # Try fallback collection if configured
                    fallback_config = (
                        processing_config.get("fallback_collection")
                        if processing_config
                        else None
                    )
                    if fallback_config:
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"No {log_service} entries found in source logs. Attempting fallback collection.",
                            dut_id,
                        )

                        # Execute fallback collection
                        fallback_result = await self._execute_fallback_collection(
                            dut_id, fallback_config, function_tag, processing_config
                        )

                        if fallback_result["success"]:
                            # Try to find entries again after fallback collection
                            source_entries = (
                                await self._find_filtered_entries_in_source_logs(
                                    dut_id, source_logs, entry_filter, processing_config
                                )
                            )

                            if source_entries:
                                await self._log_runtime(
                                    "INFO",
                                    "RedfishService",
                                    f"Found {len(source_entries)} {log_service} entries after fallback collection",
                                    dut_id,
                                )

                                # Process the entries (same logic as above)
                                entity_base_uri = self.get_configured_uri(
                                    dut_id, entity_type
                                )
                                consolidated_response = {
                                    "@odata.id": f"{entity_base_uri}/System/LogServices/{log_service}/Entries",
                                    "@odata.type": "#LogEntryCollection.LogEntryCollection",
                                    "Description": f"Collection of {log_service} Log Entries",
                                    "Members": source_entries,
                                    "Members@odata.count": len(source_entries),
                                    "Name": f"{log_service} Log Entries",
                                }

                                json_filename = (
                                    f"{function_tag}_{log_service.lower()}_logs.json"
                                )
                                json_file = await self._save_data_with_common_pattern(
                                    dut_id,
                                    consolidated_response,
                                    function_tag,
                                    output_pattern=json_filename,
                                    collector_id=collector_id,
                                )

                                if json_file:
                                    output_files.append(json_file)
                                    status_list.append(True)

                                    # Process individual entries for binary data
                                    for entry in source_entries:
                                        entry_id = entry.get("Id")
                                        entry_uri = entry.get("AdditionalDataURI")

                                        if entry_uri and entry_id:
                                            entry_success, entry_data, _ = (
                                                await self.dispatch_request(
                                                    dut_id, "GET", entry_uri
                                                )
                                            )

                                            if entry_success:
                                                binary_filename = f"{function_tag}_{log_service.lower()}_logs_{entry_id}.tar.xz"
                                                binary_file = await self._save_data_with_common_pattern(
                                                    dut_id,
                                                    entry_data,
                                                    function_tag,
                                                    output_pattern=binary_filename,
                                                    substitutions={
                                                        "entry_id": entry_id
                                                    },
                                                )

                                                if binary_file:
                                                    output_files.append(binary_file)
                                                    status_list.append(True)
                            else:
                                await self._log_runtime(
                                    "INFO",
                                    "RedfishService",
                                    f"No {log_service} entries found even after fallback collection - this is normal if no {log_service} events occurred",
                                    dut_id,
                                )

                                # Generate a report file indicating no CPER entries were found
                                no_entries_report = {
                                    "info": f"{log_service} log collection completed",
                                    "status": "no_entries_found",
                                    "reason": f"No {log_service} entries found - this is normal if no {log_service} events occurred",
                                    "collection_method": "log_processing",
                                    "source_logs": source_logs,
                                    "entry_filter": entry_filter,
                                    "fallback_collection_attempted": True,
                                    "timestamp": datetime.now().isoformat(),
                                    "note": f"This is expected behavior when no {log_service} events have occurred on the system",
                                }

                                report_filename = f"{function_tag}_{log_service.lower()}_no_entries_report.json"
                                report_file = await self._save_data_with_common_pattern(
                                    dut_id,
                                    no_entries_report,
                                    function_tag,
                                    output_pattern=report_filename,
                                    collector_id=collector_id,
                                )

                                return await self._create_standardized_collector_result(
                                    successful_operations=1 if report_file else 0,
                                    total_operations=1,
                                    output_files=[report_file] if report_file else [],
                                    error_messages=[],
                                    operation_name="log_processing_collection",
                                    additional_context={
                                        "log_service": log_service,
                                        "reason": f"No {log_service} entries found - this is normal if no {log_service} events occurred",
                                    },
                                )
                        else:
                            fallback_reason = fallback_result.get("reason")
                            if not fallback_reason:
                                fallback_reason = f"Fallback collection for {log_service} logs failed - no specific error reason provided in fallback result"
                            await self._log_runtime(
                                "WARN",
                                "RedfishService",
                                f"Fallback collection failed: {fallback_reason}",
                                dut_id,
                            )
                            return await self._create_standardized_collector_result(
                                successful_operations=0,
                                total_operations=1,
                                output_files=[],
                                error_messages=[
                                    f"Fallback collection failed: {fallback_reason}"
                                ],
                                operation_name="log_processing_collection",
                                additional_context={
                                    "log_service": log_service,
                                    "fallback_attempted": True,
                                },
                            )
                    else:
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"No {log_service} entries found in source logs and no fallback collection configured - this is normal if no {log_service} events occurred",
                            dut_id,
                        )

                        # Generate a report file indicating no CPER entries were found
                        no_entries_report = {
                            "info": f"{log_service} log collection completed",
                            "status": "no_entries_found",
                            "reason": f"No {log_service} entries found - this is normal if no {log_service} events occurred",
                            "collection_method": "log_processing",
                            "source_logs": source_logs,
                            "entry_filter": entry_filter,
                            "fallback_collection_attempted": False,
                            "timestamp": datetime.now().isoformat(),
                            "note": f"This is expected behavior when no {log_service} events have occurred on the system",
                        }

                        report_filename = f"{function_tag}_{log_service.lower()}_no_entries_report.json"
                        report_file = await self._save_data_with_common_pattern(
                            dut_id,
                            no_entries_report,
                            function_tag,
                            output_pattern=report_filename,
                            collector_id=collector_id,
                        )

                        return await self._create_standardized_collector_result(
                            successful_operations=1 if report_file else 0,
                            total_operations=1,
                            output_files=[report_file] if report_file else [],
                            error_messages=[],
                            operation_name="log_processing_collection",
                            additional_context={
                                "log_service": log_service,
                                "reason": f"No {log_service} entries found - this is normal if no {log_service} events occurred",
                            },
                        )

            successful_operations = len([s for s in status_list if s])
            total_operations = len(status_list) if status_list else 1

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=[],
                operation_name="log_processing_collection",
                additional_context={
                    "log_service": log_service,
                    "reason": f"Processed {len(output_files)} {log_service} log files",
                },
            )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Log processing collection failed: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=0,
                output_files=[],
                error_messages=[f"Log processing failed: {str(e)}"],
                operation_name="log_processing_collection",
                additional_context={
                    "log_service": log_service,
                    "error_type": type(e).__name__,
                },
            )

    async def _handle_collector_error(
        self,
        dut_id: str,
        collector_name: str,
        error_message: str,
        skip_condition: bool = False,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Common error handling for collectors (DRY pattern).

        Args:
            dut_id: DUT ID.
            collector_name: Collector name.
            error_message: Error message.
            skip_condition: Whether this is a skip condition.
            **kwargs: Additional arguments.

        Returns:
            Collector result dictionary.
        """
        await self._log_runtime(
            "ERROR", "RedfishService", f"{collector_name}: {error_message}", dut_id
        )

        if skip_condition:
            await self._log_runtime(
                "WARN",
                "RedfishService",
                f"{collector_name}: Skipping due to {error_message}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"Skipped: {error_message}"],
                operation_name="collection",
                additional_context={
                    "collector_name": collector_name,
                    "status": "skipped",
                },
            )
        else:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[error_message],
                operation_name="collection",
                additional_context={
                    "collector_name": collector_name,
                    "status": "error",
                },
            )

    async def _handle_collector_exception(
        self, dut_id: str, collector_name: str, e: Exception
    ) -> Dict[str, Any]:
        """
        Common exception handler for collectors (DRY pattern).

        Args:
            dut_id: DUT ID.
            collector_name: Collector name.
            e: Exception that occurred.

        Returns:
            Collector result dictionary.
        """
        await self._log_collector_failure(dut_id, collector_name, str(e))
        return await self._create_standardized_collector_result(
            successful_operations=0,
            total_operations=1,
            output_files=[],
            error_messages=[str(e)],
            operation_name="collection",
            additional_context={"collector_name": collector_name},
        )

    async def _handle_collector_result(
        self, dut_id: str, collector_name: str, result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Common result handler for collectors (DRY pattern).

        Args:
            dut_id: DUT ID.
            collector_name: Collector name.
            result: Collection result.

        Returns:
            Collection result dictionary.
        """
        if result["success"]:
            await self._log_collector_success(
                dut_id, collector_name, result.get("context", {})
            )
        else:
            await self._log_collector_failure(
                dut_id, collector_name, "No successful collections"
            )
        return result

    """
    Collector Public API
    """

    async def collect_redfish_unified(
        self,
        dut_id: str,
        collection_type: str,  # "get", "paginated", "collection", "sequential", "uri_list", "expand"
        uri_patterns: Union[str, List[str]] = None,
        entity_type: str = None,
        log_service: str = None,
        function_tag: str = "",
        additional_data_callback: bool = False,
        collection_level_handling: Optional[Dict[str, Any]] = None,
        expand_level: int = 1,
        filter_criteria: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Unified Redfish collection method that handles all core collection patterns.

        Args:
            dut_id: DUT identifier
            collection_type: Type of collection ("get", "paginated", "collection", "sequential", "uri_list", "expand")
            uri_patterns: Single URI or list of URIs to collect from
            entity_type: Entity type (Systems, Managers, Chassis, etc.)
            log_service: Log service name for paginated collections
            function_tag: Function tag for file naming
            additional_data_callback: Whether to collect additional data
            collection_level_handling: Collection level limits
            expand_level: Expansion level for expand collections
            filter_criteria: Filtering criteria for collections
            **kwargs: Additional parameters

        Returns:
            Dict with success status, output files, and context
        """
        collector_name = f"{function_tag}_{collection_type}"

        # Get configurable expand level if this is an expand collection
        if collection_type == "expand":
            collector_def = kwargs.get("collector_def", {})
            dut_config = self.dut_manager.get_dut_config(dut_id)
            expand_level = get_expand_level(
                kwargs.get("collector_id", ""), collector_def, dut_config, expand_level
            )

        # Extract retry_count from collector definition in kwargs
        retry_count = 3  # Default retry count
        if "collector_def" in kwargs and kwargs["collector_def"]:
            retry_count = kwargs["collector_def"].get("retry_count", 3)

        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"collect_redfish_unified called with: function_tag='{function_tag}', collection_type='{collection_type}', collector_name='{collector_name}', retry_count={retry_count}",
            dut_id,
        )

        # Debug: Log all kwargs to see what parameters are being passed
        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"All kwargs received: {list(kwargs.keys())}",
            dut_id,
        )

        # Debug: Log additional_member_collections specifically
        additional_collections = kwargs.get("additional_member_collections", [])
        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"additional_member_collections parameter: {additional_collections}",
            dut_id,
        )
        await self._log_collector_start(dut_id, collector_name)

        # Handle URI list from kwargs (for variable substitution cases)
        uri_list_from_kwargs = kwargs.get("uri_list")
        if uri_list_from_kwargs:
            if isinstance(uri_list_from_kwargs, str):
                # Check if this looks like a variable substitution pattern
                if uri_list_from_kwargs.startswith(
                    "${"
                ) and uri_list_from_kwargs.endswith("}"):
                    # Extract variable name
                    var_name = uri_list_from_kwargs[2:-1]  # Remove ${ and }
                    # Try to get the value from context (validation results)
                    if var_name in kwargs:
                        uri_list_value = kwargs[var_name]
                        if isinstance(uri_list_value, list):
                            uri_list = uri_list_value
                        else:
                            uri_list = [uri_list_value] if uri_list_value else []
                    else:
                        # Fallback to treating as literal string
                        uri_list = [uri_list_from_kwargs]
                else:
                    uri_list = [uri_list_from_kwargs]
            elif isinstance(uri_list_from_kwargs, list):
                uri_list = uri_list_from_kwargs
            else:
                uri_list = []
            # Remove from kwargs to avoid conflicts
            kwargs.pop("uri_list", None)
        else:
            # Check for uri_list_key parameter (for configuration-based URI lists)
            uri_list_key = kwargs.get("uri_list_key")
            if uri_list_key:
                # Get URI list from configuration (DUT config, tool config, or collector defaults)
                try:
                    dut_config = self.dut_manager.get_dut_config(dut_id)
                    dut_uri_list = dut_config.get(uri_list_key, [])

                    # Check DUT-level configuration first (highest priority)
                    if isinstance(dut_uri_list, list) and dut_uri_list:
                        uri_list = dut_uri_list
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Using DUT-level URI list from {uri_list_key}: {uri_list}",
                            dut_id,
                        )
                    else:
                        # Fall back to tool-level configuration (medium priority)
                        orchestrator = getattr(self, "orchestrator", None)
                        if orchestrator and hasattr(orchestrator, "config_manager"):
                            tool_config = orchestrator.config_manager.get_tool_config()
                        else:
                            tool_config = self.dut_manager.tool_config
                        tool_uri_list = tool_config.get(uri_list_key, [])
                        if isinstance(tool_uri_list, list) and tool_uri_list:
                            uri_list = tool_uri_list
                            await self._log_runtime(
                                "INFO",
                                "RedfishService",
                                f"Using tool-level URI list from {uri_list_key}: {uri_list}",
                                dut_id,
                            )
                        else:
                            await self._log_runtime(
                                "WARNING",
                                "RedfishService",
                                f"No URI list found for {uri_list_key} in DUT or tool config - collector will be skipped",
                                dut_id,
                            )
                            return await self._create_standardized_collector_result(
                                dut_id=dut_id,
                                collector_id=kwargs.get("collector_id", function_tag),
                                successful_operations=0,
                                total_operations=0,
                                output_files=[],
                                error_messages=[
                                    f"No URIs provided in configuration - collector skipped"
                                ],
                                operation_name="uri_list_collection",
                                additional_context={"uri_list_key": uri_list_key},
                            )
                except Exception as e:
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        f"Could not load URI list configuration for {uri_list_key}: {e}",
                        dut_id,
                    )
                    return await self._create_standardized_collector_result(
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id", function_tag),
                        successful_operations=0,
                        total_operations=0,
                        output_files=[],
                        error_messages=[f"Configuration error for {uri_list_key}: {e}"],
                        operation_name="uri_list_collection",
                        additional_context={"uri_list_key": uri_list_key},
                    )
            else:
                # Normalize URI patterns to list
                if isinstance(uri_patterns, str):
                    uri_list = [uri_patterns]
                elif isinstance(uri_patterns, list):
                    uri_list = uri_patterns
                else:
                    uri_list = []

            # Apply prefix overrides to URI patterns if URI config manager is available
            if uri_list and self.dut_manager and self.dut_manager.uri_config_manager:
                uri_list = [
                    self.dut_manager.uri_config_manager._apply_prefix_override(uri)
                    for uri in uri_list
                ]

        # Route to appropriate collection handler with proper error handling
        try:
            if collection_type == "get":
                return await self._handle_get_collection(
                    dut_id, uri_list, function_tag, **kwargs
                )
            elif collection_type == "paginated":
                return await self._handle_paginated_collection(
                    dut_id,
                    entity_type,
                    log_service,
                    function_tag,
                    additional_data_callback,
                    collection_level_handling,
                    uri_list,
                    **kwargs,
                )
            elif collection_type == "existing_dumps":
                return await self._handle_existing_dumps_collection(
                    dut_id, entity_type, log_service, function_tag, **kwargs
                )
            elif collection_type == "collection":
                return await self._handle_collection_with_members(
                    dut_id, uri_list, function_tag, **kwargs
                )
            elif collection_type == "sequential":
                return await self._handle_sequential_collection(
                    dut_id, uri_list, function_tag, **kwargs
                )
            elif collection_type == "uri_list":
                return await self._handle_uri_list_collection(
                    dut_id, entity_type, uri_list, function_tag, **kwargs
                )
            elif collection_type == "expand":
                return await self._handle_expand_collection(
                    dut_id, uri_list, expand_level, function_tag, **kwargs
                )
            elif collection_type == "chassis_with_filter":
                return await self._handle_chassis_with_filter_collection(
                    dut_id, uri_list, function_tag, **kwargs
                )
            elif collection_type == "log_processing":
                return await self._handle_log_processing_collection(
                    dut_id, entity_type, log_service, function_tag, **kwargs
                )
            else:
                error_msg = f"Unknown collection_type: {collection_type}"
                await self._log_runtime("ERROR", "RedfishService", error_msg, dut_id)
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[error_msg],
                    operation_name="redfish_unified_collection",
                    additional_context={
                        "collection_type": collection_type,
                        "function_tag": function_tag,
                    },
                )
        except Exception as e:
            error_msg = f"Exception in collect_redfish_unified for collection_type '{collection_type}': {str(e)}"
            await self._log_runtime("ERROR", "RedfishService", error_msg, dut_id)
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=0,
                output_files=[],
                error_messages=[error_msg],
                operation_name="redfish_unified_collection",
                additional_context={
                    "collection_type": collection_type,
                    "function_tag": function_tag,
                    "error_type": type(e).__name__,
                },
            )

    async def _collect_redfish_paginated_logs(
        self,
        dut_id: str,
        entity_type: str,
        log_service: str,
        function_tag: str,
        additional_data_callback: bool = False,
        collection_level_handling: Optional[Dict[str, Any]] = None,
        uri_pattern: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Original paginated logs collection method with full additional data support.

        Args:
            dut_id: DUT ID.
            entity_type: Type of entity.
            log_service: Log service name.
            function_tag: Function tag for naming.
            additional_data_callback: Whether to use additional data callback.
            collection_level_handling: Collection level configuration.
            uri_pattern: Optional URI pattern override.
            **kwargs: Additional arguments including filtered entities.

        Returns:
            Collector result dictionary.
        """
        collector_name = f"{function_tag}_{entity_type}_{log_service}"

        try:
            await self._log_collector_start(dut_id, collector_name)

            # Check if we have validation results with filtered entities
            filtered_systems = kwargs.get("filtered_systems", [])
            filtered_managers = kwargs.get("filtered_managers", [])
            filtered_chassis = kwargs.get("filtered_chassis", [])

            if filtered_systems and entity_type == "Systems":
                # Use filtered systems from validation
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using {len(filtered_systems)} filtered systems from validation: {[sys['id'] for sys in filtered_systems]}",
                    dut_id,
                )
                entity_ids = [sys["id"] for sys in filtered_systems]
                systems_uri = self.get_configured_uri(dut_id, "Systems")
                entities = {
                    "Members": [
                        {"@odata.id": f"{systems_uri}/{sys_id}"}
                        for sys_id in entity_ids
                    ]
                }
            elif filtered_managers and entity_type == "Managers":
                # Use filtered managers from validation
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using {len(filtered_managers)} filtered managers from validation: {[mgr['id'] for mgr in filtered_managers]}",
                    dut_id,
                )
                entity_ids = [mgr["id"] for mgr in filtered_managers]

                # Apply ID filtering based on DUT configuration
                dut_config = self.dut_manager.get_dut_config(dut_id)
                original_manager_ids = entity_ids.copy()
                entity_ids = filter_ids(entity_ids, "manager", dut_config)

                # Log filtered IDs if any were filtered
                if len(entity_ids) != len(original_manager_ids):
                    log_filtered_ids(
                        original_manager_ids, entity_ids, "manager", self.logger, dut_id
                    )

                managers_uri = self.get_configured_uri(dut_id, "Managers")
                entities = {
                    "Members": [
                        {"@odata.id": f"{managers_uri}/{mgr_id}"}
                        for mgr_id in entity_ids
                    ]
                }
            elif filtered_chassis and entity_type == "Chassis":
                # Use filtered chassis from validation
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using {len(filtered_chassis)} filtered chassis from validation: {[chassis['id'] for chassis in filtered_chassis]}",
                    dut_id,
                )
                entity_ids = [chassis["id"] for chassis in filtered_chassis]
                chassis_uri = self.get_configured_uri(dut_id, "Chassis")
                entities = {
                    "Members": [
                        {"@odata.id": f"{chassis_uri}/{chassis_id}"}
                        for chassis_id in entity_ids
                    ]
                }
            else:
                # Get entities - dut_manager handles URI construction automatically
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"No filtered {entity_type.lower()} found in context, fetching all {entity_type}",
                    dut_id,
                )
                entity_uri = self.get_configured_uri(dut_id, entity_type)
                success, entities, _ = await self.dispatch_request(
                    dut_id,
                    "GET",
                    entity_uri,
                    error_context=f"get {entity_type}",
                )

                if not success:
                    return await self._handle_collector_error(
                        dut_id,
                        collector_name,
                        f"Failed to get {entity_type}: {entities}",
                    )

            output_files = []
            all_status_list = []
            all_collected_files = []
            error_messages = []
            skipped_entities = []  # Track entities that were skipped

            # Process entities concurrently for better performance
            async def _process_entity_logs(
                dut_id: str, entity_id: str, **kwargs
            ) -> Dict[str, Any]:
                # _collect_optimized_paginated_logs now returns a standardized collector result
                result = await self._collect_optimized_paginated_logs(
                    dut_id,
                    entity_type,
                    entity_id,
                    log_service,
                    function_tag,
                    additional_data_callback,
                    collection_level_handling,
                    collect_all_pages=kwargs.get("collect_all_pages", False),
                    uri_pattern=kwargs.get("uri_pattern"),
                    retry_count=kwargs.get("retry_count", 3),
                    **kwargs,
                )

                # Return the standardized result directly
                return result

            # Extract entity IDs from members
            members = entities.get("Members", [])
            entity_ids = []
            for member in members:
                odata_id = member.get("@odata.id", "")
                if odata_id:
                    entity_id = odata_id.split("/")[-1]
                    entity_ids.append(entity_id)

            # Process each entity
            for entity_id in entity_ids:
                result = await _process_entity_logs(dut_id, entity_id, **kwargs)

                # Extract data from standardized result
                context = result.get("context", {})
                status = result.get("status", "success")

                # Initialize additional_data to avoid UnboundLocalError in error cases
                additional_data = {}

                # Add detailed logging for result processing
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"UNIFIED_RESULT_DEBUG: {entity_type} {entity_id} - result={result}, status={status}",
                    dut_id,
                )

                # Handle different status types: success, partial, error, skipped
                if status == "skipped":
                    all_status_list.append(True)  # Treat skipped as successful
                    skipped_entities.append(
                        entity_id
                    )  # Track that this entity was skipped
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Skipped collection for {entity_type} {entity_id}: {result.get('reason', 'Unknown reason')}",
                        dut_id,
                    )
                elif status in ["success", "partial"]:
                    # Extract data from standardized result for success/partial
                    status_list = context.get(
                        "status_list", [True]
                    )  # Default to success
                    collected_files = context.get("output_files", [])
                    additional_data = context.get("additional_data", {})

                    # Extend status list and collected files
                    all_status_list.extend(status_list)
                    all_collected_files.extend(collected_files)

                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Adding {len(collected_files)} files from {entity_type} {entity_id} to all_collected_files: {collected_files}",
                        dut_id,
                    )
                else:
                    # Handle failure case (status == "error")
                    all_status_list.append(False)
                    error_messages.append(
                        f"{entity_type} {entity_id}: {result.get('reason', 'Unknown error')}"
                    )

                    # Create error log file for failed operations
                    error_log_path = await self._create_error_log_file(
                        dut_id=dut_id,
                        collector_id=collector_name,
                        error_message=result.get("reason", "Unknown error"),
                        context={
                            "entity_type": entity_type,
                            "entity_id": entity_id,
                            "operation": "paginated_logs_collection",
                            "result": result,
                        },
                    )

                    # Add error log file to output files
                    if error_log_path:
                        all_collected_files.append(error_log_path)

                # Check for error in additional_data (now handled in the result structure above)
                # Additional data error handling is now done in the standardized result

                # Handle additional data if callback is enabled
                if additional_data_callback and additional_data:
                    # Debug logging
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Processing additional data for {entity_type} {entity_id}: {len(additional_data)} attachments",
                        dut_id,
                    )

                    additional_data_pattern = kwargs.get("additional_data_pattern", "")
                    if additional_data_pattern:
                        # Use the additional data pattern with proper substitutions
                        additional_filename = self.substitute_output_pattern_variables(
                            additional_data_pattern,
                            {
                                self._get_entity_id_key(entity_type): entity_id,
                            },
                            f"{function_tag}_{entity_type}_{entity_id}_additional_data.json",
                        )
                    else:
                        additional_filename = f"{function_tag}_{entity_type}_{entity_id}_additional_data.json"

                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Saving additional data to: {additional_filename}",
                        dut_id,
                    )

                    additional_file = await self._save_data_to_file_with_pattern(
                        dut_id,
                        additional_data,
                        additional_filename,
                        additional_data_pattern=additional_data_pattern,
                        substitutions={
                            self._get_entity_id_key(entity_type): entity_id,
                            "entity_id": entity_id,
                        },
                        collector_id=kwargs.get("collector_id"),
                    )

                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Additional data save result: {additional_file}",
                        dut_id,
                    )

                    if additional_file:
                        all_collected_files.append(additional_file)
                    else:
                        await self._log_runtime(
                            "ERROR",
                            "RedfishService",
                            f"Failed to save additional data for {entity_type} {entity_id}",
                            dut_id,
                        )
                else:
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Additional data callback disabled or no additional data for entity {entity_id}",
                        dut_id,
                    )

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"About to extend output_files with {len(all_collected_files)} files from all_collected_files: {all_collected_files}",
                dut_id,
            )
            output_files.extend(all_collected_files)
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"output_files now has {len(output_files)} total files: {output_files}",
                dut_id,
            )

            # Create standardized result in one call
            successful_collections = len([s for s in all_status_list if s])
            total_collections = len(all_status_list)

            # Handle the case where no collections were attempted (e.g., no entries in EventLog)
            # This should be considered a successful collection with no data, not a failure
            if total_collections == 0:
                # No collections attempted - this is a successful collection with no data
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"No collections attempted for {entity_type} {log_service} - this is a successful collection with no data",
                    dut_id,
                )
                result = await self._create_standardized_collector_result(
                    dut_id=dut_id,
                    collector_id=kwargs.get(
                        "collector_id", f"{entity_type}_{log_service}"
                    ),
                    successful_operations=1,  # Consider this successful
                    total_operations=1,
                    output_files=output_files,
                    error_messages=[],
                    operation_name="collections",
                    additional_context={
                        "entities_processed": len(entity_ids),
                        "successful_collections": 1,
                        "total_collections": 1,
                        "no_data_collected": True,
                        "reason": f"No {log_service} entries found for {entity_type} - collection successful with no data",
                    },
                )
            elif successful_collections == 0 and total_collections > 0:
                # All collections failed - check if this is due to service not being available
                # If all errors are 404s, treat as "skipped" rather than "error"
                all_404_errors = all(
                    "404" in error
                    or "not found" in error.lower()
                    or "not supported" in error.lower()
                    for error in error_messages
                )

                # Check if all errors are pagination-related (502, 503, etc.)
                all_pagination_errors = all(
                    any(
                        pagination_error in error.lower()
                        for pagination_error in [
                            "502",
                            "503",
                            "504",
                            "bad gateway",
                            "service unavailable",
                            "gateway timeout",
                            "timeout",
                            "connection refused",
                        ]
                    )
                    for error in error_messages
                )

                if all_404_errors:
                    # Service not available - treat as skipped
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"{log_service} service not available for {entity_type} - treating as skipped",
                        dut_id,
                    )
                    result = await self._create_standardized_collector_result(
                        dut_id=dut_id,
                        collector_id=kwargs.get(
                            "collector_id", f"{entity_type}_{log_service}"
                        ),
                        successful_operations=0,
                        total_operations=total_collections,
                        output_files=output_files,
                        error_messages=[],
                        operation_name="collections",
                        additional_context={
                            "entities_processed": len(entity_ids),
                            "successful_collections": 0,
                            "total_collections": total_collections,
                            "service_not_available": True,
                            "status": "skipped",
                            "reason": f"{log_service} service not available for {entity_type} - collector skipped",
                        },
                    )
                elif all_pagination_errors:
                    # Pagination errors (502, 503, etc.) - treat as partial success if we have files, error if not
                    status = "partial" if len(output_files) > 0 else "error"
                    await self._log_runtime(
                        "WARN" if status == "partial" else "ERROR",
                        "RedfishService",
                        f"Pagination errors for {log_service} on {entity_type} - treating as {status} with {len(output_files)} files collected",
                        dut_id,
                    )

                    # Create detailed error message with specific URIs and retry information
                    detailed_error_msg = f"Pagination errors (502/503) occurred for {log_service} on {entity_type}. "
                    if len(output_files) > 0:
                        detailed_error_msg += f"Successfully collected {len(output_files)} files before encountering errors. "
                    detailed_error_msg += (
                        f"Error details saved to JSON files for manual investigation."
                    )

                    result = await self._create_standardized_collector_result(
                        dut_id=dut_id,
                        collector_id=kwargs.get(
                            "collector_id", f"{entity_type}_{log_service}"
                        ),
                        successful_operations=len(
                            output_files
                        ),  # Count files as successful operations
                        total_operations=total_collections,
                        output_files=output_files,
                        error_messages=error_messages,
                        operation_name="collections",
                        additional_context={
                            "entities_processed": len(entity_ids),
                            "successful_collections": len(output_files),
                            "total_collections": total_collections,
                            "pagination_errors": True,
                            "status": status,
                            "reason": detailed_error_msg,
                        },
                    )
                else:
                    # Real errors occurred
                    result = await self._create_standardized_collector_result(
                        successful_operations=successful_collections,
                        total_operations=total_collections,
                        output_files=output_files,
                        error_messages=error_messages,
                        operation_name="collections",
                        additional_context={
                            "entities_processed": len(entity_ids),
                            "successful_collections": successful_collections,
                            "total_collections": total_collections,
                        },
                    )
            else:
                # Check if all entities were skipped
                if skipped_entities and len(skipped_entities) == len(entity_ids):
                    # All entities were skipped - treat as skipped
                    result = await self._create_standardized_collector_result(
                        successful_operations=0,
                        total_operations=total_collections,
                        output_files=output_files,
                        error_messages=error_messages,
                        operation_name="collections",
                        additional_context={
                            "entities_processed": len(entity_ids),
                            "successful_collections": successful_collections,
                            "total_collections": total_collections,
                            "skipped_entities": skipped_entities,
                            "status": "skipped",
                            "reason": f"All {entity_type} entities were skipped due to service not being available",
                        },
                    )
                else:
                    result = await self._create_standardized_collector_result(
                        successful_operations=successful_collections,
                        total_operations=total_collections,
                        output_files=output_files,
                        error_messages=error_messages,
                        operation_name="collections",
                        additional_context={
                            "entities_processed": len(entity_ids),
                            "successful_collections": successful_collections,
                            "total_collections": total_collections,
                        },
                    )

            return await self._handle_collector_result(dut_id, collector_name, result)

        except Exception as e:
            return await self._handle_collector_exception(dut_id, collector_name, e)

    async def _collect_optimized_paginated_logs(
        self,
        dut_id: str,
        entity_type: str,
        entity_id: str,
        log_service: str,
        function_tag: str,
        additional_data_callback: bool = False,
        collection_level_handling: Optional[Dict[str, Any]] = None,
        uri_pattern: Optional[str] = None,
        retry_count: int = 3,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        This function collects paginated logs from Redfish endpoints using a simple,
        reliable approach that always saves data and handles collection levels properly.
        """
        try:
            # Initialize collection variables
            collected_files = []

            # Get collection level and determine skip amount
            collection_level = kwargs.get("collection_level", "L3")
            collect_all_pages = kwargs.get("collect_all_pages", False)

            # Get configurable nextLink field name (default to standard Redfish)
            next_link_field = kwargs.get("next_link_field", "Members@odata.nextLink")
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Using nextLink field: '{next_link_field}' for {entity_type} {entity_id}",
                dut_id,
            )

            # Use common skip amount calculator
            if collect_all_pages:
                skip_amount = 0
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"COLLECT_ALL_PAGES flag enabled: collecting all pages from beginning for {entity_type} {entity_id}",
                    dut_id,
                )
            else:
                skip_amount = self._get_skip_amount(
                    collection_level, collection_level_handling
                )
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using collection level {collection_level}: skipping to {skip_amount} entries back from total for {entity_type} {entity_id}",
                    dut_id,
                )

            # Build the base URI for the log service
            if uri_pattern:
                base_uri = uri_pattern.replace("{entity_id}", entity_id)
            else:
                entity_base_uri = self.get_configured_uri(dut_id, entity_type)
                base_uri = (
                    f"{entity_base_uri}/{entity_id}/LogServices/{log_service}/Entries"
                )

            # Check for custom URIs in configuration (generic approach)
            # Skip this check if we're already processing custom URIs to avoid infinite recursion
            custom_uri_key = kwargs.get("custom_uri_key")
            if custom_uri_key and not kwargs.get("_processing_custom_uris", False):
                # Check for custom URIs in configuration
                custom_uris = await self._get_custom_uris_from_config(
                    dut_id, entity_id, custom_uri_key, entity_type
                )
                if custom_uris:
                    # Use custom URIs instead of default service
                    return await self._collect_custom_uris(
                        dut_id,
                        entity_type,
                        entity_id,
                        custom_uris,
                        function_tag,
                        log_service,
                        **kwargs,
                    )

            # For PostCodes log service, check if the service exists before accessing Entries
            if log_service == "PostCodes":
                if uri_pattern:
                    # Extract the service URI from the pattern by removing "/Entries"
                    log_service_uri = uri_pattern.replace(
                        "{entity_id}", entity_id
                    ).replace("/Entries", "")
                else:
                    log_service_uri = (
                        f"{entity_base_uri}/{entity_id}/LogServices/{log_service}"
                    )
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Checking PostCodes service existence: GET {log_service_uri} for {entity_type} {entity_id}",
                    dut_id,
                )

                service_success, service_response, _ = await self.dispatch_request(
                    dut_id,
                    "GET",
                    log_service_uri,
                    error_context=f"check {log_service} service for {entity_type} {entity_id}",
                    bypass_cache=True,
                    retry_count=retry_count,
                )

                if not service_success:
                    entity_type_singular = entity_type.lower().rstrip("s")
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"PostCodes service is not available on this {entity_type_singular} type ({entity_id})",
                        dut_id,
                    )

                    # Create a JSON file documenting that PostCodes service is not available
                    info_response = {
                        "info": f"PostCodes service check attempted",
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "service_uri": log_service_uri,
                        "status": "service_not_available",
                        "reason": f"PostCodes service is not available on this {entity_type_singular} type",
                        "error_details": (
                            service_response
                            if isinstance(service_response, dict)
                            else {"raw_response": str(service_response)}
                        ),
                        "timestamp": datetime.now().isoformat(),
                        "note": f"This {entity_type_singular} type does not support PostCodes service via Redfish",
                    }

                    output_file = (
                        f"{function_tag}_postcodes_service_check_{entity_id}.json"
                    )
                    file_path = await self._save_data_to_file_with_pattern(
                        dut_id,
                        info_response,
                        output_file,
                        filename=kwargs.get("filename", ""),
                        substitutions={"entity_id": entity_id},
                        collector_id=kwargs.get("collector_id"),
                    )
                    return await self._create_standardized_collector_result(
                        dut_id=dut_id,
                        collector_id=kwargs.get(
                            "collector_id", f"{entity_type}_{entity_id}_{log_service}"
                        ),
                        successful_operations=0,
                        total_operations=1,
                        output_files=[file_path] if file_path else [],
                        error_messages=[
                            f"PostCodes service is not available on this {entity_type_singular} type"
                        ],
                        operation_name="service_check",
                        additional_context={
                            "entity_type": entity_type,
                            "entity_id": entity_id,
                            "log_service": log_service,
                            "service_not_available": True,
                            "status": "skipped",
                            "reason": f"PostCodes service is not available on this {entity_type_singular} type",
                        },
                    )

            # Log the initial request URI for debugging
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"INITIAL_REQUEST_URI: GET {base_uri} for {entity_type} {entity_id}",
                dut_id,
            )

            # Get initial response to determine total entries
            success, response, _ = await self.dispatch_request(
                dut_id,
                "GET",
                base_uri,
                error_context=f"fetch {log_service} Logs for {entity_type} {entity_id}",
                bypass_cache=True,
                retry_count=retry_count,
            )

            if not success:
                # Debug: Log the actual response to understand what's happening
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Initial request failed for {log_service} logs on {entity_type} {entity_id}. Response type: {type(response)}, Response: {response}",
                    dut_id,
                )

                # Check if this is a 404 (URI not found) - this is not a failure, just informational
                is_404_error = self._is_404_error(response)
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"404 check result for {log_service} logs on {entity_type} {entity_id}: {is_404_error}",
                    dut_id,
                )

                if is_404_error:
                    entity_type_singular = entity_type.lower().rstrip("s")
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"{log_service} logs are not supported on this {entity_type_singular} type ({entity_id})",
                        dut_id,
                    )

                    # Create a JSON file documenting that logs are not available
                    info_response = {
                        "info": f"{log_service} log collection attempted",
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "uri": base_uri,
                        "status": "not_supported",
                        "reason": f"{log_service} logs appear to not be supported on this {entity_type_singular} type",
                        "error_details": (
                            response
                            if isinstance(response, dict)
                            else {"raw_response": str(response)}
                        ),
                        "timestamp": datetime.now().isoformat(),
                        "note": f"This {entity_type_singular} type does not support {log_service} log collection via Redfish",
                    }

                    output_file = (
                        f"{function_tag}_{log_service.lower()}_entries_{entity_id}.json"
                    )
                    file_path = await self._save_data_to_file_with_pattern(
                        dut_id,
                        info_response,
                        output_file,
                        filename=kwargs.get("filename", ""),
                        substitutions={"entity_id": entity_id},
                        collector_id=kwargs.get("collector_id"),
                    )
                    return await self._create_standardized_collector_result(
                        dut_id=dut_id,
                        collector_id=kwargs.get(
                            "collector_id", f"{entity_type}_{entity_id}_{log_service}"
                        ),
                        successful_operations=0,
                        total_operations=1,
                        output_files=[file_path] if file_path else [],
                        error_messages=[
                            f"{log_service} logs are not supported on this {entity_type_singular} type"
                        ],
                        operation_name="404_handling",
                        additional_context={
                            "entity_type": entity_type,
                            "entity_id": entity_id,
                            "log_service": log_service,
                            "service_not_available": True,
                            "status": "error",
                            "reason": f"{log_service} logs are not supported on this {entity_type_singular} type",
                        },
                    )
                else:
                    error_msg = f"Failed to collect {log_service} logs for {entity_type} {entity_id}: {response}"
                    return await self._create_standardized_collector_result(
                        dut_id=dut_id,
                        collector_id=kwargs.get(
                            "collector_id", f"{entity_type}_{entity_id}_{log_service}"
                        ),
                        successful_operations=0,
                        total_operations=1,
                        output_files=[],
                        error_messages=[error_msg],
                        operation_name="request_failure",
                        additional_context={
                            "entity_type": entity_type,
                            "entity_id": entity_id,
                            "log_service": log_service,
                            "error_type": "request_failure",
                        },
                    )

            # Save the initial metadata response
            initial_metadata_file = await self._save_data_to_file_with_pattern(
                dut_id,
                response,
                f"{function_tag}_{log_service.lower()}_initial_metadata_{entity_id}.json",
                filename=kwargs.get("filename", ""),
                substitutions={"entity_id": entity_id},
                collector_id=kwargs.get("collector_id"),
            )

            if initial_metadata_file:
                collected_files.append(initial_metadata_file)
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Saved initial metadata for {entity_type} {entity_id} to: {initial_metadata_file}",
                    dut_id,
                )

            # Extract total entries count
            total_entries = response.get("Members@odata.count")
            if total_entries is None:
                total_entries = response.get("@odata.count")

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Initial {log_service} response for {entity_type} {entity_id}: total_entries={total_entries}",
                dut_id,
            )

            # Calculate collection parameters
            page_size = 100  # Standard page size
            start_skip = 0
            estimated_pages = None
            max_entries_to_collect = None

            if collection_level and skip_amount > 0 and total_entries is not None:
                # Calculate start_skip for collection level
                start_skip = max(0, total_entries - skip_amount)
                entries_to_collect = total_entries - start_skip
                max_entries_to_collect = entries_to_collect
                estimated_pages = max(
                    1, (entries_to_collect + page_size - 1) // page_size
                )

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Level {collection_level} collection for {entity_type} {entity_id}: collecting {entries_to_collect} entries from skip={start_skip} (estimated {estimated_pages} pages)",
                    dut_id,
                )
            else:
                # Collect all available entries
                entries_to_collect = total_entries if total_entries else None
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Collecting all available entries for {entity_type} {entity_id}",
                    dut_id,
                )

            # Initialize collection variables
            all_entries = []
            additional_data = {}
            status_list = (
                []
            )  # Status per page - important for partial success determination
            page_timings = []  # Track timing for each page
            page = 1
            max_pages = 100  # Safety limit
            collection_start_time = time.time()

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"=== STARTING SIMPLE PAGINATION FOR {entity_type} {entity_id} ===",
                dut_id,
            )
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Total entries: {total_entries}, Target skip: {start_skip}, Collection level: {collection_level}",
                dut_id,
            )

            # Pagination approach - use $skip if specified
            current_uri = base_uri

            if start_skip > 0:
                current_uri = f"{base_uri}?$skip={start_skip}"
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Starting pagination with skip={start_skip} for {entity_type} {entity_id}",
                    dut_id,
                )
            else:
                current_uri = base_uri
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Starting pagination from beginning for {entity_type} {entity_id}",
                    dut_id,
                )

            # Simple pagination loop
            page_count = (
                0  # Actual page number (increments only when moving to next page)
            )
            total_entries_collected = 0
            max_pages = 100  # Safety limit
            page_retry_count = 0  # Track retries at pagination level
            max_page_retries = 2  # Maximum retries per page at pagination level
            retry_delay = 2  # Simple 2-second delay between retries
            current_page_retry = 0  # Track retries for current page

            while current_uri and page_count < max_pages:
                # Only increment page_count if we're not in a retry
                if current_page_retry == 0:
                    page_count += 1
                page_start_time = time.time()

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Fetching page {page_count} for {entity_type} {entity_id}: {current_uri}",
                    dut_id,
                )

                # Log the exact URI for manual reproduction
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"EXACT_URI_FOR_CURL: GET {current_uri}",
                    dut_id,
                )

                # Fetch the current page
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Making request: GET {current_uri} (retry_count={retry_count})",
                    dut_id,
                )

                success, response, _ = await self.dispatch_request(
                    dut_id,
                    "GET",
                    current_uri,
                    error_context=f"fetch page {page_count} for {entity_type} {entity_id}",
                    bypass_cache=True,
                    retry_count=retry_count,
                )

                page_duration = time.time() - page_start_time

                # Log the response details
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Page {page_count} response: success={success}, type={type(response)}, content={str(response)[:500]}...",
                    dut_id,
                )

                if not success:
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Failed to fetch page {page_count} for {entity_type} {entity_id}: {response}",
                        dut_id,
                    )

                    # Save the failed response for debugging purposes
                    failed_response_data = {
                        "error_type": "request_failed",
                        "success": success,
                        "response": response,
                        "page_count": page_count,
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "log_service": log_service,
                        "timestamp": time.time(),
                    }

                    if current_page_retry > 0:
                        failed_response_file = f"{function_tag}_{log_service.lower()}_{entity_id}_page{page_count}_retry{current_page_retry}_failed.json"
                    else:
                        failed_response_file = f"{function_tag}_{log_service.lower()}_{entity_id}_page{page_count}_failed.json"
                    failed_file_path = await self._save_data_to_file_with_pattern(
                        dut_id,
                        failed_response_data,
                        failed_response_file,
                        filename=kwargs.get("filename", ""),
                        substitutions={"entity_id": entity_id},
                        collector_id=kwargs.get("collector_id"),
                    )

                    if failed_file_path:
                        collected_files.append(failed_file_path)
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Saved failed response for page {page_count} to: {failed_file_path}",
                            dut_id,
                        )

                    # Save detailed error information for debugging
                    error_details = {
                        "page_count": page_count,
                        "uri": current_uri,
                        "response": response,
                        "retry_count": page_retry_count,
                        "max_retries": max_page_retries,
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "log_service": log_service,
                        "timestamp": time.time(),
                    }

                    # Save error details to a specific error file
                    if current_page_retry > 0:
                        error_file = f"{function_tag}_{log_service.lower()}_{entity_id}_page{page_count}_retry{current_page_retry}_error_details.json"
                    else:
                        error_file = f"{function_tag}_{log_service.lower()}_{entity_id}_page{page_count}_error_details.json"
                    error_file_path = await self._save_data_to_file_with_pattern(
                        dut_id,
                        error_details,
                        error_file,
                        filename=kwargs.get("filename", ""),
                        substitutions={"entity_id": entity_id},
                        collector_id=kwargs.get("collector_id"),
                    )

                    if error_file_path:
                        collected_files.append(error_file_path)
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Saved error details for page {page_count} to: {error_file_path}",
                            dut_id,
                        )

                    # Even if the request failed, the response might contain valid data
                    # Try to parse it as JSON and save it if it looks like valid data
                    if isinstance(response, str) and response.startswith("HTTP 502:"):
                        # Extract the actual response content after "HTTP 502: "
                        response_content = response[9:]  # Remove "HTTP 502: " prefix
                        try:
                            parsed_response = json.loads(response_content)
                            if (
                                isinstance(parsed_response, dict)
                                and "Members" in parsed_response
                            ):
                                await self._log_runtime(
                                    "INFO",
                                    "RedfishService",
                                    f"Page {page_count}: Got 502 but response contains valid data with {len(parsed_response.get('Members', []))} entries",
                                    dut_id,
                                )

                                # Save the valid response despite the 502
                                output_file = f"{function_tag}_{log_service.lower()}_{entity_id}_page{page_count}_502_error.json"
                                file_path = await self._save_data_to_file_with_pattern(
                                    dut_id,
                                    parsed_response,
                                    output_file,
                                    filename=kwargs.get("filename", ""),
                                    substitutions={"entity_id": entity_id},
                                    collector_id=kwargs.get("collector_id"),
                                )

                                if file_path:
                                    collected_files.append(file_path)
                                    await self._log_runtime(
                                        "INFO",
                                        "RedfishService",
                                        f"Saved page {page_count} (502 error but valid data) to: {file_path}",
                                        dut_id,
                                    )

                                    # Process the entries from this response
                                    entries = parsed_response.get("Members", [])
                                    if isinstance(entries, list):
                                        entries_in_page = len(entries)
                                        total_entries_collected += entries_in_page

                                        await self._log_runtime(
                                            "INFO",
                                            "RedfishService",
                                            f"Page {page_count} (502): collected {entries_in_page} entries (total: {total_entries_collected})",
                                            dut_id,
                                        )

                                        status_list.append(
                                            True
                                        )  # Mark as successful since we got data
                                        page_timings.append(
                                            {
                                                "page": page_count,
                                                "entries": entries_in_page,
                                                "duration": page_duration,
                                                "status": True,
                                                "file": file_path,
                                                "note": "502 error but valid data saved",
                                            }
                                        )

                                        # Check for next link
                                        if parsed_response.get(next_link_field):
                                            current_uri = parsed_response.get(
                                                next_link_field
                                            )
                                            await self._log_runtime(
                                                "INFO",
                                                "RedfishService",
                                                f"Page {page_count} (502): continuing with next link: {current_uri}",
                                                dut_id,
                                            )
                                            continue
                                        else:
                                            await self._log_runtime(
                                                "INFO",
                                                "RedfishService",
                                                f"Page {page_count} (502): no next link, stopping pagination",
                                                dut_id,
                                            )
                                            break
                        except (json.JSONDecodeError, Exception) as e:
                            await self._log_runtime(
                                "ERROR",
                                "RedfishService",
                                f"Page {page_count}: Failed to parse 502 response as JSON: {e}",
                                dut_id,
                            )

                    # Handle failed request - simple retry with 5-second delay
                    if response != "retry" and page_retry_count < max_page_retries:
                        page_retry_count += 1

                        await self._log_runtime(
                            "WARN",
                            "RedfishService",
                            f"Page {page_count}: Request failed with '{response}' - retrying {page_retry_count}/{max_page_retries} - waiting {retry_delay}s",
                            dut_id,
                        )
                        await asyncio.sleep(retry_delay)

                        # Try the same page again
                        continue

                    # Check if this is a retry signal from DUT manager
                    if response == "retry":
                        page_retry_count += 1
                        current_page_retry += 1
                        await self._log_runtime(
                            "WARN",
                            "RedfishService",
                            f"Page {page_count}: Received retry signal from DUT manager for {entity_type} {entity_id} - this indicates server error (HTTP 5xx) (retry {page_retry_count}/{max_page_retries})",
                            dut_id,
                        )

                        if page_retry_count <= max_page_retries:
                            # Simple retry with 2-second delay for retry signals
                            # This handles cases where the BMC is temporarily overloaded

                            await self._log_runtime(
                                "INFO",
                                "RedfishService",
                                f"Page {page_count}: Retry signal from DUT manager {page_retry_count}/{max_page_retries} - waiting {retry_delay}s",
                                dut_id,
                            )
                            await asyncio.sleep(retry_delay)

                            # Try the same page again
                            continue
                        else:
                            # Exhausted pagination-level retries - mark this page as failed and continue
                            status_list.append(False)
                            error_msg = f"HTTP 502 Bad Gateway - BMC server error (possibly pagination limit exceeded with skip={skip_amount}, exhausted {max_page_retries} retries)"

                            # Create error log file for failed pagination
                            error_log_path = await self._create_error_log_file(
                                dut_id=dut_id,
                                collector_id=kwargs.get("collector_id"),
                                error_message=error_msg,
                                context={
                                    "entity_type": entity_type,
                                    "entity_id": entity_id,
                                    "log_service": log_service,
                                    "page": page_count,
                                    "skip_amount": skip_amount,
                                    "operation": "pagination_retry_exhausted",
                                },
                            )

                            # Add error log file to output files
                            if error_log_path:
                                collected_files.append(error_log_path)

                            page_timings.append(
                                {
                                    "page": page_count,
                                    "entries": 0,  # No entries collected for failed page
                                    "duration": page_duration,
                                    "status": False,
                                    "error": error_msg,
                                }
                            )
                            await self._log_runtime(
                                "WARN",
                                "RedfishService",
                                f"Page {page_count}: Exhausted pagination-level retries for {entity_type} {entity_id} - continuing to next page",
                                dut_id,
                            )
                            # Continue to next page instead of breaking
                    else:
                        # Non-retry failure - mark as failed
                        status_list.append(False)
                        # Provide more specific error message based on response type
                        if response == "retry":
                            error_msg = f"HTTP 502 Bad Gateway - BMC server error (possibly pagination limit exceeded with skip={skip_amount})"
                        elif isinstance(response, str) and response.startswith(
                            "HTTP 5"
                        ):
                            error_msg = f"Server error: {response}"
                        elif isinstance(response, str) and response.startswith(
                            "HTTP 4"
                        ):
                            error_msg = f"Client error: {response}"
                        else:
                            error_msg = f"Request failed: {str(response)}"

                        # Create error log file for failed pagination
                        error_log_path = await self._create_error_log_file(
                            dut_id=dut_id,
                            collector_id=kwargs.get("collector_id"),
                            error_message=error_msg,
                            context={
                                "entity_type": entity_type,
                                "entity_id": entity_id,
                                "log_service": log_service,
                                "page": page_count,
                                "skip_amount": skip_amount,
                                "response": str(response),
                                "operation": "pagination_request_failed",
                            },
                        )

                        # Add error log file to output files
                        if error_log_path:
                            collected_files.append(error_log_path)

                        page_timings.append(
                            {
                                "page": page_count,
                                "entries": 0,  # No entries collected for failed page
                                "duration": page_duration,
                                "status": False,
                                "error": error_msg,
                            }
                        )

                        # Continue to next page if possible (only if we have a nextLink)
                        if (
                            response
                            and isinstance(response, dict)
                            and response.get(next_link_field)
                        ):
                            current_uri = response.get(next_link_field)
                            current_page_retry = 0  # Reset retry count for new page
                            continue
                        else:
                            # No nextLink available - stop pagination
                            await self._log_runtime(
                                "INFO",
                                "RedfishService",
                                f"Page {page_count}: No nextLink available, stopping pagination for {entity_type} {entity_id}",
                                dut_id,
                            )
                            break

                # Get entries from this page
                entries = []  # Initialize entries to empty list by default

                if not isinstance(response, dict):
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Page {page_count} response is not a dictionary: {type(response)} - {response}",
                        dut_id,
                    )
                    status_list.append(False)
                    # Provide user-friendly error message based on response type
                    if response == "retry":
                        error_msg = f"HTTP 502 Bad Gateway - BMC server error (possibly pagination limit exceeded with skip={skip_amount})"
                    elif isinstance(response, str) and response.startswith("HTTP 5"):
                        error_msg = f"Server error: {response}"
                    elif isinstance(response, str) and response.startswith("HTTP 4"):
                        error_msg = f"Client error: {response}"
                    else:
                        error_msg = f"Unexpected response format: {str(response)}"

                    # Create error log file for failed pagination
                    error_log_path = await self._create_error_log_file(
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id"),
                        error_message=error_msg,
                        context={
                            "entity_type": entity_type,
                            "entity_id": entity_id,
                            "log_service": log_service,
                            "page": page_count,
                            "skip_amount": skip_amount,
                            "response_type": type(response).__name__,
                            "response": str(response),
                            "operation": "pagination_response_format_error",
                        },
                    )

                    # Add error log file to output files
                    if error_log_path:
                        collected_files.append(error_log_path)

                    page_timings.append(
                        {
                            "page": page_count,
                            "duration": page_duration,
                            "status": False,
                            "error": error_msg,
                        }
                    )

                    # Non-dict response (like "retry") - mark as failed and stop
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Page {page_count}: Non-dict response '{response}', stopping pagination",
                        dut_id,
                    )
                    break

                entries = response.get("Members", [])
                if not isinstance(entries, list):
                    entries = []

                entries_in_page = len(entries)
                total_entries_collected += entries_in_page

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Page {page_count}: collected {entries_in_page} entries (total: {total_entries_collected})",
                    dut_id,
                )

                # Save this page to file
                if current_page_retry > 0:
                    output_file = f"{function_tag}_{log_service.lower()}_{entity_id}_page{page_count}_retry{current_page_retry}.json"
                else:
                    output_file = f"{function_tag}_{log_service.lower()}_{entity_id}_page{page_count}.json"
                file_path = await self._save_data_to_file_with_pattern(
                    dut_id,
                    response,
                    output_file,
                    filename=kwargs.get("filename", ""),
                    substitutions={"entity_id": entity_id},
                    collector_id=kwargs.get("collector_id"),
                )

                if file_path:
                    collected_files.append(file_path)
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Saved page {page_count} to: {file_path}",
                        dut_id,
                    )

                status_list.append(True)
                page_timings.append(
                    {
                        "page": page_count,
                        "entries": entries_in_page,
                        "duration": page_duration,
                        "status": True,
                        "file": file_path,
                    }
                )

                # Reset retry counter on successful page
                page_retry_count = 0

                # Process additional data if callback provided
                if additional_data_callback and entries:
                    # Collect all additional data URIs for this page
                    additional_data_uris = [
                        entry.get("AdditionalDataURI")
                        for entry in entries
                        if entry.get("AdditionalDataURI")
                    ]

                    if additional_data_uris:
                        # Make concurrent requests for additional data with limited concurrency
                        additional_requests = [
                            (uri, f"get additional data from {uri}")
                            for uri in additional_data_uris
                        ]

                        # Limit concurrent requests to prevent BMC overload
                        additional_results = await self._concurrent_redfish_requests(
                            dut_id,
                            additional_requests,
                            max_concurrent=3,  # Reduced from DEFAULT_MAX_CONCURRENT_REQUESTS
                        )

                        # Process results
                        for i, (success, response, _) in enumerate(additional_results):
                            if success:
                                additional_data[additional_data_uris[i]] = response

                # Collect entries for processing
                all_entries.extend(entries)

                # Check if we've reached the collection level limit
                if (
                    max_entries_to_collect is not None
                    and len(all_entries) >= max_entries_to_collect
                ):
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Reached collection level limit for {entity_type} {entity_id}: collected {len(all_entries)} entries (limit: {max_entries_to_collect} for {collection_level})",
                        dut_id,
                    )
                    break

                # Get next page URI from response
                if (
                    response
                    and isinstance(response, dict)
                    and response.get(next_link_field)
                ):
                    next_link = response.get(next_link_field)
                    current_uri = next_link
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Next page URI: {current_uri}",
                        dut_id,
                    )
                else:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"No more pages available for {entity_type} {entity_id}",
                        dut_id,
                    )
                    break

                # Add delay between pages to prevent BMC overload
                # Use moderate delays for BMC rate limiting - reduced for faster execution
                page_delay = 1  # 1 second between pages (reduced from 3)
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Waiting {page_delay}s before next page to respect BMC rate limits",
                    dut_id,
                )
                await asyncio.sleep(page_delay)

            # Print timing summary table for this entity
            if page_timings:
                total_time = sum(page.get("duration", 0) for page in page_timings)
                total_entries_from_pages = sum(
                    page.get("entries", 0) for page in page_timings
                )
                avg_time_per_page = total_time / len(page_timings)
                avg_time_per_entry = (
                    total_time / total_entries_from_pages
                    if total_entries_from_pages > 0
                    else 0
                )

                summary_lines = []
                summary_lines.append("=" * 80)
                summary_lines.append(
                    f"TIMING SUMMARY FOR {entity_type.upper()} {entity_id}"
                )
                summary_lines.append("=" * 80)
                summary_lines.append(f"Log service: {log_service}")
                summary_lines.append(f"Collection level: {collection_level}")
                summary_lines.append(f"Skip amount: {skip_amount}")
                summary_lines.append(f"Start skip position: {start_skip}")
                summary_lines.append(f"Total entries available: {total_entries}")
                summary_lines.append(f"Total pages: {len(page_timings)}")
                summary_lines.append(
                    f"Total entries collected: {total_entries_from_pages}"
                )
                summary_lines.append(f"Total time: {total_time:.2f}s")
                summary_lines.append(f"Average time per page: {avg_time_per_page:.2f}s")
                summary_lines.append(
                    f"Average time per entry: {avg_time_per_entry:.4f}s"
                )
                summary_lines.append("")

                # Print detailed table
                summary_lines.append(
                    f"{'Page':<6} {'Entries':<8} {'Duration':<10} {'Status':<8} {'File'}"
                )
                summary_lines.append(
                    f"{'-' * 6} {'-' * 8} {'-' * 10} {'-' * 8} {'-' * 50}"
                )
                for page in page_timings:
                    status_str = "SUCCESS" if page.get("status", False) else "FAILED"
                    entries_str = str(page.get("entries", 0))
                    duration_str = f"{page.get('duration', 0):.2f}"
                    file_str = (
                        os.path.basename(page.get("file", ""))
                        if page.get("file")
                        else "N/A"
                    )
                    summary_lines.append(
                        f"{page['page']:<6} {entries_str:<8} {duration_str:<10} {status_str:<8} {file_str}"
                    )
                summary_lines.append("=" * 80)

                # Log the timing summary
                for line in summary_lines:
                    await self._log_runtime("INFO", "RedfishService", line, dut_id)

            # Post-processing: Fix filenames with actual total pages
            actual_total_pages = len(collected_files)
            if actual_total_pages > 0:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Collected {actual_total_pages} pages for {entity_type} {entity_id}. Updating filenames to reflect actual total.",
                    dut_id,
                )

                # Rename files to use actual total
                renamed_files = []
                for i, file_path in enumerate(collected_files, 1):
                    try:
                        old_path = file_path
                        # Replace "unknown" or any existing total with actual total
                        new_path = re.sub(
                            r"_page(\d+)\.json$",
                            f"_page\\1_of_{actual_total_pages}.json",
                            str(old_path),
                        )

                        if os.path.exists(old_path) and old_path != new_path:
                            os.rename(old_path, new_path)
                            renamed_files.append(new_path)
                            await self._log_runtime(
                                "INFO",
                                "RedfishService",
                                f"Renamed {os.path.basename(old_path)} to {os.path.basename(new_path)}",
                                dut_id,
                            )
                        else:
                            renamed_files.append(file_path)
                    except Exception as e:
                        await self._log_runtime(
                            "ERROR",
                            "RedfishService",
                            f"Failed to rename file {file_path}: {str(e)}",
                            dut_id,
                        )
                        renamed_files.append(file_path)

                collected_files = renamed_files

            # Final summary
            total_collected = len(all_entries)
            successful_files = len([f for f in collected_files if f])

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Completed paginated log collection for {entity_type} {entity_id}: {total_collected} entries, {successful_files} files saved, {len(status_list)} pages processed",
                dut_id,
            )

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"FINAL collected_files list for {entity_type} {entity_id}: {len(collected_files)} files: {collected_files}",
                dut_id,
            )

            # Use the base collector's standardized result function
            successful_operations = len([s for s in status_list if s])
            total_operations = len(status_list)
            error_messages = []

            # Collect specific error messages from failed pages
            for i, status in enumerate(status_list):
                if not status and i < len(page_timings):
                    page_info = page_timings[i]
                    if "error" in page_info:
                        error_msg = f"Page {page_info.get('page', i+1)} failed: {page_info['error']}"
                        error_messages.append(error_msg)
                    else:
                        error_msg = (
                            f"Page {page_info.get('page', i+1)} failed: Unknown error"
                        )
                        error_messages.append(error_msg)

            # If we have collected files but some pages failed, this should be considered partial success
            # rather than complete failure, as we did successfully collect some data
            if successful_files > 0 and successful_operations < total_operations:
                # We have some successful files but not all pages succeeded
                # This is partial success, not complete failure
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Partial success: collected {successful_files} files from {successful_operations}/{total_operations} pages for {entity_type} {entity_id}",
                    dut_id,
                )

            # Add detailed logging for status determination
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"PAGINATION_STATUS_DEBUG: {entity_type} {entity_id} - status_list={status_list}, successful_operations={successful_operations}, total_operations={total_operations}, collected_files={len(collected_files)}",
                dut_id,
            )

            result = await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=f"{entity_type}_{entity_id}_{log_service}",
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=collected_files,
                error_messages=error_messages,
                operation_name="pages",
                additional_context={
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "log_service": log_service,
                    "total_entries_collected": total_collected,
                    "successful_files": successful_files,
                    "additional_data": additional_data,
                    "status_list": status_list,
                },
            )

            # Log the result from pagination function
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"PAGINATION_RESULT_DEBUG: {entity_type} {entity_id} - result={result}",
                dut_id,
            )

            return result

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception in optimized paginated logs collection: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=0,
                output_files=[],
                error_messages=[
                    f"Exception in optimized paginated logs collection: {str(e)}"
                ],
                operation_name="paginated_logs_collection",
                additional_context={
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "log_service": log_service,
                },
            )

    async def collect_component_integrity_data(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Generic function for collecting data from ComponentIntegrity endpoints.

        This function can be used for various ComponentIntegrity operations including:
        - SPDM measurements
        - Certificate collections
        - Any other ComponentIntegrity-based data collection

        All configuration should be provided via kwargs parameters.

        Required parameters:
        - collection_type: Type of collection ("spdm_measurements", "certificates", etc.)
        - member_key_config: Dict with baseboard-type-specific member keys
          - {baseboard_type}: List of keys for that baseboard type (e.g., {"NVSwitch": ["MGX"]})
        - default_member_key: Default member key for baseboard types not in member_key_config (e.g., ["HGX"])

        Optional parameters:
        - base_uri: ComponentIntegrity base URI (default: uses configured URI)
        - action_name: Action name for POST requests (e.g., "#ComponentIntegrity.SPDMGetSignedMeasurements")
        - payload_template: Template for POST request payload (for measurements)
        - member_delay: Delay between member processing in seconds (default: 1)
        - request_delay: Delay between requests in seconds (default: 1)
        - output_pattern: File output pattern with {member_id} and other placeholders
        - collection_params: Additional parameters for the specific collection type
        - baseboard_manager: Baseboard manager instance for baseboard-aware filtering
        """
        try:
            output_files = []
            collection_type = kwargs.get("collection_type", "spdm_measurements")

            # Get ComponentIntegrity information
            base_uri = kwargs.get("base_uri", "ComponentIntegrity")
            if base_uri.startswith("/"):
                # Full URI provided
                component_integrity_uri = base_uri
            else:
                # Use configured URI
                component_integrity_uri = self.get_configured_uri(dut_id, base_uri)
            success, response, _ = await self.dispatch_request(
                dut_id,
                "GET",
                component_integrity_uri,
                error_context="fetch ComponentIntegrity URIs",
            )

            if not success:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=["Failed to get ComponentIntegrity"],
                    operation_name=collection_type,
                    additional_context={},
                )

            members = response.get("Members", [])
            if not isinstance(members, list):
                members = []

            if len(members) == 0:
                await self._log_runtime(
                    "WARN",
                    "RedfishService",
                    f"No members found under ComponentIntegrity. Skipping {collection_type}",
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=["No ComponentIntegrity members found"],
                    operation_name=collection_type,
                    additional_context={},
                )

            # Get baseboard-aware member key filtering
            # Use baseboard manager to determine applicable member keys
            baseboard_manager = kwargs.get("baseboard_manager")
            if baseboard_manager:
                # Get the baseboard for this DUT from DUT config
                dut_config = self.dut_manager.get_dut_config(dut_id)
                baseboard_name = dut_config.get("baseboard", "unknown")

                # Get baseboard type from BaseboardManager
                baseboard_type = baseboard_manager.get_baseboard_type(baseboard_name)
                if not baseboard_type:
                    baseboard_type = "unknown"

                # Get member key configuration
                member_key_config = kwargs.get("member_key_config", {})

                # Generic logic: look up baseboard type in member_key_config, fallback to default
                if baseboard_type in member_key_config:
                    member_key = member_key_config[baseboard_type]
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Found member key for baseboard type {baseboard_type}: {member_key}",
                        dut_id,
                    )
                else:
                    # Use default for baseboard types not in config
                    member_key = kwargs.get("default_member_key", ["HGX"])
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"No specific config for baseboard type {baseboard_type}, using default: {member_key}",
                        dut_id,
                    )

                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Using member key {member_key} for baseboard {baseboard_name} (type: {baseboard_type})",
                    dut_id,
                )
            else:
                # Fallback to default configuration if no baseboard manager
                member_key_config = kwargs.get("member_key_config", {})
                if member_key_config:
                    # Use the first available key list as default
                    member_key = (
                        list(member_key_config.values())[0]
                        if member_key_config
                        else ["HGX"]
                    )
                else:
                    member_key = kwargs.get("default_member_key", ["HGX"])

            # Get configurable delays
            member_delay = kwargs.get("member_delay", 1)
            request_delay = kwargs.get("request_delay", 1)

            for i, member in enumerate(members):
                # Add delay between member processing to prevent BMC overload
                if i > 0:
                    await asyncio.sleep(member_delay)

                member_uri = member.get("@odata.id", None)
                if not member_uri:
                    continue

                # Platform-specific member key filtering
                if not any(key in member_uri for key in member_key):
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Skipping non-{','.join(member_key)} component integrity info for {member_uri}",
                        dut_id,
                    )
                    continue

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Collecting {collection_type} for {member_uri}",
                    dut_id,
                )

                # Get component integrity info
                success, component_response, _ = await self.dispatch_request(
                    dut_id,
                    "GET",
                    member_uri,
                    error_context=f"fetch component integrity info for {member_uri}",
                )

                if not success:
                    continue

                member_id = member_uri.split("/")[-1]

                # Handle different collection types
                if collection_type == "spdm_measurements":
                    # Handle SPDM measurements collection
                    await self._handle_spdm_measurements_collection(
                        dut_id,
                        component_response,
                        member_uri,
                        member_id,
                        kwargs,
                        function_tag,
                        output_files,
                        request_delay,
                    )
                elif collection_type == "certificates":
                    # Handle certificate collection
                    await self._handle_certificate_collection(
                        dut_id,
                        component_response,
                        member_uri,
                        member_id,
                        kwargs,
                        function_tag,
                        output_files,
                    )
                else:
                    # Generic collection - just save the component response
                    await self._handle_generic_collection(
                        dut_id,
                        component_response,
                        member_uri,
                        member_id,
                        kwargs,
                        function_tag,
                        output_files,
                    )

            return await self._create_standardized_collector_result(
                successful_operations=len(output_files),
                total_operations=len(members),
                output_files=output_files,
                error_messages=[],
                operation_name=collection_type,
                additional_context={
                    "baseboard_name": (
                        baseboard_name if "baseboard_name" in locals() else "unknown"
                    ),
                    "member_key_used": member_key,
                    "members_processed": len(members),
                    "collections_completed": len(output_files),
                    "collection_type": collection_type,
                },
            )

        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name=collection_type,
                additional_context={
                    "collector_name": "collect_component_integrity_data"
                },
            )

    async def _handle_spdm_measurements_collection(
        self,
        dut_id: str,
        component_response: Dict[str, Any],
        member_uri: str,
        member_id: str,
        kwargs: Dict[str, Any],
        function_tag: str,
        output_files: List[str],
        request_delay: int,
    ) -> None:
        """
        Handle SPDM measurements collection.

        Args:
            dut_id: DUT ID.
            component_response: Component response data.
            member_uri: Member URI.
            member_id: Member ID.
            kwargs: Additional arguments.
            function_tag: Function tag for naming.
            output_files: List to append output files to.
            request_delay: Delay between requests in seconds.
        """
        # Check for SPDM action target
        action_name = kwargs.get(
            "action_name", "#ComponentIntegrity.SPDMGetSignedMeasurements"
        )
        action_target = (
            component_response.get("Actions", {})
            .get(action_name, {})
            .get("target", None)
        )

        if not action_target:
            await self._log_runtime(
                "WARN",
                "RedfishService",
                f"No SPDM action found for uri {member_uri}. Skipping...",
                dut_id,
            )
            return

        # Collect measurements for specific indices
        index_list = kwargs.get("measurement_indices", [26, 50])
        slot_id = kwargs.get("slot_id", 0)

        for j, index in enumerate(index_list):
            # Add delay between measurement requests to prevent BMC overload
            if j > 0:
                await asyncio.sleep(request_delay)

            payload = {"SlotId": slot_id, "MeasurementIndices": [index]}

            # Execute the SPDM measurement request
            success, measurement_response, error_details = await self.dispatch_request(
                dut_id, "POST", action_target, payload
            )

            if success:
                task_id = measurement_response.get("Id", "")
                if not task_id:
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"No task ID in response for SPDM measurement index {index} from {member_uri}",
                        dut_id,
                    )
                    continue

                # Wait for task completion
                max_retries = kwargs.get("max_retries", 50)
                entity_context = {
                    "entity_type": "ComponentIntegrity",
                    "entity_id": member_id,
                    "log_service": "spdm_measurements",
                }

                task_completed = await self._wait_for_task_completion(
                    dut_id,
                    task_id,
                    max_retries=max_retries,
                    function_tag=function_tag,
                    entity_context=entity_context,
                    collector_id=kwargs.get("collector_id", "R27"),
                )

                if not task_completed:
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Task {task_id} did not complete for SPDM measurement index {index} from {member_uri}",
                        dut_id,
                    )
                    continue

                # Get dump location
                # SPDM measurements are not binary attachments, so use attachment=False
                dump_location = await self._get_dump_location(
                    task_completed, dut_id, attachment=False
                )
                if not dump_location:
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"No dump location found for task {task_id} (SPDM measurement index {index})",
                        dut_id,
                    )
                    continue

                # Fetch the actual measurement results
                success, actual_results, error_details = await self.dispatch_request(
                    dut_id, "GET", dump_location
                )

                if success:
                    # Create kwargs without output_pattern to avoid duplication
                    save_kwargs = kwargs.copy()
                    save_kwargs["output_pattern"] = kwargs.get("output_pattern", "")
                    save_kwargs["substitutions"] = {
                        "member_id": member_id,
                        "index": str(index),
                    }

                    file_path = await self._save_data_to_file_with_pattern(
                        dut_id,
                        actual_results,
                        function_tag,
                        **save_kwargs,
                    )
                    if file_path:
                        output_files.append(file_path)

                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Successfully collected SPDM measurement index {index} from {member_uri}",
                        dut_id,
                    )
                else:
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Failed to fetch actual results from {dump_location} for task {task_id}",
                        dut_id,
                    )
            else:
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"Failed to initiate SPDM measurement for index {index} from {member_uri}",
                    dut_id,
                )

    async def _handle_certificate_collection(
        self,
        dut_id: str,
        component_response: Dict[str, Any],
        member_uri: str,
        member_id: str,
        kwargs: Dict[str, Any],
        function_tag: str,
        output_files: List[str],
    ) -> None:
        """
        Handle certificate collection.

        Args:
            dut_id: DUT ID.
            component_response: Component response data.
            member_uri: Member URI.
            member_id: Member ID.
            kwargs: Additional arguments.
            function_tag: Function tag for naming.
            output_files: List to append output files to.
        """
        # For certificates, we might want to collect additional certificate data
        # This is a placeholder for certificate-specific logic
        await self._handle_generic_collection(
            dut_id,
            component_response,
            member_uri,
            member_id,
            kwargs,
            function_tag,
            output_files,
        )

    async def _handle_generic_collection(
        self,
        dut_id: str,
        component_response: Dict[str, Any],
        member_uri: str,
        member_id: str,
        kwargs: Dict[str, Any],
        function_tag: str,
        output_files: List[str],
    ) -> None:
        """
        Handle generic collection - just save the component response.

        Args:
            dut_id: DUT ID.
            component_response: Component response data.
            member_uri: Member URI.
            member_id: Member ID.
            kwargs: Additional arguments.
            function_tag: Function tag for naming.
            output_files: List to append output files to.
        """
        # Create kwargs without output_pattern to avoid duplication
        save_kwargs = kwargs.copy()
        save_kwargs["output_pattern"] = kwargs.get("output_pattern", "")
        save_kwargs["substitutions"] = {
            "member_id": member_id,
        }

        file_path = await self._save_data_to_file_with_pattern(
            dut_id,
            component_response,
            function_tag,
            **save_kwargs,
        )
        if file_path:
            output_files.append(file_path)

    async def collect_diagnostic_data(
        self,
        dut_id: str,
        entity_type: str,
        log_service: str,
        payload_types: List[str],
        default_payload: Dict[str, Any],
        function_tag: str,
        fallback_payloads: Optional[List[Dict[str, Any]]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Collect diagnostic data based on supported diagnostic types.

        Args:
            dut_id: DUT ID.
            entity_type: Type of entity.
            log_service: Log service name.
            payload_types: List of payload types to try.
            default_payload: Default payload configuration.
            function_tag: Function tag for naming.
            fallback_payloads: Optional fallback payload configurations.
            **kwargs: Additional arguments including filtered entities.

        Returns:
            Collector result dictionary.
        """
        try:
            output_files = []
            status_list = []
            error_messages = []

            # Check if we have validation results with filtered entities
            filtered_systems = kwargs.get("filtered_systems", [])
            filtered_managers = kwargs.get("filtered_managers", [])
            filtered_chassis = kwargs.get("filtered_chassis", [])

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"collect_diagnostic_data context: {kwargs.get('context', {})}",
                dut_id,
            )

            if filtered_systems and entity_type == "Systems":
                # Use filtered systems from validation
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using {len(filtered_systems)} filtered systems from validation: {[sys['id'] for sys in filtered_systems]}",
                    dut_id,
                )
                entity_ids = [sys["id"] for sys in filtered_systems]
            elif filtered_managers and entity_type == "Managers":
                # Use filtered managers from validation
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using {len(filtered_managers)} filtered managers from validation: {[mgr['id'] for mgr in filtered_managers]}",
                    dut_id,
                )
                entity_ids = [mgr["id"] for mgr in filtered_managers]

                # Apply ID filtering based on DUT configuration
                dut_config = self.dut_manager.get_dut_config(dut_id)
                original_manager_ids = entity_ids.copy()
                entity_ids = filter_ids(entity_ids, "manager", dut_config)

                # Log filtered IDs if any were filtered
                if len(entity_ids) != len(original_manager_ids):
                    log_filtered_ids(
                        original_manager_ids, entity_ids, "manager", self.logger, dut_id
                    )
            elif filtered_chassis and entity_type == "Chassis":
                # Use filtered chassis from validation
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using {len(filtered_chassis)} filtered chassis from validation: {[chassis['id'] for chassis in filtered_chassis]}",
                    dut_id,
                )
                entity_ids = [chassis["id"] for chassis in filtered_chassis]
            else:
                # Get entities - dut_manager handles URI construction automatically
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"No filtered {entity_type.lower()} found in context, fetching all {entity_type}",
                    dut_id,
                )
                success, entities, _ = await self.dispatch_request(
                    dut_id, "GET", entity_type
                )

                if not success:
                    return await self._create_standardized_collector_result(
                        successful_operations=0,
                        total_operations=1,
                        output_files=[],
                        error_messages=[f"Failed to get {entity_type}: {entities}"],
                        operation_name="entity_discovery",
                        additional_context={"entity_type": entity_type},
                    )

                entity_ids = [
                    entity.get("@odata.id", "").split("/")[-1]
                    for entity in entities.get("Members", [])
                ]

            if not entity_ids:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[f"No {entity_type} found"],
                    operation_name="entity_discovery",
                    additional_context={"entity_type": entity_type},
                )

            for k, entity_id in enumerate(entity_ids):
                # Add configurable delay between entity processing to prevent BMC overload
                if k > 0:
                    # Get sleep duration from collector definition and DUT config
                    collector_def = kwargs.get("collector_def", {})
                    dut_config = self.dut_manager.get_dut_config(dut_id)
                    sleep_duration = get_collector_sleep_duration(
                        kwargs.get("collector_id", ""), collector_def, dut_config, 1
                    )

                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Sleeping {sleep_duration}s between {entity_type} entities",
                        dut_id,
                    )
                    await asyncio.sleep(sleep_duration)

                # Handle default_payload as either single payload or list of payloads
                default_payloads = (
                    default_payload
                    if isinstance(default_payload, list)
                    else [default_payload]
                )

                # Try default payloads in sequence
                entity_success = False
                entity_output_files = []
                entity_error = None

                for i, payload in enumerate(default_payloads):
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Trying default payload {i+1}/{len(default_payloads)} for {entity_type} {entity_id}",
                        dut_id,
                    )

                    status, output_file = await self._execute_redfish_dump_task(
                        dut_id=dut_id,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        log_service=log_service,
                        payload=payload,
                        function_tag=function_tag,
                        **kwargs,
                    )

                    if status:
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Default payload {i+1} succeeded for {entity_type} {entity_id}",
                            dut_id,
                        )
                        entity_success = True
                        if output_file:
                            entity_output_files.append(output_file)

                        # Check if we should collect all default payloads or just the first successful one
                        collect_all_defaults = kwargs.get(
                            "collect_all_defaults", True
                        )  # Default to True
                        if not collect_all_defaults:
                            break  # Stop trying other default payloads for this entity
                        else:
                            await self._log_runtime(
                                "INFO",
                                "RedfishService",
                                f"Continuing to collect remaining default payloads for {entity_type} {entity_id}",
                                dut_id,
                            )
                    else:
                        entity_error = (
                            output_file
                            if output_file
                            else f"Default payload {i+1} failed for {entity_type} {entity_id}"
                        )
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Default payload {i+1} failed for {entity_type} {entity_id}: {entity_error}",
                            dut_id,
                        )

                # If all default payloads failed and we have fallback payloads, try them
                if not entity_success and fallback_payloads:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"All payload types failed for {entity_type} {entity_id}, trying {len(fallback_payloads)} fallback payload(s)",
                        dut_id,
                    )

                    for i, fallback_payload in enumerate(fallback_payloads, 1):
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Trying fallback payload {i}/{len(fallback_payloads)} for {entity_type} {entity_id}",
                            dut_id,
                        )

                        status, output_file = await self._execute_redfish_dump_task(
                            dut_id=dut_id,
                            entity_type=entity_type,
                            entity_id=entity_id,
                            log_service=log_service,
                            payload=fallback_payload,
                            function_tag=function_tag,
                            **kwargs,
                        )

                        if status:
                            await self._log_runtime(
                                "INFO",
                                "RedfishService",
                                f"Fallback payload {i} succeeded for {entity_type} {entity_id}",
                                dut_id,
                            )
                            entity_success = True
                            if output_file:
                                entity_output_files.append(output_file)
                            break
                        else:
                            entity_error = (
                                output_file
                                if output_file
                                else f"Fallback payload {i} failed for {entity_type} {entity_id}"
                            )
                            await self._log_runtime(
                                "INFO",
                                "RedfishService",
                                f"Fallback payload {i} failed for {entity_type} {entity_id}: {entity_error}",
                                dut_id,
                            )

                status_list.append(entity_success)
                output_files.extend(entity_output_files)

                # Collect error message if entity failed
                if not entity_success and entity_error:
                    error_messages.append(f"{entity_type} {entity_id}: {entity_error}")

                    # Store request context for failed entities (for detailed error logging)
                    if "failed_entity_contexts" not in locals():
                        failed_entity_contexts = {}
                    failed_entity_contexts[entity_id] = {
                        "request_uri": f"{entity_type}/{entity_id}/LogServices/{log_service}/Actions/LogService.CollectDiagnosticData",
                        "request_payload": payload,
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "log_service": log_service,
                        "error_message": entity_error,
                    }

            # Use the base collector's standardized result function
            successful_operations = len([s for s in status_list if s])
            total_operations = len(status_list)

            # Include failed entity contexts for detailed error logging
            additional_context = {
                "entity_type": entity_type,
                "log_service": log_service,
                "payload_types": payload_types,
                "entities_processed": len(entity_ids),
                "successful_entities": [
                    entity_ids[i] for i, s in enumerate(status_list) if s
                ],
                "failed_entities": [
                    entity_ids[i] for i, s in enumerate(status_list) if not s
                ],
            }

            # Add request contexts for failed entities if any exist
            if "failed_entity_contexts" in locals() and failed_entity_contexts:
                additional_context["failed_entity_contexts"] = failed_entity_contexts

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="entities",
                additional_context=additional_context,
            )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception in collect_diagnostic_data for {entity_type}/{log_service}: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=0,
                output_files=[],
                error_messages=[f"Exception in collect_diagnostic_data: {str(e)}"],
                operation_name="diagnostic_data_collection",
                additional_context={
                    "entity_type": entity_type,
                    "log_service": log_service,
                    "error_type": type(e).__name__,
                },
            )

    async def collect_device_diagnostic_data(
        self,
        dut_id: str,
        collector_name: str,
        diagnostic_configs: Dict[str, Dict[str, Dict[str, Any]]] = None,
        discovered_devices: Dict[str, List[int]] = None,
        target_baseboard: str = None,
        baseboard_config: Dict[str, Any] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Generic device diagnostic data collection method

        Args:
            dut_id: Device under test ID
            collector_name: Name of the collector (for logging)
            diagnostic_configs: Baseboard-specific diagnostic configurations
            discovered_devices: Dict of discovered devices by type from validation stage
            target_baseboard: Target baseboard from DUT config
            baseboard_config: Baseboard-specific configuration

        Returns:
            Dict with collection results and output files
        """
        try:
            # Get collector context for better logging
            collector_id = kwargs.get("collector_id", collector_name)

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"=== Starting device diagnostic data collection for {collector_name} ===",
                dut_id,
            )

            # Get discovered devices from context (passed from validation stage)
            if discovered_devices is None:
                discovered_devices = kwargs.get("discovered_devices", {})

            if target_baseboard is None:
                target_baseboard = kwargs.get("target_baseboard", "")

            if baseboard_config is None:
                baseboard_config = kwargs.get("baseboard_config", {})

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Target baseboard: {target_baseboard}, discovered devices: {discovered_devices}",
                dut_id,
            )

            # Get baseboard-specific diagnostic configuration with fallback to default
            if not diagnostic_configs:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[
                        f"No diagnostic configuration provided for collector: {collector_name}"
                    ],
                    operation_name="device_diagnostic_data",
                    additional_context={"collector_name": collector_name},
                )

            # Try to get baseboard-specific config, fall back to 'default' key if not found
            if target_baseboard in diagnostic_configs:
                baseboard_diagnostic_config = diagnostic_configs[target_baseboard]
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using diagnostic config for {target_baseboard}: {baseboard_diagnostic_config}",
                    dut_id,
                )
            elif "default" in diagnostic_configs:
                baseboard_diagnostic_config = diagnostic_configs["default"]
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"No specific config for {target_baseboard}, using default diagnostic config: {baseboard_diagnostic_config}",
                    dut_id,
                )
            else:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[
                        f"No diagnostic configuration found for baseboard '{target_baseboard}' and no 'default' config provided"
                    ],
                    operation_name="device_diagnostic_data",
                    additional_context={
                        "collector_name": collector_name,
                        "baseboard": target_baseboard,
                    },
                )

            # Get systems to use (could be filtered from validation)
            filtered_systems = kwargs.get("filtered_systems", [])
            if filtered_systems:
                system_ids = [sys["id"] for sys in filtered_systems]
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using filtered systems: {system_ids}",
                    dut_id,
                )
            else:
                # Get all systems
                systems_uri = self.get_configured_uri(dut_id, "Systems")
                success, systems_response, _ = await self.dispatch_request(
                    dut_id, "GET", systems_uri, bypass_cache=True
                )
                if not success:
                    return await self._create_standardized_collector_result(
                        successful_operations=0,
                        total_operations=1,
                        output_files=[],
                        error_messages=[f"Failed to get systems: {systems_response}"],
                        operation_name="device_diagnostic_data",
                        additional_context={},
                    )
                system_members = systems_response.get("Members", [])
                system_ids = [
                    member.get("@odata.id", "").split("/")[-1]
                    for member in system_members
                ]

            # Apply ID filtering based on DUT configuration
            dut_config = self.dut_manager.get_dut_config(dut_id)
            original_system_ids = system_ids.copy()
            system_ids = filter_ids(system_ids, "system", dut_config)

            # Log filtered IDs if any were filtered
            if len(system_ids) != len(original_system_ids):
                log_filtered_ids(
                    original_system_ids, system_ids, "system", self.logger, dut_id
                )

            await self._log_runtime(
                "INFO", "RedfishService", f"Using system IDs: {system_ids}", dut_id
            )

            all_output_files = []
            all_status_list = []
            error_messages = []

            # Process each device type in the diagnostic config
            for device_type, device_config in baseboard_diagnostic_config.items():
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Processing device type: {device_type} with config: {device_config}",
                    dut_id,
                )

                # Get discovered device IDs for this type
                device_ids = discovered_devices.get(device_type, [])
                if not device_ids:
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        f"No devices discovered for type {device_type}, skipping",
                        dut_id,
                    )
                    continue

                # Extract diagnostic configuration
                diagnostic_type = device_config.get("diagnostic_type", "")
                device_id_key = device_config.get("device_id_key", "DeviceID")
                device_id_prefix = device_config.get("device_id_prefix", "")

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using diagnostic_type: {diagnostic_type}, device_id_key: {device_id_key}, device_id_prefix: {device_id_prefix}",
                    dut_id,
                )

                # Collect dumps for each system and device combination
                for system_id in system_ids:
                    for device_id in device_ids:
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Collecting diagnostic data for system {system_id}, device {device_id}",
                            dut_id,
                        )

                        # Build device identifier
                        if device_id_prefix:
                            device_identifier = f"{device_id_prefix}{device_id}"
                        else:
                            device_identifier = str(device_id)

                        # Create diagnostic payload using configurable template
                        payload_template = device_config.get(
                            "payload_template",
                            {
                                "DiagnosticDataType": "OEM",
                                "OEMDiagnosticDataType": "{diagnostic_type};{device_id_key}={device_identifier}",
                            },
                        )

                        # Substitute placeholders in the payload template
                        payload = {}
                        for key, value in payload_template.items():
                            if isinstance(value, str):
                                # Substitute placeholders
                                substituted_value = value.format(
                                    diagnostic_type=diagnostic_type,
                                    device_id_key=device_id_key,
                                    device_identifier=device_identifier,
                                    device_id=device_id,
                                    device_type=device_type,
                                    system_id=system_id,
                                )
                                payload[key] = substituted_value
                            else:
                                payload[key] = value

                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Using payload: {payload}",
                            dut_id,
                        )

                        # Create a filtered systems context for this specific system
                        filtered_systems_for_device = [{"id": system_id}]

                        # Create substitutions for output pattern that includes device information
                        device_substitutions = {
                            "system_id": system_id,
                            "device_id": device_id,
                            "device_type": device_type,
                            "diagnostic_type": diagnostic_type,
                            "device_identifier": device_identifier,
                        }

                        # Create a clean kwargs dict without conflicting parameters
                        clean_kwargs = {
                            k: v for k, v in kwargs.items() if k not in ["function_tag"]
                        }
                        clean_kwargs["substitutions"] = device_substitutions
                        clean_kwargs["filtered_systems"] = filtered_systems_for_device

                        # Use existing collect_diagnostic_data method with custom payload
                        result = await self.collect_diagnostic_data(
                            dut_id=dut_id,
                            entity_type="Systems",
                            log_service="Dump",
                            payload_types=[diagnostic_type],  # Required parameter
                            default_payload=payload,  # Required parameter
                            function_tag=f"{collector_name}_{device_type}",  # Required parameter
                            fallback_payloads=[payload],
                            **clean_kwargs,
                        )

                        # Process result using common function
                        await self._process_collector_result(
                            result=result,
                            all_output_files=all_output_files,
                            all_status_list=all_status_list,
                            error_messages=error_messages,
                            entity_type=device_type,
                            entity_id=device_id,
                            dut_id=dut_id,
                            collector_id=collector_id,
                        )

                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Device {device_type}_{device_id} collection result: {result.get('success', False)}",
                            dut_id,
                        )

                        # Add configurable sleep duration between device dumps
                        # Get sleep duration from collector definition and DUT config
                        collector_def = kwargs.get("collector_def", {})
                        dut_config = self.dut_manager.get_dut_config(dut_id)
                        sleep_duration = get_collector_sleep_duration(
                            kwargs.get("collector_id", ""), collector_def, dut_config, 5
                        )

                        # Sleep between devices (but not after the last device)
                        if device_id != device_ids[-1] or system_id != system_ids[-1]:
                            await self._log_runtime(
                                "DEBUG",
                                "RedfishService",
                                f"Sleeping {sleep_duration}s between device dumps",
                                dut_id,
                            )
                            await asyncio.sleep(sleep_duration)

            # Calculate overall success
            successful_operations = sum(all_status_list) if all_status_list else 0
            total_operations = len(all_status_list) if all_status_list else 0

            # Check if no devices were discovered - treat as skipped
            total_devices = sum(len(devices) for devices in discovered_devices.values())
            if total_devices == 0:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"=== Device diagnostic collection complete. No devices discovered - treating as skipped ===",
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="device_diagnostic_data",
                    additional_context={
                        "collector_name": collector_name,
                        "target_baseboard": target_baseboard,
                        "devices_processed": 0,
                        "successful_collections": 0,
                        "total_collections": 0,
                        "status": "skipped",
                        "reason": f"No {list(discovered_devices.keys())} devices discovered for {collector_name} - collector skipped",
                    },
                )

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"=== Device diagnostic collection complete. Success: {successful_operations}/{total_operations}, Files: {len(all_output_files)} ===",
                dut_id,
            )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=all_output_files,
                error_messages=error_messages,
                operation_name="device_diagnostic_data",
                additional_context={
                    "collector_name": collector_name,
                    "target_baseboard": target_baseboard,
                    "devices_processed": total_devices,
                    "successful_collections": successful_operations,
                    "total_collections": total_operations,
                },
            )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception in collect_device_diagnostic_data: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"Exception in device diagnostic collection: {str(e)}"],
                operation_name="device_diagnostic_data",
                additional_context={
                    "collector_name": collector_name,
                    "error_type": type(e).__name__,
                },
            )

    async def collect_multi_step_collection(
        self,
        dut_id: str,
        function_tag: str,
        collection_config: Dict[str, Any],
        **kwargs,
    ) -> Dict[str, Any]:
        """Generic multi-step collection method for complex collection patterns

        Args:
            dut_id: Device under test ID
            function_tag: Function tag for logging
            collection_config: Configuration defining the collection steps:
                - entity_type: Type of entity to iterate (e.g., "Chassis", "Systems")
                - base_uri_pattern: Base URI pattern with {entity_id} placeholder
                - steps: List of collection steps, each with:
                    - name: Step name for logging
                    - uri_pattern: URI pattern (can reference previous step responses)
                    - output_pattern: Output filename pattern
                    - required: Whether step is required (default: False)
                    - fallback_patterns: List of fallback URI patterns to try
                    - follow_links: Whether to follow @odata.id links from response
                    - link_path: Path to @odata.id in response (e.g., "LeakDetectors.@odata.id")
                    - member_processing: Configuration for processing collection members
        """

        async def _multi_step_collection():
            # Get collector context for better logging
            collector_id = kwargs.get("collector_id", function_tag)

            await self._log_collection_start(dut_id, "multi-step", function_tag)

            # Extract configuration
            entity_type = collection_config.get("entity_type", "Chassis")
            base_uri_pattern = collection_config.get("base_uri_pattern", "")
            steps = collection_config.get("steps", [])

            # Apply prefix override if URI config manager is available
            if (
                base_uri_pattern
                and self.dut_manager
                and self.dut_manager.uri_config_manager
            ):
                base_uri_pattern = (
                    self.dut_manager.uri_config_manager._apply_prefix_override(
                        base_uri_pattern
                    )
                )
            collector_id = kwargs.get(
                "collector_id", ""
            )  # Extract collector_id from kwargs

            # Get entities to process
            if entity_type == "Chassis":
                chassis_uri = self.get_configured_uri(dut_id, "Chassis")
                success, entities_response, _ = await self.dispatch_request(
                    dut_id, "GET", chassis_uri, bypass_cache=True
                )
                entity_key = "chassis_id"
            elif entity_type == "Systems":
                systems_uri = self.get_configured_uri(dut_id, "Systems")
                success, entities_response, _ = await self.dispatch_request(
                    dut_id, "GET", systems_uri, bypass_cache=True
                )
                entity_key = "system_id"
            elif entity_type == "Managers":
                managers_uri = self.get_configured_uri(dut_id, "Managers")
                success, entities_response, _ = await self.dispatch_request(
                    dut_id, "GET", managers_uri, bypass_cache=True
                )
                entity_key = "manager_id"
            else:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[f"Unsupported entity type: {entity_type}"],
                    operation_name="multi_step_collection",
                    additional_context={"entity_type": entity_type},
                )

            if not success:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[
                        f"Failed to get {entity_type}: {entities_response}"
                    ],
                    operation_name="multi_step_collection",
                    additional_context={"entity_type": entity_type},
                )

            # Extract entity IDs
            entities = entities_response.get("Members", [])
            entity_ids = []
            for entity in entities:
                entity_id = entity.get("@odata.id", "").split("/")[-1]
                if entity_id:
                    entity_ids.append(entity_id)

            if not entity_ids:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="multi_step_collection",
                    additional_context={
                        "message": f"No {entity_type} found",
                        "entity_type": entity_type,
                    },
                )

            output_files = []
            status_list = []
            error_messages = []
            successful_operations = 0
            total_operations = 0

            # Process each entity
            for entity_id in entity_ids:
                total_operations += 1
                entity_success = True
                step_responses = {}  # Store responses for URI pattern substitution

                # Initialize step_responses with entity_id
                step_responses[entity_key] = entity_id

                # Execute each step
                for step in steps:
                    step_name = step.get("name", "unknown_step")
                    uri_pattern = step.get("uri_pattern", "")
                    output_pattern = step.get("output_pattern", "")
                    required = step.get("required", False)
                    fallback_patterns = step.get("fallback_patterns", [])
                    follow_links = step.get("follow_links", False)
                    link_path = step.get("link_path", "")
                    member_processing = step.get("member_processing", {})

                    # Check if required variables are available before substitution
                    missing_vars = []
                    for var_name in re.findall(r"\{([^}]+)\}", uri_pattern):
                        if var_name not in step_responses:
                            missing_vars.append(var_name)

                    if missing_vars:
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"Skipping {step_name} for {entity_id}: missing variables {missing_vars} (previous step likely failed)",
                            dut_id,
                        )
                        if required:
                            entity_success = False
                        continue

                    # Substitute variables in URI pattern using VariableSubstitutionService
                    try:
                        uri = await self.substitute_variables(
                            uri_pattern, step_responses, dut_id
                        )
                    except Exception as e:
                        await self._log_runtime(
                            "WARN",
                            "RedfishService",
                            f"Variable substitution failed for {step_name}: {str(e)}. Skipping step.",
                            dut_id,
                        )
                        if required:
                            entity_success = False
                        continue

                    # Try main URI
                    success, response_data, _ = await self.dispatch_request(
                        dut_id, "GET", uri
                    )

                    # If main URI fails and fallbacks exist, try them
                    if not success and fallback_patterns:
                        for fallback_pattern in fallback_patterns:
                            fallback_uri = await self.substitute_variables(
                                fallback_pattern, step_responses, dut_id
                            )

                            success, response_data, _ = await self.dispatch_request(
                                dut_id, "GET", fallback_uri
                            )
                            if success:
                                await self._log_runtime(
                                    "INFO",
                                    "RedfishService",
                                    f"Used fallback URI for {step_name}: {fallback_uri}",
                                    dut_id,
                                )
                                break

                    if not success:
                        if required:
                            await self._log_runtime(
                                "ERROR",
                                "RedfishService",
                                f"Required step {step_name} failed for {entity_id}: {uri}",
                                dut_id,
                            )
                            entity_success = False
                        else:
                            await self._log_runtime(
                                "WARN",
                                "RedfishService",
                                f"Optional step {step_name} failed for {entity_id}: {uri}",
                                dut_id,
                            )
                        continue

                    # Store response for next steps
                    step_responses[step_name] = response_data

                    # Save step response
                    if output_pattern:
                        try:
                            # Substitute variables in output pattern using VariableSubstitutionService
                            final_output_pattern = await self.substitute_variables(
                                output_pattern, step_responses, dut_id
                            )

                            file_path = await self._save_data_with_common_pattern(
                                dut_id,
                                response_data,
                                function_tag,
                                output_pattern=final_output_pattern,
                                substitutions=step_responses,
                                collector_id=collector_id,
                            )
                            if file_path:
                                output_files.append(file_path)
                                await self._log_runtime(
                                    "DEBUG",
                                    "RedfishService",
                                    f"Saved {step_name} data to: {file_path}",
                                    dut_id,
                                )
                        except Exception as e:
                            await self._log_runtime(
                                "ERROR",
                                "RedfishService",
                                f"Failed to save {step_name} data: {str(e)}",
                                dut_id,
                            )

                    # Follow links if configured
                    if follow_links and link_path:
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"Attempting to extract link from {link_path} in response for {step_name}",
                            dut_id,
                        )
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"Response data keys: {list(response_data.keys()) if isinstance(response_data, dict) else 'not dict'}",
                            dut_id,
                        )

                        link_uri = self._extract_nested_value(response_data, link_path)
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"Extract result for {link_path}: {link_uri}",
                            dut_id,
                        )
                        if link_uri:
                            step_responses[f"{step_name}_link"] = link_uri
                            await self._log_runtime(
                                "DEBUG",
                                "RedfishService",
                                f"Extracted link for {step_name}: {link_uri}",
                                dut_id,
                            )
                        else:
                            await self._log_runtime(
                                "WARN",
                                "RedfishService",
                                f"Could not extract link from {link_path} in response for {step_name}",
                                dut_id,
                            )

                    # Process members if configured
                    if member_processing and response_data.get("Members"):
                        members = response_data.get("Members", [])
                        member_uris = []

                        # Extract member URIs
                        for member in members:
                            member_uri = member.get("@odata.id")
                            if member_uri:
                                member_uris.append(member_uri)

                        # If no members found, try fallback member patterns
                        if not member_uris and member_processing.get(
                            "fallback_patterns"
                        ):
                            fallback_base = member_processing.get(
                                "fallback_base_uri", ""
                            )
                            fallback_patterns = member_processing.get(
                                "fallback_patterns", []
                            )

                            for fallback_pattern in fallback_patterns:
                                fallback_uri = fallback_base + fallback_pattern

                                # Check if required variables are available for fallback
                                missing_vars = []
                                for var_name in re.findall(
                                    r"\{([^}]+)\}", fallback_uri
                                ):
                                    if var_name not in step_responses:
                                        missing_vars.append(var_name)

                                if missing_vars:
                                    await self._log_runtime(
                                        "DEBUG",
                                        "RedfishService",
                                        f"Skipping fallback pattern {fallback_pattern}: missing variables {missing_vars}",
                                        dut_id,
                                    )
                                    continue

                                fallback_uri = await self.substitute_variables(
                                    fallback_uri, step_responses, dut_id
                                )

                                success, fallback_response, _ = (
                                    await self.dispatch_request(
                                        dut_id, "GET", fallback_uri
                                    )
                                )
                                if success:
                                    member_uris.append(fallback_uri)
                                    # Save fallback response
                                    fallback_output_pattern = member_processing.get(
                                        "fallback_output_pattern", ""
                                    )
                                    if fallback_output_pattern:
                                        final_fallback_pattern = (
                                            await self.substitute_variables(
                                                fallback_output_pattern,
                                                step_responses,
                                                dut_id,
                                            )
                                        )

                                        file_path = (
                                            await self._save_data_with_common_pattern(
                                                dut_id,
                                                fallback_response,
                                                function_tag,
                                                output_pattern=final_fallback_pattern,
                                                substitutions=step_responses,
                                                collector_id=collector_id,
                                            )
                                        )
                                        if file_path:
                                            output_files.append(file_path)

                        # Process each member
                        for member_uri in member_uris:
                            member_id = member_uri.split("/")[-1]
                            step_responses[f"{step_name}_member_id"] = member_id

                            success, member_data, _ = await self.dispatch_request(
                                dut_id, "GET", member_uri
                            )
                            if success:
                                # Save member data
                                member_output_pattern = member_processing.get(
                                    "member_output_pattern", ""
                                )
                                if member_output_pattern:
                                    final_member_pattern = (
                                        await self.substitute_variables(
                                            member_output_pattern,
                                            step_responses,
                                            dut_id,
                                        )
                                    )

                                    file_path = (
                                        await self._save_data_with_common_pattern(
                                            dut_id,
                                            member_data,
                                            function_tag,
                                            output_pattern=final_member_pattern,
                                            substitutions=step_responses,
                                            collector_id=collector_id,
                                        )
                                    )
                                    if file_path:
                                        output_files.append(file_path)

                                # Process member-related resources if configured
                                member_resources = member_processing.get(
                                    "member_resources", []
                                )

                                for resource in member_resources:
                                    resource_name = resource.get("name", "")
                                    resource_uri_pattern = resource.get(
                                        "uri_pattern", ""
                                    )
                                    resource_output_pattern = resource.get(
                                        "output_pattern", ""
                                    )

                                    if resource_uri_pattern and resource_output_pattern:
                                        # Check if required variables are available for resource
                                        missing_vars = []
                                        for var_name in re.findall(
                                            r"\{([^}]+)\}", resource_uri_pattern
                                        ):
                                            if var_name not in step_responses:
                                                missing_vars.append(var_name)

                                        if missing_vars:
                                            await self._log_runtime(
                                                "DEBUG",
                                                "RedfishService",
                                                f"Skipping resource {resource_name}: missing variables {missing_vars}",
                                                dut_id,
                                            )
                                            continue

                                        resource_uri = await self.substitute_variables(
                                            resource_uri_pattern, step_responses, dut_id
                                        )

                                        success, resource_data, _ = (
                                            await self.dispatch_request(
                                                dut_id, "GET", resource_uri
                                            )
                                        )
                                        if success:
                                            final_resource_pattern = (
                                                await self.substitute_variables(
                                                    resource_output_pattern,
                                                    step_responses,
                                                    dut_id,
                                                )
                                            )

                                            file_path = await self._save_data_with_common_pattern(
                                                dut_id,
                                                resource_data,
                                                function_tag,
                                                output_pattern=final_resource_pattern,
                                                substitutions=step_responses,
                                                collector_id=collector_id,
                                            )
                                            if file_path:
                                                output_files.append(file_path)

                if entity_success:
                    successful_operations += 1
                else:
                    error_messages.append(f"Entity {entity_id} processing failed")
                status_list.append(entity_success)

            # Check if any files were collected
            if not output_files:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Completed multi-step collection for {function_tag} - no files collected, treating as skipped",
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="multi_step_collection",
                    additional_context={
                        "entities_processed": len(entity_ids),
                        "steps_configured": len(steps),
                        "status": "skipped",
                        "reason": f"No data collected for {function_tag} - collector skipped",
                    },
                )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="multi_step_collection",
                additional_context={
                    "entities_processed": len(entity_ids),
                    "steps_configured": len(steps),
                },
            )

        return await self._execute_with_error_handling(
            dut_id, f"multi-step collection for {function_tag}", _multi_step_collection
        )

    async def collect_custom_service_executor(
        self, dut_id: str, function_tag: str, service_config: Dict[str, Any], **kwargs
    ) -> Dict[str, Any]:
        """Generic custom service executor for configurable service execution

        Args:
            dut_id: Device under test ID
            function_tag: Function tag for logging
            service_config: Configuration defining the services:
                - config_key: Key in DUT config containing service definitions
                - default_timeout: Default timeout in seconds
                - retry_interval: Retry interval in seconds
                - output_pattern: Output filename pattern with {service_id} and {task_id}
        """
        try:
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Starting custom service executor for {function_tag}",
                dut_id,
            )

            # Extract configuration
            config_key = service_config.get("config_key", "CUSTOM_DUMP_SERVICES")
            default_timeout = service_config.get("default_timeout", 1500)
            retry_interval = service_config.get("retry_interval", 30)
            output_pattern = service_config.get("output_pattern", "")

            # Get services from DUT config first, then fall back to tool config
            dut_config = await self._get_dut_config(dut_id)
            services = dut_config.get(config_key, [])

            # Check DUT-level configuration first (highest priority)
            if isinstance(services, list) and services:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using DUT-level services from {config_key}: {len(services)} services",
                    dut_id,
                )
            else:
                # Fall back to tool-level configuration (medium priority)
                orchestrator = getattr(self, "orchestrator", None)
                if orchestrator and hasattr(orchestrator, "config_manager"):
                    tool_config = orchestrator.config_manager.get_tool_config()
                else:
                    tool_config = self.dut_manager.tool_config
                services = tool_config.get(config_key, [])
                if isinstance(services, list) and services:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Using tool-level services from {config_key}: {len(services)} services",
                        dut_id,
                    )
                else:
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        f"No services found for {config_key} in DUT or tool config - collector will be skipped",
                        dut_id,
                    )

            if not services:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"No services defined in config key: {config_key}. Collector will be skipped.",
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="custom_service_executor",
                    additional_context={
                        "config_key": config_key,
                        "status": "skipped",
                        "reason": f"No services defined in config key '{config_key}' - collector skipped",
                    },
                )

            output_files = []
            status_list = []
            error_messages = []

            # Process each service
            for service_idx, service in enumerate(services, 1):
                uri = service.get("uri", "")
                payload = service.get("payload", {})
                timeout = service.get("timeout", default_timeout)

                if not uri or not payload:
                    error_msg = f"Invalid service configuration at index {service_idx}: missing uri or payload"
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        error_msg,
                        dut_id,
                    )
                    error_messages.append(error_msg)
                    status_list.append(False)

                    # Create error log file for failed service execution
                    error_log_path = await self._create_error_log_file(
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id"),
                        error_message=error_msg,
                        context={
                            "service_idx": service_idx,
                            "uri": uri,
                            "operation": "service_execution_validation",
                        },
                    )

                    # Add error log file to output files
                    if error_log_path:
                        output_files.append(error_log_path)
                    continue

                # Calculate max retries based on timeout
                max_retries = int((timeout + retry_interval - 1) / retry_interval)

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Processing service {service_idx}: URI={uri}, timeout={timeout}s, max_retries={max_retries}",
                    dut_id,
                )

                # Execute the service using either direct URI or parsed approach
                try:
                    # Try direct URI approach first (more flexible)
                    status, output_file = await self._execute_redfish_dump_task_direct(
                        dut_id=dut_id,
                        uri=uri,
                        payload=payload,
                        function_tag=function_tag,
                        **kwargs,
                    )
                except AttributeError:
                    # Fall back to parsed approach for compatibility
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Direct URI method not available, using parsed approach for {uri}",
                        dut_id,
                    )

                    # Parse URI to extract entity_type, entity_id, and log_service
                    # URI format: /redfish/v1/Systems/System_0/LogServices/DumpLogs/Actions/LogService.CollectDiagnosticData
                    uri_parts = uri.split("/")
                    if len(uri_parts) >= 7:
                        entity_type = uri_parts[3]  # e.g., "Systems"
                        entity_id = uri_parts[4]  # e.g., "System_0"
                        log_service = uri_parts[
                            6
                        ]  # e.g., "DumpLogs" (not "LogServices")
                    else:
                        # Fallback for unexpected URI format
                        entity_type = "Unknown"
                        entity_id = "Unknown"
                        log_service = "Unknown"

                    status, output_file = await self._execute_redfish_dump_task(
                        dut_id=dut_id,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        log_service=log_service,
                        payload=payload,
                        function_tag=function_tag,
                        **kwargs,
                    )
                except Exception as e:
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Exception in custom service {service_idx}: {str(e)}",
                        dut_id,
                    )
                    status = False
                    output_file = None
                    error_messages.append(f"Service {service_idx} failed: {str(e)}")

                if status and output_file:
                    # Generate output filename
                    if output_pattern:
                        # Extract task_id from output_file path or use service_idx
                        task_id = f"service_{service_idx}"
                        final_output_pattern = output_pattern.replace(
                            "{service_id}", str(service_idx)
                        )
                        final_output_pattern = final_output_pattern.replace(
                            "{task_id}", str(task_id)
                        )

                        # Save the result data
                        # Remove output_pattern from kwargs to avoid duplicate keyword argument
                        kwargs_copy = kwargs.copy()
                        kwargs_copy.pop("output_pattern", None)

                        file_path = await self._save_data_with_common_pattern(
                            dut_id,
                            {},  # No data to save since we already have output_file
                            function_tag,
                            output_pattern=final_output_pattern,
                            substitutions={
                                "service_id": service_idx,
                                "task_id": task_id,
                            },
                            **kwargs_copy,
                        )
                        if file_path:
                            output_files.append(file_path)
                    else:
                        # Use the output_file directly
                        if output_file:
                            output_files.append(output_file)

                status_list.append(status)

                # Collect error messages for failed services
                if not status:
                    error_messages.append(f"Service {service_idx} (URI: {uri}) failed")

                    # Store request context for failed services (for detailed error logging)
                    if "failed_service_contexts" not in locals():
                        failed_service_contexts = {}
                    failed_service_contexts[service_idx] = {
                        "request_uri": uri,
                        "request_payload": payload,
                        "service_index": service_idx,
                        "timeout": timeout,
                        "max_retries": max_retries,
                    }

            successful_services = sum(status_list)
            total_services = len(services)

            # Include failed service contexts for detailed error logging
            additional_context = {
                "services_processed": total_services,
                "successful_services": successful_services,
                "config_key": config_key,
            }

            # Add request contexts for failed services if any exist
            if "failed_service_contexts" in locals() and failed_service_contexts:
                additional_context["failed_service_contexts"] = failed_service_contexts

            return await self._create_standardized_collector_result(
                successful_operations=successful_services,
                total_operations=total_services,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="custom_service_executor",
                additional_context=additional_context,
            )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception in collect_custom_service_executor: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"Exception in custom service executor: {str(e)}"],
                operation_name="custom_service_executor",
                additional_context={
                    "config_key": config_key,
                },
            )

    async def collect_command_executor(
        self, dut_id: str, function_tag: str, command_config: Dict[str, Any], **kwargs
    ) -> Dict[str, Any]:
        """Generic command executor for configurable command execution

        Args:
            dut_id: Device under test ID
            function_tag: Function tag for logging
            command_config: Configuration defining the commands:
                - base_uri: Base URI for commands
                - device_discovery: Configuration for device discovery
                - command_groups: List of command groups, each with:
                    - name: Group name
                    - device_type: Type of device to iterate (e.g., "GPU", "FPGA", "Systems")
                    - commands: List of commands, each with:
                        - task: Task name
                        - action: HTTP action (usually "POST")
                        - payload_template: Payload template with variable placeholders
                        - output_pattern: Output filename pattern
                        - is_long_running: Whether command is long running
                        - wait_time: Time to wait after long-running commands
        """
        try:
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Starting command executor for {function_tag}",
                dut_id,
            )

            # Extract configuration
            base_uri = command_config.get("base_uri", "")
            device_discovery = command_config.get("device_discovery", {})
            command_groups = command_config.get("command_groups", [])

            # Define collection name for summary generation (matching host service pattern)
            collection_name = f"{function_tag} Collection"

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"=== R42 EXECUTION START === function_tag='{function_tag}', collection_name='{collection_name}'",
                dut_id,
            )

            # Apply prefix override if URI config manager is available
            if base_uri and self.dut_manager and self.dut_manager.uri_config_manager:
                base_uri = self.dut_manager.uri_config_manager._apply_prefix_override(
                    base_uri
                )

            if not base_uri:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=["No base_uri specified in command configuration"],
                    operation_name="command_executor",
                    additional_context={"command_config": command_config},
                )

            # Get device discovery configuration
            use_firmware_inventory = device_discovery.get(
                "use_firmware_inventory", True
            )
            discovery_method = device_discovery.get("method", "firmware_inventory")

            # Discover devices based on method
            discovered_devices = {}
            if discovery_method == "firmware_inventory":
                discovered_devices = await self._discover_chassis_devices(
                    dut_id,
                    device_types=["gpu"],
                    device_patterns={"gpu": [".*GPU.*", ".*SXM.*"]},
                    use_firmware_inventory=use_firmware_inventory,
                    **kwargs,
                )
            elif discovery_method == "chassis_device_discovery":
                # Use chassis-based device discovery with custom patterns
                device_patterns = device_discovery.get("device_patterns", {})
                device_types = (
                    list(device_patterns.keys()) if device_patterns else ["gpu"]
                )
                discovered_devices = await self._discover_chassis_devices(
                    dut_id,
                    device_types=device_types,
                    device_patterns=device_patterns,
                    use_firmware_inventory=use_firmware_inventory,
                    **kwargs,
                )
            elif discovery_method == "entity_collection":
                # Discover from entity collections (Systems, Chassis, Managers)
                entity_type = device_discovery.get("entity_type", "Systems")
                entity_uri = self.get_configured_uri(dut_id, entity_type)
                success, entities_response, _ = await self.dispatch_request(
                    dut_id, "GET", entity_uri
                )
                if success:
                    entities = entities_response.get("Members", [])
                    entity_ids = []
                    for entity in entities:
                        entity_id = entity.get("@odata.id", "").split("/")[-1]
                        if entity_id:
                            entity_ids.append(entity_id)
                    discovered_devices[entity_type] = entity_ids
            elif discovery_method == "static_list":
                # Use static list from configuration
                discovered_devices = device_discovery.get("static_devices", {})

            # Extract the actual discovered devices from the result
            if isinstance(discovered_devices, dict) and "context" in discovered_devices:
                discovered_devices = discovered_devices["context"].get(
                    "discovered_devices", {}
                )

            if not discovered_devices:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=["No devices discovered for command execution"],
                    operation_name="command_executor",
                    additional_context={"device_discovery": device_discovery},
                )

            output_files = []
            status_list = []
            error_messages = []

            # Process each command group
            for group in command_groups:
                group_name = group.get("name", "unknown_group")
                device_type = group.get("device_type", "GPU")
                commands = group.get("commands", [])

                # Get device instances for this type (case-insensitive lookup)
                device_instances = []
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Looking for device_type '{device_type}' in discovered_devices: {discovered_devices}",
                    dut_id,
                )
                for key, value in discovered_devices.items():
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Comparing '{key.lower()}' with '{device_type.lower()}'",
                        dut_id,
                    )
                    if key.lower() == device_type.lower():
                        device_instances = value
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"Found match! device_instances = {device_instances}",
                            dut_id,
                        )
                        break

                if not device_instances:
                    await self._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"No {device_type} devices found for command group {group_name}",
                        dut_id,
                    )
                    continue

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Processing command group {group_name} for {len(device_instances)} {device_type} devices",
                    dut_id,
                )

                # Execute commands for each device instance
                for device_instance in device_instances:
                    for command in commands:
                        task = command.get("task", "unknown_task")
                        action = command.get("action", "POST")
                        payload_template = command.get("payload_template", {})
                        output_pattern = command.get("output_pattern", "")
                        is_long_running = command.get("is_long_running", False)
                        wait_time = command.get("wait_time", 5)

                        # Substitute variables in payload template
                        payload = {}
                        for key, value in payload_template.items():
                            if isinstance(value, str):
                                # Replace common placeholders
                                substituted_value = value.replace(
                                    "{device_instance}", str(device_instance)
                                )
                                substituted_value = substituted_value.replace(
                                    "{device_type}", device_type
                                )
                                substituted_value = substituted_value.replace(
                                    "{group_name}", group_name
                                )
                                payload[key] = substituted_value
                            elif isinstance(value, list):
                                # Handle list values (like Data arrays)
                                payload[key] = value
                            else:
                                payload[key] = value

                        # Special handling for DeviceInstanceId - ensure it's an integer
                        if "DeviceInstanceId" in payload and isinstance(
                            payload["DeviceInstanceId"], str
                        ):
                            try:
                                payload["DeviceInstanceId"] = int(
                                    payload["DeviceInstanceId"]
                                )
                            except (ValueError, TypeError):
                                # Keep as string if conversion fails
                                pass

                        # Execute the command
                        success, response_data, error_details = (
                            await self.dispatch_request(
                                dut_id, action, base_uri, body=payload
                            )
                        )

                        if success:
                            # Save response
                            if output_pattern:
                                final_output_pattern = output_pattern
                                # Replace variables in output pattern
                                final_output_pattern = final_output_pattern.replace(
                                    "{device_instance}", str(device_instance)
                                )
                                final_output_pattern = final_output_pattern.replace(
                                    "{task}", task
                                )
                                final_output_pattern = final_output_pattern.replace(
                                    "{device_type}", device_type
                                )
                                final_output_pattern = final_output_pattern.replace(
                                    "{group_name}", group_name
                                )

                                # Remove output_pattern from kwargs to avoid duplicate argument
                                filtered_kwargs = {
                                    k: v
                                    for k, v in kwargs.items()
                                    if k != "output_pattern"
                                }

                                file_path = await self._save_data_with_common_pattern(
                                    dut_id,
                                    response_data,
                                    function_tag,
                                    output_pattern=final_output_pattern,
                                    substitutions={
                                        "device_instance": device_instance,
                                        "task": task,
                                        "group_name": group_name,
                                        "device_type": device_type,
                                    },
                                    **filtered_kwargs,
                                )
                                if file_path:
                                    output_files.append(file_path)

                            # Wait for long-running commands
                            if is_long_running:
                                await asyncio.sleep(wait_time)

                        if not success:
                            # Capture detailed error information with HTTP status codes
                            error_msg = f"Command failed: {group_name}/{task} for {device_type} device {device_instance}"

                            # Debug logging for error message creation (including the POST payload)
                            try:
                                payload_str = (
                                    json.dumps(payload, indent=2)
                                    if payload
                                    else "No payload"
                                )
                            except Exception:
                                payload_str = str(payload) if payload else "No payload"
                            await self._log_runtime(
                                "DEBUG",
                                "RedfishService",
                                f"Creating error message for failed command: {group_name}/{task}, device={device_instance}, success={success}, response_data={type(response_data)}, error_details={error_details}, payload={payload_str}",
                                dut_id,
                            )

                            # Extract HTTP status code and detailed error information
                            if error_details and error_details.get("http_status"):
                                # Use detailed error information from DUT manager
                                http_status = error_details.get("http_status")
                                error_message = error_details.get(
                                    "error_message", response_data
                                )
                                if response_data == "retry":
                                    if len(error_message) > 4000:
                                        error_msg += f" - HTTP {http_status} Server Error (retry exhausted) - {error_message[:4000]}... [truncated]"
                                    else:
                                        error_msg += f" - HTTP {http_status} Server Error (retry exhausted) - {error_message}"
                                else:
                                    if len(error_message) > 4000:
                                        error_msg += f" - HTTP {http_status}: {error_message[:4000]}... [truncated]"
                                    else:
                                        error_msg += (
                                            f" - HTTP {http_status}: {error_message}"
                                        )
                            elif isinstance(response_data, str):
                                # Check if it's a retry response
                                if response_data == "retry":
                                    error_msg += " - HTTP 5xx Server Error (retry exhausted) - Check BMC logs for specific error details"
                                # Check if it's an HTTP error response
                                elif response_data.startswith("HTTP "):
                                    error_msg += f" - {response_data}"
                                else:
                                    error_msg += f" - Response: {response_data}"
                            elif isinstance(response_data, dict):
                                # Extract structured error information
                                if "HTTPStatus" in response_data:
                                    status = response_data.get("HTTPStatus", "Unknown")
                                    message = response_data.get(
                                        "Message", "No message provided"
                                    )
                                    error_msg += f" - HTTP {status}: {message}"
                                elif "error" in response_data:
                                    error_obj = response_data["error"]
                                    if isinstance(error_obj, dict):
                                        error_code = error_obj.get("code", "Unknown")
                                        error_message = error_obj.get(
                                            "message", str(response_data)
                                        )
                                        error_msg += f" - Code: {error_code}, Message: {error_message}"
                                    else:
                                        error_msg += f" - Error: {error_obj}"
                                else:
                                    error_msg += f" - Error: {response_data.get('error', response_data)}"

                            error_messages.append(error_msg)

                            # Log detailed error for debugging (including POST payload)
                            if response_data == "retry":
                                await self._log_runtime(
                                    "ERROR",
                                    "RedfishService",
                                    f"Command execution failed after retries: {error_msg} - This indicates a persistent 5xx server error. Check BMC logs for detailed error information. POST payload sent: {payload_str}",
                                    dut_id,
                                )
                            else:
                                await self._log_runtime(
                                    "ERROR",
                                    "RedfishService",
                                    f"Command execution failed: {error_msg}. POST payload sent: {payload_str}",
                                    dut_id,
                                )

                            # Create error log file for failed command (including POST payload in context)
                            error_log_path = await self._create_error_log_file(
                                dut_id=dut_id,
                                collector_id=kwargs.get("collector_id"),
                                error_message=error_msg,
                                context={
                                    "group_name": group_name,
                                    "task": task,
                                    "device_type": device_type,
                                    "device_instance": device_instance,
                                    "action": action,
                                    "uri": base_uri,
                                    "payload": payload,  # Include the full payload structure
                                    "http_status": (
                                        error_details.get("http_status")
                                        if error_details
                                        else None
                                    ),
                                    "error_response": (
                                        error_details.get("error_message")
                                        if error_details
                                        else response_data
                                    ),
                                    "operation": "command_executor",
                                },
                            )

                            # Add error log file to output files
                            if error_log_path:
                                output_files.append(error_log_path)

                        status_list.append(success)

            # Determine the status based on results
            successful_operations = sum(status_list)
            total_operations = len(status_list)

            # Create detailed failure information for failures.json
            failure_details = []
            if error_messages:
                for i, error_msg in enumerate(error_messages):
                    failure_details.append(
                        {
                            "failure_id": i + 1,
                            "error_message": error_msg,
                            "timestamp": await self._get_current_timestamp(),
                            "collector": function_tag,
                            "dut_id": dut_id,
                        }
                    )

            # Log final operation counts for debugging
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Final operation counts: successful={successful_operations}, total={total_operations}, failed={len(error_messages)}, output_files={len(output_files)}",
                dut_id,
            )

            if total_operations == 0:
                # No operations attempted - treat as skipped
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Completed command executor for {function_tag} - no operations attempted, treating as skipped",
                    dut_id,
                )

                # Generate summary files
                await self._handle_collection_summary_generation(
                    dut_id=dut_id,
                    function_tag=function_tag,
                    collection_name=collection_name,
                    total_operations=0,
                    successful_operations=0,
                    failed_operations=0,
                    output_files=[],
                    additional_details={},
                    kwargs=kwargs,
                )

                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="command_executor",
                    additional_context={
                        "command_groups_processed": len(command_groups),
                        "total_commands": len(status_list),
                        "successful_commands": successful_operations,
                        "status": "skipped",
                        "reason": f"No operations attempted for {function_tag} - collector skipped",
                    },
                )
            elif successful_operations == 0:
                # All operations failed - treat as error
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Completed command executor for {function_tag} - all {total_operations} operations failed",
                    dut_id,
                )

                # Generate summary files and failures.json
                await self._handle_collection_summary_generation(
                    dut_id=dut_id,
                    function_tag=function_tag,
                    collection_name=collection_name,
                    total_operations=total_operations,
                    successful_operations=0,
                    failed_operations=total_operations,
                    output_files=output_files,
                    additional_details={"error_messages": error_messages},
                    kwargs=kwargs,
                )
                await self._save_failures_json(
                    dut_id,
                    function_tag,
                    failure_details,
                    kwargs.get("collector_id", ""),
                )

                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=total_operations,
                    output_files=output_files,
                    error_messages=[],
                    operation_name="command_executor",
                    additional_context={
                        "command_groups_processed": len(command_groups),
                        "total_commands": len(status_list),
                        "successful_commands": successful_operations,
                        "status": "error",
                        "reason": f"All {total_operations} operations failed for {function_tag}",
                    },
                )
            elif successful_operations < total_operations:
                # Some operations succeeded, some failed - treat as partial
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Completed command executor for {function_tag} - {successful_operations}/{total_operations} operations succeeded (partial)",
                    dut_id,
                )

                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Status determination: {successful_operations}/{total_operations} -> PARTIAL status",
                    dut_id,
                )

                # Generate summary files and failures.json
                await self._handle_collection_summary_generation(
                    dut_id=dut_id,
                    function_tag=function_tag,
                    collection_name=collection_name,
                    total_operations=total_operations,
                    successful_operations=successful_operations,
                    failed_operations=total_operations - successful_operations,
                    output_files=output_files,
                    additional_details={"error_messages": error_messages},
                    kwargs=kwargs,
                )
                await self._save_failures_json(
                    dut_id,
                    function_tag,
                    failure_details,
                    kwargs.get("collector_id", ""),
                )

                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"=== R42 RETURNING PARTIAL RESULT === successful_operations={successful_operations}, total_operations={total_operations}, output_files={len(output_files)}, error_messages={len(error_messages)}",
                    dut_id,
                )

                return await self._create_standardized_collector_result(
                    successful_operations=successful_operations,
                    total_operations=total_operations,
                    output_files=output_files,
                    error_messages=error_messages,
                    operation_name="command_executor",
                    additional_context={
                        "command_groups_processed": len(command_groups),
                        "total_commands": len(status_list),
                        "successful_commands": successful_operations,
                    },
                )
            else:
                # All operations succeeded
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Completed command executor for {function_tag} - all {total_operations} operations succeeded",
                    dut_id,
                )

                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Status determination: {successful_operations}/{total_operations} -> SUCCESS status",
                    dut_id,
                )

                # Generate summary files
                await self._handle_collection_summary_generation(
                    dut_id=dut_id,
                    function_tag=function_tag,
                    collection_name=collection_name,
                    total_operations=total_operations,
                    successful_operations=successful_operations,
                    failed_operations=0,
                    output_files=output_files,
                    additional_details={},
                    kwargs=kwargs,
                )

                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"=== R42 RETURNING SUCCESS RESULT === successful_operations={successful_operations}, total_operations={total_operations}, output_files={len(output_files)}",
                    dut_id,
                )

                return await self._create_standardized_collector_result(
                    successful_operations=successful_operations,
                    total_operations=total_operations,
                    output_files=output_files,
                    error_messages=[],
                    operation_name="command_executor",
                    additional_context={
                        "command_groups_processed": len(command_groups),
                        "total_commands": len(status_list),
                        "successful_commands": successful_operations,
                    },
                )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception in collect_command_executor: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"Exception in command executor: {str(e)}"],
                operation_name="command_executor",
                additional_context={},
            )
