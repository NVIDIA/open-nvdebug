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
Execution Engine for NVDebug Tool.

Handles collector execution strategies with support for sequential and parallel
execution, priority-based scheduling, and progress tracking across multiple DUTs.
"""

import asyncio
import concurrent.futures
import contextvars
import logging
import os
import queue
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from ..services.base_service import BaseService
from ..utils.enums import CollectorServiceMapping
from .async_logger import _collector_context
from .collection_status_tracker import CollectionStatusTracker

logger = logging.getLogger(__name__)


@dataclass
class CollectorBucket:
    """
    Represents a bucket of collectors (sequential or parallel).

    Attributes:
        collectors (List[str]): List of collector IDs.
        is_sequential (bool): Whether collectors run sequentially.
        service_name (str): Service name for the bucket.
    """

    collectors: List[str]
    is_sequential: bool
    service_name: str


@dataclass
class CollectorGroup:
    """
    Represents a collector group (Redfish, SSH, IPMI, Host) with its buckets.

    Attributes:
        service_name: Name of the service.
        sequential_bucket: Sequential execution bucket.
        parallel_bucket: Parallel execution bucket.
    """

    service_name: str
    sequential_bucket: CollectorBucket
    parallel_bucket: CollectorBucket


@dataclass
class DUTExecutionPlan:
    """
    Represents execution plan for a single DUT.

    Attributes:
        dut_id: DUT ID.
        collector_groups: List of collector groups to execute.
    """

    dut_id: str
    collector_groups: List[CollectorGroup]


class ExecutionEngine:
    """
    Manages collector execution strategies and progress tracking.

    Handles sequential and parallel collector execution across multiple DUTs
    with support for priority-based scheduling and service grouping.
    """

    def __init__(
        self,
        config_manager,
        dut_manager,
        logger,
        orchestrator=None,
        preflight_results=None,
        status_tracker=None,
    ):
        self.config_manager = config_manager
        self.dut_manager = dut_manager
        self.logger = logger
        self.orchestrator = orchestrator
        self.preflight_results = preflight_results or {}
        self.status_tracker = status_tracker

    async def _log_runtime(
        self,
        level: str,
        message: str,
        component: str = "ExecutionEngine",
        dut_id: str = None,
    ) -> None:
        """
        Log message using async logger if available, otherwise fall back to standard logger
        """
        if hasattr(self, "logger") and self.logger:
            # Use async logger if available
            if dut_id:
                await self.logger.write_to_dut_runtime_log(
                    dut_id, level, component, message
                )
            else:
                await self.logger.log_runtime(level, component, message)
        else:
            # Fallback to standard logger
            if level == "ERROR":
                logger.error(message)
            elif level == "WARNING":
                logger.warning(message)
            elif level == "DEBUG":
                logger.debug(message)
            else:
                logger.info(message)

    def set_preflight_results(self, preflight_results: Dict[str, Any]) -> None:
        """
        Set preflight results for collector execution decisions.

        Args:
            preflight_results: Dictionary of preflight check results.
        """
        self.preflight_results = preflight_results or {}

    # def set_progress_state(self, progress_state) -> None:
    #     """Set progress state manager for tracking execution progress"""
    #     self.progress_state = progress_state

    async def _get_service_for_collector(
        self, collector_id: str
    ) -> Optional[BaseService]:
        """
        Get the appropriate service for a collector.

        Args:
            collector_id: Collector ID.

        Returns:
            Service instance or None if not found.
        """
        collector_info = self.config_manager.get_collector_info(collector_id)
        group = collector_info.get("group", "").lower()

        service_name = CollectorServiceMapping.get_service_from_group_name(group)
        services = self.config_manager.get_services()

        await self._log_runtime(
            "DEBUG",
            f"Looking for service '{service_name}' for collector {collector_id} (group: {group}), available services: {list(services.keys())}",
        )

        return services.get(service_name)

    def _get_collector_name(self, collector_id: str) -> str:
        """
        Get the collector name from collector definitions.

        Args:
            collector_id: Collector ID.

        Returns:
            Collector name or ID if not found.
        """
        try:
            # Get collector definitions from config manager
            collector_definitions = self.config_manager.get_collector_definitions()
            # The structure is {'collectors': {'R1': {...}, 'R2': {...}}}
            if (
                "collectors" in collector_definitions
                and collector_id in collector_definitions["collectors"]
            ):
                name = collector_definitions["collectors"][collector_id].get(
                    "name", collector_id
                )
                return name
            else:
                return collector_id
        except Exception as e:
            return collector_id

    def _get_collector_id_from_path(self, collector_path: str) -> str:
        """
        Extract collector ID from collector path.

        Args:
            collector_path: Path string to parse.

        Returns:
            Extracted collector ID.
        """
        try:
            # Handle different path formats
            if "/" in collector_path:
                # Path format: "path/to/collector"
                return collector_path.split("/")[-1]
            elif "." in collector_path:
                # Dot format: "path.to.collector"
                return collector_path.split(".")[-1]
            else:
                return collector_path
        except Exception as e:
            return collector_path

    async def _should_skip_collector(
        self, collector_id: str, dut_id: str
    ) -> tuple[bool, str]:
        """
        Check if collector should be skipped based on preflight and baseboard.

        Args:
            collector_id: Collector ID.
            dut_id: DUT ID.

        Returns:
            Tuple of (should_skip, reason).
        """

        # Check baseboard applicability first
        if self.orchestrator and self.orchestrator.dut_manager:
            dut = self.orchestrator.dut_manager.get_dut(dut_id)
            if dut and dut.config:
                baseboard_info = dut.config.get("baseboard") or dut.config.get(
                    "TargetBaseboard"
                )

                # If no baseboard is configured, this is a critical configuration error
                # The tool should not run without proper baseboard configuration
                if not baseboard_info or baseboard_info == "Unknown":
                    reason = f"CRITICAL ERROR: DUT {dut_id} has no baseboard configured ('{baseboard_info}'). Baseboard is required for collector compatibility. Please configure baseboard in DUT config."
                    await self._log_runtime(
                        "ERROR",
                        f"CRITICAL: DUT {dut_id} missing baseboard configuration - cannot determine collector compatibility",
                        dut_id=dut_id,
                    )
                    # This is a critical error that should stop execution
                    # Use the same pattern as main.py validation errors
                    # Note: We need to get the console from the orchestrator since we don't have direct access to it here
                    if hasattr(self.orchestrator, "logger") and hasattr(
                        self.orchestrator.logger, "console"
                    ):
                        console = self.orchestrator.logger.console
                        console.print_error(
                            f"DUT {dut_id} missing baseboard configuration. Cannot proceed without baseboard."
                        )
                        console.print_error(
                            "Please configure baseboard in DUT config file."
                        )
                    else:
                        # Fallback to basic error message if console not available
                        print(
                            f"ERROR: DUT {dut_id} missing baseboard configuration. Cannot proceed without baseboard.\n"
                        )
                        print("ERROR: Please configure baseboard in DUT config file.")
                    sys.exit(1)

                collector_def = self.orchestrator.config_manager.get_collector_info(
                    collector_id
                )

                if (
                    collector_def
                    and not self.orchestrator.is_collector_applicable_for_baseboard(
                        collector_def, baseboard_info
                    )
                ):
                    # Check why it's not applicable
                    tags = collector_def.get("tags", {})
                    include_tags = tags.get("include", [])
                    exclude_tags = tags.get("exclude", [])

                    if exclude_tags:
                        reason = f"Collector not applicable for DUT {dut_id} baseboard '{baseboard_info}' (Tags: {exclude_tags})"
                    elif include_tags:
                        reason = f"Collector not applicable for DUT {dut_id} baseboard '{baseboard_info}' (BaseboardConstraint)"
                    else:
                        reason = f"Collector not applicable for DUT {dut_id} baseboard '{baseboard_info}' (BaseboardConstraint)"

                    return True, reason

        # Check preflight results
        if not self.preflight_results:
            return False, ""

        # Get service name from collector ID prefix
        service_name = CollectorServiceMapping.get_service_from_collector_id(
            collector_id
        )

        # Health check collectors don't require preflight checks
        if service_name == "health_check":
            return False, ""

        # In local mode, handle service-specific logic
        if self.orchestrator and self.orchestrator.dut_manager:
            dut = self.orchestrator.dut_manager.get_dut(dut_id)
            if dut and dut.config and dut.config.get("local", False):
                await self._log_runtime(
                    "DEBUG",
                    f"Local mode detected for DUT {dut_id}, service {service_name}",
                    dut_id=dut_id,
                )
                # Check if BMC IP is available
                has_bmc_ip = dut.credentials and dut.credentials.bmc_ip

                if not has_bmc_ip:
                    await self._log_runtime(
                        "DEBUG",
                        f"No BMC IP in local mode for DUT {dut_id}, service {service_name}",
                        dut_id=dut_id,
                    )
                    # No BMC IP in local mode:
                    # - Redfish and SSH require BMC IP, so skip them
                    # - IPMI can work locally via sudo, so don't skip it
                    # - Host collectors always work locally, so don't skip them
                    if service_name in ["redfish", "ssh"]:
                        await self._log_runtime(
                            "DEBUG",
                            f"Skipping {service_name} collector in local mode (no BMC IP)",
                            dut_id=dut_id,
                        )
                        return (
                            True,
                            f"Collector not executed due to {service_name} preflight failure: No BMC IP configured (local mode)",
                        )
                    elif service_name in ["ipmi", "host"]:
                        await self._log_runtime(
                            "DEBUG",
                            f"Allowing {service_name} collector in local mode (no BMC IP)",
                            dut_id=dut_id,
                        )
                        # IPMI and Host can work locally, so don't skip based on preflight
                        return False, ""
                else:
                    await self._log_runtime(
                        "DEBUG",
                        f"BMC IP available in local mode for DUT {dut_id}, service {service_name}",
                        dut_id=dut_id,
                    )
                # If BMC IP is provided in local mode, let normal preflight logic handle it

        if service_name and dut_id in self.preflight_results:
            # Get DUT-specific preflight results
            dut_preflight = self.preflight_results[dut_id]
            if (
                "services" in dut_preflight
                and service_name in dut_preflight["services"]
            ):
                service_result = dut_preflight["services"][service_name]
                if service_result.get("status") == "fail":
                    # Get the actual preflight failure reason
                    failure_reason = service_result.get(
                        "message", "Unknown preflight failure"
                    )
                    reason = f"Collector not executed due to {service_name} preflight failure: {failure_reason}"
                    return True, reason
            else:
                # Debug: Log what services are available
                available_services = (
                    list(dut_preflight.get("services", {}).keys())
                    if "services" in dut_preflight
                    else []
                )
                await self._log_runtime(
                    "DEBUG",
                    f"Collector {collector_id} for DUT {dut_id}: service_name={service_name}, available_services={available_services}",
                    dut_id=dut_id,
                )

        return False, ""

    async def get_filtered_collectors_per_dut(
        self, collector_ids: List[str], dut_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Get filtered collectors for each DUT based on all filtering criteria.

        This method applies:
        1. Baseboard filtering (per-DUT)
        2. Skip flags (tool config + DUT config overrides)
        3. Include/exclude collectors (tool config + DUT config overrides)

        Args:
            collector_ids: List of collector IDs to filter
            dut_ids: List of DUT IDs

        Returns:
            Dict with keys:
            - 'filtered_collectors': Dict mapping DUT ID to list of filtered collector IDs
            - 'skipped_collectors': Dict mapping DUT ID to list of skipped collector info
        """
        await self._log_runtime(
            "INFO",
            f"Starting per-DUT filtering for {len(dut_ids)} DUT(s) with {len(collector_ids)} input collectors",
        )
        await self._log_runtime(
            "DEBUG",
            f"Input collector IDs: {collector_ids}",
        )
        await self._log_runtime(
            "DEBUG",
            f"Input DUT IDs: {dut_ids}",
        )

        filtered_collectors_per_dut = {}
        skipped_collectors_per_dut = {}

        await self._log_runtime(
            "INFO",
            f"About to iterate over {len(dut_ids)} DUT(s): {dut_ids}",
        )
        await self._log_runtime(
            "INFO",
            f"About to check {len(collector_ids)} collector(s): {collector_ids}",
        )
        await self._log_runtime(
            "INFO",
            f"Type of dut_ids: {type(dut_ids)}, Type of collector_ids: {type(collector_ids)}",
        )
        await self._log_runtime(
            "INFO",
            f"Bool check - dut_ids: {bool(dut_ids)}, collector_ids: {bool(collector_ids)}",
        )

        iteration_count = 0
        for dut_id in dut_ids:
            iteration_count += 1
            await self._log_runtime(
                "DEBUG",
                f"FOR LOOP: Starting DUT iteration {iteration_count} for {dut_id}",
                dut_id=dut_id,
            )
            await self._log_runtime(
                "INFO",
                f"Processing DUT {dut_id} for filtering",
                dut_id=dut_id,
            )
            dut_filtered = []
            dut_skipped = []
            skipped_by_config = 0
            skipped_by_baseboard = 0

            await self._log_runtime(
                "DEBUG",
                f"DUT {dut_id}: Starting collector loop with {len(collector_ids)} collectors: {collector_ids}",
                dut_id=dut_id,
            )
            collector_loop_count = 0
            for collector_id in collector_ids:
                collector_loop_count += 1
                await self._log_runtime(
                    "DEBUG",
                    f"COLLECTOR LOOP: Iteration {collector_loop_count} - checking collector {collector_id} for DUT {dut_id}",
                    dut_id=dut_id,
                )

                # Check baseboard applicability FIRST (hard requirement, cannot be overridden)
                should_skip_baseboard, baseboard_reason = (
                    await self._should_skip_collector(collector_id, dut_id)
                )

                await self._log_runtime(
                    "DEBUG",
                    f"Baseboard check for {collector_id}: should_skip={should_skip_baseboard}, reason={baseboard_reason}",
                    dut_id=dut_id,
                )

                if should_skip_baseboard:
                    await self._log_runtime(
                        "DEBUG",
                        f"Filtering out {collector_id} for DUT {dut_id}: {baseboard_reason}",
                        dut_id=dut_id,
                    )
                    skipped_by_baseboard += 1

                    # Track skipped collector with reason for explicitly requested collectors
                    # Check if this collector was explicitly requested
                    tool_config = self.config_manager.get_tool_config()
                    explicitly_requested_str = tool_config.get("collector_id", "")
                    include_collectors = tool_config.get("include_collectors", [])

                    explicitly_requested = []
                    if explicitly_requested_str:
                        explicitly_requested = [
                            cid.strip() for cid in explicitly_requested_str.split(",")
                        ]

                    is_explicitly_requested = (
                        explicitly_requested and collector_id in explicitly_requested
                    ) or (include_collectors and collector_id in include_collectors)

                    if is_explicitly_requested:
                        # Log warning for explicitly requested but baseboard-incompatible collectors
                        await self._log_runtime(
                            "WARNING",
                            f"Collector {collector_id} was explicitly requested but skipped: {baseboard_reason}",
                            dut_id=dut_id,
                        )
                        await self._log_runtime(
                            "DEBUG",
                            f"Collector {collector_id} is explicitly requested - adding to skipped list for execution summary",
                            dut_id=dut_id,
                        )

                        # Track in skipped list so it shows in execution summary with reason
                        collector_info = self.config_manager.get_collector_info(
                            collector_id
                        )
                        collector_name = (
                            collector_info.get("name", "Unknown")
                            if collector_info
                            else "Unknown"
                        )
                        group = (
                            collector_info.get("group", "Unknown")
                            if collector_info
                            else "Unknown"
                        )

                        dut_skipped.append(
                            {
                                "collector_id": collector_id,
                                "collector_name": collector_name,
                                "group": group,
                                "reason": baseboard_reason,
                                "skip_type": "baseboard",
                            }
                        )
                    continue

                # Check if collector should be skipped by config (SKIP flags, skip_collectors list)
                should_skip_config, skip_reason = (
                    await self._should_skip_collector_by_config(collector_id, dut_id)
                )

                if should_skip_config:
                    await self._log_runtime(
                        "DEBUG",
                        f"Filtering out {collector_id} for DUT {dut_id}: {skip_reason}",
                        dut_id=dut_id,
                    )
                    skipped_by_config += 1

                    # Track skipped collector with reason
                    collector_info = self.config_manager.get_collector_info(
                        collector_id
                    )
                    collector_name = (
                        collector_info.get("name", "Unknown")
                        if collector_info
                        else "Unknown"
                    )
                    group = (
                        collector_info.get("group", "Unknown")
                        if collector_info
                        else "Unknown"
                    )

                    dut_skipped.append(
                        {
                            "collector_id": collector_id,
                            "collector_name": collector_name,
                            "group": group,
                            "reason": skip_reason,
                            "skip_type": "config",
                        }
                    )
                    continue

                # Collector passed all filters
                dut_filtered.append(collector_id)
                await self._log_runtime(
                    "DEBUG",
                    f"Collector {collector_id} passed all filters for DUT {dut_id}",
                    dut_id=dut_id,
                )

            # Apply --include-collectors as a filter (restrict to only these collectors)
            # Note: cli_handler.py already handles intersection logic, but we apply it here
            # per-DUT in case different DUTs have different baseboard compatibility
            tool_config = self.config_manager.get_tool_config()
            tool_include_collectors = getattr(tool_config, "include_collectors", [])
            if tool_include_collectors:
                await self._log_runtime(
                    "INFO",
                    f"Applying --include-collectors filter for DUT {dut_id}: only collectors in {tool_include_collectors} will run",
                    dut_id=dut_id,
                )

                # Filter: only keep collectors that are in the include_collectors list
                original_count = len(dut_filtered)
                kept_collectors = []
                filtered_out_collectors = []

                for cid in dut_filtered:
                    if cid in tool_include_collectors:
                        kept_collectors.append(cid)
                    else:
                        filtered_out_collectors.append(cid)

                dut_filtered = kept_collectors

                if filtered_out_collectors:
                    await self._log_runtime(
                        "INFO",
                        f"Filtered out {len(filtered_out_collectors)} collectors for DUT {dut_id} that were not in --include-collectors list: {filtered_out_collectors}",
                        dut_id=dut_id,
                    )

                if kept_collectors:
                    await self._log_runtime(
                        "DEBUG",
                        f"Kept {len(kept_collectors)} collectors for DUT {dut_id} from --include-collectors filter: {kept_collectors}",
                        dut_id=dut_id,
                    )

                # Log if any collectors from include_collectors were not in the original filtered list
                # This helps debug cases where users expect a collector to run but it was filtered earlier
                missing_from_original = [
                    cid
                    for cid in tool_include_collectors
                    if cid not in dut_filtered and cid not in filtered_out_collectors
                ]
                if missing_from_original:
                    await self._log_runtime(
                        "DEBUG",
                        f"Collectors in --include-collectors that were already filtered out (by baseboard/skip/etc.) for DUT {dut_id}: {missing_from_original}",
                        dut_id=dut_id,
                    )

            await self._log_runtime(
                "DEBUG",
                f"DUT {dut_id}: Collector loop complete. Filtered: {dut_filtered}, Skipped: {len(dut_skipped)}",
                dut_id=dut_id,
            )

            filtered_collectors_per_dut[dut_id] = dut_filtered
            skipped_collectors_per_dut[dut_id] = dut_skipped

            await self._log_runtime(
                "INFO",
                f"DUT {dut_id} filtering complete: {len(dut_filtered)} collectors will run, {skipped_by_config} skipped by config, {skipped_by_baseboard} skipped by baseboard, out of {len(collector_ids)} input collectors",
                dut_id=dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                f"DUT {dut_id} final filtered collectors: {dut_filtered}",
                dut_id=dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                f"DUT {dut_id} skipped collectors: {len(dut_skipped)}",
                dut_id=dut_id,
            )

        await self._log_runtime(
            "DEBUG",
            f"DUT loop complete - processed {iteration_count} DUT(s)",
        )
        await self._log_runtime(
            "INFO",
            f"Per-DUT filtering complete for all {len(dut_ids)} DUT(s)",
        )

        return {
            "filtered_collectors": filtered_collectors_per_dut,
            "skipped_collectors": skipped_collectors_per_dut,
        }

    async def _should_skip_collector_by_config(
        self, collector_id: str, dut_id: str
    ) -> tuple[bool, str]:
        """
        Check if collector should be skipped based on configuration (tool-level and per-DUT).

        Args:
            collector_id: Collector ID.
            dut_id: DUT ID.

        Returns:
            Tuple of (should_skip, reason).
        """
        try:
            await self._log_runtime(
                "DEBUG",
                f"Checking skip config for collector {collector_id} on DUT {dut_id}",
                dut_id=dut_id,
            )

            tool_config = self.config_manager.get_tool_config()
            await self._log_runtime(
                "DEBUG",
                f"Tool config keys: {list(tool_config.keys())}",
                dut_id=dut_id,
            )

            # Log skip flag values for debugging
            await self._log_runtime(
                "DEBUG",
                f"Skip flag values - tool_config: SKIP_BMC_SSH_LOGS={tool_config.get('SKIP_BMC_SSH_LOGS')}, SKIP_HOST_LOGS={tool_config.get('SKIP_HOST_LOGS')}, SKIP_REDFISH_OOB_LOGS={tool_config.get('SKIP_REDFISH_OOB_LOGS')}, SKIP_IPMI_LOGS={tool_config.get('SKIP_IPMI_LOGS')}",
                dut_id=dut_id,
            )

            # Get tool-level skip/include collector lists
            tool_skip_collectors = tool_config.get("skip_collectors", [])
            tool_include_collectors = tool_config.get("include_collectors", [])

            await self._log_runtime(
                "DEBUG",
                f"Tool skip_collectors: {tool_skip_collectors}, tool include_collectors: {tool_include_collectors}",
                dut_id=dut_id,
            )

            # Get per-DUT skip/include collector lists
            dut_config = self.dut_manager.get_dut_config(dut_id)

            # Log skip flag values for debugging
            await self._log_runtime(
                "DEBUG",
                f"Skip flag values - dut_config: SKIP_BMC_SSH_LOGS={dut_config.get('SKIP_BMC_SSH_LOGS') if dut_config else 'None'}, SKIP_HOST_LOGS={dut_config.get('SKIP_HOST_LOGS') if dut_config else 'None'}, SKIP_REDFISH_OOB_LOGS={dut_config.get('SKIP_REDFISH_OOB_LOGS') if dut_config else 'None'}, SKIP_IPMI_LOGS={dut_config.get('SKIP_IPMI_LOGS') if dut_config else 'None'}",
                dut_id=dut_id,
            )

            dut_skip_collectors = (
                dut_config.get("skip_collectors", []) if dut_config else []
            )
            dut_include_collectors = (
                dut_config.get("include_collectors", []) if dut_config else []
            )

            await self._log_runtime(
                "DEBUG",
                f"DUT {dut_id} skip_collectors: {dut_skip_collectors}, include_collectors: {dut_include_collectors}",
                dut_id=dut_id,
            )

            # Per-DUT configuration takes precedence over tool-level configuration
            # If per-DUT include_collectors is specified, it overrides everything
            if dut_include_collectors:
                if collector_id not in dut_include_collectors:
                    return (
                        True,
                        f"Collector {collector_id} not in DUT {dut_id} include list",
                    )
                # If collector is in DUT include list, check DUT skip list
                if dut_skip_collectors and collector_id in dut_skip_collectors:
                    return (
                        True,
                        f"Collector {collector_id} in DUT {dut_id} skip list",
                    )
                return False, ""

            # If per-DUT skip_collectors is specified, check it
            if dut_skip_collectors and collector_id in dut_skip_collectors:
                return (
                    True,
                    f"Collector {collector_id} in DUT {dut_id} skip list",
                )

            # Fall back to tool-level configuration
            # Note: tool_include_collectors is treated as an "add to default" list, not a "replace all" list
            # So we don't filter out collectors that aren't in the include list
            # The include_collectors are handled at the CLI level by adding them to processed_cids

            # Check if this collector was explicitly requested via -S or --include-collectors
            # If so, skip ALL skip flag checks to allow it to run
            tool_config = self.config_manager.get_tool_config()
            explicitly_requested_str = tool_config.get("collector_id", "")
            include_collectors = tool_config.get("include_collectors", [])

            # Parse explicitly_requested_str (comma-separated) into a list
            explicitly_requested = []
            if explicitly_requested_str:
                explicitly_requested = [
                    cid.strip() for cid in explicitly_requested_str.split(",")
                ]

            is_explicitly_requested = (
                explicitly_requested and collector_id in explicitly_requested
            ) or (include_collectors and collector_id in include_collectors)

            if is_explicitly_requested:
                await self._log_runtime(
                    "DEBUG",
                    f"Collector {collector_id} was explicitly requested via -S or --include-collectors",
                    dut_id=dut_id,
                )

                # Check if this is an SSH collector and SSH logs are disabled
                collector_info = self.config_manager.get_collector_info(collector_id)
                collector_group = collector_info.get("group", "").upper()

                if collector_group in ["SSH", "BMC_SSH"]:
                    # Check SSH skip flag even for explicitly requested collectors
                    tool_skip_ssh = tool_config.get("SKIP_BMC_SSH_LOGS", False)
                    dut_skip_ssh = (
                        dut_config.get("SKIP_BMC_SSH_LOGS", False)
                        if dut_config
                        else False
                    )

                    # Use DUT config value if it was explicitly set, otherwise use tool config value
                    dut = self.dut_manager.get_dut(dut_id)
                    if dut and dut.has_explicit_config_key("SKIP_BMC_SSH_LOGS"):
                        should_skip_ssh = dut_skip_ssh
                        skip_source = "DUT config"
                    else:
                        should_skip_ssh = tool_skip_ssh
                        skip_source = "tool config"

                    if should_skip_ssh:
                        await self._log_runtime(
                            "WARNING",
                            f"Collector {collector_id} was explicitly requested but skipped due to SKIP_BMC_SSH_LOGS=True in {skip_source}",
                            dut_id=dut_id,
                        )
                        return (
                            True,
                            f"Collector {collector_id} was explicitly requested but skipped due to SKIP_BMC_SSH_LOGS=True in {skip_source}",
                        )

                # For non-SSH collectors or when SSH is not disabled, allow explicitly requested collectors to run
                await self._log_runtime(
                    "DEBUG",
                    f"Collector {collector_id} was explicitly requested and will run (bypassing other skip flags)",
                    dut_id=dut_id,
                )
                return False, ""  # Don't skip the collector

            # Check tool-level skip list
            if tool_skip_collectors and collector_id in tool_skip_collectors:
                return True, f"Collector {collector_id} in tool skip list"

            # Check tool-level COLLECTOR_TO_SKIP list
            tool_collector_to_skip = tool_config.get("COLLECTOR_TO_SKIP", [])
            if tool_collector_to_skip and collector_id in tool_collector_to_skip:
                return True, f"Collector {collector_id} in tool COLLECTOR_TO_SKIP list"

            # Check new COLLECTOR_TO_SKIP list (per-DUT)
            if dut_config:
                collector_to_skip = dut_config.get("COLLECTOR_TO_SKIP", [])
                if collector_to_skip and collector_id in collector_to_skip:
                    return (
                        True,
                        f"Collector {collector_id} in DUT {dut_id} COLLECTOR_TO_SKIP list",
                    )

            # Check legacy skip flags based on collector group
            if dut_config:
                collector_info = self.config_manager.get_collector_info(collector_id)
                collector_group = collector_info.get("group", "").upper()

                await self._log_runtime(
                    "DEBUG",
                    f"Collector {collector_id} group: {collector_group}",
                    dut_id=dut_id,
                )

                # Map collector groups to skip flags
                skip_flag_mapping = {
                    "REDFISH": "SKIP_REDFISH_OOB_LOGS",
                    "SSH": "SKIP_BMC_SSH_LOGS",
                    "IPMI": "SKIP_IPMI_LOGS",
                    "HOST": "SKIP_HOST_LOGS",
                    "BMC_SSH": "SKIP_BMC_SSH_LOGS",
                }

                skip_flag = skip_flag_mapping.get(collector_group)
                if skip_flag:
                    await self._log_runtime(
                        "DEBUG",
                        f"Checking skip flag {skip_flag} for collector {collector_id} (group: {collector_group})",
                        dut_id=dut_id,
                    )

                    # Check both tool config and DUT config for skip flags
                    # DUT config takes precedence if it explicitly sets the flag
                    tool_skip = tool_config.get(skip_flag, False)
                    dut_skip = dut_config.get(skip_flag, False) if dut_config else False

                    await self._log_runtime(
                        "DEBUG",
                        f"Skip flag values: tool_skip={tool_skip}, dut_skip={dut_skip}",
                        dut_id=dut_id,
                    )

                    # Use DUT config value if it was explicitly set in the DUT config file,
                    # otherwise use tool config value
                    dut = self.dut_manager.get_dut(dut_id)
                    if dut and dut.has_explicit_config_key(skip_flag):
                        should_skip = dut_skip
                        await self._log_runtime(
                            "DEBUG",
                            f"DUT {dut_id} has explicit {skip_flag} setting in YAML, using DUT value: {dut_skip}",
                            dut_id=dut_id,
                        )
                    else:
                        should_skip = tool_skip
                        await self._log_runtime(
                            "DEBUG",
                            f"DUT {dut_id} does not have explicit {skip_flag} setting in YAML, using tool value: {tool_skip}",
                            dut_id=dut_id,
                        )

                    # Debug logging - show explicit config keys
                    await self._log_runtime(
                        "DEBUG",
                        f"DUT {dut_id} explicit config keys: {dut.explicit_config_keys}",
                        dut_id=dut_id,
                    )

                    # Debug logging
                    await self._log_runtime(
                        "DEBUG",
                        f"Skip check for {collector_id} (group: {collector_group}): tool_skip={tool_skip}, dut_skip={dut_skip}, should_skip={should_skip}",
                        dut_id=dut_id,
                    )

                    if should_skip:
                        skip_source = (
                            "DUT config"
                            if (dut_config and skip_flag in dut_config)
                            else "tool config"
                        )
                        await self._log_runtime(
                            "INFO",
                            f"Collector {collector_id} skipped due to {skip_flag}=True in {skip_source}",
                            dut_id=dut_id,
                        )
                        return (
                            True,
                            f"Collector {collector_id} skipped due to {skip_flag}=True in {skip_source}",
                        )
                    else:
                        await self._log_runtime(
                            "DEBUG",
                            f"Collector {collector_id} NOT skipped - {skip_flag}={should_skip}",
                            dut_id=dut_id,
                        )

        except Exception as e:
            await self._log_runtime(
                "WARNING",
                f"Error checking collector skip configuration for {collector_id} on {dut_id}: {e}",
                dut_id=dut_id,
            )

        return False, ""

    @staticmethod
    def _normalize_result(raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure results have a 'status' key; map legacy 'success' bool to status string.

        Args:
            raw: Raw collector result.

        Returns:
            Normalized result with status key.
        """
        if raw is None:
            return {
                "status": "error",
                "reason": "Empty result",
                "execution_time": 0.0,
            }
        result = dict(raw)

        # Only set status if it doesn't already exist (preserve existing status)
        if "status" not in result:
            success_flag = result.get("success")
            if success_flag is True:
                result["status"] = "success"
            elif success_flag is False:
                result["status"] = "error"
            else:
                result["status"] = "skipped"
        if "execution_time" not in result:
            result["execution_time"] = 0.0
        if "reason" not in result:
            # Try to extract reason from error field if status is error
            if result.get("status") == "error" and "error" in result:
                result["reason"] = str(result["error"])
            else:
                result["reason"] = ""
        return result

    async def execute_sequential_collectors_with_progress(
        self,
        collectors: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task,
    ) -> Dict[str, Any]:
        """
        Execute collectors sequentially with per-DUT progress tracking.

        Args:
            collectors: List of collector IDs.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            progress: Progress bar instance.
            main_task: Main task ID for progress tracking.

        Returns:
            Dictionary of execution results per DUT and collector.
        """
        # print(
        #     f"DEBUG: execute_sequential_collectors_with_progress called with {len(collectors)} collectors"
        # )
        await self._log_runtime(
            "DEBUG",
            f"execute_sequential_collectors_with_progress called with collectors: {collectors}, dut_ids: {dut_ids}",
        )
        await self._log_runtime(
            "DEBUG",
            f"status_tracker available: {self.status_tracker is not None}",
        )
        await self._log_runtime(
            "INFO",
            f"Starting sequential execution of {len(collectors)} collectors on {len(dut_ids)} DUTs",
        )
        await self._log_runtime("INFO", f"Collector IDs: {collectors}")
        await self._log_runtime("INFO", f"DUT IDs: {dut_ids}")
        results = {}

        # Create progress tasks for each DUT (only if progress is available)
        dut_tasks = {}
        if progress:
            for dut_id in dut_ids:
                task = progress.add_task(
                    f"[green]{dut_id}[/green]",
                    total=len(collectors),
                    start=False,
                )
                dut_tasks[dut_id] = task

            # Start all DUT tasks
            for task in dut_tasks.values():
                progress.start_task(task)

        for i, collector_id in enumerate(collectors):
            # Check for shutdown request
            if (
                hasattr(self.orchestrator, "is_shutdown_requested")
                and self.orchestrator.is_shutdown_requested()
            ):
                await self._log_runtime(
                    "WARN", "Shutdown requested, stopping collector execution"
                )
                break

            # Get collector name from definitions
            collector_name = self._get_collector_name(collector_id)

            # Update main progress description with overall status
            progress.update(
                main_task,
                description=f"Overall Progress -- Sequential collectors (0/{len(collectors)} completed)",
            )

            # Execute collector on all DUTs
            collector_results = {}
            for dut_id in dut_ids:
                # Check for shutdown request
                if (
                    hasattr(self.orchestrator, "is_shutdown_requested")
                    and self.orchestrator.is_shutdown_requested()
                ):
                    await self._log_runtime(
                        "WARN",
                        f"Shutdown requested, stopping execution for DUT {dut_id}",
                    )
                    break
                # Check if collector should be skipped based on configuration (tool-level and per-DUT)
                should_skip_config, skip_reason_config = (
                    await self._should_skip_collector_by_config(collector_id, dut_id)
                )

                if should_skip_config:
                    # Skip collector execution for this DUT due to configuration
                    collector_results[dut_id] = {
                        "status": "skipped",
                        "reason": skip_reason_config,
                        "execution_time": 0.0,
                    }

                    # Update status tracking for skipped collector
                    if self.status_tracker:
                        await self.status_tracker.complete_collector(
                            dut_id,
                            collector_id,
                            "skipped",
                            skip_reason_config,
                            0.0,
                            [],
                        )

                    # Update per-DUT progress for skipped collector (only if progress is available)
                    if progress and dut_id in dut_tasks:
                        try:
                            progress.advance(dut_tasks[dut_id], advance=1)
                        except Exception:
                            pass

                    continue  # Skip to next DUT

                # Check if collector should be skipped for this specific DUT due to preflight failure
                should_skip, skip_reason = await self._should_skip_collector(
                    collector_id, dut_id
                )

                if should_skip:
                    # Skip collector execution for this DUT
                    collector_results[dut_id] = {
                        "status": "skipped",
                        "reason": skip_reason,
                        "execution_time": 0.0,
                    }

                    # Update status tracking for skipped collector
                    if self.status_tracker:
                        await self.status_tracker.complete_collector(
                            dut_id,
                            collector_id,
                            "skipped",
                            skip_reason,
                            0.0,
                            [],
                        )

                    # Update per-DUT progress for skipped collector (only if progress is available)
                    if progress and dut_id in dut_tasks:
                        try:
                            progress.advance(dut_tasks[dut_id], advance=1)
                        except Exception:
                            pass

                    continue  # Skip to next DUT

                # Update per-DUT progress description (only if progress is available)
                if progress and dut_id in dut_tasks:
                    try:
                        progress.update(
                            dut_tasks[dut_id],
                            description=f"  - {dut_id}: Collector {i+1} out of {len(collectors)} in progress",
                        )
                    except Exception:
                        pass

                try:
                    # Update progress state (passive tracking - doesn't interfere with execution)
                    await self._log_runtime(
                        "DEBUG",
                        f"About to call progress_state.start_collector for {collector_id} on {dut_id}",
                        dut_id=dut_id,
                    )
                    if hasattr(self, "progress_state") and self.progress_state:
                        await self._log_runtime(
                            "DEBUG",
                            f"progress_state is available, calling start_collector",
                            dut_id=dut_id,
                        )
                        try:
                            service = await self._get_service_for_collector(
                                collector_id
                            )
                            service_name = (
                                service.service_name if service else "unknown"
                            )
                            await self._log_runtime(
                                "DEBUG",
                                f"Calling progress_state.start_collector({dut_id}, {collector_id}, {service_name}, 'sequential')",
                                dut_id=dut_id,
                            )
                            self.progress_state.start_collector(
                                dut_id,
                                collector_id,
                                service_name,
                                "sequential",
                            )
                        except Exception as e:
                            # Don't let progress tracking break execution
                            await self._log_runtime(
                                "DEBUG",
                                f"Error calling progress_state.start_collector: {e}",
                                dut_id=dut_id,
                            )
                            pass
                    else:
                        await self._log_runtime(
                            "DEBUG",
                            f"progress_state not available or None",
                            dut_id=dut_id,
                        )

                    # Check for shutdown before executing collector
                    if (
                        hasattr(self.orchestrator, "is_shutdown_requested")
                        and self.orchestrator.is_shutdown_requested()
                    ):
                        await self._log_runtime(
                            "WARN",
                            f"Shutdown requested, skipping collector {collector_id} on DUT {dut_id}",
                        )
                        collector_results[dut_id] = {
                            "status": "interrupted",
                            "reason": "Shutdown requested",
                            "execution_time": 0.0,
                        }
                        continue

                    await self._log_runtime(
                        "INFO",
                        f"Executing collector {collector_id} on DUT {dut_id} (sequential)",
                        dut_id=dut_id,
                    )

                    # Set async-safe context for this collector execution
                    _collector_context.set(collector_id)

                    # Start status tracking RIGHT BEFORE execution to capture actual start time
                    if self.status_tracker:
                        await self._log_runtime(
                            "DEBUG",
                            f"Starting collector {dut_id}:{collector_id}",
                            dut_id=dut_id,
                        )
                        await self.status_tracker.start_collector(dut_id, collector_id)

                    service = await self._get_service_for_collector(collector_id)
                    if service:
                        result = await service.execute_collector(
                            dut_id, collector_id, collection_level
                        )
                        collector_results[dut_id] = self._normalize_result(result)

                        # Update status tracking
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                collector_results[dut_id].get("status", "unknown"),
                                collector_results[dut_id].get("reason", ""),
                                collector_results[dut_id].get("execution_time", 0.0),
                                collector_results[dut_id].get("output_files", []),
                            )

                        # Update progress state (passive tracking - doesn't interfere with execution)
                        if hasattr(self, "progress_state") and self.progress_state:
                            try:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Calling progress_state.complete_collector for {collector_id} on {dut_id} with collector_results: {collector_results[dut_id]}",
                                    dut_id=dut_id,
                                )
                                await self.progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    collector_results[dut_id].get("status", "unknown"),
                                    collector_results[dut_id].get("reason", ""),
                                    collector_results[dut_id].get(
                                        "execution_time", 0.0
                                    ),
                                )
                            except Exception:
                                # Don't let progress tracking break execution
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Error calling progress_state.complete_collector: {e}",
                                    dut_id=dut_id,
                                )
                                pass

                        await self._log_runtime(
                            "INFO",
                            f"Completed collector {collector_id} on DUT {dut_id} with status: {collector_results[dut_id].get('status', 'unknown')} (sequential)",
                            dut_id=dut_id,
                        )
                    else:
                        collector_results[dut_id] = {
                            "status": "error",
                            "reason": f"No service found for collector {collector_id}",
                        }

                        # Update status tracking for error
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                "error",
                                collector_results[dut_id].get("reason", ""),
                                0.0,
                                [],
                            )

                        # Update progress state for error (passive tracking - doesn't interfere with execution)
                        if hasattr(self, "progress_state") and self.progress_state:
                            try:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Calling progress_state.complete_collector for {collector_id} on {dut_id} with collector_results: {collector_results[dut_id]}",
                                    dut_id=dut_id,
                                )
                                await self.progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "error",
                                    collector_results[dut_id].get("reason", ""),
                                    0.0,
                                )
                            except Exception:
                                # Don't let progress tracking break execution
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Error calling progress_state.complete_collector: {e}",
                                    dut_id=dut_id,
                                )
                                pass

                        await self._log_runtime(
                            "ERROR",
                            f"No service found for collector {collector_id} (sequential)",
                            dut_id=dut_id,
                        )
                except Exception as e:
                    collector_results[dut_id] = {
                        "status": "error",
                        "reason": f"Execution failed: {str(e)}",
                    }

                    # Update status tracking for exception
                    if self.status_tracker:
                        await self.status_tracker.complete_collector(
                            dut_id,
                            collector_id,
                            "error",
                            collector_results[dut_id].get("reason", ""),
                            0.0,
                            [],
                        )

                    # Update progress state for exception (passive tracking - doesn't interfere with execution)
                    if hasattr(self, "progress_state") and self.progress_state:
                        try:
                            await self.progress_state.complete_collector(
                                dut_id,
                                collector_id,
                                "error",
                                collector_results[dut_id].get("reason", ""),
                                0.0,
                            )
                        except Exception:
                            # Don't let progress tracking break execution
                            pass

                    await self._log_runtime(
                        "ERROR",
                        f"Exception executing collector {collector_id} on DUT {dut_id}: {str(e)} (sequential)",
                        dut_id=dut_id,
                    )

                # Update per-DUT progress (only if progress is available)
                if progress and dut_id in dut_tasks:
                    try:
                        progress.advance(dut_tasks[dut_id], advance=1)
                        # Update status to completed after advancing
                        progress.update(
                            dut_tasks[dut_id],
                            description=f"  - {dut_id}: Collector {i+1} out of {len(collectors)} completed",
                        )
                    except Exception:
                        pass

            results[collector_id] = collector_results

            # Update main progress (only if progress is available)
            if progress and main_task:
                progress.advance(main_task, advance=len(dut_ids))
                # Update progress description with completion count
                progress.update(
                    main_task,
                    description=f"Overall Progress -- Sequential collectors ({i+1}/{len(collectors)} completed)",
                )

        return results

    async def execute_sequential_collectors_parallel_duts(
        self,
        collectors: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task,
    ) -> Dict[str, Any]:
        """
        Execute sequential collectors in parallel across DUTs - each DUT runs its sequential collectors independently.

        Args:
            collectors: List of collector IDs.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            progress: Progress bar instance.
            main_task: Main task ID for progress tracking.

        Returns:
            Dictionary of execution results per DUT and collector.
        """
        await self._log_runtime(
            "INFO",
            f"Starting parallel DUT execution of {len(collectors)} sequential collectors on {len(dut_ids)} DUTs",
        )
        await self._log_runtime("INFO", f"Collector IDs: {collectors}")
        await self._log_runtime("INFO", f"DUT IDs: {dut_ids}")
        results = {}

        # Create progress tasks for each DUT (only if progress is available)
        dut_tasks = {}
        if progress:
            for dut_id in dut_ids:
                task = progress.add_task(
                    f"[green]{dut_id}[/green]",
                    total=len(collectors),
                    start=False,
                )
                dut_tasks[dut_id] = task

            # Start all DUT tasks
            for task in dut_tasks.values():
                progress.start_task(task)

        async def execute_sequential_collectors_for_dut(
            dut_id: str,
        ) -> Dict[str, Dict[str, Any]]:
            """
            Execute all sequential collectors for a single DUT.

            Args:
                dut_id: DUT ID.

            Returns:
                Dictionary of collector results.
            """
            # Set the DUT start time when collection actually begins
            if self.orchestrator and hasattr(
                self.orchestrator, "execution_summary_manager"
            ):
                self.orchestrator.execution_summary_manager.set_dut_start_time(
                    dut_id, datetime.now()
                )

            dut_results = {}

            for i, collector_id in enumerate(collectors):
                # Get collector name from definitions
                collector_name = self._get_collector_name(collector_id)

                # Check if collector should be skipped based on configuration (tool-level and per-DUT)
                should_skip_config, skip_reason_config = (
                    await self._should_skip_collector_by_config(collector_id, dut_id)
                )

                if should_skip_config:
                    # Skip collector execution for this DUT due to configuration
                    dut_results[collector_id] = {
                        "status": "skipped",
                        "reason": skip_reason_config,
                        "execution_time": 0.0,
                    }

                    # Update per-DUT progress for skipped collector (only if progress is available)
                    if progress and dut_id in dut_tasks:
                        try:
                            progress.advance(dut_tasks[dut_id], advance=1)
                        except Exception:
                            pass

                    continue  # Skip to next collector

                # Check if collector should be skipped for this specific DUT due to preflight failure
                should_skip, skip_reason = await self._should_skip_collector(
                    collector_id, dut_id
                )

                if should_skip:
                    # Skip collector execution for this DUT
                    dut_results[collector_id] = {
                        "status": "skipped",
                        "reason": skip_reason,
                        "execution_time": 0.0,
                    }

                    # Update per-DUT progress for skipped collector (only if progress is available)
                    if progress and dut_id in dut_tasks:
                        try:
                            progress.advance(dut_tasks[dut_id], advance=1)
                        except Exception:
                            pass

                    continue  # Skip to next collector

                # Update per-DUT progress description (only if progress is available)
                if progress and dut_id in dut_tasks:
                    try:
                        progress.update(
                            dut_tasks[dut_id],
                            description=f"  - {dut_id}: Collector {i+1} out of {len(collectors)} in progress",
                        )
                    except Exception:
                        pass

                    # Update progress state (passive tracking - doesn't interfere with execution)
                    if hasattr(self, "progress_state") and self.progress_state:
                        try:
                            service = await self._get_service_for_collector(
                                collector_id
                            )
                            service_name = (
                                service.service_name if service else "unknown"
                            )
                            self.progress_state.start_collector(
                                dut_id,
                                collector_id,
                                service_name,
                                "sequential_parallel_duts",
                            )
                        except Exception:
                            # Don't let progress tracking break execution
                            pass

                try:
                    await self._log_runtime(
                        "INFO",
                        f"Executing collector {collector_id} on DUT {dut_id} (sequential per DUT)",
                        dut_id=dut_id,
                    )

                    # Set async-safe context for this collector execution
                    _collector_context.set(collector_id)

                    service = await self._get_service_for_collector(collector_id)

                    if service:
                        result = await service.execute_collector(
                            dut_id, collector_id, collection_level
                        )
                        dut_results[collector_id] = self._normalize_result(result)
                        await self._log_runtime(
                            "INFO",
                            f"Completed collector {collector_id} on DUT {dut_id} with status: {dut_results[collector_id].get('status', 'unknown')} (sequential per DUT)",
                            dut_id=dut_id,
                        )
                    else:
                        dut_results[collector_id] = {
                            "status": "error",
                            "reason": f"No service found for collector {collector_id}",
                        }
                        await self._log_runtime(
                            "ERROR",
                            f"No service found for collector {collector_id} (sequential per DUT)",
                            dut_id=dut_id,
                        )
                except Exception as e:
                    dut_results[collector_id] = {
                        "status": "error",
                        "reason": f"Execution failed: {str(e)}",
                    }
                    await self._log_runtime(
                        "ERROR",
                        f"Exception executing collector {collector_id} on DUT {dut_id}: {str(e)} (sequential per DUT)",
                        dut_id=dut_id,
                    )

                # Update per-DUT progress (only if progress is available)
                if progress and dut_id in dut_tasks:
                    try:
                        progress.advance(dut_tasks[dut_id], advance=1)
                        # Update status to completed after advancing
                        progress.update(
                            dut_tasks[dut_id],
                            description=f"  - {dut_id}: Collector {i+1} out of {len(collectors)} completed",
                        )
                    except Exception:
                        pass

            return dut_results

        # Execute sequential collectors for all DUTs in parallel
        dut_tasks_list = [
            execute_sequential_collectors_for_dut(dut_id) for dut_id in dut_ids
        ]
        dut_results_list = await asyncio.gather(*dut_tasks_list)

        # Reorganize results from per-DUT structure to per-collector structure
        for i, dut_id in enumerate(dut_ids):
            dut_results = dut_results_list[i]
            for collector_id, result in dut_results.items():
                if collector_id not in results:
                    results[collector_id] = {}
                results[collector_id][dut_id] = result

        # Update main progress to completion
        progress.advance(main_task, advance=len(collectors) * len(dut_ids))
        progress.update(
            main_task,
            description=f"Overall Progress -- Sequential collectors ({len(collectors)}/{len(collectors)} completed)",
        )

        return results

    async def execute_parallel_collectors_with_progress(
        self,
        collectors: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task,
        concurrency_limit: int = 10,
        progress_state=None,
    ) -> Dict[str, Any]:
        """
        Execute collectors in parallel with progress tracking.

        Args:
            collectors: List of collector IDs.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            progress: Progress bar instance.
            main_task: Main task ID for progress tracking.
            concurrency_limit: Maximum concurrent tasks.
            progress_state: Progress state manager.

        Returns:
            Dictionary of execution results per DUT and collector.
        """
        await self._log_runtime(
            "INFO",
            f"Starting parallel execution of {len(collectors)} collectors on {len(dut_ids)} DUTs with concurrency limit {concurrency_limit}",
        )
        await self._log_runtime("INFO", f"Collector IDs: {collectors}")
        await self._log_runtime("INFO", f"DUT IDs: {dut_ids}")
        results = {}

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(concurrency_limit)

        # Create progress tasks for each DUT (similar to sequential execution)
        dut_tasks = {}
        for dut_id in dut_ids:
            task = progress.add_task(
                f"[yellow]{dut_id}[/yellow]",
                total=len(collectors),
                start=False,
            )
            dut_tasks[dut_id] = task

        # Start all DUT tasks
        for task in dut_tasks.values():
            progress.start_task(task)

        # Track completed collectors for progress display
        completed_collectors = 0
        total_collectors = len(collectors)

        # Track DUT start times for parallel execution
        dut_start_times_set = set()

        # Set initial progress description
        progress.update(
            main_task,
            description=f"Overall Progress -- Parallel collectors (0/{len(collectors)} completed)",
        )

        async def execute_single_collector(collector_id: str) -> tuple:
            """
            Execute a single collector on all DUTs.

            Args:
                collector_id: Collector ID.

            Returns:
                Tuple of (collector_id, results_dict).
            """
            nonlocal completed_collectors

            # Check for shutdown request before acquiring semaphore
            if (
                hasattr(self.orchestrator, "is_shutdown_requested")
                and self.orchestrator.is_shutdown_requested()
            ):
                await self._log_runtime(
                    "WARN", f"Shutdown requested, skipping collector {collector_id}"
                )
                return collector_id, {}

            await self._log_runtime(
                "DEBUG",
                f"Acquiring semaphore for collector {collector_id} (concurrency limit: {concurrency_limit})",
            )
            async with semaphore:
                await self._log_runtime(
                    "DEBUG",
                    f"Semaphore acquired for collector {collector_id} - starting execution",
                )
                # Get collector name from definitions
                collector_name = self._get_collector_name(collector_id)

                # Update main progress description with overall status
                # The main task total is len(collectors) * len(dut_ids), so we need to track progress accordingly
                progress.update(
                    main_task,
                    description=f"Overall Progress -- Parallel collectors ({completed_collectors}/{len(collectors)} completed)",
                )

                collector_results = {}
                for dut_id in dut_ids:
                    # Check for shutdown request
                    if (
                        hasattr(self.orchestrator, "is_shutdown_requested")
                        and self.orchestrator.is_shutdown_requested()
                    ):
                        await self._log_runtime(
                            "WARN",
                            f"Shutdown requested, stopping execution for DUT {dut_id}",
                        )
                        break

                    # Set DUT start time when first collector starts for this DUT
                    if dut_id not in dut_start_times_set:
                        if self.orchestrator and hasattr(
                            self.orchestrator, "execution_summary_manager"
                        ):
                            self.orchestrator.execution_summary_manager.set_dut_start_time(
                                dut_id, datetime.now()
                            )
                        dut_start_times_set.add(dut_id)

                    # Check if collector should be skipped based on configuration (tool-level and per-DUT)
                    should_skip_config, skip_reason_config = (
                        await self._should_skip_collector_by_config(
                            collector_id, dut_id
                        )
                    )

                    if should_skip_config:
                        # Skip collector execution for this DUT due to configuration
                        collector_results[dut_id] = {
                            "status": "skipped",
                            "reason": skip_reason_config,
                            "execution_time": 0.0,
                        }

                        # Update status tracking for skipped collector
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                "skipped",
                                skip_reason_config,
                                0.0,
                                [],
                            )

                        # Update progress state for skipped collector
                        if progress_state:
                            try:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Calling progress_state.complete_collector for {collector_id} on {dut_id} with skip_reason_config: {skip_reason_config}",
                                    dut_id=dut_id,
                                )
                                await progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "skipped",
                                    skip_reason_config,
                                    0.0,
                                )
                            except Exception:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Error calling progress_state.complete_collector: {e}",
                                    dut_id=dut_id,
                                )
                                # Don't let progress tracking break execution
                                pass

                        # Update per-DUT progress for skipped collector
                        try:
                            progress.advance(dut_tasks[dut_id], advance=1)
                        except Exception:
                            pass

                        continue  # Skip to next DUT

                    # Check if collector should be skipped for this specific DUT due to preflight failure
                    should_skip, skip_reason = await self._should_skip_collector(
                        collector_id, dut_id
                    )

                    if should_skip:
                        # Skip collector execution for this DUT
                        collector_results[dut_id] = {
                            "status": "skipped",
                            "reason": skip_reason,
                            "execution_time": 0.0,
                        }

                        # Update status tracking for skipped collector
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                "skipped",
                                skip_reason,
                                0.0,
                                [],
                            )

                        # Update progress state for skipped collector
                        if progress_state:
                            try:
                                await progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "skipped",
                                    skip_reason,
                                    0.0,
                                )
                            except Exception:
                                # Don't let progress tracking break execution
                                pass

                        # Update per-DUT progress for skipped collector
                        try:
                            progress.advance(dut_tasks[dut_id], advance=1)
                        except Exception:
                            pass

                        continue  # Skip to next DUT

                    # Update per-DUT progress description
                    try:
                        # Find the index of this collector in the list
                        collector_index = collectors.index(collector_id) + 1
                        progress.update(
                            dut_tasks[dut_id],
                            description=f"  - {dut_id}: Collector {collector_index} out of {len(collectors)} in progress",
                        )
                    except Exception:
                        pass

                    try:
                        # Update progress state (passive tracking - doesn't interfere with execution)
                        if progress_state:
                            try:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Calling progress_state.start_collector for {collector_id} on {dut_id}",
                                    dut_id=dut_id,
                                )
                                await progress_state.start_collector(
                                    dut_id,
                                    collector_id,
                                    "parallel",
                                    "parallel_execution",
                                )
                            except Exception:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Error calling progress_state.start_collector: {e}",
                                    dut_id=dut_id,
                                )
                                # Don't let progress tracking break execution
                                pass

                        # Set current collector context for logging
                        if self.orchestrator and hasattr(
                            self.orchestrator, "current_collector_id"
                        ):
                            self.orchestrator.current_collector_id = collector_id
                        if self.orchestrator and hasattr(
                            self.orchestrator, "current_execution_context"
                        ):
                            self.orchestrator.current_execution_context = {
                                "collector_id": collector_id,
                                "dut_id": dut_id,
                                "collection_level": collection_level,
                            }

                        # Set per-collector context with original collector ID for cross-contamination prevention
                        if self.orchestrator and hasattr(
                            self.orchestrator, "set_collector_execution_context"
                        ):
                            context = {
                                "collector_id": collector_id,
                                "dut_id": dut_id,
                                "collection_level": collection_level,
                                "original_collector_id": collector_id,  # Store the original collector ID
                            }
                            await self.orchestrator.set_collector_execution_context(
                                dut_id, collector_id, context
                            )

                        await self._log_runtime(
                            "INFO",
                            f"Executing collector {collector_id} on DUT {dut_id} (parallel) - START",
                            dut_id=dut_id,
                        )

                        # Set async-safe context for this collector execution
                        # This ensures all logging within this collector's execution uses the correct ID
                        _collector_context.set(collector_id)

                        # Start status tracking RIGHT BEFORE execution to capture actual start time
                        if self.status_tracker:
                            await self.status_tracker.start_collector(
                                dut_id, collector_id
                            )

                        service = await self._get_service_for_collector(collector_id)
                        if service:
                            result = await service.execute_collector(
                                dut_id, collector_id, collection_level
                            )
                            collector_results[dut_id] = self._normalize_result(result)

                            # Update status tracking
                            if self.status_tracker:
                                await self.status_tracker.complete_collector(
                                    dut_id,
                                    collector_id,
                                    collector_results[dut_id].get("status", "unknown"),
                                    collector_results[dut_id].get("reason", ""),
                                    collector_results[dut_id].get(
                                        "execution_time", 0.0
                                    ),
                                    collector_results[dut_id].get("output_files", []),
                                    collector_results[dut_id].get("context", {}),
                                )

                            # Update progress state (passive tracking - doesn't interfere with execution)
                            if progress_state:
                                try:
                                    await progress_state.complete_collector(
                                        dut_id,
                                        collector_id,
                                        collector_results[dut_id].get(
                                            "status", "unknown"
                                        ),
                                        collector_results[dut_id].get("reason", ""),
                                        collector_results[dut_id].get(
                                            "execution_time", 0.0
                                        ),
                                    )
                                except Exception:
                                    # Don't let progress tracking break execution
                                    pass

                            await self._log_runtime(
                                "INFO",
                                f"[{collector_id}] Completed collector {collector_id} on DUT {dut_id} with status: {collector_results[dut_id].get('status', 'unknown')} (parallel) - END",
                                dut_id=dut_id,
                            )
                        else:
                            collector_results[dut_id] = {
                                "status": "error",
                                "reason": f"No service found for collector {collector_id}",
                            }

                            # Update status tracking for error
                            if self.status_tracker:
                                await self.status_tracker.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "error",
                                    collector_results[dut_id].get("reason", ""),
                                    0.0,
                                    [],
                                )

                            # Update progress state for error
                            if progress_state:
                                try:
                                    await self._log_runtime(
                                        "DEBUG",
                                        f"Calling progress_state.complete_collector for {collector_id} on {dut_id} with collector_results: {collector_results[dut_id]}",
                                        dut_id=dut_id,
                                    )
                                    await progress_state.complete_collector(
                                        dut_id,
                                        collector_id,
                                        "error",
                                        collector_results[dut_id].get("reason", ""),
                                        0.0,
                                    )
                                except Exception:
                                    await self._log_runtime(
                                        "DEBUG",
                                        f"Error calling progress_state.complete_collector: {e}",
                                        dut_id=dut_id,
                                    )
                                    # Don't let progress tracking break execution
                                    pass

                            await self._log_runtime(
                                "ERROR",
                                f"[{collector_id}] No service found for collector {collector_id} (parallel)",
                                dut_id=dut_id,
                            )
                    except Exception as e:
                        collector_results[dut_id] = {
                            "status": "error",
                            "reason": f"Execution failed: {str(e)}",
                        }

                        # Update status tracking for exception
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                "error",
                                collector_results[dut_id].get("reason", ""),
                                0.0,
                                [],
                            )

                        # Update progress state for exception
                        if progress_state:
                            try:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Calling progress_state.complete_collector for {collector_id} on {dut_id} with collector_results: {collector_results[dut_id]}",
                                    dut_id=dut_id,
                                )
                                await progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "error",
                                    collector_results[dut_id].get("reason", ""),
                                    0.0,
                                )
                            except Exception:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Error calling progress_state.complete_collector: {e}",
                                    dut_id=dut_id,
                                )
                                # Don't let progress tracking break execution
                                pass

                        await self._log_runtime(
                            "ERROR",
                            f"[{collector_id}] Exception executing collector {collector_id} on DUT {dut_id}: {str(e)} (parallel)",
                            dut_id=dut_id,
                        )

                    # Update per-DUT progress
                    try:
                        progress.advance(dut_tasks[dut_id], advance=1)
                        # Update status to completed after advancing
                        collector_index = collectors.index(collector_id) + 1
                        progress.update(
                            dut_tasks[dut_id],
                            description=f"  - {dut_id}: Collector {collector_index} out of {len(collectors)} completed",
                        )
                    except Exception:
                        pass

                # Update main progress - advance by number of DUTs for each collector (like sequential)
                progress.advance(main_task, advance=len(dut_ids))
                # Update completion counter
                completed_collectors += 1
                return collector_id, collector_results

        # Execute all collectors in parallel
        tasks = [execute_single_collector(collector_id) for collector_id in collectors]
        collector_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in collector_results:
            if isinstance(result, Exception):
                await self._log_runtime(
                    "ERROR", f"Collector execution failed: {result}"
                )
                continue

            collector_id, results_dict = result
            results[collector_id] = results_dict

        return results

    async def execute_service_based_parallel_collectors(
        self,
        collectors: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task,
        progress_state=None,
    ) -> Dict[str, Any]:
        """
        Execute parallel collectors grouped by service with progress tracking.

        Args:
            collectors: List of collector IDs.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            progress: Progress bar instance.
            main_task: Main task ID for progress tracking.
            progress_state: Progress state manager.

        Returns:
            Dictionary of execution results per DUT and collector.
        """
        await self._log_runtime(
            "INFO",
            f"Starting service-based parallel execution of {len(collectors)} collectors on {len(dut_ids)} DUTs",
        )
        await self._log_runtime("INFO", f"Collector IDs: {collectors}")
        await self._log_runtime("INFO", f"DUT IDs: {dut_ids}")

        # Pre-filter collectors for all DUTs with progress bar
        await self._log_runtime(
            "DEBUG",
            f"Starting pre-filtering for {len(collectors)} collectors on {len(dut_ids)} DUTs",
        )
        filtered_collectors = await self._pre_filter_collectors_for_duts(
            collectors, dut_ids, progress, main_task
        )
        await self._log_runtime(
            "DEBUG",
            f"Pre-filtering completed, filtered_collectors keys: {list(filtered_collectors.keys())}",
        )

        results = {}

        # Create progress tasks for each DUT (only if progress is available)
        dut_tasks = {}
        if progress:
            for dut_id in dut_ids:
                task = progress.add_task(
                    f"[yellow]{dut_id}[/yellow]",
                    total=len(collectors),
                    start=False,
                )
                dut_tasks[dut_id] = task

            # Start all DUT tasks
            for task in dut_tasks.values():
                progress.start_task(task)

        # Group collectors by service
        service_groups = {}
        for collector_id in collectors:
            service = await self._get_service_for_collector(collector_id)
            if service:
                service_name = service.service_name
                if service_name not in service_groups:
                    service_groups[service_name] = []
                service_groups[service_name].append(collector_id)

        await self._log_runtime(
            "INFO",
            f"Grouped parallel collectors by service: {service_groups}",
        )

        async def execute_collectors_for_dut(
            dut_id: str,
        ) -> Dict[str, Dict[str, Any]]:
            """
            Execute all collectors for a single DUT in parallel.

            Args:
                dut_id: DUT ID.

            Returns:
                Dictionary of collector results.
            """
            dut_results = {}

            async def execute_single_collector_for_dut(
                collector_id: str,
            ) -> tuple:
                """
                Execute a single collector on a single DUT.

                Args:
                    collector_id: Collector ID.

                Returns:
                    Tuple of (collector_id, result).
                """
                # Check pre-filtering results
                should_skip, skip_reason = filtered_collectors[collector_id][dut_id]

                if should_skip:
                    # Update status tracking for skipped collector
                    if self.status_tracker:
                        await self._log_runtime(
                            "DEBUG",
                            f"Calling status_tracker.complete_collector for {collector_id} on {dut_id} with skip_reason: {skip_reason}",
                            dut_id=dut_id,
                        )
                        await self.status_tracker.complete_collector(
                            dut_id,
                            collector_id,
                            "skipped",
                            skip_reason,
                            0.0,
                        )
                        await self._log_runtime(
                            "DEBUG",
                            f"status_tracker.complete_collector completed for {collector_id} on {dut_id}",
                            dut_id=dut_id,
                        )
                    else:
                        await self._log_runtime(
                            "DEBUG",
                            f"status_tracker is None, skipping status_tracker update for {collector_id} on {dut_id}",
                            dut_id=dut_id,
                        )

                    # Update progress state for skipped collector
                    if progress_state:
                        try:
                            await self._log_runtime(
                                "DEBUG",
                                f"Calling progress_state.complete_collector for {collector_id} on {dut_id} with skip_reason: {skip_reason}",
                                dut_id=dut_id,
                            )
                            await progress_state.complete_collector(
                                dut_id,
                                collector_id,
                                "skipped",
                                skip_reason,
                                0.0,
                            )
                        except Exception:
                            await self._log_runtime(
                                "DEBUG",
                                f"Error calling progress_state.complete_collector: {e}",
                                dut_id=dut_id,
                            )
                            # Don't let progress tracking break execution
                            pass
                    # Skip collector execution for this DUT
                    return collector_id, {
                        "status": "skipped",
                        "reason": skip_reason,
                        "execution_time": 0.0,
                    }

                # Update per-DUT progress description (only if progress is available)
                if progress and dut_id in dut_tasks:
                    try:
                        # Find the index of this collector in the list
                        collector_index = collectors.index(collector_id) + 1
                        progress.update(
                            dut_tasks[dut_id],
                            description=f"  - {dut_id}: Collector {collector_id} ({collector_index}/{len(collectors)}) in progress",
                        )
                    except Exception:
                        pass

                try:
                    # Update progress state (passive tracking - doesn't interfere with execution)
                    if progress_state:
                        try:
                            await self._log_runtime(
                                "DEBUG",
                                f"Calling progress_state.start_collector for {collector_id} on {dut_id}",
                                dut_id=dut_id,
                            )
                            service = await self._get_service_for_collector(
                                collector_id
                            )
                            service_name = (
                                service.service_name if service else "unknown"
                            )
                            await progress_state.start_collector(
                                dut_id, collector_id, service_name, "parallel"
                            )
                        except Exception:
                            # Don't let progress tracking break execution
                            await self._log_runtime(
                                "DEBUG",
                                f"Error calling progress_state.start_collector: {e}",
                                dut_id=dut_id,
                            )
                            pass

                    # Set current collector context for logging
                    if self.orchestrator and hasattr(
                        self.orchestrator, "current_collector_id"
                    ):
                        self.orchestrator.current_collector_id = collector_id
                    if self.orchestrator and hasattr(
                        self.orchestrator, "current_execution_context"
                    ):
                        self.orchestrator.current_execution_context = {
                            "collector_id": collector_id,
                            "dut_id": dut_id,
                            "collection_level": collection_level,
                        }

                    # Set per-collector context with original collector ID for cross-contamination prevention
                    if self.orchestrator and hasattr(
                        self.orchestrator, "set_collector_execution_context"
                    ):
                        context = {
                            "collector_id": collector_id,
                            "dut_id": dut_id,
                            "collection_level": collection_level,
                            "original_collector_id": collector_id,  # Store the original collector ID
                        }
                        await self.orchestrator.set_collector_execution_context(
                            dut_id, collector_id, context
                        )

                    # Check for shutdown before executing collector
                    if (
                        hasattr(self.orchestrator, "is_shutdown_requested")
                        and self.orchestrator.is_shutdown_requested()
                    ):
                        await self._log_runtime(
                            "WARN",
                            f"Shutdown requested, skipping collector {collector_id} on DUT {dut_id}",
                        )
                        return collector_id, {
                            "status": "interrupted",
                            "reason": "Shutdown requested",
                            "execution_time": 0.0,
                        }

                    await self._log_runtime(
                        "INFO",
                        f"Executing collector {collector_id} on DUT {dut_id} (parallel)",
                        dut_id=dut_id,
                    )

                    # Start status tracking RIGHT BEFORE execution to capture actual start time
                    if self.status_tracker:
                        await self._log_runtime(
                            "DEBUG",
                            f"Starting collector {dut_id}:{collector_id} (service-based parallel)",
                            dut_id=dut_id,
                        )
                        await self.status_tracker.start_collector(dut_id, collector_id)

                    service = await self._get_service_for_collector(collector_id)
                    if service:
                        result = await service.execute_collector(
                            dut_id, collector_id, collection_level
                        )
                        collector_result = self._normalize_result(result)

                        # Update status tracking
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                collector_result.get("status", "unknown"),
                                collector_result.get("reason", ""),
                                collector_result.get("execution_time", 0.0),
                                collector_result.get("output_files", []),
                            )

                        # Update progress state (passive tracking - doesn't interfere with execution)
                        if progress_state:
                            try:
                                await progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    collector_result.get("status", "unknown"),
                                    collector_result.get("reason", ""),
                                    collector_result.get("execution_time", 0.0),
                                )
                            except Exception:
                                # Don't let progress tracking break execution
                                pass

                        await self._log_runtime(
                            "INFO",
                            f"Completed collector {collector_id} on DUT {dut_id} with status: {collector_result.get('status', 'unknown')} (parallel)",
                            dut_id=dut_id,
                        )
                        return collector_id, collector_result
                    else:
                        collector_result = {
                            "status": "error",
                            "reason": f"No service found for collector {collector_id}",
                        }

                        # Update status tracking for error
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                "error",
                                collector_result.get("reason", ""),
                                0.0,
                                [],
                            )

                        # Update progress state for error (passive tracking - doesn't interfere with execution)
                        if progress_state:
                            try:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Calling progress_state.complete_collector for {collector_id} on {dut_id} with collector_result: {collector_result}",
                                    dut_id=dut_id,
                                )
                                await progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "error",
                                    collector_result.get("reason", ""),
                                    0.0,
                                )
                            except Exception:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"Error calling progress_state.complete_collector: {e}",
                                    dut_id=dut_id,
                                )
                                # Don't let progress tracking break execution
                                pass

                        await self._log_runtime(
                            "ERROR",
                            f"No service found for collector {collector_id} (parallel)",
                            dut_id=dut_id,
                        )
                        return collector_id, collector_result
                except Exception as e:
                    collector_result = {
                        "status": "error",
                        "reason": f"Execution failed: {str(e)}",
                    }

                    # Update status tracking for exception
                    if self.status_tracker:
                        await self.status_tracker.complete_collector(
                            dut_id,
                            collector_id,
                            "error",
                            collector_result.get("reason", ""),
                            0.0,
                            [],
                        )

                    # Update progress state for exception (passive tracking - doesn't interfere with execution)
                    if progress_state:
                        try:
                            await self._log_runtime(
                                "DEBUG",
                                f"Calling progress_state.complete_collector for {collector_id} on {dut_id} with collector_result: {collector_result}",
                                dut_id=dut_id,
                            )
                            await progress_state.complete_collector(
                                dut_id,
                                collector_id,
                                "error",
                                collector_result.get("reason", ""),
                                0.0,
                            )
                        except Exception:
                            await self._log_runtime(
                                "DEBUG",
                                f"Error calling progress_state.complete_collector: {e}",
                                dut_id=dut_id,
                            )
                            # Don't let progress tracking break execution
                            pass

                    await self._log_runtime(
                        "ERROR",
                        f"Exception executing collector {collector_id} on DUT {dut_id}: {str(e)} (parallel)",
                        dut_id=dut_id,
                    )
                    return collector_id, collector_result

            # Execute all collectors for this DUT in parallel
            collector_tasks = [
                execute_single_collector_for_dut(collector_id)
                for collector_id in collectors
            ]
            collector_results = await asyncio.gather(
                *collector_tasks, return_exceptions=True
            )

            # Process results for this DUT
            for result in collector_results:
                if isinstance(result, Exception):
                    await self._log_runtime(
                        "ERROR",
                        f"Collector execution failed for DUT {dut_id}: {result}",
                        dut_id=dut_id,
                    )
                    continue

                collector_id, collector_result = result
                dut_results[collector_id] = collector_result

                # Update per-DUT progress (only if progress is available)
                if progress and dut_id in dut_tasks:
                    try:
                        progress.advance(dut_tasks[dut_id], advance=1)
                        # Update status to completed after advancing
                        collector_index = collectors.index(collector_id) + 1
                        progress.update(
                            dut_tasks[dut_id],
                            description=f"  - {dut_id}: Collector {collector_id} ({collector_index}/{len(collectors)}) completed",
                        )
                    except Exception:
                        pass

            return dut_results

        # Execute all DUTs in parallel
        dut_tasks = [execute_collectors_for_dut(dut_id) for dut_id in dut_ids]
        dut_results = await asyncio.gather(*dut_tasks, return_exceptions=True)

        # Process results - reorganize by collector_id
        for i, dut_result in enumerate(dut_results):
            if isinstance(dut_result, Exception):
                dut_id = dut_ids[i]
                await self._log_runtime(
                    "ERROR", f"DUT execution failed for {dut_id}: {dut_result}"
                )
                continue

            dut_id = dut_ids[i]
            for collector_id, collector_result in dut_result.items():
                if collector_id not in results:
                    results[collector_id] = {}
                results[collector_id][dut_id] = collector_result

        # Update main progress - advance by number of DUTs for each collector
        if main_task:
            progress.advance(main_task, advance=len(dut_ids))

        return results

    async def execute_sequential_collectors_grouped_by_service(
        self,
        collectors: List[str],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task,
        progress_state=None,
    ) -> Dict[str, Any]:
        """
        Execute sequential collectors with services running in parallel within each DUT.

        Args:
            collectors: List of collector IDs.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            progress: Progress bar instance.
            main_task: Main task ID for progress tracking.
            progress_state: Progress state manager.

        Returns:
            Dictionary of execution results per DUT and collector.
        """
        await self._log_runtime(
            "INFO",
            f"Starting service-grouped execution of {len(collectors)} sequential collectors on {len(dut_ids)} DUTs",
        )
        await self._log_runtime("INFO", f"Collector IDs: {collectors}")
        await self._log_runtime("INFO", f"DUT IDs: {dut_ids}")
        results = {}

        # Create progress tasks for each DUT (only if progress is available)
        dut_tasks = {}
        if progress:
            for dut_id in dut_ids:
                task = progress.add_task(
                    f"[green]{dut_id}[/green]",
                    total=len(collectors),
                    start=False,
                )
                dut_tasks[dut_id] = task

            # Start all DUT tasks
            for task in dut_tasks.values():
                progress.start_task(task)

        # Group collectors by service
        service_groups = {}
        for collector_id in collectors:
            service = await self._get_service_for_collector(collector_id)
            if service:
                service_name = service.service_name
                if service_name not in service_groups:
                    service_groups[service_name] = []
                service_groups[service_name].append(collector_id)

        await self._log_runtime(
            "INFO",
            f"Grouped sequential collectors by service: {service_groups}",
        )

        async def execute_sequential_collectors_for_dut_grouped_by_service(
            dut_id: str,
        ) -> Dict[str, Dict[str, Any]]:
            """
            Execute sequential collectors for a single DUT, with all services running in parallel.

            Args:
                dut_id: DUT ID.

            Returns:
                Dictionary of collector results.
            """
            dut_results = {}

            async def execute_service_sequential_collectors(
                service_name: str, service_collectors: List[str]
            ) -> Dict[str, Dict[str, Any]]:
                """
                Execute sequential collectors for a single service sequentially.

                Args:
                    service_name: Service name.
                    service_collectors: List of collector IDs for this service.

                Returns:
                    Dictionary of collector results.
                """
                service_results = {}

                for i, collector_id in enumerate(service_collectors):
                    # Get collector name from definitions
                    collector_name = self._get_collector_name(collector_id)

                    # Check if collector should be skipped for this specific DUT due to preflight failure
                    should_skip, skip_reason = await self._should_skip_collector(
                        collector_id, dut_id
                    )

                    if should_skip:
                        # Skip collector execution for this DUT
                        service_results[collector_id] = {
                            "status": "skipped",
                            "reason": skip_reason,
                            "execution_time": 0.0,
                        }

                        # Update progress state for skipped collector
                        if progress_state:
                            try:
                                await progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "skipped",
                                    skip_reason,
                                    0.0,
                                )
                            except Exception:
                                # Don't let progress tracking break execution
                                pass

                        # Update per-DUT progress for skipped collector (only if progress is available)
                        if progress and dut_id in dut_tasks:
                            try:
                                progress.advance(dut_tasks[dut_id], advance=1)
                            except Exception:
                                pass

                        continue  # Skip to next collector

                    # Update per-DUT progress description (only if progress is available)
                    if progress and dut_id in dut_tasks:
                        try:
                            progress.update(
                                dut_tasks[dut_id],
                                description=f"  - {dut_id}: {service_name} collector {collector_id} ({i+1}/{len(service_collectors)}) in progress",
                            )
                        except Exception:
                            pass

                    # Update progress state (passive tracking - doesn't interfere with execution)
                    await self._log_runtime(
                        "DEBUG",
                        f"About to call progress_state.start_collector for {collector_id} on {dut_id}",
                        dut_id=dut_id,
                    )
                    if progress_state:
                        await self._log_runtime(
                            "DEBUG",
                            f"progress_state is available, calling start_collector",
                            dut_id=dut_id,
                        )
                        try:
                            await progress_state.start_collector(
                                dut_id,
                                collector_id,
                                service_name,
                                "sequential_grouped_by_service",
                            )
                            await self._log_runtime(
                                "DEBUG",
                                f"progress_state.start_collector called successfully",
                                dut_id=dut_id,
                            )
                        except Exception as e:
                            # Don't let progress tracking break execution
                            await self._log_runtime(
                                "DEBUG",
                                f"Error calling progress_state.start_collector: {e}",
                                dut_id=dut_id,
                            )
                            pass
                    else:
                        await self._log_runtime(
                            "DEBUG",
                            f"progress_state not available or None",
                            dut_id=dut_id,
                        )

                    try:
                        await self._log_runtime(
                            "INFO",
                            f"Executing {service_name} collector {collector_id} on DUT {dut_id} (sequential within service)",
                        )

                        # Start status tracking RIGHT BEFORE execution to capture actual start time
                        await self._log_runtime(
                            "DEBUG",
                            f"Starting collector {dut_id}:{collector_id} (service-grouped sequential)",
                        )
                        await self.status_tracker.start_collector(dut_id, collector_id)

                        service = await self._get_service_for_collector(collector_id)
                        if service:
                            result = await service.execute_collector(
                                dut_id, collector_id, collection_level
                            )
                            service_results[collector_id] = self._normalize_result(
                                result
                            )

                            # Update status tracking
                            if self.status_tracker:
                                await self.status_tracker.complete_collector(
                                    dut_id,
                                    collector_id,
                                    service_results[collector_id].get(
                                        "status", "unknown"
                                    ),
                                    service_results[collector_id].get("reason", ""),
                                    service_results[collector_id].get(
                                        "execution_time", 0.0
                                    ),
                                    service_results[collector_id].get(
                                        "output_files", []
                                    ),
                                )

                            # Update progress state for successful completion
                            await self._log_runtime(
                                "DEBUG",
                                f"About to call progress_state.complete_collector for {collector_id} on {dut_id}",
                                dut_id=dut_id,
                            )
                            if progress_state:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"progress_state is available, calling complete_collector",
                                    dut_id=dut_id,
                                )
                                try:
                                    await progress_state.complete_collector(
                                        dut_id,
                                        collector_id,
                                        service_results[collector_id].get(
                                            "status", "unknown"
                                        ),
                                        service_results[collector_id].get("reason", ""),
                                        service_results[collector_id].get(
                                            "execution_time", 0.0
                                        ),
                                    )
                                    await self._log_runtime(
                                        "DEBUG",
                                        f"progress_state.complete_collector called successfully",
                                        dut_id=dut_id,
                                    )
                                except Exception as e:
                                    # Don't let progress tracking break execution
                                    await self._log_runtime(
                                        "DEBUG",
                                        f"Error calling progress_state.complete_collector: {e}",
                                        dut_id=dut_id,
                                    )
                                    pass
                            else:
                                await self._log_runtime(
                                    "DEBUG",
                                    f"progress_state not available or None",
                                    dut_id=dut_id,
                                )

                            await self._log_runtime(
                                "INFO",
                                f"Completed {service_name} collector {collector_id} on DUT {dut_id} with status: {service_results[collector_id].get('status', 'unknown')}",
                                dut_id=dut_id,
                            )
                        else:
                            service_results[collector_id] = {
                                "status": "error",
                                "reason": f"No service found for collector {collector_id}",
                            }

                            # Update status tracking for error
                            if self.status_tracker:
                                await self.status_tracker.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "error",
                                    service_results[collector_id].get("reason", ""),
                                    0.0,
                                    [],
                                )

                            # Update progress state for service not found error
                            if progress_state:
                                try:
                                    await progress_state.complete_collector(
                                        dut_id,
                                        collector_id,
                                        "error",
                                        service_results[collector_id].get("reason", ""),
                                        0.0,
                                    )
                                except Exception:
                                    # Don't let progress tracking break execution
                                    pass

                            await self._log_runtime(
                                "ERROR",
                                f"No service found for collector {collector_id}",
                                dut_id=dut_id,
                            )
                    except Exception as e:
                        service_results[collector_id] = {
                            "status": "error",
                            "reason": f"Execution failed: {str(e)}",
                        }

                        # Update status tracking for exception
                        if self.status_tracker:
                            await self.status_tracker.complete_collector(
                                dut_id,
                                collector_id,
                                "error",
                                f"Execution failed: {str(e)}",
                                0.0,
                                [],
                            )

                        # Update progress state for execution exception
                        if progress_state:
                            try:
                                await progress_state.complete_collector(
                                    dut_id,
                                    collector_id,
                                    "error",
                                    f"Execution failed: {str(e)}",
                                    0.0,
                                )
                            except Exception:
                                # Don't let progress tracking break execution
                                pass

                        await self._log_runtime(
                            "ERROR",
                            f"Exception executing collector {collector_id} on DUT {dut_id}: {str(e)}",
                            dut_id=dut_id,
                        )

                    # Update per-DUT progress (only if progress is available)
                    if progress and dut_id in dut_tasks:
                        try:
                            progress.advance(dut_tasks[dut_id], advance=1)
                            # Update status to completed after advancing
                            progress.update(
                                dut_tasks[dut_id],
                                description=f"  - {dut_id}: {service_name} collector {collector_id} ({i+1}/{len(service_collectors)}) completed",
                            )
                        except Exception:
                            pass

                return service_results

            # Execute all services in parallel for this DUT
            service_tasks = [
                execute_service_sequential_collectors(service_name, service_collectors)
                for service_name, service_collectors in service_groups.items()
            ]
            service_results_list = await asyncio.gather(*service_tasks)

            # Combine results from all services
            for service_results in service_results_list:
                dut_results.update(service_results)

            return dut_results

        # Execute sequential collectors for all DUTs in parallel
        dut_tasks_list = [
            execute_sequential_collectors_for_dut_grouped_by_service(dut_id)
            for dut_id in dut_ids
        ]
        dut_results_list = await asyncio.gather(*dut_tasks_list)

        # Reorganize results from per-DUT structure to per-collector structure
        for i, dut_id in enumerate(dut_ids):
            dut_results = dut_results_list[i]
            for collector_id, result in dut_results.items():
                if collector_id not in results:
                    results[collector_id] = {}
                results[collector_id][dut_id] = result

        # Update main progress to completion (only if progress is available)
        if progress and main_task:
            progress.advance(main_task, advance=len(collectors) * len(dut_ids))
            progress.update(
                main_task,
                description=f"Overall Progress -- Service-grouped sequential collectors ({len(collectors)}/{len(collectors)} completed)",
            )

        return results

    async def execute_parallel_collectors_no_progress(
        self,
        collectors: List[str],
        dut_ids: List[str],
        collection_level: str,
        concurrency_limit: int = 10,
    ) -> Dict[str, Any]:
        """
        Execute collectors in parallel without progress bars.

        Args:
            collectors: List of collector IDs.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            concurrency_limit: Maximum concurrent tasks.

        Returns:
            Dictionary of execution results per DUT and collector.
        """
        results = {}

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(concurrency_limit)

        async def execute_single_collector(collector_id: str) -> tuple:
            """
            Execute a single collector on all DUTs.

            Args:
                collector_id: Collector ID.

            Returns:
                Tuple of (collector_id, results_dict).
            """
            async with semaphore:
                # Check for shutdown request
                if (
                    hasattr(self.orchestrator, "is_shutdown_requested")
                    and self.orchestrator.is_shutdown_requested()
                ):
                    await self._log_runtime(
                        "WARN", f"Shutdown requested, skipping collector {collector_id}"
                    )
                    return collector_id, {}

                collector_results = {}
                for dut_id in dut_ids:
                    # Check for shutdown request
                    if (
                        hasattr(self.orchestrator, "is_shutdown_requested")
                        and self.orchestrator.is_shutdown_requested()
                    ):
                        await self._log_runtime(
                            "WARN",
                            f"Shutdown requested, stopping execution for DUT {dut_id}",
                        )
                        break
                    # Set current collector context for logging
                    if self.orchestrator and hasattr(
                        self.orchestrator, "current_collector_id"
                    ):
                        self.orchestrator.current_collector_id = collector_id
                    if self.orchestrator and hasattr(
                        self.orchestrator, "current_execution_context"
                    ):
                        self.orchestrator.current_execution_context = {
                            "collector_id": collector_id,
                            "dut_id": dut_id,
                            "collection_level": collection_level,
                        }

                    # Set per-collector context with original collector ID for cross-contamination prevention
                    if self.orchestrator and hasattr(
                        self.orchestrator, "set_collector_execution_context"
                    ):
                        context = {
                            "collector_id": collector_id,
                            "dut_id": dut_id,
                            "collection_level": collection_level,
                            "original_collector_id": collector_id,  # Store the original collector ID
                        }
                        await self.orchestrator.set_collector_execution_context(
                            dut_id, collector_id, context
                        )

                    # Check for shutdown before executing collector
                    if (
                        hasattr(self.orchestrator, "is_shutdown_requested")
                        and self.orchestrator.is_shutdown_requested()
                    ):
                        await self._log_runtime(
                            "WARN",
                            f"Shutdown requested, skipping collector {collector_id} on DUT {dut_id}",
                        )
                        collector_results[dut_id] = {
                            "status": "interrupted",
                            "reason": "Shutdown requested",
                            "execution_time": 0.0,
                        }
                        break

                    try:
                        service = await self._get_service_for_collector(collector_id)
                        if service:
                            result = await service.execute_collector(
                                dut_id, collector_id, collection_level
                            )
                            collector_results[dut_id] = self._normalize_result(result)
                        else:
                            collector_results[dut_id] = {
                                "status": "error",
                                "reason": f"No service found for collector {collector_id}",
                            }
                    except Exception as e:
                        collector_results[dut_id] = {
                            "status": "error",
                            "reason": f"Execution failed: {str(e)}",
                        }

                return collector_id, collector_results

        # Execute all collectors in parallel
        tasks = [execute_single_collector(collector_id) for collector_id in collectors]
        collector_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in collector_results:
            if isinstance(result, Exception):
                await self._log_runtime(
                    "error", f"Collector execution failed: {result}"
                )
                continue

            collector_id, results_dict = result
            results[collector_id] = results_dict

        return results

    async def _execute_service_groups_with_parallel_progress(
        self,
        service_groups: Dict[str, List[str]],
        dut_ids: List[str],
        collection_level: str,
        progress: Progress,
        main_task,
        dut_tasks: Dict[str, Any],
        active_collectors: Dict[str, set],
        total_collectors: int,
    ) -> Dict[str, Any]:
        """
        Execute service groups with per-DUT progress tracking.

        Args:
            service_groups: Dictionary mapping service names to collector IDs.
            dut_ids: List of DUT IDs.
            collection_level: Collection level.
            progress: Progress bar instance.
            main_task: Main task ID for progress tracking.
            dut_tasks: Dictionary of DUT-specific progress tasks.
            active_collectors: Dictionary tracking active collectors per DUT.
            total_collectors: Total number of collectors.

        Returns:
            Dictionary of execution results per DUT and collector.
        """
        all_results = {}

        # Execute each service group
        service_tasks_list = []
        for service_name, collectors in service_groups.items():
            service_task = self._execute_service_group(
                service_name,
                collectors,
                dut_ids,
                collection_level,
                progress,
                main_task,
                dut_tasks,  # Pass DUT tasks for per-DUT progress tracking
                active_collectors,  # Pass active collectors tracking
                total_collectors,  # Pass total collectors across all service groups
            )
            service_tasks_list.append(service_task)

        # Wait for all service groups to complete
        service_results = await asyncio.gather(*service_tasks_list)

        # Combine results
        for service_name, results in zip(service_groups.keys(), service_results):
            all_results.update(results)

        return all_results

    async def _pre_filter_collectors_for_duts(
        self,
        collectors: List[str],
        dut_ids: List[str],
        progress: Progress,
        main_task,
    ) -> Dict[str, Dict[str, tuple[bool, str]]]:
        """
        Pre-filters collectors for each DUT to determine if they should be skipped.
        Returns a dictionary mapping collector_id to a dictionary of DUT_id to (should_skip, reason).
        """
        await self._log_runtime(
            "INFO",
            f"Pre-filtering {len(collectors)} collectors across {len(dut_ids)} DUTs",
        )

        # Create a dictionary to hold pre-filtering results
        filtered_collectors_by_dut = {}
        for collector_id in collectors:
            filtered_collectors_by_dut[collector_id] = {}
            for dut_id in dut_ids:
                # Check if collector should be skipped based on configuration (tool-level and per-DUT)
                should_skip_config, skip_reason_config = (
                    await self._should_skip_collector_by_config(collector_id, dut_id)
                )

                if should_skip_config:
                    filtered_collectors_by_dut[collector_id][dut_id] = (
                        True,
                        skip_reason_config,
                    )
                    continue

                # Check if collector should be skipped for this specific DUT due to preflight failure
                should_skip, skip_reason = await self._should_skip_collector(
                    collector_id, dut_id
                )

                if should_skip:
                    filtered_collectors_by_dut[collector_id][dut_id] = (
                        True,
                        skip_reason,
                    )
                    continue

                filtered_collectors_by_dut[collector_id][dut_id] = (False, "")

        # Update main progress with pre-filtering status (only if progress is available)
        if progress and main_task:
            progress.update(
                main_task,
                description=f"Overall Progress -- Pre-filtering collectors ({len(collectors)}/{len(collectors)} completed)",
            )

        return filtered_collectors_by_dut

    def _categorize_collectors_by_group_and_bucket(
        self, collectors: List[str]
    ) -> Dict[str, CollectorGroup]:
        """
        Categorize collectors into groups and buckets.

        Args:
            collectors: List of collector IDs.

        Returns:
            Dictionary mapping service names to CollectorGroup instances.
        """
        groups = {}

        # Get sequential/parallel categorization
        sequential_collectors = self.config_manager.get_sequential_collectors()
        parallel_collectors = self.config_manager.get_parallel_collectors()

        # Group collectors by service
        for collector_id in collectors:
            service_name = self._get_service_name_for_collector(collector_id)
            if not service_name:
                continue

            if service_name not in groups:
                groups[service_name] = {"sequential": [], "parallel": []}

            # Categorize as sequential or parallel
            if collector_id in sequential_collectors:
                groups[service_name]["sequential"].append(collector_id)
            else:
                groups[service_name]["parallel"].append(collector_id)

        # Convert to CollectorGroup objects
        collector_groups = {}
        for service_name, buckets in groups.items():
            sequential_bucket = CollectorBucket(
                collectors=buckets["sequential"],
                is_sequential=True,
                service_name=service_name,
            )
            parallel_bucket = CollectorBucket(
                collectors=buckets["parallel"],
                is_sequential=False,
                service_name=service_name,
            )

            collector_groups[service_name] = CollectorGroup(
                service_name=service_name,
                sequential_bucket=sequential_bucket,
                parallel_bucket=parallel_bucket,
            )

        return collector_groups

    def _get_service_name_for_collector(self, collector_id: str) -> Optional[str]:
        """
        Get service name for a collector.

        Args:
            collector_id: Collector ID.

        Returns:
            Service name or None if not found.
        """
        # Map collector prefixes to service names
        service_mapping = {
            "R": "redfish",
            "S": "ssh",
            "I": "ipmi",
            "H": "host",
            "C": "health_check",
        }

        prefix = collector_id[0].upper()
        return service_mapping.get(prefix)
