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
import base64
import binascii
import copy
import csv
import hashlib
import json
import logging
import os
import re
import time
import traceback
from asyncio import Lock, Semaphore
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union

from ..utils.enums import ENTITY_URI_TO_PLACEHOLDER
from ..utils.id_filtering import filter_ids, log_filtered_ids
from ..utils.streaming import (
    append_stream_window_to_filename,
    format_redfish_stream_timestamp,
    format_stream_window_component,
    normalize_stream_window,
)
from ..utils.timeout_config import (
    get_collector_sleep_duration,
    get_collector_timeout,
    get_expand_level,
)
from .base_service import BaseService

logger = logging.getLogger(__name__)


def validate_redfish_uri(uri, expected_host=None):
    """Thin wrapper: lazy-imports from utils.validation to avoid circular dependency."""
    from ..utils.validation import validate_redfish_uri as _impl

    return _impl(uri, expected_host=expected_host)


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
        self._redfish_request_captures: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._redfish_capture_locks: Dict[Tuple[str, str], Lock] = {}

    def _get_tool_config_int(self, key: str, default: int) -> int:
        """Read an integer from runtime tool_config with a safe fallback."""
        tool_config = getattr(self.dut_manager, "tool_config", {}) or {}
        try:
            value = int(tool_config.get(key, default))
            return value if value > 0 else default
        except (TypeError, ValueError):
            return default

    def _get_redfish_request_capture_key(
        self, dut_id: str, collector_id: Optional[str] = None
    ) -> Optional[Tuple[str, str]]:
        """Return the per-collector key used for Redfish request capture."""
        resolved_collector_id = collector_id or self._get_current_collector_id()
        if (
            not dut_id
            or not resolved_collector_id
            or resolved_collector_id == "unknown"
        ):
            return None
        return dut_id, resolved_collector_id

    async def _start_redfish_request_capture(
        self, dut_id: str, collector_id: Optional[str] = None
    ) -> None:
        """Initialize Redfish request capture for a collector execution."""
        key = self._get_redfish_request_capture_key(dut_id, collector_id)
        if key:
            lock = self._redfish_capture_locks.setdefault(key, Lock())
            async with lock:
                self._redfish_request_captures[key] = {
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                    "requests": [],
                }

    async def _clear_redfish_request_capture(
        self, dut_id: str, collector_id: Optional[str] = None
    ) -> None:
        """Clear any pending Redfish request capture state."""
        key = self._get_redfish_request_capture_key(dut_id, collector_id)
        if key:
            lock = self._redfish_capture_locks.setdefault(key, Lock())
            async with lock:
                self._redfish_request_captures.pop(key, None)
                self._redfish_capture_locks.pop(key, None)

    async def _record_redfish_request_capture(
        self,
        dut_id: str,
        request_info: Dict[str, Any],
        response_info: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        collector_id: Optional[str] = None,
    ) -> None:
        """Capture a Redfish request/response pair for the active collector."""
        key = self._get_redfish_request_capture_key(dut_id, collector_id)
        if not key:
            return

        lock = self._redfish_capture_locks.setdefault(key, Lock())
        async with lock:
            capture_state = self._redfish_request_captures.get(key)
            if capture_state is None:
                # Some collector flows make Redfish calls without explicitly invoking
                # _start_redfish_request_capture first. Initialize lazily so request
                # capture still works and runtime logs do not get flooded with WARNs.
                capture_state = {
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                    "requests": [],
                }
                self._redfish_request_captures[key] = capture_state

            entry: Dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request": self._sanitize_for_capture(request_info),
            }
            if response_info is not None:
                entry["response"] = self._sanitize_for_capture(response_info)
            if metadata:
                entry["metadata"] = self._sanitize_for_capture(metadata)

            capture_state["requests"].append(entry)

    async def _get_collector_output_dir(
        self, dut_id: str, collector_id: Optional[str]
    ) -> Optional[Path]:
        """Get the collector output directory path for Redfish artifacts."""
        if not collector_id or not self.logger:
            return None

        sentinel_path = await self.logger.create_collector_log_file(
            dut_id, "redfish", collector_id, ".collector_dir_sentinel"
        )
        if not sentinel_path:
            return None

        collector_dir = Path(sentinel_path).parent
        sentinel_file = collector_dir / ".collector_dir_sentinel"
        if sentinel_file.exists():
            try:
                sentinel_file.unlink()
            except Exception as e:
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Failed to apply stream window to Redfish CSV filename {csv_filename}: {str(e)}",
                    dut_id,
                )

        return collector_dir

    async def _attach_redfish_request_capture(
        self,
        dut_id: str,
        result: Optional[Dict[str, Any]],
        collector_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Persist the Redfish request/response artifact and reference it from collector context."""
        key = self._get_redfish_request_capture_key(dut_id, collector_id)
        capture_state = None
        if key:
            lock = self._redfish_capture_locks.setdefault(key, Lock())
            async with lock:
                capture_state = self._redfish_request_captures.pop(key, None)
                self._redfish_capture_locks.pop(key, None)
        captured_requests = (capture_state or {}).get("requests", [])
        if not captured_requests or not isinstance(result, dict):
            return result

        resolved_collector_id = collector_id or self._get_current_collector_id()
        collector_dir = await self._get_collector_output_dir(
            dut_id, resolved_collector_id
        )
        if not collector_dir or not self.logger:
            return result

        artifact_name = "redfish_request_response_log.json"
        artifact_path = await self.logger.create_collector_log_file(
            dut_id, "redfish", resolved_collector_id, artifact_name
        )

        try:
            with artifact_path.open("w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "captured_at": capture_state.get("captured_at"),
                        "collector_id": resolved_collector_id,
                        "dut_id": dut_id,
                        "requests": captured_requests,
                    },
                    handle,
                    indent=2,
                )
        except Exception as exc:
            await self._log_runtime(
                "WARN",
                "RedfishService",
                f"Failed to persist Redfish request log for {resolved_collector_id}: {exc}",
                dut_id,
            )
            return result

        context = result.setdefault("context", {})
        output_files = result.setdefault("output_files", [])
        artifact_path_str = str(artifact_path)
        if artifact_path_str not in output_files:
            output_files.append(artifact_path_str)

        context_output_files = context.setdefault("output_files", [])
        if artifact_path_str not in context_output_files:
            context_output_files.append(artifact_path_str)

        context["request_response_capture"] = {
            "artifact": artifact_name,
            "captured_requests": len(captured_requests),
        }
        return result

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

    def _get_connection_host(self, dut_id: str) -> Optional[str]:
        """
        Get the BMC host/IP for a given DUT, used for SSRF validation.

        Args:
            dut_id: DUT ID.

        Returns:
            The BMC IP/hostname string, or None if unavailable.
        """
        try:
            if self.dut_manager:
                dut = self.dut_manager.get_dut(dut_id)
                if dut and hasattr(dut, "credentials") and dut.credentials:
                    return getattr(dut.credentials, "bmc_ip", None)
        except Exception:
            pass
        return None

    def _deep_merge_config(
        self, base_config: Dict[str, Any], override_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Recursively merge collector config overrides, replacing lists wholesale."""
        merged = dict(base_config)
        for key, value in override_config.items():
            if (
                key in merged
                and isinstance(merged[key], dict)
                and isinstance(value, dict)
            ):
                merged[key] = self._deep_merge_config(merged[key], value)
            else:
                merged[key] = value
        return merged

    def _extract_member_uris_from_data(
        self,
        data: Any,
        link_path: Optional[Any] = "Members",
        member_uri_path: Optional[Any] = "@odata.id",
    ) -> List[str]:
        """Extract a list of Redfish member URIs from a collection or link array."""
        if link_path in (None, ""):
            source = data
        else:
            source = self._extract_nested_value(data, link_path)

        if isinstance(source, dict) and "Members" in source:
            source = source.get("Members", [])

        uris: List[str] = []

        if isinstance(source, list):
            for item in source:
                if isinstance(item, str):
                    candidate_uri = item
                elif isinstance(item, dict):
                    if member_uri_path in (None, ""):
                        candidate_uri = item.get("@odata.id")
                    else:
                        candidate_uri = self._extract_nested_value(
                            item, member_uri_path
                        )
                else:
                    continue

                if candidate_uri and validate_redfish_uri(candidate_uri):
                    uris.append(candidate_uri)

        elif isinstance(source, str) and validate_redfish_uri(source):
            uris.append(source)

        return uris

    def _value_matches_filter_condition(
        self, value: Any, condition: Dict[str, Any]
    ) -> bool:
        """Evaluate a single filter condition against a scalar or list value."""
        values = value if isinstance(value, list) else [value]

        if "equals" in condition:
            expected = str(condition["equals"]).lower()
            return any(
                str(item).lower() == expected for item in values if item is not None
            )

        if "contains" in condition:
            needle = str(condition["contains"]).lower()
            return any(
                needle in str(item).lower() for item in values if item is not None
            )

        if "regex" in condition:
            pattern = re.compile(str(condition["regex"]), re.IGNORECASE)
            return any(pattern.search(str(item)) for item in values if item is not None)

        return False

    def _member_matches_filters(
        self,
        member_uri: str,
        member_data: Optional[Dict[str, Any]],
        filters: Optional[Dict[str, Any]],
    ) -> bool:
        """Apply optional URI and payload filters to a candidate member resource."""
        if not filters:
            return True

        include_uri_patterns = filters.get("include_uri_patterns", [])
        exclude_uri_patterns = filters.get("exclude_uri_patterns", [])

        if include_uri_patterns and not any(
            re.search(pattern, member_uri, re.IGNORECASE)
            for pattern in include_uri_patterns
        ):
            return False

        if exclude_uri_patterns and any(
            re.search(pattern, member_uri, re.IGNORECASE)
            for pattern in exclude_uri_patterns
        ):
            return False

        include_conditions = filters.get("include_conditions", [])
        if include_conditions:
            if not member_data:
                return False
            if not any(
                self._value_matches_filter_condition(
                    self._extract_nested_value(member_data, condition.get("path")),
                    condition,
                )
                for condition in include_conditions
            ):
                return False

        exclude_conditions = filters.get("exclude_conditions", [])
        if exclude_conditions and member_data:
            if any(
                self._value_matches_filter_condition(
                    self._extract_nested_value(member_data, condition.get("path")),
                    condition,
                )
                for condition in exclude_conditions
            ):
                return False

        return True

    def _set_nested_value(self, data: Any, path: Any, value: Any) -> bool:
        """
        Set a nested value on a dictionary/list using dot/bracket notation.

        Returns:
            True if the path existed and the value was updated, otherwise False.
        """
        if data is None or path is None:
            return False

        tokens = (
            list(path)
            if isinstance(path, (list, tuple))
            else self._split_path_tokens(path)
        )
        if not tokens:
            return False

        current = data
        for token in tokens[:-1]:
            if isinstance(token, int):
                if isinstance(current, list) and 0 <= token < len(current):
                    current = current[token]
                else:
                    return False
            else:
                if isinstance(current, dict) and token in current:
                    current = current[token]
                else:
                    return False

        last_token = tokens[-1]
        if isinstance(last_token, int):
            if isinstance(current, list) and 0 <= last_token < len(current):
                current[last_token] = value
                return True
            return False

        if isinstance(current, dict):
            current[last_token] = value
            return True

        return False

    def _apply_list_filters_to_data(
        self, data: Any, list_filters: Optional[List[Dict[str, Any]]]
    ) -> Any:
        """
        Filter configured list fields within a payload before saving it.
        """
        if not isinstance(data, dict) or not list_filters:
            return data

        filtered_data = copy.deepcopy(data)

        for filter_config in list_filters:
            list_path = filter_config.get("path")
            if not list_path:
                continue

            items = self._extract_nested_value(filtered_data, list_path)
            if not isinstance(items, list):
                continue

            uri_path = filter_config.get("member_uri_path", "@odata.id")
            member_filters = filter_config.get("filters", {})

            filtered_items = []
            for item in items:
                member_uri = ""
                if isinstance(item, dict):
                    extracted_uri = self._extract_nested_value(item, uri_path)
                    member_uri = str(extracted_uri) if extracted_uri else ""
                elif isinstance(item, str):
                    member_uri = item

                if self._member_matches_filters(
                    member_uri, item if isinstance(item, dict) else None, member_filters
                ):
                    filtered_items.append(item)

            if self._set_nested_value(filtered_data, list_path, filtered_items):
                count_path = filter_config.get("count_path")
                if count_path:
                    self._set_nested_value(
                        filtered_data, count_path, len(filtered_items)
                    )

        return filtered_data

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

        # Check for entity ID overrides — bypasses all discovery/filtering
        override_key_map = {
            "Systems": "SYSTEM_ID_OVERRIDE",
            "Managers": "MANAGER_ID_OVERRIDE",
            "Chassis": "CHASSIS_ID_OVERRIDE",
        }
        context_key_map = {
            "Systems": ("filtered_systems", "system_count"),
            "Managers": ("filtered_managers", "manager_count"),
            "Chassis": ("filtered_chassis", "chassis_count"),
        }
        override_key = override_key_map.get(entity_type)
        if override_key and self.dut_manager:
            dut_config = self.dut_manager.get_dut_config(dut_id)
            id_overrides = dut_config.get(override_key, [])
            if not id_overrides:
                id_overrides = (self.dut_manager.tool_config or {}).get(
                    override_key
                ) or []
            if id_overrides:
                ctx_key, count_key = context_key_map[entity_type]
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"[{collector_id}] {override_key} set to {id_overrides}, skipping discovery",
                    dut_id,
                )
                return {
                    "success": True,
                    "context": {
                        ctx_key: [
                            {
                                "id": eid,
                                "model": "",
                                "name": eid,
                                "discovery_source": "id_override",
                            }
                            for eid in id_overrides
                        ],
                        count_key: len(id_overrides),
                        "filter_mode": "override",
                        "discovery_method": "id_override",
                    },
                }

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

        result = await self._validate_entities_generic(
            dut_id,
            entity_type,
            check_hgx_prefix,
            filter_mode,
            baseboard_aware,
            **kwargs,
        )

        # Fallback: if generic filtering yielded 0 entities, try redfish_entity_defaults patterns
        context_key_map = {
            "Systems": "filtered_systems",
            "Managers": "filtered_managers",
            "Chassis": "filtered_chassis",
        }
        ctx_key = context_key_map.get(entity_type, "filtered_entities")
        filtered = result.get("context", {}).get(ctx_key, [])
        if not filtered and self.dut_manager:
            baseboard_manager = self.dut_manager._get_baseboard_manager()
            if baseboard_manager:
                dut_config = self.dut_manager.get_dut_config(dut_id)
                target_baseboard = dut_config.get("baseboard") or dut_config.get(
                    "TargetBaseboard", ""
                )
                fallback_patterns = baseboard_manager.get_entity_patterns(
                    target_baseboard, entity_type
                )
                if isinstance(fallback_patterns, list) and fallback_patterns:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"[{collector_id}] Generic filtering yielded 0 {entity_type}, "
                        f"retrying with redfish_entity_defaults patterns: {fallback_patterns}",
                        dut_id,
                    )
                    kwargs_without_collector = {
                        k: v for k, v in kwargs.items() if k != "collector_id"
                    }
                    result = await self._validate_entities_with_patterns(
                        dut_id,
                        entity_type,
                        fallback_patterns,
                        collector_id,
                        **kwargs_without_collector,
                    )

        return result

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
                        "Using preflight results for Redfish validation - connection already verified",
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
            # Log validation start — filter_mode here is the parameter default; the actual
            # resolved mode (after baseboard-aware lookup) is logged at INFO when filtering completes.
            await self._log_runtime(
                "DEBUG",
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

            # Resolve filter mode and hgx_prefix once per DUT call — the baseboard
            # does not change between entities, so recomputing inside the loop is wasteful
            # and causes the summary log to report the wrong mode.
            dut_config = self.dut_manager.get_dut_config(dut_id)
            hgx_prefix = dut_config.get(config["config_prefix"], "HGX")
            resolved_filter_mode = filter_mode
            skip_id_type = {
                "Systems": "system",
                "Managers": "manager",
                "Chassis": "chassis",
            }.get(entity_type)

            if baseboard_aware and kwargs.get("baseboard_filtering"):
                dut_baseboard = dut_config.get("baseboard") or dut_config.get(
                    "TargetBaseboard", ""
                )
                baseboard_filtering = kwargs.get("baseboard_filtering", {})
                baseboard_manager = self.dut_manager._get_baseboard_manager()
                await baseboard_manager.log_baseboard_info(dut_id)
                resolved_filter_mode = (
                    await baseboard_manager.apply_baseboard_filtering(
                        dut_id,
                        dut_baseboard,
                        baseboard_filtering,
                        "all_platforms",
                    )
                )
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Baseboard-aware filtering: dut_baseboard='{dut_baseboard}', resolved_filter_mode='{resolved_filter_mode}' (default was '{filter_mode}')",
                    dut_id,
                )

            if discovered_entities and skip_id_type:
                original_entities = [str(entity_id) for entity_id in discovered_entities]
                filtered_discovered_entities = filter_ids(
                    original_entities, skip_id_type, dut_config
                )
                if len(filtered_discovered_entities) != len(original_entities):
                    await log_filtered_ids(
                        original_entities,
                        filtered_discovered_entities,
                        skip_id_type,
                        self.logger,
                        dut_id,
                    )
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Applied {entity_type} skip list before validation requests: {filtered_discovered_entities}",
                        dut_id,
                    )
                discovered_entities = filtered_discovered_entities

                if not discovered_entities:
                    return {
                        "success": True,
                        "context": {
                            config["context_key"]: [],
                            config["count_key"]: 0,
                            "filter_mode": resolved_filter_mode,
                            "discovery_method": "dynamic_discovery",
                        },
                    }

            if discovered_entities:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using dynamic discovery results for {entity_type} validation: {discovered_entities}",
                    dut_id,
                )
                filtered_entities = []

                for entity_id in discovered_entities:
                    entity_uri = self.get_configured_uri(dut_id, config["uri_key"])
                    entity_uri_full = f"{entity_uri}/{entity_id}"

                    success, entity_data, _ = await self.dispatch_request(
                        dut_id, "GET", entity_uri_full, bypass_cache=True
                    )

                    if success:
                        model = entity_data.get("Model", "")
                        is_hgx = hgx_prefix in entity_id

                        if resolved_filter_mode == "hgx_only":
                            include_entity = is_hgx or not check_hgx_prefix
                        elif resolved_filter_mode == "all_platforms":
                            include_entity = True
                        elif resolved_filter_mode == "non_hgx_only":
                            include_entity = not is_hgx
                        else:
                            include_entity = is_hgx or not check_hgx_prefix

                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"Entity {entity_id}: include_entity={include_entity} (resolved_filter_mode='{resolved_filter_mode}')",
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
                    f"Filtered {entity_type} using mode '{resolved_filter_mode}': {len(filtered_entities)} entities found",
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
                        "filter_mode": resolved_filter_mode,
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
            if entities_list and skip_id_type:
                entity_ids = [
                    str(entity.get("@odata.id", "")).rstrip("/").split("/")[-1]
                    for entity in entities_list
                ]
                filtered_entity_ids = filter_ids(entity_ids, skip_id_type, dut_config)
                if len(filtered_entity_ids) != len(entity_ids):
                    await log_filtered_ids(
                        entity_ids,
                        filtered_entity_ids,
                        skip_id_type,
                        self.logger,
                        dut_id,
                    )
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Applied {entity_type} skip list before fallback validation requests: {filtered_entity_ids}",
                        dut_id,
                    )
                filtered_entity_id_set = set(filtered_entity_ids)
                entities_list = [
                    entity
                    for entity, entity_id in zip(entities_list, entity_ids)
                    if entity_id in filtered_entity_id_set
                ]

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
                    is_hgx = hgx_prefix in model

                    if resolved_filter_mode == "hgx_only":
                        include_entity = is_hgx or not check_hgx_prefix
                    elif resolved_filter_mode == "all_platforms":
                        include_entity = True
                    elif resolved_filter_mode == "non_hgx_only":
                        include_entity = not is_hgx
                    else:
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
                f"Filtered {entity_type} using mode '{resolved_filter_mode}': {len(filtered_entities)} entities found",
                dut_id,
            )

            return {
                "success": True,
                "context": {
                    config["context_key"]: filtered_entities,
                    config["count_key"]: len(filtered_entities),
                    "filter_mode": resolved_filter_mode,
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

        regex_special_chars = re.compile(r"[\\\^\$\+\?\{\}\(\)\|]")

        for pattern in patterns:
            if regex_special_chars.search(pattern):
                if re.search(pattern, entity_id):
                    return True
            elif fnmatch.fnmatch(entity_id, pattern):
                return True
        return False

    def validate_system_configs_schema(
        self,
        system_configs: Dict[str, Any],
        dut_id: str = None,
    ) -> Tuple[bool, List[str]]:
        """
        Validate system_configs structure before use.

        This is a safeguard to ensure system_configs has the expected structure
        and contains valid configuration entries.

        Required fields per system config:
        - diagnostic_type (str)
        - payload_template (dict)

        Optional fields:
        - device_id_key (str)
        - device_id_prefix (str)

        Args:
            system_configs: Dictionary of system patterns to config mappings
            dut_id: Optional DUT ID for logging

        Returns:
            Tuple of (is_valid, list_of_error_messages)
        """
        errors = []

        if not isinstance(system_configs, dict):
            return False, ["system_configs must be a dictionary"]

        if len(system_configs) == 0:
            # Empty dict is valid but will fall back to device config
            return True, []

        for pattern, config in system_configs.items():
            # Validate pattern is a string
            if not isinstance(pattern, str):
                errors.append(f"Pattern must be string, got {type(pattern).__name__}")
                continue

            # Validate pattern is not empty
            if not pattern.strip():
                errors.append("Pattern cannot be an empty string")
                continue

            # Validate config is a dict
            if not isinstance(config, dict):
                errors.append(
                    f"Config for pattern '{pattern}' must be dict, got {type(config).__name__}"
                )
                continue

            # Check for nested system_configs (prevent recursion)
            if "system_configs" in config:
                errors.append(
                    f"Pattern '{pattern}' contains nested system_configs (not allowed)"
                )
                continue

            # Validate required fields
            if "diagnostic_type" not in config:
                errors.append(
                    f"Pattern '{pattern}' missing required field: diagnostic_type"
                )

            if "payload_template" not in config:
                errors.append(
                    f"Pattern '{pattern}' missing required field: payload_template"
                )

            # Validate field types if present
            if "diagnostic_type" in config and not isinstance(
                config["diagnostic_type"], str
            ):
                errors.append(f"Pattern '{pattern}': diagnostic_type must be string")

            if "payload_template" in config and not isinstance(
                config["payload_template"], dict
            ):
                errors.append(f"Pattern '{pattern}': payload_template must be dict")

            if "device_id_key" in config and not isinstance(
                config["device_id_key"], str
            ):
                errors.append(f"Pattern '{pattern}': device_id_key must be string")

            if "device_id_prefix" in config and not isinstance(
                config["device_id_prefix"], str
            ):
                errors.append(f"Pattern '{pattern}': device_id_prefix must be string")

        return len(errors) == 0, errors

    async def resolve_system_config(
        self,
        system_id: str,
        device_config: Dict[str, Any],
        dut_id: str = None,
        device_type: str = None,
    ) -> Dict[str, Any]:
        """
        Resolve system-specific diagnostic configuration.

        This method enables per-system configuration for platforms with multiple
        systems (e.g., platforms with separate compute and baseboard systems).

        Resolution order (highest to lowest priority):
        1. Exact system match in system_configs (e.g., "System_0")
        2. Pattern match in system_configs using fnmatch (e.g., "System_*")
        3. Device-level config (backward compatible fallback)

        Args:
            system_id: The system ID being processed (e.g., "System_0", "HGX_Baseboard_0")
            device_config: The device configuration dict from diagnostic_configs
            dut_id: Optional DUT ID for logging
            device_type: Optional device type for logging context

        Returns:
            Resolved configuration dict for this system. Returns the original
            device_config unchanged if no system_configs key exists (backward compatible).
        """
        import fnmatch

        system_configs = device_config.get("system_configs")

        # SAFEGUARD: Log which code path is taken for debugging
        if not system_configs:
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"[resolve_system_config] No system_configs for device_type={device_type}, "
                f"system_id={system_id} - using existing config path (backward compatible)",
                dut_id,
            )
            # Return original config unchanged - backward compatible
            return device_config

        # Validate schema before proceeding
        is_valid, errors = self.validate_system_configs_schema(system_configs, dut_id)
        if not is_valid:
            await self._log_runtime(
                "WARNING",
                "RedfishService",
                f"[resolve_system_config] Invalid system_configs schema for device_type={device_type}: {errors}. "
                f"Falling back to device config.",
                dut_id,
            )
            # Return device config without system_configs key
            return {k: v for k, v in device_config.items() if k != "system_configs"}

        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"[resolve_system_config] Found system_configs for device_type={device_type}, "
            f"resolving config for system_id={system_id}, patterns available: {list(system_configs.keys())}",
            dut_id,
        )

        # 1. Check exact system match FIRST (highest priority)
        if system_id in system_configs:
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"[resolve_system_config] EXACT MATCH: system_id={system_id} -> using system-specific config",
                dut_id,
            )
            return system_configs[system_id]

        # 2. Check pattern match using fnmatch
        for pattern, config in system_configs.items():
            if fnmatch.fnmatch(system_id, pattern):
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"[resolve_system_config] PATTERN MATCH: system_id={system_id} matched pattern='{pattern}'",
                    dut_id,
                )
                return config

        # 3. Fallback to device-level config
        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"[resolve_system_config] NO MATCH: system_id={system_id} did not match any pattern in {list(system_configs.keys())}, "
            f"using device-level fallback config",
            dut_id,
        )
        # Return device config without system_configs key (to avoid passing it downstream)
        return {k: v for k, v in device_config.items() if k != "system_configs"}

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

        # Fall back to baseboard-level entity defaults from baseboards.yaml
        if patterns_to_use is None and baseboard_manager:
            baseboard_defaults = baseboard_manager.get_entity_patterns(
                target_baseboard, entity_type
            )
            if isinstance(baseboard_defaults, list) and baseboard_defaults:
                patterns_to_use = baseboard_defaults
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using redfish_entity_defaults for {target_baseboard} ({entity_type}): {patterns_to_use}",
                    dut_id,
                )

        # Final fallback to caller-provided default patterns or wildcard
        if patterns_to_use is None:
            patterns_to_use = default_patterns or ["*"]
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Using fallback patterns: {patterns_to_use}",
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

            # Normalize ID pattern configuration (supports strings, lists, and regex detection)
            id_pattern_entries: List[Tuple[str, bool]] = []
            raw_id_patterns: List[str] = []
            if "id_pattern" in filter_criteria:
                raw_patterns = filter_criteria["id_pattern"]
                if isinstance(raw_patterns, (list, tuple, set)):
                    raw_pattern_list = [str(pattern) for pattern in raw_patterns]
                else:
                    raw_pattern_list = [str(raw_patterns)]

                raw_id_patterns = raw_pattern_list
                explicit_regex_flag = filter_criteria.get("id_pattern_regex")
                regex_special_chars = re.compile(r"[\\\^\$\*\+\?\{\}\[\]\|]")

                for pattern in raw_pattern_list:
                    use_regex = explicit_regex_flag
                    if use_regex is None:
                        use_regex = bool(regex_special_chars.search(pattern))
                    id_pattern_entries.append((pattern, bool(use_regex)))

            def matches_id_patterns(entity_name: str) -> bool:
                if not id_pattern_entries:
                    return False
                for pattern, use_regex in id_pattern_entries:
                    if use_regex:
                        if re.search(pattern, entity_name):
                            return True
                    else:
                        if pattern.lower() in entity_name.lower():
                            return True
                return False

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
            if id_pattern_entries:
                matching_discovered = [
                    e for e in discovered_entities if matches_id_patterns(e)
                ]

                non_regex_patterns = [
                    pattern
                    for pattern, use_regex in id_pattern_entries
                    if not use_regex
                ]

                if not matching_discovered and non_regex_patterns:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"No {entity_type.lower()} matching patterns {raw_id_patterns} found in standard discovery. Attempting enumeration for non-regex patterns...",
                        dut_id,
                    )

                    def _build_candidate(base_pattern: str, index: int) -> str:
                        if base_pattern.endswith("_"):
                            return f"{base_pattern}{index}"
                        return f"{base_pattern}_{index}"

                    enumeration_attempts = []
                    for base_pattern in non_regex_patterns:
                        trimmed_pattern = base_pattern.strip()
                        for i in range(8):  # Try 0-7 for common GPU counts
                            enumeration_attempts.append(
                                _build_candidate(trimmed_pattern, i)
                            )

                        if "GPU" in trimmed_pattern.upper():
                            for i in range(8):
                                enumeration_attempts.append(
                                    f"{trimmed_pattern.rstrip('_')}_SXM_{i}"
                                )

                    # Probe each potential entity to see if it exists
                    enumerated_entities = []
                    seen_attempts = set()
                    for potential_id in enumeration_attempts:
                        if potential_id in seen_attempts:
                            continue
                        seen_attempts.add(potential_id)
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
                if id_pattern_entries and matches_id_patterns(entity_id):
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
                        f"Found {entity_type.lower()} matching ID pattern(s) {raw_id_patterns}: {entity_id}",
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

    async def _derive_uri_suffixes(
        self,
        dut_id: str,
        source_list: Union[str, List[str]] = None,
        output_variable: str = None,
        suffix: str = "",
        strip_trailing_slash: bool = True,
        ensure_unique: bool = True,
        include_uri_patterns: List[str] = None,
        exclude_uri_patterns: List[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Derive a new list of URIs by appending a suffix to each source URI.

        Args:
            dut_id: Device under test ID.
            source_list: List of URIs or reference to a context variable (e.g., "${rot_cert_uris}").
            output_variable: Context variable name to store derived URIs.
            suffix: Suffix to append to each URI (e.g., "/CertChain").
            strip_trailing_slash: Whether to remove trailing slash before appending suffix.
            ensure_unique: Whether to de-duplicate derived URIs.
            include_uri_patterns: Optional regex patterns; only matching source URIs are derived.
            exclude_uri_patterns: Optional regex patterns; matching source URIs are skipped.
            **kwargs: Additional context containing previously derived variables.
        """

        def _resolve_source_uris(
            source: Union[str, List[str], None], context: Dict[str, Any]
        ) -> List[str]:
            if isinstance(source, list):
                return source

            if isinstance(source, str):
                var_name = source
                if source.startswith("${") and source.endswith("}"):
                    var_name = source[2:-1]
                return context.get(var_name, []) or []

            return context.get("source_list", []) or []

        try:
            if not output_variable:
                return {
                    "success": False,
                    "reason": "output_variable must be provided for _derive_uri_suffixes",
                    "context": {},
                }

            source_uris = _resolve_source_uris(source_list, kwargs)

            derived_uris: List[str] = []
            skipped_uri_count = 0
            if source_uris:
                for uri in source_uris:
                    if not isinstance(uri, str):
                        continue

                    if include_uri_patterns and not any(
                        re.search(pattern, uri, re.IGNORECASE)
                        for pattern in include_uri_patterns
                    ):
                        skipped_uri_count += 1
                        continue

                    if exclude_uri_patterns and any(
                        re.search(pattern, uri, re.IGNORECASE)
                        for pattern in exclude_uri_patterns
                    ):
                        skipped_uri_count += 1
                        continue

                    normalized_uri = uri.rstrip("/") if strip_trailing_slash else uri

                    if suffix:
                        if suffix.startswith("/"):
                            derived_uri = f"{normalized_uri}{suffix}"
                        else:
                            derived_uri = f"{normalized_uri}/{suffix}"
                    else:
                        derived_uri = normalized_uri

                    derived_uris.append(derived_uri)

            if ensure_unique:
                seen = set()
                unique_derived = []
                for uri in derived_uris:
                    if uri not in seen:
                        seen.add(uri)
                        unique_derived.append(uri)
                derived_uris = unique_derived

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Derived {len(derived_uris)} URIs (suffix='{suffix}') from {len(source_uris)} source URIs; skipped {skipped_uri_count}",
                dut_id,
            )

            return {
                "success": True,
                "context": {
                    output_variable: derived_uris,
                    "source_uri_count": len(source_uris),
                    "derived_uri_count": len(derived_uris),
                    "skipped_uri_count": skipped_uri_count,
                    "suffix": suffix,
                },
            }

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Error in _derive_uri_suffixes: {str(e)}",
                dut_id,
            )
            return {
                "success": False,
                "reason": f"URI derivation error: {str(e)}",
                "context": {output_variable if output_variable else "derived_uris": []},
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

    async def _discover_dot_trusted_component_uris(
        self,
        dut_id: str,
        output_variable: str = "dot_trusted_component_uris",
        chassis_id_pattern: Union[str, List[str]] = r"^HGX_CPU_[0-9]+$",
        target_uri: str = "/redfish/v1/Chassis/{chassis_id}/TrustedComponents",
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Discover CPU DOT TrustedComponents collection URIs.

        R56 must not rely on the parent Chassis resource being readable: some
        systems can return 5xx for /Chassis/HGX_CPU_x while the child
        /TrustedComponents collection is available.
        """
        try:
            chassis_base_uri = self.get_configured_uri(dut_id, "Chassis")
            discovered_chassis = await self.get_discovered_chassis(dut_id)
            discovered_chassis = discovered_chassis or []

            if isinstance(chassis_id_pattern, (list, tuple, set)):
                raw_patterns = [str(pattern) for pattern in chassis_id_pattern]
            else:
                raw_patterns = [str(chassis_id_pattern)]

            compiled_patterns = [re.compile(pattern) for pattern in raw_patterns]

            def _matches_chassis_pattern(chassis_id: str) -> bool:
                return any(pattern.search(chassis_id) for pattern in compiled_patterns)

            candidate_chassis: List[str] = []
            skipped_chassis: List[str] = []

            def _add_candidate(chassis_id: str) -> None:
                if not chassis_id:
                    return
                if _matches_chassis_pattern(chassis_id):
                    if chassis_id not in candidate_chassis:
                        candidate_chassis.append(chassis_id)
                elif chassis_id not in skipped_chassis:
                    skipped_chassis.append(chassis_id)

            for chassis_id in discovered_chassis:
                _add_candidate(str(chassis_id))

            chassis_collection_success, chassis_collection_data, _ = (
                await self.dispatch_request(
                    dut_id,
                    "GET",
                    chassis_base_uri,
                    error_context="discover DOT chassis candidates",
                )
            )

            if chassis_collection_success and isinstance(chassis_collection_data, dict):
                for member in chassis_collection_data.get("Members", []):
                    if not isinstance(member, dict):
                        continue
                    member_uri = member.get("@odata.id", "")
                    chassis_id = member_uri.rstrip("/").split("/")[-1]
                    _add_candidate(chassis_id)
            elif not candidate_chassis:
                reason = (
                    f"Failed to fetch Chassis collection for DOT discovery and no "
                    f"discovered chassis candidates were available: {chassis_collection_data}"
                )
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    reason,
                    dut_id,
                )
                return {
                    "success": False,
                    "reason": reason,
                    "context": {output_variable: []},
                }
            else:
                await self._log_runtime(
                    "WARNING",
                    "RedfishService",
                    (
                        "Failed to fetch Chassis collection during DOT discovery; "
                        f"falling back to discovered chassis list: {chassis_collection_data}"
                    ),
                    dut_id,
                )

            trusted_component_uris: List[str] = []
            unavailable_targets: List[str] = []

            for chassis_id in candidate_chassis:
                trusted_components_uri = target_uri.format(chassis_id=chassis_id)
                success, trusted_components_data, _ = await self.dispatch_request(
                    dut_id,
                    "GET",
                    trusted_components_uri,
                    error_context=(
                        f"discover DOT TrustedComponents for chassis {chassis_id}"
                    ),
                )

                if success and isinstance(trusted_components_data, dict):
                    trusted_component_uris.append(trusted_components_uri)
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        (
                            "Discovered DOT TrustedComponents collection for "
                            f"{chassis_id}: {trusted_components_uri}"
                        ),
                        dut_id,
                    )
                    continue

                unavailable_targets.append(trusted_components_uri)
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    (
                        "Skipping DOT TrustedComponents collection for "
                        f"{chassis_id}: {trusted_components_data}"
                    ),
                    dut_id,
                )

            await self._log_runtime(
                "INFO",
                "RedfishService",
                (
                    f"Discovered {len(trusted_component_uris)} DOT TrustedComponents "
                    f"collections from {len(candidate_chassis)} candidate chassis"
                ),
                dut_id,
            )

            return {
                "success": True,
                "context": {
                    output_variable: trusted_component_uris,
                    "dot_trusted_component_uri_count": len(trusted_component_uris),
                    "dot_candidate_chassis": candidate_chassis,
                    "dot_unavailable_targets": unavailable_targets,
                    "dot_skipped_chassis": skipped_chassis,
                    "dot_chassis_id_patterns": raw_patterns,
                },
            }

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Error in _discover_dot_trusted_component_uris: {str(e)}",
                dut_id,
            )
            return {
                "success": False,
                "reason": f"DOT TrustedComponents discovery error: {str(e)}",
                "context": {output_variable: []},
            }

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

            def _apply_num_gpus_filter(
                device_type: str, device_ids_list: List[int]
            ) -> List[int]:
                if device_type.lower() != "gpu":
                    return device_ids_list

                num_gpus_value = None
                if baseboard_config and baseboard_config.get("num_gpus") is not None:
                    num_gpus_value = baseboard_config.get("num_gpus")
                elif dut_config and dut_config.get("num_gpus") is not None:
                    num_gpus_value = dut_config.get("num_gpus")

                try:
                    num_gpus = int(num_gpus_value) if num_gpus_value is not None else 0
                except (TypeError, ValueError):
                    num_gpus = 0

                if num_gpus > 0 and len(device_ids_list) > num_gpus:
                    limited = device_ids_list[:num_gpus]
                    asyncio.create_task(
                        self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Applying num_gpus={num_gpus} filter for {device_type}: {device_ids_list} -> {limited}",
                            dut_id,
                        )
                    )
                    return limited

                return device_ids_list

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
            # Baseboard overrides are optional; keep an empty dict so unsupported
            # device families degrade to "no patterns found" instead of raising.
            baseboard_device_patterns = (
                baseboard_config.get("device_patterns", {}) if baseboard_config else {}
            )

            # Apply baseboard-specific overrides if provided
            if baseboard_config:
                if "use_firmware_inventory" in baseboard_config:
                    use_fw_inventory = baseboard_config["use_firmware_inventory"]
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Baseboard override - use_firmware_inventory set to {use_fw_inventory}",
                        dut_id,
                    )

                if baseboard_device_patterns:
                    for (
                        pattern_key,
                        override_value,
                    ) in baseboard_device_patterns.items():
                        if override_value is None:
                            continue
                        # Handle complex override structures
                        if isinstance(override_value, dict):
                            override_patterns = override_value.get("override")
                            append_patterns = override_value.get("append")

                            if override_patterns is not None:
                                device_patterns[pattern_key] = list(override_patterns)
                                await self._log_runtime(
                                    "INFO",
                                    "RedfishService",
                                    f"Baseboard override - device_patterns[{pattern_key}] replaced with {device_patterns[pattern_key]}",
                                    dut_id,
                                )
                            if append_patterns:
                                device_patterns.setdefault(pattern_key, [])
                                device_patterns[pattern_key].extend(
                                    list(append_patterns)
                                )
                                await self._log_runtime(
                                    "INFO",
                                    "RedfishService",
                                    f"Baseboard override - device_patterns[{pattern_key}] extended with {append_patterns}",
                                    dut_id,
                                )
                        else:
                            if isinstance(override_value, (list, tuple, set)):
                                device_patterns[pattern_key] = list(override_value)
                            else:
                                device_patterns[pattern_key] = [str(override_value)]
                            await self._log_runtime(
                                "INFO",
                                "RedfishService",
                                f"Baseboard override - device_patterns[{pattern_key}] set to {device_patterns[pattern_key]}",
                                dut_id,
                            )

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
                await log_filtered_ids(
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

                    # Get firmware inventory from dynamic discovery
                    firmware_inventory = await self.get_discovered_firmware_inventory(
                        dut_id
                    )

                    if firmware_inventory:
                        # Get the actual components dict
                        fw_components = firmware_inventory.get("components", {})
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Found {len(fw_components)} firmware inventory components: {list(fw_components.keys())}",
                            dut_id,
                        )

                        # Get patterns for this device type
                        patterns_for_type = []
                        if device_type in device_patterns:
                            patterns_for_type = device_patterns[device_type]
                        elif f"{device_type}_patterns" in device_patterns:
                            patterns_for_type = device_patterns[
                                f"{device_type}_patterns"
                            ]
                        else:
                            # Attempt to normalize keys like "gpu_patterns" or "gpu" in the override
                            legacy_key = f"{device_type}_patterns"
                            if legacy_key in baseboard_device_patterns:
                                override = baseboard_device_patterns[legacy_key]
                                if isinstance(override, (list, tuple, set)):
                                    baseboard_device_patterns.setdefault(
                                        device_type, []
                                    )
                                    baseboard_device_patterns[device_type].extend(
                                        list(override)
                                    )
                                    patterns_for_type = baseboard_device_patterns[
                                        device_type
                                    ]
                                elif isinstance(override, dict):
                                    device_patterns[device_type] = list(
                                        override.get("override", [])
                                    )
                                    device_patterns.setdefault(device_type, []).extend(
                                        list(override.get("append", []))
                                    )
                                    patterns_for_type = device_patterns[device_type]
                                else:
                                    baseboard_device_patterns[device_type] = [
                                        str(override)
                                    ]
                                    patterns_for_type = baseboard_device_patterns[
                                        device_type
                                    ]

                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"Matching firmware inventory components against patterns for {device_type}: {patterns_for_type}",
                            dut_id,
                        )

                        # Match firmware inventory components against patterns
                        for fw_component_id in fw_components.keys():
                            for pattern_str in patterns_for_type:
                                try:
                                    pattern = re.compile(pattern_str)
                                    match = pattern.match(fw_component_id)
                                    if match:
                                        device_id = int(match.group(1))
                                        device_ids.add(device_id)
                                        await self._log_runtime(
                                            "INFO",
                                            "RedfishService",
                                            f"✓ Matched {device_type} device ID {device_id} from firmware inventory component '{fw_component_id}' using pattern '{pattern_str}'",
                                            dut_id,
                                        )
                                        break  # Found match, move to next component
                                    else:
                                        await self._log_runtime(
                                            "DEBUG",
                                            "RedfishService",
                                            f"  Component '{fw_component_id}' did not match pattern '{pattern_str}'",
                                            dut_id,
                                        )
                                except (ValueError, IndexError, re.error) as e:
                                    await self._log_runtime(
                                        "WARNING",
                                        "RedfishService",
                                        f"Error processing firmware inventory pattern {pattern_str} for component {fw_component_id}: {e}",
                                        dut_id,
                                    )

                        # If we found devices via firmware inventory, skip chassis-based discovery
                        if device_ids:
                            await self._log_runtime(
                                "INFO",
                                "RedfishService",
                                f"✓ Found {len(device_ids)} {device_type} devices via firmware inventory, skipping chassis-based discovery",
                                dut_id,
                            )
                            # Store and continue to next device type
                            device_ids_list = sorted(list(device_ids))
                            device_ids_list = _apply_num_gpus_filter(
                                device_type, device_ids_list
                            )
                            discovered_devices[device_type] = device_ids_list
                            await self._log_runtime(
                                "INFO",
                                "RedfishService",
                                f"Discovered {len(device_ids_list)} {device_type} devices: {device_ids_list}",
                                dut_id,
                            )
                            continue  # Skip chassis-based discovery for this device type
                        else:
                            await self._log_runtime(
                                "WARNING",
                                "RedfishService",
                                f"No {device_type} devices found via firmware inventory (checked {len(fw_components)} components), falling back to chassis-based discovery",
                                dut_id,
                            )
                    else:
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"No firmware inventory available, falling back to chassis-based discovery for {device_type}",
                            dut_id,
                        )

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
                device_ids_list = _apply_num_gpus_filter(device_type, device_ids_list)
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
        await self._start_redfish_request_capture(dut_id, kwargs.get("collector_id"))
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

    async def _create_standardized_collector_result(
        self,
        successful_operations: int,
        total_operations: int,
        output_files: List[str] = None,
        error_messages: List[str] = None,
        operation_name: str = "operations",
        additional_context: Dict[str, Any] = None,
        dut_id: str = None,
        collector_id: str = None,
    ) -> Dict[str, Any]:
        """Create a standardized collector result and attach Redfish request capture metadata."""
        resolved_dut_id = dut_id or self._get_current_dut_id()
        resolved_collector_id = collector_id or self._get_current_collector_id()
        result: Optional[Dict[str, Any]] = None
        parent_exception: Optional[Exception] = None

        try:
            result = await super()._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name=operation_name,
                additional_context=additional_context,
                dut_id=dut_id,
                collector_id=collector_id,
            )
        except Exception as exc:
            parent_exception = exc
        finally:
            try:
                attached_result = await self._attach_redfish_request_capture(
                    resolved_dut_id, result, resolved_collector_id
                )
                if attached_result is not None:
                    result = attached_result
            except Exception as attach_exc:
                if parent_exception is None:
                    raise
                await self._log_runtime(
                    "WARN",
                    "RedfishService",
                    (
                        "Failed to attach Redfish request capture while handling "
                        f"collector result exception: {attach_exc}"
                    ),
                    resolved_dut_id,
                )

        if parent_exception is not None:
            raise parent_exception

        return result

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
        collector_id = kwargs.get("collector_id", collector_name)
        try:
            await self._log_collector_start(
                dut_id, collector_name, collector_id=collector_id
            )

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
        finally:
            await self._clear_redfish_request_capture(dut_id, collector_id)

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
        if not collector_id:
            collector_id = await self._get_original_collector_id(
                dut_id, self._get_current_collector_id()
            )
        if (
            not output_pattern
            and isinstance(function_tag, str)
            and function_tag.endswith(".json")
        ):
            output_pattern = function_tag
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
                    # Use the logger's create_collector_log_file to get the collector base directory.
                    # Pass only the basename so that create_collector_log_file doesn't create a
                    # subdirectory itself — the full relative path (e.g. "DGX/foo.tar.xz") is
                    # resolved from temp_file_path.parent below, avoiding a double "DGX/DGX/" nesting.
                    temp_file_path = await self.logger.create_collector_log_file(
                        dut_id, group, collector_id, Path(final_filename).name
                    )
                    file_path = temp_file_path.parent / final_filename

                    # Ensure parent directory exists (supports subdirectories in output_pattern)
                    os.makedirs(file_path.parent, exist_ok=True)

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
                    "Platform detection: DUT config not accessible",
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
                file_path = await self.logger.create_collector_log_file(
                    dut_id, group, file_collector_id, filename
                )
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
        Wait for a Redfish task to complete (matching legacy behavior).

        Args:
            dut_id: DUT ID.
            task_id: Task ID.
            max_retries: Maximum retry attempts.
            entity_context: Optional entity context.
            **kwargs: Additional arguments.

        Returns:
            Task completion data or None if failed.
        """
        collector_id = kwargs.get("collector_id", "unknown")

        try:
            task_service_uri = self.get_configured_uri(dut_id, "TaskService")
            task_uri = f"{task_service_uri}/Tasks/{task_id}"
            retry_interval = 30
            total_timeout = max_retries * retry_interval

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"[{collector_id}] Starting task monitoring for {task_id} ({max_retries} retries, {total_timeout}s timeout)",
                dut_id,
            )

            await asyncio.sleep(2)

            test_success, test_response, _ = await self.dispatch_request(
                dut_id, "GET", task_uri, bypass_cache=True
            )
            if not test_success:
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"Task URI {task_uri} is not accessible: {test_response}",
                    dut_id,
                )
                return None

            prev_state = None
            prev_percent = None

            for attempt in range(max_retries):
                try:
                    success, response, _ = await self.dispatch_request(
                        dut_id, "GET", task_uri, bypass_cache=True
                    )
                except Exception as e:
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Task {task_id} poll error (attempt {attempt + 1}/{max_retries}): {type(e).__name__}: {e}",
                        dut_id,
                    )
                    success = False
                    response = None

                if not success:
                    await self._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"Task {task_id} poll failed (attempt {attempt + 1}/{max_retries})",
                        dut_id,
                    )
                    if isinstance(response, str) and any(
                        kw in response.lower()
                        for kw in [
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
                            f"Task {task_id} critical failure: {response}",
                            dut_id,
                        )
                        return None
                    await asyncio.sleep(retry_interval)
                    continue

                # Log full response at DEBUG only
                try:
                    if isinstance(response, bytes):
                        response_log = f"<binary data, {len(response)} bytes>"
                    else:
                        response_log = json.dumps(response, indent=2)
                except (TypeError, ValueError):
                    response_log = f"<unable to serialize: {type(response)}>"
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Task {task_id} response (attempt {attempt + 1}): {response_log}",
                    dut_id,
                )

                # Save intermediate status to metadata
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

                if not isinstance(response, dict) or "TaskState" not in response:
                    await self._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"Task {task_id} malformed response (attempt {attempt + 1}/{max_retries})",
                        dut_id,
                    )
                    await asyncio.sleep(retry_interval)
                    continue

                task_state = response.get("TaskState", "")
                task_status = response.get("TaskStatus", "")
                percent_complete = response.get("PercentComplete", "")

                # Log one line per poll: only when state or progress changes, or every 5th attempt
                state_changed = (
                    task_state != prev_state or percent_complete != prev_percent
                )
                periodic = (attempt + 1) % 5 == 0
                if state_changed or periodic or attempt == 0:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Task {task_id} attempt {attempt + 1}/{max_retries}: {task_state}, {percent_complete}% complete",
                        dut_id,
                    )
                prev_state = task_state
                prev_percent = percent_complete

                # Completion states
                if task_state in [
                    "Completed",
                    "Succeeded",
                    "Done",
                    "Completed with Warnings",
                ]:
                    label = (
                        "completed"
                        if task_state == "Completed"
                        else f"completed ({task_state})"
                    )
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Task {task_id} {label} after {attempt + 1} attempts",
                        dut_id,
                    )

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

                # Terminal failure states
                if task_state in ["Failed", "Cancelled", "Exception", "Aborted"]:
                    error_details = []
                    if "Messages" in response:
                        try:
                            messages = response["Messages"]
                            if isinstance(messages, bytes):
                                error_details.append(
                                    f"Messages: <binary, {len(messages)} bytes>"
                                )
                            else:
                                error_details.append(
                                    f"Messages: {json.dumps(messages, indent=2)}"
                                )
                        except Exception:
                            error_details.append("Messages: [serialization error]")
                    if task_status:
                        error_details.append(f"TaskStatus: {task_status}")

                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Task {task_id} failed ({task_state}) after {attempt + 1} attempts. {'; '.join(error_details) if error_details else ''}",
                        dut_id,
                    )
                    return None

                # Still running — sleep before next poll
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_interval)

            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Task {task_id} timed out after {total_timeout}s ({max_retries} retries)",
                dut_id,
            )
            return None

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Task {task_id} monitoring exception: {type(e).__name__}: {e}",
                dut_id,
            )
            return None

    async def _get_dump_location(
        self, task_response: Dict[str, Any], dut_id: str = None, attachment: bool = True
    ) -> Optional[str]:
        """
        Get the log dump location for a redfish task (matching legacy behavior).

        Args:
            task_response: Task response data.
            dut_id: Optional DUT ID.
            attachment: Whether to append attachment path.

        Returns:
            Dump location URI or None if not found.
        """
        try:
            # Get location from HttpHeaders like legacy code
            resp_headers = task_response.get("Payload", {}).get("HttpHeaders", [])
            dump_location = ""

            for header in resp_headers:
                header_name, separator, header_value = str(header).partition(":")
                if separator and header_name.strip().lower() == "location":
                    dump_location = header_value.strip()
                    if attachment:
                        if dump_location.endswith("/attachment"):
                            await self._log_runtime(
                                "DEBUG",
                                "RedfishService",
                                f"Using attachment URI from task Location header: {dump_location}",
                                dut_id,
                            )
                            break

                        # Fetch the URI to get AdditionalDataURI like legacy
                        success, resp, _ = await self.dispatch_request(
                            dut_id, "GET", dump_location, bypass_cache=True
                        )
                        if (
                            success
                            and isinstance(resp, dict)
                            and resp.get("AdditionalDataURI")
                        ):
                            dump_location = resp["AdditionalDataURI"]
                        else:
                            # Fall back to previous default like legacy
                            if not dump_location.endswith("/attachment"):
                                dump_location = dump_location + "/attachment"
                            await self._log_runtime(
                                "DEBUG",
                                "RedfishService",
                                f"No AdditionalDataURI found; using fallback attachment URI: {dump_location}",
                                dut_id,
                            )
                    break

            if dump_location:
                return dump_location

            # Fallback: DiagnosticLog endpoint (e.g. Managers/BMC/LogServices/DiagnosticLog)
            # embeds the attachment URI in Messages[*].MessageArgs rather than HttpHeaders.
            # Example MessageId: "Ami.1.0.0.DiagnosticDumpCreated"
            messages = task_response.get("Messages", [])
            for msg in messages:
                args = msg.get("MessageArgs", [])
                if args and str(args[0]).startswith("/redfish/"):
                    dump_location = args[0]
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Found dump location in Messages.MessageArgs: {dump_location}",
                        dut_id,
                    )
                    return dump_location

            return None
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception getting dump location: {str(e)}",
                dut_id,
            )
            return None

    @staticmethod
    def _replace_output_pattern_extension(
        output_pattern: str, new_extension: str
    ) -> str:
        """Replace common artifact extensions while preserving directories/templates."""
        if not output_pattern:
            return output_pattern

        known_suffixes = (
            ".tar.gz",
            ".tgz",
            ".tar.xz",
            ".txz",
            ".tar.bz2",
            ".tbz2",
            ".zip",
            ".gz",
            ".xz",
            ".bin",
            ".txt",
            ".json",
        )
        for suffix in known_suffixes:
            if output_pattern.lower().endswith(suffix):
                return output_pattern[: -len(suffix)] + new_extension
        return output_pattern + new_extension

    def _prepare_downloaded_dump_for_save(
        self, dump_data: Any, output_pattern: str
    ) -> Tuple[Any, str, str, int]:
        """
        Classify downloaded Redfish dump content before saving.

        Some Redfish attachment endpoints return JSON even though the collector
        output pattern is archive-shaped. Preserve binary/archive payloads, but
        save JSON payloads as JSON with a matching extension.
        """
        if not isinstance(dump_data, bytes):
            data_size = len(dump_data) if hasattr(dump_data, "__len__") else 0
            data_type = "json" if isinstance(dump_data, (dict, list)) else "text"
            return dump_data, data_type, output_pattern, data_size

        data_size = len(dump_data)
        stripped = dump_data.lstrip()
        if stripped.startswith((b"{", b"[")):
            try:
                parsed_json = json.loads(dump_data.decode("utf-8-sig"))
                return (
                    parsed_json,
                    "json",
                    self._replace_output_pattern_extension(output_pattern, ".json"),
                    data_size,
                )
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass

        return dump_data, "binary", output_pattern, data_size

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

    @staticmethod
    def _split_path_tokens(path: str) -> List[Union[str, int]]:
        """
        Split a dot/bracket notation path into tokens that can be used
        for nested dictionary/list traversal.

        Supports patterns like "Members[0].@odata.id" or "Location[0].Uri".
        """
        if not path:
            return []

        tokens: List[Union[str, int]] = []
        buffer: List[str] = []
        i = 0
        length = len(path)

        while i < length:
            char = path[i]

            if char == "[":
                end_idx = path.find("]", i)
                if end_idx == -1:
                    buffer.append(char)
                    i += 1
                    continue

                # Flush current buffer as string token
                if buffer:
                    tokens.append("".join(buffer))
                    buffer.clear()

                index_str = path[i + 1 : end_idx]
                if index_str.isdigit():
                    tokens.append(int(index_str))

                i = end_idx + 1
                continue

            if char == ".":
                if buffer and "@" in buffer:
                    buffer.append(char)
                else:
                    if buffer:
                        tokens.append("".join(buffer))
                        buffer.clear()
                i += 1
                continue

            buffer.append(char)
            i += 1

        if buffer:
            tokens.append("".join(buffer))

        return tokens

    def _extract_nested_value(self, data: Any, path: Any) -> Any:
        """
        Extract nested value from dictionary or list using dot/bracket notation path
        or an explicit token list.

        Args:
            data: Dictionary or list to search.
            path: Dot/bracket notation path to value, or a list/tuple of path tokens.

        Returns:
            Extracted value or None if not found.
        """
        if data is None or path is None:
            return None

        if isinstance(path, (list, tuple)):
            tokens = list(path)
        else:
            tokens = self._split_path_tokens(path)
        current: Any = data

        for token in tokens:
            if isinstance(token, int):
                if isinstance(current, list) and 0 <= token < len(current):
                    current = current[token]
                else:
                    return None
            else:
                if isinstance(current, dict) and token in current:
                    current = current[token]
                else:
                    return None

        return current

    @staticmethod
    def _resolve_placeholder(value: Any, context: Dict[str, Any]) -> Any:
        """
        Resolve simple ${var_name} placeholders using the provided context.

        Args:
            value: Original value (string with placeholder or other types).
            context: Context dictionary for variable substitution.

        Returns:
            Resolved value if placeholder is found, otherwise original value.
        """
        if isinstance(value, str):
            if value.startswith("${") and value.endswith("}"):
                key = value[2:-1]
                return context.get(key, value)
        return value

    def _get_dut_baseboard_name(self, dut_id: str) -> Optional[str]:
        """
        Helper to fetch baseboard name for a DUT.
        """
        try:
            dut = None
            if hasattr(self, "dut_manager") and self.dut_manager:
                dut = self.dut_manager.get_dut(dut_id)
            if dut and hasattr(dut, "config"):
                return dut.config.get("baseboard")

            # Fallback to DUT config lookup
            dut_config = (
                self.dut_manager.get_dut_config(dut_id)
                if hasattr(self, "dut_manager")
                else {}
            )
            return dut_config.get("baseboard")
        except Exception:
            return None

    async def _should_apply_dynamic_discovery(
        self,
        dut_id: str,
        collector_name: str,
        collector_id: str,
        function_tag: str,
        discovery_config: Dict[str, Any],
        collector_def: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Determine whether a dynamic discovery entry should be applied for the DUT.
        """
        apply_when = discovery_config.get("apply_when")
        baseboard_name = self._get_dut_baseboard_name(dut_id)

        if not apply_when:
            return True, baseboard_name

        # Collector ID filter
        collector_ids = apply_when.get("collector_ids")
        if collector_ids and collector_id not in collector_ids:
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Dynamic discovery skipped for {collector_name}: collector_id '{collector_id}' not in {collector_ids}",
                dut_id,
            )
            return False, baseboard_name

        # Function tag filter
        function_tags = apply_when.get("function_tags")
        if function_tags and function_tag not in function_tags:
            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Dynamic discovery skipped for {collector_name}: function tag '{function_tag}' not in {function_tags}",
                dut_id,
            )
            return False, baseboard_name

        applicable_baseboards: List[str] = []
        if collector_def:
            collector_applicable = collector_def.get("applicable_baseboards")
            if isinstance(collector_applicable, list):
                applicable_baseboards = collector_applicable
            elif isinstance(collector_applicable, str):
                if collector_applicable.lower() != "all":
                    applicable_baseboards = [collector_applicable]

        baseboards = apply_when.get("baseboards")
        if (
            not baseboards
            and apply_when.get("use_applicable_baseboards")
            and applicable_baseboards
        ):
            baseboards = applicable_baseboards

        if baseboards:
            if not baseboard_name:
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Dynamic discovery skipped for {collector_name}: baseboard unknown, required one of {baseboards}",
                    dut_id,
                )
                return False, baseboard_name
            if baseboard_name not in baseboards:
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Dynamic discovery skipped for {collector_name}: baseboard '{baseboard_name}' not in {baseboards}",
                    dut_id,
                )
                return False, baseboard_name

        baseboard_groups = apply_when.get("baseboard_groups")
        if (
            not baseboard_groups
            and apply_when.get("use_applicable_baseboard_groups")
            and applicable_baseboards
        ):
            derived_groups: List[str] = []
            baseboard_manager = None
            if (
                hasattr(self, "dut_manager")
                and self.dut_manager
                and hasattr(self.dut_manager, "_get_baseboard_manager")
            ):
                baseboard_manager = self.dut_manager._get_baseboard_manager()

            if baseboard_manager:
                for candidate in applicable_baseboards:
                    group_name = baseboard_manager.get_baseboard_type(candidate)
                    if group_name:
                        derived_groups.append(group_name)

            if derived_groups:
                baseboard_groups = derived_groups

        if baseboard_groups:
            if not baseboard_name:
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Dynamic discovery skipped for {collector_name}: baseboard unknown, required group in {baseboard_groups}",
                    dut_id,
                )
                return False, baseboard_name

            baseboard_manager = None
            if (
                hasattr(self, "dut_manager")
                and self.dut_manager
                and hasattr(self.dut_manager, "_get_baseboard_manager")
            ):
                baseboard_manager = self.dut_manager._get_baseboard_manager()

            baseboard_type = None
            if baseboard_manager:
                baseboard_type = baseboard_manager.get_baseboard_type(baseboard_name)
            elif hasattr(self, "dut_manager") and self.dut_manager:
                dut_config = self.dut_manager.get_dut_config(dut_id)
                baseboard_type = dut_config.get("baseboard_type")

            if baseboard_type not in baseboard_groups:
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    (
                        f"Dynamic discovery skipped for {collector_name}: baseboard "
                        f"'{baseboard_name}' (type={baseboard_type}) not in groups {baseboard_groups}"
                    ),
                    dut_id,
                )
                return False, baseboard_name

        return True, baseboard_name

    def _apply_discovered_value(
        self,
        current_value: Optional[Union[str, List[str]]],
        discovered_value: Optional[Union[str, List[str]]],
        behavior: str,
        deduplicate: bool = False,
    ) -> Optional[Union[str, List[str]]]:
        """
        Apply discovered value to existing configuration using the specified behavior.
        """
        if discovered_value is None:
            return current_value

        if behavior == "append":

            def _normalize_to_list(value: Optional[Any]) -> List[str]:
                if value is None:
                    return []
                if isinstance(value, list):
                    return list(value)
                if isinstance(value, str):
                    return [value]
                return [str(value)]

            combined: List[str] = _normalize_to_list(current_value)
            combined.extend(_normalize_to_list(discovered_value))

            if deduplicate:
                seen = set()
                deduped: List[str] = []
                for item in combined:
                    if item not in seen:
                        seen.add(item)
                        deduped.append(item)
                combined = deduped

            if not combined:
                return None

            should_return_list = (
                isinstance(current_value, list)
                or isinstance(discovered_value, list)
                or len(combined) != 1
            )

            return combined if should_return_list else combined[0]

        # Default to override behavior
        return discovered_value

    async def _perform_dynamic_uri_discovery(
        self,
        dut_id: str,
        collector_name: str,
        discovery_config: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Optional[Union[str, List[str]]]:
        """
        Execute a dynamic URI discovery workflow based on configuration.
        """
        strategy = discovery_config.get("strategy", "registry_member")
        config_name = discovery_config.get("name") or strategy

        await self._log_runtime(
            "DEBUG",
            "RedfishService",
            f"Starting dynamic URI discovery '{config_name}' using strategy '{strategy}'",
            dut_id,
        )

        if strategy != "registry_member":
            await self._log_runtime(
                "WARNING",
                "RedfishService",
                f"Unsupported dynamic discovery strategy '{strategy}' for {collector_name}",
                dut_id,
            )
            return None

        base_uri = self._resolve_placeholder(
            discovery_config.get("base_uri", "/redfish/v1/Registries"), context
        )
        if not isinstance(base_uri, str) or not base_uri:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Dynamic discovery '{config_name}' missing valid base_uri",
                dut_id,
            )
            return None

        bypass_cache = discovery_config.get("bypass_cache", True)
        success, registries_data, _ = await self.dispatch_request(
            dut_id, "GET", base_uri, bypass_cache=bypass_cache
        )

        if not success or not isinstance(registries_data, dict):
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                (
                    f"Dynamic discovery '{config_name}' failed to fetch base URI {base_uri}: "
                    f"{registries_data}"
                ),
                dut_id,
            )
            return None

        members_path = discovery_config.get("members_path", "Members")
        members = (
            registries_data.get("Members")
            if members_path in (None, "", "Members")
            else self._extract_nested_value(registries_data, members_path)
        )

        if not isinstance(members, list):
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                (
                    f"Dynamic discovery '{config_name}' expected a list at path '{members_path}' "
                    f"but received {type(members).__name__}"
                ),
                dut_id,
            )
            return None

        match_field = discovery_config.get("match_field", "@odata.id")
        match_type = discovery_config.get("match_type", "contains").lower()
        match_value_config = discovery_config.get("match_value")
        match_values_config = discovery_config.get("match_values")

        resolved_match_values: List[str] = []
        if match_values_config:
            if isinstance(match_values_config, list):
                for val in match_values_config:
                    resolved = self._resolve_placeholder(val, context)
                    if isinstance(resolved, str):
                        resolved_match_values.append(resolved)
        elif match_value_config:
            resolved = self._resolve_placeholder(match_value_config, context)
            if isinstance(resolved, str):
                resolved_match_values.append(resolved)

        match_regex = discovery_config.get("match_regex")
        match_case_insensitive = discovery_config.get("case_insensitive", True)
        return_multiple = discovery_config.get("return_multiple", False)

        discovered_results: List[str] = []

        for member in members:
            if not isinstance(member, dict):
                continue

            candidate_value = self._extract_nested_value(member, match_field)
            if candidate_value is None:
                continue

            if isinstance(candidate_value, str) and match_case_insensitive:
                candidate_compare = candidate_value.lower()
            else:
                candidate_compare = candidate_value

            matched = False

            if match_regex:
                regex_flags = re.IGNORECASE if match_case_insensitive else 0
                if isinstance(candidate_value, str) and re.search(
                    match_regex, candidate_value, flags=regex_flags
                ):
                    matched = True
            elif resolved_match_values:
                compare_values = (
                    [v.lower() for v in resolved_match_values]
                    if match_case_insensitive
                    else resolved_match_values
                )
                if isinstance(candidate_compare, str):
                    if match_type == "equals":
                        matched = candidate_compare in compare_values
                    else:  # default contains behavior
                        matched = any(
                            val in candidate_compare for val in compare_values
                        )
                else:
                    matched = candidate_compare in compare_values
            else:
                # No explicit match criteria specified; treat as automatic match
                matched = True

            if not matched:
                continue

            follow_up_config = discovery_config.get("follow_up")
            final_value: Optional[Union[str, List[str]]] = None

            if follow_up_config:
                request_path = follow_up_config.get("request_path", "@odata.id")
                request_uri = self._extract_nested_value(member, request_path)

                if not isinstance(request_uri, str):
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        (
                            f"Dynamic discovery '{config_name}' could not resolve follow-up URI "
                            f"using path '{request_path}'"
                        ),
                        dut_id,
                    )
                    continue

                request_method = follow_up_config.get("method", "GET").upper()
                follow_bypass_cache = follow_up_config.get("bypass_cache", True)

                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    (
                        f"Dynamic discovery '{config_name}' follow-up request: "
                        f"{request_method} {request_uri}"
                    ),
                    dut_id,
                )

                follow_success, follow_data, _ = await self.dispatch_request(
                    dut_id,
                    request_method,
                    request_uri,
                    bypass_cache=follow_bypass_cache,
                )

                if not follow_success or not isinstance(follow_data, (dict, list)):
                    await self._log_runtime(
                        "ERROR",
                        "RedfishService",
                        (
                            f"Dynamic discovery '{config_name}' follow-up request failed: "
                            f"{follow_data}"
                        ),
                        dut_id,
                    )
                    continue

                value_path = follow_up_config.get("value_path")
                if value_path:
                    final_value = self._extract_nested_value(follow_data, value_path)
                else:
                    final_value = follow_data
            else:
                value_path = discovery_config.get("value_path", match_field)
                final_value = self._extract_nested_value(member, value_path)

            if isinstance(final_value, list) and not final_value:
                final_value = None

            if final_value is None:
                await self._log_runtime(
                    "WARNING",
                    "RedfishService",
                    (
                        f"Dynamic discovery '{config_name}' matched entry but could not extract "
                        f"final value using configured paths."
                    ),
                    dut_id,
                )
                continue

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Dynamic discovery '{config_name}' produced value: {final_value}",
                dut_id,
            )

            discovered_results.append(final_value)  # type: ignore[arg-type]

            if not return_multiple:
                break

        if not discovered_results:
            await self._log_runtime(
                "WARNING",
                "RedfishService",
                f"Dynamic discovery '{config_name}' did not yield any results",
                dut_id,
            )
            return None

        if return_multiple:
            flattened: List[str] = []
            for item in discovered_results:
                if isinstance(item, list):
                    flattened.extend(item)
                else:
                    flattened.append(item)  # type: ignore[arg-type]
            return flattened

        return discovered_results[0]

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

    async def _build_redfish_time_filter(self, dut_id: str) -> str:
        """
        Build a Redfish OData $filter string for time-window filtering
        based on the normalized streaming window.

        Returns empty string if no time window is configured.
        """
        if not self.orchestrator or not self.orchestrator.config_manager:
            return ""
        try:
            tool_config = self.orchestrator.config_manager.get_tool_config()
            if not tool_config.get("streaming_only", False):
                return ""

            stream_begin, stream_end = normalize_stream_window(
                tool_config.get("stream_begin", "24"),
                tool_config.get("stream_end", "0"),
            )
            return (
                "$filter="
                f"Created ge '{format_redfish_stream_timestamp(stream_begin)}' and "
                f"Created le '{format_redfish_stream_timestamp(stream_end)}'"
            )
        except Exception as e:
            await self._log_runtime(
                "WARNING",
                "RedfishService",
                f"Failed to build time filter: {e}",
                dut_id,
            )
            return ""

    async def _append_streaming_time_filter(self, dut_id: str, uri: str) -> str:
        """Append the normalized Redfish time filter to a URI."""
        time_filter = await self._build_redfish_time_filter(dut_id)
        if not time_filter:
            return uri
        separator = "&" if "?" in uri else "?"
        return f"{uri}{separator}{time_filter}"

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
        collector_id: str = "",
        collector_name: str = "",
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

            # Get possible source directories from processing config.
            # For derived collectors (for example R21 CPER), configured source
            # directories must win over the current collector directory; the
            # current collector directory may already exist but be empty.
            possible_source_dirs = []
            if processing_config and "possible_source_directories" in processing_config:
                possible_source_dirs.extend(
                    processing_config["possible_source_directories"]
                )
            else:
                if collector_id and collector_name:
                    possible_source_dirs.append(
                        f"Redfish_{collector_id}_{collector_name}"
                    )

                # Fallback to default patterns for older collectors.
                possible_source_dirs.extend(
                    [
                        f"Redfish_{source_logs}",
                        f"Redfish_{source_logs.replace('_', '')}",
                    ]
                )

            possible_source_dirs = list(dict.fromkeys(possible_source_dirs))

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

    async def _capture_task_service_snapshot(
        self,
        dut_id: str,
        function_tag: str,
        collector_id: str,
        entity_type: str,
        entity_id: str,
        log_service: str,
        reason: str,
        task_id: Optional[str] = None,
        payload: Optional[Any] = None,
        diagnostic_type: Optional[str] = None,
        extra_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Capture the TaskService state when a dump request fails and save it to a JSON file.

        Args:
            dut_id: DUT identifier.
            function_tag: Function tag associated with the collector.
            collector_id: Collector identifier.
            entity_type: Redfish entity type (Systems, Managers, etc.).
            entity_id: Specific entity identifier.
            log_service: Log service being used.
            reason: Reason for capturing the snapshot.
            task_id: Task identifier if available.
            payload: Request payload associated with the dump request.
            diagnostic_type: Diagnostic type used for the request.
            extra_context: Additional context information to persist.

        Returns:
            Path to the snapshot file or None if capture failed.
        """
        try:
            timestamp = datetime.now()
            timestamp_iso = timestamp.isoformat()
            timestamp_label = timestamp.strftime("%Y%m%dT%H%M%S")

            entity_component = f"{entity_type or 'entity'}_{entity_id or 'unknown'}"
            entity_label = re.sub(r"[^A-Za-z0-9_.-]", "_", entity_component) or "entity"

            task_component = str(task_id) if task_id else "no_task_id"
            task_label = re.sub(r"[^A-Za-z0-9_.-]", "_", task_component) or "no_task_id"
            if len(task_label) > 48:
                task_label = task_label[:48]

            task_service_uri = None
            tasks_uri = None
            tasks_response: Optional[Any] = None
            tasks_error: Optional[Any] = None
            task_details: List[Dict[str, Any]] = []

            try:
                task_service_uri = self.get_configured_uri(dut_id, "TaskService")
                if task_service_uri:
                    tasks_uri = f"{task_service_uri}/Tasks"
                    tasks_success, tasks_resp_raw, _ = await self.dispatch_request(
                        dut_id, "GET", tasks_uri, bypass_cache=True
                    )
                    if tasks_success:
                        tasks_response = self._sanitize_for_capture(tasks_resp_raw)
                        if isinstance(tasks_resp_raw, dict):
                            for member in tasks_resp_raw.get("Members", []):
                                member_uri = member.get("@odata.id")
                                if not member_uri:
                                    continue
                                if not validate_redfish_uri(member_uri):
                                    continue
                                detail_success, detail_data, _ = (
                                    await self.dispatch_request(
                                        dut_id,
                                        "GET",
                                        member_uri,
                                        bypass_cache=True,
                                    )
                                )
                                detail_entry: Dict[str, Any] = {
                                    "task_uri": member_uri,
                                    "success": detail_success,
                                }
                                if detail_success:
                                    detail_entry["data"] = self._sanitize_for_capture(
                                        detail_data
                                    )
                                else:
                                    detail_entry["error"] = self._sanitize_for_capture(
                                        detail_data
                                    )
                                task_details.append(detail_entry)
                    else:
                        tasks_error = self._sanitize_for_capture(tasks_resp_raw)
                else:
                    tasks_error = "TaskService URI not configured for DUT"
            except Exception as snapshot_exc:
                tasks_error = f"Failed to retrieve tasks: {snapshot_exc}"
                await self._log_runtime(
                    "WARN",
                    "RedfishService",
                    f"Failed to retrieve TaskService snapshot: {snapshot_exc}",
                    dut_id,
                )

            snapshot_payload: Dict[str, Any] = {
                "captured_at": timestamp_iso,
                "reason": reason,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "log_service": log_service,
                "collector_id": collector_id,
                "function_tag": function_tag,
                "task_id": task_id,
                "diagnostic_type": diagnostic_type,
                "payload": (
                    self._sanitize_for_capture(payload) if payload is not None else None
                ),
                "task_service_uri": task_service_uri,
                "tasks_uri": tasks_uri,
                "tasks_response": tasks_response,
                "tasks_response_error": tasks_error,
                "task_details": task_details,
            }

            if extra_context:
                snapshot_payload["additional_context"] = self._sanitize_for_capture(
                    extra_context
                )

            substitutions = {
                "entity_label": entity_label,
                "task_label": task_label,
                "timestamp": timestamp_label,
            }

            file_path = await self._save_data_to_file_with_pattern(
                dut_id,
                snapshot_payload,
                function_tag,
                output_pattern="TaskService_snapshot_{entity_label}_{task_label}_{timestamp}.json",
                substitutions=substitutions,
                collector_id=collector_id,
            )

            if file_path:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"TaskService snapshot captured: {file_path}",
                    dut_id,
                )

            return file_path
        except Exception as e:
            await self._log_runtime(
                "WARN",
                "RedfishService",
                f"Failed to capture TaskService snapshot: {e}",
                dut_id,
            )
            return None

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

            extra_context: Optional[Dict[str, Any]] = {}
            if fallback_index is not None:
                extra_context["fallback_index"] = fallback_index
            if device_id is not None:
                extra_context["device_id"] = device_id
            if device_type_name:
                extra_context["device_type_name"] = device_type_name
            if not extra_context:
                extra_context = None

            # Get timeout from collector definition and DUT config
            collector_def = kwargs.get("collector_def", {})
            dut_config = self.dut_manager.get_dut_config(dut_id)
            tool_config = self.orchestrator.config_manager.get_tool_config()
            timeout_seconds = get_collector_timeout(
                collector_id, collector_def, dut_config, 1500, tool_config
            )

            # Calculate retries based on timeout (like legacy code)
            retry_interval = 30  # seconds, matching legacy default
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
                snapshot_path = await self._capture_task_service_snapshot(
                    dut_id,
                    function_tag,
                    collector_id,
                    entity_type,
                    entity_id,
                    log_service,
                    reason="initiation_failed",
                    payload=payload,
                    diagnostic_type=diagnostic_type,
                    extra_context=extra_context,
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
                if snapshot_path:
                    error_response["context"]["task_service_snapshot"] = snapshot_path
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

                snapshot_path = await self._capture_task_service_snapshot(
                    dut_id,
                    function_tag,
                    collector_id,
                    entity_type,
                    entity_id,
                    log_service,
                    reason="missing_task_id",
                    payload=payload,
                    diagnostic_type=diagnostic_type,
                    extra_context=extra_context,
                )

                error_entry = {
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
                if snapshot_path:
                    error_entry["task_service_snapshot"] = snapshot_path

                # Save the structured error response to array-based file
                await self._append_to_diagnostic_json_array(
                    dut_id,
                    error_entry,
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
                if snapshot_path:
                    error_response["context"]["task_service_snapshot"] = snapshot_path
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return False, "Response did not contain a task ID"

            # Wait for task completion (like legacy get_task_completed)
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

                snapshot_path = await self._capture_task_service_snapshot(
                    dut_id,
                    function_tag,
                    collector_id,
                    entity_type,
                    entity_id,
                    log_service,
                    reason="task_timeout",
                    task_id=task_id,
                    payload=payload,
                    diagnostic_type=diagnostic_type,
                    extra_context=extra_context,
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
                if snapshot_path:
                    error_data["task_service_snapshot"] = snapshot_path
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
                if snapshot_path:
                    error_response["context"]["task_service_snapshot"] = snapshot_path
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return False, f"Task {task_id} did not complete within timeout"

            # Task completion is already saved in _wait_for_task_completion method
            # No need to save it again here

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                "Task completion saved to array-based file",
                dut_id,
            )

            # Get dump location (like legacy get_dump_location)
            dump_location = await self._get_dump_location(task_completed, dut_id)
            if not dump_location:
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"Failed to get dump location for task {task_id}",
                    dut_id,
                )

                snapshot_path = await self._capture_task_service_snapshot(
                    dut_id,
                    function_tag,
                    collector_id,
                    entity_type,
                    entity_id,
                    log_service,
                    reason="no_dump_location",
                    task_id=task_id,
                    payload=payload,
                    diagnostic_type=diagnostic_type,
                    extra_context=extra_context,
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
                if snapshot_path:
                    error_data["task_service_snapshot"] = snapshot_path
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
                        "task_completion": task_completed,
                    },
                }
                if snapshot_path:
                    error_response["context"]["task_service_snapshot"] = snapshot_path
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return False, "Task completed but no dump location found in response"

            # Generate output filename with task_id substitution (like legacy)
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

            data_to_save, data_type, save_output_pattern, data_size = (
                self._prepare_downloaded_dump_for_save(dump_data, final_output_pattern)
            )

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Download attempt result: success={success}, data_type={data_type if success else 'error'}, data_size={data_size if success else 'N/A'}",
                dut_id,
            )

            # Save the dump download response metadata to array-based file
            dump_metadata = {
                "dump_location": dump_location,
                "success": success,
                "data_type": data_type if success else "error",
                "data_size": data_size if success else 0,
                "task_id": task_id,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "log_service": log_service,
                "step": "dump_download",
                "timestamp": datetime.now().isoformat(),
            }
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

                # Write the downloaded artifact using the detected content type.
                file_path = await self._save_data_to_file_with_pattern(
                    dut_id,
                    data_to_save,
                    function_tag,
                    output_pattern=save_output_pattern,
                    substitutions=merged_substitutions,
                    collector_id=collector_id,
                )
                if file_path:
                    dump_metadata["saved_file"] = file_path
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
                return True, file_path
            else:
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
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"Failed to download dump from {dump_location}",
                    dut_id,
                )

                snapshot_path = await self._capture_task_service_snapshot(
                    dut_id,
                    function_tag,
                    collector_id,
                    entity_type,
                    entity_id,
                    log_service,
                    reason="dump_download_failed",
                    task_id=task_id,
                    payload=payload,
                    diagnostic_type=diagnostic_type,
                    extra_context=extra_context,
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
                if snapshot_path:
                    error_data["task_service_snapshot"] = snapshot_path
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
                if snapshot_path:
                    error_response["context"]["task_service_snapshot"] = snapshot_path
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return False, f"Failed to download dump from {dump_location}"

        except Exception as e:
            task_id_for_snapshot = locals().get("task_id")
            snapshot_path = await self._capture_task_service_snapshot(
                dut_id,
                function_tag,
                collector_id,
                entity_type,
                entity_id,
                log_service,
                reason="exception",
                task_id=task_id_for_snapshot,
                payload=payload,
                diagnostic_type=diagnostic_type,
                extra_context=extra_context,
            )

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
            if snapshot_path:
                error_response["context"]["task_service_snapshot"] = snapshot_path
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"{error_response}",
                dut_id,
            )
            return False, f"Exception in dump task execution: {str(e)}"

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
        full_uri = uri

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

            request_capture_info = {
                "method": method,
                "uri": full_uri,
                "original_uri": uri,
                "body": body,
                "timeout": timeout,
                "bypass_cache": bypass_cache,
                "get_raw_content": get_raw_content,
                "retry_count": retry_count,
                "error_context": error_context,
            }

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

                response_capture = {
                    "success": False,
                    "error": error_details,
                }
                if retry_info:
                    response_capture["retry_info"] = retry_info
                if response not in (None, error_details):
                    response_capture["raw_response"] = response
                self._record_request_response(
                    request_capture_info,
                    response_capture,
                )
                await self._record_redfish_request_capture(
                    dut_id,
                    request_capture_info,
                    response_capture,
                    error_details,
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

            response_capture: Dict[str, Any] = {"success": True}
            if get_raw_content and isinstance(response, bytes):
                response_capture["data"] = {
                    "type": "bytes",
                    "length": len(response),
                }
            else:
                response_capture["data"] = response
            if retry_info:
                response_capture["retry_info"] = retry_info

            self._record_request_response(
                request_capture_info,
                response_capture,
            )
            await self._record_redfish_request_capture(
                dut_id,
                request_capture_info,
                response_capture,
            )

            return True, response, {}

        except Exception as e:
            exception_request_capture = {
                "method": method,
                "uri": full_uri,
                "original_uri": uri,
                "body": body,
                "timeout": timeout,
                "bypass_cache": bypass_cache,
                "get_raw_content": get_raw_content,
                "retry_count": retry_count,
                "error_context": error_context,
            }
            exception_response_capture = {
                "success": False,
                "error": {
                    "type": type(e).__name__,
                    "message": str(e),
                },
            }
            self._record_request_response(
                exception_request_capture,
                exception_response_capture,
            )
            await self._record_redfish_request_capture(
                dut_id,
                exception_request_capture,
                exception_response_capture,
            )
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
        get_raw_content: bool = False,
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
                    dut_id,
                    "GET",
                    uri,
                    error_context=error_context,
                    bypass_cache=True,
                    get_raw_content=get_raw_content,
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
        Log Redfish request details similar to legacy code.

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
        Log Redfish response details similar to legacy code.

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

            complete_on_empty_targets = kwargs.get("complete_on_empty_targets", False)
            get_raw_content = kwargs.get("get_raw_content", False)
            # Raw downloads must bypass cache so a prior JSON/text read of the same URI
            # cannot be reused in place of the binary payload.
            bypass_cache = kwargs.get("bypass_cache", False) or get_raw_content

            # If there are no URIs and the collector allows empty targets, treat as complete
            if not uri_list and complete_on_empty_targets:
                return await self._create_standardized_collector_result(
                    dut_id=dut_id,
                    collector_id=kwargs.get("collector_id", function_tag),
                    successful_operations=1,
                    total_operations=1,
                    output_files=[],
                    error_messages=[],
                    operation_name="get_collection",
                    additional_context={
                        "uris_processed": uri_list,
                        "successful_count": 0,
                        "reason": "No URIs to collect; treating as complete (empty targets allowed)",
                    },
                )

            # Phase 1: fetch all responses before writing any files.
            collected = []  # list of (uri, data, extracted_ids)
            for uri in uri_list:
                if kwargs.get("streaming_time_filtered", False):
                    uri = await self._append_streaming_time_filter(dut_id, uri)
                await self._log_collection_start(dut_id, "GET", uri)

                success, data, _ = await self.dispatch_request(
                    dut_id,
                    "GET",
                    uri,
                    get_raw_content=get_raw_content,
                    bypass_cache=bypass_cache,
                )

                if success:
                    extracted_ids = self._extract_entity_id_from_uri(uri)
                    if extracted_ids:
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"Extracted entity IDs from URI: {extracted_ids}",
                            dut_id,
                        )
                    collected.append((uri, data, extracted_ids))
                else:
                    await self._log_collection_failure(dut_id, "GET", uri, str(data))
                    return await self._create_standardized_collector_result(
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id", function_tag),
                        successful_operations=len(collected),
                        total_operations=len(uri_list),
                        output_files=output_files,
                        error_messages=[f"GET request failed: {uri} - {data}"],
                        operation_name="get_collection",
                        additional_context={
                            "uris_processed": uri_list,
                            "successful_count": len(collected),
                        },
                    )

            # Phase 2: write results.
            # When multiple URIs would produce the same filename (output_pattern has no
            # entity placeholder), combine all responses into a single dict keyed by
            # entity ID rather than overwriting on each iteration.
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )
            entity_placeholders = {"system_id", "manager_id", "chassis_id", "entity_id"}
            pattern_str = output_pattern or ""
            needs_combine = len(collected) > 1 and not any(
                f"{{{p}}}" in pattern_str for p in entity_placeholders
            )

            if needs_combine:
                combined = {}
                for uri, data, extracted_ids in collected:
                    key = (
                        extracted_ids.get("system_id")
                        or extracted_ids.get("manager_id")
                        or extracted_ids.get("chassis_id")
                        or uri
                    )
                    combined[key] = data

                file_path = await self._save_data_with_common_pattern(
                    dut_id,
                    combined,
                    f"{function_tag}_response",
                    output_pattern=output_pattern,
                    substitutions=substitutions.copy(),
                    **filtered_kwargs,
                )
                if file_path:
                    output_files.append(file_path)
                    for uri, _, _ in collected:
                        await self._log_collection_success(
                            dut_id, "GET", uri, file_path
                        )
            else:
                for uri, data, extracted_ids in collected:
                    subs = substitutions.copy()
                    subs.update(extracted_ids)
                    file_path = await self._save_data_with_common_pattern(
                        dut_id,
                        data,
                        f"{function_tag}_response",
                        output_pattern=output_pattern,
                        substitutions=subs,
                        **filtered_kwargs,
                    )
                    if file_path:
                        output_files.append(file_path)
                        await self._log_collection_success(
                            dut_id, "GET", uri, file_path
                        )

            # When combining, every collected response is a success even though they
            # produced a single output file. Count responses, not files.
            successful_ops = len(collected) if needs_combine else len(output_files)
            return await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=kwargs.get("collector_id", function_tag),
                successful_operations=successful_ops,
                total_operations=len(uri_list),
                output_files=output_files,
                error_messages=[],
                operation_name="get_collection",
                additional_context={
                    "uris_processed": uri_list,
                    "successful_count": successful_ops,
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
        entity_type = kwargs.get("entity_type")

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

                # Legacy support for backward compatibility
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

            # Generate filename based on URI (matching legacy behavior)
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
        partial_collections = []
        member_successes = 0
        member_failures = 0
        additional_member_successes = 0
        additional_member_failures = 0
        linked_member_successes = 0
        linked_member_failures = 0

        # Define collection name for summary generation (matching host service pattern)
        collection_name = f"{function_tag} Collection"

        complete_on_empty_targets = kwargs.get("complete_on_empty_targets", False)
        if not uri_list and complete_on_empty_targets:
            reason_msg = (
                f"No collection_with_members targets found for {function_tag}; "
                "treating as complete"
            )
            await self._log_runtime(
                "INFO",
                "RedfishService",
                reason_msg,
                dut_id,
            )
            result = await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=kwargs.get("collector_id", function_tag),
                successful_operations=1,
                total_operations=1,
                output_files=[],
                error_messages=[],
                operation_name="collection_with_members",
                additional_context={
                    "collections_processed": 0,
                    "successful_collections": [],
                    "partial_collections": [],
                    "failed_collections": [],
                    "status": "success",
                    "reason": reason_msg,
                },
            )
            result["status_override"] = "success"
            result["reason_override"] = reason_msg
            return result

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

        def _append_output_suffix(pattern: str, suffix: str) -> str:
            """Append a suffix before the filename extension when present."""
            if not suffix:
                return pattern
            if "." in pattern:
                stem, extension = pattern.rsplit(".", 1)
                return f"{stem}{suffix}.{extension}"
            return f"{pattern}{suffix}"

        for collection_uri in uri_list:
            await self._log_collection_start(dut_id, "collection", collection_uri)

            # Add small delay between requests to prevent BMC overload
            if (
                len(successful_collections) > 0
                or len(partial_collections) > 0
                or len(failed_collections) > 0
            ):
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

            collection_saved = False
            collection_has_nested_failures = False

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
                    collection_saved = True
                    await self._log_collection_success(
                        dut_id,
                        "collection",
                        collection_uri,
                        f"Created {len(table_files)} table files",
                    )
                else:
                    error_msg = f"Collection save failed for {collection_uri}: no table files created"
                    failed_collections.append(error_msg)
                    collection_has_nested_failures = True
                    await self._log_collection_failure(
                        dut_id, "collection", collection_uri, "No table files created"
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
                    collection_saved = True
                    await self._log_collection_success(
                        dut_id, "collection", collection_uri, collection_file
                    )
                else:
                    error_msg = f"Collection save failed for {collection_uri}: no output file generated"
                    failed_collections.append(error_msg)
                    collection_has_nested_failures = True
                    await self._log_collection_failure(
                        dut_id,
                        "collection",
                        collection_uri,
                        "No output file generated",
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

                    if member_uri and not validate_redfish_uri(member_uri):
                        continue
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
                                member_successes += 1
                                await self._log_collection_success(
                                    dut_id, "member", member_uri, member_file
                                )
                            else:
                                member_failures += 1
                                collection_has_nested_failures = True
                                error_msg = f"Member save failed for {member_uri}: no output file generated"
                                failed_collections.append(error_msg)
                                await self._log_collection_failure(
                                    dut_id,
                                    "member",
                                    member_uri,
                                    "No output file generated",
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
                                        linked_resources = additional_config.get(
                                            "linked_resources", []
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

                                            additional_last_error = additional_data
                                            await self._log_runtime(
                                                "WARNING",
                                                "RedfishService",
                                                f"Additional collection attempt {additional_retry_attempt + 1} failed for {additional_uri}: {additional_data}",
                                                dut_id,
                                            )

                                        if not additional_success:
                                            # Log additional collection failure but don't fail the main collection
                                            error_msg = f"Additional member collection failed for {additional_uri} after {additional_max_retries + 1} attempts: {additional_last_error}"
                                            failed_collections.append(error_msg)
                                            additional_member_failures += 1
                                            collection_has_nested_failures = True
                                            await self._log_runtime(
                                                "WARNING",
                                                "RedfishService",
                                                error_msg,
                                                dut_id,
                                            )
                                            continue

                                        additional_output_pattern = (
                                            _append_output_suffix(
                                                output_pattern, additional_suffix
                                            )
                                        )

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
                                            additional_member_successes += 1
                                            await self._log_collection_success(
                                                dut_id,
                                                "additional_member",
                                                additional_uri,
                                                additional_file,
                                            )
                                        else:
                                            error_msg = f"Additional member save failed for {additional_uri}: no output file generated"
                                            failed_collections.append(error_msg)
                                            additional_member_failures += 1
                                            collection_has_nested_failures = True
                                            await self._log_collection_failure(
                                                dut_id,
                                                "additional_member",
                                                additional_uri,
                                                "No output file generated",
                                            )

                                        if linked_resources and isinstance(
                                            linked_resources, list
                                        ):
                                            for linked_resource in linked_resources:
                                                if not isinstance(
                                                    linked_resource, dict
                                                ):
                                                    continue

                                                linked_uri_path = linked_resource.get(
                                                    "uri_path"
                                                )
                                                linked_suffix = linked_resource.get(
                                                    "output_suffix", ""
                                                )

                                                if not linked_uri_path:
                                                    continue

                                                linked_uri = self._extract_nested_value(
                                                    additional_data,
                                                    linked_uri_path,
                                                )

                                                if not linked_uri:
                                                    await self._log_runtime(
                                                        "DEBUG",
                                                        "RedfishService",
                                                        f"Skipping linked resource for {additional_uri}: path {linked_uri_path} not found",
                                                        dut_id,
                                                    )
                                                    continue

                                                if not validate_redfish_uri(linked_uri):
                                                    await self._log_runtime(
                                                        "DEBUG",
                                                        "RedfishService",
                                                        f"Skipping invalid linked resource URI: {linked_uri}",
                                                        dut_id,
                                                    )
                                                    continue

                                                await self._log_runtime(
                                                    "DEBUG",
                                                    "RedfishService",
                                                    f"Collecting linked member data from: {linked_uri}",
                                                    dut_id,
                                                )

                                                linked_success = False
                                                linked_data = None
                                                linked_last_error = None

                                                for linked_retry_attempt in range(
                                                    max_retries + 1
                                                ):
                                                    if linked_retry_attempt > 0:
                                                        await self._log_runtime(
                                                            "WARNING",
                                                            "RedfishService",
                                                            f"Retrying linked collection for {linked_uri} (attempt {linked_retry_attempt + 1}/{max_retries + 1})",
                                                            dut_id,
                                                        )
                                                        await asyncio.sleep(retry_delay)

                                                    linked_success, linked_data, _ = (
                                                        await self.dispatch_request(
                                                            dut_id,
                                                            "GET",
                                                            linked_uri,
                                                            error_context=f"get linked member data {linked_uri}",
                                                        )
                                                    )

                                                    if linked_success:
                                                        break

                                                    linked_last_error = linked_data
                                                    await self._log_runtime(
                                                        "WARNING",
                                                        "RedfishService",
                                                        f"Linked collection attempt {linked_retry_attempt + 1} failed for {linked_uri}: {linked_data}",
                                                        dut_id,
                                                    )

                                                if not linked_success:
                                                    linked_member_failures += 1
                                                    collection_has_nested_failures = (
                                                        True
                                                    )
                                                    failed_collections.append(
                                                        f"Linked member collection failed for {linked_uri} after {max_retries + 1} attempts: {linked_last_error}"
                                                    )
                                                    await self._log_runtime(
                                                        "WARNING",
                                                        "RedfishService",
                                                        f"Linked member collection failed for {linked_uri} after {max_retries + 1} attempts: {linked_last_error}",
                                                        dut_id,
                                                    )
                                                    continue

                                                linked_output_pattern = (
                                                    _append_output_suffix(
                                                        additional_output_pattern,
                                                        linked_suffix,
                                                    )
                                                )

                                                linked_file = await self._save_data_with_common_pattern(
                                                    dut_id,
                                                    linked_data,
                                                    function_tag,
                                                    output_pattern=linked_output_pattern,
                                                    substitutions=member_substitutions,
                                                    **filtered_kwargs,
                                                )
                                                if linked_file:
                                                    output_files.append(linked_file)
                                                    linked_member_successes += 1
                                                    await self._log_collection_success(
                                                        dut_id,
                                                        "linked_member",
                                                        linked_uri,
                                                        linked_file,
                                                    )
                                                else:
                                                    error_msg = f"Linked member save failed for {linked_uri}: no output file generated"
                                                    failed_collections.append(error_msg)
                                                    linked_member_failures += 1
                                                    collection_has_nested_failures = (
                                                        True
                                                    )
                                                    await self._log_collection_failure(
                                                        dut_id,
                                                        "linked_member",
                                                        linked_uri,
                                                        "No output file generated",
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
                            member_failures += 1
                            collection_has_nested_failures = True
                            await self._log_collection_failure(
                                dut_id, "member", member_uri, str(member_last_error)
                            )

            if collection_saved:
                if collection_has_nested_failures:
                    partial_collections.append(collection_uri)
                else:
                    successful_collections.append(collection_uri)

        # Determine overall success based on results
        successful_operations = len(successful_collections)
        partial_operations = len(partial_collections)
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
            "partial_collections": partial_collections,
            "failed_collections": failed_collections,
            "member_requests_successful": member_successes,
            "member_requests_failed": member_failures,
            "additional_member_requests_successful": additional_member_successes,
            "additional_member_requests_failed": additional_member_failures,
            "linked_member_requests_successful": linked_member_successes,
            "linked_member_requests_failed": linked_member_failures,
        }

        if (
            partial_operations > 0
            and successful_operations == 0
            and total_operations > 0
        ):
            partial_reason = f"Partial success: {partial_operations}/{total_operations} collection_with_members targets completed with nested sub-resource failures."
            if error_messages:
                partial_reason += "\n" + self._format_error_messages(
                    error_messages, "collection_with_members", is_partial=True
                )
            additional_context.update({"status": "partial", "reason": partial_reason})

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
                        "Dump service not found",
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
            if kwargs.get("streaming_time_filtered", False):
                uri = await self._append_streaming_time_filter(dut_id, uri)
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
        entity_type = kwargs.get("entity_type")

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

            filtered_collection_data = await self._filter_collection_members_by_skip_config(
                dut_id, collection_data, entity_type, base_uri
            )
            original_members = (
                collection_data.get("Members")
                if isinstance(collection_data, dict)
                else None
            )
            filtered_members = (
                filtered_collection_data.get("Members")
                if isinstance(filtered_collection_data, dict)
                else None
            )
            if (
                isinstance(original_members, list)
                and isinstance(filtered_members, list)
                and len(filtered_members) == 0
                and len(original_members) > 0
            ):
                output_pattern, substitutions, filtered_kwargs = (
                    self._extract_output_pattern_params(kwargs)
                )
                file_path = await self._save_data_with_common_pattern(
                    dut_id,
                    filtered_collection_data,
                    function_tag,
                    output_pattern=output_pattern,
                    substitutions={**substitutions, "expand_level": str(expand_level)},
                    **filtered_kwargs,
                )
                if file_path:
                    output_files.append(file_path)
                    successful_uris.append(base_uri)
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Skipped expanded query for {base_uri}: all members are excluded by skip config",
                        dut_id,
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
                expanded_data = await self._filter_collection_members_by_skip_config(
                    dut_id, expanded_data, entity_type, base_uri
                )
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

    async def _filter_collection_members_by_skip_config(
        self,
        dut_id: str,
        collection_data: Any,
        entity_type: Optional[str],
        base_uri: str,
    ) -> Any:
        """
        Apply configured Redfish entity skip lists to expanded collection payloads.
        """
        if not isinstance(collection_data, dict):
            return collection_data

        members = collection_data.get("Members")
        if not isinstance(members, list):
            return collection_data

        normalized_entity_type = str(entity_type or "").strip().lower()
        base_uri_lower = str(base_uri or "").lower()
        if normalized_entity_type == "systems" or "/systems" in base_uri_lower:
            id_type = "system"
        elif normalized_entity_type == "managers" or "/managers" in base_uri_lower:
            id_type = "manager"
        elif normalized_entity_type == "chassis" or "/chassis" in base_uri_lower:
            id_type = "chassis"
        else:
            return collection_data

        member_ids = []
        for member in members:
            if isinstance(member, dict):
                member_uri = str(member.get("@odata.id") or "")
                member_id = str(member.get("Id") or "")
                if member_uri:
                    member_id = member_uri.rstrip("/").split("/")[-1]
                member_ids.append(member_id)
            else:
                member_ids.append("")

        dut_config = self.dut_manager.get_dut_config(dut_id)
        filtered_ids = filter_ids(member_ids, id_type, dut_config)
        if len(filtered_ids) == len(member_ids):
            return collection_data

        filtered_id_set = set(filtered_ids)
        filtered_data = copy.deepcopy(collection_data)
        filtered_data["Members"] = [
            member
            for member, member_id in zip(filtered_data.get("Members", []), member_ids)
            if member_id in filtered_id_set
        ]
        if "Members@odata.count" in filtered_data:
            filtered_data["Members@odata.count"] = len(filtered_data["Members"])

        await log_filtered_ids(member_ids, filtered_ids, id_type, self.logger, dut_id)
        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"Filtered expanded {entity_type or base_uri} members from {member_ids} to {filtered_ids}",
            dut_id,
        )
        return filtered_data

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
                if chassis_uri and not validate_redfish_uri(chassis_uri):
                    continue
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
            collector_name = kwargs.get("collector_name", function_tag)

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
                    dut_id,
                    source_logs,
                    entry_filter,
                    processing_config,
                    collector_id=collector_id,
                    collector_name=collector_name,
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
                                    dut_id,
                                    source_logs,
                                    entry_filter,
                                    processing_config,
                                    collector_id=collector_id,
                                    collector_name=collector_name,
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

                                return await self._create_no_data_skipped_result(
                                    log_service=log_service,
                                    reason=(
                                        f"No {log_service} entries found - this is "
                                        f"normal if no {log_service} events occurred"
                                    ),
                                    output_files=[report_file] if report_file else [],
                                    operation_name="log_processing_collection",
                                    additional_context={
                                        "fallback_collection_attempted": True,
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

                        return await self._create_no_data_skipped_result(
                            log_service=log_service,
                            reason=(
                                f"No {log_service} entries found - this is normal "
                                f"if no {log_service} events occurred"
                            ),
                            output_files=[report_file] if report_file else [],
                            operation_name="log_processing_collection",
                            additional_context={
                                "fallback_collection_attempted": False,
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

    async def _create_no_data_skipped_result(
        self,
        log_service: str,
        reason: str,
        output_files: List[str] = None,
        operation_name: str = "collection",
        additional_context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Create a skipped result for expected no-data collectors."""
        context = {
            "log_service": log_service,
            "status": "skipped",
            "reason": reason,
            "no_data_collected": True,
            "classification": "expected_no_data",
        }
        if additional_context:
            context.update(additional_context)

        return await self._create_standardized_collector_result(
            successful_operations=0,
            total_operations=0,
            output_files=output_files or [],
            error_messages=[],
            operation_name=operation_name,
            additional_context=context,
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
                    "reason": f"Skipped: {error_message}",
                },
            )
        else:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"{collector_name}: {error_message}",
                dut_id,
            )
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

    async def generate_streaming_csv(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Post-processing hook: convert collected Redfish EventLog JSON files
        into CSV for streaming output.

        Generates:
          <collector>_events.csv — Timestamp, Id, Severity, MessageId, Message, Resolution
        """
        collector_id = kwargs.get("collector_id", "")
        output_dir = await self._get_output_directory(dut_id)

        collector_name = kwargs.get("collector_name", function_tag)
        collector_dir_name = f"Redfish_{collector_id}_{collector_name}"
        collector_dir = Path(output_dir) / dut_id / "redfish" / collector_dir_name

        if not collector_dir.exists():
            await self._log_runtime(
                "WARNING",
                "RedfishService",
                f"CSV generation skipped: directory not found {collector_dir}",
                dut_id,
            )
            return {"success": True, "output_files": [], "csv_skipped": True}

        all_events = []
        for json_file in sorted(collector_dir.glob("*.json")):
            if (
                "metadata" in json_file.name
                or "status" in json_file.name
                or "diagnostic" in json_file.name
            ):
                continue
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                members = data.get("Members", [])
                all_events.extend(members)
            except Exception:
                continue

        if not all_events:
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"CSV generation: no events found for {collector_id}",
                dut_id,
            )
            return {"success": True, "output_files": [], "csv_no_events": True}

        all_events.sort(key=lambda e: e.get("Created", ""))

        csv_filename = f"{collector_id}_events.csv"
        if self.orchestrator and self.orchestrator.config_manager:
            try:
                tool_config = self.orchestrator.config_manager.get_tool_config()
                if tool_config.get("streaming_only", False):
                    stream_begin, stream_end = normalize_stream_window(
                        tool_config.get("stream_begin", "24"),
                        tool_config.get("stream_end", "0"),
                    )
                    csv_filename = append_stream_window_to_filename(
                        csv_filename,
                        format_stream_window_component(stream_begin),
                        format_stream_window_component(stream_end),
                    )
            except Exception:
                pass

        events_csv = collector_dir / csv_filename
        with open(events_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["Timestamp", "Id", "Severity", "MessageId", "Message", "Resolution"]
            )
            for event in all_events:
                writer.writerow(
                    [
                        event.get("Created", ""),
                        event.get("Id", ""),
                        event.get("Severity", ""),
                        event.get("MessageId", ""),
                        event.get("Message", ""),
                        event.get("Resolution", ""),
                    ]
                )
        csv_files = [str(events_csv)]

        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"Generated {len(csv_files)} CSV files with {len(all_events)} events for {collector_id}",
            dut_id,
        )
        return {"success": True, "output_files": csv_files}

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
        collector_def = kwargs.get("collector_def", {})

        # Get configurable expand level if this is an expand collection
        if collection_type == "expand":
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
        collector_id = kwargs.get("collector_id", "")
        try:
            await self._log_collector_start(
                dut_id, collector_name, collector_id=collector_id
            )

            dynamic_discovery_entries = kwargs.get("dynamic_uri_discovery")
            if dynamic_discovery_entries:
                if not isinstance(dynamic_discovery_entries, list):
                    dynamic_discovery_entries = [dynamic_discovery_entries]

                resolved_uri_patterns: Optional[Union[str, List[str]]] = uri_patterns
                resolved_uri_list: Optional[Union[str, List[str]]] = kwargs.get(
                    "uri_list"
                )

                for discovery_entry in dynamic_discovery_entries:
                    if not isinstance(discovery_entry, dict):
                        await self._log_runtime(
                            "WARNING",
                            "RedfishService",
                            f"Skipping invalid dynamic_uri_discovery entry (expected dict): {discovery_entry}",
                            dut_id,
                        )
                        continue

                    should_apply, baseboard_name = (
                        await self._should_apply_dynamic_discovery(
                            dut_id,
                            collector_name,
                            collector_id,
                            function_tag,
                            discovery_entry,
                            collector_def,
                        )
                    )

                    if not should_apply:
                        continue

                    context: Dict[str, Any] = {
                        **kwargs,
                        "collector_id": collector_id,
                        "collector_name": collector_name,
                        "function_tag": function_tag,
                        "collection_type": collection_type,
                        "baseboard": baseboard_name,
                    }

                    if (
                        baseboard_name
                        and hasattr(self, "dut_manager")
                        and self.dut_manager
                    ):
                        baseboard_manager = None
                        if hasattr(self.dut_manager, "_get_baseboard_manager"):
                            baseboard_manager = (
                                self.dut_manager._get_baseboard_manager()
                            )
                        if baseboard_manager:
                            baseboard_type = baseboard_manager.get_baseboard_type(
                                baseboard_name
                            )
                            if baseboard_type:
                                context.setdefault("baseboard_type", baseboard_type)

                    discovered_value = await self._perform_dynamic_uri_discovery(
                        dut_id, collector_name, discovery_entry, context
                    )

                    if discovered_value is None:
                        continue

                    target = discovery_entry.get("target", "uri_patterns")
                    behavior = discovery_entry.get("behavior", "override")
                    if isinstance(behavior, str):
                        behavior = behavior.lower()
                    else:
                        behavior = "override"

                    deduplicate = discovery_entry.get("deduplicate", False)

                    if target == "uri_list":
                        resolved_uri_list = self._apply_discovered_value(
                            resolved_uri_list, discovered_value, behavior, deduplicate
                        )
                    else:
                        resolved_uri_patterns = self._apply_discovered_value(
                            resolved_uri_patterns,
                            discovered_value,
                            behavior,
                            deduplicate,
                        )

                uri_patterns = resolved_uri_patterns
                if resolved_uri_list is not None:
                    kwargs["uri_list"] = resolved_uri_list

                kwargs.pop("dynamic_uri_discovery", None)

            uri_list_from_kwargs = kwargs.get("uri_list")
            if uri_list_from_kwargs:
                if isinstance(uri_list_from_kwargs, str):
                    if uri_list_from_kwargs.startswith(
                        "${"
                    ) and uri_list_from_kwargs.endswith("}"):
                        var_name = uri_list_from_kwargs[2:-1]
                        if var_name in kwargs:
                            uri_list_value = kwargs[var_name]
                            if isinstance(uri_list_value, list):
                                uri_list = uri_list_value
                            else:
                                uri_list = [uri_list_value] if uri_list_value else []
                        else:
                            uri_list = [uri_list_from_kwargs]
                    else:
                        uri_list = [uri_list_from_kwargs]
                elif isinstance(uri_list_from_kwargs, list):
                    uri_list = uri_list_from_kwargs
                else:
                    uri_list = []
                kwargs.pop("uri_list", None)
            else:
                uri_list_key = kwargs.get("uri_list_key")
                if uri_list_key:
                    try:
                        dut_config = self.dut_manager.get_dut_config(dut_id)
                        dut_uri_list = dut_config.get(uri_list_key, [])

                        if isinstance(dut_uri_list, list) and dut_uri_list:
                            uri_list = dut_uri_list
                            await self._log_runtime(
                                "INFO",
                                "RedfishService",
                                f"Using DUT-level URI list from {uri_list_key}: {uri_list}",
                                dut_id,
                            )
                        else:
                            orchestrator = getattr(self, "orchestrator", None)
                            if orchestrator and hasattr(orchestrator, "config_manager"):
                                tool_config = (
                                    orchestrator.config_manager.get_tool_config()
                                )
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
                                    collector_id=kwargs.get(
                                        "collector_id", function_tag
                                    ),
                                    successful_operations=0,
                                    total_operations=0,
                                    output_files=[],
                                    error_messages=[
                                        "No URIs provided in configuration - collector skipped"
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
                            error_messages=[
                                f"Configuration error for {uri_list_key}: {e}"
                            ],
                            operation_name="uri_list_collection",
                            additional_context={"uri_list_key": uri_list_key},
                        )
                else:
                    if isinstance(uri_patterns, str):
                        uri_list = [uri_patterns]
                    elif isinstance(uri_patterns, list):
                        uri_list = uri_patterns
                    else:
                        uri_list = []

                filtered_systems = kwargs.get("filtered_systems", [])
                filtered_managers = kwargs.get("filtered_managers", [])
                filtered_chassis = kwargs.get("filtered_chassis", [])
                has_placeholder = uri_list and any("{" in uri for uri in uri_list)
                if has_placeholder and (
                    filtered_systems or filtered_managers or filtered_chassis
                ):
                    entity_map = {
                        "Systems": filtered_systems,
                        "Managers": filtered_managers,
                        "Chassis": filtered_chassis,
                    }
                    entities = (
                        entity_map.get(entity_type, [])
                        or filtered_systems
                        or filtered_managers
                        or filtered_chassis
                    )
                    expanded = []
                    for ent in entities:
                        eid = ent["id"] if isinstance(ent, dict) else ent
                        expanded.extend(
                            self._process_user_defined_uris(uri_list, eid, entity_type)
                        )
                    if expanded:
                        uri_list = expanded
                elif has_placeholder and self.dut_manager:
                    all_uris_str = " ".join(uri_list)
                    if "{system_id}" in all_uris_str:
                        fallback_type = "Systems"
                    elif "{manager_id}" in all_uris_str:
                        fallback_type = "Managers"
                    elif "{chassis_id}" in all_uris_str:
                        fallback_type = "Chassis"
                    else:
                        fallback_type = None

                    if fallback_type:
                        member_ids = await self.dut_manager.get_resource_members(
                            dut_id, fallback_type
                        )
                        if member_ids:
                            expanded = []
                            for mid in member_ids:
                                expanded.extend(
                                    self._process_user_defined_uris(
                                        uri_list, mid, fallback_type
                                    )
                                )
                            if expanded:
                                uri_list = expanded

                if (
                    uri_list
                    and self.dut_manager
                    and self.dut_manager.uri_config_manager
                ):
                    uri_list = [
                        self.dut_manager.uri_config_manager._apply_prefix_override(uri)
                        for uri in uri_list
                    ]

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
                    dut_id,
                    uri_list,
                    expand_level,
                    function_tag,
                    entity_type=entity_type,
                    **kwargs,
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
        finally:
            await self._clear_redfish_request_capture(dut_id, collector_id)

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
        collector_id = kwargs.get("collector_id", collector_name)

        try:
            await self._log_collector_start(
                dut_id, collector_name, collector_id=collector_id
            )

            # Check if we have validation results with filtered entities
            filtered_systems = kwargs.get("filtered_systems", [])
            filtered_managers = kwargs.get("filtered_managers", [])
            filtered_chassis = kwargs.get("filtered_chassis", [])

            if entity_type == "Systems" and "filtered_systems" in kwargs:
                # Use filtered systems from validation
                system_ids_for_log = [sys["id"] for sys in filtered_systems]
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using {len(filtered_systems)} filtered systems from validation: {system_ids_for_log}",
                    dut_id,
                )
                entity_ids = [sys["id"] for sys in filtered_systems]

                dut_config = self.dut_manager.get_dut_config(dut_id)
                original_system_ids = entity_ids.copy()
                entity_ids = filter_ids(entity_ids, "system", dut_config)
                if len(entity_ids) != len(original_system_ids):
                    await log_filtered_ids(
                        original_system_ids, entity_ids, "system", self.logger, dut_id
                    )

                systems_uri = self.get_configured_uri(dut_id, "Systems")
                entities = {
                    "Members": [
                        {"@odata.id": f"{systems_uri}/{sys_id}"}
                        for sys_id in entity_ids
                    ]
                }
            elif entity_type == "Managers" and "filtered_managers" in kwargs:
                # Use filtered managers from validation
                manager_ids_for_log = [mgr["id"] for mgr in filtered_managers]
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using {len(filtered_managers)} filtered managers from validation: {manager_ids_for_log}",
                    dut_id,
                )
                entity_ids = [mgr["id"] for mgr in filtered_managers]

                # Apply ID filtering based on DUT configuration
                dut_config = self.dut_manager.get_dut_config(dut_id)
                original_manager_ids = entity_ids.copy()
                entity_ids = filter_ids(entity_ids, "manager", dut_config)

                # Log filtered IDs if any were filtered
                if len(entity_ids) != len(original_manager_ids):
                    await log_filtered_ids(
                        original_manager_ids, entity_ids, "manager", self.logger, dut_id
                    )

                managers_uri = self.get_configured_uri(dut_id, "Managers")
                entities = {
                    "Members": [
                        {"@odata.id": f"{managers_uri}/{mgr_id}"}
                        for mgr_id in entity_ids
                    ]
                }
            elif entity_type == "Chassis" and "filtered_chassis" in kwargs:
                # Use filtered chassis from validation
                chassis_ids_for_log = [chassis["id"] for chassis in filtered_chassis]
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using {len(filtered_chassis)} filtered chassis from validation: {chassis_ids_for_log}",
                    dut_id,
                )
                entity_ids = [chassis["id"] for chassis in filtered_chassis]

                dut_config = self.dut_manager.get_dut_config(dut_id)
                original_chassis_ids = entity_ids.copy()
                entity_ids = filter_ids(entity_ids, "chassis", dut_config)
                if len(entity_ids) != len(original_chassis_ids):
                    await log_filtered_ids(
                        original_chassis_ids, entity_ids, "chassis", self.logger, dut_id
                    )

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
            # as an expected no-data outcome, not a successful data collection.
            if total_collections == 0:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"No collections attempted for {entity_type} {log_service} - treating as expected no-data",
                    dut_id,
                )
                result = await self._create_no_data_skipped_result(
                    log_service=log_service,
                    reason=f"No {log_service} entries found for {entity_type} - expected no-data",
                    output_files=output_files,
                    operation_name="collections",
                    additional_context={
                        "entities_processed": len(entity_ids),
                        "successful_collections": 0,
                        "total_collections": 0,
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
                        "Error details saved to JSON files for manual investigation."
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
        finally:
            await self._clear_redfish_request_capture(dut_id, collector_id)

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
            output_pattern = kwargs.get("output_pattern", "")
            resolved_collector_id = kwargs.get(
                "collector_id"
            ) or await self._get_original_collector_id(
                dut_id, self._get_current_collector_id()
            )
            entity_id_key = self._get_entity_id_key(entity_type)
            base_substitutions = {entity_id_key: entity_id, "entity_id": entity_id}

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
                        "info": "PostCodes service check attempted",
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
                # Calculate start_skip for collection level (like legacy code)
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
            page_files = []
            status_list = (
                []
            )  # Status per page - important for partial success determination
            page_timings = []  # Track timing for each page
            page = 1
            max_pages = self._get_tool_config_int("max_pagination_pages", 100)
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

            # Apply time-window $filter when streaming --since/--until are set
            time_filter = await self._build_redfish_time_filter(dut_id)
            if time_filter:
                separator = "&" if "?" in base_uri else "?"
                base_uri = f"{base_uri}{separator}{time_filter}"
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Applied time filter to {entity_type} {entity_id}: {time_filter}",
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
            page_retry_count = 0  # Track retries at pagination level
            max_page_retries = 2  # Maximum retries per page at pagination level
            max_duplicate_url_retries = self._get_tool_config_int(
                "max_duplicate_url_retries", 3
            )
            duplicate_url_count = 0
            retry_delay = 2  # Simple 2-second delay between retries (like legacy)
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
                                    page_files.append(file_path)
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
                                            next_uri = parsed_response.get(
                                                next_link_field
                                            )
                                            if next_uri == current_uri:
                                                duplicate_url_count += 1
                                                if (
                                                    duplicate_url_count
                                                    >= max_duplicate_url_retries
                                                ):
                                                    await self._log_runtime(
                                                        "WARNING",
                                                        "RedfishService",
                                                        f"Stopping pagination for {entity_type} {entity_id}: duplicate nextLink repeated {duplicate_url_count} times: {next_uri}",
                                                        dut_id,
                                                    )
                                                    current_uri = None
                                                    break
                                            else:
                                                duplicate_url_count = 0
                                            current_uri = next_uri
                                            if current_uri and not validate_redfish_uri(
                                                current_uri,
                                                expected_host=self._get_connection_host(
                                                    dut_id
                                                ),
                                            ):
                                                await self._log_runtime(
                                                    "WARNING",
                                                    "RedfishService",
                                                    f"Rejecting suspicious nextLink URI: {current_uri}",
                                                    dut_id,
                                                )
                                                current_uri = None
                                            if current_uri:
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
                            # Continue to next page instead of breaking (following legacy code pattern)
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
                            next_uri = response.get(next_link_field)
                            if next_uri == current_uri:
                                duplicate_url_count += 1
                                if duplicate_url_count >= max_duplicate_url_retries:
                                    await self._log_runtime(
                                        "WARNING",
                                        "RedfishService",
                                        f"Stopping pagination for {entity_type} {entity_id}: duplicate nextLink repeated {duplicate_url_count} times: {next_uri}",
                                        dut_id,
                                    )
                                    current_uri = None
                                    break
                            else:
                                duplicate_url_count = 0
                            current_uri = next_uri
                            if current_uri and not validate_redfish_uri(
                                current_uri,
                                expected_host=self._get_connection_host(dut_id),
                            ):
                                await self._log_runtime(
                                    "WARNING",
                                    "RedfishService",
                                    f"Rejecting suspicious nextLink URI: {current_uri}",
                                    dut_id,
                                )
                                current_uri = None
                                break
                            current_page_retry = 0  # Reset retry count for new page
                            continue
                        else:
                            # No nextLink available - stop pagination (following legacy code pattern)
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
                page_substitutions = {
                    **base_substitutions,
                    "page": page_count,
                    "total": "unknown",
                }
                file_path = await self._save_data_to_file_with_pattern(
                    dut_id,
                    response,
                    output_file,
                    filename=kwargs.get("filename", ""),
                    output_pattern=output_pattern or output_file,
                    substitutions=page_substitutions,
                    collector_id=resolved_collector_id,
                )

                if file_path:
                    collected_files.append(file_path)
                    page_files.append(file_path)
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
                            get_raw_content=True,
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
                    if next_link == current_uri:
                        duplicate_url_count += 1
                        if duplicate_url_count >= max_duplicate_url_retries:
                            await self._log_runtime(
                                "WARNING",
                                "RedfishService",
                                f"Stopping pagination for {entity_type} {entity_id}: duplicate nextLink repeated {duplicate_url_count} times: {next_link}",
                                dut_id,
                            )
                            break
                    else:
                        duplicate_url_count = 0
                    if not validate_redfish_uri(
                        next_link, expected_host=self._get_connection_host(dut_id)
                    ):
                        await self._log_runtime(
                            "WARNING",
                            "RedfishService",
                            f"Rejecting suspicious nextLink URI: {next_link}",
                            dut_id,
                        )
                        break
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
            actual_total_pages = len(page_files)
            if actual_total_pages > 0:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Collected {actual_total_pages} pages for {entity_type} {entity_id}. Updating filenames to reflect actual total.",
                    dut_id,
                )

                # Rename files to use actual total
                renamed_files = []
                page_file_set = set(page_files)
                for file_path in collected_files:
                    try:
                        old_path = file_path
                        if old_path not in page_file_set:
                            renamed_files.append(file_path)
                            continue

                        # Replace "unknown" or any existing total with actual total
                        new_path = re.sub(
                            r"_page(\d+)_of_[^/]+\.json$",
                            f"_page\\1_of_{actual_total_pages}.json",
                            str(old_path),
                        )
                        if new_path == str(old_path):
                            new_path = re.sub(
                                r"_page(\d+)\.json$",
                                f"_page\\1_of_{actual_total_pages}.json",
                                str(old_path),
                            )

                        if self.logger and resolved_collector_id:
                            new_basename = self.logger._apply_stream_window_to_filename(
                                resolved_collector_id, os.path.basename(new_path)
                            )
                            new_path = os.path.join(
                                os.path.dirname(new_path), new_basename
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
            successful_operations = 0
            total_operations = 0

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
                # Fallback to legacy configuration if no baseboard manager
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
            handler, expected_operations = (
                self._get_component_integrity_handler_and_expected_operations(
                    collection_type, kwargs
                )
            )

            for i, member in enumerate(members):
                # Add delay between member processing to prevent BMC overload
                if i > 0:
                    await asyncio.sleep(member_delay)

                member_uri = member.get("@odata.id", None)
                if not member_uri:
                    continue
                if not validate_redfish_uri(member_uri):
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
                total_operations += expected_operations

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
                handler_result = await handler(
                    dut_id,
                    component_response,
                    member_uri,
                    member_id,
                    kwargs,
                    function_tag,
                    output_files,
                    request_delay,
                )
                successful_operations += handler_result["successful_operations"]

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
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

    def _get_component_integrity_handler_and_expected_operations(
        self, collection_type: str, kwargs: Dict[str, Any]
    ) -> Tuple[Callable[..., Awaitable[Dict[str, int]]], int]:
        """
        Select the collection handler and expected operation count per member.

        The expected count is used even when the per-member GET fails before the
        handler can run, so status accounting reflects attempted work.
        """
        if collection_type == "spdm_measurements":
            measurement_indices = kwargs.get("measurement_indices", [26, 50])
            return (
                self._handle_spdm_measurements_collection,
                len(measurement_indices),
            )
        if collection_type == "certificates":
            return (self._handle_certificate_collection, 1)
        return (self._handle_generic_collection, 1)

    async def _handle_spdm_measurements_collection(
        self,
        dut_id: str,
        component_response: Dict[str, Any],
        member_uri: str,
        member_id: str,
        kwargs: Dict[str, Any],
        function_tag: str,
        output_files: List[str],
        request_delay: int = 0,
    ) -> Dict[str, int]:
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

        index_list = kwargs.get("measurement_indices", [26, 50])
        collection_result = {
            "successful_operations": 0,
            "total_operations": len(index_list),
        }

        if not action_target:
            await self._log_runtime(
                "WARN",
                "RedfishService",
                f"No SPDM action found for uri {member_uri}. Skipping...",
                dut_id,
            )
            return collection_result

        # Collect measurements for specific indices
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

                # Wait for task completion (like legacy implementation)
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

                # Get dump location (like legacy implementation)
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
                        collection_result["successful_operations"] += 1
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
                            f"Failed to save SPDM measurement index {index} from {member_uri}",
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

        return collection_result

    async def _handle_certificate_collection(
        self,
        dut_id: str,
        component_response: Dict[str, Any],
        member_uri: str,
        member_id: str,
        kwargs: Dict[str, Any],
        function_tag: str,
        output_files: List[str],
        request_delay: int,
    ) -> Dict[str, int]:
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
        return await self._handle_generic_collection(
            dut_id,
            component_response,
            member_uri,
            member_id,
            kwargs,
            function_tag,
            output_files,
            request_delay,
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
        request_delay: int = 0,
    ) -> Dict[str, int]:
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
            return {"successful_operations": 1, "total_operations": 1}

        return {"successful_operations": 0, "total_operations": 1}

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

                dut_config = self.dut_manager.get_dut_config(dut_id)
                original_system_ids = entity_ids.copy()
                entity_ids = filter_ids(entity_ids, "system", dut_config)
                if len(entity_ids) != len(original_system_ids):
                    await log_filtered_ids(
                        original_system_ids, entity_ids, "system", self.logger, dut_id
                    )
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
                    await log_filtered_ids(
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
                dut_config = self.dut_manager.get_dut_config(dut_id)
                original_chassis_ids = entity_ids.copy()
                entity_ids = filter_ids(entity_ids, "chassis", dut_config)
                if len(entity_ids) != len(original_chassis_ids):
                    await log_filtered_ids(
                        original_chassis_ids, entity_ids, "chassis", self.logger, dut_id
                    )
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

    async def collect_dgx_diagnostic_data(
        self,
        dut_id: str,
        oem_types: List[str],
        function_tag: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Collect DGX-specific diagnostic data via Managers/BMC/LogServices/DiagnosticLog.

        This hook is added to existing collectors (e.g. manager_on_demand_log_dump,
        manager_fpga_register_dump) and silently skips on non-DGX hardware.

        For DGX platforms the BMC exposes:
          POST /redfish/v1/Managers/BMC/LogServices/DiagnosticLog/Actions/LogService.CollectDiagnosticData
        with payload {"DiagnosticDataType": "OEM", "OEMDiagnosticDataType": "<type>"}.

        Output files are placed in a DGX/ subdirectory within the collector's output
        directory (enabled by an os.makedirs call in _save_data_to_file_with_pattern).

        Args:
            dut_id: DUT identifier.
            oem_types: List of OEMDiagnosticDataType values to collect
                       (e.g. ["logs", "BMCLOG", "SERVICELOGS"]).
            function_tag: Tag used for file naming / request metadata.
            **kwargs: Forwarded by the hook framework; includes collector_id,
                      output_pattern, collection_level, etc.
        """
        try:
            dut = self.dut_manager.get_dut(dut_id)
            is_dgx, dgx_signal = await self._is_dgx_platform(dut_id, dut)
            if not is_dgx:
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    "collect_dgx_diagnostic_data: not a DGX platform — skipping",
                    dut_id,
                )
                return {
                    "success": True,
                    "status": "skipped",
                    "reason": "Not a DGX platform",
                    "context": {
                        "successful_operations": 0,
                        "total_operations": 0,
                        "dgx_applicable": False,
                    },
                    "output_files": [],
                }

            collector_id = kwargs.get("collector_id", "")
            output_pattern = kwargs.get(
                "output_pattern", "DGX/Redfish_dgx_{oem_type}_BMC_{task_id}.tar.xz"
            )

            output_files = []
            status_list = []
            error_messages = []

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"DGX platform detected via {dgx_signal} — collecting {len(oem_types)} diagnostic type(s): {oem_types}",
                dut_id,
            )

            for oem_type in oem_types:
                payload = {
                    "DiagnosticDataType": "OEM",
                    "OEMDiagnosticDataType": oem_type,
                }
                # Substitute {oem_type} in the output_pattern for this iteration
                resolved_pattern = output_pattern.replace("{oem_type}", oem_type)

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"DGX: triggering {oem_type} dump via Managers/BMC/LogServices/DiagnosticLog",
                    dut_id,
                )

                # Strip all keys we pass explicitly to _execute_redfish_dump_task
                # to avoid "multiple values for keyword argument" errors from the context dict
                _explicit = {
                    "dut_id",
                    "entity_type",
                    "entity_id",
                    "log_service",
                    "payload",
                    "function_tag",
                    "output_pattern",
                    "collector_id",
                    "diagnostic_type",
                    # hook-specific params that don't belong in _execute_redfish_dump_task
                    "oem_types",
                }
                passthrough = {k: v for k, v in kwargs.items() if k not in _explicit}
                success, output_file = await self._execute_redfish_dump_task(
                    dut_id=dut_id,
                    entity_type="Managers",
                    entity_id="BMC",
                    log_service="DiagnosticLog",
                    payload=payload,
                    function_tag=function_tag,
                    output_pattern=resolved_pattern,
                    collector_id=collector_id,
                    diagnostic_type=oem_type,
                    **passthrough,
                )

                status_list.append(success)
                if output_file:
                    output_files.append(output_file)
                if not success:
                    error_messages.append(f"DGX {oem_type}: {output_file}")

            successful = len([s for s in status_list if s])
            total = len(status_list)

            return await self._create_standardized_collector_result(
                successful_operations=successful,
                total_operations=total,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="dgx_diagnostic_data",
                additional_context={
                    "dgx_applicable": True,
                    "oem_types": oem_types,
                    "entity": "Managers/BMC/LogServices/DiagnosticLog",
                },
            )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception in collect_dgx_diagnostic_data: {e}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=0,
                output_files=[],
                error_messages=[f"Exception in collect_dgx_diagnostic_data: {e}"],
                operation_name="dgx_diagnostic_data",
                additional_context={"error_type": type(e).__name__},
            )

    async def _is_dgx_platform(
        self, dut_id: str, dut: Optional[Any] = None
    ) -> Tuple[bool, str]:
        """Infer DGX applicability from explicit Redfish IDs and platform metadata."""
        if dut is None:
            dut = self.dut_manager.get_dut(dut_id)

        if getattr(dut, "is_dgx", False):
            return True, "redfish Systems member"

        discovered_systems = await self.get_discovered_systems(dut_id)
        if "DGX" in discovered_systems:
            dut.is_dgx = True
            return True, "discovered Systems member 'DGX'"

        discovered_managers = await self.get_discovered_managers(dut_id)
        if "DGX" in discovered_managers:
            dut.is_dgx = True
            return True, "discovered Managers member 'DGX'"

        platform_info = getattr(dut, "platform_info", None)
        if platform_info is None:
            try:
                platform_info = await self.dut_manager.get_platform_info(dut_id)
            except Exception:
                platform_info = None

        if isinstance(platform_info, dict):
            platform_text = " ".join(
                str(platform_info.get(key, ""))
                for key in ("model", "partnumber", "part_number", "name")
            ).upper()
            if "DGX" in platform_text:
                dut.is_dgx = True
                dut.platform_info = platform_info
                return True, "platform metadata"

        return False, "no DGX indicators"

    async def _query_action_info_for_systems(
        self,
        dut_id: str,
        system_ids: List[str],
        log_service: str = "Dump",
    ) -> Dict[str, List[str]]:
        """Query CollectDiagnosticDataActionInfo for each system to get valid diagnostic types.

        This method queries the ActionInfo endpoint for each system to determine what
        diagnostic types are actually supported. This information is used for:
        1. ActionInfo-aware success criteria (failures on non-ActionInfo items don't count)
        2. Validating expected vs actual collection results

        Args:
            dut_id: Device under test ID
            system_ids: List of system IDs to query
            log_service: Log service name (default: "Dump")

        Returns:
            Dict mapping system_id to list of valid OEMDiagnosticDataType values.
            Returns empty dict if ActionInfo is unavailable (graceful fallback).

        Example return:
            {
                "System_0": ["DiagnosticType=NetIR;DeviceType=NIC_0", ...],
                "HGX_Baseboard_0": ["DiagnosticType=GPUDiagnostics;DeviceType=GPU_SMA_0", ...]
            }
        """
        action_info_by_system: Dict[str, List[str]] = {}

        for system_id in system_ids:
            try:
                # Build the ActionInfo URI
                action_info_uri = f"/redfish/v1/Systems/{system_id}/LogServices/{log_service}/CollectDiagnosticDataActionInfo"

                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"[ActionInfo] Querying ActionInfo for system {system_id}: {action_info_uri}",
                    dut_id,
                )

                success, response, _ = await self.dispatch_request(
                    dut_id, "GET", action_info_uri, bypass_cache=True
                )

                if not success or not response:
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        f"[ActionInfo] Failed to query ActionInfo for {system_id}, will use fallback behavior",
                        dut_id,
                    )
                    continue

                # Parse the Parameters to find OEMDiagnosticDataType allowable values
                parameters = response.get("Parameters", [])
                oem_diagnostic_values = []

                for param in parameters:
                    if param.get("Name") == "OEMDiagnosticDataType":
                        oem_diagnostic_values = param.get("AllowableValues", [])
                        break

                if oem_diagnostic_values:
                    action_info_by_system[system_id] = oem_diagnostic_values
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"[ActionInfo] System {system_id} supports {len(oem_diagnostic_values)} diagnostic types",
                        dut_id,
                    )
                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"[ActionInfo] System {system_id} types: {oem_diagnostic_values}",
                        dut_id,
                    )
                else:
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        f"[ActionInfo] No OEMDiagnosticDataType values found for {system_id}",
                        dut_id,
                    )

            except Exception as e:
                await self._log_runtime(
                    "WARNING",
                    "RedfishService",
                    f"[ActionInfo] Exception querying ActionInfo for {system_id}: {str(e)}",
                    dut_id,
                )
                continue

        return action_info_by_system

    def _check_diagnostic_type_in_action_info(
        self,
        oem_diagnostic_type: str,
        action_info_values: List[str],
    ) -> bool:
        """Check if a diagnostic type is in the ActionInfo allowable values.

        Args:
            oem_diagnostic_type: The OEMDiagnosticDataType value being requested
            action_info_values: List of allowable values from ActionInfo

        Returns:
            True if the diagnostic type is in ActionInfo, False otherwise
        """
        if not action_info_values:
            # No ActionInfo available, assume it's valid (backward compatible)
            return True

        return oem_diagnostic_type in action_info_values

    async def _collect_for_system(
        self,
        dut_id: str,
        system_id: str,
        device_tasks: List[Dict[str, Any]],
        action_info_values: List[str],
        use_action_info_validation: bool,
        collector_name: str,
        collector_id: str,
        kwargs: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Collect all diagnostic data for a single system sequentially.

        This helper method is used for parallel collection across systems.
        Within a single system, collections are executed sequentially to avoid
        BMC ResourceInUse errors (BMC enforces sequential collection per LogService).

        Args:
            dut_id: Device under test ID
            system_id: The system ID to collect from
            device_tasks: List of device task dicts, each containing:
                - device_type: Type of device (e.g., "sma", "nvswitch")
                - device_id: Device ID number
                - device_config: Resolved config for this device
                - payload: The diagnostic payload to send
                - oem_diag_type: The OEMDiagnosticDataType value
                - is_in_action_info: Whether this type is in ActionInfo
                - device_identifier: Full device identifier string
                - diagnostic_type: The diagnostic type string
            action_info_values: List of valid diagnostic types from ActionInfo for this system
            use_action_info_validation: Whether ActionInfo validation is enabled
            collector_name: Name of the collector (for logging)
            collector_id: Collector ID for tracking
            kwargs: Additional kwargs to pass to collect_diagnostic_data

        Returns:
            List of result dicts, one per device task, containing:
                - success: Whether collection succeeded
                - output_files: List of output files
                - status: Boolean status
                - error_messages: List of error messages
                - device_type: The device type
                - device_id: The device ID
                - is_in_action_info: Whether this type was in ActionInfo
                - oem_diag_type: The OEMDiagnosticDataType value
        """
        results = []

        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"[Parallel] Starting sequential collection for system {system_id} with {len(device_tasks)} tasks",
            dut_id,
        )

        for idx, task in enumerate(device_tasks):
            device_type = task["device_type"]
            device_id = task["device_id"]
            payload = task["payload"]
            diagnostic_type = task["diagnostic_type"]
            device_identifier = task["device_identifier"]
            is_in_action_info = task["is_in_action_info"]
            oem_diag_type = task["oem_diag_type"]

            # Log if attempting a task that's not in ActionInfo (might still work if ActionInfo is incomplete)
            if (
                use_action_info_validation
                and action_info_values
                and not is_in_action_info
            ):
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"[ActionInfo] Attempting {device_type}_{device_id} on {system_id} - "
                    f"'{oem_diag_type}' not in ActionInfo (may fail, won't count against success)",
                    dut_id,
                )

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"[Parallel] System {system_id}: Collecting task {idx + 1}/{len(device_tasks)} - "
                f"{device_type}_{device_id}",
                dut_id,
            )

            # Create a filtered systems context for this specific system
            filtered_systems_for_device = [{"id": system_id}]

            # Create substitutions for output pattern
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
                payload_types=[diagnostic_type],
                default_payload=payload,
                function_tag=f"{collector_name}_{device_type}",
                fallback_payloads=[payload],
                **clean_kwargs,
            )

            # Build result with metadata
            task_result = {
                "success": result.get("success", False),
                "output_files": result.get("output_files", []),
                "status": result.get("success", False),
                "error_messages": result.get("error_messages", []),
                "device_type": device_type,
                "device_id": device_id,
                "system_id": system_id,
                "is_in_action_info": is_in_action_info,
                "oem_diag_type": oem_diag_type,
                "raw_result": result,
            }
            results.append(task_result)

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"[Parallel] System {system_id}: Task {idx + 1}/{len(device_tasks)} complete - "
                f"{device_type}_{device_id} success={task_result['success']}",
                dut_id,
            )

            # Add sleep between devices (but not after the last device)
            if idx < len(device_tasks) - 1:
                collector_def = kwargs.get("collector_def", {})
                dut_config = self.dut_manager.get_dut_config(dut_id)
                sleep_duration = get_collector_sleep_duration(
                    kwargs.get("collector_id", collector_id),
                    collector_def,
                    dut_config,
                    5,
                )
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"[Parallel] System {system_id}: Sleeping {sleep_duration}s between device dumps",
                    dut_id,
                )
                await asyncio.sleep(sleep_duration)

        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"[Parallel] Completed collection for system {system_id}: "
            f"{sum(1 for r in results if r['success'])}/{len(results)} successful",
            dut_id,
        )

        return results

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
                await log_filtered_ids(
                    original_system_ids, system_ids, "system", self.logger, dut_id
                )

            await self._log_runtime(
                "INFO", "RedfishService", f"Using system IDs: {system_ids}", dut_id
            )

            # Query ActionInfo for validated systems if enabled
            # This provides the authoritative list of valid diagnostic types per system
            # First check baseboard_diagnostic_config, then fallback to kwargs
            use_action_info_validation = baseboard_diagnostic_config.get(
                "use_action_info_validation",
                kwargs.get("use_action_info_validation", False),
            )
            action_info_by_system: Dict[str, List[str]] = {}

            if use_action_info_validation and system_ids:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"[ActionInfo] Querying ActionInfo for {len(system_ids)} systems (validation enabled)",
                    dut_id,
                )
                action_info_by_system = await self._query_action_info_for_systems(
                    dut_id, system_ids, log_service="Dump"
                )
                if action_info_by_system:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"[ActionInfo] Retrieved ActionInfo for {len(action_info_by_system)} systems",
                        dut_id,
                    )
                else:
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        "[ActionInfo] No ActionInfo retrieved, using fallback behavior (all failures count)",
                        dut_id,
                    )

            # If no eligible systems remain after filtering, optionally treat as complete
            # Rely on config to opt into empty-target completion behavior
            complete_on_empty_targets = kwargs.get("complete_on_empty_targets", False)
            if not system_ids:
                if complete_on_empty_targets:
                    # No systems to operate on (e.g., all filtered) — consider this a completed no-op
                    return await self._create_standardized_collector_result(
                        successful_operations=1,
                        total_operations=1,
                        output_files=[],
                        error_messages=[],
                        operation_name="device_diagnostic_data",
                        additional_context={
                            "collector_name": collector_name,
                            "reason": "No eligible systems after filtering; treating as complete",
                            "systems_before_filter": original_system_ids,
                            "systems_after_filter": system_ids,
                            "devices_discovered": discovered_devices,
                        },
                    )

            all_output_files = []
            all_status_list = []
            error_messages = []

            # ActionInfo-aware result tracking
            # These track whether each operation was expected based on ActionInfo
            action_info_results = {
                "expected_successes": 0,  # In ActionInfo and succeeded
                "expected_failures": 0,  # In ActionInfo and failed (counts against us)
                "unexpected_failures": 0,  # NOT in ActionInfo and failed (doesn't count)
                "bonus_successes": 0,  # NOT in ActionInfo but succeeded
                "action_info_available": bool(action_info_by_system),
            }

            # Parallel collection configuration (disabled by default)
            # NOTE: Some BMC implementations do not support parallel collection within a single
            # system's LogService (returns ResourceInUse error). However, parallel collection
            # across DIFFERENT systems typically works. This infrastructure supports cross-system
            # parallelism while maintaining sequential execution within each system.
            # First check baseboard_diagnostic_config, then fallback to kwargs
            parallel_collection = baseboard_diagnostic_config.get(
                "parallel_collection", kwargs.get("parallel_collection", False)
            )
            max_concurrent_tasks = baseboard_diagnostic_config.get(
                "max_concurrent_tasks", kwargs.get("max_concurrent_tasks", 4)
            )

            if parallel_collection:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"[Parallel] Parallel collection enabled with max_concurrent_tasks={max_concurrent_tasks}. "
                    f"Note: BMC may enforce sequential collection within a single LogService.",
                    dut_id,
                )

            # ================================================================
            # PHASE 1: Build tasks grouped by system_id
            # This prepares all collection tasks before execution, enabling
            # either sequential or parallel collection strategies.
            # ================================================================
            config_keys_to_skip = {
                "use_action_info_validation",
                "parallel_collection",
                "max_concurrent_tasks",
            }
            tasks_by_system: Dict[str, List[Dict[str, Any]]] = {}

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"[TaskBuild] Building collection tasks for {len(system_ids)} systems",
                dut_id,
            )

            for device_type, device_config in baseboard_diagnostic_config.items():
                # Skip non-device configuration keys
                if device_type in config_keys_to_skip:
                    continue
                # Skip non-dict device configs (shouldn't happen but be safe)
                if not isinstance(device_config, dict):
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        f"Skipping non-dict config key: {device_type}",
                        dut_id,
                    )
                    continue

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Processing device type: {device_type} with config: {device_config}",
                    dut_id,
                )

                # Get discovered device IDs for this type.
                # device_ids_override bypasses discovery for system-level queries
                # (e.g. DiagnosticType=SMA with no per-device suffix).
                device_ids_override = device_config.get("device_ids_override")
                if device_ids_override is not None:
                    device_ids = device_ids_override
                else:
                    device_ids = discovered_devices.get(device_type, [])
                if not device_ids:
                    await self._log_runtime(
                        "WARNING",
                        "RedfishService",
                        f"No devices discovered for type {device_type}, skipping",
                        dut_id,
                    )
                    continue

                # Build tasks for each system and device combination
                for system_id in system_ids:
                    # Resolve system-specific configuration (supports multi-system platforms)
                    resolved_config = await self.resolve_system_config(
                        system_id, device_config, dut_id, device_type
                    )

                    # Extract diagnostic configuration from resolved config
                    diagnostic_type = resolved_config.get("diagnostic_type", "")
                    device_id_key = resolved_config.get("device_id_key", "DeviceID")
                    device_id_prefix = resolved_config.get("device_id_prefix", "")

                    await self._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"[TaskBuild] {system_id}: diagnostic_type={diagnostic_type}, "
                        f"device_id_key={device_id_key}, device_id_prefix={device_id_prefix}",
                        dut_id,
                    )

                    for device_id in device_ids:
                        # Build device identifier
                        if device_id_prefix:
                            device_identifier = f"{device_id_prefix}{device_id}"
                        else:
                            device_identifier = str(device_id)

                        # Create diagnostic payload using configurable template
                        payload_template = resolved_config.get(
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

                        # Check if this diagnostic type is in ActionInfo (if available)
                        oem_diag_type = payload.get("OEMDiagnosticDataType", "")
                        system_action_info = action_info_by_system.get(system_id, [])
                        is_in_action_info = self._check_diagnostic_type_in_action_info(
                            oem_diag_type, system_action_info
                        )

                        if use_action_info_validation:
                            await self._log_runtime(
                                "DEBUG",
                                "RedfishService",
                                f"[TaskBuild] {oem_diag_type} in ActionInfo for {system_id}: {is_in_action_info}",
                                dut_id,
                            )

                        # Build task dict
                        task = {
                            "device_type": device_type,
                            "device_id": device_id,
                            "device_config": resolved_config,
                            "payload": payload,
                            "oem_diag_type": oem_diag_type,
                            "is_in_action_info": is_in_action_info,
                            "device_identifier": device_identifier,
                            "diagnostic_type": diagnostic_type,
                        }

                        # Add to system's task list
                        if system_id not in tasks_by_system:
                            tasks_by_system[system_id] = []
                        tasks_by_system[system_id].append(task)

            # Log task summary
            total_tasks = sum(len(tasks) for tasks in tasks_by_system.values())
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"[TaskBuild] Built {total_tasks} tasks across {len(tasks_by_system)} systems: "
                + ", ".join(
                    f"{sid}={len(tasks)}" for sid, tasks in tasks_by_system.items()
                ),
                dut_id,
            )

            # ================================================================
            # PHASE 2: Execute tasks (parallel or sequential)
            # Parallel: Different systems run concurrently via asyncio.gather
            # Sequential: Systems processed one at a time (original behavior)
            # Within each system, tasks always run sequentially (BMC limitation)
            # ================================================================
            all_task_results: List[Dict[str, Any]] = []

            if parallel_collection and len(tasks_by_system) > 1:
                # Parallel execution across systems
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"[Parallel] Executing {len(tasks_by_system)} systems in parallel "
                    f"(max_concurrent={max_concurrent_tasks})",
                    dut_id,
                )

                semaphore = asyncio.Semaphore(max_concurrent_tasks)

                async def limited_collect_for_system(
                    sid: str, tasks: List[Dict]
                ) -> List[Dict]:
                    """Wrapper to limit concurrent system collections."""
                    async with semaphore:
                        return await self._collect_for_system(
                            dut_id=dut_id,
                            system_id=sid,
                            device_tasks=tasks,
                            action_info_values=action_info_by_system.get(sid, []),
                            use_action_info_validation=use_action_info_validation,
                            collector_name=collector_name,
                            collector_id=collector_id,
                            kwargs=kwargs,
                        )

                # Run all systems in parallel
                parallel_results = await asyncio.gather(
                    *[
                        limited_collect_for_system(sid, tasks)
                        for sid, tasks in tasks_by_system.items()
                    ],
                    return_exceptions=True,
                )

                # Flatten results and handle exceptions
                for sid, result in zip(tasks_by_system.keys(), parallel_results):
                    if isinstance(result, Exception):
                        await self._log_runtime(
                            "ERROR",
                            "RedfishService",
                            f"[Parallel] Exception collecting system {sid}: {str(result)}",
                            dut_id,
                        )
                        # Create failure results for all tasks in this system
                        for task in tasks_by_system[sid]:
                            all_task_results.append(
                                {
                                    "success": False,
                                    "output_files": [],
                                    "status": False,
                                    "error_messages": [
                                        f"System collection exception: {str(result)}"
                                    ],
                                    "device_type": task["device_type"],
                                    "device_id": task["device_id"],
                                    "system_id": sid,
                                    "is_in_action_info": task["is_in_action_info"],
                                    "oem_diag_type": task["oem_diag_type"],
                                }
                            )
                    else:
                        all_task_results.extend(result)

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"[Parallel] Parallel execution complete: {len(all_task_results)} results",
                    dut_id,
                )

            else:
                # Sequential execution (original behavior or single system)
                mode = "sequential" if not parallel_collection else "single-system"
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"[Sequential] Executing {len(tasks_by_system)} systems in {mode} mode",
                    dut_id,
                )

                for system_id, system_tasks in tasks_by_system.items():
                    system_results = await self._collect_for_system(
                        dut_id=dut_id,
                        system_id=system_id,
                        device_tasks=system_tasks,
                        action_info_values=action_info_by_system.get(system_id, []),
                        use_action_info_validation=use_action_info_validation,
                        collector_name=collector_name,
                        collector_id=collector_id,
                        kwargs=kwargs,
                    )
                    all_task_results.extend(system_results)

            # ================================================================
            # PHASE 3: Process all results
            # Aggregate output files, status, errors, and ActionInfo metrics
            # ================================================================
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"[Results] Processing {len(all_task_results)} task results",
                dut_id,
            )

            # Mapping: system_id -> {oem_diag_type -> [output filenames]}
            # Written as a JSON file at the end for easy query-to-file lookups.
            dump_query_map: Dict[str, Dict[str, List[str]]] = {}

            for task_result in all_task_results:
                # Extract ActionInfo-aware metadata first for conditional processing
                collection_success = task_result.get("success", False)
                is_in_action_info = task_result.get("is_in_action_info", True)
                oem_diag_type = task_result.get("oem_diag_type", "")
                system_id = task_result.get("system_id", "unknown")

                # Determine if this is an expected failure (not in ActionInfo)
                # Expected failures should not generate error logs
                is_expected_failure = (
                    use_action_info_validation
                    and not collection_success
                    and not is_in_action_info
                )

                if is_expected_failure:
                    # For expected failures (not in ActionInfo), don't generate error logs
                    # but still track the attempt for metrics
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"[ActionInfo] Expected failure for {task_result['device_type']}_{task_result['device_id']} "
                        f"on {system_id} - '{oem_diag_type}' not in ActionInfo (no error log generated)",
                        dut_id,
                    )
                    # Don't add to all_status_list (doesn't count toward success/failure rate)
                    # Don't generate error log file
                else:
                    # Process result using common function (may generate error logs)
                    raw_result = task_result.get("raw_result", task_result)
                    await self._process_collector_result(
                        result=raw_result,
                        all_output_files=all_output_files,
                        all_status_list=all_status_list,
                        error_messages=error_messages,
                        entity_type=task_result["device_type"],
                        entity_id=task_result["device_id"],
                        dut_id=dut_id,
                        collector_id=collector_id,
                    )

                # Track ActionInfo-aware results for metrics
                if use_action_info_validation:
                    if collection_success:
                        if is_in_action_info:
                            action_info_results["expected_successes"] += 1
                        else:
                            action_info_results["bonus_successes"] += 1
                    else:
                        if is_in_action_info:
                            action_info_results["expected_failures"] += 1
                        else:
                            action_info_results["unexpected_failures"] += 1

                # Populate dump query map for successful collections
                if collection_success and oem_diag_type:
                    raw_result = task_result.get("raw_result", task_result)
                    task_files = list(
                        set(
                            raw_result.get("output_files", [])
                            + raw_result.get("context", {}).get("output_files", [])
                        )
                    )
                    if task_files:
                        dump_query_map.setdefault(system_id, {})[oem_diag_type] = [
                            os.path.basename(f) for f in task_files if f
                        ]

                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"[Results] {task_result['device_type']}_{task_result['device_id']} "
                    f"on {system_id}: success={collection_success}",
                    dut_id,
                )

            # Write dump query map JSON if any successful collections were made
            if dump_query_map:
                map_data = {
                    "collector_id": collector_id,
                    "collector_name": collector_name
                    or kwargs.get("collector_name", ""),
                    "generated_at": datetime.now().isoformat(),
                    "mappings": dump_query_map,
                }
                map_filename = f"{collector_id}_dump_query_map.json"
                map_file_path = await self._save_data_to_file_with_pattern(
                    dut_id,
                    map_data,
                    map_filename,
                    collector_id=collector_id,
                )
                if map_file_path:
                    all_output_files.append(map_file_path)

            # Calculate overall success
            successful_operations = sum(all_status_list) if all_status_list else 0
            total_operations = len(all_status_list) if all_status_list else 0

            # ActionInfo-aware success calculation
            # When enabled, failures on items NOT in ActionInfo don't count against us
            action_info_adjusted_success = successful_operations
            action_info_adjusted_total = total_operations

            if (
                use_action_info_validation
                and action_info_results["action_info_available"]
            ):
                # Calculate expected total (items that were in ActionInfo)
                expected_total = (
                    action_info_results["expected_successes"]
                    + action_info_results["expected_failures"]
                )

                if expected_total > 0:
                    action_info_adjusted_success = action_info_results[
                        "expected_successes"
                    ]
                    action_info_adjusted_total = expected_total

                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"[ActionInfo] Adjusted success rate: {action_info_adjusted_success}/{action_info_adjusted_total} "
                        f"(original: {successful_operations}/{total_operations}, "
                        f"unexpected_failures_excluded: {action_info_results['unexpected_failures']}, "
                        f"bonus_successes: {action_info_results['bonus_successes']})",
                        dut_id,
                    )

            # Check if no devices were discovered - treat as skipped
            total_devices = sum(len(devices) for devices in discovered_devices.values())
            if total_devices == 0:
                no_device_reason = f"No {list(discovered_devices.keys())} devices discovered for {collector_name}"
                if complete_on_empty_targets:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"=== Device diagnostic collection complete. {no_device_reason} - treating as complete ===",
                        dut_id,
                    )
                    return await self._create_standardized_collector_result(
                        successful_operations=1,
                        total_operations=1,
                        output_files=[],
                        error_messages=[],
                        operation_name="device_diagnostic_data",
                        additional_context={
                            "collector_name": collector_name,
                            "target_baseboard": target_baseboard,
                            "devices_processed": 0,
                            "successful_collections": 1,
                            "total_collections": 1,
                            "reason": f"{no_device_reason} - nothing to collect (expected)",
                        },
                    )
                else:
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"=== Device diagnostic collection complete. {no_device_reason} - treating as skipped ===",
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
                            "reason": f"{no_device_reason} - collector skipped",
                        },
                    )

            # Log completion with ActionInfo-aware metrics if enabled
            if (
                use_action_info_validation
                and action_info_results["action_info_available"]
            ):
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"=== Device diagnostic collection complete. ActionInfo-adjusted: {action_info_adjusted_success}/{action_info_adjusted_total}, "
                    f"Raw: {successful_operations}/{total_operations}, Files: {len(all_output_files)} ===",
                    dut_id,
                )
            else:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"=== Device diagnostic collection complete. Success: {successful_operations}/{total_operations}, Files: {len(all_output_files)} ===",
                    dut_id,
                )

            # Build additional context with ActionInfo results if available
            additional_context = {
                "collector_name": collector_name,
                "target_baseboard": target_baseboard,
                "devices_processed": total_devices,
                "successful_collections": successful_operations,
                "total_collections": total_operations,
            }

            if use_action_info_validation:
                additional_context["action_info_validation"] = {
                    "enabled": True,
                    "action_info_available": action_info_results[
                        "action_info_available"
                    ],
                    "expected_successes": action_info_results["expected_successes"],
                    "expected_failures": action_info_results["expected_failures"],
                    "unexpected_failures": action_info_results["unexpected_failures"],
                    "bonus_successes": action_info_results["bonus_successes"],
                    "adjusted_success": action_info_adjusted_success,
                    "adjusted_total": action_info_adjusted_total,
                }

            return await self._create_standardized_collector_result(
                successful_operations=action_info_adjusted_success,
                total_operations=action_info_adjusted_total,
                output_files=all_output_files,
                error_messages=error_messages,
                operation_name="device_diagnostic_data",
                additional_context=additional_context,
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
            dut_config = (
                self.dut_manager.get_dut_config(dut_id) if self.dut_manager else {}
            )
            target_baseboard = dut_config.get(
                "TargetBaseboard", dut_config.get("baseboard", "")
            )
            effective_collection_config = collection_config
            baseboard_specific_config = effective_collection_config.get(
                "baseboard_specific_config", {}
            )
            if (
                baseboard_specific_config
                and target_baseboard in baseboard_specific_config
            ):
                effective_collection_config = self._deep_merge_config(
                    effective_collection_config,
                    baseboard_specific_config[target_baseboard],
                )
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Using baseboard-specific multi-step config for {target_baseboard}",
                    dut_id,
                )

            entity_type = effective_collection_config.get("entity_type", "Chassis")
            base_uri_pattern = effective_collection_config.get("base_uri_pattern", "")
            steps = effective_collection_config.get("steps", [])

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

            # Prefer filtered entities from validation when available to avoid
            # probing unrelated Redfish resources during multi-step collection.
            filtered_systems = kwargs.get("filtered_systems", [])
            filtered_managers = kwargs.get("filtered_managers", [])
            filtered_chassis = kwargs.get("filtered_chassis", [])

            entity_ids = []
            success = True
            entities_response = {}

            # Get entities to process
            if entity_type == "Chassis":
                entity_key = "chassis_id"
                if filtered_chassis:
                    entity_ids = [chassis["id"] for chassis in filtered_chassis]
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Using {len(entity_ids)} filtered chassis from validation: {entity_ids}",
                        dut_id,
                    )
                else:
                    chassis_uri = self.get_configured_uri(dut_id, "Chassis")
                    success, entities_response, _ = await self.dispatch_request(
                        dut_id, "GET", chassis_uri, bypass_cache=True
                    )
            elif entity_type == "Systems":
                entity_key = "system_id"
                if filtered_systems:
                    entity_ids = [system["id"] for system in filtered_systems]
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Using {len(entity_ids)} filtered systems from validation: {entity_ids}",
                        dut_id,
                    )
                else:
                    systems_uri = self.get_configured_uri(dut_id, "Systems")
                    success, entities_response, _ = await self.dispatch_request(
                        dut_id, "GET", systems_uri, bypass_cache=True
                    )
            elif entity_type == "Managers":
                entity_key = "manager_id"
                if filtered_managers:
                    entity_ids = [manager["id"] for manager in filtered_managers]
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Using {len(entity_ids)} filtered managers from validation: {entity_ids}",
                        dut_id,
                    )
                else:
                    managers_uri = self.get_configured_uri(dut_id, "Managers")
                    success, entities_response, _ = await self.dispatch_request(
                        dut_id, "GET", managers_uri, bypass_cache=True
                    )
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

            # Extract entity IDs when validation did not already provide them.
            if not entity_ids:
                entities = entities_response.get("Members", [])
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
                    final_output_pattern = None
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
                        member_filters = member_processing.get("filters", {})
                        filter_collection_members = member_processing.get(
                            "filter_collection_members", False
                        )
                        kept_member_uris = []

                        # Extract member URIs
                        for member in members:
                            member_uri = member.get("@odata.id")
                            if member_uri and validate_redfish_uri(member_uri):
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
                            if not self._member_matches_filters(
                                member_uri, None, member_filters
                            ):
                                continue

                            member_id = member_uri.split("/")[-1]
                            step_responses[f"{step_name}_member_id"] = member_id

                            success, member_data, _ = await self.dispatch_request(
                                dut_id, "GET", member_uri
                            )
                            if success:
                                if not self._member_matches_filters(
                                    member_uri, member_data, member_filters
                                ):
                                    continue

                                kept_member_uris.append(member_uri)
                                filtered_member_data = self._apply_list_filters_to_data(
                                    member_data,
                                    member_processing.get("saved_data_filters", []),
                                )
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
                                            filtered_member_data,
                                            function_tag,
                                            output_pattern=final_member_pattern,
                                            substitutions=step_responses,
                                            collector_id=collector_id,
                                        )
                                    )
                                    if file_path:
                                        output_files.append(file_path)

                                linked_member_resources = member_processing.get(
                                    "linked_member_resources", []
                                )

                                for linked_resource in linked_member_resources:
                                    link_name = linked_resource.get("name", "linked")
                                    link_path = linked_resource.get("link_path")
                                    linked_output_pattern = linked_resource.get(
                                        "member_output_pattern", ""
                                    )
                                    linked_filters = linked_resource.get("filters", {})
                                    member_id_variable = linked_resource.get(
                                        "member_id_variable",
                                        f"{link_name}_member_id",
                                    )
                                    member_uri_variable = linked_resource.get(
                                        "member_uri_variable",
                                        f"{link_name}_member_uri",
                                    )
                                    member_uri_path = linked_resource.get(
                                        "member_uri_path", "@odata.id"
                                    )

                                    linked_member_uris = (
                                        self._extract_member_uris_from_data(
                                            member_data, link_path, member_uri_path
                                        )
                                    )

                                    for linked_member_uri in linked_member_uris:
                                        if not self._member_matches_filters(
                                            linked_member_uri, None, linked_filters
                                        ):
                                            continue

                                        linked_member_id = linked_member_uri.rstrip(
                                            "/"
                                        ).split("/")[-1]
                                        linked_substitutions = dict(step_responses)
                                        linked_substitutions[member_id_variable] = (
                                            linked_member_id
                                        )
                                        linked_substitutions[member_uri_variable] = (
                                            linked_member_uri
                                        )

                                        success, linked_member_data, _ = (
                                            await self.dispatch_request(
                                                dut_id, "GET", linked_member_uri
                                            )
                                        )
                                        if (
                                            success
                                            and self._member_matches_filters(
                                                linked_member_uri,
                                                linked_member_data,
                                                linked_filters,
                                            )
                                            and linked_output_pattern
                                        ):
                                            final_linked_pattern = (
                                                await self.substitute_variables(
                                                    linked_output_pattern,
                                                    linked_substitutions,
                                                    dut_id,
                                                )
                                            )

                                            file_path = await self._save_data_with_common_pattern(
                                                dut_id,
                                                linked_member_data,
                                                function_tag,
                                                output_pattern=final_linked_pattern,
                                                substitutions=linked_substitutions,
                                                collector_id=collector_id,
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

                                            resource_member_processing = resource.get(
                                                "member_processing", {}
                                            )
                                            if resource_member_processing:
                                                resource_filters = (
                                                    resource_member_processing.get(
                                                        "filters", {}
                                                    )
                                                )
                                                filter_collection_members = (
                                                    resource_member_processing.get(
                                                        "filter_collection_members",
                                                        False,
                                                    )
                                                )
                                                resource_member_output_pattern = (
                                                    resource_member_processing.get(
                                                        "member_output_pattern", ""
                                                    )
                                                )
                                                resource_member_id_variable = (
                                                    resource_member_processing.get(
                                                        "member_id_variable",
                                                        f"{resource_name}_member_id",
                                                    )
                                                )
                                                resource_member_uri_variable = (
                                                    resource_member_processing.get(
                                                        "member_uri_variable",
                                                        f"{resource_name}_member_uri",
                                                    )
                                                )
                                                resource_member_uri_path = (
                                                    resource_member_processing.get(
                                                        "member_uri_path",
                                                        "@odata.id",
                                                    )
                                                )
                                                resource_link_path = (
                                                    resource_member_processing.get(
                                                        "link_path", "Members"
                                                    )
                                                )

                                                resource_member_uris = (
                                                    self._extract_member_uris_from_data(
                                                        resource_data,
                                                        resource_link_path,
                                                        resource_member_uri_path,
                                                    )
                                                )
                                                kept_resource_member_uris = []

                                                for (
                                                    resource_member_uri
                                                ) in resource_member_uris:
                                                    if not self._member_matches_filters(
                                                        resource_member_uri,
                                                        None,
                                                        resource_filters,
                                                    ):
                                                        continue

                                                    resource_member_id = (
                                                        resource_member_uri.rstrip(
                                                            "/"
                                                        ).split("/")[-1]
                                                    )
                                                    resource_substitutions = dict(
                                                        step_responses
                                                    )
                                                    resource_substitutions[
                                                        resource_member_id_variable
                                                    ] = resource_member_id
                                                    resource_substitutions[
                                                        resource_member_uri_variable
                                                    ] = resource_member_uri

                                                    success, resource_member_data, _ = (
                                                        await self.dispatch_request(
                                                            dut_id,
                                                            "GET",
                                                            resource_member_uri,
                                                        )
                                                    )
                                                    if (
                                                        success
                                                        and self._member_matches_filters(
                                                            resource_member_uri,
                                                            resource_member_data,
                                                            resource_filters,
                                                        )
                                                        and resource_member_output_pattern
                                                    ):
                                                        kept_resource_member_uris.append(
                                                            resource_member_uri
                                                        )
                                                        final_resource_member_pattern = await self.substitute_variables(
                                                            resource_member_output_pattern,
                                                            resource_substitutions,
                                                            dut_id,
                                                        )

                                                        file_path = await self._save_data_with_common_pattern(
                                                            dut_id,
                                                            resource_member_data,
                                                            function_tag,
                                                            output_pattern=final_resource_member_pattern,
                                                            substitutions=resource_substitutions,
                                                            collector_id=collector_id,
                                                        )
                                                        if file_path:
                                                            output_files.append(
                                                                file_path
                                                            )

                                                if (
                                                    filter_collection_members
                                                    and isinstance(resource_data, dict)
                                                    and "Members" in resource_data
                                                ):
                                                    filtered_members = [
                                                        member
                                                        for member in resource_data.get(
                                                            "Members", []
                                                        )
                                                        if member.get("@odata.id")
                                                        in kept_resource_member_uris
                                                    ]
                                                    filtered_resource_data = dict(
                                                        resource_data
                                                    )
                                                    filtered_resource_data[
                                                        "Members"
                                                    ] = filtered_members
                                                    if (
                                                        "Members@odata.count"
                                                        in filtered_resource_data
                                                    ):
                                                        filtered_resource_data[
                                                            "Members@odata.count"
                                                        ] = len(filtered_members)

                                                    filtered_file_path = await self._save_data_with_common_pattern(
                                                        dut_id,
                                                        filtered_resource_data,
                                                        function_tag,
                                                        output_pattern=final_resource_pattern,
                                                        substitutions=step_responses,
                                                        collector_id=collector_id,
                                                    )
                                                    if (
                                                        filtered_file_path
                                                        and filtered_file_path
                                                        not in output_files
                                                    ):
                                                        output_files.append(
                                                            filtered_file_path
                                                        )

                        if (
                            filter_collection_members
                            and isinstance(response_data, dict)
                            and "Members" in response_data
                            and final_output_pattern
                        ):
                            filtered_members = [
                                member
                                for member in response_data.get("Members", [])
                                if member.get("@odata.id") in kept_member_uris
                            ]
                            filtered_response_data = dict(response_data)
                            filtered_response_data["Members"] = filtered_members
                            if "Members@odata.count" in filtered_response_data:
                                filtered_response_data["Members@odata.count"] = len(
                                    filtered_members
                                )

                            filtered_file_path = (
                                await self._save_data_with_common_pattern(
                                    dut_id,
                                    filtered_response_data,
                                    function_tag,
                                    output_pattern=final_output_pattern,
                                    substitutions=step_responses,
                                    collector_id=collector_id,
                                )
                            )
                            if (
                                filtered_file_path
                                and filtered_file_path not in output_files
                            ):
                                output_files.append(filtered_file_path)

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

    async def _substitute_uri_variables(
        self, dut_id: str, uri_pattern: str, context: Dict[str, Any]
    ) -> str:
        """
        Substitute variables in URI pattern using context values.

        Supports patterns like {system_id}, {chassis_id}, {device_id}, etc.

        Args:
            dut_id: DUT identifier
            uri_pattern: URI pattern with placeholders
            context: Context containing variable values

        Returns:
            Substituted URI string
        """
        uri = uri_pattern

        # Simple string substitution for common variables
        # Look for {variable_name} patterns and replace with values from context
        import re

        # Find all {variable} patterns
        variables = re.findall(r"\{(\w+)\}", uri)

        for var in variables:
            # Check if variable exists in context
            if var in context:
                value = context[var]
                uri = uri.replace(f"{{{var}}}", str(value))
            else:
                await self._log_runtime(
                    "WARN",
                    "RedfishService",
                    f"[_substitute_uri_variables] Variable '{var}' not found in context for URI: {uri_pattern}",
                    dut_id,
                )

        return uri

    async def _substitute_payload_variables(
        self, dut_id: str, payload: Any, context: Dict[str, Any]
    ) -> Any:
        """
        Recursively substitute variables in payload using context values.

        Supports patterns like {system_id} in string values within the payload.

        Args:
            dut_id: DUT identifier
            payload: Payload to substitute (dict, list, str, or other)
            context: Context containing variable values

        Returns:
            Payload with substituted values
        """
        import re

        if isinstance(payload, dict):
            result = {}
            for key, value in payload.items():
                result[key] = await self._substitute_payload_variables(
                    dut_id, value, context
                )
            return result
        elif isinstance(payload, list):
            return [
                await self._substitute_payload_variables(dut_id, item, context)
                for item in payload
            ]
        elif isinstance(payload, str):
            # Find all {variable} patterns
            variables = re.findall(r"\{(\w+)\}", payload)
            result = payload
            for var in variables:
                if var in context:
                    value = context[var]
                    result = result.replace(f"{{{var}}}", str(value))
                else:
                    await self._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"[_substitute_payload_variables] Variable '{var}' not found in context for payload substitution",
                        dut_id,
                    )
            return result
        else:
            # For non-string types (int, bool, etc.), return as-is
            return payload

    async def execute_redfish_action(
        self, dut_id: str, function_tag: str = "", **kwargs
    ) -> Dict[str, Any]:
        """
        Generic Redfish action executor - execute any HTTP method (GET, POST, PUT, DELETE, PATCH).

        This is a generic building block that can be used by any collector to execute
        Redfish actions and optionally store results in context for subsequent hooks.

        Args:
            dut_id: DUT identifier
            function_tag: Function tag for logging
            **kwargs: Configuration parameters:
                - action: HTTP method (GET, POST, PUT, DELETE, PATCH) [default: "GET"]
                - uri_pattern: URI pattern with substitutions like {system_id}
                - payload: Request body for POST/PUT [default: {}]
                - store_task_id: Extract and store task ID from response [default: False]
                - context_key: Key to store task_id under in context [default: "task_id"]
                - store_response: Store full response in context [default: False]
                - response_key: Key to store response under [default: "response"]
                - wait_after_action: Wait N seconds after action [default: None]
                - timeout: Request timeout in seconds [default: 300]

        Returns:
            Dict with success status and context:
                {
                    "success": bool,
                    "context": {
                        "task_id": "...",  # if store_task_id=True
                        "response": {...}  # if store_response=True
                    },
                    "reason": str  # if failed
                }

        Examples:
            # Simple POST action
            - method: execute_redfish_action
              params:
                action: POST
                uri_pattern: "/redfish/v1/Systems/{system_id}/Actions/ComputerSystem.Reset"
                payload:
                  ResetType: PowerCycle

            # POST with task_id storage for next hook
            - method: execute_redfish_action
              params:
                action: POST
                uri_pattern: "/redfish/v1/Systems/{system_id}/Actions/ComputerSystem.StartIST"
                payload:
                  TargetSOC: ["/redfish/v1/Systems/{system_id}/CPU_0", 1]
                store_task_id: true
                context_key: ist_task_id
        """
        try:
            # Extract parameters
            action = kwargs.get("action", "GET").upper()
            uri_pattern = kwargs.get("uri_pattern", "")
            payload = kwargs.get("payload", {})
            timeout = kwargs.get("timeout", 300)

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"[execute_redfish_action] Executing {action} on {uri_pattern}",
                dut_id,
            )

            # Substitute variables in URI pattern
            uri = await self._substitute_uri_variables(dut_id, uri_pattern, kwargs)

            # Substitute variables in payload if it contains string values
            substituted_payload = await self._substitute_payload_variables(
                dut_id, payload, kwargs
            )

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                f"[execute_redfish_action] URI: {uri}, Payload: {substituted_payload}",
                dut_id,
            )

            # Execute the request using existing dispatch_request
            success, response, metadata = await self.dispatch_request(
                dut_id=dut_id,
                method=action,
                uri=uri,
                body=(
                    substituted_payload if action in ["POST", "PUT", "PATCH"] else None
                ),
                timeout=timeout,
                bypass_cache=True,
            )

            result = {
                "success": success,
                "context": {},
            }

            if not success:
                result["reason"] = f"{action} request to {uri} failed: {response}"
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"[execute_redfish_action] Failed: {result['reason']}",
                    dut_id,
                )
                return result

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"[execute_redfish_action] {action} succeeded on {uri}",
                dut_id,
            )

            # Store task ID if requested
            if kwargs.get("store_task_id", False):
                task_id = None

                # Try to extract task ID from various response formats
                if isinstance(response, dict):
                    # Check for @odata.id in response
                    if "@odata.id" in response:
                        task_uri = response["@odata.id"]
                        # Extract task ID from URI like "/redfish/v1/TaskService/Tasks/12345"
                        if "/Tasks/" in task_uri:
                            task_id = task_uri.split("/Tasks/")[-1]

                    # Check for Id field
                    elif "Id" in response:
                        task_id = response["Id"]

                if task_id:
                    context_key = kwargs.get("context_key", "task_id")
                    result["context"][context_key] = task_id

                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"[execute_redfish_action] Stored task_id '{task_id}' in context['{context_key}']",
                        dut_id,
                    )
                else:
                    await self._log_runtime(
                        "WARN",
                        "RedfishService",
                        "[execute_redfish_action] store_task_id=True but no task ID found in response",
                        dut_id,
                    )

            # Store full response if requested
            if kwargs.get("store_response", False):
                response_key = kwargs.get("response_key", "response")
                result["context"][response_key] = response

                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"[execute_redfish_action] Stored response in context['{response_key}']",
                    dut_id,
                )

            # Wait after action if requested
            wait_seconds = kwargs.get("wait_after_action")
            if wait_seconds:
                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"[execute_redfish_action] Waiting {wait_seconds} seconds after action",
                    dut_id,
                )
                await asyncio.sleep(wait_seconds)

            return result

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"[execute_redfish_action] Exception: {str(e)}",
                dut_id,
            )
            return {
                "success": False,
                "context": {},
                "reason": f"Exception during execute_redfish_action: {str(e)}",
            }

    def _resolve_hook_value_from_context(
        self, value: Any, context: Dict[str, Any]
    ) -> Any:
        """Resolve simple ${var} placeholders for hook parameters."""
        if isinstance(value, list):
            return [
                self._resolve_hook_value_from_context(item, context) for item in value
            ]
        return self._resolve_placeholder(value, context)

    def _extract_binary_blob_from_response(
        self,
        response: Any,
        binary_response_paths: Optional[List[Any]] = None,
    ) -> Optional[bytes]:
        """Extract a binary payload from bytes or a JSON/base64 response body."""
        if isinstance(response, bytes):
            return response

        if not isinstance(response, dict):
            return None

        candidate_paths = binary_response_paths or [
            "Payload",
            "Data",
            "Binary",
            "Content",
            "Oem.Nvidia.Payload",
            "Oem.Nvidia.Data",
            "Oem.NVIDIA.Payload",
            "Oem.NVIDIA.Data",
        ]

        for path in candidate_paths:
            candidate = self._extract_nested_value(response, path)
            if candidate is None:
                continue

            if isinstance(candidate, str):
                try:
                    return base64.b64decode(candidate, validate=True)
                except (ValueError, binascii.Error):
                    continue

            if isinstance(candidate, list):
                try:
                    return bytes(candidate)
                except ValueError:
                    continue

        return None

    async def _check_power_state_off(
        self,
        dut_id: str,
        power_state_uris: List[str],
        context: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """
        Require at least one configured Redfish resource to report PowerState=Off.
        """
        if not power_state_uris:
            return (
                False,
                "require_host_power_off enabled but no power_state_uris provided",
            )

        observations: List[str] = []
        found_non_off = False

        for uri_template in power_state_uris:
            uri = await self.substitute_variables(uri_template, context, dut_id)
            success, response, error_details = await self.dispatch_request(
                dut_id=dut_id,
                method="GET",
                uri=uri,
                bypass_cache=True,
                error_context=f"power state check for {uri}",
            )
            if not success:
                observations.append(
                    f"{uri}: request failed ({error_details or response})"
                )
                continue

            if not isinstance(response, dict):
                observations.append(
                    f"{uri}: invalid response type {type(response).__name__}"
                )
                continue

            power_state = response.get("PowerState")
            if power_state == "Off":
                return True, f"{uri}: PowerState=Off"
            if power_state:
                found_non_off = True
                observations.append(f"{uri}: PowerState={power_state}")
            else:
                observations.append(f"{uri}: PowerState missing")

        if found_non_off:
            return False, "; ".join(observations)
        return False, "No configured power state resource reported PowerState=Off"

    def _resolve_oem_action_target(
        self,
        resource_data: Dict[str, Any],
        action_name_candidates: List[str],
    ) -> Optional[str]:
        """Resolve an OEM action target from a resource's Actions block."""
        actions = resource_data.get("Actions", {})
        if not isinstance(actions, dict):
            return None

        for candidate in action_name_candidates:
            action_data = actions.get(candidate)
            if isinstance(action_data, dict) and action_data.get("target"):
                return action_data["target"]

        return None

    async def _download_binary_from_uri(
        self,
        dut_id: str,
        uri: str,
        context: Dict[str, Any],
        function_tag: str,
        output_pattern: str,
        collector_id: str,
    ) -> Tuple[Optional[str], Optional[bytes], Optional[str]]:
        """Download a binary blob from a Redfish URI and persist it."""
        success, response, error_details = await self.dispatch_request(
            dut_id=dut_id,
            method="GET",
            uri=uri,
            get_raw_content=True,
            bypass_cache=True,
            error_context=f"binary download from {uri}",
        )
        if not success:
            return (
                None,
                None,
                f"Failed to download binary from {uri}: {error_details or response}",
            )

        data = response
        if not isinstance(data, bytes):
            data = self._extract_binary_blob_from_response(data)
            if data is None:
                return (
                    None,
                    None,
                    f"Response from {uri} did not contain a binary payload",
                )

        file_path = await self._save_data_to_file_with_pattern(
            dut_id,
            data,
            function_tag,
            output_pattern=output_pattern,
            substitutions=context,
            collector_id=collector_id,
        )
        if not file_path:
            return None, None, f"Downloaded binary from {uri} but failed to save it"

        return file_path, data, None

    async def _save_oem_binary_metadata(
        self,
        dut_id: str,
        metadata: Dict[str, Any],
        function_tag: str,
        metadata_output_pattern: str,
        collector_id: str,
        substitutions: Dict[str, Any],
    ) -> Optional[str]:
        """Persist metadata sidecar for an OEM binary action artifact."""
        if not metadata_output_pattern:
            return None

        return await self._save_data_to_file_with_pattern(
            dut_id,
            metadata,
            function_tag,
            output_pattern=metadata_output_pattern,
            substitutions=substitutions,
            collector_id=collector_id,
        )

    async def collect_chassis_oem_binary_action(
        self,
        dut_id: str,
        function_tag: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Execute a chassis OEM action that returns or stages a binary artifact.

        Supported response paths:
        - direct binary body from the action response
        - base64 payload embedded in the action response JSON
        - Task/TaskMonitor response followed by binary download from TaskMonitor
        - explicit download URI embedded in the action or task response
        """
        try:
            collector_id = kwargs.get("collector_id", "")
            output_pattern = kwargs.get("output_pattern", "")
            metadata_output_pattern = kwargs.get("metadata_output_pattern", "")
            payload = kwargs.get("payload", {})
            action_name_candidates = kwargs.get("action_name_candidates", [])
            action_uri_fallback_pattern = kwargs.get("action_uri_fallback_pattern")
            binary_response_paths = kwargs.get("binary_response_paths")
            download_uri_paths = kwargs.get("download_uri_paths", [])
            require_host_power_off = kwargs.get("require_host_power_off", False)
            power_state_uris = kwargs.get("power_state_uris", [])
            min_size_bytes = int(kwargs.get("min_size_bytes", 0))
            hash_algorithm = kwargs.get("hash_algorithm", "sha256")
            task_max_retries = int(kwargs.get("task_max_retries", 50))
            task_poll_interval = int(kwargs.get("task_poll_interval", 30))
            action_timeout = int(
                kwargs.get("action_timeout", kwargs.get("timeout", 300))
            )

            raw_uri_list = self._resolve_hook_value_from_context(
                kwargs.get("uri_list", []), kwargs
            )
            if isinstance(raw_uri_list, str):
                uri_list = [raw_uri_list]
            else:
                uri_list = [uri for uri in raw_uri_list if uri]

            if not uri_list:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="chassis_oem_binary_action",
                    additional_context={
                        "status": "skipped",
                        "reason": "No chassis OEM action targets provided",
                    },
                    dut_id=dut_id,
                    collector_id=collector_id,
                )

            output_files: List[str] = []
            error_messages: List[str] = []
            successful_operations = 0

            for chassis_uri in uri_list:
                context = dict(kwargs)
                context.update(self._extract_entity_id_from_uri(chassis_uri))
                chassis_id = context.get(
                    "chassis_id"
                ) or self._extract_entity_id_from_uri(chassis_uri, "Chassis")
                context["chassis_id"] = chassis_id

                socket_match = re.search(r"ProcessorModule_(\d+)_", str(chassis_id))
                socket_id = socket_match.group(1) if socket_match else "unknown"
                context["socket_id"] = socket_id

                success, chassis_data, error_details = await self.dispatch_request(
                    dut_id=dut_id,
                    method="GET",
                    uri=chassis_uri,
                    bypass_cache=True,
                    error_context=f"resolve chassis OEM action for {chassis_uri}",
                )
                if not success or not isinstance(chassis_data, dict):
                    error_messages.append(
                        f"{chassis_uri}: failed to retrieve chassis resource ({error_details or chassis_data})"
                    )
                    continue

                action_target = self._resolve_oem_action_target(
                    chassis_data, action_name_candidates
                )
                if not action_target and action_uri_fallback_pattern:
                    action_target = await self.substitute_variables(
                        action_uri_fallback_pattern, context, dut_id
                    )

                if not action_target:
                    error_messages.append(
                        f"{chassis_uri}: OEM action target not found for candidates {action_name_candidates}"
                    )
                    continue

                if require_host_power_off:
                    host_off, reason = await self._check_power_state_off(
                        dut_id, power_state_uris, context
                    )
                    if not host_off:
                        error_messages.append(
                            f"{chassis_id}: host power precondition failed ({reason})"
                        )
                        continue

                substituted_payload = await self._substitute_payload_variables(
                    dut_id, payload, context
                )
                post_success, post_response, _ = await self.dispatch_request(
                    dut_id=dut_id,
                    method="POST",
                    uri=action_target,
                    body=substituted_payload,
                    timeout=action_timeout,
                    bypass_cache=True,
                    error_context=f"invoke OEM action {action_target}",
                )
                if not post_success:
                    error_messages.append(
                        f"{chassis_id}: OEM action failed at {action_target}: {post_response}"
                    )
                    continue

                saved_file_path: Optional[str] = None
                artifact_bytes: Optional[bytes] = None
                action_response_mode = "unknown"

                direct_blob = self._extract_binary_blob_from_response(
                    post_response, binary_response_paths
                )
                if direct_blob is not None:
                    action_response_mode = (
                        "direct_binary"
                        if isinstance(post_response, bytes)
                        else "direct_base64_json"
                    )
                    saved_file_path = await self._save_data_to_file_with_pattern(
                        dut_id,
                        direct_blob,
                        function_tag,
                        output_pattern=output_pattern,
                        substitutions=context,
                        collector_id=collector_id,
                    )
                    artifact_bytes = direct_blob
                else:
                    download_uri = None
                    task_id = None
                    task_monitor_uri = None

                    if isinstance(post_response, dict):
                        for path in download_uri_paths:
                            candidate_uri = self._extract_nested_value(
                                post_response, path
                            )
                            if isinstance(candidate_uri, str) and candidate_uri:
                                download_uri = candidate_uri
                                break

                        task_monitor_uri = post_response.get("TaskMonitor")
                        odata_id = post_response.get("@odata.id", "")
                        if isinstance(odata_id, str) and "/Tasks/" in odata_id:
                            task_id = odata_id.split("/Tasks/")[-1]
                        elif post_response.get("Id") and not download_uri:
                            task_id = str(post_response["Id"])

                    if task_id:
                        action_response_mode = "task"
                        monitor_result = await self.monitor_task(
                            dut_id=dut_id,
                            task_id=task_id,
                            success_states=["Completed", "CompletedOK", "Success"],
                            failure_states=[
                                "Exception",
                                "Cancelled",
                                "Killed",
                                "Failed",
                            ],
                            terminal_states=[
                                "Completed",
                                "CompletedOK",
                                "Success",
                                "Exception",
                                "Cancelled",
                                "Killed",
                                "Failed",
                            ],
                            max_retries=task_max_retries,
                            poll_interval=task_poll_interval,
                        )
                        if not monitor_result.get("success", False):
                            error_messages.append(
                                f"{chassis_id}: task {task_id} did not complete successfully ({monitor_result.get('reason')})"
                            )
                            continue

                        if not task_monitor_uri:
                            task_service_uri = self.get_configured_uri(
                                dut_id, "TaskService"
                            )
                            task_monitor_uri = (
                                f"{task_service_uri}/TaskMonitors/{task_id}"
                            )

                        saved_file_path, artifact_bytes, error_message = (
                            await self._download_binary_from_uri(
                                dut_id=dut_id,
                                uri=task_monitor_uri,
                                context=context,
                                function_tag=function_tag,
                                output_pattern=output_pattern,
                                collector_id=collector_id,
                            )
                        )
                        if error_message:
                            error_messages.append(f"{chassis_id}: {error_message}")
                            continue
                    elif download_uri:
                        action_response_mode = "download_uri"
                        saved_file_path, artifact_bytes, error_message = (
                            await self._download_binary_from_uri(
                                dut_id=dut_id,
                                uri=download_uri,
                                context=context,
                                function_tag=function_tag,
                                output_pattern=output_pattern,
                                collector_id=collector_id,
                            )
                        )
                        if error_message:
                            error_messages.append(f"{chassis_id}: {error_message}")
                            continue
                    else:
                        error_messages.append(
                            f"{chassis_id}: OEM action response did not contain a binary payload, task reference, or download URI"
                        )
                        continue

                if not saved_file_path or artifact_bytes is None:
                    error_messages.append(
                        f"{chassis_id}: binary artifact was retrieved but could not be saved"
                    )
                    continue

                if min_size_bytes and len(artifact_bytes) < min_size_bytes:
                    error_messages.append(
                        f"{chassis_id}: binary artifact smaller than expected ({len(artifact_bytes)} < {min_size_bytes} bytes)"
                    )
                    continue

                output_files.append(saved_file_path)
                successful_operations += 1

                artifact_hash = None
                try:
                    artifact_hash = hashlib.new(
                        hash_algorithm, artifact_bytes
                    ).hexdigest()
                except ValueError:
                    artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()
                    hash_algorithm = "sha256"

                metadata = {
                    "chassis_id": chassis_id,
                    "socket_id": socket_id,
                    "resource_uri": chassis_uri,
                    "action_target": action_target,
                    "read_method": "redfish_oem",
                    "response_mode": action_response_mode,
                    "size_bytes": len(artifact_bytes),
                    hash_algorithm: artifact_hash,
                    "artifact_path": saved_file_path,
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }
                metadata_path = await self._save_oem_binary_metadata(
                    dut_id=dut_id,
                    metadata=metadata,
                    function_tag=function_tag,
                    metadata_output_pattern=metadata_output_pattern,
                    collector_id=collector_id,
                    substitutions=context,
                )
                if metadata_path:
                    output_files.append(metadata_path)

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=len(uri_list),
                output_files=output_files,
                error_messages=error_messages,
                operation_name="chassis_oem_binary_action",
                additional_context={
                    "function_tag": function_tag,
                    "targets": uri_list,
                    "successful_targets": successful_operations,
                },
                dut_id=dut_id,
                collector_id=collector_id,
            )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception in collect_chassis_oem_binary_action: {e}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=0,
                output_files=[],
                error_messages=[f"Exception in collect_chassis_oem_binary_action: {e}"],
                operation_name="chassis_oem_binary_action",
                additional_context={"error_type": type(e).__name__},
                dut_id=dut_id,
                collector_id=kwargs.get("collector_id"),
            )

    async def monitor_task(
        self, dut_id: str, function_tag: str = "", **kwargs
    ) -> Dict[str, Any]:
        """
        Generic task monitoring with configurable state checking.

        Monitor a Redfish task until it reaches a terminal state. Supports reading
        task_id from context (passed from previous hook) and configurable success/failure
        state definitions.

        Args:
            dut_id: DUT identifier
            function_tag: Function tag for logging
            **kwargs: Configuration parameters:
                - task_id: Direct task ID (if not reading from context)
                - task_id_from_context: Key to read task_id from context
                - success_states: List of states considered success [default: ["Completed"]]
                - failure_states: List of states considered failure [default: ["Exception", "Cancelled", "Killed"]]
                - terminal_states: List of states to stop on [default: success + failure states]
                - check_field: Field to check in task response [default: "TaskState"]
                - max_retries: Maximum polling attempts [default: 50]
                - poll_interval: Seconds between polls [default: 30]
                - timeout_config: Config key for timeout (e.g., "REDFISH_DUMP_TIMEOUT")
                - store_result: Store full task result in context [default: False]
                - result_key: Key to store result under [default: "task_result"]
                - store_state: Store final state in context [default: False]
                - state_key: Key to store state under [default: "task_final_state"]

        Returns:
            Dict with success status and context:
                {
                    "success": bool,  # True if task reached success_states
                    "context": {
                        "task_result": {...},  # if store_result=True
                        "task_final_state": "Completed"  # if store_state=True
                    },
                    "reason": str
                }

        Examples:
            # Basic monitoring (uses defaults)
            - method: monitor_task
              params:
                task_id_from_context: ist_task_id
                max_retries: 50
                poll_interval: 30

            # Custom state checking
            - method: monitor_task
              params:
                task_id_from_context: task_id
                success_states: ["Completed", "CompletedWithWarnings"]
                failure_states: ["Exception", "Failed"]
                store_state: true
                state_key: operation_state

            # Check different field (e.g., PercentComplete)
            - method: monitor_task
              params:
                task_id_from_context: task_id
                check_field: "PercentComplete"
                success_states: ["100"]
                terminal_states: ["100", "Exception"]
        """
        try:
            # Get task ID from context or direct parameter
            task_id = kwargs.get("task_id")
            if not task_id:
                context_key = kwargs.get("task_id_from_context")
                if context_key:
                    task_id = kwargs.get(context_key)
                    await self._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"[monitor_task] Read task_id '{task_id}' from context['{context_key}']",
                        dut_id,
                    )

            if not task_id:
                error_msg = "No task_id provided (neither direct nor from context)"
                await self._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"[monitor_task] {error_msg}",
                    dut_id,
                )
                return {
                    "success": False,
                    "context": {},
                    "reason": error_msg,
                }

            # Configurable state checking
            success_states = kwargs.get("success_states", ["Completed"])
            failure_states = kwargs.get(
                "failure_states", ["Exception", "Cancelled", "Killed"]
            )
            terminal_states = kwargs.get(
                "terminal_states", success_states + failure_states
            )
            check_field = kwargs.get("check_field", "TaskState")

            # Polling configuration
            max_retries = kwargs.get("max_retries", 50)
            poll_interval = kwargs.get("poll_interval", 30)

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"[monitor_task] Monitoring task {task_id}, checking '{check_field}' for success_states={success_states}",
                dut_id,
            )

            # Build task URI
            task_service_uri = self.get_configured_uri(dut_id, "TaskService")
            task_uri = f"{task_service_uri}/Tasks/{task_id}"

            # Initial wait for quick tasks
            await asyncio.sleep(2)

            # Poll until terminal state
            for attempt in range(max_retries):
                await self._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"[monitor_task] Poll attempt {attempt + 1}/{max_retries} for task {task_id}",
                    dut_id,
                )

                # Get task status
                success, response, _ = await self.dispatch_request(
                    dut_id=dut_id,
                    method="GET",
                    uri=task_uri,
                    bypass_cache=True,
                )

                if not success:
                    await self._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"[monitor_task] Failed to get task status on attempt {attempt + 1}",
                        dut_id,
                    )
                    await asyncio.sleep(poll_interval)
                    continue

                if not isinstance(response, dict):
                    await self._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"[monitor_task] Invalid response type: {type(response)}",
                        dut_id,
                    )
                    await asyncio.sleep(poll_interval)
                    continue

                # Check the configured field
                current_state = response.get(check_field)

                if not current_state:
                    await self._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"[monitor_task] Field '{check_field}' not found in response",
                        dut_id,
                    )
                    await asyncio.sleep(poll_interval)
                    continue

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"[monitor_task] Task {task_id} current {check_field}: {current_state}",
                    dut_id,
                )

                # Check if we've reached a terminal state
                if current_state in terminal_states:
                    # Determine success based on configured states
                    is_success = current_state in success_states

                    result = {
                        "success": is_success,
                        "context": {},
                        "reason": f"Task reached {check_field}='{current_state}' (success={is_success})",
                    }

                    await self._log_runtime(
                        "INFO" if is_success else "WARN",
                        "RedfishService",
                        f"[monitor_task] {result['reason']}",
                        dut_id,
                    )

                    # Store full result if requested
                    if kwargs.get("store_result", False):
                        result_key = kwargs.get("result_key", "task_result")
                        result["context"][result_key] = response
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"[monitor_task] Stored task result in context['{result_key}']",
                            dut_id,
                        )

                    # Store state if requested
                    if kwargs.get("store_state", False):
                        state_key = kwargs.get("state_key", "task_final_state")
                        result["context"][state_key] = current_state
                        await self._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"[monitor_task] Stored state '{current_state}' in context['{state_key}']",
                            dut_id,
                        )

                    return result

                # Not terminal yet, wait and retry
                await asyncio.sleep(poll_interval)

            # Timeout
            error_msg = f"Task monitoring timed out after {max_retries * poll_interval}s (max_retries={max_retries}, poll_interval={poll_interval})"
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"[monitor_task] {error_msg}",
                dut_id,
            )
            return {
                "success": False,
                "context": {},
                "reason": error_msg,
            }

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"[monitor_task] Exception: {str(e)}",
                dut_id,
            )
            return {
                "success": False,
                "context": {},
                "reason": f"Exception during monitor_task: {str(e)}",
            }

    async def _wait_for_system_ready_after_reset(
        self,
        dut_id: str,
        system_id: str,
        timeout_seconds: int,
        poll_interval: int,
    ) -> Tuple[bool, str]:
        """Wait for a system resource to become reachable again after a reset."""
        system_uri = f"/redfish/v1/Systems/{system_id}"
        deadline = time.monotonic() + max(0, timeout_seconds)
        attempt = 0
        last_observation = "system resource not reachable"

        while True:
            attempt += 1
            success, response, error_details = await self.dispatch_request(
                dut_id=dut_id,
                method="GET",
                uri=system_uri,
                bypass_cache=True,
            )
            if success and isinstance(response, dict):
                power_state = response.get("PowerState")
                boot_progress = response.get("BootProgress")
                if power_state == "On":
                    return True, "PowerState=On"
                if isinstance(boot_progress, dict):
                    last_state = boot_progress.get("LastState")
                    if last_state:
                        return True, f"BootProgress.LastState={last_state}"

                # Some platforms do not expose useful power/boot indicators. A
                # successful GET confirms the system resource is reachable again.
                return True, "system resource reachable"

            last_observation = str(error_details or response)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            await self._log_runtime(
                "DEBUG",
                "RedfishService",
                (
                    f"[ist] Waiting for {system_id} to return after entry reset; "
                    f"attempt {attempt}, remaining={int(remaining)}s"
                ),
                dut_id,
            )
            await asyncio.sleep(min(max(1, poll_interval), remaining))

        return False, last_observation

    async def _start_ist_for_system(
        self,
        dut_id: str,
        system_id: str,
        start_uri_pattern: str,
        payload: Dict[str, Any],
        start_context: Dict[str, Any],
        task_service_uri: str,
    ) -> Tuple[Optional[str], Optional[str], Union[Dict[str, Any], str]]:
        """Start IST for a system and extract the task metadata."""
        substituted_start_uri = await self._substitute_uri_variables(
            dut_id, start_uri_pattern, start_context
        )
        substituted_start_payload = await self._substitute_payload_variables(
            dut_id, payload, start_context
        )

        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"[ist] Starting IST for {system_id} via {substituted_start_uri}",
            dut_id,
        )
        start_success, start_response, _ = await self.dispatch_request(
            dut_id=dut_id,
            method="POST",
            uri=substituted_start_uri,
            body=substituted_start_payload,
            bypass_cache=True,
        )
        if not start_success:
            return (
                None,
                None,
                f"Systems {system_id}: failed to start IST: {start_response}",
            )

        task_id = None
        task_monitor_uri = None
        if isinstance(start_response, dict):
            task_monitor_uri = start_response.get("TaskMonitor")
            odata_id = start_response.get("@odata.id", "")
            if odata_id and "/Tasks/" in odata_id:
                task_id = odata_id.split("/Tasks/")[-1]
            elif start_response.get("Id"):
                task_id = str(start_response["Id"])

        if not task_id:
            return (
                None,
                None,
                f"Systems {system_id}: IST start response did not include a task ID",
            )

        if not task_monitor_uri:
            task_monitor_uri = f"{task_service_uri}/TaskMonitors/{task_id}"

        return task_id, task_monitor_uri, start_response

    async def _monitor_ist_initial_phase(
        self,
        dut_id: str,
        task_id: str,
        max_retries: int,
        poll_interval: int,
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Monitor IST until it reaches a runnable or completed state."""
        initial_monitor = await self.monitor_task(
            dut_id=dut_id,
            task_id=task_id,
            success_states=["Suspended", "Completed"],
            failure_states=["Exception", "Cancelled", "Killed"],
            terminal_states=[
                "Suspended",
                "Completed",
                "Exception",
                "Cancelled",
                "Killed",
            ],
            max_retries=max_retries,
            poll_interval=poll_interval,
            store_state=True,
            state_key="ist_initial_state",
            store_result=True,
            result_key="ist_initial_result",
        )
        initial_state = initial_monitor.get("context", {}).get("ist_initial_state")
        return initial_monitor.get("success", False), initial_state, initial_monitor

    async def _handle_ist_entry_power_cycle(
        self,
        dut_id: str,
        system_id: str,
        reset_uri: str,
        payload: Dict[str, Any],
        task_id: str,
        wait_after_entry_reset: int,
        poll_interval: int,
    ) -> Optional[str]:
        """Issue the entry power cycle and optionally verify the system returns."""
        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"[ist] Task {task_id} suspended for {system_id}; issuing entry power cycle",
            dut_id,
        )
        reset_success, reset_response, _ = await self.dispatch_request(
            dut_id=dut_id,
            method="POST",
            uri=reset_uri,
            body=payload,
            bypass_cache=True,
        )
        if not reset_success:
            return f"Systems {system_id}: failed to power cycle into IST mode: {reset_response}"

        if wait_after_entry_reset:
            verification_success, verification_reason = (
                await self._wait_for_system_ready_after_reset(
                    dut_id=dut_id,
                    system_id=system_id,
                    timeout_seconds=wait_after_entry_reset,
                    poll_interval=poll_interval,
                )
            )
            if not verification_success:
                return (
                    f"Systems {system_id}: power cycle into IST mode did not complete "
                    f"within {wait_after_entry_reset}s: {verification_reason}"
                )

        return None

    async def _monitor_ist_completion(
        self,
        dut_id: str,
        task_id: str,
        max_retries: int,
        poll_interval: int,
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """Monitor IST until the task reaches completion."""
        completion_monitor = await self.monitor_task(
            dut_id=dut_id,
            task_id=task_id,
            success_states=["Completed"],
            failure_states=["Exception", "Cancelled", "Killed"],
            terminal_states=[
                "Completed",
                "Exception",
                "Cancelled",
                "Killed",
            ],
            max_retries=max_retries,
            poll_interval=poll_interval,
            store_state=True,
            state_key="ist_completion_state",
            store_result=True,
            result_key="ist_completion_result",
        )
        completion_state = completion_monitor.get("context", {}).get(
            "ist_completion_state"
        )
        return completion_state, completion_monitor

    async def _download_ist_results(
        self,
        dut_id: str,
        task_monitor_uri: str,
        system_id: str,
        function_tag: str,
        output_pattern: str,
        task_id: str,
        collector_id: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Download and persist IST results for a system."""
        await self._log_runtime(
            "INFO",
            "RedfishService",
            f"[ist] Downloading IST results for {system_id} from {task_monitor_uri}",
            dut_id,
        )
        download_success, download_data, _ = await self.dispatch_request(
            dut_id=dut_id,
            method="GET",
            uri=task_monitor_uri,
            get_raw_content=True,
            bypass_cache=True,
        )
        if not download_success or not isinstance(download_data, bytes):
            return (
                None,
                f"Systems {system_id}: failed to download IST results from "
                f"{task_monitor_uri}: {download_data}",
            )

        file_path = await self._save_data_to_file_with_pattern(
            dut_id,
            download_data,
            function_tag,
            output_pattern=output_pattern,
            substitutions={
                "system_id": system_id,
                "task_id": task_id,
            },
            collector_id=collector_id,
        )
        if file_path:
            return file_path, None

        return (
            None,
            f"Systems {system_id}: IST results downloaded but could not be saved",
        )

    async def _perform_ist_exit_power_cycle(
        self,
        dut_id: str,
        system_id: str,
        reset_uri: str,
        payload: Dict[str, Any],
        completion_state: Optional[str],
        wait_after_exit_reset: int,
    ) -> None:
        """Issue the post-IST power cycle back to functional mode."""
        await self._log_runtime(
            "INFO",
            "RedfishService",
            (
                f"[ist] Issuing exit power cycle for {system_id} "
                f"after state {completion_state}"
            ),
            dut_id,
        )
        await self.dispatch_request(
            dut_id=dut_id,
            method="POST",
            uri=reset_uri,
            body=payload,
            bypass_cache=True,
        )
        if wait_after_exit_reset:
            await asyncio.sleep(wait_after_exit_reset)

    async def run_ist_workflow(
        self,
        dut_id: str,
        function_tag: str = "",
        entity_type: str = "Systems",
        start_uri_pattern: str = "/redfish/v1/Systems/{system_id}/Actions/Oem/NvidiaComputerSystem.StartIST",
        reset_uri_pattern: str = "/redfish/v1/Systems/{system_id}/Actions/ComputerSystem.Reset",
        start_payload: Optional[Dict[str, Any]] = None,
        reset_payload: Optional[Dict[str, Any]] = None,
        poll_interval: int = 30,
        wait_after_entry_reset: int = 300,
        wait_after_exit_reset: int = 300,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run the IST workflow for one or more systems.

        Workflow:
        1. Start IST
        2. Monitor until either Suspended or Completed
        3. If Suspended, issue a power cycle to enter IST mode
        4. Monitor until Completed
        5. Download results from TaskMonitor
        6. If AutoRebootOnComplete is false, power cycle back to functional mode
        """
        start_payload = start_payload or {}
        reset_payload = reset_payload or {"ResetType": "PowerCycle"}

        collector_id = kwargs.get("collector_id", function_tag)
        collector_def = kwargs.get("collector_def", {})
        output_pattern = kwargs.get("output_pattern", "")

        try:
            filtered_systems = kwargs.get("filtered_systems", [])
            if filtered_systems and entity_type == "Systems":
                entity_ids = [sys["id"] for sys in filtered_systems]
            else:
                entity_uri = self.get_configured_uri(dut_id, entity_type)
                success, entities, _ = await self.dispatch_request(
                    dut_id,
                    "GET",
                    entity_uri,
                    bypass_cache=True,
                )
                if not success:
                    return await self._create_standardized_collector_result(
                        dut_id=dut_id,
                        collector_id=collector_id,
                        successful_operations=0,
                        total_operations=1,
                        output_files=[],
                        error_messages=[f"Failed to get {entity_type}: {entities}"],
                        operation_name="ist_workflow",
                        additional_context={"entity_type": entity_type},
                    )

                entity_ids = [
                    member.get("@odata.id", "").split("/")[-1]
                    for member in entities.get("Members", [])
                    if member.get("@odata.id")
                ]

            if not entity_ids:
                return await self._create_standardized_collector_result(
                    dut_id=dut_id,
                    collector_id=collector_id,
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[f"No {entity_type} found"],
                    operation_name="ist_workflow",
                    additional_context={"entity_type": entity_type},
                )

            tool_config = {}
            if self.orchestrator and getattr(self.orchestrator, "config_manager", None):
                tool_config = self.orchestrator.config_manager.get_tool_config()
            elif self.dut_manager:
                tool_config = getattr(self.dut_manager, "tool_config", {}) or {}
            dut_config = (
                self.dut_manager.get_dut_config(dut_id)
                if self.dut_manager is not None
                else None
            )

            timeout_seconds = get_collector_timeout(
                collector_id,
                collector_def,
                dut_config,
                7200,
                tool_config,
            )
            max_retries = kwargs.get(
                "max_retries",
                max(1, int((timeout_seconds + poll_interval - 1) / poll_interval)),
            )

            output_files: List[str] = []
            error_messages: List[str] = []
            successful_systems = 0
            task_service_uri = self.get_configured_uri(dut_id, "TaskService")
            auto_reboot_on_complete = bool(
                start_payload.get("AutoRebootOnComplete", False)
            )

            for system_id in entity_ids:
                start_context = {
                    **kwargs,
                    "system_id": system_id,
                    "entity_id": system_id,
                }

                try:
                    task_id, task_monitor_uri, start_result = (
                        await self._start_ist_for_system(
                            dut_id=dut_id,
                            system_id=system_id,
                            start_uri_pattern=start_uri_pattern,
                            payload=start_payload,
                            start_context=start_context,
                            task_service_uri=task_service_uri,
                        )
                    )
                    if not task_id or not task_monitor_uri:
                        error_messages.append(
                            start_result
                            if isinstance(start_result, str)
                            else f"Systems {system_id}: failed to start IST"
                        )
                        continue

                    reset_uri = await self._substitute_uri_variables(
                        dut_id, reset_uri_pattern, start_context
                    )
                    reset_body = await self._substitute_payload_variables(
                        dut_id, reset_payload, start_context
                    )
                    initial_success, initial_state, initial_monitor = (
                        await self._monitor_ist_initial_phase(
                            dut_id=dut_id,
                            task_id=task_id,
                            max_retries=max_retries,
                            poll_interval=poll_interval,
                        )
                    )
                    if not initial_success:
                        error_messages.append(
                            f"Systems {system_id}: IST did not reach a runnable/completed state: "
                            f"{initial_monitor.get('reason', 'Unknown error')}"
                        )
                        if not auto_reboot_on_complete:
                            await self._perform_ist_exit_power_cycle(
                                dut_id=dut_id,
                                system_id=system_id,
                                reset_uri=reset_uri,
                                payload=reset_body,
                                completion_state=initial_state,
                                wait_after_exit_reset=0,
                            )
                        continue

                    completion_state = initial_state
                    if initial_state == "Suspended":
                        entry_reset_error = await self._handle_ist_entry_power_cycle(
                            dut_id=dut_id,
                            system_id=system_id,
                            reset_uri=reset_uri,
                            payload=reset_body,
                            task_id=task_id,
                            wait_after_entry_reset=wait_after_entry_reset,
                            poll_interval=poll_interval,
                        )
                        if entry_reset_error:
                            error_messages.append(entry_reset_error)
                            continue

                        completion_state, completion_monitor = (
                            await self._monitor_ist_completion(
                                dut_id=dut_id,
                                task_id=task_id,
                                max_retries=max_retries,
                                poll_interval=poll_interval,
                            )
                        )
                        completion_response = completion_monitor.get("context", {}).get(
                            "ist_completion_result", {}
                        )
                        if isinstance(completion_response, dict):
                            task_monitor_uri = (
                                completion_response.get("TaskMonitor")
                                or task_monitor_uri
                            )
                        if not completion_monitor.get("success"):
                            error_messages.append(
                                f"Systems {system_id}: IST did not complete successfully: {completion_monitor.get('reason', 'Unknown error')}"
                            )
                            if not auto_reboot_on_complete:
                                await self._perform_ist_exit_power_cycle(
                                    dut_id=dut_id,
                                    system_id=system_id,
                                    reset_uri=reset_uri,
                                    payload=reset_body,
                                    completion_state=completion_state,
                                    wait_after_exit_reset=wait_after_exit_reset,
                                )
                            continue
                    else:
                        initial_response = initial_monitor.get("context", {}).get(
                            "ist_initial_result", {}
                        )
                        if isinstance(initial_response, dict):
                            task_monitor_uri = (
                                initial_response.get("TaskMonitor") or task_monitor_uri
                            )

                    file_path, download_error = await self._download_ist_results(
                        dut_id=dut_id,
                        task_monitor_uri=task_monitor_uri,
                        system_id=system_id,
                        function_tag=function_tag,
                        output_pattern=output_pattern,
                        task_id=task_id,
                        collector_id=collector_id,
                    )
                    if download_error:
                        error_messages.append(download_error)
                    else:
                        output_files.append(file_path)
                        successful_systems += 1

                    if not auto_reboot_on_complete:
                        await self._perform_ist_exit_power_cycle(
                            dut_id=dut_id,
                            system_id=system_id,
                            reset_uri=reset_uri,
                            payload=reset_body,
                            completion_state=completion_state,
                            wait_after_exit_reset=wait_after_exit_reset,
                        )

                except Exception as system_error:
                    error_messages.append(
                        f"Systems {system_id}: IST workflow exception: {system_error}"
                    )

            return await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=collector_id,
                successful_operations=successful_systems,
                total_operations=len(entity_ids),
                output_files=output_files,
                error_messages=error_messages,
                operation_name="ist_workflow",
                additional_context={
                    "entity_type": entity_type,
                    "systems_processed": entity_ids,
                },
            )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "RedfishService",
                f"[ist] Exception: {e}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=collector_id,
                successful_operations=0,
                total_operations=0,
                output_files=[],
                error_messages=[f"Exception during IST workflow: {e}"],
                operation_name="ist_workflow",
                additional_context={"error_type": type(e).__name__},
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

            def _make_json_safe(value: Any) -> Any:
                """
                Convert arbitrary content into a JSON-serializable structure while preserving ordering.
                """
                if isinstance(value, (str, int, float, bool)) or value is None:
                    return value
                if isinstance(value, dict):
                    return {k: _make_json_safe(v) for k, v in value.items()}
                if isinstance(value, (list, tuple)):
                    return [_make_json_safe(v) for v in value]
                if isinstance(value, set):
                    # Sets are unordered; sort for deterministic JSON representation
                    return [
                        _make_json_safe(v)
                        for v in sorted(value, key=lambda item: str(item))
                    ]
                if isinstance(value, bytes):
                    try:
                        encoded = base64.b64encode(value).decode("ascii")
                    except (UnicodeDecodeError, binascii.Error):
                        encoded = str(value)
                    return {"encoding": "base64", "value": encoded}
                return str(value)

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

            # === PRE-CHECK ENDPOINT ===
            # Verify the base endpoint exists before running commands
            # This prevents wasting time on 48+ commands if the endpoint doesn't exist
            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Pre-checking endpoint availability: {base_uri}",
                dut_id,
            )

            # For POST endpoints, we need to check if the Actions endpoint exists
            # Extract the base path without the action part
            endpoint_check_uri = base_uri
            if "/Actions/" in base_uri:
                # For action URIs, check the parent resource
                endpoint_check_uri = base_uri.split("/Actions/")[0]

            success, response, _ = await self.dispatch_request(
                dut_id, "GET", endpoint_check_uri
            )

            if not success:
                skip_message = (
                    f"Endpoint not available: {endpoint_check_uri}. "
                    f"The command executor service may not be supported on this baseboard."
                )
                await self._log_runtime(
                    "WARNING",
                    "RedfishService",
                    skip_message,
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="command_executor",
                    additional_context={
                        "status": "skipped",
                        "reason": skip_message,
                        "endpoint_checked": endpoint_check_uri,
                    },
                    dut_id=dut_id,
                    collector_id=kwargs.get("collector_id"),
                )

            # If this is an Actions endpoint, also verify the action is supported
            if "/Actions/" in base_uri:
                actions = response.get("Actions", {})
                # Extract action name
                action_parts = base_uri.split("/Actions/")[-1].split("/")
                action_name = action_parts[0] if action_parts else ""

                if action_name:
                    oem_actions = actions.get("Oem", {})
                    action_key = f"#{action_name}"
                    if action_key not in oem_actions and action_name not in str(
                        actions
                    ):
                        skip_message = (
                            f"Action '{action_name}' not supported on this endpoint. "
                            f"Available actions: {list(actions.keys())}"
                        )
                        await self._log_runtime(
                            "WARNING",
                            "RedfishService",
                            skip_message,
                            dut_id,
                        )
                        return await self._create_standardized_collector_result(
                            successful_operations=0,
                            total_operations=0,
                            output_files=[],
                            error_messages=[],
                            operation_name="command_executor",
                            additional_context={
                                "status": "skipped",
                                "reason": skip_message,
                                "action_name": action_name,
                            },
                            dut_id=dut_id,
                            collector_id=kwargs.get("collector_id"),
                        )

            await self._log_runtime(
                "INFO",
                "RedfishService",
                f"Endpoint pre-check passed: {endpoint_check_uri}",
                dut_id,
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

            # === FAIL-FAST CONFIGURATION ===
            # Stop a command group if consecutive failures exceed threshold
            fail_fast_threshold = command_config.get("fail_fast_threshold", 3)
            fail_fast_enabled = command_config.get("fail_fast_enabled", True)

            # Track overall failure patterns for early termination
            total_commands_attempted = 0
            total_commands_failed = 0
            consecutive_500_errors = 0
            max_consecutive_500_for_abort = (
                5  # Abort entire collector if 5 consecutive 500s
            )

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

                # Track failures within this command group for fail-fast
                group_consecutive_failures = 0
                group_failure_reason = None
                group_skipped = False

                # Execute commands for each device instance
                for device_instance in device_instances:
                    # Check if we should skip remaining commands in this group due to fail-fast
                    if group_skipped:
                        await self._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Skipping remaining commands in group {group_name} due to fail-fast (device {device_instance})",
                            dut_id,
                        )
                        break

                    for command in commands:
                        task = command.get("task", "unknown_task").replace(
                            "{device_instance}", str(device_instance)
                        )
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
                            request_entry = {
                                "method": action,
                                "uri": base_uri,
                                "group": group_name,
                                "device_type": device_type,
                                "device_instance": device_instance,
                                "payload": _make_json_safe(payload),
                            }
                            response_entry = _make_json_safe(response_data)
                            record = {
                                "request": request_entry,
                                "response": response_entry,
                            }

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
                                    record,
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

                            # Reset failure counters on success
                            group_consecutive_failures = 0
                            consecutive_500_errors = 0
                            total_commands_attempted += 1

                        if not success:
                            total_commands_attempted += 1
                            total_commands_failed += 1
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

                            # === FAIL-FAST TRACKING ===
                            # Track consecutive failures for this group
                            group_consecutive_failures += 1
                            if group_failure_reason is None:
                                group_failure_reason = error_msg

                            # Track 500-series errors specifically
                            http_status = (
                                error_details.get("http_status")
                                if error_details
                                else None
                            )
                            is_500_error = (
                                (http_status and 500 <= http_status < 600)
                                or response_data == "retry"
                                or "HTTP 5" in str(error_msg)
                            )

                            if is_500_error:
                                consecutive_500_errors += 1
                            else:
                                consecutive_500_errors = 0  # Reset on non-500 errors

                            # Check if we should skip remaining commands in this group
                            if (
                                fail_fast_enabled
                                and group_consecutive_failures >= fail_fast_threshold
                            ):
                                await self._log_runtime(
                                    "WARNING",
                                    "RedfishService",
                                    f"FAIL-FAST: Skipping remaining commands in group '{group_name}' after {group_consecutive_failures} consecutive failures. First error: {group_failure_reason[:200] if group_failure_reason else 'Unknown'}",
                                    dut_id,
                                )
                                group_skipped = True

                            # Check if we should abort the entire collector due to persistent 500 errors
                            if consecutive_500_errors >= max_consecutive_500_for_abort:
                                await self._log_runtime(
                                    "WARNING",
                                    "RedfishService",
                                    f"ABORT: Stopping command executor after {consecutive_500_errors} consecutive HTTP 500 errors. The endpoint may be unavailable or not supported.",
                                    dut_id,
                                )
                                # Add summary error message
                                abort_msg = (
                                    f"Command executor aborted after {consecutive_500_errors} consecutive HTTP 500 errors. "
                                    f"Attempted {total_commands_attempted} commands, {total_commands_failed} failed. "
                                    f"The NSM endpoint may not be supported on this baseboard."
                                )
                                error_messages.append(abort_msg)

                                # Return early with partial results
                                return await self._create_standardized_collector_result(
                                    successful_operations=total_commands_attempted
                                    - total_commands_failed,
                                    total_operations=total_commands_attempted,
                                    output_files=output_files,
                                    error_messages=error_messages,
                                    operation_name="command_executor",
                                    additional_context={
                                        "aborted_early": True,
                                        "abort_reason": "consecutive_500_errors",
                                        "consecutive_500_count": consecutive_500_errors,
                                    },
                                    dut_id=dut_id,
                                    collector_id=kwargs.get("collector_id"),
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
                complete_on_empty_targets = kwargs.get(
                    "complete_on_empty_targets", False
                )
                reason_msg = f"No operations attempted for {function_tag} - " + (
                    "treated as complete"
                    if complete_on_empty_targets
                    else "collector skipped"
                )

                await self._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Completed command executor for {function_tag} - no operations attempted, "
                    f"treating as {'complete' if complete_on_empty_targets else 'skipped'}",
                    dut_id,
                )

                # Generate summary files
                await self._handle_collection_summary_generation(
                    dut_id=dut_id,
                    function_tag=function_tag,
                    collection_name=collection_name,
                    total_operations=0,
                    successful_operations=1 if complete_on_empty_targets else 0,
                    failed_operations=0,
                    output_files=[],
                    additional_details={},
                    kwargs=kwargs,
                )

                # Force status/reason to reflect completion when allowed
                status_override = "success" if complete_on_empty_targets else "skipped"

                result = await self._create_standardized_collector_result(
                    successful_operations=1 if complete_on_empty_targets else 0,
                    total_operations=1 if complete_on_empty_targets else 0,
                    output_files=[],
                    error_messages=[],
                    operation_name="command_executor",
                    additional_context={
                        "command_groups_processed": len(command_groups),
                        "total_commands": len(status_list),
                        "successful_commands": successful_operations,
                        "status": status_override,
                        "reason": reason_msg,
                    },
                )

                # Propagate overrides in the execution_result for downstream handling
                if complete_on_empty_targets:
                    result["status_override"] = "success"
                    result["reason_override"] = reason_msg

                return result
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
