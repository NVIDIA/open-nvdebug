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
Timing Manager for NVDebug Tool.

Handles collection and storage of detailed timing information for collector
execution, including stage timing, component timing, and performance reporting.
"""

import itertools
import json
import math
import time
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .console_output import create_sanitized_console

DEFAULT_MAX_OPERATIONS_PER_COLLECTOR = 192
DEFAULT_MAX_OPERATIONS_PER_DUT = 192
DEFAULT_MAX_OPERATIONS_PER_RUN = 100_000
# Redfish collectors can legitimately issue one request per bounded collection
# member or AdditionalDataURI.  Preserve a compact timing row for those actual
# transport attempts after the richer, shared operation budget is exhausted so
# request-capture evidence remains exactly reconcilable.
DEFAULT_MAX_REDFISH_REQUEST_OPERATIONS_PER_COLLECTOR = 1_100
DEFAULT_MAX_REDFISH_REQUEST_OPERATIONS_PER_DUT = 4_096
MAX_COMPACT_PENDING_ARTIFACT_OPERATIONS = 1_024
MAX_STAGES_PER_COLLECTOR = 16
MAX_HOOKS_PER_STAGE = 64
MAX_HOOKS_PER_COLLECTOR = 256
MAX_REQUEST_TYPES_PER_HOOK = 128
MAX_REQUEST_TYPES_PER_COLLECTOR = 512
MAX_ARTIFACT_PATHS_PER_OPERATION = 32
MAX_ARTIFACT_PATH_BYTES_PER_OPERATION = 4_096
# Compatibility alias retained for downstream imports. The value is now an
# exact JSON-serialized byte budget, not a Python character count.
MAX_ARTIFACT_PATH_CHARS_PER_OPERATION = MAX_ARTIFACT_PATH_BYTES_PER_OPERATION
MAX_UNINSTRUMENTED_ARTIFACTS_PER_COLLECTOR = 4_096
MAX_UNINSTRUMENTED_ARTIFACTS_PER_DUT = 4_096
MAX_UNINSTRUMENTED_ARTIFACTS_PER_RUN = 100_000
MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES = 1024 * 1024
MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_DUT = 1024 * 1024
MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_RUN = 25 * 1024 * 1024
MAX_UNINSTRUMENTED_ARTIFACT_PATH_CHARS = MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES
MAX_UNINSTRUMENTED_ARTIFACT_PATH_CHARS_PER_DUT = (
    MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_DUT
)
MAX_UNINSTRUMENTED_ARTIFACT_PATH_CHARS_PER_RUN = (
    MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_RUN
)
MAX_OPERATION_TEXT_BYTES = 512
MAX_OPERATION_TEXT_CHARS = MAX_OPERATION_TEXT_BYTES
MAX_OPERATION_METADATA_KEYS = 16
MAX_OPERATION_METADATA_SCAN_KEYS = 64
MAX_OPERATION_METADATA_KEY_BYTES = 128
MAX_OPERATION_METADATA_VALUE_BYTES = 128
MAX_OPERATION_METADATA_KEY_CHARS = MAX_OPERATION_METADATA_KEY_BYTES
MAX_OPERATION_METADATA_VALUE_CHARS = MAX_OPERATION_METADATA_VALUE_BYTES
_EVENT_COUNTER_KEYS = ("accepted", "deduplicated", "dropped", "malformed")


class TimingManager:
    """
    Manages timing information for collector execution.

    Tracks timing at multiple levels including collector stages, hooks, and
    high-level tool components for performance analysis and reporting.
    """

    def __init__(
        self,
        output_dir: Path,
        debug_mode: bool = False,
        *,
        max_operations_per_collector: int = DEFAULT_MAX_OPERATIONS_PER_COLLECTOR,
        max_operations_per_dut: int = DEFAULT_MAX_OPERATIONS_PER_DUT,
        max_operations_per_run: int = DEFAULT_MAX_OPERATIONS_PER_RUN,
        sanitizer: Any = None,
    ):
        """
        Initialize timing manager.

        ``current_*`` is retained as a best-effort compatibility view for
        callers/tests which inspect it directly. Runtime association uses
        ContextVar below so concurrent collector tasks cannot overwrite one
        another's stage, hook, or operation context.

        Args:
            output_dir: filesystem location used as the output dir for this
                operation.
            debug_mode: Whether debug mode is enabled or required for this
                operation.
            max_operations_per_collector: Upper bound enforced for max
                operations per collector; the consuming boundary rejects or
                truncates values that exceed it.
            max_operations_per_dut: Upper bound enforced for max operations per
                DUT; the consuming boundary rejects or truncates values that
                exceed it.
            max_operations_per_run: Upper bound enforced for max operations per
                run; the consuming boundary rejects or truncates values that
                exceed it.
            sanitizer: Optional run sanitizer applied to diagnostic timing text
                before it leaves the manager's public projection boundary.
        """
        self.output_dir = output_dir
        self.debug_mode = debug_mode
        self.sanitizer = sanitizer
        self.timing_data = {}
        # ``current_*`` is retained as a best-effort compatibility view for
        # callers/tests which inspect it directly. Runtime association uses
        # ContextVar below so concurrent collector tasks cannot overwrite one
        # another's stage, hook, or operation context.
        self.current_collector = None
        self.current_stage = None
        self.current_hook = None
        self._collector_context: ContextVar[Optional[Tuple[str, str]]] = ContextVar(
            "nvdebug_timing_collector", default=None
        )
        self._stage_context: ContextVar[Optional[str]] = ContextVar(
            "nvdebug_timing_stage", default=None
        )
        self._hook_context: ContextVar[Optional[str]] = ContextVar(
            "nvdebug_timing_hook", default=None
        )
        self._request_stack: ContextVar[Tuple[Tuple[str, str], ...]] = ContextVar(
            "nvdebug_timing_request_stack", default=()
        )
        self._operation_stack: ContextVar[Tuple[str, ...]] = ContextVar(
            "nvdebug_timing_operation_stack", default=()
        )
        self._collector_records: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._operations_by_id: Dict[str, Dict[str, Any]] = {}
        self._compact_artifact_operations: Dict[str, Dict[str, Any]] = {}
        self._operation_counter = itertools.count(1)
        self._compact_operation_counter = itertools.count(1)
        self._operation_counts_by_dut: Dict[str, int] = {}
        self._redfish_request_operation_counts_by_dut: Dict[str, int] = {}
        self._inventory_counts_by_dut: Dict[str, int] = {}
        self._inventory_path_characters_by_dut: Dict[str, int] = {}
        self._inventory_count_run = 0
        self._inventory_path_characters_run = 0
        self.max_operations_per_collector = max(1, int(max_operations_per_collector))
        self.max_operations_per_dut = max(1, int(max_operations_per_dut))
        self.max_operations_per_run = max(1, int(max_operations_per_run))
        self.retain_compact_redfish_requests = (
            self.max_operations_per_collector == DEFAULT_MAX_OPERATIONS_PER_COLLECTOR
            and self.max_operations_per_dut == DEFAULT_MAX_OPERATIONS_PER_DUT
            and self.max_operations_per_run == DEFAULT_MAX_OPERATIONS_PER_RUN
        )
        self.max_redfish_request_operations_per_collector = (
            DEFAULT_MAX_REDFISH_REQUEST_OPERATIONS_PER_COLLECTOR
            if self.max_operations_per_collector == DEFAULT_MAX_OPERATIONS_PER_COLLECTOR
            else self.max_operations_per_collector
        )
        self.max_redfish_request_operations_per_dut = (
            DEFAULT_MAX_REDFISH_REQUEST_OPERATIONS_PER_DUT
            if self.max_operations_per_dut == DEFAULT_MAX_OPERATIONS_PER_DUT
            else self.max_operations_per_dut
        )
        self.event_counters = {key: 0 for key in _EVENT_COUNTER_KEYS}

        # High-level component timing
        self.component_timing = {
            "tool_initialization": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "configuration_loading": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "dut_initialization": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "preflight_checks": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "collector_execution": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "html_report_generation": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "metadata_creation": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "cleanup": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "overall_runtime": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
        }

        # Always collect timing, but only print/save detailed reports with debug
        self.always_collect = True

    def set_sanitizer(self, sanitizer: Any) -> None:
        """
        Attach the active run sanitizer to public timing projections.

        Timing collection begins during orchestrator construction, before CLI
        configuration has supplied the sanitizer. Updating the reference here
        lets later ``timing.json`` and report projections scrub diagnostic
        operation names, metadata, and errors without changing identifiers or
        artifact paths used for reconciliation.

        Args:
            sanitizer: Sanitizer applied before diagnostic timing text leaves
                the manager boundary. ``None`` preserves the original text.

        Side Effects:
            Replaces the sanitizer used by subsequent public projections.
        """
        self.sanitizer = sanitizer

    def _sanitize_public_timing_text(self, value: Any, maximum_bytes: int) -> str:
        """
        Return bounded timing diagnostic text scrubbed by the run sanitizer.

        Bounding occurs both before and after sanitization so an unusual
        sanitizer cannot expand a small diagnostic beyond the public timing
        contract. Sanitizer failures become a fixed non-sensitive marker.

        Args:
            value: Diagnostic value retained by an operation record.
            maximum_bytes: Exact JSON-string byte ceiling applied after
                sanitization.

        Returns:
            Sanitized and bounded diagnostic text. A fixed marker is returned
            when the configured sanitizer fails or returns a non-string value.
        """
        rendered = self._bounded_json_text(value, maximum_bytes)
        sanitize = getattr(self.sanitizer, "sanitize", None)
        if not callable(sanitize):
            return rendered
        try:
            sanitized = sanitize(rendered)
        except Exception:
            return "[timing diagnostic sanitization failed]"
        if not isinstance(sanitized, str):
            return "[timing diagnostic sanitization failed]"
        return self._bounded_json_text(sanitized, maximum_bytes)

    def _project_public_operation(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Project one operation while scrubbing only diagnostic string fields.

        Operation IDs, parent links, status values, and artifact paths remain
        exact because report reconciliation depends on them. Free-form names,
        errors, and bounded metadata values pass through the active run
        sanitizer at this public boundary.

        Args:
            operation: Internal operation record owned by this manager.

        Returns:
            A public operation mapping without private bookkeeping fields or
            unsanitized diagnostic text.
        """
        public = {
            key: value for key, value in operation.items() if not key.startswith("_")
        }
        for field in ("name", "error", "stage", "hook"):
            value = public.get(field)
            if isinstance(value, str):
                public[field] = self._sanitize_public_timing_text(
                    value,
                    (
                        MAX_OPERATION_METADATA_VALUE_BYTES
                        if field == "error"
                        else MAX_OPERATION_TEXT_BYTES
                    ),
                )
        metadata = public.get("metadata")
        if isinstance(metadata, dict):
            projected_metadata: Dict[str, Any] = {}
            for key, value in metadata.items():
                projected_key = self._sanitize_public_timing_text(
                    key,
                    MAX_OPERATION_METADATA_KEY_BYTES,
                )
                if projected_key in projected_metadata:
                    continue
                projected_metadata[projected_key] = (
                    self._sanitize_public_timing_text(
                        value,
                        MAX_OPERATION_METADATA_VALUE_BYTES,
                    )
                    if isinstance(value, str)
                    else value
                )
            public["metadata"] = projected_metadata
        return public

    def _project_public_artifact_timing(
        self,
        artifact_timing: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Scrub diagnostic labels without changing an artifact's identity.

        Artifact paths and operation identifiers remain exact so status,
        manifest, and report consumers can reconcile the row with the file it
        describes. Display-only measurement labels pass through the active run
        sanitizer because callers may supply them through operation metadata.

        Args:
            artifact_timing: Internal artifact timing row owned by this manager.

        Returns:
            A public artifact timing row with bounded sanitized labels.
        """
        public = dict(artifact_timing)
        for field in ("measurement", "measurement_quality"):
            value = public.get(field)
            if isinstance(value, str):
                public[field] = self._sanitize_public_timing_text(
                    value,
                    MAX_OPERATION_TEXT_BYTES,
                )
        return public

    def _project_public_legacy_stages(
        self,
        stages: Any,
    ) -> Dict[str, Any]:
        """
        Scrub display names in the legacy stage, hook, and request tree.

        The legacy timing hierarchy stores display names as mapping keys, so
        sanitizing only mapping values is insufficient. This projection keeps
        timing values intact and drops later entries whose sanitized names
        collide with an earlier entry.

        Args:
            stages: Internal legacy stage hierarchy retained by this manager.

        Returns:
            A JSON-ready stage hierarchy with sanitized diagnostic keys.
        """
        if not isinstance(stages, dict):
            return {}
        projected_stages: Dict[str, Any] = {}
        for stage_name, stage_data in stages.items():
            if not isinstance(stage_data, dict):
                continue
            projected_stage_name = self._sanitize_public_timing_text(
                stage_name,
                MAX_OPERATION_TEXT_BYTES,
            )
            if projected_stage_name in projected_stages:
                continue
            projected_stage = self._without_internal_fields(stage_data)
            projected_hooks: Dict[str, Any] = {}
            hooks = stage_data.get("hooks", {})
            if isinstance(hooks, dict):
                for hook_name, hook_data in hooks.items():
                    if not isinstance(hook_data, dict):
                        continue
                    projected_hook_name = self._sanitize_public_timing_text(
                        hook_name,
                        MAX_OPERATION_TEXT_BYTES,
                    )
                    if projected_hook_name in projected_hooks:
                        continue
                    projected_hook = self._without_internal_fields(hook_data)
                    projected_requests: Dict[str, Any] = {}
                    requests = hook_data.get("requests", {})
                    if isinstance(requests, dict):
                        for request_name, request_data in requests.items():
                            projected_request_name = self._sanitize_public_timing_text(
                                request_name,
                                MAX_OPERATION_TEXT_BYTES,
                            )
                            if projected_request_name in projected_requests:
                                continue
                            projected_requests[projected_request_name] = (
                                self._without_internal_fields(request_data)
                            )
                    projected_hook["requests"] = projected_requests
                    projected_hooks[projected_hook_name] = projected_hook
            projected_stage["hooks"] = projected_hooks
            projected_stages[projected_stage_name] = projected_stage
        return projected_stages

    def _project_public_legacy_collector(
        self,
        collector_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Return a sanitized JSON-ready legacy collector timing record.

        Runtime-only fields are removed recursively. Diagnostic operation and
        hierarchy names use the same projection as canonical ``timing.json``
        data so debug reports do not become a weaker output boundary.

        Args:
            collector_data: Internal collector timing record owned by this
                manager.

        Returns:
            A copy without runtime bookkeeping or unsanitized diagnostics.
        """
        projected = self._without_internal_fields(collector_data)
        projected["stages"] = self._project_public_legacy_stages(
            collector_data.get("stages", {})
        )
        operations = collector_data.get("operations")
        if isinstance(operations, list):
            projected["operations"] = [
                self._project_public_operation(operation)
                for operation in operations
                if isinstance(operation, dict)
            ]
        return projected

    @staticmethod
    def _empty_event_counters() -> Dict[str, int]:
        """
        Return a fresh accounting envelope for retained timing events.

        The implementation uses current instance state to produce a fresh
        accounting envelope for retained timing events.

        Returns:
            A mapping containing empty event counters.
        """
        return {key: 0 for key in _EVENT_COUNTER_KEYS}

    @staticmethod
    def _empty_redfish_request_accounting() -> Dict[str, int]:
        """
        Return a fixed-shape accounting envelope for Redfish request spans.

        Detailed operation retention is bounded independently from request
        execution. This envelope therefore preserves the exact number of
        attempted request spans even after the operation graph reaches one of
        its collector, DUT, or run limits.

        Returns:
            A mapping containing zeroed attempted, retained, and dropped counts.
        """

        return {"attempted": 0, "retained": 0, "dropped": 0}

    @staticmethod
    def _json_text_bytes(value: str) -> int:
        """
        Return exact bytes used by the snapshot writer for one JSON string.

        The implementation uses ``value`` to produce exact bytes used by the
        snapshot writer for one JSON string.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The numeric JSON text bytes value.
        """
        return len(json.dumps(value, ensure_ascii=True).encode("utf-8")) - 2

    @classmethod
    def _bounded_json_text(cls, value: Any, maximum_bytes: int) -> str:
        """
        Bound text by its exact ensure_ascii JSON representation.

        After applying local validation, the function forwards ``value`` and
        ``maximum_bytes`` to ``join`` and preserves its return and exception
        contract.

        Args:
            value: Value evaluated while performing bound text by its exact
                ensure_ascii JSON representation.
            maximum_bytes: Upper bound enforced for bytes; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            The canonical bounded JSON text.
        """
        rendered = str(value)
        retained: List[str] = []
        observed = 0
        for character in rendered:
            character_bytes = cls._json_text_bytes(character)
            if observed + character_bytes > maximum_bytes:
                break
            retained.append(character)
            observed += character_bytes
        return "".join(retained)

    def _record_event(
        self,
        outcome: str,
        record: Optional[Dict[str, Any]] = None,
        count: int = 1,
    ) -> None:
        """
        Account for accepted, duplicate, dropped, and malformed events.

        The implementation uses ``outcome``, ``record``, and ``count`` to
        account for accepted, duplicate, dropped, and malformed events. The
        operation mutates ``record`` in place; ownership of those objects
        remains with the caller.

        Args:
            outcome: Text supplied as outcome in the format accepted by this
                function.
            record: Optional record; ``None`` selects the function's default
                behavior.
            count: Numeric count used by the operation's bounded accounting.
        """
        if outcome not in self.event_counters or count <= 0:
            return
        self.event_counters[outcome] += count
        if record is not None:
            counters = record.setdefault(
                "_event_counters", self._empty_event_counters()
            )
            counters[outcome] += count

    @staticmethod
    def _bounded_metadata_value(value: Any) -> Any:
        """
        Describe metadata without retaining arbitrary nested payloads.

        Preserve scalar semantics used by timing consumers (for example
        measurement_quality) while bounding catalog-controlled text.

        Args:
            value: Value evaluated while performing describe metadata without
                retaining arbitrary nested payloads.

        Returns:
            The bounded metadata value selected by the operation.
        """
        if isinstance(value, float) and not math.isfinite(value):
            return None
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, (str, Path)):
            # Preserve scalar semantics used by timing consumers (for example
            # measurement_quality) while bounding catalog-controlled text.
            return TimingManager._bounded_json_text(
                value, MAX_OPERATION_METADATA_VALUE_BYTES
            )
        try:
            item_count = len(value)
        except (TypeError, OverflowError):
            item_count = None
        summary: Dict[str, Any] = {"type": type(value).__name__}
        if item_count is not None:
            summary["item_count"] = item_count
        return summary

    @classmethod
    def _bounded_metadata(cls, metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Return a deterministic shallow preview of operation metadata.

        The implementation uses ``metadata`` to produce a deterministic shallow
        preview of operation metadata.

        Args:
            metadata: Mapping supplying fields for deterministic shallow preview
                of operation metadata.

        Returns:
            A mapping containing bounded metadata.
        """
        if not metadata:
            return {}
        candidates: List[Tuple[str, Any]] = []
        for key in itertools.islice(metadata, MAX_OPERATION_METADATA_SCAN_KEYS):
            if not isinstance(key, (str, int, float, bool)):
                continue
            bounded_key = cls._bounded_json_text(key, MAX_OPERATION_METADATA_KEY_BYTES)
            candidates.append((bounded_key, key))
        candidates.sort(key=lambda item: (item[0], type(item[1]).__name__))
        bounded: Dict[str, Any] = {}
        for bounded_key, original_key in candidates:
            if bounded_key in bounded:
                continue
            bounded[bounded_key] = cls._bounded_metadata_value(metadata[original_key])
            if len(bounded) >= MAX_OPERATION_METADATA_KEYS:
                break
        return bounded

    @classmethod
    def _merge_bounded_metadata(
        cls,
        current: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Merge metadata without allowing repeated updates to bypass the cap.

        The implementation uses ``current`` and ``metadata`` to merge metadata
        without allowing repeated updates to bypass the cap.

        Args:
            current: Mapping supplying fields for merge metadata without
                allowing repeated updates to bypass the cap.
            metadata: Mapping supplying fields for merge metadata without
                allowing repeated updates to bypass the cap.

        Returns:
            The validated ``merged``.
        """
        merged = dict(current)
        for key, value in cls._bounded_metadata(metadata).items():
            if key in merged or len(merged) < MAX_OPERATION_METADATA_KEYS:
                merged[key] = value
        return merged

    def start_collector(self, collector_id: str, dut_id: str) -> None:
        """
        Start timing for a collector.

        Preserve the historical collector-id lookup for existing report code.
        The tuple-keyed store above is authoritative when two DUTs execute the
        same collector concurrently.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        if not self.always_collect:
            return

        key = (str(dut_id), str(collector_id))
        self.current_collector = collector_id
        record = {
            "collector_id": collector_id,
            "dut_id": dut_id,
            "start_time": time.time(),
            "_start_monotonic": time.perf_counter(),
            "stages": {},
            "operations": [],
            "_compact_artifact_timings": {},
            "_event_counters": self._empty_event_counters(),
            "_redfish_request_accounting": (self._empty_redfish_request_accounting()),
            "_redfish_request_operation_count": 0,
            "_uninstrumented_artifacts": {},
            "_uninstrumented_artifact_path_characters": 0,
            "_hook_entry_count": 0,
            "_request_entry_count": 0,
            "total_time": 0.0,
            "status": "running",
        }
        self._collector_records[key] = record
        # Preserve the historical collector-id lookup for existing report code.
        # The tuple-keyed store above is authoritative when two DUTs execute the
        # same collector concurrently.
        self.timing_data[collector_id] = record
        self._collector_context.set(key)
        self._stage_context.set(None)
        self._hook_context.set(None)
        self._request_stack.set(())
        self._operation_stack.set(())

    def end_collector(self, collector_id: str, status: str = "completed") -> None:
        """
        End timing for a collector.

        The implementation uses ``collector_id`` and ``status`` to end timing
        for a collector. It updates ``current_collector`` on the instance as
        part of that state transition.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            status: Text supplied as status in the format accepted by this
                function.
        """
        if not self.always_collect:
            return

        context_key = self._collector_context.get()
        record = None
        if context_key and context_key[1] == str(collector_id):
            record = self._collector_records.get(context_key)
        if record is None:
            # Compatibility fallback for older direct callers which do not run
            # inside the task that called start_collector().
            record = self.timing_data.get(collector_id)
        if record is None:
            return

        for operation in record.get("operations", []):
            if operation.get("status") == "running":
                self.end_operation(
                    operation.get("operation_id"),
                    status=("success" if status == "completed" else status),
                )
        record_key = (
            str(record.get("dut_id", "")),
            str(record.get("collector_id", "")),
        )
        for operation_id, operation in list(self._compact_artifact_operations.items()):
            if operation.get("_collector_key") == record_key:
                self._compact_artifact_operations.pop(operation_id, None)
                self._record_event("dropped", record)
        record["end_time"] = time.time()
        record["_end_monotonic"] = time.perf_counter()
        record["total_time"] = record["end_time"] - record["start_time"]
        record["status"] = status
        self.current_collector = None
        self._collector_context.set(None)
        self._stage_context.set(None)
        self._hook_context.set(None)
        self._request_stack.set(())
        self._operation_stack.set(())

    def start_stage(self, stage_name: str) -> None:
        """
        Start timing for a stage.

        The implementation uses ``stage_name`` to start timing for a stage. It
        updates ``current_stage`` on the instance as part of that state
        transition.

        Args:
            stage_name: Stable stage name used for lookup and operator-facing
                diagnostics.

        Returns:
            The validated ``operation_id``, or ``None`` when no value qualifies.
        """
        key = self._collector_context.get()
        if not self.always_collect or key is None:
            return

        record = self._collector_records.get(key)
        if record is None:
            return
        if not isinstance(stage_name, str) or not stage_name.strip():
            self._record_event("malformed", record)
            return
        bounded_stage_name = self._bounded_json_text(
            stage_name.strip(), MAX_OPERATION_TEXT_BYTES
        )
        self.current_stage = bounded_stage_name
        self._stage_context.set(bounded_stage_name)
        if bounded_stage_name not in record["stages"]:
            if len(record["stages"]) >= MAX_STAGES_PER_COLLECTOR:
                self._record_event("dropped", record)
                return None
        operation_id = self.start_operation(
            "stage", bounded_stage_name, contributes_to_active_time=False
        )
        if operation_id is None:
            return None
        if bounded_stage_name not in record["stages"]:
            record["stages"][bounded_stage_name] = {
                "start_time": time.time(),
                "_start_monotonic": time.perf_counter(),
                "hooks": {},
                "total_time": 0.0,
            }
        else:
            stage_data = record["stages"][bounded_stage_name]
            stage_data["start_time"] = time.time()
            stage_data["_start_monotonic"] = time.perf_counter()
        return operation_id

    def end_stage(self, stage_name: str) -> None:
        """
        End timing for a stage.

        The implementation uses ``stage_name`` to end timing for a stage. It
        updates ``current_stage`` on the instance as part of that state
        transition.

        Args:
            stage_name: Stable stage name used for lookup and operator-facing
                diagnostics.
        """
        key = self._collector_context.get()
        if not self.always_collect or key is None:
            return

        record = self._collector_records.get(key)
        if record is None:
            return
        bounded_stage_name = self._bounded_json_text(
            str(stage_name).strip(), MAX_OPERATION_TEXT_BYTES
        )
        if bounded_stage_name in record["stages"]:
            stage_data = record["stages"][bounded_stage_name]
            stage_data["end_time"] = time.time()
            stage_data["_end_monotonic"] = time.perf_counter()
            stage_data["total_time"] = stage_data["end_time"] - stage_data["start_time"]
        self._end_latest_scope_operation("stage", bounded_stage_name)
        self.current_stage = None
        self._stage_context.set(None)

    def start_hook(self, hook_name: str) -> None:
        """
        Start timing for a hook.

        The implementation uses ``hook_name`` to start timing for a hook. It
        updates ``current_hook`` on the instance as part of that state
        transition.

        Args:
            hook_name: Callable invoked at the hook name boundary.

        Returns:
            The validated ``operation_id``, or ``None`` when no value qualifies.
        """
        if (
            not self.always_collect
            or self._collector_context.get() is None
            or not self._stage_context.get()
        ):
            return

        key = self._collector_context.get()
        record = self._collector_records.get(key) if key else None
        stage_name = self._stage_context.get()
        if record is None:
            return
        if stage_name not in record["stages"]:
            if isinstance(hook_name, str) and hook_name.strip():
                rejected_hook = self._bounded_json_text(
                    hook_name.strip(), MAX_OPERATION_TEXT_BYTES
                )
                self.current_hook = rejected_hook
                self._hook_context.set(rejected_hook)
            self._record_event("dropped", record)
            return

        if not isinstance(hook_name, str) or not hook_name.strip():
            self._record_event("malformed", record)
            return
        bounded_hook_name = self._bounded_json_text(
            hook_name.strip(), MAX_OPERATION_TEXT_BYTES
        )
        self.current_hook = bounded_hook_name
        self._hook_context.set(bounded_hook_name)
        stage_data = record["stages"][stage_name]
        if bounded_hook_name not in stage_data["hooks"]:
            if (
                len(stage_data["hooks"]) >= MAX_HOOKS_PER_STAGE
                or record.get("_hook_entry_count", 0) >= MAX_HOOKS_PER_COLLECTOR
            ):
                self._record_event("dropped", record)
                return None
        operation_id = self.start_operation(
            "hook", bounded_hook_name, contributes_to_active_time=True
        )
        if operation_id is None:
            return None
        if bounded_hook_name not in stage_data["hooks"]:
            stage_data["hooks"][bounded_hook_name] = {
                "start_time": time.time(),
                "_start_monotonic": time.perf_counter(),
                "requests": {},
                "total_time": 0.0,
            }
            record["_hook_entry_count"] = record.get("_hook_entry_count", 0) + 1
        else:
            hook_data = stage_data["hooks"][bounded_hook_name]
            hook_data["start_time"] = time.time()
            hook_data["_start_monotonic"] = time.perf_counter()
        return operation_id

    def end_hook(
        self,
        hook_name: str,
        *,
        artifact_paths: Optional[List[str]] = None,
        status: str = "success",
    ) -> None:
        """
        End timing for a hook.

        The implementation uses ``hook_name``, ``artifact_paths``, and
        ``status`` to end timing for a hook. It updates ``current_hook`` on the
        instance as part of that state transition.

        Args:
            hook_name: Callable invoked at the hook name boundary.
            artifact_paths: Filesystem locations processed in caller-provided
                order.
            status: Text supplied as status in the format accepted by this
                function.
        """
        if (
            not self.always_collect
            or self._collector_context.get() is None
            or not self._stage_context.get()
        ):
            return

        key = self._collector_context.get()
        record = self._collector_records.get(key) if key else None
        stage_name = self._stage_context.get()
        if record is None:
            return
        if stage_name not in record["stages"]:
            self._record_event("dropped", record)
            return

        stage_data = record["stages"][stage_name]
        bounded_hook_name = self._bounded_json_text(
            str(hook_name).strip(), MAX_OPERATION_TEXT_BYTES
        )
        if bounded_hook_name in stage_data["hooks"]:
            hook_data = stage_data["hooks"][bounded_hook_name]
            hook_data["end_time"] = time.time()
            hook_data["_end_monotonic"] = time.perf_counter()
            hook_data["total_time"] = hook_data["end_time"] - hook_data["start_time"]
        self._end_latest_scope_operation(
            "hook",
            bounded_hook_name,
            artifact_paths=artifact_paths,
            status=status,
        )
        self.current_hook = None
        self._hook_context.set(None)

    def start_request(self, request_name: str) -> None:
        """
        Start timing for a Redfish/IPMI request.

        The implementation uses ``request_name`` to start timing for a
        Redfish/IPMI request.

        Args:
            request_name: Stable request name used for lookup and
                operator-facing diagnostics.

        Returns:
            The validated ``operation_id``, or ``None`` when no value qualifies.
        """
        key = self._collector_context.get()
        stage_name = self._stage_context.get()
        hook_name = self._hook_context.get()
        if not self.always_collect or key is None or not stage_name or not hook_name:
            return

        record = self._collector_records.get(key)
        if record is None:
            return
        if stage_name not in record["stages"]:
            self._record_event("dropped", record)
            return

        stage_data = record["stages"][stage_name]
        if hook_name not in stage_data["hooks"]:
            self._record_event("dropped", record)
            return

        hook_data = stage_data["hooks"][hook_name]
        if not isinstance(request_name, str) or not request_name.strip():
            self._record_event("malformed", record)
            return
        bounded_request_name = self._bounded_json_text(
            request_name.strip(), MAX_OPERATION_TEXT_BYTES
        )
        if bounded_request_name not in hook_data["requests"]:
            if (
                len(hook_data["requests"]) >= MAX_REQUEST_TYPES_PER_HOOK
                or record.get("_request_entry_count", 0)
                >= MAX_REQUEST_TYPES_PER_COLLECTOR
            ):
                self._record_event("dropped", record)
                return None
        operation_id = self.start_operation("request", bounded_request_name)
        if operation_id is None:
            return None
        if bounded_request_name not in hook_data["requests"]:
            hook_data["requests"][bounded_request_name] = {
                "start_time": time.time(),
                "total_time": 0.0,
                "instance_count": 0,
            }
            record["_request_entry_count"] = record.get("_request_entry_count", 0) + 1
        request_data = hook_data["requests"][bounded_request_name]
        self._request_stack.set(
            self._request_stack.get() + ((bounded_request_name, operation_id),)
        )
        request_data["instance_count"] += 1
        return operation_id

    def end_request(self, request_name: str) -> None:
        """
        End timing for a Redfish/IPMI request.

        The implementation uses ``request_name`` to end timing for a
        Redfish/IPMI request.

        Args:
            request_name: Stable request name used for lookup and
                operator-facing diagnostics.
        """
        key = self._collector_context.get()
        stage_name = self._stage_context.get()
        hook_name = self._hook_context.get()
        if not self.always_collect or key is None or not stage_name or not hook_name:
            return

        record = self._collector_records.get(key)
        if record is None:
            return
        if stage_name not in record["stages"]:
            self._record_event("dropped", record)
            return

        stage_data = record["stages"][stage_name]
        if hook_name not in stage_data["hooks"]:
            self._record_event("dropped", record)
            return

        hook_data = stage_data["hooks"][hook_name]
        bounded_request_name = self._bounded_json_text(
            str(request_name).strip(), MAX_OPERATION_TEXT_BYTES
        )
        if bounded_request_name in hook_data["requests"]:
            request_data = hook_data["requests"][bounded_request_name]
            request_data["end_time"] = time.time()
            stack = list(self._request_stack.get())
            operation_id = None
            for index in range(len(stack) - 1, -1, -1):
                if stack[index][0] == bounded_request_name:
                    _, operation_id = stack.pop(index)
                    break
            if operation_id:
                self.end_operation(operation_id)
                operation = self._operations_by_id.get(operation_id, {})
                if request_data.get("instance_count", 0) == 1:
                    request_data["total_time"] = (
                        request_data["end_time"] - request_data["start_time"]
                    )
                else:
                    request_data["total_time"] = request_data.get(
                        "total_time", 0.0
                    ) + float(operation.get("duration_seconds", 0.0) or 0.0)
            self._request_stack.set(tuple(stack))

    @staticmethod
    def _utc_now_iso() -> str:
        """
        Return an unambiguous UTC timestamp for persisted timing data.

        After applying local validation, the function forwards current instance
        state to ``isoformat`` and preserves its return and exception contract.

        Returns:
            The canonical utc now iso text.
        """
        return datetime.now(timezone.utc).isoformat()

    def _end_latest_scope_operation(
        self, operation_type: str, name: str, **end_kwargs: Any
    ) -> None:
        """
        Close the task-local unfinished stage/hook compatibility span.

        The implementation uses ``operation_type``, ``name``, and ``end_kwargs``
        to close the task-local unfinished stage/hook compatibility span.

        Args:
            operation_type: Text supplied as operation type in the format
                accepted by this function.
            name: Stable name used for lookup and operator-facing diagnostics.
            end_kwargs: Additional named values forwarded without changing their
                keys.
        """
        for operation_id in reversed(self._operation_stack.get()):
            operation = self._operations_by_id.get(operation_id, {})
            if (
                operation.get("operation_type") == operation_type
                and operation.get("name") == name
                and operation.get("ended_at") is None
            ):
                self.end_operation(operation_id, **end_kwargs)
                return

    def start_operation(
        self,
        operation_type: str,
        name: str,
        *,
        metadata: Optional[Dict[str, Any]] = None,
        parent_id: Optional[str] = None,
        contributes_to_active_time: bool = True,
        compact_artifact_on_limit: bool = False,
    ) -> Optional[str]:
        """
        Start a unique task-local operation span.

        The returned token must be passed to :meth:`end_operation`. Explicit
        tokens avoid name collisions when identical requests or file writes run
        concurrently. Stage and hook association is copied from ContextVar at
        span creation, so it remains correct across asyncio tasks.

        Args:
            operation_type: Text supplied as operation type in the format
                accepted by this function.
            name: Stable name used for lookup and operator-facing diagnostics.
            metadata: Optional metadata; ``None`` selects the function's default
                behavior.
            parent_id: Stable parent identifier used to correlate configuration,
                logs, and results.
            contributes_to_active_time: Whether contributes to active time is
                enabled or required for this operation.
            compact_artifact_on_limit: Preserve a bounded, artifact-only timing
                token when the detailed operation budget is exhausted. Callers
                must select this only for artifact-producing operations that
                finish after a concrete local artifact is published.

        Returns:
            The validated ``operation_id``, or ``None`` when no value qualifies.
        """
        if not self.always_collect:
            return None
        key = self._collector_context.get()
        record = self._collector_records.get(key) if key else None
        if record is None:
            self._record_event("malformed")
            return None
        if (
            not isinstance(operation_type, str)
            or not operation_type.strip()
            or not isinstance(name, str)
            or not name.strip()
            or (metadata is not None and not isinstance(metadata, dict))
        ):
            self._record_event("malformed", record)
            return None

        normalized_operation_type = operation_type.strip()
        redfish_request_accounting = None
        if normalized_operation_type == "redfish_request":
            redfish_request_accounting = record.setdefault(
                "_redfish_request_accounting",
                self._empty_redfish_request_accounting(),
            )
            redfish_request_accounting["attempted"] += 1

        dut_id = str(key[0])
        collector_capacity_reached = (
            len(record.get("operations", [])) >= self.max_operations_per_collector
        )
        dut_capacity_reached = (
            self._operation_counts_by_dut.get(dut_id, 0) >= self.max_operations_per_dut
        )
        run_capacity_reached = (
            len(self._operations_by_id) >= self.max_operations_per_run
        )
        compact_redfish_request = False
        if (
            normalized_operation_type == "redfish_request"
            and self.retain_compact_redfish_requests
            and not run_capacity_reached
            and (collector_capacity_reached or dut_capacity_reached)
            and record.get("_redfish_request_operation_count", 0)
            < self.max_redfish_request_operations_per_collector
            and self._redfish_request_operation_counts_by_dut.get(dut_id, 0)
            < self.max_redfish_request_operations_per_dut
        ):
            compact_redfish_request = True
        elif collector_capacity_reached or dut_capacity_reached or run_capacity_reached:
            self._record_event("dropped", record)
            if redfish_request_accounting is not None:
                redfish_request_accounting["dropped"] += 1
            if (
                compact_artifact_on_limit
                and len(self._compact_artifact_operations)
                < MAX_COMPACT_PENDING_ARTIFACT_OPERATIONS
            ):
                operation_id = (
                    f"compact-artifact-{next(self._compact_operation_counter)}"
                )
                self._compact_artifact_operations[operation_id] = {
                    "_collector_key": key,
                    "operation_type": normalized_operation_type,
                    "name": self._bounded_json_text(
                        name.strip(), MAX_OPERATION_TEXT_BYTES
                    ),
                    "started_at": self._utc_now_iso(),
                    "_start_monotonic": time.perf_counter(),
                    "metadata": self._bounded_metadata(metadata),
                }
                return operation_id
            return None

        operation_id = f"op-{next(self._operation_counter)}"
        if parent_id is None:
            # ContextVar state is copied when asyncio creates a child task, so
            # sibling operations cannot accidentally inherit one another as a
            # parent even when they share one collector record.
            for candidate_id in reversed(self._operation_stack.get()):
                candidate = self._operations_by_id.get(candidate_id)
                if candidate and candidate.get("ended_at") is None:
                    parent_id = candidate_id
                    break

        operation = {
            "operation_id": operation_id,
            "parent_id": parent_id,
            "operation_type": self._bounded_json_text(
                normalized_operation_type, MAX_OPERATION_TEXT_BYTES
            ),
            "name": self._bounded_json_text(name.strip(), MAX_OPERATION_TEXT_BYTES),
            "stage": self._stage_context.get(),
            "hook": self._hook_context.get(),
            "started_at": self._utc_now_iso(),
            "ended_at": None,
            "duration_seconds": None,
            "status": "running",
            "artifact_paths": [],
            "size_bytes": None,
            "contributes_to_active_time": bool(contributes_to_active_time),
            "metadata": self._bounded_metadata(metadata),
            "_artifact_sizes": {},
            "_collector_key": key,
            "_compact_redfish_request": compact_redfish_request,
            "_start_monotonic": time.perf_counter(),
            "_end_monotonic": None,
        }
        record.setdefault("operations", []).append(operation)
        self._operations_by_id[operation_id] = operation
        self._operation_counts_by_dut[dut_id] = (
            self._operation_counts_by_dut.get(dut_id, 0) + 1
        )
        if redfish_request_accounting is not None:
            record["_redfish_request_operation_count"] += 1
            self._redfish_request_operation_counts_by_dut[dut_id] = (
                self._redfish_request_operation_counts_by_dut.get(dut_id, 0) + 1
            )
        self._operation_stack.set(self._operation_stack.get() + (operation_id,))
        self._record_event("accepted", record)
        if redfish_request_accounting is not None:
            redfish_request_accounting["retained"] += 1
        return operation_id

    def _retain_compact_artifact_timing(
        self,
        record: Dict[str, Any],
        collector_key: Tuple[str, str],
        artifact_timing: Dict[str, Any],
    ) -> bool:
        """
        Retain one bounded artifact timing outside the detailed span budget.

        Compact entries share the existing artifact-inventory cardinality and
        path-byte budgets. This prevents a saturated operation graph from
        turning every subsequently written file into ``not_instrumented``
        while keeping the timing snapshot bounded by the same limits as the
        fallback inventory.

        Args:
            record: Owning collector timing record updated in place.
            collector_key: Canonical ``(dut_id, collector_id)`` tuple for the
                owning record.
            artifact_timing: Canonical compact timing entry containing a
                normalized artifact path.

        Returns:
            ``True`` when the compact entry is retained or already represented;
            otherwise ``False`` when a configured bound rejects it.
        """
        normalized_path = artifact_timing["path"]
        instrumented = {
            path
            for operation in record.get("operations", [])
            for path in operation.get("artifact_paths", [])
        }
        compact = record.setdefault("_compact_artifact_timings", {})
        inventory = record.setdefault("_uninstrumented_artifacts", {})
        if normalized_path in instrumented or normalized_path in compact:
            self._record_event("deduplicated", record)
            return True

        # Status publication may have inventoried the path before a late
        # persistence callback completes. Reuse that reservation and replace
        # the weaker entry without increasing any cardinality counter.
        if normalized_path in inventory:
            inventory.pop(normalized_path, None)
            compact[normalized_path] = artifact_timing
            self._record_event("deduplicated", record)
            return True

        dut_id = collector_key[0]
        path_bytes = self._json_text_bytes(normalized_path)
        retained_path_bytes = int(
            record.get("_uninstrumented_artifact_path_characters", 0)
        )
        if (
            path_bytes > MAX_ARTIFACT_PATH_BYTES_PER_OPERATION
            or len(compact) + len(inventory)
            >= MAX_UNINSTRUMENTED_ARTIFACTS_PER_COLLECTOR
            or self._inventory_counts_by_dut.get(dut_id, 0)
            >= MAX_UNINSTRUMENTED_ARTIFACTS_PER_DUT
            or self._inventory_count_run >= MAX_UNINSTRUMENTED_ARTIFACTS_PER_RUN
            or retained_path_bytes + path_bytes > MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES
            or self._inventory_path_characters_by_dut.get(dut_id, 0) + path_bytes
            > MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_DUT
            or self._inventory_path_characters_run + path_bytes
            > MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_RUN
        ):
            self._record_event("dropped", record)
            return False

        compact[normalized_path] = artifact_timing
        record["_uninstrumented_artifact_path_characters"] = (
            retained_path_bytes + path_bytes
        )
        self._inventory_counts_by_dut[dut_id] = (
            self._inventory_counts_by_dut.get(dut_id, 0) + 1
        )
        self._inventory_path_characters_by_dut[dut_id] = (
            self._inventory_path_characters_by_dut.get(dut_id, 0) + path_bytes
        )
        self._inventory_count_run += 1
        self._inventory_path_characters_run += path_bytes
        self._record_event("accepted", record)
        return True

    def _end_compact_artifact_operation(
        self,
        operation_id: str,
        *,
        status: str,
        artifact_path: Optional[str],
        artifact_paths: Optional[List[str]],
        size_bytes: Optional[int],
        metadata: Optional[Dict[str, Any]],
    ) -> bool:
        """
        Finish an artifact-only fallback span after detailed capacity is full.

        The pending record retains only bounded names, metadata, and its start
        instant. Completion emits per-file timing rows but deliberately omits a
        public operation row, preserving the detailed-operation and snapshot
        amplification contracts.

        Args:
            operation_id: Compact token returned by :meth:`start_operation`.
            status: Terminal operation status.
            artifact_path: Optional single artifact produced by the operation.
            artifact_paths: Optional ordered collection of produced artifacts.
            size_bytes: Optional size for a single produced artifact.
            metadata: Optional bounded metadata merged into the pending record.

        Returns:
            ``True`` when ``operation_id`` names a compact operation, including
            completions that have no artifact to retain; otherwise ``False``.
        """
        operation = self._compact_artifact_operations.pop(operation_id, None)
        if operation is None:
            return False
        collector_key = operation["_collector_key"]
        record = self._collector_records.get(collector_key)
        if record is None:
            self._record_event("malformed")
            return True

        raw_paths: List[Any] = []
        if artifact_path is not None:
            raw_paths.append(artifact_path)
        if artifact_paths is not None:
            if not isinstance(artifact_paths, (list, tuple)):
                self._record_event("malformed", record)
            else:
                attempt_limit = MAX_ARTIFACT_PATHS_PER_OPERATION * 2
                if len(artifact_paths) > attempt_limit:
                    self._record_event(
                        "dropped", record, len(artifact_paths) - attempt_limit
                    )
                raw_paths.extend(artifact_paths[:attempt_limit])

        normalized_paths: List[str] = []
        retained_path_bytes = 0
        for raw_path in raw_paths:
            normalized_path = self._normalize_artifact_path(raw_path)
            if normalized_path is None:
                self._record_event("dropped", record)
                continue
            if normalized_path in normalized_paths:
                self._record_event("deduplicated", record)
                continue
            path_bytes = self._json_text_bytes(normalized_path)
            if (
                len(normalized_paths) >= MAX_ARTIFACT_PATHS_PER_OPERATION
                or retained_path_bytes + path_bytes
                > MAX_ARTIFACT_PATH_BYTES_PER_OPERATION
            ):
                self._record_event("dropped", record)
                continue
            normalized_paths.append(normalized_path)
            retained_path_bytes += path_bytes
        if not normalized_paths:
            return True

        operation_metadata = dict(operation.get("metadata", {}))
        if metadata:
            if isinstance(metadata, dict):
                operation_metadata = self._merge_bounded_metadata(
                    operation_metadata, metadata
                )
            else:
                self._record_event("malformed", record)
        measurement = (
            operation_metadata.get("artifact_measurement")
            or operation["operation_type"]
        )
        measurement_quality = operation_metadata.get("measurement_quality", "measured")
        if measurement_quality not in {
            "measured",
            "measured_duration_only",
            "estimated",
        }:
            measurement_quality = "measured"

        ended_at = self._utc_now_iso()
        duration_seconds = max(0.0, time.perf_counter() - operation["_start_monotonic"])
        artifact_count = len(normalized_paths)
        bounded_status = self._bounded_json_text(status, MAX_OPERATION_TEXT_BYTES)
        for normalized_path in normalized_paths:
            artifact_size = size_bytes if artifact_count == 1 else None
            if artifact_size is None:
                try:
                    artifact_size = Path(normalized_path).stat().st_size
                except OSError:
                    artifact_size = None
            try:
                normalized_size = (
                    max(0, int(artifact_size)) if artifact_size is not None else None
                )
            except (TypeError, ValueError, OverflowError):
                normalized_size = None
                self._record_event("malformed", record)
            self._retain_compact_artifact_timing(
                record,
                collector_key,
                {
                    "path": normalized_path,
                    "operation_id": None,
                    "measurement": self._bounded_json_text(
                        measurement, MAX_OPERATION_TEXT_BYTES
                    ),
                    "measurement_quality": measurement_quality,
                    "measurement_scope": (
                        "shared_operation" if artifact_count > 1 else "artifact"
                    ),
                    "shared_operation_artifact_count": artifact_count,
                    "started_at": operation["started_at"],
                    "ended_at": ended_at,
                    "duration_seconds": (
                        None if artifact_count > 1 else duration_seconds
                    ),
                    "size_bytes": normalized_size,
                    "status": bounded_status,
                },
            )
        return True

    def end_operation(
        self,
        operation_id: Optional[str],
        *,
        status: str = "success",
        artifact_path: Optional[str] = None,
        artifact_paths: Optional[List[str]] = None,
        size_bytes: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        """
        Finish an operation span and attach measurable artifact details.

        The implementation uses ``operation_id``, ``status``, ``artifact_path``,
        ``artifact_paths``, and ``size_bytes`` to finish an operation span and
        attach measurable artifact details. Filesystem effects remain confined
        to the caller-selected paths and the owning resource lifecycle.

        Args:
            operation_id: Stable operation identifier used to correlate
                configuration, logs, and results.
            status: Text supplied as status in the format accepted by this
                function.
            artifact_path: Optional filesystem location used as the artifact
                path for this operation.
            artifact_paths: Filesystem locations processed in caller-provided
                order.
            size_bytes: Optional size bytes; ``None`` selects the function's
                default behavior.
            metadata: Optional metadata; ``None`` selects the function's default
                behavior.
            error: Exception or failure detail associated with the operation.
        """
        if not operation_id:
            return
        if self._end_compact_artifact_operation(
            operation_id,
            status=status,
            artifact_path=artifact_path,
            artifact_paths=artifact_paths,
            size_bytes=size_bytes,
            metadata=metadata,
        ):
            return
        operation = self._operations_by_id.get(operation_id)
        if operation is None:
            self._record_event("malformed")
            return
        record = self._collector_records.get(operation.get("_collector_key"))
        if operation.get("status") != "running":
            self._record_event("deduplicated", record)
            self._operation_stack.set(
                tuple(
                    candidate
                    for candidate in self._operation_stack.get()
                    if candidate != operation_id
                )
            )
            return

        operation["_end_monotonic"] = time.perf_counter()
        operation["ended_at"] = self._utc_now_iso()
        operation["duration_seconds"] = max(
            0.0,
            operation["_end_monotonic"] - operation["_start_monotonic"],
        )
        operation["status"] = self._bounded_json_text(status, MAX_OPERATION_TEXT_BYTES)

        paths: List[Any] = []
        if artifact_path is not None:
            paths.append(artifact_path)
        if artifact_paths is not None:
            if not isinstance(artifact_paths, (list, tuple)):
                self._record_event("malformed", record)
            else:
                attempt_limit = MAX_ARTIFACT_PATHS_PER_OPERATION * 2
                if len(artifact_paths) > attempt_limit:
                    self._record_event(
                        "dropped", record, len(artifact_paths) - attempt_limit
                    )
                paths.extend(artifact_paths[:attempt_limit])
        if operation.get("_compact_redfish_request") and paths:
            self._record_event("dropped", record, len(paths))
            paths = []
        normalized_paths = []
        retained_path_bytes = 0
        for raw_path in paths:
            normalized_path = self._normalize_artifact_path(raw_path)
            if normalized_path is None:
                self._record_event("dropped", record)
                continue
            if normalized_path in normalized_paths:
                self._record_event("deduplicated", record)
                continue
            if (
                len(normalized_paths) >= MAX_ARTIFACT_PATHS_PER_OPERATION
                or retained_path_bytes + self._json_text_bytes(normalized_path)
                > MAX_ARTIFACT_PATH_BYTES_PER_OPERATION
            ):
                self._record_event("dropped", record)
                continue
            normalized_paths.append(normalized_path)
            retained_path_bytes += self._json_text_bytes(normalized_path)
        operation["artifact_paths"] = normalized_paths

        if size_bytes is None and len(operation["artifact_paths"]) == 1:
            try:
                size_bytes = Path(operation["artifact_paths"][0]).stat().st_size
            except OSError:
                size_bytes = None
        if size_bytes is not None:
            try:
                operation["size_bytes"] = max(0, int(size_bytes))
            except (TypeError, ValueError, OverflowError):
                operation["size_bytes"] = None
                self._record_event("malformed", record)
        artifact_sizes = operation.setdefault("_artifact_sizes", {})
        for normalized_path in operation["artifact_paths"]:
            artifact_size = operation.get("size_bytes")
            if artifact_size is None or len(operation["artifact_paths"]) > 1:
                try:
                    artifact_size = Path(normalized_path).stat().st_size
                except OSError:
                    artifact_size = None
            artifact_sizes[normalized_path] = artifact_size
        if metadata:
            if isinstance(metadata, dict):
                operation["metadata"] = self._merge_bounded_metadata(
                    operation["metadata"], metadata
                )
            else:
                self._record_event("malformed", record)
        if error:
            operation["error"] = self._bounded_json_text(
                error, MAX_OPERATION_METADATA_VALUE_BYTES
            )
        self._operation_stack.set(
            tuple(
                candidate
                for candidate in self._operation_stack.get()
                if candidate != operation_id
            )
        )

    def _normalize_artifact_path(self, raw_path: Any) -> Optional[str]:
        """
        Return an absolute artifact path without duplicating the output root.

        Some logger paths are cwd-relative but already include output_dir (for
        example ``logs/<run>/dut/...``). Prefer that real file before
        interpreting a shorter relative path as relative to output_dir.

        Args:
            raw_path: filesystem location used as the raw path for this
                operation.

        Returns:
            The validated ``normalized``, or ``None`` when no value qualifies.
        """
        if not isinstance(raw_path, (str, Path)):
            return None
        rendered = str(raw_path)
        if self._json_text_bytes(rendered) > MAX_ARTIFACT_PATH_BYTES_PER_OPERATION:
            return None
        path = Path(rendered).expanduser()
        if not path.is_absolute():
            # Some logger paths are cwd-relative but already include output_dir
            # (for example ``logs/<run>/dut/...``). Prefer that real file before
            # interpreting a shorter relative path as relative to output_dir.
            try:
                cwd_relative_exists = path.exists()
            except OSError:
                cwd_relative_exists = False
            if not cwd_relative_exists:
                path = self.output_dir / path
        try:
            normalized = str(path.resolve(strict=False))
        except (OSError, RuntimeError):
            normalized = str(path.absolute())
        if self._json_text_bytes(normalized) > MAX_ARTIFACT_PATH_BYTES_PER_OPERATION:
            return None
        return normalized

    def attach_artifact_to_operation(
        self,
        operation_id: Optional[str],
        artifact_path: Any,
        *,
        size_bytes: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Attach a persisted artifact to a completed operation in this collector.

        The explicit operation token and task-local collector context prevent a
        concurrent request from claiming another request's output file.

        Args:
            operation_id: Stable operation identifier used to correlate
                configuration, logs, and results.
            artifact_path: filesystem location used as the artifact path for
                this operation.
            size_bytes: Optional size bytes; ``None`` selects the function's
                default behavior.
            metadata: Optional metadata; ``None`` selects the function's default
                behavior.

        Returns:
            Whether the attach a persisted artifact to a completed operation in
            this collector operation succeeds.
        """
        if not operation_id or not artifact_path:
            return False
        collector_key = self._collector_context.get()
        record = self._collector_records.get(collector_key) if collector_key else None
        operation = self._operations_by_id.get(operation_id)
        if (
            record is None
            or operation is None
            or operation.get("status") not in {"success", "error"}
            or not any(
                candidate is operation for candidate in record.get("operations", [])
            )
        ):
            self._record_event("malformed", record)
            return False

        normalized_path = self._normalize_artifact_path(artifact_path)
        if normalized_path is None:
            self._record_event("dropped", record)
            return False
        paths = operation.setdefault("artifact_paths", [])
        if normalized_path in paths:
            self._record_event("deduplicated", record)
        elif (
            len(paths) >= MAX_ARTIFACT_PATHS_PER_OPERATION
            or sum(self._json_text_bytes(path) for path in paths)
            + self._json_text_bytes(normalized_path)
            > MAX_ARTIFACT_PATH_BYTES_PER_OPERATION
        ):
            self._record_event("dropped", record)
            return False
        else:
            paths.append(normalized_path)

        if size_bytes is None:
            try:
                size_bytes = Path(normalized_path).stat().st_size
            except OSError:
                size_bytes = None
        if size_bytes is not None:
            try:
                operation["size_bytes"] = max(0, int(size_bytes))
            except (TypeError, ValueError, OverflowError):
                operation["size_bytes"] = None
                self._record_event("malformed", record)
        operation.setdefault("_artifact_sizes", {})[normalized_path] = operation.get(
            "size_bytes"
        )
        if metadata:
            if isinstance(metadata, dict):
                operation["metadata"] = self._merge_bounded_metadata(
                    operation.setdefault("metadata", {}), metadata
                )
            else:
                self._record_event("malformed", record)
        return True

    def _artifact_path_candidates(self, raw_path: Any) -> set[str]:
        """
        Return cwd- and output-relative aliases for matching an old path.

        The implementation uses ``raw_path`` to produce cwd- and output-relative
        aliases for matching an old path. Filesystem effects remain confined to
        the caller-selected paths and the owning resource lifecycle.

        Args:
            raw_path: filesystem location used as the raw path for this
                operation.

        Returns:
            The unique artifact path candidates returned by the operation.
        """
        if not isinstance(raw_path, (str, Path)):
            return set()
        rendered = str(raw_path)
        if self._json_text_bytes(rendered) > MAX_ARTIFACT_PATH_BYTES_PER_OPERATION:
            return set()
        path = Path(rendered).expanduser()
        candidates = [path] if path.is_absolute() else [path, self.output_dir / path]
        normalized: set[str] = set()
        for candidate in candidates:
            try:
                normalized.add(str(candidate.resolve(strict=False)))
            except (OSError, RuntimeError):
                normalized.add(str(candidate.absolute()))
        return normalized

    def _release_artifact_inventory_reservation(
        self,
        record: Dict[str, Any],
        dut_id: str,
        artifact_path: str,
    ) -> None:
        """
        Release one compact or fallback artifact's bounded reservation.

        Compact timings and uninstrumented inventory entries share collector,
        DUT, and run cardinality plus path-byte limits. Removing a redundant
        entry must release exactly one reservation so later artifacts are not
        rejected by stale accounting. Defensive clamping prevents corrupt
        legacy state from making any counter negative.

        Args:
            record: Owning collector timing record updated in place.
            dut_id: Stable DUT identifier used to select per-DUT counters.
            artifact_path: Normalized artifact path whose reservation is
                released.

        Side Effects:
            Decrements the owning collector, DUT, and run inventory counters
            and path-byte totals.
        """
        path_bytes = self._json_text_bytes(artifact_path)
        record["_uninstrumented_artifact_path_characters"] = max(
            0,
            int(record.get("_uninstrumented_artifact_path_characters", 0)) - path_bytes,
        )

        remaining_dut_count = max(0, self._inventory_counts_by_dut.get(dut_id, 0) - 1)
        if remaining_dut_count:
            self._inventory_counts_by_dut[dut_id] = remaining_dut_count
        else:
            self._inventory_counts_by_dut.pop(dut_id, None)

        remaining_dut_bytes = max(
            0,
            self._inventory_path_characters_by_dut.get(dut_id, 0) - path_bytes,
        )
        if remaining_dut_bytes:
            self._inventory_path_characters_by_dut[dut_id] = remaining_dut_bytes
        else:
            self._inventory_path_characters_by_dut.pop(dut_id, None)

        self._inventory_count_run = max(0, self._inventory_count_run - 1)
        self._inventory_path_characters_run = max(
            0, self._inventory_path_characters_run - path_bytes
        )

    def remap_current_collector_artifact_path(
        self, old_path: Any, new_path: Any
    ) -> int:
        """
        Remap an artifact after a rename, only in the current collector record.

        The implementation uses ``old_path`` and ``new_path`` to remap an
        artifact after a rename, only in the current collector record.

        Args:
            old_path: filesystem location used as the old path for this
                operation.
            new_path: filesystem location used as the new path for this
                operation.

        Returns:
            The numeric remap current collector artifact path value.
        """
        collector_key = self._collector_context.get()
        record = self._collector_records.get(collector_key) if collector_key else None
        if record is None:
            return 0

        old_candidates = self._artifact_path_candidates(old_path)
        normalized_new_path = self._normalize_artifact_path(new_path)
        if normalized_new_path is None:
            self._record_event("dropped", record)
            return 0
        remapped = 0
        for operation in record.get("operations", []):
            updated_paths = []
            artifact_sizes = operation.setdefault("_artifact_sizes", {})
            for artifact_path in operation.get("artifact_paths", []):
                if self._artifact_path_candidates(artifact_path) & old_candidates:
                    retained_bytes = sum(
                        self._json_text_bytes(path)
                        for path in operation.get("artifact_paths", [])
                        if path != artifact_path
                    )
                    if (
                        self._json_text_bytes(normalized_new_path) + retained_bytes
                        > MAX_ARTIFACT_PATH_BYTES_PER_OPERATION
                    ):
                        updated_paths.append(artifact_path)
                        self._record_event("dropped", record)
                        continue
                    updated_paths.append(normalized_new_path)
                    artifact_sizes[normalized_new_path] = artifact_sizes.pop(
                        artifact_path, None
                    )
                    remapped += 1
                else:
                    updated_paths.append(artifact_path)
            operation["artifact_paths"] = list(dict.fromkeys(updated_paths))

        compact = record.setdefault("_compact_artifact_timings", {})
        inventory = record.setdefault("_uninstrumented_artifacts", {})
        dut_id = str(collector_key[0])
        instrumented = {
            path
            for operation in record.get("operations", [])
            for path in operation.get("artifact_paths", [])
        }
        for artifact_path, artifact_timing in list(compact.items()):
            if not (self._artifact_path_candidates(artifact_path) & old_candidates):
                continue
            if artifact_path == normalized_new_path:
                continue
            if normalized_new_path in instrumented or normalized_new_path in compact:
                compact.pop(artifact_path, None)
                self._release_artifact_inventory_reservation(
                    record, dut_id, artifact_path
                )
                self._record_event("deduplicated", record)
                remapped += 1
                continue

            updated_timing = dict(artifact_timing)
            updated_timing["path"] = normalized_new_path
            if normalized_new_path in inventory:
                # Keep the destination's existing reservation while replacing
                # its weaker fallback row with the measured compact timing.
                inventory.pop(normalized_new_path, None)
                compact.pop(artifact_path, None)
                compact[normalized_new_path] = updated_timing
                self._release_artifact_inventory_reservation(
                    record, dut_id, artifact_path
                )
                self._record_event("deduplicated", record)
                remapped += 1
                continue

            old_bytes = self._json_text_bytes(artifact_path)
            new_bytes = self._json_text_bytes(normalized_new_path)
            delta = new_bytes - old_bytes
            if delta > 0 and (
                int(record.get("_uninstrumented_artifact_path_characters", 0)) + delta
                > MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES
                or self._inventory_path_characters_by_dut.get(dut_id, 0) + delta
                > MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_DUT
                or self._inventory_path_characters_run + delta
                > MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_RUN
            ):
                self._record_event("dropped", record)
                continue
            compact.pop(artifact_path)
            compact[normalized_new_path] = updated_timing
            record["_uninstrumented_artifact_path_characters"] = (
                int(record.get("_uninstrumented_artifact_path_characters", 0)) + delta
            )
            self._inventory_path_characters_by_dut[dut_id] = (
                self._inventory_path_characters_by_dut.get(dut_id, 0) + delta
            )
            self._inventory_path_characters_run += delta
            remapped += 1

        for artifact_path, artifact_size in list(inventory.items()):
            if not (self._artifact_path_candidates(artifact_path) & old_candidates):
                continue
            if artifact_path == normalized_new_path:
                continue
            if (
                normalized_new_path in instrumented
                or normalized_new_path in compact
                or normalized_new_path in inventory
            ):
                inventory.pop(artifact_path, None)
                self._release_artifact_inventory_reservation(
                    record, dut_id, artifact_path
                )
                self._record_event("deduplicated", record)
                remapped += 1
                continue

            old_bytes = self._json_text_bytes(artifact_path)
            new_bytes = self._json_text_bytes(normalized_new_path)
            delta = new_bytes - old_bytes
            if delta > 0 and (
                int(record.get("_uninstrumented_artifact_path_characters", 0)) + delta
                > MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES
                or self._inventory_path_characters_by_dut.get(dut_id, 0) + delta
                > MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_DUT
                or self._inventory_path_characters_run + delta
                > MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_RUN
            ):
                self._record_event("dropped", record)
                continue
            inventory.pop(artifact_path)
            inventory[normalized_new_path] = artifact_size
            record["_uninstrumented_artifact_path_characters"] = (
                int(record.get("_uninstrumented_artifact_path_characters", 0)) + delta
            )
            self._inventory_path_characters_by_dut[dut_id] = (
                self._inventory_path_characters_by_dut.get(dut_id, 0) + delta
            )
            self._inventory_path_characters_run += delta
            remapped += 1
        return remapped

    def record_artifact_inventory(
        self,
        dut_id: str,
        collector_id: str,
        artifact_paths: Any,
    ) -> None:
        """
        Record otherwise-uninstrumented files in the canonical timing graph.

        Status publication can run more than once. A path-keyed inventory keeps
        those callbacks idempotent and avoids re-statting retained artifacts.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            artifact_paths: Filesystem locations processed in caller-provided
                order.
        """
        record = self._collector_records.get((str(dut_id), str(collector_id)))
        if record is None:
            self._record_event("malformed")
            return
        if not isinstance(artifact_paths, (list, tuple, set)):
            self._record_event("malformed", record)
            return

        instrumented = {
            path
            for operation in record.get("operations", [])
            for path in operation.get("artifact_paths", [])
        }
        compact = record.setdefault("_compact_artifact_timings", {})
        instrumented.update(compact)
        inventory = record.setdefault("_uninstrumented_artifacts", {})
        normalized_dut_id = str(dut_id)
        retained_path_bytes = int(
            record.get("_uninstrumented_artifact_path_characters", 0)
        )
        attempt_limit = min(
            MAX_UNINSTRUMENTED_ARTIFACTS_PER_RUN,
            MAX_UNINSTRUMENTED_ARTIFACTS_PER_COLLECTOR * 2,
        )
        if len(artifact_paths) > attempt_limit:
            self._record_event("dropped", record, len(artifact_paths) - attempt_limit)
            if isinstance(artifact_paths, set):
                self._record_event("dropped", record, attempt_limit)
                return
        retained_attempts = (
            list(artifact_paths[:attempt_limit])
            if isinstance(artifact_paths, (list, tuple))
            else sorted(artifact_paths, key=lambda value: str(value))[:attempt_limit]
        )
        candidates: List[str] = []
        for raw_path in retained_attempts:
            if not isinstance(raw_path, (str, Path)) or not raw_path:
                self._record_event("malformed", record)
                continue
            candidates.append(str(raw_path))

        for raw_path in sorted(candidates):
            normalized_path = self._normalize_artifact_path(raw_path)
            if normalized_path is None:
                self._record_event("dropped", record)
                continue
            if normalized_path in instrumented or normalized_path in inventory:
                self._record_event("deduplicated", record)
                continue
            path_bytes = self._json_text_bytes(normalized_path)
            if (
                path_bytes > MAX_ARTIFACT_PATH_BYTES_PER_OPERATION
                or len(inventory) + len(compact)
                >= MAX_UNINSTRUMENTED_ARTIFACTS_PER_COLLECTOR
                or self._inventory_counts_by_dut.get(normalized_dut_id, 0)
                >= MAX_UNINSTRUMENTED_ARTIFACTS_PER_DUT
                or self._inventory_count_run >= MAX_UNINSTRUMENTED_ARTIFACTS_PER_RUN
                or retained_path_bytes + path_bytes
                > MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES
                or self._inventory_path_characters_by_dut.get(normalized_dut_id, 0)
                + path_bytes
                > MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_DUT
                or self._inventory_path_characters_run + path_bytes
                > MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_RUN
            ):
                self._record_event("dropped", record)
                continue
            try:
                artifact_size = Path(normalized_path).stat().st_size
            except OSError:
                artifact_size = None
            inventory[normalized_path] = artifact_size
            retained_path_bytes += path_bytes
            record["_uninstrumented_artifact_path_characters"] = retained_path_bytes
            self._inventory_counts_by_dut[normalized_dut_id] = (
                self._inventory_counts_by_dut.get(normalized_dut_id, 0) + 1
            )
            self._inventory_path_characters_by_dut[normalized_dut_id] = (
                self._inventory_path_characters_by_dut.get(normalized_dut_id, 0)
                + path_bytes
            )
            self._inventory_count_run += 1
            self._inventory_path_characters_run += path_bytes
            self._record_event("accepted", record)

    def record_duration_operation(
        self,
        operation_type: str,
        name: str,
        duration_seconds: Any,
        *,
        status: str,
        artifact_path: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        measurement_quality: str = "measured_duration_only",
    ) -> Optional[str]:
        """
        Record an externally measured duration without inventing timestamps.

        Batch adapters can return a real per-command duration without returning
        start/end instants. Such spans remain visible but do not participate in
        active/cumulative wall-clock aggregation.

        Args:
            operation_type: Text supplied as operation type in the format
                accepted by this function.
            name: Stable name used for lookup and operator-facing diagnostics.
            duration_seconds: Maximum duration in seconds allowed for duration
                seconds.
            status: Text supplied as status in the format accepted by this
                function.
            artifact_path: Optional filesystem location used as the artifact
                path for this operation.
            metadata: Optional metadata; ``None`` selects the function's default
                behavior.
            measurement_quality: Text supplied as measurement quality in the
                format accepted by this function.

        Returns:
            The validated ``operation_id``, or ``None`` when no value qualifies.
        """
        try:
            duration = max(0.0, float(duration_seconds))
        except (TypeError, ValueError, OverflowError):
            duration = 0.0
            measurement_quality = "estimated"
        if not math.isfinite(duration):
            duration = 0.0
            measurement_quality = "estimated"

        operation_metadata = dict(metadata or {})
        operation_metadata["measurement_quality"] = measurement_quality
        operation_metadata["time_basis"] = "duration_only"
        operation_metadata["show_in_timing_table"] = True
        operation_id = self.start_operation(
            operation_type,
            name,
            metadata=operation_metadata,
            contributes_to_active_time=False,
        )
        self.end_operation(
            operation_id,
            status=status,
            artifact_path=artifact_path,
        )
        operation = self._operations_by_id.get(operation_id or "")
        if operation:
            operation["started_at"] = None
            operation["ended_at"] = None
            operation["duration_seconds"] = duration
            operation["_start_monotonic"] = None
            operation["_end_monotonic"] = None
        return operation_id

    @staticmethod
    def _interval_union_seconds(intervals: List[Tuple[float, float]]) -> float:
        """
        Return the non-overlapping union of monotonic intervals.

        The implementation uses ``intervals`` to produce the non-overlapping
        union of monotonic intervals.

        Args:
            intervals: Entries supplied as ``intervals`` without transferring
                container ownership.

        Returns:
            The numeric interval union seconds.
        """
        if not intervals:
            return 0.0
        merged_total = 0.0
        current_start, current_end = sorted(intervals)[0]
        for start, end in sorted(intervals)[1:]:
            if start <= current_end:
                current_end = max(current_end, end)
            else:
                merged_total += max(0.0, current_end - current_start)
                current_start, current_end = start, end
        return merged_total + max(0.0, current_end - current_start)

    def get_collector_duration_seconds(
        self,
        dut_id: str,
        collector_id: str,
    ) -> Optional[float]:
        """
        Read the authoritative collector duration without projecting its history.

        Status refreshes need only the monotonic collector span. Reading this
        scalar does not traverse operations, sanitize diagnostic text, inspect
        artifacts, or cache a running duration. Detailed report callers retain
        the complete projection provided by ``get_collector_timing``.

        Args:
            dut_id: Stable DUT identifier selecting the collector's owner.
            collector_id: Stable collector identifier within that DUT.

        Returns:
            Non-negative elapsed seconds from the collector's monotonic start
            to its recorded end, or the current clock while running. Returns
            ``None`` when the collector has no timing record.
        """
        record = self._collector_records.get((str(dut_id), str(collector_id)))
        if record is None:
            return None
        end_monotonic = record.get("_end_monotonic") or time.perf_counter()
        return max(0.0, end_monotonic - record["_start_monotonic"])

    def get_collector_timing(
        self,
        dut_id: str,
        collector_id: str,
    ) -> Dict[str, Any]:
        """
        Return concurrency-safe collector, operation, and artifact timing.

        ``wall_clock_duration_seconds`` is always the authoritative collector
        elapsed time. ``cumulative_operation_time_seconds`` is a work metric and
        may exceed wall time when operations overlap. The active-union metric
        removes overlap without pretending that uninstrumented time vanished.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            A mapping containing the ``collector_started_at``,
            ``collector_ended_at``, ``wall_clock_duration_seconds``,
            ``wall_clock_is_authoritative``, and
            ``cumulative_operation_time_seconds`` fields.
        """
        key = (str(dut_id), str(collector_id))
        record = self._collector_records.get(key)
        if record is None:
            return {}

        end_monotonic = record.get("_end_monotonic") or time.perf_counter()
        measured_wall = max(0.0, end_monotonic - record["_start_monotonic"])
        # The monotonic span bounded by start_collector/end_collector is the
        # sole authoritative wall clock.  Execution-summary durations are
        # useful display fields, but letting them override this span made raw
        # status, tracker metadata, and the final report disagree.
        wall_duration = measured_wall

        all_contributing = [
            operation
            for operation in record.get("operations", [])
            if operation.get("contributes_to_active_time")
            and operation.get("_end_monotonic") is not None
        ]
        contributing_ids = {operation["operation_id"] for operation in all_contributing}

        ancestor_flags: Dict[str, bool] = {}

        def has_contributing_ancestor(operation: Dict[str, Any]) -> bool:
            """
            Return whether ``operation`` has contributing ancestor.

            The implementation uses ``operation`` to determine whether
            ``operation`` has contributing ancestor.

            Args:
                operation: Mapping supplying fields for ``operation`` has
                    contributing ancestor.

            Returns:
                Whether ``operation`` has contributing ancestor.
            """
            operation_id = str(operation.get("operation_id", ""))
            if operation_id in ancestor_flags:
                return ancestor_flags[operation_id]
            parent_id = operation.get("parent_id")
            visited = set()
            while parent_id and parent_id not in visited:
                if parent_id in contributing_ids:
                    ancestor_flags[operation_id] = True
                    return True
                visited.add(parent_id)
                parent = self._operations_by_id.get(parent_id)
                parent_id = parent.get("parent_id") if parent else None
            ancestor_flags[operation_id] = False
            return False

        # Nested spans explain the outer operation but are not additional work.
        # Aggregate only top-level contributing spans so command -> persistence
        # instrumentation does not inflate cumulative time.
        contributing = [
            operation
            for operation in all_contributing
            if not has_contributing_ancestor(operation)
        ]
        nested_excluded = sum(
            float(operation.get("duration_seconds", 0.0) or 0.0)
            for operation in all_contributing
            if has_contributing_ancestor(operation)
        )
        intervals = [
            (
                max(record["_start_monotonic"], operation["_start_monotonic"]),
                min(end_monotonic, operation["_end_monotonic"]),
            )
            for operation in contributing
        ]
        intervals = [(start, end) for start, end in intervals if end >= start]
        cumulative = sum(
            float(operation.get("duration_seconds", 0.0) or 0.0)
            for operation in contributing
        )
        active_union = self._interval_union_seconds(intervals)

        public_operations = []
        artifact_timings = []
        for operation in record.get("operations", []):
            public = self._project_public_operation(operation)
            public_operations.append(public)
            artifact_paths = operation.get("artifact_paths", [])
            artifact_count = len(artifact_paths)
            operation_metadata = operation.get("metadata", {})
            try:
                shared_request_operation_count = max(
                    1,
                    int(operation_metadata.get("shared_request_operation_count", 1)),
                )
            except (TypeError, ValueError, OverflowError):
                shared_request_operation_count = 1
            shared_request_attribution = shared_request_operation_count > 1
            shared_attribution = artifact_count > 1 or shared_request_attribution
            measurement = operation_metadata.get("artifact_measurement") or (
                "hook_acquisition"
                if operation.get("operation_type") == "hook"
                else operation["operation_type"]
            )
            measurement_quality = operation_metadata.get(
                "measurement_quality", "measured"
            )
            for path in artifact_paths:
                artifact_sizes = operation.setdefault("_artifact_sizes", {})
                artifact_size = artifact_sizes.get(path)
                if artifact_size is None and path not in artifact_sizes:
                    try:
                        artifact_size = Path(path).stat().st_size
                    except OSError:
                        artifact_size = None
                    artifact_sizes[path] = artifact_size
                artifact_timing = {
                    "path": path,
                    "operation_id": operation["operation_id"],
                    "measurement": measurement,
                    "measurement_quality": measurement_quality,
                    "measurement_scope": (
                        "shared_requests"
                        if shared_request_attribution
                        else ("shared_operation" if shared_attribution else "artifact")
                    ),
                    "shared_operation_artifact_count": artifact_count,
                    "started_at": operation["started_at"],
                    "ended_at": operation["ended_at"],
                    # A single operation duration cannot be assigned to each
                    # member of a multi-file result without double-counting.
                    # The measured duration remains on the operation itself.
                    "duration_seconds": (
                        None if shared_attribution else operation["duration_seconds"]
                    ),
                    "size_bytes": artifact_size,
                    "status": operation["status"],
                }
                if shared_request_attribution:
                    artifact_timing["shared_request_operation_count"] = (
                        shared_request_operation_count
                    )
                artifact_timings.append(
                    self._project_public_artifact_timing(artifact_timing)
                )

        artifact_timings.extend(
            self._project_public_artifact_timing(artifact_timing)
            for artifact_timing in record.get("_compact_artifact_timings", {}).values()
        )
        for path, artifact_size in record.get("_uninstrumented_artifacts", {}).items():
            artifact_timings.append(
                {
                    "path": path,
                    "operation_id": None,
                    "measurement": "not_instrumented",
                    "measurement_quality": "unavailable",
                    "measurement_scope": "none",
                    "shared_operation_artifact_count": 0,
                    "started_at": None,
                    "ended_at": None,
                    "duration_seconds": None,
                    "size_bytes": artifact_size,
                    "status": "unknown",
                }
            )

        end_epoch = record.get("end_time")
        return {
            "collector_started_at": datetime.fromtimestamp(
                record["start_time"], tz=timezone.utc
            ).isoformat(),
            "collector_ended_at": (
                datetime.fromtimestamp(end_epoch, tz=timezone.utc).isoformat()
                if end_epoch is not None
                else self._utc_now_iso()
            ),
            "wall_clock_duration_seconds": wall_duration,
            "wall_clock_is_authoritative": True,
            "cumulative_operation_time_seconds": cumulative,
            "operation_aggregation": "top_level_contributing_spans",
            "nested_operation_time_excluded_seconds": nested_excluded,
            "active_operation_union_seconds": active_union,
            "overlapped_operation_time_seconds": max(0.0, cumulative - active_union),
            "unattributed_wall_time_seconds": max(0.0, wall_duration - active_union),
            "operation_sum_equals_wall_clock": False,
            "event_counters": dict(
                record.get("_event_counters", self._empty_event_counters())
            ),
            "redfish_request_accounting": dict(
                record.get(
                    "_redfish_request_accounting",
                    self._empty_redfish_request_accounting(),
                )
            ),
            "event_limits": {
                "max_operations_per_collector": self.max_operations_per_collector,
                "max_operations_per_dut": self.max_operations_per_dut,
                "max_operations_per_run": self.max_operations_per_run,
                "max_redfish_request_operations_per_collector": (
                    self.max_redfish_request_operations_per_collector
                ),
                "max_redfish_request_operations_per_dut": (
                    self.max_redfish_request_operations_per_dut
                ),
                "max_compact_pending_artifact_operations": (
                    MAX_COMPACT_PENDING_ARTIFACT_OPERATIONS
                ),
                "max_stages_per_collector": MAX_STAGES_PER_COLLECTOR,
                "max_hooks_per_stage": MAX_HOOKS_PER_STAGE,
                "max_hooks_per_collector": MAX_HOOKS_PER_COLLECTOR,
                "max_request_types_per_hook": MAX_REQUEST_TYPES_PER_HOOK,
                "max_request_types_per_collector": (MAX_REQUEST_TYPES_PER_COLLECTOR),
                "max_artifact_paths_per_operation": MAX_ARTIFACT_PATHS_PER_OPERATION,
                "max_artifact_path_json_bytes_per_operation": (
                    MAX_ARTIFACT_PATH_BYTES_PER_OPERATION
                ),
                "max_artifact_path_characters_per_operation": (
                    MAX_ARTIFACT_PATH_CHARS_PER_OPERATION
                ),
                "max_uninstrumented_artifacts_per_collector": (
                    MAX_UNINSTRUMENTED_ARTIFACTS_PER_COLLECTOR
                ),
                "max_uninstrumented_artifacts_per_dut": (
                    MAX_UNINSTRUMENTED_ARTIFACTS_PER_DUT
                ),
                "max_uninstrumented_artifacts_per_run": (
                    MAX_UNINSTRUMENTED_ARTIFACTS_PER_RUN
                ),
                "max_uninstrumented_artifact_path_characters": (
                    MAX_UNINSTRUMENTED_ARTIFACT_PATH_CHARS
                ),
                "max_uninstrumented_artifact_path_json_bytes": (
                    MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES
                ),
                "max_uninstrumented_artifact_path_characters_per_dut": (
                    MAX_UNINSTRUMENTED_ARTIFACT_PATH_CHARS_PER_DUT
                ),
                "max_uninstrumented_artifact_path_json_bytes_per_dut": (
                    MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_DUT
                ),
                "max_uninstrumented_artifact_path_characters_per_run": (
                    MAX_UNINSTRUMENTED_ARTIFACT_PATH_CHARS_PER_RUN
                ),
                "max_uninstrumented_artifact_path_json_bytes_per_run": (
                    MAX_UNINSTRUMENTED_ARTIFACT_PATH_BYTES_PER_RUN
                ),
            },
            "operations": public_operations,
            "artifact_timings": artifact_timings,
        }

    def start_component(self, component_name: str) -> None:
        """
        Start timing for a high-level component.

        The implementation uses ``component_name`` to start timing for a
        high-level component.

        Args:
            component_name: Stable component name used for lookup and
                operator-facing diagnostics.
        """
        if component_name in self.component_timing:
            self.component_timing[component_name]["start_time"] = time.time()

    def end_component(self, component_name: str) -> None:
        """
        End timing for a high-level component.

        The implementation uses ``component_name`` to end timing for a
        high-level component.

        Args:
            component_name: Stable component name used for lookup and
                operator-facing diagnostics.
        """
        if (
            component_name in self.component_timing
            and self.component_timing[component_name]["start_time"] is not None
        ):
            self.component_timing[component_name]["end_time"] = time.time()
            self.component_timing[component_name]["total_time"] = (
                self.component_timing[component_name]["end_time"]
                - self.component_timing[component_name]["start_time"]
            )

    def get_component_timing(self) -> Dict[str, Any]:
        """
        Get the component timing data.

        After applying local validation, the function forwards current instance
        state to ``self.component_timing.copy`` and preserves its return and
        exception contract.

        Returns:
            A mapping containing component timing.
        """
        return self.component_timing.copy()

    def log_timing(self, message: str) -> None:
        """
        Log a timing message (for debug output).

        The implementation uses ``message`` to log a timing message (for debug
        output).

        Args:
            message: Operator-facing text carried by the reported event or
                failure.
        """
        if self.debug_mode:
            print(f"TIMING: {message}")

    def print_timing_summary(self, sanitizer=None) -> None:
        """
        Print timing summary to console (debug mode only).

        The implementation uses ``sanitizer`` to print timing summary to console
        (debug mode only).

        Args:
            sanitizer: Sanitizer applied before untrusted or sensitive text
                leaves its boundary.
        """
        if not self.debug_mode or not self.timing_data:
            return

        console = create_sanitized_console(sanitizer)

        # Create a clear separator
        console.print_separator()
        console.print_header("TIMING SUMMARY")
        console.print_separator()

        for collector_id, data in self.timing_data.items():
            total_time = data.get("total_time", 0.0)
            status = data.get("status", "unknown")

            if status == "completed":
                console.print_success(
                    f"\nCollector {collector_id}: {total_time:.2f}s ({status})"
                )
            else:
                console.print_error(
                    f"\nCollector {collector_id}: {total_time:.2f}s ({status})"
                )

            for stage_name, stage_data in data.get("stages", {}).items():
                stage_time = stage_data.get("total_time", 0.0)
                console.print(f"  └─ {stage_name}: {stage_time:.2f}s", "cyan")

                for hook_name, hook_data in stage_data.get("hooks", {}).items():
                    hook_time = hook_data.get("total_time", 0.0)
                    console.print(f"    └─ {hook_name}: {hook_time:.2f}s", "yellow")

                    for request_name, request_data in hook_data.get(
                        "requests", {}
                    ).items():
                        request_time = request_data.get("total_time", 0.0)
                        console.print(
                            f"      └─ {request_name}: {request_time:.2f}s",
                            "white",
                        )

        console.print_separator()

    def save_timing_report(
        self, dut_id: str, dut_metadata_dir: Optional[Path] = None
    ) -> Optional[Path]:
        """
        Save timing report to JSON file in DUT metadata directory.

        Use provided DUT metadata directory or create timing_reports directory
        as fallback.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            dut_metadata_dir: Optional filesystem location used as the DUT
                metadata dir for this operation.

        Returns:
            The validated ``file_path``, or ``None`` when no value qualifies.
        """
        if not self.debug_mode or not self.timing_data:
            return None

        # Use provided DUT metadata directory or create timing_reports directory as fallback
        if dut_metadata_dir:
            timing_dir = dut_metadata_dir
        else:
            timing_dir = self.output_dir / "timing_reports"
            timing_dir.mkdir(exist_ok=True)

        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"timing_report_{dut_id}_{timestamp}.json"
        file_path = timing_dir / filename

        dut_collectors = {
            collector_id: record
            for (
                record_dut_id,
                collector_id,
            ), record in self._collector_records.items()
            if record_dut_id == str(dut_id)
        }
        collector_source = dut_collectors or self.timing_data
        collector_data = {
            collector_id: self._project_public_legacy_collector(record)
            for collector_id, record in collector_source.items()
        }

        # Prepare report data. Runtime-only monotonic fields are intentionally
        # stripped instead of leaking implementation details into the JSON.
        report_data = {
            "metadata": {
                "dut_id": dut_id,
                "timestamp": datetime.now().isoformat(),
                "debug_mode": self.debug_mode,
                "total_collectors": len(collector_data),
            },
            "collectors": collector_data,
        }

        # Save to file
        with open(file_path, "w") as f:
            json.dump(report_data, f, indent=2)

        return file_path

    @classmethod
    def _without_internal_fields(cls, value: Any) -> Any:
        """
        Return a JSON-ready copy without private runtime bookkeeping.

        The implementation uses ``value`` to produce a JSON-ready copy without
        private runtime bookkeeping.

        Args:
            value: Value object whose ``items`` state is read while performing
                JSON-ready copy without private runtime bookkeeping.

        Returns:
            A JSON-ready copy without private runtime bookkeeping.
        """
        if isinstance(value, dict):
            return {
                key: cls._without_internal_fields(item)
                for key, item in value.items()
                if not str(key).startswith("_")
            }
        if isinstance(value, list):
            return [cls._without_internal_fields(item) for item in value]
        if isinstance(value, tuple):
            return [cls._without_internal_fields(item) for item in value]
        return value

    def get_summary(self) -> Dict[str, Any]:
        """
        Get timing summary.

        The implementation uses current instance state to get timing summary.

        Returns:
            A mapping containing summary.
        """
        if not self.debug_mode or not self.timing_data:
            return {}

        summary = {"total_collectors": len(self.timing_data), "collectors": {}}

        for collector_id, data in self.timing_data.items():
            data = self._project_public_legacy_collector(data)
            summary["collectors"][collector_id] = {
                "total_time": data.get("total_time", 0.0),
                "status": data.get("status", "unknown"),
                "stages": {},
            }

            for stage_name, stage_data in data.get("stages", {}).items():
                summary["collectors"][collector_id]["stages"][stage_name] = {
                    "total_time": stage_data.get("total_time", 0.0),
                    "hooks": {},
                }

                for hook_name, hook_data in stage_data.get("hooks", {}).items():
                    summary["collectors"][collector_id]["stages"][stage_name]["hooks"][
                        hook_name
                    ] = {
                        "total_time": hook_data.get("total_time", 0.0),
                        "requests": {},
                    }

                    for request_name, request_data in hook_data.get(
                        "requests", {}
                    ).items():
                        summary["collectors"][collector_id]["stages"][stage_name][
                            "hooks"
                        ][hook_name]["requests"][request_name] = {
                            "total_time": request_data.get("total_time", 0.0)
                        }

        return summary

    def get_timing_summary_for_metadata(
        self, dut_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get timing summary for metadata storage (always available).

        When ``dut_id`` is provided, return only records owned by that DUT. A
        DUT-level metadata file must not embed every other DUT's collector and
        artifact timing payloads.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing timing summary for metadata.
        """
        if not self.timing_data and not self._collector_records:
            return {}

        records = self._collector_records or {
            (str(data.get("dut_id", "")), str(collector_id)): data
            for collector_id, data in self.timing_data.items()
        }
        if dut_id is not None:
            normalized_dut_id = str(dut_id)
            records = {
                (record_dut_id, collector_id): data
                for (record_dut_id, collector_id), data in records.items()
                if record_dut_id == normalized_dut_id
            }
            if not records:
                return {}
        # Metadata is an index into the canonical per-DUT timing.json, not a
        # second copy of its operation and artifact arrays. Run-wide callers
        # receive one DUT index; DUT-scoped callers receive one collector index.
        summary: Dict[str, Any] = {
            "schema_version": "2.0",
            "total_collectors": len(records),
            "event_counters": self.get_event_counters(dut_id=dut_id),
        }
        is_run_wide = dut_id is None
        if is_run_wide:
            summary["collectors_by_dut"] = {}
            collector_index = summary["collectors_by_dut"]
        else:
            summary["dut_id"] = str(dut_id)
            summary["collectors"] = {}
            collector_index = summary["collectors"]

        for (record_dut_id, collector_id), data in records.items():
            data = self._project_public_legacy_collector(data)
            entry = {
                "total_time": data.get("total_time", 0.0),
                "status": data.get("status", "unknown"),
                "dut_id": record_dut_id,
                "start_time": (
                    datetime.fromtimestamp(
                        data["start_time"], tz=timezone.utc
                    ).isoformat()
                    if data.get("start_time") is not None
                    else None
                ),
                "end_time": (
                    datetime.fromtimestamp(
                        data["end_time"], tz=timezone.utc
                    ).isoformat()
                    if data.get("end_time") is not None
                    else None
                ),
                "stages": {},
            }

            for stage_name, stage_data in data.get("stages", {}).items():
                entry["stages"][stage_name] = {
                    "total_time": stage_data.get("total_time", 0.0)
                }

            if is_run_wide:
                collector_index.setdefault(record_dut_id, {})[collector_id] = entry
            else:
                collector_index[collector_id] = entry

        return summary

    def get_event_counters(self, dut_id: Optional[str] = None) -> Dict[str, int]:
        """
        Return timing-event accounting, optionally scoped to one DUT.

        The implementation uses ``dut_id`` to produce timing-event accounting,
        optionally scoped to one DUT.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing event counters.
        """
        if dut_id is None:
            return dict(self.event_counters)
        counters = self._empty_event_counters()
        normalized_dut_id = str(dut_id)
        for (record_dut_id, _), record in self._collector_records.items():
            if record_dut_id != normalized_dut_id:
                continue
            for key, value in record.get("_event_counters", {}).items():
                if key in counters:
                    counters[key] += int(value or 0)
        return counters

    def get_timing_reference_for_metadata(self, dut_id: str) -> Dict[str, Any]:
        """
        Return a compact pointer to the canonical per-DUT timing document.

        The implementation uses ``dut_id`` to produce a compact pointer to the
        canonical per-DUT timing document.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing the ``schema_version``, ``storage``,
            ``source``, ``total_collectors``, and ``event_counters`` fields.
        """
        normalized_dut_id = str(dut_id)
        total_collectors = sum(
            1
            for record_dut_id, _ in self._collector_records
            if record_dut_id == normalized_dut_id
        )
        if total_collectors == 0:
            return {}
        return {
            "schema_version": "2.0",
            "storage": "external",
            "source": "timing.json",
            "total_collectors": total_collectors,
            "event_counters": self.get_event_counters(dut_id=normalized_dut_id),
        }
