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
Collector lifecycle, stage, and hook orchestration for BaseService.

BaseService remains the compatibility facade and owns its managers, runtime
budget envelope, capture recorder, output store, and collector-specific hook
methods. This runner owns only sequencing and deliberately routes nested stage
and hook calls back through the facade so existing monkeypatch and subclass
seams remain authoritative.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from ..utils.artifact_paths import ArtifactRole, classify_artifact_path
from ..utils.request_response_capture import (
    _defer_capture_failure,
    _raise_capture_cleanup_outcome,
)
from ..utils.result_log_summary import summarize_result_for_log

if TYPE_CHECKING:
    from .base_service import BaseService


_CATALOG_HOOK_METHODS = frozenset(
    {
        "GET",
        "_derive_uri_suffixes",
        "_discover_chassis_devices",
        "_discover_dot_trusted_component_uris",
        "_validate_bmc_connection",
        "_validate_chassis_dynamic",
        "_validate_entities_consolidated",
        "_validate_entities_dynamic",
        "_validate_health_check_environment",
        "_validate_host_connection",
        "_validate_managers",
        "_validate_redfish_connection",
        "_validate_ssh_connection",
        "_validate_systems",
        "chassis_device_discovery",
        "collect_chassis_oem_binary_action",
        "collect_command_executor",
        "collect_component_integrity_data",
        "collect_custom_service_executor",
        "collect_device_diagnostic_data",
        "collect_dgx_diagnostic_data",
        "collect_diagnostic_data",
        "collect_host_unified",
        "collect_multi_step_collection",
        "collect_redfish_unified",
        "collect_system_dump_capabilities",
        "finalize_collector",
        "generate_streaming_csv",
        "run_bmc_command",
        "run_bmc_commands",
        "run_bmc_file_transfer",
        "run_bmc_i2c_commands",
        "run_bmc_script",
        "run_catalog_extension",
        "run_health_check",
        "run_host_device_based_commands",
        "run_ipmi_command",
        "run_ipmi_command_with_file_output",
        "run_ipmi_command_with_nvbmc_handling",
        "upload_file_to_bmc",
    }
)


class CollectorLifecycleRunner:
    """
    Sequence one collector through dependency, stage, and hook lifecycles.

    The type coordinates ``execute_collector``, ``execute_stage``, and
    ``execute_hook`` and retains the state those operations share between calls.
    Resource ownership remains inside the instance until the matching close,
    exit, or cleanup operation completes.
    """

    def __init__(
        self,
        service: "BaseService",
        *,
        bounded_identifier: Callable[..., str],
        bounded_parameter_summary: Callable[[Dict[Any, Any]], Dict[str, Any]],
        bounded_text_summary: Callable[[Any], Dict[str, Any]],
    ) -> None:
        """
        Initialize a ``CollectorLifecycleRunner`` instance.

        The initializer records ``_bounded_identifier``,
        ``_bounded_parameter_summary``, ``_bounded_text_summary``, and
        ``_service`` for later operations and establishes the instance
        invariants before any public method runs.

        Args:
            service: Service consumed while the function attempts to initialize
                a ``CollectorLifecycleRunner`` instance.
            bounded_identifier: Stable bounded identifier used to correlate
                configuration, logs, and results.
            bounded_parameter_summary: Mapping supplying fields for initialize a
                ``CollectorLifecycleRunner`` instance.
            bounded_text_summary: Mapping supplying fields for initialize a
                ``CollectorLifecycleRunner`` instance.
        """
        self._service = service
        self._bounded_identifier = bounded_identifier
        self._bounded_parameter_summary = bounded_parameter_summary
        self._bounded_text_summary = bounded_text_summary

    async def _log_collector_execution_policy(
        self,
        dut_id: str,
        collector_id: str,
        collection_level: str,
        collector_def: Dict[str, Any],
        runtime_budget: Any,
    ) -> None:
        """
        Emit the bounded execution policy that an operator needs at INFO.

        Explicit runtime budgets already resolve configuration-aware operation
        timeouts and enforced retry counts. Legacy collectors use the shared
        timeout resolver so opt-in DUT or tool overrides are reflected instead
        of merely repeating the catalog default. The log deliberately labels
        legacy ``retry_count`` as catalog configuration because individual
        services decide whether and where that value applies.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collection_level: Resolved collection level for the current run.
            collector_def: Authored collector definition selected for execution.
            runtime_budget: Optional resolved runtime-budget contract for the
                current collector.

        Side Effects:
            Resolves legacy timeout configuration and emits one INFO runtime-log
            record.
        """

        catalog_timeout = collector_def.get("timeout")
        if (
            not isinstance(catalog_timeout, (int, float))
            or isinstance(catalog_timeout, bool)
            or catalog_timeout <= 0
        ):
            catalog_timeout = 300

        if (
            runtime_budget is not None
            and getattr(runtime_budget, "source", None) == "catalog.runtime_budget"
        ):
            timeout_policy = (
                "operation_timeout="
                f"{float(runtime_budget.operation_timeout_seconds):g}s, "
                "timeout_source=runtime_budget"
            )
            retry_policy = f"enforced_retries={runtime_budget.max_retries}"
        else:
            collector_timeout = await self._service._get_collector_timeout(
                collector_id,
                dut_id,
                default_timeout=int(catalog_timeout),
            )
            timeout_policy = (
                f"collector_timeout={float(collector_timeout):g}s, "
                "timeout_source=resolved_collector_policy"
            )
            configured_retries = collector_def.get("retry_count")
            retry_policy = (
                f"catalog_retry_count={configured_retries}"
                if isinstance(configured_retries, int)
                and not isinstance(configured_retries, bool)
                and configured_retries >= 0
                else "catalog_retry_count=unspecified"
            )

        stage_names = [
            self._bounded_identifier(stage_name)
            for stage_name in (collector_def.get("stages") or {})
        ]
        stages_text = ",".join(stage_names) if stage_names else "none"
        await self._service._log_runtime(
            "INFO",
            "BaseService",
            (
                f"Collector {self._bounded_identifier(collector_id)} policy: "
                f"service={self._bounded_identifier(self._service.service_name)}, "
                f"level={self._bounded_identifier(collection_level)}, "
                f"{timeout_policy}, {retry_policy}, "
                f"stages={stages_text}"
            ),
            dut_id,
        )

    @staticmethod
    def _operation_count_text(context: Dict[str, Any]) -> str:
        """
        Return truthful successful/total operation counts for an INFO record.

        Boolean values and partially populated counters are treated as unknown
        so malformed collector context cannot produce a plausible but false
        operation ratio.

        Args:
            context: Result context that may carry standardized operation
                counters.

        Returns:
            A ``successful/total`` string when both counters are integers;
            otherwise ``unknown``.
        """

        successful_operations = context.get("successful_operations")
        total_operations = context.get("total_operations")
        if (
            isinstance(successful_operations, int)
            and not isinstance(successful_operations, bool)
            and isinstance(total_operations, int)
            and not isinstance(total_operations, bool)
        ):
            return f"{successful_operations}/{total_operations}"
        return "unknown"

    @staticmethod
    def _new_hook_output_files(
        result: Any,
        preexisting_output_files: Optional[set[str]] = None,
    ) -> List[str]:
        """
        Return output paths newly produced by one hook invocation.

        Hook results can expose output paths either at the top level or in the
        standardized result context. Paths already present in the input
        context are excluded so runtime logs and timing evidence report the
        same artifact count. Scalar values are ignored because output-file
        collections must be explicit sequences.

        Args:
            result: Hook result that may contain output-file collections.
            preexisting_output_files: Normalized paths present before the hook
                started.

        Returns:
            De-duplicated string paths in their first-observed order.
        """

        if not isinstance(result, dict):
            return []

        result_context = result.get("context", {})
        if not isinstance(result_context, dict):
            result_context = {}
        candidates: List[Any] = []
        for values in (
            result.get("output_files"),
            result_context.get("output_files"),
        ):
            if isinstance(values, (list, tuple, set)):
                candidates.extend(values)

        existing = preexisting_output_files or set()
        return list(
            dict.fromkeys(
                str(path) for path in candidates if path and str(path) not in existing
            )
        )

    async def _log_hook_terminal(
        self,
        dut_id: str,
        collector_id: str,
        method_name: str,
        status: Any,
        success: bool,
        reason: Any,
        start_time: float,
        context: Optional[Dict[str, Any]] = None,
        output_files: Optional[List[str]] = None,
    ) -> None:
        """
        Emit one structured terminal record for a hook execution path.

        Severity follows the normalized lifecycle status rather than the
        legacy success boolean because supported outcomes such as ``skipped``
        intentionally use ``success=False``. Unknown statuses fall back to the
        boolean so malformed results cannot be logged as healthy.

        Args:
            dut_id: Stable DUT identifier used to correlate runtime records.
            collector_id: Stable collector identifier used to correlate the
                hook with its collector.
            method_name: Bounded hook method name shown to the operator.
            status: Structured terminal status reported by the hook path.
            success: Legacy success boolean used only for unknown statuses.
            reason: Operator-facing terminal reason to summarize safely.
            start_time: Event-loop timestamp recorded before hook validation.
            context: Optional standardized result context with operation
                counters.
            output_files: Paths newly produced by this hook invocation.

        Side Effects:
            Emits exactly one terminal runtime-log record for the supplied
            hook path.
        """

        terminal_context = context if isinstance(context, dict) else {}
        normalized_status = str(status or "unknown").strip().lower()
        if normalized_status in {"error", "failed"}:
            level = "ERROR"
        elif normalized_status in {
            "partial",
            "degraded",
            "cancelled",
            "canceled",
        }:
            level = "WARNING"
        elif normalized_status in {"success", "skipped"}:
            level = "INFO"
        else:
            level = "INFO" if success else "ERROR"

        elapsed = max(0.0, asyncio.get_running_loop().time() - start_time)
        reason_summary = json.dumps(
            self._bounded_text_summary(reason),
            sort_keys=True,
            separators=(",", ":"),
        )
        await self._service._log_runtime(
            level,
            "BaseService",
            (
                f"[{self._bounded_identifier(collector_id)}] Hook "
                f"{self._bounded_identifier(method_name)} finished: "
                f"status={self._bounded_identifier(normalized_status)}, "
                f"elapsed={elapsed:.2f}s, "
                f"operations={self._operation_count_text(terminal_context)}, "
                f"artifacts={len(output_files or [])}, "
                f"reason_summary={reason_summary}"
            ),
            dut_id,
        )

    async def _log_collector_terminal(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: Any,
        start_time: float,
        context: Optional[Dict[str, Any]] = None,
        output_files: Optional[List[str]] = None,
    ) -> None:
        """
        Emit one authoritative, bounded terminal record for a collector.

        The record exposes final status, elapsed time, operation counts,
        retained artifact count, and a bounded reason summary. Raw response
        content and file contents remain outside INFO logs.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            status: Final collector status after lifecycle normalization.
            reason: Operator-facing terminal reason to summarize safely.
            start_time: Event-loop timestamp recorded before collector work.
            context: Optional result context containing operation counts and
                artifact paths.
            output_files: Optional terminal artifact paths not already present in
                ``context``.

        Side Effects:
            Emits exactly one terminal runtime-log record for the caller's
            collector path.
        """

        terminal_context = context if isinstance(context, dict) else {}
        artifact_paths = list(output_files or [])
        for field in ("output_files", "diagnostic_files", "error_files", "all_files"):
            values = terminal_context.get(field, [])
            if isinstance(values, (list, tuple, set)):
                artifact_paths.extend(str(path) for path in values if path)
        artifact_count = len(dict.fromkeys(artifact_paths))

        operations_text = self._operation_count_text(terminal_context)

        normalized_status = str(status or "unknown").lower()
        if normalized_status in {"error", "failed"}:
            level = "ERROR"
        elif normalized_status in {"partial", "degraded", "cancelled"}:
            level = "WARNING"
        else:
            level = "INFO"
        elapsed = max(0.0, asyncio.get_running_loop().time() - start_time)
        operator_reason = self._service._bounded_operator_reason(
            normalized_status,
            reason,
        )
        await self._service._log_runtime(
            level,
            "BaseService",
            (
                f"Collector {self._bounded_identifier(collector_id)} finished: "
                f"status={self._bounded_identifier(normalized_status)}, "
                f"elapsed={elapsed:.2f}s, operations={operations_text}, "
                f"artifacts={artifact_count}, reason={operator_reason}"
            ),
            dut_id,
        )

    async def execute_collector(
        self, dut_id: str, collector_id: str, collection_level: str = "L1"
    ) -> Dict[str, Any]:
        """
        Execute a collector on a DUT.

        The implementation uses ``dut_id``, ``collector_id``, and
        ``collection_level`` to execute a collector on a DUT. Terminal status is
        emitted only after collector on a DUT and its owned cleanup have
        completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collection_level: Text supplied as collection level in the format
                accepted by this function.

        Returns:
            A mapping containing execute collector.
        """
        # Update variable engine with DUT-specific context
        await self._service._update_variable_engine(dut_id)
        self._service._reset_effective_timeout_policy_logging(dut_id, collector_id)

        start_time = asyncio.get_event_loop().time()
        await self._service._log_runtime(
            "INFO",
            "BaseService",
            f"Starting collector {collector_id} on DUT {dut_id}",
            dut_id,
        )
        if hasattr(self._service, "orchestrator") and self._service.orchestrator:
            try:
                await self._service.orchestrator.record_execution_order_entry(
                    dut_id, collector_id
                )
            except Exception:
                pass

        # Start timing for this collector
        if self._service.timing_manager:
            self._service.timing_manager.start_collector(collector_id, dut_id)

        context: Dict[str, Any] = {}
        output_files: List[str] = []
        try:
            # Get collector definition
            collector_def = self._service._get_resolved_collector_definition(
                dut_id, collector_id
            )
            if not collector_def:
                error_reason = f"Collector {collector_id} not found in definitions"
                await self._service._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"Collector {collector_id} not found in definitions",
                    dut_id,
                )
                await self._service._log_error(
                    "COLLECTOR_NOT_FOUND", error_reason, dut_id, collector_id
                )

                # Finalize collector with error status
                try:
                    await self._service.finalize_collector(
                        dut_id,
                        collector_id,
                        "error",
                        error_reason,
                        execution_time=0.0,
                    )
                except Exception as finalize_error:
                    await self._service._log_error(
                        "FINALIZE_ERROR",
                        f"Failed to finalize collector: {finalize_error}",
                        dut_id,
                        collector_id,
                    )

                await self._service._end_collector_timing(
                    dut_id, collector_id, "failed", "error", error_reason
                )
                await self._service._acknowledge_request_capture_publications(
                    dut_id, collector_id
                )
                await self._log_collector_terminal(
                    dut_id,
                    collector_id,
                    "error",
                    error_reason,
                    start_time,
                )
                return {
                    "success": False,
                    "reason": error_reason,
                    "execution_time": 0.0,
                }

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Found collector definition for {collector_id}",
                dut_id,
            )

            # Initialize context
            context = {
                "dut_id": dut_id,
                "collector_id": collector_id,
                "collection_level": collection_level,
                "service_name": self._service.service_name,
                "collector_def": collector_def,
                "function_tag": collector_def.get("name", collector_id),
            }
            runtime_budget = self._service._current_runtime_budget(collector_id)
            if (
                runtime_budget is not None
                and runtime_budget.source == "catalog.runtime_budget"
            ):
                context["collector_budget"] = runtime_budget.to_dict()
                context["configured_retry_count"] = runtime_budget.max_retries
                # This nested mapping is intentionally shared with the logger's
                # shallow context copy.  The parent boundary freezes its final
                # elapsed value before the terminal status refresh.
                context["collector_budget_observation"] = {
                    "collector_wall_budget_seconds": (
                        runtime_budget.wall_timeout_seconds
                    ),
                    "collector_wall_status": "running",
                    "wall_timeout_triggered": False,
                    "terminal_cause": None,
                }

            await self._log_collector_execution_policy(
                dut_id,
                collector_id,
                collection_level,
                collector_def,
                runtime_budget,
            )

            # Attach the resolved baseboard identity and config for downstream hooks
            # (for example, capability-driven Redfish discovery).  Hook parameters
            # use ``target_baseboard`` as the canonical identity key, so retain it
            # even when the baseboard has no supplemental catalog configuration.
            baseboard_name = ""
            baseboard_config = None
            if self._service.dut_manager:
                dut_config = self._service.dut_manager.get_dut_config(dut_id)
                if dut_config:
                    baseboard_name = dut_config.get("baseboard") or dut_config.get(
                        "TargetBaseboard", ""
                    )
                baseboard_manager = None
                if hasattr(self._service.dut_manager, "_get_baseboard_manager"):
                    baseboard_manager = (
                        self._service.dut_manager._get_baseboard_manager()
                    )
                elif hasattr(self._service.dut_manager, "get_baseboard_manager"):
                    baseboard_manager = (
                        self._service.dut_manager.get_baseboard_manager()
                    )
                if baseboard_manager and baseboard_name:
                    baseboard_config = baseboard_manager.get_baseboard_config(
                        baseboard_name
                    )

            if baseboard_name:
                context["target_baseboard"] = baseboard_name
            if baseboard_config:
                context["baseboard_config"] = baseboard_config
                context["baseboard_specific_config"] = {
                    baseboard_name: baseboard_config
                }

            # Check dependencies
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Checking dependencies for {collector_id}",
                dut_id,
            )
            dependency_result = await self._service._check_collector_dependencies(
                collector_id, context
            )

            # Store detailed dependency results for metadata writing
            context["dependency_result"] = dependency_result

            # Write dependency results to metadata
            await self._service._write_collector_dependency_metadata(
                collector_id, dependency_result, dut_id
            )

            if dependency_result["status"] in {"fail", "error"}:
                dependency_status = (
                    "skipped" if dependency_result["status"] == "fail" else "error"
                )
                # Join into readable prose instead of interpolating the raw
                # Python list repr into the user-facing reason.
                error_reason = "Dependency check failed: " + "; ".join(
                    str(item) for item in dependency_result["missing_required"]
                )
                await self._service._log_runtime(
                    "WARN",
                    "BaseService",
                    f"Dependency check failed for {collector_id}: {dependency_result['missing_required']}",
                    dut_id,
                )

                # Confirmed unavailability skips collection; a failed probe
                # remains an error and must not fall through to execution.
                if self._service.logger:
                    try:
                        await self._service.finalize_collector(
                            dut_id,
                            collector_id,
                            dependency_status,
                            error_reason,
                            execution_time=0.0,
                        )
                    except Exception as finalize_error:
                        await self._service._log_runtime(
                            "ERROR",
                            "BaseService",
                            f"Failed to finalize collector: {finalize_error}",
                            dut_id,
                        )

                await self._service._end_collector_timing(
                    dut_id,
                    collector_id,
                    "skipped" if dependency_status == "skipped" else "failed",
                    dependency_status,
                    error_reason,
                )
                await self._service._acknowledge_request_capture_publications(
                    dut_id, collector_id
                )
                await self._log_collector_terminal(
                    dut_id,
                    collector_id,
                    dependency_status,
                    error_reason,
                    start_time,
                    context,
                )
                return {
                    "success": False,
                    "status": dependency_status,
                    "reason": error_reason,
                    "execution_time": 0.0,
                }

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Dependencies satisfied for {collector_id}",
                dut_id,
            )

            # Execute stages
            stages = [
                "validation",
                "discovery",
                "execution",
                "post_processing",
            ]
            output_files = []  # Collect output files from execution stage

            for stage in stages:
                if stage in collector_def.get("stages", {}):
                    stage_started = asyncio.get_running_loop().time()
                    stage_definition = collector_def.get("stages", {}).get(stage, {})
                    stage_hooks = (
                        stage_definition.get("hooks", [])
                        if isinstance(stage_definition, dict)
                        else []
                    )
                    await self._service._log_runtime(
                        "INFO",
                        "BaseService",
                        (
                            f"Collector {collector_id} stage {stage} started "
                            f"(hooks={len(stage_hooks) if isinstance(stage_hooks, list) else 0})"
                        ),
                        dut_id,
                    )

                    # Start timing for this stage
                    if self._service.timing_manager:
                        self._service.timing_manager.start_stage(stage)

                    try:
                        stage_result = await self._service._execute_stage(
                            stage, collector_def, context
                        )
                    finally:
                        # A timeout, exception, or cancellation must not leave
                        # a running stage span in timing metadata.
                        if self._service.timing_manager:
                            self._service.timing_manager.end_stage(stage)

                    stage_elapsed = max(
                        0.0, asyncio.get_running_loop().time() - stage_started
                    )
                    if not stage_result["success"]:
                        reason = stage_result.get("reason", "No reason provided")
                        operator_reason = self._service._bounded_operator_reason(
                            "error",
                            reason,
                        )
                        stage_context = dict(stage_result.get("context") or {})
                        for file_path in [
                            *(stage_result.get("output_files") or []),
                            *(stage_context.get("output_files") or []),
                        ]:
                            if file_path and file_path not in output_files:
                                output_files.append(file_path)
                        if output_files:
                            stage_context["output_files"] = list(output_files)
                        await self._service._log_runtime(
                            "ERROR",
                            "BaseService",
                            (
                                f"Collector {collector_id} stage {stage} failed "
                                f"after {stage_elapsed:.2f}s: {operator_reason}"
                            ),
                            dut_id,
                        )
                        await self._service._log_error(
                            "STAGE_ERROR",
                            f"Stage {stage} failed for {collector_id}: {reason}",
                            dut_id,
                            collector_id,
                        )

                        error_reason = f"Stage {stage} failed: {reason}"
                        stage_context["status"] = "error"
                        stage_context["reason"] = error_reason
                        execution_time = asyncio.get_event_loop().time() - start_time

                        # Prepare context for error logging
                        error_context = {
                            "operation_name": f"collector_stage_{stage}",
                            "execution_time": execution_time,
                            "stage": stage,
                            "stage_result": stage_result,
                            "collection_level": collection_level,
                        }

                        # Log error to error-logs directory. Keep the path
                        # defined when no logger is configured so the failure
                        # result can still preserve any artifacts produced by
                        # the stage.
                        error_log_path = ""
                        if self._service.logger:
                            try:
                                error_log_path = (
                                    await self._service._log_collector_error(
                                        dut_id,
                                        collector_id,
                                        error_reason,
                                        error_context,
                                    )
                                )
                            except Exception as log_error:
                                await self._service._log_runtime(
                                    "ERROR",
                                    "BaseService",
                                    f"Failed to log stage error: {log_error}",
                                    dut_id,
                                )
                                error_log_path = ""

                        if error_log_path and error_log_path not in output_files:
                            output_files.append(error_log_path)
                            stage_context["output_files"] = list(output_files)

                        # Finalize collector with error status.  The finalizer
                        # owns the authoritative artifact-role projection: an
                        # error log may be present in ``all_files`` without
                        # being a primary ``output_file``.
                        finalized_result = None
                        if self._service.logger:
                            try:
                                finalized_result = (
                                    await self._service.finalize_collector(
                                        dut_id,
                                        collector_id,
                                        "error",
                                        error_reason,
                                        execution_time=execution_time,
                                        output_files=output_files,
                                        detailed_context=stage_context,
                                    )
                                )
                            except Exception as finalize_error:
                                await self._service._log_runtime(
                                    "ERROR",
                                    "BaseService",
                                    f"Failed to finalize collector: {finalize_error}",
                                    dut_id,
                                )

                        await self._service._end_collector_timing(
                            dut_id,
                            collector_id,
                            "failed",
                            "error",
                            error_reason,
                        )
                        await self._service._acknowledge_request_capture_publications(
                            dut_id, collector_id
                        )
                        result = {
                            "success": False,
                            "status": "error",
                            "reason": error_reason,
                            "context": stage_context,
                            "execution_time": execution_time,
                            "output_files": output_files,
                        }
                        if isinstance(finalized_result, dict):
                            for artifact_field in (
                                "output_files",
                                "diagnostic_files",
                                "error_files",
                                "all_files",
                                "discovered_files",
                            ):
                                if artifact_field in finalized_result:
                                    result[artifact_field] = finalized_result[
                                        artifact_field
                                    ]
                        await self._log_collector_terminal(
                            dut_id,
                            collector_id,
                            "error",
                            error_reason,
                            start_time,
                            stage_context,
                            result.get("all_files", output_files),
                        )
                        return result
                    stage_log_context = stage_result.get("context", {})
                    if not isinstance(stage_log_context, dict):
                        stage_log_context = {}
                    stage_artifacts = list(stage_result.get("output_files") or [])
                    stage_artifacts.extend(stage_log_context.get("output_files") or [])
                    stage_status = stage_result.get(
                        "status", "success" if stage_result.get("success") else "error"
                    )
                    stage_status_text = self._bounded_identifier(stage_status)
                    stage_operations = self._operation_count_text(stage_log_context)
                    stage_log_level = (
                        "WARNING"
                        if str(stage_status).lower() in {"partial", "degraded"}
                        else "INFO"
                    )
                    await self._service._log_runtime(
                        stage_log_level,
                        "BaseService",
                        (
                            f"Collector {collector_id} stage {stage} finished: "
                            f"status={stage_status_text}, elapsed={stage_elapsed:.2f}s, "
                            f"operations={stage_operations}, "
                            f"artifacts={len(dict.fromkeys(str(path) for path in stage_artifacts if path))}"
                        ),
                        dut_id,
                    )

                    # Store stage results with stage-specific keys to avoid overwriting
                    stage_context = stage_result.get("context", {})

                    # FIX: Copy top-level status and reason from stage_result into stage_context
                    # so they can be propagated to the main context through the loop below.
                    # This handles the case where _create_standardized_collector_result returns
                    # status/reason at the top level but not inside the context dict.
                    if "status" in stage_result and "status" not in stage_context:
                        stage_context["status"] = stage_result["status"]
                    if "reason" in stage_result and "reason" not in stage_context:
                        stage_context["reason"] = stage_result["reason"]

                    # FIX: If stage_result is missing status but has success, add status to stage_result and stage_context
                    # This must be done BEFORE the context update loop so the status field gets processed
                    if "status" not in stage_result and "success" in stage_result:
                        # Check if we can determine status from the context or success flag
                        if stage_context.get(
                            "successful_operations"
                        ) and stage_context.get("total_operations"):
                            successful = stage_context.get("successful_operations", 0)
                            total = stage_context.get("total_operations", 0)
                            if successful == 0:
                                stage_result["status"] = "error"
                                stage_context["status"] = "error"
                            elif successful < total:
                                stage_result["status"] = "partial"
                                stage_context["status"] = "partial"
                            else:
                                stage_result["status"] = "success"
                                stage_context["status"] = "success"
                            # print(f"DEBUG: Added missing status to stage_result and stage_context: '{stage_result['status']}' based on {successful}/{total} operations")
                        else:
                            # For stages without operation counts (like validation), use the success flag directly
                            if stage_result.get("success", False):
                                stage_result["status"] = "success"
                                stage_context["status"] = "success"
                            else:
                                stage_result["status"] = "error"
                                stage_context["status"] = "error"

                    context[f"{stage}_result"] = stage_context

                    # Update main context, but be smart about 'reason' and 'status' fields
                    # Allow execution stage to override validation stage reason and status
                    # print(f"DEBUG: Processing context update for stage='{stage}', stage_context keys: {list(stage_context.keys())}")
                    for key, value in stage_context.items():
                        # print(f"DEBUG: Processing key='{key}', value='{value}', stage='{stage}'")
                        if key == "reason" and stage == "validation":
                            # For validation stage, only store reason if it's not a skip message
                            if not any(
                                skip_msg in str(value).lower()
                                for skip_msg in [
                                    "already validated",
                                    "validation skipped",
                                    "skipping validation",
                                ]
                            ):
                                context[key] = value
                                # print(f"DEBUG: Updated context with validation stage reason: '{value}'")
                        elif key == "reason" and stage == "execution":
                            # Execution stage reason always takes precedence
                            context[key] = value
                            # print(f"DEBUG: Updated context with execution stage reason: '{value}'")
                        elif key == "status" and stage == "execution":
                            # Execution stage status always takes precedence
                            context[key] = value
                            # print(f"DEBUG: Updated context with execution stage status: '{value}'")
                        elif key == "skip_reasons":
                            context[f"{stage}_skip_reasons"] = value
                            if stage == "execution":
                                context[key] = value
                        elif key == "diagnostic_files":
                            merged_files = list(context.get(key, []))
                            for file_path in value or []:
                                if file_path and file_path not in merged_files:
                                    merged_files.append(file_path)
                            if merged_files:
                                context[key] = merged_files
                        elif key == "request_response_logs":
                            merged_logs = dict(context.get(key, {}))
                            if isinstance(value, dict):
                                merged_logs.update(value)
                            if merged_logs:
                                context[key] = merged_logs
                        elif key not in context:
                            # For other fields, store if not already present
                            context[key] = value
                            # print(f"DEBUG: Updated context with new field '{key}': '{value}'")

                    # Debug logging after context update
                    # if stage == "execution":
                    #     print(f"DEBUG: context after update: {context.get('status', 'NOT_FOUND')}")

                    await self._service._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Stage {stage} result for {collector_id}: "
                        f"{summarize_result_for_log(stage_result)}",
                        dut_id,
                    )

                    # Collect output files from execution stage
                    if stage == "execution":
                        stage_context = stage_result.get("context", {})

                        # Preserve the execution stage status for final status determination
                        execution_stage_status = stage_result.get("status")
                        if execution_stage_status:
                            context["execution_stage_status"] = execution_stage_status
                            await self._service._log_runtime(
                                "DEBUG",
                                "BaseService",
                                f"Preserved execution stage status: {execution_stage_status}",
                                dut_id,
                            )

                        await self._service._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Processing execution stage for {collector_id}, stage_context keys: {list(stage_context.keys())}",
                            dut_id,
                        )

                        await self._service._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Execution stage structure for {collector_id}: "
                            f"{summarize_result_for_log(stage_result)}",
                            dut_id,
                        )

                        if "output_files" in stage_context:
                            await self._service._log_runtime(
                                "DEBUG",
                                "BaseService",
                                f"Found {len(stage_context['output_files'])} output files in stage_context: {stage_context['output_files']}",
                                dut_id,
                            )

                            # Check for duplicates before extending
                            original_count = len(output_files)
                            output_files.extend(stage_context["output_files"])
                            new_count = len(output_files)

                            if new_count - original_count != len(
                                stage_context["output_files"]
                            ):
                                await self._service._log_runtime(
                                    "WARNING",
                                    "BaseService",
                                    f"Duplicate detection: Expected to add {len(stage_context['output_files'])} files, but added {new_count - original_count}",
                                    dut_id,
                                )
                        else:
                            await self._service._log_runtime(
                                "DEBUG",
                                "BaseService",
                                f"Execution stage for {collector_id} returned no output_files field",
                                dut_id,
                            )

                        # Ensure aggregated output_files are reflected in main context for downstream hooks
                        if output_files:
                            # Deduplicate while preserving order
                            existing_files = context.get("output_files", [])
                            combined_files = existing_files + output_files
                            deduped = list(dict.fromkeys(combined_files))
                            context["output_files"] = deduped
                            await self._service._log_runtime(
                                "DEBUG",
                                "BaseService",
                                f"Synchronized {len(deduped)} output files into main context for {collector_id}",
                                dut_id,
                            )

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Finalizing collector {collector_id}",
                dut_id,
            )

            # Debug: Log context overview before status determination
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Status determination for {collector_id}: context_keys={list(context.keys())}, output_files_count={len(output_files)}",
                dut_id,
            )
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Key context values: status={context.get('status')}, execution_stage_status={context.get('execution_stage_status')}, reason={context.get('reason')}",
                dut_id,
            )

            # Determine final status based on overall collector success, not just stage status
            # Check multiple ways a collector could be skipped, but only if no output files were produced
            # However, if ignore_empty_results is True, don't treat empty output as skipped

            # First check if ignore_empty_results is set
            ignore_empty_results = False
            if "execution_result" in context:
                ignore_empty_results = context.get("execution_result", {}).get(
                    "ignore_empty_results", False
                )

            # If not found in execution_result, check the collector definition
            if not ignore_empty_results:
                collector_info = None
                if (
                    hasattr(self._service, "orchestrator")
                    and self._service.orchestrator
                ):
                    try:
                        collector_info = self._service.orchestrator.get_collector_info(
                            collector_id
                        )
                    except Exception:
                        pass

                if collector_info and "stages" in collector_info:
                    execution_stage = collector_info.get("stages", {}).get(
                        "execution", {}
                    )
                    for hook in execution_stage.get("hooks", []):
                        if (
                            "params" in hook
                            and "ignore_empty_results" in hook["params"]
                        ):
                            ignore_empty_results = hook["params"][
                                "ignore_empty_results"
                            ]
                            break

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Collector {collector_id}: ignore_empty_results={ignore_empty_results}, output_files={len(output_files)}",
                dut_id,
            )

            real_output_files = [
                f
                for f in output_files
                if classify_artifact_path(
                    f,
                    bundle_root=getattr(
                        getattr(self._service, "logger", None),
                        "base_log_dir",
                        None,
                    ),
                )
                is ArtifactRole.PRIMARY
            ]
            intentional_evidence_only_skip = bool(
                context.get("intentional_evidence_only_skip", False)
            )

            has_explicit_skip_status = (
                ("status" in context and context["status"] == "skipped")
                or (
                    "execution_stage_status" in context
                    and context["execution_stage_status"] == "skipped"
                )
                or any(
                    stage_name in context
                    and isinstance(context[stage_name], dict)
                    and context[stage_name].get("status") == "skipped"
                    for stage_name in [
                        "execution",
                        "post_processing",
                        "validation",
                    ]
                )
            )
            validation_result = context.get("validation_result", {})
            validation_incomplete = validation_result.get("status") == "partial"
            is_skipped = (
                not validation_incomplete
                and has_explicit_skip_status
                and (len(real_output_files) == 0 or intentional_evidence_only_skip)
            )

            # Override is_skipped if ignore_empty_results is True and context indicates success
            if is_skipped and ignore_empty_results:
                # Check if the context indicates this was a successful execution with empty results
                if (
                    context.get("status") == "success"
                    or context.get("execution_stage_status") == "success"
                ):
                    is_skipped = False
                    await self._service._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Collector {collector_id}: Treating empty results as success (ignore_empty_results=True)",
                        dut_id,
                    )

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Skip detection result for {collector_id}: is_skipped={is_skipped}",
                dut_id,
            )

            if is_skipped:
                final_status = "skipped"
                # Debug: Log context structure to understand what's available
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Context keys for skipped collector: {list(context.keys())}",
                    dut_id,
                )

                # Look for skip reason in stage contexts, prioritizing post_processing then execution
                skip_reason = None
                for stage_name in [
                    "post_processing",
                    "execution",
                    "validation",
                ]:
                    if stage_name in context and isinstance(context[stage_name], dict):
                        stage_context = context[stage_name]
                        await self._service._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Stage {stage_name} context: status={stage_context.get('status')}, keys={list(stage_context.keys())}",
                            dut_id,
                        )
                        if stage_context.get("status") == "skipped":
                            # Look for skip_message in the stage's finalize_collector params
                            commands = stage_context.get("commands", [])
                            await self._service._log_runtime(
                                "DEBUG",
                                "BaseService",
                                f"Stage {stage_name} has {len(commands)} commands",
                                dut_id,
                            )
                            for command in commands:
                                if command.get("method") == "finalize_collector":
                                    skip_message = command.get("params", {}).get(
                                        "skip_message"
                                    )
                                    await self._service._log_runtime(
                                        "DEBUG",
                                        "BaseService",
                                        f"Found finalize_collector with skip_message: {skip_message}",
                                        dut_id,
                                    )
                                    if skip_message:
                                        skip_reason = skip_message
                                        break
                            if skip_reason:
                                break
                            # Fallback to stage reason
                            if stage_context.get("reason"):
                                skip_reason = stage_context["reason"]
                                await self._service._log_runtime(
                                    "DEBUG",
                                    "BaseService",
                                    f"Using stage reason as fallback: {skip_reason}",
                                    dut_id,
                                )
                                break

                # Additional fallback: look for skip_message in hook parameters directly
                if not skip_reason:
                    for stage_name in [
                        "post_processing",
                        "execution",
                        "validation",
                    ]:
                        if f"{stage_name}_hooks" in context:
                            hooks = context[f"{stage_name}_hooks"]
                            for hook in hooks:
                                if hook.get("method") == "finalize_collector":
                                    skip_message = hook.get("params", {}).get(
                                        "skip_message"
                                    )
                                    if skip_message:
                                        skip_reason = skip_message
                                        await self._service._log_runtime(
                                            "DEBUG",
                                            "BaseService",
                                            f"Found skip_message in hook params: {skip_reason}",
                                            dut_id,
                                        )
                                        break
                            if skip_reason:
                                break

                aggregated_skip_reasons = []
                for key in (
                    "execution_skip_reasons",
                    "skip_reasons",
                    "post_processing_skip_reasons",
                    "validation_skip_reasons",
                ):
                    values = context.get(key, [])
                    if isinstance(values, list):
                        for value in values:
                            if value and value not in aggregated_skip_reasons:
                                aggregated_skip_reasons.append(value)

                if aggregated_skip_reasons:
                    final_reason = "; ".join(aggregated_skip_reasons)
                else:
                    final_reason = skip_reason or context.get(
                        "reason", "Collector was skipped"
                    )
                # A post-processing finalizer can reflect the execution skip
                # reason back into the accumulated context. Collapse identical
                # semicolon-delimited clauses before publishing the terminal
                # result so one not-applicable decision is reported once.
                reason_parts = [
                    reason_part.strip()
                    for reason_part in str(final_reason).split(";")
                    if reason_part.strip()
                ]
                for unit_size in range(1, (len(reason_parts) // 2) + 1):
                    if len(reason_parts) % unit_size:
                        continue
                    reason_unit = reason_parts[:unit_size]
                    if reason_unit * (len(reason_parts) // unit_size) == reason_parts:
                        reason_parts = reason_unit
                        break
                final_reason = "; ".join(reason_parts)
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Collector marked as skipped with final reason: {final_reason}",
                    dut_id,
                )
            else:
                # For non-skipped collectors, determine status based on output and errors
                total_output_files = len(real_output_files)
                has_errors = len(context.get("error_messages", [])) > 0
                reported_total_ops = context.get("total_operations")
                reported_success_ops = context.get("successful_operations")
                execution_stage_status = context.get("execution_stage_status")

                # A collector must never be reported as
                # "PARTIAL: 0 out of 0 operations succeeded". When zero operations were
                # counted, the operation tally carries no signal, so classify by the
                # concrete evidence we do have: produced files -> success, errors but
                # no files -> error, otherwise nothing happened -> skipped.
                if execution_stage_status == "degraded":
                    final_status = "degraded"
                    final_reason = context.get(
                        "reason", "Usable data collected with degraded results"
                    )
                    await self._service._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Using execution_stage_status 'degraded' for {collector_id}",
                        dut_id,
                    )
                elif reported_total_ops == 0:
                    if total_output_files > 0 and has_errors:
                        final_status = "partial"
                        final_reason = context.get(
                            "reason", "Partial success with some errors"
                        )
                    elif total_output_files > 0:
                        final_status = "success"
                        final_reason = context.get("reason", "Completed successfully")
                    elif has_errors:
                        final_status = "error"
                        final_reason = context.get(
                            "reason", "Failed to generate output"
                        )
                    else:
                        final_status = "skipped"
                        final_reason = context.get("reason", "No operations attempted")
                    await self._service._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"0/0 guard for {collector_id}: files={total_output_files}, has_errors={has_errors} -> {final_status}",
                        dut_id,
                    )
                # Preserve an explicit execution-stage partial before interpreting
                # aggregate operation counts. Some collectors count only fully clean
                # parent targets as successful while separately proving that a parent
                # artifact was saved with nested member failures (for example R18).
                # The execution stage owns that richer semantic distinction.
                elif execution_stage_status == "partial" and (
                    total_output_files > 0 or reported_success_ops > 0
                ):
                    final_status = "partial"
                    final_reason = context.get(
                        "reason", "Partial success with some errors"
                    )
                    await self._service._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Using execution_stage_status 'partial' for {collector_id}",
                        dut_id,
                    )
                # If operation counts were reported and every one failed without an
                # explicit partial result, this is an error even if diagnostic/error
                # evidence was written. Mirrors _determine_collector_status.
                elif (
                    isinstance(reported_total_ops, int)
                    and reported_total_ops > 0
                    and reported_success_ops == 0
                ):
                    final_status = "error"
                    final_reason = context.get(
                        "reason", f"All {reported_total_ops} operations failed"
                    )
                elif total_output_files > 0 and has_errors:
                    # Has output but also has errors - partial success
                    final_status = "partial"
                    final_reason = context.get(
                        "reason", "Partial success with some errors"
                    )
                # A success reason is authoritative only when no concrete error
                # evidence survived stage aggregation.
                elif (
                    total_output_files > 0
                    and "successfully" in context.get("reason", "").lower()
                ):
                    final_status = "success"
                    final_reason = context.get("reason", "Completed successfully")
                elif total_output_files == 0 and has_errors:
                    # No output and has errors - error
                    final_status = "error"
                    final_reason = context.get("reason", "Failed to generate output")
                else:
                    # Fallback to execution stage status if available
                    if "execution_stage_status" in context:
                        final_status = context["execution_stage_status"]
                        final_reason = context.get("reason", "Completed successfully")
                        await self._service._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Using preserved execution stage status as fallback: {final_status}",
                            dut_id,
                        )
                    else:
                        final_status = context.get("status", "success")
                        final_reason = context.get("reason", "Completed successfully")
                        await self._service._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Using context status as fallback: {final_status}",
                            dut_id,
                        )

                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Final status determination: {total_output_files} files, has_errors={has_errors}, status={final_status}",
                    dut_id,
                )

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Finalizing collector {collector_id} with {len(output_files)} output_files: {output_files}",
                dut_id,
            )

            # Execution can succeed over a reduced target list after validation
            # was partial. Its success/empty reason cannot describe full coverage.
            if validation_incomplete and final_status in {"partial", "error"}:
                validation_reason = validation_result.get("reason")
                if validation_reason:
                    if context.get("execution_stage_status") in {"success", "skipped"}:
                        final_reason = validation_reason
                    elif validation_reason not in final_reason:
                        final_reason = f"{validation_reason}; {final_reason}"

            final_discovered_files: Dict[str, List[str]] = {}
            final_diagnostic_files: List[str] = []
            final_error_files: List[str] = []
            final_all_files: List[str] = list(output_files)
            finalize_result = await self._service.finalize_collector(
                dut_id,
                collector_id,
                final_status,
                final_reason,
                execution_time=asyncio.get_event_loop().time() - start_time,
                output_files=output_files,
                intentional_evidence_only_skip=intentional_evidence_only_skip,
                # Pass the accumulated context so the recorded execution_summary
                # reflects the real operation counts. Collectors with a
                # post_processing finalize_collector hook already stored a
                # populated context; collectors without one (e.g. collection_type
                # "get") otherwise fall back to an empty context and report 0/0
                # despite succeeding.
                detailed_context=context,
                enforce_outcome_policy=True,
                outcome_policy=collector_def.get("outcome_policy"),
            )

            # Update final_status and final_reason with values from finalize_collector
            # This ensures that any status changes in finalize_collector (e.g., "success" -> "skipped")
            # are reflected in the final result
            if finalize_result and "status" in finalize_result:
                final_status = finalize_result["status"]
                final_reason = finalize_result["reason"]
                output_files = finalize_result.get("output_files", output_files)
                final_discovered_files = finalize_result.get("discovered_files", {})
                final_diagnostic_files = finalize_result.get("diagnostic_files", [])
                final_error_files = finalize_result.get("error_files", [])
                final_all_files = finalize_result.get("all_files", output_files)
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Updated status from finalize_collector: status={final_status}, reason='{final_reason}'",
                    dut_id,
                )

            context = self._service._project_terminal_outcome_context(
                context, final_status, final_reason
            )
            final_reason = str(context.get("reason", ""))
            final_failure_category = context.get("failure_category")

            # End timing for this collector
            timing_status = {
                "success": "completed",
                "degraded": "degraded",
                "partial": "partial",
                "skipped": "skipped",
            }.get(final_status, "failed")
            await self._service._end_collector_timing(
                dut_id,
                collector_id,
                timing_status,
                final_status,
                final_reason,
                final_failure_category,
            )
            await self._service._acknowledge_request_capture_publications(
                dut_id, collector_id
            )

            # Clean up per-collector execution context
            if (
                hasattr(self._service, "orchestrator")
                and self._service.orchestrator
                and hasattr(
                    self._service.orchestrator, "clear_collector_execution_context"
                )
            ):
                # DEBUG: Log context cleanup
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Cleaning up execution context for {dut_id}:{collector_id}",
                )
                await self._service.orchestrator.clear_collector_execution_context(
                    dut_id, collector_id
                )

            result = {
                "success": final_status in ("success", "degraded", "partial"),
                "status": final_status,
                "reason": final_reason,
                "context": context,
                "execution_time": asyncio.get_event_loop().time() - start_time,
                "output_files": output_files,
                "diagnostic_files": final_diagnostic_files,
                "error_files": final_error_files,
                "all_files": final_all_files,
                "discovered_files": final_discovered_files,
                **(
                    {"failure_category": final_failure_category}
                    if final_failure_category is not None
                    else {}
                ),
            }

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"execute_collector returning: {list(result.keys())} with status='{result['status']}'",
                dut_id,
            )
            await self._log_collector_terminal(
                dut_id,
                collector_id,
                final_status,
                final_reason,
                start_time,
                context,
                final_all_files,
            )
            return result

        except asyncio.CancelledError:
            if self._service.timing_manager:
                self._service.timing_manager.end_collector(collector_id, "cancelled")
            await self._log_collector_terminal(
                dut_id,
                collector_id,
                "cancelled",
                "Collector execution cancelled",
                start_time,
                context,
                output_files,
            )
            raise
        except Exception as e:
            execution_time = asyncio.get_event_loop().time() - start_time
            exception_detail = str(e).strip() or type(e).__name__
            error_context = self._service._project_terminal_outcome_context(
                {
                    "operation_name": "collector_execution",
                    "execution_time": execution_time,
                    "collection_level": collection_level,
                    "exception_type": type(e).__name__,
                    "exception_message": exception_detail,
                },
                "error",
                f"Collector execution failed: {exception_detail}",
                exception=e,
            )
            error_msg = str(error_context["reason"])

            # Clean up per-collector execution context on error
            if (
                hasattr(self._service, "orchestrator")
                and self._service.orchestrator
                and hasattr(
                    self._service.orchestrator, "clear_collector_execution_context"
                )
            ):
                # DEBUG: Log context cleanup on error
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Cleaning up execution context on error for {dut_id}:{collector_id}",
                )
                await self._service.orchestrator.clear_collector_execution_context(
                    dut_id, collector_id
                )

            # Log error using helper method
            await self._service._log_error(
                "COLLECTOR_ERROR", error_msg, dut_id, collector_id
            )

            # Finalize with error
            try:
                # Log error to error-logs directory
                error_log_path = await self._service._log_collector_error(
                    dut_id, collector_id, error_msg, error_context
                )

                await self._service.finalize_collector(
                    dut_id,
                    collector_id,
                    "error",
                    error_msg,
                    execution_time=execution_time,
                    output_files=[error_log_path] if error_log_path else [],
                    detailed_context=error_context,
                )
            except Exception as finalize_error:
                await self._service._log_error(
                    "FINALIZE_ERROR",
                    f"Failed to finalize collector: {finalize_error}",
                    dut_id,
                    collector_id,
                )

            await self._service._end_collector_timing(
                dut_id,
                collector_id,
                "failed",
                "error",
                error_msg,
                error_context.get("failure_category"),
            )
            await self._service._acknowledge_request_capture_publications(
                dut_id, collector_id
            )

            result = {
                "success": False,
                "reason": error_msg,
                "execution_time": execution_time,
                "context": error_context,
            }
            classified_result = self._service._classify_collector_outcome(
                result, exception=e
            ).to_legacy_result()
            await self._log_collector_terminal(
                dut_id,
                collector_id,
                classified_result.get("status", "error"),
                classified_result.get("reason", error_msg),
                start_time,
                classified_result.get("context", error_context),
                classified_result.get("all_files", []),
            )
            return classified_result

    async def execute_stage(
        self,
        stage: str,
        collector_def: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute a specific stage.

        Track the last hook that did real work (i.e. did not skip itself). An
        optional follow-up hook that skips (e.g. collect_dgx_diagnostic_data on
        non-DGX hardware) must not own the stage status/reason and bury a
        primary hook that succeeded.

        Args:
            stage: Text supplied as stage in the format accepted by this
                function.
            collector_def: Mapping supplying fields for specific stage.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            A mapping containing execute stage.
        """
        try:
            stage_config = collector_def["stages"][stage]
            hooks = stage_config.get("hooks", [])

            stage_context = context.copy()
            last_hook_result = None
            # Track the last hook that did real work (i.e. did not skip itself).
            # An optional follow-up hook that skips (e.g. collect_dgx_diagnostic_data
            # on non-DGX hardware) must not own the stage status/reason and bury a
            # primary hook that succeeded.
            authoritative_result = None
            stage_skip_reasons = list(stage_context.get("skip_reasons", []))
            stage_output_files = list(stage_context.get("output_files", []))
            stage_diagnostic_files = list(stage_context.get("diagnostic_files", []))
            stage_request_response_logs = dict(
                stage_context.get("request_response_logs", {})
            )

            # Operation counters are aggregated across hooks rather than overwritten.
            # stage_context.update() below replaces scalar context fields with each
            # hook's values, so a later hook reporting 0/0 (a skip) would otherwise
            # clobber an earlier hook's real counts while output_files accumulate.
            # We sum the counts and re-apply them after the loop.
            agg_successful_operations = 0
            agg_total_operations = 0
            agg_error_messages = []
            any_counts_reported = False
            counted_hook_count = 0

            for hook in hooks:
                stage_context["current_stage"] = stage
                hook_result = await self._service._execute_hook(hook, stage_context)
                status_contributing = hook.get("status_contributing", True)
                if status_contributing:
                    # Keep track of the last result that is intended to decide
                    # collector status.  Supporting/diagnostic hooks can still
                    # add files and context without turning evidence capture
                    # into a successful primary collection.
                    last_hook_result = hook_result

                # Debug logging for hook results
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Stage {stage} hook {hook.get('method', 'unknown')} result: success={hook_result.get('success')}, status={hook_result.get('status', 'not_set')}",
                    context.get("dut_id"),
                )

                # A hook may use ``success=False`` to mean that no operation was
                # performed while still making an explicit, terminal
                # not-applicable decision.  The structured status is more
                # authoritative than the compatibility boolean in that case.
                # Reclassifying such a result as an optional failure made
                # unavailable Redfish resources and placeholder collectors look
                # like tool errors. Explicit partials also continue through
                # finalization without becoming hard errors.
                if hook_result.get("status") in {"skipped", "partial"}:
                    hook_result = {**hook_result, "success": True}

                if not hook_result["success"]:
                    if hook.get("required", True):
                        failure_status = hook_result.get("status", "error")
                        failure_reason = (
                            f"Hook {hook.get('method', 'unknown')} failed: "
                            f"{hook_result.get('reason', 'No specific hook error reason provided')}"
                        )
                        failure_context = dict(stage_context)
                        failure_hook_context = dict(hook_result.get("context") or {})
                        failure_context.update(
                            {
                                key: value
                                for key, value in failure_hook_context.items()
                                if key
                                not in {"diagnostic_files", "request_response_logs"}
                            }
                        )
                        for file_path in failure_hook_context.get(
                            "diagnostic_files", []
                        ):
                            if file_path and file_path not in stage_diagnostic_files:
                                stage_diagnostic_files.append(file_path)
                        failure_request_logs = failure_hook_context.get(
                            "request_response_logs", {}
                        )
                        if isinstance(failure_request_logs, dict):
                            stage_request_response_logs.update(failure_request_logs)
                        if stage_diagnostic_files:
                            failure_context["diagnostic_files"] = list(
                                stage_diagnostic_files
                            )
                        if stage_request_response_logs:
                            failure_context["request_response_logs"] = dict(
                                stage_request_response_logs
                            )
                        failure_output_files = list(stage_output_files)
                        for file_path in [
                            *(hook_result.get("output_files") or []),
                            *(
                                (hook_result.get("context") or {}).get("output_files")
                                or []
                            ),
                        ]:
                            if file_path and file_path not in failure_output_files:
                                failure_output_files.append(file_path)
                        if failure_output_files:
                            failure_context["output_files"] = failure_output_files
                        failure_context["status"] = failure_status
                        failure_context["reason"] = failure_reason
                        return {
                            "success": False,
                            "status": failure_status,
                            "reason": failure_reason,
                            "context": failure_context,
                        }

                    optional_reason = (
                        f"Optional hook {hook.get('method', 'unknown')} failed: "
                        f"{hook_result.get('reason', 'No specific hook error reason provided')}"
                    )
                    hook_context = dict(hook_result.get("context") or {})
                    optional_errors = list(hook_context.get("error_messages", []))
                    if optional_reason not in optional_errors:
                        optional_errors.append(optional_reason)
                    hook_context["error_messages"] = optional_errors
                    hook_result = {
                        **hook_result,
                        "success": True,
                        "status": "partial",
                        "reason": optional_reason,
                        "context": hook_context,
                    }
                if hook_result.get("status") == "skipped":
                    if (
                        hook_result.get("reason")
                        and hook_result["reason"] not in stage_skip_reasons
                    ):
                        stage_skip_reasons.append(hook_result["reason"])
                elif status_contributing and hook_result.get("status") in {
                    "success",
                    "degraded",
                    "partial",
                    "error",
                    "failed",
                }:
                    # Preserve the most severe non-skipped outcome. A later
                    # successful hook must not erase an earlier partial result,
                    # and a status-less helper must not erase any recognized
                    # outcome before a later optional hook skips.
                    status_priority = {
                        "success": 1,
                        "degraded": 2,
                        "partial": 3,
                        "error": 4,
                        "failed": 4,
                    }
                    current_priority = status_priority.get(
                        (authoritative_result or {}).get("status"), 0
                    )
                    candidate_priority = status_priority.get(
                        hook_result.get("status"), 1
                    )
                    if candidate_priority >= current_priority:
                        authoritative_result = hook_result

                hook_context = hook_result.get("context", {})

                # Accumulate operation counters before the context overwrite so a
                # skipping follow-up hook cannot zero out a prior hook's real counts.
                if status_contributing and (
                    "successful_operations" in hook_context
                    or "total_operations" in hook_context
                ):
                    any_counts_reported = True
                    if hook_context.get("total_operations", 0) > 0:
                        counted_hook_count += 1
                    agg_successful_operations += hook_context.get(
                        "successful_operations", 0
                    )
                    agg_total_operations += hook_context.get("total_operations", 0)
                for error_message in hook_context.get("error_messages", []):
                    if error_message not in agg_error_messages:
                        agg_error_messages.append(error_message)
                for file_path in hook_context.get("diagnostic_files", []):
                    if file_path and file_path not in stage_diagnostic_files:
                        stage_diagnostic_files.append(file_path)
                hook_request_logs = hook_context.get("request_response_logs", {})
                if isinstance(hook_request_logs, dict):
                    stage_request_response_logs.update(hook_request_logs)

                # Update context without allowing a later hook's empty file
                # list to erase artifacts produced by an earlier hook.
                stage_context.update(
                    {
                        key: value
                        for key, value in hook_context.items()
                        if key
                        not in {
                            "output_files",
                            "diagnostic_files",
                            "request_response_logs",
                        }
                    }
                )

                # Handle both patterns: output_files at top level AND in context
                top_level_files = hook_result.get("output_files", [])
                context_files = hook_result.get("context", {}).get("output_files", [])

                for file_path in [*top_level_files, *context_files]:
                    if file_path and file_path not in stage_output_files:
                        stage_output_files.append(file_path)

            if stage_output_files:
                stage_context["output_files"] = stage_output_files
            if stage_diagnostic_files:
                stage_context["diagnostic_files"] = stage_diagnostic_files
            if stage_request_response_logs:
                stage_context["request_response_logs"] = stage_request_response_logs

            # Re-apply the aggregated counters/errors so they reflect every hook,
            # not just whichever hook ran last.
            if any_counts_reported:
                stage_context["successful_operations"] = agg_successful_operations
                stage_context["total_operations"] = agg_total_operations
            if agg_error_messages:
                stage_context["error_messages"] = agg_error_messages

            # Preserve status from the last authoritative hook result or context.
            # Falling back to last_hook_result only when every hook skipped.
            representative_result = authoritative_result or last_hook_result

            result = {
                "success": True,  # Default to True, will be overridden if needed
                "context": stage_context,
            }

            # Use the status from the representative hook result if available
            if representative_result and "status" in representative_result:
                result["status"] = representative_result["status"]
                # stage_context starts as a copy of the prior stage's context.
                # Make the representative hook authoritative here as well so
                # execution cannot retain validation's status/reason.
                stage_context["status"] = representative_result["status"]
                # For partial and skipped status, success should still be True
                if representative_result["status"] in [
                    "success",
                    "degraded",
                    "partial",
                    "skipped",
                ]:
                    result["success"] = True
                else:
                    result["success"] = False
                # Preserve the reason from the hook result
                if "reason" in representative_result:
                    representative_reason = representative_result["reason"]
                    if counted_hook_count > 1 and agg_total_operations > 0:
                        if representative_result["status"] == "success":
                            aggregate_reason = (
                                "Successfully completed "
                                f"{agg_successful_operations}/{agg_total_operations} "
                                f"operations across {counted_hook_count} {stage} hooks"
                            )
                        elif representative_result["status"] == "partial":
                            aggregate_reason = (
                                f"{representative_result['status'].capitalize()} result: "
                                f"{agg_successful_operations}/{agg_total_operations} "
                                f"operations completed cleanly across "
                                f"{counted_hook_count} {stage} hooks"
                            )
                        else:
                            aggregate_reason = representative_reason
                        representative_context = representative_result.get(
                            "context", {}
                        )
                        if (
                            representative_context.get("ignore_empty_results")
                            and representative_context.get("files_collected") == 0
                            and representative_reason
                        ):
                            aggregate_reason += f"; {representative_reason}"
                        elif representative_result["status"] == "partial":
                            aggregate_reason += f"; {representative_reason}"
                        representative_reason = aggregate_reason
                    result["reason"] = representative_reason
                    stage_context["reason"] = representative_reason
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Stage {stage} using hook result status: {representative_result['status']}",
                    context.get("dut_id"),
                )
            elif "status" in stage_context:
                result["status"] = stage_context["status"]
                # For partial and skipped status, success should still be True
                if stage_context["status"] in [
                    "success",
                    "degraded",
                    "partial",
                    "skipped",
                ]:
                    result["success"] = True
                else:
                    result["success"] = False
                # Preserve the reason from the stage context
                if "reason" in stage_context:
                    result["reason"] = stage_context["reason"]
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Stage {stage} using context status: {stage_context['status']}",
                    context.get("dut_id"),
                )

            if stage_skip_reasons:
                stage_context["skip_reasons"] = stage_skip_reasons

            # Debug logging for final stage result
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Stage {stage} final result: success={result.get('success')}, status={result.get('status', 'not_set')}",
                context.get("dut_id"),
            )

            return result

        except Exception as e:
            exception_detail = str(e).strip() or type(e).__name__
            result = {
                "success": False,
                "reason": f"Stage {stage} execution error: {exception_detail}",
            }
            return self._service._classify_collector_outcome(
                result, stage=stage, exception=e
            ).to_legacy_result()

    async def execute_hook(
        self, hook: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a hook method.

        The implementation uses ``hook`` and ``context`` to execute a hook
        method. Terminal status is emitted only after hook method and its owned
        cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            hook: Callable invoked at the hook boundary.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            A mapping containing execute hook.
        """
        hook_started = asyncio.get_running_loop().time()
        dut_id = context.get("dut_id", "unknown")
        collector_id = self._bounded_identifier(context.get("collector_id", "unknown"))
        current_stage = self._bounded_identifier(
            context.get("current_stage", "unknown")
        )
        try:
            method_name = hook.get("method")
            if not isinstance(method_name, str) or not method_name:
                result = {
                    "success": False,
                    "reason": "Hook missing method name",
                }
                await self._log_hook_terminal(
                    dut_id,
                    collector_id,
                    "unknown",
                    "error",
                    False,
                    result["reason"],
                    hook_started,
                )
                return result
            logged_method_name = self._bounded_identifier(method_name)
            if method_name not in _CATALOG_HOOK_METHODS:
                result = {
                    "success": False,
                    "reason": f"Hook method {logged_method_name} is not allowed",
                }
                await self._log_hook_terminal(
                    dut_id,
                    collector_id,
                    logged_method_name,
                    "error",
                    False,
                    result["reason"],
                    hook_started,
                )
                return result

            # Log hook execution start
            await self._service._log_runtime(
                "INFO",
                "BaseService",
                (
                    f"[{collector_id}] Starting {current_stage} hook "
                    f"{logged_method_name}"
                ),
                dut_id,
            )

            # Start timing for this hook
            if self._service.timing_manager:
                self._service.timing_manager.start_hook(method_name)

            # Get method from service
            method = getattr(self._service, method_name, None)
            if not method:
                if self._service.timing_manager:
                    self._service.timing_manager.end_hook(method_name, status="error")
                result = {
                    "success": False,
                    "reason": (
                        f"Method {logged_method_name} not found in {self._service.service_name}"
                    ),
                }
                await self._log_hook_terminal(
                    dut_id,
                    collector_id,
                    logged_method_name,
                    "error",
                    False,
                    result["reason"],
                    hook_started,
                )
                return result

            # Prepare parameters
            raw_hook_params = hook.get("params", {})
            if not isinstance(raw_hook_params, dict):
                if self._service.timing_manager:
                    self._service.timing_manager.end_hook(method_name, status="error")
                result = {
                    "success": False,
                    "reason": "Hook params must be a mapping",
                }
                await self._log_hook_terminal(
                    dut_id,
                    collector_id,
                    logged_method_name,
                    "error",
                    False,
                    result["reason"],
                    hook_started,
                )
                return result
            hook_params = dict(raw_hook_params)
            route_in_params = "route" in hook_params
            configured_route = hook_params.get("route")

            # Merge context into hook params without overwriting explicit hook config.
            hook_params = {**context, **hook_params}

            # Check for output_pattern at hook level and add to params
            if "output_pattern" in hook:
                hook_params["output_pattern"] = hook["output_pattern"]

            # Route selectors are catalog-owned hook metadata. Forward the
            # selector explicitly instead of relying on it being duplicated in
            # ``params``. A conflicting duplicate is malformed catalog input
            # and must not silently choose one routing authority over another.
            if "route" in hook:
                hook_route = hook["route"]
                if route_in_params and configured_route != hook_route:
                    if self._service.timing_manager:
                        self._service.timing_manager.end_hook(
                            method_name, status="error"
                        )
                    result = {
                        "success": False,
                        "reason": (
                            "Hook has conflicting top-level and params.route values"
                        ),
                    }
                    await self._log_hook_terminal(
                        dut_id,
                        collector_id,
                        logged_method_name,
                        "error",
                        False,
                        result["reason"],
                        hook_started,
                    )
                    return result
                hook_params["route"] = hook_route

            # Special handling for finalize_collector method
            if method_name == "finalize_collector":
                # Ensure required arguments are present
                if "dut_id" not in hook_params:
                    hook_params["dut_id"] = context.get("dut_id")
                if "collector_id" not in hook_params:
                    hook_params["collector_id"] = context.get("collector_id")
                if "status" not in hook_params:
                    # Check if status is available in context from previous stage
                    if "status" in context:
                        hook_params["status"] = context["status"]
                    else:
                        hook_params["status"] = (
                            "success"  # Default to success for post_processing
                        )
                if "reason" not in hook_params:
                    # Check if reason is available in context from previous stage
                    if "reason" in context:
                        hook_params["reason"] = context["reason"]
                    else:
                        hook_params["reason"] = "Completed successfully"
                if "execution_time" not in hook_params:
                    hook_params["execution_time"] = 0.0
                # Keep the accumulated evidence attached to the declarative
                # catalog finalizer marker. The lifecycle terminal boundary
                # below performs the one actual publication after every stage
                # is complete and the authoritative wall time is known.
                if "detailed_context" not in hook_params:
                    hook_params["detailed_context"] = context
            else:
                # Apply parameter mapping for all other methods
                hook_params = await self._service._apply_parameter_mapping(
                    method_name, hook_params, context
                )

                # Add baseboard manager to hook params for all methods
                hook_params["baseboard_manager"] = (
                    self._service.dut_manager._get_baseboard_manager()
                )

            # Generalized collector directory resolution for all services
            hook_params = await self._service._resolve_collector_directory_variables(
                hook_params, context
            )

            # Parameter logging is deliberately shape-only. Catalog parameters
            # and merged runtime context can contain credentials or megabytes of
            # response data, so values must never be rendered into the run log.
            collector_id = self._bounded_identifier(
                hook_params.get("collector_id", context.get("collector_id"))
            )
            parameter_summary = self._bounded_parameter_summary(hook_params)
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"[{collector_id}] Hook {logged_method_name} parameter summary: "
                f"{json.dumps(parameter_summary, sort_keys=True, separators=(',', ':'))}",
                dut_id,
            )

            # Determine if request/response capture should be enabled for this hook
            capture_config = hook.get("store_request_response", None)
            capture_requested = method_name != "finalize_collector"
            capture_options: Dict[str, Any] = {}

            if isinstance(capture_config, dict):
                capture_requested = True
                capture_options = capture_config.copy()
            elif capture_config is not None:
                capture_requested = bool(capture_config)

            current_stage = context.get("current_stage")
            if (
                capture_config is None
                and current_stage in ("validation", "discovery")
                and (
                    method_name.startswith("_validate_")
                    or method_name.startswith("_discover_")
                )
            ):
                capture_requested = True

            if hook.get("request_response_output_pattern"):
                capture_options["output_pattern"] = hook[
                    "request_response_output_pattern"
                ]
            if hook.get("request_response_function_tag"):
                capture_options["function_tag"] = hook["request_response_function_tag"]

            # RedfishService owns one collector-wide canonical ledger. Starting
            # this hook-local recorder as well would duplicate every request and
            # defeat aggregate evidence limits.
            if getattr(self._service, "_uses_canonical_redfish_capture", False):
                capture_requested = False

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"[{collector_id}] Executing method: {logged_method_name}",
                dut_id,
            )

            capture_token = None
            result = None
            capture_result = None
            hook_exception = None
            preexisting_output_files = {
                str(path) for path in context.get("output_files", []) if path
            }

            cleanup_failures: List[BaseException] = []
            try:
                if capture_requested:
                    capture_token = await self._service._begin_request_response_capture(
                        context, method_name, capture_options
                    )

                if (
                    method_name == "finalize_collector"
                    and current_stage == "post_processing"
                ):
                    # The lifecycle owns the one authoritative terminal
                    # publication after all stages have completed and the real
                    # wall time is known. Catalog finalizer hooks are retained
                    # as declarative compatibility markers, but publishing here
                    # would write/log the same terminal result twice (the first
                    # time with the synthetic 0.0-second duration).
                    deferred_status = str(hook_params.get("status", "success"))
                    deferred_reason = str(
                        hook_params.get("reason", "Completed successfully")
                    )
                    result = {
                        "success": deferred_status
                        in {"success", "degraded", "partial", "skipped"},
                        "status": deferred_status,
                        "reason": deferred_reason,
                        "context": dict(context),
                    }
                elif asyncio.iscoroutinefunction(method):
                    result = await method(**hook_params)
                else:
                    result = method(**hook_params)

                # Debug: Log method result
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"[{collector_id}] Method {logged_method_name} returned: "
                    f"{type(result).__name__}; shape="
                    f"{json.dumps(self._bounded_parameter_summary(result), sort_keys=True, separators=(',', ':')) if isinstance(result, dict) else 'scalar'}",
                    dut_id,
                )

                # Log hook execution result
                if isinstance(result, dict) and "success" in result:
                    success = bool(result.get("success", False))
                    reason = result.get("reason", "No reason provided")
                    result_context = result.get("context", {})
                    if not isinstance(result_context, dict):
                        result_context = {}
                    hook_status = result.get(
                        "status", "success" if success else "error"
                    )
                    hook_output_files = self._new_hook_output_files(
                        result,
                        preexisting_output_files,
                    )
                    await self._log_hook_terminal(
                        dut_id,
                        collector_id,
                        logged_method_name,
                        hook_status,
                        success,
                        reason,
                        hook_started,
                        result_context,
                        hook_output_files,
                    )

                    # Log context if present
                    if "context" in result and result["context"]:
                        if isinstance(result["context"], dict):
                            context_summary = self._bounded_parameter_summary(
                                result["context"]
                            )
                            await self._service._log_runtime(
                                "DEBUG",
                                "BaseService",
                                f"[{collector_id}] Hook {logged_method_name} "
                                f"context summary: "
                                f"{json.dumps(context_summary, sort_keys=True, separators=(',', ':'))}",
                                dut_id,
                            )
                else:
                    await self._log_hook_terminal(
                        dut_id,
                        collector_id,
                        logged_method_name,
                        "success",
                        True,
                        "Hook returned a simple result",
                        hook_started,
                    )

            except BaseException as e:
                hook_exception = e
            try:
                if self._service.timing_manager:
                    hook_output_files = self._new_hook_output_files(
                        result,
                        preexisting_output_files,
                    )
                    if isinstance(hook_exception, asyncio.CancelledError):
                        hook_timing_status = "cancelled"
                    elif hook_exception is not None:
                        hook_timing_status = "error"
                    elif isinstance(result, dict):
                        hook_timing_status = str(
                            result.get(
                                "status",
                                ("success" if result.get("success", True) else "error"),
                            )
                        ).lower()
                    else:
                        hook_timing_status = "success"
                    self._service.timing_manager.end_hook(
                        method_name,
                        artifact_paths=hook_output_files,
                        status=hook_timing_status,
                    )
            except BaseException as timing_error:
                cleanup_failures.append(timing_error)

            if capture_token:
                try:
                    capture_result = (
                        await self._service._finalize_request_response_capture(
                            capture_token,
                            context,
                            method_name,
                            capture_options,
                            result,
                            hook_exception,
                        )
                    )
                except BaseException as capture_error:
                    capture_result = None
                    capture_control = _defer_capture_failure(None, [], capture_error)
                    if hook_exception is not None or capture_control is not None:
                        cleanup_failures.append(capture_error)
                    else:
                        try:
                            await self._service._log_runtime(
                                "ERROR",
                                "BaseService",
                                f"[{collector_id}] Failed to finalize request/response capture for {method_name}: {capture_error}",
                                dut_id,
                            )
                        except BaseException as logging_error:
                            cleanup_failures.append(logging_error)

            if hook_exception is not None or cleanup_failures:
                control_flow: Optional[BaseException] = None
                ordinary_errors: List[BaseException] = []
                if hook_exception is not None:
                    control_flow = _defer_capture_failure(
                        control_flow,
                        ordinary_errors,
                        hook_exception,
                    )
                for cleanup_error in cleanup_failures:
                    control_flow = _defer_capture_failure(
                        control_flow,
                        ordinary_errors,
                        cleanup_error,
                    )
                _raise_capture_cleanup_outcome(
                    control_flow,
                    ordinary_errors,
                    "Hook execution and capture finalization failed",
                )

            # Check if the result indicates success/failure
            if isinstance(result, dict) and "success" in result:
                final_result = result
            else:
                # Method returned a simple result, treat as success
                final_result = {
                    "success": True,
                    "context": (
                        result if isinstance(result, dict) else {"result": result}
                    ),
                }

            if capture_result and isinstance(final_result, dict):
                self._service._attach_capture_metadata(
                    final_result,
                    capture_result,
                    method_name,
                    current_stage,
                    context,
                )

            return final_result

        except Exception as e:
            exception_detail = str(e).strip() or type(e).__name__
            method_name = self._bounded_identifier(hook.get("method", "unknown"))
            await self._log_hook_terminal(
                dut_id,
                collector_id,
                method_name,
                "error",
                False,
                exception_detail,
                hook_started,
            )
            result = {
                "success": False,
                "reason": f"Hook execution error: {exception_detail}",
            }
            return self._service._classify_collector_outcome(
                result,
                stage=context.get("current_stage"),
                exception=e,
            ).to_legacy_result()
