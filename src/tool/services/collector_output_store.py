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
Collector output inventory, publication, and finalization orchestration.

``BaseService`` remains the compatibility facade and owns lifecycle, capture,
status, timing, result-building, logger, and all monkeypatch/subclass seams.
This store owns only output-path resolution, inventory reconciliation, writes,
publication helper sequencing, and terminal output finalization. Every nested
operation deliberately crosses the service facade so existing overrides and
atomic publication policy remain authoritative.
"""

from __future__ import annotations

import json
import os
import traceback
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union

from ..core.collector_outcome import (
    CollectorOutcomeState,
    enforce_empty_success_policy,
    extract_collector_outcome_details,
    extract_operation_accounting,
)
from ..utils.artifact_paths import ArtifactRole, classify_artifact_path
from ..utils.enums import CollectorServiceMapping

if TYPE_CHECKING:
    from .base_service import BaseService

_SUCCESS_BEARING_STATUS_NAMES = frozenset({"success", "skipped", "degraded", "partial"})


class CollectorOutputStore:
    """
    Own collector output mechanics while retaining ``BaseService`` facades.

    The type coordinates ``_get_output_directory``,
    ``_resolve_collector_directory_variables``, ``_is_diagnostic_capture_file``,
    ``_is_error_artifact_file``, and ``_group_inventory_files`` and retains the
    state those operations share between calls. Resource ownership remains
    inside the instance until the matching close, exit, or cleanup operation
    completes.
    """

    def __init__(self, service: "BaseService") -> None:
        """
        Initialize a ``CollectorOutputStore`` instance.

        The initializer records ``_service`` for later operations and
        establishes the instance invariants before any public method runs.

        Args:
            service: Service consumed while the function attempts to initialize
                a ``CollectorOutputStore`` instance.
        """
        self._service = service

    async def _get_output_directory(self, dut_id: str) -> str:
        """
        Get the base output directory for the current collection session.

        The implementation uses ``dut_id`` to get the base output directory for
        the current collection session. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The canonical output directory text.
        """
        if (
            hasattr(self._service.logger, "base_log_dir")
            and self._service.logger.base_log_dir
        ):
            return self._service.logger.base_log_dir
        else:
            await self._service._log_runtime(
                "WARN",
                "BaseService",
                "Cannot get output directory - logger not available, using /tmp fallback",
                dut_id,
            )
            return "/tmp"

    async def _resolve_collector_directory_variables(
        self, hook_params: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Resolve {collector_dir} and {log_dir} variables in hook parameters.

        This provides a centralized way for all services to handle
        collector-specific log directories.

        Args:
            hook_params: Callable invoked at the hook params boundary.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            A mapping containing collector directory variables.
        """
        try:
            dut_id = context.get("dut_id")
            collector_id = context.get("collector_id")

            if not dut_id or not collector_id:
                return hook_params  # Can't resolve without DUT and collector info

            # Check if any parameter contains collector directory variables
            needs_resolution = False
            for value in hook_params.values():
                if isinstance(value, str) and (
                    "{collector_dir}" in value or "{log_dir}" in value
                ):
                    needs_resolution = True
                    break

            if not needs_resolution:
                return hook_params  # No variables to resolve

            # Get collector directory using the logger
            if self._service.logger:
                # Get the service group from the collector ID
                service_group = self._service._get_collector_group(collector_id)

                # CRITICAL FIX: Use original collector ID for file path determination
                # This prevents cross-contamination when one collector takes over another's execution
                original_collector_id = await self._service._get_original_collector_id(
                    dut_id, collector_id
                )

                # DEBUG: Log file path determination process
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"File path determination - collector_id: {collector_id}, original_collector_id: {original_collector_id}",
                )

                if original_collector_id != "unknown":
                    file_collector_id = original_collector_id

                    # VALIDATION: Log warning if there's a mismatch between current and original collector
                    if original_collector_id != collector_id:
                        await self._service._log_runtime(
                            "WARNING",
                            "BaseService",
                            f"Cross-contamination prevention: Using original collector ID '{original_collector_id}' for file paths while current context is '{collector_id}'",
                            dut_id,
                        )
                else:
                    file_collector_id = collector_id
                    await self._service._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Using current collector_id for file paths: {file_collector_id}",
                    )

                # Create a temporary file to get the collector directory
                temp_file_path = await self._service.logger.create_collector_log_file(
                    dut_id, service_group, file_collector_id, "temp.bin"
                )
                collector_dir = str(temp_file_path.parent)

                # Create substitution context
                substitution_context = {
                    "collector_dir": collector_dir,
                    "log_dir": collector_dir,  # Backward compatibility
                }

                # Update variable engine with DUT context if needed
                if self._service.variable_engine is None:
                    await self._service._update_variable_engine(dut_id)

                # Apply variable substitution to all string parameters
                resolved_params = {}
                for key, value in hook_params.items():
                    if isinstance(value, str) and (
                        "{collector_dir}" in value or "{log_dir}" in value
                    ):
                        # Use variable substitution service
                        if self._service.variable_engine:
                            resolved_value = await self._service.variable_engine.substitute_variables(
                                value,
                                substitution_context,
                                dut_id,
                                allow_missing=True,
                            )
                        else:
                            # Fallback to simple replacement
                            resolved_value = value.replace(
                                "{collector_dir}", collector_dir
                            )
                            resolved_value = resolved_value.replace(
                                "{log_dir}", collector_dir
                            )

                        resolved_params[key] = resolved_value

                        # Log the substitution for debugging
                        await self._service._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Resolved {key}: {value} -> {resolved_value}",
                            dut_id,
                        )
                    else:
                        resolved_params[key] = value

                return resolved_params

            return hook_params  # No logger available, return as-is

        except Exception as e:
            # Log error but don't fail the hook execution
            await self._service._log_runtime(
                "WARN",
                "BaseService",
                f"Failed to resolve collector directory variables: {e}",
            )
            return hook_params  # Return original parameters on error

    @staticmethod
    def _is_diagnostic_capture_file(file_path: str) -> bool:
        """
        Return True for diagnostic metadata, including legacy flat files.

        Request/response captures, TaskService snapshots, and similar
        request-polling artifacts are diagnostic metadata, not collected data.
        They must not count as "real output" when deciding whether a skipped
        collector should be promoted to success - otherwise a collector that
        only issued a doomed request (e.g. a 404 for an absent resource) would
        be mislabeled "success" instead of "skipped".

        Args:
            file_path: filesystem location used as the file path for this
                operation.

        Returns:
            Whether the true for diagnostic metadata, including legacy flat
            files operation succeeds.
        """
        return classify_artifact_path(file_path) is ArtifactRole.DIAGNOSTIC

    @staticmethod
    def _is_error_artifact_file(file_path: str) -> bool:
        """
        Return True for collector evidence stored under error-logs/.

        The implementation uses ``file_path`` to produce True for collector
        evidence stored under error-logs/. Filesystem effects remain confined to
        the caller-selected paths and the owning resource lifecycle.

        Args:
            file_path: filesystem location used as the file path for this
                operation.

        Returns:
            Whether the true for collector evidence stored under error-logs/
            operation succeeds.
        """
        return classify_artifact_path(file_path) is ArtifactRole.ERROR

    def _artifact_role(self, file_path: Any) -> ArtifactRole:
        """
        Classify an artifact inside the configured run-root namespace.

        Absolute paths are interpreted relative to the logger's bundle root so
        a caller-selected ancestor named ``diagnostic`` or ``error-logs`` does
        not reclassify ordinary collector output.

        Args:
            file_path: Candidate artifact path supplied by a collector or the
                physical inventory scanner.

        Returns:
            The canonical role for the artifact within this run.
        """

        return classify_artifact_path(
            file_path,
            bundle_root=getattr(
                getattr(self._service, "logger", None),
                "base_log_dir",
                None,
            ),
        )

    @staticmethod
    def _group_inventory_files(files: List[str]) -> Dict[str, List[str]]:
        """
        Group a flat inventory by parent directory.

        The implementation uses ``files`` to group a flat inventory by parent
        directory.

        Args:
            files: Filesystem locations processed in caller-provided order.

        Returns:
            The validated ``grouped``.
        """
        grouped: Dict[str, List[str]] = {}
        for file_path in files:
            parent = os.path.dirname(str(file_path)) or "."
            grouped.setdefault(parent, [])
            if file_path not in grouped[parent]:
                grouped[parent].append(file_path)
        return grouped

    @staticmethod
    def _inventory_path_key(path: Any) -> Optional[str]:
        """
        Return one lexical absolute key for an inventory path.

        The comparison deliberately avoids resolving symlinks. A managed
        rollback may be excluding a replaced path, and following that
        replacement would compare the attacker's target rather than the exact
        publication name which must not enter terminal inventory.

        Args:
            path: Candidate filesystem path from an inventory boundary.

        Returns:
            A normalized absolute key, or ``None`` for an invalid path value.
        """

        if not isinstance(path, (str, os.PathLike)):
            return None
        try:
            return os.path.abspath(os.path.normpath(os.fspath(path)))
        except (TypeError, ValueError, OSError):
            return None

    @classmethod
    def _without_excluded_inventory_paths(
        cls,
        paths: Any,
        excluded_keys: set[str],
    ) -> List[str]:
        """
        Remove exact managed-publication names from an inventory sequence.

        Invalid path values are discarded with excluded names so a rollback
        boundary cannot publish an object whose identity was never comparable.
        Retained paths preserve their first-seen order.

        Args:
            paths: Candidate sequence of inventory path values.
            excluded_keys: Lexical absolute path keys forbidden from output.

        Returns:
            Ordered string paths whose normalized keys are not excluded.
        """

        if not isinstance(paths, (list, tuple)):
            return []
        retained: List[str] = []
        for path in paths:
            key = cls._inventory_path_key(path)
            if key is None or key in excluded_keys:
                continue
            retained.append(str(path))
        return list(dict.fromkeys(retained))

    def _reconcile_final_inventory(
        self,
        dut_id: str,
        collector_id: str,
        known_files: Optional[List[str]],
        discovered_files: Optional[Dict[str, List[str]]],
        excluded_keys: set[str],
        *,
        refresh_inventory: bool = True,
    ) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        """
        Reconcile terminal files while enforcing publication exclusions.

        A physical refresh can rediscover a managed publication whose exact
        rollback could not be verified. Filtering only the returned lists is
        insufficient because the logger caches that physical inventory and a
        later ``refresh=False`` reconciliation or status write can resurrect
        the forbidden name. This boundary therefore filters every terminal
        reconciliation and replaces the corresponding cache entry before any
        metadata consumer runs.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration,
                logs, and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            known_files: Previously known terminal inventory candidates.
            discovered_files: Previously grouped inventory candidates.
            excluded_keys: Lexical absolute path keys forbidden from output.
            refresh_inventory: Whether the logger may refresh physical files.

        Returns:
            The filtered inventory and its grouped discovery projection.

        Side Effects:
            Replaces the logger's cached inventory with the filtered projection
            when that cache is available.
        """

        file_inventory, grouped_files = (
            self._service._reconcile_collector_file_inventory(
                dut_id,
                collector_id,
                known_files,
                discovered_files,
                refresh_inventory=refresh_inventory,
            )
        )
        if not excluded_keys:
            return file_inventory, grouped_files

        filtered_inventory = {
            field_name: self._without_excluded_inventory_paths(
                file_inventory.get(field_name, []),
                excluded_keys,
            )
            for field_name in (
                "output_files",
                "diagnostic_files",
                "error_files",
            )
        }
        filtered_inventory["all_files"] = list(
            dict.fromkeys(
                filtered_inventory["output_files"]
                + filtered_inventory["diagnostic_files"]
                + filtered_inventory["error_files"]
            )
        )
        grouped_files = self._group_inventory_files(filtered_inventory["all_files"])

        inventories = getattr(
            getattr(self._service, "logger", None),
            "_collector_file_inventories",
            None,
        )
        if isinstance(inventories, dict):
            inventories[f"{dut_id}:{collector_id}"] = {
                field_name: list(paths)
                for field_name, paths in filtered_inventory.items()
            }
        return filtered_inventory, grouped_files

    def _reconcile_collector_file_inventory(
        self,
        dut_id: str,
        collector_id: str,
        known_files: Optional[List[str]],
        discovered_files: Optional[Dict[str, List[str]]],
        *,
        refresh_inventory: bool = True,
    ) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        """
        Return primary/diagnostic/error inventories and grouped discovery.

        The real logger scans the collector's physical tree, which picks up
        files created indirectly by post-processing and Redfish task polling.
        The fallback keeps lightweight service tests and alternate loggers
        functional using their known file lists.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            known_files: Entries supplied as ``known_files`` without
                transferring container ownership.
            discovered_files: Mapping supplying fields for
                primary/diagnostic/error inventories and grouped discovery.
            refresh_inventory: Whether refresh inventory is enabled or required
                for this operation.

        Returns:
            A tuple containing ``inventory`` and ``group inventory files`` in
            that order.
        """
        inventory_candidates = [path for path in (known_files or []) if path]
        for files in (discovered_files or {}).values():
            inventory_candidates.extend(path for path in (files or []) if path)

        reconcile = getattr(
            self._service.logger, "reconcile_collector_file_inventory", None
        )
        if callable(reconcile):
            if self._service._callable_accepts_keyword(reconcile, "refresh"):
                candidate_inventory = reconcile(
                    dut_id,
                    collector_id,
                    inventory_candidates,
                    refresh=refresh_inventory,
                )
            else:
                candidate_inventory = reconcile(
                    dut_id,
                    collector_id,
                    inventory_candidates,
                )
            required_fields = {
                "output_files",
                "diagnostic_files",
                "error_files",
                "all_files",
            }
            if isinstance(candidate_inventory, dict) and required_fields.issubset(
                candidate_inventory
            ):
                inventory = {
                    field: list(
                        dict.fromkeys(
                            str(path)
                            for path in candidate_inventory.get(field, [])
                            if path
                        )
                    )
                    for field in required_fields
                }
                inventory["all_files"] = list(
                    dict.fromkeys(
                        inventory["output_files"]
                        + inventory["diagnostic_files"]
                        + inventory["error_files"]
                    )
                )
                return inventory, self._service._group_inventory_files(
                    inventory["all_files"]
                )

        primary_files: List[str] = []
        diagnostic_files: List[str] = []
        error_files: List[str] = []
        for file_path in dict.fromkeys(path for path in inventory_candidates if path):
            if self._artifact_role(file_path) is ArtifactRole.ERROR:
                error_files.append(file_path)
            elif self._artifact_role(file_path) is ArtifactRole.DIAGNOSTIC:
                diagnostic_files.append(file_path)
            else:
                primary_files.append(file_path)
        inventory = {
            "output_files": primary_files,
            "diagnostic_files": diagnostic_files,
            "error_files": error_files,
            "all_files": primary_files + diagnostic_files + error_files,
        }
        return inventory, self._service._group_inventory_files(inventory["all_files"])

    async def finalize_collector(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: str,
        execution_time: float = 0.0,
        output_files: Optional[List[str]] = None,
        discovered_files: Optional[Dict[str, List[str]]] = None,
        detailed_context: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Finalize collector execution.

        Log entry point for all finalize_collector calls.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            status: Text supplied as status in the format accepted by this
                function.
            reason: Text supplied as reason in the format accepted by this
                function.
            execution_time: Numeric execution time used while the operation
                performs bounded accounting.
            output_files: Optional output files; ``None`` selects the function's
                default behavior.
            discovered_files: Optional discovered files; ``None`` selects the
                function's default behavior.
            detailed_context: Optional detailed context; ``None`` selects the
                function's default behavior.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing the ``status``, ``reason``, ``output_files``,
            ``discovered_files``, and ``diagnostic_files`` fields.
        """
        # This private handoff is consumed by RedfishService before it reaches
        # here. Other services discard it before logging or interpreting hook
        # parameters so the opaque execution token never becomes metadata.
        kwargs.pop("_request_capture_source_owner", None)
        excluded_path_values = kwargs.pop(
            "_managed_publication_excluded_paths",
            (),
        )
        excluded_path_keys = {
            key
            for key in (
                self._inventory_path_key(path)
                for path in (
                    excluded_path_values
                    if isinstance(excluded_path_values, (list, tuple))
                    else ()
                )
            )
            if key is not None
        }

        if not self._service._collector_budget_run_is_current(dut_id, collector_id):
            return {
                "status": "error",
                "reason": "Collector execution was superseded before final publication",
                "output_files": [],
                "discovered_files": {},
                "diagnostic_files": [],
                "error_files": [],
                "all_files": [],
            }

        # Log entry point for all finalize_collector calls
        await self._service._log_runtime(
            "DEBUG",
            "BaseService",
            f"finalize_collector called for {collector_id}: status={status}, reason='{reason}', output_files_count={len(output_files) if output_files else 0}",
            dut_id,
        )
        await self._service._log_runtime(
            "DEBUG",
            "BaseService",
            f"finalize_collector kwargs for {collector_id}: {list(kwargs.keys())}",
            dut_id,
        )
        try:
            if output_files is None:
                output_files = []
            if discovered_files is None:
                discovered_files = {}

            # Check for output files in execution_result if not provided directly
            actual_output_files = output_files
            if not actual_output_files and "execution_result" in kwargs:
                exec_result = kwargs["execution_result"]
                if isinstance(exec_result, dict) and "output_files" in exec_result:
                    actual_output_files = exec_result.get("output_files", [])
                    if actual_output_files:
                        await self._service._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Found {len(actual_output_files)} output files in execution_result for {collector_id}",
                            dut_id,
                        )

            # From this point onward the resolved execution outputs are the
            # authoritative list.  Keeping the original empty hook argument
            # caused collection_status.json to omit real execution artifacts.
            output_files = self._without_excluded_inventory_paths(
                actual_output_files,
                excluded_path_keys,
            )
            actual_output_files = output_files
            if discovered_files and excluded_path_keys:
                discovered_files = {
                    str(folder): self._without_excluded_inventory_paths(
                        files,
                        excluded_path_keys,
                    )
                    for folder, files in discovered_files.items()
                }
                discovered_files = {
                    folder: files for folder, files in discovered_files.items() if files
                }
            metadata_refresh_required = False

            # Convert output_files to discovered_files format if discovered_files is empty
            # This ensures metadata gets properly populated with file paths
            if not discovered_files and actual_output_files:
                discovered_files = {}
                for file_path in actual_output_files:
                    # Group files by their parent directory
                    folder = os.path.dirname(file_path)
                    if folder not in discovered_files:
                        discovered_files[folder] = []
                    discovered_files[folder].append(file_path)
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Converted {len(actual_output_files)} output files to discovered_files format for {collector_id}: {len(discovered_files)} folders",
                    dut_id,
                )

            # Primary output files determine whether a late "skipped" result
            # actually completed useful collection. Diagnostic and error
            # evidence proves execution was attempted but is not primary data.
            real_output_files = [
                f
                for f in actual_output_files
                if self._artifact_role(f) is ArtifactRole.PRIMARY
            ]
            intentional_evidence_only_skip = kwargs.get(
                "intentional_evidence_only_skip"
            ) is True or (
                isinstance(detailed_context, dict)
                and detailed_context.get("intentional_evidence_only_skip") is True
            )

            # Optional follow-up hooks can legitimately report "skipped" after a primary
            # collection hook already produced data (for example DGX-only sub-collections).
            # Do not let that downgrade the collector when real output files exist.
            if status == "skipped" and intentional_evidence_only_skip:
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Preserving intentional evidence-only skip for {collector_id}",
                    dut_id,
                )
            elif status == "skipped" and real_output_files:
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Preserving successful collector status for {collector_id} because {len(real_output_files)} output file(s) were produced before a later skipped hook",
                    dut_id,
                )
                status = "success"
                if reason.startswith("Not a DGX platform"):
                    reason = "Completed successfully (DGX-specific sub-collection not applicable)"
                elif not reason:
                    reason = "Completed successfully"
            elif status == "skipped" and actual_output_files:
                # A skipped state means execution never began and therefore
                # cannot truthfully own artifacts. Preserve the evidence but
                # project an execution failure instead of an impossible skip.
                status = "error"
                reason = (
                    "Collector produced only diagnostic/error evidence after "
                    f"execution: {reason or 'no primary artifact was produced'}"
                )
                await self._service._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"Collector {collector_id}: {reason}",
                    dut_id,
                )

            # A catalog ``skip_message`` is a fallback for hooks which have no
            # specific execution reason.  Do not replace a precise reason from
            # an earlier hook (for example, a capability or empty-source
            # not-applicable decision) with generic failure wording.
            generic_skip_reasons = {
                "",
                "Completed successfully",
                "success",
                "Collector was skipped",
            }
            is_actually_skipped = (
                "skip_message" in kwargs
                and kwargs["skip_message"]
                and status in {"skipped", "success"}
                and reason in generic_skip_reasons
                and not real_output_files
            )

            if is_actually_skipped:
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Correcting generic reason '{reason}' for collector {collector_id} - found skip_message",
                    dut_id,
                )

                reason = kwargs["skip_message"]
                # Also correct the status if this is actually a skipped collector
                if status == "success":
                    status = "skipped"
                    await self._service._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Corrected status from 'success' to 'skipped' for {collector_id}",
                        dut_id,
                    )
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Using skip_message as reason: {reason}",
                    dut_id,
                )

            # Check for ignore_empty_results case: status is success but no files collected
            # Keep success but surface the expected-empty reason when applicable; allow overrides
            elif status == "success":
                # Check if ignore_empty_results is set (from execution_result or collector definition)
                ignore_empty = False
                if "execution_result" in kwargs:
                    exec_result = kwargs.get("execution_result", {})
                    ignore_empty = exec_result.get("ignore_empty_results", False)

                # If not found in execution_result, check the collector definition
                if (
                    not ignore_empty
                    and hasattr(self._service, "orchestrator")
                    and self._service.orchestrator
                ):
                    collector_info = self._service.orchestrator.get_collector_info(
                        collector_id
                    )
                    if collector_info and "stages" in collector_info:
                        execution_stage = collector_info.get("stages", {}).get(
                            "execution", {}
                        )
                        for hook in execution_stage.get("hooks", []):
                            if (
                                "params" in hook
                                and "ignore_empty_results" in hook["params"]
                            ):
                                ignore_empty = hook["params"]["ignore_empty_results"]
                                break

                # If ignore_empty_results is set, check if we only have summary files
                if ignore_empty:
                    # Filter out summary files - they're metadata, not actual collected data
                    # Summary files typically end with "_summary.txt"
                    real_data_files = (
                        [
                            f
                            for f in actual_output_files
                            if not (
                                f.endswith("_summary.txt")
                                or f.endswith("_summary.json")
                                or "summary" in os.path.basename(f).lower()
                            )
                        ]
                        if actual_output_files
                        else []
                    )

                    # If no real data files collected (only summary files or nothing),
                    # keep the collector marked as success but allow overrides.
                    if not real_data_files or len(real_data_files) == 0:
                        # Look for overrides in kwargs or execution_result
                        status_override = kwargs.get("status_override")
                        reason_override = kwargs.get("reason_override")
                        if not status_override and "execution_result" in kwargs:
                            er = kwargs.get("execution_result", {})
                            status_override = er.get("status_override")
                            reason_override = er.get("reason_override", reason_override)

                        # Also honor overrides defined in post_processing hooks (collector definition)
                        if (
                            (not status_override or not reason_override)
                            and hasattr(self._service, "orchestrator")
                            and self._service.orchestrator
                        ):
                            collector_info = (
                                self._service.orchestrator.get_collector_info(
                                    collector_id
                                )
                            )
                            post_hooks = (
                                collector_info.get("stages", {})
                                .get("post_processing", {})
                                .get("hooks", [])
                                if collector_info
                                else []
                            )
                            for hook in post_hooks:
                                if hook.get("method") == "finalize_collector":
                                    params = hook.get("params", {})
                                    status_override = status_override or params.get(
                                        "status_override"
                                    )
                                    reason_override = reason_override or params.get(
                                        "reason_override"
                                    )
                                    break

                        if status_override:
                            status = status_override
                        if reason_override:
                            reason = reason_override

                        preserve_empty_target_reason = (
                            "No URIs to collect; treating as success" in reason
                        )

                        # Try to get collector_config from multiple sources
                        collector_config = kwargs.get("collector_config", {})

                        # If not in kwargs, try to get from orchestrator's collector definition
                        if (
                            not collector_config
                            and hasattr(self._service, "orchestrator")
                            and self._service.orchestrator
                        ):
                            collector_info = (
                                self._service.orchestrator.get_collector_info(
                                    collector_id
                                )
                            )
                            if collector_info and "stages" in collector_info:
                                execution_stage = collector_info.get("stages", {}).get(
                                    "execution", {}
                                )
                                for hook in execution_stage.get("hooks", []):
                                    if (
                                        "params" in hook
                                        and "collector_config" in hook["params"]
                                    ):
                                        collector_config = hook["params"][
                                            "collector_config"
                                        ]
                                        break

                        empty_note = collector_config.get("empty_expected_note")

                        if empty_note and not preserve_empty_target_reason:
                            reason = empty_note
                        elif not preserve_empty_target_reason:
                            reason = "No data collected (expected behavior)"

                        if reason_override:
                            reason = reason_override
                        if status_override:
                            status = status_override
                        else:
                            # Default behavior: treat as success when empty results are explicitly allowed.
                            # This avoids flagging "healthy system / no dumps" collectors as skipped.
                            status = "success"

                        await self._service._log_runtime(
                            "INFO",
                            "BaseService",
                            f"Collector {collector_id}: No data files collected (only {len(actual_output_files)} summary files) with ignore_empty_results=True; treating as {status}",
                            dut_id,
                        )
                        await self._service._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Using empty_expected_note/override as reason: {reason}",
                            dut_id,
                        )

            # Additional fallback: look for skip reason in detailed_context if not found above
            elif (
                detailed_context
                and status == "skipped"
                and reason in ["Completed successfully", "success"]
            ):
                # Look for skip reason in stage contexts
                for stage_name in [
                    "post_processing",
                    "execution",
                    "validation",
                ]:
                    if stage_name in detailed_context and isinstance(
                        detailed_context[stage_name], dict
                    ):
                        stage_context = detailed_context[stage_name]
                        if stage_context.get("status") == "skipped":
                            # Look for skip_message in finalize_collector params
                            commands = stage_context.get("commands", [])
                            for command in commands:
                                if command.get("method") == "finalize_collector":
                                    skip_message = command.get("params", {}).get(
                                        "skip_message"
                                    )
                                    if skip_message:
                                        reason = skip_message
                                        await self._service._log_runtime(
                                            "DEBUG",
                                            "BaseService",
                                            f"Found skip_message in detailed_context: {reason}",
                                            dut_id,
                                        )
                                        break
                            if (
                                reason != "Completed successfully"
                                and reason != "success"
                            ):
                                break

            # Use detailed_context if provided. Catalog post-processing hooks invoke
            # this method with their execution context expanded into keyword
            # arguments, so recover the bounded accounting fields from that legacy
            # call shape before consulting cached logger state. Without this bridge,
            # partial collectors write a misleading 0/0 error report even though the
            # execution result contains authoritative operation counts.
            context = dict(detailed_context or {})
            forwarded_context_keys = (
                "successful_operations",
                "total_operations",
                "error_messages",
                "collection_level",
                "execution_result",
            )
            nested_context = kwargs.get("context")
            if isinstance(nested_context, dict):
                for key in forwarded_context_keys:
                    if key in nested_context:
                        context.setdefault(key, nested_context[key])
            for key in forwarded_context_keys:
                if key in kwargs:
                    context.setdefault(key, kwargs[key])

            # Check if we have execution_result in kwargs first
            if not context and "execution_result" in kwargs:
                context = kwargs["execution_result"]
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Using execution_result from kwargs for {collector_id}: {len(context)} keys: {list(context.keys())}",
                    dut_id,
                )

            if (
                not context
                and hasattr(self._service, "logger")
                and self._service.logger
            ):
                result_key = f"{dut_id}:{collector_id}"
                collector_result = getattr(
                    self._service.logger, "collector_results", {}
                ).get(result_key, {})
                context = collector_result.get("context", {})
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Extracted context from logger for {collector_id}: {len(context)} keys",
                    dut_id,
                )
            elif context:
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Using provided detailed_context for {collector_id}: {len(context)} keys",
                    dut_id,
                )
            else:
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"No context available for {collector_id}",
                    dut_id,
                )

            # Reconcile against the physical collector tree only after all
            # collection/post-processing hooks have run.  This captures files
            # written as side effects (CSV transforms, TaskService polling
            # evidence, etc.) without adding diagnostics to primary outputs.
            file_inventory, discovered_files = self._reconcile_final_inventory(
                dut_id,
                collector_id,
                actual_output_files,
                discovered_files,
                excluded_path_keys,
            )
            output_files = file_inventory["output_files"]
            actual_output_files = file_inventory["all_files"]

            if kwargs.get("enforce_outcome_policy") is True:
                policy_context = dict(context)
                policy_context["output_files"] = list(output_files)
                classified_outcome = self._service._classify_collector_outcome(
                    {
                        "success": status in _SUCCESS_BEARING_STATUS_NAMES,
                        "status": status,
                        "reason": reason,
                        "context": policy_context,
                        "output_files": output_files,
                    }
                )
                policy_outcome = enforce_empty_success_policy(
                    classified_outcome,
                    kwargs.get("outcome_policy"),
                )
                if policy_outcome.state is not classified_outcome.state:
                    policy_result = policy_outcome.to_legacy_result()
                    status = str(policy_result["status"])
                    reason = str(policy_result["reason"])
                    await self._service._log_runtime(
                        "ERROR",
                        "BaseService",
                        f"Collector {collector_id}: {reason}",
                        dut_id,
                    )

            context = self._service._project_terminal_outcome_context(
                context, status, reason
            )
            reason = str(context.get("reason", ""))
            failure_category = context.get("failure_category")

            # Update status tracker with discovered files if available
            if (
                hasattr(self._service, "orchestrator")
                and self._service.orchestrator
                and hasattr(self._service.orchestrator, "status_tracker")
                and self._service.orchestrator.status_tracker
            ):
                await self._service.orchestrator.status_tracker.complete_collector(
                    dut_id,
                    collector_id,
                    status,
                    reason,
                    execution_time,
                    output_files,
                    discovered_files,
                    context,
                    failure_category=failure_category,
                    diagnostic_files=file_inventory["diagnostic_files"],
                    error_files=file_inventory["error_files"],
                    all_files=file_inventory["all_files"],
                )

            # Create status.json file for this collector
            try:
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"About to create status.json for collector {collector_id} with status {status}",
                    dut_id,
                )
                try:
                    await self._service._write_collector_status_with_cached_inventory(
                        collector_id, dut_id, status, reason, failure_category
                    )
                except Exception as e:
                    await self._service._log_runtime(
                        "ERROR",
                        "BaseService",
                        f"Exception in write_collector_status_file for {collector_id}: {e}",
                        dut_id,
                    )
                    raise
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Successfully created status.json for collector {collector_id}",
                    dut_id,
                )
            except Exception as e:
                await self._service._log_runtime(
                    "WARN",
                    "BaseService",
                    f"Failed to create status.json for collector {collector_id}: {e}",
                    dut_id,
                )

            # Add execution summary entry (but avoid duplicates)
            # Check if this collector already has an execution summary entry to avoid duplicates
            # Allow updates if the status has changed (e.g., from skipped to partial)
            duplicate_check_key = f"execution_summary_added_{dut_id}_{collector_id}"
            previous_status_key = f"execution_summary_status_{dut_id}_{collector_id}"

            should_add_entry = False
            if hasattr(self._service, duplicate_check_key):
                previous_status = getattr(self._service, previous_status_key, None)
                if previous_status == status:
                    # Skip duplicate entry with same status
                    pass
                else:
                    # Status changed, add new entry
                    should_add_entry = True
            else:
                # First time adding entry for this collector
                should_add_entry = True

            if (
                should_add_entry
                and hasattr(self._service, "orchestrator")
                and self._service.orchestrator
            ):
                # A skip is not an error: record it in the execution summary but
                # do NOT write an error-log file for it. Error-logs/ is reserved
                # for genuine failures (partial/error).
                if status == "skipped" and len(output_files) == 0:
                    await self._service._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Adding execution summary entry for SKIPPED collector {collector_id}",
                        dut_id,
                    )
                    try:
                        await self._service._add_execution_summary_entry(
                            dut_id,
                            collector_id,
                            status,
                            actual_output_files,
                            reason,
                            failure_category,
                        )
                        setattr(self._service, duplicate_check_key, True)
                        setattr(self._service, previous_status_key, status)
                    except Exception as summary_ex:
                        await self._service._log_runtime(
                            "ERROR",
                            "BaseService",
                            f"Failed to add execution summary entry for SKIPPED collector {collector_id}: {summary_ex}",
                            dut_id,
                        )
                elif status == "partial":
                    # Preserve either failed-operation evidence or structured
                    # partial-condition evidence in one bounded report.
                    try:
                        result_key = f"{dut_id}:{collector_id}"
                        cached_result = getattr(
                            self._service.logger, "collector_results", {}
                        ).get(result_key, {})
                        cached_context = (
                            cached_result.get("context", {})
                            if isinstance(cached_result, dict)
                            else {}
                        )
                        sanitizer = getattr(
                            getattr(self._service, "logger", None),
                            "sanitizer",
                            None,
                        )
                        sanitize = getattr(sanitizer, "sanitize", None)
                        outcome_details = extract_collector_outcome_details(
                            context,
                            additional_contexts=(cached_context,),
                            sanitizer=sanitize if callable(sanitize) else None,
                        )
                        condition_details = (
                            list(outcome_details.get("messages", []))
                            if outcome_details is not None
                            else []
                        )

                        # Use the same relevance-aware accounting as status.json,
                        # including richer stage evidence already accumulated by
                        # the logger. A finalizer's shallow 1/1 or legacy 0/N tally
                        # must not replace an authoritative partial execution result.
                        accounting_roots = (context, cached_context)

                        def _has_positive_standard_total(candidate: Any) -> bool:
                            """
                            Return whether ``candidate`` has positive standard total.

                            The implementation uses ``candidate`` to determine
                            whether ``candidate`` has positive standard total.

                            Args:
                                candidate: Candidate value or resource evaluated
                                    by this operation.

                            Returns:
                                Whether ``candidate`` has positive standard
                                total.
                            """
                            if not isinstance(candidate, dict):
                                return False
                            value = candidate.get("total_operations")
                            if isinstance(value, bool):
                                return False
                            try:
                                return int(value) > 0
                            except (TypeError, ValueError):
                                return False

                        has_standard_accounting = any(
                            _has_positive_standard_total(candidate)
                            for root in accounting_roots
                            if isinstance(root, dict)
                            for candidate in (
                                root,
                                *(
                                    value
                                    for key, value in root.items()
                                    if isinstance(key, str)
                                    and key.endswith("_result")
                                    and isinstance(value, dict)
                                ),
                            )
                        )
                        execution_result = context.get("execution_result", {})
                        if (
                            not has_standard_accounting
                            and execution_result
                            and "total_commands" in execution_result
                        ):
                            # Preserve the legacy I2C-only command schema when no
                            # standardized operation accounting exists.
                            successful_operations = execution_result.get(
                                "successful_commands", 0
                            )
                            total_operations = execution_result.get("total_commands", 0)
                            # Extract detailed error messages from failed commands
                            detailed_errors = []
                            results = execution_result.get("results", [])
                            for result in results:
                                if not result.get("success", True):
                                    cmd_name = result.get("name", "unknown_command")
                                    cmd_error = result.get(
                                        "error", "No specific error provided"
                                    )
                                    detailed_errors.append(f"{cmd_name}: {cmd_error}")
                            error_messages = detailed_errors
                        elif has_standard_accounting:
                            (
                                successful_operations,
                                total_operations,
                                error_messages,
                            ) = extract_operation_accounting(
                                context,
                                status,
                                reason,
                                additional_contexts=(cached_context,),
                            )
                        else:
                            # Preserve the collector's reason when it did not
                            # report a count; the canonical resolver's synthetic
                            # 0/1 fallback belongs in status.json, not in a
                            # fabricated partial-error-log operation summary.
                            successful_operations = 0
                            total_operations = 0
                            _, _, error_messages = extract_operation_accounting(
                                context,
                                status,
                                reason,
                                additional_contexts=(cached_context,),
                            )

                        collection_level = context.get("collection_level", "L1")

                        # Create detailed partial collection context
                        partial_context = {
                            "operation_name": "partial_collection",
                            "collection_level": collection_level,
                        }
                        if total_operations > 0:
                            partial_context.update(
                                {
                                    "successful_operations": successful_operations,
                                    "total_operations": total_operations,
                                }
                            )

                        # Add detailed error information if available
                        if error_messages:
                            partial_context["detailed_errors"] = error_messages
                        if condition_details:
                            partial_context["condition_details"] = condition_details
                        if outcome_details is not None:
                            partial_context["outcome_details"] = outcome_details

                        # Create a more informative error message for partial collections.
                        # "0 out of 0" is meaningless — if no
                        # operations were counted, retain the collector's
                        # authoritative reason and describe the produced output.
                        if total_operations == 0:
                            partial_message = (
                                f"PARTIAL: {reason}. Produced "
                                f"{len(actual_output_files)} output file(s); "
                                "no operation count was reported"
                            )
                        elif not error_messages and outcome_details is not None:
                            partial_message = (
                                f"PARTIAL: {successful_operations} out of "
                                f"{total_operations} operations succeeded; usable "
                                "output retained with condition "
                                f"{outcome_details['condition']}"
                            )
                        else:
                            partial_message = f"PARTIAL: {successful_operations} out of {total_operations} operations succeeded"
                        if total_operations > 0 and error_messages:
                            failed_count = total_operations - successful_operations
                            # Extract just the command names from error messages for summary
                            failed_commands = []
                            for error_msg in error_messages:
                                if ":" in error_msg:
                                    prefix, detail = error_msg.split(":", 1)
                                    cmd_name = (
                                        detail.strip()
                                        if prefix.strip().lower() == "command failed"
                                        else prefix.strip()
                                    )
                                    failed_commands.append(cmd_name)

                            if failed_commands:
                                # Show first few failed commands in the summary, truncate if too many
                                if len(failed_commands) <= 5:
                                    failed_list = ", ".join(failed_commands)
                                    partial_message += f". Failed: {failed_list}"
                                else:
                                    failed_list = ", ".join(failed_commands[:5])
                                    partial_message += f". Failed: {failed_list} (+{len(failed_commands) - 5} more)"
                            else:
                                partial_message += (
                                    f" ({failed_count} operations failed)"
                                )

                        condition_only_report = bool(
                            outcome_details is not None and not error_messages
                        )
                        if condition_only_report:
                            partial_report_path = await self._service.logger.write_collector_outcome_report(
                                dut_id,
                                collector_id,
                                partial_message,
                                partial_context,
                            )
                        else:
                            partial_report_path = (
                                await self._service.logger.write_error_log(
                                    dut_id,
                                    collector_id,
                                    partial_message,
                                    partial_context,
                                )
                            )
                        # Include the partial report in summary inventory without
                        # duplicating an already-published path.
                        partial_report_str = str(partial_report_path)
                        if partial_report_str not in actual_output_files:
                            actual_output_files.append(partial_report_str)
                            report_folder = os.path.dirname(partial_report_str)
                            discovered_files.setdefault(report_folder, []).append(
                                partial_report_str
                            )
                            metadata_refresh_required = True
                        output_files_with_partial_report = actual_output_files
                        await self._service._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Adding execution summary entry for PARTIAL collector {collector_id}",
                            dut_id,
                        )
                        try:
                            await self._service._add_execution_summary_entry(
                                dut_id,
                                collector_id,
                                status,
                                output_files_with_partial_report,
                                reason,
                                failure_category,
                            )
                            # Mark that we've added an entry for this collector (only after success)
                            setattr(self._service, duplicate_check_key, True)
                            setattr(self._service, previous_status_key, status)
                            metadata_refresh_required = True
                        except Exception as summary_ex:
                            await self._service._log_runtime(
                                "ERROR",
                                "BaseService",
                                f"Failed to add execution summary entry for PARTIAL collector {collector_id}: {summary_ex}",
                                dut_id,
                            )
                    except Exception as e:
                        await self._service._log_runtime(
                            "WARNING",
                            "BaseService",
                            f"Failed to create outcome report for partial collector {collector_id}: {e}",
                            dut_id,
                        )
                        # Fall back to normal execution summary entry
                        await self._service._log_runtime(
                            "DEBUG",
                            "BaseService",
                            f"Adding execution summary entry for PARTIAL collector {collector_id} (fallback)",
                            dut_id,
                        )
                        try:
                            projected_partial_context = (
                                self._service._project_terminal_outcome_context(
                                    context, status, reason
                                )
                            )
                            reason = str(projected_partial_context.get("reason", ""))
                            partial_failure_category = projected_partial_context.get(
                                "failure_category"
                            )
                            await self._service._add_execution_summary_entry(
                                dut_id,
                                collector_id,
                                status,
                                actual_output_files,
                                reason,
                                partial_failure_category,
                            )
                            # Mark that we've added an entry for this collector (only after success)
                            setattr(self._service, duplicate_check_key, True)
                            setattr(self._service, previous_status_key, status)
                            context = projected_partial_context
                            failure_category = partial_failure_category
                            metadata_refresh_required = True
                        except Exception as summary_ex:
                            await self._service._log_runtime(
                                "ERROR",
                                "BaseService",
                                f"Failed to add execution summary entry for PARTIAL collector {collector_id} (fallback): {summary_ex}",
                                dut_id,
                            )
                else:
                    try:
                        await self._service._add_execution_summary_entry(
                            dut_id,
                            collector_id,
                            status,
                            actual_output_files,
                            reason,
                            failure_category,
                        )
                        # Mark that we've added an entry for this collector (only after success)
                        setattr(self._service, duplicate_check_key, True)
                        setattr(self._service, previous_status_key, status)
                    except Exception as summary_ex:
                        await self._service._log_runtime(
                            "ERROR",
                            "BaseService",
                            f"Failed to add execution summary entry for collector {collector_id} with status {status}: {summary_ex}",
                            dut_id,
                        )
            else:
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Cannot add execution summary entry for collector {collector_id}: orchestrator not available",
                    dut_id,
                )

            # Partial error evidence is created while adding the execution
            # summary, after the first inventory pass.  Reconcile once more so
            # logger/tracker/status metadata all receive the same final lists.
            file_inventory, discovered_files = self._reconcile_final_inventory(
                dut_id,
                collector_id,
                actual_output_files,
                discovered_files,
                excluded_path_keys,
                refresh_inventory=False,
            )
            output_files = file_inventory["output_files"]
            actual_output_files = file_inventory["all_files"]

            # Log collector result using helper method (after all corrections)
            context = self._service._project_terminal_outcome_context(
                context, status, reason
            )
            reason = str(context.get("reason", ""))
            failure_category = context.get("failure_category")
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Logging final collector result for {collector_id}: status={status}, reason='{reason}', discovered_files_keys={list(discovered_files.keys()) if discovered_files else []}",
                dut_id,
            )
            await self._service._log_collector_result(
                dut_id,
                collector_id,
                status,
                reason,
                execution_time,
                output_files,
                context,
                discovered_files,
                failure_category,
            )

            # Partial-collector error evidence is created after the initial
            # tracker/status write above. Reconcile those two stores once so
            # every metadata surface links the same physical error artifact.
            if metadata_refresh_required:
                if (
                    hasattr(self._service, "orchestrator")
                    and self._service.orchestrator
                    and getattr(self._service.orchestrator, "status_tracker", None)
                ):
                    await self._service.orchestrator.status_tracker.complete_collector(
                        dut_id,
                        collector_id,
                        status,
                        reason,
                        execution_time,
                        output_files,
                        discovered_files,
                        context,
                        failure_category=failure_category,
                        diagnostic_files=file_inventory["diagnostic_files"],
                        error_files=file_inventory["error_files"],
                        all_files=file_inventory["all_files"],
                    )
                await self._service._write_collector_status_with_cached_inventory(
                    collector_id, dut_id, status, reason, failure_category
                )

            # Final summary debug log
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"finalize_collector COMPLETED for {collector_id}: final_status={status}, final_reason='{reason}', execution_summary_added={hasattr(self._service, f'execution_summary_added_{dut_id}_{collector_id}')}",
                dut_id,
            )

            return {
                "success": status in ["success", "degraded", "partial", "skipped"],
                "status": status,
                "reason": reason,
                "execution_time": execution_time,
                "output_files": output_files,
                "diagnostic_files": file_inventory["diagnostic_files"],
                "error_files": file_inventory["error_files"],
                "all_files": file_inventory["all_files"],
                "discovered_files": discovered_files,
                **(
                    {"failure_category": failure_category}
                    if failure_category is not None
                    else {}
                ),
            }

        except Exception as e:
            await self._service._log_error(
                "FINALIZE_ERROR",
                f"Error finalizing collector {collector_id}: {e}",
                dut_id,
                collector_id,
            )
            fallback_files = list(dict.fromkeys(output_files or []))
            fallback_diagnostics = [
                path
                for path in fallback_files
                if self._artifact_role(path) is ArtifactRole.DIAGNOSTIC
            ]
            fallback_errors = [
                path
                for path in fallback_files
                if self._artifact_role(path) is ArtifactRole.ERROR
            ]
            fallback_primary = [
                path
                for path in fallback_files
                if path not in fallback_diagnostics and path not in fallback_errors
            ]
            fallback_context = self._service._project_terminal_outcome_context(
                {}, "error", f"Finalization error: {e}", exception=e
            )
            fallback_reason = str(fallback_context["reason"])
            fallback_category = fallback_context.get("failure_category")
            return {
                "success": False,
                "status": "error",
                "reason": fallback_reason,
                "execution_time": execution_time,
                "output_files": fallback_primary,
                "diagnostic_files": fallback_diagnostics,
                "error_files": fallback_errors,
                "all_files": (
                    fallback_primary + fallback_diagnostics + fallback_errors
                ),
                "discovered_files": discovered_files or {},
                **(
                    {"failure_category": fallback_category}
                    if fallback_category is not None
                    else {}
                ),
            }

    def _get_collector_group(self, collector_id: str) -> str:
        """
        Get collector group from ID.

        After applying local validation, the function forwards ``collector_id``
        to ``CollectorServiceMapping.get_service_from_collector_id`` and
        preserves its return and exception contract.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The canonical collector group text.
        """
        return CollectorServiceMapping.get_service_from_collector_id(collector_id)

    async def _write_collector_output(
        self,
        dut_id: str,
        collector_id: str,
        content: str,
        filename: str = "output.txt",
    ) -> Optional[str]:
        """
        Write collector output to file.

        The implementation uses ``dut_id``, ``collector_id``, ``content``, and
        ``filename`` to write collector output to file. Success is reported only
        after the owning output boundary has completed its required write or
        publication step. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            content: Text supplied as content in the format accepted by this
                function.
            filename: Text supplied as filename in the format accepted by this
                function.

        Returns:
            The canonical write collector output text.
        """
        try:
            group = self._service._get_collector_group(collector_id)
            if self._service.logger:
                file_path = await self._service.logger.write_collector_output(
                    dut_id, group, collector_id, filename, content
                )
                if file_path:
                    return str(file_path)
                await self._service._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"Logger did not publish collector output {filename}",
                    dut_id,
                )
                await self._service._log_collector_error(
                    dut_id,
                    collector_id,
                    f"Collector output write failed for {filename}",
                    {"filename": filename, "failure": "empty_logger_result"},
                )
                return None
            else:
                # Fallback if logger not available
                return None
        except Exception as e:
            await self._service._log_error(
                "OUTPUT_ERROR",
                f"Error writing collector output: {e}",
                dut_id,
                collector_id,
            )
            await self._service._log_collector_error(
                dut_id,
                collector_id,
                f"Collector output write failed for {filename}: {e}",
                {"filename": filename, "exception_type": type(e).__name__},
            )
            return None

    async def _log_collector_error(
        self,
        dut_id: str,
        collector_id: str,
        error_message: str,
        context: dict = None,
    ) -> str:
        """
        Log collector error and return the error log path.

        The implementation uses ``dut_id``, ``collector_id``, ``error_message``,
        and ``context`` to log collector error and return the error log path.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            error_message: Text supplied as error message in the format accepted
                by this function.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            The canonical log collector error text.
        """
        try:
            # Write error to error-logs directory
            if self._service.logger:
                error_log_path = await self._service.logger.write_error_log(
                    dut_id, collector_id, error_message, context
                )
                return str(error_log_path) if error_log_path else ""
            else:
                # Fallback if logger not available
                return ""
        except Exception as e:
            await self._service._log_error(
                "ERROR_LOG_ERROR",
                f"Error logging collector error: {e}",
                dut_id,
                collector_id,
            )
            return ""

    async def _create_error_log_file(
        self,
        dut_id: str,
        collector_id: str,
        error_message: str,
        context: dict = None,
    ) -> str:
        """
        Create error log file.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``error_message``, and ``context`` to
        ``self._service._log_collector_error`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            error_message: Text supplied as error message in the format accepted
                by this function.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            The canonical error log file text.
        """
        return await self._service._log_collector_error(
            dut_id, collector_id, error_message, context
        )

    async def write_output_file(
        self,
        dut_id: str,
        collector_id: str,
        filename: str,
        content: Union[str, bytes],
    ) -> Optional[str]:
        """
        Write output content to a file.

        The implementation uses ``dut_id``, ``collector_id``, ``filename``, and
        ``content`` to write output content to a file. Success is reported only
        after the owning output boundary has completed its required write or
        publication step. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            filename: Text supplied as filename in the format accepted by this
                function.
            content: Text supplied as content in the format accepted by this
                function.

        Returns:
            The canonical write output file text.

        Raises:
            OSError: Raised internally when the logger returns no published
                path; the surrounding failure boundary records it and returns
                ``None`` to the collector.
        """
        timing_operation_id = None
        try:
            # Debug logging
            await self._service.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "BaseService",
                f"write_output_file: collector_id='{collector_id}', filename='{filename}', content_length={len(content) if content else 0}",
            )
            # print(f"DEBUG: write_output_file called with collector_id='{collector_id}', filename='{filename}'")

            # Ensure collector_id is not empty
            if not collector_id:
                await self._service._log_runtime(
                    "WARN",
                    "BaseService",
                    f"Empty collector_id for {filename}, using service name",
                    dut_id,
                )
                collector_id = self._service.service_name

            group = self._service._get_collector_group(collector_id)
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"write_output_file: group='{group}', collector_id='{collector_id}'",
                dut_id,
            )

            if self._service.logger:
                if hasattr(self._service.logger, "_apply_stream_window_to_filename"):
                    filename = self._service.logger._apply_stream_window_to_filename(
                        collector_id, filename
                    )
                if self._service.timing_manager:
                    timing_operation_id = self._service.timing_manager.start_operation(
                        "artifact_persistence",
                        filename,
                        metadata={"content_length": len(content) if content else 0},
                        compact_artifact_on_limit=True,
                    )
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"About to call logger.write_collector_output with dut_id='{dut_id}', group='{group}', collector_id='{collector_id}', filename='{filename}'",
                    dut_id,
                )

                file_path = await self._service.logger.write_collector_output(
                    dut_id, group, collector_id, filename, content
                )
                if not file_path:
                    raise OSError(f"Logger did not publish collector output {filename}")
                if self._service.timing_manager:
                    self._service.timing_manager.end_operation(
                        timing_operation_id,
                        artifact_path=str(file_path),
                    )

                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"logger.write_collector_output returned: {file_path} (type: {type(file_path)})",
                    dut_id,
                )

                result = str(file_path)
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"write_output_file returning: '{result}'",
                    dut_id,
                )
                return result
            else:
                # Fallback if logger not available
                await self._service._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"Logger is None - cannot write output file {filename}",
                    dut_id,
                )
                return None
        except Exception as e:
            if self._service.timing_manager:
                self._service.timing_manager.end_operation(
                    timing_operation_id,
                    status="error",
                    error=str(e),
                )
            await self._service._log_runtime(
                "ERROR",
                "BaseService",
                f"Exception in write_output_file for {filename}: {str(e)}",
                dut_id,
            )
            # Also log the full exception details
            import traceback

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Full traceback: {traceback.format_exc()}",
                dut_id,
            )
            await self._service._log_collector_error(
                dut_id,
                collector_id or self._service.service_name,
                f"Collector output write failed for {filename}: {e}",
                {"filename": filename, "exception_type": type(e).__name__},
            )
            return None

    def get_output_filename(
        self,
        output_pattern: str = None,
        function_tag: str = None,
        default_extension: str = ".txt",
        substitutions: Dict[str, str] = None,
    ) -> str:
        """
        Return output filename.

        Use provided substitutions or default to command_name.

        Args:
            output_pattern: Optional output pattern; ``None`` selects the
                function's default behavior.
            function_tag: Optional function tag; ``None`` selects the function's
                default behavior.
            default_extension: Text supplied as default extension in the format
                accepted by this function.
            substitutions: Optional substitutions; ``None`` selects the
                function's default behavior.

        Returns:
            The canonical output filename.
        """
        if output_pattern:
            # Use provided substitutions or default to command_name
            if substitutions is None and function_tag:
                substitutions = {"command_name": function_tag}

            # The method now handles both static patterns and variable substitution automatically
            return self._service.substitute_output_pattern_variables(
                output_pattern, substitutions
            )
        elif function_tag:
            # Fallback to function_tag with default extension
            return f"{function_tag}{default_extension}"
        else:
            # Ultimate fallback
            return f"output{default_extension}"

    async def write_output_with_generalization(
        self,
        dut_id: str,
        collector_id: str,
        content: Any,
        output_pattern: str = None,
        function_tag: str = None,
        default_extension: str = ".txt",
        substitutions: Dict[str, str] = None,
        **kwargs,
    ) -> Optional[str]:
        """
        Single function to handle all output file writing with generalization.

        This replaces the repetitive pattern of getting filename and writing
        file.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            content: Content consumed while the function attempts to single
                function to handle all output file writing with generalization.
            output_pattern: Optional output pattern; ``None`` selects the
                function's default behavior.
            function_tag: Optional function tag; ``None`` selects the function's
                default behavior.
            default_extension: Text supplied as default extension in the format
                accepted by this function.
            substitutions: Optional substitutions; ``None`` selects the
                function's default behavior.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The canonical write output with generalization text.
        """
        try:
            # Convert content to string based on type
            if isinstance(content, bytes):
                # Keep bytes as-is for binary data
                content_str = content
                await self._service.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "BaseService",
                    f"Content is bytes, keeping as binary data, length: {len(content_str)}",
                )
            elif isinstance(content, dict):
                import json

                content_str = json.dumps(content, indent=2)
                await self._service.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "BaseService",
                    f"Converted dict content to JSON string, length: {len(content_str)}",
                )
            elif isinstance(content, (list, tuple)):
                content_str = json.dumps(content, indent=2)
                await self._service.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "BaseService",
                    f"Converted {type(content).__name__} content to JSON string, length: {len(content_str)}",
                )
            elif isinstance(content, (int, float, bool)):
                content_str = str(content)
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Converted {type(content).__name__} content to string: {content_str}",
                    dut_id,
                )
            elif isinstance(content, str):
                content_str = content
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Content is already string, length: {len(content_str)}",
                    dut_id,
                )
            elif content is None:
                content_str = ""
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    "Content is None, using empty string",
                    dut_id,
                )
            else:
                # For any other type, try to convert to string
                content_str = str(content)
                await self._service._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Converted unknown type {type(content).__name__} to string, length: {len(content_str)}",
                    dut_id,
                )

            # Debug logging
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"write_output_with_generalization: collector_id='{collector_id}', function_tag='{function_tag}', output_pattern='{output_pattern}', content_type={type(content)}, content_length={len(content_str)}",
                dut_id,
            )

            # Get the final filename using generalization
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"About to call get_output_filename with output_pattern='{output_pattern}', function_tag='{function_tag}', substitutions={substitutions}",
                dut_id,
            )

            final_filename = self._service.get_output_filename(
                output_pattern, function_tag, default_extension, substitutions
            )

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"get_output_filename returned: '{final_filename}'",
                dut_id,
            )

            # Write the file
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"About to call write_output_file with final_filename='{final_filename}'",
                dut_id,
            )

            result = await self._service.write_output_file(
                dut_id, collector_id, final_filename, content_str
            )

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"write_output_with_generalization returning: '{result}'",
                dut_id,
            )

            return result
        except Exception as e:
            await self._service._log_runtime(
                "ERROR",
                "BaseService",
                f"Exception in write_output_with_generalization: {str(e)}",
                dut_id,
            )
            # Also log the full exception details
            import traceback

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Full traceback: {traceback.format_exc()}",
                dut_id,
            )
            await self._service._log_collector_error(
                dut_id,
                collector_id or self._service.service_name,
                "Collector output preparation failed: " f"{type(e).__name__}: {e}",
                {
                    "function_tag": function_tag,
                    "exception_type": type(e).__name__,
                },
            )
            return None

    async def _save_data_with_common_pattern(
        self,
        dut_id: str,
        data: Any,
        function_tag: str,
        output_pattern: str = None,
        substitutions: Dict[str, Any] = None,
        default_extension: str = ".txt",
        **kwargs,
    ) -> Optional[str]:
        """
        Common data saving function with pattern handling.

        The implementation uses ``dut_id``, ``data``, ``function_tag``,
        ``output_pattern``, and ``substitutions`` to common data saving function
        with pattern handling. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            data: Data consumed while the function attempts to common data
                saving function with pattern handling.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            output_pattern: Optional output pattern; ``None`` selects the
                function's default behavior.
            substitutions: Optional substitutions; ``None`` selects the
                function's default behavior.
            default_extension: Text supplied as default extension in the format
                accepted by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The validated ``file_path``, or ``None`` when no value qualifies.
        """
        try:
            # Log input parameters for debugging
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"_save_data_with_common_pattern called with function_tag='{function_tag}', output_pattern='{output_pattern}', data_type={type(data)}, data_length={len(str(data)) if data else 0}",
                dut_id,
            )

            # Extract collector_id from kwargs to avoid duplicate argument
            collector_id = kwargs.get("collector_id", "")
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Extracted collector_id: '{collector_id}'",
                dut_id,
            )

            # Remove collector_id and list parameters from kwargs to avoid conflicts
            if isinstance(kwargs, dict):
                filtered_kwargs = {
                    k: v
                    for k, v in kwargs.items()
                    if k != "collector_id" and not isinstance(v, list)
                }
            else:
                filtered_kwargs = {}

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"About to call write_output_with_generalization with collector_id='{collector_id}', function_tag='{function_tag}'",
                dut_id,
            )

            # Check if logger is available
            if not self._service.logger:
                await self._service._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"Logger is None - cannot save data for {function_tag}",
                    dut_id,
                )
                return None

            file_path = await self._service.write_output_with_generalization(
                dut_id,
                collector_id,
                data,
                output_pattern=output_pattern,
                function_tag=function_tag,
                default_extension=default_extension,
                substitutions=substitutions or {},
                **filtered_kwargs,
            )

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"write_output_with_generalization returned: '{file_path}' (type: {type(file_path)})",
                dut_id,
            )

            if not file_path:
                await self._service._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"write_output_with_generalization returned empty/None for {function_tag}",
                    dut_id,
                )
                return None

            # Log the final file path to track folder naming
            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Generated file path: '{file_path}' for function_tag='{function_tag}', collector_id='{collector_id}'",
                dut_id,
            )

            return file_path
        except Exception as e:
            await self._service._log_runtime(
                "ERROR",
                "BaseService",
                f"Exception in _save_data_with_common_pattern for {function_tag}: {str(e)}",
                dut_id,
            )
            # Also log the full exception details

            await self._service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Full traceback: {traceback.format_exc()}",
                dut_id,
            )
            return None
