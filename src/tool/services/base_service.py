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
Base Service for all collector services.

This module provides the foundation for all collector services with standardized
error handling, logging, and result formatting.

STANDARDIZED COLLECTOR RESULT APPROACH: =======================================

All collectors should use the standardized result approach to ensure consistent
status reporting and partial success handling:

1. Use _create_standardized_collector_result() for one-call result creation.
2. Always save what you capture, even if there are errors.
3. Never fail silently - log all errors and exceptions.

Standard Result Format: { "success": bool, # True if ANY data was collected
successfully "status": str, # "success", "degraded", "partial", or "error"
"reason": str, # Human-readable reason for status "context": { "total_files":
int, # Number of files generated "output_files": List[str], # List of file paths
"successful_operations": int, # Number of successful operations
"total_operations": int, # Total operations attempted "error_messages":
List[str], # List of error messages ...additional_context... #
Collector-specific context } }

Status Logic:

- success=True, status="success": All operations succeeded.
- success=True, status="degraded": Primary data is usable with a bounded issue.
- success=True, status="partial": Some operations succeeded, some failed.
- success=False, status="error": No operations succeeded.

Example:
    ```python
    # Create standardized result in one call
    result = self._create_standardized_collector_result(
        successful_operations=3,
        total_operations=5,
        output_files=["file1.json", "file2.json"],
        error_messages=["Failed to collect from system X"],
        operation_name="collections",
        additional_context={"systems_processed": 3}
    )
    ```
"""

import asyncio
import hashlib
import inspect
import itertools
import json
import logging
import os
import re
import secrets
import textwrap
import traceback
from contextvars import ContextVar
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union

import aiohttp

from ..core.async_logger import _collector_context, _dut_context
from ..core.collector_outcome import (
    CollectorOutcome,
    CollectorOutcomeState,
    classify_collector_outcome,
    enforce_empty_success_policy,
    project_collector_outcome_details,
    sanitize_terminal_collector_reason,
)
from ..core.finalization_receipt import select_authoritative_exception
from ..utils.artifact_paths import ArtifactRole, classify_artifact_path
from ..utils.collector_budget import (
    COLLECTOR_CANCELLATION_GRACE_SECONDS,
    CollectorBudgetError,
    ResolvedCollectorBudget,
    resolve_collector_budget,
    resolve_effective_runtime_config,
    runtime_budget_requires_runtime_config,
)
from ..utils.collector_command_profiles import (
    iter_command_profile_hooks,
    resolve_collector_command_profiles,
)
from ..utils.dependency_checker import DependencyChecker
from ..utils.enums import CollectorServiceMapping
from ..utils.redfish_tls import RedfishTLSPolicy
from ..utils.redfish_topology_profile import rebase_redfish_uri
from ..utils.redfish_transport import (
    build_redfish_request_headers,
    encode_basic_auth_header,
    format_redfish_url_host,
)
from ..utils.request_response_capture import (
    RunOwnedRequestCaptureRuntime,
)
from ..utils.result_log_summary import summarize_result_for_log
from ..utils.trusted_extensions import (
    TRUSTED_EXTENSION_PACKAGE,
    import_trusted_extension_module,
)
from ..utils.variable_substitution import (
    EnvironmentVariablePolicyError,
    VariableSubstitutionService,
)
from .collector_capture_recorder import CollectorCaptureRecorder
from .collector_lifecycle_runner import CollectorLifecycleRunner
from .collector_output_store import CollectorOutputStore
from .collector_result_builder import (
    CollectorResultBuilder,
    collector_result_to_legacy_dict,
    collector_status_to_legacy_dict,
    extract_http_error_message,
    format_collector_error_messages,
)

logger = logging.getLogger(__name__)

_CATALOG_EXTENSION_IDENTIFIER = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$")
_collector_budget_context: ContextVar[Optional[ResolvedCollectorBudget]] = ContextVar(
    "collector_budget",
    default=None,
)
_collector_budget_run_context: ContextVar[Optional[object]] = ContextVar(
    "collector_budget_run",
    default=None,
)
_CURRENT_REQUEST_CAPTURE_OWNER = object()
COLLECTOR_TIMEOUT_SUPPORT_SECONDS = 5.0


class _DuplicateCollectorBudgetRunError(RuntimeError):
    """
    Raised before a second explicit-budget run can mutate shared state.

    Callers receive this exception when the duplicate collector budget run error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


class _CollectorStatusTransactionState:
    """
    Shared lock plus pre-acquisition users for race-free pruning.

    The type gives the collector status transaction state responsibility a
    stable runtime boundary. Callers use the declared Python protocol instead of
    depending on its representation.
    """

    __slots__ = ("lock", "users")

    def __init__(self) -> None:
        """
        Initialize a ``_CollectorStatusTransactionState`` instance.

        The initializer records ``lock`` and ``users`` for later operations and
        establishes the instance invariants before any public method runs.
        """
        self.lock = asyncio.Lock()
        self.users = 0


_SENSITIVE_PARAMETER_FRAGMENTS = (
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
)
_MAX_LOGGED_PARAMETER_KEYS = 32
_MAX_HASHED_PARAMETER_KEYS = 4_096
_MAX_LOGGED_IDENTIFIER_CHARS = 128
_MAX_HASHED_TEXT_CHARS = 4_096
_HOOK_LOG_DIGEST_KEY = secrets.token_bytes(32)


def _bounded_identifier(value: Any, default: str = "unknown") -> str:
    """
    Return a bounded identifier without rendering arbitrary objects.

    The implementation uses ``value`` and ``default`` to produce a bounded
    identifier without rendering arbitrary objects.

    Args:
        value: Value evaluated while performing bounded identifier without
            rendering arbitrary objects.
        default: Fallback used when the requested value is absent or invalid.

    Returns:
        The canonical bounded identifier text.
    """
    if not isinstance(value, (str, int, float, bool)):
        return default
    rendered = str(value)
    if len(rendered) <= _MAX_LOGGED_IDENTIFIER_CHARS:
        return rendered
    omitted = len(rendered) - _MAX_LOGGED_IDENTIFIER_CHARS
    return f"{rendered[:_MAX_LOGGED_IDENTIFIER_CHARS]}...(+{omitted} chars)"


def _bounded_text_summary(value: Any) -> Dict[str, Any]:
    """
    Return a value-free, keyed correlation summary of bounded input.

    The implementation uses ``value`` to produce a value-free, keyed correlation
    summary of bounded input.

    Args:
        value: Value evaluated while performing value-free, keyed correlation
            summary of bounded input.

    Returns:
        A mapping containing the ``type``, ``characters``,
        ``hashed_characters``, ``omitted_characters``, and
        ``correlation_blake2b`` fields.
    """
    if not isinstance(value, (str, int, float, bool)):
        digest = hashlib.blake2b(
            type(value).__name__.encode("utf-8"),
            key=_HOOK_LOG_DIGEST_KEY,
            digest_size=32,
        ).hexdigest()
        return {
            "type": type(value).__name__,
            "characters": 0,
            "hashed_characters": 0,
            "omitted_characters": 0,
            "correlation_blake2b": digest,
        }
    text = str(value)
    bounded = text[:_MAX_HASHED_TEXT_CHARS]
    digest = hashlib.blake2b(key=_HOOK_LOG_DIGEST_KEY, digest_size=32)
    digest.update(type(value).__name__.encode("ascii"))
    digest.update(b"\0")
    digest.update(bounded.encode("utf-8", errors="replace"))
    return {
        "type": type(value).__name__,
        "characters": len(text),
        "hashed_characters": len(bounded),
        "omitted_characters": max(0, len(text) - len(bounded)),
        "correlation_blake2b": digest.hexdigest(),
    }


def _parameter_value_shape(value: Any) -> Tuple[str, str, int]:
    """
    Describe a parameter's shape without reading or rendering its value.

    The implementation uses ``value`` to describe a parameter's shape without
    reading or rendering its value.

    Args:
        value: Value evaluated while performing describe a parameter's shape
            without reading or rendering its value.

    Returns:
        A tuple containing ``value type``, ``status text``, and ``integer
        count`` in that order.
    """
    value_type = type(value).__name__
    if isinstance(value, str):
        return value_type, "characters", len(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return value_type, "bytes", len(value)
    if isinstance(value, (dict, list, tuple, set, frozenset)):
        return value_type, "items", len(value)
    return value_type, "scalar", 1


def _bounded_parameter_summary(parameters: Dict[Any, Any]) -> Dict[str, Any]:
    """
    Summarize parameter shape with keyed, value-free descriptors.

    Values are never stringified or hashed. Dynamic keys are never rendered;
    their per-process keyed tokens support local correlation without creating a
    stable cross-run oracle for catalog names, credentials, or runtime payloads.

    Args:
        parameters: Mapping supplying fields for summarize parameter shape with
            keyed, value-free descriptors.

    Returns:
        A mapping containing the ``total_keys``, ``retained_keys``,
        ``omitted_keys``, ``sensitive_keys``, and ``unscanned_keys`` fields.
    """
    if not isinstance(parameters, dict):
        shape_digest = hashlib.blake2b(
            b"malformed-mapping",
            key=_HOOK_LOG_DIGEST_KEY,
            digest_size=32,
        ).hexdigest()
        return {
            "total_keys": 0,
            "retained_keys": 0,
            "omitted_keys": 0,
            "sensitive_keys": 0,
            "unscanned_keys": 0,
            "omitted_bytes": 0,
            "omitted_characters": 0,
            "omitted_items": 0,
            "keys": [],
            "shape_blake2b": shape_digest,
        }

    total_keys = len(parameters)
    sampled_items = list(
        itertools.islice(parameters.items(), _MAX_HASHED_PARAMETER_KEYS)
    )
    descriptors: List[Tuple[str, str, int, str, str, int, bool]] = []
    for raw_key, value in sampled_items:
        if isinstance(raw_key, str):
            key_text = raw_key
        else:
            key_text = ""
        key_type = type(raw_key).__name__
        bounded_key = key_text[:_MAX_LOGGED_IDENTIFIER_CHARS]
        key_digest = hashlib.blake2b(key=_HOOK_LOG_DIGEST_KEY, digest_size=16)
        key_digest.update(key_type.encode("utf-8", errors="replace"))
        key_digest.update(b"\0")
        key_digest.update(bounded_key.encode("utf-8", errors="replace"))
        key_token = key_digest.hexdigest()
        sensitive = any(
            fragment in bounded_key.lower()
            for fragment in _SENSITIVE_PARAMETER_FRAGMENTS
        )
        value_type, unit, amount = _parameter_value_shape(value)
        descriptors.append(
            (
                key_token,
                key_type,
                len(key_text),
                value_type,
                unit,
                amount,
                sensitive,
            )
        )

    # Dict insertion order is not part of the semantic parameter shape.
    descriptors.sort(key=lambda descriptor: descriptor[:6])
    shape_hash = hashlib.blake2b(key=_HOOK_LOG_DIGEST_KEY, digest_size=32)
    shape_hash.update(f"total={total_keys}\n".encode("ascii"))

    preview: List[Dict[str, Any]] = []
    sensitive_keys = 0
    omitted_units = {"bytes": 0, "characters": 0, "items": 0}
    for (
        key_token,
        key_type,
        key_characters,
        value_type,
        unit,
        amount,
        sensitive,
    ) in descriptors:
        shape_hash.update(
            (
                f"{key_token}\0{key_type}\0{key_characters}\0{value_type}\0"
                f"{unit}\0{amount}\0{int(sensitive)}\n"
            ).encode("utf-8", errors="replace")
        )
        # Parameter values are never rendered, even when their key/type shape
        # is retained in the preview. Account for every omitted value unit.
        if unit in omitted_units:
            omitted_units[unit] += amount
        if sensitive:
            sensitive_keys += 1
        if not sensitive and len(preview) < _MAX_LOGGED_PARAMETER_KEYS:
            preview.append(
                {
                    "key_token": key_token,
                    "key_type": key_type,
                    "key_characters": key_characters,
                    "type": value_type,
                    unit: amount,
                }
            )

    retained_keys = len(preview)
    unscanned_keys = max(0, total_keys - len(sampled_items))
    return {
        "total_keys": total_keys,
        "retained_keys": retained_keys,
        "omitted_keys": max(0, total_keys - retained_keys),
        "sensitive_keys": sensitive_keys,
        "unscanned_keys": unscanned_keys,
        "omitted_bytes": omitted_units["bytes"],
        "omitted_characters": omitted_units["characters"],
        "omitted_items": omitted_units["items"],
        "keys": preview,
        "shape_blake2b": shape_hash.hexdigest(),
    }


class BaseService:
    """
    Base class for all collector services.

    The type coordinates ``_output_store``, ``_get_request_capture_runtime``,
    ``_capture_external_text_sanitizer``, ``_drain_capture_resource_discard``,
    and ``close_request_capture_state`` and retains the state those operations
    share between calls. Resource ownership remains inside the instance until
    the matching close, exit, or cleanup operation completes.
    """

    def __init__(self, service_name: str, orchestrator: Any) -> None:
        """
        Initialize the BaseService.

        Tolerate None orchestrator for lightweight operations (e.g., listing
        collectors).

        Args:
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.
            orchestrator: Orchestrator object whose ``dependency_checker``,
                ``dut_manager``, ``logger``, and ``timing_manager`` state is
                read while performing initialize the BaseService.
        """
        self.service_name = service_name
        self.orchestrator = orchestrator
        # Tolerate None orchestrator for lightweight operations (e.g., listing collectors)
        self.dut_manager = None
        self.logger = None
        self.dependency_checker = None
        self.timing_manager = None
        self.variable_engine = None  # Will be created asynchronously
        self._collector_result_builder = CollectorResultBuilder()
        self._collector_lifecycle_runner = CollectorLifecycleRunner(
            self,
            bounded_identifier=_bounded_identifier,
            bounded_parameter_summary=_bounded_parameter_summary,
            bounded_text_summary=_bounded_text_summary,
        )
        self._collector_capture_recorder = CollectorCaptureRecorder(
            self,
            current_publication_owner=_collector_budget_run_context.get,
            bounded_identifier=_bounded_identifier,
        )
        self._collector_output_store = CollectorOutputStore(self)
        # Capture state is strongly owned until explicit finalization or service
        # teardown. A caller task dying before token handoff must not let a weak
        # key silently orphan its live-spool token.
        self._request_response_capture_states: Dict[
            asyncio.Task[Any], List[Dict[str, Any]]
        ] = {}
        self._pending_request_capture_publications: Dict[Tuple[Any, ...], List[Any]] = (
            {}
        )
        self._active_collector_budget_runs: Dict[Tuple[str, str], set[object]] = {}
        self._logged_timeout_policies: set[Tuple[str, str, int, str]] = set()
        self._collector_status_transaction_locks: Dict[
            Tuple[str, str], _CollectorStatusTransactionState
        ] = {}
        self._local_request_capture_runtime = None
        if orchestrator is not None:
            shared_budget_runs = getattr(
                orchestrator, "_active_collector_budget_runs", None
            )
            if not isinstance(shared_budget_runs, dict):
                shared_budget_runs = {}
                setattr(
                    orchestrator,
                    "_active_collector_budget_runs",
                    shared_budget_runs,
                )
            self._active_collector_budget_runs = shared_budget_runs
            shared_status_locks = getattr(
                orchestrator, "_collector_status_transaction_locks", None
            )
            if not isinstance(shared_status_locks, dict):
                shared_status_locks = {}
                setattr(
                    orchestrator,
                    "_collector_status_transaction_locks",
                    shared_status_locks,
                )
            self._collector_status_transaction_locks = shared_status_locks
            shared_capture_publications = getattr(
                orchestrator, "_pending_request_capture_publications", None
            )
            if not isinstance(shared_capture_publications, dict):
                shared_capture_publications = {}
                setattr(
                    orchestrator,
                    "_pending_request_capture_publications",
                    shared_capture_publications,
                )
            self._pending_request_capture_publications = shared_capture_publications
            self.dut_manager = orchestrator.dut_manager
            self.logger = orchestrator.logger
            # Set up dependency checker with DUT manager
            if (
                hasattr(orchestrator, "dependency_checker")
                and orchestrator.dependency_checker
            ):
                self.dependency_checker = orchestrator.dependency_checker
                self.dependency_checker.set_dut_manager(self.dut_manager)
            else:
                self.dependency_checker = DependencyChecker(self.dut_manager)
            self.timing_manager = orchestrator.timing_manager

    def _output_store(self) -> CollectorOutputStore:
        """
        Return the lazy output boundary used by compatibility facades.

        The implementation uses current instance state to produce the lazy
        output boundary used by compatibility facades. It updates
        ``_collector_output_store`` on the instance as part of that state
        transition.

        Returns:
            The validated ``store``.
        """

        store = getattr(self, "_collector_output_store", None)
        if not isinstance(store, CollectorOutputStore):
            store = CollectorOutputStore(self)
            self._collector_output_store = store
        return store

    def _get_request_capture_runtime(self) -> RunOwnedRequestCaptureRuntime:
        """
        Return the run-owned runtime through the capture recorder.

        After applying local validation, the function forwards current instance
        state to ``_collector_capture_recorder.get_request_capture_runtime`` and
        preserves its return and exception contract.

        Returns:
            A ``RunOwnedRequestCaptureRuntime`` representing request capture
            runtime.
        """
        return self._collector_capture_recorder.get_request_capture_runtime()

    def _capture_external_text_sanitizer(self) -> Optional[Any]:
        """
        Return the logger sanitizer through the capture recorder.

        After applying local validation, the function forwards current instance
        state to ``_collector_capture_recorder.capture_external_text_sanitizer``
        and preserves its return and exception contract.

        Returns:
            The logger sanitizer through the capture recorder, or ``None`` when
            the requested value is unavailable.
        """
        return self._collector_capture_recorder.capture_external_text_sanitizer()

    def _capture_sensitive_value_replacement(self) -> str:
        """
        Return the public structured-credential marker through the recorder.

        The recorder derives this marker from the same logger sanitizer that
        publishes primary structured artifacts, keeping diagnostic response
        values byte-equivalent without exposing the sanitizer object itself.

        Returns:
            The bounded public replacement for a sensitive mapping value.
        """

        return self._collector_capture_recorder.capture_sensitive_value_replacement()

    def _capture_sensitive_name_classifier(self) -> Optional[Any]:
        """
        Return the public structured-key classifier through the recorder.

        Primary artifacts and diagnostic response captures share this callable
        so account fields and benign schema near-misses receive identical
        treatment.

        Returns:
            The public structured-key classifier, or ``None`` when unavailable.
        """

        return self._collector_capture_recorder.capture_sensitive_name_classifier()

    @staticmethod
    async def _drain_capture_resource_discard(
        runtime: Any,
        resource: Any,
    ) -> Tuple[Optional[BaseException], Optional[BaseException]]:
        """
        Finish one blocking discard through the capture recorder.

        After applying local validation, the function forwards ``runtime`` and
        ``resource`` to
        ``CollectorCaptureRecorder.drain_capture_resource_discard`` and
        preserves its return and exception contract. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            runtime: Runtime consumed while the function attempts to finish one
                blocking discard through the capture recorder.
            resource: Resource consumed while the function attempts to finish
                one blocking discard through the capture recorder.

        Returns:
            A tuple containing the fields that represent drain capture resource
            discard, or ``None`` when the requested value is unavailable.
        """
        return await CollectorCaptureRecorder.drain_capture_resource_discard(
            runtime, resource
        )

    async def close_request_capture_state(self) -> None:
        """
        Discard generic capture state through the capture recorder.

        The implementation uses current instance state to discard generic
        capture state through the capture recorder. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.
        """
        await self._collector_capture_recorder.close_request_capture_state()

    def set_orchestrator(self, orchestrator: Any) -> None:
        """
        Attach orchestrator and backfill dependencies after lazy construction.

        The implementation uses ``orchestrator`` to attach orchestrator and
        backfill dependencies after lazy construction. It updates
        ``_active_collector_budget_runs``,
        ``_collector_status_transaction_locks``,
        ``_pending_request_capture_publications``, ``dependency_checker``, and
        ``dut_manager`` on the instance as part of that state transition.

        Args:
            orchestrator: Orchestrator object whose ``dependency_checker``,
                ``dut_manager``, ``logger``, and ``timing_manager`` state is
                read while performing attach orchestrator and backfill
                dependencies after lazy construction.
        """
        self.orchestrator = orchestrator
        if orchestrator is not None:
            shared_budget_runs = getattr(
                orchestrator, "_active_collector_budget_runs", None
            )
            if not isinstance(shared_budget_runs, dict):
                shared_budget_runs = {}
                setattr(
                    orchestrator,
                    "_active_collector_budget_runs",
                    shared_budget_runs,
                )
            self._active_collector_budget_runs = shared_budget_runs
            shared_status_locks = getattr(
                orchestrator, "_collector_status_transaction_locks", None
            )
            if not isinstance(shared_status_locks, dict):
                shared_status_locks = {}
                setattr(
                    orchestrator,
                    "_collector_status_transaction_locks",
                    shared_status_locks,
                )
            self._collector_status_transaction_locks = shared_status_locks
            shared_capture_publications = getattr(
                orchestrator, "_pending_request_capture_publications", None
            )
            if not isinstance(shared_capture_publications, dict):
                shared_capture_publications = {}
                setattr(
                    orchestrator,
                    "_pending_request_capture_publications",
                    shared_capture_publications,
                )
            self._pending_request_capture_publications = shared_capture_publications
            self.dut_manager = orchestrator.dut_manager
            self.logger = orchestrator.logger
            self.dependency_checker = orchestrator.dependency_checker
            self.timing_manager = orchestrator.timing_manager

    async def _update_variable_engine(self, dut_id: str = None) -> None:
        """
        Update variable engine with DUT-specific context.

        The implementation uses ``dut_id`` to update variable engine with
        DUT-specific context. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind. It updates
        ``variable_engine`` on the instance as part of that state transition.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        # Create variable substitution service asynchronously
        dut_object = None
        if hasattr(self, "orchestrator") and self.orchestrator and dut_id:
            dut_object = getattr(self.orchestrator.dut_manager, "duts", {}).get(dut_id)

        self.variable_engine = await VariableSubstitutionService.create(
            logger=self.logger,
            orchestrator=self.orchestrator,
            config_resolver=None,  # TODO: Get from orchestrator
            dut_object=dut_object,
        )

    def _get_dut_config_value(self, dut_id: str, config_key: str) -> Optional[Any]:
        """
        Retrieve a configuration value for the given DUT.

        Fallback to baseboard configuration if not present in DUT config.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            config_key: Stable config key used for lookup and operator-facing
                diagnostics.

        Returns:
            The DUT config value selected by the operation, or ``None`` when the
            requested value is unavailable.
        """
        if not config_key or not self.dut_manager:
            return None

        try:
            dut = self.dut_manager.get_dut(dut_id)
        except Exception:
            return None

        if not dut or not hasattr(dut, "config"):
            return None

        if config_key in dut.config:
            return dut.config.get(config_key)

        # Fallback to baseboard configuration if not present in DUT config
        if self.dut_manager:
            baseboard_name = dut.config.get("baseboard")
            if baseboard_name:
                manager_getter = getattr(
                    self.dut_manager, "_get_baseboard_manager", None
                )
                baseboard_manager = (
                    manager_getter() if callable(manager_getter) else None
                )
                if baseboard_manager:
                    baseboard_config = baseboard_manager.get_baseboard_config(
                        baseboard_name
                    )
                    if baseboard_config and config_key in baseboard_config:
                        return baseboard_config.get(config_key)

        return None

    def _get_catalog_extension_config_value(
        self, dut_id: str, namespace: str, config_key: str
    ) -> Optional[Any]:
        """
        Resolve one namespaced optional-extension setting without core coupling.

        The implementation uses ``dut_id``, ``namespace``, and ``config_key`` to
        resolve one namespaced optional-extension setting without core coupling.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            namespace: Text supplied as namespace in the format accepted by this
                function.
            config_key: Stable config key used for lookup and operator-facing
                diagnostics.

        Returns:
            The catalog extension config value selected by the operation, or
            ``None`` when the requested value is unavailable.
        """
        if not namespace or not config_key:
            return None

        candidates: List[Any] = [
            self._get_dut_config_value(dut_id, "COLLECTOR_EXTENSION_CONFIG")
        ]
        tool_config = getattr(self.dut_manager, "tool_config", {}) or {}
        if isinstance(tool_config, dict):
            candidates.append(tool_config.get("COLLECTOR_EXTENSION_CONFIG"))
        else:
            candidates.append(getattr(tool_config, "COLLECTOR_EXTENSION_CONFIG", None))

        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            scoped = candidate.get(namespace)
            if isinstance(scoped, dict) and config_key in scoped:
                return scoped[config_key]
        return None

    async def run_catalog_extension(
        self,
        extension_module: str,
        extension_callable: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Run a trusted, catalog-selected extension or fail the hook explicitly.

        The implementation uses ``extension_module``, ``extension_callable``,
        and ``kwargs`` to run a trusted, catalog-selected extension or fail the
        hook explicitly. Terminal status is emitted only after trusted,
        catalog-selected extension or fail the hook explicitly and its owned
        cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            extension_module: Text supplied as extension module in the format
                accepted by this function.
            extension_callable: Text supplied as extension callable in the
                format accepted by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run catalog extension.
        """

        def unavailable(reason: str) -> Dict[str, Any]:
            """
            Return the unavailable.

            The implementation uses ``reason`` to produce the unavailable.

            Args:
                reason: Text supplied as reason in the format accepted by this
                    function.

            Returns:
                A mapping containing the ``success``, ``status``, ``reason``,
                and ``context`` fields.
            """
            return {
                "success": False,
                "status": "error",
                "reason": reason,
                "context": {"output_files": [], "error_messages": [reason]},
            }

        if (
            not isinstance(extension_module, str)
            or not _CATALOG_EXTENSION_IDENTIFIER.fullmatch(extension_module)
            or not extension_module.startswith(f"{TRUSTED_EXTENSION_PACKAGE}.")
        ):
            return unavailable(
                "Catalog extension module is outside the trusted namespace"
            )
        if (
            not isinstance(extension_callable, str)
            or not _CATALOG_EXTENSION_IDENTIFIER.fullmatch(extension_callable)
            or "." in extension_callable
            or extension_callable.startswith("_")
        ):
            return unavailable("Catalog extension callable is invalid")

        try:
            module = import_trusted_extension_module(extension_module)
        except Exception as error:
            return unavailable(
                f"Required catalog extension {extension_module} is unavailable: {error}"
            )

        entrypoint = getattr(module, extension_callable, None)
        if not callable(entrypoint):
            return unavailable(
                f"Required catalog extension entrypoint "
                f"{extension_module}:{extension_callable} is unavailable"
            )

        try:
            result = entrypoint(service=self, **kwargs)
            if inspect.isawaitable(result):
                result = await result
        except Exception as error:
            return unavailable(
                f"Catalog extension {extension_module}:{extension_callable} failed: "
                f"{error}"
            )

        if not isinstance(result, dict):
            return unavailable(
                f"Catalog extension {extension_module}:{extension_callable} "
                "returned a non-mapping result"
            )
        return result

    async def _log_error(
        self,
        error_type: str,
        message: str,
        dut_id: str = None,
        collector_id: str = None,
    ) -> None:
        """
        Log error.

        The implementation uses ``error_type``, ``message``, ``dut_id``, and
        ``collector_id`` to log error. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            error_type: Text supplied as error type in the format accepted by
                this function.
            message: Operator-facing text carried by the reported event or
                failure.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
        """
        # Auto-detect dut_id if not provided
        if dut_id is None:
            dut_id = self._get_current_dut_id()

        # Auto-detect collector_id if not provided
        if collector_id is None:
            collector_id = self._get_current_collector_id()

        if self.logger:
            try:
                await self.logger.log_error(error_type, message, dut_id, collector_id)
            except Exception as e:
                # Fallback to standard logger if async logger fails
                if dut_id and dut_id != "unknown":
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "BaseService",
                        f"Failed to log error via async logger: {e}",
                    )
                else:
                    logger.error(f"Failed to log error via async logger: {e}")
        else:
            # Fallback to standard logger if self.logger not available
            logger.error(f"{error_type}: {message}")

    def _get_current_collector_id(self) -> str:
        """
        Get the current collector ID from context if available.

        Task-local context variable set by the execution engine — safe under
        concurrency.

        Returns:
            The canonical current collector identifier text.
        """
        try:
            # Task-local context variable set by the execution engine — safe under concurrency.
            ctx_id = _collector_context.get()
            if ctx_id:
                return ctx_id

            # Fallback: shared orchestrator globals (race-prone under parallel execution).
            if hasattr(self, "orchestrator") and self.orchestrator:
                if hasattr(self.orchestrator, "current_collector_id"):
                    return self.orchestrator.current_collector_id

                if hasattr(self.orchestrator, "current_execution_context"):
                    return self.orchestrator.current_execution_context.get(
                        "collector_id", "unknown"
                    )
        except Exception:
            pass

        return "unknown"

    async def _get_original_collector_id(
        self, dut_id: str = None, collector_id: str = None
    ) -> str:
        """
        Get the original collector ID for file path determination.

        DEBUG: Log the attempt to get original collector ID.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The canonical original collector identifier text.
        """
        try:
            # DEBUG: Log the attempt to get original collector ID
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Getting original collector ID for dut_id={dut_id}, collector_id={collector_id}",
            )

            # Try to get from orchestrator context
            if hasattr(self, "orchestrator") and self.orchestrator:
                # First try to get from per-collector context (new method)
                if (
                    hasattr(self.orchestrator, "get_collector_execution_context")
                    and dut_id
                    and collector_id
                ):
                    context = await self.orchestrator.get_collector_execution_context(
                        dut_id, collector_id
                    )
                    original_collector_id = context.get(
                        "original_collector_id", collector_id
                    )

                    # DEBUG: Log the result
                    await self._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"Retrieved original_collector_id: {original_collector_id} from context for {dut_id}:{collector_id}",
                    )

                    # Return original_collector_id if available, otherwise the passed collector_id
                    return original_collector_id

                # Fallback to passed collector_id or current collector ID
                fallback_id = collector_id or self._get_current_collector_id()
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Using fallback collector ID: {fallback_id}",
                )
                return fallback_id
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BaseService",
                f"Error getting original collector ID: {e}",
            )

        await self._log_runtime(
            "DEBUG",
            "BaseService",
            "Returning 'unknown' for original collector ID",
        )
        return "unknown"

    def _get_current_dut_id(self) -> str:
        """
        Get the current DUT ID from context if available.

        Task-local execution identity is authoritative under concurrent
        multi-DUT collection. The orchestrator field below is retained only as a
        compatibility fallback because it is shared mutable state and can be
        overwritten by another DUT's task.

        Returns:
            The canonical current DUT identifier text.
        """
        try:
            # Task-local execution identity is authoritative under concurrent
            # multi-DUT collection.  The orchestrator field below is retained
            # only as a compatibility fallback because it is shared mutable
            # state and can be overwritten by another DUT's task.
            context_dut_id = _dut_context.get()
            if context_dut_id:
                return context_dut_id

            # Try to get from orchestrator context
            if hasattr(self, "orchestrator") and self.orchestrator:
                # Check if orchestrator has current execution context
                if hasattr(self.orchestrator, "current_execution_context"):
                    return self.orchestrator.current_execution_context.get(
                        "dut_id", "unknown"
                    )
        except Exception:
            pass

        return "unknown"

    async def _log_collection_summary(
        self,
        dut_id: str,
        collection_name: str,
        total_operations: int,
        successful_operations: int,
        failed_operations: int,
        skipped_operations: int = 0,
        output_files_count: int = 0,
        additional_details: Dict[str, Any] = None,
    ) -> None:
        """
        Log a standardized collection summary similar to host service pattern.

        Single-line summary at INFO; full breakdown at DEBUG.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collection_name: Stable collection name used for lookup and
                operator-facing diagnostics.
            total_operations: Numeric total operations used while the operation
                performs bounded accounting.
            successful_operations: Numeric successful operations used while the
                operation performs bounded accounting.
            failed_operations: Numeric failed operations used while the
                operation performs bounded accounting.
            skipped_operations: Numeric skipped operations used while the
                operation performs bounded accounting.
            output_files_count: Numeric output files count used by the
                operation's bounded accounting.
            additional_details: Optional additional details; ``None`` selects
                the function's default behavior.
        """
        success_rate = (
            (successful_operations / total_operations * 100)
            if total_operations > 0
            else 0
        )

        # Single-line summary at INFO; full breakdown at DEBUG
        summary = (
            f"{collection_name}: {successful_operations}/{total_operations} succeeded"
        )
        if failed_operations:
            summary += f", {failed_operations} failed"
        if skipped_operations:
            summary += f", {skipped_operations} skipped"
        summary += f" ({output_files_count} files, {success_rate:.0f}%)"

        await self._log_runtime(
            "INFO" if not failed_operations else "WARN",
            self.service_name,
            summary,
            dut_id,
        )

        if additional_details:
            for key, value in additional_details.items():
                await self._log_runtime(
                    "DEBUG", self.service_name, f"{key}: {value}", dut_id
                )

    async def _save_collection_summary_json(
        self,
        dut_id: str,
        collection_name: str,
        total_operations: int,
        successful_operations: int,
        failed_operations: int,
        skipped_operations: int = 0,
        output_files: List[str] = None,
        additional_details: Dict[str, Any] = None,
        output_dir: str = None,
    ) -> str:
        """
        Save a JSON summary file for the collection operation.

        The implementation uses ``dut_id``, ``collection_name``,
        ``total_operations``, ``successful_operations``, and
        ``failed_operations`` to save a JSON summary file for the collection
        operation. Success is reported only after the owning output boundary has
        completed its required write or publication step. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collection_name: Stable collection name used for lookup and
                operator-facing diagnostics.
            total_operations: Numeric total operations used while the operation
                performs bounded accounting.
            successful_operations: Numeric successful operations used while the
                operation performs bounded accounting.
            failed_operations: Numeric failed operations used while the
                operation performs bounded accounting.
            skipped_operations: Numeric skipped operations used while the
                operation performs bounded accounting.
            output_files: Optional output files; ``None`` selects the function's
                default behavior.
            additional_details: Optional additional details; ``None`` selects
                the function's default behavior.
            output_dir: Optional filesystem location used as the output dir for
                this operation.

        Returns:
            The canonical save collection summary JSON text.
        """
        import json
        import os
        from datetime import datetime

        # Calculate success rate
        success_rate = (
            (successful_operations / total_operations * 100)
            if total_operations > 0
            else 0
        )

        summary_data = {
            "collection_name": collection_name,
            "dut_id": dut_id,
            "timestamp": datetime.now().isoformat(),
            "statistics": {
                "total_operations": total_operations,
                "successful_operations": successful_operations,
                "failed_operations": failed_operations,
                "skipped_operations": skipped_operations,
                "success_rate_percent": round(success_rate, 1),
            },
            "output_files": output_files or [],
            "additional_details": additional_details or {},
        }

        # Determine output directory
        if not output_dir:
            # Try to get the current output directory from the logger
            if (
                hasattr(self, "logger")
                and self.logger
                and hasattr(self.logger, "output_dir")
            ):
                output_dir = str(self.logger.output_dir)
            else:
                output_dir = f"logs/{dut_id}_collection_summary"

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Generate filename
        safe_name = collection_name.lower().replace(" ", "_").replace("/", "_")
        filename = f"{safe_name}_summary.json"
        filepath = os.path.join(output_dir, filename)

        # Save JSON file
        try:
            with open(filepath, "w") as f:
                json.dump(summary_data, f, indent=2)

            await self._log_runtime(
                "INFO",
                self.service_name,
                f"Collection summary saved to: {filepath}",
                dut_id,
            )
            return filepath
        except Exception as e:
            await self._log_runtime(
                "WARNING",
                self.service_name,
                f"Failed to save collection summary: {e}",
                dut_id,
            )
            return ""

    async def _save_collection_summary_text(
        self,
        dut_id: str,
        collection_name: str,
        total_operations: int,
        successful_operations: int,
        failed_operations: int,
        skipped_operations: int = 0,
        output_files: List[str] = None,
        additional_details: Dict[str, Any] = None,
        output_dir: str = None,
    ) -> str:
        """
        Save collection summary text.

        The implementation uses ``dut_id``, ``collection_name``,
        ``total_operations``, ``successful_operations``, and
        ``failed_operations`` to save collection summary text. Success is
        reported only after the owning output boundary has completed its
        required write or publication step. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collection_name: Stable collection name used for lookup and
                operator-facing diagnostics.
            total_operations: Numeric total operations used while the operation
                performs bounded accounting.
            successful_operations: Numeric successful operations used while the
                operation performs bounded accounting.
            failed_operations: Numeric failed operations used while the
                operation performs bounded accounting.
            skipped_operations: Numeric skipped operations used while the
                operation performs bounded accounting.
            output_files: Optional output files; ``None`` selects the function's
                default behavior.
            additional_details: Optional additional details; ``None`` selects
                the function's default behavior.
            output_dir: Optional filesystem location used as the output dir for
                this operation.

        Returns:
            The canonical save collection summary text.
        """
        import os
        from datetime import datetime

        # Calculate success rate
        success_rate = (
            (successful_operations / total_operations * 100)
            if total_operations > 0
            else 0
        )

        # Create summary content
        summary_lines = [
            f"{collection_name} Summary",
            "=" * (len(collection_name) + 8),
            "",
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"DUT ID: {dut_id}",
            "",
            "Statistics:",
            f"  Total operations: {total_operations}",
            f"  Successful operations: {successful_operations}",
            f"  Failed operations: {failed_operations}",
        ]

        if skipped_operations > 0:
            summary_lines.append(f"  Skipped operations: {skipped_operations}")

        summary_lines.extend(
            [
                f"  Success rate: {success_rate:.1f}%",
                f"  Output files generated: {len(output_files) if output_files else 0}",
                "",
            ]
        )

        # Add additional details if provided
        if additional_details:
            summary_lines.append("Additional Details:")
            for key, value in additional_details.items():
                summary_lines.append(f"  {key}: {value}")
            summary_lines.append("")

        # Add output files list if provided
        if output_files:
            summary_lines.extend(
                [
                    "Output Files:",
                    *[f"  - {file}" for file in output_files],
                    "",
                ]
            )

        summary_content = "\n".join(summary_lines)

        # Determine output directory
        if not output_dir:
            # Try to get the current output directory from the logger
            if (
                hasattr(self, "logger")
                and self.logger
                and hasattr(self.logger, "output_dir")
            ):
                output_dir = str(self.logger.output_dir)
            else:
                output_dir = f"logs/{dut_id}_collection_summary"

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Generate filename
        safe_name = collection_name.lower().replace(" ", "_").replace("/", "_")
        filename = f"{safe_name}_summary.txt"
        filepath = os.path.join(output_dir, filename)

        # Save text file
        try:
            with open(filepath, "w") as f:
                f.write(summary_content)

            await self._log_runtime(
                "INFO",
                self.service_name,
                f"Collection summary saved to: {filepath}",
                dut_id,
            )
            return filepath
        except Exception as e:
            await self._log_runtime(
                "WARNING",
                self.service_name,
                f"Failed to save collection summary: {e}",
                dut_id,
            )
            return ""

    async def _create_generic_collection_summary(
        self,
        function_tag: str,
        collection_type: str,
        search_info: Dict[str, Any],
        results: Dict[str, Any],
        ignore_empty_results: bool,
        collector_config: Dict[str, Any] = None,
        total_operations: int = None,
        successful_operations: int = None,
    ) -> str:
        """
        Create a standardized summary for any collection operation.

        This is a truly generic function that can be used by any collector to
        provide consistent summary reporting. Collector-specific information
        comes from the collector_config parameter.

        Args:
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            collection_type: Text supplied as collection type in the format
                accepted by this function.
            search_info: Mapping supplying fields for standardized summary for
                any collection.
            results: Mapping supplying fields for standardized summary for any
                collection.
            ignore_empty_results: Whether ignore empty results is enabled or
                required for this operation.
            collector_config: Optional Collector config governing standardized
                summary for any collection.
            total_operations: Optional total operations; ``None`` selects the
                function's default behavior.
            successful_operations: Optional successful operations; ``None``
                selects the function's default behavior.

        Returns:
            The canonical generic collection summary text.

        Raises:
            ValueError: If declared processed-source identities are malformed,
                duplicated, or do not align one-to-one with processed files.
        """
        # Get collector-specific information from config
        if collector_config:
            collector_name = collector_config.get("name", function_tag)
            description = collector_config.get(
                "description", f"{collection_type} collection"
            )

            # Custom messages from collector config
            empty_expected_note = collector_config.get(
                "empty_expected_note",
                "No files found. This is expected behavior for this collector.",
            )
            empty_unexpected_note = collector_config.get(
                "empty_unexpected_note",
                "No files found. This may indicate missing files or configuration issues.",
            )
            success_note = collector_config.get(
                "success_note", "Collection completed successfully."
            )
        else:
            collector_name = function_tag
            description = f"{collection_type} collection"
            empty_expected_note = (
                "No files found. This is expected behavior for this collector."
            )
            empty_unexpected_note = "No files found. This may indicate missing files or configuration issues."
            success_note = "Collection completed successfully."

        summary_lines = [
            f"{collector_name.title()} Collection Summary",
            "=" * (len(collector_name) + 20),
            "",
            f"Collection Type: {collection_type}",
            f"Description: {description}",
            "",
        ]

        # Add search information based on collection type
        if collection_type == "file_collection":
            file_patterns = search_info.get("file_patterns", [])
            collected_files = results.get("collected_files", [])
            empty_patterns = results.get("empty_patterns", [])

            summary_lines.extend(
                [
                    f"Total Patterns Searched: {len(file_patterns)}",
                    f"Files Found: {len(collected_files)}",
                    f"Empty Patterns: {len(empty_patterns)}",
                    "",
                ]
            )

            if empty_patterns:
                summary_lines.extend(
                    [
                        "Patterns with no files found:",
                        *[f"- {pattern}" for pattern in empty_patterns],
                        "",
                    ]
                )

            if collected_files:
                summary_lines.extend(
                    [
                        "Files successfully collected:",
                        *[f"- {file}" for file in collected_files],
                        "",
                    ]
                )
            else:
                summary_lines.extend(
                    [
                        "Files successfully collected:",
                        "- None",
                        "",
                    ]
                )

        elif collection_type == "file_search_and_archive":
            file_pattern = search_info.get("file_pattern", "*")
            search_directories = search_info.get("search_directories", [])

            # Collect discovered, processed, and failed files (with graceful fallbacks).
            found_files = search_info.get("found_files") or results.get(
                "found_files", []
            )
            candidate_files = search_info.get("candidate_files", found_files)
            rejected_files = search_info.get("rejected_files", [])
            processed_files = search_info.get("processed_files", [])
            failed_files = search_info.get("failed_files", [])

            # Gather error messages so we can infer failed files even when only the summary runs.
            error_messages = search_info.get("error_messages") or results.get(
                "error_messages", []
            )
            if error_messages:
                failed_files_from_errors = []
                for message in error_messages:
                    match = re.search(r"Failed to process file:\s*(.+)", message)
                    if match:
                        failed_files_from_errors.append(match.group(1).strip())
                if failed_files_from_errors:
                    failed_files = (
                        failed_files or []
                    ) + failed_files_from_errors  # merge if already present

            # Ensure lists are unique while preserving order.
            def _dedupe(sequence: List[str]) -> List[str]:
                """
                Return the dedupe.

                The implementation uses ``sequence`` to produce the dedupe.

                Args:
                    sequence: Entries supplied as ``sequence`` without
                        transferring container ownership.

                Returns:
                    The validated ``ordered``.
                """
                seen = set()
                ordered = []
                for item in sequence:
                    if item and item not in seen:
                        seen.add(item)
                        ordered.append(item)
                return ordered

            found_files = _dedupe(found_files or [])
            candidate_files = _dedupe(candidate_files or [])
            rejected_files = _dedupe(rejected_files or [])
            processed_files = _dedupe(processed_files or [])
            failed_files = _dedupe(failed_files or [])

            if "processed_source_identities" in search_info:
                raw_source_identities = search_info["processed_source_identities"]
                if (
                    not isinstance(raw_source_identities, list)
                    or len(raw_source_identities) != len(processed_files)
                    or any(
                        not isinstance(identity, str)
                        or re.fullmatch(r"[0-9a-f]{64}", identity) is None
                        for identity in raw_source_identities
                    )
                    or len(raw_source_identities) != len(set(raw_source_identities))
                ):
                    raise ValueError(
                        "processed source identities must align with processed files"
                    )
                processed_source_identities = list(raw_source_identities)
            else:
                processed_source_identities = []

            # If we only know about failures, treat them as discovered files for reporting.
            if not found_files and failed_files:
                found_files = failed_files.copy()

            processed_set = set(processed_files)
            failed_set = set(failed_files)

            summary_lines.extend(
                [
                    f"Search Pattern: {file_pattern}",
                    f"Search Directories: {', '.join(search_directories) or '(none)'}",
                    f"Search Candidates: {len(candidate_files)}",
                    f"Files Found: {len(found_files)}",
                    "",
                ]
            )

            if found_files:
                summary_lines.append("Files discovered:")
                for file in found_files:
                    suffix = ""
                    if file in failed_set and file in processed_set:
                        suffix = " (processing failed after partial transfer)"
                    elif file in failed_set:
                        suffix = " (processing failed)"
                    elif file in processed_set:
                        suffix = " (processed)"
                    summary_lines.append(f"- {file}{suffix}")
                summary_lines.append("")
            else:
                summary_lines.extend(
                    [
                        "Files discovered:",
                        "- None",
                        "",
                    ]
                )

            if rejected_files:
                summary_lines.extend(
                    [
                        "Candidates rejected by content/path validation:",
                        *[f"- {file}" for file in rejected_files],
                        "",
                    ]
                )

            related_searches = search_info.get("related_file_searches")
            if isinstance(related_searches, dict):

                def _summary_detail(value: Any, default: str = "None") -> str:
                    """
                    Return bounded single-line text for remote-derived evidence.

                    The implementation uses ``value`` and ``default`` to produce
                    bounded single-line text for remote-derived evidence.

                    Args:
                        value: Value evaluated while performing bounded
                            single-line text for remote-derived evidence.
                        default: Fallback used when the requested value is
                            absent or invalid.

                    Returns:
                        The canonical summary detail text.
                    """

                    if value is None:
                        return default
                    rendered = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value))
                    rendered = " ".join(rendered.split())
                    if not rendered:
                        return default
                    max_chars = 1024
                    if len(rendered) > max_chars:
                        rendered = f"{rendered[: max_chars - 3]}..."
                    return rendered

                def _detail_items(details: Dict[str, Any], key: str) -> List[Any]:
                    """
                    Return the detail items.

                    The implementation uses ``details`` and ``key`` to produce
                    the detail items.

                    Args:
                        details: Mapping supplying fields for detail items.
                        key: Stable key used for lookup and operator-facing
                            diagnostics.

                    Returns:
                        The detail items returned in operation-defined order.
                    """
                    value = details.get(key, [])
                    return value if isinstance(value, list) else []

                def _path_reason(item: Any) -> Tuple[str, str]:
                    """
                    Return the path reason.

                    The implementation uses ``item`` to produce the path reason.

                    Args:
                        item: Item object whose ``get`` state is read while
                            performing path reason.

                    Returns:
                        A tuple containing ``summary detail`` and ``status or
                        message text`` in that order.
                    """
                    if isinstance(item, dict):
                        return (
                            _summary_detail(item.get("path")),
                            _summary_detail(item.get("reason"), "unspecified"),
                        )
                    return _summary_detail(item), "unspecified"

                for raw_search_id, raw_details in related_searches.items():
                    if not isinstance(raw_details, dict):
                        continue
                    search_id = _summary_detail(raw_search_id, "unnamed")
                    field_prefix = f"Related File Search [{search_id}]"
                    match_config = raw_details.get("match")
                    if not isinstance(match_config, dict):
                        match_config = {}
                    anchor_config = raw_details.get("anchor")
                    if not isinstance(anchor_config, dict):
                        anchor_config = {}
                    selection_config = raw_details.get("selection")
                    if not isinstance(selection_config, dict):
                        selection_config = {}
                    anchor_directories = _detail_items(
                        raw_details, "anchor_directories"
                    )
                    candidate_files = _detail_items(raw_details, "candidate_files")
                    eligible_files = _detail_items(raw_details, "eligible_files")
                    case_label = (
                        "case-sensitive"
                        if match_config.get("case_sensitive", True)
                        else "case-insensitive"
                    )
                    summary_lines.extend(
                        [
                            f"{field_prefix} Match: "
                            f"{_summary_detail(match_config.get('basename_glob'))} "
                            f"({case_label})",
                            f"{field_prefix} Anchor Source: "
                            f"{_summary_detail(anchor_config.get('source'))}",
                            f"{field_prefix} Selection Strategy: "
                            f"{_summary_detail(selection_config.get('strategy'))}",
                            f"{field_prefix} Selection Source: "
                            f"{_summary_detail(selection_config.get('source'))}",
                            f"{field_prefix} Selection Tie Breaker: "
                            f"{_summary_detail(selection_config.get('tie_breaker'))}",
                            f"{field_prefix} Absence Policy: "
                            f"{_summary_detail(raw_details.get('absence_policy'))}",
                            f"{field_prefix} Malformed-only Policy: "
                            f"{_summary_detail(raw_details.get('malformed_only_policy'))}",
                            f"{field_prefix} Anchors: {len(anchor_directories)}",
                            f"{field_prefix} Candidates: {len(candidate_files)}",
                            f"{field_prefix} Eligible: {len(eligible_files)}",
                            f"{field_prefix} Selected: "
                            f"{_summary_detail(raw_details.get('selected_file'))}",
                            f"{field_prefix} Selected Timestamp: "
                            f"{_summary_detail(raw_details.get('selected_timestamp'))}",
                            f"{field_prefix} Search Status: "
                            f"{_summary_detail(raw_details.get('search_status'))}",
                            "",
                        ]
                    )

                    rejected_anchors = _detail_items(raw_details, "rejected_anchors")
                    if rejected_anchors:
                        summary_lines.append(f"{field_prefix} Rejected Anchors:")
                        for item in rejected_anchors:
                            path, reason = _path_reason(item)
                            summary_lines.append(f"- Path: {path}; Reason: {reason}")
                        summary_lines.append("")

                    superseded_files = _detail_items(raw_details, "superseded_files")
                    if superseded_files:
                        summary_lines.extend(
                            [
                                f"{field_prefix} Superseded Candidates:",
                                *[
                                    f"- {_summary_detail(path)}"
                                    for path in superseded_files
                                ],
                                "",
                            ]
                        )

                    rejected_files = _detail_items(raw_details, "rejected_files")
                    if rejected_files:
                        summary_lines.append(f"{field_prefix} Rejected Candidates:")
                        for item in rejected_files:
                            path, reason = _path_reason(item)
                            summary_lines.append(f"- Path: {path}; Reason: {reason}")
                        summary_lines.append("")

                    search_error = raw_details.get("search_error")
                    if search_error:
                        summary_lines.extend(
                            [
                                f"{field_prefix} Search Error: "
                                f"{_summary_detail(search_error)}",
                                "",
                            ]
                        )

            if processed_source_identities:
                summary_lines.extend(
                    [
                        "Processed Source Identities [sha256_source_path]:",
                        *[f"- {identity}" for identity in processed_source_identities],
                        "",
                    ]
                )

        # Add appropriate note based on results and configuration
        # Use search_info for emptiness checks so summaries reflect archived content
        has_empty_results = (
            collection_type == "file_collection"
            and (search_info.get("empty_patterns") or [])
        ) or (collection_type == "file_search_and_archive" and not found_files)

        # Determine status note - CHECK EMPTY RESULTS FIRST before operation counts
        # This ensures that when no files are found, we show the appropriate message
        # instead of generic "All operations completed successfully"
        status_note_override = search_info.get("status_note_override")
        if status_note_override:
            status_note = str(status_note_override)
        elif has_empty_results and ignore_empty_results:
            status_note = empty_expected_note
        elif has_empty_results:
            status_note = empty_unexpected_note
        elif total_operations is not None and successful_operations is not None:
            if total_operations == 0:
                status_note = "No operations attempted."
            elif successful_operations == 0:
                status_note = "All operations failed."
            elif successful_operations < total_operations:
                status_note = f"Partial success: {successful_operations}/{total_operations} operations succeeded."
            elif collector_config and "success_note" in collector_config:
                # Preserve an explicitly authored full-success message while
                # keeping failure and partial counts authoritative.
                status_note = success_note
            else:
                status_note = (
                    f"All {successful_operations} operations completed successfully."
                )
        else:
            status_note = success_note

        summary_lines.extend(
            [
                f"Note: {status_note}",
            ]
        )

        return "\n".join(summary_lines)

    async def _log_runtime(
        self,
        level: str,
        component: str,
        message: str,
        dut_id: str = None,
        collector_id: str = None,
    ) -> None:
        """
        Log runtime.

        The implementation uses ``level``, ``component``, ``message``,
        ``dut_id``, and ``collector_id`` to log runtime. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            component: Text supplied as component in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
        """
        # Auto-detect dut_id if not provided
        if dut_id is None:
            dut_id = self._get_current_dut_id()

        # Auto-detect collector_id if not provided
        if collector_id is None:
            # Try to get from per-collector context first, then fallback to global context
            if (
                dut_id
                and hasattr(self, "orchestrator")
                and self.orchestrator
                and hasattr(self.orchestrator, "get_collector_execution_context")
            ):
                # Try to get the current collector ID from the global context first
                current_collector_id = self._get_current_collector_id()
                if current_collector_id != "unknown":
                    # Get the per-collector context to find the original collector ID
                    try:
                        context = (
                            await self.orchestrator.get_collector_execution_context(
                                dut_id, current_collector_id
                            )
                        )
                        original_collector_id = context.get(
                            "original_collector_id", current_collector_id
                        )
                        collector_id = original_collector_id
                    except Exception:
                        # Fallback to global context if per-collector context fails
                        collector_id = current_collector_id
                else:
                    collector_id = current_collector_id
            else:
                collector_id = self._get_current_collector_id()

        if self.logger:
            try:
                if dut_id and dut_id != "unknown":
                    await self.logger.write_to_dut_runtime_log(
                        dut_id, level, component, message, collector_id
                    )
                else:
                    await self.logger.log_runtime(level, component, message)
            except Exception as e:
                # Fallback to standard logger if async logger fails
                logger.error(f"Failed to log runtime via async logger: {e}")
                logger.info(f"{level} [{component}] {message}")
        else:
            # Fallback to standard logger if self.logger not available
            logger.info(f"{level} [{component}] {message}")

    def _extract_error_details(self, response: Any) -> str:
        """
        Extract error details.

        The implementation uses ``response`` to extract error details. Remote
        I/O uses the configured transport policy and returns only after its
        response or failure has been observed.

        Args:
            response: Transport response governed by the configured
                authentication and trust policy.

        Returns:
            The canonical error details text.
        """
        # This compatibility helper is intentionally pure. Runtime callers use
        # the async twin, which routes diagnostics through the sanitizing
        # logger. Logging a device-controlled response from this synchronous
        # path would bypass that boundary.
        if isinstance(response, dict):
            # Handle empty response (common with 400 errors)
            if not response:
                return (
                    "HTTP 400: Empty response - likely unsupported diagnostic "
                    "data type or invalid payload"
                )

            # Try common error response patterns
            if "error" in response:
                error_obj = response["error"]
                if isinstance(error_obj, dict):
                    error_code = error_obj.get("code", "Unknown")
                    error_message = error_obj.get("message", str(response))
                    return f"Code: {error_code}, Message: {error_message}"
                return f"Error: {error_obj}"
            if "code" in response and "message" in response:
                # Direct error response format
                return f"Code: {response['code']}, Message: {response['message']}"
            if "HTTPStatus" in response:
                # Redfish error response format
                status = response.get("HTTPStatus", "Unknown")
                message = response.get("Message", "No message provided")
                return f"HTTP {status}: {message}"
        return str(response)

    async def _get_current_timestamp(self) -> str:
        """
        Get current timestamp in ISO format.

        After applying local validation, the function forwards current instance
        state to ``isoformat`` and preserves its return and exception contract.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Returns:
            The canonical current timestamp text.
        """
        return datetime.now().isoformat()

    async def _save_failures_json(
        self,
        dut_id: str,
        collector_name: str,
        failure_details: list,
        collector_id: str = None,
    ) -> None:
        """
        Save detailed failure information to failures.json file.

        The implementation uses ``dut_id``, ``collector_name``,
        ``failure_details``, and ``collector_id`` to save detailed failure
        information to failures.json file. Success is reported only after the
        owning output boundary has completed its required write or publication
        step. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_name: Stable collector name used for lookup and
                operator-facing diagnostics.
            failure_details: Entries supplied as ``failure_details`` without
                transferring container ownership.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
        """
        if not failure_details:
            return

        try:
            # Create failures data structure
            failures_data = {
                "collector": collector_name,
                "dut_id": dut_id,
                "timestamp": await self._get_current_timestamp(),
                "total_failures": len(failure_details),
                "failures": failure_details,
            }

            # Save to failures.json file
            file_path = await self._save_data_with_common_pattern(
                dut_id,
                failures_data,
                collector_name,
                output_pattern="failures.json",
                substitutions={"collector": collector_name, "dut_id": dut_id},
                collector_id=collector_id,
            )

            if file_path:
                await self._log_runtime(
                    "INFO",
                    "BaseService",
                    f"Saved {len(failure_details)} failure details to {file_path}",
                    dut_id,
                )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BaseService",
                f"Failed to save failures.json: {str(e)}",
                dut_id,
            )

    async def _handle_collector_completion(
        self,
        dut_id: str,
        collector_name: str,
        successful_operations: int,
        total_operations: int,
        output_files: list,
        error_messages: list,
        operation_name: str = "collector",
        additional_context: dict = None,
    ) -> dict:
        """
        Handle collector completion.

        Create detailed failure information for failures.json.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_name: Stable collector name used for lookup and
                operator-facing diagnostics.
            successful_operations: Numeric successful operations used while the
                operation performs bounded accounting.
            total_operations: Numeric total operations used while the operation
                performs bounded accounting.
            output_files: Entries supplied as ``output_files`` without
                transferring container ownership.
            error_messages: Entries supplied as ``error_messages`` without
                transferring container ownership.
            operation_name: Stable operation name used for lookup and
                operator-facing diagnostics.
            additional_context: Optional additional context; ``None`` selects
                the function's default behavior.

        Returns:
            A mapping containing handle collector completion.
        """
        try:
            # Create detailed failure information for failures.json
            failure_details = []
            if error_messages:
                for i, error_msg in enumerate(error_messages):
                    failure_details.append(
                        {
                            "failure_id": i + 1,
                            "error_message": error_msg,
                            "timestamp": await self._get_current_timestamp(),
                            "collector": collector_name,
                            "dut_id": dut_id,
                        }
                    )

            # Determine status
            if total_operations == 0:
                status = "skipped"
                reason = (
                    f"No operations attempted for {collector_name} - collector skipped"
                )
            elif successful_operations == 0:
                status = "error"
                reason = (
                    f"All {total_operations} operations failed for {collector_name}"
                )
            elif successful_operations < total_operations:
                status = "partial"
                reason = f"{successful_operations}/{total_operations} operations succeeded for {collector_name}"
            else:
                status = "success"
                reason = (
                    f"All {total_operations} operations succeeded for {collector_name}"
                )

            # Log completion
            await self._log_runtime(
                "INFO",
                "BaseService",
                f"Completed {collector_name} - {successful_operations}/{total_operations} operations succeeded ({status})",
                dut_id,
            )

            # Generate summary files
            await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=collector_name,
                collection_name=f"{collector_name} Collection",
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=total_operations - successful_operations,
                output_files=output_files,
                additional_details={"error_messages": error_messages},
                kwargs={},
            )

            # Save failures.json if there are failures
            if failure_details:
                await self._save_failures_json(dut_id, collector_name, failure_details)

            # Create standardized result
            result_context = {
                "total_operations": total_operations,
                "successful_operations": successful_operations,
                "status": status,
                "reason": reason,
            }

            if additional_context:
                result_context.update(additional_context)

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name=operation_name,
                additional_context=result_context,
            )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BaseService",
                f"Exception in _handle_collector_completion: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"Exception in collector completion: {str(e)}"],
                operation_name=operation_name,
                additional_context={},
            )

    async def _extract_error_details_async(
        self, response: Any, dut_id: str = "unknown", context: str = ""
    ) -> str:
        """
        Extract error details async.

        The implementation uses ``response``, ``dut_id``, and ``context`` to
        extract error details async. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind. Remote
        I/O uses the configured transport policy and returns only after its
        response or failure has been observed.

        Args:
            response: Transport response governed by the configured
                authentication and trust policy.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            The canonical error details async text.
        """
        error_details = ""

        if isinstance(response, dict):
            # Handle empty response (common with 400 errors)
            if not response or response == {}:
                error_details = "HTTP 400: Empty response - likely unsupported diagnostic data type or invalid payload"
                await self._log_runtime(
                    "WARNING",
                    "BaseService",
                    f"{context} Empty response received: {error_details}",
                    dut_id,
                )
                return error_details

            # Try common error response patterns
            if "error" in response:
                error_obj = response["error"]
                if isinstance(error_obj, dict):
                    error_code = error_obj.get("code", "Unknown")
                    error_message = error_obj.get("message", str(response))
                    error_details = f"Code: {error_code}, Message: {error_message}"
                    await self._log_runtime(
                        "ERROR",
                        "BaseService",
                        f"{context} API Error Response: {error_details}",
                        dut_id,
                    )
                    await self._log_runtime(
                        "DEBUG",
                        "BaseService",
                        f"{context} Full error object: {error_obj}",
                        dut_id,
                    )
                else:
                    error_details = f"Error: {error_obj}"
                    await self._log_runtime(
                        "ERROR",
                        "BaseService",
                        f"{context} API Error Response: {error_details}",
                        dut_id,
                    )
            elif "code" in response and "message" in response:
                # Direct error response format
                error_details = (
                    f"Code: {response['code']}, Message: {response['message']}"
                )
                await self._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"{context} API Error Response: {error_details}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"{context} Full error response: {response}",
                    dut_id,
                )
            elif "HTTPStatus" in response:
                # Redfish error response format
                status = response.get("HTTPStatus", "Unknown")
                message = response.get("Message", "No message provided")
                error_details = f"HTTP {status}: {message}"
                await self._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"{context} Redfish Error Response: {error_details}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"{context} Full Redfish error response: {response}",
                    dut_id,
                )
            else:
                error_details = str(response)
                await self._log_runtime(
                    "WARNING",
                    "BaseService",
                    f"{context} Unknown error response format in BaseService._extract_error_details_async: {error_details}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"{context} Full response: {response}",
                    dut_id,
                )
        else:
            error_details = str(response)
            await self._log_runtime(
                "WARNING",
                "BaseService",
                f"{context} Non-dict error response: {error_details}",
                dut_id,
            )

        return error_details

    async def create_redfish_session(self) -> bool:
        """
        Create Redfish session.

        The implementation uses current instance state to create Redfish
        session. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind. It updates ``redfish_auth`` on
        the instance as part of that state transition. Remote I/O uses the
        configured transport policy and returns only after its response or
        failure has been observed. If the function cannot create Redfish
        session, its exception reaches the caller instead of being converted
        into a successful result.

        Returns:
            Whether the redfish session operation succeeds.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to create Redfish session.
        """
        try:
            if self.redfish_session is not None:
                return True  # Session already exists

            await self._log_runtime(
                "INFO", "BaseService", "Testing Redfish session pool"
            )

            # Get connection info (handles HMC transparency)
            connection_info = self.get_redfish_connection_info()

            # Setup authentication for session pool
            username = connection_info["username"]
            password = connection_info["password"]
            if connection_info.get("auth_enabled", True) and username and password:
                self.redfish_auth = encode_basic_auth_header(username, password)
            else:
                self.redfish_auth = None

            # Test the session pool with a simple request
            protocol = "https" if connection_info["use_https"] else "http"
            url_host = format_redfish_url_host(connection_info["host"])
            test_url = (
                f"{protocol}://{url_host}:{connection_info['port']}"
                f"{connection_info['service_root']}"
            )

            # Use the session pool instead of creating a separate session
            if hasattr(self, "dut_manager") and self.dut_manager:
                dut = self.dut_manager.get_dut(self.dut_id)
                if dut and dut.redfish_session_pool:
                    # Test using session pool
                    session_obj = await dut.redfish_session_pool.get_session()
                    if session_obj:
                        try:
                            tls_kwargs = (
                                dut.redfish_tls_request_kwargs(
                                    use_https=connection_info["use_https"]
                                )
                                if hasattr(dut, "redfish_tls_request_kwargs")
                                else {"ssl": dut.redfish_ssl}
                            )
                            async with session_obj["session"].get(
                                test_url,
                                allow_redirects=False,
                                auto_decompress=False,
                                headers=build_redfish_request_headers(
                                    session_obj["auth"],
                                    {"Accept-Encoding": "gzip, deflate"},
                                ),
                                **tls_kwargs,
                            ) as response:
                                if response.status == 200:
                                    await self._log_runtime(
                                        "INFO",
                                        "BaseService",
                                        "Redfish session pool test successful",
                                    )
                                    return True
                                else:
                                    await self._log_runtime(
                                        "ERROR",
                                        "BaseService",
                                        f"Redfish session pool test failed: HTTP {response.status}",
                                    )
                                    return False
                        except Exception as e:
                            raise e
                    else:
                        await self._log_runtime(
                            "ERROR",
                            "BaseService",
                            "Failed to get session from pool for testing",
                        )
                        return await self._create_fallback_session(connection_info)
                else:
                    await self._log_runtime(
                        "WARNING",
                        "BaseService",
                        "Session pool not available, using fallback",
                    )
                    return await self._create_fallback_session(connection_info)
            else:
                await self._log_runtime(
                    "WARNING",
                    "BaseService",
                    "DUT manager not available, using fallback",
                )
                return await self._create_fallback_session(connection_info)

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BaseService",
                f"Failed to create Redfish session: {str(e)}",
            )
            return await self._create_fallback_session(connection_info)

    async def _create_fallback_session(self, connection_info: Dict[str, Any]) -> bool:
        """
        Create fallback session when session pool is not available.

        Get session configuration from DUTManager if available.

        Args:
            connection_info: Mapping supplying fields for fallback session when
                session pool is not available.

        Returns:
            Whether the fallback session when session pool is not available
            operation succeeds.
        """
        try:
            await self._log_runtime(
                "INFO", "BaseService", "Creating fallback Redfish session"
            )

            # Get session configuration from DUTManager if available
            session_config = {}
            if self.dut_manager and hasattr(self.dut_manager, "redfish_session_config"):
                session_config = self.dut_manager.redfish_session_config
            try:
                dut = self.dut_manager.get_dut(self.dut_id)
            except (AttributeError, KeyError, ValueError):
                dut = None
            if dut is None and not connection_info["use_https"]:
                await self._log_runtime(
                    "ERROR",
                    "BaseService",
                    "Fallback Redfish HTTP requires a resolved DUT TLS policy",
                )
                await self.close_redfish_session()
                return False
            if dut is not None:
                tls_policy = dut.redfish_tls_policy
                ssl_parameter = dut.redfish_ssl
            else:
                tls_policy = RedfishTLSPolicy.from_session_config(session_config)
                ssl_parameter = tls_policy.build_ssl_parameter()

            # Resolve transport compatibility before allocating any owned
            # connector/session. A secure default policy must never be
            # silently downgraded merely because the DUT lookup failed.
            protocol = "https" if connection_info["use_https"] else "http"
            url_host = format_redfish_url_host(connection_info["host"])
            request_kwargs = tls_policy.request_kwargs(
                ssl_parameter,
                use_https=connection_info["use_https"],
            )
            test_url = (
                f"{protocol}://{url_host}:{connection_info['port']}"
                f"{connection_info['service_root']}"
            )

            # Create connector with configurable settings (fallback to defaults)
            self.redfish_connector = aiohttp.TCPConnector(
                ssl=ssl_parameter,
                limit=session_config.get(
                    "fallback_connection_pool_limit", 15
                ),  # Configurable fallback connection pool size
                limit_per_host=session_config.get(
                    "fallback_connection_pool_limit_per_host", 6
                ),  # Configurable fallback connections per host
                ttl_dns_cache=session_config.get(
                    "ttl_dns_cache", 300
                ),  # Configurable DNS cache TTL
                use_dns_cache=session_config.get(
                    "use_dns_cache", True
                ),  # Configurable DNS caching
                force_close=session_config.get(
                    "force_close", False
                ),  # Configurable connection reuse
                enable_cleanup_closed=session_config.get(
                    "enable_cleanup_closed", True
                ),  # Configurable cleanup
                keepalive_timeout=session_config.get(
                    "keepalive_timeout", 300
                ),  # Configurable keepalive timeout
            )

            # Create session with persistent settings
            self.redfish_session = aiohttp.ClientSession(
                connector=self.redfish_connector,
                timeout=aiohttp.ClientTimeout(
                    total=session_config.get("session_timeout", 300)
                ),  # Configurable session timeout
                auto_decompress=False,
                headers={
                    "User-Agent": "nvdebug/1.0",
                    "Accept-Encoding": "gzip, deflate",
                },
            )

            # Test the session with a simple request.
            async with self.redfish_session.get(
                test_url,
                allow_redirects=False,
                auto_decompress=False,
                headers=build_redfish_request_headers(
                    self.redfish_auth,
                    {"Accept-Encoding": "gzip, deflate"},
                ),
                **request_kwargs,
            ) as response:
                if response.status == 200:
                    await self._log_runtime(
                        "INFO",
                        "BaseService",
                        "Fallback Redfish session created successfully",
                    )
                    return True
                else:
                    await self._log_runtime(
                        "ERROR",
                        "BaseService",
                        f"Fallback Redfish session test failed: HTTP {response.status}",
                    )
                    await self.close_redfish_session()
                    return False

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BaseService",
                f"Failed to create fallback Redfish session: {str(e)}",
            )
            await self.close_redfish_session()
            return False

    async def close_redfish_session(self) -> None:
        """
        Close Redfish session (like legacy nvdebug logout).

        The implementation uses current instance state to close Redfish session
        (like legacy nvdebug logout). Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind. It
        updates ``redfish_connector``, ``redfish_session``, and ``session`` on
        the instance as part of that state transition. If the function cannot
        close Redfish session (like legacy nvdebug logout), its exception
        reaches the caller instead of being converted into a successful result.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to close Redfish session (like legacy nvdebug logout).
        """
        cleanup_errors: List[BaseException] = []
        if hasattr(self, "redfish_session") and self.redfish_session:
            try:
                await self.redfish_session.close()
                self.redfish_session = None
                await self._log_runtime("INFO", "BaseService", "Redfish session closed")
            except BaseException as error:
                cleanup_errors.append(error)

        if hasattr(self, "redfish_connector") and self.redfish_connector:
            try:
                await self.redfish_connector.close()
                self.redfish_connector = None
            except BaseException as error:
                cleanup_errors.append(error)

        # Also close any other sessions that might exist.
        if hasattr(self, "session") and self.session:
            try:
                await self.session.close()
                self.session = None
                await self._log_runtime("INFO", "BaseService", "General session closed")
            except BaseException as error:
                cleanup_errors.append(error)

        if cleanup_errors:
            try:
                await self._log_runtime(
                    "ERROR",
                    "BaseService",
                    "Error closing Redfish session: one or more owned resources remain",
                )
            except BaseException as logging_error:
                cleanup_errors.append(logging_error)
            raise select_authoritative_exception(cleanup_errors)

    @staticmethod
    def _replace_catalog_service_root(
        uri: str, catalog_root: str, target_root: str
    ) -> str:
        """
        Resolve a URI with the shared service-root and request-path policy.

        Preserve unrelated absolute paths and already-prefixed response links.
        This synchronous compatibility wrapper never starts logging tasks.

        Args:
            uri: Relative resource, absolute path, or HTTP response link.
            catalog_root: Service root authored in the catalog.
            target_root: Effective service root selected by configuration.

        Returns:
            A validated path-only request target retaining its safe query.

        Raises:
            ValueError: If a root or request URI violates Redfish URI policy.
        """

        return rebase_redfish_uri(uri, catalog_root, target_root)

    def normalize_redfish_uri(self, uri: str, ignore_prefix: bool = False) -> str:
        """
        Normalize a Redfish request using configured service-root policy.

        Apply the same path-boundary rules as DUT request normalization. A
        lightweight service without catalog routing policy leaves the URI intact.
        The operation is synchronous and does not require a running event loop.

        Args:
            uri: Relative resource, absolute path, or HTTP response link.
            ignore_prefix: Return the input unchanged when explicitly requested.

        Returns:
            The resolved path and safe query, or the unchanged bypassed input.

        Raises:
            ValueError: If the URI or configured roots violate Redfish URI policy.
        """
        if ignore_prefix:
            return uri

        uri_config_manager = getattr(self.dut_manager, "uri_config_manager", None)
        catalog_root = getattr(uri_config_manager, "service_root", None)
        if not isinstance(catalog_root, str) or not catalog_root:
            # A lightweight service without runtime routing policy cannot infer
            # which absolute prefix should be rewritten.
            return uri
        catalog_root = catalog_root.rstrip("/") or "/"

        return self._replace_catalog_service_root(
            uri, catalog_root, self.redfish_default_prefix
        )

    def reset_redfish_cache(self) -> None:
        """
        Reset Redfish cache (like legacy nvdebug).

        The implementation uses current instance state to reset Redfish cache
        (like legacy nvdebug).
        """
        self.__redfish_cache.clear()
        asyncio.create_task(
            self._log_runtime("INFO", "BaseService", "Redfish cache cleared")
        )

    def get_redfish_cache(self) -> Dict[str, Any]:
        """
        Get Redfish cache (like legacy nvdebug).

        After applying local validation, the function forwards current instance
        state to ``self.__redfish_cache.copy`` and preserves its return and
        exception contract.

        Returns:
            A mapping containing Redfish cache.
        """
        return self.__redfish_cache.copy()

    def _get_cached_response(self, uri: str) -> Optional[Any]:
        """
        Get cached response for URI.

        After applying local validation, the function forwards ``uri`` to
        ``self.__redfish_cache.get`` and preserves its return and exception
        contract.

        Args:
            uri: Validated remote resource identifier used for URI.

        Returns:
            The cached response value selected by the operation, or ``None``
            when the requested value is unavailable.
        """
        return self.__redfish_cache.get(uri)

    def _cache_response(self, uri: str, response: Any) -> None:
        """
        Cache response for URI.

        The implementation uses ``uri`` and ``response`` to cache response for
        URI.

        Args:
            uri: Validated remote resource identifier used for URI.
            response: Transport response governed by the configured
                authentication and trust policy.
        """
        self.__redfish_cache[uri] = response

    @staticmethod
    def _callable_accepts_keyword(function: Any, keyword: str) -> bool:
        """
        Return whether a callable explicitly or generically accepts a keyword.

        The implementation uses ``function`` and ``keyword`` to determine
        whether a callable explicitly or generically accepts a keyword.

        Args:
            function: Function consumed while the function attempts to determine
                whether a callable explicitly or generically accepts a keyword.
            keyword: Text supplied as keyword in the format accepted by this
                function.

        Returns:
            Whether a callable explicitly or generically accepts a keyword.
        """
        try:
            parameters = inspect.signature(function).parameters.values()
        except (TypeError, ValueError):
            return False
        return any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            or (
                parameter.name == keyword
                and parameter.kind
                in {
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                }
            )
            for parameter in parameters
        )

    def _has_cached_collector_inventory(self, dut_id: str, collector_id: str) -> bool:
        """
        Return whether the concrete logger already scanned this collector.

        The implementation uses ``dut_id`` and ``collector_id`` to determine
        whether the concrete logger already scanned this collector.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            Whether the concrete logger already scanned this collector.
        """
        inventories = getattr(self.logger, "_collector_file_inventories", {})
        return (
            isinstance(inventories, dict) and f"{dut_id}:{collector_id}" in inventories
        )

    async def _write_collector_status_with_cached_inventory(
        self,
        collector_id: str,
        dut_id: str,
        status: str,
        reason: str,
        failure_category: Optional[str] = None,
    ) -> None:
        """
        Write status metadata without rewalking an inventory already scanned.

        The implementation uses ``collector_id``, ``dut_id``, ``status``,
        ``reason``, and ``failure_category`` to write status metadata without
        rewalking an inventory already scanned. Success is reported only after
        the owning output boundary has completed its required write or
        publication step. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            status: Text supplied as status in the format accepted by this
                function.
            reason: Text supplied as reason in the format accepted by this
                function.
            failure_category: Optional failure category; ``None`` selects the
                function's default behavior.
        """
        writer = self.logger.write_collector_status_file
        kwargs = {}
        resolved_failure_category = failure_category
        if resolved_failure_category is None:
            outcome = self._classify_collector_outcome(
                {"status": status, "reason": reason}
            )
            if outcome.failure_category is not None:
                resolved_failure_category = outcome.failure_category.value
        if self._has_cached_collector_inventory(
            dut_id, collector_id
        ) and self._callable_accepts_keyword(writer, "refresh_inventory"):
            kwargs["refresh_inventory"] = False
        if self._callable_accepts_keyword(writer, "authoritative_projection"):
            kwargs["authoritative_projection"] = True
        if resolved_failure_category is not None and self._callable_accepts_keyword(
            writer, "failure_category"
        ):
            kwargs["failure_category"] = resolved_failure_category
        await writer(collector_id, dut_id, status, reason, **kwargs)

    async def _log_collector_result(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: str,
        execution_time: float,
        output_files: List[str] = None,
        context: Dict[str, Any] = None,
        discovered_files: Optional[Dict[str, List[str]]] = None,
        failure_category: Optional[str] = None,
    ) -> None:
        """
        Safely log collector results using self.logger if available.

        The implementation uses ``dut_id``, ``collector_id``, ``status``,
        ``reason``, and ``execution_time`` to safely log collector results using
        self.logger if available. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

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
            context: Runtime context carrying state shared across this
                operation.
            discovered_files: Optional discovered files; ``None`` selects the
                function's default behavior.
            failure_category: Optional failure category; ``None`` selects the
                function's default behavior.
        """
        if self.logger:
            try:
                result_logger = self.logger.log_collector_result
                kwargs = {}
                if self._has_cached_collector_inventory(
                    dut_id, collector_id
                ) and self._callable_accepts_keyword(
                    result_logger, "refresh_inventory"
                ):
                    kwargs["refresh_inventory"] = False
                if self._callable_accepts_keyword(
                    result_logger, "authoritative_projection"
                ):
                    kwargs["authoritative_projection"] = True
                if failure_category is not None and self._callable_accepts_keyword(
                    result_logger, "failure_category"
                ):
                    kwargs["failure_category"] = failure_category
                await result_logger(
                    dut_id,
                    collector_id,
                    status,
                    reason,
                    execution_time,
                    output_files or [],
                    context or {},
                    discovered_files or {},
                    **kwargs,
                )
            except Exception as e:
                # Fallback to standard logger if async logger fails
                await self._log_runtime(
                    "ERROR",
                    "BaseService",
                    f"Failed to log collector result via async logger: {e}",
                    dut_id,
                )
        else:
            # Fallback to standard logger if self.logger not available
            # Note: This is a fallback when self.logger is not available, so we can't use async logging
            logger.info(f"Collector {collector_id} on {dut_id}: {status} - {reason}")

    async def _add_execution_summary_entry(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        log_paths: List[str],
        reason: str,
        failure_category: Optional[str] = None,
    ) -> None:
        """
        Project the optional category without changing legacy calls.

        The implementation uses ``dut_id``, ``collector_id``, ``status``,
        ``log_paths``, and ``reason`` to project the optional category without
        changing legacy calls. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            status: Text supplied as status in the format accepted by this
                function.
            log_paths: Filesystem locations processed in caller-provided order.
            reason: Text supplied as reason in the format accepted by this
                function.
            failure_category: Optional failure category; ``None`` selects the
                function's default behavior.
        """

        writer = self.orchestrator.add_execution_summary_entry
        kwargs = {}
        if failure_category is not None and self._callable_accepts_keyword(
            writer, "failure_category"
        ):
            kwargs["failure_category"] = failure_category
        await writer(
            dut_id,
            collector_id,
            status,
            log_paths,
            reason,
            **kwargs,
        )

    async def _write_to_dut_runtime_log(
        self, dut_id: str, level: str, component: str, message: str
    ) -> None:
        """
        Safely write to DUT runtime log using self.logger if available.

        Fallback to standard logger if async logger fails.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            level: Text supplied as level in the format accepted by this
                function.
            component: Text supplied as component in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """
        if self.logger:
            try:
                await self.logger.write_to_dut_runtime_log(
                    dut_id, level, component, message
                )
            except Exception as e:
                # Fallback to standard logger if async logger fails
                logger.error(f"Failed to write to DUT runtime log: {e}")
                logger.info(f"{level} [{component}] {message}")
        else:
            # Fallback to standard logger if self.logger not available
            logger.info(f"{level} [{component}] {message}")

    async def validate_connection(self, dut_id: str) -> Tuple[bool, str]:
        """
        Validate connection to DUT (to be implemented by subclasses).

        The implementation uses ``dut_id`` to validate connection to DUT (to be
        implemented by subclasses). Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A tuple containing the connection-success flag and sanitized
            diagnostic message.

        Raises:
            NotImplementedError: If subclasses must implement
                validate_connection.
        """
        raise NotImplementedError("Subclasses must implement validate_connection")

    def _get_resolved_collector_definition(
        self, dut_id: Optional[str], collector_id: str
    ) -> Dict[str, Any]:
        """
        Return the collector definition with its operator-selected command profile.

        The shared catalog remains unchanged. All execution and timeout consumers
        use this projection so a slower opt-in profile receives its own budget.

        Args:
            dut_id: DUT selecting a profile, or null for tool-level defaults.
            collector_id: Catalog identifier to resolve.

        Returns:
            The selected definition, or an empty mapping for an unknown collector.

        Raises:
            ValueError: If the selected catalog command profile is invalid.
        """

        definition = self.orchestrator.get_all_collectors().get(collector_id, {})
        # Avoid consulting configuration for ordinary, profile-free collectors.
        if not any(iter_command_profile_hooks(definition)):
            return definition
        dut_config = (
            self.dut_manager.get_dut_config(dut_id) or {}
            if dut_id and self.dut_manager
            else {}
        )
        manager = getattr(self.orchestrator, "config_manager", None)
        tool_config = manager.get_tool_config() or {} if manager else {}
        return resolve_collector_command_profiles(definition, dut_config, tool_config)

    async def _get_collector_timeout(
        self, collector_id: str, dut_id: str = None, default_timeout: int = 300
    ) -> int:
        """
        Get timeout from collector definition with fallback to default.

        Uses the unified timeout system that handles timeout_config parameters.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            default_timeout: Maximum duration in seconds allowed for default
                timeout.

        Returns:
            The numeric collector timeout value.
        """
        try:
            # Import here to avoid circular imports
            from ..utils.timeout_config import get_collector_timeout

            # Get collector definition from orchestrator
            collector_def = self._get_resolved_collector_definition(
                dut_id, collector_id
            )

            # Get DUT config for timeout overrides
            dut_config = {}
            if hasattr(self, "dut_manager") and self.dut_manager and dut_id:
                # Get the specific DUT's config for timeout settings
                dut_config = self.dut_manager.get_dut_config(dut_id)
            elif hasattr(self, "dut_manager") and self.dut_manager:
                # Fallback: get the first DUT's config if no specific DUT ID provided
                all_dut_ids = self.dut_manager.get_all_dut_ids()
                if all_dut_ids:
                    dut_config = self.dut_manager.get_dut_config(all_dut_ids[0])

            # Get tool config for timeout fallback. Lightweight service callers
            # may not install a configuration manager, so catalog policy must
            # remain usable without manufacturing a resolution warning.
            tool_config = {}
            config_manager = getattr(self.orchestrator, "config_manager", None)
            if config_manager is not None:
                tool_config = config_manager.get_tool_config() or {}

            # Use the unified timeout system
            timeout = get_collector_timeout(
                collector_id,
                collector_def,
                dut_config,
                default_timeout,
                tool_config,
            )

            dut_info = f" for DUT {dut_id}" if dut_id else ""
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Using timeout {timeout}s for {collector_id}{dut_info} (from unified timeout system)",
                dut_id,
            )
            return timeout

        except Exception as e:
            await self._log_runtime(
                "WARN",
                "BaseService",
                f"Error getting timeout for {collector_id}: {e}, using default {default_timeout}s",
            )
            return default_timeout

    async def _log_effective_timeout_policy(
        self,
        dut_id: Optional[str],
        collector_id: str,
        timeout: int,
        source: str,
    ) -> None:
        """
        Log one operator-visible record for each effective timeout value.

        Command collections can resolve the same policy once per command or
        target. The per-service cache suppresses identical repetitions while
        retaining distinct values, DUTs, and collectors. Only bounded policy
        metadata is emitted; payloads, stdout, stderr, and parser internals
        remain at DEBUG.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            timeout: Effective timeout in seconds enforced by the consuming
                command boundary.
            source: Bounded policy source label describing the winning
                configuration layer.

        Side Effects:
            Adds the resolved policy to the service-local deduplication cache and
            emits one INFO runtime-log record for a previously unseen value.
        """

        bounded_collector_id = _bounded_identifier(collector_id or "unknown")
        bounded_source = _bounded_identifier(source or "unknown")
        policy_key = (
            str(dut_id or ""),
            bounded_collector_id,
            int(timeout),
            bounded_source,
        )
        logged_policies = getattr(self, "_logged_timeout_policies", None)
        if logged_policies is None:
            logged_policies = set()
            self._logged_timeout_policies = logged_policies
        if policy_key in logged_policies:
            return
        logged_policies.add(policy_key)
        await self._log_runtime(
            "INFO",
            "BaseService",
            (
                f"Collector {bounded_collector_id} effective timeout: "
                f"{int(timeout)}s (source={bounded_source})"
            ),
            dut_id,
        )

    def _reset_effective_timeout_policy_logging(
        self,
        dut_id: Optional[str],
        collector_id: str,
    ) -> None:
        """
        Reset timeout-policy deduplication for one collector execution.

        A service instance can outlive many collection runs. Removing only the
        selected DUT/collector keys ensures each new run records its effective
        policy while concurrent collectors retain their own deduplication
        state.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Side Effects:
            Removes cached timeout-policy records for the selected DUT and
            collector from the service-local set.
        """

        bounded_collector_id = _bounded_identifier(collector_id or "unknown")
        selected_key = (str(dut_id or ""), bounded_collector_id)
        self._logged_timeout_policies = {
            policy
            for policy in getattr(self, "_logged_timeout_policies", set())
            if policy[:2] != selected_key
        }

    def _bounded_operator_reason(self, status: Any, reason: Any) -> str:
        """
        Return one bounded and scrubbed reason suitable for operator logs.

        The terminal-outcome sanitizer removes credential-like material,
        collapses control whitespace, and bounds the rendered reason. Reusing
        that projection keeps runtime logs aligned with status and manifest
        surfaces even when the async logger is unavailable and the standard
        logger fallback is used.

        Args:
            status: Outcome status used to prevent failure states from carrying
                an empty or success-only reason.
            reason: Diagnostic value supplied by a collector or transport.

        Returns:
            The bounded, credential-scrubbed operator reason.
        """

        sanitizer = getattr(getattr(self, "logger", None), "sanitizer", None)
        sanitize = getattr(sanitizer, "sanitize", None)
        return sanitize_terminal_collector_reason(
            status,
            reason,
            sanitizer=sanitize if callable(sanitize) else None,
        )

    @staticmethod
    def _get_positive_timeout(value: Any) -> Optional[int]:
        """
        Return a positive integer timeout, or None when unset/invalid.

        The implementation uses ``value`` to produce a positive integer timeout,
        or None when unset/invalid.

        Args:
            value: Value evaluated while performing positive integer timeout, or
                None when unset/invalid.

        Returns:
            The numeric positive timeout value, or ``None`` when the requested
            value is unavailable.
        """
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)) and value > 0:
            timeout = int(value)
            return timeout if timeout > 0 else None
        return None

    def _first_explicit_timeout(
        self,
        timeout_sources: Optional[List[Dict[str, Any]]],
        timeout_keys: Tuple[str, ...],
    ) -> Optional[int]:
        """
        Find the first positive explicit timeout in source/key order.

        The implementation uses ``timeout_sources`` and ``timeout_keys`` to find
        the first positive explicit timeout in source/key order.

        Args:
            timeout_sources: Maximum duration in seconds allowed for timeout
                sources.
            timeout_keys: Maximum duration in seconds allowed for timeout keys.

        Returns:
            The validated ``timeout``, or ``None`` when no value qualifies.
        """
        if not timeout_sources or not timeout_keys:
            return None

        for source in timeout_sources:
            if not isinstance(source, dict):
                continue
            for key in timeout_keys:
                timeout = self._get_positive_timeout(source.get(key))
                if timeout is not None:
                    return timeout
        return None

    async def _resolve_collector_timeout(
        self,
        dut_id: str,
        kwargs: Optional[Dict[str, Any]] = None,
        default_timeout: int = 300,
        explicit_timeout_keys: Tuple[str, ...] = ("timeout",),
        explicit_timeout_sources: Optional[List[Dict[str, Any]]] = None,
        collector_id: Optional[str] = None,
        collector_def: Optional[Dict[str, Any]] = None,
    ) -> int:
        """
        Resolve collector command timeout in one common place.

        Precedence:

        1. DUT/tool override referenced by collector ``timeout_config``.
        2. Explicit hook/command timeout from the bundled collector config.
        3. Collector-level ``timeout`` from the bundled collector config.
        4. Caller fallback default.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Optional kwargs; ``None`` selects the function's default
                behavior.
            default_timeout: Maximum duration in seconds allowed for default
                timeout.
            explicit_timeout_keys: Maximum duration in seconds allowed for
                explicit timeout keys.
            explicit_timeout_sources: Maximum duration in seconds allowed for
                explicit timeout sources.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collector_def: Optional collector def; ``None`` selects the
                function's default behavior.

        Returns:
            The numeric collector timeout value.
        """
        kwargs = kwargs or {}
        resolved_collector_id = (
            collector_id
            or kwargs.get("collector_id")
            or self._get_current_collector_id()
            or ""
        )

        explicit_sources = explicit_timeout_sources
        if explicit_sources is None:
            explicit_sources = [kwargs]

        explicit_timeout = self._first_explicit_timeout(
            explicit_sources, explicit_timeout_keys
        )

        try:
            from ..utils.timeout_config import get_collector_timeout

            resolved_collector_def = collector_def or kwargs.get("collector_def") or {}
            if not isinstance(resolved_collector_def, dict):
                resolved_collector_def = {}
            if (
                not resolved_collector_def
                and self.orchestrator is not None
                and resolved_collector_id
            ):
                all_collectors = self.orchestrator.get_all_collectors()
                if isinstance(all_collectors, dict):
                    resolved_collector_def = self._get_resolved_collector_definition(
                        dut_id, resolved_collector_id
                    )

            dut_config = {}
            if self.dut_manager is not None and dut_id:
                dut_config = self.dut_manager.get_dut_config(dut_id) or {}
            elif self.dut_manager is not None:
                all_dut_ids = self.dut_manager.get_all_dut_ids()
                if all_dut_ids:
                    dut_config = self.dut_manager.get_dut_config(all_dut_ids[0]) or {}

            tool_config = {}
            if self.orchestrator is not None and getattr(
                self.orchestrator, "config_manager", None
            ):
                tool_config = self.orchestrator.config_manager.get_tool_config() or {}

            # Probe only timeout_config overrides by removing the bundled
            # collector-level timeout and using a non-positive sentinel default.
            override_probe_def = dict(resolved_collector_def or {})
            override_probe_def.pop("timeout", None)
            configured_override = get_collector_timeout(
                resolved_collector_id,
                override_probe_def,
                dut_config,
                -1,
                tool_config,
            )
            if configured_override > 0:
                await self._log_effective_timeout_policy(
                    dut_id,
                    resolved_collector_id,
                    configured_override,
                    "timeout_config_override",
                )
                return configured_override

            if explicit_timeout is not None:
                await self._log_effective_timeout_policy(
                    dut_id,
                    resolved_collector_id,
                    explicit_timeout,
                    "hook_or_command",
                )
                return explicit_timeout

            timeout = get_collector_timeout(
                resolved_collector_id,
                resolved_collector_def,
                dut_config,
                default_timeout,
                tool_config,
            )
            await self._log_effective_timeout_policy(
                dut_id,
                resolved_collector_id,
                timeout,
                "collector_or_default",
            )
            return timeout
        except Exception as e:
            await self._log_runtime(
                "WARN",
                "BaseService",
                (
                    f"Error resolving timeout for {resolved_collector_id}: {e}, "
                    f"using default {default_timeout}s"
                ),
                dut_id,
            )
            return explicit_timeout or default_timeout

    async def _end_collector_timing(
        self,
        dut_id: str,
        collector_id: str,
        timing_status: str,
        collector_status: Optional[str] = None,
        reason: str = "",
        failure_category: Optional[str] = None,
    ) -> None:
        """
        Close timing and refresh status metadata with the frozen wall time.

        finalize_collector writes status.json while the collector timer is still
        running. Rewrite it after closing the timer so the standalone status
        artifact and final timing.json expose the same authoritative wall-clock
        duration.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            timing_status: Text supplied as timing status in the format accepted
                by this function.
            collector_status: Optional collector status; ``None`` selects the
                function's default behavior.
            reason: Text supplied as reason in the format accepted by this
                function.
            failure_category: Optional failure category; ``None`` selects the
                function's default behavior.
        """
        if not self.timing_manager:
            return

        self.timing_manager.end_collector(collector_id, timing_status)
        if collector_status is None or not self.logger:
            return

        # finalize_collector writes status.json while the collector timer is
        # still running. Rewrite it after closing the timer so the standalone
        # status artifact and final timing.json expose the same authoritative
        # wall-clock duration.
        try:
            await self._write_collector_status_with_cached_inventory(
                collector_id,
                dut_id,
                collector_status,
                reason,
                failure_category,
            )
        except Exception as exc:
            await self._log_runtime(
                "WARN",
                "BaseService",
                f"Failed to refresh final timing for {collector_id}: {exc}",
                dut_id,
            )

    async def _acknowledge_request_capture_publications(
        self,
        dut_id: str,
        collector_id: str,
        *,
        owner_token: Any = _CURRENT_REQUEST_CAPTURE_OWNER,
        rollback_on_failure: bool = True,
    ) -> None:
        """
        Acknowledge pending capture publications through the recorder.

        The implementation uses ``dut_id``, ``collector_id``, ``owner_token``,
        and ``rollback_on_failure`` to acknowledge pending capture publications
        through the recorder. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            owner_token: Owner token consumed while the function attempts to
                acknowledge pending capture publications through the recorder.
            rollback_on_failure: Whether rollback on failure is enabled or
                required for this operation.
        """
        await self._collector_capture_recorder.acknowledge_request_capture_publications(
            dut_id,
            collector_id,
            owner_token=owner_token,
            rollback_on_failure=rollback_on_failure,
        )

    async def _rollback_request_capture_publications(
        self,
        dut_id: str,
        collector_id: str,
        *,
        owner_token: Any = _CURRENT_REQUEST_CAPTURE_OWNER,
    ) -> None:
        """
        Rollback pending capture publications through the recorder.

        The implementation uses ``dut_id``, ``collector_id``, and
        ``owner_token`` to rollback pending capture publications through the
        recorder. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            owner_token: Owner token consumed while the function attempts to
                rollback pending capture publications through the recorder.
        """
        await self._collector_capture_recorder.rollback_request_capture_publications(
            dut_id,
            collector_id,
            owner_token=owner_token,
        )

    async def _resolve_runtime_budget(
        self,
        dut_id: str,
        collector_id: str,
    ) -> ResolvedCollectorBudget:
        """
        Resolve the catalog budget without changing legacy timeout semantics.

        After applying local validation, the function forwards ``dut_id`` and
        ``collector_id`` to ``resolve_collector_budget`` and preserves its
        return and exception contract. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            A ``ResolvedCollectorBudget`` representing runtime budget.

        Raises:
            CollectorBudgetError: If collector ``collector_id`` has no explicit
                runtime budget.
        """

        collector_def: Dict[str, Any] = {}
        if self.orchestrator is not None and hasattr(
            self.orchestrator, "get_all_collectors"
        ):
            all_collectors = self.orchestrator.get_all_collectors()
            if isinstance(all_collectors, dict):
                candidate = all_collectors.get(collector_id, {})
                if isinstance(candidate, dict):
                    collector_def = self._get_resolved_collector_definition(
                        dut_id, collector_id
                    )
        if collector_def.get("runtime_budget") in (None, "", {}):
            raise CollectorBudgetError(
                f"collector {collector_id} has no explicit runtime budget"
            )
        runtime_config = (
            await resolve_effective_runtime_config(
                self.orchestrator,
                self.dut_manager,
                dut_id,
            )
            if runtime_budget_requires_runtime_config(collector_def)
            else {}
        )
        return resolve_collector_budget(
            collector_id,
            collector_def,
            runtime_config=runtime_config,
        )

    def _current_runtime_budget(
        self,
        collector_id: Optional[str] = None,
    ) -> Optional[ResolvedCollectorBudget]:
        """
        Return the task-local budget for this collector execution.

        The implementation uses ``collector_id`` to produce the task-local
        budget for this collector execution.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The validated ``budget``, or ``None`` when no value qualifies.
        """

        budget = _collector_budget_context.get()
        if budget is None:
            return None
        if collector_id is not None and budget.collector_id != str(collector_id):
            return None
        return budget

    @staticmethod
    def _collector_wall_timeout_reason(budget: ResolvedCollectorBudget) -> str:
        """
        Return the collector wall timeout reason.

        The implementation uses ``budget`` to produce the collector wall timeout
        reason.

        Args:
            budget: Budget object whose ``wall_timeout_seconds`` state is read
                while performing collector wall timeout reason.

        Returns:
            The canonical collector wall timeout reason text.
        """
        wall_seconds = budget.wall_timeout_seconds or 0.0
        return (
            f"Collector wall budget exhausted after {wall_seconds:g}s; "
            "operation, retry, and remote-task budgets are reported separately"
        )

    @staticmethod
    def _invalidate_rolled_back_capture_metadata(
        context: Dict[str, Any],
    ) -> set[str]:
        """
        Stop advertising a publication that durable status did not adopt.

        The implementation uses ``context`` to stop advertising a publication
        that durable status did not adopt.

        Args:
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            The validated ``rolled_back_paths``.
        """

        capture_entries: List[Dict[str, Any]] = []
        primary_capture = context.get("request_response_capture")
        if isinstance(primary_capture, dict):
            capture_entries.append(primary_capture)
        request_logs = context.get("request_response_logs")
        if isinstance(request_logs, dict):
            capture_entries.extend(
                entry for entry in request_logs.values() if isinstance(entry, dict)
            )

        rolled_back_paths: set[str] = set()
        for capture in capture_entries:
            if capture.get("published") is not True:
                continue
            artifact_path = capture.pop("artifact_path", None)
            if isinstance(artifact_path, str) and artifact_path:
                rolled_back_paths.add(artifact_path)
            capture["published"] = False
            for field in ("size_bytes", "sha256", "sanitization_policy_id"):
                capture.pop(field, None)

        diagnostic_files = context.get("diagnostic_files")
        if isinstance(diagnostic_files, list) and rolled_back_paths:
            context["diagnostic_files"] = [
                path for path in diagnostic_files if str(path) not in rolled_back_paths
            ]
        return rolled_back_paths

    def _scrub_rolled_back_capture_claims(
        self,
        dut_id: str,
        collector_id: str,
        context: Dict[str, Any],
    ) -> set[str]:
        """
        Scrub returned and logger-cached claims before corrective status.

        The implementation uses ``dut_id``, ``collector_id``, and ``context`` to
        scrub returned and logger-cached claims before corrective status.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            The validated ``rolled_back_paths``.
        """

        rolled_back_paths = self._invalidate_rolled_back_capture_metadata(context)
        result_key = f"{dut_id}:{collector_id}"
        collector_results = getattr(self.logger, "collector_results", None)
        cached_result = (
            collector_results.get(result_key)
            if isinstance(collector_results, dict)
            else None
        )
        if isinstance(cached_result, dict):
            cached_context = cached_result.get("context")
            if isinstance(cached_context, dict):
                rolled_back_paths.update(
                    self._invalidate_rolled_back_capture_metadata(cached_context)
                )

            reconcile = getattr(self.logger, "reconcile_collector_file_inventory", None)
            if callable(reconcile):
                clean_inventory = reconcile(
                    str(dut_id),
                    str(collector_id),
                    [],
                    refresh=True,
                )
            else:
                clean_inventory = {
                    field: [
                        path
                        for path in cached_result.get(field, [])
                        if str(path) not in rolled_back_paths
                    ]
                    for field in (
                        "output_files",
                        "diagnostic_files",
                        "error_files",
                        "all_files",
                    )
                }
            if isinstance(clean_inventory, dict):
                for field in (
                    "output_files",
                    "diagnostic_files",
                    "error_files",
                    "all_files",
                ):
                    values = clean_inventory.get(field, [])
                    cached_result[field] = (
                        [path for path in values if str(path) not in rolled_back_paths]
                        if isinstance(values, list)
                        else []
                    )
                cached_result["discovered_files"] = self._group_inventory_files(
                    cached_result["all_files"]
                )

        inventories = getattr(self.logger, "_collector_file_inventories", None)
        cached_inventory = (
            inventories.get(result_key) if isinstance(inventories, dict) else None
        )
        if isinstance(cached_inventory, dict):
            for field in (
                "output_files",
                "diagnostic_files",
                "error_files",
                "all_files",
            ):
                values = cached_inventory.get(field, [])
                if isinstance(values, list):
                    cached_inventory[field] = [
                        path for path in values if str(path) not in rolled_back_paths
                    ]
        return rolled_back_paths

    def _collector_budget_run_is_current(
        self,
        dut_id: str,
        collector_id: str,
    ) -> bool:
        """
        Reject late publication from a cancellation-suppressing old run.

        After applying local validation, the function forwards ``dut_id`` and
        ``collector_id`` to ``self._collector_budget_token_is_current`` and
        preserves its return and exception contract. Every required invariant is
        checked before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            Whether the late publication from a cancellation-suppressing old run
            operation succeeds.
        """

        token = _collector_budget_run_context.get()
        return self._collector_budget_token_is_current(dut_id, collector_id, token)

    def _collector_budget_token_is_current(
        self,
        dut_id: str,
        collector_id: str,
        token: Optional[object],
    ) -> bool:
        """
        Return whether one internal run owner can still publish.

        The implementation uses ``dut_id``, ``collector_id``, and ``token`` to
        determine whether one internal run owner can still publish.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            token: Sensitive value supplied through the approved input boundary
                and never logged.

        Returns:
            Whether one internal run owner can still publish.
        """

        if token is None:
            return True
        active_runs = self._active_collector_budget_runs.get(
            (str(dut_id), str(collector_id))
        )
        return isinstance(active_runs, set) and token in active_runs

    def _request_capture_publication_owner(
        self,
        dut_id: str,
        collector_id: str,
        owner_token: Any = _CURRENT_REQUEST_CAPTURE_OWNER,
    ) -> Tuple[Tuple[Any, ...], Optional[object]]:
        """
        Resolve an internal publication key without exposing its run token.

        The implementation uses ``dut_id``, ``collector_id``, and
        ``owner_token`` to resolve an internal publication key without exposing
        its run token.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            owner_token: Owner token consumed while the function attempts to
                resolve an internal publication key without exposing its run
                token.

        Returns:
            A tuple containing ``tuple[any,...]`` and ``optional[object]`` in
            that order.
        """

        resolved_owner = (
            _collector_budget_run_context.get()
            if owner_token is _CURRENT_REQUEST_CAPTURE_OWNER
            else owner_token
        )
        compatibility_key: Tuple[Any, ...] = (
            str(dut_id),
            str(collector_id),
        )
        if resolved_owner is None:
            return compatibility_key, None
        return (*compatibility_key, resolved_owner), resolved_owner

    def _register_collector_budget_run(
        self,
        run_key: Tuple[str, str],
        token: object,
    ) -> None:
        """
        Register the sole explicit-budget execution for a collector key.

        The implementation uses ``run_key`` and ``token`` to register the sole
        explicit-budget execution for a collector key. If the function cannot
        register the sole explicit-budget execution for a collector key, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            run_key: Stable run key used for lookup and operator-facing
                diagnostics.
            token: Sensitive value supplied through the approved input boundary
                and never logged.

        Raises:
            RuntimeError: If collector budget ownership registry is malformed.
            _DuplicateCollectorBudgetRunError: If duplicate explicit-budget
                collector execution rejected.
        """

        active_runs = self._active_collector_budget_runs.get(run_key)
        if active_runs is None:
            active_runs = set()
            self._active_collector_budget_runs[run_key] = active_runs
        elif not isinstance(active_runs, set):
            raise RuntimeError("collector budget ownership registry is malformed")
        elif active_runs:
            raise _DuplicateCollectorBudgetRunError(
                "duplicate explicit-budget collector execution rejected"
            )
        active_runs.add(token)

    def _claim_collector_status_transaction(
        self,
        dut_id: str,
        collector_id: str,
    ) -> _CollectorStatusTransactionState:
        """
        Claim one shared state before awaiting its lock acquisition.

        The implementation uses ``dut_id`` and ``collector_id`` to claim one
        shared state before awaiting its lock acquisition. If the function
        cannot claim one shared state before awaiting its lock acquisition, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The validated ``state``.

        Raises:
            RuntimeError: If collector status transaction registry is malformed.
        """

        key = (str(dut_id), str(collector_id))
        state = self._collector_status_transaction_locks.setdefault(
            key, _CollectorStatusTransactionState()
        )
        if not isinstance(state, _CollectorStatusTransactionState):
            raise RuntimeError("collector status transaction registry is malformed")
        state.users += 1
        return state

    def _prune_collector_status_transaction_lock(
        self,
        dut_id: str,
        collector_id: str,
    ) -> None:
        """
        Drop one terminal, uncontended status lock without retaining owners.

        The implementation uses ``dut_id`` and ``collector_id`` to drop one
        terminal, uncontended status lock without retaining owners.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
        """

        key = (str(dut_id), str(collector_id))
        active_runs = self._active_collector_budget_runs.get(key)
        if isinstance(active_runs, set) and active_runs:
            return
        state = self._collector_status_transaction_locks.get(key)
        if not isinstance(state, _CollectorStatusTransactionState):
            return
        if state.users != 0:
            return
        if self._collector_status_transaction_locks.get(key) is state:
            self._collector_status_transaction_locks.pop(key, None)

    async def _run_collector_status_transaction(
        self,
        dut_id: str,
        collector_id: str,
        operation: Callable[[], Awaitable[Any]],
    ) -> Any:
        """
        Serialize timeout status ownership across every service instance.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, and ``operation`` to ``operation`` and preserves its
        return and exception contract. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind. Cleanup
        in the ``finally`` path runs for successful, failed, and cancelled
        execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            operation: Operation consumed while the function attempts to
                serialize timeout status ownership across every service
                instance.

        Returns:
            The run collector status transaction value selected by the
            operation.
        """

        state = self._claim_collector_status_transaction(dut_id, collector_id)
        try:
            async with state.lock:
                return await operation()
        finally:
            state.users -= 1
            self._prune_collector_status_transaction_lock(dut_id, collector_id)

    def _discard_collector_budget_run(
        self,
        run_key: Tuple[str, str],
        token: object,
    ) -> None:
        """
        Discard only the caller-owned token and prune an empty key.

        The implementation uses ``run_key`` and ``token`` to discard only the
        caller-owned token and prune an empty key.

        Args:
            run_key: Stable run key used for lookup and operator-facing
                diagnostics.
            token: Sensitive value supplied through the approved input boundary
                and never logged.
        """

        active_runs = self._active_collector_budget_runs.get(run_key)
        if not isinstance(active_runs, set):
            return
        active_runs.discard(token)
        if (
            not active_runs
            and self._active_collector_budget_runs.get(run_key) is active_runs
        ):
            self._active_collector_budget_runs.pop(run_key, None)

    def _replace_collector_budget_run(
        self,
        run_key: Tuple[str, str],
        old_token: object,
        new_token: object,
    ) -> None:
        """
        Transfer one execution's ownership without disturbing peer runs.

        The implementation uses ``run_key``, ``old_token``, and ``new_token`` to
        transfer one execution's ownership without disturbing peer runs. If the
        function cannot transfer one execution's ownership without disturbing
        peer runs, its exception reaches the caller instead of being converted
        into a successful result.

        Args:
            run_key: Stable run key used for lookup and operator-facing
                diagnostics.
            old_token: Old token consumed while the function attempts to
                transfer one execution's ownership without disturbing peer runs.
            new_token: New token consumed while the function attempts to
                transfer one execution's ownership without disturbing peer runs.

        Raises:
            RuntimeError: If collector budget run lost ownership before timeout.
        """

        active_runs = self._active_collector_budget_runs.get(run_key)
        if not isinstance(active_runs, set) or old_token not in active_runs:
            raise RuntimeError("collector budget run lost ownership before timeout")
        active_runs.remove(old_token)
        active_runs.add(new_token)

    @staticmethod
    def _consume_owned_task(task: asyncio.Task[Any]) -> None:
        """
        Consume owned task.

        The implementation uses ``task`` to consume owned task.

        Args:
            task: Task object whose ``result`` state is read while performing
                consume owned task.
        """
        try:
            task.result()
        except (asyncio.CancelledError, Exception):
            return

    async def _cancel_owned_collector_task(
        self,
        task: asyncio.Task[Any],
    ) -> bool:
        """
        Cancel and observe a collector within the public cleanup grace.

        The implementation uses ``task`` to cancel and observe a collector
        within the public cleanup grace. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            task: Task object whose ``add_done_callback``, ``cancel``, and
                ``done`` state is read while performing cancel and observe a
                collector within the public cleanup grace.

        Returns:
            Whether the cancel and observe a collector within the public cleanup
            grace operation succeeds.
        """

        if task.done():
            self._consume_owned_task(task)
            return True
        task.cancel()
        try:
            completed, _ = await asyncio.wait(
                {task},
                timeout=COLLECTOR_CANCELLATION_GRACE_SECONDS,
            )
        except BaseException:
            task.add_done_callback(self._consume_owned_task)
            raise
        if task in completed:
            self._consume_owned_task(task)
            return True
        task.add_done_callback(self._consume_owned_task)
        return False

    async def _bounded_timeout_support(
        self,
        awaitable: Any,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> Tuple[bool, Any]:
        """
        Own one timeout-support coroutine without allowing an unbounded tail.

        The implementation uses ``awaitable`` and ``timeout_seconds`` to own one
        timeout-support coroutine without allowing an unbounded tail. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. If the function cannot own one
        timeout-support coroutine without allowing an unbounded tail, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            awaitable: Awaitable consumed while the function attempts to own one
                timeout-support coroutine without allowing an unbounded tail.
            timeout_seconds: Maximum duration in seconds allowed for timeout
                seconds.

        Returns:
            A tuple containing the completion flag and completed awaitable
            value.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to own one timeout-support coroutine without allowing
                an unbounded tail.
        """

        if timeout_seconds is None:
            timeout_seconds = COLLECTOR_TIMEOUT_SUPPORT_SECONDS
        timeout_seconds = max(0.0, float(timeout_seconds))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds
        cancellation_reserve = min(1.0, timeout_seconds / 2.0)
        task = asyncio.create_task(awaitable)
        try:
            completed, _ = await asyncio.wait(
                {task},
                timeout=max(0.0, timeout_seconds - cancellation_reserve),
            )
        except BaseException as control_flow:
            task.cancel()
            try:
                completed, _ = await asyncio.wait(
                    {task},
                    timeout=max(0.0, deadline - loop.time()),
                )
            except BaseException:
                completed = set()
            if task in completed:
                self._consume_owned_task(task)
            else:
                task.add_done_callback(self._consume_owned_task)
            raise control_flow
        if task in completed:
            try:
                result = task.result()
            except asyncio.CancelledError:
                return False, None
            except Exception:
                return False, None
            return True, result
        task.cancel()
        completed, _ = await asyncio.wait(
            {task},
            timeout=max(0.0, deadline - loop.time()),
        )
        if task in completed:
            self._consume_owned_task(task)
        else:
            task.add_done_callback(self._consume_owned_task)
        return False, None

    async def _collector_wall_timeout_result(
        self,
        dut_id: str,
        collector_id: str,
        collection_level: str,
        budget: ResolvedCollectorBudget,
        *,
        wall_started: float,
        cancellation_settled: bool,
        timed_out_run_token: object,
    ) -> Dict[str, Any]:
        """
        Publish one truthful, bounded terminal result for wall exhaustion.

        The implementation uses ``dut_id``, ``collector_id``,
        ``collection_level``, ``budget``, and ``wall_started`` to publish one
        truthful, bounded terminal result for wall exhaustion. Success is
        reported only after the owning output boundary has completed its
        required write or publication step. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            budget: Budget object whose ``max_retries``, ``to_dict``, and
                ``wall_timeout_seconds`` state is read while performing one
                truthful, bounded terminal result for wall exhaustion.
            wall_started: Numeric wall started used while the operation performs
                bounded accounting.
            cancellation_settled: Whether cancellation settled is enabled or
                required for this operation.
            timed_out_run_token: Timed out run token consumed while the function
                attempts to publish one truthful, bounded terminal result for
                wall exhaustion.

        Returns:
            A mapping containing the ``success``, ``status``, ``reason``,
            ``context``, and ``execution_time`` fields.
        """

        loop = asyncio.get_running_loop()
        timeout_finalizer_owner = _collector_budget_run_context.get()
        reason = self._collector_wall_timeout_reason(budget)
        context: Dict[str, Any] = {
            "dut_id": dut_id,
            "collector_id": collector_id,
            "collection_level": collection_level,
            "service_name": self.service_name,
            "status": "error",
            "reason": reason,
            "timeout_classification": "collector_wall_budget",
            "configured_retry_count": budget.max_retries,
            "collector_budget": budget.to_dict(),
            "collector_budget_observation": {
                "actual_wall_seconds": max(0.0, loop.time() - wall_started),
                "collector_wall_budget_seconds": budget.wall_timeout_seconds,
                "collector_wall_status": "exhausted",
                "wall_timeout_triggered": True,
                "cancellation_settled_within_grace": cancellation_settled,
                "cancellation_grace_seconds": COLLECTOR_CANCELLATION_GRACE_SECONDS,
                "terminal_cause": "collector_wall_budget_exhausted",
            },
        }
        observation = context["collector_budget_observation"]
        rollback_completed, _ = await self._bounded_timeout_support(
            self._rollback_request_capture_publications(
                dut_id,
                collector_id,
                owner_token=timed_out_run_token,
            )
        )

        async def finalize_timeout_owner() -> Dict[str, Any]:
            """
            Finalize timeout owner.

            After applying local validation, the function forwards current
            instance state to ``self._run_collector_status_transaction`` and
            preserves its return and exception contract. Owned asynchronous work
            is awaited before return, so completion does not leave an unobserved
            task behind.

            Returns:
                A mapping containing finalize timeout owner.
            """
            return await self._run_collector_status_transaction(
                dut_id,
                collector_id,
                lambda: self.finalize_collector(
                    dut_id,
                    collector_id,
                    "error",
                    reason,
                    execution_time=max(0.0, loop.time() - wall_started),
                    detailed_context=context,
                    _request_capture_source_owner=timed_out_run_token,
                ),
            )

        (
            finalization_completed,
            finalization_result,
        ) = await self._bounded_timeout_support(finalize_timeout_owner())

        # Assemble the complete success-path status before its last write. The
        # values are optimistic only within this transaction; every failed
        # write/ack path below overwrites them in one corrective status write.
        observation.update(
            {
                "capture_rollback_completed": rollback_completed,
                "timeout_finalization_completed": finalization_completed,
                "settlement_tail_seconds": max(
                    0.0,
                    loop.time()
                    - wall_started
                    - float(budget.wall_timeout_seconds or 0.0),
                ),
                "timeout_status_refresh_completed": finalization_completed,
                "timeout_capture_adoption_completed": finalization_completed,
                "timeout_capture_rollback_completed": None,
                "timeout_capture_scrub_completed": None,
                "timeout_corrected_status_write_completed": None,
                "terminal_status_refresh_completed": finalization_completed,
            }
        )

        timeout_transaction_progress: Dict[str, Any] = {
            "active_stage": "status_write",
            "status_write_completed": False,
            "acknowledgement_completed": False,
        }

        async def write_and_acknowledge_timeout_status() -> Dict[str, Any]:
            """
            Write and acknowledge timeout status.

            After applying local validation, the function forwards current
            instance state to ``self._run_collector_status_transaction`` and
            preserves its return and exception contract. Success is reported
            only after the owning output boundary has completed its required
            write or publication step. Owned asynchronous work is awaited before
            return, so completion does not leave an unobserved task behind.

            Returns:
                A mapping containing write and acknowledge timeout status.
            """

            async def write_and_acknowledge_owned() -> Dict[str, Any]:
                """
                Write and acknowledge owned.

                The implementation uses current instance state to write and
                acknowledge owned. Success is reported only after the owning
                output boundary has completed its required write or publication
                step. Owned asynchronous work is awaited before return, so
                completion does not leave an unobserved task behind.

                Returns:
                    A mapping containing the ``failed_stage`` and ``error``
                    fields.
                """
                try:
                    await self._write_collector_status_with_cached_inventory(
                        collector_id,
                        dut_id,
                        "error",
                        reason,
                        "timeout",
                    )
                except (asyncio.CancelledError, Exception) as status_error:
                    return {
                        **timeout_transaction_progress,
                        "failed_stage": "status_write",
                        "error": status_error,
                    }

                timeout_transaction_progress["status_write_completed"] = True
                timeout_transaction_progress["active_stage"] = "acknowledgement"
                try:
                    await self._acknowledge_request_capture_publications(
                        dut_id,
                        collector_id,
                        owner_token=timeout_finalizer_owner,
                        rollback_on_failure=False,
                    )
                except (
                    asyncio.CancelledError,
                    Exception,
                ) as acknowledgement_error:
                    return {
                        **timeout_transaction_progress,
                        "failed_stage": "acknowledgement",
                        "error": acknowledgement_error,
                    }

                timeout_transaction_progress["acknowledgement_completed"] = True
                timeout_transaction_progress["active_stage"] = None
                return {
                    **timeout_transaction_progress,
                    "failed_stage": None,
                    "error": None,
                }

            return await self._run_collector_status_transaction(
                dut_id,
                collector_id,
                write_and_acknowledge_owned,
            )

        timeout_status_refresh_completed = False
        capture_adoption_completed = False
        timeout_transaction_failed_stage: Optional[str] = None
        if finalization_completed:
            (
                timeout_transaction_completed,
                timeout_transaction_result,
            ) = await self._bounded_timeout_support(
                write_and_acknowledge_timeout_status()
            )
            if timeout_transaction_completed and isinstance(
                timeout_transaction_result, dict
            ):
                timeout_status_refresh_completed = bool(
                    timeout_transaction_result.get("status_write_completed")
                )
                capture_adoption_completed = bool(
                    timeout_transaction_result.get("acknowledgement_completed")
                )
                failed_stage = timeout_transaction_result.get("failed_stage")
                if isinstance(failed_stage, str):
                    timeout_transaction_failed_stage = failed_stage
            else:
                timeout_status_refresh_completed = bool(
                    timeout_transaction_progress.get("status_write_completed")
                )
                capture_adoption_completed = bool(
                    timeout_transaction_progress.get("acknowledgement_completed")
                )
                active_stage = timeout_transaction_progress.get("active_stage")
                timeout_transaction_failed_stage = (
                    str(active_stage) if active_stage is not None else "transaction"
                )

        rolled_back_capture_paths: set[str] = set()
        if not (
            finalization_completed
            and timeout_status_refresh_completed
            and capture_adoption_completed
        ):
            # Invalidate the timeout finalizer before rollback. A finalizer that
            # suppresses cancellation can then only roll back its own late
            # publication at the synchronous post-publication handoff.
            if timeout_finalizer_owner is not None:
                self._discard_collector_budget_run(
                    (str(dut_id), str(collector_id)),
                    timeout_finalizer_owner,
                )
            timeout_capture_rollback_completed, _ = await self._bounded_timeout_support(
                self._rollback_request_capture_publications(
                    dut_id,
                    collector_id,
                    owner_token=timeout_finalizer_owner,
                )
            )
            failure_stage = (
                "finalization"
                if not finalization_completed
                else (
                    timeout_transaction_failed_stage
                    or (
                        "status_write"
                        if not timeout_status_refresh_completed
                        else "acknowledgement"
                    )
                )
            )
            observation.update(
                {
                    "timeout_status_refresh_completed": (
                        timeout_status_refresh_completed
                    ),
                    "timeout_capture_adoption_completed": False,
                    "timeout_capture_rollback_completed": (
                        timeout_capture_rollback_completed
                    ),
                    "timeout_capture_scrub_completed": False,
                    "timeout_corrected_status_write_completed": False,
                    "terminal_status_refresh_completed": False,
                    "timeout_status_transaction_failed_stage": failure_stage,
                }
            )
            try:
                rolled_back_capture_paths.update(
                    self._invalidate_rolled_back_capture_metadata(context)
                )
            except Exception:
                pass

            async def scrub_and_write_corrected_status() -> Dict[str, Any]:
                """
                Return the scrub and write corrected status.

                After applying local validation, the function forwards current
                instance state to ``self._run_collector_status_transaction`` and
                preserves its return and exception contract. Owned asynchronous
                work is awaited before return, so completion does not leave an
                unobserved task behind.

                Returns:
                    A mapping containing scrub and write corrected status.
                """
                scrubbed_paths: set[str] = set()

                async def correct_owned() -> Dict[str, Any]:
                    """
                    Return the correct owned.

                    The implementation uses current instance state to produce
                    the correct owned. Owned asynchronous work is awaited before
                    return, so completion does not leave an unobserved task
                    behind.

                    Returns:
                        A mapping containing the ``paths``, ``scrub_completed``,
                        ``write_completed``, and ``error`` fields.
                    """
                    try:
                        scrubbed_paths.update(
                            self._scrub_rolled_back_capture_claims(
                                str(dut_id),
                                str(collector_id),
                                context,
                            )
                        )
                    except (asyncio.CancelledError, Exception) as scrub_error:
                        observation["timeout_capture_scrub_completed"] = False
                        observation["timeout_corrected_status_write_completed"] = False
                        observation["terminal_status_refresh_completed"] = False
                        return {
                            "paths": scrubbed_paths,
                            "scrub_completed": False,
                            "write_completed": False,
                            "error": scrub_error,
                        }

                    observation["timeout_capture_scrub_completed"] = True
                    observation["timeout_corrected_status_write_completed"] = True
                    observation["terminal_status_refresh_completed"] = True
                    try:
                        await self._write_collector_status_with_cached_inventory(
                            collector_id,
                            dut_id,
                            "error",
                            reason,
                            "timeout",
                        )
                    except (asyncio.CancelledError, Exception) as write_error:
                        observation["timeout_corrected_status_write_completed"] = False
                        observation["terminal_status_refresh_completed"] = False
                        return {
                            "paths": scrubbed_paths,
                            "scrub_completed": True,
                            "write_completed": False,
                            "error": write_error,
                        }
                    return {
                        "paths": scrubbed_paths,
                        "scrub_completed": True,
                        "write_completed": True,
                        "error": None,
                    }

                return await self._run_collector_status_transaction(
                    dut_id,
                    collector_id,
                    correct_owned,
                )

            (
                correction_completed,
                correction_result,
            ) = await self._bounded_timeout_support(scrub_and_write_corrected_status())
            if correction_completed and isinstance(correction_result, dict):
                rolled_back_capture_paths.update(correction_result.get("paths", ()))
            elif not correction_completed:
                # No successful bounded corrective write occurred, so these
                # returned observations may be corrected without rewriting a
                # durable status artifact.
                observation["timeout_capture_scrub_completed"] = False
                observation["timeout_corrected_status_write_completed"] = False
                observation["terminal_status_refresh_completed"] = False
        finalization_result = (
            finalization_result if isinstance(finalization_result, dict) else {}
        )

        def retained_files(field: str) -> List[str]:
            """
            Return the retained files.

            The implementation uses ``field`` to produce the retained files.

            Args:
                field: Text supplied as field in the format accepted by this
                    function.

            Returns:
                The retained files returned in operation-defined order.
            """
            values = finalization_result.get(field, [])
            return [
                str(path)
                for path in values
                if str(path) not in rolled_back_capture_paths
            ]

        discovered_files = {
            str(group): [
                str(path)
                for path in paths
                if str(path) not in rolled_back_capture_paths
            ]
            for group, paths in finalization_result.get("discovered_files", {}).items()
            if isinstance(paths, list)
        }
        discovered_files = {
            group: paths for group, paths in discovered_files.items() if paths
        }
        return {
            "success": False,
            "status": "error",
            "reason": reason,
            "context": context,
            "execution_time": max(0.0, loop.time() - wall_started),
            "output_files": retained_files("output_files"),
            "diagnostic_files": retained_files("diagnostic_files"),
            "error_files": retained_files("error_files"),
            "all_files": retained_files("all_files"),
            "discovered_files": discovered_files,
        }

    async def execute_collector(
        self, dut_id: str, collector_id: str, collection_level: str = "L1"
    ) -> Dict[str, Any]:
        """
        Execute a collector with task-local DUT and collector identity.

        Preserve the historical execution path when catalog lookup itself is
        unhealthy; the existing collector boundary owns that error.

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
        dut_token = _dut_context.set(dut_id)
        collector_token = _collector_context.set(collector_id)
        collector_definition: Dict[str, Any] = {}
        try:
            if self.orchestrator is not None and hasattr(
                self.orchestrator, "get_all_collectors"
            ):
                all_collectors = self.orchestrator.get_all_collectors()
                if isinstance(all_collectors, dict):
                    candidate = all_collectors.get(collector_id, {})
                    if isinstance(candidate, dict):
                        collector_definition = candidate
        except Exception:
            # Preserve the historical execution path when catalog lookup itself
            # is unhealthy; the existing collector boundary owns that error.
            collector_definition = {}
        if collector_definition.get("runtime_budget") in (None, "", {}):
            try:
                raw_result = await self._execute_collector_in_context(
                    dut_id, collector_id, collection_level
                )
                return self._classify_collector_outcome(raw_result).to_legacy_result()
            finally:
                _collector_context.reset(collector_token)
                _dut_context.reset(dut_token)

        run = object()
        run_key = (str(dut_id), str(collector_id))
        try:
            self._register_collector_budget_run(run_key, run)
        except _DuplicateCollectorBudgetRunError:
            _collector_context.reset(collector_token)
            _dut_context.reset(dut_token)
            reason = (
                "Concurrent explicit-budget execution for this collector is already "
                "active; duplicate rejected before execution"
            )
            return {
                "success": False,
                "status": "error",
                "reason": reason,
                "context": {
                    "dut_id": str(dut_id),
                    "collector_id": str(collector_id),
                    "collection_level": collection_level,
                    "service_name": self.service_name,
                    "duplicate_execution_rejected": True,
                },
                "execution_time": 0.0,
                "output_files": [],
                "diagnostic_files": [],
                "error_files": [],
                "all_files": [],
                "discovered_files": {},
            }
        except BaseException:
            _collector_context.reset(collector_token)
            _dut_context.reset(dut_token)
            raise
        run_context_token = _collector_budget_run_context.set(run)
        budget_context_token = None
        child: Optional[asyncio.Task[Any]] = None
        timeout_tombstone: Optional[object] = None
        try:
            budget = await self._resolve_runtime_budget(dut_id, collector_id)
            budget_context_token = _collector_budget_context.set(budget)
            wall_started = asyncio.get_running_loop().time()
            if budget.source == "catalog.runtime_budget":
                await self._log_runtime(
                    "INFO",
                    "BaseService",
                    (
                        f"Collector {collector_id} runtime budget: operation="
                        f"{budget.operation_timeout_seconds:g}s, retries="
                        f"{budget.max_retries}, projected_wall="
                        f"{budget.projected_wall_seconds:g}s, wall="
                        f"{budget.wall_timeout_seconds}, enforced="
                        f"{budget.enforce_wall_timeout}"
                    ),
                    dut_id,
                )

            if budget.enforce_wall_timeout and budget.wall_timeout_seconds is not None:
                child = asyncio.create_task(
                    self._execute_collector_in_context(
                        dut_id,
                        collector_id,
                        collection_level,
                    )
                )
                try:
                    completed, _ = await asyncio.wait(
                        {child},
                        timeout=budget.wall_timeout_seconds,
                    )
                except BaseException:
                    await self._cancel_owned_collector_task(child)
                    raise
                elapsed = asyncio.get_running_loop().time() - wall_started
                if child in completed and elapsed <= budget.wall_timeout_seconds:
                    raw_result = child.result()
                else:
                    if child in completed:
                        self._consume_owned_task(child)
                    timeout_tombstone = object()
                    self._replace_collector_budget_run(
                        run_key,
                        run,
                        timeout_tombstone,
                    )
                    _collector_budget_run_context.set(timeout_tombstone)
                    cancellation_settled = await self._cancel_owned_collector_task(
                        child
                    )
                    raw_result = await self._collector_wall_timeout_result(
                        dut_id,
                        collector_id,
                        collection_level,
                        budget,
                        wall_started=wall_started,
                        cancellation_settled=cancellation_settled,
                        timed_out_run_token=run,
                    )
                    if not cancellation_settled:
                        stale_run = run

                        def clear_stale_run(_: asyncio.Task[Any]) -> None:
                            """
                            Clear stale run.

                            The implementation uses ``_`` to clear stale run.

                            Args:
                                _: Operation consumed while the function
                                    attempts to clear stale run.
                            """
                            self._discard_collector_budget_run(run_key, stale_run)

                        child.add_done_callback(clear_stale_run)
            else:
                raw_result = await self._execute_collector_in_context(
                    dut_id,
                    collector_id,
                    collection_level,
                )

            result = self._classify_collector_outcome(raw_result).to_legacy_result()
            if budget.source == "catalog.runtime_budget":
                result = dict(result)
                result_context = (
                    result.get("context", {})
                    if isinstance(result.get("context"), dict)
                    else {}
                )
                result_context.setdefault("collector_budget", budget.to_dict())
                result_context.setdefault("configured_retry_count", budget.max_retries)
                budget_observation = result_context.get("collector_budget_observation")
                if not isinstance(budget_observation, dict):
                    budget_observation = {}
                    result_context["collector_budget_observation"] = budget_observation
                if not budget_observation.get("wall_timeout_triggered", False):
                    budget_observation.update(
                        {
                            "actual_wall_seconds": max(
                                0.0,
                                asyncio.get_running_loop().time() - wall_started,
                            ),
                            "collector_wall_budget_seconds": (
                                budget.wall_timeout_seconds
                            ),
                            "collector_wall_status": (
                                "within_budget"
                                if budget.enforce_wall_timeout
                                else "observed_only"
                            ),
                            "wall_timeout_triggered": False,
                            "terminal_cause": None,
                        }
                    )
                result["context"] = result_context
                if not budget_observation.get("wall_timeout_triggered", False):
                    status_refresh_completed, _ = await self._bounded_timeout_support(
                        self._write_collector_status_with_cached_inventory(
                            collector_id,
                            dut_id,
                            str(result.get("status", "error")),
                            str(result.get("reason", "")),
                            result.get("failure_category"),
                        )
                    )
                    budget_observation["terminal_status_refresh_completed"] = (
                        status_refresh_completed
                    )
            return result
        finally:
            if budget_context_token is not None:
                _collector_budget_context.reset(budget_context_token)
            _collector_budget_run_context.reset(run_context_token)
            self._discard_collector_budget_run(run_key, run)
            if timeout_tombstone is not None:
                self._discard_collector_budget_run(run_key, timeout_tombstone)
            self._prune_collector_status_transaction_lock(dut_id, collector_id)
            _collector_context.reset(collector_token)
            _dut_context.reset(dut_token)

    def _classify_collector_outcome(
        self,
        result: Dict[str, Any],
        *,
        stage: Optional[str] = None,
        exception: Optional[BaseException] = None,
    ) -> CollectorOutcome:
        """
        Interpret a service result without changing its dictionary contract.

        After applying local validation, the function forwards ``result``,
        ``stage``, and ``exception`` to ``classify_collector_outcome`` and
        preserves its return and exception contract.

        Args:
            result: Mapping supplying fields for interpret a service result
                without changing its dictionary contract.
            stage: Optional stage; ``None`` selects the function's default
                behavior.
            exception: Exception associated with the operation's failure path.

        Returns:
            A ``CollectorOutcome`` representing classify collector outcome.
        """

        return classify_collector_outcome(
            result,
            service_name=self.service_name,
            stage=stage,
            exception=exception,
        )

    def _project_terminal_outcome_context(
        self,
        context: Dict[str, Any],
        status: str,
        reason: str,
        *,
        exception: Optional[BaseException] = None,
    ) -> Dict[str, Any]:
        """
        Return one sanitized context aligned to the final canonical outcome.

        Stage-specific dictionaries remain unchanged as execution evidence. A
        shallow copy prevents a terminal policy correction from mutating the
        stage result object supplied by the collector. The optional category is
        computed only after the final status/reason correction and is removed
        for success and state-only outcomes, so stale provisional
        classifications cannot leak into public metadata.

        Args:
            context: Runtime context carrying state shared across this
                operation.
            status: Text supplied as status in the format accepted by this
                function.
            reason: Text supplied as reason in the format accepted by this
                function.
            exception: Exception associated with the operation's failure path.

        Returns:
            The validated ``projected``.
        """

        projected = dict(context) if isinstance(context, dict) else {}
        sanitizer = getattr(getattr(self, "logger", None), "sanitizer", None)
        sanitize = getattr(sanitizer, "sanitize", None)
        outcome_details = project_collector_outcome_details(
            projected.get("outcome_details"),
            sanitizer=sanitize if callable(sanitize) else None,
        )
        if status in {"degraded", "partial", "error"} and outcome_details is not None:
            projected["outcome_details"] = outcome_details
        else:
            projected.pop("outcome_details", None)
        classification_context = dict(projected)
        classification_context.pop("failure_category", None)
        reason = sanitize_terminal_collector_reason(
            status,
            reason,
            sanitizer=sanitize if callable(sanitize) else None,
        )
        # The incoming value may describe a provisional result. Recompute from
        # the final state and bounded diagnostic evidence instead of inheriting
        # its category. Keep the prior diagnostic reason as classification-only
        # evidence when orchestration replaces it with a generated summary.
        outcome = self._classify_collector_outcome(
            {
                "status": status,
                "reason": reason,
                "context": classification_context,
            },
            exception=exception,
        )
        projected["status"] = status
        projected["reason"] = reason
        projected.pop("failure_category", None)
        if outcome.failure_category is not None:
            projected["failure_category"] = outcome.failure_category.value
        return projected

    async def _execute_collector_in_context(
        self, dut_id: str, collector_id: str, collection_level: str = "L1"
    ) -> Dict[str, Any]:
        """
        Execute a collector through the extracted lifecycle runner.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, and ``collection_level`` to
        ``self._collector_lifecycle_runner.execute_collector`` and preserves its
        return and exception contract. Terminal status is emitted only after
        collector through the extracted lifecycle runner and its owned cleanup
        have completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collection_level: Text supplied as collection level in the format
                accepted by this function.

        Returns:
            A mapping containing execute collector in context.
        """
        return await self._collector_lifecycle_runner.execute_collector(
            dut_id, collector_id, collection_level
        )

    async def _check_collector_dependencies(
        self, collector_id: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Check dependencies for a collector using DUT-aware dependency checker.

        The implementation uses ``collector_id`` and ``context`` to check
        dependencies for a collector using DUT-aware dependency checker. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            A mapping containing the ``status``, ``missing_required``,
            ``missing_optional``, ``warnings``, and ``platform`` fields.

        Raises:
            RuntimeError: Internally when a required executable probe cannot
                determine availability. This boundary converts it to status
                ``error`` so the lifecycle does not misreport missing software
                or proceed with collection.
        """
        dut_id = context.get("dut_id", "unknown")
        try:
            collector_def = context["collector_def"]
            dependencies = collector_def.get("dependencies", {})

            # Get platform information using BaseboardManager
            platform = "default"
            baseboard = ""
            baseboard_manager = None
            if self.dut_manager:
                dut = self.dut_manager.get_dut(dut_id)
                if dut and hasattr(dut, "config"):
                    baseboard = dut.config.get("baseboard", "")
                    if baseboard:
                        # Use BaseboardManager to get platform type
                        baseboard_manager = self.dut_manager._get_baseboard_manager()
                        if baseboard_manager:
                            platform = (
                                baseboard_manager.get_baseboard_type(baseboard)
                                or "default"
                            )

            # Check required dependencies
            required_deps = dependencies.get("required", [])
            required_results = []
            missing_required = []

            for dep in required_deps:
                if isinstance(dep, dict):
                    dep_type = dep.get("type")
                    dep_name = dep.get("name")
                    checked_locally = False
                    check_local = dep.get(
                        "check_local", False
                    )  # New flag for local checking
                    config_key_name = dep.get("config_key")
                    config_default = dep.get("config_default")

                    if config_key_name:
                        config_value = self._get_dut_config_value(
                            dut_id, config_key_name
                        )
                        if config_value is None and config_default is not None:
                            config_value = config_default

                        if config_value is not None:
                            dep_name = str(config_value)
                        else:
                            await self._log_runtime(
                                "WARN",
                                "BaseService",
                                f"[{collector_id}] Required dependency '{dep_type}' "
                                f"requested config '{config_key_name}' but no value was found; "
                                f"falling back to '{dep_name}'",
                                dut_id,
                            )

                    if dep_type and dep_name:
                        # Use DUT-aware dependency checker based on type
                        if dep_type == "command":
                            # For IPMI commands, check locally since they run on the local system
                            if "alternatives" in dep or "use_sudo" in dep:
                                checked_locally = (
                                    check_local or collector_id.startswith("I")
                                )
                                result = await self.dependency_checker.check_command_requirement(
                                    {**dep, "name": dep_name},
                                    dut_id=dut_id,
                                    use_bmc=collector_id.startswith("S"),
                                    check_local=checked_locally,
                                )
                            elif check_local or collector_id.startswith(
                                "I"
                            ):  # IPMI collectors start with "I"
                                checked_locally = True
                                result = self.dependency_checker.check_command(
                                    dep_name, check_local=True
                                )
                            else:
                                # For SSH collectors, use BMC connection; for others, use host connection
                                use_bmc = collector_id.startswith(
                                    "S"
                                )  # SSH collectors start with "S"
                                result = (
                                    await self.dependency_checker._check_command_on_dut(
                                        dut_id, dep_name, use_bmc=use_bmc
                                    )
                                )
                        elif dep_type == "service":
                            # For now, fall back to local check for services
                            checked_locally = True
                            result = self.dependency_checker.check_service(dep_name)
                        elif dep_type == "file":
                            # For SSH collectors, check files on the BMC
                            if self.dut_manager:
                                use_bmc = collector_id.startswith(
                                    "S"
                                )  # SSH collectors start with "S"
                                result = (
                                    await self.dependency_checker._check_file_on_dut(
                                        dut_id, dep_name, use_bmc=use_bmc
                                    )
                                )
                            else:
                                # Fallback to local check if no DUT manager
                                checked_locally = True
                                result = self.dependency_checker.check_file(dep_name)
                        elif dep_type == "command_version":
                            # Check command version on appropriate target
                            min_version = dep.get("min_version")
                            version_cmd = dep.get(
                                "version_cmd", f"{dep_name} --version"
                            )

                            # For IPMI commands, check locally since they run on the local system
                            if check_local or collector_id.startswith("I"):
                                checked_locally = True
                                result = (
                                    await self.dependency_checker.check_command_version(
                                        dep_name, min_version, version_cmd
                                    )
                                )
                            else:
                                # For SSH collectors, use BMC connection; for Host collectors, use host connection
                                # Let execute_host_command/execute_bmc_command handle local vs remote routing
                                use_bmc = collector_id.startswith(
                                    "S"
                                )  # SSH collectors start with "S"
                                result = (
                                    await self.dependency_checker.check_command_version(
                                        dep_name,
                                        min_version,
                                        version_cmd,
                                        dut_id=dut_id,
                                        use_bmc=use_bmc,
                                    )
                                )
                        elif dep_type == "platform_service":
                            # Use platform-specific service checking with fallback logic
                            result = (
                                await self.dependency_checker.check_platform_service(
                                    dep, platform, dut_id
                                )
                            )
                        else:
                            # Fallback to regular dependency checker for unknown types
                            result = await self.dependency_checker.check_dependencies(
                                collector_id=collector_id,
                                collector_name=collector_def.get("name", collector_id),
                                dependencies={"required": [dep]},
                                platform=platform,
                            )
                            if hasattr(result, "missing_required"):
                                if result.missing_required:
                                    return {
                                        "status": "fail",
                                        "missing_required": result.missing_required,
                                        "missing_optional": result.missing_optional,
                                        "warnings": result.warnings,
                                        "platform": platform,
                                    }
                                continue
                            else:
                                # Handle case where check_dependencies returns a different format
                                return {
                                    "status": "fail",
                                    "missing_required": [
                                        f"Unsupported dependency type: {dep_type}"
                                    ],
                                    "missing_optional": [],
                                    "warnings": [],
                                    "platform": platform,
                                }

                        if getattr(result, "probe_failed", False) is True:
                            raise RuntimeError(
                                f"Dependency probe failed for {dep_name}: {result.error_message}"
                            )

                        # Store the result
                        required_results.append(
                            {
                                "name": dep_name,
                                "type": dep_type,
                                "available": result.available,
                                "error_message": result.error_message,
                                "install_instructions": dep.get("install_instructions"),
                            }
                        )

                        if not result.available:
                            # Adjust error message based on where the check was performed
                            if checked_locally:
                                error_msg = f"Required dependency {dep_name} ({dep_type}) not available on local system: {result.error_message}"
                            else:
                                error_msg = f"Required dependency {dep_name} ({dep_type}) not available on DUT {dut_id}: {result.error_message}"

                            # Surface the catalog's authored remediation so the
                            # report tells the user how to fix the skip.
                            install_instructions = dep.get("install_instructions")
                            if install_instructions:
                                error_msg += f" Remediation: {install_instructions}"

                            missing_required.append(error_msg)
                else:
                    # Simple string dependency (assumed to be a command)
                    # For IPMI collectors, check locally since they run on the local system
                    if collector_id.startswith("I"):  # IPMI collectors start with "I"
                        result = self.dependency_checker.check_command(
                            dep, check_local=True
                        )
                    else:
                        # For SSH collectors, use BMC connection; for others, use host connection
                        use_bmc = collector_id.startswith(
                            "S"
                        )  # SSH collectors start with "S"
                        result = await self.dependency_checker._check_command_on_dut(
                            dut_id, dep, use_bmc=use_bmc
                        )

                    if getattr(result, "probe_failed", False) is True:
                        raise RuntimeError(
                            f"Dependency probe failed for {dep}: {result.error_message}"
                        )

                    # Store the result
                    required_results.append(
                        {
                            "name": dep,
                            "type": "command",
                            "available": result.available,
                            "error_message": result.error_message,
                            "install_instructions": None,
                        }
                    )

                    if not result.available:
                        # Adjust error message based on where the check was performed
                        if collector_id.startswith("I"):
                            error_msg = f"Required command {dep} not available on local system: {result.error_message}"
                        else:
                            error_msg = f"Required command {dep} not available on DUT {dut_id}: {result.error_message}"

                        missing_required.append(error_msg)

            # Check optional dependencies
            optional_deps = dependencies.get("optional", [])
            optional_results = []
            missing_optional = []

            for dep in optional_deps:
                if isinstance(dep, dict):
                    dep_type = dep.get("type", "command")
                    dep_name = dep.get("name")
                    check_local = dep.get("check_local", False)
                    checked_locally = False

                    if dep_name:
                        # Use similar logic as required dependencies
                        if dep_type == "command":
                            if "alternatives" in dep or "use_sudo" in dep:
                                checked_locally = (
                                    check_local or collector_id.startswith("I")
                                )
                                result = await self.dependency_checker.check_command_requirement(
                                    dep,
                                    dut_id=dut_id,
                                    use_bmc=collector_id.startswith("S"),
                                    check_local=checked_locally,
                                )
                            elif check_local or collector_id.startswith("I"):
                                checked_locally = True
                                result = self.dependency_checker.check_command(
                                    dep_name, check_local=True
                                )
                            else:
                                use_bmc = collector_id.startswith("S")
                                result = (
                                    await self.dependency_checker._check_command_on_dut(
                                        dut_id, dep_name, use_bmc=use_bmc
                                    )
                                )
                        elif dep_type == "file":
                            if collector_id.startswith("S"):
                                result = (
                                    await self.dependency_checker._check_file_on_dut(
                                        dut_id, dep_name
                                    )
                                )
                            else:
                                checked_locally = True
                                result = self.dependency_checker.check_file(dep_name)
                        else:
                            checked_locally = True
                            result = self.dependency_checker.check_service(dep_name)

                        # Store the result
                        optional_results.append(
                            {
                                "name": dep_name,
                                "type": dep_type,
                                "available": result.available,
                                "error_message": result.error_message,
                                "install_instructions": dep.get("install_instructions"),
                            }
                        )

                        if not result.available:
                            if checked_locally:
                                error_msg = f"Optional dependency {dep_name} ({dep_type}) not available on local system: {result.error_message}"
                            else:
                                error_msg = f"Optional dependency {dep_name} ({dep_type}) not available on DUT {dut_id}: {result.error_message}"
                            missing_optional.append(error_msg)
                else:
                    # Simple string dependency
                    if collector_id.startswith("I"):
                        result = self.dependency_checker.check_command(
                            dep, check_local=True
                        )
                    else:
                        use_bmc = collector_id.startswith("S")
                        result = await self.dependency_checker._check_command_on_dut(
                            dut_id, dep, use_bmc=use_bmc
                        )

                    # Store the result
                    optional_results.append(
                        {
                            "name": dep,
                            "type": "command",
                            "available": result.available,
                            "error_message": result.error_message,
                            "install_instructions": None,
                        }
                    )

                    if not result.available:
                        if collector_id.startswith("I"):
                            error_msg = f"Optional command {dep} not available on local system: {result.error_message}"
                        else:
                            error_msg = f"Optional command {dep} not available on DUT {dut_id}: {result.error_message}"
                        missing_optional.append(error_msg)

            # Return detailed results
            return {
                "status": "pass" if not missing_required else "fail",
                "missing_required": missing_required,
                "missing_optional": missing_optional,
                "warnings": [],
                "platform": platform,
                "required_dependencies": required_results,
                "optional_dependencies": optional_results,
            }

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "BaseService",
                f"Error checking dependencies for {collector_id}: {e}",
            )
            return {
                "status": "error",
                "missing_required": [f"Error: {e}"],
                "missing_optional": [],
                "warnings": [],
                "platform": "unknown",
            }

    async def _write_collector_dependency_metadata(
        self, collector_id: str, dependency_result: Dict[str, Any], dut_id: str
    ) -> None:
        """
        Write collector dependency metadata.

        The implementation uses ``collector_id``, ``dependency_result``, and
        ``dut_id`` to write collector dependency metadata. Success is reported
        only after the owning output boundary has completed its required write
        or publication step. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dependency_result: Mapping supplying fields for collector dependency
                metadata.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        try:
            if not self.logger:
                return

            # Get collector definition for name
            collector_def = self.orchestrator.get_all_collectors().get(collector_id)
            collector_name = (
                collector_def.get("name", collector_id)
                if collector_def
                else collector_id
            )

            # Convert dependency result to the format expected by write_dependency_metadata
            dependency_data = {
                collector_id: {
                    "collector_id": collector_id,
                    "collector_name": collector_name,
                    "all_required_available": dependency_result["status"] == "pass",
                    "required_dependencies": dependency_result.get(
                        "required_dependencies", []
                    ),
                    "optional_dependencies": dependency_result.get(
                        "optional_dependencies", []
                    ),
                    "missing_required": dependency_result.get("missing_required", []),
                    "missing_optional": dependency_result.get("missing_optional", []),
                    "warnings": dependency_result.get("warnings", []),
                }
            }

            # Write to DUT-specific metadata directory
            await self.logger.write_dependency_metadata(dependency_data, dut_id)

            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Wrote dependency metadata for collector {collector_id} to DUT {dut_id}",
                dut_id,
            )

        except Exception as e:
            await self._log_runtime(
                "WARNING",
                "BaseService",
                f"Failed to write dependency metadata for collector {collector_id}: {e}",
                dut_id,
            )

    async def _execute_stage(
        self,
        stage: str,
        collector_def: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute one stage through the extracted lifecycle runner.

        After applying local validation, the function forwards ``stage``,
        ``collector_def``, and ``context`` to
        ``self._collector_lifecycle_runner.execute_stage`` and preserves its
        return and exception contract. Terminal status is emitted only after one
        stage through the extracted lifecycle runner and its owned cleanup have
        completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            stage: Text supplied as stage in the format accepted by this
                function.
            collector_def: Mapping supplying fields for one stage through the
                extracted lifecycle runner.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            A mapping containing execute stage.
        """
        return await self._collector_lifecycle_runner.execute_stage(
            stage, collector_def, context
        )

    async def _execute_hook(
        self, hook: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute one hook through the extracted lifecycle runner.

        After applying local validation, the function forwards ``hook`` and
        ``context`` to ``self._collector_lifecycle_runner.execute_hook`` and
        preserves its return and exception contract. Terminal status is emitted
        only after one hook through the extracted lifecycle runner and its owned
        cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            hook: Callable invoked at the hook boundary.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            A mapping containing execute hook.
        """
        return await self._collector_lifecycle_runner.execute_hook(hook, context)

    def _attach_capture_metadata(
        self,
        target_result: Dict[str, Any],
        capture_result: Tuple[str, Dict[str, Any]],
        method_name: str,
        current_stage: Optional[str],
        context: Dict[str, Any],
    ) -> None:
        """
        Attach capture metadata through the capture recorder.

        The implementation uses ``target_result``, ``capture_result``,
        ``method_name``, ``current_stage``, and ``context`` to attach capture
        metadata through the capture recorder.

        Args:
            target_result: Mapping supplying fields for attach capture metadata
                through the capture recorder.
            capture_result: Mapping supplying fields for attach capture metadata
                through the capture recorder.
            method_name: Stable method name used for lookup and operator-facing
                diagnostics.
            current_stage: Text supplied as current stage in the format accepted
                by this function.
            context: Runtime context carrying state shared across this
                operation.
        """
        self._collector_capture_recorder.attach_capture_metadata(
            target_result,
            capture_result,
            method_name,
            current_stage,
            context,
        )

    def _sanitize_for_capture(self, value: Any, depth: int = 4) -> Any:
        """
        Return the historical capture-safe value through the recorder.

        After applying local validation, the function forwards ``value`` and
        ``depth`` to ``_collector_capture_recorder.sanitize_for_capture`` and
        preserves its return and exception contract.

        Args:
            value: Value evaluated while performing historical capture-safe
                value through the recorder.
            depth: Numeric depth used while the operation performs bounded
                accounting.

        Returns:
            The historical capture-safe value through the recorder.
        """
        return self._collector_capture_recorder.sanitize_for_capture(value, depth)

    async def _begin_request_response_capture(
        self,
        context: Dict[str, Any],
        method_name: str,
        options: Dict[str, Any],
    ) -> Optional[asyncio.Task]:
        """
        Begin generic request/response capture through the recorder.

        After applying local validation, the function forwards ``context``,
        ``method_name``, and ``options`` to
        ``_collector_capture_recorder.begin_request_response_capture`` and
        preserves its return and exception contract. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            context: Runtime context carrying state shared across this
                operation.
            method_name: Stable method name used for lookup and operator-facing
                diagnostics.
            options: Mapping supplying fields for begin generic request/response
                capture through the recorder.

        Returns:
            The owned ``Task`` that performs begin request response capture, or
            ``None`` when the requested value is unavailable.
        """
        return await self._collector_capture_recorder.begin_request_response_capture(
            context,
            method_name,
            options,
        )

    async def _record_request_response(
        self,
        request_info: Dict[str, Any],
        response_info: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record one request/response pair through the capture recorder.

        The implementation uses ``request_info``, ``response_info``, and
        ``metadata`` to record one request/response pair through the capture
        recorder. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            request_info: Mapping supplying fields for record one
                request/response pair through the capture recorder.
            response_info: Optional response info; ``None`` selects the
                function's default behavior.
            metadata: Optional metadata; ``None`` selects the function's default
                behavior.
        """
        await self._collector_capture_recorder.record_request_response(
            request_info,
            response_info,
            metadata,
        )

    async def _finalize_request_response_capture(
        self,
        token: Optional[asyncio.Task],
        context: Dict[str, Any],
        method_name: str,
        options: Dict[str, Any],
        hook_result: Optional[Dict[str, Any]],
        error: Optional[BaseException],
    ) -> Optional[Tuple[Optional[str], Dict[str, Any]]]:
        """
        Finalize generic request/response capture through the recorder.

        After applying local validation, the function forwards ``token``,
        ``context``, ``method_name``, ``options``, and ``hook_result`` to
        ``_collector_capture_recorder.finalize_request_response_capture`` and
        preserves its return and exception contract. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            token: Sensitive value supplied through the approved input boundary
                and never logged.
            context: Runtime context carrying state shared across this
                operation.
            method_name: Stable method name used for lookup and operator-facing
                diagnostics.
            options: Mapping supplying fields for finalize generic
                request/response capture through the recorder.
            hook_result: Callable invoked at the hook result boundary.
            error: Exception or failure detail associated with the operation.

        Returns:
            A tuple containing the fields that represent finalize request
            response capture, or ``None`` when the requested value is
            unavailable.
        """
        return await self._collector_capture_recorder.finalize_request_response_capture(
            token,
            context,
            method_name,
            options,
            hook_result,
            error,
        )

    async def _get_output_directory(self, dut_id: str) -> str:
        """
        Get the output directory through the output-store boundary.

        After applying local validation, the function forwards ``dut_id`` to
        ``_get_output_directory`` and preserves its return and exception
        contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The canonical output directory text.
        """
        return await self._output_store()._get_output_directory(dut_id)

    async def _resolve_collector_directory_variables(
        self, hook_params: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Resolve collector paths through the output-store boundary.

        After applying local validation, the function forwards ``hook_params``
        and ``context`` to ``_resolve_collector_directory_variables`` and
        preserves its return and exception contract. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            hook_params: Callable invoked at the hook params boundary.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            A mapping containing collector directory variables.
        """
        return await self._output_store()._resolve_collector_directory_variables(
            hook_params, context
        )

    @staticmethod
    def _is_diagnostic_capture_file(
        file_path: str,
        *,
        bundle_root: Optional[Path] = None,
    ) -> bool:
        """
        Classify diagnostic metadata through the output-store boundary.

        After applying local validation, the function forwards ``file_path`` to
        ``CollectorOutputStore._is_diagnostic_capture_file`` and preserves its
        return and exception contract.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            bundle_root: Optional run root used to exclude unrelated ancestor
                directory names from artifact-role classification.

        Returns:
            Whether the classify diagnostic metadata through the output-store
            boundary operation succeeds.
        """
        return (
            classify_artifact_path(file_path, bundle_root=bundle_root)
            is ArtifactRole.DIAGNOSTIC
        )

    @staticmethod
    def _is_error_artifact_file(
        file_path: str,
        *,
        bundle_root: Optional[Path] = None,
    ) -> bool:
        """
        Classify error evidence through the output-store boundary.

        After applying local validation, the function forwards ``file_path`` to
        ``CollectorOutputStore._is_error_artifact_file`` and preserves its
        return and exception contract.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            bundle_root: Optional run root used to exclude unrelated ancestor
                directory names from artifact-role classification.

        Returns:
            Whether the classify error evidence through the output-store
            boundary operation succeeds.
        """
        return (
            classify_artifact_path(file_path, bundle_root=bundle_root)
            is ArtifactRole.ERROR
        )

    @staticmethod
    def _group_inventory_files(files: List[str]) -> Dict[str, List[str]]:
        """
        Group inventory paths through the output-store boundary.

        After applying local validation, the function forwards ``files`` to
        ``CollectorOutputStore._group_inventory_files`` and preserves its return
        and exception contract.

        Args:
            files: Filesystem locations processed in caller-provided order.

        Returns:
            A mapping containing group inventory files.
        """
        return CollectorOutputStore._group_inventory_files(files)

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
        Reconcile output inventory through the output-store boundary.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``known_files``, ``discovered_files``, and
        ``refresh_inventory`` to ``_reconcile_collector_file_inventory`` and
        preserves its return and exception contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            known_files: Entries supplied as ``known_files`` without
                transferring container ownership.
            discovered_files: Mapping supplying fields for reconcile output
                inventory through the output-store boundary.
            refresh_inventory: Whether refresh inventory is enabled or required
                for this operation.

        Returns:
            A tuple containing the fields that represent reconcile collector
            file inventory.
        """
        return self._output_store()._reconcile_collector_file_inventory(
            dut_id,
            collector_id,
            known_files,
            discovered_files,
            refresh_inventory=refresh_inventory,
        )

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
        Finalize collector outputs through the output-store boundary.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``status``, ``reason``, and ``execution_time`` to
        ``finalize_collector`` and preserves its return and exception contract.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

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
            A mapping containing finalize collector.
        """
        return await self._output_store().finalize_collector(
            dut_id,
            collector_id,
            status,
            reason,
            execution_time=execution_time,
            output_files=output_files,
            discovered_files=discovered_files,
            detailed_context=detailed_context,
            **kwargs,
        )

    def _get_collector_group(self, collector_id: str) -> str:
        """
        Resolve the collector group through the output-store boundary.

        After applying local validation, the function forwards ``collector_id``
        to ``_get_collector_group`` and preserves its return and exception
        contract.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The canonical collector group text.
        """
        return self._output_store()._get_collector_group(collector_id)

    async def _write_collector_output(
        self,
        dut_id: str,
        collector_id: str,
        content: str,
        filename: str = "output.txt",
    ) -> Optional[str]:
        """
        Write collector output through the output-store boundary.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``content``, and ``filename`` to
        ``_write_collector_output`` and preserves its return and exception
        contract. Success is reported only after the owning output boundary has
        completed its required write or publication step. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind.

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
        return await self._output_store()._write_collector_output(
            dut_id, collector_id, content, filename
        )

    async def _log_collector_error(
        self,
        dut_id: str,
        collector_id: str,
        error_message: str,
        context: dict = None,
    ) -> str:
        """
        Publish error evidence through the output-store boundary.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``error_message``, and ``context`` to
        ``_log_collector_error`` and preserves its return and exception
        contract. Success is reported only after the owning output boundary has
        completed its required write or publication step. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind.

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
        return await self._output_store()._log_collector_error(
            dut_id, collector_id, error_message, context
        )

    async def _create_error_log_file(
        self,
        dut_id: str,
        collector_id: str,
        error_message: str,
        context: dict = None,
    ) -> str:
        """
        Create error evidence through the output-store boundary.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``error_message``, and ``context`` to
        ``_create_error_log_file`` and preserves its return and exception
        contract. Owned asynchronous work is awaited before return, so
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
        return await self._output_store()._create_error_log_file(
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
        Write an output file through the output-store boundary.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``filename``, and ``content`` to ``write_output_file``
        and preserves its return and exception contract. Success is reported
        only after the owning output boundary has completed its required write
        or publication step. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind.

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
        """
        return await self._output_store().write_output_file(
            dut_id, collector_id, filename, content
        )

    async def substitute_variables(
        self,
        template: str,
        context: Dict[str, Any],
        dut_id: str = None,
        **kwargs,
    ) -> str:
        """
        Substitute variables.

        Environment policy failures are security decisions, not ordinary legacy
        substitution failures. Returning the original template here could pass a
        live policy token into a URI, command, or output path.

        Args:
            template: Text supplied as template in the format accepted by this
                function.
            context: Runtime context carrying state shared across this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The canonical substitute variables text.
        """
        # Create variable engine if it doesn't exist
        if self.variable_engine is None:
            await self._update_variable_engine(dut_id)

        try:
            return await self.variable_engine.substitute_variables(
                template, context, dut_id, **kwargs
            )
        except EnvironmentVariablePolicyError:
            # Environment policy failures are security decisions, not ordinary
            # legacy substitution failures. Returning the original template here
            # could pass a live policy token into a URI, command, or output path.
            raise
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BaseService",
                f"Variable substitution failed: {e}",
                dut_id,
            )
            # Return original template on error
            return template

    async def get_variable_engine_stats(self, dut_id: str = None) -> Dict[str, Any]:
        """
        Get statistics from the variable substitution service.

        After applying local validation, the function forwards ``dut_id`` to
        ``self.variable_engine.get_cache_stats`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing variable engine stats.
        """
        # Create variable engine if it doesn't exist
        if self.variable_engine is None:
            await self._update_variable_engine(dut_id)

        return await self.variable_engine.get_cache_stats(dut_id)

    async def clear_variable_cache(self, dut_id: str = None) -> None:
        """
        Clear the variable substitution cache.

        The implementation uses ``dut_id`` to clear the variable substitution
        cache. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        # Create variable engine if it doesn't exist
        if self.variable_engine is None:
            await self._update_variable_engine(dut_id)

        await self.variable_engine.clear_cache(dut_id)

    def substitute_output_pattern_variables(
        self,
        output_pattern: str,
        substitutions: Dict[str, str] = None,
        fallback_name: str = None,
    ) -> str:
        """
        Substitute variables in an output pattern with provided values.

        If no variables are present, returns the pattern as-is.

        Args:
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            substitutions: Optional substitutions; ``None`` selects the
                function's default behavior.
            fallback_name: Stable fallback name used for lookup and
                operator-facing diagnostics.

        Returns:
            The canonical substitute output pattern variables text.
        """
        if not output_pattern:
            return fallback_name or "output.json"

        # If no substitutions provided, return pattern as-is
        if not substitutions:
            return output_pattern

        result = output_pattern

        # Apply each substitution
        for variable, value in substitutions.items():
            placeholder = f"{{{variable}}}"
            if placeholder in result:
                result = result.replace(placeholder, str(value))

        # If no substitutions were made, return the original pattern
        # This handles both static strings and patterns with no matching variables
        return result

    def get_output_filename(
        self,
        output_pattern: str = None,
        function_tag: str = None,
        default_extension: str = ".txt",
        substitutions: Dict[str, str] = None,
    ) -> str:
        """
        Resolve an output filename through the output-store boundary.

        After applying local validation, the function forwards
        ``output_pattern``, ``function_tag``, ``default_extension``, and
        ``substitutions`` to ``get_output_filename`` and preserves its return
        and exception contract.

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
        return self._output_store().get_output_filename(
            output_pattern,
            function_tag,
            default_extension,
            substitutions,
        )

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
        Generalize and write output through the output-store boundary.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``content``, ``output_pattern``, and ``function_tag``
        to ``write_output_with_generalization`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            content: Content consumed while the function attempts to generalize
                and write output through the output-store boundary.
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
        return await self._output_store().write_output_with_generalization(
            dut_id,
            collector_id,
            content,
            output_pattern=output_pattern,
            function_tag=function_tag,
            default_extension=default_extension,
            substitutions=substitutions,
            **kwargs,
        )

    def _get_hook_parameter_mapping(self, method_name: str) -> Dict[str, str]:
        """
        Get parameter mapping configuration for a method.

        After applying local validation, the function forwards ``method_name``
        to ``mappings.get`` and preserves its return and exception contract.

        Args:
            method_name: Stable method name used for lookup and operator-facing
                diagnostics.

        Returns:
            A mapping containing hook parameter mapping.
        """
        # Define parameter mappings for different methods
        mappings = {
            # Redfish service methods
            "get_redfish_response_to_file": {
                # No parameter mapping needed - uri maps to uri directly
            },
            "collect_redfish_expand_with_traversal": {
                # No parameter mapping needed - base_uri maps to base_uri directly
                # expand_level maps to expand_level directly
            },
            "collect_redfish_collection_with_members": {
                "base_uri": "collection_uri",
                "function_tag": "entity_type",
            },
            "collect_redfish_uri_list": {
                "uri_list_key": "uri_list",  # Will be processed specially
                "function_tag": "entity_type",
            },
            "collect_redfish_chassis_with_filter": {
                "chassis_filter": "filter_criteria",  # Will be processed specially
            },
            "collect_redfish_unified": {
                "additional_member_collections": "additional_member_collections",
            },
            # Host service methods
            "run_host_commands": {
                "commands": "commands",
                "function_tag": "function_tag",
            },
            # IPMI service methods
            "run_ipmi_command": {
                "command": "command",
                "function_tag": "function_tag",
            },
            "run_ipmi_commands": {
                "commands": "commands",
                "function_tag": "function_tag",
            },
            "run_ipmi_command_with_nvbmc_handling": {
                "command": "command",
                "function_tag": "function_tag",
                "nvbmc_platforms": "nvbmc_platforms",
            },
            "run_ipmi_command_with_file_output": {
                "command": "command",
                "function_tag": "function_tag",
            },
            # BMC SSH service methods
            "run_bmc_command": {
                "command": "command",
                "function_tag": "function_tag",
                "baseboard_commands": "baseboard_commands",
            },
            "run_bmc_commands": {
                "commands": "commands",
                "function_tag": "function_tag",
            },
            "run_bmc_file_transfer": {
                "source_path": "source_path",
                "fallback_source_path": "fallback_source_path",
                "archive_name": "archive_name",
                "function_tag": "function_tag",
                "use_sftp": "use_sftp",
                "archive_missing_member_policy": "archive_missing_member_policy",
                "fallback_hexdump": "fallback_hexdump",
                "baseboard_archive_use_sudo": "baseboard_archive_use_sudo",
                "baseboard_archive_empty_is_not_applicable": (
                    "baseboard_archive_empty_is_not_applicable"
                ),
                "complete_on_empty_targets": "complete_on_empty_targets",
                "empty_reason": "empty_reason",
                "empty_output_pattern": "empty_output_pattern",
                "key_files": "key_files",
                "retry_count": "retry_count",
                "retry_delay": "retry_delay",
            },
            "run_bmc_script": {
                "script_name": "script_name",
                "script_name_pattern": "script_name_pattern",
                "function_tag": "function_tag",
                "use_hmc_ip": "use_hmc_ip",
                "auto_retrieve_files": "auto_retrieve_files",
                "use_working_directory": "use_working_directory",
                "working_dir": "working_dir",
                "pass_working_dir_to_script": "pass_working_dir_to_script",
                "script_timeout": "script_timeout",
                "output_file_pattern": "output_file_pattern",
                "output_search_dirs": "output_search_dirs",
                "execution_mode": "execution_mode",
                "script_args": "script_args",
                "alternative_scripts": "alternative_scripts",
            },
            "copy_files_from_bmc": {
                "working_dir": "working_dir",
                "output_file_pattern": "output_file_pattern",
                "output_search_dirs": "output_search_dirs",
                "function_tag": "function_tag",
                "cleanup_working_dir": "cleanup_working_dir",
            },
            "run_bmc_platform_specific": {
                "platform": "platform",
                "commands": "commands",
                "function_tag": "function_tag",
            },
        }

        return mappings.get(method_name, {})

    async def _apply_parameter_mapping(
        self,
        method_name: str,
        hook_params: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Apply parameter mapping and special processing for a method.

        The implementation uses ``method_name``, ``hook_params``, and
        ``context`` to apply parameter mapping and special processing for a
        method. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            method_name: Stable method name used for lookup and operator-facing
                diagnostics.
            hook_params: Callable invoked at the hook params boundary.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            The validated ``processed_params``.
        """
        mapping = self._get_hook_parameter_mapping(method_name)
        processed_params = hook_params.copy()

        # Debug: Log parameter mapping
        dut_id = context.get("dut_id", "unknown")
        await self._log_runtime(
            "DEBUG",
            "BaseService",
            f"Parameter mapping for {method_name}: {mapping}",
            dut_id,
        )
        await self._log_runtime(
            "DEBUG",
            "BaseService",
            f"Original hook_params: {list(hook_params.keys())}",
            dut_id,
        )

        # Apply standard parameter mappings
        for hook_param, method_param in mapping.items():
            if hook_param in processed_params:
                value = processed_params.pop(hook_param)

                # Special processing for certain parameters
                if (
                    method_name == "collect_redfish_uri_list"
                    and hook_param == "uri_list_key"
                ):
                    # For now, use empty list - would need config resolution
                    processed_params[method_param] = []
                elif (
                    method_name == "collect_redfish_chassis_with_filter"
                    and hook_param == "chassis_filter"
                ):
                    # Convert to filter criteria format
                    processed_params[method_param] = {"filter": value}
                else:
                    # Standard mapping
                    processed_params[method_param] = value

        # Add common parameters if not present
        if "dut_id" not in processed_params:
            processed_params["dut_id"] = context.get("dut_id")
        if "collector_id" not in processed_params:
            processed_params["collector_id"] = context.get("collector_id")

        # Handle output_pattern consistently
        if "output_pattern" in hook_params:
            processed_params["filename"] = hook_params["output_pattern"]
        elif "output_pattern" in processed_params:
            processed_params["filename"] = processed_params.pop("output_pattern")

        return processed_params

    def _process_command_output(
        self, output: Union[str, bytes, None], encoding: str = "utf-8"
    ) -> str:
        """
        Process command output to ensure it's in string format.

        Matches legacy nvdebug implementation.

        The implementation uses ``output`` and ``encoding`` to process command
        output to ensure it's in string format. Terminal status is emitted only
        after command output to ensure it's in string format and its owned
        cleanup have completed.

        Args:
            output: Optional output; ``None`` selects the function's default
                behavior.
            encoding: Character encoding used to decode or write the selected
                text.

        Returns:
            The canonical process command output text.
        """
        if output is None:
            return ""

        if isinstance(output, bytes):
            try:
                # First try UTF-8 with replace
                return output.decode(encoding, errors="replace")
            except Exception:
                try:
                    # Try latin1 as fallback - it can handle all byte values
                    return output.decode("latin1", errors="replace")
                except Exception:
                    # Last resort - hex representation
                    return f"hex:{output.hex()}"

        # Handle case where output is already a string
        if isinstance(output, str):
            return output

        # For any other type, try string conversion with error handling
        try:
            return str(output)
        except Exception:
            return f"<unconvertible output of type {type(output).__name__}>"

    def _format_command_error(
        self,
        command: str,
        exit_code: int,
        stdout: Union[str, bytes, None],
        stderr: Union[str, bytes, None],
        command_type: str = "",
        output_file: Optional[str] = None,
    ) -> str:
        """
        Format error messages for command execution failures consistently.

        Matches legacy nvdebug implementation.

        The implementation uses ``command``, ``exit_code``, ``stdout``,
        ``stderr``, and ``command_type`` to format error messages for command
        execution failures consistently. The source value keeps its ownership
        while the normalized representation is returned separately.

        Args:
            command: Text supplied as command in the format accepted by this
                function.
            exit_code: Numeric exit code used while the operation performs
                bounded accounting.
            stdout: Optional stdout; ``None`` selects the function's default
                behavior.
            stderr: Optional stderr; ``None`` selects the function's default
                behavior.
            command_type: Text supplied as command type in the format accepted
                by this function.
            output_file: Optional filesystem location used as the output file
                for this operation.

        Returns:
            The canonical command error text.
        """
        try:
            # Process stdout and stderr
            stdout_msg = self._process_command_output(stdout) if stdout else "<empty>"
            stderr_msg = self._process_command_output(stderr) if stderr else "<empty>"
            cmd_type = f"{command_type}" if command_type else ""

            # Wrap stdout and stderr in curly braces and indent their content by 4 spaces
            indented_stdout = "" + textwrap.indent(stdout_msg, "    ") + ""
            indented_stderr = "" + textwrap.indent(stderr_msg, "    ") + ""

            error_msg = f"""
Error while running {cmd_type} collector
Command   : {command}
Exit Code : {exit_code}
STDERR    :
{indented_stderr}
STDOUT    :
{indented_stdout}
"""
            return error_msg
        except Exception as e:
            return f"Error formatting command output: {str(e)}"

    async def _log_command_result(
        self,
        command: str,
        exit_code: int,
        stdout: Union[str, bytes, None],
        stderr: Union[str, bytes, None],
        command_type: str = "",
        dut_id: Optional[str] = None,
        collector_id: Optional[str] = None,
        log_errors: bool = True,
    ) -> None:
        """
        Log command execution results consistently.

        Matches legacy nvdebug logging pattern.

        The implementation uses ``command``, ``exit_code``, ``stdout``,
        ``stderr``, and ``command_type`` to log command execution results
        consistently. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            command: Text supplied as command in the format accepted by this
                function.
            exit_code: Numeric exit code used while the operation performs
                bounded accounting.
            stdout: Optional stdout; ``None`` selects the function's default
                behavior.
            stderr: Optional stderr; ``None`` selects the function's default
                behavior.
            command_type: Text supplied as command type in the format accepted
                by this function.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            log_errors: Whether log errors is enabled or required for this
                operation.
        """
        if exit_code == 0:
            await self._log_runtime(
                "INFO",
                f"{command_type.upper() if command_type else 'COMMAND'}",
                f"Command run successfully: {command}",
            )
        else:
            if log_errors:
                error_msg = self._format_command_error(
                    command, exit_code, stdout, stderr, command_type
                )
                await self._log_error(
                    f"{command_type.upper() if command_type else 'COMMAND'}_ERROR",
                    error_msg,
                    dut_id,
                    collector_id,
                )

    def _create_command_output_content(
        self,
        command: str,
        exit_code: int,
        stdout: Union[str, bytes, None],
        stderr: Union[str, bytes, None],
    ) -> str:
        """
        Create standardized command output content for file writing.

        Matches legacy nvdebug output format.

        The implementation uses ``command``, ``exit_code``, ``stdout``, and
        ``stderr`` to create standardized command output content for file
        writing.

        Args:
            command: Text supplied as command in the format accepted by this
                function.
            exit_code: Numeric exit code used while the operation performs
                bounded accounting.
            stdout: Optional stdout; ``None`` selects the function's default
                behavior.
            stderr: Optional stderr; ``None`` selects the function's default
                behavior.

        Returns:
            The validated ``content``.
        """
        stdout_processed = self._process_command_output(stdout) if stdout else ""
        stderr_processed = self._process_command_output(stderr) if stderr else ""

        content = f"Command: {command}\n"
        content += f"Exit Code: {exit_code}\n"
        content += f"Output:\n{stdout_processed}"

        # Include stderr if present
        if stderr_processed:
            content += f"\n\nSTDERR:\n{stderr_processed}"

        return content

    # ============================================================================
    # 11. COMMON UTILITY FUNCTIONS (Shared between services)
    # ============================================================================

    async def _log_collection_start(self, dut_id: str, collector_name: str) -> None:
        """
        Common logging for collection start.

        The implementation uses ``dut_id`` and ``collector_name`` to common
        logging for collection start. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_name: Stable collector name used for lookup and
                operator-facing diagnostics.
        """
        await self._log_runtime(
            "INFO",
            "BaseService",
            f"Starting {collector_name} collection",
            dut_id,
        )

    def _create_success_response(
        self, output_files: List[str], context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Create standardized success response.

        The implementation uses ``output_files`` and ``context`` to create
        standardized success response.

        Args:
            output_files: Entries supplied as ``output_files`` without
                transferring container ownership.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            A mapping containing the ``success``, ``output_files``, and
            ``context`` fields.
        """
        return {
            "success": True,
            "output_files": output_files,
            "context": context or {},
        }

    def _create_error_response(
        self, reason: str, output_files: List[str] = None
    ) -> Dict[str, Any]:
        """
        Create standardized error response.

        The implementation uses ``reason`` and ``output_files`` to create
        standardized error response.

        Args:
            reason: Text supplied as reason in the format accepted by this
                function.
            output_files: Optional output files; ``None`` selects the function's
                default behavior.

        Returns:
            A mapping containing the ``success``, ``reason``, and
            ``output_files`` fields.
        """
        return {
            "success": False,
            "reason": reason,
            "output_files": output_files or [],
        }

    async def _log_collection_success(
        self,
        dut_id: str,
        collection_type: str,
        details: str,
        file_path: str = None,
    ) -> None:
        """
        Common logging for collection success.

        The implementation uses ``dut_id``, ``collection_type``, ``details``,
        and ``file_path`` to common logging for collection success. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collection_type: Text supplied as collection type in the format
                accepted by this function.
            details: Text supplied as details in the format accepted by this
                function.
            file_path: Optional filesystem location used as the file path for
                this operation.
        """
        message = f"{collection_type} collection succeeded: {details}"
        if file_path:
            message += f" -> {file_path}"
        await self._log_runtime("INFO", "BaseService", message, dut_id)

    async def _log_collection_failure(
        self,
        dut_id: str,
        collection_type: str,
        details: str,
        error: str = None,
        collector_id: str = None,
    ) -> None:
        """
        Common logging for collection failure.

        Also create detailed error log file for better debugging.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collection_type: Text supplied as collection type in the format
                accepted by this function.
            details: Text supplied as details in the format accepted by this
                function.
            error: Exception or failure detail associated with the operation.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
        """
        message = f"{collection_type} collection failed: {details}"
        if error:
            message += f" - {error}"
        await self._log_runtime("ERROR", "BaseService", message, dut_id)

        # Also create detailed error log file for better debugging
        try:
            # Use provided collector_id or fall back to collection_type
            actual_collector_id = collector_id or f"{collection_type}_collection"
            # Create error log file with context
            error_log_path = await self._create_error_log_file(
                dut_id=dut_id,
                collector_id=actual_collector_id,
                error_message=message,
                context={
                    "collection_type": collection_type,
                    "details": details,
                    "error": error,
                    "operation": "collection_failure",
                },
            )
            if error_log_path:
                await self._log_runtime(
                    "DEBUG",
                    "BaseService",
                    f"Created error log file: {error_log_path}",
                    dut_id,
                )
        except Exception as e:
            # Don't let error log creation failure break the main flow
            await self._log_runtime(
                "WARN",
                "BaseService",
                f"Failed to create error log file for {collection_type} collection: {str(e)}",
                dut_id,
            )

    async def _execute_with_error_handling(
        self, dut_id: str, operation_name: str, operation_func, *args, **kwargs
    ) -> Dict[str, Any]:
        """
        Common error handling wrapper for operations.

        The implementation uses ``dut_id``, ``operation_name``,
        ``operation_func``, ``args``, and ``kwargs`` to common error handling
        wrapper for operations. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            operation_name: Stable operation name used for lookup and
                operator-facing diagnostics.
            operation_func: Operation func consumed while the function attempts
                to common error handling wrapper for operations.
            args: Additional positional values forwarded in caller-provided
                order.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing execute with error handling.
        """
        try:
            return await operation_func(*args, **kwargs)
        except Exception as e:
            exception_detail = str(e).strip() or type(e).__name__
            await self._log_collection_failure(
                dut_id,
                operation_name,
                "Exception occurred",
                exception_detail,
                collector_id=kwargs.get("collector_id"),
            )
            return self._create_error_response(
                f"Exception in {operation_name}: {exception_detail}"
            )

    def _extract_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """
        Extract nested value from dictionary using dot notation.

        The implementation uses ``data`` and ``path`` to extract nested value
        from dictionary using dot notation.

        Args:
            data: Mapping supplying fields for extract nested value from
                dictionary using dot notation.
            path: filesystem location used as the path for this operation.

        Returns:
            The validated ``current``.
        """
        keys = path.split(".")
        current = data

        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None

        return current

    def _extract_output_pattern_params(
        self, kwargs: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        """
        Extract output pattern params.

        Extract output_pattern and substitutions from kwargs, return filtered
        kwargs.

        Args:
            kwargs: Mapping supplying fields for extract output pattern params.

        Returns:
            A tuple containing the output pattern, substitution mapping, and
            remaining keyword arguments, in that order.
        """
        # Handle case where kwargs might not be a dictionary
        if not isinstance(kwargs, dict):
            return None, {}, {}

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
        default_extension: str = ".txt",
        **kwargs,
    ) -> Optional[str]:
        """
        Save patterned data through the output-store boundary.

        After applying local validation, the function forwards ``dut_id``,
        ``data``, ``function_tag``, ``output_pattern``, and ``substitutions`` to
        ``_save_data_with_common_pattern`` and preserves its return and
        exception contract. Success is reported only after the owning output
        boundary has completed its required write or publication step. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            data: Data consumed while the function attempts to save patterned
                data through the output-store boundary.
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
            The canonical save data with common pattern text, or ``None`` when
            the requested value is unavailable.
        """
        return await self._output_store()._save_data_with_common_pattern(
            dut_id,
            data,
            function_tag,
            output_pattern=output_pattern,
            substitutions=substitutions,
            default_extension=default_extension,
            **kwargs,
        )

    async def _determine_collector_status(
        self,
        successful_operations: int,
        total_operations: int,
        error_messages: List[str] = None,
        operation_name: str = "operations",
        additional_context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Return the determine collector status.

        The implementation uses ``successful_operations``, ``total_operations``,
        ``error_messages``, ``operation_name``, and ``additional_context`` to
        produce the determine collector status. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            successful_operations: Numeric successful operations used while the
                operation performs bounded accounting.
            total_operations: Numeric total operations used while the operation
                performs bounded accounting.
            error_messages: Optional error messages; ``None`` selects the
                function's default behavior.
            operation_name: Stable operation name used for lookup and
                operator-facing diagnostics.
            additional_context: Optional additional context; ``None`` selects
                the function's default behavior.

        Returns:
            The validated ``result``.
        """
        request = self._collector_result_builder.prepare_request(
            successful_operations=successful_operations,
            total_operations=total_operations,
            error_messages=error_messages,
            operation_name=operation_name,
            additional_context=additional_context,
        )
        status_record = self._collector_result_builder.determine_status(request)
        result = collector_status_to_legacy_dict(status_record)

        # Debug logging for status determination
        if hasattr(self, "_log_runtime"):
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Status determination: successful_operations={successful_operations}, total_operations={total_operations}, determined_status={result['status']}, success={result['success']}",
                None,  # No dut_id available in this context
            )

        return result

    def _build_standardized_result(
        self,
        status_info: Dict[str, Any],
        output_files: List[str] = None,
        additional_context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Build a standardized result dictionary for collectors.

        After applying local validation, the function forwards ``status_info``,
        ``output_files``, and ``additional_context`` to
        ``collector_result_to_legacy_dict`` and preserves its return and
        exception contract.

        Args:
            status_info: Mapping supplying fields for standardized result
                dictionary for collectors.
            output_files: Optional output files; ``None`` selects the function's
                default behavior.
            additional_context: Optional additional context; ``None`` selects
                the function's default behavior.

        Returns:
            A mapping containing standardized result.
        """
        record = self._collector_result_builder.build_legacy_status_result(
            status_info=status_info,
            output_files=output_files,
            additional_context=additional_context,
        )
        return collector_result_to_legacy_dict(record)

    async def _create_standardized_collector_result_internal(
        self,
        successful_operations: int,
        total_operations: int,
        output_files: List[str] = None,
        error_messages: List[str] = None,
        operation_name: str = "operations",
        additional_context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Create standardized collector result internal.

        After applying local validation, the function forwards
        ``successful_operations``, ``total_operations``, ``output_files``,
        ``error_messages``, and ``operation_name`` to
        ``self._build_standardized_result`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

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

        Returns:
            A mapping containing standardized collector result internal.
        """
        request = self._collector_result_builder.prepare_request(
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name=operation_name,
            additional_context=additional_context,
        )

        # Determine status
        status_info = await self._determine_collector_status(
            request.successful_operations,
            request.total_operations,
            request.legacy_error_messages(),
            request.operation_name,
            request.legacy_additional_context(),
        )

        # Build and return standardized result
        return self._build_standardized_result(
            status_info,
            request.legacy_output_files(),
            request.legacy_additional_context(),
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
        """
        Create a standardized collector result with optional debug logging.

        This is the main method that all collectors should call. It includes
        debug logging when dut_id and collector_id are provided.

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
            The validated ``result``.
        """
        request = self._collector_result_builder.prepare_request(
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name=operation_name,
            additional_context=additional_context,
            clamp_excess_successes=True,
        )
        successful_operations = request.successful_operations
        total_operations = request.total_operations
        output_files = request.legacy_output_files()
        error_messages = request.legacy_error_messages()
        operation_name = request.operation_name
        additional_context = request.legacy_additional_context()
        accounting_warning = request.accounting_warning

        # Auto-detect dut_id and collector_id if not provided
        if dut_id is None:
            dut_id = self._get_current_dut_id()
        if collector_id is None:
            collector_id = self._get_current_collector_id()

        if accounting_warning and hasattr(self, "_log_runtime"):
            await self._log_runtime(
                "WARNING",
                "BaseService",
                accounting_warning,
                dut_id,
            )

        # Add debug logging if dut_id and collector_id are available and not "unknown"
        if (
            dut_id
            and dut_id != "unknown"
            and collector_id
            and collector_id != "unknown"
        ):
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"About to return standardized result for {collector_id} with {len(output_files)} output_files: {output_files}",
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"About to return standardized result for {collector_id} with {len(error_messages)} error_messages: {error_messages}",
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Successful operations over total operations: {successful_operations}/{total_operations}",
                dut_id,
            )

        # Call the internal method to create the result
        result = await self._create_standardized_collector_result_internal(
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name=operation_name,
            additional_context=additional_context,
        )

        # Add debug logging if dut_id and collector_id are available and not "unknown"
        if (
            dut_id
            and dut_id != "unknown"
            and collector_id
            and collector_id != "unknown"
        ):
            await self._log_runtime(
                "DEBUG",
                "BaseService",
                f"Returning standardized result for {collector_id}: success={result.get('success')}, status={result.get('status')}, output_files in context: {result.get('context', {}).get('output_files', [])}",
                dut_id,
            )

        return result

    async def _process_collector_result(
        self,
        result: Dict[str, Any],
        all_output_files: List[str],
        all_status_list: List[bool],
        error_messages: List[str],
        entity_type: str = "entity",
        entity_id: str = "unknown",
        dut_id: str = None,
        collector_id: str = None,
        custom_error_format: str = None,
    ) -> None:
        """
        Process collector result.

        The implementation uses ``result``, ``all_output_files``,
        ``all_status_list``, ``error_messages``, and ``entity_type`` to process
        collector result. Terminal status is emitted only after collector result
        and its owned cleanup have completed. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        The operation mutates ``all_output_files``, ``all_status_list``, and
        ``error_messages`` in place; ownership of those objects remains with the
        caller.

        Args:
            result: Mapping supplying fields for collector result.
            all_output_files: Entries supplied as ``all_output_files`` without
                transferring container ownership.
            all_status_list: Entries supplied as ``all_status_list`` without
                transferring container ownership.
            error_messages: Entries supplied as ``error_messages`` without
                transferring container ownership.
            entity_type: Text supplied as entity type in the format accepted by
                this function.
            entity_id: Stable entity identifier used to correlate configuration,
                logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            custom_error_format: Optional custom error format; ``None`` selects
                the function's default behavior.
        """
        # Handle success, degraded, partial, error, and skipped statuses.
        status = result.get("status", "success")
        success = result.get("success", False)

        if status == "skipped":
            # Treat skipped as successful
            all_status_list.append(True)
        elif status in ["success", "degraded", "partial"] or success:
            # Collect output files from both top-level and context (like R35 fix)
            top_level_files = result.get("output_files", [])
            context_files = result.get("context", {}).get("output_files", [])
            all_files = list(set(top_level_files + context_files))
            all_output_files.extend(all_files)

            # For partial status, we might have mixed success/failure in status_list
            if status == "partial" and "context" in result:
                status_list = result.get("context", {}).get("status_list", [True])
                all_status_list.extend(status_list)
            else:
                all_status_list.append(True)
        else:
            # Handle failure case (status == "error" or success == False)
            all_status_list.append(False)

            # Use custom error format if provided, otherwise use default
            if custom_error_format:
                error_msg = custom_error_format
            else:
                error_msg = result.get(
                    "reason",
                    f"Failed to collect {entity_type} {entity_id}",
                )

            # Use different error message formats based on entity type
            if entity_type == "entity" and entity_id == "unknown":
                # Generic format for unknown entities
                error_messages.append(error_msg)
            else:
                # Specific format for known entities
                error_messages.append(f"{entity_type} {entity_id}: {error_msg}")

            # Create error log file for failed operations (only if dut_id and collector_id provided)
            if dut_id and collector_id:
                # Check if there are detailed request contexts for this entity
                detailed_context = {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "operation": "collector_operation",
                    "result": result,
                }

                # Add detailed request context if available
                if result.get("context", {}).get("failed_entity_contexts"):
                    # Pass the full failed entity contexts dictionary
                    detailed_context["result"] = {
                        "context": {
                            "failed_entity_contexts": result["context"][
                                "failed_entity_contexts"
                            ],
                            # Also include the specific entity context for this error
                            "current_entity_context": result["context"][
                                "failed_entity_contexts"
                            ].get(entity_id, {}),
                        }
                    }
                elif result.get("context", {}).get("failed_service_contexts"):
                    # Pass the full failed service contexts dictionary
                    detailed_context["result"] = {
                        "context": {
                            "failed_service_contexts": result["context"][
                                "failed_service_contexts"
                            ],
                            # Also include the specific service context for this error
                            "current_service_context": result["context"][
                                "failed_service_contexts"
                            ].get(entity_id, {}),
                        }
                    }

                error_log_path = await self._create_error_log_file(
                    dut_id=dut_id,
                    collector_id=collector_id,
                    error_message=error_msg,
                    context=detailed_context,
                )

                # Add error log file to output files
                if error_log_path:
                    all_output_files.append(error_log_path)

    def _format_error_messages(
        self,
        error_messages: List[str],
        operation_name: str,
        is_partial: bool = False,
    ) -> str:
        """
        Format error messages into a readable, structured format.

        After applying local validation, the function forwards
        ``error_messages``, ``operation_name``, and ``is_partial`` to
        ``format_collector_error_messages`` and preserves its return and
        exception contract. The source value keeps its ownership while the
        normalized representation is returned separately.

        Args:
            error_messages: Entries supplied as ``error_messages`` without
                transferring container ownership.
            operation_name: Stable operation name used for lookup and
                operator-facing diagnostics.
            is_partial: Whether is partial is enabled or required for this
                operation.

        Returns:
            The canonical error messages text.
        """
        return format_collector_error_messages(
            error_messages,
            operation_name,
            is_partial=is_partial,
        )

    def _extract_http_error_message(self, http_error: str) -> str:
        """
        Extract a readable error message from HTTP error response.

        After applying local validation, the function forwards ``http_error`` to
        ``extract_http_error_message`` and preserves its return and exception
        contract.

        Args:
            http_error: Text supplied as HTTP error in the format accepted by
                this function.

        Returns:
            The canonical HTTP error message.
        """
        return extract_http_error_message(http_error)

    async def _handle_collection_summary_generation(
        self,
        dut_id: str,
        function_tag: str,
        collection_name: str,
        total_operations: int,
        successful_operations: int,
        failed_operations: int,
        output_files: list,
        additional_details: dict,
        kwargs: dict,
        collection_type: str = "generic",
        ignore_empty_results: bool = True,
        skipped_operations: int = 0,
    ) -> list:
        """
        Handle collection summary generation based on configuration.

        This method can be used by any collector to:

        1. Generate summary files (text and JSON).
        2. Save detailed failure information to failures.json.
        3. Create standardized collector results.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            collection_name: Stable collection name used for lookup and
                operator-facing diagnostics.
            total_operations: Numeric total operations used while the operation
                performs bounded accounting.
            successful_operations: Numeric successful operations used while the
                operation performs bounded accounting.
            failed_operations: Numeric failed operations used while the
                operation performs bounded accounting.
            output_files: Entries supplied as ``output_files`` without
                transferring container ownership.
            additional_details: Mapping supplying fields for collection summary
                generation based on configuration.
            kwargs: Mapping supplying fields for collection summary generation
                based on configuration.
            collection_type: Text supplied as collection type in the format
                accepted by this function.
            ignore_empty_results: Whether ignore empty results is enabled or
                required for this operation.
            skipped_operations: Operations intentionally not required on the
                target. These are reported separately from failures.

        Returns:
            The handle collection summary generation returned in
            operation-defined order.
        """
        # Debug logging to track folder naming issues and status determination.

        await self._log_runtime(
            "DEBUG",
            "BaseService",
            f"_handle_collection_summary_generation called: function_tag='{function_tag}', collection_name='{collection_name}', total_ops={total_operations}, successful_ops={successful_operations}, failed_ops={failed_operations}",
            dut_id,
        )

        # Log status determination logic
        if total_operations == 0:
            status = "skipped"
        elif successful_operations == 0:
            status = "error"
        elif successful_operations + skipped_operations < total_operations:
            status = "partial"
        else:
            status = "success"

        await self._log_runtime(
            "DEBUG",
            "BaseService",
            f"Status determination: {successful_operations}/{total_operations} operations -> status='{status}'",
            dut_id,
        )
        """
        Handle collection summary generation based on configuration.

        Args:
            dut_id: DUT identifier
            function_tag: Function tag for output files
            collection_name: Name for the collection (used in summaries)
            total_operations: Total number of operations attempted
            successful_operations: Number of successful operations
            failed_operations: Number of failed operations
            output_files: List of output files (will be modified)
            additional_details: Additional details for the summary
            kwargs: Collection kwargs containing summary configuration
            collection_type: Type of collection for text summary
            ignore_empty_results: Whether to ignore empty results

        Returns:
            Updated list of output files (may include summary files)
        """
        # Extract summary configuration
        generate_summary = kwargs.get(
            "generate_summary", True
        )  # Default to True for backward compatibility
        summary_format = kwargs.get(
            "summary_format", "text"
        )  # Default to text for backward compatibility
        collector_config = kwargs.get("collector_config")

        if not generate_summary:
            return output_files

        # Use standardized collection summary logging
        await self._log_collection_summary(
            dut_id=dut_id,
            collection_name=collection_name,
            total_operations=total_operations,
            successful_operations=successful_operations,
            failed_operations=failed_operations,
            skipped_operations=skipped_operations,
            output_files_count=len(output_files),
            additional_details=additional_details,
        )

        # Generate JSON summary if requested
        if summary_format in ["json", "both"]:
            # Extract output pattern parameters for JSON summary
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            # Create JSON summary content
            success_rate = (
                (successful_operations / total_operations * 100)
                if total_operations > 0
                else 0
            )
            summary_data = {
                "collection_name": collection_name,
                "dut_id": dut_id,
                "timestamp": datetime.now().isoformat(),
                "statistics": {
                    "total_operations": total_operations,
                    "successful_operations": successful_operations,
                    "failed_operations": failed_operations,
                    "skipped_operations": skipped_operations,
                    "success_rate_percent": round(success_rate, 1),
                },
                "output_files": output_files,
                "additional_details": additional_details or {},
            }

            summary_filename = f"{function_tag}_{collection_type}_summary"
            # print(f"DEBUG: Creating JSON summary: function_tag='{function_tag}', collection_name='{collection_name}', summary_filename='{summary_filename}'")
            json_summary_file = await self._save_data_with_common_pattern(
                dut_id,
                json.dumps(summary_data, indent=2),
                summary_filename,
                output_pattern=None,  # Don't use the misleading output_pattern
                substitutions={"file_name": summary_filename},
                default_extension=".json",  # Ensure JSON extension
                **filtered_kwargs,
            )

            if json_summary_file:
                output_files.append(json_summary_file)

        # Generate text summary if requested (for backward compatibility)
        if summary_format in ["text", "both"]:
            # Extract output pattern parameters for text summary
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            summary_content = await self._create_generic_collection_summary(
                function_tag,
                collection_type,
                additional_details,  # Use additional_details as search_info
                {"successful_operations": successful_operations},  # Use results dict
                ignore_empty_results,
                collector_config=collector_config,
                total_operations=total_operations,
                successful_operations=successful_operations,
            )

            summary_filename = f"{function_tag}_{collection_type}_summary"
            # print(f"DEBUG: Creating text summary: function_tag='{function_tag}', collection_name='{collection_name}', summary_filename='{summary_filename}'")
            summary_file_path = await self._save_data_with_common_pattern(
                dut_id,
                summary_content,
                summary_filename,
                output_pattern=None,  # Don't use the misleading output_pattern
                substitutions={"file_name": summary_filename},
                default_extension=".txt",
                **filtered_kwargs,
            )

            if summary_file_path:
                output_files.append(summary_file_path)

        return output_files
