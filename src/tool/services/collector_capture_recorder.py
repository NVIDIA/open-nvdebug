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
Bounded generic request/response capture for :class:`BaseService`.

``BaseService`` remains the compatibility facade and owns the run-scoped state,
logger, collector budget registry, and all monkeypatch/subclass seams. This
recorder owns only capture orchestration, private-resource cleanup, publication
acknowledgement, metadata projection, and bounded capture diagnostics. Calls
that cross those ownership boundaries deliberately route back through the facade
so existing overrides remain authoritative.
"""

from __future__ import annotations

import asyncio
import os
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple, cast

from ..utils.redfish_download import StreamedRedfishBody
from ..utils.request_response_capture import (
    CaptureLimitExceeded,
    CapturePublicationAmbiguousError,
    CaptureSanitizationPolicy,
    PrivateCaptureCandidate,
    PrivateCapturePublicationTransaction,
    PublishedCaptureSummary,
    RequestResponseCaptureSpool,
    RunOwnedRequestCaptureRuntime,
    VerifiedPrivateCapture,
    _defer_capture_failure,
    _raise_capture_cleanup_outcome,
    _remember_capture_control_flow,
    bounded_capture_failure_metadata,
)

if TYPE_CHECKING:
    from .base_service import BaseService


_REQUEST_CAPTURE_RUNTIME_CREATION_LOCK = threading.Lock()


class CollectorCaptureRecorder:
    """
    Own generic capture mechanics while retaining ``BaseService`` facades.

    The type coordinates ``get_request_capture_runtime``,
    ``capture_external_text_sanitizer``, ``drain_capture_resource_discard``,
    ``close_request_capture_state``, and
    ``acknowledge_request_capture_publications`` and retains the state those
    operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        service: "BaseService",
        *,
        current_publication_owner: Callable[[], Optional[object]],
        bounded_identifier: Callable[..., str],
    ) -> None:
        """
        Initialize a ``CollectorCaptureRecorder`` instance.

        The initializer records ``_bounded_identifier``,
        ``_current_publication_owner``, and ``_service`` for later operations
        and establishes the instance invariants before any public method runs.

        Args:
            service: Service consumed while the function attempts to initialize
                a ``CollectorCaptureRecorder`` instance.
            current_publication_owner: Current publication owner consumed while
                the function attempts to initialize a
                ``CollectorCaptureRecorder`` instance.
            bounded_identifier: Stable bounded identifier used to correlate
                configuration, logs, and results.
        """
        self._service = service
        self._current_publication_owner = current_publication_owner
        self._bounded_identifier = bounded_identifier

    def get_request_capture_runtime(self) -> RunOwnedRequestCaptureRuntime:
        """
        Return the sole orchestrator-owned capture runtime for this run.

        The implementation uses current instance state to produce the sole
        orchestrator-owned capture runtime for this run. If the function cannot
        produce the sole orchestrator-owned capture runtime for this run, its
        exception reaches the caller instead of being converted into a
        successful result.

        Returns:
            A ``RunOwnedRequestCaptureRuntime`` representing request capture
            runtime.

        Raises:
            RuntimeError: If run-owned capture runtime lacks the logger output
                root.
        """

        service = self._service
        owner = service.orchestrator if service.orchestrator is not None else service
        attribute = (
            "_request_response_capture_runtime"
            if service.orchestrator is not None
            else "_local_request_capture_runtime"
        )
        runtime = getattr(owner, attribute, None)
        if runtime is None:
            with _REQUEST_CAPTURE_RUNTIME_CREATION_LOCK:
                runtime = getattr(owner, attribute, None)
                if runtime is None:
                    tool_config = getattr(
                        getattr(service, "dut_manager", None), "tool_config", {}
                    )
                    output_root = getattr(
                        getattr(service, "logger", None), "base_log_dir", None
                    )
                    if output_root is None:
                        raise RuntimeError(
                            "Run-owned capture runtime requires the logger output root"
                        )
                    runtime = RunOwnedRequestCaptureRuntime.create(
                        tool_config or {}, output_root=output_root
                    )
                    setattr(owner, attribute, runtime)
        monitor = getattr(owner, "resource_usage_monitor", None)
        attach_sampler = getattr(monitor, "set_request_capture_sampler", None)
        if callable(attach_sampler):
            attach_sampler(runtime.metrics_snapshot)
        return runtime

    def capture_external_text_sanitizer(self) -> Optional[Any]:
        """
        Return the logger sanitizer callback when one is available.

        The implementation uses current instance state to produce the logger
        sanitizer callback when one is available.

        Returns:
            The logger sanitizer callback when one is available, or ``None``
            when the requested value is unavailable.
        """

        sanitizer = getattr(getattr(self._service, "logger", None), "sanitizer", None)
        sanitize = getattr(sanitizer, "sanitize", None)
        return sanitize if callable(sanitize) else None

    def capture_sensitive_value_replacement(self) -> str:
        """
        Return the public logger's structured credential replacement.

        Primary JSON artifacts and diagnostic request captures must project a
        sensitive mapping value identically.  The logger sanitizer owns that
        public representation, while a fixed fail-closed marker remains the
        fallback when no usable logger replacement is available.

        Returns:
            The bounded replacement string used for sensitive mapping values.
        """

        sanitizer = getattr(getattr(self._service, "logger", None), "sanitizer", None)
        replacement = getattr(sanitizer, "replacement", None)
        if type(replacement) is str and replacement and len(replacement) <= 256:
            return replacement
        return "<redacted>"

    def capture_sensitive_name_classifier(self) -> Optional[Any]:
        """
        Return the public logger's structured credential classifier.

        The primary artifact writer owns the schema-aware distinction between
        credential fields such as ``UserName`` and telemetry near-misses such
        as ``UserPercent``. Diagnostic capture must use that same decision to
        preserve both secrecy and exact structured-response parity. A disabled
        sanitizer does not provide an active classification policy, so the
        request-capture boundary uses its non-optional canonical fallback.

        Returns:
            The logger's structured-key classifier, or ``None`` when the
            sanitizer does not expose one.
        """

        sanitizer = getattr(getattr(self._service, "logger", None), "sanitizer", None)
        if getattr(sanitizer, "enabled", True) is False:
            # A disabled public sanitizer deliberately classifies every field
            # as non-sensitive. Do not expose that no-op callback to the
            # diagnostic boundary: absence selects its independent fail-closed
            # structural policy instead.
            return None
        classifier = getattr(sanitizer, "is_sensitive_structured_key", None)
        return classifier if callable(classifier) else None

    @staticmethod
    async def drain_capture_resource_discard(
        runtime: Any,
        resource: Any,
    ) -> Tuple[Optional[BaseException], Optional[BaseException]]:
        """
        Finish one blocking discard despite deferred process control.

        Never let KeyboardInterrupt/SystemExit escape a child Task; return the
        exact object to the lifecycle owner for ranking.

        Args:
            runtime: Runtime consumed while the function attempts to finish one
                blocking discard despite deferred process control.
            resource: Resource consumed while the function attempts to finish
                one blocking discard despite deferred process control.

        Returns:
            A tuple containing ``control flow`` and ``optional[base exception]``
            in that order.
        """

        async def discard_owned() -> Optional[BaseException]:
            """
            Discard owned.

            Never let KeyboardInterrupt/SystemExit escape a child Task; return
            the exact object to the lifecycle owner for ranking.

            Returns:
                The validated ``error``, or ``None`` when no value qualifies.
            """
            try:
                await runtime.run(resource.discard)
            except BaseException as error:
                # Never let KeyboardInterrupt/SystemExit escape a child Task;
                # return the exact object to the lifecycle owner for ranking.
                return error
            return None

        discard_task = asyncio.create_task(discard_owned())
        control_flow: Optional[BaseException] = None
        wait_errors: List[BaseException] = []
        while not discard_task.done():
            try:
                await asyncio.shield(discard_task)
            except BaseException as error:
                control_flow = _defer_capture_failure(control_flow, wait_errors, error)
        task_error = discard_task.result()
        if task_error is not None:
            terminal_errors = list(wait_errors)
            control_flow = _defer_capture_failure(
                control_flow, terminal_errors, task_error
            )
            if len(terminal_errors) == 1:
                return control_flow, terminal_errors[0]
            if terminal_errors:
                return control_flow, BaseExceptionGroup(
                    "Capture discard task failed",
                    terminal_errors,
                )
            return control_flow, None
        if wait_errors:
            first_error = wait_errors[0]
            for wait_error in wait_errors[1:]:
                first_error.add_note(
                    "Additional capture discard wait failure: "
                    f"{type(wait_error).__name__}"
                )
            return control_flow, first_error
        return control_flow, None

    async def close_request_capture_state(self) -> None:
        """
        Discard every hook-local capture before run-owned runtime teardown.

        The implementation uses current instance state to discard every
        hook-local capture before run-owned runtime teardown. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.
        """

        service = self._service
        runtime = getattr(
            service.orchestrator if service.orchestrator is not None else service,
            (
                "_request_response_capture_runtime"
                if service.orchestrator is not None
                else "_local_request_capture_runtime"
            ),
            None,
        )
        if runtime is None:
            return
        states: List[Any] = []
        retained_states: Dict[asyncio.Task[Any], List[Dict[str, Any]]] = {}
        for task, stack in tuple(service._request_response_capture_states.items()):
            retained_stack: List[Dict[str, Any]] = []
            for state_value in tuple(stack):
                state: Any = state_value
                if not isinstance(state, dict):
                    states.append(state)
                    continue
                owner = state.get("publication_owner")
                if owner is not None and service._collector_budget_token_is_current(
                    str(state.get("dut_id")),
                    str(state.get("collector_id")),
                    owner,
                ):
                    retained_stack.append(state)
                else:
                    states.append(state)
            if retained_stack:
                retained_states[task] = retained_stack
        service._request_response_capture_states.clear()
        service._request_response_capture_states.update(retained_states)
        errors: List[BaseException] = []
        control_flow: Optional[BaseException] = None
        for state in states:
            resource = state.get("spool") if isinstance(state, dict) else None
            if resource is None:
                continue
            try:
                (
                    discard_control,
                    discard_error,
                ) = await service._drain_capture_resource_discard(runtime, resource)
                if discard_control is not None:
                    control_flow = _remember_capture_control_flow(
                        control_flow, discard_control
                    )
                if discard_error is not None:
                    control_flow = _defer_capture_failure(
                        control_flow, errors, discard_error
                    )
            except BaseException as error:
                control_flow = _defer_capture_failure(control_flow, errors, error)
            finally:
                try:
                    runtime.abandon(resource)
                except BaseException as error:
                    control_flow = _defer_capture_failure(control_flow, errors, error)

        # Publications are shared at orchestrator scope. Close may reclaim a
        # compatibility owner or an invalidated explicit owner, but it must not
        # disturb another execution that is still entitled to adopt its own
        # publication.
        for key in tuple(service._pending_request_capture_publications):
            if len(key) < 2:
                continue
            owner = key[2] if len(key) == 3 else None
            if owner is not None and service._collector_budget_token_is_current(
                str(key[0]),
                str(key[1]),
                owner,
            ):
                continue
            try:
                await service._rollback_request_capture_publications(
                    str(key[0]),
                    str(key[1]),
                    owner_token=owner,
                )
            except BaseException as error:
                control_flow = _defer_capture_failure(control_flow, errors, error)
        _raise_capture_cleanup_outcome(
            control_flow,
            errors,
            "Generic request capture teardown failed",
        )

    async def acknowledge_request_capture_publications(
        self,
        dut_id: str,
        collector_id: str,
        *,
        owner_token: Any,
        rollback_on_failure: bool = True,
    ) -> None:
        """
        Acknowledge publications only after scheduler status finalization.

        The implementation uses ``dut_id``, ``collector_id``, ``owner_token``,
        and ``rollback_on_failure`` to acknowledge publications only after
        scheduler status finalization. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind. If the
        function cannot acknowledge publications only after scheduler status
        finalization, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            owner_token: Owner token consumed while the function attempts to
                acknowledge publications only after scheduler status
                finalization.
            rollback_on_failure: Whether rollback on failure is enabled or
                required for this operation.

        Raises:
            RuntimeError: If capture publication owner is no longer active; or
                capture publication was not adopted by durable collector status.
        """

        service = self._service
        key, resolved_owner = service._request_capture_publication_owner(
            dut_id,
            collector_id,
            owner_token,
        )
        pending = tuple(service._pending_request_capture_publications.get(key, ()))
        if not pending:
            return
        if not service._collector_budget_token_is_current(
            dut_id,
            collector_id,
            resolved_owner,
        ):
            if rollback_on_failure:
                await service._rollback_request_capture_publications(
                    dut_id,
                    collector_id,
                    owner_token=resolved_owner,
                )
            raise RuntimeError("Capture publication owner is no longer active")
        runtime = service._get_request_capture_runtime()
        checker = getattr(
            getattr(service, "logger", None),
            "is_capture_publication_durably_tracked",
            None,
        )
        # Validate the complete immutable status binding before committing any
        # registry acknowledgement. A checker failure or cancellation between
        # entries therefore leaves every publication retryable/rollbackable.
        all_tracked = True
        for published in pending:
            tracked = (
                bool(
                    await runtime.run(
                        runtime.verify_durable_publication,
                        published,
                        checker,
                        dut_id=str(dut_id),
                        collector_id=str(collector_id),
                    )
                )
                if callable(checker)
                else False
            )
            all_tracked = all_tracked and tracked
        if not all_tracked:
            if rollback_on_failure:
                await service._rollback_request_capture_publications(
                    dut_id,
                    collector_id,
                    owner_token=resolved_owner,
                )
            raise RuntimeError(
                "Capture publication was not adopted by durable collector status"
            )

        # Verification yields to external status storage. Re-check the captured
        # execution before the synchronous acknowledgement handoff so a child
        # that suppressed timeout cancellation cannot adopt a stale publication.
        if not service._collector_budget_token_is_current(
            dut_id,
            collector_id,
            resolved_owner,
        ):
            if rollback_on_failure:
                await service._rollback_request_capture_publications(
                    dut_id,
                    collector_id,
                    owner_token=resolved_owner,
                )
            raise RuntimeError("Capture publication owner is no longer active")

        # Registry acknowledgement is synchronous and cannot yield between
        # entries. Remove each committed item immediately so an unexpected
        # local failure can retry only the uncommitted suffix.
        for published in pending:
            runtime.acknowledge_publication(
                published,
                dut_id=str(dut_id),
                collector_id=str(collector_id),
            )
            current = service._pending_request_capture_publications.get(key)
            if current is not None:
                for index, candidate in enumerate(current):
                    if candidate is published:
                        current.pop(index)
                        break
                if not current:
                    service._pending_request_capture_publications.pop(key, None)

    async def rollback_request_capture_publications(
        self,
        dut_id: str,
        collector_id: str,
        *,
        owner_token: Any,
    ) -> None:
        """
        Exact-rollback every publication not yet adopted by status.

        The implementation uses ``dut_id``, ``collector_id``, and
        ``owner_token`` to exact-rollback every publication not yet adopted by
        status. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            owner_token: Owner token consumed while the function attempts to
                exact-rollback every publication not yet adopted by status.
        """

        service = self._service
        key, _ = service._request_capture_publication_owner(
            dut_id,
            collector_id,
            owner_token,
        )
        pending = tuple(service._pending_request_capture_publications.pop(key, ()))
        if not pending:
            return
        runtime = service._get_request_capture_runtime()
        control_flow: Optional[BaseException] = None
        errors: List[BaseException] = []
        for published in pending:
            try:
                await runtime.run(runtime.rollback_published, published)
            except BaseException as error:
                control_flow = _defer_capture_failure(control_flow, errors, error)
        _raise_capture_cleanup_outcome(
            control_flow,
            errors,
            "Capture publication rollback failed",
        )

    @staticmethod
    def attach_capture_metadata(
        target_result: Dict[str, Any],
        capture_result: Tuple[str, Dict[str, Any]],
        method_name: str,
        current_stage: Optional[str],
        context: Dict[str, Any],
    ) -> None:
        """
        Append request/response capture metadata to a hook result.

        The implementation uses ``target_result``, ``capture_result``,
        ``method_name``, ``current_stage``, and ``context`` to append
        request/response capture metadata to a hook result. The operation
        mutates ``target_result`` in place; ownership of those objects remains
        with the caller.

        Args:
            target_result: Mapping supplying fields for append request/response
                capture metadata to a hook result.
            capture_result: Mapping supplying fields for append request/response
                capture metadata to a hook result.
            method_name: Stable method name used for lookup and operator-facing
                diagnostics.
            current_stage: Text supplied as current stage in the format accepted
                by this function.
            context: Runtime context carrying state shared across this
                operation.
        """

        file_path, capture_data = capture_result
        capture_data = capture_data or {}

        context_block = target_result.setdefault("context", {})
        if file_path:
            diagnostic_files = target_result.setdefault("diagnostic_files", [])
            if file_path not in diagnostic_files:
                diagnostic_files.append(file_path)
            diagnostic_context = context_block.setdefault("diagnostic_files", [])
            if file_path not in diagnostic_context:
                diagnostic_context.append(file_path)

        logs_block = context_block.setdefault("request_response_logs", {})
        capture_key = capture_data.get("key")
        if not capture_key:
            stage_hint = capture_data.get("stage")
            stage_name = stage_hint or current_stage or context.get("current_stage")
            method_key = method_name.strip("_")
            capture_key = f"{stage_name}:{method_key}" if stage_name else method_key
        logs_block[capture_key] = {
            key: value
            for key, value in capture_data.items()
            if key not in {"key", "stage"}
        }
        if file_path:
            logs_block[capture_key]["artifact_path"] = file_path

    def sanitize_for_capture(self, value: Any, depth: int = 4) -> Any:
        """
        Convert arbitrary data into the historical capture-safe shape.

        The implementation uses ``value`` and ``depth`` to convert arbitrary
        data into the historical capture-safe shape. The source value keeps its
        ownership while the normalized representation is returned separately.

        Args:
            value: Value object whose ``capture_metadata`` and ``items`` state
                is read while performing arbitrary data into the historical
                capture-safe shape.
            depth: Numeric depth used while the operation performs bounded
                accounting.

        Returns:
            The for capture value selected by the operation.
        """

        service = self._service
        sanitizer = getattr(getattr(service, "logger", None), "sanitizer", None)

        def sanitize_text(text: str) -> str:
            """
            Sanitize text.

            The implementation uses ``text`` to sanitize text.

            Args:
                text: Text supplied as text in the format accepted by this
                    function.

            Returns:
                The canonical text.
            """
            return sanitizer.sanitize(text) if sanitizer else text

        if depth <= 0:
            return sanitize_text(str(value))

        if isinstance(value, str):
            return sanitize_text(value)

        if value is None or isinstance(value, (int, float, bool)):
            return value

        if isinstance(value, bytes):
            return {
                "type": "bytes",
                "length": len(value),
                "note": "binary content omitted",
            }

        if isinstance(value, StreamedRedfishBody):
            return value.capture_metadata()

        # Recursion deliberately crosses the facade so a historical subclass or
        # monkeypatch override remains authoritative at every nested boundary.
        if isinstance(value, (list, tuple)):
            return [service._sanitize_for_capture(item, depth - 1) for item in value]

        if isinstance(value, dict):
            return {
                str(key): service._sanitize_for_capture(item, depth - 1)
                for key, item in value.items()
            }

        return sanitize_text(str(value))

    def _capture_log_label(self, value: Any) -> str:
        """
        Bound one capture-only diagnostic label before interpolation.

        After applying local validation, the function forwards ``value`` to
        ``self._bounded_identifier`` and preserves its return and exception
        contract.

        Args:
            value: Value evaluated while performing bound one capture-only
                diagnostic label before interpolation.

        Returns:
            The canonical capture log label.
        """

        return self._bounded_identifier(value, default="unknown")

    async def begin_request_response_capture(
        self,
        context: Dict[str, Any],
        method_name: str,
        options: Dict[str, Any],
    ) -> Optional[asyncio.Task[Any]]:
        """
        Enable request/response capture for the current coroutine.

        The implementation uses ``context``, ``method_name``, and ``options`` to
        enable request/response capture for the current coroutine. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. If the function
        cannot enable request/response capture for the current coroutine, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            context: Runtime context carrying state shared across this
                operation.
            method_name: Stable method name used for lookup and operator-facing
                diagnostics.
            options: Mapping supplying fields for enable request/response
                capture for the current coroutine.

        Returns:
            The validated ``task``, or ``None`` when no value qualifies.

        Raises:
            RuntimeError: If capture logger or DUT identity is unavailable.
        """

        service = self._service
        task = asyncio.current_task()
        if not task:
            return None
        publication_owner = self._current_publication_owner()

        target_collector_id = (
            context.get("collector_id")
            or service._get_current_collector_id()
            or service.service_name
        )
        target_dut_id = context.get("dut_id") or service._get_current_dut_id()
        method_slug = method_name.strip("_").replace(" ", "_") or method_name
        output_pattern = options.get("output_pattern") or (
            f"diagnostic/request_{method_slug}.json"
        )
        if not str(output_pattern).replace("\\", "/").startswith("diagnostic/"):
            output_pattern = f"diagnostic/{os.path.basename(str(output_pattern))}"

        spool = None
        capture_failure = None
        artifact_path = None
        runtime = service._get_request_capture_runtime()
        try:
            if not service.logger or not target_dut_id:
                raise RuntimeError("Capture logger or DUT identity is unavailable")
            group = service._get_collector_group(target_collector_id)
            artifact_path = await service.logger.create_collector_log_file(
                target_dut_id,
                group,
                target_collector_id,
                output_pattern,
            )
            started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            spool = await runtime.run(
                runtime.create_spool,
                policy=CaptureSanitizationPolicy.GENERIC_DIAGNOSTIC,
                captured_at=started_at,
                collector_id=str(target_collector_id),
                dut_id=str(target_dut_id),
                collector_group=str(group),
                publication_destination=artifact_path,
                external_text_sanitizer=service._capture_external_text_sanitizer(),
                sensitive_value_replacement=(
                    service._capture_sensitive_value_replacement()
                ),
                external_sensitive_name=(service._capture_sensitive_name_classifier()),
            )
        except (
            asyncio.CancelledError,
            KeyboardInterrupt,
            SystemExit,
        ) as initialization_control:
            cleanup_errors: List[BaseException] = []
            completed = getattr(
                initialization_control, "capture_completed_result", None
            )
            if isinstance(completed, RequestResponseCaptureSpool):
                try:
                    (
                        discard_control,
                        discard_error,
                    ) = await service._drain_capture_resource_discard(
                        runtime, completed
                    )
                    if discard_control is not None:
                        initialization_control = _remember_capture_control_flow(
                            initialization_control, discard_control
                        )
                    if discard_error is not None:
                        initialization_control = _defer_capture_failure(
                            initialization_control, cleanup_errors, discard_error
                        )
                except BaseException as cleanup_error:
                    initialization_control = _defer_capture_failure(
                        initialization_control, cleanup_errors, cleanup_error
                    )
                try:
                    runtime.abandon(completed)
                except BaseException as cleanup_error:
                    initialization_control = _defer_capture_failure(
                        initialization_control, cleanup_errors, cleanup_error
                    )
            _raise_capture_cleanup_outcome(
                initialization_control,
                cleanup_errors,
                "Generic request capture initialization cleanup failed",
            )
        except Exception as error:
            started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            capture_failure = bounded_capture_failure_metadata("initialize", error)

        state = {
            "collector_id": target_collector_id,
            "dut_id": target_dut_id,
            "stage": context.get("current_stage")
            or options.get("stage")
            or context.get("stage")
            or "unknown_stage",
            "method": method_name,
            "options": options.copy(),
            "spool": spool,
            "record_count": 0,
            "capture_failure": capture_failure,
            "artifact_path": str(artifact_path) if artifact_path else None,
            "started_at": started_at,
            "publication_owner": publication_owner,
        }
        try:
            stage_label = self._capture_log_label(state["stage"])
            method_label = self._capture_log_label(method_name)
            await service._log_runtime(
                "DEBUG",
                "BaseService",
                f"Enabled request/response capture for {stage_label}::{method_label}",
                cast(str, context.get("dut_id")),
            )
        except BaseException as logging_error:
            cleanup_errors = []
            logging_control = _defer_capture_failure(
                None, cleanup_errors, logging_error
            )
            if spool is not None:
                try:
                    (
                        discard_control,
                        discard_error,
                    ) = await service._drain_capture_resource_discard(runtime, spool)
                    if discard_control is not None:
                        logging_control = _defer_capture_failure(
                            logging_control,
                            cleanup_errors,
                            discard_control,
                        )
                    if discard_error is not None:
                        logging_control = _defer_capture_failure(
                            logging_control,
                            cleanup_errors,
                            discard_error,
                        )
                except BaseException as cleanup_error:
                    logging_control = _defer_capture_failure(
                        logging_control,
                        cleanup_errors,
                        cleanup_error,
                    )
                try:
                    runtime.abandon(spool)
                except BaseException as cleanup_error:
                    logging_control = _defer_capture_failure(
                        logging_control,
                        cleanup_errors,
                        cleanup_error,
                    )
            _raise_capture_cleanup_outcome(
                logging_control,
                cleanup_errors,
                "Generic request capture logging-boundary cleanup failed",
            )

        # The append and token return form one non-awaiting ownership handoff.
        service._request_response_capture_states.setdefault(task, []).append(state)
        return task

    async def record_request_response(
        self,
        request_info: Dict[str, Any],
        response_info: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Append one pair through the run-owned bounded capture worker.

        The implementation uses ``request_info``, ``response_info``, and
        ``metadata`` to append one pair through the run-owned bounded capture
        worker. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            request_info: Mapping supplying fields for append one pair through
                the run-owned bounded capture worker.
            response_info: Optional response info; ``None`` selects the
                function's default behavior.
            metadata: Optional metadata; ``None`` selects the function's default
                behavior.
        """

        service = self._service
        task = asyncio.current_task()
        if not task:
            return

        stack = service._request_response_capture_states.get(task)
        if not stack:
            return

        state = stack[-1] if stack else None
        if not state:
            return

        spool = state.get("spool")
        if spool is None or state.get("capture_failure"):
            return
        runtime = service._get_request_capture_runtime()
        try:
            await runtime.run(
                spool.append,
                timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                request=request_info,
                response=response_info,
                metadata=metadata,
            )
            state["record_count"] = spool.record_count
        except asyncio.CancelledError:
            raise
        except Exception as error:
            state["capture_failure"] = bounded_capture_failure_metadata(
                "append",
                error,
                limit_reached=isinstance(error, CaptureLimitExceeded),
            )

    async def finalize_request_response_capture(
        self,
        token: Optional[asyncio.Task[Any]],
        context: Dict[str, Any],
        method_name: str,
        options: Dict[str, Any],
        hook_result: Optional[Dict[str, Any]],
        error: Optional[BaseException],
    ) -> Optional[Tuple[Optional[str], Dict[str, Any]]]:
        """
        Flush captured request/response pairs to disk and return metadata.

        A hook that escaped never has a successful evidence lifecycle. Drain its
        private spool and leave the original hook outcome to the caller-side
        precedence selector; never publish from this branch.

        Args:
            token: Sensitive value supplied through the approved input boundary
                and never logged.
            context: Runtime context carrying state shared across this
                operation.
            method_name: Stable method name used for lookup and operator-facing
                diagnostics.
            options: Mapping supplying fields for flush captured
                request/response pairs to disk and return metadata.
            hook_result: Callable invoked at the hook result boundary.
            error: Exception or failure detail associated with the operation.

        Returns:
            A tuple containing ``status or message text`` and ``metadata
            mapping`` in that order.
        """

        del hook_result  # Retained by the facade as a historical compatibility seam.
        service = self._service
        task = token or asyncio.current_task()
        if not task:
            return None

        stack = service._request_response_capture_states.get(task)
        if not stack:
            return None

        state = stack.pop()
        if not stack:
            service._request_response_capture_states.pop(task, None)

        spool = state.get("spool")
        record_count = int(state.get("record_count") or 0)
        capture_failure = state.get("capture_failure")
        runtime = service._get_request_capture_runtime()
        if error is not None:
            # A hook that escaped never has a successful evidence lifecycle.
            # Drain its private spool and leave the original hook outcome to the
            # caller-side precedence selector; never publish from this branch.
            control_flow: Optional[BaseException] = None
            cleanup_errors: List[BaseException] = []
            if spool is not None:
                try:
                    (
                        discard_control,
                        discard_error,
                    ) = await service._drain_capture_resource_discard(runtime, spool)
                    if discard_control is not None:
                        control_flow = _defer_capture_failure(
                            control_flow,
                            cleanup_errors,
                            discard_control,
                        )
                    if discard_error is not None:
                        control_flow = _defer_capture_failure(
                            control_flow,
                            cleanup_errors,
                            discard_error,
                        )
                except BaseException as cleanup_error:
                    control_flow = _defer_capture_failure(
                        control_flow,
                        cleanup_errors,
                        cleanup_error,
                    )
                try:
                    runtime.abandon(spool)
                except BaseException as cleanup_error:
                    control_flow = _defer_capture_failure(
                        control_flow,
                        cleanup_errors,
                        cleanup_error,
                    )
            _raise_capture_cleanup_outcome(
                control_flow,
                cleanup_errors,
                "Failed-hook request capture cleanup failed",
            )
            return None
        if spool is None or record_count <= 0:
            if spool is not None:
                try:
                    await runtime.run(spool.discard)
                finally:
                    runtime.abandon(spool)
            stage_label = self._capture_log_label(state.get("stage", "unknown_stage"))
            method_label = self._capture_log_label(method_name)
            await service._log_runtime(
                "DEBUG",
                "BaseService",
                f"No request/response data captured for {stage_label}::{method_label}",
                cast(str, context.get("dut_id")),
            )
            if capture_failure:
                return None, {
                    "key": f"{state.get('stage')}:{method_name.strip('_')}",
                    "stage": state.get("stage"),
                    "captured_records": 0,
                    "capture_failure": capture_failure,
                }
            return None

        merged_options = state.get("options", {}).copy()
        if options:
            merged_options.update(options)
        stage_name = state.get("stage") or "stage"
        method_slug = method_name.strip("_") or method_name
        capture_key = merged_options.get("capture_key") or f"{stage_name}:{method_slug}"
        candidate = None
        verified = None
        transaction = None
        published = None
        retained_ambiguous = None
        control_flow = None
        cleanup_errors = []
        try:
            candidate = await runtime.run(spool.finalize_private_candidate)
            await runtime.run(spool.discard)
            verified = await runtime.run(candidate.verify_private_copy)
            await runtime.run(candidate.discard)
            transaction = await runtime.run(verified.handoff_to_private_transaction)
            published = await runtime.run(runtime.publish_and_discard, transaction)
        except (
            asyncio.CancelledError,
            KeyboardInterrupt,
            SystemExit,
        ) as operation_control:
            control_flow = operation_control
            completed = getattr(operation_control, "capture_completed_result", None)
            if isinstance(completed, PublishedCaptureSummary):
                published = completed
                try:
                    await runtime.run(runtime.rollback_published, completed)
                except BaseException as rollback_error:
                    if hasattr(rollback_error, "capture_completed_result"):
                        published = None
                    control_flow = _defer_capture_failure(
                        control_flow, cleanup_errors, rollback_error
                    )
                else:
                    published = None
            elif isinstance(completed, PrivateCapturePublicationTransaction):
                transaction = completed
            elif isinstance(completed, VerifiedPrivateCapture):
                verified = completed
            elif isinstance(completed, PrivateCaptureCandidate):
                candidate = completed
        except CapturePublicationAmbiguousError as capture_error:
            retained_ambiguous = capture_error.summary
            capture_failure = bounded_capture_failure_metadata(
                "publication_rollback", capture_error
            )
            try:
                await runtime.run(runtime.rollback_published, capture_error.summary)
            except Exception:
                pass
            else:
                retained_ambiguous = None
        except Exception as capture_error:
            capture_failure = bounded_capture_failure_metadata(
                "finalize", capture_error
            )
        finally:
            for resource in (transaction, verified, candidate, spool):
                if resource is None:
                    continue
                try:
                    (
                        discard_control,
                        discard_error,
                    ) = await service._drain_capture_resource_discard(runtime, resource)
                    if discard_control is not None:
                        control_flow = _remember_capture_control_flow(
                            control_flow, discard_control
                        )
                    if discard_error is not None:
                        control_flow = _defer_capture_failure(
                            control_flow, cleanup_errors, discard_error
                        )
                except BaseException as cleanup_error:
                    control_flow = _defer_capture_failure(
                        control_flow, cleanup_errors, cleanup_error
                    )
            if published is None and retained_ambiguous is None:
                try:
                    runtime.abandon(transaction or verified or candidate or spool)
                except BaseException as cleanup_error:
                    control_flow = _defer_capture_failure(
                        control_flow, cleanup_errors, cleanup_error
                    )

        if control_flow is not None and published is not None:
            try:
                await runtime.run(runtime.rollback_published, published)
            except BaseException as rollback_error:
                if hasattr(rollback_error, "capture_completed_result"):
                    published = None
                control_flow = _defer_capture_failure(
                    control_flow, cleanup_errors, rollback_error
                )
            else:
                published = None
        if control_flow is not None or cleanup_errors:
            _raise_capture_cleanup_outcome(
                control_flow,
                cleanup_errors,
                "Generic request capture finalization cleanup failed",
            )

        if published is None:
            return None, {
                "key": capture_key,
                "stage": stage_name,
                "captured_records": record_count,
                "capture_failure": capture_failure,
            }

        publication_key, publication_owner = service._request_capture_publication_owner(
            str(state.get("dut_id")),
            str(state.get("collector_id")),
            state.get("publication_owner"),
        )
        if not service._collector_budget_token_is_current(
            str(state.get("dut_id")),
            str(state.get("collector_id")),
            publication_owner,
        ):
            rollback_control: Optional[BaseException] = None
            rollback_errors: List[BaseException] = []
            try:
                await runtime.run(runtime.rollback_published, published)
            except BaseException as rollback_error:
                if hasattr(rollback_error, "capture_completed_result"):
                    published = None
                rollback_control = _defer_capture_failure(
                    rollback_control,
                    rollback_errors,
                    rollback_error,
                )
            else:
                published = None
            _raise_capture_cleanup_outcome(
                rollback_control,
                rollback_errors,
                "Stale request capture publication rollback failed",
            )
            return None

        # Ownership check and append are one synchronous handoff. No timeout or
        # peer task can invalidate this owner between the check and registration.
        service._pending_request_capture_publications.setdefault(
            publication_key, []
        ).append(published)
        return published.path, {
            "key": capture_key,
            "stage": stage_name,
            "captured_records": record_count,
            "size_bytes": published.size_bytes,
            "sha256": published.sha256,
            "sanitization_policy_id": published.sanitization_policy_id,
            "published": True,
            "capture_failure": capture_failure,
        }
