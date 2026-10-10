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
Generic host for optional trusted run-lifecycle extensions.

This module owns the extension lifecycle boundary and exposes
``ExtensionLifecycleError``, ``ExtensionLifecycleDescriptor``,
``ExtensionLifecycleContext``, ``_PreparedExtension``, and ``_as_enabled``.
Keeping those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import inspect
import json
import os
import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

from ..utils.trusted_extensions import (
    TRUSTED_EXTENSION_PACKAGE,
    TrustedExtensionError,
    import_trusted_extension_module,
    lifecycle_descriptors,
)

_NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MODULE_RE = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")


class ExtensionLifecycleError(RuntimeError):
    """
    Raised before mutation when lifecycle configuration is not executable.

    Callers receive this exception when the extension lifecycle error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


@dataclass(frozen=True)
class ExtensionLifecycleDescriptor:
    """
    Implement the extension lifecycle descriptor boundary used by the NVDebug runtime.

    Implement the extension lifecycle descriptor boundary used by the NVDebug
    runtime.

    The immutable record keeps ``namespace``, ``module``, ``factory``,
    ``capability_namespace``, and ``required_services`` together so consumers
    observe one extension lifecycle descriptor state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        namespace: Canonical text used as namespace.
        module: Canonical text used as module.
        factory: Canonical text used as factory.
        capability_namespace: Canonical text used as capability namespace.
        required_services: Collection of required services entries retained by
            this record.
    """

    namespace: str
    module: str
    factory: str
    capability_namespace: str
    required_services: tuple[str, ...]


@dataclass(frozen=True)
class ExtensionLifecycleContext:
    """
    Restricted service surface supplied to trusted lifecycle factories.

    The immutable record keeps ``dut_manager``, ``logger``,
    ``dependency_checker``, ``timing_manager``, and ``log_dir`` together so
    consumers observe one extension lifecycle context state. Consumers receive
    the fields as one unit instead of assembling partial state.

    Attributes:
        dut_manager: DUT manager retained as part of the record's public state.
        logger: Logger retained as part of the record's public state.
        dependency_checker: Dependency checker retained as part of the record's
            public state.
        timing_manager: Timing manager retained as part of the record's public
            state.
        log_dir: Log dir retained as part of the record's public state.
    """

    dut_manager: Any
    logger: Any
    dependency_checker: Any
    timing_manager: Any
    log_dir: Any
    _shutdown_check: Any
    _collector_catalog_getter: Any
    _collector_scope_getter: Any
    _runtime_capabilities_getter: Any
    _lifecycle_status_getter: Any
    _collector_results_getter: Any

    def is_shutdown_requested(self) -> bool:
        """
        Return whether ``the current value`` is shutdown requested.

        After applying local validation, the function forwards current instance
        state to ``bool`` and preserves its return and exception contract.

        Returns:
            Whether ``the current value`` is shutdown requested.
        """
        return bool(self._shutdown_check())

    def get_collector_catalog(self) -> Dict[str, Any]:
        """
        Return an isolated snapshot of the runtime collector catalog.

        The implementation uses current instance state to produce an isolated
        snapshot of the runtime collector catalog.

        Returns:
            A mapping containing collector catalog.
        """

        value = self._collector_catalog_getter()
        return deepcopy(value) if isinstance(value, dict) else {}

    def get_collector_scope(self, dut_id: str) -> Dict[str, Any]:
        """
        Return selected, available, and skipped collector evidence for a DUT.

        The implementation uses ``dut_id`` to produce selected, available, and
        skipped collector evidence for a DUT.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing collector scope.
        """

        value = self._collector_scope_getter(dut_id)
        return deepcopy(value) if isinstance(value, dict) else {}

    def get_runtime_capabilities(self, dut_id: str) -> Dict[str, Any]:
        """
        Return capabilities already published by an earlier extension.

        The implementation uses ``dut_id`` to produce capabilities already
        published by an earlier extension.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing runtime capabilities.
        """

        value = self._runtime_capabilities_getter(dut_id)
        return deepcopy(value) if isinstance(value, dict) else {}

    def get_lifecycle_status(self, namespace: str, dut_id: str) -> Dict[str, str]:
        """
        Return only safe phase/outcome evidence from an earlier extension.

        The implementation uses ``namespace`` and ``dut_id`` to produce only
        safe phase/outcome evidence from an earlier extension.

        Args:
            namespace: Text supplied as namespace in the format accepted by this
                function.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing lifecycle status.
        """

        value = self._lifecycle_status_getter(namespace, dut_id)
        if not isinstance(value, dict):
            return {}
        return {
            key: value[key]
            for key in ("phase", "outcome")
            if isinstance(value.get(key), str)
        }

    def get_collector_results(
        self, collector_ids: Optional[Iterable[str]] = None
    ) -> Dict[str, Any]:
        """
        Return an isolated, optionally filtered collector-result snapshot.

        The implementation uses ``collector_ids`` to produce an isolated,
        optionally filtered collector-result snapshot.

        Args:
            collector_ids: Optional collector identifiers; ``None`` selects the
                function's default behavior.

        Returns:
            A mapping containing collector results.
        """

        value = self._collector_results_getter()
        if not isinstance(value, dict):
            return {}
        if collector_ids is None:
            return deepcopy(value)
        selected = {str(collector_id) for collector_id in collector_ids}
        filtered: Dict[str, Any] = {}
        for lane in ("sequential_results", "parallel_results"):
            lane_results = value.get(lane)
            if not isinstance(lane_results, dict):
                continue
            filtered[lane] = {
                collector_id: deepcopy(result)
                for collector_id, result in lane_results.items()
                if str(collector_id) in selected
            }
        return filtered


@dataclass
class _PreparedExtension:
    """
    Implement the prepared extension boundary used by the NVDebug runtime.

    The coherent record keeps ``descriptor``, ``instance``, ``dut_ids``, and
    ``finalized`` together so consumers observe one prepared extension state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        descriptor: Descriptor retained as part of the record's public state.
        instance: Instance retained as part of the record's public state.
        dut_ids: Collection of DUT identifiers entries retained by this record.
        finalized: Whether finalized applies to this record.
    """

    descriptor: ExtensionLifecycleDescriptor
    instance: Any
    dut_ids: tuple[str, ...]
    finalized: bool = False


def _as_enabled(value: Any) -> bool:
    """
    Return the as enabled.

    The implementation uses ``value`` to produce the as enabled.

    Args:
        value: Value object whose ``strip`` state is read while performing as
            enabled.

    Returns:
        Whether the as enabled operation succeeds.
    """
    if isinstance(value, str):
        return value.strip().casefold() in {"1", "true", "yes", "on"}
    return value is True


class ExtensionLifecycleManager:
    """
    Prepare, execute, and finalize trusted extensions without product dispatch.

    The type coordinates ``reset_run_state``, ``_descriptor``, ``_descriptors``,
    ``_config_for_dut``, and ``_enabled`` and retains the state those operations
    share between calls. Resource ownership remains inside the instance until
    the matching close, exit, or cleanup operation completes.
    """

    def __init__(self, orchestrator: Any) -> None:
        """
        Initialize an ``ExtensionLifecycleManager`` instance.

        The initializer records ``_prepared``, ``orchestrator``, and ``results``
        for later operations and establishes the instance invariants before any
        public method runs.

        Args:
            orchestrator: Orchestrator consumed while the function attempts to
                initialize an ``ExtensionLifecycleManager`` instance.
        """
        self.orchestrator = orchestrator
        self._prepared: list[_PreparedExtension] = []
        self.results: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def reset_run_state(self) -> None:
        """
        Discard only completed run state before a new collection invocation.

        The implementation uses current instance state to discard only completed
        run state before a new collection invocation. It updates ``_prepared``
        and ``results`` on the instance as part of that state transition. If the
        function cannot discard only completed run state before a new collection
        invocation, its exception reaches the caller instead of being converted
        into a successful result.

        Raises:
            ExtensionLifecycleError: If lifecycle extensions must finalize
                before a new run starts.
        """

        if any(not prepared.finalized for prepared in self._prepared):
            raise ExtensionLifecycleError(
                "Lifecycle extensions must finalize before a new run starts"
            )
        self._prepared = []
        self.results = {}

    @staticmethod
    def _descriptor(raw: Mapping[str, Any]) -> ExtensionLifecycleDescriptor:
        """
        Return the descriptor.

        After applying local validation, the function forwards ``raw`` to
        ``ExtensionLifecycleDescriptor`` and preserves its return and exception
        contract.

        Args:
            raw: Mapping supplying fields for descriptor.

        Returns:
            An ``ExtensionLifecycleDescriptor`` representing descriptor.

        Raises:
            ExtensionLifecycleError: If trusted lifecycle descriptors must
                contain exactly the supported fields; lifecycle extension
                namespace is invalid; lifecycle extension module is outside the
                trusted namespace; or lifecycle extension factory is invalid; or
                another input invariant is violated.
        """
        expected = {
            "namespace",
            "module",
            "factory",
            "capability_namespace",
            "required_services",
        }
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise ExtensionLifecycleError(
                "Trusted lifecycle descriptors must contain exactly the supported fields"
            )
        namespace = raw["namespace"]
        module = raw["module"]
        factory = raw["factory"]
        capability_namespace = raw["capability_namespace"]
        required_services = raw["required_services"]
        if not isinstance(namespace, str) or not _NAMESPACE_RE.fullmatch(namespace):
            raise ExtensionLifecycleError("Lifecycle extension namespace is invalid")
        if (
            not isinstance(module, str)
            or not _MODULE_RE.fullmatch(module)
            or not module.startswith(f"{TRUSTED_EXTENSION_PACKAGE}.")
        ):
            raise ExtensionLifecycleError(
                "Lifecycle extension module is outside the trusted namespace"
            )
        if not isinstance(factory, str) or not _IDENTIFIER_RE.fullmatch(factory):
            raise ExtensionLifecycleError("Lifecycle extension factory is invalid")
        if not isinstance(capability_namespace, str) or not _NAMESPACE_RE.fullmatch(
            capability_namespace
        ):
            raise ExtensionLifecycleError("Lifecycle capability namespace is invalid")
        if not isinstance(required_services, (list, tuple)) or not all(
            isinstance(item, str) and _NAMESPACE_RE.fullmatch(item)
            for item in required_services
        ):
            raise ExtensionLifecycleError(
                "Lifecycle required_services must contain valid service names"
            )
        return ExtensionLifecycleDescriptor(
            namespace=namespace,
            module=module,
            factory=factory,
            capability_namespace=capability_namespace,
            required_services=tuple(required_services),
        )

    def _descriptors(self) -> Dict[str, ExtensionLifecycleDescriptor]:
        """
        Return the descriptors.

        The implementation uses current instance state to produce the
        descriptors. If the function cannot produce the descriptors, its
        exception reaches the caller instead of being converted into a
        successful result.

        Returns:
            The validated ``descriptors``.

        Raises:
            ExtensionLifecycleError: If the function cannot produce the
                descriptors safely; or duplicate lifecycle namespace
                ``namespace``.
        """
        try:
            items = tuple(lifecycle_descriptors())
        except TrustedExtensionError as error:
            raise ExtensionLifecycleError(str(error)) from error
        descriptors: Dict[str, ExtensionLifecycleDescriptor] = {}
        for raw in items:
            descriptor = self._descriptor(raw)
            if descriptor.namespace in descriptors:
                raise ExtensionLifecycleError(
                    f"Duplicate lifecycle namespace {descriptor.namespace!r}"
                )
            descriptors[descriptor.namespace] = descriptor
        return descriptors

    def _config_for_dut(self, dut_id: str) -> Dict[str, Any]:
        """
        Return the config for DUT.

        The implementation uses ``dut_id`` to produce the config for DUT.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing config for DUT.
        """
        dut_manager = self.orchestrator.dut_manager
        if dut_manager is None:
            return {}
        config = dut_manager.get_dut_config(dut_id)
        if not isinstance(config, dict):
            return {}
        extensions = config.get("COLLECTOR_EXTENSION_CONFIG", {})
        return extensions if isinstance(extensions, dict) else {}

    def _enabled(self, dut_ids: Iterable[str]) -> Dict[str, list[str]]:
        """
        Return whether enabled for the current input and state.

        The implementation uses ``dut_ids`` to determine whether enabled for the
        current input and state.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.

        Returns:
            The validated ``enabled``.
        """
        enabled: Dict[str, list[str]] = {}
        for dut_id in dut_ids:
            for namespace, config in self._config_for_dut(dut_id).items():
                if isinstance(config, dict) and _as_enabled(config.get("enabled")):
                    enabled.setdefault(str(namespace), []).append(dut_id)
        return enabled

    def has_enabled_extensions(self, dut_ids: Iterable[str]) -> bool:
        """
        Return whether ``dut_ids`` has enabled extensions.

        The implementation uses ``dut_ids`` to determine whether ``dut_ids`` has
        enabled extensions. If the function cannot determine whether ``dut_ids``
        has enabled extensions, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.

        Returns:
            Whether ``dut_ids`` has enabled extensions.

        Raises:
            ExtensionLifecycleError: If the function cannot determine whether
                ``dut_ids`` has enabled extensions safely.
        """
        enabled = self._enabled(dut_ids)
        if not enabled:
            return False
        missing = sorted(set(enabled) - set(self._descriptors()))
        if missing:
            raise ExtensionLifecycleError(
                "Enabled lifecycle extension has no trusted descriptor: "
                + ", ".join(missing)
            )
        return True

    def _context(self) -> ExtensionLifecycleContext:
        """
        Return the context.

        After applying local validation, the function forwards current instance
        state to ``ExtensionLifecycleContext`` and preserves its return and
        exception contract.

        Returns:
            An ``ExtensionLifecycleContext`` representing context.
        """
        orchestrator = self.orchestrator
        return ExtensionLifecycleContext(
            dut_manager=orchestrator.dut_manager,
            logger=orchestrator.logger,
            dependency_checker=orchestrator.dependency_checker,
            timing_manager=orchestrator.timing_manager,
            log_dir=orchestrator.log_dir,
            _shutdown_check=orchestrator.is_shutdown_requested,
            _collector_catalog_getter=getattr(
                orchestrator, "get_all_collectors", lambda: {}
            ),
            _collector_scope_getter=lambda dut_id: getattr(
                orchestrator, "_extension_collector_scope", {}
            ).get(dut_id, {}),
            _runtime_capabilities_getter=lambda dut_id: getattr(
                orchestrator, "runtime_capabilities", {}
            ).get(dut_id, {}),
            _lifecycle_status_getter=lambda namespace, dut_id: self.results.get(
                namespace, {}
            ).get(dut_id, {}),
            _collector_results_getter=lambda: getattr(
                orchestrator, "_extension_collector_results", {}
            ),
        )

    async def _log(self, level: str, message: str) -> None:
        """
        Log one sanitized runtime event.

        The implementation uses ``level`` and ``message`` to log one sanitized
        runtime event. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """
        logger = getattr(self.orchestrator, "logger", None)
        if logger is not None:
            await logger.log_runtime(level, "ExtensionLifecycle", message)

    @staticmethod
    async def _invoke(callable_value: Any, **kwargs: Any) -> Any:
        """
        Invoke the configured operation.

        The implementation uses ``callable_value`` and ``kwargs`` to invoke the
        configured operation. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind.

        Args:
            callable_value: Callable value consumed while the function attempts
                to invoke the configured operation.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The validated ``result``.
        """
        result = callable_value(**kwargs)
        if inspect.isawaitable(result):
            result = await result
        return result

    def _failure_records(
        self, namespace: str, dut_ids: Sequence[str], phase: str, reason: str
    ) -> Dict[str, Dict[str, Any]]:
        """
        Return the failure records.

        The implementation uses ``namespace``, ``dut_ids``, ``phase``, and
        ``reason`` to produce the failure records.

        Args:
            namespace: Text supplied as namespace in the format accepted by this
                function.
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            phase: Text supplied as phase in the format accepted by this
                function.
            reason: Text supplied as reason in the format accepted by this
                function.

        Returns:
            A mapping containing failure records.
        """
        return {
            dut_id: {
                "schema_version": "1.0",
                "namespace": namespace,
                "dut_id": dut_id,
                "phase": phase,
                "outcome": "failed",
                "capabilities": [],
                "errors": [{"code": f"{phase}_failed", "message": reason}],
                "warnings": [],
            }
            for dut_id in dut_ids
        }

    def _result_path(self, namespace: str, dut_id: str) -> Path:
        """
        Return a contained, namespace-scoped result path for one DUT.

        The implementation uses ``namespace`` and ``dut_id`` to produce a
        contained, namespace-scoped result path for one DUT. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle. If the function cannot produce a contained, namespace-scoped
        result path for one DUT, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            namespace: Text supplied as namespace in the format accepted by this
                function.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``target``.

        Raises:
            ExtensionLifecycleError: If lifecycle result path for DUT ``dut_id``
                escapes the output root.
        """

        output_root = Path(self.orchestrator.log_dir).resolve()
        target = (
            output_root / dut_id / ".metadata" / "extensions" / f"{namespace}.json"
        ).resolve()
        if not target.is_relative_to(output_root):
            raise ExtensionLifecycleError(
                f"Lifecycle result path for DUT {dut_id!r} escapes the output root"
            )
        return target

    def _persist_record(
        self, namespace: str, dut_id: str, record: Mapping[str, Any]
    ) -> None:
        """
        Atomically retain the latest JSON-safe lifecycle result snapshot.

        The implementation uses ``namespace``, ``dut_id``, and ``record`` to
        atomically retain the latest JSON-safe lifecycle result snapshot.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle. If the function cannot atomically retain the
        latest JSON-safe lifecycle result snapshot, its exception reaches the
        caller instead of being converted into a successful result. Cleanup in
        the ``finally`` path runs for successful, failed, and cancelled
        execution.

        Args:
            namespace: Text supplied as namespace in the format accepted by this
                function.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            record: Mapping supplying fields for atomically retain the latest
                JSON-safe lifecycle result snapshot.

        Raises:
            ExtensionLifecycleError: If lifecycle result for ``dut_id`` is not
                JSON-safe.
        """

        if not self._json_safe(record):
            raise ExtensionLifecycleError(
                f"Lifecycle result for {dut_id!r} is not JSON-safe"
            )
        target = self._result_path(namespace, dut_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(record, handle, indent=2, sort_keys=True, allow_nan=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def _persist_records(
        self, namespace: str, records: Mapping[str, Mapping[str, Any]]
    ) -> None:
        """
        Persist records.

        The implementation uses ``namespace`` and ``records`` to persist
        records. Success is reported only after the owning output boundary has
        completed its required write or publication step.

        Args:
            namespace: Text supplied as namespace in the format accepted by this
                function.
            records: Mapping supplying fields for records.
        """
        for dut_id, record in records.items():
            self._persist_record(namespace, dut_id, record)

    async def prepare(
        self,
        dut_ids: Iterable[str],
        platform_results: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Complete every non-mutating prepare before any execute is allowed.

        Trusted descriptor order is the lifecycle dependency order. Every
        extension still prepares before any execute call, while execute runs
        forward and finalize runs in reverse. Sorting namespaces here would
        silently break dependencies such as authorization verification,
        dependent evidence planning, and deferred cleanup.

        Args:
            dut_ids: Entries supplied as ``dut_ids`` without transferring
                container ownership.
            platform_results: Optional platform results; ``None`` selects the
                function's default behavior.

        Raises:
            ExtensionLifecycleError: If lifecycle extensions were already
                prepared; the function cannot complete every non-mutating
                prepare before any execute is allowed safely; lifecycle factory
                ``module``:``factory`` is unavailable; or lifecycle extension
                ``namespace`` has no ``method_name`` method.
        """

        if self._prepared:
            raise ExtensionLifecycleError("Lifecycle extensions were already prepared")
        enabled = self._enabled(dut_ids)
        if not enabled:
            return
        descriptors = self._descriptors()
        missing = sorted(set(enabled) - set(descriptors))
        if missing:
            raise ExtensionLifecycleError(
                "Enabled lifecycle extension has no trusted descriptor: "
                + ", ".join(missing)
            )
        available_services = self.orchestrator.config_manager.get_services()
        # Trusted descriptor order is the lifecycle dependency order.  Every
        # extension still prepares before any execute call, while execute runs
        # forward and finalize runs in reverse.  Sorting namespaces here would
        # silently break dependencies such as authorization verification,
        # dependent evidence planning, and deferred cleanup.
        for namespace, descriptor in descriptors.items():
            if namespace not in enabled:
                continue
            extension_duts = tuple(enabled[namespace])
            missing_services = [
                name
                for name in descriptor.required_services
                if available_services.get(name) is None
            ]
            if missing_services:
                raise ExtensionLifecycleError(
                    f"Lifecycle extension {namespace!r} requires unavailable services: "
                    + ", ".join(missing_services)
                )
            try:
                module = import_trusted_extension_module(descriptor.module)
                factory = getattr(module, descriptor.factory, None)
                if not callable(factory):
                    raise ExtensionLifecycleError(
                        f"Lifecycle factory {descriptor.module}:{descriptor.factory} "
                        "is unavailable"
                    )
                instance = factory(
                    context=self._context(),
                    services={
                        name: available_services[name]
                        for name in descriptor.required_services
                    },
                    descriptor=descriptor,
                )
                for method_name in ("prepare", "execute", "finalize"):
                    if not callable(getattr(instance, method_name, None)):
                        raise ExtensionLifecycleError(
                            f"Lifecycle extension {namespace!r} has no {method_name} method"
                        )
                await self._invoke(
                    instance.prepare,
                    dut_ids=extension_duts,
                    platform_results=platform_results or {},
                )
                self._prepared.append(
                    _PreparedExtension(descriptor, instance, extension_duts)
                )
            except Exception as error:
                reason = f"{type(error).__name__}: {error}"
                self.results[namespace] = self._failure_records(
                    namespace, extension_duts, "prepare", reason
                )
                self._persist_records(namespace, self.results[namespace])
                await self._log(
                    "ERROR",
                    f"Lifecycle extension {namespace!r} prepare failed: {reason}",
                )

    @staticmethod
    def _json_safe(value: Any) -> bool:
        """
        Return the JSON safe.

        The implementation uses ``value`` to produce the JSON safe.

        Args:
            value: Value evaluated while performing JSON safe.

        Returns:
            Whether the JSON safe operation succeeds.
        """
        try:
            json.dumps(value, allow_nan=False)
        except (TypeError, ValueError):
            return False
        return True

    def _normalize_record(
        self,
        namespace: str,
        dut_id: str,
        value: Any,
    ) -> Dict[str, Any]:
        """
        Normalize record.

        The implementation uses ``namespace``, ``dut_id``, and ``value`` to
        normalize record. The source value keeps its ownership while the
        normalized representation is returned separately. If the function cannot
        normalize record, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            namespace: Text supplied as namespace in the format accepted by this
                function.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            value: Value evaluated while performing record.

        Returns:
            The validated ``record``.

        Raises:
            ExtensionLifecycleError: If lifecycle result for ``dut_id`` is
                absent or not JSON-safe; lifecycle result identity for
                ``dut_id`` does not match its request; or lifecycle result for
                ``dut_id`` has invalid ``key``.
        """
        if not isinstance(value, dict) or not self._json_safe(value):
            raise ExtensionLifecycleError(
                f"Lifecycle result for {dut_id!r} is absent or not JSON-safe"
            )
        record = dict(value)
        declared_namespace = record.setdefault("namespace", namespace)
        declared_dut = record.setdefault("dut_id", dut_id)
        if declared_namespace != namespace or declared_dut != dut_id:
            raise ExtensionLifecycleError(
                f"Lifecycle result identity for {dut_id!r} does not match its request"
            )
        for key in ("schema_version", "phase", "outcome"):
            field = record.get(key)
            if not isinstance(field, str) or not field.strip():
                raise ExtensionLifecycleError(
                    f"Lifecycle result for {dut_id!r} has invalid {key}"
                )
        for key in ("capabilities", "errors", "warnings"):
            field = record.get(key)
            if not isinstance(field, list) or not self._json_safe(field):
                raise ExtensionLifecycleError(
                    f"Lifecycle result for {dut_id!r} has invalid {key}"
                )
        return record

    async def execute(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """
        Execute the configured operation through its owned lifecycle.

        The implementation uses current instance state to execute the configured
        operation through its owned lifecycle. Terminal status is emitted only
        after configured operation through its owned lifecycle and its owned
        cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind. If the
        function cannot execute the configured operation through its owned
        lifecycle, its exception reaches the caller instead of being converted
        into a successful result.

        Returns:
            A mapping containing execute.

        Raises:
            ExtensionLifecycleError: If lifecycle execute returned a non-mapping
                result; or the function cannot execute the configured operation
                through its owned lifecycle safely.
        """
        for prepared in self._prepared:
            descriptor = prepared.descriptor
            namespace = descriptor.namespace
            try:
                raw = await self._invoke(prepared.instance.execute)
                if not isinstance(raw, dict):
                    raise ExtensionLifecycleError(
                        "Lifecycle execute returned a non-mapping result"
                    )
                unexpected = sorted(
                    str(item) for item in set(raw) - set(prepared.dut_ids)
                )
                if unexpected:
                    raise ExtensionLifecycleError(
                        "Lifecycle execute returned results for unexpected DUTs: "
                        + ", ".join(unexpected)
                    )
                records: Dict[str, Dict[str, Any]] = {}
                for dut_id in prepared.dut_ids:
                    record = self._normalize_record(namespace, dut_id, raw.get(dut_id))
                    records[dut_id] = record
                    capabilities = record["capabilities"]
                    self.orchestrator.runtime_capabilities.setdefault(dut_id, {})[
                        descriptor.capability_namespace
                    ] = capabilities
                self.results[namespace] = records
                self._persist_records(namespace, records)
            except Exception as error:
                reason = f"{type(error).__name__}: {error}"
                self.results[namespace] = self._failure_records(
                    namespace, prepared.dut_ids, "execute", reason
                )
                self._persist_records(namespace, self.results[namespace])
                await self._log(
                    "ERROR",
                    f"Lifecycle extension {namespace!r} execute failed: {reason}",
                )
        return self.results

    async def finalize(self) -> None:
        """
        Finalize each prepared extension exactly once in reverse order.

        The implementation uses current instance state to finalize each prepared
        extension exactly once in reverse order. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. If the function cannot finalize each prepared extension exactly
        once in reverse order, its exception reaches the caller instead of being
        converted into a successful result.

        Raises:
            ExtensionLifecycleError: If lifecycle finalize returned a
                non-mapping result; or the function cannot finalize each
                prepared extension exactly once in reverse order safely.
        """

        for prepared in reversed(self._prepared):
            if prepared.finalized:
                continue
            prepared.finalized = True
            try:
                raw = await self._invoke(prepared.instance.finalize)
                if raw is not None:
                    if not isinstance(raw, dict):
                        raise ExtensionLifecycleError(
                            "Lifecycle finalize returned a non-mapping result"
                        )
                    unexpected = sorted(
                        str(item) for item in set(raw) - set(prepared.dut_ids)
                    )
                    if unexpected:
                        raise ExtensionLifecycleError(
                            "Lifecycle finalize returned results for unexpected DUTs: "
                            + ", ".join(unexpected)
                        )
                    records: Dict[str, Dict[str, Any]] = {}
                    for dut_id in prepared.dut_ids:
                        record = self._normalize_record(
                            prepared.descriptor.namespace,
                            dut_id,
                            raw.get(dut_id),
                        )
                        records[dut_id] = record
                        self.orchestrator.runtime_capabilities.setdefault(dut_id, {})[
                            prepared.descriptor.capability_namespace
                        ] = record["capabilities"]
                    self.results[prepared.descriptor.namespace] = records
            except Exception as error:
                reason = f"{type(error).__name__}: {error}"
                records = self.results.get(prepared.descriptor.namespace, {})
                for record in records.values():
                    record.setdefault("errors", []).append(
                        {"code": "finalize_failed", "message": reason}
                    )
                    record["finalization"] = {
                        "outcome": "failed",
                        "error": reason,
                    }
                    if record.get("outcome") == "completed":
                        record["outcome"] = "partial"
                self._persist_records(prepared.descriptor.namespace, records)
                await self._log(
                    "WARNING",
                    f"Lifecycle extension {prepared.descriptor.namespace!r} "
                    f"finalize failed: {reason}",
                )
            else:
                records = self.results.get(prepared.descriptor.namespace, {})
                for record in records.values():
                    record.setdefault("finalization", {"outcome": "completed"})
                self._persist_records(prepared.descriptor.namespace, records)
