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
Bounded diagnostic-task orchestration for :class:`RedfishService`.

The service remains the compatibility facade and owns transports, diagnostic
capture, artifact publication, provenance capabilities, runtime budgets, and all
externally patchable methods. This runner owns only diagnostic sequencing and
deliberately sends every nested operation back through that facade so existing
subclass and monkeypatch seams remain authoritative.
"""

from __future__ import annotations

import asyncio
import copy
import json
import math
import re
import time
from asyncio import Lock
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import (
    TYPE_CHECKING,
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Tuple,
)
from urllib.parse import urlsplit

from ..core.redfish_controller import request_controller_dut
from ..utils.persistent_post_guard import PersistentPostReservation
from ..utils.redfish_diagnostic_capacity import (
    DIAGNOSTIC_CAPACITY_POOLS_KEY,
    resolve_diagnostic_capacity_pool,
    validate_diagnostic_capacity_pools,
)
from ..utils.redfish_download import StreamedRedfishBody
from .redfish_task_monitor import (
    TaskPollDisposition,
    TaskPollFailureKind,
    classify_task_monitor_exhaustion,
    evaluate_task_poll,
    is_task_monitor_authorization_failure,
    should_try_next_monitor_candidate,
)

if TYPE_CHECKING:
    from .redfish_service import RedfishService


_DIAGNOSTIC_QUIESCENCE_PROBE_SECONDS = 5.0
_DIAGNOSTIC_QUIESCENCE_REQUEST_SECONDS = 2.0
_REMOTE_NO_RESUBMIT_MESSAGE_KEYS = frozenset(
    {"CreateLimitReachedForResource", "ResourceInUse"}
)


@dataclass
class DiagnosticAttemptDisposition:
    """
    Carry one internal diagnostic attempt decision across compatibility seams.

    The public dump-task API remains a two-item ``(success, value)`` tuple.
    Callers that own payload iteration may pass this mutable, per-attempt object
    to distinguish an attempted remote rejection from a pre-POST domain block
    without parsing human-readable reason text.

    Attributes:
        post_sent: Whether this attempt issued its non-idempotent POST.
        resubmit_allowed: Whether the caller may try another payload safely.
        blocked_before_post: Whether a prior gate stopped this attempt before I/O.
        remote_rejection: Whether an exact remote registry rejection is involved.
        message_id: Optional complete Redfish registry MessageId.
        http_status: Optional validated HTTP response status.
        origin_collector_id: Optional collector that established the gate.
        origin_dut_id: Optional DUT route that established the gate.
        reason: Optional controlled operator-facing disposition reason.
        capacity_pool: Qualified pool when only that pool forbids resubmission.
    """

    post_sent: bool = False
    resubmit_allowed: bool = True
    blocked_before_post: bool = False
    remote_rejection: bool = False
    message_id: Optional[str] = None
    http_status: Optional[int] = None
    origin_collector_id: Optional[str] = None
    origin_dut_id: Optional[str] = None
    reason: Optional[str] = None
    capacity_pool: Optional[str] = None

    def as_context(self) -> Dict[str, Any]:
        """
        Return a bounded mapping suitable for collector result context.

        Optional values are omitted instead of emitting ambiguous ``None``
        fields, while the four attempt-state booleans are always retained.

        Returns:
            A mapping containing only controlled diagnostic disposition fields.
        """

        context: Dict[str, Any] = {
            "post_sent": self.post_sent,
            "resubmit_allowed": self.resubmit_allowed,
            "blocked_before_post": self.blocked_before_post,
            "remote_rejection": self.remote_rejection,
        }
        for name in (
            "message_id",
            "http_status",
            "origin_collector_id",
            "origin_dut_id",
            "reason",
            "capacity_pool",
        ):
            value = getattr(self, name)
            if value is not None:
                context[name] = value
        return context


@dataclass(eq=False)
class DiagnosticParallelSession:
    """
    Own one bounded adaptive-parallel diagnostic execution session.

    A session exists only while its runner holds the ordinary diagnostic-domain
    lock. Device attempts receive distinct child domains so their complete
    lifecycles may overlap without allowing an unrelated collector to enter the
    same physical diagnostic domain. The runner invalidates the session before
    releasing the parent lock and promotes unresolved child state fail closed.

    Attributes:
        runner: Runner that created and validates the opaque session.
        dut_id: DUT route whose diagnostic domain is exclusively owned.
        parent_domain_key: Ordinary serialization domain held by the session.
        session_id: Process-local identifier used only for child-domain keys.
        attempts: Prepared attempts keyed by caller-controlled bounded labels.
        active: Whether the parent domain remains exclusively held.
    """

    runner: "RedfishDiagnosticRunner" = field(repr=False)
    dut_id: str
    parent_domain_key: Tuple[str, str]
    session_id: str
    attempts: Dict[str, "DiagnosticParallelAttempt"] = field(
        default_factory=dict,
        repr=False,
    )
    active: bool = True


@dataclass(eq=False)
class DiagnosticParallelAttempt:
    """
    Carry one prepared device attempt through adaptive task creation.

    The creation event lets the scheduler wait until the first Redfish POST has
    either produced a validated task reference or definitively failed before it
    starts the second probe. Exact structured busy rejections are retained as
    typed evidence; response prose is never parsed for fallback decisions.

    Attributes:
        session: Active parent session that owns this attempt.
        attempt_id: Bounded process-local label chosen by the scheduler.
        domain_key: Unique child domain used for task lifecycle tainting.
        creation_resolved: Event set after task-creation outcome is known.
        creation_accepted: Whether firmware returned a valid async task.
        creation_rejection_message_id: Exact governed Redfish busy rejection.
    """

    session: DiagnosticParallelSession = field(repr=False)
    attempt_id: str
    domain_key: Tuple[str, str]
    creation_resolved: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    creation_accepted: Optional[bool] = None
    creation_rejection_message_id: Optional[str] = None


@dataclass(eq=False)
class _DiagnosticParallelSessionState:
    """
    Retain runner-owned authority for one active adaptive session.

    Public session objects carry scheduler-facing metadata, but none of their
    mutable fields grant concurrency authority. This private record is inserted
    only while the runner holds the parent diagnostic lock and is removed before
    that lock is released.

    Attributes:
        session: Public opaque handle paired with this private record.
        dut_id: Immutable DUT route authorized for the session.
        parent_domain_key: Ordinary diagnostic domain held by the runner.
        session_id: Runner-assigned identifier used to derive child domains.
        attempts: Runner-owned attempt records keyed by their bounded labels.
        accepting_posts: Whether child attempts may start another POST.
    """

    session: DiagnosticParallelSession = field(repr=False)
    dut_id: str
    parent_domain_key: Tuple[str, str]
    session_id: str
    attempts: Dict[str, "_DiagnosticParallelAttemptState"] = field(
        default_factory=dict,
        repr=False,
    )
    accepting_posts: bool = True


@dataclass(eq=False)
class _DiagnosticParallelAttemptState:
    """
    Retain runner-owned authority and creation evidence for one child attempt.

    This record is keyed by public-handle identity in the runner registry. Its
    immutable routing fields and private outcome fields prevent caller-mutated
    diagnostic metadata from authorizing an extra POST or lock bypass.

    Attributes:
        attempt: Public opaque handle paired with this private record.
        session_state: Active runner-owned session that authorized the attempt.
        attempt_id: Immutable bounded scheduler label.
        domain_key: Immutable child diagnostic domain used for taint ownership.
        creation_accepted: Whether firmware returned a validated task reference.
        creation_rejection_message_id: Exact structured capacity rejection.
        execution_task: Local task that owns this attempt's device lifecycle.
        post_started: Whether a non-idempotent POST may have reached transport.
    """

    attempt: DiagnosticParallelAttempt = field(repr=False)
    session_state: _DiagnosticParallelSessionState = field(repr=False)
    attempt_id: str
    domain_key: Tuple[str, str]
    creation_accepted: Optional[bool] = None
    creation_rejection_message_id: Optional[str] = None
    execution_task: Optional[asyncio.Task[Any]] = field(default=None, repr=False)
    post_started: bool = False


def validate_redfish_uri(uri: Any, expected_host: Any = None) -> bool:
    """
    Load URI validation lazily to preserve the established import graph.

    After applying local validation, the function forwards ``uri`` and
    ``expected_host`` to ``_impl`` and preserves its return and exception
    contract. Parsing or I/O must finish before the validated representation is
    made available to the caller.

    Args:
        uri: Validated remote resource identifier used for URI.
        expected_host: Optional expected host; ``None`` selects the function's
            default behavior.

    Returns:
        The normalized Redfish URI returned by the shared host and scheme
        validator.
    """

    from ..utils.validation import validate_redfish_uri as _impl

    return _impl(uri, expected_host=expected_host)


def redfish_uri_is_collection_member(value: Any, collection_uri: Any) -> bool:
    """
    Load collection anchoring lazily to preserve the established import graph.

    After applying local validation, the function forwards ``value`` and
    ``collection_uri`` to ``_impl`` and preserves its return contract.

    Args:
        value: Response-derived member URI to test.
        collection_uri: URI of the collection that advertised the member.

    Returns:
        Whether the member URI is a valid path beneath the collection.
    """

    from ..utils.redfish_topology_profile import (
        redfish_uri_is_collection_member as _impl,
    )

    return _impl(value, collection_uri)


class RedfishDiagnosticRunner:
    """
    Sequence diagnostic POSTs, task polling, resolution, and download.

    The type coordinates ``_monotonic``,
    ``_dispatch_task_status_with_deadline``,
    ``_sleep_with_task_monitor_deadline``, ``_wait_for_task_completion``, and
    ``_get_dump_location`` and retains the state those operations share between
    calls. Resource ownership remains inside the instance until the matching
    close, exit, or cleanup operation completes.
    """

    def __init__(self, service: "RedfishService") -> None:
        """
        Initialize a ``RedfishDiagnosticRunner`` instance.

        The initializer records ``_service`` for later operations and
        establishes the instance invariants before any public method runs.

        Args:
            service: Service consumed while the function attempts to initialize
                a ``RedfishDiagnosticRunner`` instance.
        """
        self._service = service
        # These maps live for exactly one RedfishService/runner lifetime.  A
        # gate therefore cannot leak between CLI runs, while every collector
        # in one run sees the same unresolved task or remote no-resubmit state.
        self._diagnostic_domain_locks: Dict[Tuple[str, str], Lock] = {}
        self._diagnostic_domain_taints: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._diagnostic_capacity_taints: Dict[
            Tuple[str, str], Dict[str, Dict[str, Any]]
        ] = {}
        self._active_scoped_domain_owners: Dict[Tuple[str, str], int] = {}
        self._scoped_domain_idle_events: Dict[Tuple[str, str], asyncio.Event] = {}
        self._parallel_session_sequence = 0
        self._parallel_session_states: Dict[
            DiagnosticParallelSession,
            _DiagnosticParallelSessionState,
        ] = {}
        self._parallel_attempt_states: Dict[
            DiagnosticParallelAttempt,
            _DiagnosticParallelAttemptState,
        ] = {}

    async def _diagnostic_capacity_pool(
        self, dut_id: str, action_uri: str
    ) -> Optional[str]:
        """
        Qualify an exact action against the catalog and complete producer graph.

        Forwarded HMC and task-local controller views deliberately retain the
        existing physical-domain gate. A complete Manager member list is
        required. Missing detail bodies use bounded GETs through the existing
        transport cache, so qualification does not depend on verbose discovery.

        Args:
            dut_id: DUT whose existing route and discovery evidence are used.
            action_uri: Exact diagnostic action path selected by the caller.

        Returns:
            A verified capacity-pool label, or ``None`` for unknown ownership.

        Side Effects:
            May fetch up to sixteen missing Manager bodies using cached GETs.
        """

        manager = getattr(self._service, "dut_manager", None)
        getter = getattr(manager, "_get_baseboard_manager", None)
        if not callable(getter):
            return None
        board_manager = getter()
        config = manager.get_dut_config(dut_id)
        if board_manager is None or not isinstance(config, dict):
            return None
        board = board_manager.get_baseboard_config(config.get("baseboard", ""))
        if not isinstance(board, dict):
            return None
        pools = validate_diagnostic_capacity_pools(
            board.get(DIAGNOSTIC_CAPACITY_POOLS_KEY)
        )
        if not pools:
            return None
        dut = manager.get_dut(dut_id)
        if (
            request_controller_dut(dut) is not dut
            or self._service._hmc_diagnostic_lock_key(dut_id) is not None
            or dut.get_redfish_connection_info().get("is_hmc_forwarded") is not False
        ):
            return None
        discovery = await manager.get_discovery_results(dut_id)
        if not isinstance(discovery, dict):
            return None
        evidence = discovery.get("discovered_resources", {}).get("Managers", {})
        if not isinstance(evidence, dict) or evidence.get("complete") is not True:
            return None
        members = evidence.get("members")
        if (
            not isinstance(members, list)
            or not 1 <= len(members) <= 16
            or any(
                not isinstance(member, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", member)
                for member in members
            )
            or len(set(members)) != len(members)
        ):
            return None
        details = await manager.get_resource_details(dut_id, "Managers")
        if not isinstance(details, dict) or set(details) - set(members):
            return None
        managers = dict(details)
        collection_uri = self._service.get_configured_uri(dut_id, "Managers")
        for member in members:
            if member in managers:
                if (
                    not isinstance(managers[member], dict)
                    or managers[member].get("@odata.id") != f"{collection_uri}/{member}"
                ):
                    return None
                continue
            success, body, _ = await self._service.dispatch_request(
                dut_id, "GET", f"{collection_uri}/{member}", timeout=5, retry_count=0
            )
            if (
                not success
                or not isinstance(body, dict)
                or body.get("@odata.id") != f"{collection_uri}/{member}"
            ):
                return None
            managers[member] = body
        return resolve_diagnostic_capacity_pool(
            pools, dut.normalize_redfish_uri(action_uri), managers
        )

    def _is_pure_capacity_rejection(
        self, response: Any, metadata: Any, http_status: Optional[int]
    ) -> bool:
        """
        Recognize only an explicit quota-only HTTP 400 with no task evidence.

        Every structured error source must agree. Generic wrapper codes are
        allowed, but mixed/busy identities, malformed messages and any task or
        Location declaration retain the ordinary whole-domain gate.

        Args:
            response: Original POST response, possibly a bounded JSON string.
            metadata: Original transport metadata and response headers.
            http_status: Validated transport status.

        Returns:
            Whether the response proves a quota-only rejected creation.
        """

        if http_status != 400 or any(
            self._service._response_header_value(metadata, name) is not None
            for name in ("Location", "TaskMonitor")
        ):
            return False
        sources = [response]
        if isinstance(metadata, dict) and metadata.get("error_message") is not None:
            sources.append(metadata["error_message"])
        for source in sources:
            document = self._bounded_redfish_error_mapping(source)
            if not isinstance(document, dict) or set(document) != {"error"}:
                return False
            error = document["error"]
            if not isinstance(error, dict) or set(error) - {
                "code",
                "message",
                "@Message.ExtendedInfo",
            }:
                return False
            extended = error.get("@Message.ExtendedInfo", [])
            if not isinstance(extended, list) or len(extended) > 64:
                return False
            ids = [error.get("code")]
            for entry in extended:
                if not isinstance(entry, dict):
                    return False
                ids.append(entry.get("MessageId"))
            keys = set()
            for identity in ids:
                if (
                    not isinstance(identity, str)
                    or len(identity) > 256
                    or not re.fullmatch(
                        r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+", identity
                    )
                ):
                    return False
                keys.add(identity.rsplit(".", 1)[-1])
            if "CreateLimitReachedForResource" not in keys or keys - {
                "CreateLimitReachedForResource",
                "GeneralError",
            }:
                return False
        return True

    def _diagnostic_block_reason(
        self, dut_id: str, capacity_pool: Optional[str], disposition: Any
    ) -> Optional[str]:
        """
        Recheck global lifecycle uncertainty before a qualified pool refusal.

        The synchronous final check prevents state learned during awaited
        preparation from being bypassed by an already admitted local scope.

        Args:
            dut_id: Existing physical-domain owner for this request.
            capacity_pool: Qualified target pool, or unknown ownership.
            disposition: Optional caller-owned attempt record.

        Returns:
            A controlled no-POST reason when refused, otherwise ``None``.

        Side Effects:
            Marks a blocked attempt without altering any lifecycle taint.
        """

        global_key, _, _ = self._diagnostic_domain(dut_id)
        taint = self._diagnostic_domain_taints.get(global_key)
        if taint is not None:
            self._apply_remote_gate_to_disposition(
                disposition, taint, blocked_before_post=True
            )
            reason = (
                f"Diagnostic task POST blocked: {taint['reason']}; no POST was sent"
            )
            if isinstance(disposition, DiagnosticAttemptDisposition):
                disposition.reason = reason
            return reason
        refusals = self._diagnostic_capacity_taints.get(global_key, {})
        refusal = (
            refusals.get(capacity_pool)
            if capacity_pool
            else next(iter(refusals.values()), None)
        )
        if refusal is None:
            return None
        self._apply_remote_gate_to_disposition(
            disposition, refusal, blocked_before_post=True
        )
        reason = f"Diagnostic task POST blocked: {refusal['reason']}; no POST was sent"
        if isinstance(disposition, DiagnosticAttemptDisposition):
            disposition.capacity_pool = capacity_pool
            disposition.reason = reason
        return reason

    def _bounded_redfish_error_mapping(self, value: Any) -> Optional[Dict[str, Any]]:
        """
        Return one bounded structured Redfish error mapping.

        Parsed transport strings must contain a complete JSON object after any
        fixed HTTP-status prefix. Free-form text is never searched for registry
        identifiers, which prevents prose from spoofing a no-resubmit decision.

        Args:
            value: Structured response or bounded transport error text.

        Returns:
            The parsed error mapping, or ``None`` when no complete bounded JSON
            mapping is available.
        """

        if type(value) is dict:
            return value
        max_text = int(getattr(self._service, "_DIAGNOSTIC_LOG_TEXT_MAX_CHARS", 2048))
        if type(value) is not str or not value or len(value) > max_text:
            return None
        json_start = value.find("{")
        if json_start < 0:
            return None
        try:
            parsed = json.loads(value[json_start:])
        except (json.JSONDecodeError, RecursionError, ValueError):
            return None
        return parsed if type(parsed) is dict else None

    def _remote_no_resubmit_message_id(
        self,
        response: Any,
        metadata: Any,
    ) -> Optional[str]:
        """
        Classify exact structured Redfish registry no-resubmit messages.

        Registry names and versions may vary, so only the final validated
        MessageId key is compared. The narrow allowlist deliberately excludes
        generic HTTP failures and payload-shape errors that can legitimately
        select a compatibility fallback.

        Args:
            response: Transport response governed by the Redfish boundary.
            metadata: Bounded response metadata returned by that boundary.

        Returns:
            The complete validated MessageId, or ``None`` when the response
            does not carry a governed remote capacity/busy rejection.
        """

        sources: List[Any] = [response]
        if isinstance(metadata, dict):
            sources.append(dict.get(metadata, "error_message"))

        max_items = int(getattr(self._service, "_DIAGNOSTIC_LOG_MAX_ITEMS", 64))
        max_name = int(getattr(self._service, "_DIAGNOSTIC_FIELD_NAME_MAX_CHARS", 256))
        for source in sources:
            document = self._bounded_redfish_error_mapping(source)
            if document is None:
                continue
            raw_error = dict.get(document, "error")
            error = raw_error if type(raw_error) is dict else document
            candidates: List[Any] = [dict.get(error, "code")]
            raw_extended = dict.get(error, "@Message.ExtendedInfo")
            if type(raw_extended) is list:
                for index, entry in enumerate(list.__iter__(raw_extended)):
                    if index >= max_items:
                        break
                    if type(entry) is dict:
                        candidates.append(dict.get(entry, "MessageId"))

            for candidate in candidates:
                if (
                    type(candidate) is not str
                    or not candidate
                    or len(candidate) > max_name
                ):
                    continue
                message_id = candidate.strip()
                if not re.fullmatch(
                    r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+",
                    message_id,
                ):
                    continue
                if message_id.rsplit(".", 1)[-1] in _REMOTE_NO_RESUBMIT_MESSAGE_KEYS:
                    return message_id
        return None

    def _record_remote_no_resubmit_rejection(
        self,
        domain_key: Tuple[str, str],
        *,
        dut_id: str,
        collector_id: str,
        action_uri: str,
        message_id: str,
        http_status: Optional[int],
        task_id: str = "",
        monitor_uris: Optional[List[str]] = None,
        capacity_pool: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Gate one run-scoped domain after a definitive remote rejection.

        The gate is written synchronously while the caller holds the diagnostic
        domain lock. It contains only validated registry identity, bounded URI
        evidence, and optional exact monitor candidates supplied by firmware.

        Args:
            domain_key: Opaque process-local diagnostic domain identifier.
            dut_id: Stable DUT identifier whose route rejected the request.
            collector_id: Collector that sent the rejected diagnostic action.
            action_uri: Validated action URI that rejected creation.
            message_id: Validated Redfish registry MessageId.
            http_status: Optional bounded HTTP status returned with the error.
            task_id: Optional exact task identifier supplied by firmware.
            monitor_uris: Optional validated task-monitor URI candidates.
            capacity_pool: Verified quota-only pool, otherwise the whole domain.

        Returns:
            The recorded refusal evidence for the attempt disposition.

        Side Effects:
            Records the domain gate or verified pool refusal for this run.
        """

        max_text = int(getattr(self._service, "_DIAGNOSTIC_LOG_TEXT_MAX_CHARS", 2048))
        max_items = int(getattr(self._service, "_DIAGNOSTIC_LOG_MAX_ITEMS", 64))
        max_name = int(getattr(self._service, "_DIAGNOSTIC_FIELD_NAME_MAX_CHARS", 256))
        bounded_monitors: List[str] = []
        for candidate in list(monitor_uris or [])[:max_items]:
            if (
                type(candidate) is str
                and candidate.strip()
                and len(candidate) <= max_text
                and candidate.strip() not in bounded_monitors
            ):
                bounded_monitors.append(candidate.strip())
        bounded_task_id = (
            task_id[:max_name] if type(task_id) is str and task_id else "unknown"
        )
        bounded_collector_id = (
            collector_id.strip()[:max_name]
            if type(collector_id) is str and collector_id.strip()
            else "unknown"
        )
        bounded_action_uri = (
            action_uri[:max_text] if type(action_uri) is str else "<omitted-uri>"
        )
        reason = (
            f"remote diagnostic creation was rejected with {message_id}; "
            "resubmission is not safe in this run"
        )
        taint = {
            "kind": "remote_no_resubmit",
            "dut_id": str(dut_id)[:max_name],
            "origin_collector_id": bounded_collector_id,
            "action_uri": bounded_action_uri,
            "message_id": message_id[:max_name],
            "http_status": (
                http_status
                if type(http_status) is int and 100 <= http_status <= 599
                else None
            ),
            "task_id": bounded_task_id,
            "monitor_uris": tuple(bounded_monitors),
            "reason": reason[:max_text],
        }
        if capacity_pool is None:
            self._diagnostic_domain_taints[domain_key] = taint
        else:
            taint["capacity_pool"] = capacity_pool
            taint["reason"] = (
                f"remote diagnostic creation was rejected with {message_id}; "
                f"capacity pool {capacity_pool} is blocked for this run"
            )[:max_text]
            global_key, _, _ = self._diagnostic_domain(dut_id)
            self._diagnostic_capacity_taints.setdefault(global_key, {})[
                capacity_pool
            ] = taint
            # Adaptive POST admission records a provisional child taint. A pure
            # rejected creation proves that THIS attempt created no remote task.
            self._diagnostic_domain_taints.pop(domain_key, None)
        return taint

    @staticmethod
    def _apply_remote_gate_to_disposition(
        disposition: Any,
        taint: Any,
        *,
        blocked_before_post: bool,
    ) -> None:
        """
        Copy controlled remote-gate fields into one typed attempt disposition.

        Unknown objects and non-gate state are ignored so legacy callers keep
        their established compatibility behavior without reason-text parsing.

        Args:
            disposition: Caller-owned per-attempt disposition object.
            taint: Run-scoped diagnostic-domain state.
            blocked_before_post: Whether the current call was stopped before
                issuing its own POST.

        Side Effects:
            Mutates ``disposition`` when it has the expected internal type.
        """

        if not isinstance(disposition, DiagnosticAttemptDisposition):
            return
        if blocked_before_post:
            disposition.resubmit_allowed = False
            disposition.blocked_before_post = True
        if not isinstance(taint, dict) or taint.get("kind") != "remote_no_resubmit":
            return
        disposition.resubmit_allowed = False
        disposition.blocked_before_post = blocked_before_post
        disposition.remote_rejection = True
        disposition.message_id = taint.get("message_id")
        disposition.http_status = taint.get("http_status")
        disposition.origin_collector_id = taint.get("origin_collector_id")
        disposition.origin_dut_id = taint.get("dut_id")
        disposition.capacity_pool = taint.get("capacity_pool")
        disposition.reason = taint.get("reason")

    def _diagnostic_domain(
        self,
        dut_id: str,
        diagnostic_domain_scope: Optional[str] = None,
    ) -> Tuple[Tuple[str, str], Lock, Optional[str]]:
        """
        Resolve the process-local diagnostic task domain and its lifecycle lock.

        Forwarded DUTs that share one physical HMC retain the existing opaque
        shared-HMC domain. Other routes ordinarily receive a per-DUT domain.
        A validated internal scope receives its own lifecycle lock while
        unresolved state is promoted back to the direct-DUT safety domain.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            diagnostic_domain_scope: Optional validated internal scope granted
                only after catalog and endpoint cohort admission.

        Returns:
            A tuple containing the opaque run-scoped domain key, its lifecycle
            lock, and the existing shared-HMC log key when applicable.

        Side Effects:
            Lazily creates one process-local lock for the resolved domain.
        """

        shared_key = self._service._hmc_diagnostic_lock_key(dut_id)
        if isinstance(shared_key, str) and shared_key:
            locks = getattr(self._service, "_hmc_diagnostic_locks", None)
            if not isinstance(locks, dict):
                locks = {}
                self._service._hmc_diagnostic_locks = locks
            return (
                ("shared_hmc", shared_key),
                locks.setdefault(shared_key, Lock()),
                shared_key,
            )

        scope = (
            diagnostic_domain_scope.strip()
            if isinstance(diagnostic_domain_scope, str)
            and diagnostic_domain_scope.strip()
            and len(diagnostic_domain_scope) <= 256
            else None
        )
        direct_key = (
            (
                "dut_scope",
                json.dumps([str(dut_id), scope], separators=(",", ":")),
            )
            if scope is not None
            else ("dut", str(dut_id))
        )
        return (
            direct_key,
            self._diagnostic_domain_locks.setdefault(direct_key, Lock()),
            None,
        )

    def _promote_scoped_domain_taint(
        self,
        scoped_key: Tuple[str, str],
        global_key: Tuple[str, str],
        *,
        dut_id: str,
    ) -> None:
        """
        Move unresolved scoped state into the direct-DUT safety domain.

        A clean scoped lifecycle has nothing to promote. If another scoped
        lifecycle already promoted different unresolved state, the direct-DUT
        domain becomes a permanent aggregate gate because proving only one
        remote monitor terminal would not establish complete quiescence.

        Args:
            scoped_key: Collector-scoped diagnostic domain that is closing.
            global_key: Direct-DUT diagnostic domain governing later cohorts.
            dut_id: Stable DUT identifier retained in bounded gate evidence.

        Side Effects:
            Removes unresolved state from ``scoped_key`` and installs an
            equivalent or conservative aggregate state at ``global_key``.
        """

        scoped_taint = self._diagnostic_domain_taints.pop(scoped_key, None)
        if scoped_taint is None:
            return
        existing = self._diagnostic_domain_taints.get(global_key)
        if existing is None:
            self._diagnostic_domain_taints[global_key] = copy.deepcopy(scoped_taint)
            return

        self._diagnostic_domain_taints[global_key] = self._merge_diagnostic_taints(
            [existing, scoped_taint], dut_id=dut_id
        )

    def _merge_diagnostic_taints(
        self,
        taints: List[Dict[str, Any]],
        *,
        dut_id: str,
    ) -> Dict[str, Any]:
        """
        Merge unresolved owners without losing explicit remote refusal provenance.

        A single owner retains its existing monitor recovery. Multiple owners
        remain permanently blocked because proving one monitor terminal cannot
        establish complete quiescence. Only exclusively typed remote refusals
        retain no-POST skip classification; mixed or unknown outcomes never do.

        Args:
            taints: Nonempty internal owner records already bounded at creation.
            dut_id: Diagnostic domain whose unresolved owners are being merged.

        Returns:
            Independent bounded state preserving refusal origins when every
            constituent is a remote no-resubmit rejection.
        """

        if len(taints) == 1:
            return copy.deepcopy(taints[0])
        max_text = int(getattr(self._service, "_DIAGNOSTIC_LOG_TEXT_MAX_CHARS", 2048))
        merged = {
            "kind": "parallel_session_unresolved",
            "dut_id": str(dut_id),
            "task_id": "multiple",
            "monitor_uris": (),
            "reason": (
                "multiple compatible diagnostic collectors ended with "
                "unresolved task state; resubmission is not safe in this run"
            )[:max_text],
        }
        if all(taint.get("kind") == "remote_no_resubmit" for taint in taints):
            max_items = max(
                1, int(getattr(self._service, "_DIAGNOSTIC_LOG_MAX_ITEMS", 64))
            )
            fields = (
                "dut_id",
                "origin_collector_id",
                "action_uri",
                "message_id",
                "http_status",
            )
            origins: List[Dict[str, Any]] = []
            for taint in taints:
                for origin in taint.get("rejection_origins", (taint,)):
                    bounded = {field: origin.get(field) for field in fields}
                    if bounded not in origins and len(origins) < max_items:
                        origins.append(bounded)
            merged.update(
                origins[0],
                kind="remote_no_resubmit",
                rejection_origins=tuple(origins),
                reason=(
                    "multiple prior remote diagnostic rejections prevent resubmission "
                    "in this run: "
                    + "; ".join(
                        dict.fromkeys(
                            f"{origin['origin_collector_id']}: {origin['message_id']}"
                            for origin in origins
                        )
                    )
                )[:max_text],
            )
        return merged

    def _scoped_domain_idle_event(
        self,
        global_key: Tuple[str, str],
    ) -> asyncio.Event:
        """
        Return the run-scoped signal for direct-domain reader quiescence.

        A newly observed direct-DUT domain has no scoped owners, so its event
        starts set. The signal is cleared before a scoped lifecycle releases
        the direct lock and set only after the final scoped owner promotes any
        unresolved state.

        Args:
            global_key: Direct-DUT diagnostic domain shared by scoped owners
                and ordinary exclusive collectors.

        Returns:
            The stable asynchronous idle event for ``global_key``.

        Side Effects:
            Creates and initializes one event on first access.
        """

        event = self._scoped_domain_idle_events.get(global_key)
        if event is None:
            event = asyncio.Event()
            event.set()
            self._scoped_domain_idle_events[global_key] = event
        return event

    async def _acquire_diagnostic_domain_lock(
        self,
        domain_key: Tuple[str, str],
        lock: Lock,
    ) -> None:
        """
        Acquire a lifecycle lock without bypassing active scoped owners.

        Scoped and shared-HMC domains use their ordinary lock directly. An
        unscoped direct-DUT collector waits for the reader-idle signal, then
        rechecks the scoped-owner count while holding the direct lock. This
        closes the race between observing an idle event and a new scoped owner
        clearing it.

        Args:
            domain_key: Opaque diagnostic domain being acquired.
            lock: Stable lock owned by ``domain_key``.

        Raises:
            asyncio.CancelledError: If the caller is cancelled while waiting.

        Side Effects:
            Acquires ``lock``. The caller must release it exactly once.
        """

        if domain_key[0] != "dut":
            await lock.acquire()
            return

        idle_event = self._scoped_domain_idle_event(domain_key)
        while True:
            await idle_event.wait()
            await lock.acquire()
            if self._active_scoped_domain_owners.get(domain_key, 0) == 0:
                return
            lock.release()

    async def _activate_scoped_diagnostic_domain(
        self,
        global_key: Tuple[str, str],
        global_lock: Lock,
    ) -> Tuple[bool, str]:
        """
        Admit one scoped lifecycle against a quiescent direct-DUT domain.

        Admission and owner-count publication occur while holding the direct
        lock. Ordinary collectors therefore cannot pass their final owner
        recheck between the quiescence proof and publication of this owner.

        Args:
            global_key: Direct-DUT safety domain governing incompatible work.
            global_lock: Stable lock owned by ``global_key``.

        Returns:
            A tuple containing whether scoped admission was granted and the
            controlled quiescence failure reason when it was denied.

        Raises:
            asyncio.CancelledError: If bounded quiescence proof is cancelled.

        Side Effects:
            May issue bounded GET-only quiescence probes, increments the active
            scoped-owner count, and clears the domain idle event on success.
        """

        async with global_lock:
            quiescent, reason = await self._prove_diagnostic_domain_quiescent(
                global_key
            )
            if not quiescent:
                return False, reason
            self._active_scoped_domain_owners[global_key] = (
                self._active_scoped_domain_owners.get(global_key, 0) + 1
            )
            self._scoped_domain_idle_event(global_key).clear()
            return True, ""

    def _release_scoped_diagnostic_domain(
        self,
        scoped_key: Tuple[str, str],
        global_key: Tuple[str, str],
        *,
        dut_id: str,
    ) -> None:
        """
        Publish scoped completion before waking ordinary collectors.

        This method deliberately contains no suspension point. Promotion,
        owner-count decrement, and final event publication are one atomic
        event-loop operation, including when the scoped owner is cancelled.

        Args:
            scoped_key: Collector-scoped diagnostic domain that is closing.
            global_key: Direct-DUT safety domain governing incompatible work.
            dut_id: Stable DUT identifier retained in promoted gate evidence.

        Side Effects:
            Promotes unresolved state, decrements the active scoped-owner
            count, and wakes direct-domain waiters after the final owner exits.
        """

        self._promote_scoped_domain_taint(
            scoped_key,
            global_key,
            dut_id=dut_id,
        )
        active_count = self._active_scoped_domain_owners.get(global_key, 0)
        if active_count <= 1:
            self._active_scoped_domain_owners.pop(global_key, None)
            self._scoped_domain_idle_event(global_key).set()
            return
        self._active_scoped_domain_owners[global_key] = active_count - 1

    def _validate_parallel_session(
        self,
        session: Any,
        *,
        dut_id: Optional[str] = None,
    ) -> _DiagnosticParallelSessionState:
        """
        Return runner-owned state for an active adaptive session.

        Configuration and hook kwargs are not trusted to manufacture internal
        concurrency authority. Only the opaque object created while this runner
        holds the parent diagnostic lock is accepted, and an optional DUT check
        prevents an object from crossing routes.

        Args:
            session: Candidate internal session object.
            dut_id: Optional DUT route that must match the session owner.

        Returns:
            The validated private diagnostic parallel session state.

        Raises:
            ValueError: If the session is invalid, inactive, foreign, or bound
                to a different DUT route.
        """

        if not isinstance(session, DiagnosticParallelSession):
            raise ValueError("diagnostic parallel session is not active")
        session_state = self._parallel_session_states.get(session)
        if session_state is None or session_state.session is not session:
            raise ValueError("diagnostic parallel session is not active")
        if (
            session.runner is not self
            or session.dut_id != session_state.dut_id
            or session.parent_domain_key != session_state.parent_domain_key
            or session.session_id != session_state.session_id
        ):
            raise ValueError("diagnostic parallel session metadata was modified")
        if dut_id is not None and session_state.dut_id != dut_id:
            raise ValueError("diagnostic parallel session DUT does not match")
        return session_state

    def prepare_parallel_attempt(
        self,
        session: DiagnosticParallelSession,
        attempt_id: str,
    ) -> DiagnosticParallelAttempt:
        """
        Prepare one unique child domain before scheduling its coroutine.

        Preparing before task creation gives the owning scheduler an event it
        can safely await even when local setup fails before the Redfish POST.
        Attempt labels are bounded process-local identifiers and are never used
        as remote paths, payloads, or artifact names.

        Args:
            session: Active adaptive session that owns the child attempt.
            attempt_id: Unique bounded label for this device execution attempt.

        Returns:
            A prepared diagnostic parallel attempt.

        Raises:
            ValueError: If the label is malformed or already belongs to the
                session.

        Side Effects:
            Adds the prepared attempt to ``session.attempts``.
        """

        session_state = self._validate_parallel_session(session)
        if not isinstance(attempt_id, str) or not re.fullmatch(
            r"[A-Za-z0-9_.:-]{1,128}", attempt_id
        ):
            raise ValueError("diagnostic parallel attempt_id is invalid")
        if attempt_id in session_state.attempts:
            raise ValueError(
                f"diagnostic parallel attempt_id is duplicated: {attempt_id}"
            )
        attempt = DiagnosticParallelAttempt(
            session=session_state.session,
            attempt_id=attempt_id,
            domain_key=(
                "adaptive_parallel",
                f"{session_state.session_id}:{attempt_id}",
            ),
        )
        attempt_state = _DiagnosticParallelAttemptState(
            attempt=attempt,
            session_state=session_state,
            attempt_id=attempt_id,
            domain_key=attempt.domain_key,
        )
        session_state.attempts[attempt_id] = attempt_state
        self._parallel_attempt_states[attempt] = attempt_state
        # Retain the public mapping for diagnostics only. Validation and cleanup
        # always use the private registry above.
        session_state.session.attempts[attempt_id] = attempt
        return attempt

    def _validate_parallel_attempt(
        self,
        attempt: Any,
        *,
        dut_id: Optional[str] = None,
    ) -> _DiagnosticParallelAttemptState:
        """
        Return a prepared attempt owned by an active local session.

        Object identity is checked against the session registry rather than
        trusting matching field values. This prevents copied or caller-created
        objects from obtaining the session's internal concurrency authority.

        Args:
            attempt: Candidate internal attempt object.
            dut_id: Optional DUT route that must match the parent session.

        Returns:
            The validated private diagnostic parallel attempt state.

        Raises:
            ValueError: If the attempt is foreign, unprepared, inactive, or
                associated with a different DUT.
        """

        if not isinstance(attempt, DiagnosticParallelAttempt):
            raise ValueError("diagnostic parallel attempt is invalid")
        attempt_state = self._parallel_attempt_states.get(attempt)
        if attempt_state is None or attempt_state.attempt is not attempt:
            raise ValueError("diagnostic parallel attempt was not prepared")
        session_state = self._validate_parallel_session(
            attempt_state.session_state.session,
            dut_id=dut_id,
        )
        if (
            session_state is not attempt_state.session_state
            or session_state.attempts.get(attempt_state.attempt_id) is not attempt_state
        ):
            raise ValueError("diagnostic parallel attempt was not prepared")
        if (
            attempt.session is not session_state.session
            or attempt.attempt_id != attempt_state.attempt_id
            or attempt.domain_key != attempt_state.domain_key
        ):
            raise ValueError("diagnostic parallel attempt metadata was modified")
        return attempt_state

    def resolve_parallel_attempt_creation(
        self,
        attempt: DiagnosticParallelAttempt,
        *,
        accepted: bool,
        rejection_message_id: Optional[str] = None,
    ) -> None:
        """
        Publish the first definitive task-creation outcome to the scheduler.

        A device child can contain compatibility payload fallbacks, but the
        adaptive probe is governed only by its first POST. Later calls cannot
        overwrite that evidence or wake the scheduler twice.

        Args:
            attempt: Prepared child attempt whose event is resolved.
            accepted: Whether firmware supplied a valid asynchronous task.
            rejection_message_id: Optional exact structured busy rejection.

        Side Effects:
            Sets the attempt outcome and wakes ``creation_resolved`` once.
        """

        attempt_state = self._validate_parallel_attempt(attempt)
        validated_attempt = attempt_state.attempt
        if validated_attempt.creation_resolved.is_set():
            return
        attempt_state.creation_accepted = bool(accepted)
        validated_attempt.creation_accepted = attempt_state.creation_accepted
        if (
            isinstance(rejection_message_id, str)
            and rejection_message_id.rsplit(".", 1)[-1]
            in _REMOTE_NO_RESUBMIT_MESSAGE_KEYS
        ):
            attempt_state.creation_rejection_message_id = rejection_message_id
            validated_attempt.creation_rejection_message_id = rejection_message_id
        validated_attempt.creation_resolved.set()

    def finalize_parallel_attempt_creation(
        self,
        attempt: Any,
    ) -> None:
        """
        Resolve an attempt conservatively when local execution ended early.

        The scheduler calls this in a task-finalization path. It prevents an
        indefinite wait when logging, validation, cancellation, or another
        local operation exits before the runner can classify a POST response.
        A pre-POST exit is definitively not created. Once the POST has started,
        the outcome remains unknown and its child domain stays tainted so no
        later diagnostic POST can be admitted without terminal evidence.

        Args:
            attempt: Prepared attempt that may still have an unresolved event.

        Side Effects:
            Wakes waiters and retains a fail-closed child-domain gate when a
            non-idempotent POST may have started.
        """

        if not isinstance(attempt, DiagnosticParallelAttempt):
            return
        try:
            attempt_state = self._validate_parallel_attempt(attempt)
        except ValueError:
            return
        validated_attempt = attempt_state.attempt
        if validated_attempt.creation_resolved.is_set():
            return
        if attempt_state.post_started:
            if attempt_state.domain_key not in self._diagnostic_domain_taints:
                self._record_unproven_diagnostic_task(
                    attempt_state.domain_key,
                    dut_id=attempt_state.session_state.dut_id,
                    task_id="unknown",
                    monitor_uris=[],
                    reason=(
                        "diagnostic POST started but its task-creation outcome "
                        "was not observed"
                    ),
                    accepted=False,
                )
            attempt_state.creation_accepted = None
            validated_attempt.creation_accepted = None
            validated_attempt.creation_resolved.set()
            return
        attempt_state.creation_accepted = False
        validated_attempt.creation_accepted = False
        validated_attempt.creation_resolved.set()

    def _claim_parallel_attempt_execution(
        self,
        attempt_state: _DiagnosticParallelAttemptState,
    ) -> None:
        """
        Bind one adaptive attempt to its runner-observed local task.

        The binding lets session teardown cancel and drain a child that the
        scheduler failed to observe. Re-entry from the same task remains valid
        for compatibility payload fallbacks, while a second task cannot reuse
        the same concurrency authority.

        Args:
            attempt_state: Validated runner-owned attempt record.

        Raises:
            RuntimeError: If no current asynchronous task owns the execution.
            ValueError: If a different task already claimed the attempt.

        Side Effects:
            Records the current asynchronous task on first use.
        """

        current_task = asyncio.current_task()
        if current_task is None:
            raise RuntimeError("diagnostic parallel attempt requires an async task")
        if attempt_state.execution_task is None:
            attempt_state.execution_task = current_task
        elif attempt_state.execution_task is not current_task:
            raise ValueError("diagnostic parallel attempt is already executing")

    def _start_parallel_attempt_post(
        self,
        attempt_state: _DiagnosticParallelAttemptState,
    ) -> bool:
        """
        Record an unknown non-idempotent POST before transport dispatch.

        Session teardown first closes admission and then drains every claimed
        child. Checking the runner-owned session flag here prevents a cached
        attempt handle from starting I/O after teardown begins. The provisional
        taint is replaced by exact rejection or accepted-task evidence when a
        response arrives; otherwise it remains a run-scoped fail-closed gate.

        Args:
            attempt_state: Validated runner-owned attempt record.

        Returns:
            Whether the POST remains authorized by the active parent session.

        Raises:
            ValueError: If the attempt is stale, modified, or owned by a
                different asynchronous task.

        Side Effects:
            Marks the POST started and records provisional unresolved state.
        """

        validated_state = self._validate_parallel_attempt(
            attempt_state.attempt,
            dut_id=attempt_state.session_state.dut_id,
        )
        if validated_state is not attempt_state:
            raise ValueError("diagnostic parallel attempt authority changed")
        self._claim_parallel_attempt_execution(attempt_state)
        if not attempt_state.session_state.accepting_posts:
            return False
        attempt_state.post_started = True
        self._record_unproven_diagnostic_task(
            attempt_state.domain_key,
            dut_id=attempt_state.session_state.dut_id,
            task_id="unknown",
            monitor_uris=[],
            reason="diagnostic POST transport outcome has not been observed",
            accepted=False,
        )
        return True

    def parallel_attempt_creation_outcome(
        self,
        attempt: DiagnosticParallelAttempt,
    ) -> Tuple[Optional[bool], Optional[str]]:
        """
        Return runner-owned task-creation evidence for one prepared attempt.

        Scheduler decisions use this private record rather than caller-mutable
        dataclass outcome fields. The public fields remain synchronized only for
        diagnostics and compatibility with existing internal test fixtures.

        Args:
            attempt: Prepared child attempt whose creation may be resolved.

        Returns:
            A tuple containing the accepted flag and exact structured rejection
            MessageId, either of which may be ``None`` before resolution.

        Raises:
            ValueError: If the attempt is foreign, inactive, or modified.
        """

        attempt_state = self._validate_parallel_attempt(attempt)
        return (
            attempt_state.creation_accepted,
            attempt_state.creation_rejection_message_id,
        )

    def dismiss_parallel_creation_rejections(
        self,
        session: DiagnosticParallelSession,
        attempts: List[DiagnosticParallelAttempt],
    ) -> bool:
        """
        Clear exact no-task busy rejections after sibling quiescence is proven.

        This is the narrow serial-fallback exception to the ordinary run-scoped
        no-resubmit gate. Every remaining child taint in the held session must
        be one of the supplied structured busy rejections, and firmware must
        have supplied neither a task identifier nor a monitor URI. Therefore no
        accepted sibling remains unobserved when the scheduler retries serially.

        Args:
            session: Active session holding the parent diagnostic-domain lock.
            attempts: Rejected child attempts selected for serial retry.

        Returns:
            Whether all supplied rejections were safely cleared.

        Side Effects:
            Removes the exact child rejection taints when every invariant holds.
        """

        session_state = self._validate_parallel_session(session)
        if not isinstance(attempts, list) or not attempts:
            return False
        validated_attempts: List[_DiagnosticParallelAttemptState] = []
        for attempt in attempts:
            try:
                attempt_state = self._validate_parallel_attempt(
                    attempt,
                    dut_id=session_state.dut_id,
                )
            except ValueError:
                return False
            if attempt_state.session_state is not session_state:
                return False
            validated_attempts.append(attempt_state)

        target_keys = {attempt.domain_key for attempt in validated_attempts}
        remaining_taints = {
            attempt_state.domain_key: self._diagnostic_domain_taints[
                attempt_state.domain_key
            ]
            for attempt_state in session_state.attempts.values()
            if attempt_state.domain_key in self._diagnostic_domain_taints
        }
        if set(remaining_taints) != target_keys:
            return False

        for attempt in validated_attempts:
            taint = remaining_taints.get(attempt.domain_key)
            message_id = taint.get("message_id") if isinstance(taint, dict) else None
            if (
                not isinstance(taint, dict)
                or taint.get("kind") != "remote_no_resubmit"
                or not isinstance(message_id, str)
                or message_id != attempt.creation_rejection_message_id
                or message_id.rsplit(".", 1)[-1] not in _REMOTE_NO_RESUBMIT_MESSAGE_KEYS
                or taint.get("task_id") != "unknown"
                or bool(taint.get("monitor_uris"))
            ):
                return False

        for domain_key in target_keys:
            self._diagnostic_domain_taints.pop(domain_key, None)
        return True

    def parallel_attempt_is_quiescent(
        self,
        attempt: DiagnosticParallelAttempt,
    ) -> bool:
        """
        Return whether a completed child left no unresolved domain state.

        The scheduler uses this check only after it has awaited the owned child
        coroutine. A remaining taint means task terminal state was not proven or
        a remote no-resubmit rejection still governs the child domain, so no new
        parallel POST may be admitted.

        Args:
            attempt: Prepared child attempt whose coroutine has completed.

        Returns:
            Whether the attempt's child diagnostic domain is quiescent.
        """

        attempt_state = self._validate_parallel_attempt(attempt)
        return attempt_state.domain_key not in self._diagnostic_domain_taints

    @asynccontextmanager
    async def parallel_diagnostic_session(
        self,
        dut_id: str,
        *,
        diagnostic_domain_scope: Optional[str] = None,
    ) -> AsyncIterator[Optional[DiagnosticParallelSession]]:
        """
        Own one diagnostic domain for adaptive device concurrency.

        The default parent lock excludes other collectors for the full session.
        A catalog-authorized scope uses a separate lifecycle lock after checking
        the direct-DUT safety domain, allowing compatible collectors to overlap.
        A pre-existing unresolved task yields ``None``. On scoped exit, any
        unresolved child state is promoted to the direct-DUT domain so a later
        incompatible cohort remains fail closed.

        Args:
            dut_id: Stable DUT identifier whose diagnostic domain is owned.
            diagnostic_domain_scope: Optional validated internal scope granted
                by collector-level endpoint admission.

        Yields:
            An active opaque session, or ``None`` when the parent domain is not
            proven quiescent.

        Side Effects:
            Acquires the resolved diagnostic lock, may issue bounded GET-only
            quiescence probes, and promotes unresolved scoped taints on exit.
        """

        domain_key, lock, shared_lock_key = self._diagnostic_domain(
            dut_id,
            diagnostic_domain_scope,
        )
        global_domain_key: Optional[Tuple[str, str]] = None
        global_domain_lock: Optional[Lock] = None
        if domain_key[0] == "dut_scope":
            global_domain_key, global_domain_lock, _ = self._diagnostic_domain(dut_id)
        if lock.locked() and shared_lock_key is not None:
            await self._service._log_runtime(
                "INFO",
                "RedfishService",
                f"Waiting for shared HMC diagnostic slot {shared_lock_key}",
                dut_id,
            )
        await self._acquire_diagnostic_domain_lock(domain_key, lock)
        scoped_admitted = False
        try:
            if global_domain_key is not None and global_domain_lock is not None:
                scoped_admitted, _ = await self._activate_scoped_diagnostic_domain(
                    global_domain_key,
                    global_domain_lock,
                )
                if not scoped_admitted:
                    yield None
                    return
            quiescent, _ = await self._prove_diagnostic_domain_quiescent(domain_key)
            if not quiescent:
                yield None
                return

            self._parallel_session_sequence += 1
            session = DiagnosticParallelSession(
                runner=self,
                dut_id=dut_id,
                parent_domain_key=domain_key,
                session_id=str(self._parallel_session_sequence),
            )
            session_state = _DiagnosticParallelSessionState(
                session=session,
                dut_id=str(dut_id),
                parent_domain_key=domain_key,
                session_id=str(self._parallel_session_sequence),
            )
            self._parallel_session_states[session] = session_state
            try:
                yield session
            finally:
                # Close admission before yielding to child cleanup. Any child
                # that cached its private attempt state must be cancelled and
                # observed while the registries and parent lock remain active.
                session_state.accepting_posts = False
                current_task = asyncio.current_task()
                child_tasks = {
                    attempt_state.execution_task
                    for attempt_state in session_state.attempts.values()
                    if attempt_state.execution_task is not None
                    and attempt_state.execution_task is not current_task
                    and not attempt_state.execution_task.done()
                }
                for child_task in child_tasks:
                    child_task.cancel()
                if child_tasks:
                    await asyncio.gather(*child_tasks, return_exceptions=True)

                child_taints = [
                    self._diagnostic_domain_taints[attempt_state.domain_key]
                    for attempt_state in session_state.attempts.values()
                    if attempt_state.domain_key in self._diagnostic_domain_taints
                ]
                if child_taints:
                    self._diagnostic_domain_taints[domain_key] = (
                        self._merge_diagnostic_taints(child_taints, dut_id=dut_id)
                    )
                for attempt_state in session_state.attempts.values():
                    self._diagnostic_domain_taints.pop(attempt_state.domain_key, None)
                    self._parallel_attempt_states.pop(attempt_state.attempt, None)
                self._parallel_session_states.pop(session, None)
                session.active = False
        finally:
            if scoped_admitted and global_domain_key is not None:
                self._release_scoped_diagnostic_domain(
                    domain_key,
                    global_domain_key,
                    dut_id=dut_id,
                )
            lock.release()

    def _record_unproven_diagnostic_task(
        self,
        domain_key: Tuple[str, str],
        *,
        dut_id: str,
        task_id: str,
        monitor_uris: List[str],
        reason: str,
        accepted: bool = True,
    ) -> None:
        """
        Taint one run-scoped domain after a diagnostic POST may have created work.

        The retained state contains only bounded task identity and validated
        monitor candidates already accepted by the Redfish transport boundary.
        Re-recording the same task updates its reason without accumulating
        attacker-controlled history.

        Args:
            domain_key: Opaque process-local diagnostic domain identifier.
            dut_id: Stable DUT identifier whose route received the POST.
            task_id: Bounded Redfish task identifier returned by firmware.
            monitor_uris: Validated task or TaskMonitor URI candidates.
            reason: Controlled explanation of why terminal state is unproven.
            accepted: Whether an accepted transport response was observed, rather
                than a provisional POST with an unconfirmed remote outcome.

        Side Effects:
            Replaces the unresolved-task state for ``domain_key``.
        """

        max_text = int(getattr(self._service, "_DIAGNOSTIC_LOG_TEXT_MAX_CHARS", 2048))
        max_items = int(getattr(self._service, "_DIAGNOSTIC_LOG_MAX_ITEMS", 64))
        bounded_uris: List[str] = []
        for candidate in monitor_uris[:max_items]:
            if (
                type(candidate) is str
                and candidate.strip()
                and len(candidate) <= max_text
                and candidate.strip() not in bounded_uris
            ):
                bounded_uris.append(candidate.strip())
        max_task_id = int(
            getattr(self._service, "_DIAGNOSTIC_FIELD_NAME_MAX_CHARS", 256)
        )
        bounded_task_id = (
            task_id[:max_task_id] if type(task_id) is str and task_id else "unknown"
        )
        self._diagnostic_domain_taints[domain_key] = {
            "kind": "accepted_task" if accepted else "unconfirmed_post",
            "dut_id": str(dut_id),
            "task_id": bounded_task_id,
            "monitor_uris": tuple(bounded_uris),
            "reason": str(reason)[:max_text],
        }

    def _clear_proven_terminal_diagnostic_task(
        self,
        domain_key: Any,
        task_id: str,
    ) -> None:
        """
        Clear a domain gate only when it still identifies the proven monitor.

        Comparing task identity prevents delayed evidence for an older monitor
        from clearing a newer unresolved owner of the same diagnostic domain.
        Callers may pass ``None`` for paths that bypass the guarded wrapper;
        those compatibility paths leave all run-scoped state untouched.

        Args:
            domain_key: Opaque process-local diagnostic domain identifier.
            task_id: Task identifier whose terminal state has been proven.

        Side Effects:
            Removes the matching unresolved-task record from this runner.
        """

        current = self._diagnostic_domain_taints.get(domain_key)
        if isinstance(current, dict) and current.get("task_id") == task_id:
            self._diagnostic_domain_taints.pop(domain_key, None)

    async def _prove_diagnostic_domain_quiescent(
        self,
        domain_key: Tuple[str, str],
    ) -> Tuple[bool, str]:
        """
        Boundedly prove that an exact prior task monitor reached terminal state.

        This recovery path performs GET-only probes against exact monitor
        candidates supplied by firmware. Missing, malformed, inaccessible, or
        still-running resources do not prove quiescence. A recognized terminal
        success or failure does, because either releases the firmware
        diagnostic slot without hiding the original collector outcome.

        Args:
            domain_key: Opaque process-local diagnostic domain identifier.

        Returns:
            A tuple containing whether the domain is safe for another POST and
            a controlled explanation when terminal state remains unproven.

        Side Effects:
            Issues a bounded number of read-only Redfish GETs and clears the
            matching run-scoped taint when a terminal task state is observed.
        """

        taint = self._diagnostic_domain_taints.get(domain_key)
        if not isinstance(taint, dict):
            return True, ""

        taint_kind = str(taint.get("kind") or "accepted_task")
        task_id = str(taint.get("task_id") or "unknown")
        origin_dut_id = str(taint.get("dut_id") or "")
        if taint_kind == "parallel_session_unresolved" or taint.get(
            "rejection_origins"
        ):
            return (
                False,
                str(
                    taint.get("reason")
                    or "adaptive diagnostic session has unresolved task state"
                ),
            )
        raw_monitor_uris = taint.get("monitor_uris", ())
        monitor_uris = (
            list(raw_monitor_uris)
            if isinstance(raw_monitor_uris, (list, tuple))
            else []
        )
        if not origin_dut_id or not monitor_uris:
            if taint_kind == "unconfirmed_post":
                return (
                    False,
                    "prior diagnostic POST outcome is unconfirmed and no validated "
                    "monitor URI is available, so terminal state cannot be proven",
                )
            if taint_kind == "remote_no_resubmit":
                message_id = str(taint.get("message_id") or "remote rejection")
                origin_collector_id = str(
                    taint.get("origin_collector_id") or "unknown collector"
                )
                return (
                    False,
                    f"prior remote diagnostic rejection {message_id} from "
                    f"{origin_collector_id} remains a run-scoped no-resubmit "
                    "gate because firmware supplied no exact task monitor",
                )
            return (
                False,
                f"prior accepted diagnostic task {task_id} has no validated "
                "monitor URI, so terminal state cannot be proven",
            )

        deadline = self._monotonic() + _DIAGNOSTIC_QUIESCENCE_PROBE_SECONDS
        observations: List[str] = []
        for monitor_uri in monitor_uris:
            try:
                (
                    success,
                    response,
                    metadata,
                    deadline_exhausted,
                ) = await self._dispatch_task_status_with_deadline(
                    origin_dut_id,
                    monitor_uri,
                    deadline,
                    _DIAGNOSTIC_QUIESCENCE_REQUEST_SECONDS,
                )
            except Exception:
                observations.append("monitor request failed")
                if self._monotonic() >= deadline:
                    break
                continue

            if self._service._is_redfish_resource_absent(response, metadata):
                observations.append("task resource missing")
                if deadline_exhausted:
                    break
                continue
            if not success:
                observations.append("monitor inaccessible")
                if deadline_exhausted:
                    break
                continue

            normalized = self._service._normalize_task_monitor_response(
                response,
                metadata,
                monitor_uri,
            )
            decision = evaluate_task_poll(
                normalized,
                attempt_index=0,
                previous_state=None,
                previous_percent=None,
            )
            if decision.disposition in {
                TaskPollDisposition.SUCCEEDED,
                TaskPollDisposition.FAILED,
            }:
                self._clear_proven_terminal_diagnostic_task(domain_key, task_id)
                prior_label = (
                    "Remote diagnostic rejection monitor"
                    if taint_kind == "remote_no_resubmit"
                    else "Prior accepted diagnostic task"
                )
                await self._service._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"{prior_label} {task_id} reached terminal "
                    f"state {decision.task_state}; diagnostic domain is quiescent",
                    origin_dut_id,
                )
                return True, ""
            if decision.disposition is TaskPollDisposition.RUNNING:
                if taint_kind == "remote_no_resubmit":
                    return (
                        False,
                        "prior remote diagnostic rejection monitor "
                        f"{task_id} remains in nonterminal state "
                        f"{decision.task_state}",
                    )
                return (
                    False,
                    f"prior accepted diagnostic task {task_id} remains in "
                    f"nonterminal state {decision.task_state}",
                )
            observations.append("monitor response malformed")
            if deadline_exhausted:
                break

        prior_reason = str(taint.get("reason") or "terminal state was not observed")
        observation = observations[-1] if observations else "no terminal response"
        if taint_kind == "remote_no_resubmit":
            return (
                False,
                "prior remote diagnostic rejection has an unproven release "
                f"condition ({prior_reason}); bounded exact-monitor probe ended "
                f"with {observation}",
            )
        return (
            False,
            f"prior accepted diagnostic task {task_id} has an unproven terminal "
            f"state ({prior_reason}); bounded quiescence probe ended with "
            f"{observation}",
        )

    def _monotonic(self) -> float:
        """
        Read the service clock so existing test/subclass seams stay authoritative.

        The implementation uses current instance state to read the service clock
        so existing test/subclass seams stay authoritative. Parsing or I/O must
        finish before the validated representation is made available to the
        caller.

        Returns:
            The numeric monotonic value.
        """

        clock = getattr(self._service, "_diagnostic_monotonic", None)
        return clock() if callable(clock) else time.monotonic()

    async def _dispatch_task_status_with_deadline(
        self,
        dut_id: str,
        task_uri: str,
        deadline: float,
        poll_interval: float,
    ) -> Tuple[bool, Any, Dict[str, Any], bool]:
        """
        Fetch task status once without allowing nested retries past a deadline.

        Poll cadence and request timeout are different concerns. A caller may
        request zero-delay polling, but the HTTP request still needs a usable
        (bounded) opportunity to complete.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            task_uri: Validated remote resource identifier used for task URI.
            deadline: Absolute monotonic deadline after which the operation must
                stop.
            poll_interval: Maximum duration in seconds allowed for poll
                interval.

        Returns:
            A tuple containing ``status flag``, ``returned value``, ``metadata
            mapping``, and ``outcome flag`` in that order.
        """
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            return False, "Task monitoring deadline exhausted", {}, True

        # Poll cadence and request timeout are different concerns.  A caller
        # may request zero-delay polling, but the HTTP request still needs a
        # usable (bounded) opportunity to complete.
        request_timeout = min(max(float(poll_interval), 1.0), remaining)
        try:
            success, response, metadata = await asyncio.wait_for(
                self._service.dispatch_request(
                    dut_id,
                    "GET",
                    task_uri,
                    timeout=request_timeout,
                    bypass_cache=True,
                    retry_count=0,
                    expected_http_statuses=[404],
                ),
                timeout=remaining,
            )
        except asyncio.TimeoutError:
            return False, "Task monitoring deadline exhausted", {}, True

        return success, response, metadata, self._monotonic() >= deadline

    @staticmethod
    async def _sleep_with_task_monitor_deadline(delay: float, deadline: float) -> bool:
        """
        Sleep no longer than the task-monitor budget and report time remaining.

        The implementation uses ``delay`` and ``deadline`` to sleep no longer
        than the task-monitor budget and report time remaining. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            delay: Numeric delay used while the operation performs bounded
                accounting.
            deadline: Absolute monotonic deadline after which the operation must
                stop.

        Returns:
            Whether the sleep no longer than the task-monitor budget and report
            time remaining operation succeeds.
        """
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        await asyncio.sleep(min(max(float(delay), 0.0), remaining))
        return time.monotonic() < deadline

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
        Monitor one accepted Redfish task within its original polling budget.

        Transient failures of the initial status GET retain the same deadline
        and retry loop used for subsequent polls. Authorization and terminal
        client failures remain immediate failures. Only status GETs are retried;
        this monitor never resubmits the action which created the task. Awaited
        requests and sleeps preserve cancellation and do not outlive the caller.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            task_id: Stable task identifier used to correlate configuration,
                logs, and results.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            entity_context: Optional entity context; ``None`` selects the
                function's default behavior.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing wait for task completion, or ``None`` when the
            requested value is unavailable.
        """
        collector_id = kwargs.get("collector_id", "unknown")
        require_result_location = kwargs.get("require_result_location") is True
        monitor_uris: List[str] = []
        raw_monitor_uris = kwargs.get("task_monitor_uris", [])
        if type(raw_monitor_uris) is str:
            raw_monitor_uris = [raw_monitor_uris]
        if type(raw_monitor_uris) not in {list, tuple}:
            raw_monitor_uris = []
        for index, monitor_uri in enumerate(raw_monitor_uris):
            if index >= self._service._DIAGNOSTIC_LOG_MAX_ITEMS:
                break
            if (
                type(monitor_uri) is str
                and len(monitor_uri) <= self._service._DIAGNOSTIC_LOG_TEXT_MAX_CHARS
                and monitor_uri.strip()
                and monitor_uri.strip() not in monitor_uris
            ):
                monitor_uris.append(monitor_uri.strip())

        def record_task_failure(
            state: str,
            status: str,
            messages: Any,
            response: Any = None,
            monitor_uri: Optional[str] = None,
            *,
            response_metadata: Any = None,
        ) -> None:
            """
            Expose bounded poll-failure evidence without changing the return contract.

            Standard Redfish message fields are retained through the existing
            diagnostic allowlist so failed-task snapshots remain actionable.
            Free-form text is sanitized and length-bounded, while OEM and other
            arbitrary nested content remains excluded. Remote I/O uses the
            configured transport policy and returns only after its response or
            failure has been observed.

            Args:
                state: Text supplied as state in the format accepted by this
                    function.
                status: Text supplied as status in the format accepted by this
                    function.
                messages: Messages consumed while the function attempts to
                    expose poll failures to callers without changing the return
                    contract.
                response: Transport response governed by the configured
                    authentication and trust policy.
                monitor_uri: Validated remote resource identifier used for
                    monitor URI.
                response_metadata: Optional response metadata; ``None`` selects
                    the function's default behavior.
            """
            if entity_context is None:
                return
            if type(messages) is list:
                message_source = messages
            elif messages is None:
                message_source = []
            else:
                message_source = [messages]
            safe_messages, messages_omitted = self._service._bounded_task_messages(
                message_source,
                include_diagnostic_text=True,
            )
            entity_context["task_failure"] = {
                "task_id": self._service._bounded_diagnostic_log_text(task_id),
                "state": self._service._bounded_task_state(state) or "Unknown",
                "status": self._service._bounded_task_status(status) or "Unknown",
                "messages": safe_messages,
            }
            if messages_omitted:
                entity_context["task_failure"]["messages_omitted"] = messages_omitted
            if safe_monitor_uri := self._service._bounded_diagnostic_uri(monitor_uri):
                entity_context["task_failure"]["monitor_uri"] = safe_monitor_uri
            if monitor_uris:
                entity_context["task_failure"]["monitor_uris"] = [
                    safe_uri
                    for uri in monitor_uris
                    if (safe_uri := self._service._bounded_diagnostic_uri(uri))
                    is not None
                ]
            if response is not None:
                entity_context["task_failure"]["response_summary"] = (
                    self._service._bounded_task_response_summary(
                        response, response_metadata
                    )
                )

        async def record_task_timeout(message: str) -> None:
            """
            Record task timeout.

            The implementation uses ``message`` to record task timeout. Owned
            asynchronous work is awaited before return, so completion does not
            leave an unobserved task behind.

            Args:
                message: Operator-facing text carried by the reported event or
                    failure.
            """
            await self._service._log_runtime(
                "ERROR",
                "RedfishService",
                f"Task {task_id} timed out after {total_timeout}s ({max_retries} retries)",
                dut_id,
            )
            record_task_failure(
                "Timeout",
                "Warning",
                [{"Message": message}],
            )

        try:
            # The task identifier is device-supplied. Compose it through the
            # single screened construction so an identifier carrying a path
            # separator or query cannot select another resource.
            compatibility_task_uri = self._service._compose_task_resource_uri(
                dut_id, task_id
            )
            if compatibility_task_uri and compatibility_task_uri not in monitor_uris:
                monitor_uris.append(compatibility_task_uri)
            retry_interval = max(0.0, float(kwargs.get("poll_interval", 30)))
            timeout_interval = max(retry_interval, 1.0)
            configured_timeout = max_retries * timeout_interval
            monitoring_started = self._monotonic()
            configured_deadline = monitoring_started + configured_timeout
            supplied_deadline = kwargs.get("deadline")
            try:
                supplied_deadline = float(supplied_deadline)
            except (TypeError, ValueError):
                supplied_deadline = configured_deadline
            if not math.isfinite(supplied_deadline):
                supplied_deadline = configured_deadline
            deadline = min(configured_deadline, supplied_deadline)
            total_timeout = max(0.0, deadline - monitoring_started)

            initial_retry_after = self._service._parse_retry_after_seconds(
                kwargs.get("initial_retry_after")
            )

            async def poll_monitor_candidates() -> Tuple[
                bool,
                Any,
                Dict[str, Any],
                bool,
                Optional[str],
                bool,
            ]:
                """
                Poll candidates once, falling back for missing or ambiguous resources.

                The implementation uses current instance state to poll
                candidates once, falling back for missing or ambiguous
                resources. Owned asynchronous work is awaited before return, so
                completion does not leave an unobserved task behind. Remote I/O
                uses the configured transport policy and returns only after its
                response or failure has been observed.

                Returns:
                    A tuple containing ``success flag``, ``returned value``,
                    ``last metadata``, ``status flag``, ``status or message
                    text``, and ``status flag`` in that order.
                """
                last_response: Any = None
                last_metadata: Dict[str, Any] = {}
                last_uri: Optional[str] = None
                missing_count = 0

                for monitor_uri in monitor_uris:
                    last_uri = monitor_uri
                    (
                        success,
                        response,
                        metadata,
                        deadline_exhausted,
                    ) = await self._service._dispatch_task_status_with_deadline(
                        dut_id,
                        monitor_uri,
                        deadline,
                        retry_interval,
                    )
                    last_response = response
                    last_metadata = metadata if isinstance(metadata, dict) else {}
                    if success:
                        http_status = self._service._http_status_from_response(
                            response, last_metadata
                        )
                        if should_try_next_monitor_candidate(
                            response,
                            http_status=http_status,
                            monitor_uri=monitor_uri,
                            has_fallback=monitor_uri != monitor_uris[-1],
                            require_result_location=require_result_location,
                            location=self._service._diagnostic_response_headers(
                                last_metadata
                            ).get("Location"),
                            max_text_chars=(
                                self._service._DIAGNOSTIC_LOG_TEXT_MAX_CHARS
                            ),
                            max_items=self._service._DIAGNOSTIC_LOG_MAX_ITEMS,
                        ):
                            await self._service._log_runtime(
                                "WARN",
                                "RedfishService",
                                f"Task {task_id} returned an ambiguous response at "
                                f"{self._service._sanitize_diagnostic_uri(monitor_uri)}; "
                                "trying the next accepted task URI",
                                dut_id,
                            )
                            continue
                        if entity_context is not None:
                            entity_context["selected_monitor_uri"] = (
                                self._service._sanitize_diagnostic_uri(monitor_uri)
                            )
                        return (
                            True,
                            response,
                            last_metadata,
                            deadline_exhausted,
                            monitor_uri,
                            False,
                        )

                    if self._service._is_redfish_resource_absent(response, metadata):
                        missing_count += 1
                        await self._service._log_runtime(
                            "WARN",
                            "RedfishService",
                            f"Task {task_id} monitor resource is missing at "
                            f"{self._service._sanitize_diagnostic_uri(monitor_uri)}; trying "
                            "the next accepted task URI",
                            dut_id,
                        )
                        if deadline_exhausted:
                            break
                        continue

                    return (
                        False,
                        response,
                        last_metadata,
                        deadline_exhausted,
                        monitor_uri,
                        False,
                    )

                return (
                    False,
                    last_response,
                    last_metadata,
                    self._monotonic() >= deadline,
                    last_uri,
                    bool(monitor_uris) and missing_count == len(monitor_uris),
                )

            await self._service._log_runtime(
                "INFO",
                "RedfishService",
                f"[{collector_id}] Starting task monitoring for {task_id} "
                f"({max_retries} retries, {total_timeout}s timeout) using "
                f"{[self._service._sanitize_diagnostic_uri(uri) for uri in monitor_uris]}",
                dut_id,
            )

            initial_delay = (
                initial_retry_after
                if initial_retry_after is not None
                else min(2.0, retry_interval)
            )
            if not await self._service._sleep_with_task_monitor_deadline(
                initial_delay, deadline
            ):
                await record_task_timeout("Task monitoring deadline exhausted")
                return None

            (
                test_success,
                test_response,
                test_metadata,
                deadline_exhausted,
                test_monitor_uri,
                test_resource_missing,
            ) = await poll_monitor_candidates()
            if test_success:
                test_response = self._service._normalize_task_monitor_response(
                    test_response,
                    test_metadata,
                    test_monitor_uri,
                )
            if deadline_exhausted and not test_success:
                if test_resource_missing:
                    record_task_failure(
                        "TaskResourceMissing",
                        "Error",
                        [
                            {
                                "Message": "Accepted task resources remained missing "
                                "until the monitoring deadline"
                            }
                        ],
                        test_response,
                        test_monitor_uri,
                    )
                else:
                    await record_task_timeout("Task monitoring deadline exhausted")
                return None
            initial_authorization_failure = is_task_monitor_authorization_failure(
                test_response,
                http_status=self._service._http_status_from_response(
                    test_response, test_metadata
                ),
                max_text_chars=self._service._DIAGNOSTIC_LOG_TEXT_MAX_CHARS,
            )
            initial_retryable_failure = (
                not test_success
                and not test_resource_missing
                and not initial_authorization_failure
                and self._service._redfish_get_failure_is_retryable(
                    test_response, test_metadata
                )
            )
            if (
                not test_success
                and not test_resource_missing
                and not initial_retryable_failure
            ):
                test_response_summary = self._service._bounded_task_response_summary(
                    test_response,
                    test_metadata,
                )
                test_response_log = json.dumps(
                    test_response_summary,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                record_task_failure(
                    "Inaccessible",
                    "Error",
                    [
                        {
                            "MessageId": "NvDebug.1.TaskMonitorInaccessible",
                            "Severity": "Error",
                        }
                    ],
                    test_response,
                    test_monitor_uri,
                    response_metadata=test_metadata,
                )
                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    "Task monitor URI "
                    f"{self._service._sanitize_diagnostic_uri(test_monitor_uri)} is not "
                    f"accessible; response metadata={test_response_log}",
                    dut_id,
                )
                return None

            if test_resource_missing or initial_retryable_failure:
                initial_failure_description = (
                    "was not visible"
                    if test_resource_missing
                    else "encountered a transient status GET failure"
                )
                await self._service._log_runtime(
                    "WARN",
                    "RedfishService",
                    f"Task {task_id} {initial_failure_description} during the initial probe; "
                    "continuing within the original polling budget",
                    dut_id,
                )
                initial_failure_retry_after = self._service._retry_after_from_metadata(
                    test_metadata
                )
                initial_failure_delay = (
                    initial_failure_retry_after
                    if initial_failure_retry_after is not None
                    else retry_interval
                )
                if not await self._service._sleep_with_task_monitor_deadline(
                    initial_failure_delay, deadline
                ):
                    if test_resource_missing:
                        record_task_failure(
                            "TaskResourceMissing",
                            "Error",
                            [
                                {
                                    "Message": "Accepted task resource never became visible"
                                }
                            ],
                            test_response,
                            test_monitor_uri,
                        )
                    else:
                        await record_task_timeout(
                            "Task monitoring deadline exhausted before retrying "
                            "the initial status GET"
                        )
                    return None
            else:
                test_retry_after = self._service._retry_after_from_metadata(
                    test_metadata
                )
                if (
                    test_retry_after is not None
                    and not await self._service._sleep_with_task_monitor_deadline(
                        test_retry_after, deadline
                    )
                ):
                    await record_task_timeout(
                        "Task monitoring deadline exhausted while honoring Retry-After"
                    )
                    return None

            test_poll_decision = evaluate_task_poll(
                test_response,
                attempt_index=0,
                previous_state=None,
                previous_percent=None,
            )
            test_task_state = test_poll_decision.task_state
            if (
                test_success
                and test_poll_decision.disposition is TaskPollDisposition.SUCCEEDED
            ):
                await self._service._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Task {task_id} completed during the initial monitor probe",
                    dut_id,
                )
                if function_tag and entity_context:
                    completion_data = {
                        "task_id": task_id,
                        "final_state": test_task_state,
                        "total_attempts": 1,
                        "max_retries": max_retries,
                        "completion_response": self._service._bounded_task_artifact_response_summary(
                            test_response, test_metadata
                        ),
                        "http_status": self._service._http_status_from_response(
                            test_response, test_metadata
                        ),
                        "response_headers": self._service._response_headers_from_metadata(
                            test_metadata
                        ),
                        "monitor_uri": self._service._sanitize_diagnostic_uri(
                            test_monitor_uri
                        ),
                        "entity_type": entity_context.get("entity_type", "unknown"),
                        "entity_id": entity_context.get("entity_id", "unknown"),
                        "log_service": entity_context.get("log_service", "unknown"),
                        "timestamp": datetime.now().isoformat(),
                    }
                    await self._service._append_to_diagnostic_json_array(
                        dut_id,
                        completion_data,
                        function_tag,
                        "task_completions",
                        kwargs.get("collector_id", "unknown"),
                    )
                return test_response

            prev_state = None
            prev_percent = None
            last_poll_kind: Optional[TaskPollFailureKind] = (
                TaskPollFailureKind.TASK_RESOURCE_MISSING
                if test_resource_missing
                else (
                    TaskPollFailureKind.HTTP_FAILURE
                    if initial_retryable_failure
                    else None
                )
            )
            last_poll_response: Any = test_response
            last_poll_metadata: Dict[str, Any] = test_metadata
            last_monitor_uri: Optional[str] = test_monitor_uri

            for attempt in range(max_retries):
                try:
                    (
                        success,
                        response,
                        response_metadata,
                        deadline_exhausted,
                        selected_monitor_uri,
                        resource_missing,
                    ) = await poll_monitor_candidates()
                except Exception as e:
                    safe_poll_error = self._service._bounded_diagnostic_log_text(e)
                    await self._service._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Task {task_id} poll error (attempt {attempt + 1}/{max_retries}): "
                        f"{type(e).__name__}: {safe_poll_error}",
                        dut_id,
                    )
                    success = False
                    response = None
                    response_metadata = {}
                    selected_monitor_uri = None
                    resource_missing = False
                    deadline_exhausted = self._monotonic() >= deadline

                last_poll_response = response
                last_poll_metadata = response_metadata
                last_monitor_uri = selected_monitor_uri

                if not success:
                    if resource_missing:
                        last_poll_kind = TaskPollFailureKind.TASK_RESOURCE_MISSING
                        await self._service._log_runtime(
                            "WARN",
                            "RedfishService",
                            f"Task {task_id} resources are missing "
                            f"(attempt {attempt + 1}/{max_retries}); retaining "
                            "the remaining polling budget",
                            dut_id,
                        )
                    else:
                        last_poll_kind = TaskPollFailureKind.HTTP_FAILURE
                    await self._service._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"Task {task_id} poll failed (attempt {attempt + 1}/{max_retries})",
                        dut_id,
                    )
                    if deadline_exhausted:
                        if (
                            not resource_missing
                            and self._service._http_status_from_response(
                                response, response_metadata
                            )
                            is None
                        ):
                            # A request that consumes the absolute deadline is
                            # a real timeout, even when the transport describes
                            # the final failed attempt generically.
                            last_poll_kind = None
                        break
                    failed_http_status = self._service._http_status_from_response(
                        response,
                        response_metadata,
                    )
                    authorization_failure = is_task_monitor_authorization_failure(
                        response,
                        http_status=failed_http_status,
                        max_text_chars=self._service._DIAGNOSTIC_LOG_TEXT_MAX_CHARS,
                    )
                    if not resource_missing and authorization_failure:
                        failure_summary = self._service._bounded_task_response_summary(
                            response,
                            response_metadata,
                        )
                        failure_log = json.dumps(
                            failure_summary,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        await self._service._log_runtime(
                            "ERROR",
                            "RedfishService",
                            f"Task {task_id} authorization failure; "
                            f"response metadata={failure_log}",
                            dut_id,
                        )
                        record_task_failure(
                            "HttpFailure",
                            "Error",
                            [
                                {
                                    "MessageId": (
                                        "NvDebug.1.TaskMonitorAuthorizationFailure"
                                    ),
                                    "Severity": "Error",
                                }
                            ],
                            response,
                            selected_monitor_uri,
                            response_metadata=response_metadata,
                        )
                        return None
                    if not await self._service._sleep_with_task_monitor_deadline(
                        retry_interval, deadline
                    ):
                        break
                    continue

                last_poll_kind = None
                response = self._service._normalize_task_monitor_response(
                    response,
                    response_metadata,
                    selected_monitor_uri,
                )
                last_poll_response = response
                response_retry_after = self._service._retry_after_from_metadata(
                    response_metadata
                )
                next_poll_delay = (
                    response_retry_after
                    if response_retry_after is not None
                    else retry_interval
                )

                response_log = json.dumps(
                    self._service._bounded_task_response_summary(
                        response,
                        response_metadata,
                    ),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                await self._service._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Task {task_id} response (attempt {attempt + 1}): {response_log}",
                    dut_id,
                )

                poll_decision = evaluate_task_poll(
                    response,
                    attempt_index=attempt,
                    previous_state=prev_state,
                    previous_percent=prev_percent,
                )
                task_state = poll_decision.task_state
                task_status = poll_decision.task_status
                percent_complete = poll_decision.percent_complete

                # Save intermediate status to metadata
                if (
                    function_tag
                    and entity_context
                    and success
                    and type(response) is dict
                ):
                    status_data = {
                        "task_id": task_id,
                        "attempt": attempt + 1,
                        "max_retries": max_retries,
                        "task_state": task_state or "Unknown",
                        "task_status": task_status or "Unknown",
                        "percent_complete": percent_complete,
                        "response_summary": self._service._bounded_task_artifact_response_summary(
                            response, response_metadata
                        ),
                        "monitor_uri": self._service._sanitize_diagnostic_uri(
                            selected_monitor_uri
                        ),
                        "entity_type": entity_context.get("entity_type", "unknown"),
                        "entity_id": entity_context.get("entity_id", "unknown"),
                        "log_service": entity_context.get("log_service", "unknown"),
                        "timestamp": datetime.now().isoformat(),
                    }
                    await self._service._append_to_diagnostic_json_array(
                        dut_id,
                        status_data,
                        function_tag,
                        "task_status_updates",
                        kwargs.get("collector_id", "unknown"),
                    )

                if poll_decision.disposition is TaskPollDisposition.MALFORMED:
                    await self._service._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"Task {task_id} malformed response (attempt {attempt + 1}/{max_retries})",
                        dut_id,
                    )
                    if not await self._service._sleep_with_task_monitor_deadline(
                        next_poll_delay, deadline
                    ):
                        break
                    continue
                assert task_state is not None

                # Log one line per poll only when selected by pure monitor policy.
                if poll_decision.should_log_progress:
                    await self._service._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Task {task_id} attempt {attempt + 1}/{max_retries}: "
                        f"{task_state}, "
                        f"{percent_complete if percent_complete is not None else 'unknown'}% complete",
                        dut_id,
                    )
                prev_state = task_state
                prev_percent = percent_complete

                # Completion states
                if poll_decision.disposition is TaskPollDisposition.SUCCEEDED:
                    label = (
                        "completed"
                        if task_state == "Completed"
                        else f"completed ({task_state})"
                    )
                    await self._service._log_runtime(
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
                            "completion_response": self._service._bounded_task_artifact_response_summary(
                                response, response_metadata
                            ),
                            "http_status": self._service._http_status_from_response(
                                response, response_metadata
                            ),
                            "response_headers": self._service._response_headers_from_metadata(
                                response_metadata
                            ),
                            "monitor_uri": self._service._sanitize_diagnostic_uri(
                                selected_monitor_uri
                            ),
                            "entity_type": entity_context.get("entity_type", "unknown"),
                            "entity_id": entity_context.get("entity_id", "unknown"),
                            "log_service": entity_context.get("log_service", "unknown"),
                            "timestamp": datetime.now().isoformat(),
                        }
                        await self._service._append_to_diagnostic_json_array(
                            dut_id,
                            completion_data,
                            function_tag,
                            "task_completions",
                            kwargs.get("collector_id", "unknown"),
                        )
                    return response

                # Terminal failure states
                if poll_decision.disposition is TaskPollDisposition.FAILED:
                    error_details = []
                    if "Messages" in response:
                        safe_messages = (
                            self._service._bounded_sensitive_response_capture(
                                {"Messages": dict.get(response, "Messages")}
                            ).get("Messages", [])
                        )
                        if safe_messages:
                            error_details.append(
                                "Messages: "
                                + json.dumps(
                                    safe_messages,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                )
                            )
                    if task_status:
                        error_details.append(f"TaskStatus: {task_status}")

                    await self._service._log_runtime(
                        "ERROR",
                        "RedfishService",
                        f"Task {task_id} failed ({task_state}) after {attempt + 1} attempts. {'; '.join(error_details) if error_details else ''}",
                        dut_id,
                    )
                    record_task_failure(
                        task_state,
                        task_status or "Unknown",
                        dict.get(response, "Messages", []),
                        response,
                        selected_monitor_uri,
                        response_metadata=response_metadata,
                    )
                    return None

                # Still running — sleep before next poll
                if attempt < max_retries - 1:
                    if not await self._service._sleep_with_task_monitor_deadline(
                        next_poll_delay, deadline
                    ):
                        break

            http_status = (
                self._service._http_status_from_response(
                    last_poll_response, last_poll_metadata
                )
                if last_poll_kind is TaskPollFailureKind.HTTP_FAILURE
                else None
            )
            exhaustion = classify_task_monitor_exhaustion(
                last_poll_kind,
                http_status=http_status,
                max_retries=max_retries,
                total_timeout=total_timeout,
            )
            if exhaustion.log_as_timeout:
                await record_task_timeout(exhaustion.message)
            else:
                record_task_failure(
                    exhaustion.task_state,
                    exhaustion.task_status,
                    [{"Message": exhaustion.message}],
                    last_poll_response,
                    last_monitor_uri,
                    response_metadata=last_poll_metadata,
                )
            return None

        except Exception as e:
            safe_monitoring_error = self._service._bounded_diagnostic_log_text(e)
            record_task_failure(
                "MonitoringException",
                "Error",
                [{"Message": f"{type(e).__name__}: {safe_monitoring_error}"}],
            )
            await self._service._log_runtime(
                "ERROR",
                "RedfishService",
                f"Task {task_id} monitoring exception: {type(e).__name__}: "
                f"{safe_monitoring_error}",
                dut_id,
            )
            return None

    async def _get_dump_location(
        self,
        task_response: Dict[str, Any],
        dut_id: str = None,
        attachment: bool = True,
        resolution_evidence: Optional[Dict[str, Any]] = None,
        collector_deadline: Optional[float] = None,
    ) -> Optional[str]:
        """
        Get the log dump location for a redfish task (matching legacy behavior).

        The implementation uses ``task_response``, ``dut_id``, ``attachment``,
        ``resolution_evidence``, and ``collector_deadline`` to get the log dump
        location for a redfish task (matching legacy behavior). Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            task_response: Mapping supplying fields for get the log dump
                location for a redfish task (matching legacy behavior).
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            attachment: Whether attachment is enabled or required for this
                operation.
            resolution_evidence: Optional resolution evidence; ``None`` selects
                the function's default behavior.
            collector_deadline: Optional collector deadline; ``None`` selects
                the function's default behavior.

        Returns:
            The canonical dump location text, or ``None`` when the requested
            value is unavailable.
        """
        evidence = resolution_evidence if resolution_evidence is not None else {}
        evidence.update(
            {
                "resolution_source": None,
                "task_location_uri": None,
                "resolved_entry_uri": None,
                "attachment_uri": None,
                "advertised_attachment_size_bytes": None,
                "entry_http_status": None,
                "entry_response_headers": {},
            }
        )

        def remaining_resolution_budget() -> Optional[float]:
            """
            Return the remaining resolution budget.

            The implementation uses current instance state to produce the
            remaining resolution budget.

            Returns:
                The numeric remaining resolution budget value, or ``None`` when
                the requested value is unavailable.
            """
            if collector_deadline is None:
                return None
            return collector_deadline - self._monotonic()

        try:
            initial_remaining = remaining_resolution_budget()
            if initial_remaining is not None and initial_remaining <= 0:
                evidence["resolution_error"] = (
                    "diagnostic lifecycle deadline expired before attachment resolution"
                )
                return None

            # Inspect only fixed-width Location values without copying arbitrary
            # task payload content. The transport already bounds the parsed
            # response bytes; the smaller persisted-evidence item cap must not
            # change live attachment resolution semantics.
            if type(task_response) is not dict:
                return None
            payload = dict.get(task_response, "Payload")
            raw_headers = (
                dict.get(payload, "HttpHeaders") if type(payload) is dict else None
            )
            resp_headers: List[str] = []
            if type(raw_headers) is list:
                for header in list.__iter__(raw_headers):
                    if (
                        type(header) is str
                        and len(header) <= self._service._DIAGNOSTIC_LOG_TEXT_MAX_CHARS
                        and header.partition(":")[0].strip().casefold() == "location"
                    ):
                        resp_headers.append(header)
            has_location_header = any(
                header.partition(":")[0].strip().casefold() == "location"
                for header in resp_headers
            )
            if not has_location_header:
                direct_location = dict.get(task_response, "Location")
                if (
                    type(direct_location) is not str
                    or len(direct_location)
                    > self._service._DIAGNOSTIC_LOG_TEXT_MAX_CHARS
                    or not direct_location.strip()
                ):
                    direct_location = dict.get(task_response, "@odata.id")
                if (
                    type(direct_location) is str
                    and len(direct_location)
                    <= self._service._DIAGNOSTIC_LOG_TEXT_MAX_CHARS
                    and direct_location.strip()
                ):
                    try:
                        direct_path = urlsplit(direct_location).path
                    except ValueError:
                        direct_path = direct_location
                    if not re.search(
                        r"/TaskService/(?:Tasks|TaskMonitors)(?:/|$)",
                        direct_path,
                        flags=re.IGNORECASE,
                    ):
                        resp_headers = [
                            *resp_headers,
                            f"Location: {direct_location.strip()}",
                        ]
            dump_location = ""

            for header in resp_headers:
                header_name, separator, header_value = header.partition(":")
                if separator and header_name.strip().lower() == "location":
                    candidate_location = header_value.strip()
                    if not validate_redfish_uri(candidate_location):
                        # Reject rather than dispatch, and keep looking: the
                        # MessageArgs and attachment fallbacks below stay
                        # reachable instead of a failed request being the only
                        # signal.
                        evidence["task_location_policy_rejected"] = True
                        await self._service._log_runtime(
                            "WARNING",
                            "RedfishService",
                            "Rejected task Location header that failed the "
                            "response URI policy",
                            dut_id,
                        )
                        continue
                    dump_location = candidate_location
                    evidence["task_location_uri"] = (
                        self._service._sanitize_diagnostic_uri(dump_location)
                    )
                    if attachment:
                        if self._service._uri_has_attachment_path(dump_location):
                            evidence.update(
                                {
                                    "resolution_source": "task_location_attachment",
                                    "resolved_entry_uri": self._service._sanitize_diagnostic_uri(
                                        self._service._entry_uri_from_attachment_uri(
                                            dump_location
                                        )
                                    ),
                                    "attachment_uri": self._service._sanitize_diagnostic_uri(
                                        dump_location
                                    ),
                                }
                            )
                            await self._service._log_runtime(
                                "DEBUG",
                                "RedfishService",
                                "Using attachment URI from task Location header: "
                                f"{self._service._sanitize_diagnostic_uri(dump_location)}",
                                dut_id,
                            )
                            break

                        # Fetch the URI to get AdditionalDataURI like legacy
                        evidence["resolved_entry_uri"] = (
                            self._service._sanitize_diagnostic_uri(dump_location)
                        )
                        request_options: Dict[str, Any] = {"bypass_cache": True}
                        resolution_remaining = remaining_resolution_budget()
                        if resolution_remaining is not None:
                            if resolution_remaining <= 0:
                                evidence["resolution_error"] = (
                                    "diagnostic lifecycle deadline expired before "
                                    "attachment entry lookup"
                                )
                                return None
                            request_options.update(
                                {
                                    "retry_count": 0,
                                    "timeout": max(0.001, resolution_remaining),
                                }
                            )
                        (
                            success,
                            resp,
                            entry_metadata,
                        ) = await self._service.dispatch_request(
                            dut_id, "GET", dump_location, **request_options
                        )
                        resolution_remaining = remaining_resolution_budget()
                        if (
                            resolution_remaining is not None
                            and resolution_remaining <= 0
                        ):
                            evidence["resolution_error"] = (
                                "diagnostic lifecycle deadline expired during "
                                "attachment entry lookup"
                            )
                            return None
                        evidence["entry_http_status"] = (
                            self._service._http_status_from_response(
                                resp, entry_metadata
                            )
                        )
                        evidence["entry_response_headers"] = (
                            self._service._response_headers_from_metadata(
                                entry_metadata
                            )
                        )
                        advertised_size = (
                            dict.get(resp, "AdditionalDataSizeBytes")
                            if success and type(resp) is dict
                            else None
                        )
                        if type(advertised_size) is int:
                            if (
                                advertised_size < 0
                                or int.bit_length(advertised_size) > 256
                            ):
                                advertised_size = None
                        elif (
                            type(advertised_size) is str
                            and len(advertised_size) <= 32
                            and advertised_size.strip().isascii()
                            and advertised_size.strip().isdecimal()
                        ):
                            advertised_size = int(advertised_size.strip())
                        else:
                            advertised_size = None
                        evidence["advertised_attachment_size_bytes"] = advertised_size
                        additional_data_uri = (
                            dict.get(resp, "AdditionalDataURI")
                            if success and type(resp) is dict
                            else None
                        )
                        additional_data_uri_accepted = bool(
                            type(additional_data_uri) is str
                            and len(additional_data_uri)
                            <= self._service._DIAGNOSTIC_LOG_TEXT_MAX_CHARS
                            and additional_data_uri.strip()
                            and validate_redfish_uri(additional_data_uri.strip())
                        )
                        if (
                            not additional_data_uri_accepted
                            and type(additional_data_uri) is str
                            and additional_data_uri.strip()
                        ):
                            # A value that fails policy leaves dump_location
                            # unchanged, so the attachment fallback below still
                            # produces a truthful result.
                            evidence["additional_data_uri_policy_rejected"] = True
                            await self._service._log_runtime(
                                "WARNING",
                                "RedfishService",
                                "Rejected AdditionalDataURI that failed the "
                                "response URI policy",
                                dut_id,
                            )
                        if additional_data_uri_accepted:
                            dump_location = additional_data_uri
                            evidence.update(
                                {
                                    "resolution_source": "entry_additional_data_uri",
                                    "attachment_uri": self._service._sanitize_diagnostic_uri(
                                        dump_location
                                    ),
                                }
                            )
                        else:
                            # Fall back to previous default like legacy
                            dump_location = self._service._append_attachment_uri(
                                dump_location
                            )
                            evidence.update(
                                {
                                    "resolution_source": "entry_attachment_fallback",
                                    "attachment_uri": self._service._sanitize_diagnostic_uri(
                                        dump_location
                                    ),
                                }
                            )
                            await self._service._log_runtime(
                                "DEBUG",
                                "RedfishService",
                                "No AdditionalDataURI found; using fallback attachment URI: "
                                f"{self._service._sanitize_diagnostic_uri(dump_location)}",
                                dut_id,
                            )
                    else:
                        evidence.update(
                            {
                                "resolution_source": "task_location",
                                "resolved_entry_uri": self._service._sanitize_diagnostic_uri(
                                    dump_location
                                ),
                            }
                        )
                    break

            if dump_location:
                return dump_location

            # Fallback: DiagnosticLog endpoint (e.g. Managers/BMC/LogServices/DiagnosticLog)
            # embeds the attachment URI in Messages[*].MessageArgs rather than HttpHeaders.
            # Example MessageId: "Ami.1.0.0.DiagnosticDumpCreated"
            messages = dict.get(task_response, "Messages")
            if type(messages) is not list:
                messages = []
            # As with headers above, response byte limits own resource bounds;
            # the artifact evidence cap must not hide a valid protocol target.
            for msg in list.__iter__(messages):
                if type(msg) is not dict:
                    continue
                args = dict.get(msg, "MessageArgs")
                if type(args) not in {list, tuple} or not args:
                    continue
                dump_location = args[0]
                if (
                    type(dump_location) is str
                    and len(dump_location)
                    <= self._service._DIAGNOSTIC_LOG_TEXT_MAX_CHARS
                    and dump_location.startswith("/redfish/")
                ):
                    safe_location = self._service._sanitize_diagnostic_uri(
                        dump_location
                    )
                    is_attachment_uri = bool(
                        attachment
                        and self._service._uri_has_attachment_path(dump_location)
                    )
                    evidence.update(
                        {
                            "resolution_source": (
                                "task_message_arg_attachment"
                                if is_attachment_uri
                                else "task_message_arg_entry"
                            ),
                            "resolved_entry_uri": (
                                self._service._sanitize_diagnostic_uri(
                                    self._service._entry_uri_from_attachment_uri(
                                        dump_location
                                    )
                                )
                                if is_attachment_uri
                                else safe_location
                            ),
                            "attachment_uri": (
                                safe_location if is_attachment_uri else None
                            ),
                        }
                    )
                    await self._service._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Found dump location in Messages.MessageArgs: {safe_location}",
                        dut_id,
                    )
                    return dump_location

            if evidence.get("task_location_policy_rejected") and not evidence.get(
                "resolution_error"
            ):
                evidence["resolution_error"] = (
                    "task Location header rejected by response URI policy"
                )
            return None
        except Exception as e:
            safe_error = self._service._bounded_diagnostic_log_text(e)
            await self._service._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception getting dump location: {safe_error}",
                dut_id,
            )
            evidence["resolution_error"] = (
                f"{self._service._bounded_type_name(e)}: {safe_error}"
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

        The implementation uses ``dut_id``, ``entity_type``, ``entity_id``,
        ``log_service``, and ``default_payload`` to try fallback payloads in
        order until one succeeds. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind. The
        operation mutates ``output_files`` and ``status_list`` in place;
        ownership of those objects remains with the caller.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            entity_type: Text supplied as entity type in the format accepted by
                this function.
            entity_id: Stable entity identifier used to correlate configuration,
                logs, and results.
            log_service: Text supplied as log service in the format accepted by
                this function.
            default_payload: Mapping supplying fields for try fallback payloads
                in order until one succeeds.
            fallback_payloads: Mapping supplying fields for try fallback
                payloads in order until one succeeds.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            status_list: Entries supplied as ``status_list`` without
                transferring container ownership.
            output_files: Entries supplied as ``output_files`` without
                transferring container ownership.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            diagnostic_type: Optional diagnostic type; ``None`` selects the
                function's default behavior.
            fallback_index: Numeric fallback index used by the operation's
                bounded accounting.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            Whether the try fallback payloads in order until one succeeds
            operation succeeds.
        """
        try:
            # Try fallback payloads first if provided
            if fallback_payloads:
                for i, fallback_payload in enumerate(fallback_payloads):
                    await self._service._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Trying fallback payload {i + 1}/{len(fallback_payloads)} for {entity_type} {entity_id}",
                        dut_id,
                    )

                    attempt_disposition = DiagnosticAttemptDisposition()
                    attempt_kwargs = dict(kwargs)
                    attempt_kwargs["_diagnostic_attempt_disposition"] = (
                        attempt_disposition
                    )
                    status, output_file = (
                        await self._service._execute_redfish_dump_task(
                            dut_id=dut_id,
                            entity_type=entity_type,
                            entity_id=entity_id,
                            log_service=log_service,
                            payload=fallback_payload,
                            function_tag=function_tag,
                            fallback_index=i,
                            collector_id=collector_id,
                            **attempt_kwargs,
                        )
                    )
                    if not attempt_disposition.blocked_before_post:
                        status_list.append(status)
                    if status and output_file:
                        output_files.append(output_file)

                    if status:
                        await self._service._log_runtime(
                            "INFO",
                            "RedfishService",
                            f"Fallback payload {i + 1} succeeded for {entity_type} {entity_id}",
                            dut_id,
                        )
                        return True
                    if not attempt_disposition.resubmit_allowed:
                        return False

            # If no fallback payloads or all failed, try default payload
            await self._service._log_runtime(
                "INFO",
                "RedfishService",
                f"Trying default payload for {entity_type} {entity_id}",
                dut_id,
            )

            attempt_disposition = DiagnosticAttemptDisposition()
            attempt_kwargs = dict(kwargs)
            attempt_kwargs["_diagnostic_attempt_disposition"] = attempt_disposition
            status, output_file = await self._service._execute_redfish_dump_task(
                dut_id=dut_id,
                entity_type=entity_type,
                entity_id=entity_id,
                log_service=log_service,
                payload=default_payload,
                function_tag=function_tag,
                collector_id=collector_id,
                **attempt_kwargs,
            )
            if not attempt_disposition.blocked_before_post:
                status_list.append(status)
            if status and output_file:
                output_files.append(output_file)

            return status

        except Exception as e:
            await self._service._log_runtime(
                "ERROR",
                "RedfishService",
                f"Exception in fallback payload execution: {str(e)}",
                dut_id,
            )
            return False

    async def _execute_redfish_dump_task_direct(
        self,
        dut_id: str,
        uri: str,
        payload: Dict[str, Any],
        function_tag: str,
        **kwargs,
    ) -> Tuple[bool, Optional[str]]:
        """
        Run the normal dump lifecycle while honoring a catalog-supplied URI.

        Absolute Redfish paths (including the path of an absolute URL) must use
        the canonical service-root prefix. Relative paths start directly at the
        entity collection.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            uri: Validated remote resource identifier used for URI.
            payload: Mapping supplying fields for normal dump lifecycle while
                honoring a catalog-supplied URI.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A tuple containing ``success flag`` and ``reason`` in that order.

        Raises:
            ValueError: If unsupported URI scheme; absolute URI is missing a
                host; network-path URI is not supported; or invalid Redfish
                service-root prefix; or another input invariant is violated.
        """

        try:
            parsed_uri = urlsplit(uri)
            if parsed_uri.scheme:
                if parsed_uri.scheme.lower() not in {"http", "https"}:
                    raise ValueError("unsupported URI scheme")
                if not parsed_uri.netloc:
                    raise ValueError("absolute URI is missing a host")
            elif parsed_uri.netloc:
                raise ValueError("network-path URI is not supported")

            path_parts = parsed_uri.path.split("/")
            if parsed_uri.path.startswith("/"):
                # Absolute Redfish paths (including the path of an absolute
                # URL) must use the canonical service-root prefix. Relative
                # paths start directly at the entity collection.
                if path_parts[1:3] != ["redfish", "v1"]:
                    raise ValueError("invalid Redfish service-root prefix")
                uri_parts = path_parts[3:]
            else:
                uri_parts = path_parts

            if (
                len(uri_parts) < 4
                or uri_parts[2] != "LogServices"
                or not uri_parts[0]
                or not uri_parts[1]
                or not uri_parts[3]
            ):
                raise ValueError("invalid LogServices resource path")

            entity_type, entity_id, _, log_service = uri_parts[:4]
        except (TypeError, ValueError):
            reason = (
                "Custom dump URI must identify an entity and LogServices member: "
                f"{self._service._diagnostic_uri_evidence(uri)}"
            )
            await self._service._log_runtime(
                "ERROR",
                "RedfishService",
                reason,
                dut_id,
            )
            return False, reason

        return await self._service._execute_redfish_dump_task(
            dut_id=dut_id,
            entity_type=entity_type,
            entity_id=entity_id,
            log_service=log_service,
            payload=payload,
            function_tag=function_tag,
            dump_uri_override=uri,
            **kwargs,
        )

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
        task_detail_limit: int = 3,
        snapshot_timeout: float = 5.0,
        request_timeout: float = 2.0,
    ) -> Optional[str]:
        """
        Capture task service snapshot.

        The implementation uses ``dut_id``, ``function_tag``, ``collector_id``,
        ``entity_type``, and ``entity_id`` to capture task service snapshot.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            entity_type: Text supplied as entity type in the format accepted by
                this function.
            entity_id: Stable entity identifier used to correlate configuration,
                logs, and results.
            log_service: Text supplied as log service in the format accepted by
                this function.
            reason: Text supplied as reason in the format accepted by this
                function.
            task_id: Stable task identifier used to correlate configuration,
                logs, and results.
            payload: Optional payload; ``None`` selects the function's default
                behavior.
            diagnostic_type: Optional diagnostic type; ``None`` selects the
                function's default behavior.
            extra_context: Optional extra context; ``None`` selects the
                function's default behavior.
            task_detail_limit: Upper bound enforced for task detail limit; the
                consuming boundary rejects or truncates values that exceed it.
            snapshot_timeout: Maximum duration in seconds allowed for snapshot
                timeout.
            request_timeout: Maximum duration in seconds allowed for request
                timeout.

        Returns:
            The validated ``file_path``, or ``None`` when no value qualifies.
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
            tasks_response: Optional[Dict[str, Any]] = None
            tasks_error: Optional[Any] = None
            task_details: List[Dict[str, Any]] = []
            omitted_task_uris: List[str] = []
            omitted_task_count = 0

            try:
                task_detail_limit = min(
                    self._service._DIAGNOSTIC_LOG_MAX_ITEMS,
                    max(0, int(task_detail_limit)),
                )
            except (TypeError, ValueError):
                task_detail_limit = 3
            try:
                snapshot_timeout = max(0.1, float(snapshot_timeout))
            except (TypeError, ValueError):
                snapshot_timeout = 5.0
            try:
                request_timeout = max(0.1, float(request_timeout))
            except (TypeError, ValueError):
                request_timeout = 2.0
            snapshot_deadline = self._monotonic() + snapshot_timeout

            async def bounded_snapshot_get(uri: str) -> Tuple[bool, Any, Any]:
                """
                Return the bounded snapshot get.

                The implementation uses ``uri`` to produce the bounded snapshot
                get. Owned asynchronous work is awaited before return, so
                completion does not leave an unobserved task behind.

                Args:
                    uri: Validated remote resource identifier used for URI.

                Returns:
                    A tuple containing ``success flag``, ``status text``, and
                    ``metadata mapping`` in that order.
                """
                remaining = snapshot_deadline - self._monotonic()
                if remaining <= 0:
                    return False, "TaskService snapshot deadline exhausted", {}
                timeout = min(request_timeout, remaining)
                try:
                    return await asyncio.wait_for(
                        self._service.dispatch_request(
                            dut_id,
                            "GET",
                            uri,
                            bypass_cache=True,
                            retry_count=0,
                            timeout=timeout,
                        ),
                        timeout=remaining,
                    )
                except asyncio.TimeoutError:
                    return False, "TaskService snapshot deadline exhausted", {}

            try:
                task_service_uri = self._service.get_configured_uri(
                    dut_id, "TaskService"
                )
                if task_service_uri:
                    tasks_uri = f"{task_service_uri}/Tasks"
                    tasks_success, tasks_resp_raw, _ = await bounded_snapshot_get(
                        tasks_uri
                    )
                    if tasks_success:
                        member_uris: List[str] = []
                        raw_members = (
                            dict.get(tasks_resp_raw, "Members", [])
                            if type(tasks_resp_raw) is dict
                            else []
                        )
                        member_count = (
                            list.__len__(raw_members)
                            if type(raw_members) is list
                            else 0
                        )
                        if type(raw_members) is list:
                            for index, member in enumerate(list.__iter__(raw_members)):
                                if (
                                    index
                                    >= self._service._CAPTURE_AUXILIARY_SCAN_MAX_ITEMS
                                ):
                                    break
                                if type(member) is not dict:
                                    continue
                                member_uri = dict.get(member, "@odata.id")
                                if (
                                    type(member_uri) is not str
                                    or not member_uri
                                    or len(member_uri)
                                    > self._service._DIAGNOSTIC_LOG_TEXT_MAX_CHARS
                                ):
                                    continue
                                if not validate_redfish_uri(member_uri):
                                    continue
                                if not redfish_uri_is_collection_member(
                                    member_uri, tasks_uri
                                ):
                                    continue
                                if member_uri not in member_uris:
                                    member_uris.append(member_uri)

                        tasks_response = {
                            "member_count": member_count,
                            "members_scanned": min(
                                member_count,
                                self._service._CAPTURE_AUXILIARY_SCAN_MAX_ITEMS,
                            ),
                            "member_uris": [
                                self._service._bounded_diagnostic_uri(uri)
                                for uri in member_uris
                            ],
                            "content": "omitted",
                        }

                        if task_id:
                            requested_task_id = str(task_id)
                            selected_uris = [
                                uri
                                for uri in member_uris
                                if uri.rstrip("/").split("/")[-1] == requested_task_id
                            ]
                            if not selected_uris:
                                targeted_uri = self._service._compose_task_resource_uri(
                                    dut_id, requested_task_id
                                )
                                if targeted_uri:
                                    selected_uris = [targeted_uri]
                            selected_uris = selected_uris[:1]
                        else:
                            selected_uris = member_uris[:task_detail_limit]
                        selected_set = set(selected_uris)
                        omitted_task_uris = [
                            self._service._bounded_diagnostic_uri(uri)
                            or "<omitted-uri>"
                            for uri in member_uris
                            if uri not in selected_set
                        ]
                        omitted_task_count = max(
                            member_count - len(selected_uris),
                            len(omitted_task_uris),
                        )

                        for member_uri in selected_uris:
                            detail_success, detail_data, _ = await bounded_snapshot_get(
                                member_uri
                            )
                            detail_entry: Dict[str, Any] = {
                                "task_uri": self._service._bounded_diagnostic_uri(
                                    member_uri
                                ),
                                "success": detail_success,
                            }
                            if detail_success:
                                detail_entry["response_summary"] = (
                                    self._service._bounded_task_artifact_response_summary(
                                        detail_data
                                    )
                                )
                            else:
                                detail_entry["error_summary"] = (
                                    self._service._bounded_task_artifact_response_summary(
                                        detail_data
                                    )
                                )
                            task_details.append(detail_entry)
                    else:
                        tasks_error = (
                            self._service._bounded_task_artifact_response_summary(
                                tasks_resp_raw
                            )
                        )
                else:
                    tasks_error = "TaskService URI not configured for DUT"
            except Exception as snapshot_exc:
                safe_snapshot_error = self._service._sanitize_diagnostic_text(
                    snapshot_exc
                )
                tasks_error = f"Failed to retrieve tasks: {safe_snapshot_error}"
                await self._service._log_runtime(
                    "WARN",
                    "RedfishService",
                    f"Failed to retrieve TaskService snapshot: {safe_snapshot_error}",
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
                "payload_summary": (
                    self._service._bounded_request_payload_summary(payload)
                    if payload is not None
                    else None
                ),
                "task_service_uri": self._service._bounded_diagnostic_uri(
                    task_service_uri
                ),
                "tasks_uri": self._service._bounded_diagnostic_uri(tasks_uri),
                "tasks_response": tasks_response,
                "tasks_response_error": tasks_error,
                "task_details": task_details,
                "task_details_omitted_count": omitted_task_count,
                "task_details_omitted_uris": omitted_task_uris,
                "task_detail_limit": task_detail_limit,
                "snapshot_timeout_seconds": snapshot_timeout,
            }

            if extra_context is not None:
                bounded_context = self._service._bounded_diagnostic_log_value(
                    extra_context,
                    depth=2,
                )
                if type(bounded_context) is not dict:
                    bounded_context = {"context": bounded_context}
                raw_task_failure = (
                    dict.get(extra_context, "task_failure")
                    if type(extra_context) is dict
                    else None
                )
                if type(raw_task_failure) is dict:
                    bounded_context["task_failure"] = (
                        self._service._bounded_task_failure_artifact_summary(
                            raw_task_failure
                        )
                    )
                snapshot_payload["additional_context"] = bounded_context

            substitutions = {
                "entity_label": entity_label,
                "task_label": task_label,
                "timestamp": timestamp_label,
            }

            file_path = await self._service._save_data_to_file_with_pattern(
                dut_id,
                snapshot_payload,
                function_tag,
                output_pattern="diagnostic/TaskService_snapshot_{entity_label}_{task_label}_{timestamp}.json",
                substitutions=substitutions,
                collector_id=collector_id,
            )

            if file_path:
                await self._service._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"TaskService snapshot captured: {file_path}",
                    dut_id,
                )

            return file_path
        except Exception as e:
            safe_snapshot_error = self._service._sanitize_diagnostic_text(e)
            await self._service._log_runtime(
                "WARN",
                "RedfishService",
                f"Failed to capture TaskService snapshot: {safe_snapshot_error}",
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
        Serialize a complete dump lifecycle when DUTs share an HMC target.

        The implementation uses ``dut_id``, ``entity_type``, ``entity_id``,
        ``log_service``, and ``payload`` to serialize a complete dump lifecycle
        when DUTs share an HMC target. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            entity_type: Text supplied as entity type in the format accepted by
                this function.
            entity_id: Stable entity identifier used to correlate configuration,
                logs, and results.
            log_service: Text supplied as log service in the format accepted by
                this function.
            payload: Mapping supplying fields for serialize a complete dump
                lifecycle when DUTs share an HMC target.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """

        collector_id = kwargs.get("collector_id")
        if not isinstance(collector_id, str) or not collector_id.strip():
            reason = "collector_id is required for diagnostic dump artifact ownership"
            await self._service._log_runtime("ERROR", "RedfishService", reason, dut_id)
            return False, reason
        kwargs["collector_id"] = collector_id.strip()
        diagnostic_domain_scope = kwargs.pop("_diagnostic_domain_scope", None)
        attempt_disposition = kwargs.get("_diagnostic_attempt_disposition")
        uri_builder = getattr(self._service, "_diagnostic_task_uri", None)
        dump_uri = kwargs.get("dump_uri_override") or (
            uri_builder(
                entity_type,
                entity_id,
                log_service,
                use_actions_segment=kwargs.get("use_actions_segment", True),
            )
            if callable(uri_builder)
            else None
        )
        capacity_pool = (
            await self._diagnostic_capacity_pool(dut_id, dump_uri) if dump_uri else None
        )
        kwargs["_diagnostic_capacity_pool"] = capacity_pool
        parallel_attempt = kwargs.get("_diagnostic_parallel_attempt")
        parallel_attempt_state = None
        if parallel_attempt is not None:
            # Validate opaque concurrency authority before planning can grant an
            # extra POST allowance or any execution path can bypass the parent
            # diagnostic-domain lock.
            parallel_attempt_state = self._validate_parallel_attempt(
                parallel_attempt,
                dut_id=dut_id,
            )
            self._claim_parallel_attempt_execution(parallel_attempt_state)

        diagnostic_post_request_budget: Dict[str, float] = {}
        kwargs["_diagnostic_post_request_budget"] = diagnostic_post_request_budget

        persistent_post_reservation: PersistentPostReservation | None = None
        runtime = self._service._persistent_post_runtime
        if runtime is not None:
            dump_uri_override = kwargs.get("dump_uri_override")
            dump_uri = dump_uri_override or self._service._diagnostic_task_uri(
                entity_type,
                entity_id,
                log_service,
                use_actions_segment=kwargs.get("use_actions_segment", True),
            )
            normalized_uri = self._service.dut_manager.get_dut(
                dut_id
            ).normalize_redfish_uri(dump_uri)
            dut_slot = self._service._persistent_post_dut_slot(dut_id)
            detached_payload = copy.deepcopy(payload)
            if runtime.is_planning:
                runtime.record_post(
                    collector_id=collector_id.strip(),
                    dut_slot=dut_slot,
                    normalized_uri=normalized_uri,
                    body=detached_payload,
                )
                if parallel_attempt_state is not None:
                    # Adaptive execution can send this exact target once as a
                    # concurrency probe and once as its bounded serial retry.
                    # The persistent plan is an upper-bound allowlist, so retain
                    # both possible occurrences without authorizing a third.
                    runtime.record_post(
                        collector_id=collector_id.strip(),
                        dut_slot=dut_slot,
                        normalized_uri=normalized_uri,
                        body=detached_payload,
                    )
                # Target discovery is GET-only.  Returning a successful planned
                # operation lets the caller continue discovering later targets
                # without entering task polling or artifact download paths.
                return True, None
            async with self._service._persistent_post_lock:
                persistent_post_reservation = runtime.reserve_post(
                    collector_id=collector_id.strip(),
                    dut_slot=dut_slot,
                    normalized_uri=normalized_uri,
                    body=detached_payload,
                    retry_count=0,
                )
            payload = detached_payload

        async def _post_dump_task(
            request_uri: str, request_payload: Dict[str, Any]
        ) -> Tuple[bool, Any, Any]:
            # Starting a diagnostic task is not idempotent. Retrying this POST
            # in the transport layer can create a second firmware task after a
            # lost or delayed response; task-level polling owns recovery.
            """
            Return the post dump task.

            After applying local validation, the function forwards
            ``request_uri`` and ``request_payload`` to
            ``self._service.dispatch_request`` and preserves its return and
            exception contract. Owned asynchronous work is awaited before
            return, so completion does not leave an unobserved task behind.

            Args:
                request_uri: Validated remote resource identifier used for
                    request URI.
                request_payload: Mapping supplying fields for post dump task.

            Returns:
                A tuple containing the fields that represent post dump task.
            """
            request_options = {}
            blocked_reason = self._diagnostic_block_reason(
                dut_id, capacity_pool, attempt_disposition
            )
            if blocked_reason is not None:
                return False, blocked_reason, {}
            if persistent_post_reservation is not None:
                request_options["persistent_post_reservation"] = (
                    persistent_post_reservation
                )
            request_timeout = diagnostic_post_request_budget.get("timeout_seconds")
            if request_timeout is not None:
                request_options["timeout"] = max(0.001, float(request_timeout))
            if isinstance(attempt_disposition, DiagnosticAttemptDisposition):
                attempt_disposition.post_sent = True
            if (
                parallel_attempt_state is not None
                and not self._start_parallel_attempt_post(parallel_attempt_state)
            ):
                blocked_reason = (
                    "Diagnostic task POST blocked because the adaptive session "
                    "is closing; no POST was sent"
                )
                if isinstance(attempt_disposition, DiagnosticAttemptDisposition):
                    attempt_disposition.post_sent = False
                    attempt_disposition.resubmit_allowed = False
                    attempt_disposition.blocked_before_post = True
                    attempt_disposition.reason = blocked_reason
                return False, blocked_reason, {}
            return await self._service.dispatch_request(
                dut_id,
                "POST",
                request_uri,
                request_payload,
                bypass_cache=True,
                retry_count=0,
                **request_options,
            )

        if parallel_attempt_state is not None:
            domain_key = parallel_attempt_state.domain_key
            kwargs["_diagnostic_domain_key"] = domain_key
            try:
                quiescent, quiescence_reason = (
                    await self._prove_diagnostic_domain_quiescent(domain_key)
                )
                if not quiescent:
                    blocked_reason = (
                        "Diagnostic task POST blocked inside adaptive session: "
                        f"{quiescence_reason}; no POST was sent"
                    )
                    self._apply_remote_gate_to_disposition(
                        attempt_disposition,
                        self._diagnostic_domain_taints.get(domain_key),
                        blocked_before_post=True,
                    )
                    if isinstance(
                        attempt_disposition,
                        DiagnosticAttemptDisposition,
                    ):
                        attempt_disposition.resubmit_allowed = False
                        attempt_disposition.blocked_before_post = True
                        attempt_disposition.reason = blocked_reason
                    await self._service._log_runtime(
                        "WARN",
                        "RedfishService",
                        blocked_reason,
                        dut_id,
                    )
                    return False, blocked_reason
                blocked_reason = self._diagnostic_block_reason(
                    dut_id, capacity_pool, attempt_disposition
                )
                if blocked_reason is not None:
                    return False, blocked_reason
                return await self._service._execute_redfish_dump_task_unlocked(
                    dut_id,
                    entity_type,
                    entity_id,
                    log_service,
                    payload,
                    function_tag,
                    _post_dump_task=_post_dump_task,
                    **kwargs,
                )
            finally:
                self.finalize_parallel_attempt_creation(parallel_attempt_state.attempt)

        domain_key, lock, shared_lock_key = self._diagnostic_domain(
            dut_id,
            diagnostic_domain_scope,
        )
        global_domain_key: Optional[Tuple[str, str]] = None
        global_domain_lock: Optional[Lock] = None
        if domain_key[0] == "dut_scope":
            global_domain_key, global_domain_lock, _ = self._diagnostic_domain(dut_id)
        kwargs["_diagnostic_domain_key"] = domain_key
        wait_started = self._monotonic()
        if lock.locked() and shared_lock_key is not None:
            await self._service._log_runtime(
                "INFO",
                "RedfishService",
                f"Waiting for shared HMC diagnostic slot {shared_lock_key}",
                dut_id,
            )
        await self._acquire_diagnostic_domain_lock(domain_key, lock)
        scoped_admitted = False
        try:
            waited_seconds = self._monotonic() - wait_started
            if waited_seconds >= 0.001 and shared_lock_key is not None:
                await self._service._log_runtime(
                    "INFO",
                    "RedfishService",
                    f"Acquired shared HMC diagnostic slot {shared_lock_key} after "
                    f"{waited_seconds:.3f}s",
                    dut_id,
                )
            if global_domain_key is not None and global_domain_lock is not None:
                scoped_admitted, global_reason = (
                    await self._activate_scoped_diagnostic_domain(
                        global_domain_key,
                        global_domain_lock,
                    )
                )
                if not scoped_admitted:
                    blocked_reason = (
                        "Diagnostic task POST blocked by earlier collector: "
                        f"{global_reason}; no POST was sent"
                    )
                    self._apply_remote_gate_to_disposition(
                        attempt_disposition,
                        self._diagnostic_domain_taints.get(global_domain_key),
                        blocked_before_post=True,
                    )
                    if isinstance(
                        attempt_disposition,
                        DiagnosticAttemptDisposition,
                    ):
                        attempt_disposition.reason = blocked_reason
                    await self._service._log_runtime(
                        "WARN",
                        "RedfishService",
                        blocked_reason,
                        dut_id,
                    )
                    return False, blocked_reason

            quiescent, quiescence_reason = (
                await self._prove_diagnostic_domain_quiescent(domain_key)
            )
            if not quiescent:
                blocked_reason = (
                    "Diagnostic task POST blocked: "
                    f"{quiescence_reason}; no POST was sent"
                )
                self._apply_remote_gate_to_disposition(
                    attempt_disposition,
                    self._diagnostic_domain_taints.get(domain_key),
                    blocked_before_post=True,
                )
                if isinstance(attempt_disposition, DiagnosticAttemptDisposition):
                    attempt_disposition.reason = blocked_reason
                await self._service._log_runtime(
                    "WARN",
                    "RedfishService",
                    blocked_reason,
                    dut_id,
                )
                return False, blocked_reason
            blocked_reason = self._diagnostic_block_reason(
                dut_id, capacity_pool, attempt_disposition
            )
            if blocked_reason is not None:
                return False, blocked_reason
            return await self._service._execute_redfish_dump_task_unlocked(
                dut_id,
                entity_type,
                entity_id,
                log_service,
                payload,
                function_tag,
                _post_dump_task=_post_dump_task,
                **kwargs,
            )
        finally:
            if scoped_admitted and global_domain_key is not None:
                self._release_scoped_diagnostic_domain(
                    domain_key,
                    global_domain_key,
                    dut_id=dut_id,
                )
            lock.release()

    async def _execute_redfish_dump_task_unlocked(
        self,
        dut_id: str,
        entity_type: str,
        entity_id: str,
        log_service: str,
        payload: Dict[str, Any],
        function_tag: str,
        _post_dump_task: Callable[
            [str, Dict[str, Any]], Awaitable[Tuple[bool, Any, Any]]
        ],
        **kwargs,
    ) -> Tuple[bool, Optional[str]]:
        """
        Execute a Redfish dump task and collect the result.

        The implementation uses ``dut_id``, ``entity_type``, ``entity_id``,
        ``log_service``, and ``payload`` to execute a Redfish dump task and
        collect the result. Terminal status is emitted only after redfish dump
        task and collect the result and its owned cleanup have completed. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. Remote I/O uses
        the configured transport policy and returns only after its response or
        failure has been observed. If the function cannot execute a Redfish dump
        task and collect the result, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            entity_type: Text supplied as entity type in the format accepted by
                this function.
            entity_id: Stable entity identifier used to correlate configuration,
                logs, and results.
            log_service: Text supplied as log service in the format accepted by
                this function.
            payload: Mapping supplying fields for redfish dump task and collect
                the result.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            _post_dump_task: Mapping supplying fields for redfish dump task and
                collect the result.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A tuple containing the fields that represent execute Redfish dump
            task unlocked, or ``None`` when the requested value is unavailable.

        Raises:
            ValueError: If the lifecycle_timeout_cap_seconds are not a positive
                number.
        """
        file_acquisition_operation_id = None
        if self._service.timing_manager:
            file_acquisition_operation_id = (
                self._service.timing_manager.start_operation(
                    "redfish_file_acquisition",
                    function_tag,
                    metadata={
                        "entity_type": entity_type,
                        "log_service": log_service,
                    },
                )
            )

        def _finish_dump_timing(
            success: bool, value: Optional[str]
        ) -> Tuple[bool, Optional[str]]:
            """
            Finish dump timing.

            The implementation uses ``success`` and ``value`` to finish dump
            timing.

            Args:
                success: Whether success is enabled or required for this
                    operation.
                value: Text supplied as value in the format accepted by this
                    function.

            Returns:
                A tuple containing ``success`` and ``status or message text`` in
                that order.
            """
            if self._service.timing_manager:
                self._service.timing_manager.end_operation(
                    file_acquisition_operation_id,
                    status="success" if success else "error",
                    artifact_path=value if success else None,
                    error=(
                        None if success else str(value or "dump acquisition failed")
                    ),
                )
            return success, value

        dump_uri = ""
        task_id: Optional[str] = None
        try:
            # Extract parameters from kwargs
            output_pattern = kwargs.get("output_pattern", "")
            diagnostic_type = kwargs.get("diagnostic_type")
            collector_id = kwargs["collector_id"]
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

            collector_def = kwargs.get("collector_def", {})
            runtime_budget = self._service._current_runtime_budget(str(collector_id))
            uses_runtime_remote_task_budget = (
                runtime_budget is not None
                and runtime_budget.source == "catalog.runtime_budget"
                and runtime_budget.remote_task_timeout_seconds is not None
            )
            if uses_runtime_remote_task_budget:
                timeout_seconds = runtime_budget.remote_task_timeout_seconds
            else:
                timeout_seconds = await self._service._resolve_collector_timeout(
                    dut_id,
                    kwargs,
                    default_timeout=1500,
                    collector_id=collector_id,
                    collector_def=collector_def,
                )
            lifecycle_timeout_cap = kwargs.get("lifecycle_timeout_cap_seconds")
            if lifecycle_timeout_cap is not None:
                try:
                    lifecycle_timeout_cap = float(lifecycle_timeout_cap)
                except (TypeError, ValueError) as error:
                    raise ValueError(
                        "lifecycle_timeout_cap_seconds must be a positive number"
                    ) from error
                if (
                    not math.isfinite(lifecycle_timeout_cap)
                    or lifecycle_timeout_cap <= 0
                ):
                    raise ValueError(
                        "lifecycle_timeout_cap_seconds must be a positive number"
                    )
                timeout_seconds = min(timeout_seconds, lifecycle_timeout_cap)
            collector_deadline = self._monotonic() + max(0.0, float(timeout_seconds))

            # Keep the configured task-poll cadence within the collector's
            # absolute timeout budget.  Custom services supply this from the
            # catalog's ``retry_interval`` setting.
            try:
                retry_interval = float(kwargs.get("task_poll_interval", 30))
            except (TypeError, ValueError):
                retry_interval = 30.0
            if not math.isfinite(retry_interval) or retry_interval <= 0:
                retry_interval = 30.0
            timeout_interval = max(retry_interval, 1.0)
            max_retries = max(1, math.ceil(timeout_seconds / timeout_interval))

            await self._service._log_runtime(
                "INFO",
                "RedfishService",
                f"Using timeout of {timeout_seconds} seconds ({max_retries} retries at {retry_interval}s intervals) for {entity_type} {entity_id}",
                dut_id,
            )

            # Initiate the dump task
            # Some implementations require the Actions segment; others (e.g., R43) do not.
            dump_uri_override = kwargs.get("dump_uri_override")
            use_actions_segment = kwargs.get("use_actions_segment", True)
            if dump_uri_override:
                dump_uri = dump_uri_override
            else:
                dump_uri = self._service._diagnostic_task_uri(
                    entity_type,
                    entity_id,
                    log_service,
                    use_actions_segment=use_actions_segment,
                )

            # Get DUT for full URI logging
            dut = self._service.dut_manager.get_dut(dut_id)
            full_dump_uri = dut.normalize_redfish_uri(dump_uri)
            safe_full_dump_uri = self._service._sanitize_diagnostic_uri(full_dump_uri)
            reproduction_scheme = None
            try:
                use_https = dut.get_redfish_connection_info().get("use_https")
                if use_https is True:
                    reproduction_scheme = "https"
                elif use_https is False:
                    reproduction_scheme = "http"
            except Exception:
                # Reproduction evidence is best-effort and must never affect
                # the diagnostic collection path.
                pass

            await self._service._log_runtime(
                "INFO",
                "RedfishService",
                f"Initiating diagnostic data collection: POST {safe_full_dump_uri}",
                dut_id,
            )

            # Save the initial request payload
            # Save the diagnostic request to array-based file
            request_data = {
                "request_uri": self._service._bounded_diagnostic_uri(dump_uri),
                "full_uri": safe_full_dump_uri,
                "payload_summary": self._service._bounded_request_payload_summary(
                    payload
                ),
                "entity_type": entity_type,
                "entity_id": entity_id,
                "log_service": log_service,
                "step": "request",
                "timestamp": datetime.now().isoformat(),
            }
            request_file_path = await self._service._append_to_diagnostic_json_array(
                dut_id,
                request_data,
                function_tag,
                "diagnostic_requests",
                collector_id,
            )

            await self._service._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Saved diagnostic request to: {request_file_path}",
                dut_id,
            )

            # Only collectors that explicitly opt into the hard lifecycle cap
            # clamp the non-idempotent POST transport timeout. Existing dump
            # collectors retain the established dispatch timeout contract.
            if lifecycle_timeout_cap is not None:
                post_remaining = collector_deadline - self._monotonic()
                if post_remaining <= 0:
                    return _finish_dump_timing(
                        False, "Diagnostic lifecycle deadline expired before POST"
                    )
                post_request_budget = kwargs.get("_diagnostic_post_request_budget")
                if isinstance(post_request_budget, dict):
                    post_request_budget["timeout_seconds"] = post_remaining

            success, response, response_metadata = await _post_dump_task(
                dump_uri, payload
            )
            attempt_disposition = kwargs.get("_diagnostic_attempt_disposition")
            if (
                isinstance(attempt_disposition, DiagnosticAttemptDisposition)
                and attempt_disposition.blocked_before_post
            ):
                return _finish_dump_timing(False, response)

            diagnostic_domain_key = kwargs.get("_diagnostic_domain_key")
            initial_http_status = self._service._http_status_from_response(
                response, response_metadata
            )
            remote_rejection_message_id = (
                None
                if success
                else self._remote_no_resubmit_message_id(response, response_metadata)
            )
            capacity_pool = (
                kwargs.get("_diagnostic_capacity_pool")
                if not success
                and self._is_pure_capacity_rejection(
                    response, response_metadata, initial_http_status
                )
                else None
            )
            if (
                remote_rejection_message_id is not None
                and isinstance(diagnostic_domain_key, tuple)
                and len(diagnostic_domain_key) == 2
            ):
                # Record the gate before any awaited evidence persistence. A
                # cancellation after the non-idempotent POST must not reopen a
                # domain that firmware explicitly told us not to resubmit to.
                rejection = self._record_remote_no_resubmit_rejection(
                    diagnostic_domain_key,
                    dut_id=dut_id,
                    collector_id=collector_id,
                    action_uri=(
                        self._service._bounded_diagnostic_uri(dump_uri)
                        or "<omitted-uri>"
                    ),
                    message_id=remote_rejection_message_id,
                    http_status=initial_http_status,
                    capacity_pool=capacity_pool,
                )
                self._apply_remote_gate_to_disposition(
                    kwargs.get("_diagnostic_attempt_disposition"),
                    rejection,
                    blocked_before_post=False,
                )
            if (
                success
                and isinstance(diagnostic_domain_key, tuple)
                and len(diagnostic_domain_key) == 2
            ):
                # The first synchronous action after an accepted POST is a
                # provisional taint.  Any cancellation or exception while
                # parsing/persisting its response therefore cannot release the
                # remote diagnostic slot as if no task had been created.
                self._record_unproven_diagnostic_task(
                    diagnostic_domain_key,
                    dut_id=dut_id,
                    task_id="",
                    monitor_uris=[],
                    reason="accepted task response has not been fully processed",
                )

            response_summary = self._service._bounded_task_response_summary(
                response,
                response_metadata,
            )
            artifact_response_summary = (
                self._service._bounded_task_artifact_response_summary(
                    response,
                    response_metadata,
                )
            )
            response_headers = self._service._diagnostic_response_headers(
                response_metadata
            )
            task_id, task_monitor_uris, task_reference_error = (
                self._service._resolve_async_task_reference(
                    dut_id,
                    response,
                    response_metadata,
                    initial_http_status,
                )
            )
            if success and task_reference_error:
                attempt_disposition = kwargs.get("_diagnostic_attempt_disposition")
                if isinstance(attempt_disposition, DiagnosticAttemptDisposition):
                    attempt_disposition.resubmit_allowed = False
                    attempt_disposition.http_status = initial_http_status
                    attempt_disposition.reason = task_reference_error
            if (
                success
                and isinstance(diagnostic_domain_key, tuple)
                and len(diagnostic_domain_key) == 2
            ):
                self._record_unproven_diagnostic_task(
                    diagnostic_domain_key,
                    dut_id=dut_id,
                    task_id=task_id,
                    monitor_uris=task_monitor_uris,
                    reason=(
                        task_reference_error
                        or "accepted task has not reached a proven terminal state"
                    ),
                )
            elif (
                remote_rejection_message_id is not None
                and isinstance(diagnostic_domain_key, tuple)
                and len(diagnostic_domain_key) == 2
            ):
                # Upgrade the provisional rejection gate with only exact,
                # validated monitor candidates supplied in the response.
                remote_monitor_uris = self._service._select_task_monitor_uris(
                    dut_id,
                    "",
                    response,
                    response_metadata,
                )
                rejection = self._record_remote_no_resubmit_rejection(
                    diagnostic_domain_key,
                    dut_id=dut_id,
                    collector_id=collector_id,
                    action_uri=(
                        self._service._bounded_diagnostic_uri(dump_uri)
                        or "<omitted-uri>"
                    ),
                    message_id=remote_rejection_message_id,
                    http_status=initial_http_status,
                    task_id=task_id,
                    monitor_uris=remote_monitor_uris,
                    capacity_pool=capacity_pool,
                )
                self._apply_remote_gate_to_disposition(
                    kwargs.get("_diagnostic_attempt_disposition"),
                    rejection,
                    blocked_before_post=False,
                )

            parallel_attempt = kwargs.get("_diagnostic_parallel_attempt")
            if isinstance(parallel_attempt, DiagnosticParallelAttempt):
                self.resolve_parallel_attempt_creation(
                    parallel_attempt,
                    accepted=bool(success and task_id and not task_reference_error),
                    rejection_message_id=remote_rejection_message_id,
                )

            # Apply TASK_ID_PREFIX before constructing the compatibility task
            # URI. Explicit Location/TaskMonitor values remain authoritative.
            if success and task_id:
                tool_config = (
                    await self._service.orchestrator.get_dut_specific_tool_config(
                        dut_id
                    )
                )
                task_prefix = tool_config.get("TASK_ID_PREFIX", "")
                if task_prefix:
                    task_id = f"{task_prefix}_{task_id}"
                    task_monitor_uris = self._service._select_task_monitor_uris(
                        dut_id,
                        task_id,
                        response,
                        response_metadata,
                    )
                    if (
                        isinstance(diagnostic_domain_key, tuple)
                        and len(diagnostic_domain_key) == 2
                    ):
                        self._record_unproven_diagnostic_task(
                            diagnostic_domain_key,
                            dut_id=dut_id,
                            task_id=task_id,
                            monitor_uris=task_monitor_uris,
                            reason=(
                                "accepted task has not reached a proven terminal state"
                            ),
                        )
                    await self._service._log_runtime(
                        "DEBUG",
                        "RedfishService",
                        f"Applied task ID prefix '{task_prefix}' to task ID: {task_id}",
                        dut_id,
                    )

            structured_response = {
                "request_uri": self._service._bounded_diagnostic_uri(dump_uri),
                "request_payload_summary": self._service._bounded_request_payload_summary(
                    payload
                ),
                "response_status": "success" if success else "failure",
                "http_status": initial_http_status,
                "response_headers": response_headers,
                "location": response_headers.get("Location"),
                "retry_after": response_headers.get("Retry-After"),
                "response_summary": artifact_response_summary,
                "selected_monitor_uri": (
                    task_monitor_uris[0] if task_monitor_uris else None
                ),
                "monitor_uri_candidates": task_monitor_uris,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "log_service": log_service,
                "step": "initial_response",
                "timestamp": datetime.now().isoformat(),
            }

            # Save the structured response to array-based file
            response_file_path = await self._service._append_to_diagnostic_json_array(
                dut_id,
                structured_response,
                function_tag,
                "diagnostic_responses",
                collector_id,
            )

            await self._service._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Saved initial response to: {response_file_path}",
                dut_id,
            )

            if not success:
                error_details = await self._service._extract_error_details_async(
                    response,
                    dut_id,
                    f"Failed to initiate dump task for {entity_type} {entity_id} "
                    f"(URI: {safe_full_dump_uri}): ",
                )
                snapshot_path = await self._service._capture_task_service_snapshot(
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
                        "request_uri": self._service._bounded_diagnostic_uri(dump_uri),
                        "full_uri": safe_full_dump_uri,
                        "request_payload_summary": (
                            self._service._bounded_request_payload_summary(payload)
                        ),
                        "response_summary": response_summary,
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "log_service": log_service,
                    },
                }
                if snapshot_path:
                    error_response["context"]["task_service_snapshot"] = snapshot_path
                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return _finish_dump_timing(False, error_details)

            if not task_id:
                task_error_message = (
                    task_reference_error or "Response did not contain a task ID"
                )
                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{task_error_message} for {entity_type} {entity_id}",
                    dut_id,
                )

                snapshot_path = await self._service._capture_task_service_snapshot(
                    dut_id,
                    function_tag,
                    collector_id,
                    entity_type,
                    entity_id,
                    log_service,
                    reason=(
                        "invalid_task_reference"
                        if task_reference_error != "Response did not contain a task ID"
                        else "missing_task_id"
                    ),
                    payload=payload,
                    diagnostic_type=diagnostic_type,
                    extra_context=extra_context,
                )

                error_entry = {
                    "request_uri": self._service._bounded_diagnostic_uri(dump_uri),
                    "request_payload_summary": self._service._bounded_request_payload_summary(
                        payload
                    ),
                    "response_status": "failure",
                    "error_type": (
                        "invalid_task_reference"
                        if task_reference_error != "Response did not contain a task ID"
                        else "no_task_id"
                    ),
                    "error_message": task_error_message,
                    "response_summary": artifact_response_summary,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "log_service": log_service,
                    "timestamp": datetime.now().isoformat(),
                }
                if snapshot_path:
                    error_entry["task_service_snapshot"] = snapshot_path

                # Save the structured error response to array-based file
                await self._service._append_to_diagnostic_json_array(
                    dut_id,
                    error_entry,
                    function_tag,
                    "diagnostic_errors",
                    collector_id,
                )

                # Include request details in the error response for better debugging
                error_response = {
                    "success": False,
                    "reason": task_error_message,
                    "context": {
                        "request_uri": self._service._bounded_diagnostic_uri(dump_uri),
                        "request_payload_summary": (
                            self._service._bounded_request_payload_summary(payload)
                        ),
                        "response_summary": response_summary,
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "log_service": log_service,
                    },
                }
                if snapshot_path:
                    error_response["context"]["task_service_snapshot"] = snapshot_path
                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return _finish_dump_timing(False, task_error_message)

            # Wait for task completion (like legacy get_task_completed)
            entity_context = {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "log_service": log_service,
                "monitor_uri_candidates": task_monitor_uris,
            }
            task_completed = await self._service._wait_for_task_completion(
                dut_id,
                task_id,
                max_retries=max_retries,
                poll_interval=retry_interval,
                function_tag=function_tag,
                entity_context=entity_context,
                collector_id=collector_id,
                task_monitor_uris=task_monitor_uris,
                require_result_location=True,
                initial_retry_after=self._service._parse_retry_after_seconds(
                    response_headers.get("Retry-After")
                ),
                deadline=collector_deadline,
            )
            if not task_completed:
                task_failure = self._service._bounded_task_failure_summary(
                    entity_context.get("task_failure", {})
                )

                failure_state = str(task_failure.get("state") or "").strip()
                failure_status = str(task_failure.get("status") or "").strip()
                failure_parts = [
                    part for part in (failure_state, failure_status) if part
                ]
                raw_messages = task_failure.get("messages", [])
                if raw_messages is None:
                    task_messages = []
                elif isinstance(raw_messages, list):
                    task_messages = raw_messages
                else:
                    task_messages = [raw_messages]
                for message in task_messages:
                    if isinstance(message, dict):
                        text = message.get("Message") or message.get("MessageId")
                    else:
                        text = str(message)
                    if text:
                        failure_parts.append(str(text))

                # A missing failure record is retained as the legacy timeout
                # fallback for mocked/older monitors.  Every current monitor
                # exit records its actual state in entity_context.
                is_timeout = not task_failure or failure_state.lower() == "timeout"
                if is_timeout:
                    error_type = "task_timeout"
                    error_status = "timeout"
                    failure_reason = f"Task {task_id} did not complete within timeout"
                else:
                    error_type = {
                        "inaccessible": "task_inaccessible",
                        "pollfailed": "task_poll_failed",
                        "httpfailure": "task_http_failure",
                        "taskresourcemissing": "task_resource_missing",
                        "monitoringexception": "task_monitoring_exception",
                    }.get(failure_state.lower(), "task_failed")
                    error_status = "error"
                    failure_detail = "; ".join(failure_parts)
                    failure_reason = f"Task {task_id} monitoring failed"
                    if failure_detail:
                        failure_reason = f"{failure_reason}: {failure_detail}"

                terminal_failure = evaluate_task_poll(
                    {"TaskState": failure_state},
                    attempt_index=0,
                    previous_state=None,
                    previous_percent=None,
                )
                if terminal_failure.disposition in {
                    TaskPollDisposition.SUCCEEDED,
                    TaskPollDisposition.FAILED,
                }:
                    self._clear_proven_terminal_diagnostic_task(
                        diagnostic_domain_key,
                        task_id,
                    )
                elif (
                    isinstance(diagnostic_domain_key, tuple)
                    and len(diagnostic_domain_key) == 2
                ):
                    self._record_unproven_diagnostic_task(
                        diagnostic_domain_key,
                        dut_id=dut_id,
                        task_id=task_id,
                        monitor_uris=task_monitor_uris,
                        reason=failure_reason,
                    )

                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{failure_reason} for {entity_type} {entity_id}",
                    dut_id,
                )

                snapshot_context = dict(extra_context or {})
                if task_failure:
                    snapshot_context["task_failure"] = task_failure

                snapshot_path = await self._service._capture_task_service_snapshot(
                    dut_id,
                    function_tag,
                    collector_id,
                    entity_type,
                    entity_id,
                    log_service,
                    reason=error_type,
                    task_id=task_id,
                    payload=payload,
                    diagnostic_type=diagnostic_type,
                    extra_context=snapshot_context or None,
                )

                # Persist the monitor's actual failure, rather than labeling
                # every unsuccessful task poll as a timeout.
                error_data = {
                    "task_id": task_id,
                    "status": error_status,
                    "max_retries": max_retries,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "log_service": log_service,
                    "error_type": error_type,
                    "error_message": failure_reason,
                    "timestamp": datetime.now().isoformat(),
                }
                if is_timeout:
                    error_data["timeout_classification"] = (
                        "remote_task_budget"
                        if uses_runtime_remote_task_budget
                        else "remote_task_timeout"
                    )
                if task_failure:
                    error_data["task_failure"] = task_failure
                if snapshot_path:
                    error_data["task_service_snapshot"] = snapshot_path
                await self._service._append_to_diagnostic_json_array(
                    dut_id,
                    error_data,
                    function_tag,
                    "diagnostic_errors",
                    collector_id,
                )

                # Include request details in the error response for better debugging
                error_response = {
                    "success": False,
                    "reason": failure_reason,
                    "context": {
                        "request_uri": self._service._bounded_diagnostic_uri(dump_uri),
                        "request_payload_summary": (
                            self._service._bounded_request_payload_summary(payload)
                        ),
                        "task_id": task_id,
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "log_service": log_service,
                        "max_retries": max_retries,
                    },
                }
                if is_timeout:
                    error_response["context"]["timeout_classification"] = (
                        "remote_task_budget"
                        if uses_runtime_remote_task_budget
                        else "remote_task_timeout"
                    )
                if task_failure:
                    error_response["context"]["task_failure"] = task_failure
                if snapshot_path:
                    error_response["context"]["task_service_snapshot"] = snapshot_path
                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return _finish_dump_timing(False, failure_reason)

            self._clear_proven_terminal_diagnostic_task(
                diagnostic_domain_key,
                task_id,
            )

            # Task completion is already saved in _wait_for_task_completion method
            # No need to save it again here

            await self._service._log_runtime(
                "DEBUG",
                "RedfishService",
                "Task completion saved to array-based file",
                dut_id,
            )

            # Get dump location (like legacy get_dump_location)
            dump_resolution: Dict[str, Any] = {}
            dump_location = await self._service._get_dump_location(
                task_completed,
                dut_id,
                resolution_evidence=dump_resolution,
                collector_deadline=collector_deadline,
            )
            if not dump_location:
                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"Failed to get dump location for task {task_id}",
                    dut_id,
                )

                snapshot_path = await self._service._capture_task_service_snapshot(
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
                    "task_completion": (
                        self._service._bounded_task_artifact_response_summary(
                            task_completed
                        )
                    ),
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
                error_file_path = await self._service._append_to_diagnostic_json_array(
                    dut_id,
                    error_data,
                    function_tag,
                    "diagnostic_errors",
                    collector_id,
                )

                await self._service._log_runtime(
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
                        "request_uri": self._service._bounded_diagnostic_uri(dump_uri),
                        "request_payload_summary": (
                            self._service._bounded_request_payload_summary(payload)
                        ),
                        "task_id": task_id,
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "log_service": log_service,
                        "task_completion": self._service._bounded_task_response_summary(
                            task_completed
                        ),
                    },
                }
                if snapshot_path:
                    error_response["context"]["task_service_snapshot"] = snapshot_path
                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return _finish_dump_timing(
                    False,
                    "Task completed but no dump location found in response",
                )

            safe_dump_location = self._service._sanitize_diagnostic_uri(dump_location)
            if not dump_resolution.get("attachment_uri"):
                dump_resolution["attachment_uri"] = (
                    safe_dump_location
                    if self._service._uri_has_attachment_path(dump_location)
                    else None
                )
            dump_resolution["download_target_uri"] = safe_dump_location
            if not dump_resolution.get("resolved_entry_uri"):
                dump_resolution["resolved_entry_uri"] = (
                    self._service._sanitize_diagnostic_uri(
                        self._service._entry_uri_from_attachment_uri(dump_location)
                    )
                    if self._service._uri_has_attachment_path(dump_location)
                    else safe_dump_location
                )
            if not dump_resolution.get("resolution_source"):
                dump_resolution["resolution_source"] = "legacy_location_result"

            # Generate output filename with task_id substitution (like legacy)
            if "$task_id" in output_pattern:
                final_output_pattern = output_pattern.replace("$task_id", str(task_id))
            else:
                final_output_pattern = output_pattern

            # Download the dump
            await self._service._log_runtime(
                "INFO",
                "RedfishService",
                f"Attempting to download dump from: {safe_dump_location}",
                dut_id,
            )

            (
                success,
                dump_data,
                download_metadata,
                download_attempts,
            ) = await self._service._download_dump_when_ready(
                dut_id,
                dump_location,
                collector_deadline,
                readiness_timeout=kwargs.get("attachment_readiness_timeout", 60.0),
                poll_interval=kwargs.get("attachment_poll_interval", 5.0),
                max_attempts=kwargs.get("attachment_max_attempts"),
                binary_download_timeout=kwargs.get(
                    "attachment_download_timeout", timeout_seconds
                ),
                max_attachment_size_bytes=self._service._clamped_attachment_limit(
                    dut_id,
                    kwargs.get("max_attachment_size_bytes"),
                ),
            )

            data_to_save, data_type, save_output_pattern, data_size = (
                self._service._prepare_downloaded_dump_for_save(
                    dump_data, final_output_pattern
                )
            )
            save_output_pattern = self._service._add_utc_timestamp_to_archive_pattern(
                save_output_pattern
            )

            archive_validation: Optional[Dict[str, Any]] = None
            archive_validation_reference: Optional[Dict[str, Any]] = None
            if success and kwargs.get("require_valid_archive", False):
                if data_size <= 0:
                    archive_validation = {
                        "filename": save_output_pattern,
                        "original_size": data_size,
                        "saved_size": 0,
                        "status": "invalid",
                        "normalization": None,
                        "validation_error": (
                            "diagnostic attachment for archive output is empty"
                        ),
                    }
                elif data_type != "binary" or not isinstance(
                    data_to_save, (bytes, StreamedRedfishBody)
                ):
                    archive_validation = {
                        "filename": save_output_pattern,
                        "original_size": data_size,
                        "saved_size": 0,
                        "status": "invalid",
                        "normalization": None,
                        "validation_error": (
                            "diagnostic attachment for archive output returned "
                            f"{data_type} content"
                        ),
                    }
                elif not save_output_pattern.lower().endswith(
                    self._service._ARCHIVE_PATTERN_SUFFIXES
                ):
                    archive_validation = {
                        "filename": save_output_pattern,
                        "original_size": data_size,
                        "saved_size": 0,
                        "status": "invalid",
                        "normalization": None,
                        "validation_error": (
                            "diagnostic attachment has no supported archive format"
                        ),
                    }
                else:
                    archive_validator = (
                        self._service._validate_and_normalize_streamed_archive_payload
                        if isinstance(data_to_save, StreamedRedfishBody)
                        else self._service._validate_and_normalize_archive_payload
                    )
                    (
                        data_to_save,
                        archive_validation,
                    ) = await self._service._run_blocking_redfish_operation(
                        archive_validator,
                        data_to_save,
                        save_output_pattern,
                    )
                    data_size = int(archive_validation.get("saved_size", data_size))

                if archive_validation.get("status") == "invalid":
                    archive_validation = (
                        self._service._canonical_invalid_archive_validation(
                            archive_validation
                        )
                    )
                    evidence_path = await self._service._record_archive_validation(
                        dut_id,
                        archive_validation,
                        collector_id=collector_id,
                        function_tag=function_tag,
                    )
                    if evidence_path:
                        archive_validation_reference = (
                            self._service._archive_validation_reference(
                                archive_validation
                            )
                        )
                    if isinstance(data_to_save, StreamedRedfishBody):
                        data_to_save.cleanup()
                    success = False
                    validation_error = archive_validation.get(
                        "validation_error", "archive validation failed"
                    )
                    download_metadata = (
                        dict(download_metadata)
                        if isinstance(download_metadata, dict)
                        else {}
                    )
                    download_metadata.update(
                        {
                            "attachment_validation_terminal_reason": (
                                "invalid_archive"
                            ),
                            "archive_validation": archive_validation,
                        }
                    )
                    if download_attempts:
                        download_attempts[-1].update(
                            {
                                "success": False,
                                "will_retry": False,
                                "retry_delay_seconds": None,
                                "terminal_reason": "invalid_archive",
                                "archive_validation_error": validation_error,
                            }
                        )

            await self._service._log_runtime(
                "INFO",
                "RedfishService",
                f"Download attempt result: success={success}, data_type={data_type if success else 'error'}, data_size={data_size if success else 'N/A'}",
                dut_id,
            )

            final_http_status = self._service._http_status_from_response(
                dump_data, download_metadata
            )
            final_attempt = download_attempts[-1] if download_attempts else {}
            final_response_headers = final_attempt.get("response_headers") or (
                self._service._response_headers_from_metadata(download_metadata)
            )
            final_body_summary = final_attempt.get("response_body_summary") or (
                self._service._response_body_summary(dump_data)
            )
            declared_content_length = final_attempt.get("declared_content_length_bytes")
            if declared_content_length is None:
                declared_content_length = self._service._content_length_from_headers(
                    final_response_headers
                )
            entry_advertised_size = dump_resolution.get(
                "advertised_attachment_size_bytes"
            )
            task_state = (
                task_completed.get("TaskState")
                if isinstance(task_completed, dict)
                else None
            )
            task_status = (
                task_completed.get("TaskStatus")
                if isinstance(task_completed, dict)
                else None
            )
            task_percent_complete = (
                task_completed.get("PercentComplete")
                if isinstance(task_completed, dict)
                else None
            )

            # Save the dump download response metadata to array-based file
            dump_metadata = {
                "dump_location": safe_dump_location,
                "resolved_entry_uri": dump_resolution.get("resolved_entry_uri"),
                "attachment_uri": dump_resolution.get("attachment_uri"),
                "download_target_uri": dump_resolution.get("download_target_uri"),
                "attachment_resolution_source": dump_resolution.get(
                    "resolution_source"
                ),
                "advertised_attachment_size_bytes": entry_advertised_size,
                "entry_advertised_attachment_size_bytes": entry_advertised_size,
                "declared_content_length_bytes": declared_content_length,
                "attachment_size_bytes": data_size if success else None,
                "success": success,
                "data_type": data_type if success else "error",
                "data_size": data_size if success else 0,
                "task_id": task_id,
                "task_state": task_state,
                "task_status": task_status,
                "task_percent_complete": task_percent_complete,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "log_service": log_service,
                "step": "dump_download",
                "http_status": final_http_status,
                "response_headers": final_response_headers,
                "response_body_summary": final_body_summary,
                "download_attempt_count": len(download_attempts),
                "download_attempts": download_attempts,
                "timestamp": datetime.now().isoformat(),
            }
            if archive_validation_reference is not None:
                dump_metadata["archive_validation"] = archive_validation_reference
            if success:
                # Get device-specific substitutions from kwargs and merge with standard ones
                device_substitutions = kwargs.get("substitutions", {})
                standard_substitutions = {
                    self._service._get_entity_id_key(
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

                save_kwargs: Dict[str, Any] = {
                    "output_pattern": save_output_pattern,
                    "substitutions": merged_substitutions,
                    "collector_id": collector_id,
                }
                archive_publication_capability: Optional[object] = None
                if archive_validation is not None:
                    archive_publication_capability = (
                        self._service._issue_archive_publication_capability(
                            archive_validation,
                        )
                    )
                    save_kwargs["_archive_publication_capability"] = (
                        archive_publication_capability
                    )

                # Write the downloaded artifact using the detected content type.
                file_path = await self._service._save_data_to_file_with_pattern(
                    dut_id,
                    data_to_save,
                    function_tag,
                    **save_kwargs,
                )
                if file_path:
                    dump_metadata["saved_file"] = file_path
                    published_reference = (
                        self._service._take_archive_publication_result(
                            archive_publication_capability
                        )
                        if archive_publication_capability is not None
                        else None
                    )
                    if isinstance(published_reference, dict):
                        dump_metadata["archive_validation"] = published_reference
                else:
                    if isinstance(data_to_save, StreamedRedfishBody):
                        data_to_save.cleanup()
                    dump_metadata["success"] = False
                    dump_metadata["error"] = "artifact_publication_failed"
                dump_metadata_file_path = (
                    await self._service._append_to_diagnostic_json_array(
                        dut_id,
                        dump_metadata,
                        function_tag,
                        "diagnostic_responses",
                        collector_id,
                    )
                )
                await self._service._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Saved dump metadata to: {dump_metadata_file_path}",
                    dut_id,
                )
                if not file_path:
                    failure_reason = (
                        "Dump download succeeded but artifact persistence failed for "
                        f"task {task_id}"
                    )
                    await self._service._append_to_diagnostic_json_array(
                        dut_id,
                        {
                            "error_type": "dump_persistence_failed",
                            "error_message": failure_reason,
                            "task_id": task_id,
                            "dump_location": safe_dump_location,
                            "entity_type": entity_type,
                            "entity_id": entity_id,
                            "log_service": log_service,
                            "timestamp": datetime.now().isoformat(),
                        },
                        function_tag,
                        "diagnostic_errors",
                        collector_id,
                    )
                    await self._service._log_runtime(
                        "ERROR",
                        "RedfishService",
                        failure_reason,
                        dut_id,
                    )
                    return _finish_dump_timing(False, failure_reason)
                return _finish_dump_timing(True, file_path)
            else:
                terminal_reason = final_attempt.get("terminal_reason")
                if terminal_reason is None and isinstance(download_metadata, dict):
                    terminal_reason = download_metadata.get(
                        "attachment_readiness_terminal_reason"
                    )
                retry_details = {
                    "attempt_count": len(download_attempts),
                    "configured_max_attempts": kwargs.get("attachment_max_attempts"),
                    "readiness_timeout_seconds": kwargs.get(
                        "attachment_readiness_timeout", 60.0
                    ),
                    "poll_interval_seconds": kwargs.get(
                        "attachment_poll_interval", 5.0
                    ),
                    "terminal_reason": terminal_reason,
                    "attempts": download_attempts,
                }
                attachment_failure_evidence = {
                    "task_id": task_id,
                    "task_state": task_state,
                    "task_status": task_status,
                    "task_percent_complete": task_percent_complete,
                    "resolved_entry_uri": dump_resolution.get("resolved_entry_uri"),
                    "attachment_uri": dump_resolution.get("attachment_uri"),
                    "download_target_uri": dump_resolution.get("download_target_uri"),
                    "attachment_resolution_source": dump_resolution.get(
                        "resolution_source"
                    ),
                    "advertised_attachment_size_bytes": entry_advertised_size,
                    "entry_advertised_attachment_size_bytes": entry_advertised_size,
                    "declared_content_length_bytes": declared_content_length,
                    "http_status": final_http_status,
                    "response_headers": final_response_headers,
                    "response_body_summary": final_body_summary,
                    "retry_details": retry_details,
                    "curl_equivalent": self._service._attachment_reproduction_context(
                        dump_location,
                        kwargs.get("attachment_download_timeout", timeout_seconds),
                        base_uri=full_dump_uri,
                        scheme_hint=reproduction_scheme,
                    ),
                }
                dump_metadata["attachment_failure"] = attachment_failure_evidence
                dump_metadata_file_path = (
                    await self._service._append_to_diagnostic_json_array(
                        dut_id,
                        dump_metadata,
                        function_tag,
                        "diagnostic_responses",
                        collector_id,
                    )
                )
                await self._service._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"Saved dump metadata to: {dump_metadata_file_path}",
                    dut_id,
                )
                failure_evidence = []
                archive_validation_error = (
                    archive_validation.get("validation_error")
                    if isinstance(archive_validation, dict)
                    else None
                )
                if archive_validation_error:
                    failure_evidence.append(str(archive_validation_error))
                if final_http_status is not None:
                    failure_evidence.append(f"HTTP {final_http_status}")
                final_response_preview = final_body_summary.get("preview")
                if final_response_preview not in (None, "", {}):
                    failure_evidence.append(f"response={final_response_preview}")
                failure_suffix = (
                    f": {'; '.join(failure_evidence)}" if failure_evidence else ""
                )
                failure_reason = (
                    f"Failed to download dump from {safe_dump_location} after "
                    f"{len(download_attempts)} attempt(s){failure_suffix}"
                )

                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    failure_reason,
                    dut_id,
                )
                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    "Diagnostic attachment failure evidence: "
                    + json.dumps(
                        attachment_failure_evidence,
                        sort_keys=True,
                        default=str,
                    ),
                    dut_id,
                )

                snapshot_path = await self._service._capture_task_service_snapshot(
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
                    "dump_data": final_body_summary,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "log_service": log_service,
                    "error_type": "dump_download_failed",
                    "task_id": task_id,
                    "dump_location": safe_dump_location,
                    "http_status": final_http_status,
                    "download_attempts": download_attempts,
                    "attachment_failure": attachment_failure_evidence,
                    "timestamp": datetime.now().isoformat(),
                }
                if snapshot_path:
                    error_data["task_service_snapshot"] = snapshot_path
                error_file_path = await self._service._append_to_diagnostic_json_array(
                    dut_id,
                    error_data,
                    function_tag,
                    "diagnostic_errors",
                    collector_id,
                )

                # Include request details in the error response for better debugging
                error_response = {
                    "success": False,
                    "reason": failure_reason,
                    "context": {
                        "request_uri": self._service._bounded_diagnostic_uri(dump_uri),
                        "request_payload_summary": (
                            self._service._bounded_request_payload_summary(payload)
                        ),
                        "task_id": task_id,
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "log_service": log_service,
                        "dump_location": safe_dump_location,
                        "download_success": success,
                        "http_status": final_http_status,
                        "download_attempts": download_attempts,
                        "attachment_failure": attachment_failure_evidence,
                    },
                }
                if snapshot_path:
                    error_response["context"]["task_service_snapshot"] = snapshot_path
                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"{error_response}",
                    dut_id,
                )
                return _finish_dump_timing(False, failure_reason)

        except asyncio.CancelledError as e:
            if self._service.timing_manager:
                self._service.timing_manager.end_operation(
                    file_acquisition_operation_id,
                    status="cancelled",
                    error=str(e),
                )
            raise
        except Exception as e:
            safe_exception = self._service._sanitize_diagnostic_text(e)
            task_id_for_snapshot = task_id
            snapshot_path = await self._service._capture_task_service_snapshot(
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
                "reason": f"Exception in dump task execution: {safe_exception}",
                "context": {
                    "request_uri": self._service._sanitize_diagnostic_uri(dump_uri),
                    "request_payload_summary": (
                        self._service._bounded_request_payload_summary(payload)
                    ),
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "log_service": log_service,
                    "exception": safe_exception,
                },
            }
            if snapshot_path:
                error_response["context"]["task_service_snapshot"] = snapshot_path
            await self._service._log_runtime(
                "ERROR",
                "RedfishService",
                f"{error_response}",
                dut_id,
            )
            return _finish_dump_timing(
                False, f"Exception in dump task execution: {safe_exception}"
            )

    async def monitor_task(
        self, dut_id: str, function_tag: str = "", **kwargs
    ) -> Dict[str, Any]:
        """
        Generic task monitoring with configurable state checking.

        Monitor a Redfish task until it reaches a terminal state. Supports
        reading task_id from context (passed from previous hook) and
        configurable success/failure state definitions.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

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

        Returns:
            A mapping containing monitor task.
        """
        try:
            # Get task ID from context or direct parameter
            task_id = kwargs.get("task_id")
            if not task_id:
                context_key = kwargs.get("task_id_from_context")
                if context_key:
                    task_id = kwargs.get(context_key)
                    await self._service._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"[monitor_task] Read task_id '{task_id}' from context['{context_key}']",
                        dut_id,
                    )

            if not task_id:
                error_msg = "No task_id provided (neither direct nor from context)"
                await self._service._log_runtime(
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
            check_field = kwargs.get("check_field", "TaskState")
            if check_field not in {"TaskState", "TaskStatus", "PercentComplete"}:
                error_msg = "Unsupported task monitor check_field"
                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"[monitor_task] {error_msg}",
                    dut_id,
                )
                return {"success": False, "context": {}, "reason": error_msg}

            def bounded_configured_states(values: Any) -> List[Any]:
                """
                Return the bounded configured states.

                The implementation uses ``values`` to produce the bounded
                configured states.

                Args:
                    values: Values consumed while the function attempts to
                        produce the bounded configured states.

                Returns:
                    The bounded configured states returned in operation-defined
                    order.
                """
                if type(values) not in {list, tuple}:
                    return []
                bounded: List[Any] = []
                iterator = (
                    list.__iter__(values)
                    if type(values) is list
                    else tuple.__iter__(values)
                )
                for index, value in enumerate(iterator):
                    if index >= self._service._DIAGNOSTIC_LOG_MAX_ITEMS:
                        break
                    normalized = self._service._bounded_task_check_value(
                        check_field, value
                    )
                    if normalized is not None and normalized not in bounded:
                        bounded.append(normalized)
                return bounded

            success_states = bounded_configured_states(success_states)
            failure_states = bounded_configured_states(failure_states)
            configured_terminal_states = kwargs.get("terminal_states")
            terminal_states = (
                bounded_configured_states(configured_terminal_states)
                if configured_terminal_states is not None
                else [*success_states, *failure_states]
            )

            # Polling configuration
            max_retries = max(0, int(kwargs.get("max_retries", 50)))
            poll_interval = max(0.0, float(kwargs.get("poll_interval", 30)))
            # A zero interval is useful in unit tests and for callers that want
            # immediate polling.  It must not also create a zero-length
            # deadline, otherwise no request is attempted.  Keep a small,
            # bounded wall-clock budget while preserving the requested
            # no-sleep behavior between attempts.
            total_timeout = max(
                max_retries * poll_interval,
                1.0 if max_retries > 0 else 0.0,
            )
            deadline = self._monotonic() + total_timeout

            async def timeout_result() -> Dict[str, Any]:
                """
                Return the timeout result.

                The implementation uses current instance state to produce the
                timeout result. Owned asynchronous work is awaited before
                return, so completion does not leave an unobserved task behind.

                Returns:
                    A mapping containing the ``success``, ``context``, and
                    ``reason`` fields.
                """
                error_msg = (
                    f"Task monitoring timed out after {total_timeout}s "
                    f"(max_retries={max_retries}, poll_interval={poll_interval})"
                )
                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"[monitor_task] {error_msg}",
                    dut_id,
                )
                return {"success": False, "context": {}, "reason": error_msg}

            await self._service._log_runtime(
                "INFO",
                "RedfishService",
                f"[monitor_task] Monitoring task {task_id}, checking '{check_field}' for success_states={success_states}",
                dut_id,
            )

            # Build task URI through the single screened composition.
            task_uri = self._service._compose_task_resource_uri(dut_id, task_id)
            if not task_uri:
                error_msg = "monitor_task rejected an unsafe task identifier"
                await self._service._log_runtime(
                    "ERROR",
                    "RedfishService",
                    f"[monitor_task] {error_msg}",
                    dut_id,
                )
                return {"success": False, "context": {}, "reason": error_msg}

            # Initial wait for quick tasks
            initial_delay = min(2.0, max(float(poll_interval), 0.0))
            if not await self._service._sleep_with_task_monitor_deadline(
                initial_delay, deadline
            ):
                return await timeout_result()

            # Poll until terminal state
            for attempt in range(max_retries):
                await self._service._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    f"[monitor_task] Poll attempt {attempt + 1}/{max_retries} for task {task_id}",
                    dut_id,
                )

                # Get task status
                (
                    success,
                    response,
                    response_metadata,
                    deadline_exhausted,
                ) = await self._service._dispatch_task_status_with_deadline(
                    dut_id, task_uri, deadline, poll_interval
                )

                if not success:
                    await self._service._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"[monitor_task] Failed to get task status on attempt {attempt + 1}",
                        dut_id,
                    )
                    if (
                        deadline_exhausted
                        or not await self._service._sleep_with_task_monitor_deadline(
                            poll_interval, deadline
                        )
                    ):
                        break
                    continue

                if type(response) is not dict:
                    await self._service._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"[monitor_task] Invalid response type: {type(response)}",
                        dut_id,
                    )
                    if not await self._service._sleep_with_task_monitor_deadline(
                        poll_interval, deadline
                    ):
                        break
                    continue

                # Check the configured field
                current_state = self._service._bounded_task_check_value(
                    check_field,
                    dict.get(response, check_field),
                )

                if not current_state:
                    await self._service._log_runtime(
                        "WARN",
                        "RedfishService",
                        f"[monitor_task] Field '{check_field}' not found in response",
                        dut_id,
                    )
                    if not await self._service._sleep_with_task_monitor_deadline(
                        poll_interval, deadline
                    ):
                        break
                    continue

                await self._service._log_runtime(
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

                    await self._service._log_runtime(
                        "INFO" if is_success else "WARN",
                        "RedfishService",
                        f"[monitor_task] {result['reason']}",
                        dut_id,
                    )

                    # The canonical capture spool is the only detailed-body
                    # owner. Context receives a fixed metadata summary.
                    if kwargs.get("store_result", False):
                        result_key = kwargs.get("result_key", "task_result")
                        result["context"][result_key] = (
                            self._service._bounded_task_response_summary(
                                response,
                                response_metadata,
                            )
                        )
                        await self._service._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"[monitor_task] Stored task result in context['{result_key}']",
                            dut_id,
                        )

                    # Store state if requested
                    if kwargs.get("store_state", False):
                        state_key = kwargs.get("state_key", "task_final_state")
                        result["context"][state_key] = current_state
                        await self._service._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"[monitor_task] Stored state '{current_state}' in context['{state_key}']",
                            dut_id,
                        )

                    return result

                # Not terminal yet, wait and retry
                if not await self._service._sleep_with_task_monitor_deadline(
                    poll_interval, deadline
                ):
                    break

            # Timeout
            return await timeout_result()

        except Exception as e:
            safe_error = self._service._bounded_diagnostic_log_text(e)
            await self._service._log_runtime(
                "ERROR",
                "RedfishService",
                f"[monitor_task] Exception: {safe_error}",
                dut_id,
            )
            return {
                "success": False,
                "context": {},
                "reason": f"Exception during monitor_task: {safe_error}",
            }
