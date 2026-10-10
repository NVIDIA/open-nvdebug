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
Reusable, bounded AsyncSSH connections for Host command endpoints.

This module owns the host ssh pool boundary and exposes
``CredentialGenerationFingerprint``, ``HostSSHBackpressureTimeout``,
``HostSSHPoolShutdown``, ``HostSSHConnectFailure``, and ``_AttemptFailure``.
Keeping those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import hmac
import ipaddress
import logging
import secrets
import socket
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

import asyncssh

SSHCommandResult = Tuple[int, str, str]
ConnectionFactory = Callable[[float], Awaitable[Any]]
ConnectionCloser = Callable[[Any], Awaitable[None]]
ConnectionCleanup = Callable[[], Awaitable[None]]
CommandRunner = Callable[[Any, float], Awaitable[SSHCommandResult]]
AsyncLog = Callable[[str, str], Awaitable[None]]
EndpointKey = Tuple[Any, ...]
RouteKey = Tuple[Any, ...]

MAX_ERROR_DETAIL_CHARS = 512
MAX_PENDING_LOG_TASKS = 64
MAX_METRIC_COUNTER = (1 << 63) - 1
HOST_SSH_SAFE_CONNECT_RETRIES = 1
_SAFE_PROCESS_CREATION_RETRIES = 1
_MISSING_HEALTH_CHECK = object()

logger = logging.getLogger(__name__)


class CredentialGenerationFingerprint:
    """
    Pool-scoped route token with no byte-exporting public surface.

    The type gives the credential generation fingerprint responsibility a stable
    runtime boundary. Callers use the declared Python protocol instead of
    depending on its representation.
    """

    __slots__ = ("__digest", "__hash_value")

    def __init__(self, digest: bytes) -> None:
        """
        Initialize a ``CredentialGenerationFingerprint`` instance.

        The initializer records ``__digest`` and ``__hash_value`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            digest: Bounded byte sequence supplied as digest.
        """
        self.__digest = bytes(digest)
        self.__hash_value = hash(self.__digest)

    def __eq__(self, other: object) -> bool:
        """
        Return whether another value represents the same state.

        The implementation uses ``other`` to determine whether another value
        represents the same state.

        Args:
            other: Other object whose ``__digest`` state is read while
                performing another value represents the same state.

        Returns:
            Whether another value represents the same state.
        """
        if not isinstance(other, CredentialGenerationFingerprint):
            return NotImplemented
        return hmac.compare_digest(self.__digest, other.__digest)

    def __hash__(self) -> int:
        """
        Return the stable hash value for the CredentialGenerationFingerprint.

        The implementation uses current instance state to produce the stable
        hash value for the CredentialGenerationFingerprint.

        Returns:
            The numeric result value.
        """
        return self.__hash_value

    def __repr__(self) -> str:
        """
        Return a developer-facing representation of the CredentialGenerationFingerprint.

        Return a developer-facing representation of the
        CredentialGenerationFingerprint.

        The implementation uses current instance state to produce a
        developer-facing representation of the CredentialGenerationFingerprint.

        Returns:
            The canonical repr text.
        """
        return "<credential-generation>"


class HostSSHBackpressureTimeout(TimeoutError):
    """
    Raised when an endpoint has no channel capacity before the deadline.

    Callers receive this exception when the host SSH backpressure timeout
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


class HostSSHPoolShutdown(RuntimeError):
    """
    Raised when work reaches a pool which is shutting down.

    Callers receive this exception when the host SSH pool shutdown invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


class HostSSHProcessCreationFailure(Exception):
    """
    Identify a transport failure proven to precede remote execution.

    The pool uses this typed boundary to distinguish safe connect-phase retry
    from any failure which might have followed remote process creation. The
    original exception remains attached for permanent/transient classification
    without relying on sanitized message text.

    Attributes:
        error: Original connect-phase exception retained for classification.
    """

    def __init__(self, error: BaseException) -> None:
        """
        Initialize one pre-execution process-creation failure.

        The wrapper preserves the concrete exception type for retry policy and
        exposes only its ordinary exception text through the base class.

        Args:
            error: Original exception raised before a remote process existed.
        """
        super().__init__(str(error))
        self.error = error


class HostSSHConnectFailure(Exception):
    """
    Transfer partial-connect cleanup into exact pool ownership.

    Connection factories use this wrapper when a failed or cancelled connect has
    already created a proxy or endpoint resource. The pool starts cleanup
    without awaiting it on the caller's command deadline, then raises
    ``primary_error`` as the authoritative operation outcome.
    """

    def __init__(
        self,
        primary_error: BaseException,
        *,
        cleanup: ConnectionCleanup,
        connection: Optional[Any] = None,
        ownership_ids: Optional[set[int]] = None,
    ) -> None:
        """
        Initialize a ``HostSSHConnectFailure`` instance.

        The initializer records ``cleanup``, ``connection``, ``ownership_ids``,
        and ``primary_error`` for later operations and establishes the instance
        invariants before any public method runs.

        Args:
            primary_error: Primary error consumed while the function attempts to
                initialize a ``HostSSHConnectFailure`` instance.
            cleanup: Cleanup consumed while the function attempts to initialize
                a ``HostSSHConnectFailure`` instance.
            connection: Optional connection; ``None`` selects the function's
                default behavior.
            ownership_ids: Optional ownership identifiers; ``None`` selects the
                function's default behavior.
        """
        super().__init__(str(primary_error))
        self.primary_error = primary_error
        self.cleanup = cleanup
        self.connection = connection
        self.ownership_ids = frozenset(ownership_ids or ())


class _AttemptFailure(Exception):
    """
    Signal a failure in the attempt failure contract.

    Callers receive this exception when the attempt failure invariant prevents
    the requested operation from completing. The distinct type lets them handle
    that boundary without parsing an error message.
    """

    def __init__(self, phase: str, error: BaseException) -> None:
        """
        Initialize an ``_AttemptFailure`` instance.

        The initializer records ``error`` and ``phase`` for later operations and
        establishes the instance invariants before any public method runs.

        Args:
            phase: Text supplied as phase in the format accepted by this
                function.
            error: Exception or failure detail associated with the operation.
        """
        super().__init__(str(error))
        self.phase = phase
        self.error = error


class _CleanupFailure(Exception):
    """
    Signal a failure in the cleanup failure contract.

    Callers receive this exception when the cleanup failure invariant prevents
    the requested operation from completing. The distinct type lets them handle
    that boundary without parsing an error message.
    """

    def __init__(self, error: BaseException) -> None:
        """
        Initialize a ``_CleanupFailure`` instance.

        The initializer records ``error`` for later operations and establishes
        the instance invariants before any public method runs.

        Args:
            error: Exception or failure detail associated with the operation.
        """
        super().__init__(str(error))
        self.error = error


def normalize_ssh_endpoint_host(host: Any) -> str:
    """
    Return a stable, secret-free host identity for endpoint route keys.

    The implementation uses ``host`` to produce a stable, secret-free host
    identity for endpoint route keys.

    Args:
        host: Host consumed while the function attempts to produce a stable,
            secret-free host identity for endpoint route keys.

    Returns:
        The canonical SSH endpoint host text.
    """

    normalized = str(host or "").strip()
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        return ipaddress.ip_address(normalized).compressed.lower()
    except ValueError:
        return normalized.rstrip(".").lower()


def _ssh_connection_is_usable(connection: Any) -> bool:
    """
    Return whether an existing AsyncSSH connection merits a command probe.

    AsyncSSH 2.15 and newer expose the public ``is_closed()`` query. Earlier
    supported versions have no public connection-health query, so a non-null
    legacy connection is retained and the next channel open or command is the
    authoritative probe. The pool retires and retries it on command failure.

    Args:
        connection: Connection consumed while the function attempts to determine
            whether an existing AsyncSSH connection merits a command probe.

    Returns:
        Whether an existing AsyncSSH connection merits a command probe.
    """

    if connection is None:
        return False
    try:
        is_closed = getattr(connection, "is_closed", _MISSING_HEALTH_CHECK)
    except Exception:
        return False
    if is_closed is _MISSING_HEALTH_CHECK:
        return True
    if not callable(is_closed):
        return False
    try:
        return not is_closed()
    except Exception:
        return False


def _exception_detail(error: BaseException) -> str:
    """
    Return a bounded diagnostic which is never empty.

    The implementation uses ``error`` to produce a bounded diagnostic which is
    never empty.

    Args:
        error: Exception or failure detail associated with the operation.

    Returns:
        The canonical exception detail text.
    """

    detail = str(error).strip() or type(error).__name__
    if not detail.startswith(type(error).__name__):
        detail = f"{type(error).__name__}: {detail}"
    if len(detail) > MAX_ERROR_DETAIL_CHARS:
        return detail[: MAX_ERROR_DETAIL_CHARS - 3] + "..."
    return detail


def _is_control_flow(error: BaseException) -> bool:
    """
    Return whether ``error`` is control flow.

    After applying local validation, the function forwards ``error`` to
    ``isinstance`` and preserves its return and exception contract.

    Args:
        error: Exception or failure detail associated with the operation.

    Returns:
        Whether ``error`` is control flow.
    """
    return isinstance(error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit))


def _is_transient_pre_execution_connect_failure(error: BaseException) -> bool:
    """
    Admit only transport failures which can plausibly recover on one retry.

    Authentication, host-key, key-exchange, protocol, and configuration
    failures are intentionally excluded. Socket timeouts, temporary DNS
    failures, transient network reachability errors, and an AsyncSSH connection
    loss before command entry may use the single fresh pre-execution budget.

    Args:
        error: Connect-phase exception raised before a command runner exists.

    Returns:
        Whether one narrowly bounded pre-execution retry is safe and useful.
    """

    if isinstance(error, asyncio.TimeoutError):
        return True
    if isinstance(error, socket.gaierror):
        return error.errno == socket.EAI_AGAIN
    if isinstance(error, asyncssh.ConnectionLost):
        return True
    if isinstance(error, asyncssh.DisconnectError):
        return error.code in {
            asyncssh.DISC_CONNECTION_LOST,
            asyncssh.DISC_SERVICE_NOT_AVAILABLE,
            asyncssh.DISC_TOO_MANY_CONNECTIONS,
        }
    if isinstance(error, OSError):
        return error.errno in {
            errno.EAGAIN,
            errno.ECONNABORTED,
            errno.ECONNREFUSED,
            errno.ECONNRESET,
            errno.EHOSTDOWN,
            errno.EHOSTUNREACH,
            errno.EINTR,
            errno.ENETDOWN,
            errno.ENETRESET,
            errno.ENETUNREACH,
            errno.ETIMEDOUT,
        }
    return False


def retry_delay_seconds(
    route_key: RouteKey,
    retry_index: int,
    *,
    cap_seconds: float,
) -> float:
    """
    Return deterministic route-scoped exponential backoff with jitter.

    After applying local validation, the function forwards ``route_key``,
    ``retry_index``, and ``cap_seconds`` to ``min`` and preserves its return and
    exception contract.

    Args:
        route_key: Stable route key used for lookup and operator-facing
            diagnostics.
        retry_index: Numeric retry index used by the operation's bounded
            accounting.
        cap_seconds: Maximum duration in seconds allowed for cap seconds.

    Returns:
        The numeric retry delay seconds.
    """

    cap = max(0.0, float(cap_seconds))
    base = min(2.0 ** min(max(0, retry_index), 63), cap)
    digest = hashlib.sha256(repr((route_key, retry_index)).encode()).digest()
    fraction = int.from_bytes(digest[:8], "big") / float((1 << 64) - 1)
    return min(cap, base * (0.75 + (0.5 * fraction)))


@dataclass
class _EndpointMetrics:
    """
    Implement the endpoint metrics boundary used by the NVDebug runtime.

    The coherent record keeps ``connections_created``, ``connection_reuses``,
    ``commands_started``, ``command_failures``, and ``backpressure_waits``
    together so consumers observe one endpoint metrics state. Consumers receive
    the fields as one unit instead of assembling partial state.

    Attributes:
        connections_created: Numeric connections created retained by this
            record.
        connection_reuses: Number of connection reuses represented by this
            record.
        commands_started: Numeric commands started retained by this record.
        command_failures: Number of command failures represented by this record.
        backpressure_waits: Number of backpressure waits represented by this
            record.
        backpressure_timeouts: Number of backpressure timeouts represented by
            this record.
        peak_active_sessions: Highest simultaneous pool-owned session count.
        peak_active_channels: Highest simultaneous admitted channel count.
        peak_queued_commands: Highest simultaneous backpressure queue depth.
    """

    connections_created: int = 0
    connection_reuses: int = 0
    commands_started: int = 0
    command_failures: int = 0
    backpressure_waits: int = 0
    backpressure_timeouts: int = 0
    peak_active_sessions: int = 0
    peak_active_channels: int = 0
    peak_queued_commands: int = 0


@dataclass
class _EndpointState:
    """
    Represent endpoint state data exchanged by the runtime.

    The coherent record keeps ``key``, ``condition``, ``routes``, ``sessions``,
    and ``drained`` together so consumers observe one endpoint state.
    Construction validates cross-field invariants before the instance is
    exposed.

    Attributes:
        key: Numeric key retained by this record.
        condition: Condition retained as part of the record's public state.
        routes: Collection of routes entries retained by this record.
        sessions: Collection of sessions entries retained by this record.
        drained: Drained retained as part of the record's public state.
        active_channels: Number of active channels represented by this record.
        queued_commands: Number of queued commands represented by this record.
        operations: Number of operations represented by this record.
        closed: Whether closed applies to this record.
        notify_pending: Whether notify pending applies to this record.
    """

    key: EndpointKey
    condition: asyncio.Condition = field(default_factory=asyncio.Condition)
    routes: list[_RouteState] = field(default_factory=list)
    sessions: list[_Session] = field(default_factory=list)
    drained: asyncio.Event = field(default_factory=asyncio.Event)
    active_channels: int = 0
    queued_commands: int = 0
    operations: int = 0
    closed: bool = False
    notify_pending: bool = False

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized _EndpointState state.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.
        """
        self.drained.set()


@dataclass
class _RouteState:
    """
    Represent route state data exchanged by the runtime.

    The coherent record keeps ``key``, ``label``, ``connect``, ``endpoint``, and
    ``sessions`` together so consumers observe one route state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        key: Key retained as part of the record's public state.
        label: Canonical text used as label.
        connect: Connect retained as part of the record's public state.
        endpoint: Numeric endpoint retained by this record.
        sessions: Collection of sessions entries retained by this record.
        operations: Number of operations represented by this record.
    """

    key: RouteKey
    label: str
    connect: Optional[ConnectionFactory]
    endpoint: _EndpointState
    sessions: list[_Session] = field(default_factory=list)
    operations: int = 0


@dataclass
class _Session:
    """
    Implement the session boundary used by the NVDebug runtime.

    The coherent record keeps ``route``, ``connection``, ``cleanup``,
    ``leases``, and ``status`` together so consumers observe one session state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        route: Route retained as part of the record's public state.
        connection: Connection retained as part of the record's public state.
        cleanup: Cleanup retained as part of the record's public state.
        leases: Number of leases represented by this record.
        commands_started: Number of remote processes started on the session.
        status: Canonical status exposed to downstream status consumers.
        close_task: Close task retained as part of the record's public state.
        close_error: Close error retained as part of the record's public state.
        close_error_reported: Whether close error reported applies to this
            record.
        ownership_ids: Collection of ownership identifiers entries retained by
            this record.
    """

    route: _RouteState
    connection: Optional[Any] = None
    cleanup: Optional[ConnectionCleanup] = None
    leases: int = 0
    commands_started: int = 0
    status: str = "connecting"
    close_task: Optional[asyncio.Task[None]] = None
    close_error: Optional[BaseException] = None
    close_error_reported: bool = False
    ownership_ids: frozenset[int] = field(default_factory=frozenset)


@dataclass
class _ChannelPermit:
    """
    Implement the channel permit boundary used by the NVDebug runtime.

    The coherent record keeps ``endpoint`` and ``released`` together so
    consumers observe one channel permit state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        endpoint: Numeric endpoint retained by this record.
        released: Whether released applies to this record.
    """

    endpoint: _EndpointState
    released: bool = False


@dataclass
class _SessionLease:
    """
    Implement the session lease boundary used by the NVDebug runtime.

    The coherent record keeps ``session`` and ``released`` together so consumers
    observe one session lease state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        session: Session retained as part of the record's public state.
        released: Whether released applies to this record.
    """

    session: _Session
    released: bool = False


@dataclass
class _OperationState:
    """
    Represent operation state data exchanged by the runtime.

    The coherent record keeps the current phase and command deadline together
    so timeout reporting observes one operation state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        phase: Canonical text used as phase.
        command_deadline: Absolute deadline for the current connect-and-command
            budget, or ``None`` before endpoint capacity is admitted.
    """

    phase: str = "backpressure"
    command_deadline: Optional[float] = None


class HostSSHConnectionPool:
    """
    Pool Host SSH transports by normalized configured endpoint identity.

    The type coordinates ``route_count``, ``credential_generation_fingerprint``,
    ``_destroy_credential_fingerprint_key``, ``_bounded_metric``, and
    ``_increment_metric`` and retains the state those operations share between
    calls. Resource ownership remains inside the instance until the matching
    close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        *,
        close_connection: ConnectionCloser,
        max_sessions_per_endpoint: int,
        max_channels_per_session: int,
        connect_timeout_seconds: float,
        retry_backoff_cap_seconds: float,
        shutdown_timeout_seconds: float,
        max_commands_per_session: Optional[int] = None,
        backpressure_timeout_seconds: Optional[float] = None,
        log: Optional[AsyncLog] = None,
    ) -> None:
        """
        Initialize a ``HostSSHConnectionPool`` instance.

        The HMAC key is owned by this run pool, never exported, and erased after
        the last route is closed. Tokens from different pool runs are therefore
        neither stable nor correlatable.

        Args:
            close_connection: Close connection consumed while the function
                attempts to initialize a ``HostSSHConnectionPool`` instance.
            max_sessions_per_endpoint: Validated remote resource identifier used
                for max sessions per endpoint.
            max_channels_per_session: Upper bound enforced for max channels per
                session; the consuming boundary rejects or truncates values that
                exceed it.
            max_commands_per_session: Optional maximum commands admitted on one
                session before it is retired; ``None`` selects the compatibility
                default.
            backpressure_timeout_seconds: Optional maximum duration allowed
                while waiting for endpoint capacity; ``None`` derives the wait
                from the command timeout.
            connect_timeout_seconds: Maximum duration in seconds allowed for
                connect timeout seconds.
            retry_backoff_cap_seconds: Maximum duration in seconds allowed for
                retry backoff cap seconds.
            shutdown_timeout_seconds: Maximum duration in seconds allowed for
                shutdown timeout seconds.
            max_commands_per_session: Optional lifetime process-start ceiling
                for one SSH session; ``None`` uses the governed counter bound.
            backpressure_timeout_seconds: Optional endpoint-capacity admission
                timeout applied separately from connect and command runtime.
            log: Sanitized logging interface used for operator-visible
                diagnostics.
        """
        self._close_connection = close_connection
        self._log = log
        self._max_sessions = max_sessions_per_endpoint
        self._max_channels = max_channels_per_session
        self._max_commands = (
            max_commands_per_session
            if max_commands_per_session is not None
            else MAX_METRIC_COUNTER
        )
        self._capacity = max_sessions_per_endpoint * max_channels_per_session
        self._backpressure_timeout = backpressure_timeout_seconds
        self._connect_timeout = connect_timeout_seconds
        self._retry_backoff_cap = retry_backoff_cap_seconds
        self._shutdown_timeout = shutdown_timeout_seconds
        self._endpoints: Dict[EndpointKey, _EndpointState] = {}
        self._routes: Dict[Tuple[EndpointKey, RouteKey], _RouteState] = {}
        self._metrics = _EndpointMetrics()
        self._cleanup_tasks: set[asyncio.Task[Any]] = set()
        self._operation_tasks: set[asyncio.Task[Any]] = set()
        self._auxiliary_tasks: set[asyncio.Task[Any]] = set()
        self._log_tasks: set[asyncio.Task[Any]] = set()
        self._accepting: bool = True
        self._metrics_reported: bool = False
        self._close_lock = asyncio.Lock()
        # The HMAC key is owned by this run pool, never exported, and erased
        # after the last route is closed. Tokens from different pool runs are
        # therefore neither stable nor correlatable.
        self._credential_fingerprint_key: Optional[bytearray] = bytearray(
            secrets.token_bytes(32)
        )

    @property
    def route_count(self) -> int:
        """
        Return the route count.

        Each access computes the value from ``_routes`` on the current instance;
        the derived view is not stored as independent state.

        Returns:
            The numeric route count.
        """
        return len(self._routes)

    def credential_generation_fingerprint(
        self,
        *values: Any,
    ) -> CredentialGenerationFingerprint:
        """
        Return an opaque identity keyed only for this pool's lifetime.

        After applying local validation, the function forwards ``values`` to
        ``CredentialGenerationFingerprint`` and preserves its return and
        exception contract.

        Args:
            values: Additional positional values forwarded in caller-provided
                order.

        Returns:
            The numeric credential generation fingerprint value.

        Raises:
            HostSSHPoolShutdown: If host SSH pool credential key is retired.
        """

        key = self._credential_fingerprint_key
        if key is None:
            raise HostSSHPoolShutdown("Host SSH pool credential key is retired")
        digest = hmac.new(key, digestmod=hashlib.sha256)
        digest.update(b"nvdebug-ssh-v1\x00")
        for value in values:
            if value is None:
                encoded = b"\x00"
            else:
                encoded = b"\x01" + str(value).encode("utf-8", errors="surrogatepass")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        return CredentialGenerationFingerprint(digest.digest()[:16])

    def _destroy_credential_fingerprint_key(self) -> None:
        """
        Destroy credential fingerprint key.

        The implementation uses current instance state to destroy credential
        fingerprint key. It updates ``_credential_fingerprint_key`` on the
        instance as part of that state transition.
        """
        key = self._credential_fingerprint_key
        if key is None:
            return
        for index in range(len(key)):
            key[index] = 0
        key.clear()
        self._credential_fingerprint_key = None

    @staticmethod
    def _bounded_metric(value: int) -> int:
        """
        Return the bounded metric.

        After applying local validation, the function forwards ``value`` to
        ``min`` and preserves its return and exception contract.

        Args:
            value: Numeric value used while the operation performs bounded
                accounting.

        Returns:
            The numeric bounded metric value.
        """
        return min(MAX_METRIC_COUNTER, max(0, int(value)))

    def _increment_metric(self, attribute: str) -> None:
        """
        Increment metric.

        The implementation uses ``attribute`` to increment metric.

        Args:
            attribute: Text supplied as attribute in the format accepted by this
                function.
        """
        current = getattr(self._metrics, attribute)
        setattr(self._metrics, attribute, self._bounded_metric(current + 1))

    def _observe_pool_occupancy(self) -> None:
        """
        Retain saturating high-water marks before transient state is released.

        The event loop mutates pool occupancy synchronously between await
        boundaries. Calling this helper immediately after each increment keeps
        teardown evidence truthful even when all sessions, channels, and queue
        entries have returned to zero by the time the final snapshot is read.

        Side effects:
            Raises the three peak occupancy counters retained for this pool;
            existing peaks are never reduced.
        """

        endpoints = tuple(self._endpoints.values())
        active_sessions = sum(len(endpoint.sessions) for endpoint in endpoints)
        active_channels = sum(endpoint.active_channels for endpoint in endpoints)
        queued_commands = sum(endpoint.queued_commands for endpoint in endpoints)
        self._metrics.peak_active_sessions = max(
            self._metrics.peak_active_sessions,
            self._bounded_metric(active_sessions),
        )
        self._metrics.peak_active_channels = max(
            self._metrics.peak_active_channels,
            self._bounded_metric(active_channels),
        )
        self._metrics.peak_queued_commands = max(
            self._metrics.peak_queued_commands,
            self._bounded_metric(queued_commands),
        )

    def metrics_snapshot(self) -> Dict[str, int]:
        """
        Return one fixed-shape, label-free, saturating run aggregate.

        The implementation uses current instance state to produce one
        fixed-shape, label-free, saturating run aggregate.

        Returns:
            A mapping containing the ``normalized_endpoints``,
            ``active_sessions``, ``active_channels``, ``queued_commands``, and
            ``connections_created`` fields.
        """

        endpoints = tuple(self._endpoints.values())

        return {
            "normalized_endpoints": self._bounded_metric(len(endpoints)),
            "active_sessions": self._bounded_metric(
                sum(len(endpoint.sessions) for endpoint in endpoints)
            ),
            "active_channels": self._bounded_metric(
                sum(endpoint.active_channels for endpoint in endpoints)
            ),
            "queued_commands": self._bounded_metric(
                sum(endpoint.queued_commands for endpoint in endpoints)
            ),
            "connections_created": self._bounded_metric(
                self._metrics.connections_created
            ),
            "connection_reuses": self._bounded_metric(self._metrics.connection_reuses),
            "commands_started": self._bounded_metric(self._metrics.commands_started),
            "command_failures": self._bounded_metric(self._metrics.command_failures),
            "backpressure_waits": self._bounded_metric(
                self._metrics.backpressure_waits
            ),
            "backpressure_timeouts": self._bounded_metric(
                self._metrics.backpressure_timeouts
            ),
            "peak_active_sessions": self._bounded_metric(
                self._metrics.peak_active_sessions
            ),
            "peak_active_channels": self._bounded_metric(
                self._metrics.peak_active_channels
            ),
            "peak_queued_commands": self._bounded_metric(
                self._metrics.peak_queued_commands
            ),
        }

    @staticmethod
    def empty_metrics_snapshot() -> Dict[str, int]:
        """
        Return the same public shape before a pool has been materialized.

        The implementation uses current instance state to produce the same
        public shape before a pool has been materialized.

        Returns:
            A mapping containing the ``normalized_endpoints``,
            ``active_sessions``, ``active_channels``, ``queued_commands``, and
            ``connections_created`` fields.
        """

        return {
            "normalized_endpoints": 0,
            "active_sessions": 0,
            "active_channels": 0,
            "queued_commands": 0,
            "connections_created": 0,
            "connection_reuses": 0,
            "commands_started": 0,
            "command_failures": 0,
            "backpressure_waits": 0,
            "backpressure_timeouts": 0,
            "peak_active_sessions": 0,
            "peak_active_channels": 0,
            "peak_queued_commands": 0,
        }

    def metrics_summary(self) -> Dict[str, int]:
        """
        Compatibility alias for the fixed-shape public aggregate.

        After applying local validation, the function forwards current instance
        state to ``self.metrics_snapshot`` and preserves its return and
        exception contract.

        Returns:
            A mapping containing metrics summary.
        """

        return self.metrics_snapshot()

    def claim_metrics_summary(self) -> Optional[Dict[str, int]]:
        """
        Return one fixed-shape snapshot for the run teardown owner.

        After applying local validation, the function forwards current instance
        state to ``self.metrics_summary`` and preserves its return and exception
        contract. It updates ``_metrics_reported`` on the instance as part of
        that state transition.

        Returns:
            A mapping containing claim metrics summary, or ``None`` when the
            requested value is unavailable.
        """

        if self._metrics_reported:
            return None
        self._metrics_reported = True
        return self.metrics_summary()

    def cleanup_ownership_ids(self) -> set[int]:
        """
        Return resource IDs whose cleanup remains exclusively pool-owned.

        The implementation uses current instance state to produce resource IDs
        whose cleanup remains exclusively pool-owned.

        Returns:
            The unique cleanup ownership identifiers returned by the operation.
        """

        return {
            ownership_id
            for endpoint in self._endpoints.values()
            for session in endpoint.sessions
            for ownership_id in session.ownership_ids
        }

    async def _write_log(self, level: str, message: str) -> None:
        """
        Write log.

        The implementation uses ``level`` and ``message`` to write log. Success
        is reported only after the owning output boundary has completed its
        required write or publication step. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """
        if self._log is None:
            return
        try:
            await self._log(level, message)
        except Exception:
            logger.debug("Host SSH pool logging failed", exc_info=True)

    @staticmethod
    def _observe_task(tasks: set[asyncio.Task[Any]], task: asyncio.Task[Any]) -> None:
        """
        Observe task.

        The implementation uses ``tasks`` and ``task`` to observe task. The
        operation mutates ``tasks`` in place; ownership of those objects remains
        with the caller.

        Args:
            tasks: Entries supplied as ``tasks`` without transferring container
                ownership.
            task: Task object whose ``exception`` state is read while performing
                observe task.
        """
        tasks.discard(task)
        try:
            task.exception()
        except asyncio.CancelledError:
            pass

    def _schedule_log(self, level: str, message: str) -> None:
        """
        Schedule log.

        The implementation uses ``level`` and ``message`` to schedule log.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """
        if self._log is None:
            return
        if len(self._log_tasks) >= MAX_PENDING_LOG_TASKS:
            logger.debug("Host SSH pool log backlog is full; diagnostic dropped")
            return
        task = asyncio.create_task(self._write_log(level, message))
        self._log_tasks.add(task)
        task.add_done_callback(
            lambda completed: self._observe_task(self._log_tasks, completed)
        )

    async def _notify(self, endpoint: _EndpointState) -> None:
        """
        Notify callers waiting on the owned state transition.

        The implementation uses ``endpoint`` to notify callers waiting on the
        owned state transition. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind. Cleanup
        in the ``finally`` path runs for successful, failed, and cancelled
        execution.

        Args:
            endpoint: Validated remote resource identifier used for endpoint.
        """
        try:
            async with endpoint.condition:
                endpoint.condition.notify_all()
        finally:
            endpoint.notify_pending = False

    def _schedule_notify(self, endpoint: _EndpointState) -> None:
        """
        Schedule notify.

        The implementation uses ``endpoint`` to schedule notify.

        Args:
            endpoint: Validated remote resource identifier used for endpoint.
        """
        if endpoint.notify_pending:
            return
        endpoint.notify_pending = True
        task = asyncio.create_task(self._notify(endpoint))
        self._auxiliary_tasks.add(task)
        task.add_done_callback(
            lambda completed: self._observe_task(self._auxiliary_tasks, completed)
        )

    def _get_route(
        self,
        endpoint_key: EndpointKey,
        route_key: RouteKey,
        route_label: str,
        connect: ConnectionFactory,
    ) -> _RouteState:
        """
        Return route.

        The implementation uses ``endpoint_key``, ``route_key``,
        ``route_label``, and ``connect`` to produce route.

        Args:
            endpoint_key: Validated remote resource identifier used for endpoint
                key.
            route_key: Stable route key used for lookup and operator-facing
                diagnostics.
            route_label: Text supplied as route label in the format accepted by
                this function.
            connect: Connect consumed while the function attempts to produce
                route.

        Returns:
            The validated ``route``.
        """
        endpoint = self._endpoints.get(endpoint_key)
        if endpoint is None:
            endpoint = _EndpointState(endpoint_key)
            self._endpoints[endpoint_key] = endpoint

        state_key = (endpoint_key, route_key)
        route = self._routes.get(state_key)
        if route is None:
            route = _RouteState(route_key, route_label, connect, endpoint)
            endpoint.routes.append(route)
            self._routes[state_key] = route
        return route

    @staticmethod
    def _connection_is_usable(connection: Any) -> bool:
        """
        Return the connection is usable.

        After applying local validation, the function forwards ``connection`` to
        ``_ssh_connection_is_usable`` and preserves its return and exception
        contract.

        Args:
            connection: Connection consumed while the function attempts to
                produce the connection is usable.

        Returns:
            Whether the connection is usable operation succeeds.
        """
        return _ssh_connection_is_usable(connection)

    def _is_shutting_down(self, endpoint: _EndpointState) -> bool:
        """
        Re-read mutable lifecycle state after an awaited operation.

        The implementation uses ``endpoint`` to re-read mutable lifecycle state
        after an awaited operation.

        Args:
            endpoint: Validated remote resource identifier used for endpoint.

        Returns:
            Whether the re-read mutable lifecycle state after an awaited
            operation succeeds.
        """

        return endpoint.closed or not self._accepting

    def _prune_endpoint_now(self, endpoint: _EndpointState) -> None:
        """
        Drop an empty endpoint without retaining host-derived identities.

        The implementation uses ``endpoint`` to drop an empty endpoint without
        retaining host-derived identities.

        Args:
            endpoint: Validated remote resource identifier used for endpoint.
        """

        if endpoint.operations or endpoint.sessions or endpoint.routes:
            return
        self._endpoints.pop(endpoint.key, None)
        if not self._accepting and not self._endpoints:
            self._destroy_credential_fingerprint_key()

    def _prune_route_now(self, route: _RouteState) -> None:
        """
        Erase an idle route's connect closure and credential token refs.

        The connect closure is the sole pool state retaining raw immutable auth
        fields. Clear it only after operations, waiters, sessions, and their
        close tasks have relinquished the route.

        Args:
            route: Route object whose ``connect``, ``endpoint``, ``key``,
                ``label``, and ``operations`` state is read while performing
                erase an idle route's connect closure and credential token refs.
        """

        endpoint = route.endpoint
        if route.operations or route.sessions:
            return
        self._routes.pop((endpoint.key, route.key), None)
        if route in endpoint.routes:
            endpoint.routes.remove(route)
        # The connect closure is the sole pool state retaining raw immutable
        # auth fields. Clear it only after operations, waiters, sessions, and
        # their close tasks have relinquished the route.
        route.connect = None
        route.key = ()
        route.label = ""
        self._prune_endpoint_now(endpoint)

    def _begin_operation(self, route: _RouteState) -> None:
        """
        Begin operation.

        The implementation uses ``route`` to begin operation. If the function
        cannot begin operation, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            route: Route object whose ``endpoint`` and ``operations`` state is
                read while performing begin.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to begin operation.
        """
        endpoint = route.endpoint
        if not self._accepting or endpoint.closed:
            raise HostSSHPoolShutdown
        route.operations += 1
        endpoint.operations += 1
        endpoint.drained.clear()

    def _end_operation(self, route: _RouteState) -> None:
        """
        End operation.

        The implementation uses ``route`` to end operation.

        Args:
            route: Route object whose ``endpoint`` and ``operations`` state is
                read while performing end.
        """
        endpoint = route.endpoint
        route.operations -= 1
        endpoint.operations -= 1
        if endpoint.operations == 0:
            endpoint.drained.set()
        self._schedule_notify(endpoint)
        self._prune_route_now(route)

    def _observe_operation_task(
        self,
        route: _RouteState,
        task: asyncio.Task[Any],
    ) -> None:
        """
        Release operation ownership only after the child truly settles.

        The implementation uses ``route`` and ``task`` to release operation
        ownership only after the child truly settles.

        Args:
            route: Route consumed while the function attempts to release
                operation ownership only after the child truly settles.
            task: Task consumed while the function attempts to release operation
                ownership only after the child truly settles.
        """

        self._operation_tasks.discard(task)
        self._end_operation(route)
        self._observe_task(self._operation_tasks, task)

    async def _reserve_channel(
        self,
        endpoint: _EndpointState,
        deadline: float,
    ) -> _ChannelPermit:
        """
        Reserve channel.

        After applying local validation, the function forwards ``endpoint`` and
        ``deadline`` to ``_ChannelPermit`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            endpoint: Validated remote resource identifier used for endpoint.
            deadline: Absolute monotonic deadline after which the operation must
                stop.

        Returns:
            A ``_ChannelPermit`` representing reserve channel.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to reserve channel.
        """
        loop = asyncio.get_running_loop()
        queued = False
        async with endpoint.condition:
            try:
                while endpoint.active_channels >= self._capacity:
                    if endpoint.closed or not self._accepting:
                        raise HostSSHPoolShutdown
                    if not queued:
                        queued = True
                        endpoint.queued_commands += 1
                        self._observe_pool_occupancy()
                        self._increment_metric("backpressure_waits")
                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        raise HostSSHBackpressureTimeout
                    try:
                        await asyncio.wait_for(
                            endpoint.condition.wait(), timeout=remaining
                        )
                    except asyncio.TimeoutError as error:
                        raise HostSSHBackpressureTimeout from error

                if endpoint.closed or not self._accepting:
                    raise HostSSHPoolShutdown
                endpoint.active_channels += 1
                self._observe_pool_occupancy()
                return _ChannelPermit(endpoint)
            finally:
                if queued:
                    endpoint.queued_commands -= 1

    def _release_channel_now(self, permit: _ChannelPermit) -> None:
        """
        Release channel now.

        The implementation uses ``permit`` to release channel now.

        Args:
            permit: Permit object whose ``active_channels``, ``endpoint``, and
                ``released`` state is read while performing release channel now.
        """
        if permit.released:
            return
        permit.released = True
        permit.endpoint.active_channels -= 1
        self._schedule_notify(permit.endpoint)

    async def _finish_session_close(
        self,
        endpoint: _EndpointState,
        session: _Session,
    ) -> None:
        """
        Finish session close.

        The implementation uses ``endpoint`` and ``session`` to finish session
        close. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind. The operation mutates
        ``endpoint`` and ``session`` in place; ownership of those objects
        remains with the caller. If the function cannot finish session close,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            endpoint: Validated remote resource identifier used for endpoint.
            session: Transport session governed by the configured authentication
                and trust policy.

        Raises:
            RuntimeError: If host SSH session cleanup owner is missing.
        """
        cleanup = session.cleanup
        try:
            if cleanup is None:
                raise RuntimeError("Host SSH session cleanup owner is missing")
            await cleanup()
        except BaseException as error:
            session.status = "retiring"
            session.close_task = None
            session.close_error = error
            self._schedule_notify(endpoint)
            raise

        session.status = "closed"
        session.close_task = None
        session.close_error = None
        session.close_error_reported = False
        if session in endpoint.sessions:
            endpoint.sessions.remove(session)
        if session in session.route.sessions:
            session.route.sessions.remove(session)
        session.connection = None
        session.cleanup = None
        session.ownership_ids = frozenset()
        self._schedule_notify(endpoint)

    def _observe_session_close_task(
        self,
        session: _Session,
        task: asyncio.Task[Any],
    ) -> None:
        """
        Observe close completion before releasing its route references.

        The implementation uses ``session`` and ``task`` to observe close
        completion before releasing its route references.

        Args:
            session: Transport session governed by the configured authentication
                and trust policy.
            task: Task consumed while the function attempts to observe close
                completion before releasing its route references.
        """

        self._observe_task(self._cleanup_tasks, task)
        if session.status == "closed":
            self._prune_route_now(session.route)

    def _claim_session_close_now(
        self,
        endpoint: _EndpointState,
        session: _Session,
        *,
        force: bool = False,
    ) -> Optional[asyncio.Task[None]]:
        """
        Atomically give exactly one pool task ownership of this cleanup.

        The implementation uses ``endpoint``, ``session``, and ``force`` to
        atomically give exactly one pool task ownership of this cleanup.

        Args:
            endpoint: Validated remote resource identifier used for endpoint.
            session: Transport session governed by the configured authentication
                and trust policy.
            force: Whether force is enabled or required for this operation.

        Returns:
            The pool-owned close task, or ``None`` when another task owns
            cleanup.
        """

        if session.status in {"closing", "closed", "connecting"}:
            return session.close_task
        if session.leases and not force:
            return None
        if session.cleanup is None:
            return None

        session.status = "closing"
        session.close_error = None
        session.close_error_reported = False
        task = asyncio.create_task(
            self._finish_session_close(endpoint, session),
            name="host-ssh-close",
        )
        session.close_task = task
        self._cleanup_tasks.add(task)
        task.add_done_callback(
            lambda completed: self._observe_session_close_task(session, completed)
        )
        return task

    def _remove_connecting_session_now(self, session: _Session) -> None:
        """
        Remove a connecting SSH session and notify waiting callers.

        The implementation uses ``session`` to remove a connecting SSH session
        and notify waiting callers. The operation mutates ``session`` in place;
        ownership of those objects remains with the caller.

        Args:
            session: Transport session governed by the configured authentication
                and trust policy.
        """
        endpoint = session.route.endpoint
        session.status = "closed"
        if session in endpoint.sessions:
            endpoint.sessions.remove(session)
        if session in session.route.sessions:
            session.route.sessions.remove(session)
        self._schedule_notify(endpoint)

    def _retire_partial_connect_now(
        self,
        session: _Session,
        failure: HostSSHConnectFailure,
    ) -> None:
        """
        Retire partial connect now.

        The implementation uses ``session`` and ``failure`` to retire partial
        connect now.

        Args:
            session: Transport session governed by the configured authentication
                and trust policy.
            failure: Failure object whose ``cleanup``, ``connection``, and
                ``ownership_ids`` state is read while performing retire partial
                connect now.
        """
        session.connection = failure.connection
        session.cleanup = failure.cleanup
        session.ownership_ids = failure.ownership_ids
        session.leases = 0
        session.status = "retiring"
        self._claim_session_close_now(session.route.endpoint, session)
        self._schedule_notify(session.route.endpoint)

    async def _acquire_session(
        self,
        route: _RouteState,
        deadline: float,
    ) -> _SessionLease:
        """
        Return the acquire session.

        The implementation uses ``route`` and ``deadline`` to produce the
        acquire session. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. The operation
        mutates ``route`` in place; ownership of those objects remains with the
        caller. If the function cannot produce the acquire session, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            route: Route object whose ``append``, ``connect``, ``endpoint``, and
                ``sessions`` state is read while performing acquire session.
            deadline: Absolute monotonic deadline after which the operation must
                stop.

        Returns:
            A ``_SessionLease`` representing acquire session.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to produce the acquire session.
            _CleanupFailure: If owned cleanup cannot complete while attempting
                to produce the acquire session.
            RuntimeError: If host SSH endpoint capacity state is inconsistent;
                or host SSH route was retired during acquisition.
        """
        endpoint = route.endpoint
        loop = asyncio.get_running_loop()

        while True:
            placeholder: Optional[_Session] = None
            async with endpoint.condition:
                if endpoint.closed or not self._accepting:
                    raise HostSSHPoolShutdown

                for session in route.sessions:
                    if session.status == "open" and not self._connection_is_usable(
                        session.connection
                    ):
                        session.status = "retiring"

                cleanup_failure: Optional[BaseException] = None
                for session in list(endpoint.sessions):
                    if session.status != "retiring" or session.leases:
                        continue
                    if (
                        session.close_error is not None
                        and not session.close_error_reported
                    ):
                        if cleanup_failure is None:
                            cleanup_failure = session.close_error
                            session.close_error_reported = True
                        continue
                    # Retry a previously reported failure under the same cleanup
                    # ownership. Capacity remains occupied until close succeeds.
                    self._claim_session_close_now(endpoint, session)

                available = [
                    session
                    for session in route.sessions
                    if session.status == "open"
                    and session.leases < self._max_channels
                    and session.commands_started < self._max_commands
                ]
                if available:
                    session = min(available, key=lambda candidate: candidate.leases)
                    session.leases += 1
                    session.commands_started += 1
                    self._increment_metric("connection_reuses")
                    return _SessionLease(session)

                if cleanup_failure is not None:
                    raise _CleanupFailure(cleanup_failure)

                if len(endpoint.sessions) < self._max_sessions:
                    placeholder = _Session(route)
                    endpoint.sessions.append(placeholder)
                    route.sessions.append(placeholder)
                    self._observe_pool_occupancy()
                else:
                    # Full route identities may not share a transport. Retire
                    # an idle incompatible route before creating its replacement,
                    # while retaining one normalized configured-endpoint domain.
                    evictable = next(
                        (
                            session
                            for session in endpoint.sessions
                            if session.status == "open" and session.leases == 0
                        ),
                        None,
                    )
                    if evictable is not None:
                        evictable.status = "retiring"
                        self._claim_session_close_now(endpoint, evictable)

                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        raise asyncio.TimeoutError
                    await asyncio.wait_for(endpoint.condition.wait(), timeout=remaining)
                    continue

            if placeholder is None:
                raise RuntimeError("Host SSH endpoint capacity state is inconsistent")
            connect_budget = min(self._connect_timeout, deadline - loop.time())
            if connect_budget <= 0:
                self._remove_connecting_session_now(placeholder)
                raise asyncio.TimeoutError

            try:
                connect = route.connect
                if connect is None:
                    raise RuntimeError("Host SSH route was retired during acquisition")
                connection = await connect(connect_budget)
            except HostSSHConnectFailure as failure:
                self._retire_partial_connect_now(placeholder, failure)
                raise failure.primary_error
            except BaseException:
                self._remove_connecting_session_now(placeholder)
                raise

            placeholder.connection = connection
            placeholder.cleanup = lambda: self._close_connection(connection)
            placeholder.ownership_ids = frozenset({id(connection)})
            self._increment_metric("connections_created")
            if self._is_shutting_down(endpoint):
                placeholder.status = "retiring"
                self._claim_session_close_now(endpoint, placeholder)
                self._schedule_notify(endpoint)
                raise HostSSHPoolShutdown
            if loop.time() >= deadline:
                placeholder.status = "retiring"
                self._claim_session_close_now(endpoint, placeholder)
                self._schedule_notify(endpoint)
                raise asyncio.TimeoutError

            placeholder.status = "open"
            placeholder.leases = 1
            placeholder.commands_started = 1
            self._schedule_notify(endpoint)
            return _SessionLease(placeholder)

    def _mark_unusable_session_now(
        self,
        lease: _SessionLease,
        *,
        command_failed: bool,
    ) -> None:
        """
        Mark unusable session now.

        The implementation uses ``lease`` and ``command_failed`` to mark
        unusable session now.

        Args:
            lease: Lease object whose ``session`` state is read while performing
                mark unusable session now.
            command_failed: Whether command failed is enabled or required for
                this operation.
        """
        session = lease.session
        if not command_failed and self._connection_is_usable(session.connection):
            return
        if session.status == "open":
            session.status = "retiring"
            self._schedule_notify(session.route.endpoint)

    def _release_session_now(self, lease: _SessionLease) -> None:
        """
        Release session now.

        The implementation uses ``lease`` to release session now.

        Args:
            lease: Lease object whose ``released`` and ``session`` state is read
                while performing release session now.
        """
        if lease.released:
            return
        lease.released = True
        session = lease.session
        endpoint = session.route.endpoint
        session.leases -= 1
        if session.status == "open" and session.commands_started >= self._max_commands:
            session.status = "retiring"
        if endpoint.closed and session.status == "open":
            session.status = "retiring"
        if session.status == "retiring" and session.leases == 0:
            self._claim_session_close_now(endpoint, session)
        self._schedule_notify(endpoint)

    async def _run_attempt(
        self,
        route: _RouteState,
        run: CommandRunner,
        backpressure_deadline: float,
        timeout_seconds: float,
        operation: _OperationState,
    ) -> SSHCommandResult:
        """
        Run attempt.

        The implementation uses ``route``, ``run``, the separate backpressure
        and command budgets, and ``operation`` to run one attempt. Terminal
        status is emitted only after attempt and its owned cleanup have
        completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. If the function
        cannot run attempt, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path
        runs for successful, failed, and cancelled execution.

        Args:
            route: Route object whose ``endpoint`` state is read while
                performing attempt.
            run: Run consumed while the function attempts to run attempt.
            backpressure_deadline: Absolute deadline for initial admission to
                normalized endpoint capacity.
            timeout_seconds: Maximum duration of the active
                connect-and-command budget.
            operation: Operation object whose ``phase`` state is read while
                performing attempt.

        Returns:
            The validated ``result``.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to run attempt.
            RuntimeError: If host SSH command returned no result; or host SSH
                command result state is inconsistent.
            _AttemptFailure: If cleanup; or the function cannot run attempt
                safely.
        """
        endpoint = route.endpoint
        loop = asyncio.get_running_loop()
        phase = "backpressure"
        operation.phase = phase
        permit: Optional[_ChannelPermit] = None
        lease: Optional[_SessionLease] = None
        result: Optional[SSHCommandResult] = None
        primary_error: Optional[BaseException] = None

        try:
            acquisition_deadline = backpressure_deadline
            if operation.command_deadline is not None:
                acquisition_deadline = min(
                    acquisition_deadline, operation.command_deadline
                )
            permit = await self._reserve_channel(endpoint, acquisition_deadline)
            if operation.command_deadline is None:
                operation.command_deadline = loop.time() + timeout_seconds
            phase = "connect"
            operation.phase = phase
            lease = await self._acquire_session(route, operation.command_deadline)
            if endpoint.closed:
                raise HostSSHPoolShutdown
            phase = "command"
            operation.phase = phase
            remaining = operation.command_deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError
            self._increment_metric("commands_started")
            async with asyncio.timeout(remaining):
                result = await run(lease.session.connection, remaining)
            if result is None:
                raise RuntimeError("Host SSH command returned no result")
            if loop.time() >= operation.command_deadline:
                raise asyncio.TimeoutError
        except BaseException as error:
            primary_error = error
            if lease is not None:
                self._mark_unusable_session_now(
                    lease,
                    command_failed=phase == "command",
                )
        finally:
            # These state transitions contain no await. Cancellation can never
            # strand a lease or channel permit between ownership handoffs.
            if lease is not None:
                self._release_session_now(lease)
            if permit is not None:
                self._release_channel_now(permit)

        if primary_error is not None:
            if _is_control_flow(primary_error):
                raise primary_error
            if isinstance(
                primary_error,
                (HostSSHBackpressureTimeout, HostSSHPoolShutdown),
            ):
                raise primary_error
            if isinstance(primary_error, _CleanupFailure):
                if _is_control_flow(primary_error.error):
                    raise primary_error.error
                raise _AttemptFailure("cleanup", primary_error.error)
            raise _AttemptFailure(phase, primary_error)
        if result is None:
            raise RuntimeError("Host SSH command result state is inconsistent")
        return result

    async def _execute_operation(
        self,
        *,
        route: _RouteState,
        route_key: RouteKey,
        route_label: str,
        run: CommandRunner,
        timeout_seconds: float,
        backpressure_timeout_seconds: float,
        attempts: int,
        backpressure_deadline: float,
        operation: _OperationState,
    ) -> SSHCommandResult:
        """
        Execute operation.

        The implementation uses ``route``, ``route_key``, ``route_label``,
        ``run``, and ``timeout_seconds`` to execute operation. Terminal status
        is emitted only after operation and its owned cleanup have completed.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            route: Route object whose ``endpoint`` state is read while
                performing operation.
            route_key: Stable route key used for lookup and operator-facing
                diagnostics.
            route_label: Text supplied as route label in the format accepted by
                this function.
            run: Run consumed while the function attempts to execute operation.
            timeout_seconds: Maximum duration in seconds allowed for timeout
                seconds.
            backpressure_timeout_seconds: Maximum duration spent waiting for
                normalized endpoint capacity before execution begins.
            attempts: Numeric attempts used while the operation performs bounded
                accounting.
            backpressure_deadline: Absolute deadline for admission to endpoint
                capacity; it is not renewed by the safe connect retry.
            operation: Operation object whose ``phase`` state is read while
                performing operation.

        Returns:
            A tuple containing ``execute operation value 1``, ``status text``,
            and ``execute operation value 3`` in that order.
        """
        endpoint = route.endpoint
        loop = asyncio.get_running_loop()
        last_error = ""
        safe_connect_retry_available = True
        safe_creation_retry_available = True
        for attempt_index in range(
            attempts + HOST_SSH_SAFE_CONNECT_RETRIES + _SAFE_PROCESS_CREATION_RETRIES
        ):
            attempt_number = attempt_index + 1
            try:
                return await self._run_attempt(
                    route,
                    run,
                    backpressure_deadline,
                    timeout_seconds,
                    operation,
                )
            except asyncio.CancelledError:
                raise
            except HostSSHBackpressureTimeout:
                self._increment_metric("backpressure_timeouts")
                return (
                    -1,
                    "",
                    "Host SSH "
                    f"route={route_label} phase=backpressure timed out after "
                    f"{backpressure_timeout_seconds:g}s waiting for endpoint capacity "
                    f"(sessions={self._max_sessions}, "
                    f"channels_per_session={self._max_channels})",
                )
            except HostSSHPoolShutdown:
                return (
                    -1,
                    "",
                    f"Host SSH route={route_label} phase=shutdown rejected command",
                )
            except _AttemptFailure as failure:
                self._increment_metric("command_failures")
                safe_creation_failure = isinstance(
                    failure.error, HostSSHProcessCreationFailure
                )
                reported_error = (
                    failure.error.error if safe_creation_failure else failure.error
                )
                owner_task = asyncio.current_task()
                owner_cancelling = bool(
                    owner_task is not None and owner_task.cancelling()
                )
                safe_connect_failure = (
                    failure.phase == "connect"
                    and _is_transient_pre_execution_connect_failure(reported_error)
                    and not owner_cancelling
                )
                detail = _exception_detail(reported_error)
                last_error = (
                    "Host SSH "
                    f"route={route_label} phase={failure.phase} attempt "
                    f"{min(attempt_number, attempts)}/{attempts} failed: {detail}"
                )
                self._schedule_log("WARNING", last_error)
                if failure.phase == "connect":
                    if not safe_connect_failure or not safe_connect_retry_available:
                        return -1, "", last_error
                    safe_connect_retry_available = False
                    # No command runner was entered while ``phase`` remained
                    # ``connect``. Give the one proven pre-execution retry a
                    # fresh connect-and-command budget without making command
                    # or cleanup failures replayable.
                    operation.command_deadline = loop.time() + timeout_seconds
                    self._schedule_log(
                        "INFO",
                        "Host SSH "
                        f"route={route_label} retrying once because connection "
                        "failed before remote execution began",
                    )
                elif failure.phase == "command":
                    if not safe_creation_failure or not safe_creation_retry_available:
                        return -1, "", last_error
                    safe_creation_retry_available = False
                    self._schedule_log(
                        "INFO",
                        "Host SSH "
                        f"route={route_label} retrying once because process "
                        "creation failed before remote execution began",
                    )
                elif (
                    failure.phase == "cleanup"
                    or attempt_number >= attempts
                    or isinstance(reported_error, ValueError)
                ):
                    return -1, "", last_error
                if isinstance(reported_error, asyncio.TimeoutError):
                    if (
                        operation.command_deadline is None
                        or loop.time() >= operation.command_deadline
                    ):
                        return (
                            -1,
                            "",
                            f"{last_error} after {timeout_seconds:g}s total",
                        )

                delay = retry_delay_seconds(
                    route_key,
                    attempt_index,
                    cap_seconds=self._retry_backoff_cap,
                )
                operation.phase = "retry_budget"
                retry_deadline = operation.command_deadline or backpressure_deadline
                if retry_deadline - loop.time() <= delay:
                    return (
                        -1,
                        "",
                        "Host SSH "
                        f"route={route_label} phase=retry_budget timed out "
                        f"after {timeout_seconds:g}s; last_error={last_error}",
                    )
                await asyncio.sleep(delay)
        return -1, "", last_error or "Host SSH command failed"

    def _total_timeout_result(
        self,
        *,
        route_label: str,
        phase: str,
        timeout_seconds: float,
    ) -> SSHCommandResult:
        """
        Return the total timeout result.

        The implementation uses ``route_label``, ``phase``, and
        ``timeout_seconds`` to produce the total timeout result.

        Args:
            route_label: Text supplied as route label in the format accepted by
                this function.
            phase: Text supplied as phase in the format accepted by this
                function.
            timeout_seconds: Maximum duration in seconds allowed for timeout
                seconds.

        Returns:
            A tuple containing ``total timeout result value 1``, ``status
            text``, and ``message text`` in that order.
        """
        if phase == "backpressure":
            return (
                -1,
                "",
                "Host SSH "
                f"route={route_label} phase=backpressure timed out after "
                f"{timeout_seconds:g}s waiting for endpoint capacity "
                f"(sessions={self._max_sessions}, "
                f"channels_per_session={self._max_channels})",
            )
        return (
            -1,
            "",
            "Host SSH "
            f"route={route_label} phase={phase} timed out after "
            f"{timeout_seconds:g}s total",
        )

    async def execute(
        self,
        *,
        endpoint_key: EndpointKey,
        route_key: RouteKey,
        route_label: str,
        connect: ConnectionFactory,
        run: CommandRunner,
        timeout_seconds: float,
        max_attempts: int,
    ) -> SSHCommandResult:
        """
        Execute one isolated command channel within a total time budget.

        The implementation uses ``endpoint_key``, ``route_key``,
        ``route_label``, ``connect``, and ``run`` to execute one isolated
        command channel within a total time budget. Terminal status is emitted
        only after one isolated command channel within a total time budget and
        its owned cleanup have completed. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            endpoint_key: Validated remote resource identifier used for endpoint
                key.
            route_key: Stable route key used for lookup and operator-facing
                diagnostics.
            route_label: Text supplied as route label in the format accepted by
                this function.
            connect: Connect consumed while the function attempts to execute one
                isolated command channel within a total time budget.
            run: Run consumed while the function attempts to execute one
                isolated command channel within a total time budget.
            timeout_seconds: Maximum duration in seconds allowed for timeout
                seconds.
            max_attempts: Upper bound enforced for max attempts; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            A tuple containing ``execute value 1``, ``status text``, and
            ``message text`` in that order.
        """

        attempts = max(0, int(max_attempts))
        if attempts == 0:
            return (
                -1,
                "",
                f"Host SSH route={route_label} phase=connect has zero allowed attempts",
            )
        if not self._accepting:
            return (
                -1,
                "",
                f"Host SSH route={route_label} phase=shutdown rejected new command",
            )

        route = self._get_route(endpoint_key, route_key, route_label, connect)
        endpoint = route.endpoint
        try:
            self._begin_operation(route)
        except HostSSHPoolShutdown:
            return (
                -1,
                "",
                f"Host SSH route={route_label} phase=shutdown rejected new command",
            )

        loop = asyncio.get_running_loop()
        timeout_seconds = max(0.0, float(timeout_seconds))
        backpressure_timeout_seconds = (
            timeout_seconds
            if self._backpressure_timeout is None
            else max(0.0, float(self._backpressure_timeout))
        )
        backpressure_deadline = loop.time() + backpressure_timeout_seconds
        # A connect failure is proven to precede remote execution. Reserve one
        # additional command budget for that narrowly admitted retry while
        # retaining a finite outer owner for cancellation-suppressing clients.
        overall_deadline = backpressure_deadline + timeout_seconds * (
            1 + HOST_SSH_SAFE_CONNECT_RETRIES
        )
        operation = _OperationState()
        try:
            task = asyncio.create_task(
                self._execute_operation(
                    route=route,
                    route_key=route_key,
                    route_label=route_label,
                    run=run,
                    timeout_seconds=timeout_seconds,
                    backpressure_timeout_seconds=backpressure_timeout_seconds,
                    attempts=attempts,
                    backpressure_deadline=backpressure_deadline,
                    operation=operation,
                ),
                name="host-ssh-operation",
            )
        except BaseException:
            self._end_operation(route)
            raise

        self._operation_tasks.add(task)
        task.add_done_callback(
            lambda completed: self._observe_operation_task(route, completed)
        )

        try:
            remaining = max(0.0, overall_deadline - loop.time())
            done, _pending = await asyncio.wait({task}, timeout=remaining)
        except BaseException:
            # Cancellation is requested but never awaited here. A coroutine
            # which suppresses it keeps its pool-owned permit and lease until
            # the child task actually settles.
            task.cancel()
            raise

        if task in done:
            return task.result()

        task.cancel()
        self._increment_metric("command_failures")
        result = self._total_timeout_result(
            route_label=route_label,
            phase=operation.phase,
            timeout_seconds=(
                backpressure_timeout_seconds
                if operation.phase == "backpressure"
                else timeout_seconds * (1 + HOST_SSH_SAFE_CONNECT_RETRIES)
            ),
        )
        self._schedule_log("WARNING", result[2])
        return result

    def _claim_shutdown_closes(
        self,
        endpoints: list[_EndpointState],
        errors: list[BaseException],
    ) -> list[asyncio.Task[None]]:
        """
        Return the claim shutdown closes.

        A prior operation reported the failure. This shutdown pass owns the
        exact retry instead of losing the resource.

        Args:
            endpoints: Validated remote resource identifier used for endpoints.
            errors: Entries supplied as ``errors`` without transferring
                container ownership.

        Returns:
            The claim shutdown closes returned in operation-defined order, or
            ``None`` when the requested value is unavailable.
        """
        tasks: list[asyncio.Task[None]] = []
        for endpoint in endpoints:
            for session in list(endpoint.sessions):
                if session.close_error is not None and not session.close_error_reported:
                    session.close_error_reported = True
                    errors.append(session.close_error)
                    continue
                if session.close_error is not None:
                    # A prior operation reported the failure. This shutdown
                    # pass owns the exact retry instead of losing the resource.
                    session.close_error = None
                    session.close_error_reported = False
                if session.status == "open":
                    session.status = "retiring"
                task = self._claim_session_close_now(
                    endpoint,
                    session,
                    force=True,
                )
                if task is not None:
                    tasks.append(task)
        return list(dict.fromkeys(tasks))

    @staticmethod
    def _authoritative_error(errors: list[BaseException]) -> BaseException:
        """
        Return the authoritative error.

        After applying local validation, the function forwards ``errors`` to
        ``next`` and preserves its return and exception contract.

        Args:
            errors: Entries supplied as ``errors`` without transferring
                container ownership.

        Returns:
            A ``BaseException`` describing authoritative error.
        """
        return next((error for error in errors if _is_control_flow(error)), errors[0])

    def _record_new_close_errors(
        self,
        endpoints: list[_EndpointState],
        errors: list[BaseException],
    ) -> None:
        """
        Record new close errors.

        The implementation uses ``endpoints`` and ``errors`` to record new close
        errors. The operation mutates ``errors`` in place; ownership of those
        objects remains with the caller.

        Args:
            endpoints: Validated remote resource identifier used for endpoints.
            errors: Entries supplied as ``errors`` without transferring
                container ownership.
        """
        for endpoint in endpoints:
            for session in endpoint.sessions:
                if session.close_error is None or session.close_error_reported:
                    continue
                session.close_error_reported = True
                errors.append(session.close_error)

    def _prune_closed_endpoints(self) -> None:
        """
        Prune closed endpoints.

        The implementation uses current instance state to prune closed
        endpoints.
        """
        for endpoint in list(self._endpoints.values()):
            if endpoint.operations or endpoint.sessions:
                continue
            for route in list(endpoint.routes):
                self._prune_route_now(route)
            self._prune_endpoint_now(endpoint)

    async def close(self) -> None:
        """
        Reject work, bound draining, and never cancel an external caller task.

        The implementation uses current instance state to reject work, bound
        draining, and never cancel an external caller task. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind. It updates ``_accepting`` on the instance as
        part of that state transition.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to reject work, bound draining, and never cancel an
                external caller task.
        """

        async with self._close_lock:
            self._accepting = False
            endpoints = list(self._endpoints.values())
            if not endpoints:
                self._destroy_credential_fingerprint_key()
                return

            loop = asyncio.get_running_loop()
            deadline = loop.time() + self._shutdown_timeout
            for endpoint in endpoints:
                endpoint.closed = True
                self._schedule_notify(endpoint)

            errors: list[BaseException] = []
            try:
                remaining = max(0.0, deadline - loop.time())
                async with asyncio.timeout(remaining):
                    await asyncio.gather(
                        *(endpoint.drained.wait() for endpoint in endpoints)
                    )
            except asyncio.TimeoutError:
                errors.append(
                    RuntimeError(
                        "Host SSH pool shutdown timed out while draining commands"
                    )
                )
            except BaseException as error:
                errors.append(error)

            close_tasks = self._claim_shutdown_closes(endpoints, errors)
            if close_tasks:
                remaining = max(0.0, deadline - loop.time())
                try:
                    _done, pending = await asyncio.wait(
                        close_tasks,
                        timeout=remaining,
                    )
                    if pending:
                        errors.append(
                            RuntimeError(
                                "Host SSH pool shutdown timed out while closing transports"
                            )
                        )
                except BaseException as error:
                    errors.append(error)

            self._record_new_close_errors(endpoints, errors)
            self._prune_closed_endpoints()

            if not self._endpoints:
                self._destroy_credential_fingerprint_key()
            if errors:
                raise self._authoritative_error(errors)
