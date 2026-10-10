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
Pure policy and immutable records for standardized collector results.

``BaseService`` remains the compatibility facade and continues to own logging,
collector identity, and async orchestration. This module owns only deterministic
status selection, result assembly, accounting normalization, and error-message
formatting. Explicit adapters return the historical mutable dictionaries while
keeping caller-owned inputs and immutable records isolated from later mutation.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any, Literal, Mapping, Optional, Sequence, Union, cast

from ..core.collector_outcome import CollectorOutcomeState, _canonical_state

ResultScalar = Union[str, int, float, bool, bytes, None]
_OVERRIDE_STATUSES = frozenset({"skipped", "degraded", "partial", "error", "success"})


@dataclass(frozen=True, slots=True)
class _FrozenResultSequence:
    """
    Immutable snapshot of a legacy sequence value.

    The immutable record keeps ``kind`` and ``values`` together so consumers
    observe one frozen result sequence state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        kind: Container-kind discriminator; accepted values are ``'list',
            'tuple'``.
        values: Values retained by the snapshot in the source sequence's order.
    """

    kind: Literal["list", "tuple"]
    values: tuple["FrozenResultValue", ...]


@dataclass(frozen=True, slots=True)
class _FrozenResultMapping:
    """
    Immutable insertion-ordered snapshot of a legacy mapping value.

    The immutable record keeps ``items`` together so consumers observe one
    frozen result mapping state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        items: Key/value pairs retained by the snapshot in insertion order.
    """

    items: tuple[tuple["FrozenResultValue", "FrozenResultValue"], ...]


@dataclass(frozen=True, slots=True)
class _FrozenResultSet:
    """
    Immutable snapshot of a legacy set value.

    The immutable record keeps ``kind`` and ``values`` together so consumers
    observe one frozen result set state. Consumers receive the fields as one
    unit instead of assembling partial state.

    Attributes:
        kind: Container-kind discriminator; accepted values are ``'set',
            'frozenset'``.
        values: Frozen set members retained by the snapshot without mutable
            aliases.
    """

    kind: Literal["set", "frozenset"]
    values: tuple["FrozenResultValue", ...]


@dataclass(frozen=True, slots=True)
class _FrozenByteArray:
    """
    Immutable snapshot retaining the legacy ``bytearray`` shape.

    The immutable record keeps ``value`` together so consumers observe one
    frozen byte array state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        value: Bounded byte sequence retained as value.
    """

    value: bytes


@dataclass(frozen=True, slots=True)
class _FrozenOpaqueValue:
    """
    Detached snapshot for uncommon non-container extension values.

    The immutable record keeps ``value`` together so consumers observe one
    frozen opaque value state. Consumers receive the fields as one unit instead
    of assembling partial state.

    Attributes:
        value: Value retained as part of the record's public state.
    """

    value: Any = field(repr=False, compare=False)


FrozenResultValue = Union[
    ResultScalar,
    _FrozenResultSequence,
    _FrozenResultMapping,
    _FrozenResultSet,
    _FrozenByteArray,
    _FrozenOpaqueValue,
]


def _freeze_result_value(
    value: Any,
    active_containers: Optional[set[int]] = None,
) -> FrozenResultValue:
    """
    Detach and recursively freeze one value from a legacy result.

    Mutable containers are copied recursively into frozen record types while a
    stack of object identities rejects cycles. Scalar values retain their value,
    and uncommon extension objects are detached with a deep copy.

    Args:
        value: Value object whose ``items`` state is read while performing
            detach and recursively freeze one value from a legacy result.
        active_containers: Object identities on the current recursion stack;
            ``None`` starts a new cycle check.

    Returns:
        An immutable snapshot of ``value`` detached from mutable caller-owned
        containers.

    Raises:
        ValueError: If collector result values must not contain cycles.
    """

    if isinstance(value, (str, int, float, bool, bytes)) or value is None:
        return value
    if isinstance(value, bytearray):
        return _FrozenByteArray(bytes(value))

    if active_containers is None:
        active_containers = set()
    marker = id(value)
    if marker in active_containers:
        raise ValueError("Collector result values must not contain cycles")

    active_containers.add(marker)
    try:
        if isinstance(value, Mapping):
            return _FrozenResultMapping(
                items=tuple(
                    (
                        _freeze_result_value(key, active_containers),
                        _freeze_result_value(item, active_containers),
                    )
                    for key, item in value.items()
                )
            )
        if isinstance(value, (list, tuple)):
            return _FrozenResultSequence(
                kind="list" if isinstance(value, list) else "tuple",
                values=tuple(
                    _freeze_result_value(item, active_containers) for item in value
                ),
            )
        if isinstance(value, (set, frozenset)):
            return _FrozenResultSet(
                kind="set" if isinstance(value, set) else "frozenset",
                values=tuple(
                    _freeze_result_value(item, active_containers) for item in value
                ),
            )
    finally:
        active_containers.remove(marker)

    # Extension values have historically been retained in collector contexts.
    # Deep copies preserve that public shape without retaining caller aliases.
    return _FrozenOpaqueValue(copy.deepcopy(value))


def _thaw_result_value(value: FrozenResultValue) -> Any:
    """
    Return a detached value in its historical mutable facade shape.

    Each frozen record is rebuilt in its original list, tuple, set, mapping,
    bytearray, or opaque shape. The reconstruction never returns a mutable
    object retained by the snapshot.

    Args:
        value: Value object whose ``items``, ``kind``, ``value``, and ``values``
            state is read while performing detached value in its historical
            mutable facade shape.

    Returns:
        A detached legacy value restored in its original container or scalar
        shape.
    """

    if isinstance(value, _FrozenResultMapping):
        return {
            _thaw_result_value(key): _thaw_result_value(item)
            for key, item in value.items
        }
    if isinstance(value, _FrozenResultSequence):
        sequence_items = tuple(_thaw_result_value(item) for item in value.values)
        return list(sequence_items) if value.kind == "list" else sequence_items
    if isinstance(value, _FrozenResultSet):
        set_items = frozenset(_thaw_result_value(item) for item in value.values)
        return set(set_items) if value.kind == "set" else set_items
    if isinstance(value, _FrozenByteArray):
        return bytearray(value.value)
    if isinstance(value, _FrozenOpaqueValue):
        return copy.deepcopy(value.value)
    return value


def _freeze_mapping(value: Mapping[str, Any]) -> _FrozenResultMapping:
    """
    Freeze one mapping into an immutable result snapshot.

    The mapping is recursively detached with the same cycle checks as other
    result values. A type guard ensures callers cannot receive a non-mapping
    snapshot.

    Args:
        value: Mapping supplying fields for freeze one mapping into an immutable
            result snapshot.

    Returns:
        An immutable mapping snapshot detached from caller-owned values.

    Raises:
        TypeError: If expected a mapping.
    """
    frozen = _freeze_result_value(value)
    if not isinstance(frozen, _FrozenResultMapping):  # pragma: no cover - typing guard
        raise TypeError("expected a mapping")
    return frozen


def _mapping_get(
    mapping: _FrozenResultMapping,
    key: str,
    default: FrozenResultValue = None,
) -> FrozenResultValue:
    """
    Return the mapping get.

    The implementation uses ``mapping``, ``key``, and ``default`` to produce the
    mapping get.

    Args:
        mapping: Mapping supplying fields for mapping get.
        key: Stable key used for lookup and operator-facing diagnostics.
        default: Fallback used when the requested value is absent or invalid.

    Returns:
        A ``FrozenResultValue`` representing mapping get.
    """
    for frozen_key, value in mapping.items:
        if frozen_key == key:
            return value
    return default


@dataclass(frozen=True, slots=True)
class CollectorResultRequest:
    """
    Immutable input snapshot for one standardized result decision.

    The immutable record keeps ``successful_operations``, ``total_operations``,
    ``operation_name``, and ``accounting_warning`` together so consumers observe
    one collector result request state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        successful_operations: Number of successful operations represented by
            this record.
        total_operations: Number of total operations represented by this record.
        operation_name: Canonical text used as operation name.
        accounting_warning: Canonical text used as accounting warning.
    """

    successful_operations: int
    total_operations: int
    operation_name: str
    _output_files: _FrozenResultSequence = field(repr=False)
    _error_messages: _FrozenResultSequence = field(repr=False)
    _additional_context: _FrozenResultMapping = field(repr=False)
    accounting_warning: Optional[str] = None

    def legacy_output_files(self) -> list[Any]:
        """
        Return a fresh legacy output-file list.

        The implementation uses current instance state to produce a fresh legacy
        output-file list. If the function cannot produce a fresh legacy
        output-file list, its exception reaches the caller instead of being
        converted into a successful result.

        Returns:
            The validated ``value``.

        Raises:
            TypeError: If output files snapshot is not a list.
        """

        value = _thaw_result_value(self._output_files)
        if not isinstance(value, list):  # pragma: no cover - construction invariant
            raise TypeError("output files snapshot is not a list")
        return value

    def legacy_error_messages(self) -> list[Any]:
        """
        Return a fresh legacy error-message list.

        The implementation uses current instance state to produce a fresh legacy
        error-message list. If the function cannot produce a fresh legacy
        error-message list, its exception reaches the caller instead of being
        converted into a successful result.

        Returns:
            The validated ``value``.

        Raises:
            TypeError: If error messages snapshot is not a list.
        """

        value = _thaw_result_value(self._error_messages)
        if not isinstance(value, list):  # pragma: no cover - construction invariant
            raise TypeError("error messages snapshot is not a list")
        return value

    def legacy_additional_context(self) -> dict[Any, Any]:
        """
        Return a fresh legacy additional-context dictionary.

        The implementation uses current instance state to produce a fresh legacy
        additional-context dictionary. If the function cannot produce a fresh
        legacy additional-context dictionary, its exception reaches the caller
        instead of being converted into a successful result.

        Returns:
            The validated ``value``.

        Raises:
            TypeError: If additional context snapshot is not a dictionary.
        """

        value = _thaw_result_value(self._additional_context)
        if not isinstance(value, dict):  # pragma: no cover - construction invariant
            raise TypeError("additional context snapshot is not a dictionary")
        return value


@dataclass(frozen=True, slots=True)
class CollectorStatusRecord:
    """
    Immutable status-policy result before collector context is assembled.

    The immutable record keeps ``success``, ``status``, and ``reason`` together
    so consumers observe one collector status state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        success: Success retained as part of the record's public state.
        status: Canonical status exposed to downstream status consumers.
        reason: Canonical reason exposed to downstream status consumers.
    """

    success: FrozenResultValue
    status: FrozenResultValue
    reason: FrozenResultValue
    _context: FrozenResultValue = field(repr=False)


@dataclass(frozen=True, slots=True)
class CollectorResultRecord:
    """
    Immutable standardized collector result before legacy adaptation.

    The immutable record keeps ``success``, ``status``, and ``reason`` together
    so consumers observe one collector result state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        success: Success retained as part of the record's public state.
        status: Canonical status exposed to downstream status consumers.
        reason: Canonical reason exposed to downstream status consumers.
    """

    success: FrozenResultValue
    status: FrozenResultValue
    reason: FrozenResultValue
    _context: _FrozenResultMapping = field(repr=False)


def collector_status_to_legacy_dict(
    status: CollectorStatusRecord,
) -> dict[str, Any]:
    """
    Return a fresh dictionary matching the historical status shape.

    The implementation uses ``status`` to produce a fresh dictionary matching
    the historical status shape.

    Args:
        status: Status object whose ``_context``, ``reason``, ``status``, and
            ``success`` state is read while performing fresh dictionary matching
            the historical status shape.

    Returns:
        A mapping containing the ``success``, ``status``, ``reason``, and
        ``context`` fields.
    """

    return {
        "success": _thaw_result_value(status.success),
        "status": _thaw_result_value(status.status),
        "reason": _thaw_result_value(status.reason),
        "context": _thaw_result_value(status._context),
    }


def collector_result_to_legacy_dict(
    result: CollectorResultRecord,
) -> dict[str, Any]:
    """
    Return a fresh dictionary matching the historical collector result shape.

    The implementation uses ``result`` to produce a fresh dictionary matching
    the historical collector result shape. If the function cannot produce a
    fresh dictionary matching the historical collector result shape, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        result: Result object whose ``_context``, ``reason``, ``status``, and
            ``success`` state is read while performing fresh dictionary matching
            the historical collector result shape.

    Returns:
        A mapping containing the ``success``, ``status``, ``reason``, and
        ``context`` fields.

    Raises:
        TypeError: If collector result context is not a dictionary.
    """

    context = _thaw_result_value(result._context)
    if not isinstance(context, dict):  # pragma: no cover - construction invariant
        raise TypeError("collector result context is not a dictionary")
    return {
        "success": _thaw_result_value(result.success),
        "status": _thaw_result_value(result.status),
        "reason": _thaw_result_value(result.reason),
        "context": context,
    }


def extract_http_error_message(http_error: str) -> str:
    """
    Extract the legacy readable message from one HTTP error string.

    The implementation uses ``http_error`` to extract the legacy readable
    message from one HTTP error string.

    Args:
        http_error: Text supplied as HTTP error in the format accepted by this
            function.

    Returns:
        The canonical HTTP error message.
    """

    try:
        if '"message":' in http_error:
            json_start = http_error.find("{")
            if json_start != -1:
                json_part = http_error[json_start:]
                brace_count = 0
                json_end = 0
                for index, character in enumerate(json_part):
                    if character == "{":
                        brace_count += 1
                    elif character == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            json_end = index + 1
                            break

                if json_end > 0:
                    json_text = json_part[:json_end]
                    try:
                        error_data = json.loads(json_text)
                        if "error" in error_data and "message" in error_data["error"]:
                            return cast(str, error_data["error"]["message"])
                    except json.JSONDecodeError:
                        pass

        if "ActionParameterValueError" in http_error:
            return "Invalid parameter value in diagnostic request"
        if "ResourceMissingAtURI" in http_error:
            return "Resource not found at specified URI"
        if "AuthenticationRequired" in http_error:
            return "Authentication required"
        return http_error[:100] + "..." if len(http_error) > 100 else http_error
    except Exception:
        return http_error[:100] + "..." if len(http_error) > 100 else http_error


def format_collector_error_messages(
    error_messages: Sequence[str],
    operation_name: str,
    is_partial: bool = False,
) -> str:
    """
    Format collector errors using the historical grouping and wording.

    Identifier-like prefixes name devices: either the first token is an id (e.g.
    "HGX_ERoT_0", "IRoT_HPM_SMA_0 index 50") or the prefix is an "{EntityType}
    {id}" pair (e.g. "Chassis HGX_Chassis_0", "gpu HGX_GPU_SXM_1"). Prose
    prefixes such as "GET request returned no raw content" are not device names
    even when the rest of the message contains an underscore.

    Args:
        error_messages: Entries supplied as ``error_messages`` without
            transferring container ownership.
        operation_name: Stable operation name used for lookup and
            operator-facing diagnostics.
        is_partial: Whether is partial is enabled or required for this
            operation.

    Returns:
        The canonical collector error messages text.
    """

    if not error_messages:
        return f"No specific error messages captured for {operation_name}"

    device_errors: dict[str, list[str]] = {}
    http_errors: dict[str, list[str]] = {}
    other_errors: list[str] = []

    for error_message in error_messages:
        if ": HTTP " in error_message:
            parts = error_message.split(": HTTP ", 1)
            if len(parts) == 2:
                device = parts[0].strip()
                http_error = parts[1].strip()
                http_errors.setdefault(device, []).append(http_error)
            else:  # pragma: no cover - split invariant retained for compatibility
                other_errors.append(error_message)
        elif "_" in error_message and ": " in error_message:
            parts = error_message.split(": ", 1)
            prefix_tokens = parts[0].strip().split()
            # Identifier-like prefixes name devices: either the first token is
            # an id (e.g. "HGX_ERoT_0", "IRoT_HPM_SMA_0 index 50") or the
            # prefix is an "{EntityType} {id}" pair (e.g. "Chassis
            # HGX_Chassis_0", "gpu HGX_GPU_SXM_1"). Prose prefixes such as
            # "GET request returned no raw content" are not device names even
            # when the rest of the message contains an underscore.
            is_device_prefix = bool(prefix_tokens) and (
                "_" in prefix_tokens[0]
                or (
                    len(prefix_tokens) == 2
                    and "_" in prefix_tokens[1]
                    and "/" not in prefix_tokens[1]
                )
            )
            if len(parts) == 2 and is_device_prefix:
                device = parts[0].strip()
                error_detail = parts[1].strip()
                device_errors.setdefault(device, []).append(error_detail)
            else:
                other_errors.append(error_message)
        else:
            other_errors.append(error_message)

    formatted_parts = [
        "Failed operations:" if is_partial else f"All {operation_name} failed. Details:"
    ]

    if http_errors:
        formatted_parts.append("\nHTTP Errors:")
        for device, errors in http_errors.items():
            formatted_parts.append(f"  • {device}:")
            for error in errors:
                if error.startswith("HTTP 400:"):
                    formatted_parts.append(
                        f"    - Bad Request: {extract_http_error_message(error)}"
                    )
                elif error.startswith("HTTP 404:"):
                    formatted_parts.append(
                        f"    - Not Found: {extract_http_error_message(error)}"
                    )
                elif error.startswith("HTTP 500:"):
                    formatted_parts.append(
                        f"    - Server Error: {extract_http_error_message(error)}"
                    )
                else:
                    formatted_parts.append(f"    - {error}")

    if device_errors:
        formatted_parts.append("\nDevice Errors:")
        for device, errors in device_errors.items():
            formatted_parts.append(f"  • {device}:")
            for error in errors:
                formatted_parts.append(f"    - {error}")

    if other_errors:
        formatted_parts.append("\nOther Errors:")
        for error in other_errors:
            formatted_parts.append(f"  • {error}")

    return "\n".join(formatted_parts)


class CollectorResultBuilder:
    """
    Side-effect-free standardized collector result policy.

    The type coordinates ``prepare_request``, ``determine_status``,
    ``status_from_legacy``, ``build_result``, and ``create_result`` and retains
    the state those operations share between calls. Resource ownership remains
    inside the instance until the matching close, exit, or cleanup operation
    completes.
    """

    def prepare_request(
        self,
        successful_operations: int,
        total_operations: int,
        output_files: Optional[Sequence[Any]] = None,
        error_messages: Optional[Sequence[Any]] = None,
        operation_name: str = "operations",
        additional_context: Optional[Mapping[str, Any]] = None,
        *,
        clamp_excess_successes: bool = False,
    ) -> CollectorResultRequest:
        """
        Snapshot inputs and optionally normalize excess-success accounting.

        After applying local validation, the function forwards
        ``successful_operations``, ``total_operations``, ``output_files``,
        ``error_messages``, and ``operation_name`` to ``CollectorResultRequest``
        and preserves its return and exception contract.

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
            clamp_excess_successes: Whether clamp excess successes is enabled or
                required for this operation.

        Returns:
            A ``CollectorResultRequest`` representing prepare request.

        Raises:
            TypeError: If output files snapshot is not a sequence; error
                messages snapshot is not a sequence; or additional context
                snapshot is not a dictionary.
        """

        output_snapshot = _freeze_result_value(list(output_files or []))
        error_snapshot = _freeze_result_value(list(error_messages or []))
        if not isinstance(output_snapshot, _FrozenResultSequence):
            raise TypeError("output files snapshot is not a sequence")
        if not isinstance(error_snapshot, _FrozenResultSequence):
            raise TypeError("error messages snapshot is not a sequence")

        context_snapshot = _freeze_mapping(additional_context or {})
        accounting_warning = None
        normalized_successes = successful_operations
        if clamp_excess_successes and successful_operations > total_operations:
            accounting_warning = (
                "Collector accounting anomaly detected: "
                f"successful_operations ({successful_operations}) exceeds "
                f"total_operations ({total_operations}). Clamping to total_operations."
            )
            mutable_context = _thaw_result_value(context_snapshot)
            if not isinstance(mutable_context, dict):  # pragma: no cover
                raise TypeError("additional context snapshot is not a dictionary")
            mutable_context.setdefault("accounting_warnings", []).append(
                accounting_warning
            )
            context_snapshot = _freeze_mapping(mutable_context)
            normalized_successes = total_operations

        return CollectorResultRequest(
            successful_operations=normalized_successes,
            total_operations=total_operations,
            operation_name=operation_name,
            _output_files=output_snapshot,
            _error_messages=error_snapshot,
            _additional_context=context_snapshot,
            accounting_warning=accounting_warning,
        )

    def determine_status(
        self,
        request: CollectorResultRequest,
    ) -> CollectorStatusRecord:
        """
        Apply the standardized degraded/partial/empty/skipped status policy.

        After applying local validation, the function forwards ``request`` to
        ``CollectorStatusRecord`` and preserves its return and exception
        contract.

        Args:
            request: Transport request governed by the configured authentication
                and trust policy.

        Returns:
            A ``CollectorStatusRecord`` representing determine status.
        """

        successful_operations = request.successful_operations
        total_operations = request.total_operations
        operation_name = request.operation_name
        error_messages = request.legacy_error_messages()
        override_status = _thaw_result_value(
            _mapping_get(request._additional_context, "status")
        )
        accounting_warnings: list[str] = []
        if (
            isinstance(override_status, str)
            and override_status not in _OVERRIDE_STATUSES
        ):
            canonical_override = _canonical_state(override_status).value
            effective_override = (
                canonical_override
                if canonical_override in _OVERRIDE_STATUSES
                else CollectorOutcomeState.ERROR.value
            )
            accounting_warnings.append(
                "Collector status override anomaly detected: "
                f"{override_status!r} normalized to {effective_override!r}."
            )
            override_status = effective_override

        if override_status in _OVERRIDE_STATUSES:
            if (
                override_status in {"success", "skipped", "degraded", "partial"}
                and total_operations > 0
                and successful_operations == 0
            ):
                accounting_warnings.append(
                    "Collector status override anomaly detected: a success-bearing "
                    f"{override_status!r} override reported zero successful operations; "
                    "demoted to 'error'."
                )
                override_status = "error"
            status = override_status
            if override_status == "skipped":
                success = True
                default_reason = f"Collector {operation_name} was skipped"
            elif override_status == "error":
                success = False
                default_reason = format_collector_error_messages(
                    error_messages, operation_name
                )
            elif override_status in {"degraded", "partial"}:
                success = True
                if override_status == "degraded":
                    default_reason = "Usable data collected with degraded results"
                else:
                    default_reason = (
                        f"Partial success: {successful_operations}/{total_operations} "
                        f"{operation_name} succeeded.\n"
                        + format_collector_error_messages(
                            error_messages,
                            operation_name,
                            is_partial=True,
                        )
                    )
            else:
                success = True
                default_reason = (
                    f"Successfully completed {successful_operations}/"
                    f"{total_operations} {operation_name}"
                )
            reason = _mapping_get(
                request._additional_context,
                "reason",
                _freeze_result_value(default_reason),
            )
        elif successful_operations == 0 and total_operations == 0:
            success = True
            status = "skipped"
            reason = _freeze_result_value(
                f"No {operation_name} to perform - collector skipped"
            )
        elif successful_operations == 0:
            success = False
            status = "error"
            reason = _freeze_result_value(
                format_collector_error_messages(error_messages, operation_name)
            )
        elif successful_operations < total_operations:
            success = True
            status = "partial"
            reason = _freeze_result_value(
                f"Partial success: {successful_operations}/{total_operations} "
                f"{operation_name} succeeded.\n"
                + format_collector_error_messages(
                    error_messages,
                    operation_name,
                    is_partial=True,
                )
            )
        else:
            success = True
            status = "success"
            reason = _freeze_result_value(
                f"Successfully completed {successful_operations}/"
                f"{total_operations} {operation_name}"
            )

        return CollectorStatusRecord(
            success=success,
            status=status,
            reason=reason,
            _context=_freeze_result_value(
                {
                    "successful_operations": successful_operations,
                    "total_operations": total_operations,
                    "error_messages": error_messages,
                    **(
                        {"accounting_warnings": accounting_warnings}
                        if accounting_warnings
                        else {}
                    ),
                }
            ),
        )

    def status_from_legacy(
        self,
        status_info: Mapping[str, Any],
    ) -> CollectorStatusRecord:
        """
        Snapshot a historical status dictionary for deterministic assembly.

        After applying local validation, the function forwards ``status_info``
        to ``CollectorStatusRecord`` and preserves its return and exception
        contract.

        Args:
            status_info: Mapping supplying fields for snapshot a historical
                status dictionary for deterministic assembly.

        Returns:
            A ``CollectorStatusRecord`` representing status from legacy.
        """

        return CollectorStatusRecord(
            success=_freeze_result_value(status_info["success"]),
            status=_freeze_result_value(status_info["status"]),
            reason=_freeze_result_value(status_info["reason"]),
            _context=_freeze_result_value(status_info["context"]),
        )

    def build_result(
        self,
        status: CollectorStatusRecord,
        request: CollectorResultRequest,
    ) -> CollectorResultRecord:
        """
        Assemble one immutable result while preserving legacy merge order.

        After applying local validation, the function forwards ``status`` and
        ``request`` to ``CollectorResultRecord`` and preserves its return and
        exception contract.

        Args:
            status: Status object whose ``_context``, ``reason``, ``status``,
                and ``success`` state is read while performing assemble one
                immutable result while preserving legacy merge order.
            request: Transport request governed by the configured authentication
                and trust policy.

        Returns:
            A validated ``CollectorResultRecord`` instance initialized from the
            supplied fields.

        Raises:
            TypeError: If collector result context is not a mapping.
        """

        output_files = request.legacy_output_files()
        status_context = _thaw_result_value(status._context)
        additional_context = request.legacy_additional_context()
        authoritative_context = {
            "total_files": len(output_files),
            "output_files": output_files,
            "successful_operations": status_context["successful_operations"],
            "total_operations": status_context["total_operations"],
            "error_messages": status_context["error_messages"],
        }
        status_extras = {
            key: value
            for key, value in status_context.items()
            if key not in {*authoritative_context, "accounting_warnings"}
        }
        warnings = list(status_context.get("accounting_warnings", []))
        supplied_warnings = additional_context.pop("accounting_warnings", [])
        if isinstance(supplied_warnings, list):
            warnings = [*supplied_warnings, *warnings]
        for key, authoritative_value in authoritative_context.items():
            if (
                key in additional_context
                and additional_context[key] != authoritative_value
            ):
                warnings.append(
                    "Collector accounting anomaly detected: caller-supplied "
                    f"{key} disagrees with authoritative result accounting and was ignored."
                )
            additional_context.pop(key, None)
        supplied_status = additional_context.get("status")
        if (
            isinstance(supplied_status, str)
            and supplied_status not in _OVERRIDE_STATUSES
        ):
            additional_context.pop("status", None)
            warnings.append(
                "Collector status override anomaly detected: unrecognized context "
                f"status {supplied_status!r} was omitted."
            )
        context = {
            **additional_context,
            **status_extras,
            **authoritative_context,
        }
        if warnings:
            context["accounting_warnings"] = warnings
        frozen_context = _freeze_result_value(context)
        if not isinstance(frozen_context, _FrozenResultMapping):
            raise TypeError("collector result context is not a mapping")
        return CollectorResultRecord(
            success=status.success,
            status=status.status,
            reason=status.reason,
            _context=frozen_context,
        )

    def create_result(
        self,
        request: CollectorResultRequest,
    ) -> CollectorResultRecord:
        """
        Determine status and assemble a standardized immutable result.

        After applying local validation, the function forwards ``request`` to
        ``self.build_result`` and preserves its return and exception contract.

        Args:
            request: Transport request governed by the configured authentication
                and trust policy.

        Returns:
            A ``CollectorResultRecord`` returned after determine status and
            assemble a standardized immutable result.
        """

        return self.build_result(self.determine_status(request), request)

    def build_legacy_status_result(
        self,
        status_info: Mapping[str, Any],
        output_files: Optional[Sequence[Any]] = None,
        additional_context: Optional[Mapping[str, Any]] = None,
    ) -> CollectorResultRecord:
        """
        Assemble from the historical split status/result facade arguments.

        After applying local validation, the function forwards ``status_info``,
        ``output_files``, and ``additional_context`` to ``self.build_result``
        and preserves its return and exception contract.

        Args:
            status_info: Mapping supplying fields for assemble from the
                historical split status/result facade arguments.
            output_files: Optional output files; ``None`` selects the function's
                default behavior.
            additional_context: Optional additional context; ``None`` selects
                the function's default behavior.

        Returns:
            A ``CollectorResultRecord`` representing legacy status result.
        """

        request = self.prepare_request(
            successful_operations=0,
            total_operations=0,
            output_files=output_files,
            additional_context=additional_context,
        )
        return self.build_result(self.status_from_legacy(status_info), request)


__all__ = [
    "CollectorResultBuilder",
    "CollectorResultRecord",
    "CollectorResultRequest",
    "CollectorStatusRecord",
    "collector_result_to_legacy_dict",
    "collector_status_to_legacy_dict",
    "extract_http_error_message",
    "format_collector_error_messages",
]
