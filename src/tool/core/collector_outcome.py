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
Canonical collector outcome types and the legacy service-result boundary.

Transport and service implementations currently return dictionaries with a small
set of conventional fields plus collector-specific data. This module provides
one typed interpretation of those results while retaining a lossless legacy
dictionary representation for existing consumers.

The boundary maps structured exception, status, code, and diagnostic signals
into the canonical taxonomy. Empty success is a separate, fail-closed catalog
policy: a collector must produce output or satisfy its explicit valid-empty
condition before a success is published.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Optional

from .finalization_receipt import sanitize_finalization_message


class CollectorOutcomeState(str, Enum):
    """
    Canonical collector lifecycle and terminal result states.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"
    DEGRADED = "degraded"
    PARTIAL = "partial"
    ERROR = "error"
    CANCELLED = "cancelled"


class CollectorFailureCategory(str, Enum):
    """
    Canonical actionable collector failure categories.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    TIMEOUT = "timeout"
    DEPENDENCY_MISSING = "dependency-missing"
    AUTH_FAILURE = "auth-failure"
    TRANSPORT_FAILURE = "transport-failure"
    PARSER_FAILURE = "parser-failure"
    DATA_QUALITY = "data-quality"
    INTERNAL_ERROR = "internal-error"


class CollectorOutcomeService(str, Enum):
    """
    Collector services whose boundary outcomes are normalized.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    REDFISH = "redfish"
    SSH = "ssh"
    HOST = "host"
    IPMI = "ipmi"
    HEALTH_CHECK = "health_check"


def extract_operation_accounting(
    context: Any,
    status: str,
    reason: str,
    *,
    additional_contexts: Iterable[Any] = (),
) -> tuple[int, int, list[str]]:
    """
    Return status-consistent counts from current and accumulated context.

    Finalization hooks often carry a shallow validation or post-processing
    tally, while the logger has already accumulated the richer execution result.
    Treat every supplied root and its direct ``*_result`` mappings as candidates
    so all metadata and error-artifact projections can select the same
    accounting.

    Args:
        context: Runtime context carrying state shared across this operation.
        status: Text supplied as status in the format accepted by this function.
        reason: Text supplied as reason in the format accepted by this function.
        additional_contexts: Entries supplied as ``additional_contexts`` without
            transferring container ownership.

    Returns:
        A tuple containing ``successful``, ``total``, and ``all errors`` in that
        order.
    """

    roots = [context, *additional_contexts]
    candidates: list[tuple[Mapping[str, Any], bool]] = []
    for root_value in roots:
        root = root_value if isinstance(root_value, Mapping) else {}
        candidates.append((root, True))
        candidates.extend(
            (value, False)
            for key, value in root.items()
            if isinstance(key, str)
            and key.endswith("_result")
            and isinstance(value, Mapping)
        )

    def _as_count(value: Any) -> int:
        """
        Return the as count.

        The implementation uses ``value`` to produce the as count.

        Args:
            value: Value evaluated while performing as count.

        Returns:
            The numeric as count.
        """
        if isinstance(value, bool):
            return 0
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return 0

    def _as_errors(value: Any) -> list[str]:
        """
        Return the as errors.

        The implementation uses ``value`` to produce the as errors.

        Args:
            value: Value evaluated while performing as errors.

        Returns:
            The as errors returned in operation-defined order.
        """
        if isinstance(value, (list, tuple)):
            return [str(item) for item in value if item]
        return [str(value)] if value else []

    accounting = []
    all_errors: list[str] = []
    normalized_status = str(status).lower()
    for candidate, is_root in candidates:
        successful = _as_count(candidate.get("successful_operations", 0))
        total = _as_count(candidate.get("total_operations", 0))
        errors = _as_errors(candidate.get("error_messages", []))
        for error in errors:
            if error not in all_errors:
                all_errors.append(error)
        candidate_status = candidate.get("status")
        if is_root and not candidate_status:
            candidate_status = candidate.get("execution_stage_status")
        accounting.append(
            {
                "successful": successful,
                "total": total,
                "status": str(candidate_status).lower(),
                "incomplete": total > successful,
            }
        )

    # For degraded/partial/error results, status-matching incomplete stage evidence
    # is more authoritative than a larger, successful validation tally.
    matching_incomplete = [
        item
        for item in accounting
        if item["status"] == normalized_status and item["incomplete"]
    ]
    matching = [item for item in accounting if item["status"] == normalized_status]
    incomplete = [item for item in accounting if item["incomplete"]]
    candidates_by_relevance = (
        matching_incomplete or matching or incomplete or accounting
    )
    selected = max(
        candidates_by_relevance,
        key=lambda item: (item["total"], item["successful"]),
    )
    successful = selected["successful"]
    total = selected["total"]
    successful = min(successful, total) if total else successful

    # A non-success result with no operation accounting still establishes one
    # failed operation.  Do not, however, manufacture a second operation for an
    # explicit N/N result: a parent target can complete and persist usable data
    # while a nested member fails, so ``partial`` with 1/1 parent targets is
    # truthful accounting (the nested failure remains in ``error_messages``).
    if normalized_status in {"degraded", "error", "partial"} and total == 0:
        successful = 0
        total = 1
    structured_conditions = extract_collector_outcome_details(
        context,
        additional_contexts=additional_contexts,
    )
    if (
        normalized_status in {"degraded", "error", "partial"}
        and not all_errors
        and not (
            normalized_status in {"degraded", "partial"}
            and structured_conditions is not None
            and structured_conditions.get("category")
            == CollectorFailureCategory.DATA_QUALITY.value
        )
    ):
        all_errors = [reason or f"Collector completed with status {normalized_status}"]
    return successful, total, all_errors


_STATUS_ALIASES = {
    "pass": CollectorOutcomeState.SUCCESS,
    "complete": CollectorOutcomeState.SUCCESS,
    "completed": CollectorOutcomeState.SUCCESS,
    "fail": CollectorOutcomeState.ERROR,
    "failed": CollectorOutcomeState.ERROR,
    "not_ran": CollectorOutcomeState.SKIPPED,
    "canceled": CollectorOutcomeState.CANCELLED,
    "interrupted": CollectorOutcomeState.CANCELLED,
}

_SERVICE_ALIASES = {
    "bmc-ssh": CollectorOutcomeService.SSH,
    "bmc_ssh": CollectorOutcomeService.SSH,
    "health-check": CollectorOutcomeService.HEALTH_CHECK,
    "healthcheck": CollectorOutcomeService.HEALTH_CHECK,
}

_TIMEOUT_PATTERN = re.compile(
    r"\b(?:timeout|timed\s+out|deadline\s+exceeded)\b", re.IGNORECASE
)
_DEPENDENCY_PATTERN = re.compile(
    r"\b(?:no\s+module\s+named|module\s+not\s+found|"
    r"missing\s+(?:required\s+)?dependenc(?:y|ies)|command\s+not\s+found|"
    r"not\s+installed)\b",
    re.IGNORECASE,
)
_AUTH_PATTERN = re.compile(
    r"\b(?:unauthorized|forbidden|authentication\s+(?:failed|failure)|"
    r"authorization\s+(?:failed|failure)|permission\s+denied|access\s+denied|"
    r"invalid\s+(?:user\s*name|credentials?|password)|"
    r"password\s+verification\s+failed|insufficient\s+privilege(?:\s+level)?|"
    r"rakp[^\n]*invalid)\b",
    re.IGNORECASE,
)
_PARSER_PATTERN = re.compile(
    r"\b(?:(?:parse|decode)(?:r|d|ing)?\s+(?:error|failed|failure)|"
    r"failed\s+to\s+(?:parse|decode)|could\s+not\s+be\s+decoded|"
    r"(?:invalid|malformed)\s+(?:json|yaml|xml|csv)|"
    r"jsondecodeerror|yaml\s+error)\b",
    re.IGNORECASE,
)
_TRANSPORT_PATTERN = re.compile(
    r"\b(?:connection\s+(?:refused|reset|lost|closed)|"
    r"unable\s+to\s+(?:connect|establish)|unreachable|no\s+route\s+to\s+host|"
    r"network\s+(?:error|failure|unreachable)|broken\s+pipe|"
    r"remote\s+(?:host\s+)?disconnected|rmcp\+?\s+session)\b",
    re.IGNORECASE,
)
_UNSUPPORTED_PATTERN = re.compile(
    r"\b(?:unsupported|not\s+supported|not\s+implemented|method\s+not\s+allowed)\b",
    re.IGNORECASE,
)
_DEGRADED_PATTERN = re.compile(r"\bdegraded\b", re.IGNORECASE)
_HTTP_STATUS_PATTERN = re.compile(r"\bHTTP\s+(?P<status>\d{3})\b", re.IGNORECASE)

_TIMEOUT_EXCEPTION_NAMES = {
    "asynciotimeouterror",
    "servertimeouterror",
    "timeouterror",
}
_DEPENDENCY_EXCEPTION_NAMES = {
    "distributionnotfound",
    "importerror",
    "modulenotfounderror",
}
_AUTH_EXCEPTION_NAMES = {
    "authenticationerror",
    "autherror",
    "clientauthenticationerror",
    "permissiondenied",
    "permissionerror",
}
_PARSER_EXCEPTION_NAMES = {
    "decodeerror",
    "jsondecodeerror",
    "markedyamlerror",
    "parsererror",
    "scannererror",
    "unicodeerror",
    "unicodedecodeerror",
    "yamlerror",
}
_TRANSPORT_EXCEPTION_NAMES = {
    "brokenpipeerror",
    "channelopenerror",
    "clientconnectionerror",
    "clientconnectorerror",
    "connectionabortederror",
    "connectionclosed",
    "connectionerror",
    "connectionlost",
    "connectionrefusederror",
    "connectionreseterror",
    "disconnecterror",
    "serverdisconnectederror",
}

_SUCCESSFUL_STAGE_STATUSES = frozenset(
    {"complete", "completed", "executed", "pass", "passed", "success"}
)
_VALID_OUTCOME_STAGES = frozenset(
    {"validation", "discovery", "execution", "post_processing"}
)
_SUCCESS_ONLY_REASONS = frozenset(
    {
        "complete",
        "completed",
        "completed successfully",
        "ok",
        "pass",
        "passed",
        "success",
        "successful",
    }
)

VALID_NOT_APPLICABLE_SKIP_CLASSIFICATION = "valid_not_applicable"


def is_valid_not_applicable_skip(status: Any, context: Any) -> bool:
    """
    Return whether a skipped result proves that its capability is not applicable.

    The classification is explicit and machine-readable. Human-readable reason
    text and the broader ``intentional_evidence_only_skip`` marker are not
    sufficient because they also describe runtime skips that can leave required
    work incomplete.

    Args:
        status: Candidate terminal collector status.
        context: Candidate result context carrying the skip classification.

    Returns:
        ``True`` only for a skipped result with the canonical
        ``valid_not_applicable`` classification.
    """

    return (
        str(getattr(status, "value", status)).strip().casefold() == "skipped"
        and isinstance(context, Mapping)
        and context.get("skip_classification")
        == VALID_NOT_APPLICABLE_SKIP_CLASSIFICATION
    )


_FAILURE_REASON_BY_STATUS = {
    "degraded": "Collector completed in a degraded state",
    "partial": "Collector completed with partial results",
    "error": "Collector execution failed",
    "fail": "Collector execution failed",
    "failed": "Collector execution failed",
}
_CATEGORIZABLE_STATES = frozenset(
    {
        CollectorOutcomeState.DEGRADED,
        CollectorOutcomeState.PARTIAL,
        CollectorOutcomeState.ERROR,
    }
)
_OUTCOME_DETAILS_SCHEMA_VERSION = "1.0"
_OUTCOME_DETAILS_CONDITION_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_OUTCOME_DETAILS_ATTRIBUTE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_OUTCOME_DETAILS_MAX_MESSAGES = 32
_OUTCOME_DETAILS_MAX_ATTRIBUTES = 32
_OUTCOME_DETAILS_MAX_ATTRIBUTE_ITEMS = 32
_OUTCOME_ATTRIBUTE_OMITTED = object()
_OUTCOME_DETAILS_CONTEXT_KEYS = (
    "execution_result",
    "discovery_result",
    "validation_result",
    "post_processing_result",
)
_EMPTY_SUCCESS_POLICY_STATES = frozenset({CollectorOutcomeState.SUCCESS})
_VALID_EMPTY_POLICY_KEYS = frozenset(
    {
        "reason_regex",
        "required_stages",
        "require_no_errors",
        "require_output_evidence",
    }
)


def normalize_terminal_collector_reason(status: Any, reason: Any) -> str:
    """
    Prevent failure states from carrying a blank/success-only reason.

    This is a shared authority-boundary rule for tracker, collector envelope,
    timing, and execution-summary projections. Meaningful diagnostic text is
    retained byte-for-byte; only absent or exact success-only phrases are
    replaced.

    Args:
        status: Status consumed while the function attempts to prevent failure
            states from carrying a blank/success-only reason.
        reason: Reason consumed while the function attempts to prevent failure
            states from carrying a blank/success-only reason.

    Returns:
        The canonical terminal collector reason text.
    """

    status_value = str(getattr(status, "value", status) or "").strip().casefold()
    reason_value = reason if isinstance(reason, str) else ""
    canonical_failure_reason = _FAILURE_REASON_BY_STATUS.get(status_value)
    if canonical_failure_reason is None:
        return reason_value
    success_only = " ".join(reason_value.split()).strip(" .!").casefold()
    if not success_only or success_only in _SUCCESS_ONLY_REASONS:
        return canonical_failure_reason
    return reason_value


def sanitize_terminal_collector_reason(
    status: Any,
    reason: Any,
    *,
    sanitizer: Optional[Callable[[str], Any]] = None,
) -> str:
    """
    Return one bounded, scrubbed terminal reason without inventing success text.

    Collector result surfaces share this projection so a credential-like value,
    embedded control whitespace, or oversized diagnostic cannot disagree between
    the result dictionary, status snapshots, summaries, and report manifest.
    Empty success/state-only reasons remain empty for backward compatibility.

    Args:
        status: Status consumed while the function attempts to produce one
            bounded, scrubbed terminal reason without inventing success text.
        reason: Reason consumed while the function attempts to produce one
            bounded, scrubbed terminal reason without inventing success text.
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.

    Returns:
        The canonical terminal collector reason text.
    """

    normalized = normalize_terminal_collector_reason(status, reason)
    if not normalized:
        return ""
    return sanitize_finalization_message(normalized, sanitizer=sanitizer)


def _enum_text(value: Any) -> Optional[str]:
    """
    Return normalized text from a string or string-valued enum.

    The implementation uses ``value`` to produce normalized text from a string
    or string-valued enum.

    Args:
        value: Value evaluated while performing normalized text from a string or
            string-valued enum.

    Returns:
        Whether the normalized text from a string or string-valued enum
        operation succeeds.
    """

    try:
        enum_value = getattr(value, "value", value)
    except Exception:
        return None
    if not isinstance(enum_value, str):
        return None
    normalized = enum_value.strip().lower()
    return normalized or None


def _canonical_state(status: Any) -> CollectorOutcomeState:
    """
    Interpret a legacy status without altering its public representation.

    Existing status tracking treats unknown completion states as errors. The
    source status remains untouched in ``legacy_result`` for compatibility.

    Args:
        status: Status consumed while the function attempts to interpret a
            legacy status without altering its public representation.

    Returns:
        A ``CollectorOutcomeState`` representing canonical state.
    """

    normalized = _enum_text(status)
    if normalized in _STATUS_ALIASES:
        return _STATUS_ALIASES[normalized]
    if normalized is not None:
        try:
            return CollectorOutcomeState(normalized)
        except ValueError:
            pass

    # Existing status tracking treats unknown completion states as errors.  The
    # source status remains untouched in ``legacy_result`` for compatibility.
    return CollectorOutcomeState.ERROR


def _canonical_service(value: Any) -> Optional[CollectorOutcomeService]:
    """
    Normalize a service name while keeping unknown extensions unclassified.

    The implementation uses ``value`` to normalize a service name while keeping
    unknown extensions unclassified. The source value keeps its ownership while
    the normalized representation is returned separately.

    Args:
        value: Value evaluated while performing service name while keeping
            unknown extensions unclassified.

    Returns:
        A ``CollectorOutcomeService`` representing canonical service, or
        ``None`` when the requested value is unavailable.
    """

    if isinstance(value, CollectorOutcomeService):
        return value
    normalized = _enum_text(value)
    if normalized in _SERVICE_ALIASES:
        return _SERVICE_ALIASES[normalized]
    if normalized is not None:
        try:
            return CollectorOutcomeService(normalized)
        except ValueError:
            pass
    return None


def _canonical_failure_category(value: Any) -> Optional[CollectorFailureCategory]:
    """
    Interpret an explicitly supplied category without inferring one.

    ``failure_category`` is now a reserved public contract field. Unknown
    extension values remain in the immutable input view but are not promoted
    into the canonical/public projection.

    Args:
        value: Value evaluated while performing interpret an explicitly supplied
            category without inferring one.

    Returns:
        A ``CollectorFailureCategory`` representing canonical failure category,
        or ``None`` when the requested value is unavailable.
    """

    if isinstance(value, CollectorFailureCategory):
        return value
    normalized = _enum_text(value)
    if normalized is None:
        return None
    try:
        return CollectorFailureCategory(normalized.replace("_", "-"))
    except ValueError:
        # ``failure_category`` is now a reserved public contract field. Unknown
        # extension values remain in the immutable input view but are not
        # promoted into the canonical/public projection.
        return None


def normalize_collector_failure_category(status: Any, value: Any) -> Optional[str]:
    """
    Return a public canonical category only for a failure-bearing state.

    The implementation uses ``status`` and ``value`` to produce a public
    canonical category only for a failure-bearing state.

    Args:
        status: Status consumed while the function attempts to produce a public
            canonical category only for a failure-bearing state.
        value: Value evaluated while performing public canonical category only
            for a failure-bearing state.

    Returns:
        The canonical collector failure category text, or ``None`` when the
        requested value is unavailable.
    """

    if _canonical_state(status) not in _CATEGORIZABLE_STATES:
        return None
    category = _canonical_failure_category(value)
    return category.value if category is not None else None


def _project_outcome_attribute_value(
    value: Any,
    *,
    sanitizer: Optional[Callable[[str], Any]] = None,
) -> Any:
    """
    Return one bounded JSON-safe outcome attribute value.

    Outcome attributes are portable diagnostic facts rather than an arbitrary
    collector-context escape hatch. Scalar values and bounded scalar sequences
    are retained; nested mappings, non-finite numbers, and extension objects are
    omitted so public status documents remain bounded and deterministic.

    Args:
        value: Candidate scalar or scalar sequence supplied by a collector.
        sanitizer: Sanitizer applied to strings before they enter public
            reporting metadata.

    Returns:
        A JSON-safe scalar or list, or ``None`` when ``value`` is outside the
        portable outcome-details contract. A caller-supplied ``None`` is also a
        valid scalar and is therefore returned unchanged.
    """

    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else _OUTCOME_ATTRIBUTE_OMITTED
    if isinstance(value, str):
        return sanitize_finalization_message(value, sanitizer=sanitizer)
    if isinstance(value, (list, tuple)):
        if len(value) > _OUTCOME_DETAILS_MAX_ATTRIBUTE_ITEMS:
            return _OUTCOME_ATTRIBUTE_OMITTED
        projected_items = []
        for item in value:
            projected = _project_outcome_attribute_value(item, sanitizer=sanitizer)
            if projected is _OUTCOME_ATTRIBUTE_OMITTED or isinstance(projected, list):
                return _OUTCOME_ATTRIBUTE_OMITTED
            projected_items.append(projected)
        return projected_items
    return _OUTCOME_ATTRIBUTE_OMITTED


def project_collector_outcome_details(
    value: Any,
    *,
    sanitizer: Optional[Callable[[str], Any]] = None,
) -> Optional[dict[str, Any]]:
    """
    Return one bounded public projection of structured outcome details.

    Any collector may author this contract in its standardized result context.
    The projection validates a stable condition identifier, a canonical failure
    category, bounded diagnostic messages, and optional flat attributes. It
    deliberately ignores arbitrary neighboring service context and malformed
    values so reporting never serializes recursive objects, credentials, or
    unbounded payloads by accident.

    Args:
        value: Candidate outcome-details mapping supplied by a collector.
        sanitizer: Sanitizer applied to message and string-attribute values
            before they enter public reporting metadata.

    Returns:
        A detached JSON-safe outcome-details mapping, or ``None`` when the
        candidate does not satisfy the shared contract.
    """

    if not isinstance(value, Mapping):
        return None
    if value.get("schema_version") != _OUTCOME_DETAILS_SCHEMA_VERSION:
        return None
    category = _canonical_failure_category(value.get("category"))
    condition = value.get("condition")
    messages = value.get("messages")
    attributes = value.get("attributes", {})
    if (
        category is None
        or not isinstance(condition, str)
        or _OUTCOME_DETAILS_CONDITION_PATTERN.fullmatch(condition) is None
        or not isinstance(messages, (list, tuple))
        or not messages
        or len(messages) > _OUTCOME_DETAILS_MAX_MESSAGES
        or not isinstance(attributes, Mapping)
        or len(attributes) > _OUTCOME_DETAILS_MAX_ATTRIBUTES
    ):
        return None

    projected_messages = [
        sanitize_finalization_message(message, sanitizer=sanitizer)
        for message in messages
    ]
    projected_attributes: dict[str, Any] = {}
    for key, attribute_value in attributes.items():
        if (
            not isinstance(key, str)
            or _OUTCOME_DETAILS_ATTRIBUTE_PATTERN.fullmatch(key) is None
        ):
            continue
        projected_value = _project_outcome_attribute_value(
            attribute_value,
            sanitizer=sanitizer,
        )
        if projected_value is not _OUTCOME_ATTRIBUTE_OMITTED:
            projected_attributes[key] = projected_value

    return {
        "schema_version": _OUTCOME_DETAILS_SCHEMA_VERSION,
        "category": category.value,
        "condition": condition,
        "messages": projected_messages,
        "attributes": projected_attributes,
    }


def extract_collector_outcome_details(
    context: Any,
    *,
    additional_contexts: Iterable[Any] = (),
    sanitizer: Optional[Callable[[str], Any]] = None,
) -> Optional[dict[str, Any]]:
    """
    Find the first valid structured outcome-details record at known boundaries.

    The aggregate context is authoritative, followed by direct stage-result
    contexts in execution-first order. Only fixed field names and one nesting
    level are inspected; arbitrary collector payloads are never traversed.

    Args:
        context: Primary aggregate or service-result context.
        additional_contexts: Additional aggregate contexts considered after the
            primary value without transferring ownership.
        sanitizer: Sanitizer applied when projecting public message text.

    Returns:
        The first valid detached outcome-details mapping, or ``None`` when none
        of the known boundaries contains one.
    """

    for root_value in (context, *additional_contexts):
        if not isinstance(root_value, Mapping):
            continue
        candidates = [root_value]
        candidates.extend(
            nested
            for key in _OUTCOME_DETAILS_CONTEXT_KEYS
            if isinstance((nested := root_value.get(key)), Mapping)
        )
        for candidate in candidates:
            projected = project_collector_outcome_details(
                candidate.get("outcome_details"),
                sanitizer=sanitizer,
            )
            if projected is not None:
                return projected
    return None


def _result_context(result: Mapping[str, Any]) -> Mapping[str, Any]:
    """
    Return the conventional context mapping when one is present.

    The implementation uses ``result`` to produce the conventional context
    mapping when one is present.

    Args:
        result: Mapping supplying fields for conventional context mapping when
            one is present.

    Returns:
        A mapping containing result context.
    """

    context = result.get("context")
    return context if isinstance(context, Mapping) else {}


def _first_value(result: Mapping[str, Any], *keys: str) -> Any:
    """
    Read a known field from the result or its conventional context.

    The implementation uses ``result`` and ``keys`` to read a known field from
    the result or its conventional context. Parsing or I/O must finish before
    the validated representation is made available to the caller.

    Args:
        result: Mapping supplying fields for known field from the result or its
            conventional context.
        keys: Additional positional values forwarded in caller-provided order.

    Returns:
        The first value selected by the operation.
    """

    context = _result_context(result)
    for source in (result, context):
        for key in keys:
            if key in source:
                return source[key]
    return None


def _integer_code(value: Any) -> Optional[int]:
    """
    Return a non-boolean integer code from a legacy scalar.

    After applying local validation, the function forwards ``value`` to ``int``
    and preserves its return and exception contract.

    Args:
        value: Value evaluated while performing non-boolean integer code from a
            legacy scalar.

    Returns:
        The numeric integer code value, or ``None`` when the requested value is
        unavailable.
    """

    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _safe_text(value: Any) -> str:
    """
    Stringify one diagnostic value without making classification disruptive.

    The implementation uses ``value`` to stringify one diagnostic value without
    making classification disruptive.

    Args:
        value: Value evaluated while performing stringify one diagnostic value
            without making classification disruptive.

    Returns:
        The canonical safe text.
    """

    try:
        return str(value)[:4096]
    except Exception:
        return ""


def _known_diagnostic_text(result: Mapping[str, Any]) -> str:
    """
    Join bounded, known diagnostic fields without scanning arbitrary payloads.

    After applying local validation, the function forwards ``result`` to
    ``join`` and preserves its return and exception contract.

    Args:
        result: Mapping supplying fields for join bounded, known diagnostic
            fields without scanning arbitrary payloads.

    Returns:
        The canonical known diagnostic text.
    """

    context = _result_context(result)
    values = []
    for source in (result, context):
        for key in ("reason", "error", "message", "stderr", "exception_message"):
            value = source.get(key)
            if value is not None:
                values.append(_safe_text(value))
        error_messages = source.get("error_messages")
        if isinstance(error_messages, (list, tuple)):
            values.extend(_safe_text(value) for value in error_messages[:32])
    return "\n".join(values)


def _exception_category_from_name(
    exception_name: Any,
) -> Optional[CollectorFailureCategory]:
    """
    Map a serialized exception class name from a legacy result context.

    The implementation uses ``exception_name`` to map a serialized exception
    class name from a legacy result context.

    Args:
        exception_name: Stable exception name used for lookup and
            operator-facing diagnostics.

    Returns:
        A ``CollectorFailureCategory`` representing exception category from
        name, or ``None`` when the requested value is unavailable.
    """

    normalized = _enum_text(exception_name)
    if normalized in _TIMEOUT_EXCEPTION_NAMES:
        return CollectorFailureCategory.TIMEOUT
    if normalized in _DEPENDENCY_EXCEPTION_NAMES:
        return CollectorFailureCategory.DEPENDENCY_MISSING
    if normalized in _AUTH_EXCEPTION_NAMES:
        return CollectorFailureCategory.AUTH_FAILURE
    if normalized in _PARSER_EXCEPTION_NAMES:
        return CollectorFailureCategory.PARSER_FAILURE
    if normalized in _TRANSPORT_EXCEPTION_NAMES:
        return CollectorFailureCategory.TRANSPORT_FAILURE
    return None


def _http_outcome(
    status_code: Optional[int],
) -> tuple[Optional[CollectorOutcomeState], Optional[CollectorFailureCategory]]:
    """
    Map a structured HTTP status without inspecting response text.

    The implementation uses ``status_code`` to map a structured HTTP status
    without inspecting response text.

    Args:
        status_code: Numeric status code used while the operation performs
            bounded accounting.

    Returns:
        A tuple containing ``optional[collector outcome state]`` and
        ``optional[collector failure category]`` in that order.
    """

    if status_code in {405, 501}:
        return CollectorOutcomeState.UNSUPPORTED, None
    if status_code in {401, 403}:
        return None, CollectorFailureCategory.AUTH_FAILURE
    if status_code in {408, 504}:
        return None, CollectorFailureCategory.TIMEOUT
    if status_code is not None and 400 <= status_code <= 599:
        return None, CollectorFailureCategory.TRANSPORT_FAILURE
    return None, None


def _exception_outcome(
    exception: Optional[BaseException],
    service: Optional[CollectorOutcomeService],
) -> tuple[Optional[CollectorOutcomeState], Optional[CollectorFailureCategory]]:
    """
    Map a live boundary exception using stable Python and class-name signals.

    The implementation uses ``exception`` and ``service`` to map a live boundary
    exception using stable Python and class-name signals.

    Args:
        exception: Exception associated with the operation's failure path.
        service: Service consumed while the function attempts to map a live
            boundary exception using stable Python and class-name signals.

    Returns:
        A tuple containing ``optional[collector outcome state]`` and
        ``optional[collector failure category]`` in that order.
    """

    if exception is None:
        return None, None
    if isinstance(exception, NotImplementedError):
        return CollectorOutcomeState.UNSUPPORTED, None
    if isinstance(exception, TimeoutError):
        return None, CollectorFailureCategory.TIMEOUT
    if isinstance(exception, (ModuleNotFoundError, ImportError, FileNotFoundError)):
        return None, CollectorFailureCategory.DEPENDENCY_MISSING
    if isinstance(exception, PermissionError):
        return None, CollectorFailureCategory.AUTH_FAILURE
    if isinstance(exception, UnicodeError):
        return None, CollectorFailureCategory.PARSER_FAILURE
    if isinstance(exception, ConnectionError):
        return None, CollectorFailureCategory.TRANSPORT_FAILURE

    try:
        status_code = _integer_code(getattr(exception, "status", None))
    except Exception:
        status_code = None
    state, category = _http_outcome(status_code)
    if state is not None or category is not None:
        return state, category

    exception_names = {
        cls.__name__.strip().lower() for cls in type(exception).__mro__ if cls.__name__
    }
    for name in exception_names:
        category = _exception_category_from_name(name)
        if category is not None:
            return None, category

    if isinstance(exception, OSError) and service in {
        CollectorOutcomeService.REDFISH,
        CollectorOutcomeService.SSH,
        CollectorOutcomeService.IPMI,
    }:
        return None, CollectorFailureCategory.TRANSPORT_FAILURE
    return None, CollectorFailureCategory.INTERNAL_ERROR


def _has_missing_dependency(result: Mapping[str, Any]) -> bool:
    """
    Return True for structured required-dependency failures.

    The implementation uses ``result`` to produce True for structured
    required-dependency failures.

    Args:
        result: Mapping supplying fields for true for structured
            required-dependency failures.

    Returns:
        Whether the true for structured required-dependency failures operation
        succeeds.
    """

    missing = _first_value(result, "missing_required")
    if isinstance(missing, (list, tuple, set, dict, str)) and bool(missing):
        return True
    dependency_result = _first_value(result, "dependency_result")
    return bool(
        isinstance(dependency_result, Mapping)
        and _enum_text(dependency_result.get("status")) in {"fail", "failed", "error"}
        and dependency_result.get("missing_required")
    )


def _has_true_flag(result: Mapping[str, Any], *keys: str) -> bool:
    """
    Check explicit boolean flags at the result/context boundary.

    After applying local validation, the function forwards ``result`` and
    ``keys`` to ``any`` and preserves its return and exception contract. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        result: Mapping supplying fields for explicit boolean flags at the
            result/context boundary.
        keys: Additional positional values forwarded in caller-provided order.

    Returns:
        Whether the explicit boolean flags at the result/context boundary
        operation succeeds.
    """

    context = _result_context(result)
    return any(source.get(key) is True for source in (result, context) for key in keys)


def _classify_result(
    result: Mapping[str, Any],
    *,
    service_name: Any = None,
    stage: Optional[str] = None,
    exception: Optional[BaseException] = None,
) -> tuple[
    CollectorOutcomeState,
    Optional[CollectorFailureCategory],
    Optional[CollectorOutcomeService],
]:
    """
    Return the typed state, category, and service for one boundary result.

    The implementation uses ``result``, ``service_name``, ``stage``, and
    ``exception`` to produce the typed state, category, and service for one
    boundary result.

    Args:
        result: Mapping supplying fields for typed state, category, and service
            for one boundary result.
        service_name: Stable service name used for lookup and operator-facing
            diagnostics.
        stage: Optional stage; ``None`` selects the function's default behavior.
        exception: Exception associated with the operation's failure path.

    Returns:
        A tuple containing ``state``, ``optional[collector failure category]``,
        and ``service`` in that order.
    """

    context = _result_context(result)
    effective_status = result.get("status")
    if "status" not in result:
        success = result.get("success")
        if success is True:
            effective_status = "success"
        elif success is False:
            effective_status = "error"
        else:
            effective_status = "skipped"

    state = _canonical_state(effective_status)
    service = _canonical_service(
        service_name
        or result.get("service_name")
        or context.get("service_name")
        or result.get("transport")
        or context.get("transport")
    )

    category_supplied = "failure_category" in result
    category = _canonical_failure_category(result.get("failure_category"))
    if category_supplied:
        return (
            state,
            category if state in _CATEGORIZABLE_STATES else None,
            service,
        )

    exception_state, exception_category = _exception_outcome(exception, service)
    if exception_state is not None:
        state = exception_state
    if exception_category is not None:
        return state, exception_category, service

    outcome_details = extract_collector_outcome_details(context)
    if outcome_details is not None and state in _CATEGORIZABLE_STATES:
        detail_category = _canonical_failure_category(outcome_details.get("category"))
        if detail_category is not None:
            return state, detail_category, service

    failure_like = result.get("success") is False or state in {
        CollectorOutcomeState.ERROR,
        CollectorOutcomeState.PARTIAL,
        CollectorOutcomeState.DEGRADED,
        CollectorOutcomeState.UNSUPPORTED,
    }
    if not failure_like:
        return state, None, service

    status_code = _integer_code(
        _first_value(result, "http_status", "status_code", "response_status")
    )
    diagnostic_text = _known_diagnostic_text(result)
    if status_code is None and service is CollectorOutcomeService.REDFISH:
        http_match = _HTTP_STATUS_PATTERN.search(diagnostic_text)
        if http_match:
            status_code = _integer_code(http_match.group("status"))
    http_state, http_category = _http_outcome(status_code)
    if http_state is not None:
        state = http_state
    if http_category is not None:
        return state, http_category, service

    if (
        _has_missing_dependency(result)
        or _integer_code(_first_value(result, "return_code", "exit_code", "rc")) == 127
    ):
        return state, CollectorFailureCategory.DEPENDENCY_MISSING, service

    serialized_exception_category = _exception_category_from_name(
        _first_value(result, "exception_type")
    )
    if serialized_exception_category is not None:
        return state, serialized_exception_category, service

    unsupported = _has_true_flag(
        result,
        "unsupported",
        "not_supported",
        "catalog_transport_unsupported",
    ) or bool(_UNSUPPORTED_PATTERN.search(diagnostic_text))
    degraded = _has_true_flag(result, "degraded") or bool(
        _DEGRADED_PATTERN.search(diagnostic_text)
    )
    if unsupported:
        state = CollectorOutcomeState.UNSUPPORTED
    elif degraded and state in {
        CollectorOutcomeState.ERROR,
        CollectorOutcomeState.PARTIAL,
    }:
        state = CollectorOutcomeState.DEGRADED

    if _TIMEOUT_PATTERN.search(diagnostic_text):
        category = CollectorFailureCategory.TIMEOUT
    elif _DEPENDENCY_PATTERN.search(diagnostic_text):
        category = CollectorFailureCategory.DEPENDENCY_MISSING
    elif _AUTH_PATTERN.search(diagnostic_text):
        category = CollectorFailureCategory.AUTH_FAILURE
    elif _PARSER_PATTERN.search(diagnostic_text) or (
        stage == "post_processing" and "parse" in diagnostic_text.lower()
    ):
        category = CollectorFailureCategory.PARSER_FAILURE
    elif _TRANSPORT_PATTERN.search(diagnostic_text):
        category = CollectorFailureCategory.TRANSPORT_FAILURE
    elif state in {
        CollectorOutcomeState.ERROR,
        CollectorOutcomeState.PARTIAL,
        CollectorOutcomeState.DEGRADED,
    }:
        category = CollectorFailureCategory.INTERNAL_ERROR

    return state, category, service


@dataclass(frozen=True, slots=True)
class CollectorOutcome:
    """
    Typed interpretation of a collector result with lossless compatibility.

    The immutable record keeps ``state``, ``reason``, ``failure_category``,
    ``service``, and ``legacy_result`` together so consumers observe one
    collector outcome state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        state: Canonical state exposed to downstream status consumers.
        reason: Canonical reason exposed to downstream status consumers.
        failure_category: Failure category retained as part of the record's
            public state.
        service: Service retained as part of the record's public state.
        legacy_result: Mapping that retains the legacy result fields for this
            record.
    """

    state: CollectorOutcomeState
    reason: str
    failure_category: Optional[CollectorFailureCategory]
    service: Optional[CollectorOutcomeService]
    legacy_result: Mapping[str, Any] = field(repr=False, compare=False)

    def to_legacy_result(self) -> dict[str, Any]:
        """
        Return the additive, legacy-compatible public result dictionary.

        Existing fields retain their representation. ``failure_category`` is a
        reserved optional v1 projection: emit only a canonical value for a
        failure-bearing outcome and otherwise omit it, including when input
        carried a stale or invalid provisional value.

        Returns:
            The validated ``result``.
        """

        result = dict(self.legacy_result)
        result.pop("failure_category", None)
        if self.failure_category is not None and self.state in _CATEGORIZABLE_STATES:
            result["failure_category"] = self.failure_category.value
        return result


def _has_output_files(result: Mapping[str, Any]) -> bool:
    """
    Return whether the compatibility result reports collected output.

    The implementation uses ``result`` to determine whether the compatibility
    result reports collected output.

    Args:
        result: Mapping supplying fields for compatibility result reports
            collected output.

    Returns:
        Whether the compatibility result reports collected output.
    """

    if "output_files" in result:
        output_files = result.get("output_files")
        return bool(isinstance(output_files, (list, tuple, set)) and any(output_files))
    context_output = _result_context(result).get("output_files")
    return bool(isinstance(context_output, (list, tuple, set)) and any(context_output))


def _has_reported_errors(result: Mapping[str, Any]) -> bool:
    """
    Fail closed when aggregate or per-stage context reports an error.

    The implementation uses ``result`` to fail closed when aggregate or
    per-stage context reports an error.

    Args:
        result: Mapping supplying fields for fail closed when aggregate or
            per-stage context reports an error.

    Returns:
        Whether the fail closed when aggregate or per-stage context reports an
        error operation succeeds.
    """

    context = _result_context(result)
    candidates: list[Mapping[str, Any]] = [context]
    candidates.extend(
        value
        for key, value in context.items()
        if isinstance(key, str)
        and key.endswith("_result")
        and isinstance(value, Mapping)
    )
    execution_summary = context.get("execution_summary")
    if isinstance(execution_summary, Mapping):
        candidates.append(execution_summary)

    for candidate in candidates:
        error_count = candidate.get("error_count")
        if isinstance(error_count, bool):
            if error_count:
                return True
        elif isinstance(error_count, int) and error_count > 0:
            return True
        elif error_count not in (None, 0):
            return True

        for key in ("error_messages", "error_details", "errors"):
            if key in candidate and bool(candidate.get(key)):
                return True
    return False


def _stage_status(result: Mapping[str, Any], stage: str) -> Optional[str]:
    """
    Read one stage status from runtime or status-document context.

    After applying local validation, the function forwards ``result`` and
    ``stage`` to ``_enum_text`` and preserves its return and exception contract.
    Parsing or I/O must finish before the validated representation is made
    available to the caller.

    Args:
        result: Mapping supplying fields for one stage status from runtime or
            status-document context.
        stage: Text supplied as stage in the format accepted by this function.

    Returns:
        The canonical stage status, or ``None`` when the requested value is
        unavailable.
    """

    context = _result_context(result)
    stage_result = context.get(f"{stage}_result")
    if not isinstance(stage_result, Mapping):
        stages = context.get("stages")
        if isinstance(stages, Mapping):
            stage_result = stages.get(stage)
    if not isinstance(stage_result, Mapping):
        return None
    return _enum_text(stage_result.get("status"))


def _valid_empty_rejection(result: Mapping[str, Any], policy: Any) -> Optional[str]:
    """
    Return the fail-closed reason, or ``None`` when policy evidence passes.

    The implementation uses ``result`` and ``policy`` to produce the fail-closed
    reason, or ``None`` when policy evidence passes.

    Args:
        result: Mapping supplying fields for fail-closed reason, or ``None``
            when policy evidence passes.
        policy: Policy governing fail-closed reason, or ``None`` when policy
            evidence passes.

    Returns:
        The canonical valid empty rejection text, or ``None`` when the requested
        value is unavailable.
    """

    if not isinstance(policy, Mapping):
        return "collector catalog has no valid-empty policy"
    condition = policy.get("valid_empty")
    if not isinstance(condition, Mapping):
        return "collector catalog has no valid-empty policy"
    if set(condition) != _VALID_EMPTY_POLICY_KEYS:
        return "collector catalog valid-empty policy has an invalid schema"

    reason_regex = condition.get("reason_regex")
    required_stages = condition.get("required_stages")
    require_no_errors = condition.get("require_no_errors")
    require_output_evidence = condition.get("require_output_evidence")
    if (
        not isinstance(reason_regex, str)
        or not reason_regex
        or len(reason_regex) > 4096
        or not isinstance(required_stages, list)
        or not required_stages
        or any(
            not isinstance(stage, str) or stage not in _VALID_OUTCOME_STAGES
            for stage in required_stages
        )
        or len(set(required_stages)) != len(required_stages)
        or require_no_errors is not True
        or not isinstance(require_output_evidence, bool)
    ):
        return "collector catalog valid-empty policy has an invalid schema"

    try:
        reason_matches = re.fullmatch(reason_regex, _safe_text(result.get("reason")))
    except re.error:
        return "collector catalog valid-empty policy has an invalid reason regex"
    if reason_matches is None:
        return "result reason does not satisfy the catalog valid-empty policy"
    if _has_reported_errors(result):
        return "collector reported errors during an otherwise empty result"
    for stage in required_stages:
        if _stage_status(result, stage) not in _SUCCESSFUL_STAGE_STATUSES:
            return f"{stage} stage is not proven successful"
    if require_output_evidence:
        return "required empty-result evidence was not produced"
    return None


def enforce_empty_success_policy(
    outcome: CollectorOutcome, policy: Any
) -> CollectorOutcome:
    """
    Reject silent empty success unless an explicit catalog condition passes.

    Results with output retain their historical dictionary unchanged. A typed
    intentional evidence-only skip also remains skipped: its strict marker
    records that execution was deliberately not attempted, so it is not an
    empty success. Only a true empty success requires the catalog's valid-empty
    policy; partial, degraded, and ordinary skipped outcomes retain their
    established accounting. A rejected empty success changes only the existing
    success/status/reason values; it does not add a public result field.

    Args:
        outcome: Outcome object whose ``legacy_result``, ``service``, ``state``,
            and ``to_legacy_result`` state is read while performing silent empty
            success unless an explicit catalog condition passes.
        policy: Policy governing silent empty success unless an explicit catalog
            condition passes.

    Returns:
        A ``CollectorOutcome`` representing enforce empty success policy.
    """

    context = outcome.legacy_result.get("context")
    intentional_evidence_only_skip = (
        outcome.state is CollectorOutcomeState.SKIPPED
        and isinstance(context, Mapping)
        and context.get("intentional_evidence_only_skip") is True
    )
    if (
        outcome.state not in _EMPTY_SUCCESS_POLICY_STATES
        or _has_output_files(outcome.legacy_result)
        or intentional_evidence_only_skip
    ):
        return outcome

    rejection = _valid_empty_rejection(outcome.legacy_result, policy)
    if rejection is None:
        return outcome

    result = outcome.to_legacy_result()
    if "success" in result:
        result["success"] = False
    result["status"] = "error"
    result["reason"] = (
        f"Empty success rejected by collector outcome policy: {rejection}"
    )
    return _build_outcome(result, service_name=outcome.service)


def _build_outcome(
    result: dict[str, Any],
    *,
    service_name: Any = None,
    stage: Optional[str] = None,
    exception: Optional[BaseException] = None,
) -> CollectorOutcome:
    """
    Build the immutable typed view over one compatibility dictionary.

    After applying local validation, the function forwards ``result``,
    ``service_name``, ``stage``, and ``exception`` to ``CollectorOutcome`` and
    preserves its return and exception contract.

    Args:
        result: Mapping supplying fields for immutable typed view over one
            compatibility dictionary.
        service_name: Stable service name used for lookup and operator-facing
            diagnostics.
        stage: Optional stage; ``None`` selects the function's default behavior.
        exception: Exception associated with the operation's failure path.

    Returns:
        A ``CollectorOutcome`` representing outcome.
    """

    state, category, service = _classify_result(
        result,
        service_name=service_name,
        stage=stage,
        exception=exception,
    )
    reason_value = result.get("reason", "")
    if "reason" not in result and state is CollectorOutcomeState.ERROR:
        reason_value = result.get("error", "")
    reason = "" if reason_value is None else str(reason_value)
    return CollectorOutcome(
        state=state,
        reason=reason,
        failure_category=category,
        service=service,
        legacy_result=MappingProxyType(result),
    )


def classify_collector_outcome(
    raw: Mapping[str, Any],
    *,
    service_name: Any = None,
    stage: Optional[str] = None,
    exception: Optional[BaseException] = None,
) -> CollectorOutcome:
    """
    Classify a boundary result without adding, removing, or rewriting fields.

    After applying local validation, the function forwards ``raw``,
    ``service_name``, ``stage``, and ``exception`` to ``_build_outcome`` and
    preserves its return and exception contract.

    Args:
        raw: Mapping supplying fields for classify a boundary result without
            adding, removing, or rewriting fields.
        service_name: Stable service name used for lookup and operator-facing
            diagnostics.
        stage: Optional stage; ``None`` selects the function's default behavior.
        exception: Exception associated with the operation's failure path.

    Returns:
        A ``CollectorOutcome`` representing classify collector outcome.
    """

    return _build_outcome(
        dict(raw),
        service_name=service_name,
        stage=stage,
        exception=exception,
    )


def normalize_collector_result(
    raw: Optional[Mapping[str, Any]],
    *,
    service_name: Any = None,
    stage: Optional[str] = None,
    exception: Optional[BaseException] = None,
) -> CollectorOutcome:
    """
    Normalize one transport/service result into the canonical outcome type.

    The compatibility dictionary deliberately matches the historical
    ``ExecutionEngine._normalize_result`` behavior, including strict identity
    checks for the legacy ``success`` boolean and preservation of explicit
    status, reason, timing, and extension fields.

    Args:
        raw: Mapping supplying fields for one transport/service result into the
            canonical outcome type.
        service_name: Stable service name used for lookup and operator-facing
            diagnostics.
        stage: Optional stage; ``None`` selects the function's default behavior.
        exception: Exception associated with the operation's failure path.

    Returns:
        A ``CollectorOutcome`` representing collector result.
    """

    if raw is None:
        result: dict[str, Any] = {
            "status": "error",
            "reason": "Empty result",
            "execution_time": 0.0,
        }
    else:
        result = dict(raw)

        if "status" not in result:
            success_flag = result.get("success")
            if success_flag is True:
                result["status"] = "success"
            elif success_flag is False:
                result["status"] = "error"
            else:
                result["status"] = "skipped"
        if "execution_time" not in result:
            result["execution_time"] = 0.0
        if "reason" not in result:
            if result.get("status") == "error" and "error" in result:
                result["reason"] = str(result["error"])
            else:
                result["reason"] = ""
        result.setdefault("execution_started", True)

    return _build_outcome(
        result,
        service_name=service_name,
        stage=stage,
        exception=exception,
    )


__all__ = [
    "CollectorFailureCategory",
    "CollectorOutcome",
    "CollectorOutcomeService",
    "CollectorOutcomeState",
    "classify_collector_outcome",
    "enforce_empty_success_policy",
    "extract_collector_outcome_details",
    "extract_operation_accounting",
    "normalize_collector_result",
    "normalize_collector_failure_category",
    "normalize_terminal_collector_reason",
    "project_collector_outcome_details",
    "sanitize_terminal_collector_reason",
]
