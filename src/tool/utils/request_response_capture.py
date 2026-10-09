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
Bounded-memory request/response capture spooling.

The collector can receive responses that are hundreds of megabytes and can issue
thousands of requests. Capturing those responses must not create a second
in-memory copy of either an individual response or the complete request list.
This module serializes one record at a time into a private JSONL spool and can
later stream it into a private legacy-envelope candidate. It is the one
canonical capture/attachment seam: it deliberately preserves every append and
does not invent content-based deduplication that could erase retries or other
evidence. A run-owned runtime supplies the only publication-capable sanitizer
policy, bounds blocking work to a validated worker count, and owns deterministic
teardown.

Private storage is not by itself a sanitization attestation. Only a spool made
by the runtime's canonical structural sanitizer receives the unforgeable policy
capability required by publication. A private candidate remains confidential
input until its anonymous verified copy is handed to the atomic publisher.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from concurrent.futures import Future as ConcurrentFuture
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from enum import Enum
from functools import partial
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlsplit, urlunsplit

from .filesystem_identity import filesystem_owner_uid
from .redfish_download import StreamedRedfishBody
from .redfish_limits import (
    DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_ARTIFACT_BYTES,
    DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_FILE_DESCRIPTORS,
    DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_OBJECTS,
    DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_READERS,
    DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_SPOOL_BYTES,
    DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_RECORD_BYTES,
    DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_RECORDS,
    DEFAULT_REDFISH_REQUEST_CAPTURE_MIN_FREE_SPACE_RESERVE_BYTES,
    MAX_SIGNED_64_BIT_INTEGER,
    RedfishRequestCaptureLimits,
)

_COPY_CHUNK_BYTES = 64 * 1024
_DEFAULT_MAX_STRING_CHARS = 256 * 1024
_STRING_PREVIEW_CHARS = 4096
_PRIVATE_KEY_BODY_MAX_CHARS = 64 * 1024
_PRIVATE_KEY_PREVIEW_LOOKAHEAD_CHARS = _PRIVATE_KEY_BODY_MAX_CHARS + 1024
_DEFAULT_MAX_DEPTH = 16
_ENCODED_AUTHORITY_DELIMITER = re.compile(
    r"%(?:25)*(?:23|2f|3f|40|5c)",
    flags=re.IGNORECASE,
)
_OPAQUE_AUTHORITY_PREFIX = re.compile(
    r"^(?:(?:[\\/])|(?:%(?:25)*(?:2f|5c))){2}",
    flags=re.IGNORECASE,
)
_ENCODED_SCHEME_AUTHORITY_PREFIX = re.compile(
    # The percent token is atomic.  Without that boundary, ``%2525`` can be
    # partitioned as both one recursively encoded byte and an encoded byte
    # followed by literal scheme characters, causing exponential backtracking.
    r"^(?:(?>%(?:25)*[0-9a-f]{2})|[a-z0-9+.-]){1,64}?"
    r"(?::|%(?:25)*3a)"
    r"(?:(?:[\\/])|(?:%(?:25)*(?:2f|5c))){2}",
    flags=re.IGNORECASE,
)
_ENCODED_PATH_QUERY_OR_FRAGMENT = re.compile(
    r"%(?:25)*(?:23|3f)",
    flags=re.IGNORECASE,
)
_ENCODED_SENSITIVE_URI_DELIMITER = re.compile(
    r"%(?:25)*(?:23|3f|40)",
    flags=re.IGNORECASE,
)
_TOOL_GENERATED_ODATA_EXPAND_QUERY = re.compile(
    r"\$expand=\*\(\$levels=[1-9][0-9]{0,8}\)\Z"
)
_CAPTURE_TEXT_URI_TOKEN = re.compile(r"[^\s\"'<>),}]+")
_CAPTURE_CAMEL_CASE_NAME_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_CAPTURE_ACRONYM_NAME_BOUNDARY = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")


def _capture_control_flow_priority(error: BaseException) -> int:
    """
    Rank control flow that must win over ordinary capture cleanup errors.

    The implementation uses ``error`` to rank control flow that must win over
    ordinary capture cleanup errors.

    Args:
        error: Exception or failure detail associated with the operation.

    Returns:
        The numeric capture control flow priority value.
    """

    if isinstance(error, (asyncio.CancelledError, KeyboardInterrupt)):
        return 2
    if isinstance(error, SystemExit):
        return 2 if type(error.code) is int and error.code == 130 else 1
    return 0


def _add_capture_note(error: BaseException, note: str) -> None:
    """
    Attach diagnostics without allowing hostile note hooks to alter outcome.

    Notes are evidence only. They must never replace the exact exception
    selected by the control-flow precedence contract.

    Args:
        error: Exception or failure detail associated with the operation.
        note: Text supplied as note in the format accepted by this function.
    """

    try:
        BaseException.add_note(error, note)
    except BaseException:
        # Notes are evidence only. They must never replace the exact exception
        # selected by the control-flow precedence contract.
        pass


def _remember_capture_control_flow(
    current: Optional[BaseException],
    candidate: BaseException,
) -> BaseException:
    """
    Keep the first highest-priority interruption without changing identity.

    The implementation uses ``current`` and ``candidate`` to keep the first
    highest-priority interruption without changing identity. If the function
    cannot keep the first highest-priority interruption without changing
    identity, its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        current: Current consumed while the function attempts to keep the first
            highest-priority interruption without changing identity.
        candidate: Candidate value or resource evaluated by this operation.

    Returns:
        A ``BaseException`` describing remember capture control flow.

    Raises:
        TypeError: If the capture control flow is not an interruption or
            SystemExit.
    """

    candidate_priority = _capture_control_flow_priority(candidate)
    if candidate_priority <= 0:
        raise TypeError("Capture control flow must be an interruption or SystemExit")
    if current is None:
        return candidate
    current_priority = _capture_control_flow_priority(current)
    if candidate_priority > current_priority:
        _add_capture_note(
            candidate,
            "Capture cleanup also observed lower-priority control flow: "
            f"{type(current).__name__}",
        )
        return candidate
    _add_capture_note(
        current,
        f"Capture cleanup also observed control flow: {type(candidate).__name__}",
    )
    return current


def _defer_capture_failure(
    control_flow: Optional[BaseException],
    ordinary_errors: list[BaseException],
    error: BaseException,
) -> Optional[BaseException]:
    """
    Partition one failure while retaining authoritative control flow.

    The implementation uses ``control_flow``, ``ordinary_errors``, and ``error``
    to partition one failure while retaining authoritative control flow. The
    operation mutates ``ordinary_errors`` in place; ownership of those objects
    remains with the caller.

    Args:
        control_flow: Control flow consumed while the function attempts to
            partition one failure while retaining authoritative control flow.
        ordinary_errors: Entries supplied as ``ordinary_errors`` without
            transferring container ownership.
        error: Exception or failure detail associated with the operation.

    Returns:
        A ``BaseException`` describing defer capture failure, or ``None`` when
        the requested value is unavailable.
    """

    if isinstance(error, BaseExceptionGroup):
        for nested_error in error.exceptions:
            control_flow = _defer_capture_failure(
                control_flow, ordinary_errors, nested_error
            )
        return control_flow
    if _capture_control_flow_priority(error) > 0:
        return _remember_capture_control_flow(control_flow, error)
    ordinary_errors.append(error)
    return control_flow


def _raise_capture_cleanup_outcome(
    control_flow: Optional[BaseException],
    ordinary_errors: list[BaseException],
    message: str,
) -> None:
    """
    Raise control flow ahead of cleanup failures after all owners drain.

    The implementation uses ``control_flow``, ``ordinary_errors``, and
    ``message`` to raise control flow ahead of cleanup failures after all owners
    drain. If the function cannot raise control flow ahead of cleanup failures
    after all owners drain, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        control_flow: Control flow consumed while the function attempts to raise
            control flow ahead of cleanup failures after all owners drain.
        ordinary_errors: Entries supplied as ``ordinary_errors`` without
            transferring container ownership.
        message: Operator-facing text carried by the reported event or failure.

    Raises:
        BaseException: If a delegated failure occurs while the function attempts
            to raise control flow ahead of cleanup failures after all owners
            drain.
        Exception: If the function cannot raise control flow ahead of cleanup
            failures after all owners drain safely.
        BaseExceptionGroup: If the function cannot raise control flow ahead of
            cleanup failures after all owners drain safely.
    """

    flattened_errors: list[BaseException] = []
    for error in ordinary_errors:
        control_flow = _defer_capture_failure(control_flow, flattened_errors, error)
    ordinary_errors = flattened_errors
    if control_flow is not None:
        for error in ordinary_errors:
            _add_capture_note(
                control_flow,
                f"{message} also failed with {type(error).__name__}",
            )
        raise control_flow
    if len(ordinary_errors) == 1:
        raise ordinary_errors[0]
    if ordinary_errors:
        raise BaseExceptionGroup(message, ordinary_errors)


class CaptureSanitizationPolicy(str, Enum):
    """
    Runtime-owned canonical capture policies eligible for publication.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    REDFISH_DIAGNOSTIC = "redfish-diagnostic-v1"
    GENERIC_DIAGNOSTIC = "generic-diagnostic-v1"


def _canonical_name_components(name: Any) -> tuple[str, ...]:
    """
    Split one capture field name into canonical semantic components.

    CamelCase, acronym boundaries, punctuation, and ordinary separators all
    produce the same lowercase component representation. This prevents short
    credential markers from matching unrelated substrings while retaining
    common header and snake-case spellings.

    Args:
        name: Field name supplied by an untrusted captured mapping.

    Returns:
        Canonical lowercase name components in source order.
    """

    separated = _CAPTURE_ACRONYM_NAME_BOUNDARY.sub("-", str(name).strip())
    separated = _CAPTURE_CAMEL_CASE_NAME_BOUNDARY.sub("-", separated)
    normalized = re.sub(r"[^a-z0-9]+", "-", separated.casefold()).strip("-")
    return tuple(component for component in normalized.split("-") if component)


def _canonical_sensitive_name(name: Any) -> bool:
    """
    Return the canonical sensitive name.

    Short credential abbreviations must match a complete normalized name
    component. Treating ``key`` or ``auth`` as an arbitrary substring would
    unnecessarily redact benign fields such as ``keyboard`` or ``author``.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.

    Returns:
        Whether the canonical sensitive name operation succeeds.
    """
    raw_name = str(name).strip()
    components = _canonical_name_components(raw_name)
    if raw_name.startswith("#") or components[-1:] in {("uri",), ("url",)}:
        return False

    # Every marker must occupy a complete semantic component. Plural Redfish
    # telemetry such as ``MaxConcurrentSessions`` and ``TokensProcessed`` is
    # therefore retained, while Password, access_token, X-Auth-Session, and
    # equivalent credential fields still fail closed.
    if set(components) & {
        "authorization",
        "cookie",
        "token",
        "secret",
        "apikey",
        "csrf",
        "password",
        "passwd",
        "session",
        "credential",
        "signature",
        "auth",
        "nonce",
        "otp",
        "creds",
        "xsrf",
    }:
        return True

    # A terminal generic key name (for example ``device_key``) and the common
    # credential-key compounds remain sensitive. A non-terminal schema token
    # such as ``KeyUsage`` or ``HotKeySequenceDisplay`` describes behavior,
    # not credential material, and must retain its typed value.
    if components[-1:] == ("key",):
        return True
    credential_key_pairs = {
        ("api", "key"),
        ("access", "key"),
        ("secret", "key"),
        ("private", "key"),
    }
    return any(
        tuple(components[index : index + 2]) in credential_key_pairs
        for index in range(max(0, len(components) - 1))
    )


def _authoritative_sensitive_name(
    external_classifier: Optional[Callable[[str], bool]],
    name: Any,
) -> bool:
    """
    Apply the primary structured-key policy with a fail-closed fallback.

    The logger classifier is authoritative when available because the primary
    JSON writer uses it for exact schema projection. If it is absent, the
    capture boundary retains its independent canonical policy. A classifier
    failure is treated as sensitive so an exceptional sanitizer cannot expose
    a value through diagnostic evidence.

    Args:
        external_classifier: Primary artifact structured-key classifier, or
            ``None`` when no logger sanitizer is available.
        name: Candidate mapping key from captured structured data.

    Returns:
        Whether the corresponding mapping value must be replaced.
    """

    if external_classifier is None:
        return _canonical_sensitive_name(name)
    try:
        # The primary structured-artifact classifier is authoritative when it
        # is available. Combining it with the capture fallback would reclassify
        # schema fields such as KeyUsage and HotKeySequenceDisplay, causing the
        # diagnostic response to diverge from the published primary artifact.
        return bool(external_classifier(str(name)))
    except Exception:
        return True


def _canonical_uri_name(name: Any) -> bool:
    """
    Return the canonical URI name.

    The implementation uses ``name`` to produce the canonical URI name.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.

    Returns:
        Whether the canonical URI name operation succeeds.
    """
    normalized = re.sub(r"[^a-z0-9]+", "-", str(name).strip().lower()).strip("-")
    return normalized in {
        "location",
        "content-location",
        "uri",
        "url",
        "odata-id",
        "odata-nextlink",
        "next-link",
        "target",
        "action-target",
        "taskmonitor",
        "href",
    } or normalized.endswith(("uri", "url", "nextlink", "next-link"))


def _external_text_sanitizer(
    sanitizer: Optional[Callable[[str], str]], value: Any
) -> str:
    """
    Return the external text sanitizer.

    The implementation uses ``sanitizer`` and ``value`` to produce the external
    text sanitizer. If the function cannot produce the external text sanitizer,
    its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        value: Value evaluated while performing external text sanitizer.

    Returns:
        The canonical external text sanitizer text.

    Raises:
        RuntimeError: If configured capture sanitizer failed closed; or
            configured capture sanitizer returned non-text.
    """
    text = str(value)
    if sanitizer is None:
        return text
    try:
        sanitized = sanitizer(text)
    except Exception as error:
        raise RuntimeError("Configured capture sanitizer failed closed") from error
    if not isinstance(sanitized, str):
        raise RuntimeError("Configured capture sanitizer returned non-text")
    return sanitized


def _canonical_uri_sanitizer(
    sanitizer: Optional[Callable[[str], str]], value: Any
) -> Optional[str]:
    """
    Return a structurally safe URI for diagnostic evidence only.

    Query names can themselves be opaque bearer values, so arbitrary queries
    are replaced. The sole retained query grammar is the exact bounded OData
    ``$expand=*($levels=N)`` form constructed by the Redfish expand collector.
    It contains no user-controlled value and is retained only when userinfo and
    fragments are absent. Malformed authorities fail closed instead of feeding
    the raw URI back through the free-text URL matcher, which would both retain
    userinfo and recurse on unmatched bracketed hosts.

    Args:
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        value: Value evaluated while performing structurally safe URI for
            diagnostic evidence only.

    Returns:
        The canonical URI sanitizer text, or ``None`` when the requested value
        is unavailable.
    """

    if value in (None, ""):
        return None
    raw_uri = str(value)
    try:
        parts = urlsplit(raw_uri)
        encoded_authority = _ENCODED_AUTHORITY_DELIMITER.search(parts.netloc)
        encoded_path_delimiter = _ENCODED_PATH_QUERY_OR_FRAGMENT.search(parts.path)
        opaque_authority = not parts.netloc and (
            _OPAQUE_AUTHORITY_PREFIX.search(parts.path)
            or _ENCODED_SCHEME_AUTHORITY_PREFIX.search(parts.path)
        )
        if encoded_authority or encoded_path_delimiter or opaque_authority:
            return "<redacted-uri>"
        # Apply the complete non-optional text policy to URI components before
        # reconstructing the approved query. This lets structured URI values be
        # written once without a second free-text pass that would mistake the
        # benign OData punctuation for an arbitrary query.
        netloc = _canonical_text_sanitizer(sanitizer, parts.netloc.rsplit("@", 1)[-1])
        path = _canonical_text_sanitizer(sanitizer, parts.path)
        retain_expand_query = bool(
            parts.query
            and "@" not in parts.netloc
            and not parts.fragment
            and _TOOL_GENERATED_ODATA_EXPAND_QUERY.fullmatch(parts.query)
        )
        query = (
            parts.query
            if retain_expand_query
            else "%5BREDACTED%5D" if parts.query else ""
        )
        return urlunsplit((parts.scheme, netloc, path, query, ""))
    except (TypeError, ValueError):
        return "<redacted-uri>"


def _bounded_uri_preview(
    uri_sanitizer: Callable[[Any], Optional[str]],
    value: str,
    *,
    max_chars: int,
) -> Optional[str]:
    """
    Sanitize a bounded URI preview without cutting through an authority.

    A URI whose authority is longer than the preview cannot be rendered safely:
    an ``@`` beyond the boundary could reclassify the entire visible prefix as
    userinfo. Fail that rare case closed. Once a path/query/fragment delimiter
    has ended the authority, only the bounded prefix needs to be copied and
    passed to the configured URI sanitizer.

    Args:
        uri_sanitizer: Validated remote resource identifier used for URI
            sanitizer.
        value: Text supplied as value in the format accepted by this function.
        max_chars: Upper bound enforced for max chars; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The canonical bounded URI preview text, or ``None`` when the requested
        value is unavailable.
    """

    if type(value) is not str or not value:
        return None
    limit = max(1, int(max_chars))
    if len(value) <= limit:
        return uri_sanitizer(value)

    preview = value[:limit]
    if ord(preview[0]) <= 32 or preview[0].isspace():
        return "<redacted-uri>"
    authority_start: Optional[int] = None
    if preview.startswith("//"):
        authority_start = 2
    else:
        scheme_separator = preview.find(":")
        if (
            scheme_separator > 0
            and re.fullmatch(
                r"[A-Za-z][A-Za-z0-9+.-]*",
                preview[:scheme_separator],
            )
            and preview.startswith("//", scheme_separator + 1)
        ):
            authority_start = scheme_separator + 3

    if authority_start is not None:
        authority_end = min(
            (
                index
                for delimiter in "/?#"
                if (index := preview.find(delimiter, authority_start)) >= 0
            ),
            default=-1,
        )
        if authority_end < 0:
            return "<redacted-uri>"
        if preview.find("://", authority_start) >= 0:
            return "<redacted-uri>"
    elif "://" in preview:
        return "<redacted-uri>"

    return uri_sanitizer(preview)


_PRIVATE_KEY_BEGIN_RE = re.compile(
    r"-{4,5}BEGIN [^-\r\n]*PRIVATE KEY-{4,5}",
    flags=re.IGNORECASE,
)
_CAPTURE_AWS_ACCESS_KEY = re.compile(
    r"(?-i:(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9]))"
)
_CAPTURE_PRIVATE_KEY = re.compile(
    r"(?i)-{4,5}BEGIN [^-\r\n]*PRIVATE KEY-{4,5}"
    rf"(?:(?!-{{4,5}}BEGIN)[\s\S]){{0,{_PRIVATE_KEY_BODY_MAX_CHARS}}}?"
    r"-{4,5}END [^-\r\n]*PRIVATE KEY-{4,5}"
)
_CAPTURE_AUTH_SCHEME = re.compile(r"(?i)\b(bearer|basic)\s+[^\s,;\"']+")
_CAPTURE_COOKIE_ASSIGNMENT = re.compile(
    r"(?i)(?<![a-z0-9_-])([\"']?(?:[a-z0-9]+[_-])*(?:cookie|set-cookie))"
    r"([\"']?\s*[:=][^\S\r\n]*)"
    r"[^\r\n]*(?:\r?\n[^\S\r\n]+[^\r\n]*)*"
)
_CAPTURE_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(?<![a-z0-9_-])([\"']?(?:[a-z0-9]+[_-])*"
    r"(?:authorization|proxy-authorization|"
    r"x-auth-token|x-auth-session|x-xsrf-token|x-csrf-token|"
    r"x-api-key|api-key|apikey|api_key|access-key|access_key|"
    r"secret-key|secret_key|access-token|"
    r"token|password|passwd|pwd|passphrase|secret|"
    r"credential|private-key|private_key|signature))"
    r"([\"']?\s*[:=]\s*)([^\r\n,;]+)"
)


def _redact_incomplete_private_key(text: str) -> str:
    """
    Fail closed when a private-key header survives sanitization.

    The canonical and external PEM passes only match a complete ``BEGIN``..
    ``END`` pair, so a truncated key (or one whose body exceeds the bounded
    interval) keeps its header and material verbatim because the closing
    delimiter never arrives.  When a ``BEGIN ... PRIVATE KEY`` header still
    remains after sanitization the value holds incomplete key material, and
    everything from that header onward is replaced with a redaction marker.
    This mirrors the guard ``_bounded_text_preview`` applies so the bounded,
    non-oversized string value path cannot publish key material the preview
    path would have removed.

    Args:
        text: Already-sanitized text that may still contain a dangling
            private-key header.

    Returns:
        ``text`` unchanged when no private-key header remains, otherwise the
        prefix preceding the header followed by ``<redacted-private-key>``.
    """

    incomplete_key = _PRIVATE_KEY_BEGIN_RE.search(text)
    if incomplete_key:
        return text[: incomplete_key.start()] + "<redacted-private-key>"
    return text


def _bounded_text_preview(
    text_sanitizer: Callable[[str], str],
    value: str,
    *,
    max_chars: int,
) -> str:
    """
    Return a sanitized preview without cutting through a private key.

    Multi-line secret patterns need a bounded amount of input beyond the
    visible preview so their closing delimiter can be recognized.  If a
    private-key header still remains after sanitization, the preview ended
    inside an incomplete or over-limit key and must fail closed from that
    header onward.

    Args:
        text_sanitizer: Sanitizer applied before the preview is truncated.
        value: Untrusted text to sanitize and preview.
        max_chars: Maximum number of visible preview characters.

    Returns:
        A bounded, sanitized preview of ``value``.
    """

    limit = max(1, int(max_chars))
    window_end = min(
        len(value),
        limit + _PRIVATE_KEY_PREVIEW_LOOKAHEAD_CHARS,
    )
    sanitized = text_sanitizer(value[:window_end])
    return _redact_incomplete_private_key(sanitized[:limit])


def _canonical_text_sanitizer(
    sanitizer: Optional[Callable[[str], str]], value: Any
) -> str:
    """
    Apply the runtime sanitizer and non-optional structural redaction.

    Run the configured sanitizer first, then preserve the complete capture
    backstop policy. Literal guards omit a scan only when a character required
    by every match is absent from the current text. They do not cache payloads
    or alter Unicode, replacement, or URI handling.

    Args:
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
        value: Untrusted value converted to text before redaction.

    Returns:
        Text with configured secrets and structural credentials redacted.

    Raises:
        RuntimeError: If the configured sanitizer fails or returns non-text.
    """

    text = _external_text_sanitizer(sanitizer, value)
    if str.__contains__(text, "AKIA") or str.__contains__(text, "ASIA"):
        text = _CAPTURE_AWS_ACCESS_KEY.sub("<redacted-aws-access-key>", text)
    # The interval is tempered so it cannot run past a following BEGIN header,
    # and is length-bounded. ``[\s\S]*?`` re-scanned to end-of-input for every
    # BEGIN that had no matching END, which is quadratic on repeated headers;
    # the tempered form fails such a start immediately while still accepting
    # any real key body between a matched BEGIN/END pair.
    if str.__contains__(text, "----"):
        text = _CAPTURE_PRIVATE_KEY.sub("<redacted-private-key>", text)
    text = _CAPTURE_AUTH_SCHEME.sub(r"\1 <redacted>", text)
    # Align the fail-safe backstop with the primary sanitizer's credential-pair
    # coverage: tolerate quotes around the key, accept underscore/hyphen
    # compound name prefixes (``access_token``, ``client_secret``,
    # ``user_password``), and cover the JSON-quoted spellings (``"password":
    # "x"``, ``"X-Auth-Token": "y"``).  The ``(?<![a-z0-9_-])`` start guard
    # keeps the compound-prefix match linear-time by preventing restarts inside
    # an alphanumeric/underscore/hyphen run.
    if str.__contains__(text, ":") or str.__contains__(text, "="):
        # Cookie fields contain multiple semicolon-separated credentials, and
        # Set-Cookie expiry attributes can contain commas. Mask the complete
        # field and indented continuations without consuming the next header.
        text = _CAPTURE_COOKIE_ASSIGNMENT.sub(r"\1\2<redacted>", text)
        text = _CAPTURE_CREDENTIAL_ASSIGNMENT.sub(r"\1\2<redacted>", text)
    # Structural URI parsing is needed only when the text contains a query,
    # fragment, or userinfo delimiter. Skipping the authority patterns for
    # delimiter-free text avoids repeatedly reconsidering every ``//`` in
    # long benign path sequences while preserving all secret-bearing forms.
    has_literal_query_or_fragment = "?" in text or "#" in text
    has_encoded_query_or_fragment = bool(_ENCODED_PATH_QUERY_OR_FRAGMENT.search(text))
    if (
        "@" in text
        or has_literal_query_or_fragment
        or _ENCODED_SENSITIVE_URI_DELIMITER.search(text)
    ):
        text = re.sub(
            # Match literal and recursively encoded authority forms, but keep
            # the consumed URI interval bounded so repeated hostile prefixes
            # remain linear-time input rather than triggering tail rescans.
            r"(?i)(?<![a-z0-9])((?:"
            r"(?:(?>%(?:25)*[0-9a-f]{2})|[a-z0-9+.-]){1,64}?"
            r"(?::|%(?:25)*3a))?"
            r"(?:(?:[\\/])|(?:%(?:25)*(?:2f|5c))){2}[^\s\"'<>),}]{0,2048})",
            lambda match: (
                _canonical_uri_sanitizer(sanitizer, match.group(1)) or "<redacted-uri>"
            ),
            text,
        )
        text = re.sub(
            r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"'<>),}]+",
            lambda match: (
                _canonical_uri_sanitizer(sanitizer, match.group(0)) or "<redacted-url>"
            ),
            text,
        )
    if not has_literal_query_or_fragment and not has_encoded_query_or_fragment:
        return text
    return _redact_path_query_tokens(sanitizer, text)


def _redact_path_query_tokens(
    sanitizer: Optional[Callable[[str], str]], text: str
) -> str:
    """
    Redact path-like tokens containing a query or fragment in linear time.

    Searching from every slash makes a slash-heavy token quadratic whenever a
    query delimiter occurs only before those slashes.  Tokenize the text once,
    select at most one path start per token, and search only the remaining
    suffix for a literal or recursively encoded delimiter.

    Args:
        sanitizer: Sanitizer applied to each identified URI token.
        text: Capture text whose path-like URI tokens are inspected.

    Returns:
        Text with every query- or fragment-bearing path token sanitized.
    """

    output: list[str] = []
    copied_through = 0
    for token_match in _CAPTURE_TEXT_URI_TOKEN.finditer(text):
        token = token_match.group(0)
        path_match = re.search(r"(?i)(?<![a-z0-9])/", token)
        if path_match is None:
            continue

        path_start = path_match.start()
        suffix_start = path_start + 1
        literal_positions = [
            position
            for delimiter in "?#"
            if (position := token.find(delimiter, suffix_start)) >= 0
        ]
        encoded_delimiter = _ENCODED_PATH_QUERY_OR_FRAGMENT.search(token, suffix_start)
        if not literal_positions and encoded_delimiter is None:
            continue

        replacement_start = token_match.start() + path_start
        output.append(text[copied_through:replacement_start])
        output.append(
            _canonical_uri_sanitizer(sanitizer, token[path_start:]) or "<redacted-uri>"
        )
        copied_through = token_match.end()

    if not output:
        return text
    output.append(text[copied_through:])
    return "".join(output)


def bounded_capture_failure_metadata(
    stage: str,
    error: BaseException,
    *,
    limit_reached: bool = False,
) -> dict[str, Any]:
    """
    Return fixed, non-content-bearing failure metadata for public results.

    Exception messages are deliberately excluded. Transport and filesystem
    exceptions routinely embed URI credentials, query tokens, or sensitive local
    paths, and a configured sanitizer may itself be unavailable or fail.

    Args:
        stage: Text supplied as stage in the format accepted by this function.
        error: Exception or failure detail associated with the operation.
        limit_reached: Whether limit reached is enabled or required for this
            operation.

    Returns:
        A mapping containing the ``stage``, ``type``, ``reason``, and
        ``limit_reached`` fields.
    """

    safe_stage = re.sub(r"[^a-z0-9_.-]+", "-", str(stage).casefold())[:64]
    safe_type = re.sub(r"[^A-Za-z0-9_.-]+", "-", type(error).__name__)[:96]
    return {
        "stage": safe_stage or "capture",
        "type": safe_type or "CaptureError",
        "reason": "capture operation failed",
        "limit_reached": bool(limit_reached),
    }


@dataclass(frozen=True)
class _RuntimePublicationAuthorization:
    """
    Run-registry entry binding one capture to one collector destination.

    The immutable record keeps ``token``, ``policy``, ``dut_id``,
    ``collector_id``, and ``collector_group`` together so consumers observe one
    runtime publication authorization state. Consumers receive the fields as one
    unit instead of assembling partial state.

    Attributes:
        token: Token retained as part of the record's public state.
        policy: Policy retained as part of the record's public state.
        dut_id: Canonical text used as DUT identifier.
        collector_id: Canonical text used as collector identifier.
        collector_group: Canonical text used as collector group.
        destination: Destination retained as part of the record's public state.
        collector_root: Collector root retained as part of the record's public
            state.
        collector_root_identity: Collection of collector root identity entries
            retained by this record.
    """

    token: object = field(repr=False, compare=False)
    policy: CaptureSanitizationPolicy
    dut_id: str
    collector_id: str
    collector_group: str
    destination: Path
    collector_root: Path
    collector_root_identity: tuple[int, int]


@dataclass(frozen=True)
class _TrackedPublication:
    """
    Runtime-owned publication and its continuous byte/object lease.

    The immutable record keeps ``summary`` and ``retained_budget_key`` together
    so consumers observe one tracked publication state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        summary: Summary retained as part of the record's public state.
        retained_budget_key: Retained budget key retained as part of the
            record's public state.
    """

    summary: PublishedCaptureSummary
    retained_budget_key: object = field(repr=False, compare=False)


class CaptureFilesystemBoundaryError(RuntimeError):
    """
    Raised when private staging no longer matches its pinned identity.

    Callers receive this exception when the capture filesystem boundary error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


def _absolute_path(path: Path) -> Path:
    """
    Return an absolute lexical path without resolving symlinks.

    After applying local validation, the function forwards ``path`` to ``Path``
    and preserves its return and exception contract.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        The validated absolute path filesystem path.
    """

    return Path(os.path.abspath(os.fspath(path)))


def _remove_exact_created_directory(
    parent_descriptor: int,
    leaf_name: str,
    expected_identity: Optional[tuple[int, int]],
) -> bool:
    """
    Remove only the exact empty directory created by this process.

    A pathname can be replaced after its descriptor was pinned. Exception
    cleanup must never remove whatever now happens to occupy that pathname. When
    creation failed before an identity could be established, leaking the random
    empty leaf is safer than deleting an unowned replacement.

    Args:
        parent_descriptor: Numeric parent descriptor used while the operation
            performs bounded accounting.
        leaf_name: Stable leaf name used for lookup and operator-facing
            diagnostics.
        expected_identity: Entries supplied as ``expected_identity`` without
            transferring container ownership.

    Returns:
        Whether the remove only the exact empty directory created by this
        process operation succeeds.
    """

    if not leaf_name or expected_identity is None:
        return False
    try:
        leaf_stat = os.stat(
            leaf_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError:
        return False
    if (
        not stat.S_ISDIR(leaf_stat.st_mode)
        or (leaf_stat.st_dev, leaf_stat.st_ino) != expected_identity
    ):
        return False
    try:
        os.rmdir(leaf_name, dir_fd=parent_descriptor)
    except OSError:
        return False
    return True


def _open_private_staging_root(
    directory: Path,
) -> tuple[Path, int, tuple[int, int], int]:
    """
    Create or open one owner-only root through pinned directory handles.

    Every component is opened relative to the preceding descriptor with
    ``O_NOFOLLOW``. This avoids the path-wide lstat/open race where an attacker
    could replace a checked parent with a symlink before the final open.

    Args:
        directory: filesystem location used as the directory for this operation.

    Returns:
        The directory, pinned descriptor, inode identity, and verified owner UID
        reported by this filesystem. The caller retains that UID for rechecks.

    Raises:
        CaptureFilesystemBoundaryError: If private capture staging path anchor
            is unavailable; private capture staging parent must already exist;
            private capture staging root could not be created; or the private
            capture staging root is not a real directory; or another input
            invariant is violated.
    """

    directory = _absolute_path(Path(directory))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    components = directory.parts[1:]
    walk_descriptor = -1
    parent_descriptor = -1
    descriptor = -1
    created = False
    leaf_name = ""
    created_identity: Optional[tuple[int, int]] = None

    try:
        try:
            walk_descriptor = os.open(directory.anchor, flags)
        except OSError as error:
            raise CaptureFilesystemBoundaryError(
                "Private capture staging path anchor is unavailable"
            ) from error

        if not components:
            descriptor = walk_descriptor
            walk_descriptor = -1
        else:
            for index, component in enumerate(components):
                is_leaf = index == len(components) - 1
                try:
                    child_descriptor = os.open(
                        component,
                        flags,
                        dir_fd=walk_descriptor,
                    )
                except FileNotFoundError as error:
                    if not is_leaf:
                        raise CaptureFilesystemBoundaryError(
                            "Private capture staging parent must already exist"
                        ) from error
                    try:
                        os.mkdir(component, 0o700, dir_fd=walk_descriptor)
                        created = True
                    except FileExistsError:
                        # A racing creator is acceptable only if the pinned,
                        # no-follow open and all privacy checks below succeed.
                        pass
                    except FileNotFoundError as mkdir_error:
                        raise CaptureFilesystemBoundaryError(
                            "Private capture staging parent must already exist"
                        ) from mkdir_error
                    except OSError as mkdir_error:
                        raise CaptureFilesystemBoundaryError(
                            "Private capture staging root could not be created"
                        ) from mkdir_error
                    try:
                        child_descriptor = os.open(
                            component,
                            flags,
                            dir_fd=walk_descriptor,
                        )
                    except OSError as open_error:
                        raise CaptureFilesystemBoundaryError(
                            "Private capture staging root must be a real directory"
                        ) from open_error
                except OSError as error:
                    raise CaptureFilesystemBoundaryError(
                        "Private capture staging path must not contain symlinks "
                        "or non-directories"
                    ) from error

                if is_leaf:
                    leaf_name = component
                    parent_descriptor = walk_descriptor
                    walk_descriptor = -1
                    descriptor = child_descriptor
                else:
                    os.close(walk_descriptor)
                    walk_descriptor = child_descriptor

        if created:
            os.fchmod(descriptor, 0o700)
        descriptor_stat = os.fstat(descriptor)
        identity = (descriptor_stat.st_dev, descriptor_stat.st_ino)
        if created:
            created_identity = identity
        if not stat.S_ISDIR(descriptor_stat.st_mode):
            raise CaptureFilesystemBoundaryError(
                "Private capture staging root must be a real directory"
            )
        owner_uid = filesystem_owner_uid(
            descriptor, observed_uid=descriptor_stat.st_uid
        )
        if descriptor_stat.st_uid != owner_uid:
            raise CaptureFilesystemBoundaryError(
                "Private capture staging root must be owned by the current user"
            )
        if stat.S_IMODE(descriptor_stat.st_mode) != 0o700:
            raise CaptureFilesystemBoundaryError(
                "Private capture staging root permissions must be 0700"
            )

        # The descriptor walk is the security boundary. The final pathname
        # comparison additionally fails closed if an ancestor was swapped while
        # the walk was in progress, rather than returning an unreachable root.
        _assert_private_root(directory, descriptor, identity, owner_uid)
        return directory, descriptor, identity, owner_uid
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        if created and parent_descriptor >= 0:
            _remove_exact_created_directory(
                parent_descriptor,
                leaf_name,
                created_identity,
            )
        raise
    finally:
        if walk_descriptor >= 0:
            os.close(walk_descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _open_pinned_existing_directory(directory: Path) -> tuple[int, tuple[int, int]]:
    """
    Open every existing directory component without following symlinks.

    The implementation uses ``directory`` to open every existing directory
    component without following symlinks.

    Args:
        directory: filesystem location used as the directory for this operation.

    Returns:
        A tuple containing ``descriptor`` and ``identity`` in that order.
    """

    directory = _absolute_path(Path(directory))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(directory.anchor, flags)
        for component in directory.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        descriptor_stat = os.fstat(descriptor)
        identity = (descriptor_stat.st_dev, descriptor_stat.st_ino)
        _assert_pinned_directory_path(directory, descriptor, identity)
        return descriptor, identity
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _create_private_staging_root(
    parent: Path,
    *,
    output_root: Path,
    output_root_descriptor: int,
) -> tuple[Path, tuple[int, int]]:
    """
    Create an owner-only sibling root on the pinned output filesystem.

    The implementation uses ``parent``, ``output_root``, and
    ``output_root_descriptor`` to create an owner-only sibling root on the
    pinned output filesystem. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. If the function
    cannot create an owner-only sibling root on the pinned output filesystem,
    its exception reaches the caller instead of being converted into a
    successful result. Cleanup in the ``finally`` path runs for successful,
    failed, and cancelled execution.

    Args:
        parent: filesystem location used as the parent for this operation.
        output_root: filesystem location used as the output root for this
            operation.
        output_root_descriptor: Numeric output root descriptor used while the
            operation performs bounded accounting.

    Returns:
        A tuple containing ``staging root`` and ``root identity`` in that order.

    Raises:
        CaptureFilesystemBoundaryError: If the private capture staging parent is
            not outside the run output root; private capture staging and run
            output must share a filesystem; could not allocate a unique private
            capture staging root; or private capture staging root failed
            ownership or filesystem checks.
    """

    parent = _absolute_path(Path(parent))
    output_root = _absolute_path(Path(output_root))
    try:
        parent.relative_to(output_root)
    except ValueError:
        pass
    else:
        raise CaptureFilesystemBoundaryError(
            "Private capture staging parent must be outside the run output root"
        )

    parent_descriptor, parent_identity = _open_pinned_existing_directory(parent)
    leaf_name = ""
    descriptor = -1
    root_identity: Optional[tuple[int, int]] = None
    try:
        output_stat = os.fstat(output_root_descriptor)
        parent_stat = os.fstat(parent_descriptor)
        if output_stat.st_dev != parent_stat.st_dev:
            raise CaptureFilesystemBoundaryError(
                "Private capture staging and run output must share a filesystem"
            )
        _assert_pinned_directory_path(parent, parent_descriptor, parent_identity)

        for _attempt in range(16):
            leaf_name = f".nvdebug-private-capture-{secrets.token_hex(18)}"
            try:
                os.mkdir(leaf_name, 0o700, dir_fd=parent_descriptor)
                break
            except FileExistsError:
                leaf_name = ""
        if not leaf_name:
            raise CaptureFilesystemBoundaryError(
                "Could not allocate a unique private capture staging root"
            )

        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(leaf_name, flags, dir_fd=parent_descriptor)
        os.fchmod(descriptor, 0o700)
        root_stat = os.fstat(descriptor)
        root_identity = (root_stat.st_dev, root_stat.st_ino)
        owner_uid = filesystem_owner_uid(descriptor, observed_uid=root_stat.st_uid)
        if (
            root_stat.st_dev != output_stat.st_dev
            or root_stat.st_uid != owner_uid
            or stat.S_IMODE(root_stat.st_mode) != 0o700
        ):
            raise CaptureFilesystemBoundaryError(
                "Private capture staging root failed ownership or filesystem checks"
            )
        staging_root = parent / leaf_name
        _assert_private_root(staging_root, descriptor, root_identity, owner_uid)
        _assert_pinned_directory_path(
            output_root,
            output_root_descriptor,
            (output_stat.st_dev, output_stat.st_ino),
        )
        os.fsync(parent_descriptor)
        return staging_root, root_identity
    except BaseException:
        if _remove_exact_created_directory(
            parent_descriptor,
            leaf_name,
            root_identity,
        ):
            try:
                os.fsync(parent_descriptor)
            except OSError:
                pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def _remove_exact_empty_staging_root(
    staging_root: Path,
    expected_identity: tuple[int, int],
) -> None:
    """
    Remove only the exact empty staging directory created by this run.

    The implementation uses ``staging_root`` and ``expected_identity`` to remove
    only the exact empty staging directory created by this run. If the function
    cannot remove only the exact empty staging directory created by this run,
    its exception reaches the caller instead of being converted into a
    successful result. Cleanup in the ``finally`` path runs for successful,
    failed, and cancelled execution.

    Args:
        staging_root: filesystem location used as the staging root for this
            operation.
        expected_identity: Entries supplied as ``expected_identity`` without
            transferring container ownership.

    Raises:
        CaptureFilesystemBoundaryError: If refusing to remove a replaced private
            capture staging root.
    """

    parent_descriptor, parent_identity = _open_pinned_existing_directory(
        staging_root.parent
    )
    try:
        _assert_pinned_directory_path(
            staging_root.parent, parent_descriptor, parent_identity
        )
        leaf_stat = os.stat(
            staging_root.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(leaf_stat.st_mode)
            or (leaf_stat.st_dev, leaf_stat.st_ino) != expected_identity
        ):
            raise CaptureFilesystemBoundaryError(
                "Refusing to remove a replaced private capture staging root"
            )
        os.rmdir(staging_root.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _assert_pinned_directory_path(
    directory: Path,
    descriptor: int,
    identity: tuple[int, int],
) -> None:
    """
    Revalidate one lexical directory path against its pinned descriptor.

    The implementation uses ``directory``, ``descriptor``, and ``identity`` to
    revalidate one lexical directory path against its pinned descriptor.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. If the function cannot revalidate one lexical
    directory path against its pinned descriptor, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        directory: filesystem location used as the directory for this operation.
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.
        identity: Entries supplied as ``identity`` without transferring
            container ownership.

    Raises:
        CaptureFilesystemBoundaryError: If capture publication parent is no
            longer available; or capture publication parent identity changed.
    """

    try:
        descriptor_stat = os.fstat(descriptor)
        path_stat = os.lstat(directory)
    except OSError as error:
        raise CaptureFilesystemBoundaryError(
            "Capture publication parent is no longer available"
        ) from error
    if (
        not stat.S_ISDIR(descriptor_stat.st_mode)
        or stat.S_ISLNK(path_stat.st_mode)
        or (descriptor_stat.st_dev, descriptor_stat.st_ino) != identity
        or (path_stat.st_dev, path_stat.st_ino) != identity
    ):
        raise CaptureFilesystemBoundaryError(
            "Capture publication parent identity changed"
        )


def _open_authorized_publication_parent(
    authorization: _RuntimePublicationAuthorization,
) -> tuple[int, tuple[int, int]]:
    """
    Open a bound collector root and walk only to its authorized parent.

    The implementation uses ``authorization`` to open a bound collector root and
    walk only to its authorized parent. If the function cannot open a bound
    collector root and walk only to its authorized parent, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        authorization: Authorization object whose ``collector_root``,
            ``collector_root_identity``, ``destination``, ``parent``, and
            ``relative_to`` state is read while performing open a bound
            collector root and walk only to its authorized parent.

    Returns:
        A tuple containing ``descriptor`` and ``identity`` in that order.

    Raises:
        CaptureFilesystemBoundaryError: If capture destination escaped its
            authorized collector root; or authorized collector root identity
            changed.
    """

    try:
        relative_parent = authorization.destination.parent.relative_to(
            authorization.collector_root
        )
    except ValueError as error:
        raise CaptureFilesystemBoundaryError(
            "Capture destination escaped its authorized collector root"
        ) from error
    descriptor, observed_root_identity = _open_pinned_existing_directory(
        authorization.collector_root
    )
    if observed_root_identity != authorization.collector_root_identity:
        os.close(descriptor)
        raise CaptureFilesystemBoundaryError(
            "Authorized collector root identity changed"
        )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        for component in relative_parent.parts:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        descriptor_stat = os.fstat(descriptor)
        identity = (descriptor_stat.st_dev, descriptor_stat.st_ino)
        _assert_pinned_directory_path(
            authorization.destination.parent,
            descriptor,
            identity,
        )
        return descriptor, identity
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _digest_descriptor(descriptor: int, size_bytes: int) -> str:
    """
    Hash an exact descriptor prefix without changing its shared offset.

    After applying local validation, the function forwards ``descriptor`` and
    ``size_bytes`` to ``digest.hexdigest`` and preserves its return and
    exception contract.

    Args:
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.
        size_bytes: Numeric size bytes used while the operation performs bounded
            accounting.

    Returns:
        The canonical digest descriptor text.

    Raises:
        CaptureFilesystemBoundaryError: If private capture file was truncated
            during verification.
    """

    digest = hashlib.sha256()
    offset = 0
    while offset < size_bytes:
        chunk = os.pread(
            descriptor, min(_COPY_CHUNK_BYTES, size_bytes - offset), offset
        )
        if not chunk:
            raise CaptureFilesystemBoundaryError(
                "Private capture file was truncated during verification"
            )
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _assert_private_root(
    root_path: Path,
    root_descriptor: int,
    root_identity: tuple[int, int],
    owner_uid: int,
) -> None:
    """
    Verify that both the pinned root and its pathname remain private.

    The implementation uses ``root_path``, ``root_descriptor``, and
    ``root_identity`` to verify that both the pinned root and its pathname
    remain private. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path. Filesystem effects remain confined to the caller-selected paths and
    the owning resource lifecycle.

    Args:
        root_path: filesystem location used as the root path for this operation.
        root_descriptor: Numeric root descriptor used while the operation
            performs bounded accounting.
        root_identity: Entries supplied as ``root_identity`` without
            transferring container ownership.
        owner_uid: Filesystem owner UID verified when this root was opened.
            Rechecks retain this value so ownership drift is rejected.

    Raises:
        CaptureFilesystemBoundaryError: If private capture staging root is no
            longer available; private capture staging root was replaced; private
            capture staging root identity changed; or private capture staging
            root is not owner-only (0700).
    """

    try:
        path_stat = os.lstat(root_path)
        descriptor_stat = os.fstat(root_descriptor)
    except OSError as error:
        raise CaptureFilesystemBoundaryError(
            "Private capture staging root is no longer available"
        ) from error
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISDIR(path_stat.st_mode):
        raise CaptureFilesystemBoundaryError(
            "Private capture staging root was replaced"
        )
    if (path_stat.st_dev, path_stat.st_ino) != root_identity or (
        descriptor_stat.st_dev,
        descriptor_stat.st_ino,
    ) != root_identity:
        raise CaptureFilesystemBoundaryError(
            "Private capture staging root identity changed"
        )
    if (
        path_stat.st_uid != owner_uid
        or descriptor_stat.st_uid != owner_uid
        or stat.S_IMODE(path_stat.st_mode) != 0o700
        or stat.S_IMODE(descriptor_stat.st_mode) != 0o700
    ):
        raise CaptureFilesystemBoundaryError(
            "Private capture staging root is not owner-only (0700)"
        )


def _assert_private_descriptor(
    descriptor: int,
    identity: tuple[int, int],
    *,
    expected_size: Optional[int] = None,
    expected_digest: Optional[str] = None,
) -> os.stat_result:
    """
    Verify one pinned, anonymous, owner-only regular file descriptor.

    The implementation uses ``descriptor``, ``identity``, ``expected_size``, and
    ``expected_digest`` to verify one pinned, anonymous, owner-only regular file
    descriptor. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.
        identity: Entries supplied as ``identity`` without transferring
            container ownership.
        expected_size: Numeric expected size used by the operation's bounded
            accounting.
        expected_digest: Optional expected digest; ``None`` selects the
            function's default behavior.

    Returns:
        The validated ``descriptor_stat``.

    Raises:
        CaptureFilesystemBoundaryError: If private capture descriptor is no
            longer available; private capture descriptor is not a regular file;
            private capture descriptor identity changed; or private capture
            descriptor permissions changed from 0600; or another input invariant
            is violated.
    """

    try:
        descriptor_stat = os.fstat(descriptor)
    except OSError as error:
        raise CaptureFilesystemBoundaryError(
            "Private capture descriptor is no longer available"
        ) from error
    if not stat.S_ISREG(descriptor_stat.st_mode):
        raise CaptureFilesystemBoundaryError(
            "Private capture descriptor is not a regular file"
        )
    if (descriptor_stat.st_dev, descriptor_stat.st_ino) != identity:
        raise CaptureFilesystemBoundaryError(
            "Private capture descriptor identity changed"
        )
    if stat.S_IMODE(descriptor_stat.st_mode) != 0o600:
        raise CaptureFilesystemBoundaryError(
            "Private capture descriptor permissions changed from 0600"
        )
    if descriptor_stat.st_nlink != 0:
        raise CaptureFilesystemBoundaryError(
            "Private capture descriptor unexpectedly has filesystem links"
        )
    if expected_size is not None and descriptor_stat.st_size != expected_size:
        raise CaptureFilesystemBoundaryError(
            "Private capture descriptor size changed outside accounting"
        )
    if expected_digest is not None and (
        _digest_descriptor(descriptor, descriptor_stat.st_size) != expected_digest
    ):
        raise CaptureFilesystemBoundaryError(
            "Private capture descriptor digest changed outside accounting"
        )
    return descriptor_stat


class CaptureLimitExceeded(RuntimeError):
    """
    Raised before a configured capture resource boundary is crossed.

    Callers receive this exception when the capture limit exceeded invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """

    def __init__(
        self,
        limit_name: str,
        limit: int,
        attempted: int,
        *,
        unit: str = "bytes",
    ) -> None:
        """
        Initialize a ``CaptureLimitExceeded`` instance.

        The initializer records ``attempted``, ``limit``, ``limit_name``, and
        ``unit`` for later operations and establishes the instance invariants
        before any public method runs.

        Args:
            limit_name: Stable limit name used for lookup and operator-facing
                diagnostics.
            limit: Numeric limit used while the operation performs bounded
                accounting.
            attempted: Numeric attempted used while the operation performs
                bounded accounting.
            unit: Text supplied as unit in the format accepted by this function.
        """
        self.limit_name = limit_name
        self.limit = int(limit)
        self.attempted = int(attempted)
        self.unit = unit
        super().__init__(
            f"{limit_name} exceeded: attempted {self.attempted} {unit}, "
            f"limit {self.limit} {unit}"
        )


class CaptureDisabled(RuntimeError):
    """
    Raised when request/response capture is disabled by operator policy.

    The distinct exception lets capture callers record a bounded, content-free
    reason and continue the collector without constructing private spool state.
    It is deliberately separate from resource-limit exhaustion because no
    configured byte or object limit was reached.
    """

    def __init__(self) -> None:
        """
        Initialize the stable operator-policy refusal.

        The message contains no request, response, endpoint, or credential
        content, so it is safe to retain in degraded-capture metadata.
        """
        super().__init__("Redfish request/response capture is disabled")


@dataclass(frozen=True)
class _BudgetAllocation:
    """
    One immutable resource allocation owned by the shared budget.

    The immutable record keeps ``kind``, ``bytes_reserved``,
    ``objects_reserved``, ``readers_reserved``, and
    ``file_descriptors_reserved`` together so consumers observe one budget
    allocation state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        kind: Container-kind discriminator.
        bytes_reserved: Numeric bytes reserved retained by this record.
        objects_reserved: Numeric objects reserved retained by this record.
        readers_reserved: Numeric readers reserved retained by this record.
        file_descriptors_reserved: Numeric file descriptors reserved retained by
            this record.
    """

    kind: str
    bytes_reserved: int
    objects_reserved: int
    readers_reserved: int
    file_descriptors_reserved: int


@dataclass(frozen=True)
class _BudgetState:
    """
    Atomically replaced accounting state.

    Building a replacement can be interrupted without mutating the currently
    published counters. The one state assignment is the accounting commit.

    Attributes:
        allocations: Mapping that retains the allocations fields for this
            record.
        reserved_bytes: Byte count recorded for reserved.
        reserved_objects: Number of reserved objects represented by this record.
        reserved_readers: Number of reserved readers represented by this record.
        reserved_file_descriptors: Number of reserved file descriptors
            represented by this record.
        high_water_bytes: Byte count recorded for high water.
        high_water_objects: Number of high water objects represented by this
            record.
        high_water_readers: Number of high water readers represented by this
            record.
        high_water_file_descriptors: Number of high water file descriptors
            represented by this record.
    """

    allocations: Mapping[object, _BudgetAllocation]
    reserved_bytes: int = 0
    reserved_objects: int = 0
    reserved_readers: int = 0
    reserved_file_descriptors: int = 0
    high_water_bytes: int = 0
    high_water_objects: int = 0
    high_water_readers: int = 0
    high_water_file_descriptors: int = 0


class _CaptureBudgetLease:
    """
    Idempotent capability for one budget-owned allocation.

    The type coordinates ``active``, ``bytes_reserved``, ``increase_bytes``,
    ``decrease_bytes``, and ``release`` and retains the state those operations
    share between calls. Resource ownership remains inside the instance until
    the matching close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        budget: "ConcurrentPrivateSpoolBudget",
        owner_key: object,
    ) -> None:
        """
        Initialize a ``_CaptureBudgetLease`` instance.

        The initializer records ``_budget`` and ``_owner_key`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            budget: Budget consumed while the function attempts to initialize a
                ``_CaptureBudgetLease`` instance.
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.
        """
        self._budget = budget
        self._owner_key = owner_key

    @property
    def active(self) -> bool:
        """
        Return whether active.

        Each access computes the value from ``_budget`` and ``_owner_key`` on
        the current instance; the derived view is not stored as independent
        state.

        Returns:
            Whether active.
        """
        return self._budget.is_active(self._owner_key)

    @property
    def bytes_reserved(self) -> int:
        """
        Return the bytes reserved.

        Each access computes the value from ``_budget`` and ``_owner_key`` on
        the current instance; the derived view is not stored as independent
        state.

        Returns:
            The numeric bytes reserved value.
        """
        allocation = self._budget.allocation_for(self._owner_key)
        return 0 if allocation is None else allocation.bytes_reserved

    def increase_bytes(self, size_bytes: int) -> None:
        """
        Reserve additional bytes against the active capture-budget lease.

        The implementation uses ``size_bytes`` to reserve additional bytes
        against the active capture-budget lease.

        Args:
            size_bytes: Numeric size bytes used while the operation performs
                bounded accounting.
        """
        self._budget._resize_bytes(self._owner_key, int(size_bytes))

    def decrease_bytes(self, size_bytes: int) -> None:
        """
        Release bytes from the active capture-budget lease.

        The implementation uses ``size_bytes`` to release bytes from the active
        capture-budget lease.

        Args:
            size_bytes: Numeric size bytes used while the operation performs
                bounded accounting.
        """
        self._budget._resize_bytes(self._owner_key, -int(size_bytes))

    def release(self) -> bool:
        """
        Release exactly once; repeated calls are harmless.

        After applying local validation, the function forwards current instance
        state to ``self._budget._release_owner`` and preserves its return and
        exception contract.

        Returns:
            Whether the release exactly once; repeated calls are harmless
            operation succeeds.
        """

        return self._budget._release_owner(self._owner_key)


class ConcurrentPrivateSpoolBudget:
    """
    Thread-safe byte/object/reader/FD accounting with owned leases.

    The type coordinates ``_hit``, ``reserved_bytes``, ``high_water_bytes``,
    ``reserved_objects``, and ``high_water_objects`` and retains the state those
    operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        max_bytes: int,
        *,
        max_objects: int = DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_OBJECTS,
        max_readers: int = DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_READERS,
        max_file_descriptors: int = (
            DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_FILE_DESCRIPTORS
        ),
        failpoint: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Initialize a ``ConcurrentPrivateSpoolBudget`` instance.

        The initializer records ``_failpoint``, ``_lock``, ``_state``,
        ``max_bytes``, and ``max_file_descriptors`` for later operations and
        establishes the instance invariants before any public method runs. If
        the function cannot initialize a ``ConcurrentPrivateSpoolBudget``
        instance, its exception reaches the caller instead of being converted
        into a successful result.

        Args:
            max_bytes: Upper bound enforced for max bytes; the consuming
                boundary rejects or truncates values that exceed it.
            max_objects: Upper bound enforced for max objects; the consuming
                boundary rejects or truncates values that exceed it.
            max_readers: Upper bound enforced for max readers; the consuming
                boundary rejects or truncates values that exceed it.
            max_file_descriptors: Upper bound enforced for max file descriptors;
                the consuming boundary rejects or truncates values that exceed
                it.
            failpoint: Optional failpoint; ``None`` selects the function's
                default behavior.

        Raises:
            TypeError: If the ``label`` is not an integer.
            ValueError: If the ``label`` is not at least ``minimum``.
        """
        limits = {
            "Private capture byte budget": (max_bytes, 1),
            "Private capture object budget": (max_objects, 1),
            "Private capture reader budget": (max_readers, 1),
            "Private capture file descriptor budget": (max_file_descriptors, 1),
        }
        for label, (value, minimum) in limits.items():
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{label} must be an integer")
            if value < minimum:
                raise ValueError(f"{label} must be at least {minimum}")
        self.max_bytes = max_bytes
        self.max_objects = max_objects
        self.max_readers = max_readers
        self.max_file_descriptors = max_file_descriptors
        self._failpoint = failpoint
        self._state = _BudgetState(allocations=MappingProxyType({}))
        self._lock = threading.Lock()

    def _hit(self, name: str) -> None:
        """
        Record a successful lookup or matching event.

        The implementation uses ``name`` to record a successful lookup or
        matching event.

        Args:
            name: Stable name used for lookup and operator-facing diagnostics.
        """
        if self._failpoint is not None:
            self._failpoint(name)

    @property
    def reserved_bytes(self) -> int:
        """
        Return the number of bytes currently reserved.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric reserved bytes value.
        """
        with self._lock:
            return self._state.reserved_bytes

    @property
    def high_water_bytes(self) -> int:
        """
        Return the high water bytes.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric high water bytes value.
        """
        with self._lock:
            return self._state.high_water_bytes

    @property
    def reserved_objects(self) -> int:
        """
        Return the reserved objects.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric reserved objects value.
        """
        with self._lock:
            return self._state.reserved_objects

    @property
    def high_water_objects(self) -> int:
        """
        Return the high water objects.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric high water objects value.
        """
        with self._lock:
            return self._state.high_water_objects

    @property
    def reserved_readers(self) -> int:
        """
        Return the reserved readers.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric reserved readers value.
        """
        with self._lock:
            return self._state.reserved_readers

    @property
    def high_water_readers(self) -> int:
        """
        Return the high water readers.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric high water readers value.
        """
        with self._lock:
            return self._state.high_water_readers

    @property
    def reserved_file_descriptors(self) -> int:
        """
        Return the reserved file descriptors.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric reserved file descriptors value.
        """
        with self._lock:
            return self._state.reserved_file_descriptors

    @property
    def high_water_file_descriptors(self) -> int:
        """
        Return the high water file descriptors.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric high water file descriptors value.
        """
        with self._lock:
            return self._state.high_water_file_descriptors

    @property
    def active_allocation_count(self) -> int:
        """
        Return the active allocation count.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric active allocation count.
        """
        with self._lock:
            return len(self._state.allocations)

    def reserve(
        self,
        size_bytes: int = 0,
        *,
        kind: str = "private capture resource",
        objects: int = 0,
        readers: int = 0,
        file_descriptors: int = 0,
        owner_key: Optional[object] = None,
    ) -> _CaptureBudgetLease:
        """
        Create one budget-owned allocation and return its idempotent lease.

        The implementation uses ``size_bytes``, ``kind``, ``objects``,
        ``readers``, and ``file_descriptors`` to create one budget-owned
        allocation and return its idempotent lease. It updates ``_state`` on the
        instance as part of that state transition. If the function cannot create
        one budget-owned allocation and return its idempotent lease, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            size_bytes: Numeric size bytes used while the operation performs
                bounded accounting.
            kind: Text supplied as kind in the format accepted by this function.
            objects: Numeric objects used while the operation performs bounded
                accounting.
            readers: Numeric readers used while the operation performs bounded
                accounting.
            file_descriptors: Numeric file descriptors used while the operation
                performs bounded accounting.
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.

        Returns:
            The validated ``lease``.

        Raises:
            ValueError: If private capture reservations cannot be negative.
            RuntimeError: If private capture budget owner is already reserved.
        """

        key = object() if owner_key is None else owner_key
        allocation = _BudgetAllocation(
            kind=str(kind),
            bytes_reserved=int(size_bytes),
            objects_reserved=int(objects),
            readers_reserved=int(readers),
            file_descriptors_reserved=int(file_descriptors),
        )
        for value in (
            allocation.bytes_reserved,
            allocation.objects_reserved,
            allocation.readers_reserved,
            allocation.file_descriptors_reserved,
        ):
            if value < 0:
                raise ValueError("Private capture reservations cannot be negative")

        with self._lock:
            current = self._state
            if key in current.allocations:
                raise RuntimeError("Private capture budget owner is already reserved")
            next_bytes = current.reserved_bytes + allocation.bytes_reserved
            next_objects = current.reserved_objects + allocation.objects_reserved
            next_readers = current.reserved_readers + allocation.readers_reserved
            next_fds = (
                current.reserved_file_descriptors + allocation.file_descriptors_reserved
            )
            self._validate_totals(
                next_bytes,
                next_objects,
                next_readers,
                next_fds,
            )
            allocations = dict(current.allocations)
            allocations[key] = allocation
            next_state = _BudgetState(
                allocations=MappingProxyType(allocations),
                reserved_bytes=next_bytes,
                reserved_objects=next_objects,
                reserved_readers=next_readers,
                reserved_file_descriptors=next_fds,
                high_water_bytes=max(current.high_water_bytes, next_bytes),
                high_water_objects=max(current.high_water_objects, next_objects),
                high_water_readers=max(current.high_water_readers, next_readers),
                high_water_file_descriptors=max(
                    current.high_water_file_descriptors,
                    next_fds,
                ),
            )
            self._state = next_state
        lease = _CaptureBudgetLease(self, key)
        try:
            self._hit("budget.after_reserve")
        except BaseException as reservation_error:
            try:
                self._release_owner(key)
            except BaseException as cleanup_error:
                reservation_error.add_note(
                    f"Budget reservation rollback required retry: {cleanup_error}"
                )
            raise
        return lease

    def _validate_totals(
        self,
        bytes_reserved: int,
        objects_reserved: int,
        readers_reserved: int,
        file_descriptors_reserved: int,
    ) -> None:
        """
        Validate totals.

        The implementation uses ``bytes_reserved``, ``objects_reserved``,
        ``readers_reserved``, and ``file_descriptors_reserved`` to validate
        totals. Every required invariant is checked before a successful value is
        returned; invalid input follows the function's explicit exception path.

        Args:
            bytes_reserved: Numeric bytes reserved used while the operation
                performs bounded accounting.
            objects_reserved: Numeric objects reserved used while the operation
                performs bounded accounting.
            readers_reserved: Numeric readers reserved used while the operation
                performs bounded accounting.
            file_descriptors_reserved: Numeric file descriptors reserved used
                while the operation performs bounded accounting.

        Raises:
            CaptureLimitExceeded: If a configured resource limit is exceeded
                while attempting to validate totals.
        """
        limits = (
            (
                bytes_reserved,
                self.max_bytes,
                "concurrent private capture spool byte limit",
                "bytes",
            ),
            (
                objects_reserved,
                self.max_objects,
                "concurrent private capture object limit",
                "objects",
            ),
            (
                readers_reserved,
                self.max_readers,
                "concurrent private capture reader limit",
                "readers",
            ),
            (
                file_descriptors_reserved,
                self.max_file_descriptors,
                "concurrent private capture file descriptor limit",
                "file descriptors",
            ),
        )
        for attempted, limit, name, unit in limits:
            if attempted > limit:
                raise CaptureLimitExceeded(name, limit, attempted, unit=unit)

    def allocation_for(self, owner_key: object) -> Optional[_BudgetAllocation]:
        """
        Return the allocation for.

        After applying local validation, the function forwards ``owner_key`` to
        ``self._state.allocations.get`` and preserves its return and exception
        contract.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.

        Returns:
            A ``_BudgetAllocation`` representing allocation for, or ``None``
            when the requested value is unavailable.
        """
        with self._lock:
            return self._state.allocations.get(owner_key)

    def is_active(self, owner_key: object) -> bool:
        """
        Return whether ``owner_key`` is active.

        The implementation uses ``owner_key`` to determine whether ``owner_key``
        is active.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.

        Returns:
            Whether ``owner_key`` is active.
        """
        with self._lock:
            return owner_key in self._state.allocations

    def _resize_bytes(self, owner_key: object, delta_bytes: int) -> None:
        """
        Resize a concurrent spool reservation within the shared budget.

        The implementation uses ``owner_key`` and ``delta_bytes`` to resize a
        concurrent spool reservation within the shared budget. It updates
        ``_state`` on the instance as part of that state transition. If the
        function cannot resize a concurrent spool reservation within the shared
        budget, its exception reaches the caller instead of being converted into
        a successful result.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.
            delta_bytes: Numeric delta bytes used while the operation performs
                bounded accounting.

        Raises:
            RuntimeError: If private capture budget lease is released; or
                private capture byte release exceeds owner reservation.
        """
        with self._lock:
            current = self._state
            allocation = current.allocations.get(owner_key)
            if allocation is None:
                raise RuntimeError("Private capture budget lease is released")
            next_owner_bytes = allocation.bytes_reserved + delta_bytes
            if next_owner_bytes < 0:
                raise RuntimeError(
                    "Private capture byte release exceeds owner reservation"
                )
            next_bytes = current.reserved_bytes + delta_bytes
            self._validate_totals(
                next_bytes,
                current.reserved_objects,
                current.reserved_readers,
                current.reserved_file_descriptors,
            )
            allocations = dict(current.allocations)
            allocations[owner_key] = _BudgetAllocation(
                kind=allocation.kind,
                bytes_reserved=next_owner_bytes,
                objects_reserved=allocation.objects_reserved,
                readers_reserved=allocation.readers_reserved,
                file_descriptors_reserved=allocation.file_descriptors_reserved,
            )
            self._state = _BudgetState(
                allocations=MappingProxyType(allocations),
                reserved_bytes=next_bytes,
                reserved_objects=current.reserved_objects,
                reserved_readers=current.reserved_readers,
                reserved_file_descriptors=current.reserved_file_descriptors,
                high_water_bytes=max(current.high_water_bytes, next_bytes),
                high_water_objects=current.high_water_objects,
                high_water_readers=current.high_water_readers,
                high_water_file_descriptors=current.high_water_file_descriptors,
            )
        self._hit("budget.after_resize")

    def _release_owner(self, owner_key: object) -> bool:
        """
        Release owner.

        The implementation uses ``owner_key`` to release owner. It updates
        ``_state`` on the instance as part of that state transition.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.

        Returns:
            Whether the release owner operation succeeds.
        """
        with self._lock:
            current = self._state
            allocation = current.allocations.get(owner_key)
            if allocation is None:
                return False
            allocations = dict(current.allocations)
            del allocations[owner_key]
            self._state = _BudgetState(
                allocations=MappingProxyType(allocations),
                reserved_bytes=current.reserved_bytes - allocation.bytes_reserved,
                reserved_objects=(
                    current.reserved_objects - allocation.objects_reserved
                ),
                reserved_readers=(
                    current.reserved_readers - allocation.readers_reserved
                ),
                reserved_file_descriptors=(
                    current.reserved_file_descriptors
                    - allocation.file_descriptors_reserved
                ),
                high_water_bytes=current.high_water_bytes,
                high_water_objects=current.high_water_objects,
                high_water_readers=current.high_water_readers,
                high_water_file_descriptors=current.high_water_file_descriptors,
            )
        self._hit("budget.after_release")
        return True


@dataclass(frozen=True)
class _PhysicalReservationState:
    """
    Atomically replaced free-space credits keyed by their owner.

    The immutable record keeps ``allocations``, ``reserved_bytes``, and
    ``high_water_bytes`` together so consumers observe one physical reservation
    state. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        allocations: Mapping that retains the allocations fields for this
            record.
        reserved_bytes: Byte count recorded for reserved.
        high_water_bytes: Byte count recorded for high water.
    """

    allocations: Mapping[object, int]
    reserved_bytes: int = 0
    high_water_bytes: int = 0


class CapturePhysicalSpaceReservation:
    """
    Reserve write capacity using only a pinned staging-root descriptor.

    The type coordinates ``_hit``, ``reserved_bytes``, ``high_water_bytes``,
    ``owner_reserved_bytes``, and ``reserve`` and retains the state those
    operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        *,
        min_free_space_reserve_bytes: int = (
            DEFAULT_REDFISH_REQUEST_CAPTURE_MIN_FREE_SPACE_RESERVE_BYTES
        ),
        failpoint: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Initialize a ``CapturePhysicalSpaceReservation`` instance.

        The initializer records ``_failpoint``, ``_lock``, ``_state``, and
        ``min_free_space_reserve_bytes`` for later operations and establishes
        the instance invariants before any public method runs. If the function
        cannot initialize a ``CapturePhysicalSpaceReservation`` instance, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            min_free_space_reserve_bytes: Numeric min free space reserve bytes
                used while the operation performs bounded accounting.
            failpoint: Optional failpoint; ``None`` selects the function's
                default behavior.

        Raises:
            TypeError: If the capture free-space reserve is not an integer.
            ValueError: If the capture free-space reserve is not a positive
                signed-64-bit integer.
        """
        if isinstance(min_free_space_reserve_bytes, bool) or not isinstance(
            min_free_space_reserve_bytes, int
        ):
            raise TypeError("Capture free-space reserve must be an integer")
        if not 0 < min_free_space_reserve_bytes <= MAX_SIGNED_64_BIT_INTEGER:
            raise ValueError(
                "Capture free-space reserve must be a positive signed-64-bit integer"
            )
        self.min_free_space_reserve_bytes = min_free_space_reserve_bytes
        self._state = _PhysicalReservationState(allocations=MappingProxyType({}))
        self._failpoint = failpoint
        self._lock = threading.Lock()

    def _hit(self, name: str) -> None:
        """
        Record a successful lookup or matching event.

        The implementation uses ``name`` to record a successful lookup or
        matching event.

        Args:
            name: Stable name used for lookup and operator-facing diagnostics.
        """
        if self._failpoint is not None:
            self._failpoint(name)

    @property
    def reserved_bytes(self) -> int:
        """
        Return the number of bytes currently reserved.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric reserved bytes value.
        """
        with self._lock:
            return self._state.reserved_bytes

    @property
    def high_water_bytes(self) -> int:
        """
        Return the high water bytes.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric high water bytes value.
        """
        with self._lock:
            return self._state.high_water_bytes

    def owner_reserved_bytes(self, owner_key: object) -> int:
        """
        Return one owner's current unconsumed credit atomically.

        After applying local validation, the function forwards ``owner_key`` to
        ``self._state.allocations.get`` and preserves its return and exception
        contract.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.

        Returns:
            The numeric owner reserved bytes value.
        """

        with self._lock:
            return self._state.allocations.get(owner_key, 0)

    def reserve(
        self,
        root_descriptor: int,
        size_bytes: int,
        capacity_observer: Optional[Callable[[os.statvfs_result, int], None]] = None,
        *,
        owner_key: object,
    ) -> None:
        """
        Add an owner credit after checking the pinned filesystem capacity.

        Snapshot capacity only after serializing reservations. Taking it before
        this lock lets a waiter retain stale free space while a prior owner
        commits, writes, and consumes its reservation.

        Args:
            root_descriptor: Numeric root descriptor used while the operation
                performs bounded accounting.
            size_bytes: Numeric size bytes used while the operation performs
                bounded accounting.
            capacity_observer: Optional capacity observer; ``None`` selects the
                function's default behavior.
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.

        Raises:
            ValueError: If physical capture reservation cannot be negative.
            CaptureLimitExceeded: If private capture filesystem usable byte
                limit after reserve.
        """

        size_bytes = int(size_bytes)
        if size_bytes < 0:
            raise ValueError("Physical capture reservation cannot be negative")
        if size_bytes == 0:
            return
        with self._lock:
            # Snapshot capacity only after serializing reservations. Taking it
            # before this lock lets a waiter retain stale free space while a
            # prior owner commits, writes, and consumes its reservation.
            filesystem = os.fstatvfs(root_descriptor)
            current = self._state
            attempted = current.reserved_bytes + size_bytes
            available = int(filesystem.f_bavail) * int(filesystem.f_frsize)
            usable = max(0, available - self.min_free_space_reserve_bytes)
            if attempted > usable:
                raise CaptureLimitExceeded(
                    "private capture filesystem usable byte limit after reserve",
                    usable,
                    attempted,
                )
            if capacity_observer is not None:
                capacity_observer(filesystem, attempted)
            allocations = dict(current.allocations)
            allocations[owner_key] = allocations.get(owner_key, 0) + size_bytes
            self._state = _PhysicalReservationState(
                allocations=MappingProxyType(allocations),
                reserved_bytes=attempted,
                high_water_bytes=max(current.high_water_bytes, attempted),
            )
        self._hit("physical.after_reserve")

    def consume(self, owner_key: object, size_bytes: int) -> None:
        """
        Consume capacity after those bytes are durably allocated.

        The implementation uses ``owner_key`` and ``size_bytes`` to consume
        capacity after those bytes are durably allocated.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.
            size_bytes: Numeric size bytes used while the operation performs
                bounded accounting.
        """

        self._release(owner_key, size_bytes, "physical.after_consume")

    def consume_owner(self, owner_key: object) -> bool:
        """
        Consume every credit only after its owner has synced allocation.

        After applying local validation, the function forwards ``owner_key`` to
        ``self._release_owner`` and preserves its return and exception contract.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.

        Returns:
            Whether the consume every credit only after its owner has synced
            allocation operation succeeds.
        """

        return self._release_owner(owner_key, "physical.after_consume")

    def release_owner(self, owner_key: object) -> bool:
        """
        Idempotently release all unconsumed credits for one owner.

        After applying local validation, the function forwards ``owner_key`` to
        ``self._release_owner`` and preserves its return and exception contract.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.

        Returns:
            Whether the idempotently release all unconsumed credits for one
            owner operation succeeds.
        """

        return self._release_owner(owner_key, "physical.after_release")

    def rollback(self, owner_key: object, size_bytes: int) -> None:
        """
        Roll back only one failed reservation delta, preserving older credit.

        The implementation uses ``owner_key`` and ``size_bytes`` to roll back
        only one failed reservation delta, preserving older credit.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.
            size_bytes: Numeric size bytes used while the operation performs
                bounded accounting.
        """

        self._release(owner_key, size_bytes, "physical.after_release")

    def _release_owner(self, owner_key: object, failpoint: str) -> bool:
        """
        Read and remove one complete owner allocation atomically.

        The implementation uses ``owner_key`` and ``failpoint`` to read and
        remove one complete owner allocation atomically. Parsing or I/O must
        finish before the validated representation is made available to the
        caller. It updates ``_state`` on the instance as part of that state
        transition.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.
            failpoint: Text supplied as failpoint in the format accepted by this
                function.

        Returns:
            Whether the and remove one complete owner allocation atomically
            operation succeeds.
        """

        with self._lock:
            current = self._state
            amount = current.allocations.get(owner_key)
            if amount is None:
                return False
            self._hit("physical.before_release_owner_commit")
            allocations = dict(current.allocations)
            del allocations[owner_key]
            self._state = _PhysicalReservationState(
                allocations=MappingProxyType(allocations),
                reserved_bytes=current.reserved_bytes - amount,
                high_water_bytes=current.high_water_bytes,
            )
        self._hit(failpoint)
        return True

    def _release(self, owner_key: object, size_bytes: int, failpoint: str) -> None:
        """
        Release the currently owned resource.

        The implementation uses ``owner_key``, ``size_bytes``, and ``failpoint``
        to release the currently owned resource. It updates ``_state`` on the
        instance as part of that state transition. If the function cannot
        release the currently owned resource, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.
            size_bytes: Numeric size bytes used while the operation performs
                bounded accounting.
            failpoint: Text supplied as failpoint in the format accepted by this
                function.

        Raises:
            ValueError: If physical capture reservation release cannot be
                negative.
            RuntimeError: If physical capture reservation release exceeds owner
                credit.
        """
        size_bytes = int(size_bytes)
        if size_bytes < 0:
            raise ValueError("Physical capture reservation release cannot be negative")
        if size_bytes == 0:
            return
        with self._lock:
            current = self._state
            owned = current.allocations.get(owner_key)
            if owned is None or size_bytes > owned:
                raise RuntimeError(
                    "Physical capture reservation release exceeds owner credit"
                )
            allocations = dict(current.allocations)
            remaining = owned - size_bytes
            if remaining:
                allocations[owner_key] = remaining
            else:
                del allocations[owner_key]
            self._state = _PhysicalReservationState(
                allocations=MappingProxyType(allocations),
                reserved_bytes=current.reserved_bytes - size_bytes,
                high_water_bytes=current.high_water_bytes,
            )
        self._hit(failpoint)


class _PrivateFileRole(str, Enum):
    """
    Private file purpose used for diagnostics and resource accounting.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    SPOOL = "spool"
    STAGED_RECORD = "staged record"
    CANDIDATE = "candidate"
    VERIFIED_COPY = "verified copy"


class _PrivateFilePhase(str, Enum):
    """
    Enumerate the supported private file phase values.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    ALLOCATING = "allocating"
    OPEN = "open"
    CLOSED = "closed"


@dataclass(frozen=True)
class _PrivateFileState:
    """
    One explicitly owned descriptor lifecycle snapshot.

    The immutable record keeps ``descriptor``, ``identity``, ``leaf_name``,
    ``linked``, and ``compromised_links_scrubbed`` together so consumers observe
    one private file state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        descriptor: Numeric descriptor retained by this record.
        identity: Collection of identity entries retained by this record.
        leaf_name: Canonical text used as leaf name.
        linked: Whether linked applies to this record.
        compromised_links_scrubbed: Whether compromised links scrubbed applies
            to this record.
        phase: Phase retained as part of the record's public state.
        cleanup_failures: Collection of cleanup failures entries retained by
            this record.
    """

    descriptor: int = -1
    identity: Optional[tuple[int, int]] = None
    leaf_name: Optional[str] = None
    linked: bool = False
    compromised_links_scrubbed: bool = False
    phase: _PrivateFilePhase = _PrivateFilePhase.ALLOCATING
    cleanup_failures: tuple[str, ...] = ()


@dataclass(frozen=True)
class _RegistryState:
    """
    Represent registry state data exchanged by the runtime.

    The immutable record keeps ``entries`` and ``failed_owners`` together so
    consumers observe one registry state. Consumers receive the fields as one
    unit instead of assembling partial state.

    Attributes:
        entries: Mapping that retains the entries fields for this record.
        failed_owners: Collection of failed owners entries retained by this
            record.
    """

    entries: Mapping[object, "_OwnedPrivateFile"]
    failed_owners: frozenset[object] = frozenset()


class _OwnedPrivateFile:
    """
    Registry-owned anonymous file with exact byte and descriptor leases.

    The type coordinates ``cleanup_complete``, ``cleanup_failures``,
    ``reserved_bytes``, ``_hit``, and ``allocate`` and retains the state those
    operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    _FALLBACK_ERRNOS = frozenset(
        {
            errno.EINVAL,
            errno.EISDIR,
            errno.ENOENT,
            errno.ENOSYS,
            errno.EOPNOTSUPP,
            getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
        }
    )

    def __init__(
        self,
        context: "_CaptureContext",
        owner_key: object,
        role: _PrivateFileRole,
    ) -> None:
        """
        Initialize an ``_OwnedPrivateFile`` instance.

        The initializer records ``_context``, ``_lock``, ``_physical_key``,
        ``_resource_key``, and ``_state`` for later operations and establishes
        the instance invariants before any public method runs.

        Args:
            context: Runtime context carrying state shared across this
                operation.
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.
            role: Role consumed while the function attempts to initialize an
                ``_OwnedPrivateFile`` instance.
        """
        self._context = context
        self.owner_key = owner_key
        self.role = role
        self._resource_key = (owner_key, "resource")
        self._physical_key = (owner_key, "physical")
        self._state = _PrivateFileState()
        self._lock = threading.RLock()

    @property
    def cleanup_complete(self) -> bool:
        """
        Return whether cleanup complete.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            Whether cleanup complete.
        """
        with self._lock:
            return self._state.phase is _PrivateFilePhase.CLOSED

    @property
    def cleanup_failures(self) -> tuple[str, ...]:
        """
        Return the cleanup failures.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The cleanup failures returned in operation-defined order.
        """
        with self._lock:
            return self._state.cleanup_failures

    @property
    def reserved_bytes(self) -> int:
        """
        Return the number of bytes currently reserved.

        Each access computes the value from ``_context`` and ``_resource_key``
        on the current instance; the derived view is not stored as independent
        state.

        Returns:
            The numeric reserved bytes value.
        """
        allocation = self._context.budget.allocation_for(self._resource_key)
        return 0 if allocation is None else allocation.bytes_reserved

    def _hit(self, name: str) -> None:
        """
        Record a successful lookup or matching event.

        The implementation uses ``name`` to record a successful lookup or
        matching event.

        Args:
            name: Stable name used for lookup and operator-facing diagnostics.
        """
        self._context.hit(name)

    def allocate(self) -> None:
        """
        Allocate and immediately anonymize this registry-owned file.

        The implementation uses current instance state to allocate and
        immediately anonymize this registry-owned file.
        """

        self._context.budget.reserve(
            kind=f"private capture {self.role.value}",
            objects=1,
            file_descriptors=1,
            owner_key=self._resource_key,
        )
        self._hit("file.after_resource_reserve")
        tmpfile_flag = getattr(os, "O_TMPFILE", 0)
        if tmpfile_flag:
            try:
                self._open_and_adopt(
                    ".",
                    os.O_RDWR | os.O_CLOEXEC | tmpfile_flag,
                    leaf_name=None,
                    linked=False,
                )
            except OSError as error:
                with self._lock:
                    descriptor_was_adopted = self._state.descriptor >= 0
                if descriptor_was_adopted or error.errno not in self._FALLBACK_ERRNOS:
                    raise
            else:
                self._finish_allocation()
                return
        self._allocate_unlinked_fallback()
        self._finish_allocation()

    def _open_and_adopt(
        self,
        name: str,
        flags: int,
        *,
        leaf_name: Optional[str],
        linked: bool,
    ) -> None:
        """
        Guard the open-to-registry transfer with a close sentinel.

        The implementation uses ``name``, ``flags``, ``leaf_name``, and
        ``linked`` to guard the open-to-registry transfer with a close sentinel.
        It updates ``_state`` on the instance as part of that state transition.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Args:
            name: Stable name used for lookup and operator-facing diagnostics.
            flags: Numeric flags used while the operation performs bounded
                accounting.
            leaf_name: Stable leaf name used for lookup and operator-facing
                diagnostics.
            linked: Whether linked is enabled or required for this operation.
        """

        descriptor = -1
        adopted = False
        try:
            descriptor = os.open(
                name,
                flags,
                0o600,
                dir_fd=self._context.root_descriptor,
            )
            with self._lock:
                self._state = replace(
                    self._state,
                    descriptor=descriptor,
                    leaf_name=leaf_name,
                    linked=linked,
                )
            adopted = True
            self._hit("file.after_descriptor_adopt")
            os.fchmod(descriptor, 0o600)
            descriptor_stat = os.fstat(descriptor)
            identity = (descriptor_stat.st_dev, descriptor_stat.st_ino)
            with self._lock:
                self._state = replace(self._state, identity=identity)
            self._hit("file.after_identity_adopt")
        finally:
            if descriptor >= 0 and not adopted:
                os.close(descriptor)

    def _allocate_unlinked_fallback(self) -> None:
        """
        Allocate a private unlinked fallback file.

        The implementation uses current instance state to allocate a private
        unlinked fallback file. If the function cannot allocate a private
        unlinked fallback file, its exception reaches the caller instead of
        being converted into a successful result.

        Raises:
            OSError: If unable to allocate a unique private capture leaf.
        """
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW
            | getattr(os, "O_NONBLOCK", 0)
        )
        for _attempt in range(128):
            leaf_name = f".nvdebug-private-{secrets.token_hex(18)}"
            try:
                self._open_and_adopt(
                    leaf_name,
                    flags,
                    leaf_name=leaf_name,
                    linked=True,
                )
            except FileExistsError:
                continue
            break
        else:
            raise OSError("Unable to allocate a unique private capture leaf")

        self._hit("file.before_fallback_unlink")
        self._unlink_owned_fallback()
        self._hit("file.after_fallback_unlink")

    def _finish_allocation(self) -> None:
        """
        Finish allocation.

        The implementation uses current instance state to finish allocation. It
        updates ``_state`` on the instance as part of that state transition.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle. If the function cannot finish allocation, its
        exception reaches the caller instead of being converted into a
        successful result.

        Raises:
            CaptureFilesystemBoundaryError: If private capture descriptor
                ownership is incomplete.
        """
        with self._lock:
            state = self._state
        if state.descriptor < 0 or state.identity is None:
            raise CaptureFilesystemBoundaryError(
                "Private capture descriptor ownership is incomplete"
            )
        _assert_private_descriptor(
            state.descriptor,
            state.identity,
            expected_size=0,
            expected_digest=hashlib.sha256(b"").hexdigest(),
        )
        with self._lock:
            self._state = replace(self._state, phase=_PrivateFilePhase.OPEN)
        self._hit("file.after_open_commit")

    def _unlink_owned_fallback(self) -> None:
        """
        Remove owned fallback.

        The final descriptor link-count check below decides whether an unknown
        link must be scrubbed.

        Raises:
            CaptureFilesystemBoundaryError: If private capture fallback identity
                is unavailable; or private capture fallback hard link was
                scrubbed.
        """
        with self._lock:
            state = self._state
        if not state.linked:
            return
        if not state.leaf_name or state.identity is None:
            raise CaptureFilesystemBoundaryError(
                "Private capture fallback identity is unavailable"
            )
        try:
            leaf_stat = os.stat(
                state.leaf_name,
                dir_fd=self._context.root_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            # The final descriptor link-count check below decides whether an
            # unknown link must be scrubbed.
            pass
        else:
            if (leaf_stat.st_dev, leaf_stat.st_ino) != state.identity:
                # Never unlink a replacement path. The final descriptor
                # link-count check handles any surviving link to our inode.
                pass
            else:
                os.unlink(
                    state.leaf_name,
                    dir_fd=self._context.root_descriptor,
                )
        descriptor_stat = os.fstat(state.descriptor)
        if descriptor_stat.st_nlink != 0:
            # Another same-UID process may have linked the short-lived fallback
            # inode through /proc between open and unlink. The unknown link can
            # never be named safely, so destroy its content before surrendering
            # the descriptor. Construction then fails closed.
            os.ftruncate(state.descriptor, 0)
            os.fsync(state.descriptor)
            self._context.physical.release_owner(self._physical_key)
            if self.reserved_bytes:
                self._context.budget._resize_bytes(
                    self._resource_key, -self.reserved_bytes
                )
            with self._lock:
                self._state = replace(
                    self._state,
                    linked=False,
                    compromised_links_scrubbed=True,
                )
            raise CaptureFilesystemBoundaryError(
                "Private capture fallback hard link was scrubbed"
            )
        with self._lock:
            self._state = replace(self._state, linked=False)

    def _open_state(self) -> _PrivateFileState:
        """
        Open state.

        The implementation uses current instance state to open state. If the
        function cannot open state, its exception reaches the caller instead of
        being converted into a successful result.

        Returns:
            The validated ``state``.

        Raises:
            RuntimeError: If private capture file is not open.
            CaptureFilesystemBoundaryError: If private capture descriptor
                ownership is incomplete.
        """
        with self._lock:
            state = self._state
        if state.phase is not _PrivateFilePhase.OPEN:
            raise RuntimeError("Private capture file is not open")
        if state.descriptor < 0 or state.identity is None:
            raise CaptureFilesystemBoundaryError(
                "Private capture descriptor ownership is incomplete"
            )
        self._context.assert_root()
        return state

    def verify(
        self,
        *,
        expected_size: Optional[int] = None,
        expected_digest: Optional[str] = None,
    ) -> os.stat_result:
        """
        Verify the current _OwnedPrivateFile state.

        After applying local validation, the function forwards ``expected_size``
        and ``expected_digest`` to ``_assert_private_descriptor`` and preserves
        its return and exception contract. Every required invariant is checked
        before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Args:
            expected_size: Numeric expected size used by the operation's bounded
                accounting.
            expected_digest: Optional expected digest; ``None`` selects the
                function's default behavior.

        Returns:
            A ``stat_result`` representing verify.
        """
        state = self._open_state()
        return _assert_private_descriptor(
            state.descriptor,
            state.identity,
            expected_size=expected_size,
            expected_digest=expected_digest,
        )

    def read_at(self, size_bytes: int, offset: int) -> bytes:
        """
        Read at.

        After applying local validation, the function forwards ``size_bytes``
        and ``offset`` to ``os.pread`` and preserves its return and exception
        contract. Parsing or I/O must finish before the validated representation
        is made available to the caller.

        Args:
            size_bytes: Numeric size bytes used while the operation performs
                bounded accounting.
            offset: Numeric offset used by the operation's bounded accounting.

        Returns:
            The bounded at bytes.

        Raises:
            ValueError: If private capture reads must use fixed-size chunks.
        """
        if size_bytes < 0 or size_bytes > _COPY_CHUNK_BYTES:
            raise ValueError("Private capture reads must use fixed-size chunks")
        state = self._open_state()
        return os.pread(state.descriptor, size_bytes, offset)

    def write_at(self, payload: bytes, offset: int) -> None:
        """
        Write exactly one payload while retaining all accounting ownership.

        The implementation uses ``payload`` and ``offset`` to write exactly one
        payload while retaining all accounting ownership. Success is reported
        only after the owning output boundary has completed its required write
        or publication step. If the function cannot write exactly one payload
        while retaining all accounting ownership, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            payload: Bounded byte sequence supplied as payload.
            offset: Numeric offset used by the operation's bounded accounting.

        Raises:
            ValueError: If private capture write offset cannot be negative.
            AssertionError: If unreachable reservation rollback outcome.
            OSError: If incomplete capture filesystem write.
        """

        if offset < 0:
            raise ValueError("Private capture write offset cannot be negative")
        data = memoryview(payload)
        state = self._open_state()
        before = os.fstat(state.descriptor).st_size
        reserved_growth = max(0, offset + data.nbytes - before)
        if reserved_growth:
            self._context.budget._resize_bytes(
                self._resource_key,
                reserved_growth,
            )
            physical_before = self._context.physical.owner_reserved_bytes(
                self._physical_key
            )
            try:
                self._context.physical.reserve(
                    self._context.root_descriptor,
                    reserved_growth,
                    self._context.capacity_observer,
                    owner_key=self._physical_key,
                )
            except BaseException as reserve_error:
                rollback_errors: list[BaseException] = []
                physical_after = self._context.physical.owner_reserved_bytes(
                    self._physical_key
                )
                committed_growth = max(0, physical_after - physical_before)
                try:
                    if committed_growth:
                        self._context.physical.rollback(
                            self._physical_key,
                            min(committed_growth, reserved_growth),
                        )
                except BaseException as rollback_error:
                    rollback_errors.append(rollback_error)
                try:
                    self._context.budget._resize_bytes(
                        self._resource_key,
                        -reserved_growth,
                    )
                except BaseException as rollback_error:
                    rollback_errors.append(rollback_error)
                _raise_capture_cleanup_outcome(
                    None,
                    [reserve_error, *rollback_errors],
                    "Private capture reservation rollback failed",
                )
                raise AssertionError("unreachable reservation rollback outcome")
        written_total = 0
        try:
            while written_total < data.nbytes:
                written = os.pwrite(
                    state.descriptor,
                    data[written_total : written_total + _COPY_CHUNK_BYTES],
                    offset + written_total,
                )
                if written <= 0:
                    raise OSError("Incomplete capture filesystem write")
                written_total += written
            self._hit("file.after_write")
        except BaseException:
            self.sync_reserved_bytes()
            raise

    def append(self, payload: bytes) -> None:
        """
        Append the supplied bytes to the owned output.

        The implementation uses ``payload`` to append the supplied bytes to the
        owned output.

        Args:
            payload: Bounded byte sequence supplied as payload.
        """
        state = self._open_state()
        self.write_at(payload, os.fstat(state.descriptor).st_size)

    def truncate(self, size_bytes: int) -> None:
        """
        Truncate the owned private file to the requested bounded size.

        The implementation uses ``size_bytes`` to truncate the owned private
        file to the requested bounded size. If the function cannot truncate the
        owned private file to the requested bounded size, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            size_bytes: Numeric size bytes used while the operation performs
                bounded accounting.

        Raises:
            ValueError: If private capture truncate size cannot be negative.
        """
        if size_bytes < 0:
            raise ValueError("Private capture truncate size cannot be negative")
        state = self._open_state()
        os.ftruncate(state.descriptor, size_bytes)
        self._context.physical.release_owner(self._physical_key)
        self._hit("file.after_truncate")
        self.sync_reserved_bytes()

    def sync_reserved_bytes(self) -> None:
        """
        Conservatively reconcile the byte lease to the descriptor size.

        The implementation uses current instance state to conservatively
        reconcile the byte lease to the descriptor size.
        """

        state = self._open_state()
        actual = os.fstat(state.descriptor).st_size
        reserved = self.reserved_bytes
        delta = actual - reserved
        if delta:
            self._context.budget._resize_bytes(self._resource_key, delta)

    def fsync(self) -> None:
        """
        Synchronize the owned file's pending data and metadata.

        Delayed-allocation filesystems may not debit f_bavail until fsync.
        Retain every growth credit through that durability boundary so no
        concurrent owner can reserve against the same apparently free block.
        """
        state = self._open_state()
        os.fsync(state.descriptor)
        # Delayed-allocation filesystems may not debit f_bavail until fsync.
        # Retain every growth credit through that durability boundary so no
        # concurrent owner can reserve against the same apparently free block.
        self._context.physical.consume_owner(self._physical_key)

    def mutate_for_test(self, payload: bytes, offset: int = 0) -> None:
        """
        Private adversarial-test seam; never returns a descriptor or path.

        The implementation uses ``payload`` and ``offset`` to private
        adversarial-test seam; never returns a descriptor or path.

        Args:
            payload: Bounded byte sequence supplied as payload.
            offset: Numeric offset used by the operation's bounded accounting.
        """

        state = self._open_state()
        os.pwrite(state.descriptor, payload, offset)

    def truncate_for_test(self, size_bytes: int) -> None:
        """
        Private adversarial-test seam; deliberately bypasses accounting.

        The implementation uses ``size_bytes`` to private adversarial-test seam;
        deliberately bypasses accounting.

        Args:
            size_bytes: Numeric size bytes used while the operation performs
                bounded accounting.
        """

        state = self._open_state()
        os.ftruncate(state.descriptor, size_bytes)

    def add_hardlink_failure_for_test(self) -> None:
        """
        Fail explicitly because anonymous files must never acquire links.

        The implementation uses current instance state to fail explicitly
        because anonymous files must never acquire links. If the function cannot
        fail explicitly because anonymous files must never acquire links, its
        exception reaches the caller instead of being converted into a
        successful result.

        Raises:
            CaptureFilesystemBoundaryError: If private capture descriptor
                unexpectedly has filesystem links; or anonymous private capture
                descriptors cannot be hard-linked by this API.
        """

        state = self._open_state()
        if os.fstat(state.descriptor).st_nlink:
            raise CaptureFilesystemBoundaryError(
                "Private capture descriptor unexpectedly has filesystem links"
            )
        raise CaptureFilesystemBoundaryError(
            "Anonymous private capture descriptors cannot be hard-linked by this API"
        )

    def cleanup(self) -> None:
        """
        Retry-safe unlink, close, capacity, and token release.

        The implementation uses current instance state to retry-safe unlink,
        close, capacity, and token release. It updates ``_state`` on the
        instance as part of that state transition. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        """

        try:
            self._cleanup_once()
        except BaseException as error:
            with self._lock:
                self._state = replace(
                    self._state,
                    cleanup_failures=(
                        *self._state.cleanup_failures,
                        f"{type(error).__name__}: {error}",
                    ),
                )
            raise

    def _cleanup_once(self) -> None:
        """
        Clean up once.

        The implementation uses current instance state to clean up once. It
        updates ``_state`` on the instance as part of that state transition.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle.
        """
        with self._lock:
            state = self._state
        if state.phase is _PrivateFilePhase.CLOSED:
            return

        if state.descriptor >= 0:
            try:
                descriptor_stat = os.fstat(state.descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
                with self._lock:
                    self._state = replace(self._state, descriptor=-1, linked=False)
            else:
                observed_identity = (
                    descriptor_stat.st_dev,
                    descriptor_stat.st_ino,
                )
                if state.identity is None:
                    with self._lock:
                        self._state = replace(
                            self._state,
                            identity=observed_identity,
                        )
                elif observed_identity != state.identity:
                    # A prior close completed but its bookkeeping was
                    # interrupted and the integer descriptor was reused. Never
                    # close the replacement descriptor.
                    with self._lock:
                        self._state = replace(
                            self._state,
                            descriptor=-1,
                            linked=False,
                        )

        with self._lock:
            state = self._state
        if state.descriptor >= 0 and state.linked:
            self._unlink_owned_fallback()
            with self._lock:
                state = self._state

        if state.descriptor >= 0:
            descriptor_stat = os.fstat(state.descriptor)
            if descriptor_stat.st_nlink != 0:
                # Never retain confidential bytes solely because an attacker
                # created an unnameable same-UID hard link. Scrub and durably
                # truncate first; the surviving external inode is empty.
                os.ftruncate(state.descriptor, 0)
                os.fsync(state.descriptor)
                self._context.physical.release_owner(self._physical_key)
                if self.reserved_bytes:
                    self._context.budget._resize_bytes(
                        self._resource_key, -self.reserved_bytes
                    )
                with self._lock:
                    self._state = replace(
                        self._state,
                        compromised_links_scrubbed=True,
                    )
            os.close(state.descriptor)
            self._hit("file.after_descriptor_close")
            with self._lock:
                self._state = replace(self._state, descriptor=-1, linked=False)

        self._context.physical.release_owner(self._physical_key)
        self._context.budget._release_owner(self._resource_key)
        self._hit("file.after_resource_release")
        with self._lock:
            self._state = replace(
                self._state,
                descriptor=-1,
                linked=False,
                phase=_PrivateFilePhase.CLOSED,
            )


class _PrivateFileRegistry:
    """
    Canonical cleanup owner for every private capture file.

    The type coordinates ``entry_count``, ``failed_count``, ``assert_ready``,
    ``create``, and ``get`` and retains the state those operations share between
    calls. Resource ownership remains inside the instance until the matching
    close, exit, or cleanup operation completes.
    """

    def __init__(self, context: "_CaptureContext") -> None:
        """
        Initialize a ``_PrivateFileRegistry`` instance.

        The initializer records ``_context``, ``_lock``, and ``_state`` for
        later operations and establishes the instance invariants before any
        public method runs.

        Args:
            context: Runtime context carrying state shared across this
                operation.
        """
        self._context = context
        self._state = _RegistryState(entries=MappingProxyType({}))
        self._lock = threading.RLock()

    @property
    def entry_count(self) -> int:
        """
        Return the entry count.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric entry count.
        """
        with self._lock:
            return len(self._state.entries)

    @property
    def failed_count(self) -> int:
        """
        Return the failed count.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric failed count.
        """
        with self._lock:
            return len(self._state.failed_owners)

    def assert_ready(self) -> None:
        """
        Verify ready.

        The implementation uses current instance state to verify ready. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Raises:
            RuntimeError: If the pending private capture cleanup is not retried
                before new work.
        """
        if self.failed_count:
            raise RuntimeError(
                "Pending private capture cleanup must be retried before new work"
            )

    def create(self, role: _PrivateFileRole) -> _OwnedPrivateFile:
        """
        Create the configured resource.

        The implementation uses ``role`` to create the configured resource. It
        updates ``_state`` on the instance as part of that state transition.

        Args:
            role: Role consumed while the function attempts to create the
                configured resource.

        Returns:
            The validated ``owned``.
        """
        self.assert_ready()
        owner_key = object()
        owned = _OwnedPrivateFile(self._context, owner_key, role)
        with self._lock:
            entries = dict(self._state.entries)
            entries[owner_key] = owned
            self._state = _RegistryState(
                entries=MappingProxyType(entries),
                failed_owners=self._state.failed_owners,
            )
        try:
            owned.allocate()
        except BaseException as construction_error:
            try:
                self.cleanup(owner_key)
            except BaseException as cleanup_error:
                construction_error.add_note(
                    "Private capture construction cleanup remains owned for retry: "
                    f"{cleanup_error}"
                )
            raise
        return owned

    def get(self, owner_key: object) -> Optional[_OwnedPrivateFile]:
        """
        Return get.

        After applying local validation, the function forwards ``owner_key`` to
        ``self._state.entries.get`` and preserves its return and exception
        contract.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.

        Returns:
            A ``_OwnedPrivateFile`` returned after get, or ``None`` when the
            requested value is unavailable.
        """
        with self._lock:
            return self._state.entries.get(owner_key)

    def cleanup(self, owner_key: object) -> bool:
        """
        Clean up resources owned by the _PrivateFileRegistry.

        The implementation uses ``owner_key`` to clean up resources owned by the
        _PrivateFileRegistry. It updates ``_state`` on the instance as part of
        that state transition.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.

        Returns:
            Whether the clean up resources owned by the _PrivateFileRegistry
            operation succeeds.
        """
        with self._lock:
            owned = self._state.entries.get(owner_key)
        if owned is None:
            return False
        try:
            owned.cleanup()
            self._context.hit("registry.after_file_cleanup")
            with self._lock:
                entries = dict(self._state.entries)
                entries.pop(owner_key, None)
                self._state = _RegistryState(
                    entries=MappingProxyType(entries),
                    failed_owners=(self._state.failed_owners - frozenset({owner_key})),
                )
            self._context.hit("registry.after_owner_release")
        except BaseException:
            with self._lock:
                if owner_key in self._state.entries:
                    self._state = _RegistryState(
                        entries=self._state.entries,
                        failed_owners=(
                            self._state.failed_owners | frozenset({owner_key})
                        ),
                    )
            raise
        return True

    def retry_failures(self) -> None:
        """
        Retry failures.

        The implementation uses current instance state to retry failures.
        """
        with self._lock:
            failed = tuple(self._state.failed_owners)
        errors: list[BaseException] = []
        for owner_key in failed:
            try:
                self.cleanup(owner_key)
            except BaseException as error:
                errors.append(error)
        _raise_capture_cleanup_outcome(
            None,
            errors,
            "Private capture registry retry failed",
        )


@dataclass(frozen=True)
class _ContextState:
    """
    Represent context state data exchanged by the runtime.

    The immutable record keeps ``root_descriptor``, ``root_identity``,
    ``live_spools``, ``root_removed``, and ``root_parent_identity`` together so
    consumers observe one context state. Consumers receive the fields as one
    unit instead of assembling partial state.

    Attributes:
        root_descriptor: Numeric root descriptor retained by this record.
        root_identity: Collection of root identity entries retained by this
            record.
        owner_uid: Verified caller UID as reported by the staging filesystem.
        live_spools: Collection of live spools entries retained by this record.
        root_removed: Whether root removed applies to this record.
        root_parent_identity: Collection of root parent identity entries
            retained by this record.
        root_parent_synced: Whether root parent synced applies to this record.
        closed: Whether closed applies to this record.
        close_failures: Collection of close failures entries retained by this
            record.
    """

    root_descriptor: int
    root_identity: tuple[int, int]
    owner_uid: int
    live_spools: frozenset[object] = frozenset()
    root_removed: bool = False
    root_parent_identity: Optional[tuple[int, int]] = None
    root_parent_synced: bool = False
    closed: bool = False
    close_failures: tuple[str, ...] = ()


class _CaptureContext:
    """
    Pinned root, registry, and shared resource-accounting context.

    The type coordinates ``open``, ``hit``, ``root_descriptor``,
    ``live_spool_count``, and ``assert_root`` and retains the state those
    operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        *,
        root_path: Path,
        root_descriptor: int,
        root_identity: tuple[int, int],
        owner_uid: int,
        budget: ConcurrentPrivateSpoolBudget,
        physical: CapturePhysicalSpaceReservation,
        capacity_observer: Optional[Callable[[os.statvfs_result, int], None]],
        auto_close: bool,
        remove_root_on_close: bool,
        failpoint: Optional[Callable[[str], None]],
    ) -> None:
        """
        Initialize a ``_CaptureContext`` instance.

        The initializer records ``_failpoint``, ``_lock``,
        ``_root_resource_key``, ``_state``, and ``auto_close`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            root_path: filesystem location used as the root path for this
                operation.
            root_descriptor: Numeric root descriptor used while the operation
                performs bounded accounting.
            root_identity: Entries supplied as ``root_identity`` without
                transferring container ownership.
            owner_uid: Verified staging-filesystem UID retained across capture
                writes, publication, and cleanup without further probes.
            budget: Budget consumed while the function attempts to initialize a
                ``_CaptureContext`` instance.
            physical: Physical consumed while the function attempts to
                initialize a ``_CaptureContext`` instance.
            capacity_observer: Optional capacity observer; ``None`` selects the
                function's default behavior.
            auto_close: Whether auto close is enabled or required for this
                operation.
            remove_root_on_close: Whether remove root on close is enabled or
                required for this operation.
            failpoint: Optional failpoint; ``None`` selects the function's
                default behavior.
        """
        self.root_path = root_path
        self.budget = budget
        self.physical = physical
        self.capacity_observer = capacity_observer
        self.auto_close = auto_close
        self.remove_root_on_close = remove_root_on_close
        self._failpoint = failpoint
        self._root_resource_key = (object(), "root descriptor")
        self._state = _ContextState(
            root_descriptor=root_descriptor,
            root_identity=root_identity,
            owner_uid=owner_uid,
        )
        self._lock = threading.RLock()
        self.registry = _PrivateFileRegistry(self)

    @classmethod
    def open(
        cls,
        staging_root: Path,
        *,
        budget: ConcurrentPrivateSpoolBudget,
        physical: CapturePhysicalSpaceReservation,
        capacity_observer: Optional[Callable[[os.statvfs_result, int], None]] = None,
        auto_close: bool,
        remove_root_on_close: bool = False,
        failpoint: Optional[Callable[[str], None]] = None,
    ) -> "_CaptureContext":
        """
        Open the configured resource.

        The implementation uses ``staging_root``, ``budget``, ``physical``,
        ``capacity_observer``, and ``auto_close`` to open the configured
        resource. Cleanup in the ``finally`` path runs for successful, failed,
        and cancelled execution.

        Args:
            staging_root: filesystem location used as the staging root for this
                operation.
            budget: Budget object whose ``_release_owner`` and ``reserve`` state
                is read while performing open the configured resource.
            physical: Physical consumed while the function attempts to open the
                configured resource.
            capacity_observer: Optional capacity observer; ``None`` selects the
                function's default behavior.
            auto_close: Whether auto close is enabled or required for this
                operation.
            remove_root_on_close: Whether remove root on close is enabled or
                required for this operation.
            failpoint: Optional failpoint; ``None`` selects the function's
                default behavior.

        Returns:
            The validated ``context``.
        """
        root_path, descriptor, identity, owner_uid = _open_private_staging_root(
            staging_root
        )
        context = cls(
            root_path=root_path,
            root_descriptor=descriptor,
            root_identity=identity,
            owner_uid=owner_uid,
            budget=budget,
            physical=physical,
            capacity_observer=capacity_observer,
            auto_close=auto_close,
            remove_root_on_close=remove_root_on_close,
            failpoint=failpoint,
        )
        try:
            budget.reserve(
                kind="private capture staging root",
                file_descriptors=1,
                owner_key=context._root_resource_key,
            )
            context.hit("context.after_root_reserve")
        except BaseException:
            try:
                os.close(descriptor)
            finally:
                budget._release_owner(context._root_resource_key)
            raise
        return context

    def hit(self, name: str) -> None:
        """
        Record a successful lookup or matching event.

        The implementation uses ``name`` to record a successful lookup or
        matching event.

        Args:
            name: Stable name used for lookup and operator-facing diagnostics.
        """
        if self._failpoint is not None:
            self._failpoint(name)

    @property
    def root_descriptor(self) -> int:
        """
        Return the root descriptor.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.
        If the function cannot produce the root descriptor, its exception
        reaches the caller instead of being converted into a successful result.

        Returns:
            The validated ``descriptor``.

        Raises:
            RuntimeError: If redfish request capture boundary is closed.
        """
        with self._lock:
            descriptor = self._state.root_descriptor
            if self._state.closed or descriptor < 0:
                raise RuntimeError("Redfish request capture boundary is closed")
            return descriptor

    @property
    def live_spool_count(self) -> int:
        """
        Return the live spool count.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric live spool count.
        """
        with self._lock:
            return len(self._state.live_spools)

    @property
    def owner_uid(self) -> int:
        """
        Return the verified staging-filesystem UID for publication checks.

        Keep the value fixed across the context lifetime so metadata drift
        cannot trigger a new probe that silently authorizes another owner.

        Returns:
            The immutable owner UID captured when the private root was opened.
        """

        return self._state.owner_uid

    def assert_root(self) -> None:
        """
        Verify root.

        The implementation uses current instance state to verify root. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Raises:
            RuntimeError: If redfish request capture boundary is closed.
        """
        with self._lock:
            state = self._state
        if state.closed or state.root_descriptor < 0:
            raise RuntimeError("Redfish request capture boundary is closed")
        _assert_private_root(
            self.root_path,
            state.root_descriptor,
            state.root_identity,
            state.owner_uid,
        )

    def assert_ready(self) -> None:
        """
        Verify ready.

        The implementation uses current instance state to verify ready. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.
        """
        self.assert_root()
        self.registry.assert_ready()

    def register_spool(self) -> object:
        """
        Return the register spool.

        The implementation uses current instance state to produce the register
        spool. It updates ``_state`` on the instance as part of that state
        transition. Filesystem effects remain confined to the caller-selected
        paths and the owning resource lifecycle. If the function cannot produce
        the register spool, its exception reaches the caller instead of being
        converted into a successful result.

        Returns:
            The validated ``token``.

        Raises:
            RuntimeError: If redfish request capture boundary is closed.
        """
        self.assert_ready()
        token = object()
        with self._lock:
            if self._state.closed:
                raise RuntimeError("Redfish request capture boundary is closed")
            self._state = replace(
                self._state,
                live_spools=self._state.live_spools | frozenset({token}),
            )
        try:
            self.hit("context.after_spool_register")
        except BaseException:
            with self._lock:
                self._state = replace(
                    self._state,
                    live_spools=(self._state.live_spools - frozenset({token})),
                )
            raise
        return token

    def unregister_spool(self, token: object) -> bool:
        """
        Return the unregister spool.

        The implementation uses ``token`` to produce the unregister spool. It
        updates ``_state`` on the instance as part of that state transition.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle.

        Args:
            token: Sensitive value supplied through the approved input boundary
                and never logged.

        Returns:
            Whether the unregister spool operation succeeds.
        """
        with self._lock:
            if token not in self._state.live_spools:
                return False
            self._state = replace(
                self._state,
                live_spools=self._state.live_spools - frozenset({token}),
            )
        self.hit("context.after_spool_unregister")
        self.maybe_auto_close()
        return True

    def create_file(self, role: _PrivateFileRole) -> _OwnedPrivateFile:
        """
        Create file.

        After applying local validation, the function forwards ``role`` to
        ``self.registry.create`` and preserves its return and exception
        contract.

        Args:
            role: Role consumed while the function attempts to create file.

        Returns:
            A ``_OwnedPrivateFile`` representing file.
        """
        self.assert_ready()
        return self.registry.create(role)

    def retry_cleanups(self) -> None:
        """
        Retry cleanups.

        The implementation uses current instance state to retry cleanups.
        """
        self.registry.retry_failures()
        self.maybe_auto_close()

    def maybe_auto_close(self) -> None:
        """
        Close the capture automatically when its terminal conditions hold.

        The implementation uses current instance state to close the capture
        automatically when its terminal conditions hold.
        """
        if (
            self.auto_close
            and not self.live_spool_count
            and self.registry.entry_count == 0
            and self.registry.failed_count == 0
        ):
            self.close()

    def close(self) -> None:
        """
        Retry-safe root descriptor and root-token release.

        The implementation uses current instance state to retry-safe root
        descriptor and root-token release. It updates ``_state`` on the instance
        as part of that state transition. Filesystem effects remain confined to
        the caller-selected paths and the owning resource lifecycle. If the
        function cannot retry-safe root descriptor and root-token release, its
        exception reaches the caller instead of being converted into a
        successful result. Cleanup in the ``finally`` path runs for successful,
        failed, and cancelled execution.

        Raises:
            RuntimeError: If cannot close Redfish request capture boundary with
                live spools; cannot close Redfish request capture boundary with
                live private files; cannot close Redfish request capture
                boundary with pending cleanup; or cannot remove non-empty
                private capture staging root.
            CaptureFilesystemBoundaryError: If private capture staging parent
                identity changed; or private capture staging root identity
                changed.
        """

        with self._lock:
            state = self._state
        if state.closed:
            return
        if state.live_spools:
            raise RuntimeError(
                "Cannot close Redfish request capture boundary with live spools"
            )
        if self.registry.entry_count:
            raise RuntimeError(
                "Cannot close Redfish request capture boundary with live private files"
            )
        if self.registry.failed_count:
            raise RuntimeError(
                "Cannot close Redfish request capture boundary with pending cleanup"
            )

        try:
            if (
                self.remove_root_on_close
                and not state.root_parent_synced
                and state.root_descriptor >= 0
            ):
                if not state.root_removed:
                    _assert_private_root(
                        self.root_path,
                        state.root_descriptor,
                        state.root_identity,
                        state.owner_uid,
                    )
                close_parent_key = (
                    self._root_resource_key,
                    "staging root parent descriptor",
                )
                self.budget.reserve(
                    kind="private staging root teardown",
                    file_descriptors=1,
                    owner_key=close_parent_key,
                )
                try:
                    if not state.root_removed and os.listdir(state.root_descriptor):
                        raise RuntimeError(
                            "Cannot remove non-empty private capture staging root"
                        )
                    parent_descriptor, parent_identity = (
                        _open_pinned_existing_directory(self.root_path.parent)
                    )
                    try:
                        _assert_pinned_directory_path(
                            self.root_path.parent,
                            parent_descriptor,
                            parent_identity,
                        )
                        if (
                            state.root_parent_identity is not None
                            and parent_identity != state.root_parent_identity
                        ):
                            raise CaptureFilesystemBoundaryError(
                                "Private capture staging parent identity changed"
                            )
                        if not state.root_removed:
                            leaf_stat = os.stat(
                                self.root_path.name,
                                dir_fd=parent_descriptor,
                                follow_symlinks=False,
                            )
                            if (
                                leaf_stat.st_dev,
                                leaf_stat.st_ino,
                            ) != state.root_identity:
                                raise CaptureFilesystemBoundaryError(
                                    "Private capture staging root identity changed"
                                )
                            os.rmdir(self.root_path.name, dir_fd=parent_descriptor)
                            with self._lock:
                                self._state = replace(
                                    self._state,
                                    root_removed=True,
                                    root_parent_identity=parent_identity,
                                )
                                state = self._state
                            self.hit("context.after_root_unlink")
                        os.fsync(parent_descriptor)
                        with self._lock:
                            self._state = replace(
                                self._state,
                                root_parent_identity=parent_identity,
                                root_parent_synced=True,
                            )
                            state = self._state
                    finally:
                        os.close(parent_descriptor)
                finally:
                    self.budget._release_owner(close_parent_key)
                self.hit("context.after_root_remove")
            if state.root_descriptor >= 0:
                try:
                    descriptor_stat = os.fstat(state.root_descriptor)
                except OSError as error:
                    if error.errno != errno.EBADF:
                        raise
                else:
                    if (
                        descriptor_stat.st_dev,
                        descriptor_stat.st_ino,
                    ) == state.root_identity:
                        if not state.root_removed:
                            _assert_private_root(
                                self.root_path,
                                state.root_descriptor,
                                state.root_identity,
                                state.owner_uid,
                            )
                        # The descriptor still owns the removed directory after
                        # rmdir.  Closing it is mandatory: dropping only the
                        # integer from state leaks one FD for every run-owned
                        # capture runtime.
                        os.close(state.root_descriptor)
                        # Commit descriptor release before any injected or
                        # observational callback can interrupt teardown.  A
                        # retry must never reinterpret a reused integer as an
                        # owned capability, even if it happens to reference an
                        # inode with the same identity.
                        with self._lock:
                            self._state = replace(
                                self._state,
                                root_descriptor=-1,
                            )
                            state = self._state
                        self.hit("context.after_root_close")
                    # If a prior close completed and its failpoint interrupted
                    # bookkeeping, the integer may now name an unrelated,
                    # reused descriptor.  Never close a mismatched identity.
                with self._lock:
                    self._state = replace(self._state, root_descriptor=-1)
            self.budget._release_owner(self._root_resource_key)
            self.hit("context.after_root_release")
            with self._lock:
                self._state = replace(
                    self._state,
                    root_descriptor=-1,
                    closed=True,
                )
        except BaseException as error:
            with self._lock:
                self._state = replace(
                    self._state,
                    close_failures=(
                        *self._state.close_failures,
                        f"{type(error).__name__}: {error}",
                    ),
                )
            raise


class RedfishRequestCaptureBoundary:
    """
    Configured owner for private capture spools and anonymous resources.

    The type coordinates ``from_tool_config``, ``create_spool``,
    ``_create_spool``, ``live_spool_count``, and ``pending_cleanup_count`` and
    retains the state those operations share between calls. Resource ownership
    remains inside the instance until the matching close, exit, or cleanup
    operation completes.
    """

    def __init__(
        self,
        staging_root: Path,
        limits: RedfishRequestCaptureLimits,
        *,
        capacity_observer: Optional[Callable[[os.statvfs_result, int], None]] = None,
        failpoint: Optional[Callable[[str], None]] = None,
        remove_staging_root_on_close: bool = False,
    ) -> None:
        """
        Initialize a ``RedfishRequestCaptureBoundary`` instance.

        The initializer records ``_context``,
        ``concurrent_private_spool_budget``, ``limits``,
        ``physical_space_reservation``, and ``staging_root`` for later
        operations and establishes the instance invariants before any public
        method runs. Filesystem effects remain confined to the caller-selected
        paths and the owning resource lifecycle.

        Args:
            staging_root: filesystem location used as the staging root for this
                operation.
            limits: Limits governing initialize a
                ``RedfishRequestCaptureBoundary`` instance.
            capacity_observer: Optional capacity observer; ``None`` selects the
                function's default behavior.
            failpoint: Optional failpoint; ``None`` selects the function's
                default behavior.
            remove_staging_root_on_close: Whether remove staging root on close
                is enabled or required for this operation.
        """
        self.limits = RedfishRequestCaptureLimits.model_validate(limits)
        self.staging_root = _absolute_path(Path(staging_root))
        self.concurrent_private_spool_budget = ConcurrentPrivateSpoolBudget(
            self.limits.max_concurrent_private_spool_bytes,
            max_objects=self.limits.max_concurrent_private_objects,
            max_readers=self.limits.max_concurrent_private_readers,
            max_file_descriptors=(self.limits.max_concurrent_private_file_descriptors),
            failpoint=failpoint,
        )
        self.physical_space_reservation = CapturePhysicalSpaceReservation(
            min_free_space_reserve_bytes=(self.limits.min_free_space_reserve_bytes),
            failpoint=failpoint,
        )
        self._context = _CaptureContext.open(
            self.staging_root,
            budget=self.concurrent_private_spool_budget,
            physical=self.physical_space_reservation,
            capacity_observer=capacity_observer,
            auto_close=False,
            remove_root_on_close=remove_staging_root_on_close,
            failpoint=failpoint,
        )

    @classmethod
    def from_tool_config(
        cls,
        tool_config: Any,
        *,
        staging_root: Path,
        **kwargs: Any,
    ) -> "RedfishRequestCaptureBoundary":
        """
        Build a RedfishRequestCaptureBoundary from tool config.

        After applying local validation, the function forwards ``tool_config``,
        ``staging_root``, and ``kwargs`` to ``cls`` and preserves its return and
        exception contract.

        Args:
            tool_config: Tool config governing redfishRequestCaptureBoundary
                from tool config.
            staging_root: filesystem location used as the staging root for this
                operation.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A ``RedfishRequestCaptureBoundary`` initialized from tool config.
        """
        return cls(
            staging_root,
            RedfishRequestCaptureLimits.from_tool_config(tool_config),
            **kwargs,
        )

    def create_spool(
        self,
        *,
        captured_at: str,
        collector_id: str,
        dut_id: str,
        **kwargs: Any,
    ) -> "RequestResponseCaptureSpool":
        """
        Create an unpublished private spool with caller callbacks.

        Arbitrary callbacks are useful for isolated serialization tests, but
        they never receive the runtime policy capability required to publish. A
        string policy label is deliberately rejected because it cannot prove
        which sanitizer actually ran.

        Args:
            captured_at: Text supplied as captured at in the format accepted by
                this function.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A ``RequestResponseCaptureSpool`` representing spool.

        Raises:
            CaptureDisabled: If request/response capture is disabled by the
                operator-owned runtime limits.
            TypeError: If a policy label cannot attest capture sanitization; use
                the run-owned canonical capture runtime.
        """

        if not self.limits.enabled:
            raise CaptureDisabled()
        if "sanitization_policy_id" in kwargs:
            raise TypeError(
                "A policy label cannot attest capture sanitization; use the "
                "run-owned canonical capture runtime"
            )
        return self._create_spool(
            captured_at=captured_at,
            collector_id=collector_id,
            dut_id=dut_id,
            **kwargs,
        )

    def _create_spool(
        self,
        *,
        captured_at: str,
        collector_id: str,
        dut_id: str,
        **kwargs: Any,
    ) -> "RequestResponseCaptureSpool":
        """
        Create spool.

        After applying local validation, the function forwards ``captured_at``,
        ``collector_id``, ``dut_id``, and ``kwargs`` to
        ``RequestResponseCaptureSpool._create`` and preserves its return and
        exception contract.

        Args:
            captured_at: Text supplied as captured at in the format accepted by
                this function.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A ``RequestResponseCaptureSpool`` representing spool.
        """
        token = self._context.register_spool()
        try:
            return RequestResponseCaptureSpool._create(
                self._context,
                token,
                captured_at=captured_at,
                collector_id=collector_id,
                dut_id=dut_id,
                max_record_bytes=self.limits.max_record_bytes,
                max_artifact_bytes=self.limits.max_artifact_bytes,
                max_records=self.limits.max_records,
                **kwargs,
            )
        except BaseException:
            self._context.unregister_spool(token)
            raise

    @property
    def live_spool_count(self) -> int:
        """
        Return the live spool count.

        Each access computes the value from ``_context`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The numeric live spool count.
        """
        return self._context.live_spool_count

    @property
    def pending_cleanup_count(self) -> int:
        """
        Return the pending cleanup count.

        Each access computes the value from ``_context`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The numeric pending cleanup count.
        """
        return self._context.registry.failed_count

    def retry_failed_spool_cleanups(self) -> None:
        """
        Retry failed spool cleanups.

        The implementation uses current instance state to retry failed spool
        cleanups.
        """
        self._context.retry_cleanups()

    def close(self) -> None:
        """
        Close the RedfishRequestCaptureBoundary.

        The implementation uses current instance state to close the
        RedfishRequestCaptureBoundary.
        """
        self._context.close()


class RunOwnedRequestCaptureRuntime:
    """
    One run-wide boundary and bounded cancellation-draining worker pool.

    The type coordinates ``create``, ``staging_root``, ``active_worker_count``,
    ``metrics_snapshot``, ``create_spool``, and
    ``_resource_authorization_token`` and retains the state those operations
    share between calls. Resource ownership remains inside the instance until
    the matching close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        boundary: RedfishRequestCaptureBoundary,
        *,
        output_root: Path,
        output_root_descriptor: int,
        output_root_identity: tuple[int, int],
    ) -> None:
        """
        Initialize a ``RunOwnedRequestCaptureRuntime`` instance.

        Strong ownership survives caller-task loss and failed discard
        bookkeeping. Close retries these exact capabilities before the private
        boundary can be released.

        Args:
            boundary: Boundary consumed while the function attempts to
                initialize a ``RunOwnedRequestCaptureRuntime`` instance.
            output_root: filesystem location used as the output root for this
                operation.
            output_root_descriptor: Numeric output root descriptor used while
                the operation performs bounded accounting.
            output_root_identity: Entries supplied as ``output_root_identity``
                without transferring container ownership.
        """
        self.boundary = boundary
        self.output_root = output_root
        self._output_root_descriptor = output_root_descriptor
        self._output_root_identity = output_root_identity
        self._output_root_resource_key = (object(), "run output root descriptor")
        self.boundary.concurrent_private_spool_budget.reserve(
            kind="capture run output root",
            file_descriptors=1,
            owner_key=self._output_root_resource_key,
        )
        self.worker_count = int(self.boundary.limits.worker_count)
        self._executor = ThreadPoolExecutor(
            max_workers=self.worker_count,
            thread_name_prefix="nvdebug-capture",
        )
        self._slots = asyncio.Semaphore(self.worker_count)
        self._state_lock = threading.Lock()
        self._inflight: set[ConcurrentFuture[Any]] = set()
        self._active_runs = 0
        self._metrics_started_monotonic: Optional[float] = None
        self._metrics_last_transition_monotonic: Optional[float] = None
        self._metrics_queued_runs = 0
        self._metrics_enqueued_calls = 0
        self._metrics_queue_exits = 0
        self._metrics_worker_submissions = 0
        self._metrics_worker_completions = 0
        self._metrics_worker_failures = 0
        self._metrics_abandoned_before_submission = 0
        self._metrics_peak_queued = 0
        self._metrics_peak_active = 0
        self._metrics_queue_wait_seconds_total = 0.0
        self._metrics_queue_wait_seconds_max = 0.0
        self._metrics_worker_seconds_total = 0.0
        self._metrics_worker_seconds_max = 0.0
        self._metrics_active_worker_seconds = 0.0
        self._metrics_queued_wall_seconds = 0.0
        self._metrics_queued_capacity_worker_seconds = 0.0
        self._metrics_queued_active_worker_seconds = 0.0
        self._metrics_saturated_while_queued_seconds = 0.0
        self._metrics_runnable_gap_worker_seconds = 0.0
        self._authorizations: dict[object, _RuntimePublicationAuthorization] = {}
        self._published: dict[object, _TrackedPublication] = {}
        # Strong ownership survives caller-task loss and failed discard
        # bookkeeping. Close retries these exact capabilities before the
        # private boundary can be released.
        self._tracked_resources: dict[object, list[Any]] = {}
        self._pending_abandons: set[object] = set()
        self._closed = False
        self._cleanup_complete = False
        self._close_complete = False
        self._close_task: Optional[asyncio.Task[Optional[BaseException]]] = None
        self._close_cleanup_future: Optional[ConcurrentFuture[None]] = None
        self._close_failures: list[BaseException] = []

    @classmethod
    def create(
        cls,
        tool_config: Any,
        *,
        output_root: Path,
        temporary_parent: Optional[Path] = None,
        capacity_observer: Optional[Callable[[os.statvfs_result, int], None]] = None,
        failpoint: Optional[Callable[[str], None]] = None,
    ) -> "RunOwnedRequestCaptureRuntime":
        """
        Create a fresh owner-only root outside the distributable bundle.

        After applying local validation, the function forwards ``tool_config``,
        ``output_root``, ``temporary_parent``, ``capacity_observer``, and
        ``failpoint`` to ``cls`` and preserves its return and exception
        contract. Cleanup in the ``finally`` path runs for successful, failed,
        and cancelled execution.

        Args:
            tool_config: Tool config governing fresh owner-only root outside the
                distributable bundle.
            output_root: filesystem location used as the output root for this
                operation.
            temporary_parent: Optional filesystem location used as the temporary
                parent for this operation.
            capacity_observer: Optional capacity observer; ``None`` selects the
                function's default behavior.
            failpoint: Optional failpoint; ``None`` selects the function's
                default behavior.

        Returns:
            A validated ``RunOwnedRequestCaptureRuntime`` instance initialized
            from the supplied fields.

        Raises:
            CaptureFilesystemBoundaryError: If private capture staging is not
                pinned to the output filesystem.
        """

        output_root = _absolute_path(Path(output_root))
        output_root_descriptor, output_root_identity = _open_pinned_existing_directory(
            output_root
        )
        staging_parent = (
            output_root.parent
            if temporary_parent is None
            else _absolute_path(Path(temporary_parent))
        )
        try:
            staging_root, staging_root_identity = _create_private_staging_root(
                staging_parent,
                output_root=output_root,
                output_root_descriptor=output_root_descriptor,
            )
        except BaseException:
            os.close(output_root_descriptor)
            raise
        boundary: Optional[RedfishRequestCaptureBoundary] = None
        try:
            boundary = RedfishRequestCaptureBoundary.from_tool_config(
                tool_config,
                staging_root=staging_root,
                capacity_observer=capacity_observer,
                failpoint=failpoint,
                remove_staging_root_on_close=True,
            )
        except BaseException as error:
            cleanup_error: Optional[BaseException] = None
            try:
                _remove_exact_empty_staging_root(staging_root, staging_root_identity)
            except FileNotFoundError:
                pass
            except BaseException as removal_error:
                cleanup_error = removal_error
            finally:
                os.close(output_root_descriptor)
            if cleanup_error is not None:
                error.add_note(
                    "Private staging allocation cleanup also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise
        try:
            boundary_root_stat = os.fstat(boundary._context.root_descriptor)
            output_root_stat = os.fstat(output_root_descriptor)
            if (
                (boundary_root_stat.st_dev, boundary_root_stat.st_ino)
                != staging_root_identity
                or boundary_root_stat.st_dev != output_root_stat.st_dev
            ):
                raise CaptureFilesystemBoundaryError(
                    "Private capture staging is not pinned to the output filesystem"
                )
            return cls(
                boundary,
                output_root=output_root,
                output_root_descriptor=output_root_descriptor,
                output_root_identity=output_root_identity,
            )
        except BaseException as error:
            cleanup_errors: list[BaseException] = []
            try:
                boundary.close()
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
            try:
                os.close(output_root_descriptor)
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
            for cleanup_error in cleanup_errors:
                error.add_note(
                    "Capture runtime construction cleanup also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise

    @property
    def staging_root(self) -> Path:
        """
        Return the staging root.

        Each access computes the value from ``boundary`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The validated staging root filesystem path.
        """
        return self.boundary.staging_root

    @property
    def active_worker_count(self) -> int:
        """
        Return the active worker count.

        Each access computes the value from ``_inflight`` and ``_state_lock`` on
        the current instance; the derived view is not stored as independent
        state.

        Returns:
            The numeric active worker count.
        """
        with self._state_lock:
            return len(self._inflight)

    def _advance_worker_metrics_locked(self, now: float) -> None:
        """
        Integrate exact queue and worker occupancy through ``now``.

        The caller must hold ``_state_lock`` so queue and active-worker state
        cannot change between observing the current cardinalities and applying
        their elapsed contribution. The method records only aggregate counts
        and durations; callable names, DUT identities, paths, and captured
        content never enter telemetry.

        Args:
            now: Monotonic timestamp ending the current occupancy interval.

        Side effects:
            Advances aggregate worker-pool duration counters on this runtime.
        """

        if self._metrics_started_monotonic is None:
            self._metrics_started_monotonic = now
            self._metrics_last_transition_monotonic = now
            return
        previous = self._metrics_last_transition_monotonic
        if previous is None:
            self._metrics_last_transition_monotonic = now
            return
        elapsed = max(0.0, now - previous)
        active = min(self.worker_count, len(self._inflight))
        queued = max(0, self._metrics_queued_runs)
        self._metrics_active_worker_seconds += active * elapsed
        if queued:
            self._metrics_queued_wall_seconds += elapsed
            self._metrics_queued_capacity_worker_seconds += self.worker_count * elapsed
            self._metrics_queued_active_worker_seconds += active * elapsed
            if active >= self.worker_count:
                self._metrics_saturated_while_queued_seconds += elapsed
            else:
                self._metrics_runnable_gap_worker_seconds += (
                    self.worker_count - active
                ) * elapsed
        self._metrics_last_transition_monotonic = now

    def _record_worker_enqueue(self, now: float) -> None:
        """
        Record one caller entering bounded worker admission.

        Occupancy is advanced before cardinality changes so the preceding
        interval remains attributed to the queue state that actually owned it.

        Args:
            now: Monotonic enqueue timestamp for the caller.

        Side effects:
            Increments queue cardinality, demand, and peak accounting.
        """

        with self._state_lock:
            self._advance_worker_metrics_locked(now)
            self._metrics_queued_runs += 1
            self._metrics_enqueued_calls += 1
            self._metrics_peak_queued = max(
                self._metrics_peak_queued, self._metrics_queued_runs
            )

    def _record_worker_queue_exit(self, enqueued_at: float, now: float) -> None:
        """
        Record one caller leaving worker admission on every terminal path.

        Successful acquisition, cancellation, and admission failure all pass
        through this boundary, keeping current queue state truthful even when
        no blocking function is submitted.

        Args:
            enqueued_at: Monotonic timestamp captured before admission began.
            now: Monotonic timestamp at which admission finished or failed.

        Side effects:
            Decrements queue cardinality and updates bounded wait aggregates.
        """

        wait_seconds = max(0.0, now - enqueued_at)
        with self._state_lock:
            self._advance_worker_metrics_locked(now)
            self._metrics_queued_runs = max(0, self._metrics_queued_runs - 1)
            self._metrics_queue_exits += 1
            self._metrics_queue_wait_seconds_total += wait_seconds
            self._metrics_queue_wait_seconds_max = max(
                self._metrics_queue_wait_seconds_max, wait_seconds
            )

    def _record_worker_abandoned(self) -> None:
        """
        Record an admitted caller that never submitted blocking work.

        This counter covers admission cancellation, runtime closure, and
        executor-submission failure without converting those outcomes into
        worker failures.

        Side effects:
            Increments the aggregate pre-submission abandonment counter.
        """

        with self._state_lock:
            self._metrics_abandoned_before_submission += 1

    def metrics_snapshot(self) -> dict[str, Any]:
        """
        Return a bounded identity-free worker-pool telemetry snapshot.

        Occupancy integration is event-driven and exact through the snapshot's
        monotonic timestamp. Ratios remain ``None`` when their denominator has
        no observed demand instead of manufacturing a zero-utilization claim.
        The returned mapping is detached from runtime state and safe for the
        resource-usage artifact.

        Returns:
            A JSON-safe mapping of configured capacity, current/peak demand,
            aggregate timing, utilization, and terminal worker outcomes.
        """

        now = time.monotonic()
        with self._state_lock:
            self._advance_worker_metrics_locked(now)
            started = self._metrics_started_monotonic
            observation_seconds = (
                max(0.0, now - started) if started is not None else 0.0
            )
            queue_exits = self._metrics_queue_exits
            worker_completions = self._metrics_worker_completions
            queued_capacity = self._metrics_queued_capacity_worker_seconds
            queued_wall = self._metrics_queued_wall_seconds
            total_capacity = self.worker_count * observation_seconds
            if self._close_complete:
                status = "closed"
            elif self._closed:
                status = "closing"
            elif started is None:
                status = "ready"
            else:
                status = "running"
            return {
                "schema_version": "1.0",
                "status": status,
                "worker_count": self.worker_count,
                "observation_seconds": round(observation_seconds, 6),
                "calls": {
                    "enqueued": self._metrics_enqueued_calls,
                    "queue_exits": queue_exits,
                    "worker_submissions": self._metrics_worker_submissions,
                    "worker_completions": worker_completions,
                    "worker_failures": self._metrics_worker_failures,
                    "abandoned_before_submission": (
                        self._metrics_abandoned_before_submission
                    ),
                },
                "pool": {
                    "active_workers": len(self._inflight),
                    "queued_calls": self._metrics_queued_runs,
                    "peak_active_workers": self._metrics_peak_active,
                    "peak_queued_calls": self._metrics_peak_queued,
                },
                "queue": {
                    "wait_seconds_total": round(
                        self._metrics_queue_wait_seconds_total, 6
                    ),
                    "wait_seconds_average": (
                        round(self._metrics_queue_wait_seconds_total / queue_exits, 6)
                        if queue_exits
                        else 0.0
                    ),
                    "wait_seconds_max": round(self._metrics_queue_wait_seconds_max, 6),
                    "queued_wall_seconds": round(queued_wall, 6),
                    "queued_capacity_worker_seconds": round(queued_capacity, 6),
                    "queued_active_worker_seconds": round(
                        self._metrics_queued_active_worker_seconds, 6
                    ),
                    "saturated_while_queued_seconds": round(
                        self._metrics_saturated_while_queued_seconds, 6
                    ),
                    "runnable_gap_worker_seconds": round(
                        self._metrics_runnable_gap_worker_seconds, 6
                    ),
                    "utilization_while_queued_ratio": (
                        round(
                            self._metrics_queued_active_worker_seconds
                            / queued_capacity,
                            6,
                        )
                        if queued_capacity > 0
                        else None
                    ),
                    "saturation_while_queued_ratio": (
                        round(
                            self._metrics_saturated_while_queued_seconds / queued_wall,
                            6,
                        )
                        if queued_wall > 0
                        else None
                    ),
                },
                "workers": {
                    "seconds_total": round(self._metrics_worker_seconds_total, 6),
                    "seconds_average": (
                        round(
                            self._metrics_worker_seconds_total / worker_completions, 6
                        )
                        if worker_completions
                        else 0.0
                    ),
                    "seconds_max": round(self._metrics_worker_seconds_max, 6),
                    "active_worker_seconds": round(
                        self._metrics_active_worker_seconds, 6
                    ),
                    "utilization_ratio": (
                        round(self._metrics_active_worker_seconds / total_capacity, 6)
                        if total_capacity > 0
                        else None
                    ),
                },
            }

    def create_spool(
        self,
        *,
        policy: CaptureSanitizationPolicy,
        captured_at: str,
        collector_id: str,
        dut_id: str,
        collector_group: str,
        publication_destination: Path,
        external_text_sanitizer: Optional[Callable[[str], str]] = None,
        sensitive_value_replacement: str = "<redacted>",
        external_sensitive_name: Optional[Callable[[str], bool]] = None,
    ) -> "RequestResponseCaptureSpool":
        """
        Create spool.

        The implementation uses ``policy``, ``captured_at``, ``collector_id``,
        ``dut_id``, and ``collector_group`` to create spool. If the function
        cannot create spool, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            policy: Policy governing spool.
            captured_at: Text supplied as captured at in the format accepted by
                this function.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_group: Text supplied as collector group in the format
                accepted by this function.
            publication_destination: filesystem location used as the destination
                for this operation.
            external_text_sanitizer: Optional external text sanitizer; ``None``
                selects the function's default behavior.
            sensitive_value_replacement: Public replacement emitted for a
                sensitive structured mapping value.
            external_sensitive_name: Primary artifact structured-key classifier;
                ``None`` selects the canonical capture fallback.

        Returns:
            The validated ``spool``.

        Raises:
            CaptureDisabled: If request/response capture is disabled by the
                operator-owned runtime limits.
            TypeError: If the capture sanitization policy is not canonical.
            CaptureFilesystemBoundaryError: If capture destination is outside
                the pinned run output root; or capture destination does not
                match its canonical collector layout.
            RuntimeError: If run-owned capture runtime is closed.
        """
        if not self.boundary.limits.enabled:
            raise CaptureDisabled()
        if not isinstance(policy, CaptureSanitizationPolicy):
            raise TypeError("Capture sanitization policy must be canonical")
        destination = _absolute_path(Path(publication_destination))
        _assert_pinned_directory_path(
            self.output_root,
            self._output_root_descriptor,
            self._output_root_identity,
        )
        try:
            relative_destination = destination.relative_to(self.output_root)
        except ValueError as error:
            raise CaptureFilesystemBoundaryError(
                "Capture destination is outside the pinned run output root"
            ) from error
        parts = relative_destination.parts
        expected_collector_prefix = (
            f"{str(collector_group).capitalize()}_{collector_id}_"
        )
        if (
            len(parts) < 5
            or parts[0] != dut_id
            or parts[1] != collector_group
            or not parts[2].startswith(expected_collector_prefix)
            or parts[3] != "diagnostic"
            or len(parts) != 5
            or destination.suffix.casefold() != ".json"
        ):
            raise CaptureFilesystemBoundaryError(
                "Capture destination does not match its canonical collector layout"
            )
        collector_root = self.output_root.joinpath(*parts[:3])
        validation_key = (object(), "collector root validation descriptor")
        self.boundary.concurrent_private_spool_budget.reserve(
            kind="capture collector root validation",
            file_descriptors=1,
            owner_key=validation_key,
        )
        try:
            root_descriptor, root_identity = _open_pinned_existing_directory(
                collector_root
            )
            os.close(root_descriptor)
        finally:
            self.boundary.concurrent_private_spool_budget._release_owner(validation_key)
        token = object()
        authorization = _RuntimePublicationAuthorization(
            token=token,
            policy=policy,
            dut_id=dut_id,
            collector_id=collector_id,
            collector_group=collector_group,
            destination=destination,
            collector_root=collector_root,
            collector_root_identity=root_identity,
        )
        with self._state_lock:
            if self._closed:
                raise RuntimeError("Run-owned capture runtime is closed")
            self._authorizations[token] = authorization
        try:
            spool = self.boundary._create_spool(
                captured_at=captured_at,
                collector_id=collector_id,
                dut_id=dut_id,
                sanitize_text=partial(
                    _canonical_text_sanitizer, external_text_sanitizer
                ),
                sanitize_uri=partial(_canonical_uri_sanitizer, external_text_sanitizer),
                sensitive_name=partial(
                    _authoritative_sensitive_name, external_sensitive_name
                ),
                uri_name=_canonical_uri_name,
                sensitive_value_replacement=sensitive_value_replacement,
                _runtime_authorization_token=token,
                _sanitization_policy_id=policy.value,
            )
            self._track_capture_resource(spool)
            return spool
        except BaseException:
            with self._state_lock:
                self._authorizations.pop(token, None)
            raise

    @staticmethod
    def _resource_authorization_token(resource: Any) -> Optional[object]:
        """
        Return the resource authorization token.

        The implementation uses ``resource`` to produce the resource
        authorization token.

        Args:
            resource: Resource object whose ``_runtime_authorization_token``,
                ``receipt``, and ``summary`` state is read while performing
                resource authorization token.

        Returns:
            The resource authorization token, or ``None`` when the requested
            value is unavailable.
        """
        if isinstance(resource, RequestResponseCaptureSpool):
            return resource._runtime_authorization_token
        if isinstance(resource, PrivateCaptureCandidate):
            return resource.summary._runtime_authorization_token
        if isinstance(resource, VerifiedPrivateCapture):
            return resource.receipt._runtime_authorization_token
        if isinstance(resource, PrivateCapturePublicationTransaction):
            return resource._runtime_authorization_token
        if isinstance(resource, PublishedCaptureSummary):
            return resource._runtime_authorization_token
        return None

    @staticmethod
    def _capture_resource_discard_complete(resource: Any) -> bool:
        """
        Capture resource discard complete.

        The implementation uses ``resource`` to capture resource discard
        complete.

        Args:
            resource: Resource object whose ``_discarded``, ``_lock``,
                ``_ownership``, ``_state``, and ``is_discarded`` state is read
                while performing capture resource discard complete.

        Returns:
            Whether the capture resource discard complete operation succeeds.
        """
        if isinstance(resource, RequestResponseCaptureSpool):
            with resource._lock:
                return resource._state.phase is _SpoolPhase.DISCARDED
        if isinstance(resource, PrivateCaptureCandidate):
            with resource._lock:
                return resource._state.phase is _CandidatePhase.DISCARDED
        if isinstance(resource, VerifiedPrivateCapture):
            return resource._ownership.is_discarded()
        if isinstance(resource, PrivateCapturePublicationTransaction):
            with resource._lock:
                return resource._discarded
        return True

    def _track_capture_resource(self, resource: Any) -> None:
        """
        Track capture resource.

        The implementation uses ``resource`` to track capture resource.

        Args:
            resource: Resource consumed while the function attempts to track
                capture resource.
        """
        token = self._resource_authorization_token(resource)
        if token is None or isinstance(resource, PublishedCaptureSummary):
            return
        with self._state_lock:
            tracked = self._tracked_resources.setdefault(token, [])
            if not any(candidate is resource for candidate in tracked):
                tracked.append(resource)

    def _untrack_capture_resource(self, resource: Any) -> None:
        """
        Stop tracking capture resource.

        The implementation uses ``resource`` to stop tracking capture resource.

        Args:
            resource: Resource consumed while the function attempts to stop
                tracking capture resource.
        """
        token = self._resource_authorization_token(resource)
        if token is None:
            return
        with self._state_lock:
            tracked = self._tracked_resources.get(token)
            if tracked is None:
                return
            remaining = [
                candidate for candidate in tracked if candidate is not resource
            ]
            if remaining:
                self._tracked_resources[token] = remaining
            else:
                self._tracked_resources.pop(token, None)
                if token in self._pending_abandons and token not in self._published:
                    self._pending_abandons.discard(token)
                    self._authorizations.pop(token, None)

    def _prune_discarded_capture_resources(self, token: object) -> None:
        """
        Prune discarded capture resources.

        The implementation uses ``token`` to prune discarded capture resources.

        Args:
            token: Sensitive value supplied through the approved input boundary
                and never logged.
        """
        with self._state_lock:
            tracked = tuple(self._tracked_resources.get(token, ()))
        for resource in tracked:
            if self._capture_resource_discard_complete(resource):
                self._untrack_capture_resource(resource)

    def _register_publication(
        self,
        summary: "PublishedCaptureSummary",
        transaction: "PrivateCapturePublicationTransaction",
    ) -> "PublishedCaptureSummary":
        """
        Atomically transfer a retained publication lease into runtime ownership.

        The implementation uses ``summary`` and ``transaction`` to atomically
        transfer a retained publication lease into runtime ownership. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle. If the function cannot atomically transfer a
        retained publication lease into runtime ownership, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            summary: Summary object whose ``_publication_budget_key`` and
                ``_runtime_authorization_token`` state is read while performing
                atomically transfer a retained publication lease into runtime
                ownership.
            transaction: Transaction object whose
                ``_transfer_publication_budget`` state is read while performing
                atomically transfer a retained publication lease into runtime
                ownership.

        Returns:
            The validated ``registered_summary``.

        Raises:
            RuntimeError: If capture publication lease is unavailable; or
                capture publication is already registered.
        """

        token = summary._runtime_authorization_token
        budget_key = summary._publication_budget_key
        if token is None or budget_key is None:
            raise RuntimeError("Capture publication lease is unavailable")
        registered_summary = replace(summary, _publication_budget_key=None)
        record = _TrackedPublication(
            summary=registered_summary,
            retained_budget_key=budget_key,
        )
        with self._state_lock:
            if token in self._published:
                raise RuntimeError("Capture publication is already registered")
            self._published[token] = record
        try:
            transaction._transfer_publication_budget(budget_key)
        except BaseException:
            with self._state_lock:
                if self._published.get(token) is record:
                    self._published.pop(token, None)
            raise
        return registered_summary

    def _registered_publication(
        self,
        summary: "PublishedCaptureSummary",
    ) -> _TrackedPublication:
        """
        Return the registered publication.

        The implementation uses ``summary`` to produce the registered
        publication. If the function cannot produce the registered publication,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            summary: Summary object whose ``_runtime_authorization_token`` state
                is read while performing registered publication.

        Returns:
            The validated ``record``.

        Raises:
            RuntimeError: If capture publication is not registered.
        """
        token = summary._runtime_authorization_token
        with self._state_lock:
            record = self._published.get(token)
        if token is None or record is None or record.summary is not summary:
            raise RuntimeError("Capture publication is not registered")
        return record

    def _retire_publication(
        self,
        record: _TrackedPublication,
        *,
        allow_live_private_source: bool,
    ) -> None:
        """
        Retire a released publication while preserving live source ownership.

        Prune while the public record is still registered, so untracking a
        discarded alias cannot retire authorization before this transition.

        Args:
            record: Record object whose ``summary`` state is read while
                performing retire a released publication while preserving live
                source ownership.
            allow_live_private_source: Whether allow live private source is
                enabled or required for this operation.

        Raises:
            RuntimeError: If capture publication registration changed; or
                capture publication has a live private source.
        """

        summary = record.summary
        token = summary._runtime_authorization_token
        assert token is not None
        # Prune while the public record is still registered, so untracking a
        # discarded alias cannot retire authorization before this transition.
        self._prune_discarded_capture_resources(token)
        with self._state_lock:
            if self._published.get(token) is not record:
                raise RuntimeError("Capture publication registration changed")
            live_private_source = bool(self._tracked_resources.get(token))
            if live_private_source and not allow_live_private_source:
                raise RuntimeError("Capture publication has a live private source")
            self._published.pop(token, None)
            if live_private_source:
                self._pending_abandons.add(token)
            else:
                self._pending_abandons.discard(token)
                self._authorizations.pop(token, None)

    def _authorization_for(self, resource: Any) -> _RuntimePublicationAuthorization:
        """
        Return the authorization for.

        The implementation uses ``resource`` to produce the authorization for.
        If the function cannot produce the authorization for, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            resource: Resource consumed while the function attempts to produce
                the authorization for.

        Returns:
            The validated ``authorization``.

        Raises:
            RuntimeError: If capture is not registered with this run-owned
                publication runtime.
        """
        token = self._resource_authorization_token(resource)
        with self._state_lock:
            authorization = self._authorizations.get(token)
        if token is None or authorization is None:
            raise RuntimeError(
                "Capture is not registered with this run-owned publication runtime"
            )
        return authorization

    def publish_and_discard(
        self,
        transaction: "PrivateCapturePublicationTransaction",
    ) -> "PublishedCaptureSummary":
        """
        Perform the only production publication path for a registered capture.

        The implementation uses ``transaction`` to perform the only production
        publication path for a registered capture.

        Args:
            transaction: Transaction object whose
                ``_publish_authorized_and_discard`` state is read while
                performing perform the only production publication path for a
                registered capture.

        Returns:
            The validated ``registered_summary``.
        """

        authorization = self._authorization_for(transaction)
        try:
            summary = transaction._publish_authorized_and_discard(authorization)
        except CapturePublicationAmbiguousError as error:
            error.summary = self._register_publication(error.summary, transaction)
            raise
        except BaseException as error:
            completed = getattr(error, "capture_completed_result", None)
            if isinstance(completed, PublishedCaptureSummary):
                completed = self._register_publication(completed, transaction)
                try:
                    setattr(error, "capture_completed_result", completed)
                except BaseException:
                    pass
            self._prune_discarded_capture_resources(authorization.token)
            raise
        registered_summary = self._register_publication(summary, transaction)
        self._untrack_capture_resource(transaction)
        return registered_summary

    def rollback_published(self, summary: "PublishedCaptureSummary") -> None:
        """
        Rollback an exact publication when cancellation wins after its worker.

        The implementation uses ``summary`` to rollback an exact publication
        when cancellation wins after its worker.

        Args:
            summary: Summary consumed while the function attempts to rollback an
                exact publication when cancellation wins after its worker.
        """

        authorization = self._authorization_for(summary)
        record = self._registered_publication(summary)
        rollback_key = (object(), "publication rollback descriptors")
        self.boundary.concurrent_private_spool_budget.reserve(
            kind="capture publication rollback",
            file_descriptors=2,
            owner_key=rollback_key,
        )
        rollback_errors: list[BaseException] = []
        try:
            PrivateCapturePublicationTransaction._rollback_authorized(
                summary,
                authorization,
                self.boundary._context,
            )
        except BaseException as error:
            rollback_errors.append(error)
        try:
            self.boundary.concurrent_private_spool_budget._release_owner(rollback_key)
        except BaseException as error:
            rollback_errors.append(error)
        if not rollback_errors:
            try:
                self.boundary.concurrent_private_spool_budget._release_owner(
                    record.retained_budget_key
                )
            except BaseException as error:
                rollback_errors.append(error)
        _raise_capture_cleanup_outcome(
            None,
            rollback_errors,
            "Capture publication rollback ownership release failed",
        )
        self._retire_publication(record, allow_live_private_source=True)

    def acknowledge_publication(
        self,
        summary: "PublishedCaptureSummary",
        *,
        dut_id: str,
        collector_id: str,
    ) -> None:
        """
        Acknowledge only after durable collector status adopts publication.

        The implementation uses ``summary``, ``dut_id``, and ``collector_id`` to
        acknowledge only after durable collector status adopts publication. If
        the function cannot acknowledge only after durable collector status
        adopts publication, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            summary: Summary object whose ``_private_leaf_name`` state is read
                while performing acknowledge only after durable collector status
                adopts publication.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Raises:
            RuntimeError: If capture publication acknowledgement identity
                mismatch; ambiguous private publication link cannot be
                acknowledged; or capture publication has a live private source.
        """

        authorization = self._authorization_for(summary)
        if (authorization.dut_id, authorization.collector_id) != (
            dut_id,
            collector_id,
        ):
            raise RuntimeError("Capture publication acknowledgement identity mismatch")
        record = self._registered_publication(summary)
        if summary._private_leaf_name is not None:
            raise RuntimeError(
                "Ambiguous private publication link cannot be acknowledged"
            )
        self._prune_discarded_capture_resources(authorization.token)
        with self._state_lock:
            if self._tracked_resources.get(authorization.token):
                raise RuntimeError("Capture publication has a live private source")
        self.boundary.concurrent_private_spool_budget._release_owner(
            record.retained_budget_key
        )
        self._retire_publication(record, allow_live_private_source=False)

    def verify_durable_publication(
        self,
        summary: "PublishedCaptureSummary",
        checker: Callable[..., bool],
        *,
        dut_id: str,
        collector_id: str,
    ) -> bool:
        """
        Run the canonical status/artifact proof under the shared FD gate.

        The implementation uses ``summary``, ``checker``, ``dut_id``, and
        ``collector_id`` to run the canonical status/artifact proof under the
        shared FD gate. Terminal status is emitted only after canonical
        status/artifact proof under the shared FD gate and its owned cleanup
        have completed. If the function cannot run the canonical status/artifact
        proof under the shared FD gate, its exception reaches the caller instead
        of being converted into a successful result. Cleanup in the ``finally``
        path runs for successful, failed, and cancelled execution.

        Args:
            summary: Summary object whose ``_published_identity``, ``path``,
                ``sanitization_policy_id``, ``sha256``, and ``size_bytes`` state
                is read while performing canonical status/artifact proof under
                the shared FD gate.
            checker: Checker consumed while the function attempts to run the
                canonical status/artifact proof under the shared FD gate.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            Whether the canonical status/artifact proof under the shared FD gate
            operation succeeds.

        Raises:
            RuntimeError: If capture durable-status identity mismatch.
        """

        if not callable(checker):
            return False
        authorization = self._authorization_for(summary)
        if (authorization.dut_id, authorization.collector_id) != (
            dut_id,
            collector_id,
        ):
            raise RuntimeError("Capture durable-status identity mismatch")
        self._registered_publication(summary)
        if summary._published_identity is None:
            return False

        verification_key = (object(), "durable status verification descriptors")
        self.boundary.concurrent_private_spool_budget.reserve(
            kind="capture durable status verification",
            file_descriptors=3,
            owner_key=verification_key,
        )
        try:
            return bool(
                checker(
                    dut_id,
                    collector_id,
                    summary.path,
                    summary.sha256,
                    summary.size_bytes,
                    summary.sanitization_policy_id,
                    summary._published_identity,
                )
            )
        finally:
            self.boundary.concurrent_private_spool_budget._release_owner(
                verification_key
            )

    def abandon(self, resource: Any) -> None:
        """
        Release an unpublished capture's authorized-destination registry entry.

        Retain both the exact capability and its authorization until a retry
        unregisters every live-spool token.

        Args:
            resource: Resource consumed while the function attempts to release
                an unpublished capture's authorized-destination registry entry.

        Raises:
            RuntimeError: If the published capture is not committed or rolled
                back explicitly.
        """

        token = self._resource_authorization_token(resource)
        if token is None:
            return
        self._prune_discarded_capture_resources(token)
        with self._state_lock:
            if token in self._published:
                raise RuntimeError(
                    "Published capture must be committed or rolled back explicitly"
                )
            if self._tracked_resources.get(token):
                # Retain both the exact capability and its authorization until
                # a retry unregisters every live-spool token.
                self._pending_abandons.add(token)
                return
            self._pending_abandons.discard(token)
            self._authorizations.pop(token, None)

    async def run(
        self, function: Callable[..., Any], /, *args: Any, **kwargs: Any
    ) -> Any:
        """
        Run blocking capture work, draining it before propagating control flow.

        The implementation uses ``function``, ``args``, and ``kwargs`` to run
        blocking capture work, draining it before propagating control flow.
        Terminal status is emitted only after blocking capture work, draining it
        before propagating control flow and its owned cleanup have completed.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind. It updates ``_active_runs`` on the
        instance as part of that state transition. If the function cannot run
        blocking capture work, draining it before propagating control flow, its
        exception reaches the caller instead of being converted into a
        successful result. Cleanup in the ``finally`` path runs for successful,
        failed, and cancelled execution.

        Args:
            function: Function consumed while the function attempts to run
                blocking capture work, draining it before propagating control
                flow.
            args: Additional positional values forwarded in caller-provided
                order.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The validated ``result``.

        Raises:
            RuntimeError: If capture worker admission did not acquire a slot; or
                run-owned capture runtime is closed.
        """

        async def acquire_owned() -> tuple[bool, Optional[BaseException]]:
            """
            Return the acquire owned.

            The implementation uses current instance state to produce the
            acquire owned. Owned asynchronous work is awaited before return, so
            completion does not leave an unobserved task behind.

            Returns:
                A tuple containing ``status flag`` and ``optional[base
                exception]`` in that order.
            """
            try:
                return bool(await self._slots.acquire()), None
            except BaseException as error:
                return False, error

        enqueued_at = time.monotonic()
        self._record_worker_enqueue(enqueued_at)
        admission_task = asyncio.create_task(acquire_owned())
        caller_control: Optional[BaseException] = None
        wait_errors: list[BaseException] = []
        while not admission_task.done():
            try:
                await asyncio.shield(admission_task)
            except BaseException as error:
                caller_control = _defer_capture_failure(
                    caller_control, wait_errors, error
                )
        try:
            acquired, admission_error = admission_task.result()
        except BaseException as error:
            acquired = False
            admission_error = error
        self._record_worker_queue_exit(enqueued_at, time.monotonic())
        if admission_error is not None:
            caller_control = _defer_capture_failure(
                caller_control, wait_errors, admission_error
            )
        if caller_control is not None or wait_errors:
            if acquired:
                self._slots.release()
            self._record_worker_abandoned()
            _raise_capture_cleanup_outcome(
                caller_control,
                wait_errors,
                "Capture worker admission failed",
            )
        if not acquired:
            self._record_worker_abandoned()
            raise RuntimeError("Capture worker admission did not acquire a slot")

        future: Optional[ConcurrentFuture[Any]] = None
        worker_started_at: Optional[float] = None
        active_run = False
        worker_error: Optional[BaseException] = None
        result: Any = None
        try:
            with self._state_lock:
                if self._closed:
                    raise RuntimeError("Run-owned capture runtime is closed")
                future = self._executor.submit(partial(function, *args, **kwargs))
                worker_started_at = time.monotonic()
                self._advance_worker_metrics_locked(worker_started_at)
                self._inflight.add(future)
                self._active_runs += 1
                self._metrics_worker_submissions += 1
                self._metrics_peak_active = max(
                    self._metrics_peak_active, len(self._inflight)
                )
                active_run = True

            while not future.done():
                try:
                    # Polling a concurrent future also avoids relying on a
                    # cross-thread event-loop wakeup after an executor worker
                    # finishes.  Some supported Python/event-loop combinations
                    # can lose that wakeup when the work completes between
                    # submission and callback registration.
                    await asyncio.sleep(0.01)
                except BaseException as error:
                    caller_control = _defer_capture_failure(
                        caller_control, wait_errors, error
                    )
            try:
                result = future.result()
            except BaseException as error:
                worker_error = error
        finally:
            if future is not None:
                worker_finished_at = time.monotonic()
                with self._state_lock:
                    self._advance_worker_metrics_locked(worker_finished_at)
                    self._inflight.discard(future)
                    self._metrics_worker_completions += 1
                    if worker_error is not None:
                        self._metrics_worker_failures += 1
                    worker_seconds = max(
                        0.0,
                        worker_finished_at - (worker_started_at or worker_finished_at),
                    )
                    self._metrics_worker_seconds_total += worker_seconds
                    self._metrics_worker_seconds_max = max(
                        self._metrics_worker_seconds_max, worker_seconds
                    )
            else:
                self._record_worker_abandoned()
            self._slots.release()

        closing_during_handoff = False
        completed_is_capture_resource = False
        try:
            bound_owner = getattr(function, "__self__", None)
            if worker_error is None:
                self._track_capture_resource(result)
                if getattr(function, "__name__", None) == "discard":
                    self._untrack_capture_resource(bound_owner)
            elif bound_owner is not None and self._capture_resource_discard_complete(
                bound_owner
            ):
                # A post-commit failpoint may report control flow after the resource
                # is already fully discarded. Retaining it would be harmless, but
                # pruning it makes close ownership and accounting explicit.
                self._untrack_capture_resource(bound_owner)
            completed_is_capture_resource = (
                worker_error is None
                and self._resource_authorization_token(result) is not None
            )
        except BaseException as handoff_error:
            caller_control = _defer_capture_failure(
                caller_control,
                wait_errors,
                handoff_error,
            )
        finally:
            if active_run:
                with self._state_lock:
                    closing_during_handoff = self._closed
                    self._active_runs -= 1
        if closing_during_handoff and completed_is_capture_resource:
            wait_errors.append(
                RuntimeError(
                    "Capture runtime closed before worker result ownership handoff"
                )
            )

        if worker_error is not None:
            caller_control = _defer_capture_failure(
                caller_control,
                wait_errors,
                worker_error,
            )
        if caller_control is not None or wait_errors:
            if worker_error is None and not (
                closing_during_handoff and completed_is_capture_resource
            ):
                completed_outcome = caller_control or wait_errors[0]
                try:
                    setattr(completed_outcome, "capture_completed_result", result)
                except BaseException:
                    pass
            _raise_capture_cleanup_outcome(
                caller_control,
                wait_errors,
                "Capture worker drain failed",
            )
        return result

    async def _close_owned_impl(self) -> None:
        """
        Perform the single retryable teardown owned by all close callers.

        The implementation uses current instance state to perform the single
        retryable teardown owned by all close callers. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind. It updates ``_close_cleanup_future``, ``_close_complete``,
        and ``_closed`` on the instance as part of that state transition.
        """

        with self._state_lock:
            self._closed = True

        control_flow: Optional[BaseException] = None
        wait_errors: list[BaseException] = []
        while True:
            with self._state_lock:
                active_runs = self._active_runs
            if active_runs == 0:
                break
            try:
                await asyncio.sleep(0.01)
            except BaseException as error:
                control_flow = _defer_capture_failure(control_flow, wait_errors, error)
        with self._state_lock:
            cleanup_complete = self._cleanup_complete
        if not cleanup_complete:

            def close_blocking() -> None:
                """
                Close blocking.

                The implementation uses current instance state to close
                blocking. It updates ``_cleanup_complete`` and
                ``_output_root_descriptor`` on the instance as part of that
                state transition.
                """
                with self._state_lock:
                    unacknowledged = tuple(
                        record.summary for record in self._published.values()
                    )
                cleanup_errors: list[BaseException] = []
                for summary in unacknowledged:
                    try:
                        self.rollback_published(summary)
                    except BaseException as error:
                        cleanup_errors.append(error)
                try:
                    self.boundary.retry_failed_spool_cleanups()
                except BaseException as error:
                    cleanup_errors.append(error)

                def resource_order(resource: Any) -> int:
                    """
                    Return the resource order.

                    The implementation uses ``resource`` to produce the resource
                    order.

                    Args:
                        resource: Resource consumed while the function attempts
                            to produce the resource order.

                    Returns:
                        The numeric resource order value.
                    """
                    if isinstance(resource, PrivateCapturePublicationTransaction):
                        return 0
                    if isinstance(resource, VerifiedPrivateCapture):
                        return 1
                    if isinstance(resource, PrivateCaptureCandidate):
                        return 2
                    return 3

                # A discard can fail after its file cleanup committed. Retry the
                # registry, then the retained exact capability, so live-spool
                # tokens are unregistered before the boundary is considered.
                for _attempt in range(2):
                    with self._state_lock:
                        resources = sorted(
                            (
                                resource
                                for tracked in self._tracked_resources.values()
                                for resource in tracked
                            ),
                            key=resource_order,
                        )
                    if not resources:
                        break
                    for resource in resources:
                        try:
                            resource.discard()
                        except BaseException as error:
                            cleanup_errors.append(error)
                            if self._capture_resource_discard_complete(resource):
                                self._untrack_capture_resource(resource)
                        else:
                            self._untrack_capture_resource(resource)
                    try:
                        self.boundary.retry_failed_spool_cleanups()
                    except BaseException as error:
                        cleanup_errors.append(error)

                with self._state_lock:
                    unresolved_publications = bool(self._published)
                    unresolved_resources = bool(self._tracked_resources)
                unresolved_private = bool(
                    self.boundary.live_spool_count
                    or self.boundary.pending_cleanup_count
                )
                # A failed publication rollback remains retryable only while
                # the pinned private staging root is still available.  Drain
                # every independent publication and private-file cleanup, but
                # do not tear down that capability until all of them succeed.
                if not (
                    unresolved_publications
                    or unresolved_resources
                    or unresolved_private
                ):
                    try:
                        self.boundary.close()
                    except BaseException as error:
                        cleanup_errors.append(error)
                else:
                    if not cleanup_errors:
                        cleanup_errors.append(
                            RuntimeError(
                                "Capture resources remain owned after teardown retry"
                            )
                        )

                boundary_closed = self.boundary._context._state.closed
                if not boundary_closed:
                    _raise_capture_cleanup_outcome(
                        None,
                        cleanup_errors,
                        "Capture publication and private teardown failed",
                    )
                with self._state_lock:
                    output_root_descriptor = self._output_root_descriptor
                if output_root_descriptor >= 0:
                    try:
                        descriptor_stat = os.fstat(output_root_descriptor)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise
                        with self._state_lock:
                            self._output_root_descriptor = -1
                    else:
                        if (
                            descriptor_stat.st_dev,
                            descriptor_stat.st_ino,
                        ) != self._output_root_identity:
                            # A prior close completed before bookkeeping and
                            # this integer was reused. Never close a capability
                            # whose identity is no longer ours.
                            with self._state_lock:
                                self._output_root_descriptor = -1
                            cleanup_errors.append(
                                CaptureFilesystemBoundaryError(
                                    "Pinned run output root descriptor identity changed"
                                )
                            )
                        else:
                            try:
                                os.close(output_root_descriptor)
                            except BaseException as error:
                                cleanup_errors.append(error)
                            else:
                                with self._state_lock:
                                    self._output_root_descriptor = -1
                with self._state_lock:
                    output_closed = self._output_root_descriptor < 0
                if output_closed:
                    try:
                        self.boundary.concurrent_private_spool_budget._release_owner(
                            self._output_root_resource_key
                        )
                    except BaseException as error:
                        cleanup_errors.append(error)
                output_budget_released = not (
                    self.boundary.concurrent_private_spool_budget.is_active(
                        self._output_root_resource_key
                    )
                )
                if output_closed and output_budget_released:
                    with self._state_lock:
                        self._authorizations.clear()
                        self._tracked_resources.clear()
                        self._pending_abandons.clear()
                        self._cleanup_complete = True
                else:
                    cleanup_errors.append(
                        RuntimeError("Capture output-root ownership remains active")
                    )
                _raise_capture_cleanup_outcome(
                    None,
                    cleanup_errors,
                    "Capture publication and private teardown failed",
                )

            with self._state_lock:
                cleanup_future = self._close_cleanup_future
            if cleanup_future is None:
                cleanup_future = self._executor.submit(close_blocking)
                with self._state_lock:
                    self._close_cleanup_future = cleanup_future
            cleanup_error: Optional[BaseException] = None
            while not cleanup_future.done():
                try:
                    await asyncio.sleep(0.01)
                except BaseException as error:
                    control_flow = _defer_capture_failure(
                        control_flow, wait_errors, error
                    )
            try:
                cleanup_future.result()
            except BaseException as error:
                cleanup_error = error
            with self._state_lock:
                if self._close_cleanup_future is cleanup_future:
                    self._close_cleanup_future = None
            if cleanup_error is not None:
                with self._state_lock:
                    self._close_failures.append(cleanup_error)
                control_flow = _defer_capture_failure(
                    control_flow, wait_errors, cleanup_error
                )
                with self._state_lock:
                    cleanup_complete = self._cleanup_complete
                if not cleanup_complete:
                    _raise_capture_cleanup_outcome(
                        control_flow,
                        wait_errors,
                        "Capture publication and private teardown failed",
                    )
        executor_threads = tuple(self._executor._threads)
        self._executor.shutdown(wait=False, cancel_futures=False)
        try:
            self.boundary._context.hit("runtime.before_executor_join")
        except BaseException as error:
            control_flow = _defer_capture_failure(control_flow, wait_errors, error)
        while any(thread.is_alive() for thread in executor_threads):
            try:
                await asyncio.sleep(0.01)
            except BaseException as error:
                control_flow = _defer_capture_failure(control_flow, wait_errors, error)
        # All capture workers have stopped, so the final join cannot block the
        # event loop.  It releases executor bookkeeping deterministically.
        self._executor.shutdown(wait=True, cancel_futures=False)
        with self._state_lock:
            self._close_complete = True
        _raise_capture_cleanup_outcome(
            control_flow,
            wait_errors,
            "Capture runtime teardown failed",
        )

    async def _close_owned(self) -> Optional[BaseException]:
        """
        Return, rather than task-propagate, process-control close outcomes.

        The implementation uses current instance state to return, rather than
        task-propagate, process-control close outcomes. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind.

        Returns:
            The validated ``error``, or ``None`` when no value qualifies.
        """

        try:
            await self._close_owned_impl()
        except BaseException as error:
            # asyncio gives KeyboardInterrupt and SystemExit raised *from a
            # child Task* event-loop-wide semantics before its waiter can
            # inspect result(). Return the exact object to the owner instead.
            return error
        return None

    async def close(self) -> None:
        """
        Join one shared teardown before re-raising caller process control.

        The implementation uses current instance state to join one shared
        teardown before re-raising caller process control. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind. It updates ``_close_task`` on the instance as
        part of that state transition.
        """

        with self._state_lock:
            if self._close_complete:
                return
            close_task = self._close_task
            if close_task is None:
                close_task = asyncio.create_task(self._close_owned())
                self._close_task = close_task

        caller_control: Optional[BaseException] = None
        wait_errors: list[BaseException] = []
        while not close_task.done():
            try:
                await asyncio.shield(close_task)
            except BaseException as error:
                caller_control = _defer_capture_failure(
                    caller_control, wait_errors, error
                )

        close_error: Optional[BaseException] = None
        try:
            close_error = close_task.result()
        except BaseException as error:
            close_error = error
        with self._state_lock:
            if self._close_task is close_task:
                self._close_task = None
        if close_error is not None:
            caller_control = _defer_capture_failure(
                caller_control, wait_errors, close_error
            )
        _raise_capture_cleanup_outcome(
            caller_control,
            wait_errors,
            "Capture runtime close failed",
        )


@dataclass(frozen=True)
class CaptureCandidateSummary:
    """
    Non-sensitive metadata for one finalized private candidate.

    The immutable record keeps ``record_count``, ``size_bytes``, ``sha256``,
    ``truncated_values``, and ``omitted_values`` together so consumers observe
    one capture candidate summary state. Consumers receive the fields as one
    unit instead of assembling partial state.

    Attributes:
        record_count: Number of record entries represented by the record.
        size_bytes: Byte count recorded for size.
        sha256: Lowercase SHA-256 digest binding the SHA-256 content.
        truncated_values: Number of truncated values represented by this record.
        omitted_values: Number of omitted values represented by this record.
        sanitization_policy_id: Canonical text used as sanitization policy
            identifier.
    """

    record_count: int
    size_bytes: int
    sha256: str
    truncated_values: int = 0
    omitted_values: int = 0
    sanitization_policy_id: Optional[str] = None
    _runtime_authorization_token: Optional[object] = field(
        default=None, repr=False, compare=False
    )


@dataclass(frozen=True)
class VerifiedCaptureReceipt:
    """
    Receipt issued only after an anonymous private copy fully verifies.

    The immutable record keeps ``record_count``, ``size_bytes``, ``sha256``,
    ``verification_id``, and ``sanitization_policy_id`` together so consumers
    observe one verified capture receipt state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        record_count: Number of record entries represented by the record.
        size_bytes: Byte count recorded for size.
        sha256: Lowercase SHA-256 digest binding the SHA-256 content.
        verification_id: Canonical text used as verification identifier.
        sanitization_policy_id: Canonical text used as sanitization policy
            identifier.
    """

    record_count: int
    size_bytes: int
    sha256: str
    verification_id: str
    sanitization_policy_id: Optional[str] = None
    _runtime_authorization_token: Optional[object] = field(
        default=None, repr=False, compare=False
    )


class _CandidatePhase(str, Enum):
    """
    Enumerate the supported candidate phase values.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    AVAILABLE = "available"
    DISCARDED = "discarded"


@dataclass(frozen=True)
class _CandidateState:
    """
    Represent candidate state data exchanged by the runtime.

    The immutable record keeps ``phase``, ``readers``, and ``verified_outputs``
    together so consumers observe one candidate state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        phase: Phase retained as part of the record's public state.
        readers: Collection of readers entries retained by this record.
        verified_outputs: Collection of verified outputs entries retained by
            this record.
    """

    phase: _CandidatePhase = _CandidatePhase.AVAILABLE
    readers: frozenset[object] = frozenset()
    verified_outputs: tuple["VerifiedPrivateCapture", ...] = ()


_DISCARDED_VERIFIED_OWNER = object()


@dataclass(frozen=True)
class PrivateSanitizationInputAttestation:
    """
    Metadata-only proof that a private transaction input reverified.

    The immutable record keeps ``record_count``, ``size_bytes``, ``sha256``,
    ``verification_id``, and ``transaction_id`` together so consumers observe
    one private sanitization input attestation state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        record_count: Number of record entries represented by the record.
        size_bytes: Byte count recorded for size.
        sha256: Lowercase SHA-256 digest binding the SHA-256 content.
        verification_id: Canonical text used as verification identifier.
        transaction_id: Canonical text used as transaction identifier.
        sanitization_policy_id: Canonical text used as sanitization policy
            identifier.
    """

    record_count: int
    size_bytes: int
    sha256: str
    verification_id: str
    transaction_id: str
    sanitization_policy_id: str


@dataclass(frozen=True)
class PublishedCaptureSummary:
    """
    Metadata for one atomically published, pre-sanitized artifact.

    The immutable record keeps ``path``, ``size_bytes``, ``sha256``, and
    ``sanitization_policy_id`` together so consumers observe one published
    capture summary state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        size_bytes: Byte count recorded for size.
        sha256: Lowercase SHA-256 digest binding the SHA-256 content.
        sanitization_policy_id: Canonical text used as sanitization policy
            identifier.
    """

    path: str
    size_bytes: int
    sha256: str
    sanitization_policy_id: str
    _runtime_authorization_token: Optional[object] = field(
        default=None, repr=False, compare=False
    )
    _published_identity: Optional[tuple[int, int]] = field(default=None, repr=False)
    _private_leaf_name: Optional[str] = field(default=None, repr=False, compare=False)
    _publication_budget_key: Optional[object] = field(
        default=None, repr=False, compare=False
    )


class CapturePublicationAmbiguousError(RuntimeError):
    """
    A post-rename failure whose exact public inode needs owned retry.

    Callers receive this exception when the capture publication ambiguous error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """

    def __init__(
        self,
        summary: PublishedCaptureSummary,
        original_error: BaseException,
        rollback_error: BaseException,
    ) -> None:
        """
        Initialize a ``CapturePublicationAmbiguousError`` instance.

        The initializer records ``original_error``, ``rollback_error``, and
        ``summary`` for later operations and establishes the instance invariants
        before any public method runs.

        Args:
            summary: Summary consumed while the function attempts to initialize
                a ``CapturePublicationAmbiguousError`` instance.
            original_error: Original error consumed while the function attempts
                to initialize a ``CapturePublicationAmbiguousError`` instance.
            rollback_error: Rollback error consumed while the function attempts
                to initialize a ``CapturePublicationAmbiguousError`` instance.
        """
        self.summary = summary
        self.original_error = original_error
        self.rollback_error = rollback_error
        super().__init__(
            "Capture publication outcome requires exact run-owned rollback"
        )


@dataclass(frozen=True)
class _VerifiedOwnershipState:
    """
    Represent verified ownership state data exchanged by the runtime.

    The immutable record keeps ``owner`` together so consumers observe one
    verified ownership state. Consumers receive the fields as one unit instead
    of assembling partial state.

    Attributes:
        owner: Owner retained as part of the record's public state.
    """

    owner: object


class _VerifiedOwnership:
    """
    Single atomic ownership record shared across a private handoff.

    The type coordinates ``assert_owner``, ``transfer``, ``discard``,
    ``is_owned_by``, and ``is_discarded`` and retains the state those operations
    share between calls. Resource ownership remains inside the instance until
    the matching close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        *,
        context: _CaptureContext,
        owned_file: _OwnedPrivateFile,
        receipt: VerifiedCaptureReceipt,
        capability_owner: object,
    ) -> None:
        """
        Initialize a ``_VerifiedOwnership`` instance.

        The initializer records ``_lock``, ``_state``, ``context``, ``file``,
        and ``receipt`` for later operations and establishes the instance
        invariants before any public method runs.

        Args:
            context: Runtime context carrying state shared across this
                operation.
            owned_file: filesystem location used as the owned file for this
                operation.
            receipt: Receipt consumed while the function attempts to initialize
                a ``_VerifiedOwnership`` instance.
            capability_owner: Capability owner consumed while the function
                attempts to initialize a ``_VerifiedOwnership`` instance.
        """
        self.context = context
        self.file = owned_file
        self.receipt = receipt
        self._state = _VerifiedOwnershipState(owner=capability_owner)
        self._lock = threading.RLock()

    def assert_owner(self, owner: object) -> None:
        """
        Verify owner.

        The implementation uses ``owner`` to verify owner. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path.

        Args:
            owner: Owner consumed while the function attempts to verify owner.

        Raises:
            RuntimeError: If verified private capture ownership is no longer
                available.
        """
        with self._lock:
            if self._state.owner is not owner:
                raise RuntimeError(
                    "Verified private capture ownership is no longer available"
                )

    def transfer(self, current_owner: object, next_owner: object) -> None:
        """
        Commit a zero-copy private handoff with one state assignment.

        The implementation uses ``current_owner`` and ``next_owner`` to commit a
        zero-copy private handoff with one state assignment. It updates
        ``_state`` on the instance as part of that state transition. If the
        function cannot commit a zero-copy private handoff with one state
        assignment, its exception reaches the caller instead of being converted
        into a successful result.

        Args:
            current_owner: Current owner consumed while the function attempts to
                commit a zero-copy private handoff with one state assignment.
            next_owner: Next owner consumed while the function attempts to
                commit a zero-copy private handoff with one state assignment.

        Raises:
            RuntimeError: If verified private capture capability cannot be
                reused.
        """

        with self._lock:
            if self._state.owner is not current_owner:
                raise RuntimeError(
                    "Verified private capture capability cannot be reused"
                )
            self.file.verify(
                expected_size=self.receipt.size_bytes,
                expected_digest=self.receipt.sha256,
            )
            self._state = _VerifiedOwnershipState(owner=next_owner)

    def discard(self, owner: object) -> None:
        """
        Release the file only for its current canonical owner.

        Integrity failure must still destroy the private bytes and release every
        accounting owner. Report it only after registry cleanup has completed.

        Args:
            owner: Owner consumed while the function attempts to release the
                file only for its current canonical owner.

        Raises:
            RuntimeError: If verified private capture ownership was transferred.
            BaseException: If a delegated failure occurs while the function
                attempts to release the file only for its current canonical
                owner.
        """

        integrity_error: Optional[CaptureFilesystemBoundaryError] = None
        with self._lock:
            if self._state.owner is _DISCARDED_VERIFIED_OWNER:
                return
            if self._state.owner is not owner:
                raise RuntimeError("Verified private capture ownership was transferred")
            registered = self.context.registry.get(self.file.owner_key)
            if registered is not None:
                if not registered.cleanup_complete:
                    try:
                        self.file.verify(
                            expected_size=self.receipt.size_bytes,
                            expected_digest=self.receipt.sha256,
                        )
                    except CaptureFilesystemBoundaryError as error:
                        # Integrity failure must still destroy the private
                        # bytes and release every accounting owner. Report it
                        # only after registry cleanup has completed.
                        integrity_error = error
                self.context.registry.cleanup(self.file.owner_key)
            self._state = _VerifiedOwnershipState(owner=_DISCARDED_VERIFIED_OWNER)
        self.context.maybe_auto_close()
        if integrity_error is not None:
            raise integrity_error

    def is_owned_by(self, owner: object) -> bool:
        """
        Return whether ``owner`` is owned by.

        The implementation uses ``owner`` to determine whether ``owner`` is
        owned by.

        Args:
            owner: Owner consumed while the function attempts to determine
                whether ``owner`` is owned by.

        Returns:
            Whether ``owner`` is owned by.
        """
        with self._lock:
            return self._state.owner is owner

    def is_discarded(self) -> bool:
        """
        Return whether ``the current value`` is discarded.

        The implementation uses current instance state to determine whether
        ``the current value`` is discarded.

        Returns:
            Whether ``the current value`` is discarded.
        """
        with self._lock:
            return self._state.owner is _DISCARDED_VERIFIED_OWNER

    def transferred_transaction(
        self,
    ) -> Optional["PrivateCapturePublicationTransaction"]:
        """
        Return the transferred transaction.

        The implementation uses current instance state to produce the
        transferred transaction.

        Returns:
            The validated ``owner``, or ``None`` when no value qualifies.
        """
        with self._lock:
            owner = self._state.owner
        if isinstance(owner, PrivateCapturePublicationTransaction):
            return owner
        return None


class PrivateCapturePublicationTransaction:
    """
    Module-created handoff and atomic canonical publication transaction.

    The transaction exposes metadata attestations and one policy-gated atomic
    publication operation. It never returns private bytes, descriptors, paths,
    readers, or generic callbacks to the caller.
    """

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        """
        Initialize a ``PrivateCapturePublicationTransaction`` instance.

        The initializer establishes the instance invariants required by later
        operations before the object becomes visible to callers. If the function
        cannot initialize a ``PrivateCapturePublicationTransaction`` instance,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            _args: Additional positional values forwarded in caller-provided
                order.
            _kwargs: Additional named values forwarded without changing their
                keys.

        Raises:
            TypeError: If private capture publication transactions are created
                by handoff only.
        """
        raise TypeError(
            "Private capture publication transactions are created by handoff only"
        )

    @classmethod
    def _adopt(
        cls,
        ownership: _VerifiedOwnership,
        current_owner: object,
    ) -> "PrivateCapturePublicationTransaction":
        """
        Return the adopt.

        The implementation uses ``ownership`` and ``current_owner`` to produce
        the adopt.

        Args:
            ownership: Ownership object whose ``_runtime_authorization_token``,
                ``receipt``, and ``transfer`` state is read while performing
                adopt.
            current_owner: Current owner consumed while the function attempts to
                produce the adopt.

        Returns:
            The validated ``transaction``.
        """
        transaction = object.__new__(cls)
        transaction._ownership = ownership
        transaction._transaction_id = secrets.token_hex(32)
        transaction._runtime_authorization_token = (
            ownership.receipt._runtime_authorization_token
        )
        transaction._discarded = False
        transaction._publication_leaf: Optional[tuple[str, tuple[int, int], bool]] = (
            None
        )
        transaction._publication_budget_key: Optional[object] = None
        transaction._publication_budget_published = False
        transaction._lock = threading.RLock()
        ownership.transfer(current_owner, transaction)
        return transaction

    @property
    def ready_for_sanitization(self) -> bool:
        """
        Return whether ready for sanitization.

        Each access computes the value from ``_discarded``, ``_lock``, and
        ``_ownership`` on the current instance; the derived view is not stored
        as independent state.

        Returns:
            Whether ready for sanitization.
        """
        with self._lock:
            discarded = self._discarded
        return not discarded and self._ownership.is_owned_by(self)

    @property
    def receipt(self) -> VerifiedCaptureReceipt:
        """
        Return the receipt.

        Each access computes the value from ``_ownership`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            A ``VerifiedCaptureReceipt`` representing receipt.
        """
        self._ownership.assert_owner(self)
        return self._ownership.receipt

    def attest_private_input(self) -> PrivateSanitizationInputAttestation:
        """
        Reverify private input and return no content-bearing capability.

        After applying local validation, the function forwards current instance
        state to ``PrivateSanitizationInputAttestation`` and preserves its
        return and exception contract.

        Returns:
            A ``PrivateSanitizationInputAttestation`` representing attest
            private input.

        Raises:
            RuntimeError: If private capture has no run-owned sanitization
                registration.
        """

        self._ownership.assert_owner(self)
        receipt = self._ownership.receipt
        self._ownership.file.verify(
            expected_size=receipt.size_bytes,
            expected_digest=receipt.sha256,
        )
        if (
            receipt._runtime_authorization_token is None
            or not receipt.sanitization_policy_id
        ):
            raise RuntimeError(
                "Private capture has no run-owned sanitization registration"
            )
        return PrivateSanitizationInputAttestation(
            record_count=receipt.record_count,
            size_bytes=receipt.size_bytes,
            sha256=receipt.sha256,
            verification_id=receipt.verification_id,
            transaction_id=self._transaction_id,
            sanitization_policy_id=receipt.sanitization_policy_id,
        )

    def _remember_publication_leaf(
        self,
        leaf_name: str,
        identity: tuple[int, int],
    ) -> None:
        """
        Remember publication leaf.

        The implementation uses ``leaf_name`` and ``identity`` to remember
        publication leaf. It updates ``_publication_leaf`` on the instance as
        part of that state transition. If the function cannot remember
        publication leaf, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            leaf_name: Stable leaf name used for lookup and operator-facing
                diagnostics.
            identity: Entries supplied as ``identity`` without transferring
                container ownership.

        Raises:
            RuntimeError: If capture publication staging is already owned.
        """
        with self._lock:
            if self._publication_leaf is not None:
                raise RuntimeError("Capture publication staging is already owned")
            self._publication_leaf = (leaf_name, identity, False)

    def _mark_publication_linked(self) -> None:
        """
        Mark publication linked.

        The implementation uses current instance state to mark publication
        linked. It updates ``_publication_budget_published`` and
        ``_publication_leaf`` on the instance as part of that state transition.
        If the function cannot mark publication linked, its exception reaches
        the caller instead of being converted into a successful result.

        Raises:
            RuntimeError: If capture publication staging is unavailable.
        """
        with self._lock:
            if self._publication_leaf is None:
                raise RuntimeError("Capture publication staging is unavailable")
            name, identity, _ = self._publication_leaf
            self._publication_leaf = (name, identity, True)
            self._publication_budget_published = True

    def _mark_publication_destination_removed(self) -> None:
        """
        Mark publication destination removed.

        The implementation uses current instance state to mark publication
        destination removed. It updates ``_publication_budget_published`` and
        ``_publication_leaf`` on the instance as part of that state transition.
        """
        with self._lock:
            self._publication_budget_published = False
            if self._publication_leaf is None:
                return
            name, identity, _ = self._publication_leaf
            self._publication_leaf = (name, identity, False)

    def _clear_publication_leaf(
        self,
        leaf_name: str,
        identity: tuple[int, int],
    ) -> None:
        """
        Clear publication leaf.

        The implementation uses ``leaf_name`` and ``identity`` to clear
        publication leaf. It updates ``_publication_leaf`` on the instance as
        part of that state transition. If the function cannot clear publication
        leaf, its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            leaf_name: Stable leaf name used for lookup and operator-facing
                diagnostics.
            identity: Entries supplied as ``identity`` without transferring
                container ownership.

        Raises:
            RuntimeError: If capture publication staging identity mismatch.
        """
        with self._lock:
            if self._publication_leaf is None:
                return
            current_name, current_identity, _ = self._publication_leaf
            if (current_name, current_identity) != (leaf_name, identity):
                raise RuntimeError("Capture publication staging identity mismatch")
            self._publication_leaf = None

    def _remember_publication_budget(self, owner_key: object) -> None:
        """
        Remember publication budget.

        The implementation uses ``owner_key`` to remember publication budget. It
        updates ``_publication_budget_key`` on the instance as part of that
        state transition. If the function cannot remember publication budget,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.

        Raises:
            RuntimeError: If capture publication budget is already owned.
        """
        with self._lock:
            if self._publication_budget_key is not None:
                raise RuntimeError("Capture publication budget is already owned")
            self._publication_budget_key = owner_key

    def _transfer_publication_budget(self, owner_key: object) -> None:
        """
        Transfer the continuous publication lease to the runtime record.

        The implementation uses ``owner_key`` to transfer the continuous
        publication lease to the runtime record. It updates
        ``_publication_budget_key`` on the instance as part of that state
        transition. If the function cannot transfer the continuous publication
        lease to the runtime record, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            owner_key: Stable owner key used for lookup and operator-facing
                diagnostics.

        Raises:
            RuntimeError: If capture publication budget transfer mismatch.
        """

        with self._lock:
            if self._publication_budget_key is not owner_key or not (
                self._publication_budget_published or self._publication_leaf is not None
            ):
                raise RuntimeError("Capture publication budget transfer mismatch")
            self._publication_budget_key = None

    def _release_unpublished_publication_budget(self) -> bool:
        """
        Release accounting only when no private or public link remains.

        The implementation uses current instance state to release accounting
        only when no private or public link remains. It updates
        ``_publication_budget_key`` on the instance as part of that state
        transition. Cleanup in the ``finally`` path runs for successful, failed,
        and cancelled execution.

        Returns:
            Whether the release accounting only when no private or public link
            remains operation succeeds.
        """

        with self._lock:
            if self._publication_leaf is not None or self._publication_budget_published:
                return False
            owner_key = self._publication_budget_key
        if owner_key is None:
            return False
        budget = self._ownership.context.budget
        try:
            return budget._release_owner(owner_key)
        finally:
            if not budget.is_active(owner_key):
                with self._lock:
                    if self._publication_budget_key is owner_key:
                        self._publication_budget_key = None

    def _remove_owned_publication_leaf(
        self,
        *,
        expected_other_links: int,
        descriptor: int = -1,
    ) -> bool:
        """
        Unlink and sync the exact private staging leaf this transaction owns.

        The implementation uses ``expected_other_links`` and ``descriptor`` to
        unlink and sync the exact private staging leaf this transaction owns.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle. If the function cannot unlink and sync the
        exact private staging leaf this transaction owns, its exception reaches
        the caller instead of being converted into a successful result. Cleanup
        in the ``finally`` path runs for successful, failed, and cancelled
        execution.

        Args:
            expected_other_links: Numeric expected other links used while the
                operation performs bounded accounting.
            descriptor: Numeric descriptor used while the operation performs
                bounded accounting.

        Returns:
            Whether the unlink and sync the exact private staging leaf this
            transaction owns operation succeeds.

        Raises:
            RuntimeError: If capture publication link ownership mismatch.
            CaptureFilesystemBoundaryError: If capture publication staging
                ownership changed; capture publication staging path identity
                changed; capture publication staging link ownership changed; or
                capture publication staging acquired an unknown hard link.
        """

        with self._lock:
            publication_leaf = self._publication_leaf
        if publication_leaf is None:
            return False
        leaf_name, identity, public_link = publication_leaf
        if int(bool(public_link)) != expected_other_links:
            raise RuntimeError("Capture publication link ownership mismatch")

        context = self._ownership.context
        context.assert_root()
        opened_here = False
        resource_key = (object(), "publication leaf cleanup descriptor")
        if descriptor < 0:
            context.budget.reserve(
                kind="capture publication leaf cleanup",
                file_descriptors=1,
                owner_key=resource_key,
            )
        try:
            try:
                leaf_stat = os.stat(
                    leaf_name,
                    dir_fd=context.root_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                if descriptor >= 0:
                    descriptor_stat = os.fstat(descriptor)
                    if (
                        (
                            descriptor_stat.st_dev,
                            descriptor_stat.st_ino,
                        )
                        != identity
                        or descriptor_stat.st_nlink != expected_other_links
                    ):
                        raise CaptureFilesystemBoundaryError(
                            "Capture publication staging ownership changed"
                        )
                # The prior unlink may have succeeded while its fsync or
                # bookkeeping was interrupted.  Re-sync the pinned directory
                # before declaring that deletion complete on retry.
                os.fsync(context.root_descriptor)
                self._clear_publication_leaf(leaf_name, identity)
                return False

            if (
                not stat.S_ISREG(leaf_stat.st_mode)
                or (leaf_stat.st_dev, leaf_stat.st_ino) != identity
            ):
                raise CaptureFilesystemBoundaryError(
                    "Capture publication staging path identity changed"
                )
            if descriptor < 0:
                descriptor = os.open(
                    leaf_name,
                    os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=context.root_descriptor,
                )
                opened_here = True
            descriptor_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(descriptor_stat.st_mode)
                or (descriptor_stat.st_dev, descriptor_stat.st_ino) != identity
                or descriptor_stat.st_nlink != expected_other_links + 1
            ):
                raise CaptureFilesystemBoundaryError(
                    "Capture publication staging link ownership changed"
                )
            os.unlink(leaf_name, dir_fd=context.root_descriptor)
            context.hit("publication.after_staging_unlink")
            os.fsync(context.root_descriptor)
            context.hit("publication.after_staging_parent_fsync")
            final_stat = os.fstat(descriptor)
            if final_stat.st_nlink != expected_other_links:
                if final_stat.st_nlink > expected_other_links:
                    os.ftruncate(descriptor, 0)
                    os.fsync(descriptor)
                raise CaptureFilesystemBoundaryError(
                    "Capture publication staging acquired an unknown hard link"
                )
            self._clear_publication_leaf(leaf_name, identity)
            return True
        finally:
            if opened_here:
                os.close(descriptor)
            if descriptor < 0 or opened_here:
                context.budget._release_owner(resource_key)

    def _publish_authorized(
        self,
        authorization: _RuntimePublicationAuthorization,
    ) -> PublishedCaptureSummary:
        """
        Atomically publish only a fully verified, policy-attested input.

        Bytes are first copied to a random 0600 leaf inside the owner-only
        staging root. The public destination is linked with atomic no-clobber
        semantics only after the source and staging leaf both match the attested
        size and digest. Both directory transitions are synced before the final
        single-link artifact is returned.

        Args:
            authorization: Authorization object whose ``destination``,
                ``policy``, ``token``, and ``value`` state is read while
                performing atomically publish only a fully verified,
                policy-attested input.

        Returns:
            A ``PublishedCaptureSummary`` representing publish authorized.

        Raises:
            RuntimeError: If capture publication authorization token mismatch;
                or private capture sanitization policy attestation does not
                match.
            CaptureFilesystemBoundaryError: If atomic capture publication lacks
                one filesystem; verified capture changed during publication;
                capture publication staging digest changed; or capture
                publication staging verification failed; or another input
                invariant is violated.
            OSError: If incomplete capture publication write.
            BaseException: If a delegated failure occurs while the function
                attempts to atomically publish only a fully verified,
                policy-attested input.
            CapturePublicationAmbiguousError: If the function cannot atomically
                publish only a fully verified, policy-attested input safely.
        """

        attestation = self.attest_private_input()
        if (
            self._ownership.receipt._runtime_authorization_token
            is not authorization.token
        ):
            raise RuntimeError("Capture publication authorization token mismatch")
        required_policy = authorization.policy.value
        if attestation.sanitization_policy_id != required_policy:
            raise RuntimeError(
                "Private capture sanitization policy attestation does not match"
            )
        destination = authorization.destination
        context = self._ownership.context
        context.assert_ready()

        owner_key = object()
        publication_budget_key = (owner_key, "publication staging")
        descriptor_budget_key = (owner_key, "publication descriptors")
        physical_key = (owner_key, "publication physical")
        leaf_name = f".nvdebug-publish-{secrets.token_hex(18)}"
        parent_descriptor = -1
        parent_identity: Optional[tuple[int, int]] = None
        descriptor = -1
        identity: Optional[tuple[int, int]] = None
        renamed = False
        renamed_summary: Optional[PublishedCaptureSummary] = None
        primary_error: Optional[BaseException] = None
        cleanup_errors: list[BaseException] = []
        try:
            # Byte/object ownership transfers with a public or ambiguous
            # artifact and survives until durable ack or exact rollback.
            self._remember_publication_budget(publication_budget_key)
            context.budget.reserve(
                attestation.size_bytes,
                kind="private capture publication staging",
                objects=1,
                owner_key=publication_budget_key,
            )
            # Descriptor accounting is transient and is released during final
            # publication cleanup.
            context.budget.reserve(
                kind="private capture publication descriptors",
                file_descriptors=2,
                owner_key=descriptor_budget_key,
            )
            parent_descriptor, parent_identity = _open_authorized_publication_parent(
                authorization
            )
            if (
                os.fstat(parent_descriptor).st_dev
                != os.fstat(context.root_descriptor).st_dev
            ):
                raise CaptureFilesystemBoundaryError(
                    "Atomic capture publication requires one filesystem"
                )
            context.physical.reserve(
                context.root_descriptor,
                attestation.size_bytes,
                context.capacity_observer,
                owner_key=physical_key,
            )
            descriptor = os.open(
                leaf_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=context.root_descriptor,
            )
            os.fchmod(descriptor, 0o600)
            descriptor_stat = os.fstat(descriptor)
            identity = (descriptor_stat.st_dev, descriptor_stat.st_ino)
            self._remember_publication_leaf(leaf_name, identity)

            digest = hashlib.sha256()
            offset = 0
            while offset < attestation.size_bytes:
                chunk = self._ownership.file.read_at(
                    min(_COPY_CHUNK_BYTES, attestation.size_bytes - offset),
                    offset,
                )
                if not chunk:
                    raise CaptureFilesystemBoundaryError(
                        "Verified capture changed during publication"
                    )
                written_total = 0
                while written_total < len(chunk):
                    written = os.pwrite(
                        descriptor,
                        chunk[written_total:],
                        offset + written_total,
                    )
                    if written <= 0:
                        raise OSError("Incomplete capture publication write")
                    written_total += written
                digest.update(chunk)
                offset += len(chunk)
                context.hit("publication.after_copy_chunk")
            os.fsync(descriptor)
            context.physical.consume(physical_key, attestation.size_bytes)
            if (
                offset != attestation.size_bytes
                or digest.hexdigest() != attestation.sha256
            ):
                raise CaptureFilesystemBoundaryError(
                    "Capture publication staging digest changed"
                )
            staged_stat = os.fstat(descriptor)
            if (
                identity is None
                or (staged_stat.st_dev, staged_stat.st_ino) != identity
                or not stat.S_ISREG(staged_stat.st_mode)
                or staged_stat.st_uid != context.owner_uid
                or staged_stat.st_size != attestation.size_bytes
                or staged_stat.st_nlink != 1
                or stat.S_IMODE(staged_stat.st_mode) != 0o600
                or _digest_descriptor(descriptor, staged_stat.st_size)
                != attestation.sha256
            ):
                raise CaptureFilesystemBoundaryError(
                    "Capture publication staging verification failed"
                )
            self._ownership.file.verify(
                expected_size=attestation.size_bytes,
                expected_digest=attestation.sha256,
            )
            context.assert_root()
            assert parent_identity is not None
            _assert_pinned_directory_path(
                destination.parent, parent_descriptor, parent_identity
            )
            try:
                os.stat(
                    destination.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise CaptureFilesystemBoundaryError(
                    "Capture publication destination already exists"
                )
            try:
                # link(2) supplies the no-clobber guarantee that replace(2)
                # cannot: a destination created after the absence check causes
                # EEXIST instead of being overwritten. The temporary and final
                # names are on the already-proved single filesystem.
                os.link(
                    leaf_name,
                    destination.name,
                    src_dir_fd=context.root_descriptor,
                    dst_dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise CaptureFilesystemBoundaryError(
                    "Capture publication destination already exists"
                ) from error
            except OSError as error:
                raise CaptureFilesystemBoundaryError(
                    "Atomic no-clobber capture publication failed"
                ) from error
            renamed = True
            self._mark_publication_linked()
            renamed_summary = PublishedCaptureSummary(
                path=str(destination),
                size_bytes=attestation.size_bytes,
                sha256=attestation.sha256,
                sanitization_policy_id=required_policy,
                _runtime_authorization_token=authorization.token,
                _published_identity=identity,
                _private_leaf_name=leaf_name,
                _publication_budget_key=publication_budget_key,
            )
            context.hit("publication.after_replace")

            published_stat = os.stat(
                destination.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                identity is None
                or (published_stat.st_dev, published_stat.st_ino) != identity
                or not stat.S_ISREG(published_stat.st_mode)
                or published_stat.st_uid != context.owner_uid
                or stat.S_IMODE(published_stat.st_mode) != 0o600
                or published_stat.st_size != attestation.size_bytes
                or published_stat.st_nlink != 2
                or _digest_descriptor(descriptor, published_stat.st_size)
                != attestation.sha256
            ):
                raise CaptureFilesystemBoundaryError(
                    "Capture publication destination verification failed"
                )
            _assert_pinned_directory_path(
                destination.parent, parent_descriptor, parent_identity
            )
            self._ownership.file.verify(
                expected_size=attestation.size_bytes,
                expected_digest=attestation.sha256,
            )
            self._remove_owned_publication_leaf(
                expected_other_links=1,
                descriptor=descriptor,
            )
            renamed_summary = replace(renamed_summary, _private_leaf_name=None)
            os.fsync(parent_descriptor)
            context.hit("publication.after_parent_fsync")
            _assert_pinned_directory_path(
                destination.parent, parent_descriptor, parent_identity
            )
            final_stat = os.stat(
                destination.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                identity is None
                or (final_stat.st_dev, final_stat.st_ino) != identity
                or not stat.S_ISREG(final_stat.st_mode)
                or final_stat.st_uid != context.owner_uid
                or stat.S_IMODE(final_stat.st_mode) != 0o600
                or final_stat.st_size != attestation.size_bytes
                or final_stat.st_nlink != 1
                or _digest_descriptor(descriptor, final_stat.st_size)
                != attestation.sha256
            ):
                raise CaptureFilesystemBoundaryError(
                    "Capture publication changed after directory sync"
                )
            return PublishedCaptureSummary(
                path=str(destination),
                size_bytes=attestation.size_bytes,
                sha256=attestation.sha256,
                sanitization_policy_id=required_policy,
                _runtime_authorization_token=authorization.token,
                _published_identity=(final_stat.st_dev, final_stat.st_ino),
                _publication_budget_key=publication_budget_key,
            )
        except BaseException as error:
            primary_error = error
            if renamed and parent_descriptor >= 0 and identity is not None:
                try:
                    context.hit("publication.before_rollback")
                    try:
                        published_stat = os.stat(
                            destination.name,
                            dir_fd=parent_descriptor,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        published_stat = None
                    else:
                        private_link_expected = bool(
                            renamed_summary is not None
                            and renamed_summary._private_leaf_name
                        )
                        expected_links = 1 + int(private_link_expected)
                        if (
                            not stat.S_ISREG(published_stat.st_mode)
                            or (published_stat.st_dev, published_stat.st_ino)
                            != identity
                            or published_stat.st_size != attestation.size_bytes
                            or published_stat.st_nlink != expected_links
                            or _digest_descriptor(descriptor, published_stat.st_size)
                            != attestation.sha256
                        ):
                            raise CaptureFilesystemBoundaryError(
                                "Refusing to roll back a changed capture publication"
                            )
                        os.unlink(
                            destination.name,
                            dir_fd=parent_descriptor,
                        )
                    os.fsync(parent_descriptor)
                    self._mark_publication_destination_removed()
                    if (
                        renamed_summary is not None
                        and renamed_summary._private_leaf_name
                    ):
                        self._remove_owned_publication_leaf(
                            expected_other_links=0,
                            descriptor=descriptor,
                        )
                    remaining_links = os.fstat(descriptor).st_nlink
                    if remaining_links != 0:
                        os.ftruncate(descriptor, 0)
                        os.fsync(descriptor)
                        raise CaptureFilesystemBoundaryError(
                            "Capture rollback detected an unknown hard link"
                        )
                    renamed = False
                except BaseException as rollback_error:
                    assert renamed_summary is not None
                    ambiguous = CapturePublicationAmbiguousError(
                        renamed_summary,
                        error,
                        rollback_error,
                    )
                    primary_error = ambiguous
                    raise ambiguous from error
            raise
        finally:
            if not renamed and identity is not None:
                try:
                    with self._lock:
                        publication_leaf = self._publication_leaf
                    if publication_leaf is not None and not publication_leaf[2]:
                        self._remove_owned_publication_leaf(
                            expected_other_links=0,
                            descriptor=descriptor,
                        )
                except BaseException as error:
                    cleanup_errors.append(error)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except BaseException as error:
                    cleanup_errors.append(error)
            try:
                context.physical.release_owner(physical_key)
            except BaseException as error:
                cleanup_errors.append(error)
            if parent_descriptor >= 0:
                try:
                    os.close(parent_descriptor)
                except BaseException as error:
                    cleanup_errors.append(error)
            try:
                context.budget._release_owner(descriptor_budget_key)
            except BaseException as error:
                cleanup_errors.append(error)
            try:
                self._release_unpublished_publication_budget()
            except BaseException as error:
                cleanup_errors.append(error)
            if cleanup_errors:
                failures = [
                    *([primary_error] if primary_error is not None else []),
                    *cleanup_errors,
                ]
                control_flow: Optional[BaseException] = None
                ordinary_errors: list[BaseException] = []
                for failure in failures:
                    control_flow = _defer_capture_failure(
                        control_flow,
                        ordinary_errors,
                        failure,
                    )
                if control_flow is not None:
                    if renamed and renamed_summary is not None:
                        try:
                            setattr(
                                control_flow,
                                "capture_completed_result",
                                renamed_summary,
                            )
                        except BaseException:
                            pass
                    _raise_capture_cleanup_outcome(
                        control_flow,
                        ordinary_errors,
                        "Capture publication cleanup failed",
                    )
                if primary_error is not None:
                    for cleanup_error in cleanup_errors:
                        _add_capture_note(
                            primary_error,
                            "Capture publication cleanup failed: "
                            f"{type(cleanup_error).__name__}: {cleanup_error}",
                        )
                    raise primary_error
                first_cleanup_error = ordinary_errors[0]
                for cleanup_error in ordinary_errors[1:]:
                    _add_capture_note(
                        first_cleanup_error,
                        "Additional capture publication cleanup failure: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}",
                    )
                if renamed and renamed_summary is not None:
                    raise CapturePublicationAmbiguousError(
                        renamed_summary,
                        first_cleanup_error,
                        RuntimeError(
                            "Published capture cleanup requires exact rollback"
                        ),
                    ) from first_cleanup_error
                raise first_cleanup_error

    @staticmethod
    def _rollback_authorized(
        summary: PublishedCaptureSummary,
        authorization: _RuntimePublicationAuthorization,
        context: _CaptureContext,
    ) -> None:
        """
        Remove and sync every exact link still owned by one publication.

        The implementation uses ``summary``, ``authorization``, and ``context``
        to remove and sync every exact link still owned by one publication. If
        the function cannot remove and sync every exact link still owned by one
        publication, its exception reaches the caller instead of being converted
        into a successful result. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Args:
            summary: Summary object whose ``_private_leaf_name``,
                ``_published_identity``, ``_runtime_authorization_token``,
                ``path``, and ``sanitization_policy_id`` state is read while
                performing remove and sync every exact link still owned by one
                publication.
            authorization: Authorization object whose ``destination``,
                ``policy``, ``token``, and ``value`` state is read while
                performing remove and sync every exact link still owned by one
                publication.
            context: Runtime context carrying state shared across this
                operation.

        Raises:
            TypeError: If published capture summary is required for rollback.
            RuntimeError: If published capture rollback authorization mismatch.
            CaptureFilesystemBoundaryError: If published capture rollback
                identity is unavailable; refusing to roll back a changed capture
                publication; capture rollback detected an unknown hard link; or
                refusing to remove a changed private publication link; or
                another input invariant is violated.
        """

        if not isinstance(summary, PublishedCaptureSummary):
            raise TypeError("Published capture summary is required for rollback")
        if (
            summary._runtime_authorization_token is not authorization.token
            or summary.path != str(authorization.destination)
            or summary.sanitization_policy_id != authorization.policy.value
        ):
            raise RuntimeError("Published capture rollback authorization mismatch")
        destination = authorization.destination
        if summary._published_identity is None:
            raise CaptureFilesystemBoundaryError(
                "Published capture rollback identity is unavailable"
            )

        errors: list[BaseException] = []
        private_present = False
        private_leaf_name = summary._private_leaf_name
        if private_leaf_name:
            try:
                context.assert_root()
                private_stat = os.stat(
                    private_leaf_name,
                    dir_fd=context.root_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            except BaseException as error:
                errors.append(error)
            else:
                if (
                    not stat.S_ISREG(private_stat.st_mode)
                    or (private_stat.st_dev, private_stat.st_ino)
                    != summary._published_identity
                ):
                    errors.append(
                        CaptureFilesystemBoundaryError(
                            "Private capture publication link identity changed"
                        )
                    )
                else:
                    private_present = True

        parent_descriptor = -1
        artifact_descriptor = -1
        try:
            parent_descriptor, parent_identity = _open_authorized_publication_parent(
                authorization
            )
            _assert_pinned_directory_path(
                destination.parent, parent_descriptor, parent_identity
            )
            try:
                destination_stat = os.stat(
                    destination.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                expected_links = 1 + int(private_present)
                if (
                    not stat.S_ISREG(destination_stat.st_mode)
                    or destination_stat.st_size != summary.size_bytes
                    or (destination_stat.st_dev, destination_stat.st_ino)
                    != summary._published_identity
                    or destination_stat.st_nlink != expected_links
                ):
                    raise CaptureFilesystemBoundaryError(
                        "Refusing to roll back a changed capture publication"
                    )
                artifact_descriptor = os.open(
                    destination.name,
                    os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=parent_descriptor,
                )
                opened_stat = os.fstat(artifact_descriptor)
                if (
                    (opened_stat.st_dev, opened_stat.st_ino)
                    != summary._published_identity
                    or opened_stat.st_size != summary.size_bytes
                    or opened_stat.st_nlink != expected_links
                    or _digest_descriptor(artifact_descriptor, opened_stat.st_size)
                    != summary.sha256
                ):
                    raise CaptureFilesystemBoundaryError(
                        "Refusing to roll back a changed capture publication"
                    )
                os.unlink(destination.name, dir_fd=parent_descriptor)
                remaining_links = os.fstat(artifact_descriptor).st_nlink
                expected_remaining = int(private_present)
                if remaining_links != expected_remaining:
                    if remaining_links > expected_remaining:
                        os.ftruncate(artifact_descriptor, 0)
                        os.fsync(artifact_descriptor)
                    raise CaptureFilesystemBoundaryError(
                        "Capture rollback detected an unknown hard link"
                    )
            # Also sync when a retry observes the destination already absent:
            # a previous unlink may have completed before its directory fsync.
            os.fsync(parent_descriptor)
        except BaseException as error:
            errors.append(error)
        finally:
            if artifact_descriptor >= 0:
                try:
                    os.close(artifact_descriptor)
                except BaseException as error:
                    errors.append(error)
            if parent_descriptor >= 0:
                try:
                    os.close(parent_descriptor)
                except BaseException as error:
                    errors.append(error)

        if private_leaf_name:
            private_descriptor = -1
            try:
                context.assert_root()
                try:
                    private_stat = os.stat(
                        private_leaf_name,
                        dir_fd=context.root_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    private_stat = None
                if private_stat is not None:
                    if (
                        not stat.S_ISREG(private_stat.st_mode)
                        or (private_stat.st_dev, private_stat.st_ino)
                        != summary._published_identity
                        or private_stat.st_nlink != 1
                    ):
                        raise CaptureFilesystemBoundaryError(
                            "Refusing to remove a changed private publication link"
                        )
                    private_descriptor = os.open(
                        private_leaf_name,
                        os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=context.root_descriptor,
                    )
                    opened_private = os.fstat(private_descriptor)
                    if (
                        opened_private.st_dev,
                        opened_private.st_ino,
                    ) != summary._published_identity or opened_private.st_nlink != 1:
                        raise CaptureFilesystemBoundaryError(
                            "Private publication link changed during rollback"
                        )
                    os.unlink(private_leaf_name, dir_fd=context.root_descriptor)
                    os.fsync(context.root_descriptor)
                    remaining_links = os.fstat(private_descriptor).st_nlink
                    if remaining_links != 0:
                        os.ftruncate(private_descriptor, 0)
                        os.fsync(private_descriptor)
                        raise CaptureFilesystemBoundaryError(
                            "Private publication rollback found an unknown hard link"
                        )
                else:
                    # Preserve durability when an earlier unlink completed but
                    # its staging-directory fsync was interrupted.
                    os.fsync(context.root_descriptor)
            except BaseException as error:
                errors.append(error)
            finally:
                if private_descriptor >= 0:
                    try:
                        os.close(private_descriptor)
                    except BaseException as error:
                        errors.append(error)

        _raise_capture_cleanup_outcome(
            None,
            errors,
            "Capture publication rollback failed",
        )

    def _publish_authorized_and_discard(
        self,
        authorization: _RuntimePublicationAuthorization,
    ) -> PublishedCaptureSummary:
        """
        Publish and release private ownership as one worker operation.

        The implementation uses ``authorization`` to publish and release private
        ownership as one worker operation. Success is reported only after the
        owning output boundary has completed its required write or publication
        step. If the function cannot publish and release private ownership as
        one worker operation, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            authorization: Authorization consumed while the function attempts to
                publish and release private ownership as one worker operation.

        Returns:
            The validated ``summary``.

        Raises:
            CapturePublicationAmbiguousError: If the function cannot publish and
                release private ownership as one worker operation safely.
            BaseException: If a delegated failure occurs while the function
                attempts to publish and release private ownership as one worker
                operation.
        """

        summary = self._publish_authorized(authorization)
        try:
            self.discard()
        except BaseException as discard_error:
            rollback_key = (object(), "publication rollback descriptors")
            rollback_errors: list[BaseException] = []
            try:
                self._ownership.context.budget.reserve(
                    kind="capture publication rollback",
                    file_descriptors=2,
                    owner_key=rollback_key,
                )
                self._rollback_authorized(
                    summary,
                    authorization,
                    self._ownership.context,
                )
                if summary._publication_budget_key is not None:
                    self._ownership.context.budget._release_owner(
                        summary._publication_budget_key
                    )
            except BaseException as rollback_error:
                rollback_errors.append(rollback_error)
            try:
                self._ownership.context.budget._release_owner(rollback_key)
            except BaseException as rollback_error:
                rollback_errors.append(rollback_error)

            failures = [discard_error, *rollback_errors]
            control_flow: Optional[BaseException] = None
            ordinary_errors: list[BaseException] = []
            for failure in failures:
                control_flow = _defer_capture_failure(
                    control_flow,
                    ordinary_errors,
                    failure,
                )
            if control_flow is not None:
                try:
                    setattr(control_flow, "capture_completed_result", summary)
                except BaseException:
                    pass
                _raise_capture_cleanup_outcome(
                    control_flow,
                    ordinary_errors,
                    "Capture private discard and publication rollback failed",
                )
            if rollback_errors:
                if len(rollback_errors) == 1:
                    rollback_failure = rollback_errors[0]
                else:
                    rollback_failure = BaseExceptionGroup(
                        "Capture publication rollback failed",
                        rollback_errors,
                    )
                raise CapturePublicationAmbiguousError(
                    summary,
                    discard_error,
                    rollback_failure,
                ) from discard_error
            raise discard_error
        return summary

    def discard(self) -> None:
        """
        Idempotently abort and clean the transaction's private input.

        The implementation uses current instance state to idempotently abort and
        clean the transaction's private input. It updates ``_discarded`` on the
        instance as part of that state transition.
        """

        with self._lock:
            if self._discarded:
                return
            publication_leaf = self._publication_leaf
        errors: list[BaseException] = []
        if publication_leaf is not None and not publication_leaf[2]:
            try:
                self._remove_owned_publication_leaf(expected_other_links=0)
            except BaseException as error:
                errors.append(error)
        try:
            self._release_unpublished_publication_budget()
        except BaseException as error:
            errors.append(error)
        try:
            self._ownership.discard(self)
        except BaseException as error:
            errors.append(error)
        _raise_capture_cleanup_outcome(
            None,
            errors,
            "Capture transaction cleanup failed",
        )
        with self._lock:
            self._discarded = True


class VerifiedPrivateCapture:
    """
    Pathless verified capability with a single private handoff.

    The type coordinates ``receipt``, ``size_bytes``, ``sha256``,
    ``transferred_transaction``, and ``handoff_to_private_transaction`` and
    retains the state those operations share between calls. Resource ownership
    remains inside the instance until the matching close, exit, or cleanup
    operation completes.
    """

    def __init__(
        self,
        *,
        context: _CaptureContext,
        owned_file: _OwnedPrivateFile,
        receipt: VerifiedCaptureReceipt,
    ) -> None:
        """
        Initialize a ``VerifiedPrivateCapture`` instance.

        The initializer records ``_context``, ``_owner_token``, and
        ``_ownership`` for later operations and establishes the instance
        invariants before any public method runs.

        Args:
            context: Runtime context carrying state shared across this
                operation.
            owned_file: filesystem location used as the owned file for this
                operation.
            receipt: Receipt object whose ``sha256`` and ``size_bytes`` state is
                read while performing initialize a ``VerifiedPrivateCapture``
                instance.
        """
        self._context = context
        self._owner_token = object()
        self._ownership = _VerifiedOwnership(
            context=context,
            owned_file=owned_file,
            receipt=receipt,
            capability_owner=self._owner_token,
        )
        owned_file.verify(
            expected_size=receipt.size_bytes,
            expected_digest=receipt.sha256,
        )

    @property
    def receipt(self) -> VerifiedCaptureReceipt:
        """
        Return the receipt.

        Each access computes the value from ``_ownership`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            A ``VerifiedCaptureReceipt`` representing receipt.
        """
        return self._ownership.receipt

    @property
    def size_bytes(self) -> int:
        """
        Return the size bytes.

        Each access computes the value from ``receipt`` on the current instance;
        the derived view is not stored as independent state.

        Returns:
            The numeric size bytes value.
        """
        return self.receipt.size_bytes

    @property
    def sha256(self) -> str:
        """
        Return the SHA-256.

        Each access computes the value from ``receipt`` on the current instance;
        the derived view is not stored as independent state.

        Returns:
            The canonical SHA-256 text.
        """
        return self.receipt.sha256

    @property
    def transferred_transaction(
        self,
    ) -> Optional[PrivateCapturePublicationTransaction]:
        """
        Recover a transaction if handoff return was interrupted.

        Each access computes the value from ``_ownership`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            A ``PrivateCapturePublicationTransaction`` representing transferred
            transaction, or ``None`` when the requested value is unavailable.
        """

        return self._ownership.transferred_transaction()

    def handoff_to_private_transaction(
        self,
    ) -> PrivateCapturePublicationTransaction:
        """
        Transfer exact anonymous ownership once without exposing bytes.

        After applying local validation, the function forwards current instance
        state to ``PrivateCapturePublicationTransaction._adopt`` and preserves
        its return and exception contract.

        Returns:
            A ``PrivateCapturePublicationTransaction`` representing handoff to
            private transaction.
        """

        return PrivateCapturePublicationTransaction._adopt(
            self._ownership,
            self._owner_token,
        )

    def discard(self) -> None:
        """
        Idempotently release an untransferred verified capability.

        The implementation uses current instance state to idempotently release
        an untransferred verified capability.
        """

        self._ownership.discard(self._owner_token)


class PrivateCaptureCandidate:
    """
    Anonymous candidate that can only verify into another anonymous file.

    The type coordinates ``summary``, ``record_count``, ``size_bytes``,
    ``sha256``, and ``truncated_values`` and retains the state those operations
    share between calls. Resource ownership remains inside the instance until
    the matching close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        *,
        context: _CaptureContext,
        owned_file: _OwnedPrivateFile,
        summary: CaptureCandidateSummary,
    ) -> None:
        """
        Initialize a ``PrivateCaptureCandidate`` instance.

        The initializer records ``_context``, ``_file``, ``_lock``, ``_state``,
        and ``_summary`` for later operations and establishes the instance
        invariants before any public method runs.

        Args:
            context: Runtime context carrying state shared across this
                operation.
            owned_file: filesystem location used as the owned file for this
                operation.
            summary: Summary object whose ``sha256`` and ``size_bytes`` state is
                read while performing initialize a ``PrivateCaptureCandidate``
                instance.
        """
        self._context = context
        self._file = owned_file
        self._summary = summary
        self._verification_id = secrets.token_hex(32)
        self._state = _CandidateState()
        self._lock = threading.RLock()
        self._file.verify(
            expected_size=summary.size_bytes,
            expected_digest=summary.sha256,
        )

    @property
    def summary(self) -> CaptureCandidateSummary:
        """
        Return the summary.

        Each access computes the value from ``_summary`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            A ``CaptureCandidateSummary`` representing summary.
        """
        return self._summary

    @property
    def record_count(self) -> int:
        """
        Return the record count.

        Each access computes the value from ``_summary`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The numeric record count.
        """
        return self._summary.record_count

    @property
    def size_bytes(self) -> int:
        """
        Return the size bytes.

        Each access computes the value from ``_summary`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The numeric size bytes value.
        """
        return self._summary.size_bytes

    @property
    def sha256(self) -> str:
        """
        Return the SHA-256.

        Each access computes the value from ``_summary`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The canonical SHA-256 text.
        """
        return self._summary.sha256

    @property
    def truncated_values(self) -> int:
        """
        Return the truncated values.

        Each access computes the value from ``_summary`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The numeric truncated values value.
        """
        return self._summary.truncated_values

    @property
    def omitted_values(self) -> int:
        """
        Return the omitted values.

        Each access computes the value from ``_summary`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The numeric omitted values value.
        """
        return self._summary.omitted_values

    @property
    def latest_verified_copy(self) -> Optional[VerifiedPrivateCapture]:
        """
        Return the last committed private verification capability, if any.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            A ``VerifiedPrivateCapture`` representing latest verified copy, or
            ``None`` when the requested value is unavailable.
        """

        with self._lock:
            if not self._state.verified_outputs:
                return None
            return self._state.verified_outputs[-1]

    def verify_private_copy(self) -> VerifiedPrivateCapture:
        """
        Verify into an anonymous sink and publish only the completed capability.

        The implementation uses current instance state to verify into an
        anonymous sink and publish only the completed capability. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path. It updates
        ``_state`` on the instance as part of that state transition. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle. Cleanup in the ``finally`` path runs for successful,
        failed, and cancelled execution.

        Returns:
            The validated ``verified``.

        Raises:
            RuntimeError: If private capture candidate is discarded.
            CaptureFilesystemBoundaryError: If private capture candidate was
                truncated during verification; private capture candidate
                exceeded its verified size; or private capture candidate changed
                during verification.
        """

        with self._lock:
            if self._state.phase is not _CandidatePhase.AVAILABLE:
                raise RuntimeError("Private capture candidate is discarded")
        self._context.assert_ready()
        destination = self._context.create_file(_PrivateFileRole.VERIFIED_COPY)
        reader_key = object()
        resource_key = (reader_key, "reader")
        verified: Optional[VerifiedPrivateCapture] = None
        try:
            with self._lock:
                if self._state.phase is not _CandidatePhase.AVAILABLE:
                    raise RuntimeError("Private capture candidate is discarded")
                try:
                    self._context.budget.reserve(
                        kind="private capture verified reader",
                        readers=1,
                        owner_key=resource_key,
                    )
                    self._state = replace(
                        self._state,
                        readers=self._state.readers | frozenset({reader_key}),
                    )
                except BaseException:
                    self._context.budget._release_owner(resource_key)
                    raise

            digest = hashlib.sha256()
            consumed = 0
            try:
                self._file.verify(
                    expected_size=self.size_bytes,
                    expected_digest=self.sha256,
                )
                while consumed < self.size_bytes:
                    chunk = self._file.read_at(
                        min(_COPY_CHUNK_BYTES, self.size_bytes - consumed),
                        consumed,
                    )
                    if not chunk:
                        raise CaptureFilesystemBoundaryError(
                            "Private capture candidate was truncated during verification"
                        )
                    destination.write_at(chunk, consumed)
                    digest.update(chunk)
                    consumed += len(chunk)
                    self._context.hit("candidate.after_verified_chunk")
                if self._file.read_at(1, self.size_bytes):
                    raise CaptureFilesystemBoundaryError(
                        "Private capture candidate exceeded its verified size"
                    )
                if consumed != self.size_bytes or digest.hexdigest() != self.sha256:
                    raise CaptureFilesystemBoundaryError(
                        "Private capture candidate changed during verification"
                    )
                self._file.verify(
                    expected_size=self.size_bytes,
                    expected_digest=self.sha256,
                )
                destination.fsync()
                destination.verify(
                    expected_size=consumed,
                    expected_digest=digest.hexdigest(),
                )
            finally:
                try:
                    self._context.budget._release_owner(resource_key)
                finally:
                    with self._lock:
                        self._state = replace(
                            self._state,
                            readers=(self._state.readers - frozenset({reader_key})),
                        )

            receipt = VerifiedCaptureReceipt(
                record_count=self.record_count,
                size_bytes=consumed,
                sha256=digest.hexdigest(),
                verification_id=self._verification_id,
                sanitization_policy_id=(self._summary.sanitization_policy_id),
                _runtime_authorization_token=(
                    self._summary._runtime_authorization_token
                ),
            )
            verified = VerifiedPrivateCapture(
                context=self._context,
                owned_file=destination,
                receipt=receipt,
            )
            with self._lock:
                self._state = replace(
                    self._state,
                    verified_outputs=(
                        *self._state.verified_outputs,
                        verified,
                    ),
                )
            self._context.hit("candidate.after_verification_commit")
            return verified
        except BaseException as verification_error:
            with self._lock:
                committed = (
                    verified is not None and verified in self._state.verified_outputs
                )
            if not committed:
                try:
                    self._context.registry.cleanup(destination.owner_key)
                except BaseException as cleanup_error:
                    verification_error.add_note(
                        "Failed verification sink cleanup remains owned for retry: "
                        f"{cleanup_error}"
                    )
            raise

    def discard(self) -> None:
        """
        Idempotently discard the candidate without exposing its descriptor.

        The implementation uses current instance state to idempotently discard
        the candidate without exposing its descriptor. It updates ``_state`` on
        the instance as part of that state transition. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        If the function cannot idempotently discard the candidate without
        exposing its descriptor, its exception reaches the caller instead of
        being converted into a successful result.

        Raises:
            RuntimeError: If cannot discard private capture candidate with live
                readers.
            BaseException: If a delegated failure occurs while the function
                attempts to idempotently discard the candidate without exposing
                its descriptor.
        """

        with self._lock:
            if self._state.phase is _CandidatePhase.DISCARDED:
                self._context.maybe_auto_close()
                return
            if self._state.readers:
                raise RuntimeError(
                    "Cannot discard private capture candidate with live readers"
                )
        integrity_error: Optional[CaptureFilesystemBoundaryError] = None
        registered = self._context.registry.get(self._file.owner_key)
        if registered is not None and not registered.cleanup_complete:
            try:
                self._file.verify(
                    expected_size=self.size_bytes,
                    expected_digest=self.sha256,
                )
            except CaptureFilesystemBoundaryError as error:
                integrity_error = error
        if registered is not None:
            self._context.registry.cleanup(self._file.owner_key)
        with self._lock:
            self._state = replace(self._state, phase=_CandidatePhase.DISCARDED)
        self._context.maybe_auto_close()
        if integrity_error is not None:
            raise integrity_error


class _HashingWriter:
    """
    Bounded sink writer that never exposes a filesystem handle.

    The type coordinates ``write``, ``flush``, and ``hexdigest`` and retains the
    state those operations share between calls. Resource ownership remains
    inside the instance until the matching close, exit, or cleanup operation
    completes.
    """

    def __init__(
        self,
        sink: Callable[[bytes], None],
        *,
        max_bytes: Optional[int] = None,
        limit_name: str = "capture byte limit",
    ) -> None:
        """
        Initialize a ``_HashingWriter`` instance.

        The initializer records ``_buffer``, ``_digest``, ``_limit_name``,
        ``_max_bytes``, and ``_sink`` for later operations and establishes the
        instance invariants before any public method runs.

        Args:
            sink: Optional sink; ``None`` selects the function's default
                behavior.
            max_bytes: Upper bound enforced for max bytes; the consuming
                boundary rejects or truncates values that exceed it.
            limit_name: Stable limit name used for lookup and operator-facing
                diagnostics.
        """
        self._sink = sink
        self._digest = hashlib.sha256()
        self._max_bytes = max_bytes
        self._limit_name = limit_name
        self._buffer = bytearray()
        self.size_bytes = 0
        self.truncated_values = 0
        self.omitted_values = 0

    def write(self, payload: bytes) -> None:
        """
        Write the supplied data to the owned destination.

        The implementation uses ``payload`` to write the supplied data to the
        owned destination. Success is reported only after the owning output
        boundary has completed its required write or publication step. It
        updates ``size_bytes`` on the instance as part of that state transition.
        If the function cannot write the supplied data to the owned destination,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            payload: Bounded byte sequence supplied as payload.

        Raises:
            CaptureLimitExceeded: If a configured resource limit is exceeded
                while attempting to write the supplied data to the owned
                destination.
        """
        data = bytes(payload)
        attempted = self.size_bytes + len(data)
        if self._max_bytes is not None and attempted > self._max_bytes:
            raise CaptureLimitExceeded(
                self._limit_name,
                self._max_bytes,
                attempted,
            )
        if len(data) >= _COPY_CHUNK_BYTES:
            self.flush()
            for offset in range(0, len(data), _COPY_CHUNK_BYTES):
                self._sink(data[offset : offset + _COPY_CHUNK_BYTES])
        elif data:
            self._buffer.extend(data)
            if len(self._buffer) >= _COPY_CHUNK_BYTES:
                self.flush()
        self._digest.update(data)
        self.size_bytes = attempted

    def flush(self) -> None:
        """
        Flush one bounded batch to avoid a filesystem syscall per token.

        The implementation uses current instance state to flush one bounded
        batch to avoid a filesystem syscall per token.
        """

        if not self._buffer:
            return
        payload = bytes(self._buffer)
        self._sink(payload)
        self._buffer.clear()

    @property
    def hexdigest(self) -> str:
        """
        Return the hexdigest.

        Each access computes the value from ``_digest`` on the current instance;
        the derived view is not stored as independent state.

        Returns:
            The canonical hexdigest.
        """
        return self._digest.hexdigest()


@dataclass(frozen=True)
class _SpoolSnapshot:
    """
    Represent spool snapshot data exchanged by the runtime.

    The immutable record keeps ``record_count``, ``spool_bytes``,
    ``digest_state``, ``truncated_values``, and ``omitted_values`` together so
    consumers observe one spool state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        record_count: Number of record entries represented by the record.
        spool_bytes: Byte count recorded for spool.
        digest_state: Digest state retained as part of the record's public
            state.
        truncated_values: Number of truncated values represented by this record.
        omitted_values: Number of omitted values represented by this record.
    """

    record_count: int = 0
    spool_bytes: int = 0
    digest_state: Any = field(
        default_factory=hashlib.sha256,
        repr=False,
        compare=False,
    )
    truncated_values: int = 0
    omitted_values: int = 0

    @property
    def sha256(self) -> str:
        """
        Return the SHA-256.

        Each access computes the value from ``digest_state`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The canonical SHA-256 text.
        """
        return self.digest_state.hexdigest()


class _SpoolPhase(str, Enum):
    """
    Enumerate the supported spool phase values.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    ACTIVE = "active"
    FINALIZED = "finalized"
    DISCARDED = "discarded"


@dataclass(frozen=True)
class _SpoolState:
    """
    Represent spool state data exchanged by the runtime.

    The immutable record keeps ``phase``, ``snapshot``, and ``candidate``
    together so consumers observe one spool state. Consumers receive the fields
    as one unit instead of assembling partial state.

    Attributes:
        phase: Phase retained as part of the record's public state.
        snapshot: Snapshot retained as part of the record's public state.
        candidate: Candidate retained as part of the record's public state.
    """

    phase: _SpoolPhase = _SpoolPhase.ACTIVE
    snapshot: _SpoolSnapshot = _SpoolSnapshot()
    candidate: Optional[PrivateCaptureCandidate] = None


class RequestResponseCaptureSpool:
    """
    Incrementally persist capture records without exporting storage handles.

    The type coordinates ``create``, ``_create``, ``record_count``,
    ``spool_bytes``, and ``truncated_values`` and retains the state those
    operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        *,
        context: _CaptureContext,
        ownership_token: object,
        owned_file: _OwnedPrivateFile,
        captured_at: str,
        collector_id: str,
        dut_id: str,
        sanitize_text: Optional[Callable[[str], str]] = None,
        sanitize_uri: Optional[Callable[[str], Optional[str]]] = None,
        sensitive_name: Optional[Callable[[str], bool]] = None,
        uri_name: Optional[Callable[[str], bool]] = None,
        sensitive_value_replacement: str = "<redacted>",
        max_string_chars: int = _DEFAULT_MAX_STRING_CHARS,
        max_depth: int = _DEFAULT_MAX_DEPTH,
        max_record_bytes: int = DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_RECORD_BYTES,
        max_artifact_bytes: int = DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_ARTIFACT_BYTES,
        max_records: int = DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_RECORDS,
        _runtime_authorization_token: Optional[object] = None,
        _sanitization_policy_id: Optional[str] = None,
    ) -> None:
        """
        Initialize a ``RequestResponseCaptureSpool`` instance.

        The initializer records ``_context``, ``_envelope_bytes``,
        ``_envelope_prefix``, ``_envelope_suffix``, and ``_file`` for later
        operations and establishes the instance invariants before any public
        method runs. If the function cannot initialize a
        ``RequestResponseCaptureSpool`` instance, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            context: Runtime context carrying state shared across this
                operation.
            ownership_token: Ownership token consumed while the function
                attempts to initialize a ``RequestResponseCaptureSpool``
                instance.
            owned_file: filesystem location used as the owned file for this
                operation.
            captured_at: Text supplied as captured at in the format accepted by
                this function.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            sanitize_text: Optional sanitize text; ``None`` selects the
                function's default behavior.
            sanitize_uri: Validated remote resource identifier used for sanitize
                URI.
            sensitive_name: Stable sensitive name used for lookup and
                operator-facing diagnostics.
            uri_name: Validated remote resource identifier used for URI name.
            sensitive_value_replacement: Public replacement emitted for a
                sensitive structured mapping value.
            max_string_chars: Upper bound enforced for max string chars; the
                consuming boundary rejects or truncates values that exceed it.
            max_depth: Upper bound enforced for max depth; the consuming
                boundary rejects or truncates values that exceed it.
            max_record_bytes: Upper bound enforced for max record bytes; the
                consuming boundary rejects or truncates values that exceed it.
            max_artifact_bytes: Upper bound enforced for max artifact bytes; the
                consuming boundary rejects or truncates values that exceed it.
            max_records: Upper bound enforced for max records; the consuming
                boundary rejects or truncates values that exceed it.
            _runtime_authorization_token: Optional runtime authorization token;
                ``None`` selects the function's default behavior.
            _sanitization_policy_id: Stable sanitization policy identifier used
                to correlate configuration, logs, and results.

        Raises:
            TypeError: If the capture envelope identity values are not strings.
            CaptureLimitExceeded: If per-artifact capture byte limit.
        """
        self._context = context
        self._ownership_token = ownership_token
        self._file = owned_file
        self._sanitize_text = sanitize_text or (lambda value: value)
        self._sanitize_uri = sanitize_uri or (lambda value: value)
        self._sensitive_name = sensitive_name or (lambda _name: False)
        self._uri_name = uri_name or (lambda _name: False)
        if (
            type(sensitive_value_replacement) is not str
            or not sensitive_value_replacement
            or len(sensitive_value_replacement) > 256
        ):
            raise TypeError(
                "Sensitive capture replacement must be a non-empty bounded string"
            )
        self._sensitive_value_replacement = sensitive_value_replacement
        self._max_string_chars = max(1, int(max_string_chars))
        self._max_depth = max(1, int(max_depth))
        self._max_record_bytes = max(1, int(max_record_bytes))
        self._max_artifact_bytes = max(1, int(max_artifact_bytes))
        self._max_records = max(1, int(max_records))
        self._runtime_authorization_token = _runtime_authorization_token
        self._sanitization_policy_id = _sanitization_policy_id
        self._operation_lock = threading.RLock()
        self._lock = threading.RLock()
        self._state = _SpoolState()

        if not all(
            isinstance(value, str) for value in (captured_at, collector_id, dut_id)
        ):
            raise TypeError("Capture envelope identity values must be strings")
        self._envelope_prefix = self._serialize_envelope_prefix(
            captured_at=captured_at,
            collector_id=collector_id,
            dut_id=dut_id,
        )
        self._envelope_suffix = b"]}\n"
        self._envelope_bytes = len(self._envelope_prefix) + len(self._envelope_suffix)
        if self._envelope_bytes > self._max_artifact_bytes:
            raise CaptureLimitExceeded(
                "per-artifact capture byte limit",
                self._max_artifact_bytes,
                self._envelope_bytes,
            )
        self._file.verify(
            expected_size=0,
            expected_digest=self._state.snapshot.sha256,
        )

    @classmethod
    def create(
        cls,
        directory: Path,
        **kwargs: Any,
    ) -> "RequestResponseCaptureSpool":
        """
        Create a standalone auto-closing private capture context.

        After applying local validation, the function forwards ``directory`` and
        ``kwargs`` to ``cls._create`` and preserves its return and exception
        contract. The operation mutates ``kwargs`` in place; ownership of those
        objects remains with the caller. Filesystem effects remain confined to
        the caller-selected paths and the owning resource lifecycle.

        Args:
            directory: filesystem location used as the directory for this
                operation.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A validated ``RequestResponseCaptureSpool`` instance initialized
            from the supplied fields.
        """

        budget = kwargs.pop("concurrent_spool_budget", None)
        if budget is None:
            budget = ConcurrentPrivateSpoolBudget(
                kwargs.pop(
                    "max_concurrent_private_spool_bytes",
                    DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_SPOOL_BYTES,
                )
            )
        physical = kwargs.pop("physical_space_reservation", None)
        if physical is None:
            physical = CapturePhysicalSpaceReservation()
        capacity_observer = kwargs.pop("require_capacity", None)
        failpoint = kwargs.pop("failpoint", None)
        context = _CaptureContext.open(
            directory,
            budget=budget,
            physical=physical,
            capacity_observer=capacity_observer,
            auto_close=True,
            failpoint=failpoint,
        )
        ownership_token: Optional[object] = None
        try:
            ownership_token = context.register_spool()
            return cls._create(
                context,
                ownership_token,
                **kwargs,
            )
        except BaseException as construction_error:
            if ownership_token is not None:
                try:
                    context.unregister_spool(ownership_token)
                except BaseException as cleanup_error:
                    construction_error.add_note(
                        f"Private capture spool-token cleanup failed: {cleanup_error}"
                    )
            try:
                context.maybe_auto_close()
            except BaseException as cleanup_error:
                construction_error.add_note(
                    f"Private capture context cleanup failed: {cleanup_error}"
                )
            if context.registry.failed_count:
                setattr(construction_error, "private_capture_cleanup_context", context)
            raise

    @classmethod
    def _create(
        cls,
        context: _CaptureContext,
        ownership_token: object,
        **kwargs: Any,
    ) -> "RequestResponseCaptureSpool":
        """
        Create the configured resource.

        After applying local validation, the function forwards ``context``,
        ``ownership_token``, and ``kwargs`` to ``cls`` and preserves its return
        and exception contract.

        Args:
            context: Runtime context carrying state shared across this
                operation.
            ownership_token: Ownership token consumed while the function
                attempts to create the configured resource.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A validated ``RequestResponseCaptureSpool`` instance initialized
            from the supplied fields.
        """
        owned_file = context.create_file(_PrivateFileRole.SPOOL)
        try:
            return cls(
                context=context,
                ownership_token=ownership_token,
                owned_file=owned_file,
                **kwargs,
            )
        except BaseException as construction_error:
            try:
                context.registry.cleanup(owned_file.owner_key)
            except BaseException as cleanup_error:
                construction_error.add_note(
                    "Private spool construction cleanup remains owned for retry: "
                    f"{cleanup_error}"
                )
            raise

    @property
    def record_count(self) -> int:
        """
        Return the record count.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric record count.
        """
        with self._lock:
            return self._state.snapshot.record_count

    @property
    def spool_bytes(self) -> int:
        """
        Return the spool bytes.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric spool bytes value.
        """
        with self._lock:
            return self._state.snapshot.spool_bytes

    @property
    def truncated_values(self) -> int:
        """
        Return the truncated values.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric truncated values value.
        """
        with self._lock:
            return self._state.snapshot.truncated_values

    @property
    def omitted_values(self) -> int:
        """
        Return the omitted values.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            The numeric omitted values value.
        """
        with self._lock:
            return self._state.snapshot.omitted_values

    @property
    def finalized_candidate(self) -> Optional[PrivateCaptureCandidate]:
        """
        Return the finalized candidate.

        Each access computes the value from ``_lock`` and ``_state`` on the
        current instance; the derived view is not stored as independent state.

        Returns:
            A ``PrivateCaptureCandidate`` representing finalized candidate, or
            ``None`` when the requested value is unavailable.
        """
        with self._lock:
            return self._state.candidate

    @property
    def has_pending_candidate_cleanup(self) -> bool:
        """
        Return whether ``the current value`` has pending candidate cleanup.

        Each access computes the value from ``_context`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            Whether ``the current value`` has pending candidate cleanup.
        """
        return self._context.registry.failed_count > 0

    def retry_failed_candidate_cleanup(self) -> None:
        """
        Retry failed candidate cleanup.

        The implementation uses current instance state to retry failed candidate
        cleanup.
        """
        self._context.retry_cleanups()

    def _active_snapshot(self) -> _SpoolSnapshot:
        """
        Return the active snapshot.

        The implementation uses current instance state to produce the active
        snapshot. If the function cannot produce the active snapshot, its
        exception reaches the caller instead of being converted into a
        successful result.

        Returns:
            A ``_SpoolSnapshot`` representing active snapshot.

        Raises:
            RuntimeError: If redfish request capture spool is discarded; or
                redfish request capture is already finalized.
        """
        with self._lock:
            state = self._state
        if state.phase is _SpoolPhase.DISCARDED:
            raise RuntimeError("Redfish request capture spool is discarded")
        if state.phase is _SpoolPhase.FINALIZED:
            raise RuntimeError("Redfish request capture is already finalized")
        return state.snapshot

    def _assert_spool_integrity(
        self,
        snapshot: _SpoolSnapshot,
        *,
        verify_digest: bool,
    ) -> os.stat_result:
        """
        Verify spool integrity.

        After applying local validation, the function forwards ``snapshot`` and
        ``verify_digest`` to ``self._file.verify`` and preserves its return and
        exception contract. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path.

        Args:
            snapshot: Snapshot object whose ``sha256`` and ``spool_bytes`` state
                is read while performing spool integrity.
            verify_digest: Whether verify digest is enabled or required for this
                operation.

        Returns:
            A ``stat_result`` representing assert spool integrity.
        """
        return self._file.verify(
            expected_size=snapshot.spool_bytes,
            expected_digest=(snapshot.sha256 if verify_digest else None),
        )

    def append(
        self,
        *,
        timestamp: str,
        request: Any,
        response: Any = None,
        metadata: Any = None,
    ) -> None:
        """
        Stage and atomically account one complete JSONL record.

        The implementation uses ``timestamp``, ``request``, ``response``, and
        ``metadata`` to stage and atomically account one complete JSONL record.

        Args:
            timestamp: Text supplied as timestamp in the format accepted by this
                function.
            request: Transport request governed by the configured authentication
                and trust policy.
            response: Transport response governed by the configured
                authentication and trust policy.
            metadata: Optional metadata; ``None`` selects the function's default
                behavior.
        """

        with self._operation_lock:
            self._context.assert_ready()
            self._active_snapshot()
            staged = self._context.create_file(_PrivateFileRole.STAGED_RECORD)
            try:
                self._append_with_stage(
                    staged,
                    timestamp=timestamp,
                    request=request,
                    response=response,
                    metadata=metadata,
                )
            except BaseException as operation_error:
                try:
                    self._context.registry.cleanup(staged.owner_key)
                except BaseException as cleanup_error:
                    operation_error.add_note(
                        "Staged record cleanup remains owned for retry: "
                        f"{cleanup_error}"
                    )
                raise
            else:
                self._context.registry.cleanup(staged.owner_key)

    def _append_with_stage(
        self,
        staged: _OwnedPrivateFile,
        *,
        timestamp: str,
        request: Any,
        response: Any,
        metadata: Any,
    ) -> None:
        """
        Append with stage.

        The implementation uses ``staged``, ``timestamp``, ``request``,
        ``response``, and ``metadata`` to append with stage. It updates
        ``_state`` on the instance as part of that state transition. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle. If the function cannot append with stage, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            staged: Staged object whose ``append``, ``fsync``, and ``verify``
                state is read while performing append with stage.
            timestamp: Text supplied as timestamp in the format accepted by this
                function.
            request: Transport request governed by the configured authentication
                and trust policy.
            response: Transport response governed by the configured
                authentication and trust policy.
            metadata: Metadata consumed while the function attempts to append
                with stage.

        Raises:
            CaptureLimitExceeded: If per-artifact capture record limit; or
                per-artifact capture byte limit.
            CaptureFilesystemBoundaryError: If staged capture record digest
                changed during append.
        """
        entry = {"timestamp": timestamp, "request": request}
        if response is not None:
            entry["response"] = response
        if metadata is not None:
            entry["metadata"] = metadata

        writer = _HashingWriter(
            staged.append,
            max_bytes=self._max_record_bytes,
            limit_name="per-record capture byte limit",
        )
        self._write_value(writer, entry, self._max_depth, set())
        writer.write(b"\n")
        writer.flush()
        staged.fsync()
        staged.verify(
            expected_size=writer.size_bytes,
            expected_digest=writer.hexdigest,
        )

        snapshot = self._active_snapshot()
        # The spool is an anonymous, registry-owned descriptor. Re-reading its
        # entire committed prefix before and after every append makes an N-record
        # capture O(N^2). Keep the append boundary O(1) for the committed prefix,
        # then verify the staged and newly durable record bytes exactly. A full
        # prefix digest remains mandatory before finalization and publication.
        self._assert_spool_integrity(snapshot, verify_digest=False)
        attempted_records = snapshot.record_count + 1
        if attempted_records > self._max_records:
            raise CaptureLimitExceeded(
                "per-artifact capture record limit",
                self._max_records,
                attempted_records,
                unit="records",
            )
        attempted_spool_bytes = snapshot.spool_bytes + writer.size_bytes
        attempted_artifact_bytes = (
            self._envelope_bytes
            + attempted_spool_bytes
            - (1 if attempted_records else 0)
        )
        if attempted_artifact_bytes > self._max_artifact_bytes:
            raise CaptureLimitExceeded(
                "per-artifact capture byte limit",
                self._max_artifact_bytes,
                attempted_artifact_bytes,
            )

        next_snapshot: Optional[_SpoolSnapshot] = None
        try:
            copied_digest = hashlib.sha256()
            self._copy_staged_record(
                staged,
                destination_offset=snapshot.spool_bytes,
                expected_bytes=writer.size_bytes,
                digest=copied_digest,
            )
            if copied_digest.hexdigest() != writer.hexdigest:
                raise CaptureFilesystemBoundaryError(
                    "Staged capture record digest changed during append"
                )
            self._context.hit("spool.after_record_copy")
            self._file.fsync()
            self._file.verify(
                expected_size=attempted_spool_bytes,
                expected_digest=None,
            )
            next_digest = snapshot.digest_state.copy()
            self._verify_appended_record(
                destination_offset=snapshot.spool_bytes,
                expected_bytes=writer.size_bytes,
                expected_digest=writer.hexdigest,
                digest=next_digest,
            )
            next_snapshot = _SpoolSnapshot(
                record_count=attempted_records,
                spool_bytes=attempted_spool_bytes,
                digest_state=next_digest,
                truncated_values=(snapshot.truncated_values + writer.truncated_values),
                omitted_values=(snapshot.omitted_values + writer.omitted_values),
            )
            with self._lock:
                self._state = replace(self._state, snapshot=next_snapshot)
        except BaseException as append_error:
            with self._lock:
                state_committed = (
                    next_snapshot is not None and self._state.snapshot is next_snapshot
                )
            if not state_committed:
                try:
                    self._file.truncate(snapshot.spool_bytes)
                except BaseException as rollback_error:
                    append_error.add_note(
                        f"Private capture append rollback failed: {rollback_error}"
                    )
            raise
        self._context.hit("spool.after_record_commit")

    def _copy_staged_record(
        self,
        source: _OwnedPrivateFile,
        *,
        destination_offset: int,
        expected_bytes: int,
        digest: Any,
    ) -> None:
        """
        Copy staged record.

        The implementation uses ``source``, ``destination_offset``,
        ``expected_bytes``, and ``digest`` to copy staged record. The operation
        mutates ``digest`` in place; ownership of those objects remains with the
        caller. If the function cannot copy staged record, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            source: Source object whose ``read_at`` state is read while
                performing copy staged record.
            destination_offset: Numeric destination offset used by the
                operation's bounded accounting.
            expected_bytes: Numeric expected bytes used while the operation
                performs bounded accounting.
            digest: Digest object whose ``update`` state is read while
                performing copy staged record.

        Raises:
            OSError: If staged capture record is incomplete; or staged capture
                record exceeded its accounted size.
        """
        remaining = max(0, int(expected_bytes))
        source_offset = 0
        while remaining:
            chunk = source.read_at(min(_COPY_CHUNK_BYTES, remaining), source_offset)
            if not chunk:
                raise OSError("Staged capture record is incomplete")
            self._file.write_at(chunk, destination_offset + source_offset)
            digest.update(chunk)
            source_offset += len(chunk)
            remaining -= len(chunk)
        if source.read_at(1, expected_bytes):
            raise OSError("Staged capture record exceeded its accounted size")

    def _verify_appended_record(
        self,
        *,
        destination_offset: int,
        expected_bytes: int,
        expected_digest: str,
        digest: Any,
    ) -> None:
        """
        Verify only one newly durable record and extend the rolling digest.

        The implementation uses ``destination_offset``, ``expected_bytes``,
        ``expected_digest``, and ``digest`` to verify only one newly durable
        record and extend the rolling digest. Every required invariant is
        checked before a successful value is returned; invalid input follows the
        function's explicit exception path. The operation mutates ``digest`` in
        place; ownership of those objects remains with the caller.

        Args:
            destination_offset: Numeric destination offset used by the
                operation's bounded accounting.
            expected_bytes: Numeric expected bytes used while the operation
                performs bounded accounting.
            expected_digest: Text supplied as expected digest in the format
                accepted by this function.
            digest: Digest object whose ``update`` state is read while
                performing only one newly durable record and extend the rolling
                digest.

        Raises:
            CaptureFilesystemBoundaryError: If appended capture record was
                truncated during verification; or appended capture record digest
                changed during verification.
        """

        record_digest = hashlib.sha256()
        remaining = max(0, int(expected_bytes))
        source_offset = 0
        while remaining:
            chunk = self._file.read_at(
                min(_COPY_CHUNK_BYTES, remaining),
                destination_offset + source_offset,
            )
            if not chunk:
                raise CaptureFilesystemBoundaryError(
                    "Appended capture record was truncated during verification"
                )
            record_digest.update(chunk)
            digest.update(chunk)
            source_offset += len(chunk)
            remaining -= len(chunk)
        if record_digest.hexdigest() != expected_digest:
            raise CaptureFilesystemBoundaryError(
                "Appended capture record digest changed during verification"
            )

    def finalize_private_candidate(self) -> PrivateCaptureCandidate:
        """
        Finalize an anonymous candidate after complete size/digest verification.

        The implementation uses current instance state to finalize an anonymous
        candidate after complete size/digest verification. It updates ``_state``
        on the instance as part of that state transition. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle. If the function cannot finalize an anonymous candidate after
        complete size/digest verification, its exception reaches the caller
        instead of being converted into a successful result.

        Returns:
            The validated ``candidate``.

        Raises:
            CaptureFilesystemBoundaryError: If private capture candidate size
                disagrees with accounting.
        """

        with self._operation_lock:
            self._context.assert_ready()
            snapshot = self._active_snapshot()
            self._assert_spool_integrity(snapshot, verify_digest=True)
            candidate_size = (
                self._envelope_bytes
                + snapshot.spool_bytes
                - (1 if snapshot.record_count else 0)
            )
            candidate_file = self._context.create_file(_PrivateFileRole.CANDIDATE)
            candidate: Optional[PrivateCaptureCandidate] = None
            try:
                writer = _HashingWriter(
                    candidate_file.append,
                    max_bytes=self._max_artifact_bytes,
                    limit_name="per-artifact capture byte limit",
                )
                writer.write(self._envelope_prefix)
                self._copy_jsonl_records(writer, snapshot)
                writer.write(self._envelope_suffix)
                writer.flush()
                candidate_file.fsync()
                if writer.size_bytes != candidate_size:
                    raise CaptureFilesystemBoundaryError(
                        "Private capture candidate size disagrees with accounting"
                    )
                candidate_file.verify(
                    expected_size=writer.size_bytes,
                    expected_digest=writer.hexdigest,
                )
                summary = CaptureCandidateSummary(
                    record_count=snapshot.record_count,
                    size_bytes=writer.size_bytes,
                    sha256=writer.hexdigest,
                    truncated_values=snapshot.truncated_values,
                    omitted_values=snapshot.omitted_values,
                    sanitization_policy_id=(self._sanitization_policy_id),
                    _runtime_authorization_token=(self._runtime_authorization_token),
                )
                candidate = PrivateCaptureCandidate(
                    context=self._context,
                    owned_file=candidate_file,
                    summary=summary,
                )
                with self._lock:
                    self._state = _SpoolState(
                        phase=_SpoolPhase.FINALIZED,
                        snapshot=snapshot,
                        candidate=candidate,
                    )
            except BaseException as finalization_error:
                with self._lock:
                    state_committed = (
                        candidate is not None and self._state.candidate is candidate
                    )
                if not state_committed:
                    try:
                        self._context.registry.cleanup(candidate_file.owner_key)
                    except BaseException as cleanup_error:
                        finalization_error.add_note(
                            "Candidate cleanup remains owned for retry: "
                            f"{cleanup_error}"
                        )
                raise
            self._context.hit("spool.after_candidate_commit")
            return candidate

    def discard(self) -> None:
        """
        Idempotently release spool ownership and its live-spool token.

        The implementation uses current instance state to idempotently release
        spool ownership and its live-spool token. It updates ``_state`` on the
        instance as part of that state transition. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        If the function cannot idempotently release spool ownership and its
        live-spool token, its exception reaches the caller instead of being
        converted into a successful result.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to idempotently release spool ownership and its
                live-spool token.
        """

        with self._operation_lock:
            with self._lock:
                state = self._state
            if state.phase is _SpoolPhase.DISCARDED:
                self._context.unregister_spool(self._ownership_token)
                self._context.maybe_auto_close()
                return

            integrity_error: Optional[CaptureFilesystemBoundaryError] = None
            registered = self._context.registry.get(self._file.owner_key)
            if registered is not None and not registered.cleanup_complete:
                try:
                    self._assert_spool_integrity(
                        state.snapshot,
                        verify_digest=True,
                    )
                except CaptureFilesystemBoundaryError as error:
                    integrity_error = error
            if registered is not None:
                self._context.registry.cleanup(self._file.owner_key)
            with self._lock:
                self._state = replace(self._state, phase=_SpoolPhase.DISCARDED)
            self._context.unregister_spool(self._ownership_token)
            self._context.maybe_auto_close()
            if integrity_error is not None:
                raise integrity_error

    def _serialize_envelope_prefix(
        self,
        *,
        captured_at: str,
        collector_id: str,
        dut_id: str,
    ) -> bytes:
        """
        Serialize immutable envelope fields once for exact limit accounting.

        After applying local validation, the function forwards ``captured_at``,
        ``collector_id``, and ``dut_id`` to ``bytes`` and preserves its return
        and exception contract. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            captured_at: Text supplied as captured at in the format accepted by
                this function.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The bounded envelope prefix bytes.
        """

        payload = bytearray()
        writer = _HashingWriter(payload.extend)
        writer.write(b"{")
        self._write_key_value(writer, "captured_at", captured_at, first=True)
        self._write_key_value(writer, "collector_id", collector_id)
        self._write_key_value(writer, "dut_id", dut_id)
        writer.write(b',"requests":[')
        writer.flush()
        return bytes(payload)

    def _copy_jsonl_records(
        self,
        writer: _HashingWriter,
        snapshot: _SpoolSnapshot,
    ) -> None:
        """
        Copy exact JSONL records without returning a source capability.

        The implementation uses ``writer`` and ``snapshot`` to copy exact JSONL
        records without returning a source capability. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        If the function cannot copy exact JSONL records without returning a
        source capability, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            writer: Writer object whose ``write`` state is read while performing
                copy exact JSONL records without returning a source capability.
            snapshot: Snapshot object whose ``record_count``, ``sha256``, and
                ``spool_bytes`` state is read while performing copy exact JSONL
                records without returning a source capability.

        Raises:
            CaptureFilesystemBoundaryError: If private capture record count
                disagrees with an empty spool; committed private capture spool
                is incomplete; private capture spool contains an empty record;
                or committed private capture record boundary is incomplete; or
                another input invariant is violated.
        """

        committed_bytes = snapshot.spool_bytes
        self._assert_spool_integrity(snapshot, verify_digest=True)
        if committed_bytes <= 0:
            if snapshot.record_count != 0:
                raise CaptureFilesystemBoundaryError(
                    "Private capture record count disagrees with an empty spool"
                )
            return

        first_record = True
        at_record_start = True
        observed_records = 0
        digest = hashlib.sha256()
        source_offset = 0
        while source_offset < committed_bytes:
            chunk = self._file.read_at(
                min(_COPY_CHUNK_BYTES, committed_bytes - source_offset),
                source_offset,
            )
            if not chunk:
                raise CaptureFilesystemBoundaryError(
                    "Committed private capture spool is incomplete"
                )
            source_offset += len(chunk)
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                newline = chunk.find(b"\n", offset)
                end = len(chunk) if newline < 0 else newline
                segment = chunk[offset:end]
                if segment:
                    if at_record_start:
                        if not first_record:
                            writer.write(b",")
                        first_record = False
                        at_record_start = False
                    writer.write(segment)
                if newline < 0:
                    break
                if at_record_start:
                    raise CaptureFilesystemBoundaryError(
                        "Private capture spool contains an empty record"
                    )
                observed_records += 1
                at_record_start = True
                offset = newline + 1
        if not at_record_start:
            raise CaptureFilesystemBoundaryError(
                "Committed private capture record boundary is incomplete"
            )
        if observed_records != snapshot.record_count:
            raise CaptureFilesystemBoundaryError(
                "Private capture spool record count changed outside accounting"
            )
        if digest.hexdigest() != snapshot.sha256:
            raise CaptureFilesystemBoundaryError(
                "Private capture spool digest changed outside accounting"
            )
        self._assert_spool_integrity(snapshot, verify_digest=True)

    def _write_key_value(
        self,
        writer: _HashingWriter,
        key: str,
        value: Any,
        *,
        first: bool = False,
    ) -> None:
        """
        Write key value.

        The implementation uses ``writer``, ``key``, ``value``, and ``first`` to
        write key value. Success is reported only after the owning output
        boundary has completed its required write or publication step.

        Args:
            writer: Writer object whose ``write`` state is read while performing
                key value.
            key: Stable key used for lookup and operator-facing diagnostics.
            value: Value evaluated while performing key value.
            first: Whether first is enabled or required for this operation.
        """
        if not first:
            writer.write(b",")
        self._write_text(writer, key)
        writer.write(b":")
        self._write_value(writer, value, self._max_depth, set())

    def _write_value(
        self,
        writer: _HashingWriter,
        value: Any,
        depth: int,
        ancestors: set[int],
    ) -> None:
        """
        Write value.

        Three bits per permitted character is deliberately conservative (a
        decimal digit needs about 3.32 bits). It guarantees that the conversion
        below cannot materialize a scalar larger than the configured
        bounded-string envelope.

        Args:
            writer: Writer object whose ``omitted_values``,
                ``truncated_values``, and ``write`` state is read while
                performing value.
            value: Entries supplied as ``value`` and processed in
                caller-provided order.
            depth: Numeric depth used while the operation performs bounded
                accounting.
            ancestors: Entries supplied as ``ancestors`` without transferring
                container ownership.
        """
        value_type = type(value)

        if value is None or value_type is bool:
            writer.write(
                json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            )
            return

        if value_type is int:
            bit_length = int.bit_length(value)
            # Three bits per permitted character is deliberately conservative
            # (a decimal digit needs about 3.32 bits). It guarantees that the
            # conversion below cannot materialize a scalar larger than the
            # configured bounded-string envelope.
            if bit_length > self._max_string_chars * 3:
                writer.omitted_values += 1
                self._write_internal_object(
                    writer,
                    type="integer",
                    bit_length=bit_length,
                    content="omitted",
                    reason="integer exceeded bounded diagnostic limit",
                )
            else:
                writer.write(
                    json.dumps(
                        value,
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ).encode("ascii")
                )
            return

        if value_type is float:
            if math.isfinite(value):
                writer.write(json.dumps(value, allow_nan=False).encode("ascii"))
            else:
                self._write_internal_object(
                    writer,
                    type="float",
                    value=str(value),
                    content="omitted",
                    reason="non-finite value is not valid JSON",
                )
            return

        if value_type is str:
            self._write_bounded_text_value(writer, value)
            return

        if value_type in {bytes, bytearray, memoryview}:
            raw = memoryview(value)
            self._write_internal_object(
                writer,
                type="bytes",
                length=raw.nbytes,
                sha256=hashlib.sha256(raw).hexdigest(),
                note="binary content omitted",
            )
            return

        if value_type is StreamedRedfishBody:
            if depth <= 0:
                self._write_omission(writer, "custom_object", 1)
                return
            # Call the trusted implementation directly. Arbitrary objects are
            # never allowed to run a capture_metadata extension hook.
            self._write_value(
                writer,
                StreamedRedfishBody.capture_metadata(value),
                depth - 1,
                ancestors,
            )
            return

        if value_type is dict:
            if depth <= 0:
                self._write_omission(writer, "object", dict.__len__(value))
                return
            identity = id(value)
            if identity in ancestors:
                self._write_omission(writer, "cyclic_object", dict.__len__(value))
                return
            ancestors.add(identity)
            try:
                writer.write(b"{")
                first = True
                for key_index, (raw_key, item) in enumerate(dict.items(value)):
                    if not first:
                        writer.write(b",")
                    first = False
                    unsupported_key = type(raw_key) is not str
                    key = (
                        f"<unsupported-field-name-{key_index}>"
                        if unsupported_key
                        else raw_key
                    )
                    oversized_key = len(key) > self._max_string_chars
                    self._write_text(writer, self._bounded_key_text(key))
                    writer.write(b":")
                    if unsupported_key:
                        writer.omitted_values += 1
                        self._write_text(
                            writer, "<value omitted for unsupported field name>"
                        )
                    elif oversized_key:
                        writer.truncated_values += 1
                        writer.omitted_values += 1
                        self._write_text(
                            writer, "<value omitted for oversized field name>"
                        )
                    elif self._uri_name(key) and type(item) is str:
                        self._write_bounded_uri_value(writer, item)
                    elif self._sensitive_name(key):
                        self._write_text(writer, self._sensitive_value_replacement)
                    elif self._uri_name(key):
                        # Redfish reuses names such as ``Location`` for typed
                        # objects. Recursing preserves the governed response
                        # shape while applying the same bounds and sanitizers to
                        # every nested key and string.
                        self._write_value(writer, item, depth - 1, ancestors)
                    else:
                        self._write_value(writer, item, depth - 1, ancestors)
                writer.write(b"}")
            finally:
                ancestors.remove(identity)
            return

        if value_type in {list, tuple}:
            if depth <= 0:
                item_count = (
                    list.__len__(value) if value_type is list else tuple.__len__(value)
                )
                self._write_omission(writer, "array", item_count)
                return
            identity = id(value)
            if identity in ancestors:
                item_count = (
                    list.__len__(value) if value_type is list else tuple.__len__(value)
                )
                self._write_omission(writer, "cyclic_array", item_count)
                return
            ancestors.add(identity)
            try:
                writer.write(b"[")
                iterator = (
                    list.__iter__(value)
                    if value_type is list
                    else tuple.__iter__(value)
                )
                for index, item in enumerate(iterator):
                    if index:
                        writer.write(b",")
                    self._write_value(writer, item, depth - 1, ancestors)
                writer.write(b"]")
            finally:
                ancestors.remove(identity)
            return

        # Do not invoke arbitrary __str__ implementations: they are unbounded
        # extension code and can block capture teardown or expose host details.
        writer.omitted_values += 1
        self._write_internal_object(
            writer,
            type="unsupported_object",
            content="omitted",
            reason="unsupported object extension omitted",
        )

    def _write_bounded_text_value(self, writer: _HashingWriter, value: str) -> None:
        """
        Write bounded text value.

        The implementation uses ``writer`` and ``value`` to write bounded text
        value. Success is reported only after the owning output boundary has
        completed its required write or publication step.

        Args:
            writer: Writer object whose ``truncated_values`` state is read while
                performing bounded text value.
            value: Text supplied as value in the format accepted by this
                function.
        """
        if len(value) <= self._max_string_chars:
            self._write_text(
                writer,
                _redact_incomplete_private_key(self._sanitize_text(value)),
            )
            return

        digest = hashlib.sha256()
        for offset in range(0, len(value), _COPY_CHUNK_BYTES):
            digest.update(
                value[offset : offset + _COPY_CHUNK_BYTES].encode(
                    "utf-8", errors="surrogatepass"
                )
            )
        writer.truncated_values += 1
        self._write_internal_object(
            writer,
            type="string",
            length_chars=len(value),
            sha256=digest.hexdigest(),
            preview=_bounded_text_preview(
                self._sanitize_text,
                value,
                max_chars=_STRING_PREVIEW_CHARS,
            ),
            truncated=True,
            note="capture string exceeded bounded diagnostic limit",
        )

    def _write_bounded_uri_value(self, writer: _HashingWriter, value: str) -> None:
        """
        Sanitize structured URI fields without materializing huge values.

        The implementation uses ``writer`` and ``value`` to sanitize structured
        URI fields without materializing huge values.

        Args:
            writer: Writer object whose ``truncated_values`` state is read while
                performing sanitize structured URI fields without materializing
                huge values.
            value: Text supplied as value in the format accepted by this
                function.
        """

        if len(value) <= self._max_string_chars:
            sanitized = self._sanitize_uri(value) or "<redacted-uri>"
            self._write_text(writer, sanitized)
            return

        digest = hashlib.sha256()
        for offset in range(0, len(value), _COPY_CHUNK_BYTES):
            digest.update(
                value[offset : offset + _COPY_CHUNK_BYTES].encode(
                    "utf-8", errors="surrogatepass"
                )
            )
        writer.truncated_values += 1
        preview = _bounded_uri_preview(
            self._sanitize_uri,
            value,
            max_chars=_STRING_PREVIEW_CHARS,
        )
        self._write_internal_object(
            writer,
            type="uri",
            length_chars=len(value),
            sha256=digest.hexdigest(),
            preview=preview or "<redacted-uri>",
            truncated=True,
            note="capture URI exceeded bounded diagnostic limit",
        )

    def _bounded_key_text(self, value: str) -> str:
        """
        Return the bounded key text.

        The implementation uses ``value`` to produce the bounded key text.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The canonical bounded key text.
        """
        if len(value) <= self._max_string_chars:
            return _redact_incomplete_private_key(self._sanitize_text(value))

        digest = hashlib.sha256()
        for offset in range(0, len(value), _COPY_CHUNK_BYTES):
            digest.update(
                value[offset : offset + _COPY_CHUNK_BYTES].encode(
                    "utf-8", errors="surrogatepass"
                )
            )
        preview = _bounded_text_preview(
            self._sanitize_text,
            value,
            max_chars=_STRING_PREVIEW_CHARS,
        )
        return (
            f"{preview}...<truncated-key chars={len(value)} "
            f"sha256={digest.hexdigest()}>"
        )

    def _write_omission(
        self, writer: _HashingWriter, value_type: str, item_count: int
    ) -> None:
        """
        Write omission.

        The implementation uses ``writer``, ``value_type``, and ``item_count``
        to write omission. Success is reported only after the owning output
        boundary has completed its required write or publication step.

        Args:
            writer: Writer object whose ``omitted_values`` state is read while
                performing omission.
            value_type: Text supplied as value type in the format accepted by
                this function.
            item_count: Numeric item count used by the operation's bounded
                accounting.
        """
        writer.omitted_values += 1
        self._write_internal_object(
            writer,
            type=value_type,
            item_count=item_count,
            content="omitted",
            reason="capture nesting limit exceeded",
        )

    @staticmethod
    def _write_internal_object(writer: _HashingWriter, **values: Any) -> None:
        """
        Write small, implementation-owned metadata without applying limits again.

        The implementation uses ``writer`` and ``values`` to write small,
        implementation-owned metadata without applying limits again. Success is
        reported only after the owning output boundary has completed its
        required write or publication step.

        Args:
            writer: Writer object whose ``write`` state is read while performing
                small, implementation-owned metadata without applying limits
                again.
            values: Additional named values forwarded without changing their
                keys.
        """

        writer.write(
            json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        )

    @staticmethod
    def _write_text(writer: _HashingWriter, value: str) -> None:
        # ASCII escaping keeps lone surrogate code points emitted by unusual
        # firmware payloads valid and round-trippable in strict JSON.
        """
        Write text.

        The implementation uses ``writer`` and ``value`` to write text. Success
        is reported only after the owning output boundary has completed its
        required write or publication step.

        Args:
            writer: Writer object whose ``write`` state is read while performing
                text.
            value: Text supplied as value in the format accepted by this
                function.
        """
        writer.write(json.dumps(value, ensure_ascii=True).encode("ascii"))
