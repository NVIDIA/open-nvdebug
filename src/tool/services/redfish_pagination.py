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
Pure policy helpers for Redfish collection pagination.

The Redfish service owns transport and artifact persistence. This module owns
the deterministic, side-effect-free decisions used while walking a collection:
entry identity, timestamp ordering, the initial-snapshot boundary, and page/
next-link progression.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional, Tuple
from urllib.parse import unquote, urlsplit

_DECIMAL_OFFSET_PATTERN = re.compile(r"[0-9]+\Z")
_MAX_PAGINATION_NEXT_LINK_CHARS = 8192

DEFAULT_MAX_PAGINATION_PAGES = 4096


class PaginationNextLinkMode(str, Enum):
    """
    Facade path that supplied a pagination response's next link.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    SUCCESS = "success"
    SALVAGED_502 = "salvaged_502"
    FAILED_RESPONSE = "failed_response"


class PaginationStopReason(str, Enum):
    """
    Terminal reasons owned by page and next-link progression policy.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    END_OF_COLLECTION = "end_of_collection"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    MAX_PAGES = "max_pages"
    REPEATED_NEXT_LINK = "repeated_next_link"
    REQUEST_FAILED = "request_failed"
    SNAPSHOT_BOUNDARY = "snapshot_boundary"
    SNAPSHOT_OFFSET_GAP = "snapshot_offset_gap"
    SNAPSHOT_OFFSET_NON_PROGRESS = "snapshot_offset_non_progress"
    SNAPSHOT_OFFSET_OVERLAP = "snapshot_offset_overlap"
    SNAPSHOT_OFFSET_UNVERIFIABLE = "snapshot_offset_unverifiable"
    SNAPSHOT_MEMBERS_INVALID = "snapshot_members_invalid"
    SNAPSHOT_MEMBERS_MISSING = "snapshot_members_missing"
    SNAPSHOT_INITIAL_RESPONSE_INVALID = "snapshot_initial_response_invalid"
    SNAPSHOT_PAGE_COUNT_INVALID = "snapshot_page_count_invalid"
    SNAPSHOT_PAGE_COUNT_MISSING = "snapshot_page_count_missing"
    SNAPSHOT_WATERMARK_INVALID = "snapshot_watermark_invalid"
    SNAPSHOT_WATERMARK_MISSING = "snapshot_watermark_missing"
    SUSPICIOUS_NEXT_LINK = "suspicious_next_link"


@dataclass(frozen=True)
class PaginationPageState:
    """
    Immutable state for selecting the next Redfish page request.

    The immutable record keeps ``current_uri``, ``current_offset``,
    ``page_count``, ``repeated_next_link_count``, ``seen_next_links``, and
    ``stop_reason`` together so consumers observe one pagination page state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        current_uri: Canonical text used as current URI.
        current_offset: Numeric current offset retained by this record.
        page_count: Number of page entries represented by the record.
        repeated_next_link_count: Number of repeated next link entries
            represented by the record.
        seen_next_links: Canonical links already visited by this walk.
        stop_reason: Stop reason retained as part of the record's public state.
    """

    current_uri: Optional[str]
    current_offset: Optional[int] = None
    page_count: int = 0
    repeated_next_link_count: int = 0
    seen_next_links: frozenset[str] = frozenset()
    stop_reason: Optional[PaginationStopReason] = None

    @property
    def can_request(self) -> bool:
        """
        Return whether the facade should issue a request for this state.

        Each access computes the value from ``current_uri`` and ``stop_reason``
        on the current instance; the derived view is not stored as independent
        state.

        Returns:
            Whether the facade should issue a request for this state.
        """
        return bool(self.current_uri and self.stop_reason is None)


def begin_pagination_page(
    state: PaginationPageState,
    *,
    retrying_current_page: bool,
    max_pages: Optional[int],
) -> PaginationPageState:
    """
    Return the state for one loop iteration without issuing any I/O.

    Every transport attempt for the current URI retains its logical page number.
    The facade sets ``retrying_current_page`` for both explicit retry signals
    and generic failed-response retries so attempts do not consume ``max_pages``
    or inflate page artifact numbering.

    Args:
        state: State object whose ``can_request`` and ``page_count`` state is
            read while performing state for one loop iteration without issuing
            any I/O.
        retrying_current_page: Whether retrying current page is enabled or
            required for this operation.
        max_pages: Upper bound enforced for max pages; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        A ``PaginationPageState`` representing begin pagination page.
    """
    if not state.can_request:
        return state
    if max_pages is not None and state.page_count >= max_pages:
        return replace(
            state,
            current_uri=None,
            stop_reason=PaginationStopReason.MAX_PAGES,
        )
    if retrying_current_page:
        return state
    return replace(state, page_count=state.page_count + 1)


def progress_pagination_next_link(
    state: PaginationPageState,
    next_link: Any,
    *,
    mode: PaginationNextLinkMode,
    snapshot_end_offset: Optional[int],
    max_repeated_next_links: int,
    expected_host: Optional[str],
    uri_validator: Callable[..., bool],
    enforce_snapshot_continuity: bool = False,
    allow_forward_offset_gaps: bool = False,
    observed_rows: Optional[int] = None,
) -> PaginationPageState:
    """
    Return the next immutable state for a response-advertised link.

    Successful and salvaged-502 pages are bounded by the initial collection
    snapshot. Failed responses retain the facade's legacy behavior unless the
    caller explicitly enables initial-snapshot continuity: after retries are
    exhausted, an advertised link may advance to another page, and a missing
    link terminates with ``request_failed`` rather than ``end_of_collection``.

    Args:
        state: State object whose ``current_offset``, ``current_uri``, and
            ``repeated_next_link_count`` state is read while performing next
            immutable state for a response-advertised link.
        next_link: Next link consumed while the function attempts to produce the
            next immutable state for a response-advertised link.
        mode: Mode consumed while the function attempts to produce the next
            immutable state for a response-advertised link.
        snapshot_end_offset: Numeric snapshot end offset used by the operation's
            bounded accounting.
        max_repeated_next_links: Upper bound enforced for max repeated next
            links; the consuming boundary rejects or truncates values that
            exceed it.
        expected_host: Text supplied as expected host in the format accepted by
            this function.
        uri_validator: Validated remote resource identifier used for URI
            validator.
        enforce_snapshot_continuity: Whether enforce snapshot continuity is
            enabled or required for this operation.
        allow_forward_offset_gaps: Whether a validated, strictly forward
            server cursor may advance beyond the number of returned rows.
        observed_rows: Optional observed rows; ``None`` selects the function's
            default behavior.

    Returns:
        A ``PaginationPageState`` representing progress pagination next link.
    """
    if not next_link:
        stop_reason = (
            PaginationStopReason.REQUEST_FAILED
            if mode is PaginationNextLinkMode.FAILED_RESPONSE
            else PaginationStopReason.END_OF_COLLECTION
        )
        return replace(state, current_uri=None, stop_reason=stop_reason)

    next_offset = None
    if enforce_snapshot_continuity:
        continuity_stop_reason = initial_snapshot_next_link_stop_reason(
            current_offset=state.current_offset,
            next_link=next_link,
            observed_rows=observed_rows,
            allow_forward_offset_gaps=allow_forward_offset_gaps,
        )
        if continuity_stop_reason is not None:
            return replace(
                state,
                current_uri=None,
                stop_reason=continuity_stop_reason,
            )
        next_offset = pagination_skip_offset(next_link)
    else:
        skip_values = _pagination_skip_query_values(next_link)
        if skip_values is None or (
            skip_values and _pagination_skip_offset_from_values(skip_values) is None
        ):
            return replace(
                state,
                current_uri=None,
                stop_reason=PaginationStopReason.SUSPICIOUS_NEXT_LINK,
            )

    if (
        mode is not PaginationNextLinkMode.FAILED_RESPONSE
        and next_link_reaches_snapshot_end(next_link, snapshot_end_offset)
    ):
        return replace(
            state,
            current_uri=None,
            stop_reason=PaginationStopReason.SNAPSHOT_BOUNDARY,
        )

    repeated_next_link_count = (
        state.repeated_next_link_count + 1 if next_link == state.current_uri else 0
    )
    if (
        next_link == state.current_uri
        and repeated_next_link_count >= max_repeated_next_links
    ):
        return replace(
            state,
            current_uri=None,
            repeated_next_link_count=repeated_next_link_count,
            stop_reason=PaginationStopReason.REPEATED_NEXT_LINK,
        )

    if not uri_validator(next_link, expected_host=expected_host):
        return replace(
            state,
            current_uri=None,
            repeated_next_link_count=repeated_next_link_count,
            stop_reason=PaginationStopReason.SUSPICIOUS_NEXT_LINK,
        )

    def canonical_link(value: Any) -> str:
        """
        Return a stable cycle-detection key for one validated next link.

        Scheme and authority casing plus fragments do not change the request
        target. Normalizing those parts prevents a two-link cycle from evading
        the visited set through superficial spelling changes.

        Args:
            value: Validated response-derived next-link value.

        Returns:
            A canonical text key suitable for bounded set membership.
        """
        parts = urlsplit(str(value))
        return parts._replace(
            scheme=parts.scheme.lower(),
            netloc=parts.netloc.lower(),
            fragment="",
        ).geturl()

    seen_next_links = set(state.seen_next_links)
    if state.current_uri:
        seen_next_links.add(canonical_link(state.current_uri))
    next_link_key = canonical_link(next_link)
    if next_link != state.current_uri and next_link_key in seen_next_links:
        return replace(
            state,
            current_uri=None,
            seen_next_links=frozenset(seen_next_links),
            stop_reason=PaginationStopReason.REPEATED_NEXT_LINK,
        )
    seen_next_links.add(next_link_key)

    return replace(
        state,
        current_uri=next_link,
        current_offset=next_offset if enforce_snapshot_continuity else None,
        repeated_next_link_count=repeated_next_link_count,
        seen_next_links=frozenset(seen_next_links),
        stop_reason=None,
    )


def pagination_skip_offset(uri: Any) -> Optional[int]:
    """
    Return one unambiguous numeric Redfish ``$skip`` offset.

    After applying local validation, the function forwards ``uri`` to
    ``_pagination_skip_offset_from_values`` and preserves its return and
    exception contract.

    Args:
        uri: Validated remote resource identifier used for URI.

    Returns:
        The numeric pagination skip offset, or ``None`` when the requested value
        is unavailable.
    """

    values = _pagination_skip_query_values(uri)
    if values is None:
        return None
    return _pagination_skip_offset_from_values(values)


def _pagination_skip_offset_from_values(values: Tuple[str, ...]) -> Optional[int]:
    """
    Return the bounded offset represented by one parsed query value.

    After applying local validation, the function forwards ``values`` to ``int``
    and preserves its return and exception contract.

    Args:
        values: Entries supplied as ``values`` without transferring container
            ownership.

    Returns:
        The numeric pagination skip offset from values value, or ``None`` when
        the requested value is unavailable.
    """

    if len(values) != 1:
        return None
    digits = values[0]
    if len(digits) > 32 or _DECIMAL_OFFSET_PATTERN.fullmatch(digits) is None:
        return None
    return int(digits)


def _pagination_skip_query_values(uri: Any) -> Optional[Tuple[str, ...]]:
    """
    Return only actual ``$skip`` values from the URL query component.

    After applying local validation, the function forwards ``uri`` to ``tuple``
    and preserves its return and exception contract.

    Args:
        uri: Validated remote resource identifier used for URI.

    Returns:
        The pagination skip query values returned in operation-defined order, or
        ``None`` when the requested value is unavailable.
    """

    if not isinstance(uri, str) or len(uri) > _MAX_PAGINATION_NEXT_LINK_CHARS:
        return None
    try:
        query = urlsplit(uri).query
    except ValueError:
        return None

    values = []
    for parameter in query.split("&"):
        raw_key, separator, value = parameter.partition("=")
        if len(raw_key) > 32:
            continue
        try:
            key = unquote(raw_key)
        except Exception:
            continue
        if key.casefold() == "$skip":
            values.append(value if separator else "")
            if len(values) == 2:
                break
    return tuple(values)


def initial_snapshot_next_link_stop_reason(
    *,
    current_offset: Optional[int],
    next_link: Any,
    observed_rows: Optional[int],
    allow_forward_offset_gaps: bool = False,
) -> Optional[PaginationStopReason]:
    """
    Validate positional continuity for one initial-snapshot next link.

    The implementation uses ``current_offset``, ``next_link``, and
    ``observed_rows`` to validate positional continuity for one initial-snapshot
    next link. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        current_offset: Numeric current offset used by the operation's bounded
            accounting.
        next_link: Next link consumed while the function attempts to validate
            positional continuity for one initial-snapshot next link.
        observed_rows: Numeric observed rows used while the operation performs
            bounded accounting.
        allow_forward_offset_gaps: Whether a validated, strictly forward
            server cursor may advance beyond the number of returned rows.

    Returns:
        A ``PaginationStopReason`` representing initial snapshot next link stop
        reason, or ``None`` when the requested value is unavailable.
    """

    if (
        type(current_offset) is not int
        or current_offset < 0
        or type(observed_rows) is not int
        or observed_rows < 0
    ):
        return PaginationStopReason.SNAPSHOT_OFFSET_UNVERIFIABLE

    next_offset = pagination_skip_offset(next_link)
    if next_offset is None:
        return PaginationStopReason.SNAPSHOT_OFFSET_UNVERIFIABLE

    expected_next_offset = current_offset + observed_rows
    if next_offset == current_offset:
        return PaginationStopReason.SNAPSHOT_OFFSET_NON_PROGRESS
    if next_offset < expected_next_offset:
        return PaginationStopReason.SNAPSHOT_OFFSET_OVERLAP
    if next_offset > expected_next_offset:
        if allow_forward_offset_gaps:
            return None
        return PaginationStopReason.SNAPSHOT_OFFSET_GAP
    return None


def paginated_log_entry_key(entry: Any) -> str:
    """
    Return a stable identity for deduplicating paginated log entries.

    The implementation uses ``entry`` to produce a stable identity for
    deduplicating paginated log entries.

    Args:
        entry: Entry object whose ``get`` state is read while performing stable
            identity for deduplicating paginated log entries.

    Returns:
        The canonical paginated log entry key text.
    """
    if isinstance(entry, dict):
        entry_id = entry.get("Id")
        if entry_id not in (None, ""):
            return f"Id:{entry_id}"

        odata_id = entry.get("@odata.id")
        if odata_id not in (None, ""):
            return f"@odata.id:{odata_id}"

    canonical_entry = json.dumps(
        entry,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical_entry.encode("utf-8")).hexdigest()
    return f"content:{digest}"


def redfish_created_timestamp(entry: Any) -> Optional[float]:
    """
    Return a UTC timestamp for a valid Redfish ``Created`` value.

    After applying local validation, the function forwards ``entry`` to
    ``timestamp`` and preserves its return and exception contract. Filesystem
    effects remain confined to the caller-selected paths and the owning resource
    lifecycle.

    Args:
        entry: Entry object whose ``get`` state is read while performing UTC
            timestamp for a valid Redfish ``Created`` value.

    Returns:
        The numeric Redfish created timestamp value, or ``None`` when the
        requested value is unavailable.
    """
    created = entry.get("Created") if isinstance(entry, dict) else None
    if not isinstance(created, str) or not created.strip():
        return None
    try:
        parsed = datetime.fromisoformat(created.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).timestamp()
    except (OverflowError, TypeError, ValueError):
        return None


def additional_data_attachment_sort_key(
    uri: str,
    entry: Any,
    *,
    timestamp_getter: Callable[[Any], Optional[float]] = redfish_created_timestamp,
) -> Tuple[int, float, str]:
    """
    Order valid timestamps newest-first, then use URI deterministically.

    The implementation uses ``uri``, ``entry``, and ``timestamp_getter`` to
    order valid timestamps newest-first, then use URI deterministically.

    Args:
        uri: Validated remote resource identifier used for URI.
        entry: Entry evaluated while performing order valid timestamps
            newest-first, then use URI deterministically.
        timestamp_getter: Numeric timestamp getter used while the operation
            performs bounded accounting.

    Returns:
        A tuple containing ``integer count``, ``numeric value``, and ``URI`` in
        that order.
    """
    timestamp = timestamp_getter(entry)
    if timestamp is None:
        return (1, 0.0, uri)
    return (0, -timestamp, uri)


def next_link_reaches_snapshot_end(
    next_link: Any,
    snapshot_end_offset: Optional[int],
) -> bool:
    """
    Return whether ``next_link`` leaves the initial collection snapshot.

    The implementation uses ``next_link`` and ``snapshot_end_offset`` to
    determine whether ``next_link`` leaves the initial collection snapshot.

    Args:
        next_link: Next link consumed while the function attempts to determine
            whether ``next_link`` leaves the initial collection snapshot.
        snapshot_end_offset: Numeric snapshot end offset used by the operation's
            bounded accounting.

    Returns:
        Whether ``next_link`` leaves the initial collection snapshot.
    """
    if snapshot_end_offset is None:
        return False
    skip_offset = pagination_skip_offset(next_link)
    return skip_offset is not None and skip_offset >= snapshot_end_offset


__all__ = [
    "PaginationNextLinkMode",
    "PaginationPageState",
    "PaginationStopReason",
    "additional_data_attachment_sort_key",
    "begin_pagination_page",
    "initial_snapshot_next_link_stop_reason",
    "next_link_reaches_snapshot_end",
    "pagination_skip_offset",
    "paginated_log_entry_key",
    "progress_pagination_next_link",
    "redfish_created_timestamp",
]
