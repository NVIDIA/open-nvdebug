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
Helpers for streaming-window parsing, formatting, and file naming.

This module owns the streaming boundary and exposes ``_normalize_utc_minute``,
``_parse_absolute_stream_timestamp``, ``parse_stream_window_value``,
``normalize_stream_window``, and ``format_stream_window_component``. Keeping
those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Tuple

STREAM_WINDOW_FORMAT = "%Y%m%dT%H%MZ"
_STREAM_WINDOW_RE = re.compile(r"^\d{8}T\d{4}Z$")
_STREAM_WINDOW_IN_FILENAME_RE = re.compile(r"_\d{8}T\d{4}Z_\d{8}T\d{4}Z(?=\.|$)")
_COMPOUND_EXTENSIONS = (".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst")


def _normalize_utc_minute(value: datetime) -> datetime:
    """
    Normalize a datetime to UTC minute granularity.

    After applying local validation, the function forwards ``value`` to
    ``value.replace`` and preserves its return and exception contract. The
    source value keeps its ownership while the normalized representation is
    returned separately. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Args:
        value: Value object whose ``astimezone``, ``replace``, and ``tzinfo``
            state is read while performing datetime to UTC minute granularity.

    Returns:
        A ``datetime`` representing utc minute.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.replace(second=0, microsecond=0)


def _parse_absolute_stream_timestamp(value: str) -> datetime:
    """
    Parse a UTC timestamp in the fleet-sharing filename format.

    After applying local validation, the function forwards ``value`` to
    ``parsed.replace`` and preserves its return and exception contract. Parsing
    or I/O must finish before the validated representation is made available to
    the caller. Filesystem effects remain confined to the caller-selected paths
    and the owning resource lifecycle.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        A ``datetime`` representing absolute stream timestamp.
    """
    parsed = datetime.strptime(value, STREAM_WINDOW_FORMAT)
    return parsed.replace(tzinfo=timezone.utc)


def parse_stream_window_value(
    value: Any, now_utc: Optional[datetime] = None
) -> Optional[datetime]:
    """
    Parse a streaming window value from absolute UTC or relative hours-ago.

    The implementation uses ``value`` and ``now_utc`` to parse a streaming
    window value from absolute UTC or relative hours-ago. Parsing or I/O must
    finish before the validated representation is made available to the caller.
    If the function cannot parse a streaming window value from absolute UTC or
    relative hours-ago, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        value: Value evaluated while performing streaming window value from
            absolute UTC or relative hours-ago.
        now_utc: Optional now utc; ``None`` selects the function's default
            behavior.

    Returns:
        A ``datetime`` representing stream window value, or ``None`` when the
        requested value is unavailable.

    Raises:
        ValueError: If the streaming windows are not UTC timestamps like
            YYYYMMDDTHHMMZ or relative hours-ago values like 12 or 1.5.
    """
    if value in (None, ""):
        return None

    now_utc = _normalize_utc_minute(now_utc or datetime.now(timezone.utc))

    if isinstance(value, datetime):
        return _normalize_utc_minute(value)

    if isinstance(value, (int, float)):
        return _normalize_utc_minute(now_utc - timedelta(hours=float(value)))

    text = str(value).strip()
    if not text:
        return None

    if _STREAM_WINDOW_RE.fullmatch(text):
        return _normalize_utc_minute(_parse_absolute_stream_timestamp(text))

    try:
        return _normalize_utc_minute(now_utc - timedelta(hours=float(text)))
    except ValueError as exc:
        raise ValueError(
            "Streaming windows must be UTC timestamps like YYYYMMDDTHHMMZ "
            "or relative hours-ago values like 12 or 1.5."
        ) from exc


def normalize_stream_window(
    stream_begin: Any, stream_end: Any, now_utc: Optional[datetime] = None
) -> Tuple[datetime, datetime]:
    """
    Resolve begin/end values into an absolute UTC window.

    The implementation uses ``stream_begin``, ``stream_end``, and ``now_utc`` to
    resolve begin/end values into an absolute UTC window. If the function cannot
    resolve begin/end values into an absolute UTC window, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        stream_begin: Stream begin consumed while the function attempts to
            resolve begin/end values into an absolute UTC window.
        stream_end: Stream end consumed while the function attempts to resolve
            begin/end values into an absolute UTC window.
        now_utc: Optional now utc; ``None`` selects the function's default
            behavior.

    Returns:
        A tuple containing ``begin dt`` and ``end dt`` in that order.

    Raises:
        ValueError: If the supplied input cannot be used to resolve begin/end
            values into an absolute UTC window.
    """
    normalized_now = _normalize_utc_minute(now_utc or datetime.now(timezone.utc))
    begin_dt = parse_stream_window_value(stream_begin, normalized_now)
    end_dt = parse_stream_window_value(stream_end, normalized_now)

    if begin_dt is None:
        begin_dt = _normalize_utc_minute(normalized_now - timedelta(hours=24))
    if end_dt is None:
        end_dt = normalized_now

    if begin_dt >= end_dt:
        raise ValueError(
            "--stream-begin must be earlier than --stream-end. "
            f"Got begin={format_stream_window_component(begin_dt)} and "
            f"end={format_stream_window_component(end_dt)}."
        )

    return begin_dt, end_dt


def format_stream_window_component(value: datetime) -> str:
    """
    Format a UTC datetime using the fleet-sharing filename convention.

    After applying local validation, the function forwards ``value`` to
    ``strftime`` and preserves its return and exception contract. The source
    value keeps its ownership while the normalized representation is returned
    separately.

    Args:
        value: Value evaluated while performing UTC datetime using the
            fleet-sharing filename convention.

    Returns:
        The canonical stream window component text.
    """
    return _normalize_utc_minute(value).strftime(STREAM_WINDOW_FORMAT)


def format_redfish_stream_timestamp(value: datetime) -> str:
    """
    Format a UTC datetime for Redfish OData filtering.

    After applying local validation, the function forwards ``value`` to
    ``strftime`` and preserves its return and exception contract. The source
    value keeps its ownership while the normalized representation is returned
    separately.

    Args:
        value: Value evaluated while performing UTC datetime for Redfish OData
            filtering.

    Returns:
        The canonical Redfish stream timestamp text.
    """
    return _normalize_utc_minute(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_host_stream_timestamp(value: datetime) -> str:
    """
    Format a UTC datetime for host log tools like journalctl and dmesg.

    After applying local validation, the function forwards ``value`` to
    ``strftime`` and preserves its return and exception contract. The source
    value keeps its ownership while the normalized representation is returned
    separately.

    Args:
        value: Value evaluated while performing UTC datetime for host log tools
            like journalctl and dmesg.

    Returns:
        The canonical host stream timestamp text.
    """
    return _normalize_utc_minute(value).strftime("%Y-%m-%d %H:%M:%S UTC")


def append_stream_window_to_filename(
    filename: str, stream_begin: str, stream_end: str
) -> str:
    """
    Insert a <START>_<END> suffix before the filename extension.

    The implementation uses ``filename``, ``stream_begin``, and ``stream_end``
    to insert a <START>_<END> suffix before the filename extension.

    Args:
        filename: Text supplied as filename in the format accepted by this
            function.
        stream_begin: Text supplied as stream begin in the format accepted by
            this function.
        stream_end: Text supplied as stream end in the format accepted by this
            function.

    Returns:
        The canonical append stream window to filename.
    """
    if not filename or filename.startswith("."):
        return filename
    if _STREAM_WINDOW_IN_FILENAME_RE.search(filename):
        return filename

    for extension in _COMPOUND_EXTENSIONS:
        if filename.endswith(extension):
            return (
                f"{filename[:-len(extension)]}_{stream_begin}_{stream_end}{extension}"
            )

    stem, dot, suffix = filename.rpartition(".")
    if dot:
        return f"{stem}_{stream_begin}_{stream_end}.{suffix}"
    return f"{filename}_{stream_begin}_{stream_end}"
