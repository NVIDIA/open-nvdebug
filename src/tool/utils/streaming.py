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

"""Helpers for streaming-window parsing, formatting, and file naming."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Tuple

STREAM_WINDOW_FORMAT = "%Y%m%dT%H%MZ"
_STREAM_WINDOW_RE = re.compile(r"^\d{8}T\d{4}Z$")
_STREAM_WINDOW_IN_FILENAME_RE = re.compile(r"_\d{8}T\d{4}Z_\d{8}T\d{4}Z(?=\.|$)")
_COMPOUND_EXTENSIONS = (".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst")


def _normalize_utc_minute(value: datetime) -> datetime:
    """Normalize a datetime to UTC minute granularity."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.replace(second=0, microsecond=0)


def _parse_absolute_stream_timestamp(value: str) -> datetime:
    """Parse a UTC timestamp in the fleet-sharing filename format."""
    parsed = datetime.strptime(value, STREAM_WINDOW_FORMAT)
    return parsed.replace(tzinfo=timezone.utc)


def parse_stream_window_value(
    value: Any, now_utc: Optional[datetime] = None
) -> Optional[datetime]:
    """Parse a streaming window value from absolute UTC or relative hours-ago."""
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
    """Resolve begin/end values into an absolute UTC window."""
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
    """Format a UTC datetime using the fleet-sharing filename convention."""
    return _normalize_utc_minute(value).strftime(STREAM_WINDOW_FORMAT)


def format_redfish_stream_timestamp(value: datetime) -> str:
    """Format a UTC datetime for Redfish OData filtering."""
    return _normalize_utc_minute(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_host_stream_timestamp(value: datetime) -> str:
    """Format a UTC datetime for host log tools like journalctl and dmesg."""
    return _normalize_utc_minute(value).strftime("%Y-%m-%d %H:%M:%S UTC")


def append_stream_window_to_filename(
    filename: str, stream_begin: str, stream_end: str
) -> str:
    """Insert a <START>_<END> suffix before the filename extension."""
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
