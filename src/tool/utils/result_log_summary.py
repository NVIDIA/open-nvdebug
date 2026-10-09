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
Bounded structural summaries for collector and stage result logging.

This module owns the result log summary boundary and exposes ``_bounded_text``,
``_summarize_keys``, ``_container_count``, and ``summarize_result_for_log``.
Keeping those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

from typing import Any, Dict, List

_MAX_KEYS = 12
_MAX_KEY_LENGTH = 48
_MAX_REASON_LENGTH = 240


def _bounded_text(value: Any, limit: int) -> str:
    """
    Return a bounded scalar description without rendering containers.

    The implementation uses ``value`` and ``limit`` to produce a bounded scalar
    description without rendering containers.

    Args:
        value: Value object whose ``splitlines`` state is read while performing
            bounded scalar description without rendering containers.
        limit: Numeric limit used while the operation performs bounded
            accounting.

    Returns:
        The canonical bounded text.
    """
    if value is None:
        return "none"
    if isinstance(value, str):
        text = " ".join(value.splitlines())
        if len(text) > limit:
            return f"{text[:limit]}..."
        return text
    if isinstance(value, (bool, int, float)):
        return str(value)
    return f"<{type(value).__name__}>"


def _summarize_keys(mapping: Dict[Any, Any]) -> str:
    """
    Summarize dictionary keys without rendering their values.

    The implementation uses ``mapping`` to summarize dictionary keys without
    rendering their values.

    Args:
        mapping: Mapping supplying fields for summarize dictionary keys without
            rendering their values.

    Returns:
        The canonical summarize keys text.
    """
    names: List[str] = []
    for key in mapping:
        if len(names) >= _MAX_KEYS:
            break
        if isinstance(key, str):
            names.append(_bounded_text(key, _MAX_KEY_LENGTH))
        else:
            names.append(f"<{type(key).__name__}>")

    omitted = max(0, len(mapping) - len(names))
    if omitted:
        names.append(f"+{omitted} more")
    return "[" + ", ".join(names) + "]"


def _container_count(value: Any) -> int:
    """
    Count common result containers without traversing their contents.

    A single path or error string is one item, not one item per character.

    Args:
        value: Value evaluated while performing count common result containers
            without traversing their contents.

    Returns:
        The numeric container count.
    """
    if isinstance(value, (dict, list, tuple, set, frozenset)):
        return len(value)
    if value is None:
        return 0
    # A single path or error string is one item, not one item per character.
    if isinstance(value, str):
        return 1
    return 0


def summarize_result_for_log(result: Any) -> str:
    """
    Build a compact summary without rendering artifact payloads or context.

    Collector contexts can contain megabytes of response data and can be
    recursive. This helper intentionally inspects only scalar status fields,
    container sizes, and bounded key names.

    Args:
        result: Result object whose ``get`` state is read while performing
            compact summary without rendering artifact payloads or context.

    Returns:
        The canonical summarize result for log text.
    """
    if not isinstance(result, dict):
        return f"result_type={type(result).__name__}"

    context = result.get("context")
    if not isinstance(context, dict):
        context = {}

    def field(name: str) -> Any:
        """
        Return the field.

        The implementation uses ``name`` to produce the field.

        Args:
            name: Stable name used for lookup and operator-facing diagnostics.

        Returns:
            The field selected by this operation.
        """
        value = result.get(name)
        return context.get(name) if value is None else value

    output_files = result.get("output_files")
    if output_files is None:
        output_files = context.get("output_files")

    error_messages = result.get("error_messages")
    if error_messages is None:
        error_messages = context.get("error_messages")

    discovered_files = result.get("discovered_files")
    if discovered_files is None:
        discovered_files = context.get("discovered_files")

    return " ".join(
        (
            f"success={_bounded_text(field('success'), 16)}",
            f"status={_bounded_text(field('status'), 32)}",
            f"reason={_bounded_text(field('reason'), _MAX_REASON_LENGTH)}",
            "successful_operations="
            f"{_bounded_text(field('successful_operations'), 24)}",
            f"total_operations={_bounded_text(field('total_operations'), 24)}",
            f"output_file_count={_container_count(output_files)}",
            f"error_count={_container_count(error_messages)}",
            f"discovered_file_group_count={_container_count(discovered_files)}",
            f"result_key_count={len(result)}",
            f"result_keys={_summarize_keys(result)}",
            f"context_key_count={len(context)}",
            f"context_keys={_summarize_keys(context)}",
        )
    )
