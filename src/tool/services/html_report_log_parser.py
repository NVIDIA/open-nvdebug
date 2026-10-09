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
Pure runtime-log parsing policy for the HTML report service.

This module owns the html report log parser boundary and exposes
``LogParserSpec``, ``ParsedLogLine``, ``escape_shared_regex_literal``,
``compile_log_format_parser``, and ``canonical_lifecycle_parser``. Keeping those
contracts together gives importers one source of truth for their validation,
lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Pattern, Sequence, TypedDict

from ..core.async_logger import DEFAULT_RUNTIME_LOG_FORMAT

PERCENT_LOG_DIRECTIVE = re.compile(
    r"%\((?P<field>[^)\r\n]+)\)"
    r"(?P<flags>[#0\- +]*)"
    r"(?P<width>\d+)?"
    r"(?:\.(?P<precision>\d*))?"
    r"(?P<length>[hlL])?"
    r"(?P<conversion>[diouxXeEfFgGcrsa])"
)
LOG_FIELD_ROLES = {
    "asctime": "timestamp",
    "levelname": "level",
    "name": "component",
    "component": "component",
    "message": "message",
}
MAX_LOG_FORMAT_DIRECTIVES = 128
MAX_LOG_FORMAT_LENGTH = 4096


class LogParserSpec(TypedDict):
    """
    Python and browser metadata for one accepted log format.

    The coherent record keeps ``name``, ``pattern``, ``groups``, and ``tokens``
    together so consumers observe one log parser spec state. Consumers receive
    the fields as one unit instead of assembling partial state.

    Attributes:
        name: Canonical text used as name.
        pattern: Canonical text used as pattern.
        groups: Mapping that retains the groups fields for this record.
        tokens: Mapping that retains the tokens fields for this record.
    """

    name: str
    pattern: str
    groups: Dict[str, int]
    tokens: List[Dict[str, Any]]
    _compiled: Pattern[str]


class ParsedLogLine(TypedDict):
    """
    Semantic fields projected from one runtime-log line.

    The coherent record keeps ``timestamp``, ``level``, ``component``, and
    ``message`` together so consumers observe one parsed log line state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        timestamp: Canonical text used as timestamp.
        level: Canonical text used as level.
        component: Canonical text used as component.
        message: Canonical text used as message.
    """

    timestamp: Optional[str]
    level: Optional[str]
    component: Optional[str]
    message: Optional[str]


def escape_shared_regex_literal(value: str) -> str:
    """
    Escape a literal for both Python and JavaScript regular expressions.

    After applying local validation, the function forwards ``value`` to ``join``
    and preserves its return and exception contract.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        The canonical escape shared regex literal text.
    """
    special = frozenset(r"\.^$|?*+()[]{}")
    escaped = []
    for character in value:
        if character in special:
            escaped.append("\\" + character)
        elif character == "\t":
            escaped.append(r"\t")
        elif ord(character) < 32:
            escaped.append(f"\\x{ord(character):02x}")
        else:
            escaped.append(character)
    return "".join(escaped)


def compile_log_format_parser(
    log_format: Any, parser_name: str
) -> Optional[LogParserSpec]:
    """
    Compile a percent-style logging format into shared parser metadata.

    The implementation uses ``log_format`` and ``parser_name`` to compile a
    percent-style logging format into shared parser metadata.

    Args:
        log_format: Log format object whose ``startswith`` state is read while
            performing compile a percent-style logging format into shared parser
            metadata.
        parser_name: Stable parser name used for lookup and operator-facing
            diagnostics.

    Returns:
        A mapping containing the ``name``, ``pattern``, ``groups``, ``tokens``,
        and ``_compiled`` fields.
    """
    if (
        not isinstance(log_format, str)
        or not log_format
        or len(log_format) > MAX_LOG_FORMAT_LENGTH
        or any(character in log_format for character in ("\x00", "\r", "\n"))
    ):
        return None

    tokens: List[Dict[str, Any]] = []
    literal: List[str] = []
    cursor = 0
    group_index = 0
    message_seen = False

    def flush_literal() -> None:
        """
        Flush literal.

        The implementation uses current instance state to flush literal.
        """
        if literal:
            tokens.append({"text": "".join(literal)})
            literal.clear()

    while cursor < len(log_format):
        if log_format[cursor] != "%":
            literal.append(log_format[cursor])
            cursor += 1
            continue

        if log_format.startswith("%%", cursor):
            literal.append("%")
            cursor += 2
            continue

        directive = PERCENT_LOG_DIRECTIVE.match(log_format, cursor)
        if directive is None:
            return None

        flush_literal()
        group_index += 1
        if group_index > MAX_LOG_FORMAT_DIRECTIVES:
            return None

        field = directive.group("field")
        role = LOG_FIELD_ROLES.get(field, "plain")
        message_seen = message_seen or field == "message"
        tokens.append(
            {
                "group": group_index,
                "role": role,
                "field": field,
            }
        )
        cursor = directive.end()

    flush_literal()
    if not message_seen:
        return None

    directive_positions = [
        index for index, token in enumerate(tokens) if "group" in token
    ]
    last_directive_position = directive_positions[-1]
    regex_parts = ["^"]
    for index, token in enumerate(tokens):
        if "text" in token:
            regex_parts.append(escape_shared_regex_literal(token["text"]))
        elif index == last_directive_position:
            regex_parts.append("(.*)")
        else:
            regex_parts.append("(.*?)")
    regex_parts.append("$")
    pattern = "".join(regex_parts)

    try:
        compiled = re.compile(pattern)
    except re.error:
        return None

    groups: Dict[str, int] = {}
    component_source = None
    for token in tokens:
        if "group" not in token:
            continue
        role = token.get("role")
        if role == "plain":
            continue
        if role == "component":
            if component_source != "component" or token["field"] == "component":
                groups[role] = token["group"]
                component_source = token["field"]
            continue
        groups.setdefault(role, token["group"])

    browser_tokens = [
        (
            {"text": token["text"]}
            if "text" in token
            else {"group": token["group"], "role": token["role"]}
        )
        for token in tokens
    ]
    return {
        "name": parser_name,
        "pattern": pattern,
        "groups": groups,
        "tokens": browser_tokens,
        "_compiled": compiled,
    }


def canonical_lifecycle_parser() -> LogParserSpec:
    """
    Return the strict parser for lifecycle lines that stay canonical.

    The implementation uses current instance state to produce the strict parser
    for lifecycle lines that stay canonical.

    Returns:
        The validated ``parser``.
    """
    parser = compile_log_format_parser(
        DEFAULT_RUNTIME_LOG_FORMAT, "canonical-lifecycle"
    )
    assert parser is not None
    pattern = (
        r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\] "
        r"\[([^\]\r\n]+)\] \[([^\]\r\n]+)\] (.*)$"
    )
    parser["pattern"] = pattern
    parser["_compiled"] = re.compile(pattern)
    return parser


def build_log_parser_specs(log_format: Any) -> List[LogParserSpec]:
    """
    Build parsers for the effective diagnostic and lifecycle formats.

    The implementation uses ``log_format`` to build parsers for the effective
    diagnostic and lifecycle formats.

    Args:
        log_format: Log format consumed while the function attempts to build
            parsers for the effective diagnostic and lifecycle formats.

    Returns:
        The validated ``parsers``.
    """
    active = compile_log_format_parser(log_format, "configured")
    if active is None:
        active = compile_log_format_parser(DEFAULT_RUNTIME_LOG_FORMAT, "configured")
    assert active is not None

    parsers = [active]
    if log_format != DEFAULT_RUNTIME_LOG_FORMAT:
        parsers.append(canonical_lifecycle_parser())
    return parsers


def parse_log_line(
    line: str, parsers: Sequence[LogParserSpec]
) -> Optional[ParsedLogLine]:
    """
    Parse one line, preferring the match with the richest structure.

    The implementation uses ``line`` and ``parsers`` to parse one line,
    preferring the match with the richest structure. Parsing or I/O must finish
    before the validated representation is made available to the caller.

    Args:
        line: Text supplied as line in the format accepted by this function.
        parsers: Entries supplied as ``parsers`` without transferring container
            ownership.

    Returns:
        The validated ``best_match``, or ``None`` when no value qualifies.
    """
    best_match: Optional[ParsedLogLine] = None
    best_score = -1

    for parser in parsers:
        match = parser["_compiled"].match(line)
        if match is None:
            continue

        parsed: ParsedLogLine = {
            "timestamp": None,
            "level": None,
            "component": None,
            "message": line,
        }
        for role, group_index in parser["groups"].items():
            value = match.group(group_index)
            parsed[role] = value if role == "message" else value.strip()

        score = sum(bool(parsed[role]) for role in ("timestamp", "level", "component"))
        if score > best_score:
            best_match = parsed
            best_score = score

    return best_match


def browser_log_parser_metadata(
    parsers: Sequence[LogParserSpec],
) -> Dict[str, Any]:
    """
    Drop Python-only compiled expressions before embedding metadata.

    The implementation uses ``parsers`` to drop Python-only compiled expressions
    before embedding metadata.

    Args:
        parsers: Entries supplied as ``parsers`` without transferring container
            ownership.

    Returns:
        A mapping containing the ``parsers`` fields.
    """
    return {
        "parsers": [
            {key: value for key, value in parser.items() if key != "_compiled"}
            for parser in parsers
        ]
    }
