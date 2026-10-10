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
Async-safe logging system for the NVDebug Tool.

Provides thread-safe and async-safe logging with support for structured logs,
progress tracking, and detailed debug information for concurrent operations.
"""

import asyncio
import atexit
import contextvars
import copy
import hashlib
import json
import logging
import os
import re
import stat
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..utils.filesystem_identity import filesystem_owner_uid

from ..utils.artifact_paths import (
    ArtifactRole,
    classify_artifact_path,
    normalize_artifact_file_list,
    normalize_artifact_timings,
    normalize_timing_artifact_paths,
    run_tree_path_component,
)
from ..utils.atomic_publication import (
    atomic_publish_bytes,
    atomic_publish_locked_bytes,
    read_locked_bytes,
)
from ..utils.collector_attempt_policy import (
    project_additive_attempts,
    project_advanced_managed_receipt,
    project_attempt_policy,
)
from ..utils.constants import ASCII_HEADER
from ..utils.enums import CollectorServiceMapping, get_main_preflight_names
from ..utils.json_utils import safe_json_dump, safe_json_dumps
from ..utils.logging import ensure_secure_log_directory
from ..utils.managed_filesystem import run_managed_filesystem_operation
from ..utils.report_publication_lock import (
    PinnedDirectoryLock,
    async_report_publication_lock,
)
from ..utils.result_log_summary import summarize_result_for_log
from ..utils.streaming import (
    append_stream_window_to_filename,
    format_stream_window_component,
    normalize_stream_window,
)
from ..utils.trusted_extensions import redact_optional_config_mapping
from .collector_outcome import (
    extract_collector_outcome_details,
    extract_operation_accounting,
    normalize_collector_failure_category,
    sanitize_terminal_collector_reason,
)

# Context variable for async-safe collector ID tracking
# This allows each async task to maintain its own collector_id without interference
_collector_context: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "collector_context", default=None
)
_dut_context: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "dut_context", default=None
)


logger = logging.getLogger(__name__)

MAX_LOG_FILE_SIZE_MB = 100  # Warn when a single log file exceeds this
MAX_COMMAND_DIAGNOSTIC_STREAM_BYTES = 16 * 1024
MAX_COMMAND_DIAGNOSTIC_TOTAL_BYTES = 32 * 1024 * 1024
MAX_COMMAND_DIAGNOSTIC_RECORDS = 4096
_BULK_PREPARATION_INPUT_LIMIT = 64 * 1024
MAX_DUT_RUNTIME_LOG_ENTRY_BYTES = 64 * 1024
MAX_STRUCTURED_LOG_METADATA_BYTES = 4 * 1024 * 1024
MAX_STRUCTURED_LOG_ENTRIES = 10_000
MAX_STRUCTURED_LOG_CELL_CHARS = 160
MAX_STRUCTURED_LOG_OUTPUT_BYTES = 8 * 1024 * 1024
_STRUCTURED_COLLECTOR_METADATA = (
    ("redfish", "redfish.json"),
    ("ipmi", "ipmi.json"),
    ("host", "host.json"),
    ("health_check", "health_check.json"),
    ("ssh", "ssh.json"),
)
_STRUCTURED_COLLECTOR_OUTPUT_SUFFIXES = (".json", ".jsonl", ".ndjson")
MAX_STATUS_ARTIFACT_TIMING_ENTRIES = 32
_truncation_warned: set = set()
DEFAULT_RUNTIME_LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
_CONFIGURED_LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}
_PERCENT_FLAGS = frozenset("#0- +")
_PERCENT_CONVERSIONS = frozenset("diouxXeEfFgGcrsa")
_CREDENTIAL_CONFIG_KEY_RE = re.compile(
    r"(?:^|[_-])(?:pass|passwd|password|passphrase|secret|token|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|credential|authorization|cookie)s?"
    r"(?:$|[_-])",
    re.IGNORECASE,
)
_DEBUG_TOKEN_NONCREDENTIAL_KEYS = frozenset(
    {"debug_token", "tokens", "existing_token_policy", "max_token_size_bytes"}
)
_SERIALIZED_PROFILE_SUFFIXES = ("_profile", "_profiles")


def _is_credential_config_key(key: object) -> bool:
    """
    Return whether a config key names credential material.

    The implementation uses ``key`` to determine whether a config key names
    credential material.

    Args:
        key: Stable key used for lookup and operator-facing diagnostics.

    Returns:
        Whether a config key names credential material.
    """

    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(key))
    if "passwordless" in normalized.casefold():
        return False
    return bool(_CREDENTIAL_CONFIG_KEY_RE.search(normalized))


def _parse_serialized_json_container(value: str) -> Optional[Union[dict, list]]:
    """
    Return a decoded JSON object or array without treating scalars as schemas.

    Configuration snapshots can contain catalog-owned profiles serialized as a
    JSON string. Running regular expressions across the serialized document can
    consume structural punctuation, so callers sanitize decoded containers and
    serialize them again. JSON scalar strings remain ordinary configuration
    values and retain the established sanitizer behavior.

    Args:
        value: Candidate serialized JSON configuration value.

    Returns:
        The decoded object or array, or ``None`` when ``value`` is not a JSON
        container.
    """

    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return None
    return decoded if isinstance(decoded, (dict, list)) else None


def _is_catalog_profile_key(key: object) -> bool:
    """
    Return whether a configuration key carries catalog-owned profile data.

    Catalog profiles use a stable suffix rather than an enumerated key list so
    new collector profiles receive the same structure-preserving treatment.
    The suffix is intentionally evaluated only at the configuration-field
    boundary; arbitrary nested containers do not become profiles by shape.

    Args:
        key: Configuration field name to classify.

    Returns:
        Whether the field is a catalog profile carrier.
    """

    return str(key).casefold().endswith(_SERIALIZED_PROFILE_SUFFIXES)


def _write_private_json(path: Path, value: object) -> None:
    """
    Write one config snapshot as a non-symlink, mode-0600 regular file.

    The implementation uses ``path`` and ``value`` to write one config snapshot
    as a non-symlink, mode-0600 regular file. Success is reported only after the
    owning output boundary has completed its required write or publication step.

    Args:
        path: filesystem location used as the path for this operation.
        value: Value evaluated while performing one config snapshot as a
            non-symlink, mode-0600 regular file.
    """

    def private_opener(filename: str, flags: int) -> int:
        """
        Return the private opener.

        After applying local validation, the function forwards ``filename`` and
        ``flags`` to ``os.open`` and preserves its return and exception
        contract. Filesystem effects remain confined to the caller-selected
        paths and the owning resource lifecycle.

        Args:
            filename: Text supplied as filename in the format accepted by this
                function.
            flags: Numeric flags used while the operation performs bounded
                accounting.

        Returns:
            The numeric private opener value.
        """
        secure_flags = flags | getattr(os, "O_CLOEXEC", 0)
        secure_flags |= getattr(os, "O_NOFOLLOW", 0)
        return os.open(filename, secure_flags, 0o600)

    with open(path, "w", encoding="utf-8", opener=private_opener) as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, indent=4)


async def _await_executor_future(future: Any) -> Any:
    """
    Observe executor work with a bounded event-loop heartbeat.

    Some frozen/platform event loops do not reliably wake when a filesystem
    worker completes. The short timer keeps cancellation responsive and avoids
    ever moving the blocking write back onto the event-loop thread.

    Args:
        future: Future object whose ``done`` and ``result`` state is read while
            performing observe executor work with a bounded event-loop
            heartbeat.

    Returns:
        The await executor future value selected by the operation.
    """
    while not future.done():
        loop = asyncio.get_running_loop()
        heartbeat = loop.create_future()

        def wake() -> None:
            """
            Wake the event-loop heartbeat waiting on background work.

            The implementation uses current instance state to wake the
            event-loop heartbeat waiting on background work.
            """
            if not heartbeat.done():
                heartbeat.set_result(None)

        timer = loop.call_later(0.01, wake)
        try:
            await heartbeat
        finally:
            timer.cancel()
    return future.result()


class _NVDebugPercentFormatter(logging.Formatter):
    """
    Percent-style formatter with stable nvdebug context fields.

    The type coordinates ``format`` and ``formatTime`` and retains the state
    those operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the supplied value for downstream use.

        After applying local validation, the function forwards ``record`` to
        ``format`` and preserves its return and exception contract. The source
        value keeps its ownership while the normalized representation is
        returned separately.

        Args:
            record: Record object whose ``name`` state is read while performing
                supplied value for downstream use.

        Returns:
            The canonical result text.
        """
        for name, value in (
            ("component", record.name),
            ("dut_id", ""),
            ("collector_id", ""),
        ):
            if not hasattr(record, name):
                setattr(record, name, value)
        return super().format(record)

    def formatTime(
        self, record: logging.LogRecord, datefmt: Optional[str] = None
    ) -> str:
        """
        Return the format time.

        The implementation uses ``record`` and ``datefmt`` to produce the format
        time.

        Args:
            record: Record object whose ``created`` state is read while
                performing format time.
            datefmt: Optional datefmt; ``None`` selects the function's default
                behavior.

        Returns:
            The canonical time text.
        """
        timestamp = datetime.fromtimestamp(record.created)
        if datefmt:
            return timestamp.strftime(datefmt)
        return timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _apply_runtime_log_format(
    logger_obj: Any,
    original_entry: str,
    level: Any,
    component: Any,
    message: Any,
    *,
    dut_id: Optional[str] = None,
    collector_id: Optional[str] = None,
) -> str:
    """
    Apply a configured runtime format to an otherwise canonical entry.

    The implementation uses ``logger_obj``, ``original_entry``, ``level``,
    ``component``, and ``message`` to apply a configured runtime format to an
    otherwise canonical entry.

    Args:
        logger_obj: Sanitized logging interface used for operator-visible
            diagnostics.
        original_entry: Text supplied as original entry in the format accepted
            by this function.
        level: Level consumed while the function attempts to apply a configured
            runtime format to an otherwise canonical entry.
        component: Component consumed while the function attempts to apply a
            configured runtime format to an otherwise canonical entry.
        message: Operator-facing text carried by the reported event or failure.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.

    Returns:
        The canonical runtime log format text.
    """
    default_format = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
    log_format = getattr(logger_obj, "log_format", None)
    if log_format is None or log_format == default_format:
        return original_entry

    normalized_level = str(level or "INFO").strip().upper()
    if normalized_level == "WARN":
        normalized_level = "WARNING"
    numeric_level = _CONFIGURED_LOG_LEVELS.get(normalized_level, logging.INFO)

    component_text = str(component)
    collector_text = (
        str(collector_id) if collector_id not in (None, "", "unknown") else ""
    )
    display_name = component_text
    if collector_text:
        display_name = f"CID:{collector_text}] [{component_text}"

    cached = getattr(logger_obj, "_runtime_formatter_cache", None)
    if cached is None or cached[0] != log_format:
        formatter = _NVDebugPercentFormatter(log_format, style="%", validate=True)
        logger_obj._runtime_formatter_cache = (log_format, formatter)
    else:
        formatter = cached[1]

    record = logging.LogRecord(
        name=display_name,
        level=numeric_level,
        pathname="",
        lineno=0,
        msg=str(message),
        args=(),
        exc_info=None,
    )
    record.levelname = normalized_level
    record.component = component_text
    record.dut_id = "" if dut_id is None else str(dut_id)
    record.collector_id = collector_text
    return logger_obj._sanitize_text(formatter.format(record) + "\n")


class StreamToLogger:
    """
    Redirect stdout/stderr to logger and console with progress bar filtering.

    The type coordinates ``encoding``, ``errors``, ``isatty``, ``fileno``, and
    ``_is_progress_bar_line`` and retains the state those operations share
    between calls. Resource ownership remains inside the instance until the
    matching close, exit, or cleanup operation completes.
    """

    def __init__(self, logger, level, original_stream=None):
        """
        Initialize the StreamToLogger.

        The initializer records ``last_progress_line``, ``level``,
        ``line_buffer``, ``logger``, and ``original_stream`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            logger: Sanitized logger used for operator-visible diagnostics.
            level: Level consumed while the function attempts to initialize the
                StreamToLogger.
            original_stream: Optional original stream; ``None`` selects the
                function's default behavior.
        """
        self.logger = logger
        self.level = level
        self.original_stream = original_stream
        self.line_buffer = ""
        self.last_progress_line = ""

    @property
    def encoding(self):
        """
        Expose the wrapped text stream's encoding to console renderers.

        Each access computes the value from ``original_stream`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            Whether the expose the wrapped text stream's encoding to console
            renderers operation succeeds.
        """
        return getattr(self.original_stream, "encoding", None) or "utf-8"

    @property
    def errors(self):
        """
        Expose the wrapped text stream's error policy with a safe default.

        Each access computes the value from ``original_stream`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            Whether the expose the wrapped text stream's error policy with a
            safe default operation succeeds.
        """
        return getattr(self.original_stream, "errors", None) or "strict"

    def isatty(self):
        """
        Preserve terminal detection when stdout/stderr is redirected here.

        The implementation uses current instance state to preserve terminal
        detection when stdout/stderr is redirected here.

        Returns:
            Whether the preserve terminal detection when stdout/stderr is
            redirected here operation succeeds.
        """
        try:
            return bool(self.original_stream.isatty())
        except (AttributeError, OSError, ValueError):
            return False

    def fileno(self):
        """
        Delegate the file descriptor used by terminal-aware libraries.

        After applying local validation, the function forwards current instance
        state to ``self.original_stream.fileno`` and preserves its return and
        exception contract.

        Returns:
            The wrapped stream's operating-system file descriptor.

        Raises:
            OSError: If wrapped stream has no usable file descriptor.
        """
        try:
            return self.original_stream.fileno()
        except (AttributeError, OSError, ValueError) as exc:
            raise OSError("wrapped stream has no usable file descriptor") from exc

    def _is_progress_bar_line(self, line):
        """
        Check if a line is a progress bar update (NOT a table).

        The implementation uses ``line`` to check if a line is a progress bar
        update (NOT a table). Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path.

        Args:
            line: Line consumed while the function attempts to check if a line
                is a progress bar update (NOT a table).

        Returns:
            Whether the if a line is a progress bar update (NOT a table)
            operation succeeds.
        """
        # Spinner characters used in progress bars
        spinner_chars = [
            "⠋",
            "⠙",
            "⠹",
            "⠸",
            "⠼",
            "⠴",
            "⠦",
            "⠧",
            "⠇",
            "⠏",
        ]

        # Progress bar specific characters
        progress_bar_chars = ["━", "╺", "╸"]

        # Table box drawing characters - these indicate a table, not a progress bar
        table_box_chars = [
            "┏",
            "┓",
            "┗",
            "┛",
            "┃",
            "┣",
            "┫",
            "┳",
            "┻",
            "╋",
            "┡",
            "┩",
            "╇",
            "╈",
            "│",
            "─",
            "├",
            "┤",
            "┬",
            "┴",
            "┼",
            "╭",
            "╮",
            "╯",
            "╰",
        ]

        # Check if this looks like a table line (has box drawing characters)
        is_table_line = any(char in line for char in table_box_chars)

        # Tables should be logged normally, not treated as progress bars
        if is_table_line:
            return False

        # Check for actual progress bar patterns
        has_spinner = any(char in line for char in spinner_chars)
        has_percentage = "%" in line
        has_progress_chars = any(char in line for char in progress_bar_chars)
        has_time_remaining = "0:00:" in line

        # If it looks like a progress bar, filter it
        return has_spinner and (
            has_percentage or has_progress_chars or has_time_remaining
        )

    def write(self, message):
        """
        Write message to logger, filtering progress bars.

        The implementation uses ``message`` to write message to logger,
        filtering progress bars. Success is reported only after the owning
        output boundary has completed its required write or publication step. It
        updates ``last_progress_line`` and ``line_buffer`` on the instance as
        part of that state transition.

        Args:
            message: Operator-facing text carried by the reported event or
                failure.
        """
        if message:
            self.line_buffer += message
            if self.line_buffer.endswith("\n"):
                line = self.line_buffer.rstrip()

                # Check if this is a progress bar line
                if self._is_progress_bar_line(line):
                    # Only log the first occurrence of a progress bar line
                    if line != self.last_progress_line:
                        # Log progress start as a structured event
                        if "Preflight" in line:
                            self.logger.log(
                                self.level,
                                f"PROGRESS: {line.split(' - ')[0] if ' - ' in line else line}",
                            )
                        elif "Parallel Collectors" in line or "redfish:" in line:
                            self.logger.log(self.level, f"PROGRESS: {line}")
                        elif "Dependency" in line:
                            self.logger.log(self.level, f"PROGRESS: {line}")
                        self.last_progress_line = line
                elif line:
                    # Regular nonblank line - log normally
                    self.logger.log(self.level, line)
                    self.last_progress_line = ""  # Reset progress tracking

                # Always write to original console
                if self.original_stream:
                    self.original_stream.write(self.line_buffer)
                    self.original_stream.flush()
                self.line_buffer = ""

    def flush(self):
        """
        Flush any buffered content to the logger.

        The implementation uses current instance state to flush any buffered
        content to the logger. It updates ``line_buffer`` on the instance as
        part of that state transition. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.
        """
        if self.line_buffer:
            line = self.line_buffer.rstrip()

            # Check if this is a progress bar line
            if line and not self._is_progress_bar_line(line):
                # Only log non-progress lines
                self.logger.log(self.level, line)

            # Always write to original console
            if self.original_stream:
                self.original_stream.write(self.line_buffer)
                self.original_stream.flush()
            self.line_buffer = ""


class _SanitizingCaptureHandler(logging.StreamHandler):
    """
    Write fully rendered stdlib records through the active sanitizer.

    The handler owns the final stdlib formatting boundary so records emitted
    outside ``AsyncSafeLogger`` cannot bypass credential sanitization.
    """

    def __init__(self, stream: Any, safe_logger: "AsyncSafeLogger") -> None:
        """
        Bind the capture stream to its owning sanitizing logger.

        The supplied logger remains the sole sanitizer and owns the fixed,
        non-sensitive fallback used when a record cannot be rendered safely.

        Args:
            stream: Captured text stream receiving sanitized records.
            safe_logger: Logger that owns sanitization and fallback streams.
        """

        super().__init__(stream)
        self._safe_logger = safe_logger

    def emit(self, record: logging.LogRecord) -> None:
        """
        Render, sanitize, and persist one record without a raw fallback.

        Formatting or sanitization failures emit only a fixed diagnostic to the
        original operator stream; the untrusted record is never replayed.

        Args:
            record: Standard-library log record to render and sanitize.
        """

        try:
            rendered = self.format(record)
            self.stream.write(self._safe_logger._sanitize_text(rendered))
            self.stream.write(self.terminator)
            self.flush()
        except Exception:
            # ``logging.StreamHandler.handleError`` can print the raw record to
            # stderr while logging.raiseExceptions is true. Stderr is itself
            # captured here, so that fallback both leaks data and can recurse.
            # Emit only a fixed diagnostic to the original operator stream.
            fallback = getattr(self._safe_logger, "original_stderr", None)
            if fallback is not None:
                try:
                    fallback.write(
                        "[nvdebug] Failed to sanitize a captured log record\n"
                    )
                    fallback.flush()
                except Exception:
                    pass


class AsyncSafeLogger:
    """
    Async-safe logging system with structured output.

    Provides thread-safe and async-safe logging with support for DUT-specific
    logs, structured metadata, collector tracking, and stdout/stderr capture.
    """

    @staticmethod
    def _validate_runtime_log_format(value: Any) -> str:
        """
        Validate runtime log format.

        The implementation uses ``value`` to validate runtime log format. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Args:
            value: Value object whose ``find``, ``isdigit``, and ``splitlines``
                state is read while performing runtime log format.

        Returns:
            The validated ``value``.

        Raises:
            ValueError: If the log format is not a percent-style string; log
                format must contain between 1 and 4096 characters; log format
                must not contain NUL or newline characters; or invalid
                percent-style log format: trailing '%'; or another input
                invariant is violated.
        """

        def _reject_oversized_component(raw_component: str) -> None:
            """
            Reject oversized component.

            The implementation uses ``raw_component`` to reject oversized
            component. Every required invariant is checked before a successful
            value is returned; invalid input follows the function's explicit
            exception path.

            Args:
                raw_component: Text supplied as raw component in the format
                    accepted by this function.

            Raises:
                ValueError: If log format field width and precision must not
                    exceed 4096.
            """
            normalized = raw_component.lstrip("0") or "0"
            if len(normalized) > 4 or (len(normalized) == 4 and normalized > "4096"):
                raise ValueError(
                    "Log format field width and precision must not exceed 4096"
                )

        if not isinstance(value, str):
            raise ValueError("Log format must be a percent-style string")
        if not value or len(value) > 4096:
            raise ValueError("Log format must contain between 1 and 4096 characters")
        if "\x00" in value or value.splitlines() != [value]:
            raise ValueError("Log format must not contain NUL or newline characters")

        has_message_directive = False
        cursor = 0
        while cursor < len(value):
            directive_start = value.find("%", cursor)
            if directive_start < 0:
                break
            cursor = directive_start + 1
            if cursor >= len(value):
                raise ValueError("Invalid percent-style log format: trailing '%'")
            if value[cursor] == "%":
                cursor += 1
                continue

            mapping_key = None
            if value[cursor] == "(":
                mapping_end = value.find(")", cursor + 1)
                if mapping_end < 0:
                    raise ValueError(
                        "Invalid percent-style log format: unclosed mapping key"
                    )
                mapping_key = value[cursor + 1 : mapping_end]
                cursor = mapping_end + 1

            while cursor < len(value) and value[cursor] in _PERCENT_FLAGS:
                cursor += 1

            width_start = cursor
            while cursor < len(value) and value[cursor].isdigit():
                cursor += 1
            _reject_oversized_component(value[width_start:cursor])

            if cursor < len(value) and value[cursor] == ".":
                cursor += 1
                precision_start = cursor
                while cursor < len(value) and value[cursor].isdigit():
                    cursor += 1
                _reject_oversized_component(value[precision_start:cursor])

            if cursor < len(value) and value[cursor] in "hlL":
                cursor += 1
            if cursor >= len(value) or value[cursor] not in _PERCENT_CONVERSIONS:
                raise ValueError("Invalid percent-style log format directive")
            cursor += 1

            if (
                mapping_key == "message"
                and value[directive_start:cursor] == "%(message)s"
            ):
                has_message_directive = True

        if not has_message_directive:
            raise ValueError("Log format must contain %(message)s")

        try:
            formatter = logging.Formatter(value, style="%", validate=True)
            sample = logging.LogRecord(
                name="Component",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg="message",
                args=(),
                exc_info=None,
            )
            sample.component = "Component"
            sample.dut_id = "dut-1"
            sample.collector_id = "R1"
            formatter.format(sample)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid percent-style log format: {exc}") from exc
        return value

    @staticmethod
    def _normalize_configured_log_level(value: Any) -> tuple[str, int]:
        """
        Normalize configured log level.

        The implementation uses ``value`` to normalize configured log level. The
        source value keeps its ownership while the normalized representation is
        returned separately. If the function cannot normalize configured log
        level, its exception reaches the caller instead of being converted into
        a successful result.

        Args:
            value: Value evaluated while performing configured log level.

        Returns:
            A tuple containing ``normalized`` and ``integer count`` in that
            order.

        Raises:
            ValueError: If invalid log level ``value``; expected one of:
                ``choices``.
        """
        normalized = str(value or "").strip().upper()
        if normalized == "WARN":
            normalized = "WARNING"
        if normalized not in _CONFIGURED_LOG_LEVELS:
            choices = ", ".join(_CONFIGURED_LOG_LEVELS)
            raise ValueError(f"Invalid log level {value!r}; expected one of: {choices}")
        return normalized, _CONFIGURED_LOG_LEVELS[normalized]

    @staticmethod
    def _normalize_event_level(value: Any) -> tuple[str, int]:
        """
        Normalize event level.

        The implementation uses ``value`` to normalize event level. The source
        value keeps its ownership while the normalized representation is
        returned separately.

        Args:
            value: Value evaluated while performing event level.

        Returns:
            A tuple containing ``normalized`` and ``get`` in that order.
        """
        normalized = str(value or "INFO").strip().upper()
        if normalized == "WARN":
            normalized = "WARNING"
        return normalized, _CONFIGURED_LOG_LEVELS.get(normalized, logging.INFO)

    def _should_emit(self, level: Any) -> bool:
        """
        Return whether ``level`` should emit.

        The implementation uses ``level`` to determine whether ``level`` should
        emit.

        Args:
            level: Level consumed while the function attempts to determine
                whether ``level`` should emit.

        Returns:
            Whether ``level`` should emit.
        """
        _, numeric_level = self._normalize_event_level(level)
        threshold = logging.DEBUG if self.debug_mode else self._log_level_number
        return numeric_level >= threshold

    def __init__(
        self,
        base_log_dir: str,
        orchestrator=None,
        sanitizer=None,
        debug_mode: bool = False,
        verbose_mode: bool = False,
        log_level: str = "INFO",
        log_format: str = DEFAULT_RUNTIME_LOG_FORMAT,
    ) -> None:
        """
        Initialize an ``AsyncSafeLogger`` instance.

        --debug is an explicit CLI/runtime request and therefore wins over a
        less-verbose configured threshold.

        Args:
            base_log_dir: filesystem location used as the base log dir for this
                operation.
            orchestrator: Optional orchestrator; ``None`` selects the function's
                default behavior.
            sanitizer: Sanitizer applied before untrusted or sensitive text
                leaves its boundary.
            debug_mode: Whether debug mode is enabled or required for this
                operation.
            verbose_mode: Whether verbose mode is enabled or required for this
                operation.
            log_level: Text supplied as log level in the format accepted by this
                function.
            log_format: Text supplied as log format in the format accepted by
                this function.
        """
        self.base_log_dir = Path(base_log_dir)
        self.base_log_dir.mkdir(parents=True, exist_ok=True)
        self.orchestrator = orchestrator
        self.debug_mode = debug_mode
        self.verbose_mode = verbose_mode

        configured_level, configured_level_number = (
            self._normalize_configured_log_level(log_level)
        )
        # --debug is an explicit CLI/runtime request and therefore wins over a
        # less-verbose configured threshold.
        if self.debug_mode:
            configured_level = "DEBUG"
            configured_level_number = logging.DEBUG
        self.log_level = configured_level
        self._log_level_number = configured_level_number
        self.log_format = self._validate_runtime_log_format(log_format)

        # Runtime log file
        self.runtime_file_handle: Optional[Any] = None
        self.runtime_lock = asyncio.Lock()

        # Error log file
        self.error_file_handle: Optional[Any] = None
        self.error_lock = asyncio.Lock()

        # Metadata directory
        self.metadata_dir = self.base_log_dir / ".metadata"
        self._create_output_directory(self.metadata_dir)

        # DUT-specific log directories
        self.dut_log_dirs: Dict[str, Path] = {}
        self.dut_runtime_files: Dict[str, Any] = {}  # Added for per-DUT runtime logs
        self.dut_runtime_lock = (
            asyncio.Lock()
        )  # Lock for DUT runtime log synchronization

        # Tracking dictionaries
        self.collector_results: Dict[str, Any] = {}
        # Final, filesystem-reconciled artifact inventories keyed by
        # ``<dut_id>:<collector_id>``.  Keep this separate from
        # ``collector_results`` so an early status.json write does not look like
        # a completed collector to result-accounting code.
        self._collector_file_inventories: Dict[str, Dict[str, List[str]]] = {}
        # Exact managed-publication names which must remain absent from every
        # later physical or cached inventory projection for this run.
        self._collector_file_inventory_exclusions: Dict[str, set[str]] = {}
        # Canonical directories actually selected by create_collector_log_file.
        # This is required for synthetic IDs whose service cannot be inferred
        # reliably from their prefix.
        self._collector_artifact_dirs: Dict[str, Path] = {}
        self.preflight_results: Dict[str, Any] = {}
        self.execution_summary: Dict[str, Union[List[Any], int, None]] = {
            "total_collectors": 0,
            "successful_collectors": 0,
            "degraded_collectors": 0,
            "failed_collectors": 0,
            "partial_collectors": 0,
            "skipped_collectors": 0,
        }

        # Collector status tracking
        self.collector_status: Dict[str, Dict[str, Any]] = {}

        # Original stdout/stderr for restoration
        self.original_stdout = None
        self.original_stderr = None
        self.stdout_logger = None
        self.stderr_logger = None
        self._stdout_capture_handler = None
        self._stderr_capture_handler = None

        # One immutable tool identity is projected into every runtime log for
        # this logger instance. The orchestrator owns the authoritative cache
        # during normal CLI runs; this local cache preserves the same contract
        # for direct logger consumers.
        self._runtime_identity_tool_facts: Optional[Dict[str, str]] = None

        # Sanitizer for sensitive data
        self.sanitizer = sanitizer

        # Per-file asyncio locks for metadata writes
        self._metadata_file_locks: Dict[str, asyncio.Lock] = {}

        # Register emergency cleanup for file handles
        atexit.register(self._emergency_file_cleanup)

    def _get_runtime_identity_tool_facts(self) -> Dict[str, str]:
        """
        Resolve one normalized build identity for all runtime log headers.

        Normal CLI runs reuse the orchestrator-owned identity so runtime logs,
        signatures, and run metadata describe the same executable. Direct
        logger consumers resolve the governed identity locally. The result is
        cached for the logger lifecycle and returned as a copy so callers
        cannot mutate later header output.

        Returns:
            A mapping containing the tool version, build hash, source mode,
            source revision, and UTC build timestamp used by runtime logs.
        """
        if self._runtime_identity_tool_facts is None:
            identity_facts = None
            fact_resolver = getattr(
                self.orchestrator,
                "_get_run_identity_tool_facts",
                None,
            )
            if callable(fact_resolver):
                resolved_facts = fact_resolver()
                if isinstance(resolved_facts, dict):
                    identity_facts = resolved_facts

            if identity_facts is None:
                from .run_identity_builder import tool_identity_facts

                identity_facts = tool_identity_facts()

            self._runtime_identity_tool_facts = dict(identity_facts)

        return dict(self._runtime_identity_tool_facts)

    def _runtime_identity_header_lines(
        self,
        *,
        timestamp: str,
        component: str,
    ) -> List[str]:
        """
        Format the cached tool identity as runtime-log header records.

        Every record uses the caller-selected timestamp and component while
        preserving the normalized identity labels shared by root and per-DUT
        runtime logs.

        Args:
            timestamp: Preformatted runtime timestamp shared by the surrounding
                header records.
            component: Logging component recorded in each identity line.

        Returns:
            Ordered runtime-log lines for version and build provenance.
        """
        identity_facts = self._get_runtime_identity_tool_facts()
        prefix = f"[{timestamp}] [INFO] [{component}]"
        return [
            f"{prefix} NVDebug version: {identity_facts['tool_version']}",
            f"{prefix} Build hash: {identity_facts['build_hash']}",
            f"{prefix} Source mode: {identity_facts['source_mode']}",
            f"{prefix} Source revision: {identity_facts['source_revision']}",
            f"{prefix} Build time: {identity_facts['build_timestamp_utc']}",
        ]

    def _sanitize_text(self, text: str) -> str:
        """
        Apply the active run sanitizer to text destined for disk.

        The implementation uses ``text`` to apply the active run sanitizer to
        text destined for disk.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical text.
        """
        if self.sanitizer:
            return self.sanitizer.sanitize(text)
        return text

    @staticmethod
    def _reject_duplicate_json_keys(
        pairs: List[tuple[str, Any]],
    ) -> Dict[str, Any]:
        """
        Build one JSON object without accepting ambiguous duplicate keys.

        The implementation uses ``pairs`` to build one JSON object without
        accepting ambiguous duplicate keys. If the function cannot build one
        JSON object without accepting ambiguous duplicate keys, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            pairs: Entries supplied as ``pairs`` without transferring container
                ownership.

        Returns:
            The validated ``value``.

        Raises:
            ValueError: If collector JSON contains a duplicate mapping key.
        """
        value: Dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError("Collector JSON contains a duplicate mapping key")
            value[key] = child
        return value

    @staticmethod
    def _reject_nonfinite_json_constant(_value: str) -> None:
        """
        Reject JavaScript numeric constants which are not valid JSON.

        The implementation uses ``_value`` to reject JavaScript numeric
        constants which are not valid JSON. Every required invariant is checked
        before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Args:
            _value: Text supplied as value in the format accepted by this
                function.

        Raises:
            ValueError: If collector JSON contains a non-finite numeric value.
        """
        raise ValueError("Collector JSON contains a non-finite numeric value")

    @classmethod
    def _load_strict_collector_json(cls, text: str) -> Any:
        """
        Load standards-compliant JSON while rejecting ambiguous objects.

        After applying local validation, the function forwards ``text`` to
        ``json.loads`` and preserves its return and exception contract. Parsing
        or I/O must finish before the validated representation is made available
        to the caller.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The strict collector JSON value selected by the operation.
        """
        return json.loads(
            text,
            object_pairs_hook=cls._reject_duplicate_json_keys,
            parse_constant=cls._reject_nonfinite_json_constant,
        )

    def _sanitize_collector_json_value(self, value: Any) -> tuple[Any, bool]:
        """
        Sanitize JSON values without discarding records with colliding keys.

        A configured credential can also be a public Redfish schema token (for
        example, an OEM/action namespace). Dropping the complete response is
        avoidable by assigning colliding redacted keys non-secret ordinal
        suffixes. Reserve every sibling's sanitized name before assigning an
        alias, and preserve unchanged keys regardless of input order. Aliases
        must themselves survive sanitization unchanged so a later sanitization
        pass cannot collapse them. Actual duplicate input keys are rejected by
        the strict JSON loader before this method runs.

        Args:
            value: Parsed JSON value to sanitize recursively without modifying
                the caller's objects.

        Returns:
            The sanitized value and whether any key or descendant changed.

        Raises:
            ValueError: If the configured sanitizer would rewrite a generated
                alias, making lossless key disambiguation unsafe.
        """
        if isinstance(value, dict):
            sanitized: Dict[str, Any] = {}
            sanitized_keys = {key: self._sanitize_text(key) for key in value}
            reserved_keys = set(sanitized_keys.values())
            unchanged_keys = {
                key
                for key, sanitized_key in sanitized_keys.items()
                if key == sanitized_key
            }
            alias_index = 1
            changed = False
            for key, child in value.items():
                sanitized_key = sanitized_keys[key]
                if sanitized_key in sanitized or (
                    sanitized_key != key and sanitized_key in unchanged_keys
                ):
                    # A monotonic counter and finite reserved set bound alias
                    # allocation to the number of sibling keys and collisions.
                    while True:
                        alias_index += 1
                        alias = f"{sanitized_key}__{alias_index}"
                        if alias not in reserved_keys and alias not in sanitized:
                            break
                    if self._sanitize_text(alias) != alias:
                        raise ValueError(
                            "Collector JSON mapping key sanitization collision: "
                            "generated alias is not stable under sanitization"
                        )
                    sanitized_key = alias
                structured_checker = getattr(
                    self.sanitizer,
                    "is_sensitive_structured_key",
                    None,
                )
                if callable(structured_checker):
                    # The structure-aware matcher distinguishes schema names
                    # such as Redfish ``#...EraseToken`` actions and URI
                    # locators from credential-bearing fields. It is the
                    # authoritative decision whenever the sanitizer provides
                    # one.
                    credential_field = sanitized_key == key and structured_checker(key)
                else:
                    # Compatibility sanitizers may expose only flat text
                    # replacement. Probe a synthetic non-secret value so their
                    # credential-pair coverage still applies without rewriting
                    # JSON syntax.
                    credential_field = sanitized_key == key and any(
                        self._sanitize_text(f"{key}{separator}x")
                        != f"{key}{separator}x"
                        for separator in ("=", ": ")
                    )
                if credential_field:
                    replacement = str(getattr(self.sanitizer, "replacement", "XXXX"))
                    sanitized[sanitized_key] = replacement
                    changed = changed or child != replacement
                    continue
                sanitized_child, child_changed = self._sanitize_collector_json_value(
                    child
                )
                sanitized[sanitized_key] = sanitized_child
                changed = changed or child_changed or sanitized_key != key
            return sanitized, changed

        if isinstance(value, list):
            sanitized_list = []
            changed = False
            for child in value:
                sanitized_child, child_changed = self._sanitize_collector_json_value(
                    child
                )
                sanitized_list.append(sanitized_child)
                changed = changed or child_changed
            return sanitized_list, changed

        if isinstance(value, str):
            sanitized = self._sanitize_text(value)
            return sanitized, sanitized != value

        # Exact string canaries belong to the text domain. Applying them to a
        # JSON number can turn unrelated telemetry that happens to share the
        # same digits into a string and corrupt the Redfish response contract.
        # Credential-bearing mapping keys are handled above, so typed values
        # under fields such as ``Password`` still fail closed.
        return value, False

    def _prepare_json_lines_collector_output(self, text: str) -> bytes:
        """
        Validate and sanitize one JSON value per LF-delimited record.

        Validate the exact bytes which will be published.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The bounded prepare JSON lines collector output bytes.
        """
        output_lines: List[str] = []
        changed = False
        segments = text.split("\n")
        for index, segment in enumerate(segments):
            has_lf = index < len(segments) - 1
            has_cr = segment.endswith("\r")
            body = segment[:-1] if has_cr else segment
            line_ending = ("\r" if has_cr else "") + ("\n" if has_lf else "")
            if not body.strip():
                output_lines.append(body + line_ending)
                continue

            value = self._load_strict_collector_json(body)
            sanitized, line_changed = self._sanitize_collector_json_value(value)
            if line_changed:
                rendered = json.dumps(
                    sanitized,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                )
                # Validate the exact bytes which will be published.
                self._load_strict_collector_json(rendered)
                output_lines.append(rendered + line_ending)
                changed = True
            else:
                output_lines.append(body + line_ending)

        rendered_text = "".join(output_lines)
        return (rendered_text if changed else text).encode("utf-8")

    def _prepare_structured_collector_output(
        self,
        destination: Path,
        content: Union[str, bytes],
    ) -> bytes:
        """
        Return validated, structure-preserving collector JSON bytes.

        Validate the exact bytes which will be published.

        Args:
            destination: filesystem location used as the destination for this
                operation.
            content: Text supplied as content in the format accepted by this
                function.

        Returns:
            The bounded prepare structured collector output bytes.

        Raises:
            ValueError: If collector JSON artifact must contain valid UTF-8; or
                collector JSON artifact must contain valid strict JSON.
        """
        try:
            text = content.decode("utf-8") if isinstance(content, bytes) else content
        except UnicodeDecodeError as exc:
            raise ValueError(
                "Collector JSON artifact must contain valid UTF-8"
            ) from exc

        try:
            if destination.name.lower().endswith((".jsonl", ".ndjson")):
                return self._prepare_json_lines_collector_output(text)

            value = self._load_strict_collector_json(text)
            sanitized, changed = self._sanitize_collector_json_value(value)
            if not changed:
                return text.encode("utf-8")
            rendered = (
                json.dumps(
                    sanitized,
                    indent=2,
                    ensure_ascii=False,
                    allow_nan=False,
                )
                + "\n"
            )
            # Validate the exact bytes which will be published.
            self._load_strict_collector_json(rendered)
            return rendered.encode("utf-8")
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ValueError(
                "Collector JSON artifact must contain valid strict JSON"
            ) from exc

    def _prepare_collector_output(
        self,
        destination: Path,
        content: Union[str, bytes],
    ) -> bytes:
        """
        Prepare complete collector bytes before atomic publication.

        The implementation uses ``destination`` and ``content`` to prepare
        complete collector bytes before atomic publication.

        Args:
            destination: filesystem location used as the destination for this
                operation.
            content: Text supplied as content in the format accepted by this
                function.

        Returns:
            The bounded prepare collector output bytes.
        """
        if destination.name.lower().endswith(_STRUCTURED_COLLECTOR_OUTPUT_SUFFIXES):
            return self._prepare_structured_collector_output(destination, content)
        if isinstance(content, bytes):
            try:
                decoded = content.decode("utf-8")
            except UnicodeDecodeError:
                return content
            return self._sanitize_text(decoded).encode("utf-8")
        return self._sanitize_text(content).encode("utf-8")

    @staticmethod
    def _atomic_publish_collector_output(
        destination: Path,
        content: bytes,
        *,
        inherit_creation_mode: bool = False,
    ) -> None:
        """
        Atomically publish prepared collector bytes for live read access.

        Callers validate and sanitize content before this boundary. Staging
        remains private while bytes are written; new completed artifacts use
        0644 by default, while replacements retain the existing access mode.
        Status writers may inherit normal file creation permissions: the empty
        staging inode first records the filesystem and process creation policy,
        then becomes private before any content is written. No process-wide
        umask is read or changed by this worker.
        The final pathname never exposes partial writes. Configuration snapshots
        and private capture transactions use their separate private writers.

        Args:
            destination: Final collector artifact pathname.
            content: Complete, prepared bytes authorized for collector output.
            inherit_creation_mode: Whether new artifacts retain the mode of a
                normal 0666 creation, including the process umask and directory
                creation policy, instead of the default completed-artifact mode.

        Raises:
            FileExistsError: If unable to allocate atomic temporary file for
                ``destination``.
            OSError: If writing, setting permissions, syncing, or publication fails.

        Side Effects:
            Creates a private staging file and atomically replaces the final
            artifact only after its complete bytes and access mode are durable.
        """
        atomic_publish_bytes(
            destination, content, inherit_creation_mode=inherit_creation_mode
        )

    async def _write_metadata_json(
        self, destination: Path, document: object, *, only_if_missing: bool = False
    ) -> None:
        """
        Serialize and atomically publish a metadata document in an owned worker.

        The stable path lock serializes logger callers while one owned worker
        performs path validation, encoding and replacement. No partial document
        is exposed at the public pathname if that worker fails before rename.

        Args:
            destination: Metadata path confined to the selected output root.
            document: Complete projected metadata, already sanitized by its owner.
            only_if_missing: Recheck initialization under path ownership so a
                later initialization cannot replace a populated group document.

        Raises:
            OSError: If directory preparation or publication fails.
            ValueError: If the destination escapes the output root.
            asyncio.CancelledError: After an admitted publication has been joined.

        Side Effects:
            Serializes same-path callers and retains old complete bytes until
            replacement. Creation and replacement access modes are preserved.
        """

        def publish_document() -> None:
            """
            Perform path checks, JSON encoding and same-filesystem publication.

            Side Effects:
                Creates the selected parent and atomically replaces the metadata
                leaf only after its complete staging bytes have been flushed.
            """
            path = self._resolve_under_log_root(destination)
            if only_if_missing and path.exists():
                return
            payload = safe_json_dumps(document, indent=4).encode("utf-8")
            self._atomic_publish_collector_output(
                path, payload, inherit_creation_mode=True
            )

        async with self._get_lock_for_path(destination):
            await run_managed_filesystem_operation(publish_document)

    @staticmethod
    def _read_collector_report_for_append(path: Path) -> bytes:
        """
        Read one stable regular report without following a final symlink.

        The descriptor-bound read rejects non-regular, oversized, or changing
        files so a later atomic append cannot publish bytes from an unsafe or
        inconsistent source. A report that disappeared before it could be
        opened is treated as an empty initial report.

        Args:
            path: Existing collector report considered for append.

        Returns:
            Stable report bytes, or an empty byte string when the report does
            not exist.

        Raises:
            OSError: If the report changes while it is being read or another
                descriptor operation fails.
            ValueError: If the report is not regular or exceeds the append
                safety limit.
        """

        descriptor: Optional[int] = None
        max_bytes = MAX_LOG_FILE_SIZE_MB * 1024 * 1024
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("Collector report path must be a regular file")
            if before.st_size < 0 or before.st_size > max_bytes:
                raise ValueError("Collector report exceeds the append safety limit")

            raw = bytearray()
            while len(raw) < before.st_size:
                chunk = os.read(descriptor, min(64 * 1024, before.st_size - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)

            after = os.fstat(descriptor)
            stable_fields = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if len(raw) != before.st_size or any(
                getattr(before, field) != getattr(after, field)
                for field in stable_fields
            ):
                raise OSError("Collector report changed while it was read")
            return bytes(raw)
        except FileNotFoundError:
            return b""
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _append_collector_report(
        self,
        path: Path,
        report: str,
        *,
        separator_label: str,
    ) -> None:
        """
        Append through a bounded read and atomic no-follow publication.

        Existing stable text is combined with a labeled separator and the new
        report, then published through the same safe replacement path used for
        collector output. The final size check bounds the complete accumulated
        report rather than only the new entry.

        Args:
            path: Collector report destination.
            report: New structured report entry to append.
            separator_label: Boundary label inserted before an additional
                entry.

        Raises:
            OSError: If the existing report cannot be read safely or the
                replacement cannot be published.
            UnicodeDecodeError: If an existing report is not valid UTF-8.
            ValueError: If the existing or combined report exceeds the append
                safety limit.
        """

        existing = self._read_collector_report_for_append(path)
        if existing:
            separator = "\n\n" + "=" * 80 + "\n"
            separator += separator_label
            separator += "\n" + "=" * 80 + "\n\n"
            report = existing.decode("utf-8") + separator + report
        prepared = self._prepare_collector_output(path, report)
        if len(prepared) > MAX_LOG_FILE_SIZE_MB * 1024 * 1024:
            raise ValueError("Collector report exceeds the append safety limit")
        self._atomic_publish_collector_output(path, prepared)

    @staticmethod
    def _atomic_publish_collector_file(
        destination: Path,
        source: Path,
    ) -> None:
        """
        Atomically publish a complete same-filesystem staging file.

        DUTManager creates its private spool beside the run output. Keeping this
        boundary same-filesystem makes publication a single atomic rename; an
        unexpected cross-filesystem source fails explicitly. A new completed
        file receives the same 0644 mode as byte-content publication, rather
        than retaining its private spool's 0600 mode. Replacements preserve
        the existing destination mode; the process umask is never changed.
        Apply that mode through an opened regular-file descriptor, avoiding
        optional pathname no-follow chmod support on the collection host. Close
        the descriptor before committing the rename so a close error retains
        the complete source and the previous destination for recovery.

        Args:
            destination: Validated final collector artifact pathname.
            source: Complete caller-owned staging file on the same filesystem.

        Raises:
            ValueError: If the collector staging source is not a regular file
                or changes before its descriptor is opened.
            OSError: If metadata lookup, mode adjustment, close, or replacement
                fails.

        Side Effects:
            Applies the final access mode to the completed source and atomically
            moves it to the destination. The caller retains cleanup ownership
            when publication fails.
        """

        destination = Path(destination)
        source = Path(source)
        destination.parent.mkdir(parents=True, exist_ok=True)

        source_stat = source.lstat()
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError("Collector staging source must be a regular file")

        existing_mode = None
        try:
            destination_stat = destination.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISREG(destination_stat.st_mode):
                existing_mode = stat.S_IMODE(destination_stat.st_mode)

        descriptor = os.open(
            source,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        try:
            opened_stat = os.fstat(descriptor)
            if not stat.S_ISREG(opened_stat.st_mode) or (
                opened_stat.st_dev,
                opened_stat.st_ino,
            ) != (source_stat.st_dev, source_stat.st_ino):
                raise ValueError("Collector staging source changed before opening")
            os.fchmod(
                descriptor,
                existing_mode if existing_mode is not None else 0o644,
            )

        finally:
            os.close(descriptor)

        # Finish fallible descriptor cleanup before committing publication.
        # The caller-owned spool is on the output filesystem, so the remaining
        # operation is a single rename with its final permissions already set.
        os.replace(source, destination)

    @staticmethod
    def _safe_path_component(value: Any, fallback: str) -> str:
        """
        Return a filesystem-safe single path component.

        The implementation uses ``value`` and ``fallback`` to produce a
        filesystem-safe single path component. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.

        Args:
            value: Value evaluated while performing filesystem-safe single path
                component.
            fallback: Text supplied as fallback in the format accepted by this
                function.

        Returns:
            The canonical filesystem-safe path component, or ``fallback`` when
            the supplied value has no usable characters.
        """
        return run_tree_path_component(value, fallback)

    @classmethod
    def _safe_output_filename(cls, filename: Any) -> str:
        """
        Return a safe filename, sanitizing each path segment independently.

        Allows collector writers to nest output under subdirectories (e.g.
        ``diagnostic/request_x.json``) without permitting traversal outside the
        collector directory - each segment goes through the same
        single-component sanitization as dut_id/group/collector_id.

        Args:
            filename: Filename consumed while the function attempts to produce a
                safe filename, sanitizing each path segment independently.

        Returns:
            The canonical safe output filename.
        """
        text = str(filename or "").replace("\\", "/")
        segments = [part for part in text.split("/") if part not in ("", ".")]
        if not segments:
            return "output.txt"
        *dirs, name = segments
        safe_name = cls._safe_path_component(name, "output.txt")
        safe_dirs = [cls._safe_path_component(part, "dir") for part in dirs]
        return str(Path(*safe_dirs, safe_name)) if safe_dirs else safe_name

    def _is_diagnostic_artifact_path(self, path_value: Any) -> bool:
        """
        Return whether a file is collector diagnostic metadata.

        The implementation uses ``path_value`` to determine whether a file is
        collector diagnostic metadata. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            path_value: Path value consumed while the function attempts to
                determine whether a file is collector diagnostic metadata.

        Returns:
            Whether a file is collector diagnostic metadata.
        """
        return (
            classify_artifact_path(path_value, bundle_root=self.base_log_dir)
            is ArtifactRole.DIAGNOSTIC
        )

    def _is_error_artifact_path(self, path_value: Any) -> bool:
        """
        Return whether a file belongs to the per-DUT error-log store.

        The implementation uses ``path_value`` to determine whether a file
        belongs to the per-DUT error-log store. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.

        Args:
            path_value: Path value consumed while the function attempts to
                determine whether a file belongs to the per-DUT error-log store.

        Returns:
            Whether a file belongs to the per-DUT error-log store.
        """
        return (
            classify_artifact_path(path_value, bundle_root=self.base_log_dir)
            is ArtifactRole.ERROR
        )

    def _is_primary_host_execution_ledger(
        self,
        path_value: Any,
        *,
        collector_id: str,
        collector_dir: Path,
    ) -> bool:
        """
        Return whether a Host ledger is an explicit primary-role exception.

        Host execution accounting deliberately lives below ``diagnostic/`` so
        command output bytes and secrets remain separated from collected data.
        The workbook contract nevertheless requires the bounded ledger itself
        to be a primary output. This exception is therefore confined to Host
        collectors, the canonical collector directory, and the reviewed ledger
        filename family; no other diagnostic artifact can cross roles.

        Args:
            path_value: Candidate path already resolved through the inventory
                boundary.
            collector_id: Stable collector identifier owning the candidate.
            collector_dir: Canonical directory for that collector.

        Returns:
            ``True`` only for an in-tree Host execution ledger.
        """

        if not str(collector_id).startswith("H"):
            return False
        candidate = Path(path_value)
        if not candidate.is_absolute():
            candidate = self.base_log_dir / candidate
        name = candidate.name
        if (
            re.fullmatch(
                r"host_execution_log(?:_[A-Za-z0-9._-]{1,128})?\.json",
                name,
            )
            is None
        ):
            return False
        try:
            resolved = candidate.resolve(strict=False)
            relative = resolved.relative_to(collector_dir.resolve(strict=False))
        except (OSError, RuntimeError, ValueError):
            return False
        return len(relative.parts) == 2 and relative.parts[0] == "diagnostic"

    def _collector_artifact_directory(
        self,
        dut_id: str,
        collector_id: str,
        *,
        group: Optional[str] = None,
        collector_name: Optional[str] = None,
        reuse_recorded: bool = True,
    ) -> Path:
        """
        Resolve the canonical, traversal-safe directory for a collector.

        The implementation uses ``dut_id``, ``collector_id``, ``group``,
        ``collector_name``, and ``reuse_recorded`` to resolve the canonical,
        traversal-safe directory for a collector.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            group: Optional group; ``None`` selects the function's default
                behavior.
            collector_name: Stable collector name used for lookup and
                operator-facing diagnostics.
            reuse_recorded: Whether reuse recorded is enabled or required for
                this operation.

        Returns:
            The validated collector artifact directory filesystem path.
        """
        key = f"{dut_id}:{collector_id}"
        recorded_dirs = getattr(self, "_collector_artifact_dirs", {})
        if reuse_recorded and key in recorded_dirs:
            return self._resolve_under_log_root(Path(recorded_dirs[key]))

        resolved_group = group or self._get_collector_group(collector_id)
        resolved_name = collector_name
        if resolved_name is None:
            resolved_name = collector_id
            if self.orchestrator:
                try:
                    collector_info = (
                        self.orchestrator.get_collector_info(collector_id) or {}
                    )
                    resolved_name = collector_info.get("name") or resolved_group
                except Exception:
                    resolved_name = resolved_group

        safe_dut_id = self._safe_path_component(dut_id, "dut")
        safe_group = self._safe_path_component(resolved_group, "collector")
        safe_collector_id = self._safe_path_component(collector_id, "collector")
        safe_collector_name = self._safe_path_component(
            resolved_name, safe_collector_id
        )
        service_prefix = safe_group.capitalize()
        return self._resolve_under_log_root(
            self.base_log_dir
            / safe_dut_id
            / safe_group
            / f"{service_prefix}_{safe_collector_id}_{safe_collector_name}"
        )

    def _resolve_inventory_path(self, path_value: Any, dut_id: str) -> str:
        """
        Resolve an existing artifact while preserving unresolved test inputs.

        The implementation uses ``path_value`` and ``dut_id`` to resolve an
        existing artifact while preserving unresolved test inputs. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Args:
            path_value: Path value consumed while the function attempts to
                resolve an existing artifact while preserving unresolved test
                inputs.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The canonical inventory path.
        """
        raw_value = str(path_value)
        path = Path(raw_value).expanduser()
        if path.is_absolute():
            try:
                return str(path.resolve(strict=False))
            except (OSError, RuntimeError):
                return str(path)

        dut_log_dir = self.get_dut_log_dir(dut_id)
        candidates = (
            dut_log_dir / path,
            self.base_log_dir / path,
            path,
        )
        for candidate in candidates:
            try:
                if candidate.exists():
                    return str(candidate.resolve(strict=False))
            except OSError:
                continue
        return raw_value

    def _bundle_relative_file_inventory(
        self, inventory: Dict[str, List[str]], dut_id: str
    ) -> Dict[str, List[str]]:
        """
        Normalize a collector inventory into the bundle path namespace.

        The implementation uses ``inventory`` and ``dut_id`` to normalize a
        collector inventory into the bundle path namespace. The source value
        keeps its ownership while the normalized representation is returned
        separately.

        Args:
            inventory: Mapping supplying fields for collector inventory into the
                bundle path namespace.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing the ``output_files``, ``diagnostic_files``,
            ``error_files``, and ``all_files`` fields.
        """
        safe_dut_id = self._safe_path_component(dut_id, "dut")

        def normalize(values: Any) -> List[str]:
            """
            Normalize the supplied value.

            After applying local validation, the function forwards ``values`` to
            ``normalize_artifact_file_list`` and preserves its return and
            exception contract. The source value keeps its ownership while the
            normalized representation is returned separately.

            Args:
                values: Values consumed while the function attempts to normalize
                    the supplied value.

            Returns:
                The result returned in operation-defined order.
            """
            return normalize_artifact_file_list(
                values,
                self.base_log_dir,
                dut_id=safe_dut_id,
            )

        primary = normalize(inventory.get("output_files", []))
        diagnostics = normalize(inventory.get("diagnostic_files", []))
        errors = normalize(inventory.get("error_files", []))
        return {
            "output_files": primary,
            "diagnostic_files": diagnostics,
            "error_files": errors,
            "all_files": list(dict.fromkeys(primary + diagnostics + errors)),
        }

    def _bundle_relative_capture_metadata(
        self, metadata: Any, dut_id: str
    ) -> Dict[str, Any]:
        """
        Normalize only the explicit capture artifact binding for status.

        The implementation uses ``metadata`` and ``dut_id`` to normalize only
        the explicit capture artifact binding for status. The source value keeps
        its ownership while the normalized representation is returned
        separately.

        Args:
            metadata: Metadata object whose ``get`` state is read while
                performing only the explicit capture artifact binding for
                status.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing bundle relative capture metadata.
        """

        if not isinstance(metadata, dict):
            return {}
        normalized = dict(metadata)
        artifact_path = metadata.get("artifact_path")
        normalized_paths = normalize_artifact_file_list(
            [artifact_path] if artifact_path else [],
            self.base_log_dir,
            dut_id=self._safe_path_component(dut_id, "dut"),
        )
        normalized["artifact_path"] = (
            normalized_paths[0] if len(normalized_paths) == 1 else ""
        )
        return normalized

    def _bundle_relative_artifact_timings(
        self, artifact_timings: Any, dut_id: str
    ) -> List[Dict[str, Any]]:
        """
        Normalize timed artifact references and omit unsafe entries.

        After applying local validation, the function forwards
        ``artifact_timings`` and ``dut_id`` to ``normalize_artifact_timings``
        and preserves its return and exception contract. The source value keeps
        its ownership while the normalized representation is returned
        separately.

        Args:
            artifact_timings: Artifact timings consumed while the function
                attempts to normalize timed artifact references and omit unsafe
                entries.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The bundle relative artifact timings returned in operation-defined
            order.
        """
        return normalize_artifact_timings(
            artifact_timings,
            self.base_log_dir,
            dut_id=self._safe_path_component(dut_id, "dut"),
        )

    @staticmethod
    def _group_inventory_files(files: List[str]) -> Dict[str, List[str]]:
        """
        Group an inventory by parent directory for discovered_files.

        The implementation uses ``files`` to group an inventory by parent
        directory for discovered_files.

        Args:
            files: Filesystem locations processed in caller-provided order.

        Returns:
            The validated ``grouped``.
        """
        grouped: Dict[str, List[str]] = {}
        for file_path in files:
            parent = str(Path(file_path).parent)
            grouped.setdefault(parent, [])
            if file_path not in grouped[parent]:
                grouped[parent].append(file_path)
        return grouped

    def _inventory_lexical_path_keys(
        self,
        path_value: Any,
        dut_id: str,
    ) -> set[str]:
        """
        Return lexical absolute candidates for one inventory path value.

        Managed-publication exclusions bind the output name, not whichever
        inode or symlink target later occupies it. Absolute values therefore
        remain unresolved. Relative values are compared in both namespaces
        accepted by the inventory resolver: the DUT root and the run root.

        Args:
            path_value: Candidate inventory path in absolute, DUT-relative, or
                run-relative form.
            dut_id: Stable DUT identifier selecting the relative namespace.

        Returns:
            Lexically normalized absolute keys, or an empty set for an invalid
            path value.
        """

        if not isinstance(path_value, (str, os.PathLike)):
            return set()
        try:
            raw_path = os.fspath(path_value)
        except (TypeError, ValueError, OSError):
            return set()
        if not isinstance(raw_path, str) or not raw_path:
            return set()
        if os.path.isabs(raw_path):
            candidates = (raw_path,)
        else:
            safe_dut_id = self._safe_path_component(dut_id, "dut")
            candidates = (
                os.path.join(os.fspath(self.base_log_dir), safe_dut_id, raw_path),
                os.path.join(os.fspath(self.base_log_dir), raw_path),
            )
        try:
            return {
                os.path.abspath(os.path.normpath(candidate)) for candidate in candidates
            }
        except (TypeError, ValueError, OSError):
            return set()

    def exclude_collector_file_inventory_paths(
        self,
        dut_id: str,
        collector_id: str,
        paths: Any,
    ) -> None:
        """
        Permanently exclude exact names from one collector's run inventory.

        This run-scoped authority survives cache replacement and physical
        ``refresh=True`` walks. It is used when a managed publication did not
        reach durable adoption and exact inode rollback could not be trusted;
        a later file at the same name must not be advertised as that artifact.

        Args:
            dut_id: Stable DUT identifier owning the excluded publication.
            collector_id: Stable collector identifier owning the publication.
            paths: One path or a bounded collection of exact publication paths.

        Side Effects:
            Adds lexical path keys to the logger's run-scoped exclusion map.
        """

        path_values = (
            paths if isinstance(paths, (list, tuple, set, frozenset)) else (paths,)
        )
        excluded_keys: set[str] = set()
        for path_value in path_values:
            excluded_keys.update(self._inventory_lexical_path_keys(path_value, dut_id))
        if not excluded_keys:
            return
        key = f"{dut_id}:{collector_id}"
        self._collector_file_inventory_exclusions.setdefault(key, set()).update(
            excluded_keys
        )

    def managed_publication_delivery_exclusion_paths(self) -> tuple[str, ...]:
        """
        Return bounded lexical exclusion names inside the current run root.

        The returned names remain authoritative even while absent so the ZIP
        transaction can reject a replacement created after an earlier loose
        delivery check. Paths are normalized lexically without resolving an
        occupant or transferring ownership of it.

        Returns:
            Sorted absolute exclusion names inside the run root.

        Raises:
            RuntimeError: If the registry is malformed or an exclusion escapes
                the run root.
        """

        registry = getattr(self, "_collector_file_inventory_exclusions", {})
        if not isinstance(registry, dict) or not registry:
            return ()
        try:
            run_root = os.path.abspath(os.path.normpath(os.fspath(self.base_log_dir)))
        except (TypeError, ValueError, OSError) as error:
            raise RuntimeError(
                "Managed publication delivery root is unavailable"
            ) from error

        excluded_keys: set[str] = set()
        for registered in registry.values():
            if not isinstance(registered, (set, frozenset)):
                raise RuntimeError(
                    "Managed publication exclusion registry is malformed"
                )
            for raw_path in registered:
                try:
                    candidate = os.path.abspath(os.path.normpath(os.fspath(raw_path)))
                    if (
                        candidate == run_root
                        or os.path.commonpath((run_root, candidate)) != run_root
                    ):
                        raise RuntimeError(
                            "Managed publication exclusion escaped the run root"
                        )
                except RuntimeError:
                    raise
                except (TypeError, ValueError, OSError) as error:
                    raise RuntimeError(
                        "Managed publication exclusion is malformed"
                    ) from error
                excluded_keys.add(candidate)
        return tuple(sorted(excluded_keys))

    def validate_managed_publication_exclusions_for_delivery(self) -> None:
        """
        Reject delivery while an excluded managed publication name exists.

        Inventory exclusions intentionally bind a lexical output name after a
        nondurable managed publication cannot be removed with inode certainty.
        A final ZIP or loose-directory delivery must honor the same authority;
        otherwise a replacement inode could bypass status metadata and enter
        the delivered bundle. This check never resolves, removes, or relabels
        the occupant because that inode is not owned by the failed transaction.

        Raises:
            RuntimeError: If an exclusion is malformed, escapes the run root,
                cannot be inspected, or still has a physical occupant.
        """

        retained_count = 0
        for candidate in self.managed_publication_delivery_exclusion_paths():
            try:
                os.lstat(candidate)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise RuntimeError(
                    "Managed publication exclusion could not be verified"
                ) from error
            retained_count += 1

        if retained_count:
            raise RuntimeError(
                "Run output retains an excluded managed publication name"
            )

    def reconcile_collector_file_inventory(
        self,
        dut_id: str,
        collector_id: str,
        known_files: Optional[List[Any]] = None,
        *,
        refresh: bool = True,
    ) -> Dict[str, List[str]]:
        """
        Build a complete collector inventory from known and physical files.

        ``output_files`` intentionally contains only primary collector output.
        Diagnostic request/poll evidence and partial/error logs remain explicit
        without being allowed to turn an otherwise-empty collector into one with
        primary data.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            known_files: Optional known files; ``None`` selects the function's
                default behavior.
            refresh: Whether refresh is enabled or required for this operation.

        Returns:
            The validated ``inventory``.
        """
        key = f"{dut_id}:{collector_id}"
        candidates: List[Any] = list(known_files or [])
        exclusion_registry = getattr(
            self,
            "_collector_file_inventory_exclusions",
            {},
        )
        registered_exclusions = (
            exclusion_registry.get(key, set())
            if isinstance(exclusion_registry, dict)
            else set()
        )
        excluded_keys = (
            set(registered_exclusions)
            if isinstance(registered_exclusions, (set, frozenset))
            else set()
        )
        inventories = getattr(self, "_collector_file_inventories", None)
        if not isinstance(inventories, dict):
            inventories = {}
            self._collector_file_inventories = inventories
        # A full recursive walk is intentionally cached. Finalization writes the
        # same inventory to several metadata surfaces; repeating the walk for a
        # large dump can materially inflate the collector's measured duration.
        # Callers that just finished another hook pass request an explicit
        # refresh, while metadata-only rewrites consume the cached inventory.
        previous = inventories.get(key, {})
        if not refresh:
            candidates.extend(previous.get("all_files", []))

        collector_dir = self._collector_artifact_directory(dut_id, collector_id)
        if refresh and collector_dir.is_dir():
            for path in sorted(collector_dir.rglob("*")):
                if not path.is_file():
                    continue
                # status.json is the inventory envelope, not collected output.
                if path == collector_dir / "status.json":
                    continue
                candidates.append(path)

        # Error evidence is deliberately outside the collector tree.  Match a
        # collector-id boundary so R1 never absorbs R10's error log.
        error_dir = self.get_dut_log_dir(dut_id) / "error-logs"
        safe_collector_id = self._safe_path_component(collector_id, collector_id)
        if error_dir.is_dir():
            candidates.extend(sorted(error_dir.glob(f"{safe_collector_id}_error.log")))
            candidates.extend(
                sorted(error_dir.glob(f"{safe_collector_id}_*_error.log"))
            )

        primary_files: List[str] = []
        diagnostic_files: List[str] = []
        error_files: List[str] = []
        seen = set()
        status_path = (collector_dir / "status.json").resolve(strict=False)
        log_root = self.base_log_dir.resolve(strict=False)
        for candidate in candidates:
            if candidate in (None, ""):
                continue
            if excluded_keys and (
                self._inventory_lexical_path_keys(candidate, dut_id) & excluded_keys
            ):
                continue
            resolved = self._resolve_inventory_path(candidate, dut_id)
            if excluded_keys and (
                self._inventory_lexical_path_keys(resolved, dut_id) & excluded_keys
            ):
                continue
            identity = resolved
            try:
                candidate_path = Path(resolved)
                if candidate_path.is_absolute():
                    canonical_path = candidate_path.resolve(strict=False)
                    identity = str(canonical_path)
                    if canonical_path == status_path:
                        continue
                    if refresh:
                        try:
                            canonical_path.relative_to(log_root)
                        except ValueError:
                            pass
                        else:
                            # Authoritative refreshes describe physical run
                            # artifacts. Do not resurrect an in-root file that
                            # a previous result listed but has since been moved
                            # or deleted. External unresolved references retain
                            # the long-standing compatibility behavior.
                            if not canonical_path.is_file():
                                continue
            except (OSError, RuntimeError):
                pass
            if identity in seen:
                continue
            seen.add(identity)

            if self._is_error_artifact_path(resolved):
                error_files.append(resolved)
            elif self._is_primary_host_execution_ledger(
                resolved,
                collector_id=collector_id,
                collector_dir=collector_dir,
            ):
                primary_files.append(resolved)
            elif self._is_diagnostic_artifact_path(resolved):
                diagnostic_files.append(resolved)
            else:
                primary_files.append(resolved)

        inventory = {
            "output_files": primary_files,
            "diagnostic_files": diagnostic_files,
            "error_files": error_files,
            "all_files": primary_files + diagnostic_files + error_files,
        }
        inventories[key] = inventory
        return inventory

    def _resolve_under_log_root(self, path: Path) -> Path:
        """
        Resolve a path and ensure it remains under the logger root.

        The implementation uses ``path`` to resolve a path and ensure it remains
        under the logger root. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. If the function
        cannot resolve a path and ensure it remains under the logger root, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The validated ``resolved``.

        Raises:
            ValueError: If refusing to write outside log directory: ``path``.
        """
        base = self.base_log_dir.resolve()
        resolved = path.resolve()
        try:
            resolved.relative_to(base)
        except ValueError as exc:
            raise ValueError(
                f"Refusing to write outside log directory: {path}"
            ) from exc
        return resolved

    def _emergency_file_cleanup(self) -> None:
        """
        Called by atexit to ensure file handles are closed on unexpected exit.

        The implementation uses current instance state to called by atexit to
        ensure file handles are closed on unexpected exit.
        """
        for dut_id, handle in getattr(self, "dut_runtime_files", {}).items():
            try:
                if handle and not handle.closed:
                    handle.close()
            except Exception:
                pass
        for attr in ("runtime_file_handle", "error_file_handle"):
            handle = getattr(self, attr, None)
            if handle and hasattr(handle, "closed") and not handle.closed:
                try:
                    handle.close()
                except Exception:
                    pass

    def __del__(self) -> None:
        """
        Emergency cleanup of file handles if stop() wasn't called.

        The implementation uses current instance state to emergency cleanup of
        file handles if stop() wasn't called.
        """
        self._emergency_file_cleanup()

    async def start(self) -> None:
        """
        Start the global runtime log and capture stdout and stderr.

        The method creates the root runtime and error files, writes the cached
        tool build identity before any redirected output, and then installs the
        stream capture handlers. Repeated calls are idempotent while the
        runtime file remains open.
        """
        async with self.runtime_lock:
            if self.runtime_file_handle is None:
                # Create runtime log file with new name
                runtime_file = self.base_log_dir / ".nvdebug_stdout.log"
                self.runtime_file_handle = open(runtime_file, "w")

                # Create error log file
                error_file = self.base_log_dir / "error.log"
                self.error_file_handle = open(error_file, "w")

                # Write ASCII header first (before stream capture)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                header_lines = [
                    ASCII_HEADER,
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] {'=' * 80}",
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] NVDebug Tool - Runtime Log",
                    *self._runtime_identity_header_lines(
                        timestamp=timestamp,
                        component="AsyncSafeLogger",
                    ),
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] Started at: {datetime.now().isoformat()}",
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] {'=' * 80}",
                ]

                for line in header_lines:
                    self.runtime_file_handle.write(line + "\n")
                self.runtime_file_handle.flush()

                # Setup stdout/stderr capture after writing header
                await self._setup_stream_capture()

    async def _setup_stream_capture(self) -> None:
        """
        Setup stdout/stderr capture.

        Configures logging handlers and redirects stdout/stderr to log files.
        """
        # Create loggers for stdout/stderr
        stdout_logger = logging.getLogger("stdout")
        stderr_logger = logging.getLogger("stderr")

        self._remove_stale_capture_handlers(stdout_logger)
        self._remove_stale_capture_handlers(stderr_logger)

        # The root/module loggers can ultimately write through these capture
        # streams. Sanitize the fully formatted record at this final sink so
        # %-arguments and exception tracebacks cannot bypass write-time
        # redaction.
        stdout_handler = _SanitizingCaptureHandler(self.runtime_file_handle, self)
        stderr_handler = _SanitizingCaptureHandler(self.runtime_file_handle, self)
        stdout_handler._nvdebug_capture_handler = True
        stderr_handler._nvdebug_capture_handler = True

        # Set formatters
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
        )
        stdout_handler.setFormatter(formatter)
        stderr_handler.setFormatter(formatter)

        # Setup loggers
        stdout_logger.addHandler(stdout_handler)
        stderr_logger.addHandler(stderr_handler)
        stdout_logger.setLevel(logging.INFO)
        stderr_logger.setLevel(logging.ERROR)
        self._stdout_capture_handler = stdout_handler
        self._stderr_capture_handler = stderr_handler

        # Store original streams
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr

        # Create stream redirectors with original streams
        self.stdout_logger = StreamToLogger(
            stdout_logger, logging.INFO, self.original_stdout
        )
        self.stderr_logger = StreamToLogger(
            stderr_logger, logging.ERROR, self.original_stderr
        )

        # Redirect streams
        sys.stdout = self.stdout_logger
        sys.stderr = self.stderr_logger

    @staticmethod
    def _remove_stale_capture_handlers(target_logger: logging.Logger) -> None:
        """
        Remove old nvdebug stream-capture handlers backed by closed streams.

        The implementation uses ``target_logger`` to remove old nvdebug
        stream-capture handlers backed by closed streams.

        Args:
            target_logger: Sanitized logging interface used for operator-visible
                diagnostics.
        """
        for handler in list(target_logger.handlers):
            if not getattr(handler, "_nvdebug_capture_handler", False):
                continue
            stream = getattr(handler, "stream", None)
            if stream is not None and not getattr(stream, "closed", False):
                continue
            target_logger.removeHandler(handler)
            handler.close()

    def _remove_capture_handler(
        self, target_logger: logging.Logger, handler: Optional[logging.Handler]
    ) -> None:
        """
        Detach the capture handler from every logger that owns it.

        The implementation uses ``target_logger`` and ``handler`` to detach the
        capture handler from every logger that owns it.

        Args:
            target_logger: Sanitized logging interface used for operator-visible
                diagnostics.
            handler: Handler object whose ``close`` state is read while
                performing detach the capture handler from every logger that
                owns it.
        """
        if handler is None:
            return
        if handler in target_logger.handlers:
            target_logger.removeHandler(handler)
        handler.close()

    async def stop(self) -> None:
        """
        Stop the logging system and restore stdout/stderr.

        Closes all log files, restores streams, and writes footers.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to stop the logging system and restore stdout/stderr.
        """
        async with self.runtime_lock:
            dut_runtime_failure: Optional[Exception] = None

            # Close per-DUT runtime files
            for dut_id, dut_runtime_handle in self.dut_runtime_files.items():
                try:
                    # Check if "Completed at:" timestamp was already written
                    # (to avoid duplicates when cleanup writes timestamps early)
                    dut_log_dir = self.dut_log_dirs.get(dut_id) or self.get_dut_log_dir(
                        dut_id
                    )
                    log_path = dut_log_dir / "nvdebug_runtime_output.txt"
                    timestamp_already_written = False
                    if log_path.exists():
                        try:
                            with open(log_path, "r", encoding="utf-8") as f:
                                content = f.read()
                                if "Completed at:" in content:
                                    timestamp_already_written = True
                        except Exception:
                            pass

                    # Only write footer if not already written
                    if not timestamp_already_written:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                        footer_lines = [
                            f"[{timestamp}] [INFO] [DUT:{dut_id}] {'=' * 80}",
                            f"[{timestamp}] [INFO] [DUT:{dut_id}] DUT Runtime Log - {dut_id} - Completed",
                            f"[{timestamp}] [INFO] [DUT:{dut_id}] Completed at: {datetime.now().isoformat()}",
                            f"[{timestamp}] [INFO] [DUT:{dut_id}] {'=' * 80}",
                        ]

                        for line in footer_lines:
                            dut_runtime_handle.write(line + "\n")
                        dut_runtime_handle.flush()
                except Exception as error:
                    if dut_runtime_failure is None:
                        dut_runtime_failure = error
                finally:
                    try:
                        dut_runtime_handle.close()
                    except Exception as error:
                        if dut_runtime_failure is None:
                            dut_runtime_failure = error

            # Restore original streams
            if self.original_stdout:
                sys.stdout = self.original_stdout
            if self.original_stderr:
                sys.stderr = self.original_stderr

            # Flush and close loggers
            if self.stdout_logger:
                self.stdout_logger.flush()
            if self.stderr_logger:
                self.stderr_logger.flush()

            # Write footer (directly since we already have the lock)
            if (
                self.runtime_file_handle is not None
                and not self.runtime_file_handle.closed
            ):
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                footer_lines = [
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] {'=' * 80}",
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] Completed at: {datetime.now().isoformat()}",
                    f"[{timestamp}] [INFO] [AsyncSafeLogger] {'=' * 80}",
                ]
                for line in footer_lines:
                    self.runtime_file_handle.write(line + "\n")
                self.runtime_file_handle.flush()

            self._remove_capture_handler(
                logging.getLogger("stdout"), self._stdout_capture_handler
            )
            self._remove_capture_handler(
                logging.getLogger("stderr"), self._stderr_capture_handler
            )
            self._stdout_capture_handler = None
            self._stderr_capture_handler = None

            # Close file handles
            if (
                self.runtime_file_handle is not None
                and not self.runtime_file_handle.closed
            ):
                self.runtime_file_handle.close()
                self.runtime_file_handle = None

            if self.error_file_handle is not None and not self.error_file_handle.closed:
                self.error_file_handle.close()
                self.error_file_handle = None

            if dut_runtime_failure is not None:
                raise dut_runtime_failure

    async def write_dut_metadata(self, dut_id: str, metadata: Dict[str, Any]) -> None:
        """
        Merge DUT lifecycle metadata under directory ownership and publish atomically.

        Retain the directory lock across the existing-document read and complete
        replacement so cooperating processes cannot discard each other's fields.
        Cancellation joins admitted filesystem work before releasing ownership.

        Args:
            dut_id: Declared DUT selecting its metadata directory.
            metadata: Payload fields to merge with the existing DUT document.

        Raises:
            OSError: If pinning, reading or atomic publication fails.
            TimeoutError: If another process holds the publication lock too long.
            asyncio.CancelledError: After admitted metadata work has been joined.

        Side Effects:
            Creates the selected metadata parent off the event loop and replaces
            complete bytes while preserving mode, lifecycle fields and merge data.
        """
        dut_dir = (
            self.base_log_dir / run_tree_path_component(dut_id, "dut") / ".metadata"
        )
        metadata_file = dut_dir / "metadata.json"
        try:
            async with self._get_lock_for_path(metadata_file):
                await run_managed_filesystem_operation(dut_dir.mkdir, 0o777, True, True)
                async with async_report_publication_lock(dut_dir) as publication_lock:
                    await run_managed_filesystem_operation(
                        self._persist_dut_metadata, dut_id, metadata, publication_lock
                    )
        except Exception as error:
            try:
                await self.write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "AsyncSafeLogger",
                    f"Failed to write DUT metadata for {dut_id}: {error}",
                )
            except Exception:
                pass
            raise

    def _persist_dut_metadata(
        self,
        dut_id: str,
        metadata: Dict[str, Any],
        publication_lock: PinnedDirectoryLock,
    ) -> None:
        """
        Read, merge and atomically replace one pinned DUT metadata document.

        Filesystem failures leave the previous complete document available.
        Malformed JSON retains the existing rebuild behavior, while lifecycle
        projection continues to preserve sanitization and retained-bundle state.

        Args:
            dut_id: Declared DUT used for configuration and lifecycle projection.
            metadata: New payload fields supplied by the asynchronous owner.
            publication_lock: Directory lock retained until this worker finishes.

        Raises:
            OSError: If the bounded existing-file read or publication fails.

        Side Effects:
            Preserves earlier payload fields and sanitization lifecycle metadata.
            Invalid JSON may be rebuilt, but filesystem read errors are propagated.
        """
        raw = read_locked_bytes(
            publication_lock,
            "metadata.json",
            max_bytes=MAX_LOG_FILE_SIZE_MB * 1024 * 1024,
        )
        existing_payload = {}
        existing_lifecycle = {}
        if raw.strip():
            try:
                existing_data = json.loads(raw)
                existing_payload = existing_data.get("payload", {})
                existing_lifecycle = existing_data.get("metadata", {})
            except (ValueError, AttributeError, TypeError):
                existing_payload = {}
                existing_lifecycle = {}
        lifecycle_metadata = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
        if self._get_tool_config_value("dry_run", False):
            lifecycle_metadata.update(self._dry_run_lifecycle_metadata(dut_id=dut_id))
        payload = {
            "metadata": lifecycle_metadata,
            "payload": {**existing_payload, **metadata},
        }
        payload["metadata"].update(
            self._sanitization_lifecycle_metadata(existing_lifecycle)
        )
        payload["metadata"].update(self._retained_bundle_metadata())
        atomic_publish_locked_bytes(
            publication_lock,
            "metadata.json",
            safe_json_dumps(payload, indent=4).encode("utf-8"),
        )

    async def write_collector_status_file(
        self,
        collector_id: str,
        dut_id: str,
        status: str,
        reason: str,
        *,
        failure_category: Optional[str] = None,
        refresh_inventory: bool = True,
        authoritative_projection: bool = False,
    ) -> None:
        """
        Publish one complete collector status without blocking on durability.

        Build the authoritative metadata on the owning event loop, then freeze
        its document before worker admission. A shared path lock orders writes
        to the same collector. The bounded worker sanitizes, atomically replaces
        and syncs the status artifact; cancellation joins that worker before
        releasing the path lock.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            status: Text supplied as status in the format accepted by this
                function.
            reason: Text supplied as reason in the format accepted by this
                function.
            failure_category: Optional failure category; ``None`` selects the
                function's default behavior.
            refresh_inventory: Whether refresh inventory is enabled or required
                for this operation.
            authoritative_projection: Whether authoritative projection is
                enabled or required for this operation.
        """
        sanitize = getattr(getattr(self, "sanitizer", None), "sanitize", None)
        reason = sanitize_terminal_collector_reason(
            status,
            reason,
            sanitizer=sanitize if callable(sanitize) else None,
        )
        await self.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AsyncSafeLogger",
            f"write_collector_status_file called for {collector_id} on {dut_id} with status {status}",
        )

        try:
            # Get collector info for command details
            collector_info = None
            command_info = {}
            if hasattr(self, "orchestrator") and self.orchestrator:
                collector_info = self.orchestrator.get_collector_info(collector_id)

                # Extract command information from collector definition
                if collector_info and "stages" in collector_info:
                    execution_stage = collector_info.get("stages", {}).get(
                        "execution", {}
                    )
                    if "hooks" in execution_stage:
                        for hook in execution_stage["hooks"]:
                            if "method" in hook:
                                command_info["method"] = hook["method"]
                            if "params" in hook:
                                # Clean up params to avoid circular references and verbose output
                                params = hook["params"]
                                if isinstance(params, dict):
                                    # Keep only essential params, remove circular references
                                    clean_params = {}
                                    for key, value in params.items():
                                        if key in [
                                            "uri",
                                            "command",
                                            "function_tag",
                                            "collection_name",
                                            "error_message",
                                        ]:
                                            clean_params[key] = value
                                        elif key == "output_pattern":
                                            command_info["output_file"] = value
                                    command_info["params"] = clean_params
                                else:
                                    command_info["params"] = {}
                            if "output_pattern" in hook:
                                command_info["output_file"] = hook["output_pattern"]
                            break

            # Get output files from stored collector results
            output_files = []
            result_key = f"{dut_id}:{collector_id}"
            if result_key in self.collector_results:
                output_files = self.collector_results[result_key].get(
                    "output_files", []
                )
                # Remove duplicates while preserving order
                seen = set()
                unique_output_files = []
                for file_path in output_files:
                    if file_path not in seen:
                        seen.add(file_path)
                        unique_output_files.append(file_path)
                output_files = unique_output_files

            # Get detailed collector result information
            result_key = f"{dut_id}:{collector_id}"
            collector_result = self.collector_results.get(result_key, {})

            known_inventory_files: List[Any] = list(output_files)
            for field_name in (
                "diagnostic_files",
                "error_files",
                "all_files",
            ):
                field_files = collector_result.get(field_name, [])
                if isinstance(field_files, list):
                    known_inventory_files.extend(field_files)
            result_discovered_files = collector_result.get("discovered_files", {})
            if isinstance(result_discovered_files, dict):
                for files in result_discovered_files.values():
                    if isinstance(files, list):
                        known_inventory_files.extend(files)

            file_inventory = self.reconcile_collector_file_inventory(
                dut_id,
                collector_id,
                known_inventory_files,
                refresh=refresh_inventory,
            )
            status_inventory = self._bundle_relative_file_inventory(
                file_inventory,
                dut_id,
            )
            # Preserve the long-standing output_files key as the primary-data
            # contract.  Diagnostic evidence and partial error logs have their
            # own fields below.
            output_files = status_inventory["output_files"]
            discovered_files = self._group_inventory_files(
                status_inventory["all_files"]
            )

            # Debug logging to see what context information we have
            await self.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AsyncLogger",
                f"Collector result for {collector_id}: "
                f"{summarize_result_for_log(collector_result)}",
            )

            # Stage contexts can contain more complete accounting than the
            # aggregate context (for example, validation may leave 1/1 at the
            # top level while execution correctly reports 1/2).
            collector_context = collector_result.get("context", {})
            outcome_details = extract_collector_outcome_details(
                collector_context,
                sanitizer=sanitize if callable(sanitize) else None,
            )
            if status not in {"degraded", "partial", "error"}:
                outcome_details = None
            warning_details = (
                list(outcome_details.get("messages", []))
                if outcome_details is not None
                else []
            )
            (
                successful_operations,
                total_operations,
                error_messages,
            ) = self._extract_operation_accounting(
                collector_context,
                status,
                collector_result.get("reason", reason),
            )
            execution_time = collector_result.get("execution_time", None)
            command_execution = collector_result.get("context", {}).get(
                "command_execution"
            )
            request_response_capture = collector_result.get("context", {}).get(
                "request_response_capture"
            )
            request_response_logs = collector_result.get("context", {}).get(
                "request_response_logs"
            )
            granular_timing: Dict[str, Any] = {}
            timing_manager = getattr(
                getattr(self, "orchestrator", None), "timing_manager", None
            )
            record_inventory = getattr(
                timing_manager, "record_artifact_inventory", None
            )
            if callable(record_inventory):
                record_inventory(
                    dut_id,
                    collector_id,
                    status_inventory["all_files"],
                )
            if timing_manager and hasattr(timing_manager, "get_collector_timing"):
                timing_candidate = timing_manager.get_collector_timing(
                    dut_id,
                    collector_id,
                )
                if isinstance(timing_candidate, dict):
                    granular_timing = normalize_timing_artifact_paths(
                        timing_candidate,
                        self.base_log_dir,
                        dut_id=self._safe_path_component(dut_id, "dut"),
                    )
                    execution_time = granular_timing.get(
                        "wall_clock_duration_seconds", execution_time
                    )

            # Debug logging to see what we extracted
            await self.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AsyncLogger",
                f"Extracted context for {collector_id}: "
                f"successful_operations={successful_operations}, "
                f"total_operations={total_operations}, "
                f"error_count={len(error_messages)}",
            )

            # A passed status correction is terminal.  Do not pair it with the
            # cached reason from the prior status (for example, a provisional
            # empty success later rejected by the catalog outcome policy).
            cached_status = collector_result.get("status")
            status_corrected = (
                cached_status is not None
                and str(getattr(cached_status, "value", cached_status)).strip().lower()
                != str(getattr(status, "value", status)).strip().lower()
            )

            # Use a same-status detailed reason from the collector result when
            # available; this preserves the long-standing compatibility path.
            detailed_reason = collector_result.get("reason", reason)
            if authoritative_projection or status_corrected:
                final_reason = reason
            elif detailed_reason and detailed_reason != "Completed successfully":
                final_reason = detailed_reason
            else:
                final_reason = reason
            final_reason = sanitize_terminal_collector_reason(
                status,
                final_reason,
                sanitizer=sanitize if callable(sanitize) else None,
            )
            category_source = failure_category
            if category_source is None and not authoritative_projection:
                category_source = collector_result.get("failure_category")
            if (
                category_source is None
                and not authoritative_projection
                and isinstance(collector_context, dict)
            ):
                category_source = collector_context.get("failure_category")
            if category_source is None and outcome_details is not None:
                category_source = outcome_details["category"]
            final_failure_category = normalize_collector_failure_category(
                status,
                category_source,
            )

            # Create comprehensive status.json structure
            status_data = {
                "collector_id": collector_id,
                "collector_name": (
                    collector_info.get("name", collector_id)
                    if collector_info
                    else collector_id
                ),
                "dut_id": dut_id,
                "timestamp": datetime.now().isoformat(),
                "status": status,
                "reason": final_reason,
                "failure_category": final_failure_category,
                "execution_summary": {
                    "successful_operations": successful_operations,
                    "total_operations": total_operations,
                    "success_rate": (
                        f"{successful_operations}/{total_operations}"
                        if total_operations > 0
                        else "0/0"
                    ),
                    "error_count": len(error_messages),
                    "warning_count": len(warning_details),
                    "execution_time_seconds": execution_time,
                },
                "error_details": error_messages if error_messages else [],
                "warning_details": warning_details,
                "stages": {},
                "output_files": output_files,
                "diagnostic_files": status_inventory["diagnostic_files"],
                "error_files": status_inventory["error_files"],
                "all_files": status_inventory["all_files"],
                "discovered_files": discovered_files,
                "collector_group": self._get_collector_group(collector_id),
                "collection_level": (
                    collector_info.get("collection_level", "unknown")
                    if collector_info
                    else "unknown"
                ),
                # These two fields are required by the collector-status v1
                # contract.  Keep a small compatibility projection here while
                # the operation graph remains canonical in timing.json.
                "timing": {
                    key: granular_timing.get(key)
                    for key in (
                        "collector_started_at",
                        "collector_ended_at",
                        "wall_clock_duration_seconds",
                        "wall_clock_is_authoritative",
                        "cumulative_operation_time_seconds",
                        "active_operation_union_seconds",
                        "overlapped_operation_time_seconds",
                        "unattributed_wall_time_seconds",
                        "event_counters",
                        "redfish_request_accounting",
                        "event_limits",
                    )
                    if key in granular_timing
                },
                "artifact_timings": [
                    {
                        key: item.get(key)
                        for key in (
                            "path",
                            "operation_id",
                            "measurement",
                            "measurement_quality",
                            "measurement_scope",
                            "shared_operation_artifact_count",
                            "shared_request_operation_count",
                            "started_at",
                            "ended_at",
                            "duration_seconds",
                            "size_bytes",
                            "status",
                        )
                        if key in item
                    }
                    for item in sorted(
                        (
                            item
                            for item in granular_timing.get("artifact_timings", [])
                            if isinstance(item, dict)
                            and isinstance(item.get("path"), str)
                        ),
                        key=lambda item: (
                            str(item.get("path", "")),
                            str(item.get("operation_id", "")),
                        ),
                    )[:MAX_STATUS_ARTIFACT_TIMING_ENTRIES]
                ],
            }
            if outcome_details is not None:
                status_data["outcome_details"] = outcome_details
            command_diagnostics = getattr(self, "_command_diagnostic_states", {}).get(
                (dut_id, collector_id)
            )
            if command_diagnostics is not None:
                status_data["command_diagnostics"] = dict(command_diagnostics)
            collector_budget = collector_context.get("collector_budget")
            if isinstance(collector_budget, dict):
                status_data["collector_budget"] = collector_budget
            attempt_policy = collector_context.get("attempt_policy")
            advanced_receipt = collector_context.get("advanced_managed_receipt")
            if advanced_receipt is not None:
                status_data["advanced_managed_receipt"] = (
                    project_advanced_managed_receipt(advanced_receipt)
                )
            if attempt_policy is not None:
                # Attempt receipts are correctness evidence. Project a strict,
                # path-free allowlist and fail status publication if the
                # transition record is internally inconsistent.
                status_data["attempt_policy"] = project_attempt_policy(attempt_policy)
            additive_attempts = collector_context.get("additive_attempts")
            if additive_attempts is not None:
                projected_additive_attempts = project_additive_attempts(
                    additive_attempts
                )
                if projected_additive_attempts:
                    status_data["additive_attempts"] = projected_additive_attempts
            budget_observation = collector_context.get("collector_budget_observation")
            if isinstance(budget_observation, dict):
                status_data["collector_budget_observation"] = budget_observation
            configured_retry_count = collector_context.get("configured_retry_count")
            if (
                isinstance(configured_retry_count, int)
                and not isinstance(configured_retry_count, bool)
                and configured_retry_count >= 0
            ):
                status_data["configured_retry_count"] = configured_retry_count
            timeout_classification = collector_context.get("timeout_classification")
            if isinstance(timeout_classification, str) and timeout_classification:
                status_data["timeout_classification"] = timeout_classification

            if (
                status == "skipped"
                and collector_context.get("intentional_evidence_only_skip") is True
            ):
                status_data["intentional_evidence_only_skip"] = True

            if command_execution:
                status_data["command_execution"] = command_execution
                status_data["context"] = {
                    "command_execution": copy.deepcopy(command_execution)
                }

            if request_response_capture:
                status_data["request_response_capture"] = (
                    self._bundle_relative_capture_metadata(
                        request_response_capture, dut_id
                    )
                )
            if isinstance(request_response_logs, dict):
                status_data["request_response_logs"] = {
                    str(key): self._bundle_relative_capture_metadata(value, dut_id)
                    for key, value in request_response_logs.items()
                    if isinstance(value, dict)
                }

            # Extract all stages and their commands from collector definition
            if collector_info and "stages" in collector_info:
                stage_names = list(collector_info["stages"])
                for stage_name, stage_data in collector_info["stages"].items():
                    stage_commands = []
                    if "hooks" in stage_data:
                        for hook in stage_data["hooks"]:
                            # Clean up params to avoid circular references and verbose output
                            params = hook.get("params", {})
                            if isinstance(params, dict):
                                clean_params = {}
                                for key, value in params.items():
                                    if key in [
                                        "uri",
                                        "command",
                                        "function_tag",
                                        "collection_name",
                                        "error_message",
                                        "skip_message",
                                    ]:
                                        clean_params[key] = value
                            else:
                                clean_params = {}

                            command_info = {
                                "method": hook.get("method", ""),
                                "params": clean_params,
                                "required": hook.get("required", False),
                            }
                            if "output_pattern" in hook:
                                command_info["output_file"] = hook["output_pattern"]
                            stage_commands.append(command_info)

                    stage_status = self._infer_stage_status(
                        stage_name,
                        stage_names,
                        status,
                        final_reason,
                        collector_context,
                    )

                    status_data["stages"][stage_name] = {
                        "commands": stage_commands,
                        "status": stage_status,
                        "command_count": len(stage_commands),
                        "required_commands": len(
                            [
                                cmd
                                for cmd in stage_commands
                                if cmd.get("required", False)
                            ]
                        ),
                    }

            # Create collector directory and status.json file
            group = self._get_collector_group(collector_id)
            collector_name = (
                collector_info.get("name", collector_id)
                if collector_info
                else collector_id
            )
            collector_dir = self._collector_artifact_directory(
                dut_id,
                collector_id,
                group=group,
                collector_name=collector_name,
            )
            status_file = collector_dir / "status.json"
            status_document = deepcopy(status_data)
            async with self._get_lock_for_path(status_file):
                await run_managed_filesystem_operation(
                    self._publish_collector_status_document,
                    status_file,
                    status_document,
                )

        except Exception as e:
            # Preserve collector context before failing required publication.
            try:
                await self.write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "AsyncSafeLogger",
                    f"Failed to write collector status file for {collector_id} on {dut_id}: {e}",
                )
            except Exception:
                pass
            raise

    def _publish_collector_status_document(
        self, destination: Path, document: Dict[str, Any]
    ) -> None:
        """
        Sanitize and durably publish a frozen status document in an owned worker.

        The existing atomic artifact writer keeps the previous complete status
        visible until replacement. Its staging file remains on the selected
        output filesystem. Syncing the parent preserves the status publisher's
        directory durability contract after atomic replacement.

        Args:
            destination: Collector status pathname validated by the caller.
            document: Detached metadata snapshot owned exclusively by this write.

        Raises:
            OSError: If staging, replacement, or file/directory durability fails.
            ValueError: If the document cannot pass the existing sanitizer.
        """

        prepared = safe_json_dumps(
            self._sanitize_collector_status_document(document), indent=2
        ).encode("utf-8")
        self._atomic_publish_collector_output(
            destination, prepared, inherit_creation_mode=True
        )
        descriptor = os.open(
            destination.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def is_capture_publication_durably_tracked(
        self,
        dut_id: str,
        collector_id: str,
        artifact_path: str,
        sha256: str,
        size_bytes: int,
        sanitization_policy_id: str,
        published_identity: tuple[int, int],
    ) -> bool:
        """
        Prove exact status metadata and exact published inode/content.

        The implementation uses ``dut_id``, ``collector_id``, ``artifact_path``,
        ``sha256``, and ``size_bytes`` to prove exact status metadata and exact
        published inode/content. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            artifact_path: filesystem location used as the artifact path for
                this operation.
            sha256: Text supplied as SHA-256 in the format accepted by this
                function.
            size_bytes: Numeric size bytes used while the operation performs
                bounded accounting.
            sanitization_policy_id: Stable sanitization policy identifier used
                to correlate configuration, logs, and results.
            published_identity: Entries supplied as ``published_identity``
                without transferring container ownership.

        Returns:
            Whether the prove exact status metadata and exact published
            inode/content operation succeeds.
        """

        max_status_bytes = 16 * 1024 * 1024
        flags_dir = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        flags_file = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW

        def read_exact(descriptor: int, size: int) -> Optional[bytes]:
            """
            Read exact.

            After applying local validation, the function forwards
            ``descriptor`` and ``size`` to ``join`` and preserves its return and
            exception contract. Parsing or I/O must finish before the validated
            representation is made available to the caller.

            Args:
                descriptor: Numeric descriptor used while the operation performs
                    bounded accounting.
                size: Numeric size used by the operation's bounded accounting.

            Returns:
                The bounded exact bytes, or ``None`` when the requested value is
                unavailable.
            """
            chunks: List[bytes] = []
            offset = 0
            while offset < size:
                chunk = os.pread(descriptor, min(64 * 1024, size - offset), offset)
                if not chunk:
                    return None
                chunks.append(chunk)
                offset += len(chunk)
            return b"".join(chunks)

        def open_pinned_directory(path: Path) -> tuple[int, tuple[int, int]]:
            """
            Open pinned directory.

            The implementation uses ``path`` to open pinned directory. If the
            function cannot open pinned directory, its exception reaches the
            caller instead of being converted into a successful result.

            Args:
                path: filesystem location used as the path for this operation.

            Returns:
                A tuple containing ``descriptor`` and ``identity`` in that
                order.

            Raises:
                OSError: If directory identity changed.
            """
            absolute = Path(os.path.abspath(os.fspath(path)))
            descriptor = os.open(absolute.anchor, flags_dir)
            try:
                for component in absolute.parts[1:]:
                    child = os.open(component, flags_dir, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = child
                descriptor_stat = os.fstat(descriptor)
                path_stat = os.lstat(absolute)
                identity = (descriptor_stat.st_dev, descriptor_stat.st_ino)
                if (
                    not stat.S_ISDIR(descriptor_stat.st_mode)
                    or stat.S_ISLNK(path_stat.st_mode)
                    or (path_stat.st_dev, path_stat.st_ino) != identity
                ):
                    raise OSError("directory identity changed")
                return descriptor, identity
            except BaseException:
                os.close(descriptor)
                raise

        base_root = Path(os.path.abspath(os.fspath(self.base_log_dir)))
        collector_dir = self._collector_artifact_directory(dut_id, collector_id)
        collector_dir = Path(os.path.abspath(os.fspath(collector_dir)))
        try:
            collector_relative = collector_dir.relative_to(base_root)
        except ValueError:
            return False
        if any(part in {"", ".", ".."} for part in collector_relative.parts):
            return False

        raw_artifact_path = os.fspath(artifact_path)
        artifact = Path(raw_artifact_path)
        absolute_artifact = Path(os.path.abspath(raw_artifact_path))
        if not artifact.is_absolute() or raw_artifact_path != str(absolute_artifact):
            return False
        try:
            artifact_relative = absolute_artifact.relative_to(collector_dir)
            bundle_relative = absolute_artifact.relative_to(base_root).as_posix()
        except ValueError:
            return False
        if (
            len(artifact_relative.parts) != 2
            or artifact_relative.parts[0] != "diagnostic"
            or artifact_relative.parts[1] in {"", ".", ".."}
        ):
            return False
        if (
            isinstance(size_bytes, bool)
            or not isinstance(size_bytes, int)
            or size_bytes < 0
            or not isinstance(sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", sha256)
            or not isinstance(sanitization_policy_id, str)
            or not sanitization_policy_id
            or not isinstance(published_identity, tuple)
            or len(published_identity) != 2
        ):
            return False

        base_descriptor = -1
        status_descriptor = -1
        try:
            base_descriptor, base_identity = open_pinned_directory(base_root)
            os.close(base_descriptor)
            base_descriptor = -1

            def open_collector() -> tuple[int, tuple[int, int]]:
                """
                Open collector.

                The implementation uses current instance state to open
                collector. If the function cannot open collector, its exception
                reaches the caller instead of being converted into a successful
                result.

                Returns:
                    A tuple containing ``descriptor`` and ``identity`` in that
                    order.

                Raises:
                    OSError: If output root identity changed; or collector
                        directory identity changed.
                """
                descriptor, observed_base = open_pinned_directory(base_root)
                if observed_base != base_identity:
                    os.close(descriptor)
                    raise OSError("output root identity changed")
                try:
                    for component in collector_relative.parts:
                        child = os.open(component, flags_dir, dir_fd=descriptor)
                        os.close(descriptor)
                        descriptor = child
                    descriptor_stat = os.fstat(descriptor)
                    identity = (descriptor_stat.st_dev, descriptor_stat.st_ino)
                    path_stat = os.lstat(collector_dir)
                    if (
                        not stat.S_ISDIR(descriptor_stat.st_mode)
                        or stat.S_ISLNK(path_stat.st_mode)
                        or (path_stat.st_dev, path_stat.st_ino) != identity
                    ):
                        raise OSError("collector directory identity changed")
                    return descriptor, identity
                except BaseException:
                    os.close(descriptor)
                    raise

            collector_descriptor, collector_identity = open_collector()
            try:
                status_descriptor = os.open(
                    "status.json", flags_file, dir_fd=collector_descriptor
                )
                status_path_stat = os.stat(
                    "status.json",
                    dir_fd=collector_descriptor,
                    follow_symlinks=False,
                )
            finally:
                os.close(collector_descriptor)
            status_stat = os.fstat(status_descriptor)
            status_identity = (status_stat.st_dev, status_stat.st_ino)
            if (
                not stat.S_ISREG(status_stat.st_mode)
                or status_identity != (status_path_stat.st_dev, status_path_stat.st_ino)
                or status_stat.st_size <= 0
                or status_stat.st_size > max_status_bytes
            ):
                return False
            status_bytes = read_exact(status_descriptor, status_stat.st_size)
            if status_bytes is None or len(status_bytes) != status_stat.st_size:
                return False
            status_digest = hashlib.sha256(status_bytes).digest()
            status_data = json.loads(status_bytes.decode("utf-8"))
            if not isinstance(status_data, dict):
                return False
            if (
                status_data.get("dut_id") != dut_id
                or status_data.get("collector_id") != collector_id
            ):
                return False
            diagnostic_files = status_data.get("diagnostic_files")
            all_files = status_data.get("all_files")
            if (
                not isinstance(diagnostic_files, list)
                or not isinstance(all_files, list)
                or bundle_relative not in diagnostic_files
                or bundle_relative not in all_files
            ):
                return False

            capture_entries: List[Dict[str, Any]] = []
            primary_entry = status_data.get("request_response_capture")
            if isinstance(primary_entry, dict):
                capture_entries.append(primary_entry)
            log_entries = status_data.get("request_response_logs")
            if isinstance(log_entries, dict):
                capture_entries.extend(
                    value for value in log_entries.values() if isinstance(value, dict)
                )
            matches = [
                entry
                for entry in capture_entries
                if entry.get("artifact_path") == bundle_relative
            ]
            if len(matches) != 1:
                return False
            binding = matches[0]
            if (
                binding.get("published") is not True
                or binding.get("sha256") != sha256
                or binding.get("size_bytes") != size_bytes
                or binding.get("sanitization_policy_id") != sanitization_policy_id
            ):
                return False

            collector_descriptor, observed_collector = open_collector()
            if observed_collector != collector_identity:
                os.close(collector_descriptor)
                return False
            diagnostic_descriptor = -1
            artifact_descriptor = -1
            diagnostic_identity: Optional[tuple[int, int]] = None
            try:
                diagnostic_descriptor = os.open(
                    "diagnostic", flags_dir, dir_fd=collector_descriptor
                )
                diagnostic_stat = os.fstat(diagnostic_descriptor)
                diagnostic_identity = (
                    diagnostic_stat.st_dev,
                    diagnostic_stat.st_ino,
                )
                os.close(collector_descriptor)
                collector_descriptor = -1
                artifact_descriptor = os.open(
                    artifact_relative.parts[1],
                    flags_file,
                    dir_fd=diagnostic_descriptor,
                )
                artifact_path_stat = os.stat(
                    artifact_relative.parts[1],
                    dir_fd=diagnostic_descriptor,
                    follow_symlinks=False,
                )
                artifact_stat = os.fstat(artifact_descriptor)
                expected_owner_uid = filesystem_owner_uid(
                    diagnostic_descriptor, observed_uid=artifact_stat.st_uid
                )
                artifact_stability = (
                    artifact_stat.st_size,
                    artifact_stat.st_nlink,
                    artifact_stat.st_mtime_ns,
                    artifact_stat.st_ctime_ns,
                )
                if (
                    not stat.S_ISREG(artifact_stat.st_mode)
                    or (artifact_stat.st_dev, artifact_stat.st_ino)
                    != published_identity
                    or (artifact_path_stat.st_dev, artifact_path_stat.st_ino)
                    != published_identity
                    or artifact_stat.st_uid != expected_owner_uid
                    or artifact_path_stat.st_uid != expected_owner_uid
                    or stat.S_IMODE(artifact_stat.st_mode) != 0o600
                    or stat.S_IMODE(artifact_path_stat.st_mode) != 0o600
                    or artifact_stat.st_size != size_bytes
                    or artifact_stat.st_nlink != 1
                ):
                    return False
                digest = hashlib.sha256()
                offset = 0
                while offset < size_bytes:
                    chunk = os.pread(
                        artifact_descriptor,
                        min(64 * 1024, size_bytes - offset),
                        offset,
                    )
                    if not chunk:
                        return False
                    digest.update(chunk)
                    offset += len(chunk)
                if digest.hexdigest() != sha256:
                    return False
                final_artifact_stat = os.fstat(artifact_descriptor)
                if (
                    (
                        final_artifact_stat.st_dev,
                        final_artifact_stat.st_ino,
                    )
                    != published_identity
                    or (
                        final_artifact_stat.st_size,
                        final_artifact_stat.st_nlink,
                        final_artifact_stat.st_mtime_ns,
                        final_artifact_stat.st_ctime_ns,
                    )
                    != artifact_stability
                    or (
                        not stat.S_ISREG(final_artifact_stat.st_mode)
                        or final_artifact_stat.st_uid != expected_owner_uid
                        or stat.S_IMODE(final_artifact_stat.st_mode) != 0o600
                    )
                ):
                    return False
                final_artifact_path_stat = os.stat(
                    artifact_relative.parts[1],
                    dir_fd=diagnostic_descriptor,
                    follow_symlinks=False,
                )
                if (
                    final_artifact_path_stat.st_dev,
                    final_artifact_path_stat.st_ino,
                ) != published_identity or (
                    not stat.S_ISREG(final_artifact_path_stat.st_mode)
                    or final_artifact_path_stat.st_uid != expected_owner_uid
                    or stat.S_IMODE(final_artifact_path_stat.st_mode) != 0o600
                ):
                    return False
            finally:
                if artifact_descriptor >= 0:
                    os.close(artifact_descriptor)
                if diagnostic_descriptor >= 0:
                    os.close(diagnostic_descriptor)
                if collector_descriptor >= 0:
                    os.close(collector_descriptor)

            if diagnostic_identity is None:
                return False
            collector_descriptor, observed_collector = open_collector()
            rebound_diagnostic_descriptor = -1
            try:
                diagnostic_path_stat = os.stat(
                    "diagnostic",
                    dir_fd=collector_descriptor,
                    follow_symlinks=False,
                )
                rebound_diagnostic_descriptor = os.open(
                    "diagnostic", flags_dir, dir_fd=collector_descriptor
                )
                rebound_diagnostic_stat = os.fstat(rebound_diagnostic_descriptor)
                if (
                    observed_collector != collector_identity
                    or not stat.S_ISDIR(diagnostic_path_stat.st_mode)
                    or (
                        diagnostic_path_stat.st_dev,
                        diagnostic_path_stat.st_ino,
                    )
                    != diagnostic_identity
                    or (
                        rebound_diagnostic_stat.st_dev,
                        rebound_diagnostic_stat.st_ino,
                    )
                    != diagnostic_identity
                ):
                    return False
                rebound_artifact_stat = os.stat(
                    artifact_relative.parts[1],
                    dir_fd=rebound_diagnostic_descriptor,
                    follow_symlinks=False,
                )
                if (
                    (
                        rebound_artifact_stat.st_dev,
                        rebound_artifact_stat.st_ino,
                    )
                    != published_identity
                    or (
                        rebound_artifact_stat.st_size,
                        rebound_artifact_stat.st_nlink,
                        rebound_artifact_stat.st_mtime_ns,
                        rebound_artifact_stat.st_ctime_ns,
                    )
                    != artifact_stability
                    or (
                        rebound_artifact_stat.st_size != size_bytes
                        or rebound_artifact_stat.st_nlink != 1
                        or not stat.S_ISREG(rebound_artifact_stat.st_mode)
                        or rebound_artifact_stat.st_uid != expected_owner_uid
                        or stat.S_IMODE(rebound_artifact_stat.st_mode) != 0o600
                    )
                ):
                    return False
            finally:
                if rebound_diagnostic_descriptor >= 0:
                    os.close(rebound_diagnostic_descriptor)
                os.close(collector_descriptor)

            final_status_stat = os.fstat(status_descriptor)
            final_status_bytes = read_exact(
                status_descriptor, final_status_stat.st_size
            )
            if (
                (final_status_stat.st_dev, final_status_stat.st_ino) != status_identity
                or final_status_stat.st_size != status_stat.st_size
                or final_status_bytes is None
                or len(final_status_bytes) != final_status_stat.st_size
                or hashlib.sha256(final_status_bytes).digest() != status_digest
            ):
                return False
            collector_descriptor, observed_collector = open_collector()
            try:
                current_status = os.stat(
                    "status.json",
                    dir_fd=collector_descriptor,
                    follow_symlinks=False,
                )
                if (
                    observed_collector != collector_identity
                    or (current_status.st_dev, current_status.st_ino) != status_identity
                ):
                    return False
            finally:
                os.close(collector_descriptor)
            return True
        except (
            OSError,
            ValueError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError,
        ):
            return False
        finally:
            if status_descriptor >= 0:
                os.close(status_descriptor)
            if base_descriptor >= 0:
                os.close(base_descriptor)

    @staticmethod
    def _extract_operation_accounting(
        context: Any, status: str, reason: str
    ) -> tuple[int, int, List[str]]:
        """
        Return status-consistent operation counts from aggregate/stage context.

        After applying local validation, the function forwards ``context``,
        ``status``, and ``reason`` to ``extract_operation_accounting`` and
        preserves its return and exception contract.

        Args:
            context: Runtime context carrying state shared across this
                operation.
            status: Text supplied as status in the format accepted by this
                function.
            reason: Text supplied as reason in the format accepted by this
                function.

        Returns:
            A tuple containing the fields that represent operation accounting.
        """
        return extract_operation_accounting(context, status, reason)

    @staticmethod
    def _infer_stage_status(
        stage_name: str,
        stage_names: List[str],
        collector_status: str,
        reason: str,
        context: Any,
    ) -> str:
        """
        Use recorded stage evidence before falling back to overall status.

        The implementation uses ``stage_name``, ``stage_names``,
        ``collector_status``, ``reason``, and ``context`` to use recorded stage
        evidence before falling back to overall status.

        Args:
            stage_name: Stable stage name used for lookup and operator-facing
                diagnostics.
            stage_names: Entries supplied as ``stage_names`` without
                transferring container ownership.
            collector_status: Text supplied as collector status in the format
                accepted by this function.
            reason: Text supplied as reason in the format accepted by this
                function.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            The canonical infer stage status.
        """
        context = context if isinstance(context, dict) else {}
        stage_result = context.get(f"{stage_name}_result", {})
        raw_status = (
            stage_result.get("status") if isinstance(stage_result, dict) else None
        )
        if stage_name == "execution":
            raw_status = context.get("execution_stage_status", raw_status)

        normalized = {
            "success": "executed",
            "passed": "executed",
            "executed": "executed",
            "error": "failed",
            "failed": "failed",
            "degraded": "degraded",
            "partial": "partial",
            "skipped": "skipped",
        }.get(str(raw_status).lower())
        if normalized:
            return normalized

        failed_stage_match = re.search(r"\bstage\s+([\w-]+)\s+failed\b", reason, re.I)
        if failed_stage_match:
            failed_stage = failed_stage_match.group(1).lower()
            lowered_names = [name.lower() for name in stage_names]
            if failed_stage in lowered_names:
                failed_index = lowered_names.index(failed_stage)
                stage_index = lowered_names.index(stage_name.lower())
                if stage_index < failed_index:
                    return "executed"
                if stage_index == failed_index:
                    return "failed"
                return "skipped"

        if collector_status == "degraded":
            return "degraded" if stage_name == "execution" else "executed"
        if collector_status == "partial":
            return "partial" if stage_name == "execution" else "executed"
        if collector_status == "error":
            return "failed"
        if collector_status == "skipped":
            return "skipped"
        return "executed"

    async def _print_to_console(self, level: str, component: str, message: str) -> None:
        """
        Print to console.

        Never reconstruct the raw fields in the fallback path. A broken
        sanitizer must fail closed rather than expose the original event.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            component: Text supplied as component in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        try:
            formatted_message = self._sanitize_text(
                f"[{timestamp}] [{level}] [{component}] {message}"
            )
        except Exception:
            # Never reconstruct the raw fields in the fallback path. A broken
            # sanitizer must fail closed rather than expose the original event.
            formatted_message = (
                f"[{timestamp}] [ERROR] [AsyncSafeLogger] "
                "Log message sanitization failed"
            )

        try:
            # Use the orchestrator's console if available, otherwise create a new one
            if self.orchestrator and hasattr(self.orchestrator, "console"):
                console = self.orchestrator.console
            else:
                from rich.console import Console

                console = Console()

            # Choose color based on log level
            if level.upper() == "ERROR":
                style = "bold red"
            elif level.upper() == "WARNING":
                style = "bold yellow"
            elif level.upper() == "INFO":
                style = "bold blue"
            elif level.upper() == "DEBUG":
                style = "dim white"
            else:
                style = ""

            # Print to console (this works with Rich progress bars)
            console.print(formatted_message, style=style)

        except Exception:
            # Reuse the already-sanitized line if Rich console fails.
            print(formatted_message)

    async def log_runtime(
        self,
        level: str,
        component: str,
        message: str,
        dut_id: Optional[str] = None,
        collector_id: Optional[str] = None,
    ) -> None:
        """
        Log runtime messages.

        The implementation uses ``level``, ``component``, ``message``,
        ``dut_id``, and ``collector_id`` to log runtime messages. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            component: Text supplied as component in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
        """
        normalized_level, _ = self._normalize_event_level(level)
        if not self._should_emit(normalized_level):
            return

        # Print to console based on log level and mode
        if normalized_level == "INFO" and self.verbose_mode:
            # INFO messages only when verbose mode is enabled
            await self._print_to_console(normalized_level, component, message)
        elif normalized_level == "DEBUG" and self.verbose_mode:
            # DEBUG messages require verbose output and an effective DEBUG threshold.
            await self._print_to_console(normalized_level, component, message)
        elif normalized_level in ["WARNING", "ERROR", "CRITICAL"] and self.verbose_mode:
            # WARNING and higher messages are shown only in verbose mode.
            await self._print_to_console(normalized_level, component, message)

        message = self._sanitize_text(message)

        if dut_id:
            await self.write_to_dut_runtime_log(
                dut_id, normalized_level, component, message, collector_id
            )
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] [{normalized_level}] [{component}] {message}\n"
        # Sanitize the fully formatted line so component/context fields cannot
        # bypass the protection already applied to the message body.
        log_entry = self._sanitize_text(log_entry)
        log_entry = _apply_runtime_log_format(
            self,
            log_entry,
            level,
            component,
            message,
            collector_id=collector_id,
        )

        async with self.runtime_lock:
            # Always write to global runtime log
            if (
                self.runtime_file_handle is not None
                and not self.runtime_file_handle.closed
            ):
                self.runtime_file_handle.write(log_entry)
                self.runtime_file_handle.flush()

            # If this is a DUT-specific message, also write to DUT runtime log
            if component.startswith("DUT:"):
                dut_id = component[4:]  # Remove "DUT:" prefix
                if dut_id in self.dut_runtime_files:
                    dut_runtime_handle = self.dut_runtime_files[dut_id]
                    if not dut_runtime_handle.closed:
                        dut_runtime_handle.write(log_entry)
                        dut_runtime_handle.flush()

    async def log_error(
        self,
        error_type: str,
        error_message: str,
        dut_id: Optional[str] = None,
        collector_id: Optional[str] = None,
    ) -> None:
        """
        Log error messages to both runtime and error logs.

        The implementation uses ``error_type``, ``error_message``, ``dut_id``,
        and ``collector_id`` to log error messages to both runtime and error
        logs. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.

        Args:
            error_type: Text supplied as error type in the format accepted by
                this function.
            error_message: Text supplied as error message in the format accepted
                by this function.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
        """
        # Sanitize error message if sanitizer is available
        if self.sanitizer:
            error_message = self.sanitizer.sanitize(error_message)

        component = (
            f"{dut_id}:{collector_id}" if dut_id and collector_id else error_type
        )

        if dut_id and dut_id != "unknown":
            # Log to runtime log
            await self.write_to_dut_runtime_log(
                dut_id, "ERROR", component, error_message
            )
        else:
            await self.log_runtime("ERROR", component, error_message)

        # Log to error log
        async with self.error_lock:
            if self.error_file_handle is not None and not self.error_file_handle.closed:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                error_entry = f"[{timestamp}] [{component}] {error_message}\n"
                self.error_file_handle.write(error_entry)
                self.error_file_handle.flush()

    def _create_output_directory(self, directory: Path) -> None:
        """
        Create missing output directories with the selected sharing policy.

        Sanitized output uses 0755 directories independently of the process
        umask. Private runs use 0700. The existing no-follow directory creator
        pins new components while setting their modes and validates ownership;
        existing directories retain their operator-selected permissions.
        Already prepared paths avoid another full ancestor walk.

        Args:
            directory: Output directory already confined by its owning caller.

        Raises:
            OSError: If creation, ownership validation or mode adjustment fails.

        Side Effects:
            Creates only missing directories. This synchronous filesystem work
            must remain inside the calling operation's worker when asynchronous
            publication prepares a destination.
        """
        if directory.is_dir():
            return
        ensure_secure_log_directory(
            str(directory),
            shared_read=not self._get_tool_config_value("skip_sanitization", False),
            allow_external_path_owners=True,
        )

    async def setup_dut_logging(self, dut_id: str) -> None:
        """
        Setup logging for a specific DUT.

        The implementation uses ``dut_id`` to setup logging for a specific DUT.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind. Filesystem effects remain confined to
        the caller-selected paths and the owning resource lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        try:
            safe_dut_id = self._safe_path_component(dut_id, "dut")
            dut_log_dir = self._resolve_under_log_root(self.base_log_dir / safe_dut_id)
            self._create_output_directory(dut_log_dir)

            if self._get_tool_config_value("dry_run", False) is True:
                self.dut_log_dirs[dut_id] = dut_log_dir
                self._create_output_directory(dut_log_dir / ".metadata")
                return

            # Create subdirectories
            for subdir in ["redfish", "ipmi", "host", "ssh", "error-logs"]:
                self._create_output_directory(dut_log_dir / subdir)

            append_mode = self._get_tool_config_value("append", False)

            # Create per-DUT runtime log file (like legacy nvdebug)
            dut_runtime_file = dut_log_dir / "nvdebug_runtime_output.txt"

            open_mode = "a" if append_mode and dut_runtime_file.exists() else "w"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            if open_mode == "w":
                header_lines = [
                    ASCII_HEADER,
                    f"[{timestamp}] [INFO] [DUT:{dut_id}] {'=' * 80}",
                    f"[{timestamp}] [INFO] [DUT:{dut_id}] DUT Runtime Log - {dut_id}",
                    *self._runtime_identity_header_lines(
                        timestamp=timestamp,
                        component=f"DUT:{dut_id}",
                    ),
                    f"[{timestamp}] [INFO] [DUT:{dut_id}] Started at: {datetime.now().isoformat()}",
                    f"[{timestamp}] [INFO] [DUT:{dut_id}] {'=' * 80}",
                ]
            else:
                header_lines = [
                    f"[{timestamp}] [INFO] [DUT:{dut_id}] {'=' * 80}",
                    f"[{timestamp}] [INFO] [DUT:{dut_id}] NVDebug append session - {dut_id}",
                    *self._runtime_identity_header_lines(
                        timestamp=timestamp,
                        component=f"DUT:{dut_id}",
                    ),
                    f"[{timestamp}] [INFO] [DUT:{dut_id}] Append started at: {datetime.now().isoformat()}",
                    f"[{timestamp}] [INFO] [DUT:{dut_id}] {'=' * 80}",
                ]

            dut_runtime_handle = open(dut_runtime_file, open_mode)
            for line in header_lines:
                dut_runtime_handle.write(line + "\n")
            dut_runtime_handle.flush()

            self.dut_log_dirs[dut_id] = dut_log_dir
            self.dut_runtime_files[dut_id] = dut_runtime_handle

            # Create .metadata directory and initialize metadata files
            metadata_dir = dut_log_dir / ".metadata"
            self._create_output_directory(metadata_dir)
            await self._initialize_metadata_files(dut_id)

            await self.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "AsyncSafeLogger",
                f"Logging directory created: {dut_log_dir}",
            )
        except Exception as e:
            try:
                await self.log_error(
                    "LOGGING_ERROR",
                    f"Error setting up DUT logging for {dut_id}: {e}",
                )
            except Exception:
                pass
            raise

    def get_dut_log_dir(self, dut_id: str) -> Path:
        """
        Get the log directory for a specific DUT.

        After applying local validation, the function forwards ``dut_id`` to
        ``self._resolve_under_log_root`` and preserves its return and exception
        contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated DUT log dir filesystem path.
        """
        safe_dut_id = self._safe_path_component(dut_id, "dut")
        return self._resolve_under_log_root(self.base_log_dir / safe_dut_id)

    def get_dut_metadata_dir(self, dut_id: str) -> Path:
        """
        Get the metadata directory for a specific DUT.

        The implementation uses ``dut_id`` to get the metadata directory for a
        specific DUT. Filesystem effects remain confined to the caller-selected
        paths and the owning resource lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``metadata_dir``.
        """
        if dut_id not in self.dut_log_dirs:
            # Create DUT log directory if it doesn't exist
            safe_dut_id = self._safe_path_component(dut_id, "dut")
            dut_log_dir = self._resolve_under_log_root(self.base_log_dir / safe_dut_id)
            self._create_output_directory(dut_log_dir)
            self.dut_log_dirs[dut_id] = dut_log_dir

        dut_log_dir = self.dut_log_dirs[dut_id]
        metadata_dir = dut_log_dir / ".metadata"
        self._create_output_directory(metadata_dir)
        return metadata_dir

    _SANITIZATION_ERROR_LIMIT = 8
    _SANITIZATION_DIAGNOSTIC_LIMIT = 2048
    _SANITIZATION_COUNT_LIMIT = (1 << 31) - 1

    def _sanitization_lifecycle_state(self) -> str:
        """
        Return the configured sanitization state for bundle metadata.

        The implementation uses current instance state to produce the configured
        sanitization state for bundle metadata.

        Returns:
            The canonical sanitization lifecycle state text.
        """
        if self._get_tool_config_value("skip_sanitization", False) is True:
            return "disabled_by_user"
        if self._get_tool_config_value("apply_sanitization", False) is not True:
            return "write_time_only"
        return "enabled"

    def _validated_failed_safe_details(self, value: Any) -> Optional[Dict[str, Any]]:
        """
        Return a bounded canonical projection of terminal scan details.

        The implementation uses ``value`` to produce a bounded canonical
        projection of terminal scan details.

        Args:
            value: Value object whose ``get`` state is read while performing
                bounded canonical projection of terminal scan details.

        Returns:
            A mapping containing the ``state`` and ``errors`` fields.
        """
        if not isinstance(value, dict) or value.get("state") != "failed_safe":
            return None

        count_fields = (
            "files_scanned",
            "files_rewritten",
            "nested_archives_scanned",
        )
        counts = {}
        for field in count_fields:
            count = value.get(field)
            if (
                count.__class__ is not int
                or count < 0
                or count > self._SANITIZATION_COUNT_LIMIT
            ):
                return None
            counts[field] = count

        raw_errors = value.get("errors")
        if not isinstance(raw_errors, list) or not raw_errors:
            return None
        errors = []
        remaining = self._SANITIZATION_DIAGNOSTIC_LIMIT
        for raw_error in raw_errors[: self._SANITIZATION_ERROR_LIMIT]:
            if not isinstance(raw_error, str):
                return None
            try:
                rendered = self._sanitize_text(
                    raw_error[: self._SANITIZATION_DIAGNOSTIC_LIMIT]
                )
            except Exception:
                return None
            if not isinstance(rendered, str):
                return None
            rendered = re.sub(
                r"[\x00-\x1f\x7f]+",
                " ",
                rendered[: self._SANITIZATION_DIAGNOSTIC_LIMIT],
            ).strip()
            if not rendered:
                return None
            if remaining <= 0:
                break
            rendered = rendered[:remaining]
            errors.append(rendered)
            remaining -= len(rendered)
        if not errors:
            return None

        return {"state": "failed_safe", **counts, "errors": errors}

    def _sanitization_lifecycle_metadata(
        self,
        existing_metadata: Any = None,
        *,
        preserve_details: bool = False,
    ) -> Dict[str, Any]:
        """
        Project configured state without downgrading a terminal safe failure.

        The implementation uses ``existing_metadata`` and ``preserve_details``
        to project configured state without downgrading a terminal safe failure.

        Args:
            existing_metadata: Optional existing metadata; ``None`` selects the
                function's default behavior.
            preserve_details: Whether preserve details is enabled or required
                for this operation.

        Returns:
            A mapping containing sanitization lifecycle metadata.
        """
        lifecycle = {"sanitization": self._sanitization_lifecycle_state()}
        if (
            not isinstance(existing_metadata, dict)
            or existing_metadata.get("sanitization") != "failed_safe"
        ):
            return lifecycle

        lifecycle["sanitization"] = "failed_safe"
        if preserve_details:
            details = self._validated_failed_safe_details(
                existing_metadata.get("sanitization_details")
            )
            if details is not None:
                lifecycle["sanitization_details"] = details
        return lifecycle

    def _get_tool_config_value(self, key: str, default: Any = None) -> Any:
        """
        Read a tool config value from the attached orchestrator if available.

        The implementation uses ``key`` and ``default`` to read a tool config
        value from the attached orchestrator if available. Parsing or I/O must
        finish before the validated representation is made available to the
        caller.

        Args:
            key: Stable key used for lookup and operator-facing diagnostics.
            default: Fallback used when the requested value is absent or
                invalid.

        Returns:
            The tool config value selected by the operation.
        """
        if not self.orchestrator or not getattr(
            self.orchestrator, "config_manager", None
        ):
            return default
        try:
            tool_config = self.orchestrator.config_manager.get_tool_config()
        except Exception:
            return default

        if isinstance(tool_config, dict):
            return tool_config.get(key, default)
        return getattr(tool_config, key, default)

    def _dry_run_lifecycle_metadata(
        self, *, dut_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Return typed lifecycle fields for a dry-run metadata envelope.

        The implementation uses ``dut_id`` to produce typed lifecycle fields for
        a dry-run metadata envelope.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``metadata``.
        """
        from ..version import __version__

        raw_level = self._get_tool_config_value("collection_level", "L1")
        collection_level = str(getattr(raw_level, "value", raw_level) or "L1")
        if collection_level not in {"L1", "L2", "L3"}:
            collection_level = "L1"

        sanitization = self._sanitization_lifecycle_state()
        metadata: Dict[str, Any] = {
            "tool_version": __version__,
            "collection_level": collection_level,
            "bundle_mode": "dry_run",
            "run_mode": "dry-run",
            "sanitization": sanitization,
        }
        if dut_id is not None:
            metadata["dut_id"] = self._safe_path_component(dut_id, "dut")
        return metadata

    def _apply_stream_window_to_filename(self, collector_id: str, filename: str) -> str:
        """
        Add the streaming window suffix to collector outputs when enabled.

        The implementation uses ``collector_id`` and ``filename`` to add the
        streaming window suffix to collector outputs when enabled.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            filename: Text supplied as filename in the format accepted by this
                function.

        Returns:
            The canonical stream window to filename.
        """
        if not filename or filename.startswith(".") or not collector_id:
            return filename
        if not self._get_tool_config_value("streaming_only", False):
            return filename

        collector_info = None
        try:
            if self.orchestrator:
                collector_info = self.orchestrator.get_collector_info(collector_id)
        except Exception:
            collector_info = None

        if not collector_info or not collector_info.get("streaming_candidate", False):
            return filename

        try:
            stream_begin, stream_end = normalize_stream_window(
                self._get_tool_config_value("stream_begin"),
                self._get_tool_config_value("stream_end"),
            )
        except Exception:
            return filename

        return append_stream_window_to_filename(
            filename,
            format_stream_window_component(stream_begin),
            format_stream_window_component(stream_end),
        )

    def _get_lock_for_path(self, path: Path) -> asyncio.Lock:
        """
        Get or create a shared asyncio lock for a given file path.

        The implementation uses ``path`` to get or create a shared asyncio lock
        for a given file path.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The validated ``lock``.
        """
        key = str(path)
        lock = self._metadata_file_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._metadata_file_locks[key] = lock
        return lock

    def _retained_bundle_metadata(self) -> Dict[str, str]:
        """
        Return lifecycle metadata for a successful retained loose bundle.

        The implementation uses current instance state to produce lifecycle
        metadata for a successful retained loose bundle.

        Returns:
            A mapping containing retained bundle metadata.
        """
        if self._get_tool_config_value("dry_run", False) or self._get_tool_config_value(
            "streaming_only", False
        ):
            return {}

        skip_zip = self._get_tool_config_value("skip_zip", False)
        output_config = self._get_tool_config_value("output", {})
        if isinstance(output_config, dict):
            skip_zip = skip_zip or output_config.get(
                "skip_zip", output_config.get("skipzip", False)
            )
        return {"bundle_mode": "loose"} if skip_zip else {}

    async def _log_simple(
        self, level: str, message: str, dut_id: Optional[str] = None
    ) -> None:
        """
        Log simple.

        The implementation uses ``level``, ``message``, and ``dut_id`` to log
        simple. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        try:
            if dut_id:
                await self.write_to_dut_runtime_log(
                    dut_id, level, "AsyncLogger", message
                )
            else:
                await self.log_runtime(level, "AsyncLogger", message)
        except Exception:
            # Best-effort logging only
            pass

    def _merge_dependency_metadata(
        self,
        existing_data: Dict[str, Any],
        incoming_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Merge incoming dependency metadata into existing data and recompute summary.

        The implementation uses ``existing_data`` and ``incoming_data`` to merge
        incoming dependency metadata into existing data and recompute summary.
        The operation mutates ``existing_data`` in place; ownership of those
        objects remains with the caller.

        Args:
            existing_data: Mapping supplying fields for merge incoming
                dependency metadata into existing data and recompute summary.
            incoming_data: Mapping supplying fields for merge incoming
                dependency metadata into existing data and recompute summary.

        Returns:
            The validated ``existing_data``.
        """
        if not isinstance(existing_data, dict):
            existing_data = {}

        # Ensure required top-level structures exist
        existing_data.setdefault("metadata", {})
        existing_data.setdefault("collectors", {})
        existing_data.setdefault(
            "status_fields", incoming_data.get("status_fields", {})
        )

        # Merge collectors (new data overwrites same collector id)
        existing_data["collectors"].update(incoming_data.get("collectors", {}))

        # Preserve or set created_at
        created_at = (
            existing_data["metadata"].get("created_at")
            or incoming_data.get("metadata", {}).get("created_at")
            or datetime.now(timezone.utc).isoformat()
        )
        existing_data["metadata"]["created_at"] = created_at
        # Always update last_updated to now
        existing_data["metadata"]["last_updated"] = datetime.now(
            timezone.utc
        ).isoformat()

        # Recalculate summary
        summary = {
            "total_checks": 0,
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "not_applicable": 0,
            "required_failed": 0,
            "optional_failed": 0,
        }
        for coll_data in existing_data.get("collectors", {}).values():
            for dep in coll_data.get("dependencies", []):
                status_val = dep.get("status", "skipped")
                summary["total_checks"] += 1
                summary[status_val] = summary.get(status_val, 0) + 1
                if status_val == "failed":
                    if dep.get("required"):
                        summary["required_failed"] += 1
                    else:
                        summary["optional_failed"] += 1
        existing_data["summary"] = summary

        return existing_data

    def _get_current_collector_id_from_orchestrator(self) -> str:
        """
        Get the current collector ID from orchestrator context if available.

        Priority order (highest to lowest):

        1. Context variable (async-safe, per-task).
        2. Orchestrator current_collector_id (global, subject to races).
        3. Orchestrator execution context (global, subject to races).

        Returns:
            The canonical current collector identifier from orchestrator text.
        """
        try:
            # First, try to get from context variable (async-safe)
            context_collector_id = _collector_context.get()
            if context_collector_id:
                return context_collector_id

            # Fallback to orchestrator (may have race conditions in concurrent execution)
            if hasattr(self, "orchestrator") and self.orchestrator:
                # Check if orchestrator has current collector context
                if (
                    hasattr(self.orchestrator, "current_collector_id")
                    and self.orchestrator.current_collector_id
                ):
                    return self.orchestrator.current_collector_id

                # Check if orchestrator has current execution context
                if (
                    hasattr(self.orchestrator, "current_execution_context")
                    and self.orchestrator.current_execution_context
                ):
                    return self.orchestrator.current_execution_context.get(
                        "collector_id", "unknown"
                    )
        except Exception:
            pass

        return "unknown"

    def _validate_cid_context_consistency(
        self, collector_id: str, component: str, message: str
    ) -> None:
        """
        Validate cid context consistency.

        Check for potential cross-contamination indicators.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            component: Text supplied as component in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """
        try:
            # Check for potential cross-contamination indicators
            if "Starting collector" in message and "R" in collector_id:
                # Extract the target collector ID from the message
                match = re.search(r"Starting collector ([A-Z]\d+)", message)
                if match:
                    target_collector_id = match.group(1)
                    if target_collector_id != collector_id:
                        # Log a warning about potential cross-contamination
                        print(
                            f"WARNING: CID context mismatch detected - logging as {collector_id} but starting {target_collector_id}"
                        )

            # Check for file path mismatches - but be smart about async concurrency
            if "Saved" in message:
                # Extract collector ID from file path (supports multiple path patterns)
                file_collector_id = None
                group_prefix = None

                # Try Redfish pattern
                match = re.search(r"redfish/Redfish_([A-Z]\d+)_", message)
                if match:
                    file_collector_id = match.group(1)
                    group_prefix = "R"

                # Try SSH pattern
                if not file_collector_id:
                    match = re.search(r"ssh/Ssh_([A-Z]\d+)_", message)
                    if match:
                        file_collector_id = match.group(1)
                        group_prefix = "S"

                # Try Host pattern
                if not file_collector_id:
                    match = re.search(r"host/Host_([A-Z]\d+)_", message)
                    if match:
                        file_collector_id = match.group(1)
                        group_prefix = "H"

                # Try IPMI pattern
                if not file_collector_id:
                    match = re.search(r"ipmi/Ipmi_([A-Z]\d+)_", message)
                    if match:
                        file_collector_id = match.group(1)
                        group_prefix = "I"

                if file_collector_id and file_collector_id != collector_id:
                    # Check if this is a cross-group mismatch (e.g., SSH logging to Redfish directory)
                    # This would be a REAL bug, not just async context switching
                    collector_group_prefix = collector_id[0] if collector_id else None

                    if (
                        collector_group_prefix
                        and group_prefix
                        and collector_group_prefix != group_prefix
                    ):
                        pass
                        # False positives are being printed. Disabling for now.
                        # REAL CROSS-CONTAMINATION: Different collector groups!
                        # Example: S5 (SSH) saving files to redfish/ directory
                        # print(
                        #     f"ERROR: Cross-group file contamination detected - {collector_id} ({collector_group_prefix}-group) "
                        #     f"saving to {file_collector_id} ({group_prefix}-group) directory!"
                        # )
                    # else: Same group, different collector ID - likely async race condition, ignore

        except Exception:
            # Don't let validation break logging
            pass

    async def write_to_dut_runtime_log(
        self,
        dut_id: str,
        level: str,
        component: str,
        message: str,
        collector_id: str = None,
        *,
        lifecycle: bool = False,
    ) -> None:
        """
        Write to DUT runtime log.

        Setup logging outside the lock to avoid deadlock.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            level: Text supplied as level in the format accepted by this
                function.
            component: Text supplied as component in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            lifecycle: Whether lifecycle is enabled or required for this
                operation.
        """
        normalized_level, _ = self._normalize_event_level(level)
        if not lifecycle and not self._should_emit(normalized_level):
            return
        if self._get_tool_config_value("dry_run", False) is True:
            return

        # Setup logging outside the lock to avoid deadlock
        if dut_id not in self.dut_runtime_files:
            await self.setup_dut_logging(dut_id)

        write_error: Optional[Exception] = None
        async with self.dut_runtime_lock:
            dut_runtime_handle = self.dut_runtime_files[dut_id]
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            # Auto-detect collector_id if not provided
            if collector_id is None and not lifecycle:
                collector_id = self._get_current_collector_id_from_orchestrator()

            # Validate CID context consistency (debug mode only to avoid performance impact)
            # Now uses context variables for async-safe tracking, reducing false positives
            if self.debug_mode and collector_id and collector_id != "unknown":
                self._validate_cid_context_consistency(collector_id, component, message)

            # DEBUG: Log CID context for debugging (DISABLED - causes massive performance impact)
            # if self.debug_mode:
            #     asyncio.create_task(
            #         self.log_runtime(
            #             "DEBUG",
            #             "AsyncSafeLogger",
            #             f"Logging with CID: {collector_id}, component: {component}",
            #         )
            #     )

            # Lifecycle lines retain the canonical shape consumed by reporting
            # and timing parsers; diagnostic lines use the configured format.
            if lifecycle:
                log_entry = (
                    f"[{timestamp}] [{normalized_level}] [{component}] {message}\n"
                )
            elif collector_id and collector_id != "unknown":
                log_entry = f"[{timestamp}] [{normalized_level}] [CID:{collector_id}] [{component}] {message}\n"
            else:
                log_entry = (
                    f"[{timestamp}] [{normalized_level}] [{component}] {message}\n"
                )

            log_entry = self._sanitize_text(log_entry)
            encoded_entry = log_entry.encode("utf-8")
            if not lifecycle:
                formatted_entry = _apply_runtime_log_format(
                    self,
                    log_entry,
                    level,
                    component,
                    message,
                    dut_id=dut_id,
                    collector_id=collector_id,
                )
                if formatted_entry != log_entry:
                    log_entry = formatted_entry
                    encoded_entry = log_entry.encode("utf-8")
            if len(encoded_entry) > MAX_DUT_RUNTIME_LOG_ENTRY_BYTES:
                truncation_marker = (
                    "\n[TRUNCATED: DUT runtime log entry "
                    f"was {len(encoded_entry)} bytes; limit is "
                    f"{MAX_DUT_RUNTIME_LOG_ENTRY_BYTES} bytes]\n"
                ).encode("utf-8")
                retained_bytes = MAX_DUT_RUNTIME_LOG_ENTRY_BYTES - len(
                    truncation_marker
                )
                log_entry = encoded_entry[:retained_bytes].decode(
                    "utf-8", errors="ignore"
                ) + truncation_marker.decode("utf-8")

            try:
                # Check file size to prevent disk fill
                try:
                    current_size = dut_runtime_handle.tell()
                    if current_size > MAX_LOG_FILE_SIZE_MB * 1024 * 1024:
                        handle_key = id(dut_runtime_handle)
                        if handle_key not in _truncation_warned:
                            dut_runtime_handle.write(
                                f"\n[WARNING] Log file exceeded {MAX_LOG_FILE_SIZE_MB}MB. "
                                f"Further entries truncated.\n"
                            )
                            dut_runtime_handle.flush()
                            _truncation_warned.add(handle_key)
                        return
                except Exception:
                    pass  # Don't let size check break logging

                # Write log entry directly (no need to seek to end of file)
                dut_runtime_handle.write(log_entry)
                dut_runtime_handle.flush()
            except Exception as e:
                write_error = e

        # Error reporting may itself use DUT logging, so it must happen after
        # releasing the non-reentrant per-DUT runtime lock.
        if write_error is not None:
            try:
                await self.log_error(
                    "LOGGING_ERROR",
                    f"Failed to write to DUT runtime log for {dut_id}: {write_error}",
                )
            except Exception:
                pass

    def _get_collector_group(self, collector_id: str) -> str:
        """
        Get collector group from ID.

        After applying local validation, the function forwards ``collector_id``
        to ``CollectorServiceMapping.get_service_from_collector_id`` and
        preserves its return and exception contract.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The canonical collector group text.
        """
        return CollectorServiceMapping.get_service_from_collector_id(collector_id)

    async def create_collector_log_file(
        self,
        dut_id: str,
        group: str,
        collector_id: str,
        filename: str,
        *,
        apply_stream_window: bool = True,
    ) -> Path:
        """
        Prepare a validated collector destination without blocking the event loop.

        Directory resolution and creation can issue NFS requests, so they run in
        one owned filesystem operation. The parent is created once, preserving
        callers that download directly into the returned directory. Artifact
        bookkeeping is adopted on the event loop only after preparation finishes.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            group: Text supplied as group in the format accepted by this
                function.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            filename: Text supplied as filename in the format accepted by this
                function.
            apply_stream_window: Whether apply stream window is enabled or
                required for this operation.

        Returns:
            The validated ``file_path``.
        """
        # Get collector name and output pattern from orchestrator if available
        collector_name = collector_id
        output_filename = filename
        try:
            # Try to get collector info from orchestrator
            if hasattr(self, "orchestrator") and self.orchestrator:
                collector_info = self.orchestrator.get_collector_info(collector_id)
                if collector_info:
                    if "name" in collector_info:
                        collector_name = collector_info["name"]
                    # Only use output_pattern if the filename still contains variable placeholders
                    # This allows pre-substituted filenames to be respected
                    # Use regex to detect any variable pattern like {variable_name}
                    variable_pattern = re.compile(r"\{[^}]+\}")
                    has_variables = variable_pattern.search(filename) is not None

                    if (
                        "stages" in collector_info
                        and "execution" in collector_info["stages"]
                        and has_variables
                    ):
                        execution_stage = collector_info["stages"]["execution"]
                        if "hooks" in execution_stage:
                            for hook in execution_stage["hooks"]:
                                if "output_pattern" in hook:
                                    output_filename = hook["output_pattern"]
                                    break
                else:
                    # Fallback: use group name if no collector name found
                    collector_name = group
        except Exception:
            # Fallback: use group name if any error occurs
            collector_name = group

        if apply_stream_window:
            output_filename = self._apply_stream_window_to_filename(
                collector_id, output_filename
            )
        output_filename = self._safe_output_filename(output_filename)

        def prepare_destination() -> tuple[Path, Path]:
            """
            Resolve and create the selected output parent in its owned worker.

            Path resolution performs filesystem metadata lookups as well as the
            explicit mkdir. Both remain inside admission, and direct download
            callers receive an existing parent after the worker is joined.

            Returns:
                The canonical collector directory and traversal-checked output
                path, with its actual parent ready for direct download callers.

            Raises:
                OSError: If directory preparation fails on the selected filesystem.
                ValueError: If the resolved destination escapes the output root.
            """
            collector_dir = self._collector_artifact_directory(
                dut_id,
                collector_id,
                group=group,
                collector_name=collector_name,
                reuse_recorded=False,
            )
            file_path = self._resolve_under_log_root(collector_dir / output_filename)
            self._create_output_directory(file_path.parent)
            return collector_dir, file_path

        collector_dir, file_path = await run_managed_filesystem_operation(
            prepare_destination
        )
        artifact_dirs = getattr(self, "_collector_artifact_dirs", None)
        if not isinstance(artifact_dirs, dict):
            artifact_dirs = {}
            self._collector_artifact_dirs = artifact_dirs
        artifact_dirs[f"{dut_id}:{collector_id}"] = collector_dir

        return file_path

    async def create_config_files(
        self,
        dut_id: str,
        tool_config: Dict[str, Any],
        dut_config: Dict[str, Any],
    ) -> None:
        """
        Create config.json and dut_config.json files for a DUT.

        Create config.json (tool configuration) with sanitization.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            tool_config: Tool config governing config.json and dut_config.json
                files for a DUT.
            dut_config: DUT config governing config.json and dut_config.json
                files for a DUT.
        """
        try:
            dut_dir = self.get_dut_log_dir(dut_id)

            # Create config.json (tool configuration) with sanitization
            config_file = dut_dir / "config.json"

            # Sanitize the tool config if sanitizer is available
            # Structural extension file-reference redaction is unconditional; the
            # configured sanitizer additionally handles general secrets.
            sanitized_tool_config = self._sanitize_config_dict(tool_config)

            _write_private_json(config_file, sanitized_tool_config)

            # Create dut_config.json (DUT configuration) with sanitization
            dut_config_file = dut_dir / "dut_config.json"

            # Sanitize the DUT config if sanitizer is available
            sanitized_dut_config = self._sanitize_config_dict(dut_config)

            _write_private_json(dut_config_file, sanitized_dut_config)

        except Exception as e:
            try:
                await self.log_error(
                    "LOGGING_ERROR",
                    f"Error creating config files for DUT {dut_id}: {e}",
                )
            except Exception:
                pass
            raise

    def _sanitize_collector_status_document(
        self, status_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Sanitize device text while retaining generated artifact provenance.

        The implementation uses ``status_data`` to sanitize device text while
        retaining generated artifact provenance.

        Args:
            status_data: Mapping supplying fields for sanitize device text while
                retaining generated artifact provenance.

        Returns:
            The validated ``sanitized``.
        """

        sanitized = self._sanitize_config_dict(status_data)
        for field_name in (
            "dut_id",
            "collector_id",
            "collector_name",
            "collector_group",
            "collection_level",
            "output_files",
            "diagnostic_files",
            "error_files",
            "all_files",
            "discovered_files",
        ):
            if field_name in status_data:
                sanitized[field_name] = copy.deepcopy(status_data[field_name])

        raw_timings = status_data.get("artifact_timings")
        projected_timings = sanitized.get("artifact_timings")
        if isinstance(raw_timings, list) and isinstance(projected_timings, list):
            for raw_item, projected_item in zip(raw_timings, projected_timings):
                if (
                    isinstance(raw_item, dict)
                    and isinstance(projected_item, dict)
                    and isinstance(raw_item.get("path"), str)
                ):
                    projected_item["path"] = raw_item["path"]

        for field_name in (
            "request_response_capture",
            "request_response_logs",
        ):
            raw_capture = status_data.get(field_name)
            projected_capture = sanitized.get(field_name)
            if isinstance(raw_capture, dict) and isinstance(projected_capture, dict):
                capture_keys = (
                    tuple(raw_capture)
                    if field_name == "request_response_logs"
                    else (None,)
                )
                for capture_key in capture_keys:
                    raw_item = (
                        raw_capture.get(capture_key)
                        if capture_key is not None
                        else raw_capture
                    )
                    projected_item = (
                        projected_capture.get(capture_key)
                        if capture_key is not None
                        else projected_capture
                    )
                    if (
                        isinstance(raw_item, dict)
                        and isinstance(projected_item, dict)
                        and isinstance(raw_item.get("artifact_path"), str)
                    ):
                        projected_item["artifact_path"] = raw_item["artifact_path"]
        return sanitized

    def _sanitize_config_dict(
        self,
        config_dict: Dict[str, Any],
        *,
        _inside_extension_config: bool = False,
        _inside_debug_token_config: bool = False,
        _inside_catalog_profile: bool = False,
        _apply_trusted_hook: bool = True,
    ) -> Dict[str, Any]:
        """
        Recursively sanitize all string values in a configuration dictionary.

        Credential-named fields are masked before generic string sanitization
        unless the run explicitly disables write-time sanitization. The opt-out
        preserves those values in owner-only configuration snapshots and is
        represented elsewhere as ``UNSAFE_TO_SHARE``. Trusted extension file
        references remain unconditionally redacted in either mode.

        ``debug_token`` is a governed extension schema whose ``tokens`` are
        selector/file-reference records, not bearer values. Its trusted hook has
        already blanked those file references above.

        Args:
            config_dict: Config dict governing recursively sanitize all string
                values in a configuration dictionary.
            _inside_extension_config: Whether inside extension config is enabled
                or required for this operation.
            _inside_debug_token_config: Whether inside debug token config is
                enabled or required for this operation.
            _inside_catalog_profile: Whether the mapping belongs to a
                catalog-owned profile whose schema containers must remain
                intact.
            _apply_trusted_hook: Whether apply trusted hook is enabled or
                required for this operation.

        Returns:
            The validated ``sanitized``.
        """
        if _apply_trusted_hook:
            config_dict = redact_optional_config_mapping(config_dict, "XXXX")
        sanitization_disabled = (
            self._get_tool_config_value("skip_sanitization", False) is True
        )
        sanitized = {}
        for key, value in config_dict.items():
            normalized_key = str(key).casefold()
            inside_debug_token_config = (
                _inside_debug_token_config or normalized_key == "debug_token"
            )
            # ``debug_token`` is a governed extension schema whose ``tokens``
            # are selector/file-reference records, not bearer values. Its
            # trusted hook has already blanked those file references above.
            serialized_container = (
                _parse_serialized_json_container(value)
                if isinstance(value, str)
                and self.sanitizer
                and not sanitization_disabled
                else None
            )
            is_container = isinstance(value, (dict, list)) or (
                serialized_container is not None
            )
            inside_catalog_profile = _inside_catalog_profile or (
                _is_catalog_profile_key(key) and is_container
            )
            if (
                not sanitization_disabled
                and _is_credential_config_key(key)
                and not (inside_catalog_profile and is_container)
                and not (
                    inside_debug_token_config
                    and normalized_key in _DEBUG_TOKEN_NONCREDENTIAL_KEYS
                )
                and not isinstance(value, bool)
            ):
                sanitized[key] = value if value in (None, "") else "XXXX"
                continue
            inside_extension_config = (
                _inside_extension_config
                or normalized_key == "collector_extension_config"
            )
            if _inside_extension_config and (
                normalized_key in {"path", "file", "source"}
                or normalized_key.endswith(("_path", "_file", "_source"))
            ):
                sanitized[key] = "XXXX"
                continue
            value_to_sanitize = (
                serialized_container if serialized_container is not None else value
            )
            sanitized_value = self._sanitize_config_value(
                value_to_sanitize,
                inside_extension_config=inside_extension_config,
                inside_debug_token_config=inside_debug_token_config,
                inside_catalog_profile=inside_catalog_profile,
                sanitization_disabled=sanitization_disabled,
            )
            sanitized[key] = (
                json.dumps(
                    sanitized_value,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                if serialized_container is not None
                else sanitized_value
            )
        return sanitized

    def _sanitize_config_value(
        self,
        value: Any,
        *,
        inside_extension_config: bool,
        inside_debug_token_config: bool,
        inside_catalog_profile: bool,
        sanitization_disabled: bool,
    ) -> Any:
        """
        Sanitize one decoded configuration value without changing its shape.

        Container values recurse through the same key-aware policy used by the
        outer snapshot, while scalar text retains the established redaction
        rules.

        Args:
            value: Decoded configuration value to sanitize.
            inside_extension_config: Whether the value is below the governed
                collector-extension namespace.
            inside_debug_token_config: Whether the value is below the governed
                debug-token namespace.
            inside_catalog_profile: Whether the value is within a
                catalog-owned profile schema.
            sanitization_disabled: Whether write-time sanitization was
                explicitly disabled for this snapshot.

        Returns:
            A shape-preserving sanitized configuration value.
        """

        if isinstance(value, dict):
            return self._sanitize_config_dict(
                value,
                _inside_extension_config=inside_extension_config,
                _inside_debug_token_config=inside_debug_token_config,
                _inside_catalog_profile=inside_catalog_profile,
                _apply_trusted_hook=False,
            )
        if isinstance(value, list):
            return [
                self._sanitize_config_value(
                    item,
                    inside_extension_config=inside_extension_config,
                    inside_debug_token_config=inside_debug_token_config,
                    inside_catalog_profile=inside_catalog_profile,
                    sanitization_disabled=sanitization_disabled,
                )
                for item in value
            ]
        if isinstance(value, str):
            serialized_container = (
                _parse_serialized_json_container(value)
                if self.sanitizer and not sanitization_disabled
                else None
            )
            if serialized_container is not None:
                sanitized_container = self._sanitize_config_value(
                    serialized_container,
                    inside_extension_config=inside_extension_config,
                    inside_debug_token_config=inside_debug_token_config,
                    inside_catalog_profile=inside_catalog_profile,
                    sanitization_disabled=sanitization_disabled,
                )
                return json.dumps(
                    sanitized_container,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            return self.sanitizer.sanitize(value) if self.sanitizer else value
        return value

    async def create_log_signature(
        self, dut_id: str, platform: str = None, baseboard: str = None
    ) -> None:
        """
        Create .log_signature.txt file with version and platform information.

        The implementation uses ``dut_id``, ``platform``, and ``baseboard`` to
        create .log_signature.txt file with version and platform information.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind. It updates
        ``_root_log_signature_records`` on the instance as part of that state
        transition. Filesystem effects remain confined to the caller-selected
        paths and the owning resource lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            platform: Optional platform; ``None`` selects the function's default
                behavior.
            baseboard: Optional baseboard; ``None`` selects the function's
                default behavior.
        """
        try:
            from ..version import (
                __build_hash__,
                __build_time__,
                __source_revision__,
                __version__,
            )
            from .run_identity_builder import resolved_profile

            identity_facts = {
                "tool_version": __version__,
                "build_hash": __build_hash__,
                "source_revision": __source_revision__,
                "build_timestamp_utc": __build_time__,
            }
            fact_resolver = getattr(
                self.orchestrator,
                "_get_run_identity_tool_facts",
                None,
            )
            if callable(fact_resolver):
                identity_facts.update(fact_resolver())
            identity_config: Any = getattr(
                self.orchestrator,
                "_tool_config_obj",
                None,
            )
            if identity_config is None and self.orchestrator is not None:
                config_manager = getattr(self.orchestrator, "config_manager", None)
                if config_manager is not None:
                    identity_config = config_manager.get_tool_config()
            raw_level = (
                identity_config.get("collection_level", "unknown")
                if isinstance(identity_config, dict)
                else getattr(identity_config, "collection_level", "unknown")
            )
            collection_level = str(
                getattr(raw_level, "value", raw_level) or "unknown"
            ).upper()
            collection_profile = (
                resolved_profile(identity_config)
                if identity_config is not None
                else "unknown"
            )

            dut_dir = self.get_dut_log_dir(dut_id)
            signature_file = dut_dir / ".log_signature.txt"

            # Get current timestamp
            from datetime import datetime

            generated_at = datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")

            # Build signature content
            signature_content = f"""NVDebug Tool Version {identity_facts["tool_version"]}
Build hash: {identity_facts["build_hash"]}
Source revision: {identity_facts["source_revision"]}
Build time: {identity_facts["build_timestamp_utc"]}
Collection level: {collection_level}
Collection profile: {collection_profile}
Generated at: {generated_at}
Platform: {platform or "unknown"}
Baseboard: {baseboard or "unknown"}
"""

            # Create signature file in DUT directory
            with open(signature_file, "w") as f:
                f.write(signature_content)

            if not self._get_tool_config_value("dry_run", False):
                records = getattr(self, "_root_log_signature_records", None)
                if not isinstance(records, dict):
                    records = {}
                    self._root_log_signature_records = records
                safe_dut_id = self._safe_path_component(dut_id, "dut")
                records[safe_dut_id] = signature_content
                signature_content = "NVDebug multi-DUT signature\n"
                for recorded_dut in sorted(records):
                    signature_content += (
                        f"\nDUT: {recorded_dut}\n{records[recorded_dut]}"
                    )

            # Also create root-level signature file for legacy parser compatibility
            root_signature_file = self.base_log_dir / ".log_signature.txt"
            root_signature_content = signature_content
            root_signature_mode = "w"
            if self._get_tool_config_value("dry_run", False):
                safe_dut_id = self._safe_path_component(dut_id, "dut")
                root_signature_content += f"DUT: {safe_dut_id}\n"
                if root_signature_file.exists():
                    root_signature_mode = "a"
            with open(root_signature_file, root_signature_mode) as f:
                f.write(root_signature_content)

        except Exception as e:
            try:
                await self.log_error(
                    "LOGGING_ERROR",
                    f"Error creating log signature for DUT {dut_id}: {e}",
                )
            except Exception:
                pass
            raise

    @staticmethod
    def _bounded_structured_cell(value: Any) -> str:
        """
        Render one metadata scalar without allowing multiline expansion.

        The implementation uses ``value`` to render one metadata scalar without
        allowing multiline expansion. The source value keeps its ownership while
        the normalized representation is returned separately. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle.

        Args:
            value: Value evaluated while performing one metadata scalar without
                allowing multiline expansion.

        Returns:
            The canonical bounded structured cell text.
        """
        if value is None:
            text = ""
        elif isinstance(value, (str, int, float, bool)):
            text = str(value)
        else:
            text = f"<{type(value).__name__}>"
        text = " ".join(text.replace("\x00", "").splitlines())
        if len(text) <= MAX_STRUCTURED_LOG_CELL_CHARS:
            return text
        omitted = len(text) - MAX_STRUCTURED_LOG_CELL_CHARS
        return f"{text[:MAX_STRUCTURED_LOG_CELL_CHARS]}...(+{omitted} chars)"

    @staticmethod
    def _read_bounded_structured_metadata(
        path: Path,
        counters: Dict[str, int],
    ) -> Dict[str, Any]:
        """
        Read a stable bounded metadata file through one no-follow descriptor.

        The implementation uses ``path`` and ``counters`` to read a stable
        bounded metadata file through one no-follow descriptor. Parsing or I/O
        must finish before the validated representation is made available to the
        caller. Cleanup in the ``finally`` path runs for successful, failed, and
        cancelled execution.

        Args:
            path: filesystem location used as the path for this operation.
            counters: Mapping supplying fields for stable bounded metadata file
                through one no-follow descriptor.

        Returns:
            A mapping containing bounded structured metadata.
        """
        descriptor: Optional[int] = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                counters["malformed"] += 1
                return {}
            if before.st_size < 0 or before.st_size > MAX_STRUCTURED_LOG_METADATA_BYTES:
                counters["dropped"] += 1
                return {}
            raw = bytearray()
            while True:
                chunk = os.read(
                    descriptor,
                    min(
                        64 * 1024,
                        MAX_STRUCTURED_LOG_METADATA_BYTES + 1 - len(raw),
                    ),
                )
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > MAX_STRUCTURED_LOG_METADATA_BYTES:
                    counters["dropped"] += 1
                    return {}
            after = os.fstat(descriptor)
            identity_fields = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if len(raw) != before.st_size or any(
                getattr(before, field) != getattr(after, field)
                for field in identity_fields
            ):
                counters["malformed"] += 1
                return {}
            candidate = json.loads(raw.decode("utf-8"))
            if not isinstance(candidate, dict):
                counters["malformed"] += 1
                return {}
            return candidate
        except FileNotFoundError:
            return {}
        except (OSError, UnicodeError, json.JSONDecodeError):
            counters["malformed"] += 1
            return {}
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _create_structured_log_sync(self, dut_id: str) -> bool:
        """
        Write a bounded index without copying the canonical runtime log.

        The implementation uses ``dut_id`` to write a bounded index without
        copying the canonical runtime log. Success is reported only after the
        owning output boundary has completed its required write or publication
        step. Cleanup in the ``finally`` path runs for successful, failed, and
        cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            Whether the bounded index without copying the canonical runtime log
            operation succeeds.
        """
        dut_dir = self.get_dut_log_dir(dut_id)
        structured_log_file = dut_dir / "nvdebug_runtime_output_structured.txt"
        runtime_log_file = dut_dir / "nvdebug_runtime_output.txt"
        try:
            runtime_stat = runtime_log_file.lstat()
        except OSError:
            logger.warning("Runtime log file not found for DUT %s", dut_id)
            return False
        if runtime_log_file.is_symlink() or not stat.S_ISREG(runtime_stat.st_mode):
            logger.warning("Runtime log path is not a regular file for DUT %s", dut_id)
            return False

        counters = {
            "accepted": 0,
            "deduplicated": 0,
            "dropped": 0,
            "malformed": 0,
        }
        execution_order = self._read_bounded_structured_metadata(
            dut_dir / ".metadata" / "execution_order.json", counters
        )

        execution_entries = execution_order.get("payload", {}).get(
            "execution_order", []
        )
        if not isinstance(execution_entries, list):
            counters["malformed"] += 1
            execution_entries = []
        collector_items = []
        for group, filename in _STRUCTURED_COLLECTOR_METADATA:
            metadata = self._read_bounded_structured_metadata(
                dut_dir / ".metadata" / filename, counters
            )
            collectors = metadata.get("collectors", {})
            if not isinstance(collectors, dict):
                counters["malformed"] += 1
                continue
            collector_items.extend(
                (group, collector_id, collector_info)
                for collector_id, collector_info in collectors.items()
            )

        temp_path = structured_log_file.with_name(
            f".{structured_log_file.name}.{uuid.uuid4().hex}.tmp"
        )
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        bytes_written = 0
        data_budget = MAX_STRUCTURED_LOG_OUTPUT_BYTES - 4_096

        def write_text(handle: Any, value: str, *, data_line: bool = False) -> bool:
            """
            Write text.

            The implementation uses ``handle``, ``value``, and ``data_line`` to
            write text. Success is reported only after the owning output
            boundary has completed its required write or publication step.

            Args:
                handle: Handle object whose ``write`` state is read while
                    performing text.
                value: Text supplied as value in the format accepted by this
                    function.
                data_line: Whether data line is enabled or required for this
                    operation.

            Returns:
                Whether the text operation succeeds.
            """
            nonlocal bytes_written
            encoded_size = len(value.encode("utf-8"))
            limit = data_budget if data_line else MAX_STRUCTURED_LOG_OUTPUT_BYTES
            if bytes_written + encoded_size > limit:
                return False
            handle.write(value)
            bytes_written += encoded_size
            return True

        try:
            with temp_path.open("x", encoding="utf-8", newline="\n") as output:
                write_text(
                    output,
                    "=" * 80
                    + f"\nNVDEBUGTOOL ORGANIZED LOG - {timestamp}\n"
                    + "=" * 80
                    + "\n\n",
                )
                write_text(
                    output,
                    "MAIN PROCESS LOG REFERENCE\n"
                    "--------------------------\n"
                    "path: nvdebug_runtime_output.txt\n"
                    f"size_bytes: {runtime_stat.st_size}\n"
                    "content_embedded: false\n\n",
                )
                write_text(
                    output,
                    "EXECUTION ORDER\n"
                    "---------------\n"
                    "Order | Timestamp | ID | Name | Group\n",
                )

                seen_entries = set()
                retained_execution = 0
                for index, entry in enumerate(execution_entries):
                    if not isinstance(entry, dict):
                        counters["malformed"] += 1
                        continue
                    shape = tuple(
                        self._bounded_structured_cell(entry.get(field, ""))
                        for field in (
                            "order",
                            "timestamp",
                            "id",
                            "name",
                            "group",
                        )
                    )
                    if shape in seen_entries:
                        counters["deduplicated"] += 1
                        continue
                    if retained_execution >= MAX_STRUCTURED_LOG_ENTRIES:
                        counters["dropped"] += len(execution_entries) - index
                        break
                    line = " | ".join(shape) + "\n"
                    if not write_text(output, line, data_line=True):
                        counters["dropped"] += len(execution_entries) - index
                        break
                    seen_entries.add(shape)
                    retained_execution += 1
                    counters["accepted"] += 1

                write_text(
                    output,
                    "\nCOLLECTOR RESULTS SUMMARY\n"
                    "-------------------------\n"
                    "Group | ID | Collector Name | Status | Execution Time\n",
                )
                retained_collectors = 0
                for index, (
                    collector_group,
                    collector_id,
                    collector_info,
                ) in enumerate(collector_items):
                    if not isinstance(collector_info, dict):
                        counters["malformed"] += 1
                        continue
                    if retained_collectors >= MAX_STRUCTURED_LOG_ENTRIES:
                        counters["dropped"] += len(collector_items) - index
                        break
                    raw_execution_time = collector_info.get("execution_time", 0.0)
                    execution_text = self._bounded_structured_cell(raw_execution_time)
                    try:
                        execution_time = float(execution_text)
                    except (TypeError, ValueError, OverflowError):
                        time_text = "N/A"
                    else:
                        time_text = (
                            f"{execution_time:.2f}s" if execution_time > 0 else "N/A"
                        )
                    shape = (
                        collector_group,
                        self._bounded_structured_cell(collector_id),
                        self._bounded_structured_cell(
                            collector_info.get("name", collector_id)
                        ),
                        self._bounded_structured_cell(
                            collector_info.get("status", "Unknown")
                        ),
                        time_text,
                    )
                    if shape in seen_entries:
                        counters["deduplicated"] += 1
                        continue
                    line = " | ".join(shape) + "\n"
                    if not write_text(output, line, data_line=True):
                        counters["dropped"] += len(collector_items) - index
                        break
                    seen_entries.add(shape)
                    retained_collectors += 1
                    counters["accepted"] += 1

                write_text(
                    output,
                    "\nEVENT ACCOUNTING\n"
                    "----------------\n"
                    f"accepted: {counters['accepted']}\n"
                    f"deduplicated: {counters['deduplicated']}\n"
                    f"dropped: {counters['dropped']}\n"
                    f"malformed: {counters['malformed']}\n"
                    "runtime_log_bytes_embedded: 0\n\n"
                    + "=" * 80
                    + "\nEND OF ORGANIZED LOG\n"
                    + "=" * 80
                    + "\n",
                )
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp_path, structured_log_file)
            return True
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass

    async def create_structured_log(self, dut_id: str) -> None:
        """
        Create a bounded structured index off the event-loop thread.

        The synchronous publisher owns a unique temporary path and its finally
        block removes it. Let that owner finish in the private worker, while
        propagating cancellation without a blocking executor shutdown on the
        event loop. The callback observes the exact worker outcome and releases
        the executor even if the caller is cancelled again.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="nvdebug-structured-log"
        )
        cleanup_deferred = False
        try:
            future = executor.submit(self._create_structured_log_sync, dut_id)
        except BaseException:
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        try:
            await _await_executor_future(future)
        except asyncio.CancelledError:
            # The synchronous publisher owns a unique temporary path and its
            # finally block removes it. Let that owner finish in the private
            # worker, while propagating cancellation without a blocking
            # executor shutdown on the event loop. The callback observes the
            # exact worker outcome and releases the executor even if the caller
            # is cancelled again.
            cleanup_deferred = True

            def release_worker(completed: Any) -> None:
                """
                Release worker.

                The implementation uses ``completed`` to release worker. Cleanup
                in the ``finally`` path runs for successful, failed, and
                cancelled execution.

                Args:
                    completed: Completed object whose ``result`` state is read
                        while performing release worker.
                """
                try:
                    completed.result()
                except BaseException:
                    pass
                finally:
                    executor.shutdown(wait=False, cancel_futures=True)

            future.add_done_callback(release_worker)
            raise
        except Exception as e:
            await self.log_error(
                "LOGGING_ERROR",
                f"Error creating structured log for DUT {dut_id}: {e}",
            )
        finally:
            if not cleanup_deferred:
                executor.shutdown(wait=False, cancel_futures=True)

    async def _initialize_metadata_files(self, dut_id: str) -> None:
        """
        Initialize metadata files for a DUT.

        Initialize preflight.json with all possible preflight checks.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        try:
            metadata_dir = self.get_dut_log_dir(dut_id) / ".metadata"

            # Initialize preflight.json with all possible preflight checks
            preflight_data = {
                "metadata": {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                },
                "preflights": {},
            }

            # Add all preflight checks with default "Skipped" status
            from ..utils.enums import get_main_preflight_names

            for preflight_name in get_main_preflight_names():
                preflight_data["preflights"][preflight_name] = {
                    "status": "Skipped",
                    "reason": "Preflight check was not executed",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": None,
                }

            preflight_file = metadata_dir / "preflight.json"
            await self._write_metadata_json(preflight_file, preflight_data)

            # Initialize other metadata files
            metadata_files = [
                "redfish.json",
                "ipmi.json",
                "host.json",
                "health_check.json",
                "ssh.json",
            ]

            for filename in metadata_files:
                file_path = metadata_dir / filename
                if not file_path.exists():
                    # Create empty metadata structure
                    empty_metadata = {
                        "metadata": {
                            "created_at": datetime.now(timezone.utc).isoformat(),
                            "last_updated": datetime.now(timezone.utc).isoformat(),
                        },
                        "status_fields": {
                            "description": "Possible status values for collectors",
                            "values": {
                                "Passed": "Collection completed successfully",
                                "Failed": "Collection failed",
                                "Degraded": "Collection completed with degraded results",
                                "Skipped": "Collection was skipped",
                                "NotRan": "Collection was not included in current collection map",
                                "Partial": "Collection partially succeeded",
                            },
                            "collector_fields": {
                                "id": "Unique identifier for the collector (e.g., R1, H2)",
                                "name": "Name of the collector",
                                "status": "Result status of the collection",
                                "reason": "Detailed message about the collection result",
                                "execution_time": "Time taken to execute the collector",
                                "output_files": "List of output files generated by the collector",
                            },
                        },
                        "collectors": {},
                        "summary": {
                            "total_collectors": 0,
                            "passed": 0,
                            "failed": 0,
                            "degraded": 0,
                            "skipped": 0,
                            "not_ran": 0,
                            "partial": 0,
                        },
                    }

                    await self._write_metadata_json(
                        file_path, empty_metadata, only_if_missing=True
                    )

        except Exception as e:
            try:
                await self.log_error(
                    "LOGGING_ERROR",
                    f"Error initializing metadata files for DUT {dut_id}: {e}",
                )
            except Exception:
                pass
            raise

    async def record_command_diagnostic(
        self,
        dut_id: Optional[str],
        *,
        transport: str,
        command: str,
        exit_code: Optional[int],
        stdout: Any,
        stderr: Any,
        timeout: Optional[float],
        duration_seconds: Optional[float],
        operation: str,
        target: str,
        error: Optional[BaseException] = None,
        redacted: bool = False,
        collector_id: Optional[str] = None,
        outcome: Optional[str] = None,
        stdout_truncated: bool = False,
        stderr_truncated: bool = False,
    ) -> Optional[Path]:
        """
        Atomically retain a bounded, sanitized command transcript as diagnostics.

        Attribution uses task-local identities, never the orchestrator's shared
        current-collector fallback. Managed callers may supply their explicit
        collector identity and decoded target result. Empty streams and unknown
        exit status remain explicit; truncation and publication failures are
        counted in status.json instead of being silently omitted. Publications
        for the same collector serialize their stream-budget accounting; failed
        writes do not consume the allowance for later command evidence.

        Args:
            dut_id: DUT owning this execution.
            transport: Transport or managed-target label.
            command: Command text, sanitized before persistence.
            exit_code: Raw returned code, or null when no status was received.
            stdout: Returned standard output, including an empty stream.
            stderr: Returned standard error, including an empty stream.
            timeout: Configured command timeout in seconds, when known.
            duration_seconds: Observed elapsed time, or null if unavailable.
            operation: Stable operation name distinguishing retries and wrappers.
            target: Logical target label without connection credentials.
            error: Raised transport exception or cancellation, when applicable.
            redacted: Whether command text and protocol stdout are intentionally
                excluded in favor of a separate decoded managed-target record.
            collector_id: Explicit identity for an owned managed command.
            outcome: Target outcome independent of the outer transport status.
            stdout_truncated: Whether the producer already truncated stdout.
            stderr_truncated: Whether the producer already truncated stderr.

        Returns:
            The diagnostic path, or null outside collection or after the record
            ceiling. The status summary reports any ceiling reached.

        Raises:
            Exception: If sanitization or atomic publication fails. The failure
                counter is updated before propagating the error.

        Side Effects:
            Writes one diagnostic JSON artifact and updates bounded per-collector
            accounting. No transcript becomes primary collector output.
        """

        if collector_id is None:
            if not dut_id or _dut_context.get() != dut_id:
                return None
            collector_id = _collector_context.get()
        if not dut_id or not collector_id:
            return None
        states = getattr(self, "_command_diagnostic_states", None)
        if states is None:
            states = self._command_diagnostic_states = {}
        state = states.setdefault(
            (dut_id, collector_id),
            {
                "schema_version": "1.0",
                "directory": "diagnostic/commands",
                "total_commands": 0,
                "recorded_commands": 0,
                "dropped_commands": 0,
                "stream_bytes": 0,
                "truncated_streams": 0,
                "publication_failures": 0,
                "complete": True,
            },
        )
        state["total_commands"] += 1
        sequence = state["total_commands"]
        if sequence > MAX_COMMAND_DIAGNOSTIC_RECORDS:
            state["dropped_commands"] += 1
            state["complete"] = False
            return None

        def bounded_text(value: Any, maximum: int) -> tuple[str, bool]:
            """
            Sanitize before retaining the tail so clipping cannot reveal a secret.

            UTF-8 clipping may drop an incomplete leading codepoint. The returned
            text still fits the byte allowance and cannot contain partial secrets
            created by truncating before the active sanitizer runs.

            Args:
                value: Text or bytes received from the command.
                maximum: Remaining UTF-8 byte allowance for this field.

            Returns:
                Sanitized text and whether this boundary truncated it.
            """

            text = (
                value.decode("utf-8", errors="replace")
                if isinstance(value, bytes)
                else str(value or "")
            )
            safe = self._sanitize_text(text).encode("utf-8", errors="replace")
            tail = safe[-maximum:] if maximum else b""
            return tail.decode("utf-8", errors="ignore"), len(safe) > maximum

        def prepare_document(
            stream_allowance: int, captured_at: str
        ) -> tuple[Dict[str, Any], int, int]:
            """
            Sanitize complete command streams before clipping in an owned worker.

            Large stdout can take seconds to redact even when the retained tail
            is small. This preparation does not mutate collector accounting or
            publish files; its caller adopts the returned deltas only after the
            diagnostic document has been durably published.

            Args:
                stream_allowance: Remaining per-collector stream byte allowance.
                captured_at: Timestamp captured before worker admission.

            Returns:
                Prepared document, retained stream bytes, and truncated streams.
            """

            document = {
                "schema_version": "1.0",
                "sequence": sequence,
                "transport": transport,
                "operation": operation,
                "target": target,
                "captured_at": captured_at,
                "exit_code": exit_code,
                "outcome": outcome
                or (
                    "cancelled"
                    if isinstance(error, asyncio.CancelledError)
                    else "exception" if error else "returned"
                ),
                "timeout_seconds": timeout,
                "duration_seconds": duration_seconds,
                "command": (
                    "[managed command; see target transcript]"
                    if redacted
                    else bounded_text(command, 4096)[0]
                ),
                "protocol_stdout_omitted": redacted,
                "exception_type": type(error).__name__ if error else None,
                "exception": bounded_text(str(error), 4096)[0] if error else None,
            }
            stream_bytes_delta = 0
            truncated_streams_delta = 0
            for name, value, previously_truncated in (
                ("stdout", "" if redacted else stdout, stdout_truncated),
                ("stderr", stderr, stderr_truncated),
            ):
                remaining = max(0, stream_allowance - stream_bytes_delta)
                content, clipped = bounded_text(
                    value, min(MAX_COMMAND_DIAGNOSTIC_STREAM_BYTES, remaining)
                )
                document[name] = content
                document[f"{name}_truncated"] = clipped or previously_truncated
                stream_bytes_delta += len(content.encode("utf-8"))
                if clipped or previously_truncated:
                    truncated_streams_delta += 1
            return document, stream_bytes_delta, truncated_streams_delta

        locks = getattr(self, "_command_diagnostic_locks", None)
        if locks is None:
            locks = self._command_diagnostic_locks = {}
        lock = locks.setdefault((dut_id, collector_id), asyncio.Lock())
        try:
            async with lock:
                document, stream_bytes_delta, truncated_streams_delta = (
                    await run_managed_filesystem_operation(
                        prepare_document,
                        max(
                            0,
                            MAX_COMMAND_DIAGNOSTIC_TOTAL_BYTES - state["stream_bytes"],
                        ),
                        datetime.now().astimezone().isoformat(),
                        bulk=self._requires_bulk_preparation(
                            None if redacted else command,
                            None if redacted else stdout,
                            stderr,
                            error,
                        ),
                    )
                )
                path = await self.write_collector_output(
                    dut_id,
                    self._get_collector_group(collector_id),
                    collector_id,
                    f"diagnostic/commands/command-{sequence:06d}.json",
                    json.dumps(document, ensure_ascii=True, indent=2),
                )
                state["stream_bytes"] += stream_bytes_delta
                state["truncated_streams"] += truncated_streams_delta
                if truncated_streams_delta:
                    state["complete"] = False
                state["recorded_commands"] += 1
                return path
        except BaseException:
            state["publication_failures"] += 1
            state["complete"] = False
            raise

    @staticmethod
    def _requires_bulk_preparation(*values: Any) -> bool:
        """
        Classify preparation without decoding streams or coercing user objects.

        Strings count characters and bytes count bytes; this inexpensive hint
        controls worker admission only. Unknown value types use the bulk path
        because their string conversion may be expensive. Complete redaction,
        encoding, clipping and publication still occur in the owned worker.

        Args:
            values: Complete unsanitized inputs that preparation will inspect.

        Returns:
            Whether the inputs require the bounded bulk-preparation allowance.
        """
        units = 0
        for value in values:
            if value is None:
                continue
            if type(value) not in (str, bytes):
                return True
            units += len(value)
            if units > _BULK_PREPARATION_INPUT_LIMIT:
                return True
        return False

    async def write_collector_output(
        self,
        dut_id: str,
        group: str,
        collector_id: str,
        filename: str,
        content: Union[str, bytes],
    ) -> Path:
        """
        Write output content to a collector log file.

        Validate, sanitize, and atomically publish through the bounded filesystem
        pool. Large structured pages must not block collector scheduling while
        every field is inspected. Cancellation drains any admitted worker before
        returning, so publication cannot continue after its owner has exited.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            group: Text supplied as group in the format accepted by this
                function.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            filename: Text supplied as filename in the format accepted by this
                function.
            content: Text supplied as content in the format accepted by this
                function.

        Returns:
            Path to the completely sanitized and published collector artifact.

        Raises:
            ValueError: If structured output is invalid or redaction makes keys
                ambiguous.
            OSError: If atomic publication fails.
            asyncio.CancelledError: If cancelled, after admitted work is drained.
        """
        file_path = await self.create_collector_log_file(
            dut_id, group, collector_id, filename
        )

        await run_managed_filesystem_operation(
            self._prepare_and_publish_collector_output,
            file_path,
            content,
            bulk=self._requires_bulk_preparation(content),
        )

        return file_path

    def _prepare_and_publish_collector_output(
        self, destination: Path, content: Union[str, bytes]
    ) -> None:
        """
        Complete validation and atomic publication in one owned worker slot.

        The existing sanitizer and publisher remain the only output boundaries.
        Prepared bytes live only for this operation, and private staging stays
        beside the destination on the caller-selected output filesystem.

        Args:
            destination: Validated collector artifact pathname.
            content: Complete input bytes or text requiring sanitization.

        Raises:
            ValueError: If structured content fails validation or key redaction.
            OSError: If staging or atomic publication fails.
        """

        prepared = self._prepare_collector_output(destination, content)
        self._atomic_publish_collector_output(destination, prepared)

    async def write_collector_output_file(
        self,
        dut_id: str,
        group: str,
        collector_id: str,
        filename: str,
        source: Path,
    ) -> Path:
        """
        Publish a complete private staging file as a collector artifact.

        Staging is allocated on the output filesystem for atomic replacement.
        Its metadata checks and rename run in an owned filesystem worker, so
        slow storage does not block the event loop. Cancellation joins any
        admitted publisher before the caller can clean up its private source.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            group: Text supplied as group in the format accepted by this
                function.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            filename: Text supplied as filename in the format accepted by this
                function.
            source: filesystem location used as the source for this operation.

        Returns:
            The validated destination after the complete staging file is moved.

        Raises:
            ValueError: If the staging source is not a regular file.
            OSError: If destination preparation or atomic publication fails.
            asyncio.CancelledError: After any admitted publisher has finished.
        """

        file_path = await self.create_collector_log_file(
            dut_id, group, collector_id, filename
        )
        await run_managed_filesystem_operation(
            self._atomic_publish_collector_file, file_path, Path(source)
        )
        return file_path

    def _format_structured_error(
        self,
        collector_id: str,
        collector_name: str,
        dut_id: str,
        error_message: str,
        context: dict = None,
    ) -> str:
        """
        Format a structured error message with rich context for better debugging.

        After applying local validation, the function forwards ``collector_id``,
        ``collector_name``, ``dut_id``, ``error_message``, and ``context`` to
        ``join`` and preserves its return and exception contract. The source
        value keeps its ownership while the normalized representation is
        returned separately.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collector_name: Stable collector name used for lookup and
                operator-facing diagnostics.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            error_message: Text supplied as error message in the format accepted
                by this function.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            The canonical structured error text.
        """
        lines = []
        partial_report = bool(
            isinstance(context, dict)
            and context.get("operation_name") == "partial_collection"
        )
        report_kind = "PARTIAL" if partial_report else "ERROR"

        # Header section
        lines.append("=" * 80)
        lines.append(f"COLLECTOR {report_kind} REPORT")
        lines.append("=" * 80)
        lines.append("")

        # Basic information
        lines.append("BASIC INFORMATION:")
        lines.append(f"  Collector ID: {collector_id}")
        lines.append(f"  Collector Name: {collector_name}")
        lines.append(f"  DUT: {dut_id}")
        lines.append(f"  Timestamp: {datetime.now().isoformat()}")
        lines.append("")

        # Error or partial-outcome summary
        lines.append("OUTCOME SUMMARY:" if partial_report else "ERROR SUMMARY:")
        lines.append(f"  {error_message}")
        lines.append("")

        # Add context information if available
        if context:
            lines.append("DETAILED CONTEXT:")

            # Operation details
            if "operation_name" in context:
                lines.append(f"  Operation: {context['operation_name']}")

            if "target_baseboard" in context:
                lines.append(f"  Target Baseboard: {context['target_baseboard']}")

            if "devices_processed" in context:
                lines.append(f"  Devices Processed: {context['devices_processed']}")

            if "successful_operations" in context and "total_operations" in context:
                lines.append(
                    f"  Success Rate: {context['successful_operations']}/{context['total_operations']}"
                )

            # Detailed error information for partial collections
            if "detailed_errors" in context and context["detailed_errors"]:
                lines.append("")
                lines.append("FAILED OPERATIONS:")
                detailed_errors = context["detailed_errors"]
                if isinstance(detailed_errors, list):
                    for i, error in enumerate(detailed_errors, 1):
                        if isinstance(error, str):
                            # Split long error messages into multiple lines for readability
                            error_lines = error.split("\n")
                            lines.append(f"  {i}. {error_lines[0]}")
                            for additional_line in error_lines[1:]:
                                if additional_line.strip():
                                    lines.append(f"     {additional_line.strip()}")
                        else:
                            lines.append(f"  {i}. {str(error)}")
                else:
                    lines.append(f"  {detailed_errors}")

            if "condition_details" in context and context["condition_details"]:
                lines.append("")
                lines.append("PARTIAL CONDITIONS:")
                condition_details = context["condition_details"]
                if isinstance(condition_details, list):
                    for index, condition in enumerate(condition_details, 1):
                        lines.append(f"  {index}. {condition}")
                else:
                    lines.append(f"  {condition_details}")

            # Timing information
            if "execution_time" in context:
                lines.append(f"  Execution Time: {context['execution_time']:.2f}s")

            # Request details (for diagnostic collection errors)
            if "result" in context and isinstance(context["result"], dict):
                result = context["result"]

                # Check if this is a diagnostic collection result with request info
                if "context" in result and isinstance(result["context"], dict):
                    result_context = result["context"]

                    # Request URI
                    if "request_uri" in result_context:
                        lines.append("")
                        lines.append("REQUEST DETAILS:")
                        lines.append(f"  URI: {result_context['request_uri']}")

                        # Request payload (formatted as multi-line JSON)
                        if "request_payload" in result_context:
                            payload = result_context["request_payload"]
                            lines.append("  Payload:")
                            try:
                                if isinstance(payload, dict):
                                    formatted_payload = json.dumps(payload, indent=4)
                                else:
                                    # Try to parse as JSON first
                                    parsed_payload = json.loads(str(payload))
                                    formatted_payload = json.dumps(
                                        parsed_payload, indent=4
                                    )

                                # Indent each line of the payload
                                for line in formatted_payload.split("\n"):
                                    lines.append(f"    {line}")
                            except (json.JSONDecodeError, TypeError):
                                # If not valid JSON, just show as string
                                lines.append(f"    {payload}")

                        # Response data (formatted as multi-line JSON)
                        if "response_data" in result_context:
                            response_data = result_context["response_data"]
                            lines.append("  Response:")
                            try:
                                if isinstance(response_data, dict):
                                    formatted_response = json.dumps(
                                        response_data, indent=4
                                    )
                                else:
                                    # Try to parse as JSON first
                                    parsed_response = json.loads(str(response_data))
                                    formatted_response = json.dumps(
                                        parsed_response, indent=4
                                    )

                                # Indent each line of the response
                                for line in formatted_response.split("\n"):
                                    lines.append(f"    {line}")
                            except (json.JSONDecodeError, TypeError):
                                # If not valid JSON, just show as string
                                lines.append(f"    {response_data}")

                    # Handle failed entity contexts (for diagnostic collection)
                    if "failed_entity_contexts" in result_context:
                        lines.append("")
                        lines.append("FAILED ENTITY CONTEXTS:")
                        failed_entities = result_context["failed_entity_contexts"]
                        for (
                            entity_id,
                            entity_context,
                        ) in failed_entities.items():
                            lines.append(f"  Entity: {entity_id}")
                            if "request_uri" in entity_context:
                                lines.append(
                                    f"    URI: {entity_context['request_uri']}"
                                )
                            if "request_payload" in entity_context:
                                payload = entity_context["request_payload"]
                                lines.append("    Payload:")
                                try:
                                    if isinstance(payload, dict):
                                        formatted_payload = json.dumps(
                                            payload, indent=6
                                        )
                                    else:
                                        parsed_payload = json.loads(str(payload))
                                        formatted_payload = json.dumps(
                                            parsed_payload, indent=6
                                        )
                                    for line in formatted_payload.split("\n"):
                                        lines.append(f"      {line}")
                                except (json.JSONDecodeError, TypeError):
                                    lines.append(f"      {payload}")
                            if "error_message" in entity_context:
                                lines.append(
                                    f"    Error: {entity_context['error_message']}"
                                )
                            lines.append("")

                    # Handle failed service contexts (for custom service executor)
                    if "failed_service_contexts" in result_context:
                        lines.append("")
                        lines.append("FAILED SERVICE CONTEXTS:")
                        failed_services = result_context["failed_service_contexts"]
                        for (
                            service_id,
                            service_context,
                        ) in failed_services.items():
                            lines.append(f"  Service: {service_id}")
                            if "request_uri" in service_context:
                                lines.append(
                                    f"    URI: {service_context['request_uri']}"
                                )
                            if "request_payload" in service_context:
                                payload = service_context["request_payload"]
                                lines.append("    Payload:")
                                try:
                                    if isinstance(payload, dict):
                                        formatted_payload = json.dumps(
                                            payload, indent=6
                                        )
                                    else:
                                        parsed_payload = json.loads(str(payload))
                                        formatted_payload = json.dumps(
                                            parsed_payload, indent=6
                                        )
                                    for line in formatted_payload.split("\n"):
                                        lines.append(f"      {line}")
                                except (json.JSONDecodeError, TypeError):
                                    lines.append(f"      {payload}")
                            if "timeout" in service_context:
                                lines.append(
                                    f"    Timeout: {service_context['timeout']}s"
                                )
                            if "max_retries" in service_context:
                                lines.append(
                                    f"    Max Retries: {service_context['max_retries']}"
                                )
                            lines.append("")

            # Error details
            if "error_messages" in context and context["error_messages"]:
                lines.append("")
                lines.append("ERROR DETAILS:")
                error_messages = context["error_messages"]
                if isinstance(error_messages, list):
                    for i, error_msg in enumerate(error_messages, 1):
                        lines.append(f"  {i}. {error_msg}")
                else:
                    lines.append(f"  {error_messages}")

            # Handle direct payload field (for command executor errors)
            if "payload" in context and context["payload"]:
                lines.append("")
                lines.append("REQUEST PAYLOAD:")
                payload = context["payload"]
                try:
                    if isinstance(payload, dict):
                        formatted_payload = json.dumps(payload, indent=4)
                    else:
                        # Try to parse as JSON first
                        parsed_payload = json.loads(str(payload))
                        formatted_payload = json.dumps(parsed_payload, indent=4)

                    # Indent each line of the payload
                    for line in formatted_payload.split("\n"):
                        lines.append(f"  {line}")
                except (json.JSONDecodeError, TypeError):
                    # If not valid JSON, just show as string
                    lines.append(f"  {payload}")

            # Additional context
            if "additional_context" in context:
                additional = context["additional_context"]
                if isinstance(additional, dict) and additional:
                    lines.append("")
                    lines.append("ADDITIONAL CONTEXT:")
                    for key, value in additional.items():
                        lines.append(f"  {key}: {value}")

            lines.append("")

        # Footer
        lines.append("=" * 80)
        lines.append(f"END OF {report_kind} REPORT")
        lines.append("=" * 80)

        return "\n".join(lines)

    async def write_error_log(
        self,
        dut_id: str,
        collector_id: str,
        error_message: str,
        context: dict = None,
    ) -> Path:
        """
        Write error message to error-logs directory.

        Get collector name from orchestrator if available.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            error_message: Text supplied as error message in the format accepted
                by this function.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            The validated write error log filesystem path.
        """
        # Create error-logs directory path
        error_logs_dir = self.get_dut_log_dir(dut_id) / "error-logs"
        self._create_output_directory(error_logs_dir)

        # Get collector name from orchestrator if available
        collector_name = collector_id
        if hasattr(self, "orchestrator") and self.orchestrator:
            try:
                collector_def = self.orchestrator.get_all_collectors().get(collector_id)
                if collector_def:
                    collector_name = collector_def.get("name", collector_id)
            except Exception:
                pass

        # Create error log file path. When the collector name could not be
        # resolved it falls back to collector_id (common for synthetic
        # per-target sub-collector ids), so avoid doubling the name.
        safe_collector_id = self._safe_path_component(collector_id, "collector")
        safe_collector_name = self._safe_path_component(
            collector_name, safe_collector_id
        )
        if safe_collector_name != safe_collector_id:
            error_filename = f"{safe_collector_id}_{safe_collector_name}_error.log"
        else:
            error_filename = f"{safe_collector_id}_error.log"
        file_path = self._resolve_under_log_root(error_logs_dir / error_filename)

        # Create structured error message with rich context
        structured_error = self._format_structured_error(
            collector_id, collector_name, dut_id, error_message, context
        )
        structured_error = self._sanitize_text(structured_error)

        timing_manager = getattr(
            getattr(self, "orchestrator", None), "timing_manager", None
        )
        timing_operation_id = None
        if timing_manager and hasattr(timing_manager, "start_operation"):
            timing_operation_id = timing_manager.start_operation(
                "artifact_persistence",
                error_filename,
                metadata={"artifact_kind": "collector_error_log"},
                compact_artifact_on_limit=True,
            )

        try:
            lock = self._get_lock_for_path(file_path)
            async with lock:
                self._append_collector_report(
                    file_path,
                    structured_error,
                    separator_label="ADDITIONAL ERROR ENTRY",
                )
        except Exception as exc:
            if timing_manager and hasattr(timing_manager, "end_operation"):
                timing_manager.end_operation(
                    timing_operation_id,
                    status="error",
                    error=str(exc),
                )
            raise

        if timing_manager and hasattr(timing_manager, "end_operation"):
            timing_manager.end_operation(
                timing_operation_id,
                artifact_path=str(file_path),
            )

        # Other collector writers return absolute paths. Keep error artifacts
        # consistent so status/tracker consumers never interpret an already
        # run-root-prefixed relative path as DUT-relative and duplicate it.
        return file_path.resolve()

    async def write_collector_outcome_report(
        self,
        dut_id: str,
        collector_id: str,
        outcome_message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Path:
        """
        Publish a condition-only collector report as diagnostic evidence.

        Partial and degraded collectors can retain usable primary output even
        when a bounded data-quality condition remains. Those reports are not
        error artifacts: they live below the collector's ``diagnostic``
        directory so the shared artifact classifier projects them through
        ``diagnostic_files`` without inflating ``error_files``. Collector IDs,
        names, and paths pass through the same canonical path helpers as other
        logger-owned artifacts.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            outcome_message: Bounded operator-facing summary rendered in the
                structured report.
            context: Optional structured condition context used by the report
                formatter.

        Returns:
            The absolute path of the published diagnostic outcome report.
        """

        collector_name = collector_id
        if self.orchestrator:
            try:
                collector_def = self.orchestrator.get_all_collectors().get(collector_id)
                if collector_def:
                    collector_name = collector_def.get("name", collector_id)
            except Exception:
                pass

        safe_collector_id = self._safe_path_component(collector_id, "collector")
        filename = f"{safe_collector_id}_partial.log"
        group = self._get_collector_group(collector_id)
        file_path = await self.create_collector_log_file(
            dut_id,
            group,
            collector_id,
            f"diagnostic/{filename}",
            apply_stream_window=False,
        )
        structured_report = self._format_structured_error(
            collector_id,
            collector_name,
            dut_id,
            outcome_message,
            context,
        )
        structured_report = self._sanitize_text(structured_report)

        timing_manager = getattr(
            getattr(self, "orchestrator", None), "timing_manager", None
        )
        timing_operation_id = None
        if timing_manager and hasattr(timing_manager, "start_operation"):
            timing_operation_id = timing_manager.start_operation(
                "artifact_persistence",
                filename,
                metadata={"artifact_kind": "collector_outcome_report"},
                compact_artifact_on_limit=True,
            )

        try:
            lock = self._get_lock_for_path(file_path)
            async with lock:
                self._append_collector_report(
                    file_path,
                    structured_report,
                    separator_label="ADDITIONAL PARTIAL CONDITION ENTRY",
                )
        except Exception as exc:
            if timing_manager and hasattr(timing_manager, "end_operation"):
                timing_manager.end_operation(
                    timing_operation_id,
                    status="error",
                    error=str(exc),
                )
            raise

        if timing_manager and hasattr(timing_manager, "end_operation"):
            timing_manager.end_operation(
                timing_operation_id,
                artifact_path=str(file_path),
            )
        return file_path.resolve()

    async def log_collector_result(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: str = "",
        execution_time: float = 0.0,
        output_files: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
        discovered_files: Optional[Dict[str, List[str]]] = None,
        *,
        failure_category: Optional[str] = None,
        refresh_inventory: bool = True,
        authoritative_projection: bool = False,
    ) -> None:
        """
        Log collector execution result.

        The implementation uses ``dut_id``, ``collector_id``, ``status``,
        ``reason``, and ``execution_time`` to log collector execution result.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            status: Text supplied as status in the format accepted by this
                function.
            reason: Text supplied as reason in the format accepted by this
                function.
            execution_time: Numeric execution time used while the operation
                performs bounded accounting.
            output_files: Optional output files; ``None`` selects the function's
                default behavior.
            context: Runtime context carrying state shared across this
                operation.
            discovered_files: Optional discovered files; ``None`` selects the
                function's default behavior.
            failure_category: Optional failure category; ``None`` selects the
                function's default behavior.
            refresh_inventory: Whether refresh inventory is enabled or required
                for this operation.
            authoritative_projection: Whether authoritative projection is
                enabled or required for this operation.
        """
        sanitize = getattr(getattr(self, "sanitizer", None), "sanitize", None)
        reason = sanitize_terminal_collector_reason(
            status,
            reason,
            sanitizer=sanitize if callable(sanitize) else None,
        )
        # Debug: Log entry point
        await self.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AsyncLogger",
            f"log_collector_result called for {collector_id}: status={status}, reason='{reason}', context_keys={list(context.keys()) if context else []}, discovered_files_keys={list(discovered_files.keys()) if discovered_files else []}",
        )

        if output_files is None:
            output_files = []

        result_key = f"{dut_id}:{collector_id}"
        previous_result = self.collector_results.get(result_key)
        previous_status = (
            previous_result.get("status") if isinstance(previous_result, dict) else None
        )
        if (
            not authoritative_projection
            and previous_status == status
            and isinstance(previous_result, dict)
        ):
            canonical_failure_reason = sanitize_terminal_collector_reason(status, "")
            previous_reason = previous_result.get("reason")
            if (
                reason == canonical_failure_reason
                and isinstance(previous_reason, str)
                and previous_reason
                and previous_reason != canonical_failure_reason
            ):
                reason = previous_reason

        # Services and the final reporting pass can write the same result. Keep
        # counters idempotent, while allowing a final status correction.
        status_counter_keys = {
            "success": "successful_collectors",
            "degraded": "degraded_collectors",
            "error": "failed_collectors",
            "partial": "partial_collectors",
            "skipped": "skipped_collectors",
        }
        if previous_result is None:
            if isinstance(self.execution_summary["total_collectors"], int):
                self.execution_summary["total_collectors"] += 1
        elif previous_status != status:
            previous_counter = status_counter_keys.get(previous_status)
            if previous_counter and isinstance(
                self.execution_summary.get(previous_counter), int
            ):
                self.execution_summary[previous_counter] = max(
                    0, self.execution_summary[previous_counter] - 1
                )

        if previous_result is None or previous_status != status:
            status_counter = status_counter_keys.get(status)
            if status_counter and isinstance(
                self.execution_summary.get(status_counter), int
            ):
                self.execution_summary[status_counter] += 1

        previous_context = (
            previous_result.get("context", {})
            if isinstance(previous_result, dict)
            else {}
        )
        current_context = context if isinstance(context, dict) else {}
        if previous_result is not None and previous_status != status:
            # A final status correction starts a new accounting/stage view.
            # Retaining nested results from the prior status can make a
            # corrected success still render failed stages and stale errors.
            merged_context = dict(current_context)
        else:
            merged_context = {**previous_context, **current_context}

        outcome_details = extract_collector_outcome_details(
            current_context,
            additional_contexts=(previous_context,),
            sanitizer=sanitize if callable(sanitize) else None,
        )
        if status in {"degraded", "partial", "error"} and outcome_details is not None:
            merged_context["outcome_details"] = outcome_details
        else:
            merged_context.pop("outcome_details", None)

        category_source = failure_category
        if category_source is None:
            category_source = current_context.get("failure_category")
        if category_source is None and outcome_details is not None:
            category_source = outcome_details["category"]
        if (
            category_source is None
            and not authoritative_projection
            and previous_status == status
            and isinstance(previous_result, dict)
        ):
            category_source = previous_result.get("failure_category")
        final_failure_category = normalize_collector_failure_category(
            status,
            category_source,
        )
        merged_context.pop("failure_category", None)
        if final_failure_category is not None:
            merged_context["failure_category"] = final_failure_category

        # Keep the most complete operation accounting across repeated writes.
        # Later orchestration stages can carry validation's shallow 1/1 tally
        # even after execution reported a richer 1/2 result.
        previous_total = previous_context.get("total_operations", 0)
        current_total = current_context.get("total_operations", 0)
        previous_successful = previous_context.get("successful_operations", 0)
        current_successful = current_context.get("successful_operations", 0)
        preserve_previous_accounting = (
            previous_status == status
            and isinstance(previous_total, int)
            and (not isinstance(current_total, int) or previous_total > current_total)
        )
        if (
            previous_status == status
            and status in {"degraded", "partial", "error"}
            and isinstance(previous_total, int)
            and isinstance(previous_successful, int)
            and isinstance(current_total, int)
            and isinstance(current_successful, int)
            and previous_total == current_total
            and previous_successful < previous_total
            and current_successful >= current_total
        ):
            preserve_previous_accounting = True
        if preserve_previous_accounting:
            merged_context["successful_operations"] = previous_context.get(
                "successful_operations", 0
            )
            merged_context["total_operations"] = previous_total

        previous_errors = previous_context.get("error_messages", [])
        current_errors = current_context.get("error_messages", [])
        if not isinstance(previous_errors, list):
            previous_errors = [previous_errors] if previous_errors else []
        if not isinstance(current_errors, list):
            current_errors = [current_errors] if current_errors else []
        if previous_status == status:
            merged_errors = list(dict.fromkeys(previous_errors + current_errors))
        else:
            merged_errors = list(dict.fromkeys(current_errors))
        if merged_errors or "error_messages" in merged_context:
            merged_context["error_messages"] = merged_errors

        previous_output_files = (
            previous_result.get("output_files", [])
            if isinstance(previous_result, dict)
            else []
        )

        known_inventory_files: List[Any] = list(previous_output_files) + list(
            output_files
        )
        if isinstance(previous_result, dict):
            for field_name in ("diagnostic_files", "error_files", "all_files"):
                field_files = previous_result.get(field_name, [])
                if isinstance(field_files, list):
                    known_inventory_files.extend(field_files)
        if isinstance(discovered_files, dict):
            for files in discovered_files.values():
                if isinstance(files, list):
                    known_inventory_files.extend(files)

        file_inventory = self.reconcile_collector_file_inventory(
            dut_id,
            collector_id,
            known_inventory_files,
            refresh=refresh_inventory,
        )
        reconciled_discovered_files = self._group_inventory_files(
            file_inventory["all_files"]
        )

        # Store result
        stored_result = {
            "dut_id": dut_id,
            "collector_id": collector_id,
            "status": status,
            "reason": reason,
            "execution_time": execution_time,
            "output_files": file_inventory["output_files"],
            "diagnostic_files": file_inventory["diagnostic_files"],
            "error_files": file_inventory["error_files"],
            "all_files": file_inventory["all_files"],
            "discovered_files": reconciled_discovered_files,
            "context": merged_context,
            "timestamp": datetime.now().isoformat(),
        }
        if final_failure_category is not None:
            stored_result["failure_category"] = final_failure_category
        self.collector_results[result_key] = stored_result

        # Update collector status
        await self._update_collector_status(
            dut_id,
            collector_id,
            status,
            reason,
            execution_time,
            reconciled_discovered_files,
            final_failure_category,
            authoritative_projection=authoritative_projection,
        )

        # Log the result
        await self.write_to_dut_runtime_log(
            dut_id,
            (
                "INFO"
                if status == "success"
                else "ERROR" if status == "error" else "WARN"
            ),
            collector_id,
            f"Status: {status}, Reason: {reason}, Time: {execution_time:.2f}s",
        )

    async def _update_collector_status(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: str,
        execution_time: float = 0.0,
        discovered_files: Optional[Dict[str, List[str]]] = None,
        failure_category: Optional[str] = None,
        *,
        authoritative_projection: bool = False,
    ) -> None:
        """
        Update collector status in metadata.

        Get existing files if collector entry already exists.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            status: Text supplied as status in the format accepted by this
                function.
            reason: Text supplied as reason in the format accepted by this
                function.
            execution_time: Numeric execution time used while the operation
                performs bounded accounting.
            discovered_files: Optional discovered files; ``None`` selects the
                function's default behavior.
            failure_category: Optional failure category; ``None`` selects the
                function's default behavior.
            authoritative_projection: Whether the supplied inventory replaces
                every pending summary update for this collector.
        """
        # Debug: Log what discovered_files we received
        await self.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AsyncLogger",
            f"_update_collector_status for {collector_id}: discovered_files={'None' if discovered_files is None else f'{len(discovered_files)} folders with {sum(len(v) for v in discovered_files.values())} files'}",
        )

        group = self._get_collector_group(collector_id)

        if group not in self.collector_status:
            self.collector_status[group] = {}

        if dut_id not in self.collector_status[group]:
            self.collector_status[group][dut_id] = {
                "total": 0,
                "successful": 0,
                "degraded": 0,
                "failed": 0,
                "skipped": 0,
                "collectors": {},
            }

        dut_status = self.collector_status[group][dut_id]

        # Get existing files if collector entry already exists
        existing_files = []
        existing_collector = dut_status["collectors"].get(collector_id)
        if existing_collector:
            existing_files = existing_collector.get("files", [])
            await self.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AsyncLogger",
                f"_update_collector_status: Found {len(existing_files)} existing files for {collector_id}",
            )
        else:
            dut_status["total"] += 1

        # Flatten discovered files into a single list
        files_list = []
        if discovered_files:
            await self.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AsyncLogger",
                f"_update_collector_status: Processing discovered_files for {collector_id}: {len(discovered_files)} folders",
            )
            for folder_path, files in discovered_files.items():
                files_list.extend(files)
                await self.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "AsyncLogger",
                    f"_update_collector_status: Added {len(files)} files from folder {folder_path}",
                )

        # Check for pending file updates from execution summary manager
        if hasattr(self, "orchestrator") and self.orchestrator:
            execution_summary_manager = getattr(
                self.orchestrator, "execution_summary_manager", None
            )
            if execution_summary_manager and hasattr(
                execution_summary_manager, "_pending_file_updates"
            ):
                key = f"{dut_id}:{collector_id}"
                if key in execution_summary_manager._pending_file_updates:
                    pending_files = execution_summary_manager._pending_file_updates.pop(
                        key
                    )
                    await self.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "AsyncLogger",
                        (
                            "_update_collector_status: "
                            f"{'Discarded' if authoritative_projection else 'Found'} "
                            f"pending file updates for {collector_id}: "
                            f"{len(pending_files)} folders"
                        ),
                    )
                    if not authoritative_projection:
                        for folder_path, files in pending_files.items():
                            files_list.extend(files)

        # Repeated reporting passes should add newly discovered files without
        # discarding artifacts recorded by the service-level finalization.
        if existing_files:
            files_list = existing_files + files_list
            await self.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AsyncLogger",
                f"_update_collector_status: Merging {len(existing_files)} existing files for {collector_id}",
            )

        # Convert file paths to be relative to DUT directory for portability
        # This makes the metadata more portable and consistent
        relative_files_list = []
        dut_path_str = f"{dut_id}/"
        for file_path in files_list:
            # Find the DUT directory in the path and make it relative from there
            if dut_path_str in file_path:
                # Extract everything after the DUT directory
                rel_path = file_path.split(dut_path_str, 1)[1]
                relative_files_list.append(rel_path)
            else:
                # If we can't find the DUT path, keep the original
                relative_files_list.append(file_path)

        relative_files_list = list(dict.fromkeys(relative_files_list))

        # Rewrites update an existing collector rather than adding another
        # execution to the status counters.
        if existing_collector:
            previous_counter = {
                "success": "successful",
                "degraded": "degraded",
                "error": "failed",
                "skipped": "skipped",
            }.get(existing_collector.get("status"))
            if previous_counter:
                dut_status[previous_counter] = max(0, dut_status[previous_counter] - 1)

        await self.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AsyncLogger",
            f"_update_collector_status: Final files_list for {collector_id}: {len(relative_files_list)} files (converted to relative paths)",
        )

        collector_record = {
            "status": status,
            "reason": reason,
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat(),
            "files": relative_files_list,
        }
        normalized_failure_category = normalize_collector_failure_category(
            status,
            failure_category,
        )
        collector_record["failure_category"] = normalized_failure_category
        result_key = f"{dut_id}:{collector_id}"
        stored_context = self.collector_results.get(result_key, {}).get("context", {})
        sanitizer = getattr(getattr(self, "sanitizer", None), "sanitize", None)
        outcome_details = extract_collector_outcome_details(
            stored_context,
            sanitizer=sanitizer if callable(sanitizer) else None,
        )
        if outcome_details is not None:
            collector_record["outcome_details"] = outcome_details
        dut_status["collectors"][collector_id] = collector_record

        if status == "success":
            dut_status["successful"] += 1
        elif status == "degraded":
            dut_status["degraded"] += 1
        elif status == "error":
            dut_status["failed"] += 1
        elif status == "skipped":
            dut_status["skipped"] += 1

        # Write group metadata
        await self._write_group_metadata(group, dut_id)

        # Debug: Log the metadata update
        await self.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AsyncLogger",
            f"Updated collector {collector_id} status to {status} in group {group} for DUT {dut_id}",
        )

    async def initialize_all_collector_metadata(self, dut_id: str) -> None:
        """
        Initialize all collector metadata.

        The implementation uses ``dut_id`` to initialize all collector metadata.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        if not self.orchestrator:
            return

        # Get all collector groups
        all_groups = self.orchestrator.get_all_collector_groups()

        for group in all_groups:
            await self._write_group_metadata(group, dut_id)

        await self.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AsyncLogger",
            f"Initialized all collector metadata for DUT {dut_id}",
        )

    async def _write_group_metadata(self, group: str, dut_id: str = None) -> None:
        """
        Write group metadata to JSON file with all collectors for the group.

        The implementation uses ``group`` and ``dut_id`` to write group metadata
        to JSON file with all collectors for the group. Success is reported only
        after the owning output boundary has completed its required write or
        publication step. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            group: Text supplied as group in the format accepted by this
                function.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        if self._get_tool_config_value("dry_run", False) is True:
            return

        sanitize = getattr(getattr(self, "sanitizer", None), "sanitize", None)

        if dut_id:
            # Write to DUT-specific metadata directory
            dut_metadata_dir = (
                self.base_log_dir / run_tree_path_component(dut_id, "dut") / ".metadata"
            )
            group_file = dut_metadata_dir / f"{group}.json"
        else:
            # Write to root metadata directory (for backward compatibility)
            group_file = self.metadata_dir / f"{group}.json"

        # Get all collectors for this group from orchestrator
        all_collectors = {}
        if self.orchestrator:
            all_collectors = self.orchestrator.get_collectors_for_group(group)

        # Create group metadata structure like legacy code
        group_metadata = {
            "metadata": {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
            },
            "status_fields": {
                "description": "Possible status values for collectors",
                "values": {
                    "Passed": "Collection completed successfully",
                    "Failed": "Collection failed",
                    "Degraded": "Collection completed with degraded results",
                    "Skipped": "Collection was skipped",
                    "Cancelled": "Collection was interrupted before completion",
                    "NotRan": "Collection was not included in current collection map",
                    "Partial": "Collection partially succeeded",
                },
                "collector_fields": {
                    "id": "Unique identifier for the collector (e.g., R1, H2)",
                    "name": "Name of the collector",
                    "report_role": "Catalog-owned semantic role used by reports",
                    "status": "Result status of the collection",
                    "reason": "Detailed message about the collection result",
                    "failure_category": (
                        "Optional canonical category for degraded, failed, or partial results"
                    ),
                    "execution_time": "Time taken to execute the collector",
                    "created_at": "When the collector was first initialized",
                    "updated_at": "When the collector was last updated",
                    "files": "List of files generated by this collector",
                },
            },
            "collectors": {},
        }

        def _legacy_status(status: Any) -> str:
            """
            Translate runtime/tracker status values to the group schema.

            The implementation uses ``status`` to translate runtime/tracker
            status values to the group schema.

            Args:
                status: Status consumed while the function attempts to translate
                    runtime/tracker status values to the group schema.

            Returns:
                The canonical legacy status.
            """
            normalized = getattr(status, "value", status)
            normalized = str(normalized or "").lower()
            if normalized in {
                "success",
                "pass",
                "passed",
                "complete",
                "completed",
            }:
                return "Passed"
            if normalized in {"error", "fail", "failed"}:
                return "Failed"
            if normalized == "degraded":
                return "Degraded"
            if normalized == "skipped":
                return "Skipped"
            if normalized in {"cancelled", "canceled"}:
                return "Cancelled"
            if normalized == "partial":
                return "Partial"
            return "NotRan"

        # Initialize every collector as NotRan so the summary accounts for the
        # full group. Runtime and tracker results below replace this state.
        for collector_id, collector_info in all_collectors.items():
            # Use lowercase collector ID like legacy format
            legacy_collector_id = collector_id.lower()
            group_metadata["collectors"][legacy_collector_id] = {
                "id": legacy_collector_id,
                "name": collector_info.get("name", collector_id),
                "report_role": collector_info.get("report_role", ""),
                "status": "NotRan",
                "reason": "Collector was not included in the current collection map",
                "failure_category": None,
                "execution_time": "",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": None,
                "files": [],
            }

        # Update with actual execution results for the specific DUT
        if (
            group in self.collector_status
            and dut_id
            and dut_id in self.collector_status[group]
        ):
            dut_status = self.collector_status[group][dut_id]
            for collector_id, collector_result in dut_status.get(
                "collectors", {}
            ).items():
                # Use lowercase collector ID like legacy format
                legacy_collector_id = collector_id.lower()
                if legacy_collector_id in group_metadata["collectors"]:
                    status = collector_result.get("status", "NotRan")
                    legacy_status = _legacy_status(status)
                    result_timestamp = collector_result.get(
                        "timestamp",
                        datetime.now(timezone.utc).isoformat(),
                    )

                    collector_projection = {
                        "status": legacy_status,
                        "reason": sanitize_terminal_collector_reason(
                            status,
                            collector_result.get("reason", ""),
                            sanitizer=sanitize if callable(sanitize) else None,
                        ),
                        "execution_time": collector_result.get("execution_time", 0.0),
                        "created_at": result_timestamp,
                        "updated_at": result_timestamp,
                        "files": collector_result.get("files", []),
                    }
                    failure_category = normalize_collector_failure_category(
                        status,
                        collector_result.get("failure_category"),
                    )
                    collector_projection["failure_category"] = failure_category
                    group_metadata["collectors"][legacy_collector_id].update(
                        collector_projection
                    )

        # Baseboard/config filtering happens before a service executes, so those
        # skips never enter logger.collector_status. Merge their authoritative
        # tracker state without overriding richer service execution results.
        tracker = getattr(self.orchestrator, "status_tracker", None)
        tracker_entries = getattr(tracker, "collector_statuses", None)
        if dut_id and isinstance(tracker_entries, dict):
            for collector_id in all_collectors:
                legacy_collector_id = collector_id.lower()
                collector_entry = group_metadata["collectors"][legacy_collector_id]
                if collector_entry["status"] != "NotRan":
                    continue
                tracker_entry = tracker_entries.get(f"{dut_id}:{collector_id}")
                if tracker_entry is None:
                    continue
                legacy_status = _legacy_status(getattr(tracker_entry, "status", None))
                if legacy_status == "NotRan":
                    continue
                start_time = getattr(tracker_entry, "start_time", None)
                end_time = getattr(tracker_entry, "end_time", None)
                created_at = start_time or end_time
                updated_at = end_time or start_time
                tracker_projection = {
                    "status": legacy_status,
                    "reason": sanitize_terminal_collector_reason(
                        getattr(tracker_entry, "status", None),
                        getattr(tracker_entry, "reason", ""),
                        sanitizer=sanitize if callable(sanitize) else None,
                    ),
                    "execution_time": getattr(tracker_entry, "execution_time", 0.0),
                    "created_at": (
                        created_at.astimezone(timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z")
                        if created_at
                        else None
                    ),
                    "updated_at": (
                        updated_at.astimezone(timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z")
                        if updated_at
                        else None
                    ),
                    "files": list(getattr(tracker_entry, "output_files", None) or []),
                }
                failure_category = normalize_collector_failure_category(
                    getattr(tracker_entry, "status", None),
                    getattr(tracker_entry, "failure_category", None),
                )
                tracker_projection["failure_category"] = failure_category
                collector_entry.update(tracker_projection)

        # Add summary section like legacy format
        total_collectors = len(group_metadata["collectors"])
        passed = sum(
            1 for c in group_metadata["collectors"].values() if c["status"] == "Passed"
        )
        failed = sum(
            1 for c in group_metadata["collectors"].values() if c["status"] == "Failed"
        )
        skipped = sum(
            1 for c in group_metadata["collectors"].values() if c["status"] == "Skipped"
        )
        not_ran = sum(
            1 for c in group_metadata["collectors"].values() if c["status"] == "NotRan"
        )
        partial = sum(
            1 for c in group_metadata["collectors"].values() if c["status"] == "Partial"
        )
        degraded = sum(
            1
            for c in group_metadata["collectors"].values()
            if c["status"] == "Degraded"
        )
        cancelled = sum(
            1
            for c in group_metadata["collectors"].values()
            if c["status"] == "Cancelled"
        )

        group_metadata["summary"] = {
            "total_collectors": total_collectors,
            "passed": passed,
            "failed": failed,
            "degraded": degraded,
            "skipped": skipped,
            "not_ran": not_ran,
            "partial": partial,
            "cancelled": cancelled,
        }

        await self._write_metadata_json(group_file, group_metadata)

    def _build_root_summary(
        self,
        *,
        total_duts: int,
        total_collectors: int,
        successful_collectors: int,
        degraded_collectors: int,
        failed_collectors: int,
        partial_collectors: int,
        skipped_collectors: int,
        cancelled_collectors: int,
        not_ran_collectors: int,
    ) -> Dict[str, Any]:
        """
        Build the root metadata summary.

        Prefers the status tracker's single source of truth (which separates
        pre-execution ``filtered_out`` from runtime ``skipped`` and provides the
        collection percentage); falls back to the counts derived from the
        per-group metadata when no tracker is attached.

        Args:
            total_duts: Numeric total duts used while the operation performs
                bounded accounting.
            total_collectors: Numeric total collectors used while the operation
                performs bounded accounting.
            successful_collectors: Numeric successful collectors used while the
                operation performs bounded accounting.
            degraded_collectors: Numeric degraded collectors used while the
                operation performs bounded accounting.
            failed_collectors: Numeric failed collectors used while the
                operation performs bounded accounting.
            partial_collectors: Numeric partial collectors used while the
                operation performs bounded accounting.
            skipped_collectors: Numeric skipped collectors used while the
                operation performs bounded accounting.
            cancelled_collectors: Numeric cancelled collectors used while the
                operation performs bounded accounting.
            not_ran_collectors: Numeric not ran collectors used while the
                operation performs bounded accounting.

        Returns:
            The validated ``summary``.
        """
        tracker = getattr(getattr(self, "orchestrator", None), "status_tracker", None)
        aligned = None
        if tracker is not None and hasattr(tracker, "compute_aligned_stats"):
            try:
                candidate = tracker.compute_aligned_stats()
                if isinstance(candidate, dict):
                    aligned = candidate
            except Exception:
                aligned = None

        if aligned is not None:
            total_collectors = aligned["total"]
            successful_collectors = aligned["completed"]
            degraded_collectors = aligned["degraded"]
            failed_collectors = aligned["failed"]
            partial_collectors = aligned["partial"]
            skipped_collectors = aligned["skipped"]
            cancelled_collectors = aligned.get("cancelled", cancelled_collectors)
            filtered_out = aligned["filtered_out"]
            collectors_to_run = aligned["collectors_to_run"]
            collection_pct = aligned["collection_pct"]
        else:
            filtered_out = 0
            collectors_to_run = max(total_collectors - skipped_collectors, 0)
            obtained = successful_collectors + degraded_collectors + partial_collectors
            collection_pct = (
                round(obtained / collectors_to_run * 100, 1)
                if collectors_to_run
                else 0.0
            )

        run_outcome = getattr(tracker, "run_outcome", {})
        if (
            isinstance(run_outcome, dict)
            and run_outcome.get("status") == "runtime_failed"
        ):
            overall_status = "Failed"
        elif failed_collectors > 0:
            overall_status = "Failed"
        elif partial_collectors > 0:
            overall_status = "Partial"
        elif degraded_collectors > 0:
            overall_status = "Degraded"
        else:
            overall_status = "Passed"

        summary = {
            "total_duts": total_duts,
            "total_collectors": total_collectors,
            "collectors_to_run": collectors_to_run,
            "successful_collectors": successful_collectors,
            "degraded_collectors": degraded_collectors,
            "partial_collectors": partial_collectors,
            "failed_collectors": failed_collectors,
            "skipped_collectors": skipped_collectors,
            "cancelled_collectors": 0,
            "filtered_out_collectors": filtered_out,
            "not_applicable_collectors": not_ran_collectors,
            "overall_collection_pct": collection_pct,
            "overall_status": overall_status,
        }
        if cancelled_collectors:
            summary["cancelled_collectors"] = cancelled_collectors
        return summary

    @staticmethod
    def _project_root_run_outcome(
        root_metadata: Dict[str, Any], run_outcome: Any
    ) -> Dict[str, Any]:
        """
        Mirror the status tracker's authoritative terminal record.

        Shape and sanitization belong to ``CollectionStatusTracker``. Keeping
        this projection byte-for-byte equivalent avoids a second validator
        drifting from the root ``collection_status.json`` authority.

        Args:
            root_metadata: Mapping supplying fields for mirror the status
                tracker's authoritative terminal record.
            run_outcome: Run outcome consumed while the function attempts to
                mirror the status tracker's authoritative terminal record.

        Returns:
            The validated ``root_metadata``.
        """
        if isinstance(run_outcome, dict):
            root_metadata["metadata"]["run_outcome"] = copy.deepcopy(run_outcome)
        return root_metadata

    def _record_dut_metadata_identities(self) -> None:
        """
        Record the published directory name in each DUT metadata envelope.

        The implementation uses current instance state to record the published
        directory name in each DUT metadata envelope. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        """
        import stat
        import tempfile

        for dut_log_dir in self.dut_log_dirs.values():
            dut_log_dir = Path(dut_log_dir)
            metadata_path = dut_log_dir / ".metadata" / "metadata.json"
            if not metadata_path.is_file():
                continue

            with metadata_path.open("r", encoding="utf-8") as handle:
                document = json.load(handle)
            metadata = document.setdefault("metadata", {})
            dut_id = dut_log_dir.name
            if metadata.get("dut_id") == dut_id:
                continue
            metadata["dut_id"] = dut_id

            temporary_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    prefix=f".{metadata_path.name}.",
                    suffix=".tmp",
                    dir=metadata_path.parent,
                    delete=False,
                ) as handle:
                    temporary_path = Path(handle.name)
                    safe_json_dump(document, handle, indent=4)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(
                    temporary_path,
                    stat.S_IMODE(metadata_path.stat().st_mode),
                )
                os.replace(temporary_path, metadata_path)
            except BaseException:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)
                raise

    async def _create_root_metadata_aggregator(self) -> None:
        """
        Create root metadata aggregator with tool-wide summary.

        Aggregates metadata from all DUTs into a root-level summary file.
        """
        self._record_dut_metadata_identities()

        # Calculate overall statistics across all DUTs
        total_duts = len(self.dut_log_dirs)
        total_collectors = 0
        successful_collectors = 0
        degraded_collectors = 0
        failed_collectors = 0
        partial_collectors = 0
        skipped_collectors = 0
        cancelled_collectors = 0
        not_ran_collectors = 0

        collection_level = "L1"
        try:
            config_manager = getattr(self.orchestrator, "config_manager", None)
            if config_manager is not None:
                tool_config = config_manager.get_tool_config()
                configured_level = (
                    tool_config.get("collection_level")
                    if isinstance(tool_config, dict)
                    else getattr(tool_config, "collection_level", None)
                )
                configured_level = getattr(configured_level, "value", configured_level)
                if isinstance(configured_level, str) and configured_level:
                    collection_level = configured_level
        except Exception:
            # Metadata generation must remain available when configuration is
            # absent or only partially initialized.
            pass

        tracker = getattr(getattr(self, "orchestrator", None), "status_tracker", None)
        run_outcome = getattr(tracker, "run_outcome", None)

        dut_summaries = {}

        # Aggregate statistics from all DUTs
        for dut_id in self.dut_log_dirs:
            dut_summary = {
                "total_collectors": 0,
                "successful_collectors": 0,
                "degraded_collectors": 0,
                "failed_collectors": 0,
                "partial_collectors": 0,
                "skipped_collectors": 0,
                "cancelled_collectors": 0,
                "not_ran_collectors": 0,
                "groups": {},
            }

            # Count collectors by group for this DUT
            for group in ["redfish", "ipmi", "ssh", "host", "health_check"]:
                if (
                    group in self.collector_status
                    and dut_id in self.collector_status[group]
                ):
                    dut_collectors = self.collector_status[group][dut_id].get(
                        "collectors", {}
                    )
                    dut_summary["groups"][group] = len(dut_collectors)

                    for collector_result in dut_collectors.values():
                        status = collector_result.get("status", "NotRan")
                        dut_summary["total_collectors"] += 1
                        total_collectors += 1

                        if status == "success":
                            dut_summary["successful_collectors"] += 1
                            successful_collectors += 1
                        elif status == "degraded":
                            dut_summary["degraded_collectors"] += 1
                            degraded_collectors += 1
                        elif status == "error":
                            dut_summary["failed_collectors"] += 1
                            failed_collectors += 1
                        elif status == "partial":
                            dut_summary["partial_collectors"] += 1
                            partial_collectors += 1
                        elif status == "skipped":
                            dut_summary["skipped_collectors"] += 1
                            skipped_collectors += 1
                        elif status == "cancelled":
                            dut_summary["cancelled_collectors"] += 1
                            cancelled_collectors += 1
                        else:
                            dut_summary["not_ran_collectors"] += 1
                            not_ran_collectors += 1

            # Add timing summary for this DUT if available
            if (
                hasattr(self, "orchestrator")
                and self.orchestrator
                and hasattr(self.orchestrator, "timing_manager")
            ):
                timing_getter = (
                    self.orchestrator.timing_manager.get_timing_summary_for_metadata
                )
                try:
                    timing_summary = timing_getter(dut_id=dut_id)
                except TypeError as exc:
                    if "unexpected keyword argument 'dut_id'" not in str(exc):
                        raise
                    timing_summary = timing_getter()
                if timing_summary and "collectors" in timing_summary:
                    # Calculate timing summary for this DUT
                    dut_collectors = timing_summary["collectors"]
                    dut_timing = {
                        "total_collectors": len(dut_collectors),
                        "max_execution_time": 0.0,
                        "total_execution_time": 0.0,
                        "avg_execution_time": 0.0,
                        "collector_times": {},
                    }

                    for collector_id, collector_data in dut_collectors.items():
                        execution_time = collector_data.get("total_time", 0.0)
                        dut_timing["collector_times"][collector_id] = execution_time
                        dut_timing["total_execution_time"] += execution_time
                        dut_timing["max_execution_time"] = max(
                            dut_timing["max_execution_time"], execution_time
                        )

                    if dut_timing["total_collectors"] > 0:
                        dut_timing["avg_execution_time"] = (
                            dut_timing["total_execution_time"]
                            / dut_timing["total_collectors"]
                        )

                    dut_summary["timing_summary"] = dut_timing

            dut_summaries[dut_id] = dut_summary

        # Create root metadata structure (legacy format). Dry-run augments the
        # envelope with typed planning lifecycle fields.
        lifecycle_metadata = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "tool_version": "nvdebugtool",
            "collection_level": collection_level,
        }
        dry_run = bool(self._get_tool_config_value("dry_run", False))
        if dry_run:
            lifecycle_metadata.update(self._dry_run_lifecycle_metadata())
            lifecycle_metadata["sanitization_details"] = {
                "state": (
                    "disabled_by_user"
                    if lifecycle_metadata["sanitization"] == "disabled_by_user"
                    else "complete"
                )
            }

        root_metadata = {
            "metadata": lifecycle_metadata,
            "payload": {
                # Platform info will be populated by DUT-specific metadata
            },
            "collectors": {
                "Redfish": [],
                "IPMI": [],
                "SSH": [],
                "Host": [],
                "HealthCheck": [],
            },
            "summary": self._build_root_summary(
                total_duts=total_duts,
                total_collectors=total_collectors,
                successful_collectors=successful_collectors,
                degraded_collectors=degraded_collectors,
                failed_collectors=failed_collectors,
                partial_collectors=partial_collectors,
                skipped_collectors=skipped_collectors,
                cancelled_collectors=cancelled_collectors,
                not_ran_collectors=not_ran_collectors,
            ),
            "duts": dut_summaries,
        }
        if dry_run:
            root_metadata["summary"]["cancelled_collectors"] = 0

        from ..version import __version__

        root_metadata["metadata"]["tool_version"] = __version__
        root_file = self.metadata_dir / "metadata.json"
        root_metadata["metadata"].update(self._retained_bundle_metadata())

        async with asyncio.Lock():
            existing_root_lifecycle = {}
            if root_file.is_file():
                try:
                    with root_file.open("r", encoding="utf-8") as handle:
                        existing_document = json.load(handle)
                    if isinstance(existing_document, dict):
                        existing_root_lifecycle = existing_document.get("metadata", {})
                except (OSError, UnicodeError, json.JSONDecodeError):
                    pass
            root_metadata["metadata"].update(
                self._sanitization_lifecycle_metadata(
                    existing_root_lifecycle,
                    preserve_details=True,
                )
            )
            rendered_root = safe_json_dumps(
                self._project_root_run_outcome(root_metadata, run_outcome),
                indent=4,
            ).encode("utf-8")
            self._atomic_publish_collector_output(root_file, rendered_root)

    async def write_dependency_metadata(
        self, dependency_data: Dict[str, Any], dut_id: str = None
    ) -> None:
        """
        Merge dependency checks into the legacy metadata document.

        Serialize cooperating writers on this client through the pinned metadata
        directory, without requesting an NFS server-side regular-file lock.
        Wait for ownership before worker admission and retain it through the
        durable write, including cancellation of the asynchronous caller.

        Args:
            dependency_data: Collector IDs mapped to required and optional
                dependency check results to merge into the existing document.
            dut_id: DUT owning the metadata, or ``None`` for root metadata.

        Raises:
            OSError: If the directory changes or required persistence fails.
        """
        if dut_id:
            # Write to DUT-specific metadata directory
            dut_metadata_dir = (
                self.base_log_dir / run_tree_path_component(dut_id, "dut") / ".metadata"
            )
            dep_file = dut_metadata_dir / "dependency_check.json"
        else:
            # Write to root metadata directory (for backward compatibility)
            dep_file = self.metadata_dir / "dependency_check.json"

        # Convert to legacy format - exact structure from legacy dependency_checker.py
        legacy_dependency_data = {
            "metadata": {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
            },
            "status_fields": {
                "description": "Possible status values for dependency checks",
                "values": {
                    "passed": "Dependency check passed successfully",
                    "failed": "Dependency check failed",
                    "skipped": "Dependency check was skipped",
                    "not_applicable": "Dependency check is not applicable for this collector",
                },
                "dependency_types": {
                    "command": "Check for availability of a command in PATH",
                    "command_version": "Check for availability of a command and optionally verify its version",
                    "file": "Check for existence of a file or glob pattern",
                    "service": "Check if a service is running",
                },
                "dependency_fields": {
                    "name": "Name of the dependency being checked",
                    "type": "Type of dependency (command, command_version, file, or service)",
                    "status": "Result status of the check",
                    "message": "Detailed message about the check result (includes installation instructions if available)",
                    "required": "Whether this dependency is required (true) or optional (false)",
                    "install_instructions": "Installation instructions for the dependency (optional)",
                    "min_version": "Minimum required version for command_version type (optional)",
                    "max_version": "Maximum allowed version for command_version type (optional)",
                    "version_cmd": "Custom command to get version for command_version type (optional, defaults to '--version')",
                },
            },
            "collectors": {},
            "summary": {
                "total_checks": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "not_applicable": 0,
                "required_failed": 0,
                "optional_failed": 0,
            },
        }

        # Convert collectors to legacy format
        for collector_id, collector_data in dependency_data.items():
            # Convert to lowercase for legacy format
            legacy_collector_id = collector_id.lower()

            # Convert dependencies to legacy format (exact structure from legacy DependencyResult)
            dependencies = []

            # Add required dependencies
            for dep in collector_data.get("required_dependencies", []):
                status = "passed" if dep.get("available", False) else "failed"
                dependencies.append(
                    {
                        "name": dep.get("name", ""),
                        "type": dep.get("type", "command"),
                        "status": status,
                        "message": dep.get("error_message", "")
                        or "Dependency check completed successfully",
                        "required": True,
                    }
                )

            # Add optional dependencies
            for dep in collector_data.get("optional_dependencies", []):
                status = "passed" if dep.get("available", False) else "failed"
                dependencies.append(
                    {
                        "name": dep.get("name", ""),
                        "type": dep.get("type", "command"),
                        "status": status,
                        "message": dep.get("error_message", "")
                        or "Dependency check completed successfully",
                        "required": False,
                    }
                )

            legacy_dependency_data["collectors"][legacy_collector_id] = {
                "id": legacy_collector_id,
                "name": collector_data.get("collector_name", ""),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "dependencies": dependencies,
            }

        def persist_dependency_metadata(
            publication_lock: PinnedDirectoryLock,
        ) -> Optional[str]:
            """
            Merge dependency evidence through its already locked directory.

            The caller acquires the directory lock before admitting this worker.
            Locking an NFS regular file would contact the server's lock service
            and could occupy every filesystem worker indefinitely. Directory
            locking follows the existing report-publication boundary instead.

            Args:
                publication_lock: Pinned metadata directory held until this
                    worker finishes, including asynchronous cancellation.

            Returns:
                A parse warning for the async owner to log, or ``None``.

            Raises:
                OSError: If the directory changes or output persistence fails.
            """

            parse_warning = None
            existing_content = read_locked_bytes(
                publication_lock,
                dep_file.name,
                max_bytes=MAX_LOG_FILE_SIZE_MB * 1024 * 1024,
            ).decode("utf-8")
            if not existing_content.strip():
                existing_data = {}
            else:
                try:
                    existing_data = json.loads(existing_content)
                    if not isinstance(existing_data, dict):
                        existing_data = {}
                except (ValueError, RecursionError) as error:
                    existing_data = {}
                    parse_warning = (
                        f"Failed to parse dependency metadata {dep_file}: "
                        f"{error}. Rebuilding file."
                    )
            existing_data = self._merge_dependency_metadata(
                existing_data, legacy_dependency_data
            )
            atomic_publish_locked_bytes(
                publication_lock,
                dep_file.name,
                safe_json_dumps(existing_data, indent=4).encode("utf-8"),
            )
            return parse_warning

        # Wait for another publisher asynchronously, before consuming a shared
        # filesystem worker. The directory descriptor releases its lock only
        # after the managed write has been joined, including cancellation.
        lock = self._get_lock_for_path(dep_file)
        async with lock:
            try:
                await run_managed_filesystem_operation(
                    dep_file.parent.mkdir, 0o777, True, True
                )
                async with async_report_publication_lock(
                    dep_file.parent
                ) as publication_lock:
                    parse_warning = await run_managed_filesystem_operation(
                        persist_dependency_metadata, publication_lock
                    )
            except Exception as error:
                await self.log_error(
                    "DEPENDENCY_METADATA_ERROR",
                    f"Unexpected error updating dependency metadata {dep_file}: {error}",
                    dut_id=dut_id,
                )
                raise
            if parse_warning is not None:
                await self._log_simple("WARN", parse_warning, dut_id)

    async def write_preflight_metadata(
        self, dut_id: str, preflight_data: Dict[str, Any]
    ) -> None:
        """
        Write preflight metadata for a specific DUT.

        The implementation uses ``dut_id`` and ``preflight_data`` to write
        preflight metadata for a specific DUT. Success is reported only after
        the owning output boundary has completed its required write or
        publication step. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            preflight_data: Mapping supplying fields for preflight metadata for
                a specific DUT.
        """
        # Create DUT-specific metadata directory
        dut_metadata_dir = (
            self.base_log_dir / run_tree_path_component(dut_id, "dut") / ".metadata"
        )

        # Convert to legacy preflight format
        legacy_preflight = {
            "metadata": {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
            },
            "preflights": {},
        }

        # Define main preflight checks that we actually use
        all_preflights = get_main_preflight_names()

        # Convert services to legacy format
        services = preflight_data.get("services", {})
        sanitize = getattr(getattr(self, "sanitizer", None), "sanitize", None)

        # Initialize all preflights with "Skipped" status
        for preflight_name in all_preflights:
            legacy_preflight["preflights"][preflight_name] = {
                "status": "Skipped",
                "reason": "Preflight check was not executed",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": None,
            }

        # Update with actual results
        for service_name, service_result in services.items():
            status = service_result.get("status", "unknown")
            # Convert to legacy status format
            legacy_status = (
                "Passed"
                if status == "pass"
                else "Failed" if status == "fail" else "Skipped"
            )

            legacy_preflight["preflights"][service_name.upper()] = {
                "status": legacy_status,
                "reason": sanitize_terminal_collector_reason(
                    "success",
                    service_result.get("message", ""),
                    sanitizer=sanitize if callable(sanitize) else None,
                ),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": None,
            }

        preflight_file = dut_metadata_dir / "preflight.json"
        await self._write_metadata_json(preflight_file, legacy_preflight)

    async def finalize(self) -> None:
        """
        Finalize logging system and create summary metadata.

        Creates root metadata aggregator, group metadata files, and stops
        logging.
        """
        await self._create_root_metadata_aggregator()
        await self._create_all_group_files()
        self._align_dut_collection_levels()
        await self.stop()

    def _align_dut_collection_levels(self) -> None:
        """
        Align per-DUT lifecycle metadata with the finalized root level.

        The implementation uses current instance state to align per-DUT
        lifecycle metadata with the finalized root level. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle.
        """
        import stat
        import tempfile

        root_metadata_path = self.metadata_dir / "metadata.json"
        if not root_metadata_path.is_file():
            return
        with root_metadata_path.open("r", encoding="utf-8") as handle:
            root_document = json.load(handle)
        collection_level = root_document.get("metadata", {}).get("collection_level")
        if collection_level not in {"L1", "L2", "L3"}:
            return

        for metadata_path in sorted(
            self.base_log_dir.glob("*/.metadata/metadata.json")
        ):
            with metadata_path.open("r", encoding="utf-8") as handle:
                document = json.load(handle)
            metadata = document.setdefault("metadata", {})
            if metadata.get("collection_level") == collection_level:
                continue
            metadata["collection_level"] = collection_level
            target_mode = stat.S_IMODE(metadata_path.stat().st_mode)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{metadata_path.name}.",
                suffix=".tmp",
                dir=metadata_path.parent,
            )
            temporary_path = Path(temporary_name)
            try:
                os.fchmod(descriptor, target_mode)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    descriptor = -1
                    safe_json_dump(document, handle, indent=4)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary_path, metadata_path)
            except BaseException:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass
                raise

    async def _create_all_group_files(self) -> None:
        """
        Create metadata files for all collector groups at DUT level.

        Creates metadata files for all possible collector groups (redfish, ipmi,
        ssh, host, health_check) even if not executed, for consistent structure.
        """
        if not self.orchestrator:
            return

        # Define all possible groups
        all_groups = ["redfish", "ipmi", "ssh", "host", "health_check"]

        # Create group files for each DUT only (not at root level)
        for dut_id in self.dut_log_dirs:
            for group in all_groups:
                await self._write_group_metadata(group, dut_id)
