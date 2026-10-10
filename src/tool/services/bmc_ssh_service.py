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
BMC SSH Service - Handles all BMC SSH-related collector operations.

Provides SSH-based collectors for BMC access including command execution, file
transfer, and log collection via SSH protocol.
"""

import asyncio
import datetime
import glob
import json
import logging
import os
import posixpath
import re
import shlex
import stat
import tempfile
import time
import traceback
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import partial
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Set, Tuple, Union

from ..core.dut_file_transfer import BoundedBMCDownloadResult
from ..utils.artifact_paths import bundle_relative_artifact_path, run_tree_dut_component
from ..utils.bounded_archive import (
    TarArchiveMember,
    collection_archive_size_advisory,
    inspect_tar_archive_metadata,
    resolve_collection_archive_limits,
    rewrite_tar_gz_regular_files,
)
from ..utils.command_safety import (
    build_remote_cmd,
    inspect_shell_template_placeholder_contexts,
    is_bmc_command_failure_output,
    quote_arg,
    validate_password_stdin_line,
    validate_ping_target,
)
from ..utils.device_discovery import (
    bounded_device_matches,
    safe_remote_output_component,
)
from ..utils.managed_filesystem import run_managed_filesystem_operation
from ..utils.streaming import format_stream_window_component, normalize_stream_window
from ..utils.tar_utils import (
    TRUSTED_REMOTE_TAR_COMMAND,
    build_remote_tar_create_command,
    build_remote_tar_hardlink_probe_command,
)
from ..utils.temp_dir_config import local_temp_dir
from .base_service import BaseService

if TYPE_CHECKING:
    from ..core.dut_manager import DUT

logger = logging.getLogger(__name__)

_I2CDETECT_SKIPPED_ADDRESS_WARNING = re.compile(
    r"warning:\s*can't use smbus quick write command,\s*will skip some addresses",
    re.IGNORECASE,
)
_OUTPUT_PATTERN_TRAILING_PLACEHOLDER = re.compile(r"\{[^{}]+\}(?P<suffix>[^{}]+)$")
_I2C_ADAPTER_LINE = re.compile(r"^\s*i2c-(?P<bus>\d+)\b")
_ALL_FF_I2C_PAYLOAD = re.compile(r"(?:\s*0xff)+\s*\Z", re.IGNORECASE)
_MAX_SCAN_EXCLUSION_PATTERN_LENGTH = 512
_I2C_VARIANT_LIST_SELECTORS = ("command_groups", "name_prefixes")
_SCRIPT_EXECUTION_MODES = frozenset({"direct", "bash", "sh", "python", "python3"})
_SAFE_REMOTE_SCRIPT_PATH = re.compile(r"/(?:[A-Za-z0-9._+@-]+/)*[A-Za-z0-9._+@-]+\Z")
_SAFE_REMOTE_COMMAND_NAME = re.compile(r"[A-Za-z0-9._+@-]+\Z")
_BMC_ARCHIVE_DOWNLOAD_CHUNK_BYTES = 64 * 1024
_BMC_DISCOVERED_FILE_MAX_COUNT = 10
_BMC_DISCOVERED_FILE_DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024
_BMC_DISCOVERED_FILE_HARD_MAX_BYTES = 256 * 1024 * 1024 * 1024
_BMC_REMOTE_CLEANUP_TIMEOUT_SECONDS = 30.0
_BMC_REMOTE_PATH_MAX_BYTES = 4096
_BMC_REMOTE_STAGING_PREFIX = ".nvdebug_bmc_transfer."
_BMC_REMOTE_STAGING_SUFFIX = re.compile(r"[A-Za-z0-9]{10}\Z")
_BMC_MAX_TRANSFER_RETRIES = 10
_BMC_MAX_RETRY_DELAY_SECONDS = 60.0
_BMC_MAX_REPORTED_ARCHIVE_LINK_PATHS = 20
_BMC_MAX_REPORTED_ARCHIVE_MISSING_MEMBER_PATHS = 20
_BMC_MAX_REPORTED_ARCHIVE_CONDITION_MESSAGES = 20
_BMC_ARCHIVE_MISSING_MEMBER_POLICIES = frozenset({"error", "partial"})
_TAR_HARDLINK_ADVISORY = (
    "nvdebug: TAR hard-link dereference unavailable; link members may be dropped"
)
_TAR_MISSING_MEMBER_SUFFIXES = (
    ": cannot stat: no such file or directory",
    ": no such file or directory",
    ": file removed before we read it",
)


@dataclass(frozen=True)
class _TarWarningClassification:
    """
    Describe a bounded, fail-closed classification of TAR diagnostics.

    Instances separate diagnostic recognition from collector-authored policy.
    A recognized missing member therefore remains unusable until the caller
    explicitly opts into partial archive handling and validates the artifact.

    Attributes:
        all_recognized: Whether every nonempty stderr line belongs to the
            explicitly supported TAR diagnostic set.
        permission_denied: Whether TAR could not read at least one member due
            to permissions.
        file_changed: Whether TAR observed a live member changing while read.
        hardlink_materialization_unavailable: Whether the tool-authored
            BusyBox compatibility marker was emitted.
        missing_members: Bounded normalized member paths whose source data was
            unavailable while TAR traversed the selected tree.
        missing_member_count: Total recognized missing-member diagnostic count.
        missing_members_truncated: Whether additional recognized paths were
            omitted from ``missing_members`` to keep result context bounded.
        condition_messages: Bounded causal TAR diagnostics that describe
            confirmed or policy-accepted artifact loss.
        condition_messages_truncated: Whether additional causal diagnostics
            were omitted from ``condition_messages``.
        advisory_messages: Bounded tool-authored capability notices whose
            actual artifact impact must be resolved by archive validation.
    """

    all_recognized: bool
    permission_denied: bool
    file_changed: bool
    hardlink_materialization_unavailable: bool
    missing_members: Tuple[str, ...]
    missing_member_count: int
    missing_members_truncated: bool
    condition_messages: Tuple[str, ...]
    condition_messages_truncated: bool
    advisory_messages: Tuple[str, ...]


class _I2CCommandTemplateError(ValueError):
    """
    An I2C config placeholder cannot be rendered as shell data safely.

    Callers receive this exception when the i2 c command template error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


@dataclass(frozen=True)
class _I2CResultValidation:
    """
    Describe data-driven semantic checks for one I2C command result.

    The immutable rule keeps platform register knowledge in authored YAML while
    the execution engine applies only generic byte-payload and validity-bit
    semantics. A staleness command is another command in the same owned batch,
    so its transport outcome and payload are available before any telemetry is
    classified as usable.

    Attributes:
        invalid_payloads: Exact byte sequences that represent invalid sensor
            sentinels rather than usable telemetry.
        staleness_command: Command name whose one-byte output carries the
            validity bit for this result, or ``None`` when no bit applies.
        staleness_mask: Nonzero byte mask that identifies the command's stale
            bit, or ``None`` when no staleness command applies.
    """

    invalid_payloads: Tuple[Tuple[int, ...], ...]
    staleness_command: Optional[str]
    staleness_mask: Optional[int]


def _quote_shell_data_always(value: str) -> str:
    """
    Return one quoted shell word even when ``value`` looks lexer-safe.

    ``shlex.quote`` deliberately leaves simple words bare. That is unsafe for
    template substitution because an adjacent operator can then reinterpret a
    value as shell syntax (for example ``2>file`` or ``PATH=value``), and a bare
    reserved word such as ``if`` can affect parsing. Keeping the quote markers
    in the rendered program preserves the value as data during tokenization.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        The canonical quote shell data always text.
    """

    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render_i2c_command_template_once(
    template: str,
    resolved_config: Dict[str, str],
) -> str:
    """
    Render config operands once without reinterpreting replacement text.

    I2C command templates are governed shell programs, so their operators must
    remain intact. Only simple ``{name}`` config placeholders are data. Quote
    those values for their existing top-level shell quote context while scanning
    the original template exactly once; a value containing another placeholder
    is therefore always literal data and can never trigger a second
    substitution. Placeholders in nested shell evaluation contexts are rejected
    because top-level quoting cannot make them data in the inner language. Shell
    parameter expansions such as ``${driver:-unknown}`` are not config
    placeholders and remain unchanged.

    Args:
        template: Text supplied as template in the format accepted by this
            function.
        resolved_config: Resolved config governing config operands once without
            reinterpreting replacement text.

    Returns:
        The canonical i2c command template once text.

    Raises:
        TypeError: If the i2c command template is not a string; or i2c command
            placeholder ``name`` lacks a string value.
        _I2CCommandTemplateError: If I2C command placeholder ``name`` cannot be
            rendered safely in or after unsupported shell context: ``context``.
        KeyError: If unresolved I2C command placeholder: ``name``.
    """

    if not isinstance(template, str):
        raise TypeError("I2C command template must be a string")

    rendered: List[str] = []
    cursor = 0
    for (
        match,
        quote_context,
        unsupported_context,
    ) in inspect_shell_template_placeholder_contexts(template):
        literal = template[cursor : match.start()]
        rendered.append(literal)

        name = match.group("name")
        if unsupported_context is not None or quote_context == "comment":
            context = unsupported_context or "shell comment"
            raise _I2CCommandTemplateError(
                f"I2C command placeholder {name!r} cannot be rendered safely "
                f"in or after unsupported shell context: {context}"
            )
        if name not in resolved_config:
            raise KeyError(f"unresolved I2C command placeholder: {name}")
        value = resolved_config[name]
        if not isinstance(value, str):
            raise TypeError(f"I2C command placeholder {name!r} requires a string value")

        if quote_context == "single":
            rendered.append(value.replace("'", "'\"'\"'"))
        elif quote_context == "double":
            rendered.append(
                value.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("$", "\\$")
                .replace("`", "\\`")
            )
        else:
            rendered.append(_quote_shell_data_always(value))
        cursor = match.end()

    rendered.append(template[cursor:])
    return "".join(rendered)


class _BMCFileTransferPolicyError(RuntimeError):
    """
    A BMC archive violated the bounded transfer contract.

    Callers receive this exception when the BMC file transfer policy error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


def _is_bmc_path_control_character(character: str) -> bool:
    """
    Return whether a character is in the C0, DEL, or C1 control ranges.

    The implementation uses ``character`` to determine whether a character is in
    the C0, DEL, or C1 control ranges.

    Args:
        character: Text supplied as character in the format accepted by this
            function.

    Returns:
        Whether a character is in the C0, DEL, or C1 control ranges.
    """

    codepoint = ord(character)
    return codepoint < 32 or 127 <= codepoint <= 159


def _normalize_bmc_remote_path(
    value: Any,
    *,
    field_name: str,
    allow_root: bool = False,
) -> str:
    """
    Return one canonical absolute BMC path or fail closed.

    The implementation uses ``value``, ``field_name``, and ``allow_root`` to
    produce one canonical absolute BMC path or fail closed. If the function
    cannot produce one canonical absolute BMC path or fail closed, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        value: Value object whose ``encode`` and ``strip`` state is read while
            performing one canonical absolute BMC path or fail closed.
        field_name: Field label included in validation failures for the selected
            input.
        allow_root: filesystem location used as the allow root for this
            operation.

    Returns:
        The validated ``normalized``.

    Raises:
        _BMCFileTransferPolicyError: If the ``field_name`` is not a nonempty
            unpadded string; ``field_name`` is too long; ``field_name`` contains
            control characters; or the ``field_name`` is not an absolute
            non-root path; or another input invariant is violated.
    """

    if not isinstance(value, str) or not value or value != value.strip():
        raise _BMCFileTransferPolicyError(
            f"{field_name} must be a nonempty unpadded string"
        )
    if (
        len(value.encode("utf-8", errors="surrogateescape"))
        > _BMC_REMOTE_PATH_MAX_BYTES
    ):
        raise _BMCFileTransferPolicyError(f"{field_name} is too long")
    if any(_is_bmc_path_control_character(character) for character in value):
        raise _BMCFileTransferPolicyError(f"{field_name} contains control characters")

    normalized = posixpath.normpath(value)
    if not posixpath.isabs(normalized) or (normalized == "/" and not allow_root):
        raise _BMCFileTransferPolicyError(
            f"{field_name} must be an absolute non-root path"
        )
    if value not in {normalized, f"{normalized}/"}:
        raise _BMCFileTransferPolicyError(f"{field_name} is not canonical")
    return normalized


def _resolve_bmc_artifact_max_bytes(value: Any) -> int:
    """
    Return one explicit finite per-artifact BMC transfer bound.

    The implementation uses ``value`` to produce one explicit finite
    per-artifact BMC transfer bound. If the function cannot produce one explicit
    finite per-artifact BMC transfer bound, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        value: Value evaluated while performing one explicit finite per-artifact
            BMC transfer bound.

    Returns:
        The validated ``value``.

    Raises:
        _BMCFileTransferPolicyError: If the max_artifact_bytes are not a
            positive integer no greater than
            ``_BMC_DISCOVERED_FILE_HARD_MAX_BYTES``.
    """

    if value is None:
        value = _BMC_DISCOVERED_FILE_DEFAULT_MAX_BYTES
    if (
        type(value) is not int
        or value <= 0
        or value > _BMC_DISCOVERED_FILE_HARD_MAX_BYTES
    ):
        raise _BMCFileTransferPolicyError(
            "max_artifact_bytes must be a positive integer no greater than "
            f"{_BMC_DISCOVERED_FILE_HARD_MAX_BYTES}"
        )
    return value


def _normalize_bmc_remote_file_path(value: Any, *, field_name: str) -> str:
    """
    Return one canonical absolute remote file path without a trailing slash.

    The implementation uses ``value`` and ``field_name`` to produce one
    canonical absolute remote file path without a trailing slash. If the
    function cannot produce one canonical absolute remote file path without a
    trailing slash, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        value: Value evaluated while performing one canonical absolute remote
            file path without a trailing slash.
        field_name: Field label included in validation failures for the selected
            input.

    Returns:
        The validated ``normalized``.

    Raises:
        _BMCFileTransferPolicyError: If ``field_name`` must not end with a
            separator.
    """

    normalized = _normalize_bmc_remote_path(value, field_name=field_name)
    if normalized != value:
        raise _BMCFileTransferPolicyError(f"{field_name} must not end with a separator")
    return normalized


def _local_file_identity(details: os.stat_result) -> Tuple[int, ...]:
    """
    Return the fields that must remain stable while staging an upload.

    The implementation uses ``details`` to produce the fields that must remain
    stable while staging an upload.

    Args:
        details: Details object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing
            fields that must remain stable while staging an upload.

    Returns:
        A tuple containing ``st dev``, ``st ino``, ``st mode``, ``st nlink``,
        ``st size``, ``st mtime ns``, and ``st ctime ns`` in that order.
    """

    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_nlink,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


async def _stage_local_bmc_upload_bounded(
    local_file: str,
    *,
    max_bytes: int,
    local_parent: Optional[str] = None,
) -> Tuple[Any, Path, int]:
    """
    Snapshot one stable no-follow regular file into private upload staging.

    The implementation uses ``local_file`` and ``max_bytes`` to snapshot one
    stable no-follow regular file into private upload staging. Owned
    asynchronous work is awaited before return, so completion does not leave an
    unobserved task behind. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. If the function
    cannot snapshot one stable no-follow regular file into private upload
    staging, its exception reaches the caller instead of being converted into a
    successful result. Cleanup in the ``finally`` path runs for successful,
    failed, and cancelled execution.

    Args:
        local_file: filesystem location used as the local file for this
            operation.
        max_bytes: Upper bound enforced for max bytes; the consuming boundary
            rejects or truncates values that exceed it.
        local_parent: Optional validated collector-local temporary directory
            beneath which private upload staging is created.

    Returns:
        A tuple containing ``private directory``, ``staged file``, and
        ``transferred`` in that order.

    Raises:
        _BMCFileTransferPolicyError: If the local upload path is not a nonempty
            string without NUL bytes; local upload path has no filename; local
            no-follow file validation is unavailable; or local upload source is
            not a stable bounded regular file; or another input invariant is
            violated.
    """

    if not isinstance(local_file, str) or not local_file or "\x00" in local_file:
        raise _BMCFileTransferPolicyError(
            "local upload path must be a nonempty string without NUL bytes"
        )
    basename = os.path.basename(local_file)
    if not basename or basename in {".", ".."}:
        raise _BMCFileTransferPolicyError("local upload path has no filename")

    open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", None)
    if nofollow_flag is None:
        raise _BMCFileTransferPolicyError(
            "local no-follow file validation is unavailable"
        )
    open_flags |= nofollow_flag

    source_fd = os.open(local_file, open_flags)
    private_directory = None
    try:
        source_before = os.fstat(source_fd)
        path_before = os.lstat(local_file)
        source_identity = _local_file_identity(source_before)
        if (
            _local_file_identity(path_before) != source_identity
            or not stat.S_ISREG(source_before.st_mode)
            or source_before.st_nlink != 1
            or source_before.st_size > max_bytes
        ):
            raise _BMCFileTransferPolicyError(
                "local upload source is not a stable bounded regular file"
            )

        private_directory = tempfile.TemporaryDirectory(
            prefix=".nvdebug_bmc_upload-",
            dir=local_parent,
        )
        private_path = Path(private_directory.name)
        private_details = private_path.lstat()
        if (
            not stat.S_ISDIR(private_details.st_mode)
            or stat.S_IMODE(private_details.st_mode) != 0o700
        ):
            raise _BMCFileTransferPolicyError(
                "local BMC upload staging is not a private directory"
            )

        staged_file = private_path / basename
        destination_fd = os.open(
            staged_file,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | nofollow_flag,
            0o600,
        )
        transferred = 0
        try:
            while True:
                chunk = os.read(source_fd, _BMC_ARCHIVE_DOWNLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                transferred += len(chunk)
                if transferred > max_bytes:
                    raise _BMCFileTransferPolicyError(
                        "local upload source exceeds max_artifact_bytes"
                    )
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise _BMCFileTransferPolicyError(
                            "local BMC upload staging made no write progress"
                        )
                    view = view[written:]
                # Local regular-file I/O is chunk-bounded; yield between
                # chunks so a large admitted upload cannot monopolize the
                # service event loop.
                await asyncio.sleep(0)
        finally:
            os.close(destination_fd)

        source_after = os.fstat(source_fd)
        path_after = os.lstat(local_file)
        staged_details = staged_file.lstat()
        if (
            _local_file_identity(source_after) != source_identity
            or _local_file_identity(path_after) != source_identity
            or transferred != source_before.st_size
            or not stat.S_ISREG(staged_details.st_mode)
            or staged_details.st_size != transferred
            or stat.S_IMODE(staged_details.st_mode) != 0o600
        ):
            raise _BMCFileTransferPolicyError(
                "local upload source changed while it was staged"
            )
        return private_directory, staged_file, transferred
    except BaseException:
        if private_directory is not None:
            private_directory.cleanup()
        raise
    finally:
        os.close(source_fd)


def _parse_bmc_discovered_file_inventory(
    command_output: Any,
) -> Tuple[str, ...]:
    """
    Parse a bounded newline-delimited BMC file inventory.

    The endpoint controls command output and may ignore the authored ``head``.
    Parse incrementally so an overlong first path or an eleventh path is
    rejected before either is materialized into the retained inventory.

    Args:
        command_output: Entries supplied as ``command_output`` and processed in
            caller-provided order.

    Returns:
        The BMC discovered file inventory returned in operation-defined order.

    Raises:
        _BMCFileTransferPolicyError: If the bmc file discovery output is not
            text; discovered BMC file path contains control characters;
            discovered BMC file path has invalid text encoding; or discovered
            BMC file path is too long.
    """

    if not isinstance(command_output, str):
        raise _BMCFileTransferPolicyError("BMC file discovery output must be text")
    if not command_output:
        return ()

    discovered: List[str] = []
    current_characters: List[str] = []
    current_bytes = 0

    def finish_line() -> None:
        """
        Finish line.

        The implementation uses current instance state to finish line. If the
        function cannot finish line, its exception reaches the caller instead of
        being converted into a successful result.

        Raises:
            _BMCFileTransferPolicyError: If BMC file discovery returned an empty
                path line; or BMC file discovery exceeded the 10-file limit.
        """
        nonlocal current_bytes
        if not current_characters:
            raise _BMCFileTransferPolicyError(
                "BMC file discovery returned an empty path line"
            )
        if len(discovered) >= _BMC_DISCOVERED_FILE_MAX_COUNT:
            raise _BMCFileTransferPolicyError(
                "BMC file discovery exceeded the 10-file limit"
            )
        raw_path = "".join(current_characters)
        normalized_path = _normalize_bmc_remote_file_path(
            raw_path,
            field_name="discovered BMC file path",
        )
        discovered.append(normalized_path)
        current_characters.clear()
        current_bytes = 0

    for index, character in enumerate(command_output):
        if character == "\n":
            if not current_characters and index == len(command_output) - 1:
                continue
            finish_line()
            continue
        if _is_bmc_path_control_character(character):
            raise _BMCFileTransferPolicyError(
                "discovered BMC file path contains control characters"
            )
        try:
            current_bytes += len(character.encode("utf-8", errors="surrogateescape"))
        except UnicodeEncodeError as error:
            raise _BMCFileTransferPolicyError(
                "discovered BMC file path has invalid text encoding"
            ) from error
        if current_bytes > _BMC_REMOTE_PATH_MAX_BYTES:
            raise _BMCFileTransferPolicyError("discovered BMC file path is too long")
        current_characters.append(character)

    if current_characters:
        finish_line()
    return tuple(discovered)


def _validate_bmc_private_staging_path(parent: str, command_output: Any) -> str:
    """
    Bind endpoint-returned ``mktemp`` output to the configured parent.

    The implementation uses ``parent`` and ``command_output`` to bind
    endpoint-returned ``mktemp`` output to the configured parent. If the
    function cannot bind endpoint-returned ``mktemp`` output to the configured
    parent, its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        parent: Text supplied as parent in the format accepted by this function.
        command_output: Command output consumed while the function attempts to
            bind endpoint-returned ``mktemp`` output to the configured parent.

    Returns:
        The validated ``candidate``.

    Raises:
        _BMCFileTransferPolicyError: If private BMC staging creation returned an
            invalid path; or private BMC staging path escaped its configured
            parent.
    """

    lines = str(command_output or "").splitlines()
    if len(lines) != 1 or lines[0] != lines[0].strip():
        raise _BMCFileTransferPolicyError(
            "private BMC staging creation returned an invalid path"
        )
    candidate = _normalize_bmc_remote_path(
        lines[0], field_name="private BMC staging path"
    )
    basename = posixpath.basename(candidate)
    suffix = basename.removeprefix(_BMC_REMOTE_STAGING_PREFIX)
    if (
        posixpath.dirname(candidate) != parent
        or not basename.startswith(_BMC_REMOTE_STAGING_PREFIX)
        or _BMC_REMOTE_STAGING_SUFFIX.fullmatch(suffix) is None
    ):
        raise _BMCFileTransferPolicyError(
            "private BMC staging path escaped its configured parent"
        )
    return candidate


def _validate_owned_bmc_upload_directory(value: Any) -> str:
    """
    Validate one private BMC upload directory carried between hooks.

    After applying local validation, the function forwards ``value`` to
    ``_validate_bmc_private_staging_path`` and preserves its return and
    exception contract. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path.

    Args:
        value: Value evaluated while performing one private BMC upload directory
            carried between hooks.

    Returns:
        The canonical owned BMC upload directory text.

    Raises:
        _BMCFileTransferPolicyError: If the owned bmc upload directory is not a
            nonempty string.
    """

    if not isinstance(value, str) or not value:
        raise _BMCFileTransferPolicyError(
            "owned BMC upload directory must be a nonempty string"
        )
    return _validate_bmc_private_staging_path(posixpath.dirname(value), value)


def _parse_bmc_archive_size(command_output: Any) -> int:
    """
    Parse one strict positive decimal remote archive size.

    The implementation uses ``command_output`` to parse one strict positive
    decimal remote archive size. Parsing or I/O must finish before the validated
    representation is made available to the caller. If the function cannot parse
    one strict positive decimal remote archive size, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        command_output: Command output consumed while the function attempts to
            parse one strict positive decimal remote archive size.

    Returns:
        The validated ``size``.

    Raises:
        _BMCFileTransferPolicyError: If remote archive size is invalid; or
            remote archive is empty.
    """

    lines = str(command_output or "").splitlines()
    if (
        len(lines) != 1
        or lines[0] != lines[0].strip()
        or not lines[0].isascii()
        or not lines[0].isdecimal()
    ):
        raise _BMCFileTransferPolicyError("remote archive size is invalid")
    size = int(lines[0])
    if size <= 0:
        raise _BMCFileTransferPolicyError("remote archive is empty")
    return size


def _validate_discovered_script_path(
    command_output: Any,
    *,
    search_directory: str,
    filename_pattern: str,
) -> str:
    """
    Validate an endpoint-returned script path before shell execution.

    Discovery is deliberately limited to one plain absolute path directly below
    the directory that was searched. The BMC controls command output, so a
    successful ``find`` exit status is not evidence that the returned text is a
    safe command operand or even matches the requested name. This directory
    policy is required for endpoint-returned paths that will be executed. Other
    endpoint-returned command operands must still be quoted with
    :func:`build_remote_cmd`, but read-only operands do not inherit this script
    execution policy.

    Args:
        command_output: Command output consumed while the function attempts to
            validate an endpoint-returned script path before shell execution.
        search_directory: filesystem location used as the search directory for
            this operation.
        filename_pattern: Text supplied as filename pattern in the format
            accepted by this function.

    Returns:
        The validated ``discovered``.

    Raises:
        ValueError: If script discovery must return exactly one plain path;
            script discovery lacks an absolute search directory; or discovered
            script is outside the requested path policy.
    """

    lines = str(command_output or "").splitlines()
    if len(lines) != 1 or lines[0] != lines[0].strip():
        raise ValueError("script discovery must return exactly one plain path")

    discovered = lines[0]
    normalized_directory = posixpath.normpath(str(search_directory))
    if not posixpath.isabs(normalized_directory):
        raise ValueError("script discovery requires an absolute search directory")
    if (
        not _SAFE_REMOTE_SCRIPT_PATH.fullmatch(discovered)
        or posixpath.normpath(discovered) != discovered
        or posixpath.dirname(discovered) != normalized_directory
        or not fnmatchcase(posixpath.basename(discovered), filename_pattern)
    ):
        raise ValueError("discovered script is outside the requested path policy")
    return discovered


def _normalize_tar_missing_member_diagnostic(line: str) -> Optional[str]:
    """
    Return a safe relative member from one recognized TAR missing diagnostic.

    Only the BusyBox and GNU diagnostic forms emitted for unavailable members
    are accepted. The extracted path is normalized for result metadata only;
    it is never used to construct a shell command. Absolute paths, traversal,
    control characters, and oversized values fail closed as unknown stderr.

    Args:
        line: One stripped stderr line emitted by a remote TAR process.

    Returns:
        A normalized relative member path for a recognized diagnostic, or
        ``None`` when the line or embedded path is outside policy.
    """

    if not line.lower().startswith("tar: "):
        return None
    diagnostic = line[5:]
    lowered = diagnostic.lower()
    member = None
    for suffix in _TAR_MISSING_MEMBER_SUFFIXES:
        if lowered.endswith(suffix):
            member = diagnostic[: -len(suffix)].rstrip()
            break
    if not member or any(
        ord(character) < 32 or ord(character) == 127 for character in member
    ):
        return None
    if len(member.encode("utf-8")) > _BMC_REMOTE_PATH_MAX_BYTES:
        return None

    normalized = posixpath.normpath(member)
    if (
        normalized in {"", ".", ".."}
        or posixpath.isabs(normalized)
        or normalized.startswith("../")
    ):
        return None
    return normalized


def _classify_recoverable_tar_warnings(
    stderr: str, *, hardlink_dereference_supported: Optional[bool] = None
) -> _TarWarningClassification:
    """
    Classify bounded TAR warnings without concealing unrelated failures.

    GNU and BusyBox TAR may leave a usable archive while returning status one
    for a live-file change, a permission-denied member, or an unavailable
    descendant. Standard trailing failure summaries are accepted only when a
    recognized causal diagnostic is also present. Any other stderr line makes
    the complete set non-recoverable.

    Args:
        stderr: Text supplied as stderr in the format accepted by this function.
        hardlink_dereference_supported: Optional runtime probe result. Unsupported
            materialization contributes a local advisory, not fabricated remote
            stderr or permission to ignore an unrelated TAR error.

    Returns:
        An immutable classification containing the recognized warning kinds and
        bounded missing-member evidence.
    """
    lines = [line.strip() for line in str(stderr or "").splitlines()]
    lines = [line for line in lines if line]
    if hardlink_dereference_supported is False:
        lines.append(_TAR_HARDLINK_ADVISORY)
    permission_denied = False
    file_changed = False
    hardlink_materialization_unavailable = False
    missing_members: List[str] = []
    missing_member_count = 0
    condition_messages: List[str] = []
    condition_message_count = 0
    advisory_messages: List[str] = []
    all_recognized = bool(lines)
    summary_lines = {
        "tar: exiting with failure status due to previous errors",
        "tar: error exit delayed from previous errors",
    }

    for line in lines:
        lowered = line.lower()
        missing_member = _normalize_tar_missing_member_diagnostic(line)
        if lowered.startswith("tar:") and lowered.endswith("permission denied"):
            permission_denied = True
            condition_message_count += 1
            if (
                line not in condition_messages
                and len(condition_messages)
                < _BMC_MAX_REPORTED_ARCHIVE_CONDITION_MESSAGES
            ):
                condition_messages.append(line)
        elif lowered.startswith("tar:") and lowered.endswith(
            "file changed as we read it"
        ):
            file_changed = True
            condition_message_count += 1
            if (
                line not in condition_messages
                and len(condition_messages)
                < _BMC_MAX_REPORTED_ARCHIVE_CONDITION_MESSAGES
            ):
                condition_messages.append(line)
        elif lowered == _TAR_HARDLINK_ADVISORY.lower():
            hardlink_materialization_unavailable = True
            if line not in advisory_messages:
                advisory_messages.append(line)
        elif missing_member is not None:
            missing_member_count += 1
            condition_message_count += 1
            if len(missing_members) < _BMC_MAX_REPORTED_ARCHIVE_MISSING_MEMBER_PATHS:
                missing_members.append(missing_member)
            if (
                line not in condition_messages
                and len(condition_messages)
                < _BMC_MAX_REPORTED_ARCHIVE_CONDITION_MESSAGES
            ):
                condition_messages.append(line)
        elif lowered not in summary_lines:
            all_recognized = False

    has_causal_warning = (
        permission_denied
        or file_changed
        or hardlink_materialization_unavailable
        or missing_member_count > 0
    )
    return _TarWarningClassification(
        all_recognized=all_recognized and has_causal_warning,
        permission_denied=permission_denied,
        file_changed=file_changed,
        hardlink_materialization_unavailable=(hardlink_materialization_unavailable),
        missing_members=tuple(missing_members),
        missing_member_count=missing_member_count,
        missing_members_truncated=(missing_member_count > len(missing_members)),
        condition_messages=tuple(condition_messages),
        condition_messages_truncated=(
            condition_message_count > len(condition_messages)
        ),
        advisory_messages=tuple(advisory_messages),
    )


def _record_validated_tar_link(
    counts: Dict[str, int], names: List[str], member: TarArchiveMember
) -> None:
    """
    Record bounded evidence for one validated TAR link member.

    The bounded archive inspector invokes this callback only after validating
    the member name and metadata. Counts retain the complete bounded inventory,
    while names retain only an operator-readable prefix so result context cannot
    grow with an adversarial archive.

    Args:
        counts: Mutable counters keyed by the exact ``symlink`` and ``hardlink``
            subtype names.
        names: Mutable list receiving at most the configured number of validated
            link member names.
        member: Immutable validated member metadata emitted by the inspector.

    Side Effects:
        Increments one existing counter and may append one bounded member name
        when ``member`` has a recognized link subtype.
    """

    if member.link_kind in counts:
        counts[member.link_kind] += 1
        if len(names) < _BMC_MAX_REPORTED_ARCHIVE_LINK_PATHS:
            names.append(member.name)


def _normalize_pattern_function_tag(
    function_tag: str, output_pattern: Optional[str]
) -> str:
    """
    Remove a suffix supplied by both a pattern and its placeholder value.

    Patternless output retains its historical naming behavior. For patterned
    output, normalization is deliberately narrow: only the complete static
    suffix following the final placeholder may be removed.

    Args:
        function_tag: Text supplied as function tag in the format accepted by
            this function.
        output_pattern: Text supplied as output pattern in the format accepted
            by this function.

    Returns:
        The canonical pattern function tag text.
    """
    if not output_pattern or not function_tag:
        return function_tag

    match = _OUTPUT_PATTERN_TRAILING_PLACEHOLDER.search(output_pattern)
    if not match:
        return function_tag

    suffix = match.group("suffix")
    if suffix and len(function_tag) > len(suffix) and function_tag.endswith(suffix):
        return function_tag[: -len(suffix)]
    return function_tag


def _i2c_adapter_name(adapter_line: str) -> str:
    """
    Extract the adapter name column from an ``i2cdetect -l`` line.

    The implementation uses ``adapter_line`` to extract the adapter name column
    from an ``i2cdetect -l`` line.

    Args:
        adapter_line: Text supplied as adapter line in the format accepted by
            this function.

    Returns:
        The canonical i2c adapter name.
    """
    tab_columns = [column.strip() for column in adapter_line.split("\t")]
    if len(tab_columns) >= 3 and tab_columns[2]:
        return tab_columns[2]

    match = _I2C_ADAPTER_LINE.match(adapter_line)
    remainder = adapter_line[match.end() :].strip() if match else adapter_line.strip()
    columns = [column for column in re.split(r"\s{2,}", remainder) if column]
    if len(columns) >= 2:
        return columns[1]
    return remainder


def _is_all_ff_i2c_payload(stdout: Any) -> bool:
    """
    Return whether an I2C read produced only one or more ``0xff`` bytes.

    After applying local validation, the function forwards ``stdout`` to
    ``bool`` and preserves its return and exception contract.

    Args:
        stdout: Stdout consumed while the function attempts to determine whether
            an I2C read produced only one or more ``0xff`` bytes.

    Returns:
        Whether an I2C read produced only one or more ``0xff`` bytes.
    """
    return bool(_ALL_FF_I2C_PAYLOAD.fullmatch(str(stdout or "")))


def _parse_i2c_byte_payload(stdout: Any) -> Optional[Tuple[int, ...]]:
    """
    Parse a complete ``i2ctransfer`` byte response without accepting noise.

    I2C semantic validation must not guess around command diagnostics or
    truncated output. The parser therefore accepts only one or more whitespace-
    separated ``0xNN`` tokens and returns ``None`` for every other shape.

    Args:
        stdout: Command standard output to parse as an I2C byte sequence.

    Returns:
        Parsed byte values, or ``None`` when the output is empty or is not a
        complete canonical ``i2ctransfer`` response.
    """
    tokens = str(stdout or "").split()
    if not tokens:
        return None
    if any(re.fullmatch(r"0[xX][0-9a-fA-F]{2}", token) is None for token in tokens):
        return None
    return tuple(int(token, 16) for token in tokens)


def _normalize_i2c_result_validations(
    value: Any,
    command_names: List[str],
) -> Dict[str, _I2CResultValidation]:
    """
    Validate data-driven result rules against the final I2C command batch.

    Rules are keyed by telemetry command name. Each rule may reject exact byte
    sentinels, require a clear bit from another one-byte command in the same
    batch, or apply both checks. Rejecting malformed or dangling rules before
    transport prevents configuration mistakes from silently accepting data.

    Args:
        value: Raw ``result_validations`` mapping from collector configuration.
        command_names: Names aligned with the final rendered command batch.

    Returns:
        Canonical validation rules keyed by target command name.

    Raises:
        ValueError: If the rules are malformed, command names are ambiguous, a
            referenced command is absent, or a payload/mask is invalid.
    """
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("result_validations must be a mapping")

    known_names = set(command_names)
    if len(known_names) != len(command_names):
        raise ValueError(
            "result_validations require unique command names in the final batch"
        )

    normalized: Dict[str, _I2CResultValidation] = {}
    for raw_target, raw_rule in value.items():
        if not isinstance(raw_target, str) or not raw_target.strip():
            raise ValueError("result validation targets must be non-empty strings")
        target = raw_target.strip()
        if target not in known_names:
            raise ValueError(f"result validation target is not selected: {target}")
        if not isinstance(raw_rule, Mapping):
            raise ValueError(f"result validation for {target} must be a mapping")

        unexpected_fields = set(raw_rule) - {"invalid_payloads", "staleness"}
        if unexpected_fields:
            raise ValueError(
                f"result validation for {target} has unsupported fields: "
                f"{', '.join(sorted(str(field) for field in unexpected_fields))}"
            )

        raw_invalid_payloads = raw_rule.get("invalid_payloads", [])
        if not isinstance(raw_invalid_payloads, list):
            raise ValueError(
                f"invalid_payloads for {target} must be a list of byte strings"
            )
        invalid_payloads: List[Tuple[int, ...]] = []
        for raw_payload in raw_invalid_payloads:
            if not isinstance(raw_payload, str):
                raise ValueError(
                    f"invalid payload for {target} must be a canonical byte string"
                )
            parsed_payload = _parse_i2c_byte_payload(raw_payload)
            if parsed_payload is None:
                raise ValueError(
                    f"invalid payload for {target} must contain only 0xNN bytes"
                )
            if parsed_payload not in invalid_payloads:
                invalid_payloads.append(parsed_payload)

        staleness_command: Optional[str] = None
        staleness_mask: Optional[int] = None
        raw_staleness = raw_rule.get("staleness")
        if raw_staleness is not None:
            if not isinstance(raw_staleness, Mapping):
                raise ValueError(f"staleness rule for {target} must be a mapping")
            if set(raw_staleness) != {"command", "mask"}:
                raise ValueError(
                    f"staleness rule for {target} requires only command and mask"
                )
            raw_command = raw_staleness.get("command")
            if not isinstance(raw_command, str) or not raw_command.strip():
                raise ValueError(
                    f"staleness command for {target} must be a non-empty string"
                )
            staleness_command = raw_command.strip()
            if staleness_command not in known_names:
                raise ValueError(
                    f"staleness command for {target} is not selected: "
                    f"{staleness_command}"
                )
            if staleness_command == target:
                raise ValueError(
                    f"staleness command for {target} cannot reference itself"
                )
            raw_mask = raw_staleness.get("mask")
            if isinstance(raw_mask, bool) or not isinstance(raw_mask, int):
                raise ValueError(f"staleness mask for {target} must be an integer")
            if raw_mask < 1 or raw_mask > 0xFF:
                raise ValueError(
                    f"staleness mask for {target} must be between 0x01 and 0xFF"
                )
            staleness_mask = raw_mask

        if not invalid_payloads and staleness_command is None:
            raise ValueError(
                f"result validation for {target} must define at least one check"
            )
        normalized[target] = _I2CResultValidation(
            invalid_payloads=tuple(invalid_payloads),
            staleness_command=staleness_command,
            staleness_mask=staleness_mask,
        )

    return normalized


def _classify_i2c_result_semantics(
    command_name: str,
    stdout: Any,
    validations: Mapping[str, _I2CResultValidation],
    observations: Mapping[str, Tuple[bool, Any]],
) -> Tuple[Optional[str], Optional[str]]:
    """
    Classify one transported I2C payload using its configured validity rules.

    Staleness is evaluated before sentinel matching because a set validity bit
    gives the authoritative reason that the associated telemetry must be
    ignored. If that status byte cannot itself be obtained and parsed, the
    dependent telemetry fails closed instead of being presented as current.

    Args:
        command_name: Name of the telemetry command being classified.
        stdout: Standard output returned for the telemetry command.
        validations: Canonical data-driven rules keyed by command name.
        observations: Transport usability and raw output for commands in the
            same owned batch.

    Returns:
        A semantic failure code and human-readable error, or ``(None, None)``
        when the command has no rule or satisfies every configured check.
    """
    rule = validations.get(command_name)
    if rule is None:
        return None, None

    if rule.staleness_command is not None:
        observation = observations.get(rule.staleness_command)
        if observation is None or observation[0] is not True:
            return (
                "staleness_unavailable",
                f"Staleness status unavailable from {rule.staleness_command}; "
                "telemetry validity cannot be established",
            )
        staleness_payload = _parse_i2c_byte_payload(observation[1])
        if staleness_payload is None or len(staleness_payload) != 1:
            return (
                "staleness_unavailable",
                f"Staleness status from {rule.staleness_command} is not one byte; "
                "telemetry validity cannot be established",
            )
        if staleness_payload[0] & int(rule.staleness_mask or 0):
            return (
                "stale_payload",
                f"Staleness bit 0x{int(rule.staleness_mask or 0):02x} is set in "
                f"{rule.staleness_command}; telemetry must be ignored",
            )

    payload = _parse_i2c_byte_payload(stdout)
    if payload is not None and payload in rule.invalid_payloads:
        return (
            "invalid_payload",
            "Configured invalid telemetry sentinel returned; payload must be ignored",
        )
    return None, None


def _has_canonical_i2c_parent_pattern(output_pattern: Any, collector_id: Any) -> bool:
    """
    Return whether the parent pattern names the collector's canonical artifact.

    Shipped I2C collectors use ``SSH_<collector-id>_...`` for their canonical
    output. Their variant metadata classifies commands but must not cause the
    same response to be persisted again under a legacy variant alias. Generic
    callers with a noncanonical parent may still intentionally request both a
    parent and a matching variant artifact.

    Args:
        output_pattern: Output pattern object whose ``replace`` state is read
            while performing parent pattern names the collector's canonical
            artifact.
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.

    Returns:
        Whether the parent pattern names the collector's canonical artifact.
    """
    if not isinstance(output_pattern, str) or not output_pattern:
        return False
    if not isinstance(collector_id, str) or not collector_id:
        return False
    filename = PurePosixPath(output_pattern.replace("\\", "/")).name
    return filename.startswith(f"SSH_{collector_id}_")


def _normalize_i2c_collector_variants(
    raw_variants: Any,
) -> List[Dict[str, Any]]:
    """
    Validate and precompile YAML-driven I2C output variants.

    The implementation uses ``raw_variants`` to validate and precompile
    YAML-driven I2C output variants. Every required invariant is checked before
    a successful value is returned; invalid input follows the function's
    explicit exception path. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Args:
        raw_variants: Entries supplied as ``raw_variants`` and processed in
            caller-provided order.

    Returns:
        The i2c collector variants returned in operation-defined order.

    Raises:
        ValueError: If the collector_variants are not a list; the
            collector_variants[``index``] is not a mapping;
            collector_variants[``index``] must define a non-empty id or name; or
            collector variant ``variant_id`` must define a non-empty
            output_pattern; or another input invariant is violated.
    """
    if raw_variants is None:
        return []
    if not isinstance(raw_variants, list):
        raise ValueError("collector_variants must be a list")

    normalized: List[Dict[str, Any]] = []
    for index, raw_variant in enumerate(raw_variants, start=1):
        if not isinstance(raw_variant, dict):
            raise ValueError(f"collector_variants[{index}] must be a mapping")

        variant_id = raw_variant.get("id") or raw_variant.get("name")
        if not isinstance(variant_id, str) or not variant_id.strip():
            raise ValueError(
                f"collector_variants[{index}] must define a non-empty id or name"
            )

        output_pattern = raw_variant.get("output_pattern")
        if not isinstance(output_pattern, str) or not output_pattern.strip():
            raise ValueError(
                f"collector variant {variant_id!r} must define a non-empty output_pattern"
            )
        if "\x00" in output_pattern:
            raise ValueError(
                f"collector variant {variant_id!r} output_pattern contains NUL"
            )
        normalized_output_path = output_pattern.replace("\\", "/")
        if (
            posixpath.isabs(normalized_output_path)
            or ".." in PurePosixPath(normalized_output_path).parts
        ):
            raise ValueError(
                f"collector variant {variant_id!r} output_pattern must be a safe relative path"
            )

        variant = dict(raw_variant)
        variant["id"] = variant_id
        variant["output_pattern"] = output_pattern

        for selector in _I2C_VARIANT_LIST_SELECTORS:
            if selector not in raw_variant:
                continue
            values = raw_variant[selector]
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, (list, tuple)) or not values:
                raise ValueError(
                    f"collector variant {variant_id!r} {selector} must be a non-empty list of strings"
                )
            if any(not isinstance(value, str) or not value for value in values):
                raise ValueError(
                    f"collector variant {variant_id!r} {selector} must contain only non-empty strings"
                )
            variant[selector] = tuple(values)

        name_regex = raw_variant.get("name_regex")
        if name_regex is not None:
            if not isinstance(name_regex, str) or not name_regex:
                raise ValueError(
                    f"collector variant {variant_id!r} name_regex must be a non-empty string"
                )
            try:
                variant["_compiled_name_regex"] = re.compile(name_regex)
            except re.error as exc:
                raise ValueError(
                    f"collector variant {variant_id!r} has invalid name_regex: {exc}"
                ) from exc

        normalized.append(variant)

    return normalized


def _matching_i2c_variant_patterns(
    variants: List[Dict[str, Any]], command_name: str, command_group: str
) -> List[str]:
    """
    Return de-duplicated output patterns for variants matching a command.

    The implementation uses ``variants``, ``command_name``, and
    ``command_group`` to produce de-duplicated output patterns for variants
    matching a command.

    Args:
        variants: Mapping supplying fields for de-duplicated output patterns for
            variants matching a command.
        command_name: Stable command name used for lookup and operator-facing
            diagnostics.
        command_group: Text supplied as command group in the format accepted by
            this function.

    Returns:
        The validated ``patterns``.
    """
    patterns: List[str] = []
    for variant in variants:
        selector_results: List[bool] = []
        if "command_groups" in variant:
            selector_results.append(command_group in variant["command_groups"])
        if "name_prefixes" in variant:
            selector_results.append(
                any(
                    command_name.startswith(prefix)
                    for prefix in variant["name_prefixes"]
                )
            )
        if "_compiled_name_regex" in variant:
            selector_results.append(
                bool(variant["_compiled_name_regex"].search(command_name))
            )

        if selector_results and not any(selector_results):
            continue
        output_pattern = variant["output_pattern"]
        if output_pattern not in patterns:
            patterns.append(output_pattern)
    return patterns


def _compile_scan_adapter_patterns(
    raw_patterns: Any, invalid_patterns: List[Dict[str, str]]
) -> List[Tuple[str, re.Pattern[str]]]:
    """
    Normalize and safely compile configured S7 adapter-line regexes.

    The implementation uses ``raw_patterns`` and ``invalid_patterns`` to
    normalize and safely compile configured S7 adapter-line regexes. The source
    value keeps its ownership while the normalized representation is returned
    separately. The operation mutates ``invalid_patterns`` in place; ownership
    of those objects remains with the caller.

    Args:
        raw_patterns: Raw patterns consumed while the function attempts to
            normalize and safely compile configured S7 adapter-line regexes.
        invalid_patterns: Mapping supplying fields for and safely compile
            configured S7 adapter-line regexes.

    Returns:
        The validated ``compiled_patterns``.
    """
    if isinstance(raw_patterns, str):
        pattern_values = [raw_patterns]
    elif isinstance(raw_patterns, (list, tuple)):
        pattern_values = list(raw_patterns)
    elif raw_patterns in (None, False):
        pattern_values = []
    else:
        invalid_patterns.append(
            {
                "pattern": repr(raw_patterns),
                "reason": "configuration must be a string or list of strings",
            }
        )
        pattern_values = []

    compiled_patterns: List[Tuple[str, re.Pattern[str]]] = []
    for configured_pattern in pattern_values:
        if not isinstance(configured_pattern, str):
            invalid_patterns.append(
                {
                    "pattern": repr(configured_pattern),
                    "reason": "pattern must be a string",
                }
            )
            continue
        if not configured_pattern:
            invalid_patterns.append(
                {"pattern": configured_pattern, "reason": "pattern is empty"}
            )
            continue
        if len(configured_pattern) > _MAX_SCAN_EXCLUSION_PATTERN_LENGTH:
            invalid_patterns.append(
                {
                    "pattern": configured_pattern,
                    "reason": (
                        "pattern exceeds the "
                        f"{_MAX_SCAN_EXCLUSION_PATTERN_LENGTH}-character limit"
                    ),
                }
            )
            continue
        try:
            compiled_patterns.append(
                (configured_pattern, re.compile(configured_pattern))
            )
        except re.error as exc:
            invalid_patterns.append(
                {
                    "pattern": configured_pattern,
                    "reason": f"invalid regular expression: {exc}",
                }
            )

    return compiled_patterns


class BMCSSHService(BaseService):
    """
    Service for BMC SSH operations.

    Provides collectors for BMC SSH-based log collection including command
    execution, file transfers, and system diagnostics over SSH.

    Inherits from: BaseService: Base service with standardized collector
    patterns.
    """

    def __init__(self, service_name: str, orchestrator: Any) -> None:
        """
        Initialize BMC SSH service.

        Remote cleanup is destructive. A path carried through hook context is
        not proof that this service created it, even when its basename looks
        like one of our mktemp directories. Keep an in-process ownership
        registry and require an exact DUT/path claim before every removal.

        Args:
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.
            orchestrator: Orchestrator consumed while the function attempts to
                initialize BMC SSH service.
        """
        super().__init__(service_name, orchestrator)
        # Remote cleanup is destructive.  A path carried through hook context is
        # not proof that this service created it, even when its basename looks
        # like one of our mktemp directories.  Keep an in-process ownership
        # registry and require an exact DUT/path claim before every removal.
        self._owned_bmc_staging_directories: set[Tuple[str, str]] = set()
        self._bmc_staging_owners: Dict[Tuple[str, str], Optional[asyncio.Task[Any]]] = (
            {}
        )

    def _published_i2c_artifact_reference(
        self,
        dut_id: str,
        path_value: Any,
    ) -> Optional[str]:
        """
        Return one archive-resolvable I2C command artifact reference.

        Production collection uses an ``AsyncSafeLogger`` whose
        ``base_log_dir`` is the bundle root. Resolve physical command artifacts
        through the shared containment helper before embedding their names in a
        structured summary, so the summary survives removal of the loose run
        tree after ZIP publication. Lightweight alternate loggers without a
        declared publication root retain the historical internal spelling;
        they do not publish a distributable archive.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration,
                logs, and results.
            path_value: Physical path returned by the collector output store.

        Returns:
            The bundle-root-relative POSIX reference, ``None`` when a declared
            bundle root does not contain a regular artifact, or the historical
            internal spelling when no publication root is available.
        """

        if path_value in (None, ""):
            return None
        bundle_root = getattr(self.logger, "base_log_dir", None)
        if not isinstance(bundle_root, (str, Path)):
            return str(path_value)
        return bundle_relative_artifact_path(
            Path(bundle_root),
            path_value,
            dut_id=run_tree_dut_component(dut_id),
        )

    async def _drain_owned_bmc_staging_directories(
        self,
        *,
        owner: Optional[asyncio.Task[Any]] = None,
    ) -> None:
        """
        Retry exact registered cleanup claims, observing every failure.

        The implementation uses ``owner`` to retry exact registered cleanup
        claims, observing every failure. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        If the function cannot retry exact registered cleanup claims, observing
        every failure, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            owner: Optional owner; ``None`` selects the function's default
                behavior.

        Raises:
            Exception: If the function cannot retry exact registered cleanup
                claims, observing every failure safely.
            BaseExceptionGroup: If BMC staging cleanup failed.
        """

        owned = [
            ownership
            for ownership in tuple(self._owned_bmc_staging_directories)
            if owner is None or self._bmc_staging_owners.get(ownership) is owner
        ]
        errors: List[BaseException] = []
        for dut_id, remote_directory in owned:
            try:
                await self._finish_private_bmc_staging_directory(
                    dut_id,
                    remote_directory,
                )
            except BaseException as error:
                errors.append(error)
        if len(errors) == 1:
            raise errors[0]
        if errors:
            raise BaseExceptionGroup("BMC staging cleanup failed", errors)

    async def close_owned_remote_staging(self) -> None:
        """
        Run-owned teardown hook for any staging that survived its stage.

        The implementation uses current instance state to run-owned teardown
        hook for any staging that survived its stage. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.
        """

        await self._drain_owned_bmc_staging_directories()

    async def _execute_stage(
        self,
        stage: str,
        collector_def: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Bind remote staging cleanup to the task that executes this stage.

        The implementation uses ``stage``, ``collector_def``, and ``context`` to
        bind remote staging cleanup to the task that executes this stage. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. If the function cannot bind remote staging
        cleanup to the task that executes this stage, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            stage: Text supplied as stage in the format accepted by this
                function.
            collector_def: Mapping supplying fields for bind remote staging
                cleanup to the task that executes this stage.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            A mapping containing execute stage.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to bind remote staging cleanup to the task that
                executes this stage.
            BaseExceptionGroup: If BMC stage and staging cleanup failed.
            RuntimeError: If BMC stage returned no result.
        """

        owner = asyncio.current_task()
        result: Optional[Dict[str, Any]] = None
        active_error: Optional[BaseException] = None
        try:
            result = await super()._execute_stage(stage, collector_def, context)
        except BaseException as error:
            active_error = error

        cleanup_error: Optional[BaseException] = None
        try:
            await self._drain_owned_bmc_staging_directories(owner=owner)
        except BaseException as error:
            cleanup_error = error

        if active_error is not None:
            if isinstance(active_error, asyncio.CancelledError):
                raise active_error
            if cleanup_error is not None:
                raise BaseExceptionGroup(
                    "BMC stage and staging cleanup failed",
                    [active_error, cleanup_error],
                )
            raise active_error
        if cleanup_error is not None:
            if isinstance(cleanup_error, asyncio.CancelledError):
                raise cleanup_error
            prior_context = dict((result or {}).get("context") or {})
            error_messages = list(prior_context.get("error_messages") or [])
            cleanup_reason = f"BMC staging cleanup failed: {cleanup_error}"
            if cleanup_reason not in error_messages:
                error_messages.append(cleanup_reason)
            prior_context.update(
                {
                    "error_messages": error_messages,
                    "status": "error",
                    "reason": cleanup_reason,
                    "remote_staging_cleanup_failed": True,
                }
            )
            return {
                **(result or {}),
                "success": False,
                "status": "error",
                "reason": cleanup_reason,
                "context": prior_context,
            }
        if result is None:
            raise RuntimeError("BMC stage returned no result")
        return result

    async def validate_connection(self, dut_id: str) -> Tuple[bool, str]:
        """
        Validate BMC SSH connection.

        After applying local validation, the function forwards ``dut_id`` to
        ``test_ssh_connection`` and preserves its return and exception contract.
        Every required invariant is checked before a successful value is
        returned; invalid input follows the function's explicit exception path.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A tuple containing the connection-success flag and sanitized
            diagnostic message.
        """
        return await self.dut_manager.get_dut(dut_id).test_ssh_connection()

    # Validation methods
    async def _validate_bmc_connection(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Validate BMC connection.

        The implementation uses ``dut_id`` and ``kwargs`` to validate BMC
        connection. Every required invariant is checked before a successful
        value is returned; invalid input follows the function's explicit
        exception path. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing BMC connection.
        """
        try:
            # First check if we have preflight results
            dut = self.dut_manager.get_dut(dut_id)
            preflight_results = getattr(dut, "preflight_results", {})

            if preflight_results:
                ssh_service_result = preflight_results.get("services", {}).get(
                    "ssh", {}
                )
                if ssh_service_result:
                    preflight_status = ssh_service_result.get("status", "unknown")
                    preflight_message = ssh_service_result.get("message", "")

                    await self._log_runtime(
                        "DEBUG",
                        "BMCSSHService",
                        f"Found preflight results for BMC SSH connection: status={preflight_status}, message={preflight_message}",
                        dut_id,
                    )

                    if preflight_status == "pass":
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            "Using preflight results for BMC SSH validation - connection already verified",
                            dut_id,
                        )
                        return await self._create_standardized_collector_result(
                            successful_operations=1,
                            total_operations=1,
                            output_files=[],
                            error_messages=[],
                            operation_name="bmc_ssh_validation",
                            additional_context={
                                "validation_message": f"Preflight verified: {preflight_message}",
                                "bmc_ssh_available": True,
                                "preflight_used": True,
                            },
                        )
                    elif preflight_status == "fail":
                        await self._log_runtime(
                            "WARN",
                            "BMCSSHService",
                            f"Preflight failed for BMC SSH connection: {preflight_message}",
                            dut_id,
                        )
                        return await self._create_standardized_collector_result(
                            successful_operations=0,
                            total_operations=1,
                            output_files=[],
                            error_messages=[f"Preflight failed: {preflight_message}"],
                            operation_name="bmc_ssh_validation",
                            additional_context={
                                "validation_message": f"Preflight failed: {preflight_message}",
                                "bmc_ssh_available": False,
                                "preflight_used": True,
                            },
                        )

            # No preflight results or unknown status - run connection test
            await self._log_runtime(
                "DEBUG",
                "BMCSSHService",
                "No preflight results found or unknown status - running BMC SSH connection test",
                dut_id,
            )

            success, message = await self.validate_connection(dut_id)

            # Log the validation result
            if success:
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"BMC SSH connection validation passed: {message}",
                    dut_id,
                )
            else:
                await self._log_runtime(
                    "ERROR",
                    "BMCSSHService",
                    f"BMC SSH connection validation failed: {message}",
                    dut_id,
                )

            return await self._create_standardized_collector_result(
                successful_operations=1 if success else 0,
                total_operations=1,
                output_files=[],
                error_messages=[] if success else [message],
                operation_name="bmc_ssh_validation",
                additional_context={
                    "validation_message": message,
                    "bmc_ssh_available": success,
                    "preflight_used": False,
                },
            )
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"SSH validation exception: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"SSH validation error: {str(e)}"],
                operation_name="bmc_ssh_validation",
                additional_context={"bmc_ssh_available": False},
                dut_id=dut_id,
                collector_id="bmc_ssh_validation",
            )

    async def _validate_ssh_connection(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Validate SSH connection (alias for BMC connection).

        After applying local validation, the function forwards ``dut_id`` and
        ``kwargs`` to ``self._validate_bmc_connection`` and preserves its return
        and exception contract. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing SSH connection.
        """
        return await self._validate_bmc_connection(dut_id, **kwargs)

    async def _validate_bmc_ssh_connection(
        self, dut_id: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Validate BMC SSH connection (alternative name).

        After applying local validation, the function forwards ``dut_id`` and
        ``kwargs`` to ``self._validate_bmc_connection`` and preserves its return
        and exception contract. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing BMC SSH connection.
        """
        return await self._validate_bmc_connection(dut_id, **kwargs)

    async def _validate_hmc_ssh_connection(
        self, dut_id: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Validate direct HMC SSH connectivity for collectors that target the HMC.

        The implementation uses ``dut_id`` and ``kwargs`` to validate direct HMC
        SSH connectivity for collectors that target the HMC. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing HMC SSH connection.
        """
        collector_id = kwargs.get("collector_id", "hmc_ssh_validation")

        try:
            if not self.dut_manager or not self.dut_manager.is_hmc_present(dut_id):
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=["HMC IP not configured for this DUT"],
                    operation_name="hmc_ssh_validation",
                    additional_context={
                        "hmc_ssh_available": False,
                        "hmc_present": False,
                    },
                    dut_id=dut_id,
                    collector_id=collector_id,
                )

            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id,
                "true",
                timeout=30,
                hmc=True,
            )

            success = exit_code == 0
            message = (
                "HMC SSH connection validation passed"
                if success
                else f"HMC SSH connection validation failed: {stderr or stdout or 'unknown error'}"
            )

            await self._log_runtime(
                "INFO" if success else "ERROR",
                "BMCSSHService",
                message,
                dut_id,
            )

            return await self._create_standardized_collector_result(
                successful_operations=1 if success else 0,
                total_operations=1,
                output_files=[],
                error_messages=[] if success else [message],
                operation_name="hmc_ssh_validation",
                additional_context={
                    "validation_message": message,
                    "hmc_ssh_available": success,
                    "hmc_present": True,
                },
                dut_id=dut_id,
                collector_id=collector_id,
            )
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"HMC SSH validation exception: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"HMC SSH validation error: {str(e)}"],
                operation_name="hmc_ssh_validation",
                additional_context={
                    "hmc_ssh_available": False,
                    "hmc_present": True,
                },
                dut_id=dut_id,
                collector_id=collector_id,
            )

    async def _render_command_template(
        self,
        dut_id: str,
        command_template: str,
        config_keys: Optional[Dict[str, str]] = None,
        config_key_defaults: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Render a command template using DUT/baseboard configuration values.

        The implementation uses ``dut_id``, ``command_template``,
        ``config_keys``, and ``config_key_defaults`` to render a command
        template using DUT/baseboard configuration values. The source value
        keeps its ownership while the normalized representation is returned
        separately. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command_template: Text supplied as command template in the format
                accepted by this function.
            config_keys: Optional Config keys governing command template using
                DUT/baseboard configuration values.
            config_key_defaults: Optional Config key defaults governing command
                template using DUT/baseboard configuration values.

        Returns:
            The canonical command template text, or ``None`` when the requested
            value is unavailable.
        """
        if not command_template:
            return None

        if not config_keys:
            return command_template

        merged_config = await self._get_merged_config(dut_id)
        resolved_values: Dict[str, str] = {}
        missing_placeholders: List[str] = []

        for placeholder, config_key in config_keys.items():
            value = None
            if merged_config:
                value = merged_config.get(config_key)

            if value is None and config_key_defaults:
                default_value = config_key_defaults.get(placeholder)
                if default_value is not None:
                    value = default_value

            if value is None:
                missing_placeholders.append(f"{placeholder}->{config_key}")
                continue

            resolved_values[placeholder] = str(value)

        if missing_placeholders:
            await self._log_runtime(
                "WARN",
                "BMCSSHService",
                "Missing values for command template placeholders: "
                + ", ".join(missing_placeholders),
                dut_id,
            )
            return None

        try:
            rendered_command = build_remote_cmd(command_template, **resolved_values)
            await self._log_runtime(
                "DEBUG",
                "BMCSSHService",
                f"Rendered command template '{command_template}' -> '{rendered_command}'",
                dut_id,
            )
            return rendered_command
        except (KeyError, IndexError) as exc:
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"Failed to render command template '{command_template}': {exc}",
                dut_id,
            )
            return None

    async def _resolve_baseboard_command(
        self,
        dut_id: str,
        command: str,
        baseboard_commands: Optional[Dict[str, str]],
    ) -> str:
        """
        Resolve an authored command override for the DUT baseboard.

        Exact baseboard names take precedence over their catalog baseboard type,
        followed by the optional ``default`` entry. Invalid lookup state is
        logged and leaves the caller's default command unchanged so existing
        collectors retain their historical execution behavior.

        Args:
            dut_id: Stable DUT identifier used to resolve baseboard metadata.
            command: Default command authored by the collector.
            baseboard_commands: Optional mapping of baseboard names or types to
                command overrides.

        Returns:
            The selected authored command, or ``command`` when no override
            applies or baseboard resolution fails.
        """
        if not baseboard_commands:
            return command

        try:
            dut = self.dut_manager.get_dut(dut_id)
            baseboard = ""
            baseboard_type = ""

            if dut:
                baseboard = dut.config.get("baseboard", "")
                baseboard_manager = self.dut_manager._get_baseboard_manager()
                if baseboard_manager and baseboard:
                    baseboard_type = (
                        baseboard_manager.get_baseboard_type(baseboard) or ""
                    )

            selected_command = None
            if baseboard and baseboard in baseboard_commands:
                selected_command = baseboard_commands[baseboard]
            elif baseboard_type and baseboard_type in baseboard_commands:
                selected_command = baseboard_commands[baseboard_type]
            elif "default" in baseboard_commands:
                selected_command = baseboard_commands["default"]

            if selected_command:
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    "Using baseboard-specific command for "
                    f"'{baseboard or baseboard_type}': {selected_command}",
                    dut_id,
                )
                return selected_command
        except Exception as override_error:
            await self._log_runtime(
                "WARN",
                "BMCSSHService",
                f"Failed to apply baseboard command override: {override_error}",
                dut_id,
            )

        return command

    # Execution methods
    @staticmethod
    def _matches_expected_nonzero_result(
        exit_code: int,
        stdout: str,
        stderr: str,
        expected_nonzero_exit_codes: Any,
        expected_output_patterns: Any,
    ) -> bool:
        """
        Return whether a configured non-zero result is an expected empty state.

        A non-zero result is accepted only when both its exit code and one of
        the configured output patterns match. This keeps ``ignore_errors`` as a
        continuation policy rather than silently turning arbitrary command
        failures into successful collection.

        Args:
            exit_code: Numeric exit code used while the operation performs
                bounded accounting.
            stdout: Text supplied as stdout in the format accepted by this
                function.
            stderr: Text supplied as stderr in the format accepted by this
                function.
            expected_nonzero_exit_codes: Expected nonzero exit codes consumed
                while the function attempts to determine whether a configured
                non-zero result is an expected empty state.
            expected_output_patterns: Expected output patterns consumed while
                the function attempts to determine whether a configured non-zero
                result is an expected empty state.

        Returns:
            Whether a configured non-zero result is an expected empty state.
        """
        if exit_code == 0 or not expected_nonzero_exit_codes:
            return False

        exit_codes = expected_nonzero_exit_codes
        if not isinstance(exit_codes, (list, tuple, set)):
            exit_codes = [exit_codes]
        try:
            normalized_exit_codes = {int(value) for value in exit_codes}
        except (TypeError, ValueError):
            return False
        if exit_code not in normalized_exit_codes:
            return False

        patterns = expected_output_patterns
        if not isinstance(patterns, (list, tuple, set)):
            patterns = [patterns] if patterns else []
        combined_output = "\n".join(part for part in (stdout, stderr) if part)

        for raw_pattern in patterns:
            pattern = str(raw_pattern)
            if not pattern:
                continue
            try:
                if re.search(pattern, combined_output, flags=re.IGNORECASE):
                    return True
            except re.error:
                if pattern.casefold() in combined_output.casefold():
                    return True
        return False

    async def run_bmc_command(
        self,
        dut_id: str,
        command: str,
        collection_level: str = "L1",
        baseboard_commands: Optional[Dict[str, str]] = None,
        command_template: Optional[str] = None,
        config_keys: Optional[Dict[str, str]] = None,
        config_key_defaults: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run BMC SSH command with collection level handling.

        The implementation uses ``dut_id``, ``command``, ``collection_level``,
        ``baseboard_commands``, and ``command_template`` to run BMC SSH command
        with collection level handling. Terminal status is emitted only after
        BMC SSH command with collection level handling and its owned cleanup
        have completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            baseboard_commands: Optional baseboard commands; ``None`` selects
                the function's default behavior.
            command_template: Optional command template; ``None`` selects the
                function's default behavior.
            config_keys: Optional Config keys governing BMC SSH command with
                collection level handling.
            config_key_defaults: Optional Config key defaults governing BMC SSH
                command with collection level handling.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run BMC command.
        """
        timing_operation_id = None
        template_fallback_context: Dict[str, Any] = {}
        try:
            collector_id = kwargs.get("collector_id")
            timeout = await self._resolve_collector_timeout(
                dut_id,
                kwargs,
                default_timeout=300,
                collector_id=collector_id,
            )
            use_hmc_ip = kwargs.get("use_hmc_ip", False)

            template_source = None
            using_command_template = False
            using_command_as_template = False
            if command_template:
                template_source = command_template
                using_command_template = True
            elif config_keys:
                template_source = command
                using_command_as_template = True

            if template_source:
                rendered_command = await self._render_command_template(
                    dut_id,
                    template_source,
                    config_keys=config_keys,
                    config_key_defaults=config_key_defaults,
                )
                if rendered_command:
                    command = rendered_command
                else:
                    if using_command_as_template:
                        error_message = (
                            f"Failed to render command template '{template_source}' "
                            "due to missing configuration values."
                        )
                        return await self._create_standardized_collector_result(
                            successful_operations=0,
                            total_operations=1,
                            output_files=[],
                            error_messages=[error_message],
                            operation_name="bmc_ssh_command",
                            additional_context={
                                "command_template": template_source,
                                "config_keys": config_keys,
                            },
                            dut_id=dut_id,
                            collector_id=collector_id,
                        )
                    else:
                        template_fallback_context = {
                            "template_render_failed": True,
                            "unrendered_command_template": template_source,
                            "config_keys": dict(config_keys or {}),
                        }
                        await self._log_runtime(
                            "WARN",
                            "BMCSSHService",
                            f"Falling back to provided command '{command}' because template rendering failed.",
                            dut_id,
                            collector_id=collector_id,
                        )

            command = await self._resolve_baseboard_command(
                dut_id,
                command,
                baseboard_commands,
            )

            # Handle collection level variations if provided
            if "collection_level_handling" in kwargs:
                level_commands = kwargs["collection_level_handling"]
                if collection_level in level_commands:
                    command = level_commands[collection_level]

            if template_fallback_context:
                template_fallback_context["executed_fallback_command"] = command

            logged_command = self._bounded_operator_reason("success", command)
            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                (
                    f"Executing BMC SSH command with effective timeout {timeout}s: "
                    f"{logged_command}"
                ),
                dut_id,
                collector_id=collector_id,
            )

            if self.timing_manager:
                timing_operation_id = self.timing_manager.start_operation(
                    "bmc_ssh_command",
                    kwargs.get("function_tag", "bmc_command"),
                )
            try:
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, command, timeout=timeout, hmc=use_hmc_ip
                )
            except BaseException as exc:
                if self.timing_manager:
                    self.timing_manager.end_operation(
                        timing_operation_id,
                        status=(
                            "cancelled"
                            if isinstance(exc, asyncio.CancelledError)
                            else "error"
                        ),
                        error=str(exc),
                    )
                raise
            # Expected non-zero exits are semantic no-data results, not command
            # failures. Classify them before writing to the shared error log.
            expected_nonzero = self._matches_expected_nonzero_result(
                exit_code,
                stdout,
                stderr,
                kwargs.get("expected_nonzero_exit_codes"),
                kwargs.get("expected_output_patterns"),
            )
            failed_output = is_bmc_command_failure_output(stdout, stderr)
            ignore_errors = kwargs.get("ignore_errors", False)
            hard_nonzero_failure = (
                not failed_output
                and exit_code != 0
                and not expected_nonzero
                and not ignore_errors
            )

            # Log command result using common utility
            await self._log_command_result(
                command,
                exit_code,
                stdout,
                stderr,
                "bmc_ssh",
                dut_id,
                kwargs.get("collector_id"),
                log_errors=not expected_nonzero or failed_output,
            )

            # Create output file with generalization using common utility
            content = self._create_command_output_content(
                command, exit_code, stdout, stderr
            )
            output_pattern = kwargs.get("output_pattern") or kwargs.get("filename")
            # A failed-output signature is diagnostic evidence even when the
            # remote shell incorrectly reports exit zero.  Never publish that
            # transcript as primary collector data.
            diagnostic_failure = hard_nonzero_failure or failed_output
            if diagnostic_failure:
                diagnostic_name = output_pattern or (
                    f"{kwargs.get('function_tag', 'bmc_command')}.txt"
                )
                output_pattern = f"diagnostic/{diagnostic_name}"
            file_path = await self.write_output_with_generalization(
                dut_id,
                kwargs.get("collector_id", ""),
                content,
                output_pattern=output_pattern,
                function_tag=kwargs.get("function_tag", "bmc_command"),
            )

            # Check if we should ignore command failures
            expected_nonzero_reason = kwargs.get(
                "expected_nonzero_reason",
                f"Command returned an expected empty/no-data result (exit_code={exit_code})",
            )

            # The BMC can return exit code 0 while producing no usable output
            # (restricted-shell stdout-redirection failure, or an SSH
            # session-limit refusal). That is never a success and is not
            # silenced by ignore_errors -- there is no data.
            semantic_success = not failed_output and (
                exit_code == 0 or expected_nonzero
            )
            if self.timing_manager:
                self.timing_manager.end_operation(
                    timing_operation_id,
                    status=(
                        "success"
                        if semantic_success and exit_code == 0
                        else ("completed_nonzero" if semantic_success else "error")
                    ),
                    artifact_path=file_path,
                    metadata={
                        "exit_code": exit_code,
                        "raw_exit_code": exit_code,
                        "semantic_success": semantic_success,
                        "ignored_nonzero": bool(exit_code != 0 and ignore_errors),
                        "expected_nonzero": expected_nonzero,
                    },
                )

            # If the command failed, return failure
            if failed_output or hard_nonzero_failure:
                failure_reason = (
                    f"BMC command produced no usable output (remote shell "
                    f"redirection failure or SSH session limit): {command}"
                    if failed_output
                    else f"SSH command failed: {command}"
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[failure_reason],
                    operation_name="bmc_ssh_command",
                    additional_context={
                        "command": command,
                        "collection_level": collection_level,
                        "exit_code": exit_code,
                        "output_failure": failed_output,
                        "semantic_success": False,
                        "expected_nonzero": expected_nonzero,
                        "output": self._process_command_output(stdout),
                        "stderr": self._process_command_output(stderr),
                        **template_fallback_context,
                        **(
                            {"diagnostic_files": [file_path]}
                            if diagnostic_failure and file_path
                            else {}
                        ),
                    },
                )

            if exit_code != 0 and not expected_nonzero:
                # ``ignore_errors`` means retain the artifact and continue the
                # remaining hooks. Account for the failed remote command and
                # the independent artifact-publication attempt separately: a
                # saved transcript is genuine partial progress, while a failed
                # write leaves no successful operation and must remain an
                # error.
                transcript_saved = bool(file_path)
                failure_reason = (
                    f"BMC command exited non-zero: {command} (exit_code: {exit_code}); "
                    + (
                        "its output was still collected and preserved"
                        if transcript_saved
                        else "its output could not be persisted"
                    )
                )
                ignored_nonzero_status = "partial" if transcript_saved else "error"
                return await self._create_standardized_collector_result(
                    successful_operations=1 if transcript_saved else 0,
                    total_operations=2,
                    output_files=[file_path] if file_path else [],
                    error_messages=[failure_reason],
                    operation_name="bmc_ssh_command",
                    additional_context={
                        "status": ignored_nonzero_status,
                        "reason": failure_reason,
                        "command": command,
                        "collection_level": collection_level,
                        "command_success": False,
                        "semantic_success": False,
                        "ignored_nonzero": True,
                        "exit_code": exit_code,
                        "output": self._process_command_output(stdout),
                        "stderr": self._process_command_output(stderr),
                        **template_fallback_context,
                    },
                )

            # Command succeeded, including a narrowly configured expected
            # empty/no-data response.
            additional_context = {
                "command": command,
                "collection_level": collection_level,
                "command_success": exit_code == 0,
                "semantic_success": True,
                "expected_nonzero": expected_nonzero,
                "exit_code": exit_code,
                "output": self._process_command_output(stdout),
                "stderr": self._process_command_output(stderr),
                **template_fallback_context,
            }
            if expected_nonzero:
                additional_context.update(
                    {
                        "status": "success",
                        "reason": expected_nonzero_reason,
                        "expected_nonzero_reason": expected_nonzero_reason,
                    }
                )
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    expected_nonzero_reason,
                    dut_id,
                    collector_id=collector_id,
                )
            if template_fallback_context:
                fallback_reason = (
                    "Configured command template could not be rendered; the "
                    "explicit fallback command was executed and preserved"
                )
                additional_context.update(
                    {
                        "status": "partial",
                        "reason": fallback_reason,
                        "template_fallback_reason": fallback_reason,
                    }
                )

            return await self._create_standardized_collector_result(
                successful_operations=1,
                total_operations=1,
                output_files=[file_path] if file_path else [],
                error_messages=[],
                operation_name="bmc_ssh_command",
                additional_context=additional_context,
            )
        except asyncio.CancelledError as e:
            if self.timing_manager:
                self.timing_manager.end_operation(
                    timing_operation_id,
                    status="cancelled",
                    error=str(e),
                )
            raise
        except Exception as e:
            if self.timing_manager:
                self.timing_manager.end_operation(
                    timing_operation_id,
                    status="error",
                    error=str(e),
                )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="bmc_ssh_command",
                additional_context={
                    "command": command,
                    **template_fallback_context,
                },
                dut_id=dut_id,
                collector_id="bmc_ssh_command",
            )

    async def run_bmc_commands(
        self,
        dut_id: str,
        commands: List[Union[str, Dict[str, Any]]],
        collection_level: str = "L1",
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run multiple BMC SSH commands with collection level handling.

        Handle both string commands and command dictionaries.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            commands: Ordered command strings or mappings. Command mappings may
                author baseboard overrides and collection-level variants.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run BMC commands.
        """
        try:
            results = []
            output_files = []
            error_messages = []
            ignored_error_messages = []
            successful_operations = 0
            total_operations = 0
            collection_level = kwargs.get("collection_level", "L1")
            use_hmc_ip = kwargs.get("use_hmc_ip", False)
            count_ignored_errors_as_failures = bool(
                kwargs.get("count_ignored_errors_as_failures", True)
            )

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Starting BMC SSH command set with {len(commands)} commands",
                dut_id,
                collector_id=kwargs.get("collector_id"),
            )

            for i, command_item in enumerate(commands):
                total_operations += 1
                # Handle both string commands and command dictionaries
                if isinstance(command_item, str):
                    command = command_item
                    file_name = f"bmc_command_{i + 1}.txt"
                    timeout = await self._resolve_collector_timeout(
                        dut_id, kwargs, default_timeout=300
                    )
                    ignore_errors = False
                else:
                    command = command_item["command"]
                    command = await self._resolve_baseboard_command(
                        dut_id,
                        command,
                        command_item.get("baseboard_commands"),
                    )

                    # Collection-level commands retain their existing final
                    # precedence over a selected baseboard command.
                    if "collection_level_handling" in command_item:
                        level_commands = command_item["collection_level_handling"]
                        command = level_commands.get(collection_level, command)

                    file_name = command_item.get(
                        "file_name", f"bmc_command_{i + 1}.txt"
                    )
                    timeout = await self._resolve_collector_timeout(
                        dut_id,
                        kwargs,
                        default_timeout=300,
                        explicit_timeout_sources=[command_item, kwargs],
                    )
                    ignore_errors = command_item.get("ignore_errors", False)

                logged_command = self._bounded_operator_reason("success", command)
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    (
                        f"Executing BMC SSH command {i + 1}/{len(commands)} "
                        f"with effective timeout {timeout}s: {logged_command}"
                    ),
                    dut_id,
                    collector_id=kwargs.get("collector_id"),
                )

                output_pattern = kwargs.get("output_pattern") or kwargs.get("filename")
                output_function_tag = _normalize_pattern_function_tag(
                    file_name, output_pattern
                )
                timing_operation_id = None
                if self.timing_manager:
                    timing_operation_id = self.timing_manager.start_operation(
                        "bmc_ssh_command",
                        output_function_tag,
                        metadata={
                            "command": command,
                            "command_index": i + 1,
                        },
                    )

                try:
                    (
                        exit_code,
                        stdout,
                        stderr,
                    ) = await self.dut_manager.execute_bmc_command(
                        dut_id, command, timeout, hmc=use_hmc_ip
                    )

                    # Include local persistence in the acquisition span so the
                    # artifact's interval ends only after it is available.
                    content = self._create_command_output_content(
                        command, exit_code, stdout, stderr
                    )
                    file_path = await self.write_output_with_generalization(
                        dut_id,
                        kwargs.get("collector_id", ""),
                        content,
                        output_pattern=output_pattern,
                        function_tag=output_function_tag,
                    )
                except BaseException as exc:
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            timing_operation_id,
                            status=(
                                "cancelled"
                                if isinstance(exc, asyncio.CancelledError)
                                else "error"
                            ),
                            error=str(exc),
                        )
                    raise
                persistence_failed = not file_path
                if file_path:
                    output_files.append(file_path)

                # Exit code 0 with no usable output (restricted-shell redirection
                # failure or SSH session-limit refusal) is never a success.
                # A command is also incomplete until its primary artifact is
                # durably published.
                failed_output = is_bmc_command_failure_output(stdout, stderr)
                command_success = (
                    exit_code == 0 and not failed_output and not persistence_failed
                )
                command_log_level = (
                    "INFO"
                    if command_success
                    else ("WARNING" if ignore_errors else "ERROR")
                )
                await self._log_runtime(
                    command_log_level,
                    "BMCSSHService",
                    (
                        f"BMC SSH command {i + 1}/{len(commands)} finished: "
                        f"exit_code={exit_code}, artifact_persisted={bool(file_path)}, "
                        f"semantic_success={command_success}"
                    ),
                    dut_id,
                    collector_id=kwargs.get("collector_id"),
                )
                if self.timing_manager:
                    self.timing_manager.end_operation(
                        timing_operation_id,
                        status="success" if command_success else "error",
                        artifact_path=file_path,
                        metadata={
                            "exit_code": exit_code,
                            "raw_exit_code": exit_code,
                            "semantic_success": command_success,
                            "ignored_nonzero": bool(exit_code != 0 and ignore_errors),
                            "output_failure": failed_output,
                            **(
                                {"persistence_failure": True}
                                if persistence_failed
                                else {}
                            ),
                        },
                    )
                if command_success:
                    successful_operations += 1
                command_error_messages = []
                if failed_output:
                    command_error_messages.append(
                        "BMC command produced no usable output (remote shell "
                        f"redirection failure or SSH session limit): {command}"
                    )
                elif exit_code != 0:
                    command_error_messages.append(
                        f"BMC command failed: {command} (exit_code: {exit_code})"
                    )
                if persistence_failed:
                    command_error_messages.append(
                        f"Failed to persist BMC command output: {command}"
                    )
                if (
                    ignore_errors
                    and not count_ignored_errors_as_failures
                    and not persistence_failed
                ):
                    ignored_error_messages.extend(command_error_messages)
                else:
                    error_messages.extend(command_error_messages)

                command_result = {
                    "command": command,
                    "success": command_success,
                    "output": self._process_command_output(stdout),
                    "stderr": self._process_command_output(stderr),
                    "exit_code": exit_code,
                    "output_failure": failed_output,
                    "file_name": file_name,
                    "collection_level": collection_level,
                }
                if persistence_failed:
                    command_result["persistence_failure"] = True
                results.append(command_result)

                # Handle ignore_errors (a no-output failure is never silenced:
                # there is no data to keep).
                if persistence_failed or (
                    (exit_code != 0 or failed_output) and not ignore_errors
                ):
                    return await self._create_standardized_collector_result(
                        successful_operations=successful_operations,
                        total_operations=total_operations,
                        output_files=output_files,
                        error_messages=error_messages,
                        operation_name="bmc_ssh_commands",
                        additional_context={
                            "total_commands": len(commands),
                            "results": results,
                        },
                    )

            additional_context = {
                "total_commands": len(commands),
                "collection_level": collection_level,
                "results": results,
                "ignored_failure_count": len(ignored_error_messages),
                "ignored_failures": ignored_error_messages,
            }
            if ignored_error_messages and not error_messages:
                optional_label = (
                    "failure" if len(ignored_error_messages) == 1 else "failures"
                )
                additional_context.update(
                    {
                        "status": "success",
                        "reason": (
                            "Required BMC command set complete: "
                            f"{successful_operations}/{total_operations} commands "
                            "produced artifacts; "
                            f"{len(ignored_error_messages)} optional command "
                            f"{optional_label} ignored"
                        ),
                    }
                )

            return await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=kwargs.get("collector_id", "unknown"),
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="bmc_ssh_commands",
                additional_context=additional_context,
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=len(commands),
                output_files=[],
                error_messages=[f"Exception in BMC commands: {str(e)}"],
                operation_name="bmc_ssh_commands",
                additional_context={"commands": commands},
                dut_id=dut_id,
                collector_id="bmc_ssh_commands",
            )

    async def run_bmc_file_collection(
        self, dut_id: str, file_patterns: List[str], **kwargs
    ) -> Dict[str, Any]:
        """
        Collect files from BMC via SSH.

        The implementation uses ``dut_id``, ``file_patterns``, and ``kwargs`` to
        collect files from BMC via SSH. Terminal status is emitted only after
        files from BMC via SSH and its owned cleanup have completed. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            file_patterns: Entries supplied as ``file_patterns`` without
                transferring container ownership.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run BMC file collection.
        """
        try:
            artifact_max_bytes = _resolve_bmc_artifact_max_bytes(
                kwargs.get("max_artifact_bytes")
            )
            output_files = []
            collected_files = []
            error_messages = []
            successful_operations = 0
            total_operations = 0

            for pattern in file_patterns:
                total_operations += 1
                # Use find command to locate files
                find_command = build_remote_cmd(
                    "find / -name {pattern} -type f 2>/dev/null | head -10",
                    pattern=pattern,
                )
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, find_command
                )

                if exit_code == 0 and stdout.strip():
                    files = _parse_bmc_discovered_file_inventory(stdout)
                    for file_path in files:
                        filename = f"bmc_file_{len(collected_files)}.txt"
                        try:
                            file_path_out, _download_result = (
                                await self._download_and_publish_bmc_artifact_bounded(
                                    dut_id,
                                    kwargs.get("collector_id", ""),
                                    file_path,
                                    function_tag=filename,
                                    max_bytes=artifact_max_bytes,
                                    output_pattern=kwargs.get("filename"),
                                    substitutions={"command_name": filename},
                                    default_extension=".txt",
                                )
                            )
                        except Exception as error:
                            error_messages.append(
                                f"Failed to read file: {file_path} ({error})"
                            )
                            continue
                        output_files.append(file_path_out)
                        collected_files.append(file_path)
                        successful_operations += 1

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="bmc_ssh_file_collection",
                additional_context={
                    "patterns_searched": len(file_patterns),
                    "files_collected": len(collected_files),
                    "max_artifact_bytes": artifact_max_bytes,
                    "bounded_binary_transfer": True,
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="bmc_ssh_file_collection",
                additional_context={},
                dut_id=dut_id,
                collector_id="bmc_ssh_file_collection",
            )

    async def run_bmc_log_collection(
        self,
        dut_id: str,
        log_commands: List[Dict[str, Any]],
        log_patterns: List[str],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Collect logs from BMC via SSH.

        The implementation uses ``dut_id``, ``log_commands``, ``log_patterns``,
        and ``kwargs`` to collect logs from BMC via SSH. Terminal status is
        emitted only after logs from BMC via SSH and its owned cleanup have
        completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            log_commands: Mapping supplying fields for logs from BMC via SSH.
            log_patterns: Entries supplied as ``log_patterns`` without
                transferring container ownership.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run BMC log collection.
        """
        try:
            artifact_max_bytes = _resolve_bmc_artifact_max_bytes(
                kwargs.get("max_artifact_bytes")
            )
            validated_log_paths = tuple(
                _normalize_bmc_remote_file_path(
                    path,
                    field_name="configured BMC log path",
                )
                for path in log_patterns
            )
            output_files = []
            error_messages = []
            successful_operations = 0
            total_operations = 0

            # Execute log commands
            for cmd_config in log_commands:
                total_operations += 1
                command = cmd_config["command"]
                file_name = cmd_config["file_name"]
                timeout = await self._resolve_collector_timeout(
                    dut_id,
                    kwargs,
                    default_timeout=300,
                    explicit_timeout_sources=[cmd_config, kwargs],
                )

                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, command, timeout
                )

                if exit_code == 0:
                    file_path = await self.write_output_with_generalization(
                        dut_id,
                        kwargs.get("collector_id", ""),
                        stdout,
                        output_pattern=kwargs.get("filename"),
                        function_tag=file_name,
                        substitutions={"command_name": file_name},
                    )
                    output_files.append(file_path)
                    successful_operations += 1
                else:
                    error_messages.append(f"Log command failed: {command}")

            # Collect log files
            for pattern in validated_log_paths:
                total_operations += 1
                filename = f"bmc_log_{pattern.replace('/', '_')}.txt"
                try:
                    file_path, _download_result = (
                        await self._download_and_publish_bmc_artifact_bounded(
                            dut_id,
                            kwargs.get("collector_id", ""),
                            pattern,
                            function_tag=filename,
                            max_bytes=artifact_max_bytes,
                            output_pattern=kwargs.get("filename"),
                            substitutions={"command_name": filename},
                            default_extension=".txt",
                        )
                    )
                except Exception as error:
                    error_messages.append(
                        f"Failed to read log file: {pattern} ({error})"
                    )
                    continue
                output_files.append(file_path)
                successful_operations += 1

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="bmc_ssh_log_collection",
                additional_context={
                    "log_commands": len(log_commands),
                    "log_patterns": len(log_patterns),
                    "max_artifact_bytes": artifact_max_bytes,
                    "bounded_binary_transfer": True,
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="bmc_ssh_log_collection",
                additional_context={},
                dut_id=dut_id,
                collector_id="bmc_ssh_log_collection",
            )

    async def run_bmc_device_based_commands(
        self,
        dut_id: str,
        device_detection: Dict[str, Any],
        device_commands: List[Dict[str, Any]],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run BMC commands based on detected devices.

        The implementation uses ``dut_id``, ``device_detection``,
        ``device_commands``, and ``kwargs`` to run BMC commands based on
        detected devices. Terminal status is emitted only after BMC commands
        based on detected devices and its owned cleanup have completed. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            device_detection: Mapping supplying fields for BMC commands based on
                detected devices.
            device_commands: Mapping supplying fields for BMC commands based on
                detected devices.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run BMC device based commands.
        """
        try:
            output_files = []
            detected_devices = []
            error_messages = []
            successful_operations = 0
            total_operations = 0

            # Detect devices
            detection_cmd = device_detection["command"]
            device_pattern = device_detection["device_pattern"]
            skip_message = device_detection.get("skip_message", "No devices found")

            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, detection_cmd
            )

            if exit_code != 0:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[f"Device detection failed: {stderr or stdout}"],
                    operation_name="bmc_device_based_commands",
                    additional_context={"detection_command": detection_cmd},
                    dut_id=dut_id,
                    collector_id="bmc_device_based_commands",
                )

            # Parse device list
            try:
                matches = bounded_device_matches(device_pattern, stdout)
            except ValueError as exc:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[str(exc)],
                    operation_name="bmc_device_based_commands",
                    additional_context={"detection_command": detection_cmd},
                    dut_id=dut_id,
                    collector_id="bmc_device_based_commands",
                )

            if not matches:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="bmc_device_based_commands",
                    additional_context={
                        "reason": skip_message,
                        "devices_found": 0,
                    },
                    dut_id=dut_id,
                    collector_id="bmc_device_based_commands",
                )

            # Execute commands for each device
            for device_id in matches:
                detected_devices.append(device_id)

                try:
                    safe_device_id = safe_remote_output_component(device_id)
                except ValueError as exc:
                    rejected_operations = max(1, len(device_commands))
                    total_operations += rejected_operations
                    error_messages.append(
                        f"Rejected device identifier {device_id!r}: {exc}"
                    )
                    continue

                for cmd_config in device_commands:
                    total_operations += 1
                    cmd_type = cmd_config["type"]
                    command_template = cmd_config["command_template"]
                    file_template = cmd_config["file_template"]

                    # Detection output is controlled by the endpoint.  Device
                    # identifiers are command operands, not trusted template
                    # fragments, so interpolate them only through the common
                    # remote-shell quoting boundary.
                    try:
                        filename = safe_remote_output_component(
                            file_template.format(device_index=safe_device_id)
                        )
                    except (KeyError, ValueError) as exc:
                        error_messages.append(
                            f"Rejected device identifier {device_id!r}: {exc}"
                        )
                        continue
                    command = build_remote_cmd(
                        command_template, device_index=safe_device_id
                    )

                    exit_code, stdout, stderr = (
                        await self.dut_manager.execute_bmc_command(dut_id, command)
                    )

                    if exit_code == 0:
                        file_path = await self.write_output_with_generalization(
                            dut_id,
                            kwargs.get("collector_id", ""),
                            stdout,
                            output_pattern=kwargs.get("filename"),
                            function_tag=filename,
                            substitutions={"command_name": filename},
                        )
                        if file_path and file_path not in output_files:
                            output_files.append(file_path)
                            successful_operations += 1
                        else:
                            error_messages.append(
                                f"Artifact write failed: {safe_device_id}_{cmd_type}"
                            )
                    else:
                        error_messages.append(
                            f"Device command failed: {device_id}_{cmd_type}"
                        )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="bmc_device_based_commands",
                additional_context={
                    "devices_found": len(detected_devices),
                    "devices_processed": detected_devices,
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="bmc_device_based_commands",
                additional_context={},
                dut_id=dut_id,
                collector_id="bmc_device_based_commands",
            )

    async def run_bmc_advanced_command(
        self,
        dut_id: str,
        command_scenarios: Dict[str, Any],
        platform_specific: Dict[str, Any],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run advanced BMC command with platform-specific handling.

        The implementation uses ``dut_id``, ``command_scenarios``,
        ``platform_specific``, and ``kwargs`` to run advanced BMC command with
        platform-specific handling. Terminal status is emitted only after
        advanced BMC command with platform-specific handling and its owned
        cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command_scenarios: Mapping supplying fields for advanced BMC command
                with platform-specific handling.
            platform_specific: Mapping supplying fields for advanced BMC command
                with platform-specific handling.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run BMC advanced command.
        """
        try:
            output_files = []

            # Get platform info using YAML-driven detection
            platform_detection_config = kwargs.get("platform_detection_config")
            platform_info = await self._get_platform_info(
                dut_id, platform_detection_config
            )
            platform_type = platform_info.get("platform_type", "unknown")

            # Select appropriate scenario
            if platform_type in command_scenarios:
                scenario = command_scenarios[platform_type]
            elif "default" in command_scenarios:
                scenario = command_scenarios["default"]
            else:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[
                        f"No command scenario found for platform {platform_type}"
                    ],
                    operation_name="bmc_advanced_command",
                    additional_context={"platform_type": platform_type},
                )

            # Execute scenario
            command = scenario["command"]
            timeout = await self._resolve_collector_timeout(
                dut_id,
                kwargs,
                default_timeout=300,
                explicit_timeout_sources=[scenario, kwargs],
            )

            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, command, timeout
            )

            if exit_code == 0:
                filename = f"bmc_advanced_{platform_type}.txt"
                file_path = await self.write_output_with_generalization(
                    dut_id,
                    kwargs.get("collector_id", ""),
                    stdout,
                    output_pattern=kwargs.get("filename"),
                    function_tag=filename,
                    substitutions={"command_name": filename},
                )
                output_files.append(file_path)

            return await self._create_standardized_collector_result(
                successful_operations=1 if exit_code == 0 else 0,
                total_operations=1,
                output_files=output_files,
                error_messages=(
                    []
                    if exit_code == 0
                    else [f"Advanced command failed with exit code {exit_code}"]
                ),
                operation_name="bmc_advanced_command",
                additional_context={
                    "platform_type": platform_type,
                    "scenario_used": scenario.get("name", "unknown"),
                    "exit_code": exit_code,
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="bmc_advanced_command",
                additional_context={},
                dut_id=dut_id,
                collector_id="bmc_advanced_command",
            )

    async def _get_merged_config(self, dut_id: str) -> Dict[str, Any]:
        """
        Get merged configuration for a DUT.

        Merges configurations in order of precedence:

        1. Baseboard config (lowest priority).
        2. Tool config (medium priority).
        3. DUT config (highest priority).

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing merged config.
        """
        # Get DUT config
        dut = self.dut_manager.get_dut(dut_id)
        if not dut:
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"DUT '{dut_id}' not found",
                dut_id,
            )
            return {}

        dut_config = dut.config

        # Get baseboard config
        baseboard_manager = self.dut_manager._get_baseboard_manager()
        baseboard_type = dut.config.get("baseboard")
        await self._log_runtime(
            "DEBUG",
            "BMCSSHService",
            f"DUT config keys: {list(dut.config.keys())}, baseboard: {baseboard_type}",
            dut_id,
        )

        baseboard_config = (
            baseboard_manager.get_baseboard_config(baseboard_type)
            if baseboard_manager
            else {}
        )

        # Merge configurations in order of precedence:
        # 1. Baseboard config (lowest priority)
        # 2. Tool config (medium priority)
        # 3. DUT config (highest priority)

        # Get tool config (global merged with DUT-specific overrides)
        tool_config = {}
        try:
            if self.orchestrator and hasattr(self.orchestrator, "config_manager"):
                tool_config = await self.orchestrator.get_dut_specific_tool_config(
                    dut_id
                )
        except Exception as e:
            await self._log_runtime(
                "WARNING",
                "BMCSSHService",
                f"Failed to get tool config for merge: {e}",
                dut_id,
            )

        # A present empty tool mapping clears lower spreadsheet/baseboard values.
        # Late baseboard detection also materializes those defaults in dut.config,
        # so ignore that copy unless the DUT source explicitly owns this key.
        if "i2c_config" in tool_config and tool_config["i2c_config"] == {}:
            baseboard_config = {**baseboard_config, "i2c_config": {}}
            if dut.has_explicit_config_key("i2c_config") is not True:
                dut_config = {**dut_config, "i2c_config": {}}

        # Start with baseboard config
        merged_config = baseboard_config.copy()

        # Merge tool config on top (tool config overrides baseboard)
        merged_config.update(tool_config)

        # Merge DUT config on top (DUT config takes highest precedence)
        merged_config.update(dut_config)

        # Special handling for i2c_config - merge nested configs with proper precedence
        baseboard_i2c_config = baseboard_config.get("i2c_config", {})
        tool_i2c_config = tool_config.get("i2c_config", {})
        dut_i2c_config = dut_config.get("i2c_config", {})

        # An explicitly present empty effective DUT mapping is a meaningful
        # clear.  Presence matters because the provenance flag can also come
        # from tool config; an absent DUT key must still inherit lower layers.
        if (
            "i2c_config" in dut_config
            and dut.has_explicit_config_key("i2c_config") is True
            and dut_i2c_config == {}
        ):
            merged_i2c_config = {}
        else:
            merged_i2c_config = {
                **baseboard_i2c_config,
                **tool_i2c_config,
                **dut_i2c_config,
            }
        merged_config["i2c_config"] = merged_i2c_config

        await self._log_runtime(
            "DEBUG",
            "BMCSSHService",
            f"i2c_config merge sources - baseboard: {len(baseboard_i2c_config)} keys, "
            f"tool_config: {len(tool_i2c_config)} keys, dut_config: {len(dut_i2c_config)} keys, "
            f"merged: {len(merged_i2c_config)} keys",
            dut_id,
        )

        await self._log_runtime(
            "DEBUG",
            "BMCSSHService",
            f"Merged config keys: {list(merged_config.keys())}",
            dut_id,
        )

        return merged_config

    async def _apply_i2c_collector_override(
        self,
        dut_id: str,
        i2c_config: Dict[str, Any],
        collector_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Overlay platform-specific I2C collector configuration when present.

        Baseboard configs can define ``I2C_COLLECTOR_OVERRIDES`` inside
        ``i2c_config``. Overrides are keyed by collector ``function_tag`` or
        collector id and replace YAML stage command/config fields for platforms
        whose telemetry is exposed through alternate paths.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            i2c_config: I2c config governing overlay platform-specific I2C
                collector configuration when present.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            A mapping containing i2c collector override.
        """
        merged_config = await self._get_merged_config(dut_id)
        merged_i2c_config = merged_config.get("i2c_config", {})
        overrides = merged_i2c_config.get("I2C_COLLECTOR_OVERRIDES", {})
        if not isinstance(overrides, dict):
            return i2c_config

        override_key = None
        for candidate in (i2c_config.get("function_tag"), collector_id):
            if candidate and candidate in overrides:
                override_key = candidate
                break

        if not override_key:
            return i2c_config

        override_config = overrides.get(override_key)
        if not isinstance(override_config, dict):
            return i2c_config

        resolved_i2c_config = dict(i2c_config)
        resolved_i2c_config.update(override_config)
        resolved_i2c_config = self._filter_i2c_commands_by_name(resolved_i2c_config)
        await self._log_runtime(
            "INFO",
            "BMCSSHService",
            f"Applied I2C collector override for {override_key}",
            dut_id,
        )
        return resolved_i2c_config

    @staticmethod
    def _normalize_i2c_execution_policy(
        value: Any,
    ) -> Optional[Dict[str, Any]]:
        """
        Validate an optional platform-specific I2C execution policy.

        The implementation uses ``value`` to validate an optional
        platform-specific I2C execution policy. Every required invariant is
        checked before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Args:
            value: Value object whose ``get`` state is read while performing
                optional platform-specific I2C execution policy.

        Returns:
            A mapping containing the ``mode``, ``route``, ``reason``,
            ``preflight_command``, and ``preflight_failure`` fields.

        Raises:
            ValueError: If the execution_policy is not a mapping; the
                execution_policy.mode is not 'validated' or 'skip'; the
                execution_policy.route is not a non-empty string; or the
                execution_policy.reason is not a non-empty string; or another
                input invariant is violated.
        """
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError("execution_policy must be a mapping")

        mode = value.get("mode")
        if mode not in {"validated", "skip"}:
            raise ValueError("execution_policy.mode must be 'validated' or 'skip'")
        route = value.get("route")
        reason = value.get("reason")
        if not isinstance(route, str) or not route.strip():
            raise ValueError("execution_policy.route must be a non-empty string")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("execution_policy.reason must be a non-empty string")

        preflight = value.get("preflight_command")
        if preflight is not None and (
            not isinstance(preflight, str) or not preflight.strip()
        ):
            raise ValueError(
                "execution_policy.preflight_command must be a non-empty string"
            )
        failure = value.get("preflight_failure", "error")
        if failure not in {"error", "skip"}:
            raise ValueError(
                "execution_policy.preflight_failure must be 'error' or 'skip'"
            )

        ownership = value.get("ownership")
        if mode == "validated" and ownership not in {
            "require_unbound",
            "require_driver",
        }:
            raise ValueError(
                "execution_policy.ownership must be 'require_unbound' or 'require_driver'"
            )
        if mode == "skip" and ownership is not None:
            raise ValueError("skip execution policy must not declare ownership")

        endpoints = value.get("endpoints", [])
        if not isinstance(endpoints, list) or any(
            not isinstance(endpoint, dict)
            or not isinstance(endpoint.get("bus"), str)
            or not endpoint.get("bus")
            or not isinstance(endpoint.get("address"), str)
            or not endpoint.get("address")
            for endpoint in endpoints
        ):
            raise ValueError(
                "execution_policy.endpoints must be a list of bus/address mappings"
            )

        driver = value.get("required_driver")
        if route == "kernel_hwmon":
            if not preflight:
                raise ValueError(
                    "kernel_hwmon execution policy requires preflight_command"
                )
            if not isinstance(driver, str) or not driver.strip():
                raise ValueError(
                    "kernel_hwmon execution policy requires required_driver"
                )
            if ownership != "require_driver":
                raise ValueError(
                    "kernel_hwmon execution policy requires ownership=require_driver"
                )
            if not endpoints:
                raise ValueError("kernel_hwmon execution policy requires endpoints")
        elif mode == "validated" and ownership != "require_unbound":
            raise ValueError(
                "validated raw I2C policy requires ownership=require_unbound"
            )

        return {
            "mode": mode,
            "route": route.strip(),
            "reason": reason.strip(),
            "preflight_command": preflight.strip() if preflight else None,
            "preflight_failure": failure,
            "required_driver": (driver.strip() if isinstance(driver, str) else None),
            "ownership": ownership,
            "endpoints": [dict(endpoint) for endpoint in endpoints],
        }

    @staticmethod
    def _extract_i2c_raw_endpoints(
        commands: List[str],
    ) -> List[Tuple[int, int]]:
        """
        Extract validated literal bus/address pairs from resolved commands.

        The safe template renderer deliberately quotes every substituted shell
        operand. Parse the rendered shell words before applying the strict I2C
        grammar so forms such as ``'-y' '2' w1@'0x4f'`` remain data-equivalent
        to their unquoted catalog template. Endpoint ownership is still checked
        separately against the exact normalized bus/address pairs returned here.

        Args:
            commands: Entries supplied as ``commands`` without transferring
                container ownership.

        Returns:
            The validated ``endpoints``.

        Raises:
            ValueError: If raw I2C command does not use the validated '-y BUS
                ADDRESS' or '-y BUS wN@ADDRESS' grammar; invalid I2C bus value
                ``bus_text``; invalid I2C address value ``address_text``; or I2C
                bus value out of range: ``bus``; or another input invariant is
                violated.
        """
        tool_pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9_./-]*/)?"
            r"(?:i2ctransfer|i2cset|i2cget|i2cdump)\b"
        )
        supported_tools = {"i2ctransfer", "i2cset", "i2cget", "i2cdump"}
        transfer_address = re.compile(r"w\d+@(?P<address>.+)\Z")

        endpoints: List[Tuple[int, int]] = []
        for command in commands:
            try:
                tokens = shlex.split(command, posix=True)
            except ValueError as exc:
                raise ValueError("raw I2C command has invalid shell quoting") from exc

            parsed: List[Tuple[str, str]] = []
            for index, token in enumerate(tokens):
                tool_name = PurePosixPath(token).name
                if tool_name not in supported_tools:
                    continue
                if index + 3 >= len(tokens) or tokens[index + 1] != "-y":
                    raise ValueError(
                        "raw I2C command does not use the validated '-y BUS ADDRESS' "
                        "or '-y BUS wN@ADDRESS' grammar"
                    )
                bus_text = tokens[index + 2]
                address_token = tokens[index + 3]
                if tool_name == "i2ctransfer":
                    address_match = transfer_address.fullmatch(address_token)
                    if address_match is None:
                        raise ValueError(
                            "raw I2C command does not use the validated '-y BUS "
                            "wN@ADDRESS' grammar"
                        )
                    address_text = address_match.group("address")
                else:
                    address_text = address_token
                parsed.append((bus_text, address_text))

            if len(parsed) != len(tool_pattern.findall(command)):
                raise ValueError(
                    "raw I2C command does not use the validated '-y BUS ADDRESS' "
                    "or '-y BUS wN@ADDRESS' grammar"
                )
            for bus_text, address_text in parsed:
                if not re.fullmatch(r"\d+", bus_text):
                    raise ValueError(f"invalid I2C bus value {bus_text!r}")
                if not re.fullmatch(r"0[xX][0-9A-Fa-f]{1,2}", address_text):
                    raise ValueError(f"invalid I2C address value {address_text!r}")
                bus = int(bus_text, 10)
                address = int(address_text, 16)
                if bus > 65535:
                    raise ValueError(f"I2C bus value out of range: {bus}")
                if not 0x03 <= address <= 0x77:
                    raise ValueError(
                        f"I2C address out of 7-bit device range: {address_text}"
                    )
                if (bus, address) not in endpoints:
                    endpoints.append((bus, address))
        return endpoints

    @classmethod
    def _resolve_i2c_policy_endpoints(
        cls,
        policy: Optional[Dict[str, Any]],
        resolved_config: Dict[str, str],
    ) -> List[Tuple[int, int]]:
        """
        Resolve declared policy endpoints from the effective baseboard config.

        The implementation uses ``policy`` and ``resolved_config`` to resolve
        declared policy endpoints from the effective baseboard config. If the
        function cannot resolve declared policy endpoints from the effective
        baseboard config, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            policy: Policy governing declared policy endpoints from the
                effective baseboard config.
            resolved_config: Resolved config governing declared policy endpoints
                from the effective baseboard config.

        Returns:
            The validated ``endpoints``.

        Raises:
            ValueError: If execution-policy endpoint references unresolved
                parameters ``bus_name``/``address_name``.
        """
        endpoints: List[Tuple[int, int]] = []
        for endpoint in (policy or {}).get("endpoints", []):
            bus_name = endpoint["bus"]
            address_name = endpoint["address"]
            if bus_name not in resolved_config or address_name not in resolved_config:
                raise ValueError(
                    "execution-policy endpoint references unresolved parameters "
                    f"{bus_name!r}/{address_name!r}"
                )
            resolved = cls._extract_i2c_raw_endpoints(
                [
                    "/usr/sbin/i2ctransfer -y "
                    f"{resolved_config[bus_name]} w1@{resolved_config[address_name]} r1"
                ]
            )[0]
            if resolved not in endpoints:
                endpoints.append(resolved)
        return endpoints

    async def _i2c_policy_terminal_result(
        self,
        dut_id: str,
        collector_id: Optional[str],
        status: str,
        reason: str,
        output_files: Optional[List[str]] = None,
        **context: Any,
    ) -> Dict[str, Any]:
        """
        Create a visible fail-closed policy result.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``status``, ``reason``, and ``output_files`` to
        ``self._create_standardized_collector_result`` and preserves its return
        and exception contract. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            status: Text supplied as status in the format accepted by this
                function.
            reason: Text supplied as reason in the format accepted by this
                function.
            output_files: Optional output files; ``None`` selects the function's
                default behavior.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            A mapping containing i2c policy terminal result.
        """
        additional_context = {"status": status, "reason": reason, **context}
        if status == "skipped":
            additional_context["intentional_policy_skip"] = True
            additional_context["intentional_evidence_only_skip"] = True
        return await self._create_standardized_collector_result(
            successful_operations=0,
            total_operations=0,
            output_files=output_files or [],
            error_messages=[] if status == "skipped" else [reason],
            operation_name="bmc_i2c_commands",
            additional_context=additional_context,
            dut_id=dut_id,
            collector_id=collector_id,
        )

    async def _persist_i2c_policy_evidence(
        self,
        dut_id: str,
        collector_id: Optional[str],
        content: str,
    ) -> Optional[str]:
        """
        Persist the policy decision before it is reported as authoritative.

        The implementation uses ``dut_id``, ``collector_id``, and ``content`` to
        persist the policy decision before it is reported as authoritative.
        Success is reported only after the owning output boundary has completed
        its required write or publication step. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            content: Text supplied as content in the format accepted by this
                function.

        Returns:
            Whether the policy decision before it is reported as authoritative
            operation succeeds.
        """
        return (
            await self.write_output_with_generalization(
                dut_id,
                collector_id or "",
                content,
                output_pattern="SSH_{collector_id}_execution_policy.txt",
                function_tag="execution_policy",
                substitutions={"collector_id": collector_id or "i2c"},
            )
            or None
        )

    async def _run_i2c_policy_preflight(
        self,
        dut_id: str,
        collector_id: Optional[str],
        collection_kwargs: Dict[str, Any],
        i2c_config: Dict[str, Any],
        policy: Dict[str, Any],
        resolved_config: Dict[str, str],
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Run and retain a declared safe route preflight.

        The implementation uses ``dut_id``, ``collector_id``,
        ``collection_kwargs``, ``i2c_config``, and ``policy`` to run and retain
        a declared safe route preflight. Terminal status is emitted only after
        and retain a declared safe route preflight and its owned cleanup have
        completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collection_kwargs: Mapping supplying fields for and retain a
                declared safe route preflight.
            i2c_config: I2c config governing and retain a declared safe route
                preflight.
            policy: Policy governing and retain a declared safe route preflight.
            resolved_config: Resolved config governing and retain a declared
                safe route preflight.

        Returns:
            A tuple containing ``metadata mapping`` and ``metadata mapping`` in
            that order.
        """
        preflight = policy.get("preflight_command")
        if not preflight:
            return None, None

        try:
            self._resolve_i2c_policy_endpoints(policy, resolved_config)
        except ValueError as exc:
            reason = f"Invalid I2C execution-policy endpoint: {exc}"
            return (
                await self._i2c_policy_terminal_result(
                    dut_id,
                    collector_id,
                    "error",
                    reason,
                    configuration_error=True,
                ),
                None,
            )

        preflight = _render_i2c_command_template_once(preflight, resolved_config)
        if re.search(r"(?<!\$)\{[A-Za-z_][A-Za-z0-9_]*\}", preflight):
            reason = (
                "I2C execution-policy preflight contains unresolved "
                "configuration placeholders"
            )
            return (
                await self._i2c_policy_terminal_result(
                    dut_id,
                    collector_id,
                    "error",
                    reason,
                    configuration_error=True,
                ),
                None,
            )

        timeout = await self._resolve_collector_timeout(
            dut_id,
            collection_kwargs,
            default_timeout=30,
            explicit_timeout_sources=[i2c_config, collection_kwargs],
        )
        exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
            dut_id, preflight, timeout=timeout
        )
        evidence = "\n".join(
            value.strip() for value in (stdout or "", stderr or "") if value.strip()
        )
        observed_drivers = re.findall(r"\bdriver=([^\s]+)", evidence)
        kernel_driver_bound: Optional[bool]
        if any(driver != "unbound" for driver in observed_drivers):
            kernel_driver_bound = True
        elif observed_drivers:
            kernel_driver_bound = False
        else:
            kernel_driver_bound = None
        kernel_driver_state = (
            str(kernel_driver_bound).lower()
            if kernel_driver_bound is not None
            else "unknown"
        )
        content = (
            f"mode={policy['mode']}\n"
            f"route={policy['route']}\n"
            f"ownership={policy['ownership']}\n"
            f"required_driver={policy.get('required_driver') or ''}\n"
            f"preflight_exit_code={exit_code}\n"
            f"{evidence}\n"
        )
        artifact = await self._persist_i2c_policy_evidence(
            dut_id, collector_id, content
        )
        if not artifact:
            reason = "Failed to persist failed I2C policy-preflight evidence"
            if exit_code == 0:
                reason = "Failed to persist I2C execution-policy provenance"
            return (
                await self._i2c_policy_terminal_result(
                    dut_id,
                    collector_id,
                    "error",
                    reason,
                    policy_preflight_failed=exit_code != 0,
                    preflight_exit_code=exit_code,
                    kernel_driver_bound=kernel_driver_bound,
                    endpoint_evidence=evidence,
                ),
                None,
            )

        provenance = {
            "mode": policy["mode"],
            "route": policy["route"],
            "ownership": policy["ownership"],
            "required_driver": policy.get("required_driver"),
            "preflight_exit_code": exit_code,
            "kernel_driver_bound": kernel_driver_bound,
            "observed_drivers": observed_drivers,
            "preflight_output": evidence,
            "artifact": artifact,
        }
        if exit_code == 0:
            return None, provenance

        reason = (
            f"{policy['reason']} kernel_driver_bound="
            f"{kernel_driver_state}; route={policy['route']}; "
            f"required_driver={policy.get('required_driver') or ''}; "
            f"preflight_exit_code={exit_code}"
            f"{f'; evidence={evidence}' if evidence else ''}"
        )
        status = "skipped" if policy["preflight_failure"] == "skip" else "error"
        return (
            await self._i2c_policy_terminal_result(
                dut_id,
                collector_id,
                status,
                reason,
                output_files=[artifact],
                execution_policy={
                    "mode": policy["mode"],
                    "route": policy["route"],
                    "preflight": {"preflight_exit_code": exit_code},
                },
                policy_preflight_failed=True,
                preflight_exit_code=exit_code,
                kernel_driver_bound=kernel_driver_bound,
                observed_drivers=observed_drivers,
                endpoint_evidence=evidence,
                execution_policy_artifact=artifact,
            ),
            None,
        )

    @staticmethod
    def _i2c_inline_driver_guard(bus: int, address: int) -> str:
        """
        Return the i2c inline driver guard.

        The implementation uses ``bus`` and ``address`` to produce the i2c
        inline driver guard.

        Args:
            bus: Numeric bus used while the operation performs bounded
                accounting.
            address: Numeric address used while the operation performs bounded
                accounting.

        Returns:
            The canonical i2c inline driver guard text.
        """
        device = shlex.quote(f"/sys/bus/i2c/devices/{bus}-{address:04x}")
        return (
            f"if [ -e {device}/driver ]; then "
            f'driver=$(basename "$(readlink {device}/driver 2>/dev/null)"); '
            "printf 'kernel_driver_bound device=%s bus=%s address=%s driver=%s\\n' "
            f'{device} {bus} 0x{address:02x} "${{driver:-unknown}}" >&2; '
            "exit 73; fi"
        )

    async def _prepare_i2c_raw_policy_commands(
        self,
        dut_id: str,
        collector_id: Optional[str],
        collection_kwargs: Dict[str, Any],
        i2c_config: Dict[str, Any],
        policy: Dict[str, Any],
        resolved_config: Dict[str, str],
        commands: List[str],
        output_files: List[str],
    ) -> Tuple[Optional[Dict[str, Any]], List[str], Optional[Dict[str, Any]]]:
        """
        Prove raw endpoints unbound and guard each shell execution boundary.

        The implementation uses ``dut_id``, ``collector_id``,
        ``collection_kwargs``, ``i2c_config``, and ``policy`` to prove raw
        endpoints unbound and guard each shell execution boundary. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. The operation mutates ``output_files`` in
        place; ownership of those objects remains with the caller.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collection_kwargs: Mapping supplying fields for prove raw endpoints
                unbound and guard each shell execution boundary.
            i2c_config: I2c config governing prove raw endpoints unbound and
                guard each shell execution boundary.
            policy: Policy governing prove raw endpoints unbound and guard each
                shell execution boundary.
            resolved_config: Resolved config governing prove raw endpoints
                unbound and guard each shell execution boundary.
            commands: Entries supplied as ``commands`` without transferring
                container ownership.
            output_files: Entries supplied as ``output_files`` without
                transferring container ownership.

        Returns:
            A tuple containing an optional terminal result, guarded commands,
            and policy provenance.
        """
        try:
            endpoints = self._extract_i2c_raw_endpoints(commands)
            for endpoint in self._resolve_i2c_policy_endpoints(policy, resolved_config):
                if endpoint not in endpoints:
                    endpoints.append(endpoint)
        except ValueError as exc:
            reason = f"Invalid validated I2C endpoint grammar: {exc}"
            result = await self._i2c_policy_terminal_result(
                dut_id,
                collector_id,
                "error",
                reason,
                output_files=output_files,
                configuration_error=True,
            )
            return result, commands, None
        if not endpoints:
            reason = (
                "Validated raw I2C route did not expose any auditable "
                "bus/address endpoints"
            )
            result = await self._i2c_policy_terminal_result(
                dut_id,
                collector_id,
                "error",
                reason,
                output_files=output_files,
                configuration_error=True,
            )
            return result, commands, None

        checks = ["_nvd_i2c_bound=0"]
        for bus, address in endpoints:
            device = shlex.quote(f"/sys/bus/i2c/devices/{bus}-{address:04x}")
            checks.append(
                "if [ -e {device}/driver ]; then "
                'driver=$(basename "$(readlink {device}/driver 2>/dev/null)"); '
                "printf 'kernel_driver_bound device=%s bus=%s address=%s driver=%s\\n' "
                '{device} {bus} {address} "${{driver:-unknown}}"; '
                "_nvd_i2c_bound=1; else printf 'kernel_driver_bound=false "
                "device=%s bus=%s address=%s driver=unbound\\n' "
                "{device} {bus} {address}; fi".format(
                    device=device, bus=bus, address=f"0x{address:02x}"
                )
            )
        checks.append('test "$_nvd_i2c_bound" -eq 0')
        timeout = await self._resolve_collector_timeout(
            dut_id,
            collection_kwargs,
            default_timeout=30,
            explicit_timeout_sources=[i2c_config, collection_kwargs],
        )
        exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
            dut_id, "; ".join(checks), timeout=timeout
        )
        evidence = "\n".join(
            value.strip() for value in (stdout or "", stderr or "") if value.strip()
        )
        content = (
            f"mode={policy['mode']}\nroute={policy['route']}\n"
            f"ownership={policy['ownership']}\n"
            f"preflight_exit_code={exit_code}\n{evidence}\n"
        )
        artifact = await self._persist_i2c_policy_evidence(
            dut_id, collector_id, content
        )
        if not artifact:
            reason = "Failed to persist I2C endpoint-ownership provenance"
            result = await self._i2c_policy_terminal_result(
                dut_id,
                collector_id,
                "error",
                reason,
                output_files=output_files,
                preflight_exit_code=exit_code,
            )
            return result, commands, None
        if artifact not in output_files:
            output_files.append(artifact)

        kernel_driver_bound = "kernel_driver_bound device=" in evidence
        if exit_code != 0:
            if kernel_driver_bound:
                reason = (
                    f"{policy['reason']} Raw I2C access was blocked because "
                    f"kernel_driver_bound=true; route={policy['route']}; "
                    f"evidence={evidence}"
                )
                result = await self._i2c_policy_terminal_result(
                    dut_id,
                    collector_id,
                    "skipped",
                    reason,
                    output_files=output_files,
                    kernel_driver_bound=True,
                    preflight_exit_code=exit_code,
                    endpoint_evidence=evidence,
                    execution_policy={
                        "mode": policy["mode"],
                        "route": policy["route"],
                        "ownership": policy["ownership"],
                        "preflight": {"preflight_exit_code": exit_code},
                    },
                )
                return result, commands, None
            reason = (
                "I2C endpoint ownership preflight failed without canonical "
                f"driver evidence: {evidence}"
            )
            result = await self._i2c_policy_terminal_result(
                dut_id,
                collector_id,
                "error",
                reason,
                output_files=output_files,
                preflight_exit_code=exit_code,
            )
            return result, commands, None

        guarded_commands: List[str] = []
        raw_tool = re.compile(
            r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9_./-]*/)?"
            r"(?:i2ctransfer|i2cset|i2cget|i2cdump)\b"
        )
        for command in commands:
            guarded_segments = []
            for segment in command.split(" && "):
                if len(raw_tool.findall(segment)) > 1:
                    reason = (
                        "Validated raw I2C command contains multiple operations "
                        "without an auditable shell boundary"
                    )
                    result = await self._i2c_policy_terminal_result(
                        dut_id,
                        collector_id,
                        "error",
                        reason,
                        output_files=output_files,
                        configuration_error=True,
                    )
                    return result, commands, None
                guards = [
                    self._i2c_inline_driver_guard(bus, address)
                    for bus, address in self._extract_i2c_raw_endpoints([segment])
                ]
                guarded_segments.append(" && ".join([*guards, segment]))
            guarded_commands.append(" && ".join(guarded_segments))

        provenance = {
            "mode": policy["mode"],
            "route": policy["route"],
            "ownership": policy["ownership"],
            "preflight_exit_code": exit_code,
            "kernel_driver_bound": False,
            "endpoint_evidence": evidence,
            "artifact": artifact,
        }
        return None, guarded_commands, provenance

    async def _i2c_inline_guard_result(
        self,
        dut_id: str,
        collector_id: Optional[str],
        policy: Optional[Dict[str, Any]],
        successful: List[Dict[str, Any]],
        failed: List[Dict[str, Any]],
        output_files: List[str],
    ) -> Optional[Dict[str, Any]]:
        """
        Convert a guard-blocked batch into a retained visible skip.

        The implementation uses ``dut_id``, ``collector_id``, ``policy``,
        ``successful``, and ``failed`` to convert a guard-blocked batch into a
        retained visible skip. The source value keeps its ownership while the
        normalized representation is returned separately. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind. The operation mutates ``output_files`` in place;
        ownership of those objects remains with the caller.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            policy: Policy governing guard-blocked batch into a retained visible
                skip.
            successful: Mapping supplying fields for guard-blocked batch into a
                retained visible skip.
            failed: Mapping supplying fields for guard-blocked batch into a
                retained visible skip.
            output_files: Entries supplied as ``output_files`` without
                transferring container ownership.

        Returns:
            A mapping containing i2c inline guard result, or ``None`` when the
            requested value is unavailable.
        """
        if not policy or not failed:
            return None
        guarded_failures = [
            result
            for result in failed
            if (
                result.get("exit_code") == 73
                and "kernel_driver_bound device=" in str(result.get("stderr", ""))
            )
        ]
        if not guarded_failures:
            return None
        evidence = "; ".join(
            str(result.get("stderr", "")).strip() for result in guarded_failures
        )
        content = (
            f"mode={policy['mode']}\nroute={policy['route']}\n"
            f"ownership={policy['ownership']}\ninline_guard=true\n{evidence}\n"
        )
        artifact = await self._persist_i2c_policy_evidence(
            dut_id, collector_id, content
        )
        if not artifact:
            return await self._i2c_policy_terminal_result(
                dut_id,
                collector_id,
                "error",
                "Failed to persist inline I2C ownership evidence",
                output_files=output_files,
            )
        if artifact not in output_files:
            output_files.append(artifact)
        reason = (
            f"{policy['reason']} Raw I2C access was blocked by the inline "
            "ownership guard because kernel_driver_bound=true; "
            f"route={policy['route']}; evidence={evidence}"
        )
        return await self._i2c_policy_terminal_result(
            dut_id,
            collector_id,
            "skipped",
            reason,
            output_files=output_files,
            kernel_driver_bound=True,
            inline_ownership_guard=True,
            endpoint_evidence=evidence,
            commands_completed_before_guard=len(successful),
            execution_policy={
                "mode": policy["mode"],
                "route": policy["route"],
                "ownership": policy["ownership"],
            },
        )

    @staticmethod
    def _normalize_i2c_command_name_filter(value: Any) -> Optional[Set[str]]:
        """
        Normalize a command-name selector without treating a string as chars.

        The implementation uses ``value`` to normalize a command-name selector
        without treating a string as chars. The source value keeps its ownership
        while the normalized representation is returned separately.

        Args:
            value: Value evaluated while performing command-name selector
                without treating a string as chars.

        Returns:
            The unique i2c command name filter returned by the operation, or
            ``None`` when the requested value is unavailable.
        """

        if value is None:
            return None
        if isinstance(value, str):
            return {value} if value else set()
        if not isinstance(value, (list, tuple, set, frozenset)):
            return None
        return {str(name) for name in value if str(name)}

    @classmethod
    def _filter_i2c_commands_by_name(cls, i2c_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply optional include/exclude selectors to named command records.

        Only the already-materialized ``commands`` and ``command_groups``
        collections are filtered. Structured ``device_commands`` remain intact
        for their normal topology-aware expansion later in the runtime flow.

        Args:
            i2c_config: I2c config governing apply optional include/exclude
                selectors to named command records.

        Returns:
            A mapping containing filter i2c commands by name.
        """

        include_names = cls._normalize_i2c_command_name_filter(
            i2c_config.get("include_command_names")
        )
        exclude_names = cls._normalize_i2c_command_name_filter(
            i2c_config.get("exclude_command_names")
        )
        if include_names is None and not exclude_names:
            return i2c_config

        excluded = exclude_names or set()

        def selected(command: Any) -> bool:
            """
            Return the selected.

            The implementation uses ``command`` to produce the selected.

            Args:
                command: Command object whose ``get`` state is read while
                    performing selected.

            Returns:
                Whether the selected operation succeeds.
            """
            if not isinstance(command, dict):
                return include_names is None
            name = str(command.get("name", ""))
            return (
                include_names is None or name in include_names
            ) and name not in excluded

        resolved = dict(i2c_config)
        commands = i2c_config.get("commands")
        if isinstance(commands, list):
            resolved["commands"] = [
                command for command in commands if selected(command)
            ]

        command_groups = i2c_config.get("command_groups")
        if isinstance(command_groups, dict):
            resolved["command_groups"] = {
                group_name: (
                    [command for command in group_commands if selected(command)]
                    if isinstance(group_commands, list)
                    else group_commands
                )
                for group_name, group_commands in command_groups.items()
            }

        return resolved

    @classmethod
    def _filter_i2c_command_batch_by_name(
        cls,
        commands: List[str],
        names: List[str],
        groups: List[str],
        i2c_config: Dict[str, Any],
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        Filter aligned final command records, including expanded devices.

        The implementation uses ``commands``, ``names``, ``groups``, and
        ``i2c_config`` to filter aligned final command records, including
        expanded devices.

        Args:
            commands: Entries supplied as ``commands`` without transferring
                container ownership.
            names: Entries supplied as ``names`` without transferring container
                ownership.
            groups: Entries supplied as ``groups`` without transferring
                container ownership.
            i2c_config: I2c config governing filter aligned final command
                records, including expanded devices.

        Returns:
            A tuple containing aligned filtered commands, command names, and
            command groups.
        """

        include_names = cls._normalize_i2c_command_name_filter(
            i2c_config.get("include_command_names")
        )
        exclude_names = (
            cls._normalize_i2c_command_name_filter(
                i2c_config.get("exclude_command_names")
            )
            or set()
        )
        if include_names is None and not exclude_names:
            return commands, names, groups

        selected_records = [
            (command, name, group)
            for command, name, group in zip(commands, names, groups)
            if (include_names is None or name in include_names)
            and name not in exclude_names
        ]
        return (
            [record[0] for record in selected_records],
            [record[1] for record in selected_records],
            [record[2] for record in selected_records],
        )

    async def _resolve_config_keys(
        self, dut_id: str, config_keys: Dict[str, str]
    ) -> Tuple[Dict[str, str], List[str]]:
        """
        Resolve config keys to actual values using merged configuration.

        The implementation uses ``dut_id`` and ``config_keys`` to resolve config
        keys to actual values using merged configuration. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            config_keys: Config keys governing config keys to actual values
                using merged configuration.

        Returns:
            A tuple containing ``resolved config`` and ``unresolved keys`` in
            that order.
        """
        merged_config = await self._get_merged_config(dut_id)
        resolved_config = {}
        unresolved_keys = []

        # Get the i2c_config section from merged config
        i2c_config = merged_config.get("i2c_config", {})

        for var_name, config_key in config_keys.items():
            if config_key in i2c_config:
                resolved_config[var_name] = str(i2c_config[config_key])
                await self._log_runtime(
                    "DEBUG",
                    "BMCSSHService",
                    f"Resolved {var_name} = {config_key} -> {i2c_config[config_key]}",
                    dut_id,
                )
            else:
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    f"Config key '{config_key}' not found in i2c_config for variable '{var_name}'",
                    dut_id,
                )
                unresolved_keys.append(f"{var_name} ({config_key})")
                # Don't add unresolved placeholders - we'll skip execution instead

        return resolved_config, unresolved_keys

    async def _expand_i2c_device_commands(
        self,
        dut_id: str,
        device_command_config: Dict[str, Any],
        resolved_config: Dict[str, str],
    ) -> Tuple[List[str], List[str], List[str], List[str]]:
        """
        Expand config-driven device commands into concrete commands.

        The implementation uses ``dut_id``, ``device_command_config``, and
        ``resolved_config`` to expand config-driven device commands into
        concrete commands. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            device_command_config: Device command config governing expand
                config-driven device commands into concrete commands.
            resolved_config: Resolved config governing expand config-driven
                device commands into concrete commands.

        Returns:
            A tuple containing expanded commands, command names, command groups,
            and errors.
        """
        merged_config = await self._get_merged_config(dut_id)
        i2c_config = merged_config.get("i2c_config", {})

        devices_key = device_command_config.get("devices_key")
        if not devices_key:
            return (
                [],
                [],
                [],
                ["device_commands missing required 'devices_key'"],
            )

        devices = i2c_config.get(devices_key)
        if devices is None:
            return (
                [],
                [],
                [],
                [f"device list key '{devices_key}' not found in i2c_config"],
            )

        if not isinstance(devices, list):
            return (
                [],
                [],
                [],
                [
                    f"device list '{devices_key}' must be a list, got {type(devices).__name__}"
                ],
            )

        command_template = device_command_config.get("command_template")
        operations = device_command_config.get("operations", [])
        name_template = device_command_config.get(
            "name_template", "{device_name}_{name_suffix}"
        )
        required_device_keys = device_command_config.get(
            "required_device_keys", ["name", "addr", "bus"]
        )

        if not command_template:
            return (
                [],
                [],
                [],
                ["device_commands missing required 'command_template'"],
            )

        if not operations:
            return (
                [],
                [],
                [],
                ["device_commands missing required 'operations'"],
            )

        commands_to_batch: List[str] = []
        command_names: List[str] = []
        command_group_names: List[str] = []
        errors: List[str] = []

        for device_index, device in enumerate(devices, start=1):
            if not isinstance(device, dict):
                errors.append(
                    f"device entry #{device_index} in '{devices_key}' must be a mapping"
                )
                continue

            missing_device_keys = [
                key for key in required_device_keys if key not in device
            ]
            if missing_device_keys:
                errors.append(
                    f"device entry #{device_index} in '{devices_key}' missing keys: {', '.join(missing_device_keys)}"
                )
                continue

            template_values = {
                **resolved_config,
                **{key: str(value) for key, value in device.items()},
                "device_index": str(device_index),
                "device_name": str(device.get("name", f"device_{device_index}")),
            }

            for operation in operations:
                if not isinstance(operation, dict):
                    errors.append(
                        f"operation entry for '{template_values['device_name']}' must be a mapping"
                    )
                    continue

                operation_values = {key: str(value) for key, value in operation.items()}
                all_values = {**template_values, **operation_values}

                try:
                    processed_cmd = build_remote_cmd(command_template, **all_values)
                    cmd_name = name_template.format(**all_values)
                except (KeyError, IndexError) as exc:
                    errors.append(
                        f"missing template value {exc!s} for device '{template_values['device_name']}'"
                    )
                    continue

                commands_to_batch.append(processed_cmd)
                command_names.append(cmd_name)
                command_group_names.append(
                    str(operation.get("group", device_command_config.get("group", "")))
                )

        return commands_to_batch, command_names, command_group_names, errors

    async def run_bmc_i2c_commands(
        self,
        dut_id: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run I2C commands with YAML-driven configuration.

        The implementation uses ``dut_id`` and ``kwargs`` to run I2C commands
        with YAML-driven configuration. Terminal status is emitted only after
        I2C commands with YAML-driven configuration and its owned cleanup have
        completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run BMC i2c commands.
        """
        start_time = time.time()
        timing_data = []

        try:
            output_files = []
            diagnostic_files: List[str] = []
            results = []
            scan_warnings: List[Dict[str, str]] = []
            excluded_adapter_scans: List[Dict[str, Any]] = []
            read_mode_adapter_scans: List[Dict[str, Any]] = []
            invalid_scan_exclusion_patterns: List[Dict[str, str]] = []
            invalid_scan_read_patterns: List[Dict[str, str]] = []
            active_adapter_scan_count = 0
            execution_policy: Optional[Dict[str, Any]] = None
            execution_policy_provenance: Optional[Dict[str, Any]] = None

            # Collect all commands for batching
            commands_to_batch = []
            command_names = []
            command_group_names = []

            # Extract i2c_config from kwargs (params from YAML)
            # The params are passed directly in kwargs, not under a "params" key
            i2c_config = {
                k: v
                for k, v in kwargs.items()
                if k
                not in [
                    "dut_id",
                    "collector_id",
                    "collection_level",
                    "service_name",
                    "collector_def",
                    "bmc_ssh_available",
                    "output_pattern",
                ]
            }

            # Debug logging
            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"run_bmc_i2c_commands called with dut_id={dut_id}, i2c_config={i2c_config}",
                dut_id,
            )

            i2c_config = await self._apply_i2c_collector_override(
                dut_id,
                i2c_config,
                kwargs.get("collector_id"),
            )
            try:
                execution_policy = self._normalize_i2c_execution_policy(
                    i2c_config.get("execution_policy")
                )
            except ValueError as exc:
                return await self._i2c_policy_terminal_result(
                    dut_id,
                    kwargs.get("collector_id"),
                    "error",
                    f"Invalid I2C execution policy: {exc}",
                    configuration_error=True,
                )
            if execution_policy and execution_policy["mode"] == "skip":
                return await self._i2c_policy_terminal_result(
                    dut_id,
                    kwargs.get("collector_id"),
                    "skipped",
                    execution_policy["reason"],
                    execution_policy={
                        "mode": execution_policy["mode"],
                        "route": execution_policy["route"],
                    },
                )
            emit_parent = i2c_config.get("emit_parent", True)
            if not isinstance(emit_parent, bool):
                config_error = "emit_parent must be a boolean"
                await self._log_runtime("ERROR", "BMCSSHService", config_error, dut_id)
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[config_error],
                    operation_name="bmc_i2c_commands",
                    additional_context={
                        "status": "error",
                        "reason": config_error,
                        "configuration_error": True,
                    },
                    dut_id=dut_id,
                    collector_id=kwargs.get("collector_id"),
                )
            try:
                collector_variants = _normalize_i2c_collector_variants(
                    i2c_config.get("collector_variants")
                )
            except ValueError as exc:
                config_error = f"Invalid collector_variants configuration: {exc}"
                await self._log_runtime("ERROR", "BMCSSHService", config_error, dut_id)
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[config_error],
                    operation_name="bmc_i2c_commands",
                    additional_context={
                        "status": "error",
                        "reason": config_error,
                        "configuration_error": True,
                    },
                    dut_id=dut_id,
                    collector_id=kwargs.get("collector_id"),
                )
            merged_i2c_config = (await self._get_merged_config(dut_id)).get(
                "i2c_config", {}
            )
            expected_absence_config_key = i2c_config.get("expected_absence_config_key")
            expected_device_absence = (
                isinstance(expected_absence_config_key, str)
                and bool(expected_absence_config_key.strip())
                and merged_i2c_config.get(expected_absence_config_key.strip()) is True
            )
            reject_all_ff_payloads = i2c_config.get("reject_all_ff_payloads") is True

            scan_exclusion_policy_configured = (
                "scan_adapter_exclude_patterns" in i2c_config
            )
            scan_read_policy_configured = "scan_adapter_read_patterns" in i2c_config
            scan_adapter_policy_configured = (
                scan_exclusion_policy_configured or scan_read_policy_configured
            )
            compiled_scan_exclusions = _compile_scan_adapter_patterns(
                i2c_config.get("scan_adapter_exclude_patterns", []),
                invalid_scan_exclusion_patterns,
            )
            compiled_scan_read_patterns = _compile_scan_adapter_patterns(
                i2c_config.get("scan_adapter_read_patterns", []),
                invalid_scan_read_patterns,
            )

            for invalid_pattern in invalid_scan_exclusion_patterns:
                await self._log_runtime(
                    "ERROR",
                    "BMCSSHService",
                    "Invalid S7 adapter exclusion pattern; active scans will be "
                    f"disabled: {invalid_pattern['pattern']}: "
                    f"{invalid_pattern['reason']}",
                    dut_id,
                )
            for invalid_pattern in invalid_scan_read_patterns:
                await self._log_runtime(
                    "ERROR",
                    "BMCSSHService",
                    "Invalid S7 adapter read pattern; active scans will be "
                    f"disabled: {invalid_pattern['pattern']}: "
                    f"{invalid_pattern['reason']}",
                    dut_id,
                )

            # Resolve config keys to actual values
            config_keys = i2c_config.get("config_keys", {})
            resolved_config, unresolved_keys = await self._resolve_config_keys(
                dut_id, config_keys
            )

            # If there are unresolved config keys, skip this collector
            # This handles the case where the baseboard doesn't have i2c_config defined
            if unresolved_keys:
                missing_keys_str = ", ".join(unresolved_keys)
                skip_message = (
                    f"Required I2C configuration keys not defined for this baseboard: {missing_keys_str}. "
                    f"Please add these values to the baseboard's i2c_config in baseboards.yaml."
                )
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    skip_message,
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="bmc_i2c_commands",
                    additional_context={
                        "status": "skipped",
                        "reason": skip_message,
                        "unresolved_config_keys": unresolved_keys,
                    },
                    dut_id=dut_id,
                    collector_id=kwargs.get("collector_id"),
                )

            if execution_policy and execution_policy.get("preflight_command"):
                terminal_result, execution_policy_provenance = (
                    await self._run_i2c_policy_preflight(
                        dut_id,
                        kwargs.get("collector_id"),
                        kwargs,
                        i2c_config,
                        execution_policy,
                        resolved_config,
                    )
                )
                if terminal_result:
                    return terminal_result
                if execution_policy_provenance:
                    output_files.append(execution_policy_provenance["artifact"])
                    diagnostic_files.append(execution_policy_provenance["artifact"])

            base_command = i2c_config.get("base_command")
            scan_commands = i2c_config.get("scan_commands", False)
            scan_output_pattern = i2c_config.get("scan_output_pattern")
            if scan_commands:
                if scan_output_pattern is None:
                    scan_output_pattern = (
                        "SSH_{collector_id}_{function_tag}_bus_scan{bus}.txt"
                    )
                invalid_scan_output_pattern = (
                    not isinstance(scan_output_pattern, str)
                    or not scan_output_pattern.strip()
                    or not re.search(
                        r"(?<!\{)\{bus(?:![rsa])?(?::[^{}]*)?\}(?!\})",
                        scan_output_pattern,
                    )
                    or os.path.basename(scan_output_pattern) != scan_output_pattern
                    or "\\" in scan_output_pattern
                )
                if not invalid_scan_output_pattern:
                    try:
                        scan_output_pattern.format(
                            bus=0,
                            collector_id="collector",
                            function_tag="i2c_scan",
                        )
                    except (IndexError, KeyError, ValueError):
                        invalid_scan_output_pattern = True
                if invalid_scan_output_pattern:
                    config_error = (
                        "scan_output_pattern must be a non-empty string containing "
                        "the {bus} placeholder and naming a collector-local file"
                    )
                    await self._log_runtime(
                        "ERROR", "BMCSSHService", config_error, dut_id
                    )
                    return await self._create_standardized_collector_result(
                        successful_operations=0,
                        total_operations=1,
                        output_files=[],
                        error_messages=[config_error],
                        operation_name="bmc_i2c_commands",
                        additional_context={
                            "status": "error",
                            "reason": config_error,
                            "configuration_error": True,
                        },
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id"),
                    )

            # Handle base command (e.g., i2cdetect -l)
            if base_command:
                base_start_time = time.monotonic()
                base_timing_operation_id = None
                if self.timing_manager:
                    base_timing_operation_id = self.timing_manager.start_operation(
                        "bmc_ssh_command",
                        "base_command",
                        metadata={"command": base_command},
                    )
                try:
                    exit_code, stdout, stderr = (
                        await self.dut_manager.execute_bmc_command(dut_id, base_command)
                    )
                except BaseException as exc:
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            base_timing_operation_id,
                            status=(
                                "cancelled"
                                if isinstance(exc, asyncio.CancelledError)
                                else "error"
                            ),
                            error=str(exc),
                        )
                    raise
                base_duration = time.monotonic() - base_start_time
                base_output_file = None

                base_output_content = stdout
                if exit_code != 0 and stderr:
                    base_output_content = (
                        f"{stdout.rstrip()}\n\n=== STDERR ===\n{stderr}"
                        if stdout
                        else f"=== STDERR ===\n{stderr}"
                    )
                if exit_code == 0 or base_output_content:
                    base_output_file = (
                        await self.write_output_with_generalization(
                            dut_id,
                            kwargs.get("collector_id", ""),
                            base_output_content,
                            output_pattern=kwargs.get("output_pattern"),
                            function_tag=kwargs.get("function_tag", "i2c_base"),
                        )
                        or None
                    )
                    if base_output_file:
                        output_files.append(base_output_file)

                base_success = exit_code == 0 and bool(base_output_file)
                if self.timing_manager:
                    self.timing_manager.end_operation(
                        base_timing_operation_id,
                        status="success" if base_success else "error",
                        artifact_path=base_output_file,
                        metadata={
                            "exit_code": exit_code,
                            "raw_exit_code": exit_code,
                            "semantic_success": base_success,
                        },
                    )
                base_result = {
                    "command": base_command,
                    "name": "base_command",
                    "success": base_success,
                    "output_file": base_output_file,
                    "exit_code": exit_code,
                    "stdout": stdout,
                    "stderr": stderr,
                    "execution_time": base_duration,
                }
                if not base_success:
                    base_result["error"] = (
                        stderr
                        if exit_code != 0
                        else "Failed to persist output for base_command"
                    )
                results.append(base_result)
                timing_data.append(
                    {
                        "command": "base_command",
                        "duration": base_duration,
                        "success": base_success,
                    }
                )

            # Handle scan commands (e.g., i2cdetect -y {bus})
            if scan_commands and base_command:
                read_mode_patterns_by_bus: Dict[int, str] = {}
                invalid_scan_policy_patterns = (
                    invalid_scan_exclusion_patterns + invalid_scan_read_patterns
                )
                if invalid_scan_policy_patterns:
                    i2c_numbers = []
                    scan_policy_error = (
                        "Active adapter scans disabled because the configured "
                        "adapter safety policy contains invalid patterns"
                    )
                    results.append(
                        {
                            "command": "validate adapter scan policy",
                            "name": "scan_adapter_policy",
                            "success": False,
                            "output_file": None,
                            "exit_code": -1,
                            "stdout": "",
                            "stderr": scan_policy_error,
                            "error": scan_policy_error,
                            "execution_time": 0.0,
                        }
                    )
                    timing_data.append(
                        {
                            "command": "scan_adapter_policy",
                            "duration": 0.0,
                            "success": False,
                        }
                    )
                elif scan_adapter_policy_configured:
                    # Parse one adapter per ``i2cdetect -l`` line so an opted-in
                    # platform can exclude unsafe adapters or select read-mode
                    # scans without suppressing the inventory artifact itself.
                    adapter_lines: Dict[int, str] = {}
                    for adapter_line in (stdout or "").splitlines():
                        adapter_match = _I2C_ADAPTER_LINE.match(adapter_line)
                        if adapter_match:
                            adapter_lines.setdefault(
                                int(adapter_match.group("bus")), adapter_line
                            )

                    i2c_numbers = []
                    for i2c_number in sorted(adapter_lines):
                        adapter_line = adapter_lines[i2c_number]
                        matched_exclusion = next(
                            (
                                configured_pattern
                                for configured_pattern, compiled_pattern in compiled_scan_exclusions
                                if compiled_pattern.search(adapter_line)
                            ),
                            None,
                        )
                        if matched_exclusion is None:
                            i2c_numbers.append(i2c_number)
                            matched_read_pattern = next(
                                (
                                    configured_pattern
                                    for configured_pattern, compiled_pattern in compiled_scan_read_patterns
                                    if compiled_pattern.search(adapter_line)
                                ),
                                None,
                            )
                            if matched_read_pattern is not None:
                                read_mode_patterns_by_bus[i2c_number] = (
                                    matched_read_pattern
                                )
                                read_mode_adapter_scans.append(
                                    {
                                        "bus": i2c_number,
                                        "name": _i2c_adapter_name(adapter_line),
                                        "reason": (
                                            "Matched configured adapter-line read pattern: "
                                            f"{matched_read_pattern}"
                                        ),
                                        "adapter_line": adapter_line,
                                    }
                                )
                            continue

                        excluded_adapter_scans.append(
                            {
                                "bus": i2c_number,
                                "name": _i2c_adapter_name(adapter_line),
                                "reason": (
                                    "Matched configured adapter-line exclusion pattern: "
                                    f"{matched_exclusion}"
                                ),
                                "adapter_line": adapter_line,
                            }
                        )
                else:
                    # Preserve the historical parser for every platform that
                    # has not explicitly opted into adapter-line filtering.
                    i2c_numbers = sorted(
                        {
                            int(number)
                            for number in re.findall(r"i2c-(\d+)", stdout or "")
                        }
                    )

                scan_command_list = [
                    (
                        f"i2cdetect -r -y {i2c_number}"
                        if i2c_number in read_mode_patterns_by_bus
                        else f"i2cdetect -y {i2c_number}"
                    )
                    for i2c_number in i2c_numbers
                ]
                active_adapter_scan_count = len(scan_command_list)
                scan_results = []
                scan_batch_start = time.monotonic()
                if scan_command_list:
                    try:
                        scan_results = (
                            await self.dut_manager.execute_bmc_commands_batched(
                                dut_id,
                                scan_command_list,
                                include_timing=True,
                            )
                        )
                    except TypeError as exc:
                        if "include_timing" not in str(
                            exc
                        ) or "unexpected keyword" not in str(exc):
                            raise
                        scan_results = (
                            await self.dut_manager.execute_bmc_commands_batched(
                                dut_id,
                                scan_command_list,
                            )
                        )
                scan_batch_duration = time.monotonic() - scan_batch_start

                for index, (i2c_number, scan_cmd) in enumerate(
                    zip(i2c_numbers, scan_command_list)
                ):
                    if index < len(scan_results):
                        raw_result = scan_results[index]
                        exit_code, scan_stdout, scan_stderr = raw_result[:3]
                        scan_duration = (
                            raw_result[3]
                            if len(raw_result) > 3
                            else scan_batch_duration / max(1, len(scan_results))
                        )
                        timing_estimated = len(raw_result) < 4
                    else:
                        exit_code = -1
                        scan_stdout = ""
                        scan_stderr = "Batched SSH execution returned no result"
                        scan_duration = 0.0
                        timing_estimated = True

                    scan_output_file = None

                    scan_output_content = scan_stdout
                    if exit_code != 0 and scan_stderr:
                        scan_output_content = (
                            f"{scan_stdout.rstrip()}\n\n=== STDERR ===\n{scan_stderr}"
                            if scan_stdout
                            else f"=== STDERR ===\n{scan_stderr}"
                        )
                    if exit_code == 0 or scan_output_content:
                        scan_substitutions = {
                            "bus": i2c_number,
                            "collector_id": str(
                                kwargs.get("collector_id") or "collector"
                            ),
                            "function_tag": str(
                                i2c_config.get("function_tag") or "i2c_scan"
                            ),
                        }
                        rendered_scan_output = scan_output_pattern.format(
                            **scan_substitutions
                        )
                        scan_output_file = (
                            await self.write_output_with_generalization(
                                dut_id,
                                kwargs.get("collector_id", ""),
                                scan_output_content,
                                output_pattern=rendered_scan_output,
                                function_tag=os.path.splitext(
                                    os.path.basename(rendered_scan_output)
                                )[0],
                                substitutions=scan_substitutions,
                            )
                            or None
                        )
                        if scan_output_file:
                            output_files.append(scan_output_file)

                    skipped_address_warning = bool(
                        _I2CDETECT_SKIPPED_ADDRESS_WARNING.search(scan_stderr or "")
                    )
                    scan_success = exit_code == 0 and bool(scan_output_file)
                    scan_result = {
                        "command": scan_cmd,
                        "name": f"bus_scan_{i2c_number}",
                        "success": scan_success,
                        "output_file": scan_output_file,
                        "exit_code": exit_code,
                        "stdout": scan_stdout,
                        "stderr": scan_stderr,
                        "execution_time": scan_duration,
                        "timing_estimated": timing_estimated,
                    }
                    if i2c_number in read_mode_patterns_by_bus:
                        scan_result["read_mode"] = True
                    if scan_success and skipped_address_warning:
                        warning_message = (
                            f"Bus {i2c_number} scan completed with an adapter "
                            f"capability warning: {scan_stderr.strip()}"
                        )
                        scan_result["warning"] = warning_message
                        scan_warnings.append(
                            {
                                "command": f"bus_scan_{i2c_number}",
                                "message": warning_message,
                            }
                        )
                    if not scan_success:
                        if exit_code == 0:
                            scan_result["error"] = (
                                f"Failed to persist output for bus_scan_{i2c_number}"
                            )
                        else:
                            scan_result["error"] = scan_stderr
                    results.append(scan_result)
                    timing_data.append(
                        {
                            "command": f"bus_scan_{i2c_number}",
                            "duration": scan_duration,
                            "success": scan_success,
                            "timing_estimated": timing_estimated,
                        }
                    )
                    if self.timing_manager:
                        self.timing_manager.record_duration_operation(
                            "bmc_ssh_command_duration",
                            f"bus_scan_{i2c_number}",
                            scan_duration,
                            status=("success" if scan_success else "error"),
                            artifact_path=scan_output_file,
                            metadata={
                                "command": scan_cmd,
                                "exit_code": exit_code,
                                "raw_exit_code": exit_code,
                                "semantic_success": scan_success,
                                "artifact_measurement": (
                                    "bmc_ssh_command_duration_estimated"
                                    if timing_estimated
                                    else "bmc_ssh_command_duration"
                                ),
                            },
                            measurement_quality=(
                                "estimated"
                                if timing_estimated
                                else "measured_duration_only"
                            ),
                        )

            # Handle command groups (e.g., temperature, power, etc.)
            command_groups = i2c_config.get("command_groups", {})
            for group_name, group_commands in command_groups.items():
                for cmd_config in group_commands:
                    cmd_name = cmd_config["name"]
                    cmd_template = cmd_config["cmd"]

                    # A list is one logical short-circuiting operation (for
                    # example an SMBPBI write followed by its read).  Preserve
                    # that boundary so a failed write cannot be followed by a
                    # stale read that is counted as a separate success.
                    if isinstance(cmd_template, str):
                        commands_to_run = [cmd_template]
                    elif isinstance(cmd_template, list):
                        commands_to_run = cmd_template
                    else:
                        continue

                    processed_commands = []
                    for cmd in commands_to_run:
                        processed_cmd = _render_i2c_command_template_once(
                            cmd, resolved_config
                        )
                        processed_commands.append(processed_cmd)

                    if processed_commands:
                        commands_to_batch.append(" && ".join(processed_commands))
                        command_names.append(cmd_name)
                        command_group_names.append(group_name)

            # Handle direct commands list
            commands = i2c_config.get("commands", [])
            for cmd_config in commands:
                cmd_name = cmd_config["name"]
                cmd_template = cmd_config["cmd"]

                # Preserve a list-valued command as one logical sequence.
                if isinstance(cmd_template, str):
                    commands_to_run = [cmd_template]
                elif isinstance(cmd_template, list):
                    commands_to_run = cmd_template
                else:
                    continue

                processed_commands = []
                for cmd in commands_to_run:
                    await self._log_runtime(
                        "DEBUG",
                        "BMCSSHService",
                        f"Processing command: {cmd}, resolved_config: {resolved_config}",
                        dut_id,
                    )
                    processed_cmd = _render_i2c_command_template_once(
                        cmd, resolved_config
                    )
                    await self._log_runtime(
                        "DEBUG",
                        "BMCSSHService",
                        f"Rendered I2C command template: {processed_cmd}",
                        dut_id,
                    )
                    processed_commands.append(processed_cmd)

                if processed_commands:
                    commands_to_batch.append(" && ".join(processed_commands))
                    command_names.append(cmd_name)
                    command_group_names.append("")  # Direct commands don't have groups

            # Handle config-driven device command expansion
            device_command_config = i2c_config.get("device_commands")
            if device_command_config:
                (
                    expanded_commands,
                    expanded_names,
                    expanded_groups,
                    expansion_errors,
                ) = await self._expand_i2c_device_commands(
                    dut_id, device_command_config, resolved_config
                )

                if expansion_errors:
                    missing_keys_str = "; ".join(expansion_errors)
                    skip_message = (
                        "Required I2C device configuration is not defined correctly for this baseboard: "
                        f"{missing_keys_str}. Please update the baseboard's i2c_config in baseboards.yaml."
                    )
                    await self._log_runtime(
                        "WARNING",
                        "BMCSSHService",
                        skip_message,
                        dut_id,
                    )
                    return await self._create_standardized_collector_result(
                        successful_operations=0,
                        total_operations=0,
                        output_files=[],
                        error_messages=[],
                        operation_name="bmc_i2c_commands",
                        additional_context={
                            "status": "skipped",
                            "reason": skip_message,
                            "device_command_errors": expansion_errors,
                        },
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id"),
                    )

                commands_to_batch.extend(expanded_commands)
                command_names.extend(expanded_names)
                command_group_names.extend(expanded_groups)

            # Reapply selectors to the aligned final batch so explicitly
            # expanded device commands participate without mutating their
            # structured topology definition.
            (
                commands_to_batch,
                command_names,
                command_group_names,
            ) = self._filter_i2c_command_batch_by_name(
                commands_to_batch,
                command_names,
                command_group_names,
                i2c_config,
            )

            try:
                result_validations = _normalize_i2c_result_validations(
                    i2c_config.get("result_validations"), command_names
                )
            except ValueError as exc:
                config_error = f"Invalid I2C result validation: {exc}"
                await self._log_runtime("ERROR", "BMCSSHService", config_error, dut_id)
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[config_error],
                    operation_name="bmc_i2c_commands",
                    additional_context={
                        "status": "error",
                        "reason": config_error,
                        "configuration_error": True,
                    },
                    dut_id=dut_id,
                    collector_id=kwargs.get("collector_id"),
                )
            validity_status_commands = {
                rule.staleness_command
                for rule in result_validations.values()
                if rule.staleness_command is not None
            }

            if (
                execution_policy
                and execution_policy["mode"] == "validated"
                and execution_policy["route"] != "kernel_hwmon"
            ):
                (
                    terminal_result,
                    commands_to_batch,
                    execution_policy_provenance,
                ) = await self._prepare_i2c_raw_policy_commands(
                    dut_id,
                    kwargs.get("collector_id"),
                    kwargs,
                    i2c_config,
                    execution_policy,
                    resolved_config,
                    commands_to_batch,
                    output_files,
                )
                if terminal_result:
                    return terminal_result
                if execution_policy_provenance:
                    policy_artifact = execution_policy_provenance.get("artifact")
                    if policy_artifact and policy_artifact not in diagnostic_files:
                        diagnostic_files.append(policy_artifact)

            # Execute all collected commands in batch (sequentially, not in parallel)
            if commands_to_batch:
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Executing {len(commands_to_batch)} I2C commands sequentially in a single SSH session",
                    dut_id,
                )

                batch_start_time = time.time()
                batch_timing_operation_id = None
                if self.timing_manager:
                    batch_timing_operation_id = self.timing_manager.start_operation(
                        "bmc_ssh_command_batch",
                        kwargs.get("function_tag")
                        or kwargs.get("collector_id", "bmc_i2c_commands"),
                        metadata={"command_count": len(commands_to_batch)},
                    )
                try:
                    batch_timeout = await self._resolve_collector_timeout(
                        dut_id,
                        kwargs,
                        default_timeout=300,
                        explicit_timeout_sources=[i2c_config, kwargs],
                    )
                    try:
                        batch_results = (
                            await self.dut_manager.execute_bmc_commands_batched(
                                dut_id,
                                commands_to_batch,
                                timeout=batch_timeout,
                                include_timing=True,
                            )
                        )
                    except TypeError as exc:
                        # Out-of-tree DUT-manager adapters may predate the
                        # optional timing tuple. Retry only signature-binding
                        # failures; runtime TypeErrors from the adapter must not
                        # execute the commands twice.
                        if "include_timing" not in str(
                            exc
                        ) or "unexpected keyword" not in str(exc):
                            raise
                        batch_results = (
                            await self.dut_manager.execute_bmc_commands_batched(
                                dut_id,
                                commands_to_batch,
                                timeout=batch_timeout,
                            )
                        )
                except BaseException as exc:
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            batch_timing_operation_id,
                            status=(
                                "cancelled"
                                if isinstance(exc, asyncio.CancelledError)
                                else "error"
                            ),
                            error=str(exc),
                        )
                    raise
                if self.timing_manager:
                    self.timing_manager.end_operation(
                        batch_timing_operation_id,
                        # This only means the SSH batch transport returned;
                        # individual command outcomes are classified below.
                        status="transport_completed",
                    )
                batch_end_time = time.time()
                batch_duration = batch_end_time - batch_start_time

                # Process batch results
                fatal_stderr_markers = [
                    "no access privilege",
                    "permission denied",
                    "access denied",
                    "not authorized",
                ]
                fatal_stderr_patterns = [
                    re.compile(
                        rf"(?<![\w-]){re.escape(marker)}(?![\w-])",
                        re.IGNORECASE,
                    )
                    for marker in fatal_stderr_markers
                ]

                semantic_observations: Dict[str, Tuple[bool, Any]] = {}
                for observation_index, observed_name in enumerate(command_names):
                    if observation_index >= len(batch_results):
                        semantic_observations[observed_name] = (False, "")
                        continue
                    observed_result = batch_results[observation_index]
                    observed_exit, observed_stdout, observed_stderr = observed_result[
                        :3
                    ]
                    observed_fatal_stderr = any(
                        pattern.search((observed_stderr or "").strip())
                        for pattern in fatal_stderr_patterns
                    )
                    observed_transport_success = (
                        observed_exit == 0
                        and not observed_fatal_stderr
                        and not is_bmc_command_failure_output(
                            observed_stdout, observed_stderr
                        )
                        and bool((observed_stdout or "").strip())
                    )
                    semantic_observations[observed_name] = (
                        observed_transport_success,
                        observed_stdout,
                    )

                for i, planned_command in enumerate(commands_to_batch):
                    missing_batch_result = i >= len(batch_results)
                    if missing_batch_result:
                        exit_code = -1
                        stdout = ""
                        stderr = "Batched SSH execution returned no result"
                    else:
                        raw_result = batch_results[i]
                        exit_code, stdout, stderr = raw_result[:3]

                    cmd_name = (
                        command_names[i] if i < len(command_names) else f"command_{i}"
                    )
                    cmd_group = (
                        command_group_names[i] if i < len(command_group_names) else ""
                    )
                    # New DUTManager results include a monotonic per-command
                    # duration. Keep the fallback for external adapters which
                    # still return the historical 3-tuple, but label it so the
                    # report never presents an even split as measured timing.
                    timing_estimated = missing_batch_result or len(raw_result) < 4
                    cmd_duration = (
                        0.0
                        if missing_batch_result
                        else (
                            float(raw_result[3])
                            if not timing_estimated
                            else batch_duration / max(1, len(batch_results))
                        )
                    )

                    stderr_str = (stderr or "").strip()
                    stderr_has_fatal = any(
                        pattern.search(stderr_str) for pattern in fatal_stderr_patterns
                    )
                    # Exit code 0 with no usable output (restricted-shell
                    # redirection failure or SSH session-limit refusal) is not a
                    # success, even though i2c reads exit 0.
                    failed_output = is_bmc_command_failure_output(stdout, stderr)
                    transport_success = (
                        (exit_code == 0) and not stderr_has_fatal and not failed_output
                    )
                    has_usable_stdout = bool((stdout or "").strip())
                    empty_stdout = transport_success and not has_usable_stdout
                    all_ff_payload = (
                        transport_success
                        and has_usable_stdout
                        and reject_all_ff_payloads
                        and cmd_name not in validity_status_commands
                        and _is_all_ff_i2c_payload(stdout)
                    )
                    semantic_failure: Optional[str] = None
                    semantic_error: Optional[str] = None
                    if all_ff_payload:
                        semantic_failure = "all_ff_payload"
                        semantic_error = (
                            "All-FF payload returned; telemetry is unsupported, "
                            "stale, or unavailable"
                        )
                    elif transport_success and has_usable_stdout:
                        semantic_failure, semantic_error = (
                            _classify_i2c_result_semantics(
                                cmd_name,
                                stdout,
                                result_validations,
                                semantic_observations,
                            )
                        )
                    cmd_success = (
                        transport_success
                        and has_usable_stdout
                        and semantic_failure is None
                    )
                    if empty_stdout:
                        semantic_failure = "empty_stdout"

                    timing_data.append(
                        {
                            "command": cmd_name,
                            "duration": cmd_duration,
                            "success": cmd_success,
                            "transport_success": transport_success,
                            "semantic_failure": semantic_failure,
                            "timing_estimated": timing_estimated,
                        }
                    )

                    await self._log_runtime(
                        "INFO",
                        "BMCSSHService",
                        f"Batched I2C command result - {cmd_name}: exit_code: {exit_code}, stdout: '{stdout}', stderr: '{stderr}', duration: {cmd_duration:.3f}s",
                        dut_id,
                    )

                    command_output_files: List[str] = []
                    artifact_error: Optional[str] = None
                    # A transported response that fails semantic validation is
                    # retained as a diagnostic artifact. It must not remain in
                    # the primary artifact namespace where consumers could
                    # mistake it for usable telemetry.
                    if transport_success and has_usable_stdout:
                        selected_output_patterns: List[Optional[str]] = []
                        parent_pattern = kwargs.get("output_pattern")
                        if emit_parent:
                            selected_output_patterns.append(parent_pattern)
                        if not (
                            emit_parent
                            and _has_canonical_i2c_parent_pattern(
                                parent_pattern, kwargs.get("collector_id")
                            )
                        ):
                            selected_output_patterns.extend(
                                _matching_i2c_variant_patterns(
                                    collector_variants, cmd_name, cmd_group
                                )
                            )

                        if not selected_output_patterns:
                            cmd_success = False
                            artifact_error = (
                                f"No output pattern selected for {cmd_name}: "
                                "emit_parent is false and no collector variant matched"
                            )
                        else:
                            deduplicated_patterns: List[Optional[str]] = []
                            for selected_pattern in selected_output_patterns:
                                if selected_pattern not in deduplicated_patterns:
                                    deduplicated_patterns.append(selected_pattern)

                            for selected_pattern in deduplicated_patterns:
                                effective_output_pattern = selected_pattern
                                if semantic_failure is not None:
                                    rejected_name = os.path.basename(
                                        str(
                                            selected_pattern or f"{cmd_name}.txt"
                                        ).replace("\\", "/")
                                    )
                                    effective_output_pattern = (
                                        f"diagnostic/{rejected_name}"
                                    )
                                output_path = (
                                    await self.write_output_with_generalization(
                                        dut_id,
                                        kwargs.get("collector_id", ""),
                                        stdout,
                                        output_pattern=effective_output_pattern,
                                        function_tag=cmd_name,
                                        substitutions={
                                            "command_name": cmd_name,
                                            "group": cmd_group,
                                        },
                                    )
                                )
                                if output_path:
                                    command_output_files.append(output_path)
                                    output_files.append(output_path)
                                    if semantic_failure is not None:
                                        diagnostic_files.append(output_path)
                                else:
                                    cmd_success = False
                                    artifact_error = (
                                        f"Failed to persist output for {cmd_name} "
                                        f"using pattern {selected_pattern!r}"
                                    )
                                    break

                    file_path = (
                        command_output_files[0] if command_output_files else None
                    )

                    if cmd_success:
                        results.append(
                            {
                                "command": planned_command,
                                "success": True,
                                "name": cmd_name,
                                "output_file": file_path,
                                "output_files": command_output_files,
                                "stdout": stdout,
                                "stderr": stderr,
                                "exit_code": exit_code,
                                "execution_time": cmd_duration,
                                "transport_success": True,
                                "artifact_role": "primary",
                            }
                        )
                    else:
                        if artifact_error is not None:
                            error_msg = artifact_error
                        elif empty_stdout:
                            error_msg = (
                                "Command returned no non-whitespace stdout for "
                                "its emitted collector artifact"
                            )
                        elif semantic_error is not None:
                            error_msg = semantic_error
                        elif empty_stdout:
                            error_msg = "Command returned no non-whitespace stdout"
                        elif stderr_has_fatal:
                            error_detail = (
                                stderr_str
                                or "stderr indicated access privilege failure"
                            )
                            error_msg = (
                                f"Command failed due to stderr content: {error_detail}"
                            )
                        else:
                            error_msg = (
                                f"Command failed with exit_code {exit_code}: {stderr}"
                            )
                        results.append(
                            {
                                "command": planned_command,
                                "success": False,
                                "error": error_msg,
                                "name": cmd_name,
                                "output_file": file_path,
                                "output_files": command_output_files,
                                "stdout": stdout,
                                "stderr": stderr,
                                "exit_code": exit_code,
                                "execution_time": cmd_duration,
                                "transport_success": transport_success,
                                "semantic_failure": semantic_failure,
                                "artifact_role": (
                                    "diagnostic"
                                    if semantic_failure is not None
                                    else None
                                ),
                            }
                        )

                    timing_data[-1]["success"] = cmd_success
                    if self.timing_manager:
                        self.timing_manager.record_duration_operation(
                            "bmc_ssh_command_duration",
                            cmd_name,
                            cmd_duration,
                            status="success" if cmd_success else "error",
                            artifact_path=file_path,
                            metadata={
                                "command": planned_command,
                                "exit_code": exit_code,
                                "raw_exit_code": exit_code,
                                "semantic_success": cmd_success,
                                "transport_success": transport_success,
                                "semantic_failure": semantic_failure,
                                "artifact_measurement": (
                                    "bmc_ssh_command_duration_estimated"
                                    if timing_estimated
                                    else "bmc_ssh_command_duration"
                                ),
                            },
                            measurement_quality=(
                                "estimated"
                                if timing_estimated
                                else "measured_duration_only"
                            ),
                        )

            # Determine overall success
            successful_commands = [r for r in results if r.get("success", False)]
            failed_commands = [r for r in results if not r.get("success", False)]
            inline_guard_result = await self._i2c_inline_guard_result(
                dut_id,
                kwargs.get("collector_id"),
                execution_policy,
                successful_commands,
                failed_commands,
                output_files,
            )
            if inline_guard_result:
                return inline_guard_result

            # ``continue_on_failure`` controls whether later logical operations
            # are attempted.  It must not turn a partial batch into an overall
            # success or make stale subcommand output look valid.
            continue_on_failure = i2c_config.get("continue_on_failure", False)
            any_success = bool(successful_commands)
            overall_success = bool(results) and not failed_commands

            # A failure that means "address not populated on this bus" (ENXIO /
            # "No such device or address", emitted by i2c_msg_xfer when i2ctransfer
            # prefixes it as "Sending messages failed: ..."). Treat this as
            # device-absent, not as a tool error.
            def _is_device_absent(err_text: str) -> bool:
                """
                Return whether ``err_text`` is device absent.

                The implementation uses ``err_text`` to determine whether
                ``err_text`` is device absent.

                Args:
                    err_text: Text supplied as err text in the format accepted
                        by this function.

                Returns:
                    Whether ``err_text`` is device absent.
                """
                return "no such device or address" in err_text.casefold()

            all_device_absent = bool(failed_commands) and all(
                _is_device_absent(
                    str(cmd.get("error", "")) + " " + str(cmd.get("stderr", ""))
                )
                for cmd in failed_commands
            )
            expected_absence = (
                all_device_absent
                and not successful_commands
                and expected_device_absence
            )
            if expected_absence:
                # The probes still failed at the transport level and remain
                # recorded as such below.  Semantically, though, a uniformly
                # absent optional device is a successful inventory result.
                overall_success = True

            # Describe the observed command outcomes independently of whether
            # continue_on_failure permits the collector to proceed.
            if failed_commands:
                if expected_absence:
                    reason = (
                        f"All {len(failed_commands)} I2C probes returned "
                        "'No such device or address' — configured PDB/HSC device "
                        "addresses are explicitly optional and not populated on "
                        "this baseboard"
                    )
                else:
                    failure_reasons = [
                        f"{cmd.get('name', 'unknown')}: {cmd.get('error', 'No specific command error reason provided')}"
                        for cmd in failed_commands
                    ]
                    if successful_commands:
                        reason = (
                            "Partial success "
                            f"({len(successful_commands)}/{len(results)} commands); "
                            f"failed: {'; '.join(failure_reasons)}"
                        )
                    else:
                        reason = (
                            f"All I2C commands failed: {'; '.join(failure_reasons)}"
                        )
            elif overall_success:
                reason = f"Completed successfully ({len(successful_commands)}/{len(results)} commands)"
            else:
                reason = "No commands executed"

            if scan_exclusion_policy_configured:
                exclusion_count = len(excluded_adapter_scans)
                reason += (
                    f"; intentionally excluded {exclusion_count} adapter "
                    f"scan{'s' if exclusion_count != 1 else ''} by platform policy "
                    f"({active_adapter_scan_count} adapters actively scanned)"
                )
            if scan_read_policy_configured:
                read_mode_count = len(read_mode_adapter_scans)
                reason += (
                    f"; used read mode for {read_mode_count} adapter "
                    f"scan{'s' if read_mode_count != 1 else ''} by platform policy"
                )

            # Generate timing summary
            total_time = time.time() - start_time
            successful_timing = [t for t in timing_data if t["success"]]
            failed_timing = [t for t in timing_data if not t["success"]]

            timing_summary = f"""
=== I2C COMMAND TIMING SUMMARY ===
Total execution time: {total_time:.3f}s
Commands executed: {len(timing_data)}
Successful commands: {len(successful_timing)}
Failed commands: {len(failed_timing)}

Command breakdown:
"""

            for cmd_timing in timing_data:
                cmd_status = "SUCCESS" if cmd_timing["success"] else "ERROR"
                timing_summary += f"  {cmd_status} {cmd_timing['command']}: {cmd_timing['duration']:.3f}s\n"

            if successful_timing:
                avg_success_time = sum(t["duration"] for t in successful_timing) / len(
                    successful_timing
                )
                timing_summary += (
                    f"\nAverage successful command time: {avg_success_time:.3f}s"
                )

            if failed_timing:
                avg_failed_time = sum(t["duration"] for t in failed_timing) / len(
                    failed_timing
                )
                timing_summary += (
                    f"\nAverage failed command time: {avg_failed_time:.3f}s"
                )

            await self._log_runtime("INFO", "BMCSSHService", timing_summary, dut_id)

            summary_log_level = (
                "INFO" if overall_success else ("WARNING" if any_success else "ERROR")
            )
            await self._log_runtime(
                summary_log_level,
                "BMCSSHService",
                f"I2C commands summary: {len(successful_commands)}/{len(results)} successful. {reason}",
                dut_id,
            )

            # Create structured JSON output with all command details
            json_output = {
                "collector_info": {
                    "collector_id": kwargs.get("collector_id", ""),
                    "function_tag": kwargs.get("function_tag", "i2c_commands"),
                    "timestamp": datetime.datetime.now().isoformat(),
                    "dut_id": dut_id,
                },
                "execution_summary": {
                    "total_commands": len(results),
                    "successful_commands": len(successful_commands),
                    "failed_commands": len(failed_commands),
                    "overall_success": overall_success,
                    "any_success": any_success,
                    "status": (
                        "success"
                        if overall_success
                        else ("partial" if any_success else "error")
                    ),
                    "continue_on_failure": continue_on_failure,
                    "total_execution_time": total_time,
                    "reason": reason,
                },
                "commands": [],
            }
            if execution_policy:
                json_output["execution_policy"] = {
                    "mode": execution_policy["mode"],
                    "route": execution_policy["route"],
                    "reason": execution_policy["reason"],
                    "preflight": execution_policy_provenance,
                }
            if expected_absence:
                json_output["execution_summary"].update(
                    {
                        "expected_absence": True,
                        "all_devices_absent": True,
                    }
                )
            if scan_exclusion_policy_configured:
                json_output["execution_summary"].update(
                    {
                        "active_adapter_scans": active_adapter_scan_count,
                        "policy_excluded_adapter_scans": len(excluded_adapter_scans),
                    }
                )
                json_output["excluded_adapter_scans"] = excluded_adapter_scans
                json_output["invalid_scan_exclusion_patterns"] = (
                    invalid_scan_exclusion_patterns
                )
            if scan_read_policy_configured:
                json_output["execution_summary"]["read_mode_adapter_scan_count"] = len(
                    read_mode_adapter_scans
                )
                json_output["read_mode_adapter_scans"] = read_mode_adapter_scans
                json_output["invalid_scan_read_patterns"] = invalid_scan_read_patterns

            # Add detailed command information
            for i, result in enumerate(results):
                published_output_file = self._published_i2c_artifact_reference(
                    dut_id,
                    result.get("output_file"),
                )
                published_output_files = [
                    reference
                    for reference in (
                        self._published_i2c_artifact_reference(dut_id, path)
                        for path in result.get("output_files", [])
                    )
                    if reference is not None
                ]
                cmd_info = {
                    "command_name": result.get("name", f"command_{i}"),
                    "full_command": result.get("command", ""),
                    "success": result.get("success", False),
                    "output_file": published_output_file,
                    "exit_code": result.get("exit_code", -1),
                    "stdout": result.get("stdout", ""),
                    "stderr": result.get("stderr", ""),
                }

                if "execution_time" in result:
                    cmd_info["execution_time"] = result["execution_time"]
                if "timing_estimated" in result:
                    cmd_info["timing_estimated"] = result["timing_estimated"]
                if result.get("read_mode"):
                    cmd_info["read_mode"] = True
                if "transport_success" in result:
                    cmd_info["transport_success"] = result["transport_success"]
                if result.get("semantic_failure"):
                    cmd_info["semantic_failure"] = result["semantic_failure"]
                if result.get("artifact_role"):
                    cmd_info["artifact_role"] = result["artifact_role"]
                if result.get("warning"):
                    cmd_info["warning"] = result["warning"]
                if published_output_files:
                    cmd_info["output_files"] = published_output_files

                # Add error information if command failed
                if not result.get("success", False):
                    cmd_info["error"] = result.get("error", "Unknown error")

                json_output["commands"].append(cmd_info)

            # Save structured JSON output with proper handling of special characters
            try:
                json_content = json.dumps(json_output, indent=2, ensure_ascii=False)
            except (TypeError, ValueError) as e:
                # Fallback: convert any non-serializable content to strings
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    f"JSON serialization issue, using fallback: {str(e)}",
                    dut_id,
                )

                # Recursively convert any non-serializable objects to strings
                def make_serializable(obj):
                    """
                    Make an object serializable.

                    The implementation uses ``obj`` to make an object
                    serializable.

                    Args:
                        obj: Object whose ``items`` state is read while
                            performing make an object serializable.

                    Returns:
                        A JSON-compatible projection of the supplied object.
                    """
                    if isinstance(obj, dict):
                        return {k: make_serializable(v) for k, v in obj.items()}
                    elif isinstance(obj, list):
                        return [make_serializable(item) for item in obj]
                    elif isinstance(obj, (str, int, float, bool, type(None))):
                        return obj
                    else:
                        return str(obj)

                safe_json_output = make_serializable(json_output)
                json_content = json.dumps(
                    safe_json_output, indent=2, ensure_ascii=False
                )
            try:
                json_file_path = (
                    await self.write_output_with_generalization(
                        dut_id,
                        kwargs.get("collector_id", ""),
                        json_content,
                        output_pattern="SSH_{function_tag}_structured.json",
                        function_tag=kwargs.get("function_tag", "i2c_commands"),
                        substitutions={
                            "function_tag": kwargs.get("function_tag", "i2c_commands")
                        },
                    )
                    or None
                )
            except Exception:
                json_file_path = None
                await self._log_runtime(
                    "ERROR",
                    "BMCSSHService",
                    "Failed to persist structured I2C command output",
                    dut_id,
                )

            # Add JSON file to output files list
            structured_json_error = None
            if json_file_path:
                output_files.append(json_file_path)
            else:
                structured_json_error = (
                    "Failed to persist structured I2C command output"
                )

            # Create detailed error messages for individual command failures
            detailed_error_messages = []
            if failed_commands and not expected_absence:
                for cmd in failed_commands:
                    cmd_name = cmd.get("name", "unknown_command")
                    cmd_error = cmd.get("error", "No specific error provided")
                    detailed_error_messages.append(f"{cmd_name}: {cmd_error}")

            if structured_json_error:
                detailed_error_messages.append(structured_json_error)

            effective_successful_operations = len(successful_commands)
            effective_total_operations = len(results) + bool(structured_json_error)
            effective_status = (
                "success"
                if not failed_commands and not structured_json_error
                else ("partial" if effective_successful_operations else "error")
            )
            effective_reason = reason
            if structured_json_error:
                effective_reason = (
                    f"{reason}; Failed to persist structured I2C command summary"
                )

            additional_context = {
                "status": effective_status,
                "reason": effective_reason,
                "total_commands": len(results),
                "successful_commands": len(successful_commands),
                "command_groups_processed": list(command_groups.keys()),
                "timing_data": timing_data,
                "total_time": total_time,
                "results": results,
                "structured_json_file": json_file_path,
            }
            if diagnostic_files:
                additional_context["diagnostic_files"] = diagnostic_files
            if scan_warnings:
                additional_context["scan_warnings"] = scan_warnings
            if structured_json_error:
                additional_context["structured_json_error"] = structured_json_error
                additional_context["structured_json_persisted"] = False
            if execution_policy:
                additional_context["execution_policy"] = {
                    "mode": execution_policy["mode"],
                    "route": execution_policy["route"],
                    "reason": execution_policy["reason"],
                    "preflight": execution_policy_provenance,
                }
            all_ff_commands = [
                cmd.get("name", "unknown_command")
                for cmd in failed_commands
                if cmd.get("semantic_failure") == "all_ff_payload"
            ]
            if all_ff_commands:
                additional_context.update(
                    {
                        "semantic_failure": "all_ff_payload",
                        "all_ff_payload_count": len(all_ff_commands),
                        "all_ff_payload_commands": all_ff_commands,
                    }
                )
            semantic_failure_commands: Dict[str, List[str]] = {}
            for command_result in failed_commands:
                failure_code = command_result.get("semantic_failure")
                if not isinstance(failure_code, str) or not failure_code:
                    continue
                semantic_failure_commands.setdefault(failure_code, []).append(
                    command_result.get("name", "unknown_command")
                )
            if semantic_failure_commands:
                additional_context["semantic_failure_commands"] = (
                    semantic_failure_commands
                )
                additional_context["semantic_failure_counts"] = {
                    failure_code: len(failed_names)
                    for failure_code, failed_names in semantic_failure_commands.items()
                }
            if scan_exclusion_policy_configured:
                additional_context.update(
                    {
                        "active_adapter_scans": active_adapter_scan_count,
                        "policy_excluded_adapter_scans": len(excluded_adapter_scans),
                        "excluded_adapter_scans": excluded_adapter_scans,
                        "invalid_scan_exclusion_patterns": (
                            invalid_scan_exclusion_patterns
                        ),
                    }
                )

            if scan_read_policy_configured:
                additional_context.update(
                    {
                        "read_mode_adapter_scan_count": len(read_mode_adapter_scans),
                        "read_mode_adapter_scans": read_mode_adapter_scans,
                        "invalid_scan_read_patterns": invalid_scan_read_patterns,
                    }
                )

            if scan_adapter_policy_configured:
                additional_context["status"] = effective_status
                additional_context["reason"] = effective_reason

            # Preserve the raw 0/N probe accounting and per-command failures,
            # but report the exact all-addresses-absent outcome as a semantic
            # success.  Expected absence is data, not a skipped collector or an
            # execution error.
            if expected_absence:
                # Treat the bounded optional-topology probe as one semantic
                # inventory operation. Raw transport outcomes remain in the
                # context below, while authoritative accounting reflects that
                # the expected-absence assertion itself succeeded.
                effective_successful_operations = 1
                effective_total_operations = 1 + bool(structured_json_error)
                additional_context["status"] = (
                    "error" if structured_json_error else "success"
                )
                additional_context["reason"] = effective_reason
                additional_context["all_devices_absent"] = True
                additional_context["expected_absence"] = True
                additional_context["raw_successful_commands"] = len(successful_commands)
                additional_context["raw_failed_commands"] = len(failed_commands)

            if not json_file_path:
                structured_output_error = (
                    "Failed to persist structured I2C command summary"
                )
                structured_json_error = (
                    "Failed to persist structured I2C command output"
                )
                detailed_error_messages.append(structured_output_error)
                additional_context["structured_json_persisted"] = False
                additional_context["structured_json_error"] = structured_json_error
                additional_context["status"] = (
                    "partial" if successful_commands and output_files else "error"
                )
                additional_context["reason"] = f"{reason}; {structured_output_error}"

            return await self._create_standardized_collector_result(
                successful_operations=effective_successful_operations,
                total_operations=effective_total_operations,
                output_files=output_files,
                error_messages=detailed_error_messages,
                operation_name="bmc_i2c_commands",
                additional_context=additional_context,
            )
        except _I2CCommandTemplateError as e:
            reason = f"Invalid I2C command template: {e}"
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                reason,
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[reason],
                operation_name="bmc_i2c_commands",
                additional_context={
                    "status": "error",
                    "reason": reason,
                    "configuration_error": True,
                    "results": [],
                },
                dut_id=dut_id,
                collector_id=kwargs.get("collector_id"),
            )
        except Exception as e:
            error_traceback = traceback.format_exc()

            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"run_bmc_i2c_commands exception: {str(e)}",
                dut_id,
            )
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"Traceback: {error_traceback}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=0,
                output_files=[],
                error_messages=[f"Exception in run_bmc_i2c_commands: {str(e)}"],
                operation_name="bmc_i2c_commands",
                additional_context={"results": []},
                dut_id=dut_id,
                collector_id="bmc_i2c_commands",
            )

    async def _create_private_bmc_staging_directory(
        self,
        dut_id: str,
        parent: str,
    ) -> str:
        """
        Create and validate one unpredictable mode-0700 BMC directory.

        The implementation uses ``dut_id`` and ``parent`` to create and validate
        one unpredictable mode-0700 BMC directory. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. If the function cannot create and validate one unpredictable
        mode-0700 BMC directory, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            parent: Text supplied as parent in the format accepted by this
                function.

        Returns:
            The validated ``remote_directory``.

        Raises:
            _BMCFileTransferPolicyError: If input or state violates constraints
                required to create and validate one unpredictable mode-0700 BMC
                directory; or private BMC staging path is already owned.
        """

        template = posixpath.join(parent, f"{_BMC_REMOTE_STAGING_PREFIX}XXXXXXXXXX")
        quoted_template = quote_arg(template)
        command = (
            "umask 077; "
            f"_nv_dir=$(mktemp -d -- {quoted_template}) || exit 70; "
            'if ! chmod 700 -- "$_nv_dir" '
            '|| [ ! -d "$_nv_dir" ] || [ -L "$_nv_dir" ] '
            '|| [ "$(stat -c \'%a\' -- "$_nv_dir")" != 700 ]; then '
            'rm -rf -- "$_nv_dir"; exit 71; fi; '
            "printf '%s\\n' \"$_nv_dir\""
        )
        exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
            dut_id, command
        )
        if exit_code != 0:
            raise _BMCFileTransferPolicyError(
                f"private BMC staging creation failed: {str(stderr).strip()}"
            )
        remote_directory = _validate_bmc_private_staging_path(parent, stdout)
        ownership = (dut_id, remote_directory)
        if ownership in self._owned_bmc_staging_directories:
            raise _BMCFileTransferPolicyError(
                "private BMC staging path is already owned"
            )
        self._owned_bmc_staging_directories.add(ownership)
        self._bmc_staging_owners[ownership] = asyncio.current_task()
        return remote_directory

    def _require_owned_bmc_staging_directory(
        self,
        dut_id: str,
        remote_directory: Any,
    ) -> str:
        """
        Return an exact service-created remote directory or fail closed.

        The implementation uses ``dut_id`` and ``remote_directory`` to produce
        an exact service-created remote directory or fail closed. If the
        function cannot produce an exact service-created remote directory or
        fail closed, its exception reaches the caller instead of being converted
        into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            remote_directory: filesystem location used as the remote directory
                for this operation.

        Returns:
            The validated ``validated``.

        Raises:
            _BMCFileTransferPolicyError: If remote BMC staging directory is not
                owned by this service.
        """

        validated = _validate_owned_bmc_upload_directory(remote_directory)
        if (dut_id, validated) not in self._owned_bmc_staging_directories:
            raise _BMCFileTransferPolicyError(
                "remote BMC staging directory is not owned by this service"
            )
        return validated

    async def _snapshot_remote_bmc_archive_size(
        self,
        dut_id: str,
        remote_archive: str,
    ) -> int:
        """
        Screen a remote archive as no-follow regular and return its size.

        The bounded SFTP boundary performs the authoritative lstat/opened-handle
        identity proof. This shell-side snapshot has no mutating operation and
        exists only to establish the caller's tighter per-stream byte ceiling.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            remote_archive: Text supplied as remote archive in the format
                accepted by this function.

        Returns:
            The numeric snapshot remote BMC archive size.

        Raises:
            _BMCFileTransferPolicyError: If input or state violates constraints
                required to screen a remote archive as no-follow regular and
                return its size.
        """

        command = build_remote_cmd(
            "if [ -f {path} ] && [ ! -L {path} ]; then "
            "stat -c '%s' -- {path}; "
            "else exit 72; fi",
            path=remote_archive,
        )
        exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
            dut_id, command
        )
        if exit_code != 0:
            raise _BMCFileTransferPolicyError(
                "remote archive is not an exact regular file "
                f"(archive check exit {exit_code}): {str(stderr).strip()}"
            )
        return _parse_bmc_archive_size(stdout)

    async def _download_bmc_file_bounded(
        self,
        dut_id: str,
        remote_file: str,
        local_file: Path,
        *,
        max_bytes: int,
    ) -> BoundedBMCDownloadResult:
        """
        Invoke the required bounded binary BMC download boundary.

        The implementation uses ``dut_id``, ``remote_file``, ``local_file``, and
        ``max_bytes`` to invoke the required bounded binary BMC download
        boundary. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle. If the function cannot invoke the required bounded binary BMC
        download boundary, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            remote_file: filesystem location used as the remote file for this
                operation.
            local_file: filesystem location used as the local file for this
                operation.
            max_bytes: Upper bound enforced for max bytes; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            The validated byte count and actual bounded binary transport.

        Raises:
            _BMCFileTransferPolicyError: If bounded binary BMC download API is
                unavailable; bounded binary BMC download returned an invalid
                receipt, byte count, or transport; bounded BMC download did not
                produce a regular file; or bounded BMC download byte count
                changed.
        """

        downloader = getattr(self.dut_manager, "download_bmc_file_bounded", None)
        if not callable(downloader):
            raise _BMCFileTransferPolicyError(
                "bounded binary BMC download API is unavailable"
            )
        download_result = await downloader(
            dut_id,
            remote_file,
            str(local_file),
            max_bytes=max_bytes,
            read_chunk_bytes=_BMC_ARCHIVE_DOWNLOAD_CHUNK_BYTES,
        )
        if not isinstance(download_result, BoundedBMCDownloadResult):
            raise _BMCFileTransferPolicyError(
                "bounded binary BMC download returned an invalid receipt"
            )
        transferred = download_result.bytes_transferred
        if type(transferred) is not int or transferred <= 0 or transferred > max_bytes:
            raise _BMCFileTransferPolicyError(
                "bounded binary BMC download returned an invalid byte count"
            )
        if download_result.transport_method not in {"SFTP", "SSH exec stream"}:
            raise _BMCFileTransferPolicyError(
                "bounded binary BMC download returned an invalid transport"
            )
        local_details = local_file.lstat()
        if not stat.S_ISREG(local_details.st_mode):
            raise _BMCFileTransferPolicyError(
                "bounded BMC download did not produce a regular file"
            )
        if local_details.st_size != transferred:
            raise _BMCFileTransferPolicyError("bounded BMC download byte count changed")
        return download_result

    async def _allocate_local_bmc_artifact_staging(
        self,
        dut_id: str,
        collector_id: str,
        *,
        output_pattern: Optional[str],
        function_tag: str,
        substitutions: Dict[str, str],
        default_extension: str,
    ) -> Tuple[Any, Path, Path, str, str]:
        """
        Allocate a private local staging directory beside the final output.

        The implementation uses ``dut_id``, ``collector_id``,
        ``output_pattern``, ``function_tag``, and ``substitutions`` to allocate
        a private local staging directory beside the final output. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. If the function
        cannot allocate a private local staging directory beside the final
        output, its exception reaches the caller instead of being converted into
        a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            substitutions: Mapping supplying fields for allocate a private local
                staging directory beside the final output.
            default_extension: Text supplied as default extension in the format
                accepted by this function.

        Returns:
            A tuple containing ``private directory``, ``filesystem path``,
            ``final path``, ``filename``, and ``resolved collector identifier``
            in that order.

        Raises:
            _BMCFileTransferPolicyError: If logger is unavailable; atomic
                collector file publication API is unavailable; or local BMC
                staging directory is not a private directory.
        """

        if self.logger is None:
            raise _BMCFileTransferPolicyError("logger is unavailable")
        create_path = getattr(self.logger, "create_collector_log_file", None)
        publish_file = getattr(self.logger, "write_collector_output_file", None)
        if not callable(create_path) or not callable(publish_file):
            raise _BMCFileTransferPolicyError(
                "atomic collector file publication API is unavailable"
            )

        resolved_collector_id = collector_id or self.service_name
        group = self._get_collector_group(resolved_collector_id)
        filename = self.get_output_filename(
            output_pattern,
            function_tag,
            default_extension,
            substitutions,
        )
        final_path = Path(
            await create_path(dut_id, group, resolved_collector_id, filename)
        )
        private_directory = tempfile.TemporaryDirectory(
            prefix=f".{final_path.name}.bmc-",
            dir=final_path.parent,
        )
        private_path = Path(private_directory.name)
        private_stat = private_path.lstat()
        if (
            not stat.S_ISDIR(private_stat.st_mode)
            or stat.S_IMODE(private_stat.st_mode) != 0o700
        ):
            private_directory.cleanup()
            raise _BMCFileTransferPolicyError(
                "local BMC staging directory is not a private directory"
            )
        return (
            private_directory,
            private_path / "artifact.bin",
            final_path,
            filename,
            resolved_collector_id,
        )

    async def _publish_local_bmc_artifact(
        self,
        dut_id: str,
        collector_id: str,
        filename: str,
        local_artifact: Path,
        expected_path: Path,
    ) -> str:
        """
        Atomically adopt one validated same-filesystem staging artifact.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``filename``, ``local_artifact``, and
        ``expected_path`` to ``str`` and preserves its return and exception
        contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            filename: Text supplied as filename in the format accepted by this
                function.
            local_artifact: filesystem location used as the local artifact for
                this operation.
            expected_path: filesystem location used as the expected path for
                this operation.

        Returns:
            The canonical publish local BMC artifact text.

        Raises:
            _BMCFileTransferPolicyError: If validated local BMC artifact is not
                a regular file; or atomic BMC artifact publication changed its
                destination.
        """

        local_details = local_artifact.lstat()
        if not stat.S_ISREG(local_details.st_mode):
            raise _BMCFileTransferPolicyError(
                "validated local BMC artifact is not a regular file"
            )
        group = self._get_collector_group(collector_id)
        published = Path(
            await self.logger.write_collector_output_file(
                dut_id,
                group,
                collector_id,
                filename,
                local_artifact,
            )
        )
        if published != expected_path:
            raise _BMCFileTransferPolicyError(
                "atomic BMC artifact publication changed its destination"
            )
        return str(published)

    async def _download_and_publish_bmc_artifact_bounded(
        self,
        dut_id: str,
        collector_id: str,
        remote_file: str,
        *,
        function_tag: str,
        max_bytes: int,
        output_pattern: Optional[str] = None,
        substitutions: Optional[Dict[str, str]] = None,
        default_extension: str = ".bin",
    ) -> Tuple[str, BoundedBMCDownloadResult]:
        """
        Stream one discovered BMC file into an atomic collector artifact.

        The implementation uses ``dut_id``, ``collector_id``, ``remote_file``,
        ``function_tag``, and ``max_bytes`` to stream one discovered BMC file
        into an atomic collector artifact. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        Cleanup in the ``finally`` path runs for successful, failed, and
        cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            remote_file: filesystem location used as the remote file for this
                operation.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            max_bytes: Upper bound enforced for max bytes; the consuming
                boundary rejects or truncates values that exceed it.
            output_pattern: Optional output pattern; ``None`` selects the
                function's default behavior.
            substitutions: Optional substitutions; ``None`` selects the
                function's default behavior.
            default_extension: Text supplied as default extension in the format
                accepted by this function.

        Returns:
            A tuple containing the published path and bounded binary transfer
            receipt in that order.
        """

        normalized_remote_file = _normalize_bmc_remote_file_path(
            remote_file,
            field_name="discovered BMC file path",
        )
        private_directory = None
        try:
            (
                private_directory,
                local_artifact,
                expected_output_path,
                final_filename,
                resolved_collector_id,
            ) = await self._allocate_local_bmc_artifact_staging(
                dut_id,
                collector_id,
                output_pattern=(
                    output_pattern or posixpath.basename(normalized_remote_file)
                ),
                function_tag=function_tag,
                substitutions=substitutions or {},
                default_extension=default_extension,
            )
            download_result = await self._download_bmc_file_bounded(
                dut_id,
                normalized_remote_file,
                local_artifact,
                max_bytes=max_bytes,
            )
            published_path = await self._publish_local_bmc_artifact(
                dut_id,
                resolved_collector_id,
                final_filename,
                local_artifact,
                expected_output_path,
            )
            return published_path, download_result
        finally:
            if private_directory is not None:
                private_directory.cleanup()

    async def _cleanup_private_bmc_staging_directory(
        self,
        dut_id: str,
        remote_directory: str,
    ) -> None:
        """
        Remove one validated owned directory and retain its cleanup transcript.

        The remote execution deadline excludes subsequent diagnostic publication.
        Ownership is released only after both operations succeed; failed execution
        or publication remains visible and retryable. Only the exact directory
        already registered by this service is admitted to the cleanup command.

        Args:
            dut_id: DUT owning the private directory and command attribution.
            remote_directory: Exact registered staging path to remove remotely.

        Raises:
            _BMCFileTransferPolicyError: If ownership validation fails or remote
                cleanup returns a nonzero exit status.
            TimeoutError: If the bounded remote execution deadline expires.
            Exception: If the command or its durable transcript cannot complete.
        """

        validated_directory = self._require_owned_bmc_staging_directory(
            dut_id, remote_directory
        )
        ownership = (dut_id, validated_directory)
        cleanup_command = build_remote_cmd("rm -rf -- {path}", path=validated_directory)
        exit_code, _stdout, stderr = await self.dut_manager.execute_bmc_command(
            dut_id,
            cleanup_command,
            timeout=_BMC_REMOTE_CLEANUP_TIMEOUT_SECONDS,
            execution_timeout_seconds=_BMC_REMOTE_CLEANUP_TIMEOUT_SECONDS,
        )
        if exit_code != 0:
            raise _BMCFileTransferPolicyError(
                f"private BMC staging cleanup failed: {str(stderr).strip()}"
            )
        self._owned_bmc_staging_directories.discard(ownership)
        self._bmc_staging_owners.pop(ownership, None)

    async def _finish_private_bmc_staging_directory(
        self,
        dut_id: str,
        remote_directory: Optional[str],
    ) -> None:
        """
        Own remote cleanup and durable diagnostics while deferring cancellation.

        The command facade bounds remote execution before diagnostic publication.
        Its completed transcript remains owned even if artifact workers are busy.
        Caller cancellation is deferred until the cleanup task settles; failures
        retain retry ownership and are never converted into successful cleanup.
        An absent directory requires no action.

        Args:
            dut_id: DUT owning the private directory and command attribution.
            remote_directory: Registered staging path, or None when none was made.

        Raises:
            asyncio.CancelledError: After owned cleanup settles if the caller was
                cancelled, including repeated cancellation while waiting.
            _BMCFileTransferPolicyError: If execution or publication cannot finish.
        """

        if not remote_directory:
            return

        async def bounded_cleanup() -> None:
            """
            Bound remote cleanup execution and await its durable transcript.

            The DUT manager enforces the transport deadline inside its command
            capture boundary. Diagnostic publication remains owned and awaited
            after execution, including when shared artifact workers are busy.
            The outer service defers caller cancellation until this task settles.

            Raises:
                Exception: If remote cleanup or diagnostic publication fails.
            """
            await self._cleanup_private_bmc_staging_directory(dut_id, remote_directory)

        cleanup_task = asyncio.create_task(bounded_cleanup())
        deferred_cancel = False
        cleanup_error: Optional[BaseException] = None
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError:
                deferred_cancel = True
            except BaseException as error:
                cleanup_error = error
                break
        if cleanup_error is None and cleanup_task.done():
            try:
                cleanup_task.result()
            except BaseException as error:
                cleanup_error = error
        if cleanup_error is not None:
            try:
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    f"Failed to clean private BMC staging: {cleanup_error}",
                    dut_id,
                )
            except Exception:
                pass
        if deferred_cancel:
            raise asyncio.CancelledError()
        if cleanup_error is not None:
            raise _BMCFileTransferPolicyError(
                f"private BMC staging cleanup did not complete: {cleanup_error}"
            ) from cleanup_error

    def _resolve_baseboard_boolean_parameter(
        self,
        dut_id: str,
        authored_values: Optional[Dict[str, bool]],
        *,
        parameter_name: str,
        default: bool = False,
    ) -> bool:
        """
        Resolve a strict boolean from a baseboard-keyed authored mapping.

        Exact baseboard names take precedence over catalog baseboard types and
        the optional ``default`` key. The whole mapping is validated before a
        value is selected so an unused malformed entry cannot silently weaken
        policy on another platform.

        Args:
            dut_id: Stable DUT identifier used to resolve baseboard metadata.
            authored_values: Optional mapping from baseboard names, baseboard
                types, or ``default`` to exact booleans.
            parameter_name: Catalog parameter name used in validation errors.
            default: Boolean returned when no authored selector applies.

        Returns:
            The selected authored boolean, or ``default`` when the parameter is
            absent or has no applicable selector.

        Raises:
            _BMCFileTransferPolicyError: If any key or value in the authored
                mapping has the wrong type or baseboard metadata cannot be
                resolved safely.
        """
        if type(default) is not bool:
            raise _BMCFileTransferPolicyError(
                f"{parameter_name} default must be a boolean"
            )
        if authored_values is None:
            return default
        if not isinstance(authored_values, dict):
            raise _BMCFileTransferPolicyError(
                f"{parameter_name} must be a baseboard-to-boolean mapping"
            )
        for selector, value in authored_values.items():
            if not isinstance(selector, str) or not selector.strip():
                raise _BMCFileTransferPolicyError(
                    f"{parameter_name} keys must be nonempty strings"
                )
            if type(value) is not bool:
                raise _BMCFileTransferPolicyError(
                    f"{parameter_name} values must be booleans"
                )
        try:
            dut = self.dut_manager.get_dut(dut_id)
            baseboard = dut.config.get("baseboard", "") if dut else ""
            baseboard_type = ""
            if baseboard:
                baseboard_manager = self.dut_manager._get_baseboard_manager()
                if baseboard_manager:
                    baseboard_type = (
                        baseboard_manager.get_baseboard_type(baseboard) or ""
                    )
        except Exception as exc:
            raise _BMCFileTransferPolicyError(
                f"failed to resolve {parameter_name} baseboard selector"
            ) from exc

        for selector in (baseboard, baseboard_type, "default"):
            if selector and selector in authored_values:
                return authored_values[selector]
        return default

    async def run_bmc_file_transfer(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Bound archive creation, download, and retries by the collector budget.

        The owned transfer task receives the same deadline for long TAR
        commands. Cancellation still drains private staging cleanup before
        returning, so a timeout cannot abandon remote or local temporary files.

        Args:
            dut_id: DUT whose archive and SSH route are owned by this operation.
            kwargs: Authored transfer settings and collector budget context.

        Returns:
            The validated transfer result, or an explicit error on timeout.

        Raises:
            asyncio.CancelledError: After cleanup when the caller cancels.
            ValueError: If the collector timeout configuration is invalid.
        """
        timeout = await self._resolve_collector_timeout(
            dut_id, kwargs, default_timeout=180
        )
        deadline = asyncio.get_running_loop().time() + timeout
        try:
            async with asyncio.timeout_at(deadline):
                return await self._run_bmc_file_transfer_with_deadline(
                    dut_id, deadline=deadline, **kwargs
                )
        except TimeoutError:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[
                    f"BMC file transfer timed out after {timeout:g} seconds"
                ],
                operation_name="bmc_file_transfer",
                additional_context={"status": "error", "timed_out": True},
                dut_id=dut_id,
                collector_id=kwargs.get("collector_id"),
            )

    async def _run_bmc_file_transfer_with_deadline(
        self,
        dut_id: str,
        *,
        deadline: float,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Create, validate, and atomically publish one bounded BMC archive.

        Extract parameters directly from kwargs (hook execution passes them
        directly).

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            deadline: Monotonic collection deadline; bounded staging cleanup
                may complete after this deadline to retain resource ownership.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run BMC file transfer.

        Raises:
            _BMCFileTransferPolicyError: If bounded binary SFTP is required for
                BMC archive transfer; retry_count is outside policy; retry_delay
                is outside policy; or remote BMC archive exceeds the configured
                ``max_input_bytes``-byte limit; or another input invariant is
                violated.
        """
        file_acquisition_operation_id = None
        remote_staging_directory: Optional[str] = None
        try:
            # Extract parameters directly from kwargs (hook execution passes them directly)
            configured_source_path = kwargs.get("source_path", "/var/log/")
            source_path = _normalize_bmc_remote_path(
                configured_source_path,
                field_name="source_path",
            )
            archive_name = kwargs.get("archive_name", "file_transfer")
            # Use archive_name for output file naming — it is per-hook and not overridden by
            # the shared context (which sets function_tag to the collector name).
            function_tag = archive_name or kwargs.get("function_tag", "file_transfer")
            use_sftp = kwargs.get("use_sftp", True)
            archive_missing_member_policy = kwargs.get(
                "archive_missing_member_policy", "error"
            )
            retry_count = kwargs.get("retry_count", 3)
            retry_delay = kwargs.get("retry_delay", 5)
            archive_use_sudo = self._resolve_baseboard_boolean_parameter(
                dut_id,
                kwargs.get("baseboard_archive_use_sudo"),
                parameter_name="baseboard_archive_use_sudo",
            )
            archive_empty_is_not_applicable = self._resolve_baseboard_boolean_parameter(
                dut_id,
                kwargs.get("baseboard_archive_empty_is_not_applicable"),
                parameter_name="baseboard_archive_empty_is_not_applicable",
            )
            if use_sftp is not True:
                raise _BMCFileTransferPolicyError(
                    "bounded binary SFTP is required for BMC archive transfer"
                )
            if (
                not isinstance(archive_missing_member_policy, str)
                or archive_missing_member_policy
                not in _BMC_ARCHIVE_MISSING_MEMBER_POLICIES
            ):
                raise _BMCFileTransferPolicyError(
                    "archive_missing_member_policy must be one of: error, partial"
                )
            if (
                type(retry_count) is not int
                or retry_count < 0
                or retry_count > _BMC_MAX_TRANSFER_RETRIES
            ):
                raise _BMCFileTransferPolicyError("retry_count is outside policy")
            if (
                not isinstance(retry_delay, (int, float))
                or isinstance(retry_delay, bool)
                or retry_delay < 0
                or retry_delay > _BMC_MAX_RETRY_DELAY_SECONDS
            ):
                raise _BMCFileTransferPolicyError("retry_delay is outside policy")

            # Get DUT config for variable substitution (now includes proper tool config overrides)
            dut_config = self.dut_manager.get_dut_config(dut_id)

            # Get BMC temp dir from merged DUT config (includes tool config overrides)
            bmc_temp_dir = _normalize_bmc_remote_path(
                dut_config.get("BMC_TEMP_DIR", "/tmp"),
                field_name="BMC_TEMP_DIR",
            )
            archive_limits = resolve_collection_archive_limits()
            await self._log_runtime(
                "DEBUG",
                "BMCSSHService",
                f"Using BMC_TEMP_DIR from merged config: {bmc_temp_dir}",
                dut_id,
            )
            archive_timestamp = datetime.datetime.now().strftime("%d_%m_%Y_%H_%M_%S")

            # Create timestamp substitution for output pattern
            timestamp_substitutions = {"timestamp": archive_timestamp}
            output_pattern = kwargs.get("output_pattern")
            if self.logger and getattr(self.logger, "_get_tool_config_value", None):
                if self.logger._get_tool_config_value("streaming_only", False):
                    try:
                        begin_dt, end_dt = normalize_stream_window(
                            self.logger._get_tool_config_value("stream_begin"),
                            self.logger._get_tool_config_value("stream_end"),
                        )
                        begin_component = format_stream_window_component(begin_dt)
                        end_component = format_stream_window_component(end_dt)
                        if output_pattern:
                            output_pattern = output_pattern.replace(
                                "_{timestamp}",
                                f"_{begin_component}_{end_component}",
                            ).replace(
                                "{timestamp}",
                                f"{begin_component}_{end_component}",
                            )
                    except ValueError as e:
                        await self._log_runtime(
                            "ERROR",
                            "BMCSSHService",
                            f"Invalid streaming window for BMC file transfer: {str(e)}",
                            dut_id,
                        )
                        raise
                    except Exception as e:
                        logger.exception(
                            "Unexpected error while normalizing streaming window for BMC file transfer on DUT %s",
                            dut_id,
                        )
                        await self._log_runtime(
                            "ERROR",
                            "BMCSSHService",
                            f"Unexpected error while applying streaming window for BMC file transfer: {str(e)}",
                            dut_id,
                        )
                        raise

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Starting file transfer for {source_path} with retry_count={retry_count}",
                dut_id,
            )
            if archive_use_sudo:
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    "Using authored passwordless sudo for TAR source reads; "
                    "the staged archive remains owned by the BMC SSH user",
                    dut_id,
                )

            output_files = []
            last_transfer_error: Optional[str] = None

            source_exists_cmd = build_remote_cmd("test -e {path}", path=source_path)
            exit_code, _, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, source_exists_cmd
            )
            # Keep the configured spelling for operator-facing missing-path
            # evidence while using only the canonical path in remote commands.
            primary_source_path = configured_source_path
            used_fallback = False
            fallback_source_path = kwargs.get("fallback_source_path")
            if exit_code != 0 and fallback_source_path:
                fallback_source_path = _normalize_bmc_remote_path(
                    fallback_source_path,
                    field_name="fallback_source_path",
                )
                fallback_exists_cmd = build_remote_cmd(
                    "test -e {path}", path=fallback_source_path
                )
                fb_exit_code, _, _ = await self.dut_manager.execute_bmc_command(
                    dut_id, fallback_exists_cmd
                )
                if fb_exit_code == 0:
                    await self._log_runtime(
                        "INFO",
                        "BMCSSHService",
                        f"Primary source path {source_path} not present on BMC; "
                        f"falling back to {fallback_source_path}",
                        dut_id,
                    )
                    source_path = fallback_source_path
                    used_fallback = True
                    exit_code = 0
            if exit_code != 0:
                if fallback_source_path:
                    skip_reason = (
                        f"Neither primary path {primary_source_path} nor fallback "
                        f"{fallback_source_path} present on BMC; skipping file transfer"
                    )
                else:
                    skip_reason = f"Source path {primary_source_path} is not present on BMC; skipping file transfer"
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    skip_reason,
                    dut_id,
                )

                if kwargs.get("complete_on_empty_targets", False):
                    empty_reason = kwargs.get("empty_reason") or (
                        "No configured BMC file-transfer source is present"
                    )
                    checked_paths = [primary_source_path]
                    if fallback_source_path:
                        checked_paths.append(fallback_source_path)
                    evidence_content = (
                        f"{empty_reason}\n\nChecked BMC paths (not present):\n"
                        + "\n".join(f"- {path}" for path in checked_paths)
                        + "\n"
                    )
                    empty_output_pattern = kwargs.get("empty_output_pattern") or (
                        f"{function_tag}_no_data.txt"
                    )
                    evidence_file = await self.write_output_with_generalization(
                        dut_id,
                        kwargs.get("collector_id", ""),
                        evidence_content,
                        output_pattern=empty_output_pattern,
                        function_tag=f"{function_tag}_no_data",
                        default_extension=".txt",
                    )
                    if not evidence_file:
                        return await self._create_standardized_collector_result(
                            successful_operations=0,
                            total_operations=1,
                            output_files=[],
                            error_messages=[
                                "Failed to write no-data evidence for missing BMC source paths"
                            ],
                            operation_name="bmc_file_transfer",
                            additional_context={
                                "source_path": primary_source_path,
                                "fallback_source_path": fallback_source_path,
                                "source_path_missing": True,
                                "checked_paths": checked_paths,
                            },
                            dut_id=dut_id,
                            collector_id=kwargs.get(
                                "collector_id", "bmc_file_transfer"
                            ),
                        )

                    await self._log_runtime(
                        "INFO",
                        "BMCSSHService",
                        f"{empty_reason}; wrote no-data evidence to {evidence_file}",
                        dut_id,
                    )
                    return await self._create_standardized_collector_result(
                        successful_operations=1,
                        total_operations=1,
                        output_files=[evidence_file],
                        error_messages=[],
                        operation_name="bmc_file_transfer",
                        additional_context={
                            "status": "success",
                            "reason": empty_reason,
                            "source_path": primary_source_path,
                            "fallback_source_path": fallback_source_path,
                            "source_path_missing": True,
                            "complete_on_empty_targets": True,
                            "checked_paths": checked_paths,
                            "no_data_evidence": evidence_file,
                        },
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id", "bmc_file_transfer"),
                    )

                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="bmc_file_transfer",
                    additional_context={
                        "status": "skipped",
                        "reason": skip_reason,
                        "source_path": primary_source_path,
                        "fallback_source_path": fallback_source_path,
                        "source_path_missing": True,
                    },
                    dut_id=dut_id,
                    collector_id="bmc_file_transfer",
                )

            if self.timing_manager:
                file_acquisition_operation_id = self.timing_manager.start_operation(
                    "bmc_file_acquisition",
                    function_tag,
                    metadata={"source_kind": "bmc_path"},
                )

            remote_staging_directory = await self._create_private_bmc_staging_directory(
                dut_id, bmc_temp_dir
            )
            await self._log_runtime(
                "DEBUG",
                "BMCSSHService",
                "Created private BMC archive staging directory",
                dut_id,
            )

            # Observe source allocation without following symbolic-link targets.
            # This is not a final archive-size estimate when the authored TAR
            # policy dereferences links; enforced byte limits use the completed
            # remote archive and bounded download instead.
            size_command = build_remote_cmd("du -sh {path}", path=source_path)
            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, size_command
            )
            if exit_code == 0:
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    "Source allocation preflight only (symlink targets not "
                    "followed; final archive size is validated separately): "
                    f"{stdout.strip()}",
                    dut_id,
                )

            # Check available space in temp directory
            df_command = build_remote_cmd(
                "df -h -- {path} | tail -1",
                path=bmc_temp_dir,
            )
            exit_code, df_output, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, df_command
            )
            if exit_code == 0:
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Available space in {bmc_temp_dir}: {df_output.strip()}",
                    dut_id,
                )

            # Check for symlinks in source directory
            symlink_check = build_remote_cmd(
                "find {path} -maxdepth 2 -type l -ls 2>/dev/null | head -5",
                path=source_path,
            )
            exit_code, symlink_output, _ = await self.dut_manager.execute_bmc_command(
                dut_id, symlink_check
            )
            if exit_code == 0 and symlink_output.strip():
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Found symlinks in {source_path} (targets will be "
                    f"materialized by BMC file-transfer TAR):\n{symlink_output.strip()}",
                    dut_id,
                )

            if use_sftp:
                probe_command = build_remote_tar_hardlink_probe_command(
                    tar_command=TRUSTED_REMOTE_TAR_COMMAND
                )
                probe_exit, _, _ = await self.dut_manager.execute_bmc_command(
                    dut_id, probe_command, timeout=30
                )
                if type(probe_exit) is not int or probe_exit not in {0, 1, 2}:
                    raise _BMCFileTransferPolicyError(
                        f"TAR capability probe failed with exit status {probe_exit}"
                    )
                tar_hardlink_supported = probe_exit == 0
                if not tar_hardlink_supported:
                    await self._log_runtime(
                        "INFO", "BMCSSHService", _TAR_HARDLINK_ADVISORY, dut_id
                    )
                # Try SFTP with retry logic
                for attempt in range(retry_count + 1):
                    try:
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            f"SFTP attempt {attempt + 1}/{retry_count + 1}",
                            dut_id,
                        )

                        # Every BMC file-transfer collector materializes linked
                        # diagnostic content before bounded validation and
                        # publication. This is an execution invariant rather
                        # than a catalog-controlled option.

                        temp_path = posixpath.join(
                            remote_staging_directory,
                            f"archive_{attempt}.tar.gz",
                        )
                        # Always archive the configured basename from its parent.
                        # Using the directory itself as ``change_dir`` would
                        # follow it when the configured source root is a symlink.
                        src_parent = posixpath.dirname(source_path.rstrip("/")) or "/"
                        src_basename = posixpath.basename(source_path.rstrip("/"))
                        sftp_command = "umask 077; " + build_remote_tar_create_command(
                            temp_path,
                            [src_basename],
                            tar_command=TRUSTED_REMOTE_TAR_COMMAND,
                            change_dir=src_parent,
                            use_sudo=archive_use_sudo,
                            hardlink_dereference_supported=tar_hardlink_supported,
                        )
                        exit_code, stdout, stderr = (
                            await self.dut_manager.execute_bmc_command(
                                dut_id,
                                sftp_command,
                                timeout=max(
                                    0.001, deadline - asyncio.get_running_loop().time()
                                ),
                            )
                        )
                        warning_classification = _classify_recoverable_tar_warnings(
                            stderr,
                            hardlink_dereference_supported=tar_hardlink_supported,
                        )
                        source_root_missing_warning = any(
                            _normalize_tar_missing_member_diagnostic(line.strip())
                            == src_basename
                            for line in str(stderr or "").splitlines()
                        )
                        missing_member_archive_candidate = (
                            archive_missing_member_policy == "partial"
                            and exit_code == 1
                            and warning_classification.all_recognized
                            and warning_classification.missing_member_count > 0
                            and not source_root_missing_warning
                        )

                        # A live source can disappear between discovery and TAR.
                        # Preserve the historical same-policy retry unless the
                        # catalog explicitly permits a validated partial archive.
                        # Repeating a recognized missing-member traversal cannot
                        # repair a stable dangling target and needlessly amplifies
                        # collection time and BMC I/O.
                        if (
                            exit_code != 0
                            and "No such file or directory" in stderr
                            and not missing_member_archive_candidate
                        ):
                            await self._log_runtime(
                                "WARNING",
                                "BMCSSHService",
                                "Archive creation saw a disappearing source; retrying once with the same link policy",
                                dut_id,
                            )
                            fallback_cmd = "umask 077; " + build_remote_tar_create_command(
                                temp_path,
                                [src_basename],
                                tar_command=TRUSTED_REMOTE_TAR_COMMAND,
                                change_dir=src_parent,
                                use_sudo=archive_use_sudo,
                                hardlink_dereference_supported=tar_hardlink_supported,
                            )
                            exit_code2, stdout2, stderr2 = (
                                await self.dut_manager.execute_bmc_command(
                                    dut_id,
                                    fallback_cmd,
                                    timeout=max(
                                        0.001,
                                        deadline - asyncio.get_running_loop().time(),
                                    ),
                                )
                            )
                            exit_code, stdout, stderr = (
                                exit_code2,
                                stdout2,
                                stderr2,
                            )
                            if exit_code != 0:
                                await self._log_runtime(
                                    "WARNING",
                                    "BMCSSHService",
                                    f"Archive retry returned status {exit_code}: {stderr}",
                                    dut_id,
                                )
                            warning_classification = _classify_recoverable_tar_warnings(
                                stderr,
                                hardlink_dereference_supported=tar_hardlink_supported,
                            )
                            source_root_missing_warning = any(
                                _normalize_tar_missing_member_diagnostic(line.strip())
                                == src_basename
                                for line in str(stderr or "").splitlines()
                            )

                        # TAR status one is usable only for a strictly recognized
                        # warning set. Permission loss always makes a validated
                        # artifact partial, even if a TAR implementation returns
                        # zero despite writing that diagnostic.
                        recoverable_warning_set = warning_classification.all_recognized
                        permission_warning = warning_classification.permission_denied
                        file_changed_warning = warning_classification.file_changed
                        hardlink_materialization_warning = (
                            warning_classification.hardlink_materialization_unavailable
                        )
                        missing_member_warning = (
                            warning_classification.missing_member_count > 0
                        )
                        missing_member_warning_allowed = (
                            archive_missing_member_policy == "partial"
                            and missing_member_warning
                            and not source_root_missing_warning
                        )
                        diagnostics_allowed = recoverable_warning_set and (
                            not missing_member_warning or missing_member_warning_allowed
                        )
                        archive_has_recoverable_diagnostics = (
                            permission_warning
                            or file_changed_warning
                            or hardlink_materialization_warning
                            or missing_member_warning_allowed
                        )
                        archive_command_usable = (
                            exit_code == 0
                            and (not str(stderr or "").strip() or diagnostics_allowed)
                        ) or (
                            exit_code == 1
                            and diagnostics_allowed
                            and (
                                permission_warning
                                or file_changed_warning
                                or missing_member_warning_allowed
                            )
                        )

                        if archive_command_usable:
                            archive_condition_messages = list(
                                warning_classification.condition_messages
                            )
                            if warning_classification.condition_messages_truncated:
                                archive_condition_messages.append(
                                    "Additional recognized TAR conditions were "
                                    "omitted from this bounded report"
                                )
                            archive_advisory_messages = list(
                                warning_classification.advisory_messages
                            )
                            if archive_has_recoverable_diagnostics:
                                await self._log_runtime(
                                    "WARNING",
                                    "BMCSSHService",
                                    "TAR diagnostics require artifact validation; "
                                    "checking the expected archive",
                                    dut_id,
                                )
                            try:
                                remote_size_before = (
                                    await self._snapshot_remote_bmc_archive_size(
                                        dut_id, temp_path
                                    )
                                )
                            except _BMCFileTransferPolicyError as error:
                                raise _BMCFileTransferPolicyError(
                                    f"TAR command returned status {exit_code}, but the "
                                    f"expected archive failed its postcondition: {error}"
                                ) from error
                            if remote_size_before > archive_limits.max_input_bytes:
                                raise _BMCFileTransferPolicyError(
                                    "remote BMC archive exceeds the configured "
                                    f"{archive_limits.max_input_bytes}-byte limit"
                                )
                            await self._log_runtime(
                                "INFO",
                                "BMCSSHService",
                                f"Remote archive exists at {temp_path} "
                                f"({remote_size_before} bytes); content validation pending",
                                dut_id,
                            )
                            archive_capacity_advisory = (
                                collection_archive_size_advisory(
                                    _BMC_DISCOVERED_FILE_DEFAULT_MAX_BYTES,
                                    remote_size_before,
                                    archive_limits.max_input_bytes,
                                )
                            )
                            if archive_capacity_advisory is not None:
                                await self._log_runtime(
                                    "WARNING",
                                    "BMCSSHService",
                                    archive_capacity_advisory,
                                    dut_id,
                                )

                            local_private_directory = None
                            try:
                                (
                                    local_private_directory,
                                    local_archive,
                                    expected_output_path,
                                    final_filename,
                                    resolved_collector_id,
                                ) = await self._allocate_local_bmc_artifact_staging(
                                    dut_id,
                                    kwargs.get("collector_id", ""),
                                    output_pattern=output_pattern,
                                    function_tag=function_tag,
                                    substitutions=timestamp_substitutions,
                                    default_extension=".tar.gz",
                                )
                                download_result = await self._download_bmc_file_bounded(
                                    dut_id,
                                    temp_path,
                                    local_archive,
                                    # Bind the stream to the archive size we
                                    # admitted. The DUT-manager boundary also
                                    # checks the opened remote inode before and
                                    # after reading, so replacement, truncation,
                                    # and growth all fail closed.
                                    max_bytes=remote_size_before,
                                )
                                remote_size_after = (
                                    await self._snapshot_remote_bmc_archive_size(
                                        dut_id, temp_path
                                    )
                                )
                                if remote_size_after != remote_size_before:
                                    raise _BMCFileTransferPolicyError(
                                        "remote BMC archive changed size during transfer"
                                    )

                                if (
                                    download_result.bytes_transferred
                                    != remote_size_before
                                ):
                                    raise _BMCFileTransferPolicyError(
                                        "bounded BMC download byte count changed"
                                    )

                                link_member_counts = {
                                    "symlink": 0,
                                    "hardlink": 0,
                                }
                                link_member_names: List[str] = []
                                validation = await run_managed_filesystem_operation(
                                    partial(
                                        inspect_tar_archive_metadata,
                                        local_archive,
                                        partial(
                                            _record_validated_tar_link,
                                            link_member_counts,
                                            link_member_names,
                                        ),
                                        limits=archive_limits,
                                    )
                                )
                                hardlink_member_loss = (
                                    link_member_counts["hardlink"] > 0
                                )
                                symlink_member_loss = link_member_counts["symlink"] > 0
                                special_member_loss = (
                                    validation.dropped_special_members > 0
                                )
                                archive_is_partial = (
                                    permission_warning
                                    or file_changed_warning
                                    or missing_member_warning_allowed
                                    or hardlink_member_loss
                                    or symlink_member_loss
                                    or special_member_loss
                                )
                                archive_warning_messages = list(
                                    archive_condition_messages
                                    if archive_is_partial
                                    else []
                                )
                                if (
                                    hardlink_member_loss
                                    or symlink_member_loss
                                    or special_member_loss
                                ):
                                    omitted_summary = (
                                        "Archive sanitization omitted unsupported "
                                        "symbolic-link, hard-link, or special members"
                                    )
                                    if link_member_names:
                                        omitted_summary += ": " + ", ".join(
                                            link_member_names
                                        )
                                    archive_warning_messages.append(omitted_summary)
                                if archive_is_partial:
                                    await self._log_runtime(
                                        "WARNING",
                                        "BMCSSHService",
                                        "Archive validation confirmed recoverable "
                                        "collection loss; preserving it as partial",
                                        dut_id,
                                    )
                                if (
                                    hardlink_materialization_warning
                                    and not hardlink_member_loss
                                ):
                                    await self._log_runtime(
                                        "INFO",
                                        "BMCSSHService",
                                        "TAR hard-link materialization was unavailable, "
                                        "but the validated archive contains no hard-link "
                                        "members",
                                        dut_id,
                                    )
                                empty_archive_has_blocking_loss = (
                                    permission_warning
                                    or file_changed_warning
                                    or missing_member_warning_allowed
                                    or hardlink_member_loss
                                    or symlink_member_loss
                                    or special_member_loss
                                )
                                if (
                                    archive_empty_is_not_applicable
                                    and missing_member_warning_allowed
                                    and validation.regular_files == 0
                                ):
                                    reason = (
                                        "Archive collection is partial because missing "
                                        "members left no regular-file payload"
                                    )
                                    outcome_details = {
                                        "schema_version": "1.0",
                                        "category": "data-quality",
                                        "condition": "incomplete-artifact",
                                        "messages": archive_warning_messages,
                                        "attributes": {
                                            "archive_complete": False,
                                            "archive_missing_member_policy": (
                                                archive_missing_member_policy
                                            ),
                                            "archive_missing_members": list(
                                                warning_classification.missing_members
                                            ),
                                            "archive_missing_member_count": (
                                                warning_classification.missing_member_count
                                            ),
                                            "archive_missing_members_truncated": (
                                                warning_classification.missing_members_truncated
                                            ),
                                        },
                                    }
                                    if self.timing_manager:
                                        self.timing_manager.end_operation(
                                            file_acquisition_operation_id,
                                            status="partial",
                                        )
                                    return await self._create_standardized_collector_result(
                                        successful_operations=1,
                                        total_operations=1,
                                        output_files=[],
                                        error_messages=[],
                                        operation_name="bmc_file_transfer",
                                        additional_context={
                                            "status": "partial",
                                            "reason": reason,
                                            "archive_empty_is_not_applicable": True,
                                            "archive_members": validation.members,
                                            "archive_regular_files": (
                                                validation.regular_files
                                            ),
                                            "archive_complete": False,
                                            "archive_missing_member_policy": (
                                                archive_missing_member_policy
                                            ),
                                            "archive_missing_members": list(
                                                warning_classification.missing_members
                                            ),
                                            "archive_missing_member_count": (
                                                warning_classification.missing_member_count
                                            ),
                                            "archive_missing_members_truncated": (
                                                warning_classification.missing_members_truncated
                                            ),
                                            "archive_warnings": archive_warning_messages,
                                            "archive_command_exit_code": exit_code,
                                            "outcome_details": outcome_details,
                                        },
                                        dut_id=dut_id,
                                        collector_id=resolved_collector_id,
                                    )
                                if (
                                    archive_empty_is_not_applicable
                                    and not empty_archive_has_blocking_loss
                                    and validation.regular_files == 0
                                ):
                                    reason = (
                                        "BMC archive source contains no regular files; "
                                        "collection is not applicable under the authored "
                                        "archive policy"
                                    )
                                    await self._log_runtime(
                                        "INFO",
                                        "BMCSSHService",
                                        reason,
                                        dut_id,
                                    )
                                    if self.timing_manager:
                                        self.timing_manager.end_operation(
                                            file_acquisition_operation_id,
                                            status="skipped",
                                        )
                                    return await self._create_standardized_collector_result(
                                        successful_operations=0,
                                        total_operations=0,
                                        output_files=[],
                                        error_messages=[],
                                        operation_name="bmc_file_transfer",
                                        additional_context={
                                            "status": "skipped",
                                            "reason": reason,
                                            "not_applicable": True,
                                            "archive_empty_is_not_applicable": True,
                                            "archive_members": validation.members,
                                            "archive_regular_files": (
                                                validation.regular_files
                                            ),
                                            "transfer_method": (
                                                download_result.transport_method
                                            ),
                                            "bounded_binary_transfer": True,
                                            "archive_bytes": remote_size_before,
                                            "archive_expected_bytes": (
                                                _BMC_DISCOVERED_FILE_DEFAULT_MAX_BYTES
                                            ),
                                            "archive_hard_limit_bytes": (
                                                archive_limits.max_input_bytes
                                            ),
                                            "archive_expected_size_exceeded": bool(
                                                archive_capacity_advisory
                                            ),
                                            "source_path": source_path,
                                            "used_fallback_source_path": used_fallback,
                                            "archive_use_sudo": archive_use_sudo,
                                            "archive_missing_member_policy": (
                                                archive_missing_member_policy
                                            ),
                                            "archive_complete": not archive_is_partial,
                                            "archive_missing_members": list(
                                                warning_classification.missing_members
                                            ),
                                            "archive_missing_member_count": (
                                                warning_classification.missing_member_count
                                            ),
                                            "archive_missing_members_truncated": (
                                                warning_classification.missing_members_truncated
                                            ),
                                            "archive_warnings": (
                                                archive_condition_messages
                                            ),
                                            "archive_advisories": (
                                                archive_advisory_messages
                                            ),
                                            "archive_command_exit_code": exit_code,
                                        },
                                        dut_id=dut_id,
                                        collector_id=resolved_collector_id,
                                    )
                                if (
                                    validation.members <= 0
                                    or validation.regular_files <= 0
                                ):
                                    omitted_link_evidence = ""
                                    if link_member_names:
                                        omitted_link_evidence = (
                                            "; unsupported link members cannot be "
                                            "published: " + ", ".join(link_member_names)
                                        )
                                        if validation.dropped_links > len(
                                            link_member_names
                                        ):
                                            omitted_link_evidence += (
                                                "; additional link paths were omitted "
                                                "from this bounded error"
                                            )
                                    raise _BMCFileTransferPolicyError(
                                        "downloaded BMC archive has no regular-file "
                                        "payload" + omitted_link_evidence
                                    )
                                published_validation = validation
                                archive_sanitized = validation.dropped_members > 0
                                if archive_sanitized:
                                    sanitized_archive = local_archive.with_name(
                                        "artifact.sanitized.tar.gz"
                                    )
                                    rewrite_result = (
                                        await run_managed_filesystem_operation(
                                            partial(
                                                rewrite_tar_gz_regular_files,
                                                local_archive,
                                                sanitized_archive,
                                                limits=archive_limits,
                                            )
                                        )
                                    )
                                    if rewrite_result.source != validation:
                                        raise _BMCFileTransferPolicyError(
                                            "BMC archive changed between validation and "
                                            "sanitization"
                                        )
                                    published_validation = rewrite_result.rewritten
                                    local_archive = sanitized_archive
                                    await self._log_runtime(
                                        "INFO",
                                        "BMCSSHService",
                                        "Published a bounded regular-file-only archive "
                                        "after controlled member filtering",
                                        dut_id,
                                    )
                                published_archive_bytes = local_archive.stat().st_size
                                file_path = await self._publish_local_bmc_artifact(
                                    dut_id,
                                    resolved_collector_id,
                                    final_filename,
                                    local_archive,
                                    expected_output_path,
                                )
                                output_files.append(file_path)
                            finally:
                                if local_private_directory is not None:
                                    local_private_directory.cleanup()

                            await self._log_runtime(
                                "INFO",
                                "BMCSSHService",
                                "Bounded binary file transfer successful via "
                                f"{download_result.transport_method}: {file_path}",
                                dut_id,
                            )

                            if self.timing_manager:
                                self.timing_manager.end_operation(
                                    file_acquisition_operation_id,
                                    status=(
                                        "partial" if archive_is_partial else "success"
                                    ),
                                    artifact_paths=output_files,
                                )

                            result_context = {
                                "transfer_method": download_result.transport_method,
                                "bounded_binary_transfer": True,
                                "archive_bytes": remote_size_before,
                                "archive_expected_bytes": (
                                    _BMC_DISCOVERED_FILE_DEFAULT_MAX_BYTES
                                ),
                                "archive_hard_limit_bytes": (
                                    archive_limits.max_input_bytes
                                ),
                                "archive_expected_size_exceeded": bool(
                                    archive_capacity_advisory
                                ),
                                "source_path": source_path,
                                "used_fallback_source_path": used_fallback,
                                "archive_use_sudo": archive_use_sudo,
                                "archive_missing_member_policy": (
                                    archive_missing_member_policy
                                ),
                                "archive_empty_is_not_applicable": (
                                    archive_empty_is_not_applicable
                                ),
                                "archive_complete": not archive_is_partial,
                                "archive_sanitized": archive_sanitized,
                                "archive_source_members": validation.members,
                                "archive_source_regular_files": (
                                    validation.regular_files
                                ),
                                "archive_published_members": (
                                    published_validation.members
                                ),
                                "archive_published_regular_files": (
                                    published_validation.regular_files
                                ),
                                "published_archive_bytes": published_archive_bytes,
                            }
                            if missing_member_warning_allowed:
                                result_context.update(
                                    {
                                        "archive_missing_members": list(
                                            warning_classification.missing_members
                                        ),
                                        "archive_missing_member_count": (
                                            warning_classification.missing_member_count
                                        ),
                                        "archive_missing_members_truncated": (
                                            warning_classification.missing_members_truncated
                                        ),
                                    }
                                )
                            if archive_sanitized or hardlink_materialization_warning:
                                result_context.update(
                                    {
                                        "archive_link_members": validation.dropped_links,
                                        "archive_hardlink_members": (
                                            link_member_counts["hardlink"]
                                        ),
                                        "archive_symlink_members": (
                                            link_member_counts["symlink"]
                                        ),
                                        "archive_special_members": (
                                            validation.dropped_special_members
                                        ),
                                        "archive_dropped_link_paths": link_member_names,
                                        "archive_dropped_link_paths_truncated": (
                                            validation.dropped_links
                                            > len(link_member_names)
                                        ),
                                    }
                                )
                            if hardlink_materialization_warning:
                                result_context.update(
                                    {
                                        "hardlink_materialization_unavailable": True,
                                        "archive_command_exit_code": exit_code,
                                    }
                                )
                            archive_advisories = []
                            if archive_capacity_advisory is not None:
                                archive_advisories.append(archive_capacity_advisory)
                            archive_advisories.extend(archive_advisory_messages)
                            if archive_advisories:
                                result_context["archive_advisories"] = (
                                    archive_advisories
                                )
                            if archive_is_partial:
                                warning_kinds = []
                                if permission_warning:
                                    warning_kinds.append("permission-denied members")
                                if file_changed_warning:
                                    warning_kinds.append("live-file changes")
                                if missing_member_warning_allowed:
                                    warning_kinds.append(
                                        "missing source members or symlink targets"
                                    )
                                if hardlink_member_loss:
                                    warning_kinds.append(
                                        "hard-link members omitted by archive policy"
                                    )
                                if symlink_member_loss:
                                    warning_kinds.append(
                                        "symbolic-link members omitted by archive policy"
                                    )
                                if special_member_loss:
                                    warning_kinds.append("unsupported special members")
                                result_context.update(
                                    {
                                        "status": "partial",
                                        "reason": "Archive collected with "
                                        + " and ".join(warning_kinds),
                                        "archive_warnings": archive_warning_messages,
                                        "permission_truncated": permission_warning,
                                        "live_files_changed": file_changed_warning,
                                        "archive_command_exit_code": exit_code,
                                    }
                                )
                                outcome_attribute_keys = (
                                    "archive_complete",
                                    "archive_missing_member_policy",
                                    "archive_missing_members",
                                    "archive_missing_member_count",
                                    "archive_missing_members_truncated",
                                    "archive_sanitized",
                                    "archive_link_members",
                                    "archive_hardlink_members",
                                    "archive_symlink_members",
                                    "archive_special_members",
                                    "permission_truncated",
                                    "live_files_changed",
                                )
                                result_context["outcome_details"] = {
                                    "schema_version": "1.0",
                                    "category": "data-quality",
                                    "condition": "incomplete-artifact",
                                    "messages": archive_warning_messages,
                                    "attributes": {
                                        key: result_context[key]
                                        for key in outcome_attribute_keys
                                        if key in result_context
                                    },
                                }

                            return await self._create_standardized_collector_result(
                                successful_operations=1,
                                total_operations=1,
                                output_files=output_files,
                                error_messages=[],
                                operation_name="bmc_file_transfer",
                                additional_context=result_context,
                                dut_id=dut_id,
                                collector_id=resolved_collector_id,
                            )
                        else:
                            # Provide helpful error message for common failures
                            error_msg = f"SFTP archive creation failed on attempt {attempt + 1}: {stderr}"
                            if (
                                "No space left on device" in stderr
                                or "no space left" in stderr.lower()
                            ):
                                error_msg += f"\n  → BMC temp directory {bmc_temp_dir} may be full. Consider freeing space or using a different temp directory."
                            elif "Cannot stat" in stderr or "No such file" in stderr:
                                error_msg += f"\n  → Some files or symlink targets in {source_path} may be missing or inaccessible."

                            await self._log_runtime(
                                "WARNING",
                                "BMCSSHService",
                                error_msg,
                                dut_id,
                            )
                            last_transfer_error = error_msg

                    except _BMCFileTransferPolicyError:
                        # Deterministic policy rejection cannot improve by
                        # repeating the same archive and download operation.
                        raise
                    except Exception as e:
                        last_transfer_error = f"{type(e).__name__}: {str(e)}"
                        await self._log_runtime(
                            "WARNING",
                            "BMCSSHService",
                            f"SFTP transfer failed on attempt {attempt + 1}: {str(e)}",
                            dut_id,
                        )

                    # Wait before retry (except on last attempt)
                    if attempt < retry_count:
                        await asyncio.sleep(retry_delay)
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            f"Waiting {retry_delay} seconds before retry...",
                            dut_id,
                        )

            error_details = [
                last_transfer_error
                or "bounded binary SFTP archive transfer exhausted its retry budget"
            ]

            if self.timing_manager:
                self.timing_manager.end_operation(
                    file_acquisition_operation_id,
                    status="error",
                    error="; ".join(error_details),
                )

            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"File transfer failed: {'; '.join(error_details)}"],
                operation_name="bmc_file_transfer",
                additional_context={"error_details": error_details},
                dut_id=dut_id,
                collector_id="bmc_file_transfer",
            )

        except asyncio.CancelledError as e:
            if self.timing_manager:
                self.timing_manager.end_operation(
                    file_acquisition_operation_id,
                    status=(
                        "error"
                        if asyncio.get_running_loop().time() >= deadline
                        else "cancelled"
                    ),
                    error=(
                        "BMC file transfer deadline expired"
                        if asyncio.get_running_loop().time() >= deadline
                        else str(e)
                    ),
                )
            raise
        except Exception as e:
            if self.timing_manager:
                self.timing_manager.end_operation(
                    file_acquisition_operation_id,
                    status="error",
                    error=str(e),
                )
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"File transfer failed: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"File transfer failed: {str(e)}"],
                operation_name="bmc_file_transfer",
                additional_context={},
            )
        finally:
            await self._finish_private_bmc_staging_directory(
                dut_id, remote_staging_directory
            )

    async def upload_file_to_bmc(
        self,
        dut_id: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Upload a local file to the BMC via existing transfer infrastructure.

        Supports wildcard patterns to find versioned files.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing upload file to BMC.

        Raises:
            ValueError: If local_path parameter is required; or remote_path
                parameter is required.
            _BMCFileTransferPolicyError: If input or state violates constraints
                required to upload a local file to the BMC via existing transfer
                infrastructure; bounded SFTP upload failed: ``transfer_error``;
                or local BMC upload staging changed during transfer.
        """
        upload_private_directory = None
        remote_upload_directory: Optional[str] = None
        upload_succeeded = False
        try:
            # Get parameters
            local_path_pattern = kwargs.get("local_path")
            remote_dir = kwargs.get("remote_path")
            create_remote_dir = kwargs.get("create_remote_dir", True)
            make_executable = kwargs.get("make_executable", False)
            artifact_max_bytes = _resolve_bmc_artifact_max_bytes(
                kwargs.get("max_artifact_bytes")
            )

            if not local_path_pattern:
                raise ValueError("local_path parameter is required")
            if not remote_dir:
                raise ValueError("remote_path parameter is required")
            remote_dir = _normalize_bmc_remote_path(
                remote_dir,
                field_name="BMC upload destination directory",
                allow_root=True,
            )

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Starting file upload: {local_path_pattern} -> {remote_dir}",
                dut_id,
            )

            # Select only the first lazy match. A broad authored pattern must
            # not materialize an unbounded local pathname inventory.
            local_file = next(glob.iglob(local_path_pattern), None)

            if local_file is None:
                error_msg = f"No files found matching pattern: {local_path_pattern}"
                await self._log_runtime(
                    "ERROR",
                    "BMCSSHService",
                    error_msg,
                    dut_id,
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[error_msg],
                    operation_name="upload_file_to_bmc",
                    additional_context={
                        "local_path_pattern": local_path_pattern,
                        "remote_path": remote_dir,
                    },
                )

            local_filename = os.path.basename(local_file)
            merged_dut_config = self.dut_manager.get_dut_config(dut_id)
            if not isinstance(merged_dut_config, dict):
                merged_dut_config = {}
            (
                upload_private_directory,
                staged_local_file,
                upload_bytes,
            ) = await _stage_local_bmc_upload_bounded(
                local_file,
                max_bytes=artifact_max_bytes,
                local_parent=local_temp_dir(merged_dut_config),
            )

            # Create remote directory if requested
            if create_remote_dir:
                mkdir_command = build_remote_cmd("mkdir -p -- {path}", path=remote_dir)
                await self._log_runtime(
                    "DEBUG",
                    "BMCSSHService",
                    f"Creating remote directory: {mkdir_command}",
                    dut_id,
                )
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, mkdir_command
                )
                if exit_code != 0:
                    raise _BMCFileTransferPolicyError(
                        "failed to create BMC upload destination directory: "
                        f"{str(stderr).strip()}"
                    )

            remote_upload_directory = await self._create_private_bmc_staging_directory(
                dut_id,
                remote_dir,
            )
            remote_file_path = _normalize_bmc_remote_file_path(
                posixpath.join(remote_upload_directory, local_filename),
                field_name="BMC upload destination file",
            )
            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Found file to upload: {local_file} -> {remote_file_path}",
                dut_id,
            )

            # Upload only the private bounded snapshot through the established
            # binary transfer facade. Command-output fallbacks would duplicate
            # the payload in memory and expose it to shell parsing.
            await self._log_runtime(
                "DEBUG",
                "BMCSSHService",
                f"Uploading file using DUT manager: {local_file} -> {remote_dir}",
                dut_id,
            )
            success, transfer_error = await self.dut_manager.transfer_files(
                dut_id=dut_id,
                sources=str(staged_local_file),
                destination_directory=remote_upload_directory,
                copy_to_destination=True,
                max_retries=3,
            )
            if not success:
                raise _BMCFileTransferPolicyError(
                    f"bounded SFTP upload failed: {transfer_error}"
                )
            staged_details = staged_local_file.lstat()
            if (
                not stat.S_ISREG(staged_details.st_mode)
                or staged_details.st_size != upload_bytes
                or staged_details.st_size > artifact_max_bytes
            ):
                raise _BMCFileTransferPolicyError(
                    "local BMC upload staging changed during transfer"
                )
            upload_method = "SFTP"

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"File uploaded successfully using {upload_method}: {remote_file_path}",
                dut_id,
            )

            # Make executable if requested
            if make_executable:
                chmod_command = build_remote_cmd(
                    "chmod +x -- {path}", path=remote_file_path
                )
                await self._log_runtime(
                    "DEBUG",
                    "BMCSSHService",
                    f"Making file executable: {chmod_command}",
                    dut_id,
                )
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, chmod_command
                )
                if exit_code != 0:
                    raise _BMCFileTransferPolicyError(
                        f"failed to make uploaded file executable: {str(stderr).strip()}"
                    )
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"File made executable: {remote_file_path}",
                    dut_id,
                )

            # Return success with uploaded script path in context for next hook
            result = await self._create_standardized_collector_result(
                successful_operations=1,
                total_operations=1,
                output_files=[],
                error_messages=[],
                operation_name="upload_file_to_bmc",
                additional_context={
                    "uploaded_script_path": remote_file_path,  # Pass to next hook
                    "local_file": local_file,
                    "remote_path": remote_file_path,
                    # Hooks in one stage share this context. Carry the already
                    # normalized catalog destination forward so script output
                    # receives a separate private directory beneath the same
                    # platform-safe parent as the uploaded executable.
                    "remote_staging_root": remote_dir,
                    "owned_upload_directory": remote_upload_directory,
                    "upload_method": upload_method,
                    "upload_bytes": upload_bytes,
                    "max_artifact_bytes": artifact_max_bytes,
                    "bounded_binary_transfer": True,
                    "status": "success",
                },
            )
            upload_succeeded = True
            return result

        except Exception as e:
            error_msg = f"File upload failed: {str(e)}"
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                error_msg,
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "BMCSSHService",
                f"Upload error traceback: {traceback.format_exc()}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[error_msg],
                operation_name="upload_file_to_bmc",
                additional_context={},
            )
        finally:
            if upload_private_directory is not None:
                upload_private_directory.cleanup()
            if not upload_succeeded:
                await self._finish_private_bmc_staging_directory(
                    dut_id,
                    remote_upload_directory,
                )

    def _expand_hmc_candidate_value(
        self, dut: "DUT", candidate: Any, visited: Optional[set] = None
    ) -> List[str]:
        """
        Expand a candidate value into concrete HMC endpoints.

        The implementation uses ``dut``, ``candidate``, and ``visited`` to
        expand a candidate value into concrete HMC endpoints. The operation
        mutates ``visited`` in place; ownership of those objects remains with
        the caller.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            candidate: Candidate value or resource evaluated by this operation.
            visited: Optional visited; ``None`` selects the function's default
                behavior.

        Returns:
            The expand HMC candidate value returned in operation-defined order.
        """
        if visited is None:
            visited = set()

        results: List[str] = []

        if candidate is None:
            return results

        if isinstance(candidate, (list, tuple, set)):
            for item in candidate:
                results.extend(
                    self._expand_hmc_candidate_value(dut, item, visited.copy())
                )
            return results

        if not isinstance(candidate, str):
            candidate = str(candidate)

        candidate = candidate.strip()
        if not candidate:
            return results

        if candidate in visited:
            return results

        visited.add(candidate)

        config_dict = getattr(dut, "config", {})
        if isinstance(config_dict, dict) and candidate in config_dict:
            config_value = config_dict[candidate]
            results.extend(
                self._expand_hmc_candidate_value(dut, config_value, visited.copy())
            )
            return results

        # Configuration references are explicit and governed. Do not treat an
        # arbitrary candidate as an environment-variable name: a secret value
        # that happens to resemble a host could otherwise be selected and
        # logged as an endpoint.
        results.append(candidate)
        return results

    @staticmethod
    def _dedupe_candidates(candidates: List[str]) -> List[str]:
        """
        Deduplicate candidate list while preserving order.

        The implementation uses ``candidates`` to deduplicate candidate list
        while preserving order.

        Args:
            candidates: Entries supplied as ``candidates`` without transferring
                container ownership.

        Returns:
            The validated ``ordered``.
        """
        seen: Set[str] = set()
        ordered: List[str] = []
        for candidate in candidates:
            value = candidate.strip()
            if value and value not in seen:
                seen.add(value)
                ordered.append(value)
        return ordered

    async def _resolve_hmc_ip_with_fallback(self, dut_id: str) -> Optional[str]:
        """
        Resolve an HMC endpoint using candidate fallbacks.

        The implementation uses ``dut_id`` to resolve an HMC endpoint using
        candidate fallbacks. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The canonical HMC IP with fallback text, or ``None`` when the
            requested value is unavailable.
        """
        dut = self.dut_manager.get_dut(dut_id)
        if not dut:
            return None

        if getattr(dut.credentials, "hmc_ip", None) and getattr(
            dut.credentials, "hmc_ip_validated", False
        ):
            return dut.credentials.hmc_ip.strip()

        candidate_sources: List[Any] = [
            getattr(dut.credentials, "hmc_ip", None),
            getattr(dut.credentials, "hmc_ip_candidates", []) or [],
            dut.config.get("HMC_IP_CANDIDATES"),
            dut.config.get("HMC_IP"),
            dut.config.get("hmc_ip"),
        ]

        platform_detection = dut.config.get("platform_detection", {})
        if isinstance(platform_detection, dict):
            candidate_sources.append(platform_detection.get("hmc_ip_candidates"))
            candidate_sources.append(platform_detection.get("hmc_ip"))

        expanded_candidates: List[str] = []
        for source in candidate_sources:
            expanded_candidates.extend(self._expand_hmc_candidate_value(dut, source))

        candidate_list = self._dedupe_candidates(expanded_candidates)
        if not candidate_list:
            await self._log_runtime(
                "WARNING",
                "BMCSSHService",
                "No HMC IP candidates available for fallback resolution",
                dut_id,
            )
            return None

        selected_candidate: Optional[str] = None
        valid_candidates: List[str] = []
        for candidate in candidate_list:
            try:
                ping_target = validate_ping_target(candidate)
            except (TypeError, ValueError):
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    "Skipping an invalid HMC endpoint candidate",
                    dut_id,
                )
                continue
            valid_candidates.append(candidate)
            ping_command = build_remote_cmd(
                "ping -c 1 -W 2 {target}",
                target=ping_target,
            )
            exit_code, _, _ = await self.dut_manager.execute_bmc_command(
                dut_id, ping_command, timeout=30
            )
            if exit_code == 0:
                selected_candidate = candidate
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Selected reachable HMC endpoint '{candidate}'",
                    dut_id,
                )
                break

            await self._log_runtime(
                "DEBUG",
                "BMCSSHService",
                f"HMC endpoint '{candidate}' unreachable via BMC ping, trying next candidate",
                dut_id,
            )

        if not selected_candidate:
            if not valid_candidates:
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    "No syntactically valid HMC endpoint candidates are available",
                    dut_id,
                )
                return None
            selected_candidate = valid_candidates[0]
            await self._log_runtime(
                "WARNING",
                "BMCSSHService",
                (
                    f"All HMC endpoint candidates unreachable; falling back to first "
                    f"candidate '{selected_candidate}'"
                ),
                dut_id,
            )

        dut.credentials.hmc_ip = selected_candidate
        dut.credentials.hmc_ip_validated = True

        if selected_candidate not in dut.credentials.hmc_ip_candidates:
            dut.credentials.hmc_ip_candidates.insert(0, selected_candidate)

        dut.config["HMC_IP"] = selected_candidate
        dut.config["hmc_ip"] = selected_candidate

        existing_config_candidates = dut.config.get("HMC_IP_CANDIDATES", [])
        if not isinstance(existing_config_candidates, list):
            existing_config_candidates = []
        dut.config["HMC_IP_CANDIDATES"] = self._dedupe_candidates(
            [selected_candidate] + existing_config_candidates
        )

        if isinstance(platform_detection, dict):
            pd_candidates = platform_detection.get("hmc_ip_candidates", [])
            if not isinstance(pd_candidates, list):
                pd_candidates = []
            platform_detection["hmc_ip_candidates"] = self._dedupe_candidates(
                [selected_candidate] + pd_candidates
            )
            platform_detection["hmc_ip"] = selected_candidate

        return selected_candidate

    async def run_bmc_script(
        self,
        dut_id: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Execute external script on BMC with full YAML-driven configuration.

        This is a generic script execution method that can run any script based
        on YAML parameters. It supports versioned scripts, alternative script
        names, configurable timeouts, and flexible output file patterns.
        The optional ``pass_hmc_credentials`` parameter exports resolved HMC
        credentials to the child through SSH stdin, keeping them out of command
        arguments and diagnostic transcripts. Absent values preserve the child
        script's defaults, including passwordless BMC SSH configurations. Line
        delimiters in supplied credentials are rejected.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run BMC script.

        Raises:
            _BMCFileTransferPolicyError: If uploaded BMC script path escaped its
                owned directory.
            ValueError: If script_name parameter is required; the script_name is
                not a non-empty string; the alternative_scripts are not a list
                of command names; or the script_args are not a list of
                arguments; or another input invariant is violated.
        """
        owned_working_directory: Optional[str] = None
        owned_upload_directory: Optional[str] = None
        try:
            # Check if previous hook uploaded a script (hooks in same stage share context via kwargs)
            uploaded_script_path = kwargs.get("uploaded_script_path")
            carried_upload_directory = kwargs.get("owned_upload_directory")
            if carried_upload_directory is not None:
                owned_upload_directory = self._require_owned_bmc_staging_directory(
                    dut_id, carried_upload_directory
                )
                uploaded_script_path = _normalize_bmc_remote_file_path(
                    uploaded_script_path,
                    field_name="uploaded BMC script path",
                )
                if posixpath.dirname(uploaded_script_path) != owned_upload_directory:
                    raise _BMCFileTransferPolicyError(
                        "uploaded BMC script path escaped its owned directory"
                    )

            # Parameters come directly from hook_params, not nested in "params"
            script_name = kwargs.get("script_name")

            # Use uploaded_script_path if available, otherwise use script_name
            if uploaded_script_path:
                script_name = uploaded_script_path
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Using uploaded script path from previous hook: {script_name}",
                    dut_id,
                )
            elif not script_name:
                raise ValueError("script_name parameter is required")
            if not isinstance(script_name, str) or not script_name:
                raise ValueError("script_name must be a non-empty string")

            function_tag = kwargs.get("function_tag", "script_execution")
            use_hmc_ip = kwargs.get("use_hmc_ip", False)

            # Flag to control automatic file retrieval after script execution
            auto_retrieve_files = kwargs.get("auto_retrieve_files", True)
            artifact_max_bytes = _resolve_bmc_artifact_max_bytes(
                kwargs.get("max_artifact_bytes")
            )

            # Create or use a known working directory for script output
            # This allows file retrieval even if script times out
            use_working_directory = kwargs.get("use_working_directory", False)
            working_dir = kwargs.get("working_dir")  # Can be passed from previous hook

            # Extract directory and base script name from the script_name parameter
            script_dir = (
                os.path.dirname(script_name) if os.path.dirname(script_name) else "."
            )
            base_script_name = os.path.basename(script_name)

            # Get alternative script names from parameters (optional)
            alternative_scripts = kwargs.get("alternative_scripts", [])
            if not isinstance(alternative_scripts, (list, tuple)):
                raise ValueError("alternative_scripts must be a list of command names")

            # Get script timeout through the common collector resolver.
            script_timeout = await self._resolve_collector_timeout(
                dut_id,
                kwargs,
                default_timeout=300,
                explicit_timeout_keys=("script_timeout", "timeout"),
            )

            # Get output file search pattern from parameters (optional)
            output_file_pattern = kwargs.get(
                "output_file_pattern", "*.tar.gz *.log *.txt"
            )

            # Get script arguments from parameters (optional)
            script_args = kwargs.get("script_args", [])
            if not isinstance(script_args, (list, tuple)):
                raise ValueError("script_args must be a list of arguments")

            # Get search directories for output files (optional, default /tmp)
            output_search_dirs = kwargs.get("output_search_dirs", ["/tmp"])

            # Get script execution mode (optional, default "direct")
            execution_mode = kwargs.get(
                "execution_mode", "direct"
            )  # direct, bash, sh, etc.
            if execution_mode not in _SCRIPT_EXECUTION_MODES:
                raise ValueError(
                    "unsupported execution_mode; expected one of "
                    + ", ".join(sorted(_SCRIPT_EXECUTION_MODES))
                )

            # Get script name pattern for finding versioned scripts (optional)
            # Pattern can include {base_script_name} placeholder and wildcards
            # Default: "{base_script_name}_*.sh" for exact prefix matching
            script_name_pattern = kwargs.get(
                "script_name_pattern", "{base_script_name}_*.sh"
            )

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Starting script execution: {script_name}",
                dut_id,
            )

            output_files = []
            producer_output_files: List[str] = []
            diagnostic_output_files: List[str] = []

            # Create a unique working directory if requested
            if use_working_directory and not working_dir:
                # A random-looking name followed by ``mkdir -p`` can still be
                # preclaimed. Allocate atomically with mktemp, validate the
                # endpoint-returned path, and retain sole cleanup ownership.
                # An upload hook carries its normalized catalog destination in
                # ``remote_staging_root``. Workflows without an upload use the
                # configured BMC scratch root.
                merged_dut_config = self.dut_manager.get_dut_config(dut_id)
                if not isinstance(merged_dut_config, dict):
                    merged_dut_config = {}
                configured_staging_root = kwargs.get("remote_staging_root")
                if configured_staging_root is None:
                    configured_staging_root = merged_dut_config.get(
                        "BMC_TEMP_DIR", "/tmp"
                    )
                remote_staging_root = _normalize_bmc_remote_path(
                    configured_staging_root,
                    field_name="BMC script staging root",
                    allow_root=True,
                )
                working_dir = await self._create_private_bmc_staging_directory(
                    dut_id,
                    remote_staging_root,
                )
                owned_working_directory = working_dir
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Created private working directory: {working_dir}",
                    dut_id,
                )
                kwargs["working_dir"] = working_dir
                kwargs["working_dir_created"] = True

            # Check if script exists - first try the exact path, then look for versioned scripts
            check_command = build_remote_cmd(
                "test -f {path} && echo 'found' || echo 'not found'",
                path=script_name,
            )
            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, check_command
            )

            if exit_code != 0 or "not found" in stdout:
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    f"Script {script_name} not found, trying alternatives with pattern: {script_name_pattern}",
                    dut_id,
                )

                # Try to find versioned scripts using the configured pattern
                # Replace {base_script_name} placeholder with actual base script name
                search_pattern = script_name_pattern.replace(
                    "{base_script_name}", base_script_name
                )
                find_command = build_remote_cmd(
                    "find {dir}/ -name {pattern} 2>/dev/null | head -1",
                    dir=script_dir,
                    pattern=search_pattern,
                )

                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, find_command
                )

                discovered_script = None
                if exit_code == 0 and stdout:
                    try:
                        discovered_script = _validate_discovered_script_path(
                            stdout,
                            search_directory=script_dir,
                            filename_pattern=search_pattern,
                        )
                    except ValueError:
                        await self._log_runtime(
                            "WARNING",
                            "BMCSSHService",
                            "Rejected an invalid script path returned by the BMC",
                            dut_id,
                        )

                if discovered_script:
                    # This is the only endpoint-returned path used as an
                    # executable.  Keep the path-policy validation immediately
                    # adjacent to assignment so future callers cannot mistake
                    # shell quoting alone for execution authorization.
                    script_name = discovered_script
                    await self._log_runtime(
                        "INFO",
                        "BMCSSHService",
                        f"Found versioned script: {script_name}",
                        dut_id,
                    )
                else:
                    # Try alternative script names in PATH
                    for alt_script in alternative_scripts:
                        alt_script = str(alt_script)
                        if not _SAFE_REMOTE_COMMAND_NAME.fullmatch(alt_script):
                            await self._log_runtime(
                                "WARNING",
                                "BMCSSHService",
                                "Ignored an invalid alternative script name",
                                dut_id,
                            )
                            continue
                        check_command = f"which {quote_arg(alt_script)}"
                        exit_code, stdout, stderr = (
                            await self.dut_manager.execute_bmc_command(
                                dut_id, check_command
                            )
                        )
                        if exit_code == 0:
                            script_name = alt_script
                            break
                    else:
                        # If no script found, return skipped status
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            f"No script found for {script_name}, skipping execution",
                            dut_id,
                        )

                        return await self._create_standardized_collector_result(
                            successful_operations=0,
                            total_operations=0,
                            output_files=[],
                            error_messages=[],
                            operation_name="script_execution",
                            additional_context={
                                "status": "skipped",
                                "reason": f"No script found for {script_name}",
                            },
                        )

            # Build the script command based on execution mode and parameters
            command_parts = []
            if execution_mode != "direct":
                command_parts.append(execution_mode)
            command_parts.append(quote_arg(script_name))

            # Add script arguments if provided
            if script_args:
                command_parts.extend(quote_arg(str(arg)) for arg in script_args)

            # Add HMC IP if requested (use short flag -i for script compatibility)
            if use_hmc_ip:
                resolved_hmc_ip = await self._resolve_hmc_ip_with_fallback(dut_id)
                if resolved_hmc_ip:
                    command_parts.extend(("-i", quote_arg(str(resolved_hmc_ip))))
                else:
                    await self._log_runtime(
                        "WARNING",
                        "BMCSSHService",
                        "Unable to determine a reachable HMC endpoint; continuing without -i flag",
                        dut_id,
                    )

            # If working directory is set, pass it to the script via -o flag
            # This tells the script where to write its output files
            pass_working_dir_to_script = kwargs.get("pass_working_dir_to_script", False)
            if working_dir and pass_working_dir_to_script:
                command_parts.extend(("-o", quote_arg(str(working_dir))))
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Passing working directory to script via -o flag: {working_dir}",
                    dut_id,
                )

            script_command = " ".join(command_parts)
            script_input_options = {}
            if kwargs.get("pass_hmc_credentials", False):
                credentials = self.dut_manager.get_dut(dut_id).credentials
                credential_values = []
                credential_names = []
                for name, value, label in (
                    ("HMC_USERNAME", credentials.hmc_username, "HMC username"),
                    ("HMC_PASSWORD", credentials.hmc_password, "HMC password"),
                ):
                    # DUTCredentials uses None/empty values for absent inputs.
                    # A key-only BMC route must not require new HMC credentials
                    # or replace the script's existing defaults with blanks.
                    if value is None or value == "":
                        continue
                    validate_password_stdin_line(value, credential_name=label)
                    credential_values.append(value)
                    credential_names.append(name)
                # SSH protects this input in transit. Shell read treats it as
                # literal data; neither credentials nor their quoting enter the
                # command line or its diagnostic transcript.
                if credential_values:
                    script_input_options["input_data"] = (
                        "\n".join(credential_values) + "\n"
                    )
                    script_command = " && ".join(
                        [f"IFS= read -r {name}" for name in credential_names]
                        + ["export " + " ".join(credential_names), script_command]
                    )

            script_exit_code, script_stdout, script_stderr = (
                await self.dut_manager.execute_bmc_command(
                    dut_id,
                    script_command,
                    timeout=script_timeout,
                    **script_input_options,
                )
            )

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Script exit_code={script_exit_code}, stdout length={len(script_stdout) if script_stdout else 0}, stderr length={len(script_stderr) if script_stderr else 0}",
                dut_id,
            )

            # Store execution result in context for downstream hooks
            kwargs["script_exit_code"] = script_exit_code
            kwargs["script_stdout"] = script_stdout
            kwargs["script_stderr"] = script_stderr

            # Retrieve files if auto_retrieve_files is True (even on timeout/failure)
            # This ensures we get partial logs even if the script didn't complete successfully
            if auto_retrieve_files:
                # Look for output files created by the script
                # Convert space-separated patterns to find command format
                patterns = output_file_pattern.split()
                find_conditions = " -o ".join(
                    [f"-name {quote_arg(pattern)}" for pattern in patterns]
                )

                # Search in all specified directories, prioritize working_dir if it exists
                search_dirs_list = output_search_dirs.copy()
                if working_dir and working_dir not in search_dirs_list:
                    # Add working directory as first search location
                    search_dirs_list.insert(0, working_dir)
                search_dirs = " ".join(quote_arg(d) for d in search_dirs_list)
                # Need to wrap find conditions in parentheses when using multiple directories
                # Use head -n 10 for BusyBox compatibility (BMC uses BusyBox)
                # search_dirs and find_conditions are pre-quoted via quote_arg above
                find_command = (
                    "find "
                    + search_dirs
                    + " \\( "
                    + find_conditions
                    + " \\) 2>/dev/null | head -n 10"
                )

                find_exit_code, find_stdout, find_stderr = (
                    await self.dut_manager.execute_bmc_command(dut_id, find_command)
                )

                # Try to retrieve files even if the original script failed/timed out
                if find_exit_code == 0 and find_stdout:
                    files = _parse_bmc_discovered_file_inventory(find_stdout)

                    await self._log_runtime(
                        "INFO",
                        "BMCSSHService",
                        f"Found {len(files)} output files (script exit_code={script_exit_code})",
                        dut_id,
                    )

                    for file_path in files:
                        try:
                            output_file_path, download_result = (
                                await self._download_and_publish_bmc_artifact_bounded(
                                    dut_id,
                                    kwargs.get("collector_id", ""),
                                    file_path,
                                    function_tag=function_tag,
                                    max_bytes=artifact_max_bytes,
                                )
                            )
                            output_files.append(output_file_path)
                            producer_output_files.append(output_file_path)
                            await self._log_runtime(
                                "INFO",
                                "BMCSSHService",
                                f"Downloaded {posixpath.basename(file_path)} "
                                f"({download_result.bytes_transferred} bytes) via "
                                f"bounded {download_result.transport_method}",
                                dut_id,
                            )
                        except Exception as e:
                            await self._log_runtime(
                                "ERROR",
                                "BMCSSHService",
                                f"Exception downloading {posixpath.basename(file_path)}: {str(e)}",
                                dut_id,
                            )
                            continue

            # Script stdout is useful evidence, but it is a derived diagnostic,
            # not a producer artifact. Preserve it without allowing it to satisfy
            # the required-primary-artifact contract.
            if script_stdout:
                script_output_path = await self.write_output_with_generalization(
                    dut_id,
                    kwargs.get("collector_id", ""),
                    script_stdout,
                    output_pattern="script_stdout.txt",
                    function_tag=function_tag,
                )
                if script_output_path:
                    output_files.append(script_output_path)
                    diagnostic_output_files.append(script_output_path)

            producer_files_retrieved = len(producer_output_files)
            common_context = {
                "exit_code": script_exit_code,
                "stderr": script_stderr,
                "stdout": script_stdout,
                "producer_files_retrieved": producer_files_retrieved,
                "producer_output_files": producer_output_files,
                "diagnostic_files": diagnostic_output_files,
                "max_artifact_bytes": artifact_max_bytes,
                "bounded_binary_transfer": True,
            }

            # Exit zero alone is insufficient for this producer-style hook: at
            # least one non-empty retrieved artifact must satisfy the contract.
            if script_exit_code == 0 and producer_files_retrieved:
                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Script execution successful: {producer_files_retrieved} producer files",
                    dut_id,
                )

                return await self._create_standardized_collector_result(
                    successful_operations=1,
                    total_operations=1,
                    output_files=output_files,
                    error_messages=[],
                    operation_name="script_execution",
                    additional_context={
                        **common_context,
                        "reason": (
                            "Script execution completed: "
                            f"{producer_files_retrieved} producer files"
                        ),
                    },
                )

            error_details = []
            if script_stderr:
                error_details.append(f"STDERR: {script_stderr}")
            if script_stdout:
                error_details.append(f"STDOUT: {script_stdout}")
            if not error_details:
                error_details.append(
                    f"Script exited with code {script_exit_code} (no output)"
                )
            full_error = "\n".join(error_details)

            if script_exit_code != 0 and producer_files_retrieved:
                failure_reason = (
                    "Script execution failed/timed out "
                    f"(exit code {script_exit_code}), but retrieved "
                    f"{producer_files_retrieved} producer files:\n{full_error}"
                )
                await self._log_runtime(
                    "WARNING", "BMCSSHService", failure_reason, dut_id
                )
                return await self._create_standardized_collector_result(
                    successful_operations=1,
                    total_operations=1,
                    output_files=output_files,
                    error_messages=[failure_reason],
                    operation_name="script_execution",
                    additional_context={
                        **common_context,
                        "status": "partial",
                        "reason": failure_reason,
                        "partial_success": True,
                        "files_retrieved": producer_files_retrieved,
                    },
                )

            if script_exit_code == 0:
                failure_reason = (
                    "Script exited successfully but produced no retrievable "
                    "primary artifacts"
                )
            else:
                failure_reason = (
                    f"Script execution failed (exit code {script_exit_code}):\n"
                    f"{full_error}"
                )
            await self._log_runtime("ERROR", "BMCSSHService", failure_reason, dut_id)
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=output_files,
                error_messages=[failure_reason],
                operation_name="script_execution",
                additional_context={
                    **common_context,
                    "status": "error",
                    "reason": failure_reason,
                },
            )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"Exception in run_bmc_script: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"Exception in run_bmc_script: {str(e)}"],
                operation_name="script_execution",
                additional_context={},
            )
        finally:
            try:
                await self._finish_private_bmc_staging_directory(
                    dut_id,
                    owned_working_directory,
                )
            finally:
                await self._finish_private_bmc_staging_directory(
                    dut_id,
                    owned_upload_directory,
                )

    async def copy_files_from_bmc(
        self,
        dut_id: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Copy files from BMC to local system.

        This can be used as a standalone hook to retrieve files from a known
        directory (e.g., after script timeout).

        This method can be called:

        1. As a separate hook after run_bmc_script (to retry file retrieval).
        2. In post_processing stage to ensure files are retrieved.
        3. With explicit paths when auto_retrieve_files=False was used.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing copy files from BMC.
        """
        owned_cleanup_directory: Optional[str] = None
        try:
            # Get parameters
            working_dir = kwargs.get("working_dir")
            output_file_pattern = kwargs.get(
                "output_file_pattern", "*.tar.gz *.log *.txt"
            )
            output_search_dirs = kwargs.get("output_search_dirs", ["/tmp"])
            function_tag = kwargs.get("function_tag", "file_transfer")
            cleanup_working_dir = kwargs.get("cleanup_working_dir", True)
            artifact_max_bytes = _resolve_bmc_artifact_max_bytes(
                kwargs.get("max_artifact_bytes")
            )
            if working_dir is not None:
                working_dir = _normalize_bmc_remote_path(
                    working_dir,
                    field_name="BMC working directory",
                )
            if (
                cleanup_working_dir
                and working_dir
                and kwargs.get("working_dir_created")
            ):
                owned_cleanup_directory = self._require_owned_bmc_staging_directory(
                    dut_id, working_dir
                )

            await self._log_runtime(
                "INFO",
                "BMCSSHService",
                f"Starting file retrieval from BMC (working_dir={working_dir})",
                dut_id,
            )

            output_files = []

            # Build search directories list
            search_dirs_list = output_search_dirs.copy()
            if working_dir and working_dir not in search_dirs_list:
                search_dirs_list.insert(0, working_dir)

            # Convert space-separated patterns to find command format
            from ..utils.command_safety import quote_arg

            patterns = output_file_pattern.split()
            find_conditions = " -o ".join(
                [f"-name {quote_arg(pattern)}" for pattern in patterns]
            )

            # Pre-quote each directory individually for shell safety
            search_dirs = " ".join(quote_arg(d) for d in search_dirs_list)
            # search_dirs and find_conditions are pre-quoted via quote_arg above
            find_command = (
                "find "
                + search_dirs
                + " \\( "
                + find_conditions
                + " \\) 2>/dev/null | head -n 10"
            )

            find_exit_code, find_stdout, find_stderr = (
                await self.dut_manager.execute_bmc_command(dut_id, find_command)
            )

            if find_exit_code == 0 and find_stdout:
                files = _parse_bmc_discovered_file_inventory(find_stdout)

                await self._log_runtime(
                    "INFO",
                    "BMCSSHService",
                    f"Found {len(files)} files to retrieve",
                    dut_id,
                )

                # Retrieve each file
                for file_path in files:
                    try:
                        output_path, download_result = (
                            await self._download_and_publish_bmc_artifact_bounded(
                                dut_id,
                                kwargs.get("collector_id", ""),
                                file_path,
                                function_tag=function_tag,
                                max_bytes=artifact_max_bytes,
                            )
                        )
                        output_files.append(output_path)
                        await self._log_runtime(
                            "INFO",
                            "BMCSSHService",
                            f"Retrieved file {file_path} via bounded "
                            f"{download_result.transport_method} "
                            f"({download_result.bytes_transferred} bytes)",
                            dut_id,
                        )
                    except Exception as e:
                        await self._log_runtime(
                            "ERROR",
                            "BMCSSHService",
                            f"Error retrieving file {file_path}: {str(e)}",
                            dut_id,
                        )
            else:
                await self._log_runtime(
                    "WARNING",
                    "BMCSSHService",
                    f"No files found matching pattern '{output_file_pattern}' in {search_dirs_list}",
                    dut_id,
                )

            # Return results
            if output_files:
                return await self._create_standardized_collector_result(
                    successful_operations=len(output_files),
                    total_operations=len(output_files),
                    output_files=output_files,
                    error_messages=[],
                    operation_name="file_transfer",
                    additional_context={
                        "reason": f"Retrieved {len(output_files)} files from BMC",
                        "working_dir": working_dir,
                        "max_artifact_bytes": artifact_max_bytes,
                        "bounded_binary_transfer": True,
                    },
                )
            else:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=["No files found to retrieve"],
                    operation_name="file_transfer",
                    additional_context={
                        "working_dir": working_dir,
                        "max_artifact_bytes": artifact_max_bytes,
                        "bounded_binary_transfer": True,
                    },
                )

        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "BMCSSHService",
                f"Exception in copy_files_from_bmc: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"Exception in copy_files_from_bmc: {str(e)}"],
                operation_name="file_transfer",
                additional_context={},
            )
        finally:
            await self._finish_private_bmc_staging_directory(
                dut_id, owned_cleanup_directory
            )

    async def _get_platform_info(
        self,
        dut_id: str,
        platform_detection_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Get platform information from BMC using YAML-driven configuration.

        Use YAML-provided platform detection config or fallback to basic
        detection.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            platform_detection_config: Optional Platform detection config
                governing get platform information from BMC using YAML-driven
                configuration.

        Returns:
            A mapping containing the ``platform_type``, ``detection_command``,
            and ``info`` fields.
        """
        try:
            # Use YAML-provided platform detection config or fallback to basic detection
            if platform_detection_config:
                commands = platform_detection_config.get(
                    "commands",
                    ["cat /etc/os-release", "uname -a", "cat /proc/version"],
                )
                platform_patterns = platform_detection_config.get(
                    "platform_patterns", {}
                )
            else:
                # Fallback to basic detection if no YAML config provided
                commands = [
                    "cat /etc/os-release",
                    "uname -a",
                    "cat /proc/version",
                ]
                platform_patterns = {
                    "OpenBMC": ["OpenBMC"],
                    "iDRAC": ["iDRAC"],
                    "iLO": ["iLO"],
                    "HMC": ["HMC", "hmc"],
                }

            for command in commands:
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    dut_id, command
                )
                if exit_code == 0 and stdout.strip():
                    # Use YAML-provided patterns to detect platform
                    for platform_type, patterns in platform_patterns.items():
                        for pattern in patterns:
                            if pattern in stdout:
                                return {
                                    "platform_type": platform_type,
                                    "detection_command": command,
                                }

                    # If no specific platform detected, return generic
                    return {
                        "platform_type": "generic",
                        "info": stdout.strip(),
                        "detection_command": command,
                    }

            return {"platform_type": "unknown"}
        except Exception as e:
            logger.error(f"Failed to get platform info: {e}")
            return {"platform_type": "unknown"}
