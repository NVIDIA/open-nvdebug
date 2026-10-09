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
DUT Manager - Handles DUT connections and operations.

Manages Device Under Test (DUT) instances including connection pooling, service
initialization, platform detection, and execution orchestration across multiple
DUTs with support for various access methods (Redfish, IPMI, SSH, HMC).
"""

import asyncio
import copy
import getpass
import grp
import hashlib
import json
import logging
import math
import os
import platform
import posixpath
import re
import secrets
import shlex
import shutil
import signal
import stat
import tempfile
import time
import zlib
from collections.abc import AsyncIterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union
from urllib.parse import urlsplit

import aiohttp
import asyncssh
from asyncssh.logging import SSHLogger
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from ..config import (
    RedfishSessionConfig,
    SSHConnectionPoolConfig,
    _reject_conflicting_redfish_session_holders,
    merge_dut_config_layers,
)
from ..services.auto_detection_service import AutoDetectionService
from ..services.dynamic_discovery_service import DynamicDiscoveryService
from ..services.hmc_service import HMCService
from ..services.platform_detection_service import PlatformDetectionService
from ..services.redfish_discovery import RedfishDiscoveryAdapter
from ..services.ssh_proxy_service import SSHProxyService
from ..utils.bounded_archive import extract_tar_archive
from ..utils.catalog_snapshot import CatalogSnapshot
from ..utils.command_diagnostics import (
    capture_command_diagnostics,
    retain_command_stream,
)
from ..utils.command_safety import (
    TRUSTED_IPMITOOL_NOT_FOUND_MESSAGE,
    TRUSTED_IPMITOOL_PATHS,
    TRUSTED_POSIX_SHELL_PATH,
    TRUSTED_PRIVILEGED_PATH,
    build_local_cmd,
    build_privileged_command_argv,
    build_trusted_ipmitool_remote_command,
    build_trusted_ipmitool_selection_script,
    build_trusted_remote_command,
    is_bmc_command_failure_output,
    resolve_trusted_ipmitool_path,
    validate_password_stdin_line,
    validate_ping_target,
)
from ..utils.managed_filesystem import run_managed_filesystem_operation
from ..utils.persistent_post_guard import (
    TARGET_DUT_COUNT_ENV,
    PersistentPostGuardError,
    PersistentPostReservation,
    validate_persistent_post_environment,
    validate_persistent_post_network_request,
)
from ..utils.redfish_download import (
    StreamedRedfishBody,
    TruncatedRedfishErrorBody,
)
from ..utils.redfish_limits import (
    DEFAULT_REDFISH_ATTACHMENT_MAX_BYTES,
    RedfishResponseLimits,
    clamp_redfish_attachment_limit,
)
from ..utils.redfish_tls import (
    INSECURE_REDFISH_TRANSPORT_WARNING_MESSAGE,
    RedfishTLSPolicy,
)
from ..utils.redfish_topology_profile import (
    RedfishTopologyProfileError,
    rebase_redfish_uri,
    validate_redfish_request_uri,
)
from ..utils.redfish_transport import (
    REDFISH_TRANSPORT_CONTENT_LENGTH_MAX_BYTES,
    build_redfish_request_headers,
    encode_basic_auth_header,
    format_redfish_url_host,
    normalize_redfish_content_type,
)
from ..utils.run_limits import MAX_DUT_ID_BYTES, is_printable_identity
from ..utils.runtime_boundary_profile import (
    DEFAULT_RUNTIME_BOUNDARIES,
    RUNTIME_BOUNDARIES_KEY,
    RUNTIME_BOUNDARY_OVERRIDES_KEY,
    redfish_preflight_retry_budget,
    redfish_preflight_wait_timeout,
    runtime_boundary_value,
)
from ..utils.secret_env import scrubbed_child_environment
from ..utils.ssh_security import (
    DEFAULT_SSH_TUNNEL_PREFIX,
    INSECURE_SSH_HOST_KEY_WARNING_MESSAGE,
    asyncssh_host_key_options,
    canonical_openssh_host_key_alias,
    normalize_ssh_host_key_policy,
    openssh_host_key_options,
)
from ..utils.tar_utils import (
    TRUSTED_REMOTE_TAR_COMMAND,
    build_link_safe_tar_create_command,
)
from ..utils.temp_dir_config import get_tool_temp_dir, local_temp_dir
from ..utils.transport_support import (
    catalog_transport_support,
    transport_support_field,
)
from ..utils.yaml_manager import YAMLManager
from .async_logger import AsyncSafeLogger
from .baseboard_manager import BaseboardManager, reconcile_baseboard_node_type
from .dut_file_transfer import (
    BMCTransferRequest,
    BoundedBMCDownloadResult,
    DUTFileTransfer,
)
from .dut_session_registry import (
    DUTSessionRegistry,
    RedfishSessionPool,
    cleanup_dut_ssh_proxy_tunnels,
)
from .dut_session_registry import (
    close_all_redfish_sessions as close_all_owned_redfish_sessions,
)
from .dut_session_registry import close_redfish_session as close_owned_redfish_session
from .dut_session_registry import (
    create_fallback_redfish_session,
)
from .dut_session_registry import create_redfish_session as create_owned_redfish_session
from .dut_session_registry import (
    initialize_redfish_session_pool as initialize_owned_redfish_session_pool,
)
from .finalization_receipt import (
    capture_owned_awaitable,
    drain_owned_tasks,
    select_authoritative_exception,
)
from .host_ssh_pool import (
    CredentialGenerationFingerprint,
    HostSSHConnectFailure,
    HostSSHConnectionPool,
    HostSSHPoolShutdown,
    HostSSHProcessCreationFailure,
    _exception_detail,
    normalize_ssh_endpoint_host,
)
from .redfish_controller import metadata_controller, redfish_controller_scope
from .redfish_http_engine import (
    RedfishHttpEngine,
    RedfishHttpLimits,
    RedfishHttpPrimitives,
)
from .redfish_session_auth import RedfishSessionAuthenticationError

logger = logging.getLogger(__name__)

_REDFISH_CLEANUP_CONCURRENCY = 8


class _RedfishCleanupError(RuntimeError):
    """
    Carry a bounded DUT/type/status summary across the manager cleanup boundary.

    Messages contain local DUT identifiers and fixed error categories, never a
    transport exception message, session URL, authentication token, or response.
    The original authoritative failure remains available as the exception cause.
    """


def _redfish_cleanup_error_detail(error: BaseException) -> str:
    """
    Describe a cleanup failure without formatting sensitive transport exceptions.

    Authentication failures expose a numeric protocol status, and operating
    system failures expose an errno. Exception messages may embed endpoints or
    credentials, so their text is excluded from the operator-facing summary.

    Args:
        error: Observed logout, transport, logging, or process-control failure.

    Returns:
        The exception category and a numeric HTTP status or errno when available.
    """
    detail = type(error).__name__
    if (
        isinstance(error, RedfishSessionAuthenticationError)
        and type(error.status) is int
    ):
        detail += f" (HTTP {error.status})"
    elif isinstance(error, OSError) and type(error.errno) is int:
        detail += f" (errno {error.errno})"
    return detail


# ``DUT.test_ipmi_connection()`` owns a 30-second ipmitool timeout.  The
# preflight wrapper must leave enough time for that bounded attempt to finish;
# a shorter outer timeout can falsely suppress every IPMI collector on a busy
# but reachable BMC.
DIRECT_IPMI_PREFLIGHT_TIMEOUT_SECONDS = 35.0
FORWARDED_IPMI_PREFLIGHT_TIMEOUT_SECONDS = 60.0

# A batched command failure gets two opportunities to prove the route remains
# usable or replace it through the route-locked session registry. The small
# delay between attempts admits short transport disruptions without recreating
# the unbounded per-command timeout multiplication this recovery protects
# against. Callers may narrow these defaults, but validation keeps the policy
# finite even when the generic batch API is reused elsewhere.
BMC_SSH_BATCH_DEFAULT_CONNECTION_RETRIES = 2
BMC_SSH_BATCH_MAX_CONNECTION_RETRIES = 5
BMC_SSH_BATCH_DEFAULT_RETRY_BACKOFF_SECONDS = 1.0
BMC_SSH_BATCH_MAX_RETRY_BACKOFF_SECONDS = 30.0
BMC_SSH_BATCH_DEFAULT_CONSECUTIVE_FAILURE_LIMIT = 2
BMC_SSH_BATCH_MAX_CONSECUTIVE_FAILURE_LIMIT = 5

# AsyncSSH normally records SFTP source and destination paths at INFO and DEBUG
# levels. Managed collector artifacts can contain run-scoped nonces and other
# sensitive path material, so each dedicated transfer session is rebound to an
# isolated disabled logger before any path-bearing SFTP request is issued.
_managed_sftp_logger_parent = logging.Logger(
    "nvdebug-managed-host-transfer-sftp", level=logging.CRITICAL + 1
)
_managed_sftp_logger_parent.disabled = True
_managed_sftp_logger_child = _managed_sftp_logger_parent.getChild("sftp")
_managed_sftp_logger_child.setLevel(logging.CRITICAL + 1)
_managed_sftp_logger_child.disabled = True
_MANAGED_SFTP_LOGGER = SSHLogger(_managed_sftp_logger_parent)

# AsyncSSH logs the full command when it opens an ``exec`` channel and may log
# channel payloads at higher debug levels. Managed collector wrappers contain
# run tokens, private paths, and the collector payload, so they must never use
# AsyncSSH's process-wide logger or a connection shared with another command.
# Rebinding a dedicated connection before ``run()`` makes every child channel
# inherit this disabled logger without changing logging for concurrent work.
_managed_command_logger_parent = logging.Logger(
    "nvdebug-managed-host-command", level=logging.CRITICAL + 1
)
_managed_command_logger_parent.disabled = True
_MANAGED_COMMAND_LOGGER = SSHLogger(_managed_command_logger_parent)


def _managed_ssh_error_type(error: BaseException) -> str:
    """
    Describe a managed SSH failure without formatting its sensitive payload.

    Transport messages can contain commands, stdin, tokens, or remote paths.
    Retain only exception classes, including the original channel-open failure
    when the bounded process runner wraps it. Never traverse arbitrary causes.

    Args:
        error: Authoritative transport or setup exception to describe.

    Returns:
        Exception class names with no exception message or traceback text.
    """
    detail = type(error).__name__
    if isinstance(error, HostSSHProcessCreationFailure):
        detail += f" ({type(error.error).__name__})"
    return detail


def _bind_managed_command_logger(
    connection: asyncssh.SSHClientConnection,
) -> None:
    """
    Fail closed unless an owned AsyncSSH connection can suppress payload logs.

    The implementation uses ``connection`` to fail closed unless an owned
    AsyncSSH connection can suppress payload logs. If the function cannot fail
    closed unless an owned AsyncSSH connection can suppress payload logs, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        connection: Connection object whose ``_logger`` and ``logger`` state is
            read while performing fail closed unless an owned AsyncSSH
            connection can suppress payload logs.

    Raises:
        RuntimeError: If unable to isolate managed SSH command logging.
    """

    try:
        connection._logger = _MANAGED_COMMAND_LOGGER
    except (AttributeError, TypeError) as error:
        raise RuntimeError("Unable to isolate managed SSH command logging") from error

    if connection.logger is not _MANAGED_COMMAND_LOGGER:
        raise RuntimeError("Unable to isolate managed SSH command logging")


def _bind_managed_sftp_logger(
    connection: asyncssh.SSHClientConnection,
) -> None:
    """
    Bind a dedicated connection before any SFTP channel can inherit logging.

    The implementation uses ``connection`` to bind a dedicated connection before
    any SFTP channel can inherit logging. If the function cannot bind a
    dedicated connection before any SFTP channel can inherit logging, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        connection: Connection object whose ``_logger`` and ``logger`` state is
            read while performing bind a dedicated connection before any SFTP
            channel can inherit logging.

    Raises:
        RuntimeError: If unable to isolate managed SFTP logging.
    """

    try:
        connection._logger = _MANAGED_SFTP_LOGGER
    except (AttributeError, TypeError) as error:
        raise RuntimeError("Unable to isolate managed SFTP logging") from error

    if connection.logger is not _MANAGED_SFTP_LOGGER:
        raise RuntimeError("Unable to isolate managed SFTP logging")


def _managed_sftp_handler_is_isolated(sftp_client: Any) -> bool:
    """
    Verify a new SFTP handler inherited only the disabled managed logger.

    The implementation uses ``sftp_client`` to verify a new SFTP handler
    inherited only the disabled managed logger. Every required invariant is
    checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        sftp_client: Sftp client consumed while the function attempts to verify
            a new SFTP handler inherited only the disabled managed logger.

    Returns:
        Whether the new SFTP handler inherited only the disabled managed logger
        operation succeeds.
    """

    handler = getattr(sftp_client, "_handler", None)
    channel_logger = getattr(handler, "_logger", None)
    return (
        type(channel_logger) is SSHLogger
        and getattr(channel_logger, "_logger", None) is _managed_sftp_logger_child
        and _managed_sftp_logger_child.disabled
        and _managed_sftp_logger_parent.disabled
    )


RedfishResponsePayload = Union[str, dict, bytes, StreamedRedfishBody]

SSH_CONNECTION_CLOSE_TIMEOUT_SECONDS = 5.0
SSH_PROCESS_CLEANUP_TIMEOUT_SECONDS = 2.0
SSH_STDOUT_MAX_BYTES = 64 * 1024 * 1024
SSH_STDERR_MAX_BYTES = 16 * 1024 * 1024
SSH_OUTPUT_AGGREGATE_MAX_BYTES = 64 * 1024 * 1024
SSH_OUTPUT_READ_CHUNK_BYTES = 64 * 1024
PROCESS_OUTPUT_MAX_LIMIT_BYTES = (1 << 63) - 1
RAW_SSH_CAPACITY_WAIT_TIMEOUT_SECONDS = 30.0
RAW_SSH_MAX_ACTIVE_ENDPOINTS_PER_DUT = 4
RAW_SSH_MAX_ACTIVE_ENDPOINTS_PER_RUN = 64
RAW_SSH_MAX_ACTIVE_PROXIES_PER_DUT = 4
RAW_SSH_MAX_ACTIVE_PROXIES_PER_RUN = 32
RAW_SSH_MAX_LIMITER_KEYS_PER_RUN = 1024
BMC_HMC_SSH_MAX_CACHED_ROUTES_PER_RUN = 512
SUBPROCESS_CLEANUP_TIMEOUT_SECONDS = 2.0
SUBPROCESS_STDOUT_MAX_BYTES = 64 * 1024 * 1024
SUBPROCESS_STDERR_MAX_BYTES = 16 * 1024 * 1024
SUBPROCESS_OUTPUT_AGGREGATE_MAX_BYTES = 64 * 1024 * 1024
SUBPROCESS_OUTPUT_READ_CHUNK_BYTES = 64 * 1024
SFTP_DOWNLOAD_DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024
SFTP_DOWNLOAD_HARD_MAX_BYTES = 256 * 1024 * 1024 * 1024
SFTP_DOWNLOAD_READ_CHUNK_BYTES = 256 * 1024
SFTP_DOWNLOAD_MAX_READ_CHUNK_BYTES = 1024 * 1024
SSH_EXEC_FILE_STREAM_METADATA_MAX_BYTES = 16 * 1024
SSH_EXEC_FILE_STREAM_MARKER = "NVDEBUG_EXEC_FILE_STREAM_V1"
SSH_EXEC_FILE_STREAM_SCRIPT = r"""set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
source_path=$1
marker=$2
if [ -L "$source_path" ] || [ ! -f "$source_path" ]; then
    exit 72
fi
exec 3< "$source_path"
identity_format='%d:%i:%s:%f:%u:%g:%Y:%Z:%h'
handle_before=$(stat -Lc "$identity_format" /proc/self/fd/3)
path_before=$(stat -Lc "$identity_format" -- "$source_path")
[ "$handle_before" = "$path_before" ]
printf '%s:HANDLE_BEFORE:%s\n' "$marker" "$handle_before" >&2
printf '%s:PATH_BEFORE:%s\n' "$marker" "$path_before" >&2
cat <&3
handle_after=$(stat -Lc "$identity_format" /proc/self/fd/3)
if [ -L "$source_path" ] || [ ! -f "$source_path" ]; then
    exit 73
fi
path_after=$(stat -Lc "$identity_format" -- "$source_path")
[ "$handle_before" = "$handle_after" ]
[ "$handle_before" = "$path_after" ]
printf '%s:HANDLE_AFTER:%s\n' "$marker" "$handle_after" >&2
printf '%s:PATH_AFTER:%s\n' "$marker" "$path_after" >&2
"""
REMOTE_TRANSFER_DIRECTORY_NAME_PATTERN = re.compile(
    r"\Anvdebug_transfer\.[A-Za-z0-9]{12}\Z",
    re.ASCII,
)
REMOTE_TRANSFER_DIRECTORY_IDENTITY_PATTERN = re.compile(
    r"\A[0-9]{1,20}:[1-9][0-9]{0,19}\Z",
    re.ASCII,
)
REMOTE_TRANSFER_DIRECTORY_CREATE_SCRIPT = r"""set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
remote_root=$1
directory=""
cleanup_failed_creation() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$directory" ] && [ ! -L "$directory" ] && [ -d "$directory" ]; then
        rm -rf -- "$directory"
    fi
    exit "$status"
}
trap cleanup_failed_creation EXIT HUP INT TERM
directory=$(mktemp -d "$remote_root/nvdebug_transfer.XXXXXXXXXXXX")
chmod 700 -- "$directory"
[ ! -L "$directory" ]
[ -d "$directory" ]
[ "$(stat -c '%a' -- "$directory")" = "700" ]
identity=$(stat -c '%d:%i' -- "$directory")
printf '%s\n%s\n' "$directory" "$identity"
trap - EXIT HUP INT TERM
"""
REMOTE_TRANSFER_DIRECTORY_CLEANUP_SCRIPT = r"""set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
directory=$1
expected_identity=$2
if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
    exit 0
fi
[ ! -L "$directory" ]
[ -d "$directory" ]
actual_identity=$(stat -c '%d:%i' -- "$directory")
[ "$actual_identity" = "$expected_identity" ]
rm -rf -- "$directory"
[ ! -e "$directory" ]
[ ! -L "$directory" ]
"""
MANAGED_HOST_TRANSFER_MAX_PATH_BYTES = 4_096
MANAGED_HOST_TRANSFER_CLEANUP_RESERVE_SECONDS = 5.0
DEFAULT_REDFISH_RESPONSE_LIMITS = RedfishResponseLimits()
REDFISH_STRUCTURED_RESPONSE_MAX_BYTES = (
    DEFAULT_REDFISH_RESPONSE_LIMITS.structured_response_max_bytes
)


def _authoritative_cleanup_error(errors: List[BaseException]) -> BaseException:
    """
    Prefer actual interruption, then other process exit, then errors.

    After applying local validation, the function forwards ``errors`` to
    ``select_authoritative_exception`` and preserves its return and exception
    contract.

    Args:
        errors: Entries supplied as ``errors`` without transferring container
            ownership.

    Returns:
        A ``BaseException`` describing authoritative cleanup error.
    """

    return select_authoritative_exception(errors)


class SSHOutputLimitExceeded(ValueError):
    """
    Report that a remote command exceeded a finite transport output limit.

    Callers receive this exception when the SSH output limit exceeded invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


@dataclass(frozen=True)
class SSHProcessOutputLimits:
    """
    Validated stdout, stderr, and combined limits for one SSH process.

    The immutable record keeps ``stdout_max_bytes``, ``stderr_max_bytes``,
    ``aggregate_max_bytes``, and ``read_chunk_bytes`` together so consumers
    observe one SSH process output state. Construction validates cross-field
    invariants before the instance is exposed.

    Attributes:
        stdout_max_bytes: Byte count recorded for stdout max.
        stderr_max_bytes: Byte count recorded for stderr max.
        aggregate_max_bytes: Byte count recorded for aggregate max.
        read_chunk_bytes: Byte count recorded for read chunk.
    """

    stdout_max_bytes: int = SSH_STDOUT_MAX_BYTES
    stderr_max_bytes: int = SSH_STDERR_MAX_BYTES
    aggregate_max_bytes: int = SSH_OUTPUT_AGGREGATE_MAX_BYTES
    read_chunk_bytes: int = SSH_OUTPUT_READ_CHUNK_BYTES

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized SSHProcessOutputLimits state.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Raises:
            ValueError: If the ssh process ``name`` is not a positive integer;
                SSH process ``name`` cannot exceed
                ``PROCESS_OUTPUT_MAX_LIMIT_BYTES``; SSH process read_chunk_bytes
                cannot exceed ``SSH_OUTPUT_READ_CHUNK_BYTES``; or SSH process
                aggregate_max_bytes must cover each per-stream limit; or another
                input invariant is violated.
        """
        values = {
            "stdout_max_bytes": self.stdout_max_bytes,
            "stderr_max_bytes": self.stderr_max_bytes,
            "aggregate_max_bytes": self.aggregate_max_bytes,
            "read_chunk_bytes": self.read_chunk_bytes,
        }
        for name, value in values.items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"SSH process {name} must be a positive integer")
        for name in (
            "stdout_max_bytes",
            "stderr_max_bytes",
            "aggregate_max_bytes",
        ):
            if values[name] > PROCESS_OUTPUT_MAX_LIMIT_BYTES:
                raise ValueError(
                    f"SSH process {name} cannot exceed {PROCESS_OUTPUT_MAX_LIMIT_BYTES}"
                )
        if self.read_chunk_bytes > SSH_OUTPUT_READ_CHUNK_BYTES:
            raise ValueError(
                f"SSH process read_chunk_bytes cannot exceed "
                f"{SSH_OUTPUT_READ_CHUNK_BYTES}"
            )
        if max(self.stdout_max_bytes, self.stderr_max_bytes) > self.aggregate_max_bytes:
            raise ValueError(
                "SSH process aggregate_max_bytes must cover each per-stream limit"
            )
        if self.aggregate_max_bytes > self.stdout_max_bytes + self.stderr_max_bytes:
            raise ValueError(
                "SSH process aggregate_max_bytes cannot exceed both stream limits"
            )
        if self.read_chunk_bytes > min(
            self.stdout_max_bytes,
            self.stderr_max_bytes,
            self.aggregate_max_bytes,
        ):
            raise ValueError(
                "SSH process read_chunk_bytes cannot exceed an output limit"
            )


DEFAULT_SSH_PROCESS_OUTPUT_LIMITS = SSHProcessOutputLimits()


@dataclass
class _SSHOutputBudget:
    """
    Atomically account for both SSH output streams on one event loop.

    The coherent record keeps ``limits``, ``stdout_bytes``, ``stderr_bytes``,
    and ``aggregate_bytes`` together so consumers observe one SSH output budget
    state. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        limits: Limits retained as part of the record's public state.
        stdout_bytes: Byte count recorded for stdout.
        stderr_bytes: Byte count recorded for stderr.
        aggregate_bytes: Byte count recorded for aggregate.
    """

    limits: SSHProcessOutputLimits
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    aggregate_bytes: int = 0

    def consume(self, stream_name: str, chunk_bytes: int) -> None:
        """
        Consume the supplied value under the current boundary.

        The implementation uses ``stream_name`` and ``chunk_bytes`` to consume
        the supplied value under the current boundary. It updates
        ``aggregate_bytes``, ``stderr_bytes``, and ``stdout_bytes`` on the
        instance as part of that state transition. If the function cannot
        consume the supplied value under the current boundary, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            stream_name: Stable stream name used for lookup and operator-facing
                diagnostics.
            chunk_bytes: Numeric chunk bytes used while the operation performs
                bounded accounting.

        Raises:
            ValueError: If SSH output stream identity is invalid.
            SSHOutputLimitExceeded: If SSH command ``stream_name`` exceeded its
                ``stream_limit``-byte transport limit; or SSH command aggregate
                output exceeded its ``aggregate_max_bytes``-byte transport
                limit.
        """
        if stream_name == "stdout":
            current = self.stdout_bytes
            stream_limit = self.limits.stdout_max_bytes
        elif stream_name == "stderr":
            current = self.stderr_bytes
            stream_limit = self.limits.stderr_max_bytes
        else:
            raise ValueError("SSH output stream identity is invalid")

        if chunk_bytes > stream_limit - current:
            raise SSHOutputLimitExceeded(
                f"SSH command {stream_name} exceeded its "
                f"{stream_limit}-byte transport limit"
            )
        if chunk_bytes > self.limits.aggregate_max_bytes - self.aggregate_bytes:
            raise SSHOutputLimitExceeded(
                "SSH command aggregate output exceeded its "
                f"{self.limits.aggregate_max_bytes}-byte transport limit"
            )

        if stream_name == "stdout":
            self.stdout_bytes = current + chunk_bytes
        else:
            self.stderr_bytes = current + chunk_bytes
        self.aggregate_bytes += chunk_bytes


class SubprocessOutputLimitExceeded(ValueError):
    """
    Report that a local child exceeded a finite captured-output limit.

    Callers receive this exception when the subprocess output limit exceeded
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


@dataclass(frozen=True)
class SubprocessOutputLimits:
    """
    Validated stdout, stderr, and combined limits for one local child.

    The immutable record keeps ``stdout_max_bytes``, ``stderr_max_bytes``,
    ``aggregate_max_bytes``, and ``read_chunk_bytes`` together so consumers
    observe one subprocess output state. Construction validates cross-field
    invariants before the instance is exposed.

    Attributes:
        stdout_max_bytes: Byte count recorded for stdout max.
        stderr_max_bytes: Byte count recorded for stderr max.
        aggregate_max_bytes: Byte count recorded for aggregate max.
        read_chunk_bytes: Byte count recorded for read chunk.
    """

    stdout_max_bytes: int = SUBPROCESS_STDOUT_MAX_BYTES
    stderr_max_bytes: int = SUBPROCESS_STDERR_MAX_BYTES
    aggregate_max_bytes: int = SUBPROCESS_OUTPUT_AGGREGATE_MAX_BYTES
    read_chunk_bytes: int = SUBPROCESS_OUTPUT_READ_CHUNK_BYTES

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized SubprocessOutputLimits state.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Raises:
            ValueError: If the subprocess ``name`` is not a positive integer;
                subprocess ``name`` cannot exceed
                ``PROCESS_OUTPUT_MAX_LIMIT_BYTES``; subprocess read_chunk_bytes
                cannot exceed ``SUBPROCESS_OUTPUT_READ_CHUNK_BYTES``; or
                subprocess aggregate_max_bytes must cover each per-stream limit;
                or another input invariant is violated.
        """
        values = {
            "stdout_max_bytes": self.stdout_max_bytes,
            "stderr_max_bytes": self.stderr_max_bytes,
            "aggregate_max_bytes": self.aggregate_max_bytes,
            "read_chunk_bytes": self.read_chunk_bytes,
        }
        for name, value in values.items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"Subprocess {name} must be a positive integer")
        for name in (
            "stdout_max_bytes",
            "stderr_max_bytes",
            "aggregate_max_bytes",
        ):
            if values[name] > PROCESS_OUTPUT_MAX_LIMIT_BYTES:
                raise ValueError(
                    f"Subprocess {name} cannot exceed {PROCESS_OUTPUT_MAX_LIMIT_BYTES}"
                )
        if self.read_chunk_bytes > SUBPROCESS_OUTPUT_READ_CHUNK_BYTES:
            raise ValueError(
                "Subprocess read_chunk_bytes cannot exceed "
                f"{SUBPROCESS_OUTPUT_READ_CHUNK_BYTES}"
            )
        if max(self.stdout_max_bytes, self.stderr_max_bytes) > self.aggregate_max_bytes:
            raise ValueError(
                "Subprocess aggregate_max_bytes must cover each per-stream limit"
            )
        if self.aggregate_max_bytes > self.stdout_max_bytes + self.stderr_max_bytes:
            raise ValueError(
                "Subprocess aggregate_max_bytes cannot exceed both stream limits"
            )
        if self.read_chunk_bytes > min(
            self.stdout_max_bytes,
            self.stderr_max_bytes,
            self.aggregate_max_bytes,
        ):
            raise ValueError(
                "Subprocess read_chunk_bytes cannot exceed an output limit"
            )


DEFAULT_SUBPROCESS_OUTPUT_LIMITS = SubprocessOutputLimits()


@dataclass
class _SubprocessOutputBudget:
    """
    Account for both child output streams without an intervening await.

    The coherent record keeps ``limits``, ``stdout_bytes``, ``stderr_bytes``,
    and ``aggregate_bytes`` together so consumers observe one subprocess output
    budget state. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        limits: Limits retained as part of the record's public state.
        stdout_bytes: Byte count recorded for stdout.
        stderr_bytes: Byte count recorded for stderr.
        aggregate_bytes: Byte count recorded for aggregate.
    """

    limits: SubprocessOutputLimits
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    aggregate_bytes: int = 0

    def consume(self, stream_name: str, chunk_bytes: int) -> None:
        """
        Consume the supplied value under the current boundary.

        The implementation uses ``stream_name`` and ``chunk_bytes`` to consume
        the supplied value under the current boundary. It updates
        ``aggregate_bytes``, ``stderr_bytes``, and ``stdout_bytes`` on the
        instance as part of that state transition. If the function cannot
        consume the supplied value under the current boundary, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            stream_name: Stable stream name used for lookup and operator-facing
                diagnostics.
            chunk_bytes: Numeric chunk bytes used while the operation performs
                bounded accounting.

        Raises:
            ValueError: If subprocess output stream identity is invalid.
            SubprocessOutputLimitExceeded: If subprocess ``stream_name``
                exceeded its ``stream_limit``-byte capture limit; or subprocess
                aggregate output exceeded its ``aggregate_max_bytes``-byte
                capture limit.
        """
        if stream_name == "stdout":
            current = self.stdout_bytes
            stream_limit = self.limits.stdout_max_bytes
        elif stream_name == "stderr":
            current = self.stderr_bytes
            stream_limit = self.limits.stderr_max_bytes
        else:
            raise ValueError("Subprocess output stream identity is invalid")

        if chunk_bytes > stream_limit - current:
            raise SubprocessOutputLimitExceeded(
                f"Subprocess {stream_name} exceeded its "
                f"{stream_limit}-byte capture limit"
            )
        if chunk_bytes > self.limits.aggregate_max_bytes - self.aggregate_bytes:
            raise SubprocessOutputLimitExceeded(
                "Subprocess aggregate output exceeded its "
                f"{self.limits.aggregate_max_bytes}-byte capture limit"
            )

        if stream_name == "stdout":
            self.stdout_bytes = current + chunk_bytes
        else:
            self.stderr_bytes = current + chunk_bytes
        self.aggregate_bytes += chunk_bytes


class SFTPDownloadError(ValueError):
    """
    Report that a remote file could not be acquired under its contract.

    Callers receive this exception when the sftp download error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


class SFTPDownloadLimitExceeded(SFTPDownloadError):
    """
    Report that a remote file exceeded its governed transfer byte limit.

    Callers receive this exception when the sftp download limit exceeded
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


@dataclass(frozen=True)
class _OwnedSFTPStagingLeaf:
    """
    Bind cleanup and publication to the exact temporary inode we created.

    The immutable record keeps ``path``, ``name``, ``device``, and ``inode``
    together so consumers observe one owned sftp staging leaf state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        name: Canonical text used as name.
        device: Numeric device retained by this record.
        inode: Numeric inode retained by this record.
    """

    path: Path
    name: str
    device: int
    inode: int


@dataclass(frozen=True)
class _SSHExecFileIdentity:
    """
    Retain one remote opened-file and path identity snapshot.

    The immutable record represents the numeric fields emitted by the governed
    remote exec-stream script. Comparing the complete record before and after
    streaming prevents a same-size path replacement from being accepted.

    Attributes:
        device: Numeric remote filesystem device identifier.
        inode: Numeric remote inode identifier.
        size: Numeric remote file size in bytes.
        mode: Numeric remote file type and permission bits.
        uid: Numeric remote owner identifier.
        gid: Numeric remote group identifier.
        mtime: Numeric remote modification timestamp in seconds.
        ctime: Numeric remote metadata-change timestamp in seconds.
        links: Numeric remote hard-link count.
    """

    device: int
    inode: int
    size: int
    mode: int
    uid: int
    gid: int
    mtime: int
    ctime: int
    links: int


@dataclass(frozen=True)
class _RemoteTransferDirectory:
    """
    Validated path and inode identity returned by remote ``mktemp``.

    The immutable record keeps ``root``, ``path``, and ``identity`` together so
    consumers observe one remote transfer directory state. Consumers receive
    the fields as one unit instead of assembling partial state.

    Attributes:
        root: Configured remote parent beneath which ``path`` was allocated.
        path: Validated filesystem location associated with path.
        identity: Canonical text used as identity.
    """

    root: str
    path: str
    identity: str


_SFTP_STABLE_IDENTITY_FIELDS = (
    "type",
    "size",
    "uid",
    "gid",
    "owner",
    "group",
    "permissions",
    "mtime",
    "mtime_ns",
    "ctime",
    "ctime_ns",
    "crtime",
    "crtime_ns",
    "nlink",
)


REDFISH_ERROR_RESPONSE_MAX_BYTES = (
    DEFAULT_REDFISH_RESPONSE_LIMITS.error_response_max_bytes
)
REDFISH_ERROR_EVIDENCE_MAX_BYTES = (
    DEFAULT_REDFISH_RESPONSE_LIMITS.error_evidence_max_bytes
)
REDFISH_ERROR_EVIDENCE_AGGREGATE_MAX_BYTES = (
    DEFAULT_REDFISH_RESPONSE_LIMITS.error_evidence_aggregate_max_bytes
)
REDFISH_ERROR_EVIDENCE_MAX_RESPONSES = (
    DEFAULT_REDFISH_RESPONSE_LIMITS.error_evidence_max_responses
)
REDFISH_PREFLIGHT_RESPONSE_MAX_BYTES = (
    DEFAULT_REDFISH_RESPONSE_LIMITS.preflight_response_max_bytes
)
REDFISH_RESPONSE_CHUNK_BYTES = 64 * 1024
REDFISH_SPOOL_FREE_SPACE_RESERVE_BYTES = 512 * 1024 * 1024
REDFISH_SPOOL_PREFIX_BYTES = 512

# A successful SSH transport connection is not sufficient proof that the BMC
# command service is usable. Require a marker from a real command before
# declaring the SSH preflight successful.
BMC_SSH_PREFLIGHT_SENTINEL = "__NVDEBUG_BMC_SSH_PREFLIGHT_OK__"
BMC_SSH_PREFLIGHT_COMMAND = f"printf '%s\n' {shlex.quote(BMC_SSH_PREFLIGHT_SENTINEL)}"
BMC_SSH_PREFLIGHT_TIMEOUT_SECONDS = 20


@dataclass(frozen=True)
class _HostReachabilityProbe:
    """
    Retain the bounded outcome of one ICMP reachability probe.

    The outcome distinguishes failures which make a transport attempt invalid
    from soft ICMP failures which do not prove that Redfish, IPMI, or SSH is
    unavailable.

    Attributes:
        reachable: Whether the endpoint answered the ICMP probe.
        failure_kind: Stable failure category, or an empty string on success.
    """

    reachable: bool
    failure_kind: str = ""

    @property
    def blocks_transport(self) -> bool:
        """
        Return whether the failure makes a protocol attempt invalid.

        DNS resolution failures, invalid targets, and a missing route are
        authoritative before a socket is opened. A silent or unavailable ICMP
        probe is not authoritative because services may still accept traffic.

        Returns:
            Whether the caller should skip the actual protocol attempt.
        """
        return not self.reachable and self.failure_kind in {
            "invalid_target",
            "resolution_failure",
            "no_route",
        }


def _classify_ping_probe_failure(
    stdout: Union[str, bytes, None],
    stderr: Union[str, bytes, None],
    *,
    returncode: Optional[int] = None,
) -> str:
    """
    Classify bounded ping output without exposing endpoint diagnostics.

    Only stable local categories are returned. Raw subprocess output may
    contain an operator-supplied endpoint and is deliberately not propagated to
    logs, reports, or status messages.

    Args:
        stdout: Captured standard output from the bounded ping process.
        stderr: Captured standard error from the bounded ping process.
        returncode: Optional ping process exit status.

    Returns:
        A stable reachability failure category.
    """

    def normalize(value: Union[str, bytes, None]) -> str:
        """
        Normalize one captured stream for local token classification.

        Byte streams are decoded with replacement so malformed subprocess
        output cannot escape the classifier or change preflight control flow.

        Args:
            value: Captured stream value to decode without raising.

        Returns:
            Lowercase diagnostic text used only inside this classifier.
        """
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace").casefold()
        return str(value or "").casefold()

    diagnostic = "\n".join((normalize(stdout), normalize(stderr)))
    if any(
        marker in diagnostic
        for marker in (
            "name or service not known",
            "temporary failure in name resolution",
            "unknown host",
            "cannot resolve",
            "bad address",
            "nodename nor servname provided",
        )
    ):
        return "resolution_failure"
    if any(
        marker in diagnostic
        for marker in (
            "network is unreachable",
            "no route to host",
            "destination host unreachable",
        )
    ):
        return "no_route"
    if any(
        marker in diagnostic
        for marker in (
            "operation not permitted",
            "permission denied",
            "command not found",
        )
    ):
        return "probe_unavailable"
    return "no_reply" if returncode == 1 else "probe_error"


SAFE_REDFISH_RESPONSE_HEADERS = frozenset(
    {
        "content-length",
        "content-type",
        "location",
        "retry-after",
        "taskmonitor",
    }
)

INTERNAL_CONFIG_KEYS = {
    "__explicit_fields",
    "__explicit_tool_config_fields",
    "__referenced_config_data",
}


@dataclass(frozen=True, repr=False)
class _HostSSHConnectSnapshot:
    """
    Immutable route inputs retained only while the pool owns that route.

    The immutable record keeps ``dut_id``, ``host``, ``port``, ``username``, and
    ``password`` together so consumers observe one host SSH connect state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        dut_id: Canonical text used as DUT identifier.
        host: Canonical text used as host.
        port: Numeric port retained by this record.
        username: Canonical text used as username.
        password: Canonical text used as password.
        ssh_key_path: Validated filesystem location associated with SSH key
            path.
        passwordless: Whether passwordless applies to this record.
        host_key_policy: Canonical text used as host key policy.
        known_hosts_file: Canonical text used as known hosts file.
        host_key_alias: Canonical text used as host key alias.
        proxy_host: Canonical text used as proxy host.
        proxy_port: Numeric proxy port retained by this record.
        proxy_username: Canonical text used as proxy username.
        proxy_password: Canonical text used as proxy password.
        proxy_key_path: Validated filesystem location associated with proxy key
            path.
        proxy_passwordless: Whether proxy passwordless applies to this record.
        proxy_host_key_policy: Canonical text used as proxy host key policy.
        proxy_known_hosts_file: Canonical text used as proxy known hosts file.
    """

    dut_id: str
    host: str
    port: int
    username: str
    password: Optional[str] = field(repr=False)
    ssh_key_path: Optional[str]
    passwordless: bool
    host_key_policy: str
    known_hosts_file: Optional[str]
    host_key_alias: Optional[str]
    proxy_host: Optional[str]
    proxy_port: Optional[int]
    proxy_username: Optional[str]
    proxy_password: Optional[str] = field(repr=False)
    proxy_key_path: Optional[str]
    proxy_passwordless: bool
    proxy_host_key_policy: str
    proxy_known_hosts_file: Optional[str]

    def __repr__(self) -> str:
        """
        Return a developer-facing representation of the _HostSSHConnectSnapshot.

        The implementation uses current instance state to produce a
        developer-facing representation of the _HostSSHConnectSnapshot.

        Returns:
            The canonical repr text.
        """
        return "<host-ssh-connect-snapshot>"


class HMCForwardingConfigurationError(ValueError):
    """
    Raised when a selected HMC forwarding route is not usable.

    Callers receive this exception when the HMC forwarding configuration error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


class RedfishResponseTooLarge(ValueError):
    """
    Raised before retaining a Redfish response beyond its byte budget.

    Callers receive this exception when the Redfish response too large invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


class RedfishEncodedResponseTooLarge(RedfishResponseTooLarge):
    """
    Raised when encoded input exceeds its decoded response budget envelope.

    The type gives the Redfish encoded response too large responsibility a
    stable runtime boundary. Callers use the declared Python protocol instead of
    depending on its representation.
    """


class RedfishDecodedResponseTooLarge(RedfishResponseTooLarge):
    """
    Raised after accepting the decoded ceiling and proving one byte remains.

    The type gives the Redfish decoded response too large responsibility a
    stable runtime boundary. Callers use the declared Python protocol instead of
    depending on its representation.
    """


class RedfishSpoolSpaceError(OSError):
    """
    Raised when a complete raw response cannot be staged without filling disk.

    Callers receive this exception when the Redfish spool space error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


def _resolved_redfish_limit(
    holder: Any,
    field_name: str,
    compatibility_default: int,
) -> int:
    """
    Read a configured limit while preserving lightweight legacy test doubles.

    The implementation uses ``holder``, ``field_name``, and
    ``compatibility_default`` to read a configured limit while preserving
    lightweight legacy test doubles. Parsing or I/O must finish before the
    validated representation is made available to the caller.

    Args:
        holder: Holder consumed while the function attempts to read a configured
            limit while preserving lightweight legacy test doubles.
        field_name: Field label included in validation failures for the selected
            input.
        compatibility_default: Numeric compatibility default used while the
            operation performs bounded accounting.

    Returns:
        The numeric resolved Redfish limit.
    """

    profile = getattr(holder, "redfish_response_limits", None)
    value = getattr(profile, field_name, compatibility_default)
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool)
        else compatibility_default
    )


def _redfish_content_encoding(
    response: aiohttp.ClientResponse,
) -> Optional[str]:
    """
    Return the single supported HTTP content coding, if any.

    The implementation uses ``response`` to produce the single supported HTTP
    content coding, if any. Remote I/O uses the configured transport policy and
    returns only after its response or failure has been observed. If the
    function cannot produce the single supported HTTP content coding, if any,
    its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        response: Transport response governed by the configured authentication
            and trust policy.

    Returns:
        The validated ``encoding``, or ``None`` when no value qualifies.

    Raises:
        aiohttp.ClientPayloadError: If unsupported Redfish HTTP content
            encoding.
    """

    headers = getattr(response, "headers", None)
    raw_encoding = None
    if isinstance(headers, Mapping):
        raw_encoding = headers.get("Content-Encoding")
        if raw_encoding is None:
            raw_encoding = headers.get("content-encoding")
    if raw_encoding is None:
        return None
    encoding = str(raw_encoding).strip().lower()
    if encoding in {"", "identity"}:
        return None
    if encoding in {"gzip", "x-gzip", "deflate"}:
        return encoding
    raise aiohttp.ClientPayloadError("Unsupported Redfish HTTP content encoding")


def _redfish_encoded_input_limit(decoded_limit: int) -> int:
    """
    Return a finite envelope allowing ordinary DEFLATE framing overhead.

    zlib's documented compressBound relationship, plus a small envelope for gzip
    framing and transport implementations. Empty-block amplification is
    deliberately not allowed to consume unbounded encoded input.

    Args:
        decoded_limit: Upper bound enforced for decoded limit; the consuming
            boundary rejects or truncates values that exceed it.

    Returns:
        The numeric Redfish encoded input limit.
    """

    decoded_limit = max(1, int(decoded_limit))
    # zlib's documented compressBound relationship, plus a small envelope for
    # gzip framing and transport implementations. Empty-block amplification is
    # deliberately not allowed to consume unbounded encoded input.
    bounded = (
        decoded_limit
        + (decoded_limit >> 12)
        + (decoded_limit >> 14)
        + (decoded_limit >> 25)
        + 64
    )
    return min(REDFISH_TRANSPORT_CONTENT_LENGTH_MAX_BYTES, bounded)


def _redfish_deflate_uses_zlib_wrapper(prefix: bytes) -> bool:
    """
    Return the canonical RFC 1950 decision for an exact two-byte prefix.

    The implementation uses ``prefix`` to produce the canonical RFC 1950
    decision for an exact two-byte prefix. If the function cannot produce the
    canonical RFC 1950 decision for an exact two-byte prefix, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        prefix: Bounded byte sequence supplied as prefix.

    Returns:
        Whether the canonical RFC 1950 decision for an exact two-byte prefix
        operation succeeds.

    Raises:
        ValueError: If deflate wrapper detection lacks exactly two bytes.
    """

    if len(prefix) != 2:
        raise ValueError("DEFLATE wrapper detection requires exactly two bytes")
    cmf, flg = prefix
    return (
        cmf & 0x0F == zlib.DEFLATED and cmf >> 4 <= 7 and ((cmf << 8) | flg) % 31 == 0
    )


async def _iter_redfish_decoded_chunks(
    response: aiohttp.ClientResponse,
    *,
    decoded_chunk_bytes: int = REDFISH_RESPONSE_CHUNK_BYTES,
    encoded_max_bytes: Optional[int] = None,
    decoded_max_bytes: Optional[int] = None,
) -> AsyncIterator[bytes]:
    """
    Yield bounded decoded chunks without aiohttp's eager decompression.

    Production requests disable aiohttp auto-decompression before any response
    bytes are received. Limiting each zlib call prevents a small compressed
    transport chunk from expanding into an arbitrarily large allocation before
    the owning response reader can enforce its total decoded-byte budget.

    Args:
        response: Transport response governed by the configured authentication
            and trust policy.
        decoded_chunk_bytes: Numeric decoded chunk bytes used while the
            operation performs bounded accounting.
        encoded_max_bytes: Upper bound enforced for encoded max bytes; the
            consuming boundary rejects or truncates values that exceed it.
        decoded_max_bytes: Upper bound enforced for decoded max bytes; the
            consuming boundary rejects or truncates values that exceed it.

    Yields:
        Each Redfish decoded chunks admitted by the operation, in deterministic
        iteration order.

    Raises:
        RedfishDecodedResponseTooLarge: If decoded Redfish response exceeds its
            bounded output envelope.
        RedfishEncodedResponseTooLarge: If encoded Redfish response exceeds its
            bounded input envelope.
        aiohttp.ClientPayloadError: If invalid Redfish HTTP content encoding;
            redfish HTTP content decoder made no progress; incomplete Redfish
            HTTP content encoding; or incomplete or concatenated Redfish HTTP
            content encoding.
    """

    decoded_chunk_bytes = max(1, int(decoded_chunk_bytes))
    if encoded_max_bytes is not None:
        encoded_max_bytes = max(1, int(encoded_max_bytes))
    if decoded_max_bytes is not None:
        decoded_max_bytes = max(1, int(decoded_max_bytes))
    encoding = _redfish_content_encoding(response)
    decoded_size = 0

    def accepted_decoded_chunk(decoded: bytes) -> Tuple[bytes, bool]:
        """
        Return accepted bytes and whether one decoded byte crossed the cap.

        The implementation uses ``decoded`` to produce accepted bytes and
        whether one decoded byte crossed the cap.

        Args:
            decoded: Bounded byte sequence supplied as decoded.

        Returns:
            A tuple containing ``byte sequence`` and ``outcome flag`` in that
            order.
        """

        nonlocal decoded_size
        if decoded_max_bytes is None:
            decoded_size += len(decoded)
            return decoded, False
        remaining = decoded_max_bytes - decoded_size
        accepted = decoded[:remaining]
        decoded_size += len(accepted)
        return accepted, len(decoded) > len(accepted)

    if encoding is None:
        content_read = getattr(response.content, "read", None)
        if callable(content_read):
            while True:
                read_size = decoded_chunk_bytes
                if decoded_max_bytes is not None:
                    read_size = max(
                        1,
                        min(
                            read_size,
                            decoded_max_bytes - decoded_size + 1,
                        ),
                    )
                chunk = await content_read(read_size)
                if not chunk:
                    break
                accepted, crossed_limit = accepted_decoded_chunk(bytes(chunk))
                if accepted:
                    yield accepted
                if crossed_limit:
                    raise RedfishDecodedResponseTooLarge(
                        "Decoded Redfish response exceeds its bounded output envelope"
                    )
        else:
            async for chunk in response.content.iter_chunked(decoded_chunk_bytes):
                if not chunk:
                    continue
                accepted, crossed_limit = accepted_decoded_chunk(bytes(chunk))
                if accepted:
                    yield accepted
                if crossed_limit:
                    raise RedfishDecodedResponseTooLarge(
                        "Decoded Redfish response exceeds its bounded output envelope"
                    )
        return

    # HTTP "deflate" canonically means an RFC 1950 zlib stream, but deployed
    # servers also send raw RFC 1951. Two bytes identify the canonical wrapper,
    # so retain only that bounded prefix before choosing one decoder. A raw
    # stream whose first two bytes also form a valid RFC 1950 CMF/FLG pair is
    # intentionally interpreted as the canonical zlib representation: HTTP
    # provides no disambiguator, and retrying raw after an arbitrarily late
    # checksum failure would require unbounded replay buffering or double work.
    decoder = (
        zlib.decompressobj(16 + zlib.MAX_WBITS)
        if encoding in {"gzip", "x-gzip"}
        else None
    )
    undecided_prefix = bytearray()

    def initialize_deflate_decoder(pending: bytes) -> Tuple[Any, bytes]:
        """
        Choose the zlib or raw DEFLATE decoder from a bounded prefix.

        The implementation uses ``pending`` to choose the zlib or raw DEFLATE
        decoder from a bounded prefix.

        Args:
            pending: Bounded byte sequence supplied as pending.

        Returns:
            A tuple containing ``returned value`` and ``byte sequence`` in that
            order.
        """

        nonlocal decoder
        needed = 2 - len(undecided_prefix)
        undecided_prefix.extend(pending[:needed])
        pending = pending[needed:]
        if len(undecided_prefix) < 2:
            return None, pending
        is_zlib_wrapper = _redfish_deflate_uses_zlib_wrapper(bytes(undecided_prefix))
        decoder = zlib.decompressobj(
            zlib.MAX_WBITS if is_zlib_wrapper else -zlib.MAX_WBITS
        )
        selected_input = bytes(undecided_prefix) + pending
        undecided_prefix.clear()
        return decoder, selected_input

    encoded_size = 0
    async for raw_chunk in response.content.iter_chunked(decoded_chunk_bytes):
        accepted_raw = raw_chunk
        crossed_encoded_limit = False
        if encoded_max_bytes is not None:
            remaining_encoded = encoded_max_bytes - encoded_size
            accepted_raw = raw_chunk[:remaining_encoded]
            crossed_encoded_limit = len(raw_chunk) > len(accepted_raw)
        encoded_size += len(accepted_raw)
        pending = bytes(accepted_raw)
        if decoder is None:
            decoder, pending = initialize_deflate_decoder(pending)
            if decoder is None:
                raw_at_eof = getattr(response.content, "at_eof", None)
                if crossed_encoded_limit or (
                    encoded_max_bytes is not None
                    and encoded_size == encoded_max_bytes
                    and not (callable(raw_at_eof) and raw_at_eof())
                ):
                    raise RedfishEncodedResponseTooLarge(
                        "Encoded Redfish response exceeds its bounded input envelope"
                    )
                continue
        while pending:
            pending_size = len(pending)
            output_limit = decoded_chunk_bytes
            if decoded_max_bytes is not None:
                output_limit = max(
                    1,
                    min(
                        output_limit,
                        decoded_max_bytes - decoded_size + 1,
                    ),
                )
            try:
                decoded = decoder.decompress(pending, output_limit)
            except zlib.error as error:
                raise aiohttp.ClientPayloadError(
                    "Invalid Redfish HTTP content encoding"
                ) from error
            pending = decoder.unconsumed_tail
            if decoded:
                accepted, crossed_decoded_limit = accepted_decoded_chunk(decoded)
                if accepted:
                    yield accepted
                if crossed_decoded_limit:
                    raise RedfishDecodedResponseTooLarge(
                        "Decoded Redfish response exceeds its bounded output envelope"
                    )
            if pending and len(pending) >= pending_size and not decoded:
                raise aiohttp.ClientPayloadError(
                    "Redfish HTTP content decoder made no progress"
                )

        raw_at_eof = getattr(response.content, "at_eof", None)
        if crossed_encoded_limit or (
            encoded_max_bytes is not None
            and encoded_size == encoded_max_bytes
            and not (callable(raw_at_eof) and raw_at_eof())
        ):
            raise RedfishEncodedResponseTooLarge(
                "Encoded Redfish response exceeds its bounded input envelope"
            )

    if decoder is None:
        raise aiohttp.ClientPayloadError("Incomplete Redfish HTTP content encoding")
    # A max_length decode can leave bounded output inside zlib even after all
    # transport input was accepted. Probe it with the remaining allowance plus
    # one byte so exact-limit completion succeeds without a large flush.
    while True:
        output_limit = decoded_chunk_bytes
        if decoded_max_bytes is not None:
            output_limit = max(
                1,
                min(
                    output_limit,
                    decoded_max_bytes - decoded_size + 1,
                ),
            )
        try:
            decoded = decoder.decompress(b"", output_limit)
        except zlib.error as error:
            raise aiohttp.ClientPayloadError(
                "Invalid Redfish HTTP content encoding"
            ) from error
        if not decoded:
            break
        accepted, crossed_decoded_limit = accepted_decoded_chunk(decoded)
        if accepted:
            yield accepted
        if crossed_decoded_limit:
            raise RedfishDecodedResponseTooLarge(
                "Decoded Redfish response exceeds its bounded output envelope"
            )
    if not decoder.eof or decoder.unused_data:
        raise aiohttp.ClientPayloadError(
            "Incomplete or concatenated Redfish HTTP content encoding"
        )


async def _read_redfish_body_bounded(
    response: aiohttp.ClientResponse,
    max_bytes: int,
    *,
    category: str = "response",
) -> bytes:
    """
    Read an aiohttp response without buffering more than ``max_bytes``.

    After applying local validation, the function forwards ``response``,
    ``max_bytes``, and ``category`` to ``bytes`` and preserves its return and
    exception contract. Parsing or I/O must finish before the validated
    representation is made available to the caller. Owned asynchronous work is
    awaited before return, so completion does not leave an unobserved task
    behind. Remote I/O uses the configured transport policy and returns only
    after its response or failure has been observed.

    Args:
        response: Transport response governed by the configured authentication
            and trust policy.
        max_bytes: Upper bound enforced for max bytes; the consuming boundary
            rejects or truncates values that exceed it.
        category: Text supplied as category in the format accepted by this
            function.

    Returns:
        The Redfish body bounded bytes.

    Raises:
        RedfishResponseTooLarge: If redfish ``category`` exceeds
            ``max_bytes``-byte limit.
    """
    content_encoding = _redfish_content_encoding(response)
    headers = getattr(response, "headers", None)
    declared_length = None
    if content_encoding is None and isinstance(headers, Mapping):
        declared_length = headers.get("Content-Length")
        if declared_length is None:
            declared_length = headers.get("content-length")
    if declared_length is not None:
        try:
            parsed_length = int(declared_length)
        except (TypeError, ValueError):
            parsed_length = None
        if parsed_length is not None and parsed_length > max_bytes:
            raise RedfishResponseTooLarge(
                f"Redfish {category} exceeds {max_bytes}-byte limit"
            )

    body = bytearray()
    try:
        async for chunk in _iter_redfish_decoded_chunks(
            response,
            decoded_chunk_bytes=min(REDFISH_RESPONSE_CHUNK_BYTES, max_bytes),
            encoded_max_bytes=(
                _redfish_encoded_input_limit(max_bytes)
                if content_encoding is not None
                else None
            ),
            decoded_max_bytes=max_bytes,
        ):
            body.extend(chunk)
    except RedfishDecodedResponseTooLarge:
        raise RedfishResponseTooLarge(
            f"Redfish {category} exceeds {max_bytes}-byte limit"
        ) from None
    return bytes(body)


def _decode_redfish_body(response: aiohttp.ClientResponse, body: bytes) -> str:
    """
    Decode a bounded Redfish body, replacing malformed text safely.

    The implementation uses ``response`` and ``body`` to decode a bounded
    Redfish body, replacing malformed text safely. Parsing or I/O must finish
    before the validated representation is made available to the caller.

    Args:
        response: Transport response governed by the configured authentication
            and trust policy.
        body: Bounded byte sequence supplied as body.

    Returns:
        The canonical Redfish body text.
    """
    encoding = getattr(response, "charset", None)
    if not isinstance(encoding, str) or not encoding:
        encoding = "utf-8"
    try:
        return body.decode(encoding, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


async def _read_redfish_error_body_with_evidence(
    response: aiohttp.ClientResponse,
    max_bytes: int,
    *,
    evidence_max_bytes: int = REDFISH_ERROR_EVIDENCE_MAX_BYTES,
    http_status: Optional[int] = None,
    attempt_number: Optional[int] = None,
) -> Tuple[Optional[bytes], Optional[TruncatedRedfishErrorBody]]:
    """
    Read an error body without losing bounded evidence above its ceiling.

    The decoded stream is aborted as soon as ``max_bytes`` are accepted and
    unread content remains. Only bytes accepted before that hard ceiling can
    contribute to the fixed head/tail windows or digest. Payload and decoding
    failures are recorded as secondary evidence while the HTTP status remains
    the primary request outcome. Caller cancellation is never intercepted.

    Args:
        response: Transport response governed by the configured authentication
            and trust policy.
        max_bytes: Upper bound enforced for max bytes; the consuming boundary
            rejects or truncates values that exceed it.
        evidence_max_bytes: Upper bound enforced for evidence max bytes; the
            consuming boundary rejects or truncates values that exceed it.
        http_status: Optional HTTP status; ``None`` selects the function's
            default behavior.
        attempt_number: Optional attempt number; ``None`` selects the function's
            default behavior.

    Returns:
        A tuple containing ``byte sequence`` and ``optional[truncated Redfish
        error body]`` in that order.

    Raises:
        ValueError: If error evidence byte limit cannot exceed the error
            response byte limit.
    """

    max_bytes = max(1, int(max_bytes))
    retention_limit = max(1, int(evidence_max_bytes))
    if retention_limit > max_bytes:
        raise ValueError(
            "error evidence byte limit cannot exceed the error response byte limit"
        )
    prefix_limit = retention_limit // 2
    suffix_limit = retention_limit - prefix_limit

    content_encoding: Optional[str] = None
    declared_size: Optional[int] = None

    body = bytearray()
    prefix = bytearray()
    suffix = bytearray()
    digest = hashlib.sha256()
    received_size = 0
    oversized = False
    stream_complete = True
    read_error_type: Optional[str] = None

    def abort_response() -> None:
        """
        Attempt deterministic close without replacing the primary outcome.

        The surrounding response context is the second exact owner.
        """

        try:
            close = getattr(response, "close", None)
            if callable(close):
                close()
        except Exception:
            # The surrounding response context is the second exact owner.
            return

    try:
        content_encoding = _redfish_content_encoding(response)
        headers = getattr(response, "headers", None)
        if content_encoding is None and isinstance(headers, Mapping):
            raw_length = headers.get("Content-Length")
            if raw_length is None:
                raw_length = headers.get("content-length")
            try:
                parsed_length = int(raw_length) if raw_length is not None else None
            except (TypeError, ValueError):
                parsed_length = None
            if (
                parsed_length is not None
                and 0 <= parsed_length <= REDFISH_TRANSPORT_CONTENT_LENGTH_MAX_BYTES
            ):
                declared_size = parsed_length
                oversized = declared_size > max_bytes

        async for raw_chunk in _iter_redfish_decoded_chunks(
            response,
            decoded_chunk_bytes=min(REDFISH_RESPONSE_CHUNK_BYTES, max_bytes),
            encoded_max_bytes=(
                _redfish_encoded_input_limit(max_bytes)
                if content_encoding is not None
                else None
            ),
            decoded_max_bytes=max_bytes,
        ):
            if not raw_chunk:
                continue
            chunk = bytes(raw_chunk)
            chunk_start = received_size
            received_size += len(chunk)
            digest.update(chunk)

            if len(prefix) < prefix_limit:
                prefix.extend(chunk[: prefix_limit - len(prefix)])

            suffix_start = max(0, prefix_limit - chunk_start)
            suffix_chunk = chunk[suffix_start:]
            if suffix_limit and suffix_chunk:
                if len(suffix_chunk) >= suffix_limit:
                    suffix[:] = suffix_chunk[-suffix_limit:]
                else:
                    suffix.extend(suffix_chunk)
                    excess = len(suffix) - suffix_limit
                    if excess > 0:
                        del suffix[:excess]

            if not oversized:
                body.extend(chunk)
    except asyncio.CancelledError:
        abort_response()
        raise
    except RedfishDecodedResponseTooLarge:
        abort_response()
        oversized = True
        body.clear()
        stream_complete = False
        read_error_type = "RedfishResponseLimitExceeded"
    except RedfishEncodedResponseTooLarge:
        abort_response()
        oversized = True
        body.clear()
        stream_complete = False
        read_error_type = "RedfishEncodedResponseTooLarge"
    except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as error:
        abort_response()
        oversized = True
        body.clear()
        stream_complete = False
        read_error_type = type(error).__name__

    if not oversized:
        return bytes(body), None

    try:
        content_type = normalize_redfish_content_type(
            getattr(response, "content_type", None)
        )
    except Exception:
        content_type = None

    return None, TruncatedRedfishErrorBody(
        received_size_bytes=received_size,
        prefix_bytes=bytes(prefix),
        suffix_bytes=bytes(suffix),
        received_sha256=digest.hexdigest(),
        response_limit_bytes=max_bytes,
        evidence_limit_bytes=retention_limit,
        content_type=content_type,
        declared_size_bytes=declared_size,
        http_status=http_status,
        attempt_number=attempt_number,
        stream_complete=stream_complete,
        read_error_type=read_error_type,
    )


class _RedfishErrorMetadata(dict):
    """
    JSON-safe metadata carrying process-private retained body windows.

    The type gives the Redfish error metadata responsibility a stable runtime
    boundary. Callers use the declared Python protocol instead of depending on
    its representation.
    """

    __slots__ = (
        "_oversized_error_bodies",
        "_oversized_error_evidence_dropped",
        "_oversized_error_evidence_limits",
    )

    def __init__(
        self,
        values: Mapping[str, Any],
        evidence: List[TruncatedRedfishErrorBody],
        *,
        dropped_response_count: int,
        aggregate_max_bytes: int,
        max_responses: int,
    ) -> None:
        """
        Initialize a ``_RedfishErrorMetadata`` instance.

        The initializer records ``_oversized_error_bodies``,
        ``_oversized_error_evidence_dropped``, and
        ``_oversized_error_evidence_limits`` for later operations and
        establishes the instance invariants before any public method runs.

        Args:
            values: Mapping supplying fields for initialize a
                ``_RedfishErrorMetadata`` instance.
            evidence: Entries supplied as ``evidence`` without transferring
                container ownership.
            dropped_response_count: Numeric dropped response count used by the
                operation's bounded accounting.
            aggregate_max_bytes: Upper bound enforced for aggregate max bytes;
                the consuming boundary rejects or truncates values that exceed
                it.
            max_responses: Upper bound enforced for max responses; the consuming
                boundary rejects or truncates values that exceed it.
        """
        super().__init__(values)
        self._oversized_error_bodies = tuple(evidence)
        self._oversized_error_evidence_dropped = max(0, int(dropped_response_count))
        self._oversized_error_evidence_limits = (
            max(1, int(aggregate_max_bytes)),
            max(1, int(max_responses)),
        )


def _attach_oversized_error_evidence(
    metadata: Dict[str, Any],
    evidence: List[TruncatedRedfishErrorBody],
    *,
    dropped_response_count: int = 0,
    aggregate_max_bytes: int = REDFISH_ERROR_EVIDENCE_AGGREGATE_MAX_BYTES,
    max_responses: int = REDFISH_ERROR_EVIDENCE_MAX_RESPONSES,
) -> Dict[str, Any]:
    """
    Attach bounded public metadata and private sanitizer input handles.

    The implementation uses ``metadata``, ``evidence``,
    ``dropped_response_count``, ``aggregate_max_bytes``, and ``max_responses``
    to attach bounded public metadata and private sanitizer input handles.

    Args:
        metadata: Mapping supplying fields for attach bounded public metadata
            and private sanitizer input handles.
        evidence: Entries supplied as ``evidence`` without transferring
            container ownership.
        dropped_response_count: Numeric dropped response count used by the
            operation's bounded accounting.
        aggregate_max_bytes: Upper bound enforced for aggregate max bytes; the
            consuming boundary rejects or truncates values that exceed it.
        max_responses: Upper bound enforced for max responses; the consuming
            boundary rejects or truncates values that exceed it.

    Returns:
        A mapping containing attach oversized error evidence.
    """

    evidence = [
        item for item in evidence if isinstance(item, TruncatedRedfishErrorBody)
    ]
    if not evidence:
        return metadata
    metadata["oversized_error_evidence"] = {
        "responses": [item.capture_metadata() for item in evidence],
        "dropped_response_count": max(0, int(dropped_response_count)),
        "limits": {
            "per_response_max_bytes": max(
                item.evidence_limit_bytes for item in evidence
            ),
            "aggregate_max_bytes": max(1, int(aggregate_max_bytes)),
            "max_responses": max(1, int(max_responses)),
        },
        "supporting_artifact": ("diagnostic/redfish_request_response_log.json"),
        "artifact_path_status_field": (
            "context.request_response_capture.artifact_path"
        ),
    }
    return _RedfishErrorMetadata(
        metadata,
        evidence,
        dropped_response_count=dropped_response_count,
        aggregate_max_bytes=aggregate_max_bytes,
        max_responses=max_responses,
    )


def _oversized_error_evidence_from_metadata(
    metadata: Any,
) -> Tuple[List[TruncatedRedfishErrorBody], int, int, int]:
    """
    Return private evidence handles and their request-wide limits.

    The implementation uses ``metadata`` to produce private evidence handles and
    their request-wide limits.

    Args:
        metadata: Metadata object whose ``_oversized_error_bodies``,
            ``_oversized_error_evidence_dropped``, and
            ``_oversized_error_evidence_limits`` state is read while performing
            private evidence handles and their request-wide limits.

    Returns:
        A tuple containing ``selected entries``, ``integer count``, ``integer
        count``, and ``integer count`` in that order.
    """

    if type(metadata) is not _RedfishErrorMetadata:
        return (
            [],
            0,
            REDFISH_ERROR_EVIDENCE_AGGREGATE_MAX_BYTES,
            REDFISH_ERROR_EVIDENCE_MAX_RESPONSES,
        )

    raw_evidence = metadata._oversized_error_bodies
    evidence = [
        item for item in raw_evidence if isinstance(item, TruncatedRedfishErrorBody)
    ]
    raw_dropped = metadata._oversized_error_evidence_dropped
    dropped = raw_dropped if isinstance(raw_dropped, int) and raw_dropped > 0 else 0
    raw_limits = metadata._oversized_error_evidence_limits
    if (
        isinstance(raw_limits, tuple)
        and len(raw_limits) == 2
        and all(isinstance(value, int) and value > 0 for value in raw_limits)
    ):
        aggregate_max_bytes, max_responses = raw_limits
    else:
        aggregate_max_bytes = REDFISH_ERROR_EVIDENCE_AGGREGATE_MAX_BYTES
        max_responses = REDFISH_ERROR_EVIDENCE_MAX_RESPONSES
    return evidence, dropped, aggregate_max_bytes, max_responses


def _copy_redfish_metadata(
    metadata: Any,
    updates: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Copy public fields without dropping private evidence handles.

    After applying local validation, the function forwards ``metadata`` and
    ``updates`` to ``_attach_oversized_error_evidence`` and preserves its return
    and exception contract.

    Args:
        metadata: Metadata consumed while the function attempts to copy public
            fields without dropping private evidence handles.
        updates: Optional updates; ``None`` selects the function's default
            behavior.

    Returns:
        A mapping containing copy Redfish metadata.
    """

    copied = dict(metadata or {})
    if updates:
        copied.update(updates)
    evidence, dropped, aggregate_max_bytes, max_responses = (
        _oversized_error_evidence_from_metadata(metadata)
    )
    return _attach_oversized_error_evidence(
        copied,
        evidence,
        dropped_response_count=dropped,
        aggregate_max_bytes=aggregate_max_bytes,
        max_responses=max_responses,
    )


DUT_TOOL_OVERRIDE_FIELDS = {
    "FW_INVENTORY_TABLE_PROPERTIES",
    "ADDITIONAL_OOB_URI_COLLECTION",
    "NVLINK_OOB_URI",
    "CUSTOM_DUMP_SERVICES",
    "REDFISH_R31_PAYLOAD",
    "POST_CODES_URI",
    "BMC_TEMP_DIR",
    "TASK_ID_PREFIX",
    "TOOL_TEMP_DIR",
    "REDFISH_DUMP_TIMEOUT",
    "REDFISH_DEVICE_DUMP_SLEEP_DURATION",
    "NVOS_TECH_DUMP_TIMEOUT",
    "SKIP_BMC_SSH_LOGS",
    "SKIP_HOST_LOGS",
    "SKIP_REDFISH_OOB_LOGS",
    "SKIP_IPMI_LOGS",
    "SKIP_PORT_FW",
    "COLLECTOR_TO_SKIP",
    "SYSTEM_ID_TO_SKIP",
    "CHASSIS_ID_TO_SKIP",
    "MANAGER_ID_TO_SKIP",
    "SYSTEM_ID_OVERRIDE",
    "MANAGER_ID_OVERRIDE",
    "CHASSIS_ID_OVERRIDE",
    "EXTRA_LOG_COLLECTION",
    "EXPAND_QUERY_CHASSIS_LEVEL",
    "EXPAND_QUERY_FIRMWARE_INVENTORY_LEVEL",
    "EXPAND_QUERY_MANAGER_LEVEL",
    "EXPAND_QUERY_SYSTEM_LEVEL",
    "COLLECTOR_EXTENSION_CONFIG",
    "sysinfo_snapshot_mode",
    "i2c_config",
    "ssh_host_key_policy",
    "ssh_known_hosts_file",
    "SSH_TUNNEL_OPTIONS",
    "bmc_rf_tls_mode",
    "bmc_rf_ca_file",
    "bmc_rf_fingerprint_sha256",
    "bmc_rf_tls_server_name",
    "bmc_rf_verify_ssl",
    "bmc_rf_authentication_mode",
}


def _strip_internal_config_keys(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a copy without internal merge bookkeeping fields.

    The implementation uses ``config`` to produce a copy without internal merge
    bookkeeping fields.

    Args:
        config: Config governing copy without internal merge bookkeeping fields.

    Returns:
        A mapping containing strip internal config keys.
    """
    return {
        key: value
        for key, value in dict(config).items()
        if key not in INTERNAL_CONFIG_KEYS
    }


def _explicit_key_map(config: Dict[str, Any]) -> Dict[str, bool]:
    """
    Return explicit-field metadata preserved from config loading.

    Loader-supplied ``__explicit_fields`` metadata wins when present and is
    normalized from mapping or sequence form. Otherwise every non-internal
    configuration key is treated as explicitly supplied.

    Args:
        config: Config governing explicit-field metadata preserved from config
            loading.

    Returns:
        A mapping containing explicit key map.
    """
    if not isinstance(config, dict):
        return {}

    raw = config.get("__explicit_fields")
    if raw is None:
        return {key: True for key in config.keys() if key not in INTERNAL_CONFIG_KEYS}
    if isinstance(raw, dict):
        return {key: bool(value) for key, value in raw.items()}
    if isinstance(raw, (list, tuple, set)):
        return {key: True for key in raw}
    return {}


def _explicit_alias_value(
    config: Dict[str, Any],
    explicit_keys: Dict[str, bool],
    canonical: str,
    legacy: str,
) -> Tuple[bool, Any]:
    """
    Return presence and value for a normalized modern/legacy alias pair.

    The implementation uses ``config``, ``explicit_keys``, ``canonical``, and
    ``legacy`` to produce presence and value for a normalized modern/legacy
    alias pair.

    Args:
        config: Config governing presence and value for a normalized
            modern/legacy alias pair.
        explicit_keys: Mapping supplying fields for presence and value for a
            normalized modern/legacy alias pair.
        canonical: Text supplied as canonical in the format accepted by this
            function.
        legacy: Text supplied as legacy in the format accepted by this function.

    Returns:
        A tuple containing the presence flag and selected canonical or legacy
        value.
    """
    if explicit_keys.get(canonical):
        return True, config.get(canonical)
    if explicit_keys.get(legacy):
        return True, config.get(legacy)
    return False, None


def _drop_implicit_tool_like_defaults(
    config: Dict[str, Any], explicit_keys: Dict[str, bool]
) -> Dict[str, Any]:
    """
    Remove DUTConfig defaults that should not override tool-level config.

    Explicit null is meaningful for this nullable field: it clears the lower
    tool-config value so the runtime or collector fallback can win.

    Args:
        config: Config governing remove DUTConfig defaults that should not
            override tool-level config.
        explicit_keys: Mapping supplying fields for remove DUTConfig defaults
            that should not override tool-level config.

    Returns:
        The validated ``cleaned``.
    """
    cleaned = _strip_internal_config_keys(config)
    for field in DUT_TOOL_OVERRIDE_FIELDS:
        # Explicit null is meaningful for this nullable field: it clears the
        # lower tool-config value so the runtime or collector fallback can win.
        explicit_null_clears_lower_value = field in {
            "EXTRA_LOG_COLLECTION",
            "REDFISH_R31_PAYLOAD",
        }
        if not explicit_keys.get(field) or (
            cleaned.get(field) is None and not explicit_null_clears_lower_value
        ):
            cleaned.pop(field, None)
    return cleaned


def _first_non_none_config_value(
    config: Dict[str, Any], *keys: str, default: Any = None
) -> Any:
    """
    Return the first configured value without treating zero as omitted.

    The implementation uses ``config``, ``default``, and ``keys`` to produce the
    first configured value without treating zero as omitted.

    Args:
        config: Config governing first configured value without treating zero as
            omitted.
        default: Fallback used when the requested value is absent or invalid.
        keys: Additional positional values forwarded in caller-provided order.

    Returns:
        The first configured value without treating zero as omitted.
    """
    for key in keys:
        value = config.get(key)
        if value is not None:
            return value
    return default


def _is_truthy(value: Any) -> bool:
    """
    Preserve permissive truthiness for non-security execution-mode aliases.

    The implementation uses ``value`` to preserve permissive truthiness for
    non-security execution-mode aliases.

    Args:
        value: Value object whose ``strip`` state is read while performing
            preserve permissive truthiness for non-security execution-mode
            aliases.

    Returns:
        Whether the preserve permissive truthiness for non-security
        execution-mode aliases operation succeeds.
    """
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _parse_legacy_boolean(value: Any, *, field_name: str) -> bool:
    """
    Parse a deprecated security boolean without fail-open coercion.

    The implementation uses ``value`` and ``field_name`` to parse a deprecated
    security boolean without fail-open coercion. Parsing or I/O must finish
    before the validated representation is made available to the caller. If the
    function cannot parse a deprecated security boolean without fail-open
    coercion, its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        value: Value object whose ``strip`` state is read while performing
            deprecated security boolean without fail-open coercion.
        field_name: Field label included in validation failures for the selected
            input.

    Returns:
        Whether the deprecated security boolean without fail-open coercion
        operation succeeds.

    Raises:
        ValueError: If the ``field_name`` is not true or false.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
    elif isinstance(value, int) and value in (0, 1):
        return bool(value)
    raise ValueError(f"{field_name} must be true or false")


def _resolve_dut_redfish_ssl(
    config: Dict[str, Any],
    explicit_keys: Dict[str, bool],
    session_default: bool,
) -> bool:
    """
    Resolve the single TLS-verification winner used by all DUT phases.

    The implementation uses ``config``, ``explicit_keys``, and
    ``session_default`` to resolve the single TLS-verification winner used by
    all DUT phases.

    Args:
        config: Config governing single TLS-verification winner used by all DUT
            phases.
        explicit_keys: Mapping supplying fields for single TLS-verification
            winner used by all DUT phases.
        session_default: Whether session default is enabled or required for this
            operation.

    Returns:
        Whether the single TLS-verification winner used by all DUT phases
        operation succeeds.
    """
    if explicit_keys.get("bmc_rf_verify_ssl"):
        return _parse_legacy_boolean(
            config.get("bmc_rf_verify_ssl"),
            field_name="bmc_rf_verify_ssl",
        )
    return bool(session_default)


def _resolve_dut_redfish_tls_policy(
    config: Dict[str, Any],
    explicit_keys: Dict[str, bool],
    session_default: RedfishTLSPolicy,
    *,
    session_default_is_explicit: bool = False,
    session_override_keys: Optional[Dict[str, bool]] = None,
) -> RedfishTLSPolicy:
    """
    Resolve one Redfish TLS policy for preflight and runtime requests.

    The implementation uses ``config``, ``explicit_keys``, ``session_default``,
    ``session_default_is_explicit``, and ``session_override_keys`` to resolve
    one Redfish TLS policy for preflight and runtime requests.

    Resolution is monotonic in the verifying direction: a lower-precedence
    source may refine or strengthen an explicit higher-precedence verifying
    selection, but it may never downgrade one to ``insecure``. The canonical
    ``bmc_rf_tls_mode`` selector and the documented "canonical outranks
    deprecated" rule are unchanged.

    Args:
        config: Config governing one Redfish TLS policy for preflight and
            runtime requests.
        explicit_keys: Mapping supplying fields for one Redfish TLS policy for
            preflight and runtime requests.
        session_default: Session default object whose ``ca_file``,
            ``fingerprint_sha256``, and ``mode`` state is read while performing
            one Redfish TLS policy for preflight and runtime requests.
        session_default_is_explicit: Whether session default is explicit is
            enabled or required for this operation.
        session_override_keys: Optional session override keys; ``None`` selects
            the function's default behavior.

    Returns:
        A ``RedfishTLSPolicy`` representing DUT Redfish TLS policy.
    """

    override_keys = (
        explicit_keys if session_override_keys is None else session_override_keys
    )
    session_sections: Dict[str, Dict[str, Any]] = {}
    session_server_name = None
    session_server_name_is_explicit = False
    for session_key in ("redfish_session_config", "redfish_sessions"):
        if not override_keys.get(session_key):
            continue
        session_values = config.get(session_key)
        if hasattr(session_values, "model_dump"):
            session_values = session_values.model_dump(exclude_unset=True)
        if not isinstance(session_values, dict):
            continue
        session_sections[session_key] = session_values
        if not session_server_name_is_explicit and "server_name" in session_values:
            session_server_name = session_values["server_name"]
            session_server_name_is_explicit = True

    if len(session_sections) == 2:
        _reject_conflicting_redfish_session_holders(session_sections)
        merged_session = {
            **session_sections["redfish_sessions"],
            **session_sections["redfish_session_config"],
        }
        session_policies = [
            RedfishSessionConfig.model_validate(merged_session).model_dump(
                exclude_unset=True
            )
        ]
    else:
        session_policies = list(session_sections.values())

    def resolved_server_name() -> Optional[str]:
        """
        Return the resolved server name.

        The implementation uses current instance state to produce the resolved
        server name.

        Returns:
            The canonical resolved server name, or ``None`` when the requested
            value is unavailable.
        """
        if explicit_keys.get("bmc_rf_tls_server_name"):
            return config.get("bmc_rf_tls_server_name")
        if session_server_name_is_explicit:
            return session_server_name
        return session_default.server_name

    if explicit_keys.get("bmc_rf_tls_mode"):
        return RedfishTLSPolicy(
            mode=config.get("bmc_rf_tls_mode"),
            ca_file=config.get("bmc_rf_ca_file"),
            fingerprint_sha256=config.get("bmc_rf_fingerprint_sha256"),
            server_name=resolved_server_name(),
        )

    # Trust selection is monotonic: a lower-precedence source may refine or
    # strengthen a higher-precedence explicit verifying selection, but it must
    # never weaken one. Resolve the deprecated per-DUT boolean once, after the
    # canonical short-circuit above so a malformed value still fails closed at
    # the same place, and reuse it to refuse an ``insecure`` downgrade from both
    # the linked session holder and the lower-precedence global default.
    #
    # A session holder that itself carries a compatibility boolean is excluded:
    # the linked-document projection flattens that nested boolean onto
    # ``bmc_rf_verify_ssl``, so treating it as an independent higher-precedence
    # selection would let a nested compatibility boolean replace an explicit
    # canonical mode, which is the opposite of the documented rule.
    session_holder_carries_legacy_verify = any(
        "ssl_verify" in session_values or "ssl" in session_values
        for session_values in session_policies
    )
    dut_legacy_selects_verification = (
        not session_holder_carries_legacy_verify
        and bool(explicit_keys.get("bmc_rf_verify_ssl"))
        and _parse_legacy_boolean(
            config.get("bmc_rf_verify_ssl"),
            field_name="bmc_rf_verify_ssl",
        )
    )

    session_legacy_mode: Optional[str] = None
    for session_values in session_policies:
        policy_fields = {
            "tls_mode",
            "ssl_verify",
            "ssl",
            "ca_file",
            "fingerprint_sha256",
        }
        if not policy_fields.intersection(session_values):
            # A server name refines whichever policy wins; it does not select
            # system-CA verification over the deprecated DUT fallback itself.
            continue

        canonical_mode_is_explicit = session_values.get("tls_mode") is not None
        legacy_verify_is_explicit = (
            "ssl_verify" in session_values or "ssl" in session_values
        )
        if canonical_mode_is_explicit:
            mode = session_values["tls_mode"]
        elif legacy_verify_is_explicit:
            legacy_key = "ssl_verify" if "ssl_verify" in session_values else "ssl"
            legacy_verify = session_values[legacy_key]
            if session_legacy_mode is None:
                session_legacy_mode = (
                    "system_ca"
                    if _parse_legacy_boolean(
                        legacy_verify,
                        field_name=legacy_key,
                    )
                    else "insecure"
                )
            # Keep looking for a canonical session policy. Compatibility
            # booleans are evaluated only after all canonical sources.
            continue
        else:
            mode = session_default.mode

        if mode == "insecure" and dut_legacy_selects_verification:
            # The linked holder sits below the per-DUT layer, so it may not
            # turn an explicit per-DUT verifying selection into plaintext
            # trust. Keep scanning; a verifying linked policy still wins.
            continue

        return RedfishTLSPolicy(
            mode=mode,
            ca_file=(
                session_values.get("ca_file")
                if "ca_file" in session_values
                else (None if canonical_mode_is_explicit else session_default.ca_file)
            ),
            fingerprint_sha256=(
                session_values.get("fingerprint_sha256")
                if "fingerprint_sha256" in session_values
                else (
                    None
                    if canonical_mode_is_explicit
                    else session_default.fingerprint_sha256
                )
            ),
            server_name=resolved_server_name(),
        )

    # A linked or DUT-scoped pool-only holder can replace the visible nested
    # mapping without intentionally replacing an explicit global trust policy.
    # Preserve that lower-layer policy before consulting the deprecated scalar.
    if session_default_is_explicit and not (
        session_default.mode == "insecure" and dut_legacy_selects_verification
    ):
        return RedfishTLSPolicy(
            mode=session_default.mode,
            ca_file=session_default.ca_file,
            fingerprint_sha256=session_default.fingerprint_sha256,
            server_name=resolved_server_name(),
        )

    if explicit_keys.get("bmc_rf_verify_ssl"):
        return RedfishTLSPolicy(
            mode=(
                "system_ca"
                if _parse_legacy_boolean(
                    config.get("bmc_rf_verify_ssl"),
                    field_name="bmc_rf_verify_ssl",
                )
                else "insecure"
            ),
            server_name=resolved_server_name(),
        )
    if session_legacy_mode is not None:
        return RedfishTLSPolicy(
            mode=session_legacy_mode,
            server_name=resolved_server_name(),
        )
    if explicit_keys.get("bmc_rf_tls_server_name") or session_server_name_is_explicit:
        return RedfishTLSPolicy(
            mode=session_default.mode,
            ca_file=session_default.ca_file,
            fingerprint_sha256=session_default.fingerprint_sha256,
            server_name=resolved_server_name(),
        )
    return session_default


def _normalize_execution_mode(value: Any, *, local: Any = False) -> str:
    """
    Normalize execution mode.

    The implementation uses ``value`` and ``local`` to normalize execution mode.
    The source value keeps its ownership while the normalized representation is
    returned separately. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Args:
        value: Value object whose ``value`` state is read while performing
            execution mode.
        local: Local consumed while the function attempts to normalize execution
            mode.

    Returns:
        The canonical execution mode text.
    """
    if _is_truthy(local):
        return "local"

    if hasattr(value, "value"):
        value = value.value

    normalized = str(value or "remote").strip().lower()
    compact = normalized.replace("_", "").replace("-", "").replace(" ", "")
    if compact == "local":
        return "local"
    if compact in {"remote", "remoteclient"}:
        return "remote"
    return normalized


def _resolve_execution_mode(config: Dict[str, Any]) -> str:
    """
    Resolve execution mode.

    After applying local validation, the function forwards ``config`` to
    ``_normalize_execution_mode`` and preserves its return and exception
    contract.

    Args:
        config: Config governing execution mode.

    Returns:
        The canonical execution mode text.
    """
    return _normalize_execution_mode(
        config.get("ExecutionMode") or config.get("execution_mode"),
        local=config.get("local", False),
    )


def _strip_leading_sudo(command: str) -> str:
    """
    Return the strip leading sudo.

    The implementation uses ``command`` to produce the strip leading sudo.

    Args:
        command: Text supplied as command in the format accepted by this
            function.

    Returns:
        The canonical strip leading sudo text.
    """
    stripped = command.lstrip()
    leading = command[: len(command) - len(stripped)]

    for prefix in ("sudo -S ", "sudo -n ", "sudo "):
        if stripped.startswith(prefix):
            return f"{leading}{stripped[len(prefix) :]}"

    return command


def _can_send_remote_sudo_password(
    password: Optional[str],
    ssh_key_path: Optional[str],
    passwordless: bool,
) -> bool:
    """
    Return True only when the configured secret is a real login password.

    In key mode ``password`` is the local private-key passphrase --
    ``_build_ssh_connect_kwargs`` hands it to asyncssh as ``passphrase`` and
    deliberately does not send it as an SSH password. Writing that value to the
    DUT's stdin as a sudo password would disclose a local secret to a
    partially-trusted device.

    Args:
        password: Sensitive value supplied through the approved input boundary
            and never logged.
        ssh_key_path: filesystem location used as the SSH key path for this
            operation.
        passwordless: Sensitive value supplied through the approved input
            boundary and never logged.

    Returns:
        Whether the true only when the configured secret is a real login
        password operation succeeds.
    """
    return bool(password) and not passwordless and not ssh_key_path


def _force_noninteractive_sudo(command: str) -> str:
    """
    Make a remote sudo command fail fast instead of blocking on a prompt.

    Mirrors the policy already applied to local execution when no sudo password
    is available.

    Args:
        command: Text supplied as command in the format accepted by this
            function.

    Returns:
        The canonical force noninteractive sudo text.
    """
    if "sudo -n" in command:
        return command
    if "sudo -S" in command:
        return command.replace("sudo -S", "sudo -n", 1)
    return command.replace("sudo ", "sudo -n ", 1)


def _build_sudo_command(command: str, *, local_execution: bool) -> str:
    """
    Build sudo command.

    The implementation uses ``command`` and ``local_execution`` to build sudo
    command.

    Args:
        command: Text supplied as command in the format accepted by this
            function.
        local_execution: Whether local execution is enabled or required for this
            operation.

    Returns:
        The canonical sudo command text.
    """
    if not local_execution:
        if command.strip().startswith("sudo"):
            return command
        return f"sudo -S {command}"

    command_without_sudo = _strip_leading_sudo(command)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return command_without_sudo
    return f"sudo -n {command_without_sudo}"


def _prepare_remote_privileged_command(
    command: str,
    *,
    use_sudo: bool,
    password: Optional[str],
    ssh_key_path: Optional[str],
    passwordless: bool,
    input_data: Optional[str],
    sudo_password: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """
    Normalize remote elevation while keeping local key secrets off remote stdin.

    An explicit sudo credential takes precedence independently of SSH's login
    mode. When it is absent or empty, only a password used for password-based SSH
    may be reused. Key passphrases are never implicitly forwarded. The trusted
    sudo validation gate consumes the credential separately from command input;
    caller-supplied ``sudo -n`` continues to prohibit password transmission.

    Args:
        command: Trusted remote shell payload, optionally prefixed with sudo.
        use_sudo: Whether this operation requests privilege elevation.
        password: SSH login password or local private-key passphrase.
        ssh_key_path: Explicit private-key path selecting local passphrase use.
        passwordless: Whether SSH uses previously provisioned authentication.
        input_data: Command stdin preserved after any sudo credential line.
        sudo_password: Explicit remote sudo credential, never placed in argv.
            None or an empty string preserves the safe login-password fallback.

    Returns:
        The normalized remote command and separately delivered stdin, including
        a validated credential line only when password-based sudo is selected.

    Raises:
        TypeError: If a credential selected for sudo is not a string.
        ValueError: If sudo syntax is unsupported or a credential contains CR,
            LF, or NUL, which would break the single-line input boundary.
    """
    if not command or not use_sudo:
        return command, input_data

    validate_password_stdin_line(sudo_password, credential_name="sudo password")
    remote_password = sudo_password
    if not remote_password and _can_send_remote_sudo_password(
        password, ssh_key_path, passwordless
    ):
        remote_password = password

    arguments, password_stdin = build_privileged_command_argv(
        command,
        password_available=bool(remote_password),
        use_shell=True,
    )
    normalized_input = input_data
    if password_stdin:
        validate_password_stdin_line(remote_password, credential_name="sudo password")
        normalized_input = f"{remote_password}\n{input_data or ''}"
    return _quote_remote_argv(arguments), normalized_input


def _quote_remote_argv(arguments: List[Any]) -> str:
    """
    Render argv for AsyncSSH's remote POSIX shell without changing arguments.

    After applying local validation, the function forwards ``arguments`` to
    ``shlex.join`` and preserves its return and exception contract. The source
    value keeps its ownership while the normalized representation is returned
    separately.

    Args:
        arguments: Entries supplied as ``arguments`` without transferring
            container ownership.

    Returns:
        The canonical quote remote argument vector text.
    """
    return shlex.join(str(argument) for argument in arguments)


def _build_remote_ipmitool_command(arguments: List[Any]) -> str:
    """
    Build a remote command which receives the IPMI password only on stdin.

    After applying local validation, the function forwards ``arguments`` to
    ``_quote_remote_argv`` and preserves its return and exception contract.

    Args:
        arguments: Entries supplied as ``arguments`` without transferring
            container ownership.

    Returns:
        The canonical remote ipmitool command text.
    """
    password_script = (
        "set -eu\n"
        f"PATH={TRUSTED_PRIVILEGED_PATH}\n"
        "export PATH\n"
        f"{build_trusted_ipmitool_selection_script()}\n"
        "umask 077\n"
        'password_file=$(mktemp "${TMPDIR:-/tmp}/nvdebug-ipmi.XXXXXX")\n'
        "trap 'rm -f -- \"$password_file\"' EXIT\n"
        "IFS= read -r password\n"
        'printf \'%s\' "$password" > "$password_file"\n'
        "unset password\n"
        'exec "$nvdebug_ipmitool_path" -f "$password_file" "$@"'
    )
    return _quote_remote_argv(
        [
            TRUSTED_POSIX_SHELL_PATH,
            "-c",
            password_script,
            "nvdebug-ipmitool",
            *arguments,
        ]
    )


@contextmanager
def _temporary_ipmitool_password_file(
    password: Optional[str],
    *,
    credential_parent: Optional[Path] = None,
) -> Iterator[Optional[str]]:
    """
    Expose an IPMI password through a short-lived mode-0600 file.

    The implementation uses ``password`` to expose an IPMI password through a
    short-lived mode-0600 file. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        password: Sensitive value supplied through the approved input boundary
            and never logged.
        credential_parent: Optional private parent owned by the current run;
            ``None`` creates a randomized private directory under the platform
            temporary root.

    Yields:
        Each temporary ipmitool password file admitted by the operation, in
        deterministic iteration order.
    """
    if password is None:
        yield None
        return

    parent = credential_parent or Path(tempfile.gettempdir())
    credential_dir = Path(tempfile.mkdtemp(prefix=".nvdebug-ipmi-cred-", dir=parent))
    os.chmod(credential_dir, 0o700)
    descriptor, password_path = tempfile.mkstemp(
        prefix="nvdebug-ipmi-",
        dir=credential_dir,
    )
    descriptor_open = True
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as password_file:
            descriptor_open = False
            password_file.write(str(password))
        yield password_path
    finally:
        if descriptor_open:
            os.close(descriptor)
        shutil.rmtree(credential_dir, ignore_errors=True)


async def _discard_subprocess_stream(reader: Any) -> None:
    """
    Drain a terminated child pipe incrementally without retaining output.

    The implementation uses ``reader`` to drain a terminated child pipe
    incrementally without retaining output. Owned asynchronous work is awaited
    before return, so completion does not leave an unobserved task behind.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle.

    Args:
        reader: Reader object whose ``read`` state is read while performing
            drain a terminated child pipe incrementally without retaining
            output.
    """

    if reader is None:
        return
    while await reader.read(SUBPROCESS_OUTPUT_READ_CHUNK_BYTES):
        pass


async def _terminate_and_drain_subprocess(
    process: asyncio.subprocess.Process,
    *,
    timeout: float = SUBPROCESS_CLEANUP_TIMEOUT_SECONDS,
    terminate_process_group: bool = False,
) -> None:
    """
    Kill a subprocess and reap its transports within one cleanup budget.

    A shell can exit while background descendants keep its pipes open. The group
    remains ours in that state, so do not gate group cleanup on the group
    leader's return code.

    Args:
        process: Process object whose ``kill``, ``returncode``, and ``wait``
            state is read while performing kill a subprocess and reap its
            transports within one cleanup budget.
        timeout: Maximum duration allowed before the operation is cancelled or
            fails.
        terminate_process_group: Whether terminate process group is enabled or
            required for this operation.

    Raises:
        ValueError: If the subprocess cleanup timeout is not finite and
            positive.
        BaseException: If a delegated failure occurs while the function attempts
            to kill a subprocess and reap its transports within one cleanup
            budget.
    """
    cleanup_timeout = float(timeout)
    if not math.isfinite(cleanup_timeout) or cleanup_timeout <= 0:
        raise ValueError("Subprocess cleanup timeout must be finite and positive")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + cleanup_timeout

    def remaining_budget() -> float:
        """
        Return the remaining budget.

        After applying local validation, the function forwards current instance
        state to ``max`` and preserves its return and exception contract.

        Returns:
            The numeric remaining budget value.
        """
        return max(0.0, deadline - loop.time())

    process_group_killed = False
    process_group_id = getattr(process, "pid", None)
    # A shell can exit while background descendants keep its pipes open.  The
    # group remains ours in that state, so do not gate group cleanup on the
    # group leader's return code.
    if (
        terminate_process_group
        and isinstance(process_group_id, int)
        and process_group_id > 0
    ):
        try:
            os.killpg(process_group_id, signal.SIGKILL)
            process_group_killed = True
        except OSError as exc:
            logger.debug("Unable to kill subprocess group (%s)", type(exc).__name__)

    if not process_group_killed and process.returncode is None:
        try:
            process.kill()
        except OSError as exc:
            logger.debug("Unable to kill subprocess (%s)", type(exc).__name__)

    stdin = getattr(process, "stdin", None)
    if stdin is not None:
        try:
            stdin.close()
        except Exception as exc:
            logger.debug(
                "Unable to close terminated subprocess stdin (%s)",
                type(exc).__name__,
            )

    cleanup_tasks = [
        asyncio.create_task(
            capture_owned_awaitable(
                _discard_subprocess_stream(getattr(process, "stdout", None))
            )
        ),
        asyncio.create_task(
            capture_owned_awaitable(
                _discard_subprocess_stream(getattr(process, "stderr", None))
            )
        ),
        asyncio.create_task(capture_owned_awaitable(process.wait())),
    ]
    try:
        async with asyncio.timeout(remaining_budget()):
            outcomes = await drain_owned_tasks(cleanup_tasks)
    except asyncio.TimeoutError:
        logger.warning(
            "Timed out after %.1f seconds cleaning up a terminated subprocess",
            cleanup_timeout,
        )
        return

    cleanup_errors = [
        outcome.error
        for outcome in outcomes
        if outcome.error is not None and not outcome.owner_cancelled
    ]
    if cleanup_errors:
        authoritative = select_authoritative_exception(cleanup_errors)
        if isinstance(
            authoritative,
            (asyncio.CancelledError, KeyboardInterrupt, SystemExit),
        ):
            raise authoritative
        logger.debug(
            "Terminated subprocess cleanup observed %s",
            type(authoritative).__name__,
        )


async def _await_subprocess_cleanup(
    process: asyncio.subprocess.Process,
    *,
    terminate_process_group: bool = False,
    primary_error: BaseException | None = None,
) -> None:
    """
    Drain one bounded cleanup task without losing later control flow.

    The shared drain records completion-edge control flow before it examines the
    child and does not return until this exact task is done.

    Args:
        process: Process consumed while the function attempts to drain one
            bounded cleanup task without losing later control flow.
        terminate_process_group: Whether terminate process group is enabled or
            required for this operation.
        primary_error: Optional primary error; ``None`` selects the function's
            default behavior.

    Raises:
        BaseException: If a delegated failure occurs while the function attempts
            to drain one bounded cleanup task without losing later control flow.
    """

    cleanup_task = asyncio.create_task(
        capture_owned_awaitable(
            _terminate_and_drain_subprocess(
                process,
                terminate_process_group=terminate_process_group,
            )
        )
    )
    drain_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    try:
        (cleanup_outcome,) = await drain_owned_tasks(
            (cleanup_task,),
            cancel_on_wait_error=False,
        )
    except BaseException as error:
        # The shared drain records completion-edge control flow before it
        # examines the child and does not return until this exact task is done.
        drain_error = error
        try:
            cleanup_outcome = cleanup_task.result()
        except BaseException as task_error:
            cleanup_error = task_error
        else:
            cleanup_error = cleanup_outcome.error
    else:
        cleanup_error = cleanup_outcome.error

    if cleanup_error is not None:
        logger.error(
            "Unable to complete subprocess cleanup",
            exc_info=(
                type(cleanup_error),
                cleanup_error,
                cleanup_error.__traceback__,
            ),
        )

    observed_errors: list[BaseException] = []
    if primary_error is not None:
        observed_errors.append(primary_error)
    if drain_error is not None:
        observed_errors.append(drain_error)
    elif cleanup_error is not None:
        observed_errors.append(cleanup_error)
    if observed_errors:
        raise select_authoritative_exception(observed_errors)


async def _communicate_subprocess(
    process: asyncio.subprocess.Process,
    timeout: Optional[float] = None,
    input_data: Optional[bytes] = None,
    *,
    terminate_process_group: bool = False,
    limits: Optional[SubprocessOutputLimits] = None,
) -> Tuple[bytes, bytes]:
    """
    Collect child pipes concurrently under finite in-memory byte limits.

    The implementation uses ``process``, ``timeout``, ``input_data``,
    ``terminate_process_group``, and ``limits`` to collect child pipes
    concurrently under finite in-memory byte limits. Terminal status is emitted
    only after child pipes concurrently under finite in-memory byte limits and
    its owned cleanup have completed. Owned asynchronous work is awaited before
    return, so completion does not leave an unobserved task behind. If the
    function cannot collect child pipes concurrently under finite in-memory byte
    limits, its exception reaches the caller instead of being converted into a
    successful result. Cleanup in the ``finally`` path runs for successful,
    failed, and cancelled execution.

    Args:
        process: Process object whose ``wait`` state is read while performing
            child pipes concurrently under finite in-memory byte limits.
        timeout: Maximum duration allowed before the operation is cancelled or
            fails.
        input_data: Optional input data; ``None`` selects the function's default
            behavior.
        terminate_process_group: Whether terminate process group is enabled or
            required for this operation.
        limits: Optional Limits governing child pipes concurrently under finite
            in-memory byte limits.

    Returns:
        A tuple containing ``byte sequence`` and ``byte sequence`` in that
        order.

    Raises:
        ValueError: If subprocess output limits have an invalid type; the
            subprocess input_data is not bytes or None; or the subprocess
            timeout is not finite.
        BaseException: If a delegated failure occurs while the function attempts
            to collect child pipes concurrently under finite in-memory byte
            limits.
        AssertionError: If subprocess cleanup lost its primary failure.
    """

    active_limits = DEFAULT_SUBPROCESS_OUTPUT_LIMITS if limits is None else limits
    if type(active_limits) is not SubprocessOutputLimits:
        raise ValueError("Subprocess output limits have an invalid type")
    if input_data is not None and not isinstance(input_data, bytes):
        raise ValueError("Subprocess input_data must be bytes or None")

    command_timeout: Optional[float] = None
    if timeout is not None:
        command_timeout = float(timeout)
        if not math.isfinite(command_timeout):
            raise ValueError("Subprocess timeout must be finite")
        if command_timeout <= 0:
            raise asyncio.TimeoutError

    async def read_stream(
        reader: Any,
        *,
        stream_name: str,
        budget: _SubprocessOutputBudget,
    ) -> bytes:
        """
        Read stream.

        After applying local validation, the function forwards ``reader``,
        ``stream_name``, and ``budget`` to ``join`` and preserves its return and
        exception contract. Parsing or I/O must finish before the validated
        representation is made available to the caller. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind.

        Args:
            reader: Reader object whose ``read`` state is read while performing
                stream.
            stream_name: Stable stream name used for lookup and operator-facing
                diagnostics.
            budget: Budget object whose ``consume`` state is read while
                performing stream.

        Returns:
            The bounded stream bytes.

        Raises:
            ValueError: If subprocess ``stream_name`` pipe is unavailable; or
                subprocess ``stream_name`` returned a non-binary chunk.
        """
        if reader is None:
            raise ValueError(f"Subprocess {stream_name} pipe is unavailable")
        chunks: List[bytes] = []
        retain_command_stream(stream_name, chunks)
        while True:
            chunk = await reader.read(active_limits.read_chunk_bytes)
            if not chunk:
                result = b"".join(chunks)
                retain_command_stream(stream_name, [result])
                return result
            if not isinstance(chunk, bytes):
                raise ValueError(
                    f"Subprocess {stream_name} returned a non-binary chunk"
                )
            budget.consume(stream_name, len(chunk))
            chunks.append(chunk)

    async def write_input() -> None:
        """
        Write input.

        The implementation uses current instance state to write input. Success
        is reported only after the owning output boundary has completed its
        required write or publication step. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        If the function cannot write input, its exception reaches the caller
        instead of being converted into a successful result. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Raises:
            ValueError: If subprocess stdin pipe is unavailable.
        """
        writer = getattr(process, "stdin", None)
        if writer is None:
            if input_data is not None:
                raise ValueError("Subprocess stdin pipe is unavailable")
            return
        try:
            if input_data:
                for offset in range(
                    0,
                    len(input_data),
                    SUBPROCESS_OUTPUT_READ_CHUNK_BYTES,
                ):
                    writer.write(
                        input_data[offset : offset + SUBPROCESS_OUTPUT_READ_CHUNK_BYTES]
                    )
                    await writer.drain()
            else:
                await writer.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            writer.close()

    owned_tasks: List[asyncio.Task[Any]] = []
    drain_started = False
    try:
        budget = _SubprocessOutputBudget(active_limits)
        owned_tasks.append(
            asyncio.create_task(
                capture_owned_awaitable(
                    read_stream(
                        getattr(process, "stdout", None),
                        stream_name="stdout",
                        budget=budget,
                    )
                )
            )
        )
        owned_tasks.append(
            asyncio.create_task(
                capture_owned_awaitable(
                    read_stream(
                        getattr(process, "stderr", None),
                        stream_name="stderr",
                        budget=budget,
                    )
                )
            )
        )
        owned_tasks.append(asyncio.create_task(capture_owned_awaitable(write_input())))
        owned_tasks.append(asyncio.create_task(capture_owned_awaitable(process.wait())))
        drain_started = True
        if command_timeout is None:
            outcomes = await drain_owned_tasks(
                owned_tasks,
                cancel_on_error=lambda _error: True,
            )
        else:
            async with asyncio.timeout(command_timeout):
                outcomes = await drain_owned_tasks(
                    owned_tasks,
                    cancel_on_error=lambda _error: True,
                )
    except BaseException as error:
        if not drain_started:
            cancelled_task_ids: set[int] = set()
            for task in owned_tasks:
                if not task.done() and task.cancel():
                    cancelled_task_ids.add(id(task))
            if owned_tasks:
                try:
                    setup_outcomes = await drain_owned_tasks(
                        owned_tasks,
                        cancel_on_wait_error=False,
                    )
                except BaseException as drain_error:
                    error = select_authoritative_exception((error, drain_error))
                else:
                    setup_errors = [
                        outcome.error
                        for task, outcome in zip(owned_tasks, setup_outcomes)
                        if outcome.error is not None
                        and not outcome.owner_cancelled
                        and not (
                            id(task) in cancelled_task_ids
                            and isinstance(outcome.error, asyncio.CancelledError)
                        )
                    ]
                    if setup_errors:
                        error = select_authoritative_exception((error, *setup_errors))
        await _await_subprocess_cleanup(
            process,
            terminate_process_group=terminate_process_group,
            primary_error=error,
        )
        raise AssertionError("subprocess cleanup lost its primary failure")

    errors = [
        outcome.error
        for outcome in outcomes
        if outcome.error is not None and not outcome.owner_cancelled
    ]
    if errors:
        error = select_authoritative_exception(errors)
        await _await_subprocess_cleanup(
            process,
            terminate_process_group=terminate_process_group,
            primary_error=error,
        )
        raise AssertionError("subprocess cleanup lost its primary failure")

    return outcomes[0].value, outcomes[1].value


def _validate_sftp_download_limits(
    max_bytes: int,
    read_chunk_bytes: int,
) -> Tuple[int, int]:
    """
    Validate explicit finite bounds before any remote or local side effect.

    The implementation uses ``max_bytes`` and ``read_chunk_bytes`` to validate
    explicit finite bounds before any remote or local side effect. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        max_bytes: Upper bound enforced for max bytes; the consuming boundary
            rejects or truncates values that exceed it.
        read_chunk_bytes: Numeric read chunk bytes used while the operation
            performs bounded accounting.

    Returns:
        A tuple containing ``max bytes`` and ``read chunk bytes`` in that order.

    Raises:
        ValueError: If the sftp download max_bytes are not a positive integer;
            SFTP download max_bytes cannot exceed
            ``SFTP_DOWNLOAD_HARD_MAX_BYTES``; the sftp download read_chunk_bytes
            are not a positive integer; or SFTP download read_chunk_bytes cannot
            exceed ``SFTP_DOWNLOAD_MAX_READ_CHUNK_BYTES``.
    """

    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("SFTP download max_bytes must be a positive integer")
    if max_bytes > SFTP_DOWNLOAD_HARD_MAX_BYTES:
        raise ValueError(
            f"SFTP download max_bytes cannot exceed {SFTP_DOWNLOAD_HARD_MAX_BYTES}"
        )
    if type(read_chunk_bytes) is not int or read_chunk_bytes <= 0:
        raise ValueError("SFTP download read_chunk_bytes must be a positive integer")
    if read_chunk_bytes > SFTP_DOWNLOAD_MAX_READ_CHUNK_BYTES:
        raise ValueError(
            "SFTP download read_chunk_bytes cannot exceed "
            f"{SFTP_DOWNLOAD_MAX_READ_CHUNK_BYTES}"
        )
    return max_bytes, read_chunk_bytes


def _normalize_remote_transfer_root(value: Any) -> str:
    """
    Return one normalized absolute Host transfer scratch root.

    The root is configuration data later passed as a single quoted shell
    argument. Rejecting traversal, control characters, the filesystem root, and
    overlong values also keeps the endpoint receipt parser bounded.

    Args:
        value: Candidate remote Host temporary-directory root.

    Returns:
        The validated normalized absolute POSIX path.

    Raises:
        ValueError: If ``value`` is not a safe normalized absolute path beneath
            the filesystem root.
    """

    if not isinstance(value, str) or not value or len(value) > 3072:
        raise ValueError("Host temp directory must be a non-empty bounded string")
    if "\x00" in value or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ValueError("Host temp directory contains unsafe characters")
    normalized = posixpath.normpath(value)
    if normalized != value or not value.startswith("/") or normalized == "/":
        raise ValueError("Host temp directory must be a normalized absolute path")
    return normalized


def _remote_transfer_directory_path_is_valid(
    path: Any,
    expected_root: Any,
) -> bool:
    """
    Return whether a remote transfer path belongs to its configured root.

    The endpoint receipt is accepted only for one direct child whose basename
    matches the randomized transfer namespace. Keeping the configured root in
    the receipt prevents cleanup from widening to an unrelated directory.

    Args:
        path: Candidate endpoint-returned temporary directory path.
        expected_root: Configured parent which must contain ``path`` directly.

    Returns:
        ``True`` only for one normalized child bearing the governed randomized
        transfer basename.
    """

    try:
        root = _normalize_remote_transfer_root(expected_root)
    except ValueError:
        return False
    if not isinstance(path, str) or posixpath.normpath(path) != path:
        return False
    return bool(
        posixpath.dirname(path) == root
        and REMOTE_TRANSFER_DIRECTORY_NAME_PATTERN.fullmatch(posixpath.basename(path))
        is not None
    )


def _parse_remote_transfer_directory(
    output: str,
    expected_root: str = "/tmp",
) -> _RemoteTransferDirectory:
    """
    Parse only the exact two-field receipt emitted by remote ``mktemp``.

    After applying local validation, the function forwards ``output`` to
    ``_RemoteTransferDirectory`` and preserves its return and exception
    contract. Parsing or I/O must finish before the validated representation is
    made available to the caller.

    Args:
        output: Text supplied as output in the format accepted by this function.
        expected_root: Configured remote parent which must directly own the
            endpoint-returned directory.

    Returns:
        A ``_RemoteTransferDirectory`` representing remote transfer directory.

    Raises:
        ValueError: If remote mktemp returned a malformed receipt; remote mktemp
            returned an invalid directory path; or remote mktemp returned an
            invalid directory identity.
    """

    if not isinstance(output, str) or not output or len(output) > 4096:
        raise ValueError("Remote mktemp returned a malformed receipt")
    if "\r" in output or output.endswith("\n\n"):
        raise ValueError("Remote mktemp returned a malformed receipt")
    body = output[:-1] if output.endswith("\n") else output
    fields = body.split("\n")
    if len(fields) != 2:
        raise ValueError("Remote mktemp returned a malformed receipt")
    path, identity = fields
    normalized_root = _normalize_remote_transfer_root(expected_root)
    if not _remote_transfer_directory_path_is_valid(path, normalized_root):
        raise ValueError("Remote mktemp returned an invalid directory path")
    if REMOTE_TRANSFER_DIRECTORY_IDENTITY_PATTERN.fullmatch(identity) is None:
        raise ValueError("Remote mktemp returned an invalid directory identity")
    return _RemoteTransferDirectory(
        root=normalized_root,
        path=path,
        identity=identity,
    )


def _sftp_regular_file_size(
    attributes: Any,
    *,
    remote_path: str,
    max_bytes: int,
) -> int:
    """
    Require bounded regular-file evidence from one SFTP stat.

    The implementation uses ``attributes``, ``remote_path``, and ``max_bytes``
    to require bounded regular-file evidence from one SFTP stat. A zero-byte
    regular file is valid transport evidence; callers which require semantic
    content must enforce that policy after acquisition. Every required invariant
    is checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        attributes: Attributes consumed while the function attempts to require
            bounded regular-file evidence from one SFTP stat.
        remote_path: filesystem location used as the remote path for this
            operation.
        max_bytes: Upper bound enforced for max bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The validated ``size``.

    Raises:
        SFTPDownloadError: If remote path ``remote_path`` returned malformed
            file-type metadata; remote path ``remote_path`` returned malformed
            permission metadata; remote path ``remote_path`` is not a regular
            file; or remote path ``remote_path`` has no trustworthy regular-file
            metadata; or another input invariant is violated.
        SFTPDownloadLimitExceeded: If remote file ``remote_path`` is ``size``
            bytes and exceeds the ``max_bytes``-byte transfer limit.
    """

    file_type = getattr(attributes, "type", None)
    permissions = getattr(attributes, "permissions", None)
    if file_type is not None and type(file_type) is not int:
        raise SFTPDownloadError(
            f"Remote path {remote_path} returned malformed file-type metadata"
        )
    if permissions is not None and type(permissions) is not int:
        raise SFTPDownloadError(
            f"Remote path {remote_path} returned malformed permission metadata"
        )

    type_proves_regular = file_type == asyncssh.FILEXFER_TYPE_REGULAR
    if file_type not in (
        None,
        asyncssh.FILEXFER_TYPE_UNKNOWN,
        asyncssh.FILEXFER_TYPE_REGULAR,
    ):
        raise SFTPDownloadError(f"Remote path {remote_path} is not a regular file")

    permission_type = stat.S_IFMT(permissions) if permissions is not None else 0
    permissions_prove_regular = permission_type == stat.S_IFREG
    if permission_type not in (0, stat.S_IFREG):
        raise SFTPDownloadError(f"Remote path {remote_path} is not a regular file")
    if not type_proves_regular and not permissions_prove_regular:
        raise SFTPDownloadError(
            f"Remote path {remote_path} has no trustworthy regular-file metadata"
        )

    size = getattr(attributes, "size", None)
    if type(size) is not int or size < 0:
        raise SFTPDownloadError(
            f"Remote path {remote_path} returned malformed size metadata"
        )
    if size > max_bytes:
        raise SFTPDownloadLimitExceeded(
            f"Remote file {remote_path} is {size} bytes and exceeds the "
            f"{max_bytes}-byte transfer limit"
        )
    return size


def _sftp_file_identity(attributes: Any) -> Tuple[Any, ...]:
    """
    Capture stable SFTP metadata used to detect replacement and growth.

    After applying local validation, the function forwards ``attributes`` to
    ``tuple`` and preserves its return and exception contract.

    Args:
        attributes: Attributes consumed while the function attempts to capture
            stable SFTP metadata used to detect replacement and growth.

    Returns:
        The sftp file identity returned in operation-defined order.
    """

    return tuple(
        getattr(attributes, field_name, None)
        for field_name in _SFTP_STABLE_IDENTITY_FIELDS
    )


def _require_sftp_identity(
    attributes: Any,
    *,
    expected_identity: Tuple[Any, ...],
    remote_path: str,
    max_bytes: int,
    phase: str,
) -> int:
    """
    Require a later snapshot to describe the same bounded regular file.

    The implementation uses ``attributes``, ``expected_identity``,
    ``remote_path``, ``max_bytes``, and ``phase`` to require a later snapshot to
    describe the same bounded regular file. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        attributes: Attributes consumed while the function attempts to require a
            later snapshot to describe the same bounded regular file.
        expected_identity: Entries supplied as ``expected_identity`` without
            transferring container ownership.
        remote_path: filesystem location used as the remote path for this
            operation.
        max_bytes: Upper bound enforced for max bytes; the consuming boundary
            rejects or truncates values that exceed it.
        phase: Text supplied as phase in the format accepted by this function.

    Returns:
        The validated ``size``.

    Raises:
        SFTPDownloadError: If remote file ``remote_path`` changed identity or
            size ``phase``.
    """

    size = _sftp_regular_file_size(
        attributes,
        remote_path=remote_path,
        max_bytes=max_bytes,
    )
    if _sftp_file_identity(attributes) != expected_identity:
        raise SFTPDownloadError(
            f"Remote file {remote_path} changed identity or size {phase}"
        )
    return size


def _open_sftp_destination_parent(destination: Path) -> Tuple[int, int, int]:
    """
    Open and bind a non-symlink destination directory.

    The implementation uses ``destination`` to open and bind a non-symlink
    destination directory. If the function cannot open and bind a non-symlink
    destination directory, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        destination: filesystem location used as the destination for this
            operation.

    Returns:
        A tuple containing ``descriptor``, ``st dev``, and ``st ino`` in that
        order.

    Raises:
        SFTPDownloadError: If SFTP destination directory does not exist:
            ``parent``; SFTP destination parent is not a non-symlink directory:
            ``parent``; or SFTP destination directory changed while it was
            opened.
    """

    parent = destination.parent
    try:
        path_metadata = parent.lstat()
    except FileNotFoundError as error:
        raise SFTPDownloadError(
            f"SFTP destination directory does not exist: {parent}"
        ) from error
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISDIR(path_metadata.st_mode):
        raise SFTPDownloadError(
            f"SFTP destination parent is not a non-symlink directory: {parent}"
        )

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(parent, flags)
    try:
        descriptor_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(descriptor_metadata.st_mode)
            or descriptor_metadata.st_dev != path_metadata.st_dev
            or descriptor_metadata.st_ino != path_metadata.st_ino
        ):
            raise SFTPDownloadError(
                "SFTP destination directory changed while it was opened"
            )
        return (
            descriptor,
            descriptor_metadata.st_dev,
            descriptor_metadata.st_ino,
        )
    except BaseException:
        os.close(descriptor)
        raise


def _require_sftp_destination_parent(
    destination: Path,
    descriptor: int,
    expected_device: int,
    expected_inode: int,
) -> None:
    """
    Require the caller-visible parent to remain the opened directory.

    The implementation uses ``destination``, ``descriptor``,
    ``expected_device``, and ``expected_inode`` to require the caller-visible
    parent to remain the opened directory. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Args:
        destination: filesystem location used as the destination for this
            operation.
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.
        expected_device: Numeric expected device used while the operation
            performs bounded accounting.
        expected_inode: Numeric expected inode used while the operation performs
            bounded accounting.

    Raises:
        SFTPDownloadError: If SFTP destination directory disappeared during
            transfer; or SFTP destination directory changed during transfer.
    """

    descriptor_metadata = os.fstat(descriptor)
    try:
        path_metadata = destination.parent.lstat()
    except FileNotFoundError as error:
        raise SFTPDownloadError(
            "SFTP destination directory disappeared during transfer"
        ) from error
    if (
        not stat.S_ISDIR(descriptor_metadata.st_mode)
        or stat.S_ISLNK(path_metadata.st_mode)
        or not stat.S_ISDIR(path_metadata.st_mode)
        or descriptor_metadata.st_dev != expected_device
        or descriptor_metadata.st_ino != expected_inode
        or path_metadata.st_dev != expected_device
        or path_metadata.st_ino != expected_inode
    ):
        raise SFTPDownloadError("SFTP destination directory changed during transfer")


def _create_sftp_staging_leaf(
    destination: Path,
    parent_descriptor: int,
) -> Tuple[int, _OwnedSFTPStagingLeaf]:
    """
    Create one private sibling leaf and retain its exact inode identity.

    The implementation uses ``destination`` and ``parent_descriptor`` to create
    one private sibling leaf and retain its exact inode identity. Filesystem
    effects remain confined to the caller-selected paths and the owning resource
    lifecycle. If the function cannot create one private sibling leaf and retain
    its exact inode identity, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        destination: filesystem location used as the destination for this
            operation.
        parent_descriptor: Numeric parent descriptor used while the operation
            performs bounded accounting.

    Returns:
        A tuple containing ``descriptor`` and ``owned sftp staging leaf`` in
        that order.

    Raises:
        SFTPDownloadError: If unable to allocate a private SFTP staging leaf; or
            SFTP staging leaf is not a private regular file.
    """

    descriptor: Optional[int] = None
    temporary_name = ""
    open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    open_flags |= getattr(os, "O_CLOEXEC", 0)
    open_flags |= getattr(os, "O_NOFOLLOW", 0)
    for _attempt in range(128):
        temporary_name = f".{destination.name}.sftp-stage-{secrets.token_hex(16)}"
        try:
            descriptor = os.open(
                temporary_name,
                open_flags,
                0o600,
                dir_fd=parent_descriptor,
            )
        except FileExistsError:
            continue
        break
    if descriptor is None:
        raise SFTPDownloadError("Unable to allocate a private SFTP staging leaf")
    temporary_path = destination.parent / temporary_name
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SFTPDownloadError("SFTP staging leaf is not a private regular file")
        return descriptor, _OwnedSFTPStagingLeaf(
            path=temporary_path,
            name=temporary_name,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        raise


def _sftp_staging_leaf_matches(
    owned: _OwnedSFTPStagingLeaf,
    parent_descriptor: int,
) -> bool:
    """
    Return whether the staging pathname still names our exact inode.

    The implementation uses ``owned`` and ``parent_descriptor`` to determine
    whether the staging pathname still names our exact inode. Filesystem effects
    remain confined to the caller-selected paths and the owning resource
    lifecycle.

    Args:
        owned: Owned object whose ``device``, ``inode``, and ``name`` state is
            read while performing staging pathname still names our exact inode.
        parent_descriptor: Numeric parent descriptor used while the operation
            performs bounded accounting.

    Returns:
        Whether the staging pathname still names our exact inode.
    """

    try:
        metadata = os.stat(
            owned.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return False
    return (
        metadata.st_dev == owned.device
        and metadata.st_ino == owned.inode
        and stat.S_ISREG(metadata.st_mode)
    )


def _unlink_owned_sftp_leaf(
    owned: _OwnedSFTPStagingLeaf,
    parent_descriptor: int,
) -> None:
    """
    Remove a failed staging/final leaf only when it is still ours.

    The implementation uses ``owned`` and ``parent_descriptor`` to remove a
    failed staging/final leaf only when it is still ours.

    Args:
        owned: Owned object whose ``name`` state is read while performing remove
            a failed staging/final leaf only when it is still ours.
        parent_descriptor: Numeric parent descriptor used while the operation
            performs bounded accounting.
    """

    if _sftp_staging_leaf_matches(owned, parent_descriptor):
        os.unlink(owned.name, dir_fd=parent_descriptor)


def _write_all_to_fd(descriptor: int, data: bytes) -> None:
    """
    Write one bounded chunk completely without retaining another copy.

    The implementation uses ``descriptor`` and ``data`` to write one bounded
    chunk completely without retaining another copy. Success is reported only
    after the owning output boundary has completed its required write or
    publication step. If the function cannot write one bounded chunk completely
    without retaining another copy, its exception reaches the caller instead of
    being converted into a successful result.

    Args:
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.
        data: Bounded byte sequence supplied as data.

    Raises:
        OSError: If SFTP staging write made no progress.
    """

    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("SFTP staging write made no progress")
        view = view[written:]


def _validate_sftp_staging_fd(
    descriptor: int,
    owned: _OwnedSFTPStagingLeaf,
    parent_descriptor: int,
    expected_size: int,
) -> None:
    """
    Verify the exact private inode before atomic publication.

    The implementation uses ``descriptor``, ``owned``, ``parent_descriptor``,
    and ``expected_size`` to verify the exact private inode before atomic
    publication. Every required invariant is checked before a successful value
    is returned; invalid input follows the function's explicit exception path.

    Args:
        descriptor: Numeric descriptor used while the operation performs bounded
            accounting.
        owned: Owned object whose ``device`` and ``inode`` state is read while
            performing exact private inode before atomic publication.
        parent_descriptor: Numeric parent descriptor used while the operation
            performs bounded accounting.
        expected_size: Numeric expected size used by the operation's bounded
            accounting.

    Raises:
        SFTPDownloadError: If SFTP staging leaf changed before publication.
    """

    metadata = os.fstat(descriptor)
    if (
        metadata.st_dev != owned.device
        or metadata.st_ino != owned.inode
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size != expected_size
        or not _sftp_staging_leaf_matches(owned, parent_descriptor)
    ):
        raise SFTPDownloadError("SFTP staging leaf changed before publication")


def _publish_sftp_staging_leaf(
    owned: _OwnedSFTPStagingLeaf,
    destination: Path,
    parent_descriptor: int,
    expected_size: int,
    published: List[_OwnedSFTPStagingLeaf],
) -> None:
    """
    Atomically replace the destination and verify the published inode.

    The implementation uses ``owned``, ``destination``, ``parent_descriptor``,
    ``expected_size``, and ``published`` to atomically replace the destination
    and verify the published inode. The operation mutates ``published`` in
    place; ownership of those objects remains with the caller. Filesystem
    effects remain confined to the caller-selected paths and the owning resource
    lifecycle. If the function cannot atomically replace the destination and
    verify the published inode, its exception reaches the caller instead of
    being converted into a successful result.

    Args:
        owned: Owned object whose ``device``, ``inode``, and ``name`` state is
            read while performing atomically replace the destination and verify
            the published inode.
        destination: filesystem location used as the destination for this
            operation.
        parent_descriptor: Numeric parent descriptor used while the operation
            performs bounded accounting.
        expected_size: Numeric expected size used by the operation's bounded
            accounting.
        published: Entries supplied as ``published`` without transferring
            container ownership.

    Raises:
        SFTPDownloadError: If SFTP staging leaf changed before publication; or
            published SFTP destination failed verification.
    """

    if not _sftp_staging_leaf_matches(owned, parent_descriptor):
        raise SFTPDownloadError("SFTP staging leaf changed before publication")
    os.replace(
        owned.name,
        destination.name,
        src_dir_fd=parent_descriptor,
        dst_dir_fd=parent_descriptor,
    )
    published_leaf = _OwnedSFTPStagingLeaf(
        path=destination,
        name=destination.name,
        device=owned.device,
        inode=owned.inode,
    )
    published.append(published_leaf)
    metadata = os.stat(
        destination.name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    if (
        metadata.st_dev != owned.device
        or metadata.st_ino != owned.inode
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size != expected_size
    ):
        raise SFTPDownloadError("Published SFTP destination failed verification")


def _is_sftp_session_open_failure(error: BaseException) -> bool:
    """
    Identify an SFTP channel rejection which is safe to recover before reads.

    AsyncSSH raises ``ChannelOpenError`` before returning an SFTP client when
    the server rejects the session/subsystem request or reports temporary
    channel resource exhaustion. No remote file bytes have been read and no
    local artifact has been published at this point, so callers may retire the
    failed transport and use a separately bounded acquisition route.

    Args:
        error: Exception raised while opening the SFTP client channel.

    Returns:
        Whether ``error`` is one of the narrowly admitted pre-read SFTP channel
        failures.
    """

    return isinstance(error, asyncssh.ChannelOpenError) and error.code in {
        asyncssh.OPEN_REQUEST_SESSION_FAILED,
        asyncssh.OPEN_RESOURCE_SHORTAGE,
    }


def _build_ssh_exec_file_stream_command(remote_path: str) -> str:
    """
    Build the fixed remote command for one exact binary file stream.

    The caller-controlled path is passed as a positional shell argument rather
    than interpolated into the governed script. The script opens one descriptor,
    proves its identity against the path before reading, and repeats both
    identity checks after streaming.

    Args:
        remote_path: Exact remote file path selected by the caller.

    Returns:
        A shell-quoted remote command suitable for an AsyncSSH exec channel.

    Raises:
        ValueError: If ``remote_path`` is empty or contains a NUL byte.
    """

    if not isinstance(remote_path, str) or not remote_path:
        raise ValueError("SSH exec stream remote_path must be a non-empty string")
    if "\x00" in remote_path:
        raise ValueError("SSH exec stream remote_path cannot contain NUL")
    return _quote_remote_argv(
        [
            TRUSTED_POSIX_SHELL_PATH,
            "-c",
            SSH_EXEC_FILE_STREAM_SCRIPT,
            "nvdebug-exec-file-stream",
            remote_path,
            SSH_EXEC_FILE_STREAM_MARKER,
        ]
    )


def _parse_ssh_exec_file_identity(value: str) -> _SSHExecFileIdentity:
    """
    Parse one numeric identity emitted by the governed remote script.

    Decimal fields retain their native representation while the remote mode
    field is decoded from ``stat`` hexadecimal output. The fixed field count
    and non-negative checks make malformed device output fail closed before it
    can influence local publication decisions.

    Args:
        value: Colon-delimited numeric identity from a marker line.

    Returns:
        The validated immutable remote file identity.

    Raises:
        SFTPDownloadError: If the identity has malformed fields.
    """

    fields = value.split(":")
    if len(fields) != 9:
        raise SFTPDownloadError("SSH exec stream returned malformed identity metadata")
    try:
        numeric = [
            int(field, 16 if index == 3 else 10) for index, field in enumerate(fields)
        ]
    except (TypeError, ValueError) as error:
        raise SFTPDownloadError(
            "SSH exec stream returned malformed identity metadata"
        ) from error
    if any(number < 0 for number in numeric):
        raise SFTPDownloadError("SSH exec stream returned malformed identity metadata")
    return _SSHExecFileIdentity(*numeric)


def _parse_ssh_exec_file_stream_metadata(
    metadata: Union[str, bytes],
    *,
    max_bytes: int,
) -> _SSHExecFileIdentity:
    """
    Validate the complete before/after identity transcript for an exec stream.

    The transcript must contain only the four expected marker lines. All path
    and opened-descriptor snapshots must match, the object must remain a
    non-negative-size single-link regular file, and its declared size must fit the
    caller's byte ceiling.

    Args:
        metadata: Bounded stderr captured from the governed remote script.
        max_bytes: Maximum admitted remote file size in bytes.

    Returns:
        The common validated identity represented by every marker line.

    Raises:
        SFTPDownloadError: If metadata is missing, malformed, inconsistent, or
            describes an unsafe remote object.
        SFTPDownloadLimitExceeded: If the declared size exceeds ``max_bytes``.
    """

    if not isinstance(metadata, bytes):
        raise SFTPDownloadError("SSH exec stream did not return binary metadata")
    if len(metadata) > SSH_EXEC_FILE_STREAM_METADATA_MAX_BYTES:
        raise SFTPDownloadError("SSH exec stream metadata exceeded its byte limit")
    try:
        lines = metadata.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise SFTPDownloadError(
            "SSH exec stream returned non-ASCII metadata"
        ) from error

    labels = ("HANDLE_BEFORE", "PATH_BEFORE", "HANDLE_AFTER", "PATH_AFTER")
    if len(lines) != len(labels):
        raise SFTPDownloadError("SSH exec stream returned incomplete identity metadata")

    identities: List[_SSHExecFileIdentity] = []
    for line, label in zip(lines, labels):
        prefix = f"{SSH_EXEC_FILE_STREAM_MARKER}:{label}:"
        if not line.startswith(prefix):
            raise SFTPDownloadError(
                "SSH exec stream returned unexpected identity metadata"
            )
        identities.append(_parse_ssh_exec_file_identity(line[len(prefix) :]))

    identity = identities[0]
    if any(candidate != identity for candidate in identities[1:]):
        raise SFTPDownloadError(
            "Remote file changed identity or size during SSH exec streaming"
        )
    if not stat.S_ISREG(identity.mode):
        raise SFTPDownloadError("SSH exec stream source is not a regular file")
    if identity.links != 1:
        raise SFTPDownloadError("SSH exec stream source has extra hard links")
    if identity.size > max_bytes:
        raise SFTPDownloadLimitExceeded(
            "SSH exec stream source exceeded the "
            f"{max_bytes}-byte transfer limit before downloading"
        )
    return identity


async def _capture_ssh_exec_stream_metadata(
    reader: Any,
    budget: _SSHOutputBudget,
) -> Any:
    """
    Own the bounded metadata reader without pre-creating a stray coroutine.

    Creating the inner reader only after this task starts ensures immediate
    caller cancellation cannot leave an un-awaited coroutine object behind.

    Args:
        reader: Binary stderr reader owned by the remote process.
        budget: Finite byte budget governing retained metadata.

    Returns:
        The ``OwnedAwaitableOutcome`` produced by the repository task-drain
        helper.
    """

    return await capture_owned_awaitable(
        _read_ssh_stream_bounded(
            reader,
            stream_name="stderr",
            budget=budget,
        )
    )


async def _capture_ssh_exec_stream_wait(process: Any) -> Any:
    """
    Own process-channel completion without pre-creating a stray coroutine.

    Delaying ``wait_closed()`` construction until this wrapper is scheduled
    prevents immediate parent cancellation from leaking an un-awaited channel
    coroutine. The standard owned-outcome shape lets the caller combine this
    lifecycle with the concurrent metadata drain deterministically.

    Args:
        process: AsyncSSH process whose channel completion must be observed.

    Returns:
        The ``OwnedAwaitableOutcome`` produced by the repository task-drain
        helper.
    """

    return await capture_owned_awaitable(process.wait_closed())


async def _download_ssh_exec_regular_file_bounded(
    conn: Any,
    remote_path: str,
    local_path: Union[str, Path],
    *,
    max_bytes: int,
    read_chunk_bytes: int,
) -> int:
    """
    Acquire one remote regular file through a bounded binary exec stream.

    This fallback is used only after the server rejects SFTP before any read.
    It never routes binary data through the text command-output collector. A
    private local inode receives bounded stdout chunks, while bounded stderr
    carries identity markers binding the opened descriptor and original path
    before and after the read. Publication remains atomic and mode 0600.

    Args:
        conn: Fresh owned AsyncSSH connection used only for this binary stream.
        remote_path: Exact remote file path selected by the caller.
        local_path: Exact local destination to publish atomically.
        max_bytes: Maximum admitted remote and transferred byte count.
        read_chunk_bytes: Maximum bytes requested from stdout per read.

    Returns:
        The exact number of bytes atomically published.

    Raises:
        ValueError: If an input or governed byte limit is invalid.
        SFTPDownloadError: If remote identity, process status, binary output,
            or local publication violates the transfer contract.
        SFTPDownloadLimitExceeded: If stdout exceeds ``max_bytes``.
        BaseException: If cancellation or another control-flow exception occurs
            while the owned process is running.
    """

    max_bytes, read_chunk_bytes = _validate_sftp_download_limits(
        max_bytes,
        read_chunk_bytes,
    )
    command = _build_ssh_exec_file_stream_command(remote_path)
    if not isinstance(local_path, (str, Path)):
        raise ValueError("SSH exec stream local_path must be a string or Path")
    destination = Path(local_path)
    if not destination.name or destination.name in (".", ".."):
        raise ValueError("SSH exec stream local_path must identify one file")

    parent_descriptor, parent_device, parent_inode = _open_sftp_destination_parent(
        destination
    )
    descriptor: Optional[int] = None
    owned: Optional[_OwnedSFTPStagingLeaf] = None
    published: List[_OwnedSFTPStagingLeaf] = []
    publication_complete = False
    process = None
    try:
        _require_sftp_destination_parent(
            destination,
            parent_descriptor,
            parent_device,
            parent_inode,
        )
        descriptor, owned = _create_sftp_staging_leaf(
            destination,
            parent_descriptor,
        )

        try:
            process_awaitable = conn.create_process(command, encoding=None)
        except BaseException as error:
            raise HostSSHProcessCreationFailure(error) from error
        creation_task = asyncio.create_task(capture_owned_awaitable(process_awaitable))
        try:
            (creation_outcome,) = await drain_owned_tasks((creation_task,))
        except BaseException as error:
            process = _completed_ssh_process_from_creation_task(creation_task)
            if process is not None:
                await _await_ssh_process_cleanup(process, primary_error=error)
                raise AssertionError("SSH exec stream cleanup lost its primary failure")
            raise
        if creation_outcome.error is not None:
            raise HostSSHProcessCreationFailure(creation_outcome.error)
        process = creation_outcome.value
        if process is None:
            raise RuntimeError("SSH exec stream process creation returned no channel")

        metadata_limits = SSHProcessOutputLimits(
            stdout_max_bytes=SSH_EXEC_FILE_STREAM_METADATA_MAX_BYTES,
            stderr_max_bytes=SSH_EXEC_FILE_STREAM_METADATA_MAX_BYTES,
            aggregate_max_bytes=SSH_EXEC_FILE_STREAM_METADATA_MAX_BYTES,
            read_chunk_bytes=min(4096, SSH_EXEC_FILE_STREAM_METADATA_MAX_BYTES),
        )
        metadata_budget = _SSHOutputBudget(metadata_limits)
        owned_tasks = [
            asyncio.create_task(
                _capture_ssh_exec_stream_metadata(
                    process.stderr,
                    metadata_budget,
                )
            ),
            asyncio.create_task(_capture_ssh_exec_stream_wait(process)),
        ]
        try:
            transferred_bytes = 0
            while True:
                requested_bytes = min(
                    read_chunk_bytes,
                    max_bytes - transferred_bytes + 1,
                )
                chunk = await process.stdout.read(requested_bytes)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise SFTPDownloadError(
                        "SSH exec stream returned a non-binary output chunk"
                    )
                if len(chunk) > requested_bytes:
                    raise SFTPDownloadError(
                        "SSH exec stream exceeded its requested read size"
                    )
                transferred_bytes += len(chunk)
                if transferred_bytes > max_bytes:
                    raise SFTPDownloadLimitExceeded(
                        "SSH exec stream exceeded the "
                        f"{max_bytes}-byte transfer limit while downloading"
                    )
                _write_all_to_fd(descriptor, chunk)

            outcomes = await drain_owned_tasks(
                owned_tasks,
                cancel_on_error=lambda _error: True,
            )
        except BaseException as error:
            cancelled_task_ids: set[int] = set()
            for task in owned_tasks:
                if not task.done() and task.cancel():
                    cancelled_task_ids.add(id(task))
            try:
                setup_outcomes = await drain_owned_tasks(
                    owned_tasks,
                    cancel_on_wait_error=False,
                )
            except BaseException as drain_error:
                error = select_authoritative_exception((error, drain_error))
            else:
                setup_errors = [
                    outcome.error
                    for task, outcome in zip(owned_tasks, setup_outcomes)
                    if outcome.error is not None
                    and not outcome.owner_cancelled
                    and not (
                        id(task) in cancelled_task_ids
                        and isinstance(outcome.error, asyncio.CancelledError)
                    )
                ]
                if setup_errors:
                    error = select_authoritative_exception((error, *setup_errors))
            await _await_ssh_process_cleanup(process, primary_error=error)
            raise AssertionError("SSH exec stream cleanup lost its primary failure")

        errors = [
            outcome.error
            for outcome in outcomes
            if outcome.error is not None and not outcome.owner_cancelled
        ]
        if errors:
            error = select_authoritative_exception(errors)
            await _await_ssh_process_cleanup(process, primary_error=error)
            raise AssertionError("SSH exec stream cleanup lost its primary failure")

        exit_status = getattr(process, "exit_status", None)
        if type(exit_status) is not int or exit_status != 0:
            raise SFTPDownloadError(
                "SSH exec stream failed before verified publication"
            )
        identity = _parse_ssh_exec_file_stream_metadata(
            outcomes[0].value,
            max_bytes=max_bytes,
        )
        if transferred_bytes != identity.size:
            raise SFTPDownloadError(
                "Remote file size changed during SSH exec streaming: "
                f"expected {identity.size} bytes, received {transferred_bytes}"
            )

        _require_sftp_destination_parent(
            destination,
            parent_descriptor,
            parent_device,
            parent_inode,
        )
        os.fsync(descriptor)
        _validate_sftp_staging_fd(
            descriptor,
            owned,
            parent_descriptor,
            transferred_bytes,
        )
        _publish_sftp_staging_leaf(
            owned,
            destination,
            parent_descriptor,
            transferred_bytes,
            published,
        )
        _require_sftp_destination_parent(
            destination,
            parent_descriptor,
            parent_device,
            parent_inode,
        )
        publication_complete = True
        return transferred_bytes
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if not publication_complete:
            if published:
                _unlink_owned_sftp_leaf(published[-1], parent_descriptor)
            elif owned is not None:
                _unlink_owned_sftp_leaf(owned, parent_descriptor)
        os.close(parent_descriptor)


async def _download_sftp_regular_file_bounded(
    sftp: Any,
    remote_path: str,
    local_path: Union[str, Path],
    *,
    max_bytes: int,
    read_chunk_bytes: int,
    expected_size: Optional[int] = None,
) -> int:
    """
    Acquire one proven regular file through bounded, atomic SFTP staging.

    The implementation uses ``sftp``, ``remote_path``, ``local_path``,
    ``max_bytes``, and ``read_chunk_bytes`` to acquire one proven regular file
    through bounded, atomic SFTP staging. Owned asynchronous work is awaited
    before return, so completion does not leave an unobserved task behind.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. If the function cannot acquire one proven regular
    file through bounded, atomic SFTP staging, its exception reaches the caller
    instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        sftp: Sftp object whose ``lstat`` and ``open`` state is read while
            performing acquire one proven regular file through bounded, atomic
            SFTP staging.
        remote_path: filesystem location used as the remote path for this
            operation.
        local_path: filesystem location used as the local path for this
            operation.
        max_bytes: Upper bound enforced for max bytes; the consuming boundary
            rejects or truncates values that exceed it.
        read_chunk_bytes: Numeric read chunk bytes used while the operation
            performs bounded accounting.
        expected_size: Optional exact byte size bound by an earlier durable
            receipt or inspection. A mismatch is rejected before opening or
            reading the remote file.

    Returns:
        The validated ``transferred_bytes``.

    Raises:
        ValueError: If the sftp remote_path is not a non-empty string; the sftp
            local_path is not a string or Path; or SFTP local_path must identify
            one file; or expected_size is not a non-negative integer within the
            configured maximum.
        SFTPDownloadError: If the server advertises an invalid read limit;
            remote file ``remote_path`` returned a non-binary chunk; remote file
            ``remote_path`` exceeded its requested read size; remote file
            ``remote_path`` grew while downloading; or remote file
            ``remote_path`` size changed while downloading: expected
            ``expected_size`` bytes, received ``transferred_bytes``.
        SFTPDownloadLimitExceeded: If remote file ``remote_path`` exceeded the
            ``max_bytes``-byte transfer limit while downloading.
        RuntimeError: If SFTP staging ownership was not established.
    """

    max_bytes, read_chunk_bytes = _validate_sftp_download_limits(
        max_bytes,
        read_chunk_bytes,
    )
    if expected_size is not None and (
        isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
        or not 0 <= expected_size <= max_bytes
    ):
        raise ValueError(
            "SFTP expected_size must be a non-negative integer within max_bytes"
        )
    if not isinstance(remote_path, str) or not remote_path:
        raise ValueError("SFTP remote_path must be a non-empty string")
    if not isinstance(local_path, (str, Path)):
        raise ValueError("SFTP local_path must be a string or Path")
    destination = Path(local_path)
    if not destination.name or destination.name in (".", ".."):
        raise ValueError("SFTP local_path must identify one file")

    initial_attributes = await sftp.lstat(remote_path)
    observed_size = _sftp_regular_file_size(
        initial_attributes,
        remote_path=remote_path,
        max_bytes=max_bytes,
    )
    if expected_size is not None and observed_size != expected_size:
        raise SFTPDownloadError(
            f"Remote file {remote_path} size changed before downloading"
        )
    expected_size = observed_size
    expected_identity = _sftp_file_identity(initial_attributes)
    sftp_limits = getattr(sftp, "limits", None)
    negotiated_max_read_len = getattr(sftp_limits, "max_read_len", None)
    if negotiated_max_read_len is None:
        direct_read_chunk_bytes = read_chunk_bytes
    elif type(negotiated_max_read_len) is not int or negotiated_max_read_len <= 0:
        raise SFTPDownloadError("SFTP server advertised an invalid maximum read length")
    else:
        direct_read_chunk_bytes = min(
            read_chunk_bytes,
            negotiated_max_read_len,
        )
    parent_descriptor, parent_device, parent_inode = _open_sftp_destination_parent(
        destination
    )

    descriptor: Optional[int] = None
    owned: Optional[_OwnedSFTPStagingLeaf] = None
    published: List[_OwnedSFTPStagingLeaf] = []
    publication_complete = False
    try:
        async with sftp.open(
            remote_path,
            "rb",
            encoding=None,
            # AsyncSSH delegates a read larger than the negotiated server
            # limit to its internal parallel reader. A transport loss while
            # that library-owned reader is being cancelled can otherwise leave
            # an internal task exception unobserved. Keeping both the file
            # block size and every request at or below the public negotiated
            # limit selects the directly awaited handler read path instead.
            block_size=direct_read_chunk_bytes,
            max_requests=1,
        ) as remote_file:
            opened_attributes = await remote_file.stat()
            _require_sftp_identity(
                opened_attributes,
                expected_identity=expected_identity,
                remote_path=remote_path,
                max_bytes=max_bytes,
                phase="between path lookup and open",
            )

            _require_sftp_destination_parent(
                destination,
                parent_descriptor,
                parent_device,
                parent_inode,
            )
            descriptor, owned = _create_sftp_staging_leaf(
                destination,
                parent_descriptor,
            )
            transferred_bytes = 0
            while True:
                remaining_declared = expected_size - transferred_bytes
                requested_bytes = min(
                    direct_read_chunk_bytes,
                    remaining_declared + 1,
                    max_bytes - transferred_bytes + 1,
                )
                chunk = await remote_file.read(requested_bytes)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise SFTPDownloadError(
                        f"Remote file {remote_path} returned a non-binary chunk"
                    )
                if len(chunk) > requested_bytes:
                    raise SFTPDownloadError(
                        f"Remote file {remote_path} exceeded its requested read size"
                    )
                transferred_bytes += len(chunk)
                if transferred_bytes > max_bytes:
                    raise SFTPDownloadLimitExceeded(
                        f"Remote file {remote_path} exceeded the "
                        f"{max_bytes}-byte transfer limit while downloading"
                    )
                if transferred_bytes > expected_size:
                    raise SFTPDownloadError(
                        f"Remote file {remote_path} grew while downloading"
                    )
                # Each local syscall is capped by ``read_chunk_bytes`` and has
                # no await boundary which could orphan an in-flight write.
                _write_all_to_fd(descriptor, chunk)

            if transferred_bytes != expected_size:
                raise SFTPDownloadError(
                    f"Remote file {remote_path} size changed while downloading: "
                    f"expected {expected_size} bytes, received {transferred_bytes}"
                )

            final_handle_attributes = await remote_file.stat()
            _require_sftp_identity(
                final_handle_attributes,
                expected_identity=expected_identity,
                remote_path=remote_path,
                max_bytes=max_bytes,
                phase="while downloading",
            )

        final_path_attributes = await sftp.lstat(remote_path)
        _require_sftp_identity(
            final_path_attributes,
            expected_identity=expected_identity,
            remote_path=remote_path,
            max_bytes=max_bytes,
            phase="before publication",
        )
        if descriptor is None or owned is None:
            raise RuntimeError("SFTP staging ownership was not established")
        _require_sftp_destination_parent(
            destination,
            parent_descriptor,
            parent_device,
            parent_inode,
        )
        os.fsync(descriptor)
        _validate_sftp_staging_fd(
            descriptor,
            owned,
            parent_descriptor,
            transferred_bytes,
        )
        _publish_sftp_staging_leaf(
            owned,
            destination,
            parent_descriptor,
            transferred_bytes,
            published,
        )
        _require_sftp_destination_parent(
            destination,
            parent_descriptor,
            parent_device,
            parent_inode,
        )
        publication_complete = True
        return transferred_bytes
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if not publication_complete:
            if published:
                _unlink_owned_sftp_leaf(published[-1], parent_descriptor)
            elif owned is not None:
                _unlink_owned_sftp_leaf(owned, parent_descriptor)
        os.close(parent_descriptor)


async def _run_ipmitool_subprocess(
    command: List[str],
    password: Optional[str],
    timeout: Optional[float],
    *,
    credential_parent: Optional[Path] = None,
) -> Tuple[int, bytes, bytes]:
    """
    Run ipmitool without placing its password in the child process argv.

    The implementation uses ``command``, ``password``, and ``timeout`` to run
    ipmitool without placing its password in the child process argv. Terminal
    status is emitted only after ipmitool without placing its password in the
    child process argv and its owned cleanup have completed. Owned asynchronous
    work is awaited before return, so completion does not leave an unobserved
    task behind.

    Args:
        command: Entries supplied as ``command`` without transferring container
            ownership.
        password: Sensitive value supplied through the approved input boundary
            and never logged.
        timeout: Maximum duration allowed before the operation is cancelled or
            fails.
        credential_parent: Optional private parent owned by the current run for
            the transient credential directory.

    Returns:
        A tuple containing ``returncode``, ``stdout``, and ``stderr`` in that
        order.

    Raises:
        TypeError: If the supplied password is not text.
        ValueError: If the password cannot be represented as one input line or
            ``command`` does not contain an approved ipmitool executable.
    """
    validate_password_stdin_line(password, credential_name="IPMI password")
    safe_command = list(command)
    ipmitool_index = next(
        (
            index
            for index, argument in enumerate(safe_command)
            if argument in TRUSTED_IPMITOOL_PATHS
        ),
        None,
    )
    if ipmitool_index is None:
        raise ValueError(
            "IPMI command does not contain an approved ipmitool executable"
        )

    with _temporary_ipmitool_password_file(
        password,
        credential_parent=credential_parent,
    ) as password_path:
        terminate_process_group = os.name == "posix"
        if password_path is not None:
            safe_command[ipmitool_index + 1 : ipmitool_index + 1] = [
                "-f",
                password_path,
            ]

        child_environment = scrubbed_child_environment()
        child_environment["PATH"] = TRUSTED_PRIVILEGED_PATH

        process = await asyncio.create_subprocess_exec(
            *safe_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=child_environment,
            start_new_session=terminate_process_group,
        )
        stdout, stderr = await _communicate_subprocess(
            process,
            timeout=timeout,
            terminate_process_group=terminate_process_group,
        )
        return process.returncode, stdout, stderr


def _ssh_stream_chunk_bytes(chunk: Union[str, bytes]) -> int:
    """
    Measure decoded SSH text and raw SSH bytes under one byte contract.

    The implementation uses ``chunk`` to measure decoded SSH text and raw SSH
    bytes under one byte contract. If the function cannot measure decoded SSH
    text and raw SSH bytes under one byte contract, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        chunk: Text supplied as chunk in the format accepted by this function.

    Returns:
        The numeric SSH stream chunk bytes value.

    Raises:
        ValueError: If SSH process returned a non-text, non-binary output chunk.
    """

    if isinstance(chunk, bytes):
        return len(chunk)
    if isinstance(chunk, str):
        return len(chunk.encode("utf-8", errors="surrogatepass"))
    raise ValueError("SSH process returned a non-text, non-binary output chunk")


async def _read_ssh_stream_bounded(
    reader: Any,
    *,
    stream_name: str,
    budget: _SSHOutputBudget,
) -> Union[str, bytes]:
    """
    Read one remote stream incrementally without accepting partial success.

    Match the historical ``result.stdout or \\"\\"`` behavior for an empty.

    Args:
        reader: Reader object whose ``read`` state is read while performing one
            remote stream incrementally without accepting partial success.
        stream_name: Stable stream name used for lookup and operator-facing
            diagnostics.
        budget: Budget object whose ``consume``, ``limits``, and
            ``read_chunk_bytes`` state is read while performing one remote
            stream incrementally without accepting partial success.

    Returns:
        The canonical SSH stream bounded text.

    Raises:
        ValueError: If SSH process ``stream_name`` returned an invalid output
            chunk; or SSH process ``stream_name`` changed output type during
            execution.
    """

    chunks: List[Union[str, bytes]] = []
    retain_command_stream(stream_name, chunks)
    chunk_type: Optional[type] = None
    while True:
        chunk = await reader.read(budget.limits.read_chunk_bytes)
        if not chunk:
            break
        if not isinstance(chunk, (str, bytes)):
            raise ValueError(
                f"SSH process {stream_name} returned an invalid output chunk"
            )
        if chunk_type is None:
            chunk_type = bytes if isinstance(chunk, bytes) else str
        elif not isinstance(chunk, chunk_type):
            raise ValueError(
                f"SSH process {stream_name} changed output type during execution"
            )

        budget.consume(stream_name, _ssh_stream_chunk_bytes(chunk))
        chunks.append(chunk)

    if chunk_type is bytes:
        result = b"".join(chunks)  # type: ignore[arg-type]
    elif chunk_type is str:
        result = "".join(chunks)  # type: ignore[arg-type]
    else:
        # Preserve the historical empty result for binary-mode connections too.
        result = ""
    retain_command_stream(stream_name, [result])
    return result


async def _write_ssh_process_input(
    writer: Any,
    input_data: Optional[Union[str, bytes]],
    *,
    chunk_units: int,
) -> None:
    """
    Feed existing caller-owned input without making another full-size copy.

    Input is written and drained in bounded chunks before EOF is signaled. A
    peer-closed stdin is treated as end-of-input because the remote process has
    already been created and its exit status and bounded output remain the
    authoritative outcome; this function never requests a replay. Cancellation
    and every other writer failure remain authoritative to the caller.

    Args:
        writer: Writer object whose ``drain``, ``write``, and ``write_eof``
            state is read while performing feed existing caller-owned input
            without making another full-size copy.
        input_data: Text supplied as input data in the format accepted by this
            function.
        chunk_units: Numeric chunk units used while the operation performs
            bounded accounting.

    Raises:
        BaseException: If cancellation or a writer failure other than peer
            closure interrupts input delivery.
    """

    # AsyncSSH's run()/communicate() sends data and EOF only when input is
    # truthy. Preserve that behavior for None and empty strings/bytes.
    if not input_data:
        return
    try:
        for offset in range(0, len(input_data), chunk_units):
            writer.write(input_data[offset : offset + chunk_units])
            await writer.drain()
        writer.write_eof()
    except (BrokenPipeError, ConnectionResetError):
        # The remote process can close its stdin after it has accepted enough
        # input, or after it has already produced a terminal nonzero result.
        # Preserve that authoritative exit status and bounded output instead of
        # cancelling the readers and manufacturing a transport failure. This
        # path is post-creation and must never trigger a command replay.
        return


def _force_abort_ssh_process(process: Any) -> None:
    """
    Best-effort forced termination after graceful channel close stalls.

    The implementation uses ``process`` to best-effort forced termination after
    graceful channel close stalls.

    Args:
        process: Process object whose ``channel`` state is read while performing
            best-effort forced termination after graceful channel close stalls.
    """

    kill = getattr(process, "kill", None)
    if callable(kill):
        try:
            kill()
        except Exception as error:
            logger.debug("Unable to kill SSH process during cleanup: %s", error)

    try:
        channel = process.channel
    except Exception as error:
        logger.debug("Unable to access SSH process channel during cleanup: %s", error)
        return
    abort = getattr(channel, "abort", None)
    if callable(abort):
        try:
            abort()
        except Exception as error:
            logger.debug(
                "Unable to abort SSH process channel during cleanup: %s", error
            )


async def _terminate_and_drain_ssh_process(
    process: Any,
    *,
    timeout: float = SSH_PROCESS_CLEANUP_TIMEOUT_SECONDS,
) -> None:
    """
    Terminate one AsyncSSH process and bound both cleanup phases.

    The implementation uses ``process`` and ``timeout`` to terminate one
    AsyncSSH process and bound both cleanup phases. Owned asynchronous work is
    awaited before return, so completion does not leave an unobserved task
    behind. If the function cannot terminate one AsyncSSH process and bound both
    cleanup phases, its exception reaches the caller instead of being converted
    into a successful result.

    Args:
        process: Process consumed while the function attempts to terminate one
            AsyncSSH process and bound both cleanup phases.
        timeout: Maximum duration allowed before the operation is cancelled or
            fails.

    Raises:
        ValueError: If the ssh process cleanup timeout is not finite and
            positive.
        RuntimeError: If SSH process cannot confirm channel cleanup; or SSH
            process channel cleanup did not complete.
    """

    cleanup_timeout = float(timeout)
    if not math.isfinite(cleanup_timeout) or cleanup_timeout <= 0:
        raise ValueError("SSH process cleanup timeout must be finite and positive")

    terminate = getattr(process, "terminate", None)
    if callable(terminate):
        try:
            terminate()
        except Exception as error:
            logger.debug("Unable to terminate SSH process during cleanup: %s", error)

    close = getattr(process, "close", None)
    if callable(close):
        try:
            close()
        except Exception as error:
            logger.debug("Unable to close SSH process during cleanup: %s", error)

    loop = asyncio.get_running_loop()
    deadline = loop.time() + cleanup_timeout
    graceful_budget = min(cleanup_timeout / 2.0, max(0.0, deadline - loop.time()))
    wait_closed = getattr(process, "wait_closed", None)
    if not callable(wait_closed):
        _force_abort_ssh_process(process)
        raise RuntimeError("SSH process cannot confirm channel cleanup")

    first_error: Optional[BaseException] = None
    if graceful_budget > 0:
        try:
            await asyncio.wait_for(wait_closed(), timeout=graceful_budget)
            return
        except Exception as error:
            first_error = error

    _force_abort_ssh_process(process)
    forced_budget = max(0.0, deadline - loop.time())
    if forced_budget > 0:
        try:
            await asyncio.wait_for(wait_closed(), timeout=forced_budget)
            return
        except Exception as error:
            first_error = error

    raise RuntimeError("SSH process channel cleanup did not complete") from first_error


async def _await_ssh_process_cleanup(
    process: Any,
    *,
    primary_error: Optional[BaseException] = None,
) -> None:
    """
    Drain exact SSH process cleanup while retaining caller control flow.

    The implementation uses ``process`` and ``primary_error`` to drain exact SSH
    process cleanup while retaining caller control flow. Owned asynchronous work
    is awaited before return, so completion does not leave an unobserved task
    behind. If the function cannot drain exact SSH process cleanup while
    retaining caller control flow, its exception reaches the caller instead of
    being converted into a successful result.

    Args:
        process: Process consumed while the function attempts to drain exact SSH
            process cleanup while retaining caller control flow.
        primary_error: Optional primary error; ``None`` selects the function's
            default behavior.

    Raises:
        BaseException: If a delegated failure occurs while the function attempts
            to drain exact SSH process cleanup while retaining caller control
            flow.
    """

    cleanup_task = asyncio.create_task(
        capture_owned_awaitable(_terminate_and_drain_ssh_process(process))
    )
    drain_error: Optional[BaseException] = None
    cleanup_error: Optional[BaseException] = None
    try:
        (cleanup_outcome,) = await drain_owned_tasks(
            (cleanup_task,),
            cancel_on_wait_error=False,
        )
    except BaseException as error:
        drain_error = error
        try:
            cleanup_outcome = cleanup_task.result()
        except BaseException as task_error:
            cleanup_error = task_error
        else:
            cleanup_error = cleanup_outcome.error
    else:
        cleanup_error = cleanup_outcome.error

    if cleanup_error is not None:
        logger.error(
            "Unable to complete SSH process cleanup",
            exc_info=(
                type(cleanup_error),
                cleanup_error,
                cleanup_error.__traceback__,
            ),
        )

    observed_errors: List[BaseException] = []
    if primary_error is not None:
        observed_errors.append(primary_error)
    if drain_error is not None:
        observed_errors.append(drain_error)
    elif cleanup_error is not None:
        observed_errors.append(cleanup_error)
    if observed_errors:
        raise select_authoritative_exception(observed_errors)


def _completed_ssh_process_from_creation_task(
    creation_task: asyncio.Task[Any],
) -> Optional[Any]:
    """
    Recover a process returned on the same loop edge as interruption.

    The implementation uses ``creation_task`` to recover a process returned on
    the same loop edge as interruption.

    Args:
        creation_task: Creation task object whose ``done`` and ``result`` state
            is read while performing recover a process returned on the same loop
            edge as interruption.

    Returns:
        The completed SSH process from creation task value selected by the
        operation, or ``None`` when the requested value is unavailable.
    """

    if not creation_task.done():
        return None
    try:
        outcome = creation_task.result()
    except BaseException:
        return None
    if outcome.error is not None:
        return None
    return outcome.value


async def _run_ssh_process_bounded(
    conn: Any,
    command: str,
    *,
    timeout: float,
    input_data: Optional[Union[str, bytes]] = None,
    limits: Optional[SSHProcessOutputLimits] = None,
) -> Tuple[int, Union[str, bytes], Union[str, bytes]]:
    """
    Run one AsyncSSH process with finite concurrent stream collection.

    The implementation uses ``conn``, ``command``, ``timeout``, ``input_data``,
    and ``limits`` to run one AsyncSSH process with finite concurrent stream
    collection. Terminal status is emitted only after one AsyncSSH process with
    finite concurrent stream collection and its owned cleanup have completed.
    Owned asynchronous work is awaited before return, so completion does not
    leave an unobserved task behind. If the function cannot run one AsyncSSH
    process with finite concurrent stream collection, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        conn: Connection object whose ``create_process`` state is read while
            performing one AsyncSSH process with finite concurrent stream
            collection.
        command: Text supplied as command in the format accepted by this
            function.
        timeout: Maximum duration allowed before the operation is cancelled or
            fails.
        input_data: Optional input data; ``None`` selects the function's default
            behavior.
        limits: Optional Limits governing one AsyncSSH process with finite
            concurrent stream collection.

    Returns:
        A tuple containing the exit status, bounded stdout, and bounded stderr.

    Raises:
        ValueError: If SSH process output limits have an invalid type; or the
            ssh command timeout is not finite.
        BaseException: If a delegated failure occurs while the function attempts
            to run one AsyncSSH process with finite concurrent stream
            collection.
        AssertionError: If SSH process cleanup lost its primary failure.
        RuntimeError: If SSH process creation returned no channel.
    """

    active_limits = DEFAULT_SSH_PROCESS_OUTPUT_LIMITS if limits is None else limits
    if type(active_limits) is not SSHProcessOutputLimits:
        raise ValueError("SSH process output limits have an invalid type")
    command_timeout = float(timeout)
    if not math.isfinite(command_timeout):
        raise ValueError("SSH command timeout must be finite")
    if command_timeout <= 0:
        raise asyncio.TimeoutError

    loop = asyncio.get_running_loop()
    deadline = loop.time() + command_timeout
    try:
        process_awaitable = conn.create_process(command)
    except BaseException as error:
        # AsyncSSH can reject a channel synchronously before returning an
        # awaitable. No remote process exists in this path, so it is safe for
        # the pool to replace the transport and make its one pre-execution retry.
        raise HostSSHProcessCreationFailure(error) from error
    creation_task = asyncio.create_task(capture_owned_awaitable(process_awaitable))
    try:
        async with asyncio.timeout(max(0.0, deadline - loop.time())):
            (creation_outcome,) = await drain_owned_tasks((creation_task,))
    except BaseException as error:
        process = _completed_ssh_process_from_creation_task(creation_task)
        if process is not None:
            await _await_ssh_process_cleanup(process, primary_error=error)
            raise AssertionError("SSH process cleanup lost its primary failure")
        raise

    if creation_outcome.error is not None:
        raise HostSSHProcessCreationFailure(creation_outcome.error)
    process = creation_outcome.value
    if process is None:
        raise RuntimeError("SSH process creation returned no channel")

    owned_tasks: List[asyncio.Task[Any]] = []
    drain_started = False
    try:
        budget = _SSHOutputBudget(active_limits)
        stdout_reader = process.stdout
        stderr_reader = process.stderr
        stdin_writer = process.stdin
        owned_tasks.append(
            asyncio.create_task(
                capture_owned_awaitable(
                    _read_ssh_stream_bounded(
                        stdout_reader,
                        stream_name="stdout",
                        budget=budget,
                    )
                )
            )
        )
        owned_tasks.append(
            asyncio.create_task(
                capture_owned_awaitable(
                    _read_ssh_stream_bounded(
                        stderr_reader,
                        stream_name="stderr",
                        budget=budget,
                    )
                )
            )
        )
        owned_tasks.append(
            asyncio.create_task(
                capture_owned_awaitable(
                    _write_ssh_process_input(
                        stdin_writer,
                        input_data,
                        chunk_units=active_limits.read_chunk_bytes,
                    )
                )
            )
        )
        owned_tasks.append(
            asyncio.create_task(capture_owned_awaitable(process.wait_closed()))
        )
        async with asyncio.timeout(max(0.0, deadline - loop.time())):
            drain_started = True
            outcomes = await drain_owned_tasks(
                owned_tasks,
                cancel_on_error=lambda _error: True,
            )
    except BaseException as error:
        cancelled_task_ids: set[int] = set()
        if not drain_started:
            for task in owned_tasks:
                if not task.done():
                    if task.cancel():
                        cancelled_task_ids.add(id(task))
        if owned_tasks and not drain_started:
            try:
                setup_outcomes = await drain_owned_tasks(
                    owned_tasks,
                    cancel_on_wait_error=False,
                )
            except BaseException as drain_error:
                error = select_authoritative_exception((error, drain_error))
            else:
                setup_errors = [
                    outcome.error
                    for task, outcome in zip(owned_tasks, setup_outcomes)
                    if outcome.error is not None
                    and not outcome.owner_cancelled
                    and not (
                        id(task) in cancelled_task_ids
                        and isinstance(outcome.error, asyncio.CancelledError)
                    )
                ]
                if setup_errors:
                    error = select_authoritative_exception((error, *setup_errors))
        await _await_ssh_process_cleanup(process, primary_error=error)
        raise AssertionError("SSH process cleanup lost its primary failure")

    errors = [
        outcome.error
        for outcome in outcomes
        if outcome.error is not None and not outcome.owner_cancelled
    ]
    if errors:
        error = select_authoritative_exception(errors)
        await _await_ssh_process_cleanup(process, primary_error=error)
        raise AssertionError("SSH process cleanup lost its primary failure")

    return process.exit_status, outcomes[0].value, outcomes[1].value


def _is_terminal_batched_ssh_error(error: BaseException) -> bool:
    """
    Return whether a shared SSH batch must stop after one command failure.

    Process-creation failures prove that the remote command never acquired a
    usable channel. Connection-loss and local socket failures likewise make
    subsequent commands on the same shared route unsafe or predictably
    unsuccessful. Command-specific failures such as bounded-output rejection
    are deliberately excluded so independent commands can still produce
    useful partial evidence.

    Args:
        error: Exception raised while starting or draining one command on the
            batch's shared SSH connection.

    Returns:
        Whether remaining commands must be recorded as not attempted.
    """

    return isinstance(
        error,
        (
            HostSSHProcessCreationFailure,
            asyncssh.ChannelOpenError,
            asyncssh.ConnectionLost,
            asyncssh.DisconnectError,
            EOFError,
            OSError,
        ),
    )


async def _wait_closed(conn: Any) -> None:
    """
    Drain asyncssh connection shutdown for deterministic fd cleanup.

    The implementation uses ``conn`` to drain asyncssh connection shutdown for
    deterministic fd cleanup. Owned asynchronous work is awaited before return,
    so completion does not leave an unobserved task behind.

    Args:
        conn: Connection object whose ``wait_closed`` state is read while
            performing drain asyncssh connection shutdown for deterministic fd
            cleanup.
    """
    await conn.wait_closed()


async def _close_ssh_connection_bounded(
    conn: Any,
    *,
    timeout: float = SSH_CONNECTION_CLOSE_TIMEOUT_SECONDS,
) -> None:
    """
    Close an asyncssh connection without allowing shutdown to hang.

    The implementation uses ``conn`` and ``timeout`` to close an asyncssh
    connection without allowing shutdown to hang. Owned asynchronous work is
    awaited before return, so completion does not leave an unobserved task
    behind. If the function cannot close an asyncssh connection without allowing
    shutdown to hang, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        conn: Connection object whose ``close`` state is read while performing
            close an asyncssh connection without allowing shutdown to hang.
        timeout: Maximum duration allowed before the operation is cancelled or
            fails.

    Raises:
        RuntimeError: If SSH connection shutdown timed out and cannot be
            aborted; or SSH connection shutdown remained incomplete after abort.
    """
    conn.close()

    try:
        await asyncio.wait_for(_wait_closed(conn), timeout=timeout)
    except asyncio.TimeoutError as error:
        abort = getattr(conn, "abort", None)
        if not callable(abort):
            raise RuntimeError(
                "SSH connection shutdown timed out and cannot be aborted"
            ) from error
        abort()
        try:
            await asyncio.wait_for(_wait_closed(conn), timeout=timeout)
        except asyncio.TimeoutError as abort_error:
            raise RuntimeError(
                "SSH connection shutdown remained incomplete after abort"
            ) from abort_error


async def _close_raw_or_external_ssh_connection(owner: Any, conn: Any) -> None:
    """
    Close through manager ownership when ``conn`` holds a capacity lease.

    The implementation uses ``owner`` and ``conn`` to close through manager
    ownership when ``conn`` holds a capacity lease. Owned asynchronous work is
    awaited before return, so completion does not leave an unobserved task
    behind.

    Args:
        owner: Owner object whose ``_close_ssh_connection_chain`` state is read
            while performing close through manager ownership when ``conn`` holds
            a capacity lease.
        conn: Connection consumed while the function attempts to close through
            manager ownership when ``conn`` holds a capacity lease.
    """

    leases = getattr(owner, "_raw_ssh_connection_leases", None)
    lease = leases.get(id(conn)) if isinstance(leases, dict) else None
    if lease is not None and lease[0] is conn:
        await owner._close_ssh_connection_chain(conn)
        return
    await _close_ssh_connection_bounded(conn)


class DUTCredentials:
    """
    DUT credentials and connection information.

    The type gives the DUT credentials responsibility a stable runtime boundary.
    Callers use the declared Python protocol instead of depending on its
    representation.
    """

    def __init__(
        self,
        bmc_ip: str,
        bmc_username: str,
        bmc_password: str,
        bmc_ssh_username: Optional[str] = None,
        bmc_ssh_password: Optional[str] = None,
        bmc_ssh_port: int = 22,
        bmc_ssh_key_path: Optional[str] = None,
        bmc_ssh_passwordless: bool = False,
        bmc_ssh_max_retries: int = 3,
        bmc_rf_port: int = 443,
        bmc_use_https: bool = True,
        bmc_rf_verify_ssl: bool = False,
        host_ip: Optional[str] = None,
        host_username: Optional[str] = None,
        host_password: Optional[str] = None,
        host_ssh_port: int = 22,
        host_ssh_key_path: Optional[str] = None,
        host_ssh_passwordless: bool = False,
        host_ssh_max_retries: int = 3,
        rf_username: Optional[str] = None,
        rf_password: Optional[str] = None,
        tunnel_tcp_port: Optional[int] = None,
        ipmi_cipher: str = "-C17",
        # HMC Configuration
        hmc_ip: Optional[str] = None,
        hmc_username: Optional[str] = None,
        hmc_password: Optional[str] = None,
        hmc_ssh_username: Optional[str] = None,
        hmc_ssh_password: Optional[str] = None,
        hmc_ssh_port: int = 22,
        hmc_ssh_key_path: Optional[str] = None,
        hmc_ssh_passwordless: bool = False,
        hmc_ssh_max_retries: int = 3,
        hmc_http_port: int = 80,
        hmc_https_port: int = 443,
        hmc_use_https: bool = False,
        use_port_forwarding: bool = False,
        rf_hmc_access_method: Optional[str] = None,
        execution_mode: str = "remote",
        hmc_ip_candidates: Optional[List[str]] = None,
        hmc_ip_explicit: bool = False,
        # SSH Proxy Configuration
        ssh_proxy_host: Optional[str] = None,
        ssh_proxy_port: int = 22,
        ssh_proxy_username: Optional[str] = None,
        ssh_proxy_password: Optional[str] = None,
        ssh_proxy_key_path: Optional[str] = None,
        ssh_proxy_passwordless: bool = False,
        ssh_proxy_max_retries: int = 3,
        ssh_host_key_policy: str = "insecure",
        ssh_known_hosts_file: Optional[str] = None,
        *,
        host_sudo_password: Optional[str] = None,
    ) -> None:
        """
        Initialize DUT credentials and connection information.

        The initializer records ``bmc_ip``, ``bmc_password``, ``bmc_rf_port``,
        ``bmc_rf_verify_ssl``, and ``bmc_ssh_key_path`` for later operations and
        establishes the instance invariants before any public method runs.

        Args:
            bmc_ip: Text supplied as BMC IP in the format accepted by this
                function.
            bmc_username: Text supplied as BMC username in the format accepted
                by this function.
            bmc_password: Sensitive value supplied through the approved input
                boundary and never logged.
            bmc_ssh_username: Optional BMC SSH username; ``None`` selects the
                function's default behavior.
            bmc_ssh_password: Sensitive value supplied through the approved
                input boundary and never logged.
            bmc_ssh_port: Numeric BMC SSH port used while the operation performs
                bounded accounting.
            bmc_ssh_key_path: Optional filesystem location used as the BMC SSH
                key path for this operation.
            bmc_ssh_passwordless: Sensitive value supplied through the approved
                input boundary and never logged.
            bmc_ssh_max_retries: Numeric BMC SSH max retries used while the
                operation performs bounded accounting.
            bmc_rf_port: Numeric BMC Redfish port used while the operation
                performs bounded accounting.
            bmc_use_https: Whether BMC use HTTPS is enabled or required for this
                operation.
            bmc_rf_verify_ssl: Whether BMC Redfish verify ssl is enabled or
                required for this operation.
            host_ip: Optional host IP; ``None`` selects the function's default
                behavior.
            host_username: Optional host username; ``None`` selects the
                function's default behavior.
            host_password: Sensitive value supplied through the approved input
                boundary and never logged.
            host_sudo_password: Optional remote sudo credential, independent of
                the SSH login password or private-key passphrase.
            host_ssh_port: Numeric host SSH port used while the operation
                performs bounded accounting.
            host_ssh_key_path: Optional filesystem location used as the host SSH
                key path for this operation.
            host_ssh_passwordless: Sensitive value supplied through the approved
                input boundary and never logged.
            host_ssh_max_retries: Numeric host SSH max retries used while the
                operation performs bounded accounting.
            rf_username: Optional Redfish username; ``None`` selects the
                function's default behavior.
            rf_password: Sensitive value supplied through the approved input
                boundary and never logged.
            tunnel_tcp_port: Optional tunnel TCP port; ``None`` selects the
                function's default behavior.
            ipmi_cipher: Text supplied as IPMI cipher in the format accepted by
                this function.
            hmc_ip: Optional HMC IP; ``None`` selects the function's default
                behavior.
            hmc_username: Optional HMC username; ``None`` selects the function's
                default behavior.
            hmc_password: Sensitive value supplied through the approved input
                boundary and never logged.
            hmc_ssh_username: Optional HMC SSH username; ``None`` selects the
                function's default behavior.
            hmc_ssh_password: Sensitive value supplied through the approved
                input boundary and never logged.
            hmc_ssh_port: Numeric HMC SSH port used while the operation performs
                bounded accounting.
            hmc_ssh_key_path: Optional filesystem location used as the HMC SSH
                key path for this operation.
            hmc_ssh_passwordless: Sensitive value supplied through the approved
                input boundary and never logged.
            hmc_ssh_max_retries: Numeric HMC SSH max retries used while the
                operation performs bounded accounting.
            hmc_http_port: Numeric HMC HTTP port used while the operation
                performs bounded accounting.
            hmc_https_port: Numeric HMC HTTPS port used while the operation
                performs bounded accounting.
            hmc_use_https: Whether HMC use HTTPS is enabled or required for this
                operation.
            use_port_forwarding: Whether use port forwarding is enabled or
                required for this operation.
            rf_hmc_access_method: Optional Redfish HMC access method; ``None``
                selects the function's default behavior.
            execution_mode: Text supplied as execution mode in the format
                accepted by this function.
            hmc_ip_candidates: Optional HMC IP candidates; ``None`` selects the
                function's default behavior.
            hmc_ip_explicit: Whether HMC IP explicit is enabled or required for
                this operation.
            ssh_proxy_host: Optional SSH proxy host; ``None`` selects the
                function's default behavior.
            ssh_proxy_port: Numeric SSH proxy port used while the operation
                performs bounded accounting.
            ssh_proxy_username: Optional SSH proxy username; ``None`` selects
                the function's default behavior.
            ssh_proxy_password: Sensitive value supplied through the approved
                input boundary and never logged.
            ssh_proxy_key_path: Optional filesystem location used as the SSH
                proxy key path for this operation.
            ssh_proxy_passwordless: Sensitive value supplied through the
                approved input boundary and never logged.
            ssh_proxy_max_retries: Numeric SSH proxy max retries used while the
                operation performs bounded accounting.
            ssh_host_key_policy: SSH host key policy governing initialize DUT
                credentials and connection information.
            ssh_known_hosts_file: Optional filesystem location used as the SSH
                known hosts file for this operation.
        """
        self.bmc_ip = bmc_ip
        self.bmc_username = bmc_username
        self.bmc_password = bmc_password
        self.bmc_ssh_username = bmc_ssh_username
        self.bmc_ssh_password = bmc_ssh_password
        self.bmc_ssh_port = bmc_ssh_port
        self.bmc_ssh_key_path = bmc_ssh_key_path
        self.bmc_ssh_passwordless = bmc_ssh_passwordless
        self.bmc_ssh_max_retries = bmc_ssh_max_retries
        self.bmc_rf_port = bmc_rf_port
        self.bmc_use_https = bmc_use_https
        self.bmc_rf_verify_ssl = bmc_rf_verify_ssl
        self.host_ip = host_ip
        self.host_username = host_username
        self.host_password = host_password
        self.host_sudo_password = host_sudo_password
        self.host_ssh_port = host_ssh_port
        self.host_ssh_key_path = host_ssh_key_path
        self.host_ssh_passwordless = host_ssh_passwordless
        self.host_ssh_max_retries = host_ssh_max_retries
        self.rf_username = rf_username
        self.rf_password = rf_password
        self.tunnel_tcp_port = tunnel_tcp_port
        self.ipmi_cipher = ipmi_cipher
        # HMC Configuration
        self.hmc_ip = hmc_ip
        self.hmc_username = hmc_username or bmc_username
        self.hmc_password = hmc_password or bmc_password
        self.hmc_ssh_username = hmc_ssh_username or bmc_ssh_username or bmc_username
        self.hmc_ssh_password = hmc_ssh_password or bmc_ssh_password or bmc_password
        self.hmc_ssh_port = hmc_ssh_port
        self.hmc_ssh_key_path = hmc_ssh_key_path
        self.hmc_ssh_passwordless = hmc_ssh_passwordless
        self.hmc_ssh_max_retries = hmc_ssh_max_retries
        self.hmc_http_port = hmc_http_port
        self.hmc_https_port = hmc_https_port
        self.hmc_use_https = hmc_use_https
        self.use_port_forwarding = use_port_forwarding
        self.rf_hmc_access_method = rf_hmc_access_method
        self.execution_mode = _normalize_execution_mode(execution_mode)
        self.hmc_ip_candidates = list(hmc_ip_candidates) if hmc_ip_candidates else []
        self.hmc_ip_explicit = hmc_ip_explicit
        self.hmc_ip_validated = False
        # SSH Proxy Configuration
        self.ssh_proxy_host = ssh_proxy_host
        self.ssh_proxy_port = ssh_proxy_port
        self.ssh_proxy_username = ssh_proxy_username
        self.ssh_proxy_password = ssh_proxy_password
        self.ssh_proxy_key_path = ssh_proxy_key_path
        self.ssh_proxy_passwordless = ssh_proxy_passwordless
        self.ssh_proxy_max_retries = ssh_proxy_max_retries
        self.ssh_host_key_policy = ssh_host_key_policy
        self.ssh_known_hosts_file = ssh_known_hosts_file


class DUTConnectionState:
    """
    DUT connection state tracking.

    The type coordinates ``set_host_connected``, ``set_ssh_connected``,
    ``set_redfish_connected``, ``set_ipmi_connected``, and ``set_hmc_connected``
    and retains the state those operations share between calls. Resource
    ownership remains inside the instance until the matching close, exit, or
    cleanup operation completes.
    """

    def __init__(self) -> None:
        """
        Initialize DUT connection state.

        The initializer records ``hmc_connected``, ``host_connected``,
        ``ipmi_connected``, ``last_hmc_check``, and ``last_host_check`` for
        later operations and establishes the instance invariants before any
        public method runs.
        """
        self.redfish_connected = False
        self.ipmi_connected = False
        self.ssh_connected = False
        self.host_connected = False
        self.hmc_connected = False
        self.port_forwarding_active = False
        self.last_redfish_check: Optional[datetime] = None
        self.last_ipmi_check: Optional[datetime] = None
        self.last_ssh_check: Optional[datetime] = None
        self.last_host_check: Optional[datetime] = None
        self.last_hmc_check: Optional[datetime] = None

    def set_host_connected(self, connected: bool, dut_id: str = None) -> None:
        """
        Set host connection state with logging.

        The implementation uses ``connected`` and ``dut_id`` to set host
        connection state with logging. It updates ``host_connected`` on the
        instance as part of that state transition.

        Args:
            connected: Whether connected is enabled or required for this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        if self.host_connected != connected:
            if dut_id:
                pass
                # print(
                #     f"[DEBUG] DUT {dut_id}: Host connection state changing from {self.host_connected} to {connected}"
                # )
        self.host_connected = connected

    def set_ssh_connected(self, connected: bool, dut_id: str = None) -> None:
        """
        Set SSH connection state with logging.

        The implementation uses ``connected`` and ``dut_id`` to set SSH
        connection state with logging. It updates ``ssh_connected`` on the
        instance as part of that state transition.

        Args:
            connected: Whether connected is enabled or required for this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        if self.ssh_connected != connected:
            if dut_id:
                pass
                # print(
                #     f"[DEBUG] DUT {dut_id}: SSH connection state changing from {self.ssh_connected} to {connected}"
                # )
        self.ssh_connected = connected

    def set_redfish_connected(self, connected: bool, dut_id: str = None) -> None:
        """
        Set Redfish connection state with logging.

        The implementation uses ``connected`` and ``dut_id`` to set Redfish
        connection state with logging. It updates ``redfish_connected`` on the
        instance as part of that state transition.

        Args:
            connected: Whether connected is enabled or required for this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        if self.redfish_connected != connected:
            if dut_id:
                pass
                # print(
                #     f"[DEBUG] DUT {dut_id}: Redfish connection state changing from {self.redfish_connected} to {connected}"
                # )
        self.redfish_connected = connected

    def set_ipmi_connected(self, connected: bool, dut_id: str = None) -> None:
        """
        Set IPMI connection state with logging.

        The implementation uses ``connected`` and ``dut_id`` to set IPMI
        connection state with logging. It updates ``ipmi_connected`` on the
        instance as part of that state transition.

        Args:
            connected: Whether connected is enabled or required for this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        if self.ipmi_connected != connected:
            if dut_id:
                pass
                # print(
                #     f"[DEBUG] DUT {dut_id}: IPMI connection state changing from {self.ipmi_connected} to {connected}"
                # )
        self.ipmi_connected = connected

    def set_hmc_connected(self, connected: bool, dut_id: str = None) -> None:
        """
        Set HMC connection state with logging.

        The implementation uses ``connected`` and ``dut_id`` to set HMC
        connection state with logging. It updates ``hmc_connected`` on the
        instance as part of that state transition.

        Args:
            connected: Whether connected is enabled or required for this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        if self.hmc_connected != connected:
            if dut_id:
                pass
                # print(
                #     f"[DEBUG] DUT {dut_id}: HMC connection state changing from {self.hmc_connected} to {connected}"
                # )
        self.hmc_connected = connected


class DUT:
    """
    Device Under Test (DUT) class.

    The type coordinates ``redfish_tls_request_kwargs``,
    ``_validated_redfish_connection_info``, ``_get_redfish_service_root``,
    ``_get_catalog_redfish_service_root``, and ``_replace_catalog_service_root``
    and retains the state those operations share between calls. Resource
    ownership remains inside the instance until the matching close, exit, or
    cleanup operation completes.
    """

    REDFISH_CACHE_MAX_ENTRIES = 500
    REDFISH_CACHE_MAX_BYTES = 32 * 1024 * 1024
    REDFISH_CACHE_MAX_ENTRY_BYTES = 4 * 1024 * 1024

    def __init__(
        self,
        dut_id: str,
        credentials: DUTCredentials,
        config: Dict[str, Any],
        dut_manager: Optional["DUTManager"] = None,
    ) -> None:
        """
        Initialize DUT.

        Check if this is HGX-HMC platform (will be set in async_init).

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            credentials: Sensitive value supplied through the approved input
                boundary and never logged.
            config: Config governing initialize DUT.
            dut_manager: Optional DUT manager; ``None`` selects the function's
                default behavior.

        Raises:
            RuntimeError: If DUT ``dut_id`` resolved an invalid HMC Redfish
                service root.
        """
        self.dut_id = dut_id
        self.credentials = credentials
        self.config = config
        self.connection_state = DUTConnectionState()
        self.log_dir: Optional[Path] = None
        self.hmc_service = None  # Will be set if HMC mode is active
        self._hmc_connection_lock = asyncio.Lock()
        self.platform_info: Optional[Dict[str, str]] = None
        self.dut_manager = dut_manager  # Reference to DUT manager for SSH operations
        self.is_initialized = False
        self.initialization_error: Optional[str] = None

        # Check if this is HGX-HMC platform (will be set in async_init)
        self.is_hmc_platform = False
        # Auto-configure HMC settings (will be done in async_init)

        # Redfish session management
        self.redfish_session = None
        self.redfish_auth = None
        self.redfish_connector = None
        self.redfish_session_pool = None  # Will be initialized when needed
        self.redfish_session_config: Dict[str, Any] = {}
        self.redfish_tls_policy = RedfishTLSPolicy()
        self.redfish_ssl = self.redfish_tls_policy.build_ssl_parameter()
        self.redfish_session_timeout = 300
        self.redfish_keepalive_timeout = 300
        self.redfish_ttl_dns_cache = 300
        self.redfish_use_dns_cache = True
        self.redfish_force_close = False
        self.redfish_enable_cleanup_closed = True
        self.redfish_fallback_connection_pool_limit = 15
        self.redfish_fallback_connection_pool_limit_per_host = 6
        self.redfish_response_limits = DEFAULT_REDFISH_RESPONSE_LIMITS

        # Redfish caching
        self.__redfish_cache = {}
        self.__redfish_cache_sizes = {}
        self.__redfish_cache_bytes = 0

        # Redfish prefix configuration
        configured_redfish_prefix = self.config.get("RF_DEFAULT_PREFIX")
        catalog_service_root = getattr(
            getattr(self.dut_manager, "uri_config_manager", None),
            "service_root",
            None,
        )
        if configured_redfish_prefix is not None:
            self.redfish_default_prefix = configured_redfish_prefix
        elif isinstance(catalog_service_root, str) and catalog_service_root:
            self.redfish_default_prefix = catalog_service_root
        else:
            # Compatibility for isolated DUT objects created without the runtime
            # URI manager. Managed DUT creation materializes the catalog root.
            self.redfish_default_prefix = "/redfish/v1"
        # HMC-specific prefix for URIs containing HGX_* resource segments.
        # When set, response-body URIs (pagination, task links, etc.) that target
        # HMC resources are normalized with this prefix instead of redfish_default_prefix.
        self.redfish_hmc_default_prefix = (
            self.config.get("RF_HMC_DEFAULT_PREFIX") or None
        )
        # An explicit empty/null HMC prefix clears lower-precedence HMC policy
        # and resolves to the catalog root.  Preserve that *effective* root for
        # response-derived HGX links even though the authored config value is
        # intentionally retained as an empty/null clear.
        dut_manager = getattr(self, "dut_manager", None)
        uri_config_manager = getattr(dut_manager, "uri_config_manager", None)
        get_root_provenance = getattr(
            uri_config_manager, "get_service_root_provenance", None
        )
        get_effective_root = getattr(uri_config_manager, "get_service_root", None)
        if callable(get_root_provenance) and callable(get_effective_root):
            hmc_root_source = get_root_provenance(self.dut_id, hmc=True)
            if hmc_root_source in {"dut_hmc", "tool_hmc"}:
                effective_hmc_root = get_effective_root(self.dut_id, hmc=True)
                if not isinstance(effective_hmc_root, str) or not effective_hmc_root:
                    raise RuntimeError(
                        f"DUT {self.dut_id} resolved an invalid HMC Redfish "
                        "service root"
                    )
                self.redfish_hmc_default_prefix = effective_hmc_root

        # Track which config keys were explicitly set in the DUT YAML (not from defaults)
        # Dictionary format: {key_name: True/False} where True means it was in the DUT YAML
        self.explicit_config_keys: Dict[str, bool] = {}

    def redfish_tls_request_kwargs(
        self, *, use_https: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Return the resolved TLS options for every Redfish request path.

        After applying local validation, the function forwards ``use_https`` to
        ``self.redfish_tls_policy.request_kwargs`` and preserves its return and
        exception contract.

        Args:
            use_https: Whether use HTTPS is enabled or required for this
                operation.

        Returns:
            A mapping containing Redfish TLS request kwargs.
        """

        if use_https is None:
            use_https = self.credentials.bmc_use_https
        return self.redfish_tls_policy.request_kwargs(
            self.redfish_ssl, use_https=use_https
        )

    def _validated_redfish_connection_info(
        self, connection_info: Dict[str, Any], *, endpoint_name: str
    ) -> Dict[str, Any]:
        """
        Validate the active endpoint before exposing connection details.

        The implementation uses ``connection_info`` and ``endpoint_name`` to
        validate the active endpoint before exposing connection details. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Args:
            connection_info: Mapping supplying fields for active endpoint before
                exposing connection details.
            endpoint_name: Validated remote resource identifier used for
                endpoint name.

        Returns:
            The validated ``connection_info``.

        Raises:
            ValueError: If active ``endpoint_name`` Redfish endpoint has no
                valid HTTPS policy.
        """

        use_https = connection_info.get("use_https")
        if not isinstance(use_https, bool):
            raise ValueError(
                f"Active {endpoint_name} Redfish endpoint has no valid HTTPS policy"
            )
        self.redfish_tls_policy.require_compatible_transport(
            use_https=use_https,
            endpoint_name=endpoint_name,
        )
        return connection_info

    def _get_redfish_service_root(self, *, hmc: bool = False) -> str:
        """
        Return the catalog-owned service root for this DUT.

        The implementation uses ``hmc`` to produce the catalog-owned service
        root for this DUT. If the function cannot produce the catalog-owned
        service root for this DUT, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            hmc: Whether HMC is enabled or required for this operation.

        Returns:
            The validated ``service_root``.

        Raises:
            RuntimeError: If DUT ``dut_id`` has no URI configuration manager for
                Redfish routing; or DUT ``dut_id`` resolved an invalid Redfish
                service root.
        """

        dut_manager = getattr(self, "dut_manager", None)
        uri_config_manager = getattr(dut_manager, "uri_config_manager", None)
        if uri_config_manager is None:
            raise RuntimeError(
                f"DUT {self.dut_id} has no URI configuration manager for Redfish routing"
            )
        service_root = uri_config_manager.get_service_root(self.dut_id, hmc=hmc)
        if not isinstance(service_root, str) or not service_root:
            raise RuntimeError(
                f"DUT {self.dut_id} resolved an invalid Redfish service root"
            )
        return service_root

    def _get_catalog_redfish_service_root(self) -> str:
        """
        Return the unmodified catalog root used when rewriting response URIs.

        Lightweight DUT objects that never issue Redfish requests can still
        normalize relative values without inventing a source root.

        Returns:
            Whether the unmodified catalog root used when rewriting response
            URIs operation succeeds.
        """

        dut_manager = getattr(self, "dut_manager", None)
        uri_config_manager = getattr(dut_manager, "uri_config_manager", None)
        catalog_root = getattr(uri_config_manager, "service_root", None)
        if isinstance(catalog_root, str) and catalog_root:
            return catalog_root.rstrip("/") or "/"
        # Lightweight DUT objects that never issue Redfish requests can still
        # normalize relative values without inventing a source root.
        return str(self.redfish_default_prefix).rstrip("/") or "/"

    @staticmethod
    def _replace_catalog_service_root(
        uri: str, catalog_root: str, target_root: str
    ) -> str:
        """
        Resolve a URI with the shared service-root and request-path policy.

        Preserve unrelated absolute paths and already-prefixed response links.
        This synchronous compatibility wrapper never starts logging tasks.

        Args:
            uri: Relative resource, absolute path, or HTTP response link.
            catalog_root: Service root authored in the catalog.
            target_root: Effective service root selected by configuration.

        Returns:
            A validated path-only request target retaining its safe query.

        Raises:
            ValueError: If a root or request URI violates Redfish URI policy.
        """

        return rebase_redfish_uri(uri, catalog_root, target_root)

    def has_explicit_config_key(self, key: str) -> bool:
        """
        Return whether ``key`` has explicit configuration key.

        Check if a config key was explicitly set in the DUT YAML (not from
        defaults).

        Args:
            key: Stable key used for lookup and operator-facing diagnostics.

        Returns:
            Whether ``key`` has explicit configuration key.
        """
        return self.explicit_config_keys.get(key, False)

    async def async_init(self) -> None:
        """
        Async initialization - detect HMC platform and configure settings.

        The implementation uses current instance state to async initialization -
        detect HMC platform and configure settings. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. It updates ``is_hmc_platform`` on the instance as part of that
        state transition.
        """
        # Check if this is HGX-HMC platform
        self.is_hmc_platform = await self._detect_hmc_platform()

        # Auto-configure HMC settings
        if self.is_hmc_platform:
            self._configure_hmc_settings()

        if self.config.get("dry_run"):
            await self._log_runtime(
                "INFO",
                "Dry-run mode - skipping Redfish session pool initialization",
            )
            return

        # Initialize Redfish session pool for better concurrency
        await self.initialize_redfish_session_pool()

        # Log initial session pool status
        if self.redfish_session_pool:
            stats = await self.redfish_session_pool.get_session_stats()
            await self._log_runtime("INFO", f"Session pool initialized: {stats}")

    async def _log_runtime(self, level: str, message: str) -> None:
        """
        Log message to DUT runtime file using async logger if available.

        Fallback to regular logger if async logger not available.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """
        if hasattr(self, "logger") and hasattr(self.logger, "write_to_dut_runtime_log"):
            await self.logger.write_to_dut_runtime_log(
                self.dut_id, level, "DUT", message
            )
        else:
            # Fallback to regular logger if async logger not available
            if level == "ERROR":
                logger.error(message)
            elif level == "WARNING":
                logger.warning(message)
            else:
                logger.info(message)

    async def create_redfish_session(self) -> bool:
        """
        Create or verify this DUT's Redfish session.

        After applying local validation, the function forwards current instance
        state to ``create_owned_redfish_session`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Returns:
            Whether the or verify this DUT's Redfish session operation succeeds.
        """

        return await create_owned_redfish_session(self)

    async def _create_fallback_session(self, connection_info: Dict[str, Any]) -> bool:
        """
        Create the DUT-owned fallback Redfish session.

        After applying local validation, the function forwards
        ``connection_info`` to ``create_fallback_redfish_session`` and preserves
        its return and exception contract. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            connection_info: Mapping supplying fields for DUT-owned fallback
                Redfish session.

        Returns:
            Whether the DUT-owned fallback Redfish session operation succeeds.
        """

        return await create_fallback_redfish_session(self, connection_info)

    async def initialize_redfish_session_pool(self) -> bool:
        """
        Initialize this DUT's high-performance Redfish pool.

        After applying local validation, the function forwards current instance
        state to ``initialize_owned_redfish_session_pool`` and preserves its
        return and exception contract. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Returns:
            Whether the initialize this DUT's high-performance Redfish pool
            operation succeeds.
        """

        return await initialize_owned_redfish_session_pool(
            self, pool_factory=RedfishSessionPool
        )

    async def close_redfish_session(self) -> None:
        """
        Close all Redfish resources owned by this DUT.

        The implementation uses current instance state to close all Redfish
        resources owned by this DUT. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.
        """

        await close_owned_redfish_session(self)

    def normalize_redfish_uri(self, uri: str, ignore_prefix: bool = False) -> str:
        """
        Normalize a Redfish request using configured service-root policy.

        Select an independent HMC root only for an HMC resource path; query
        values cannot change routing. Root replacement is idempotent for response
        links and accepts a custom root of ``/`` without adding a second slash.
        Rebase the most specific source root first so a nested BMC prefix does
        not become part of an HMC resource's identity.

        Args:
            uri: Relative resource, absolute path, or HTTP response link.
            ignore_prefix: Return the input unchanged when explicitly requested.

        Returns:
            The resolved path and safe query, or the unchanged bypassed input.

        Raises:
            ValueError: If the URI or configured roots violate Redfish URI policy.
        """
        if ignore_prefix:
            return uri

        catalog_root = self._get_catalog_redfish_service_root()
        path = urlsplit(uri).path
        target_root = self.redfish_default_prefix
        resource_path = f"/{path.lstrip('/')}"
        is_hmc_path = "/HGX_" in resource_path
        uri_manager = getattr(
            getattr(self, "dut_manager", None), "uri_config_manager", None
        )
        classify_hmc = getattr(uri_manager, "_is_hmc_uri", None)
        if callable(classify_hmc):
            classified = classify_hmc(path, self.dut_id)
            if isinstance(classified, bool):
                is_hmc_path = classified
        if self.redfish_hmc_default_prefix and is_hmc_path:
            target_root = self.redfish_hmc_default_prefix
            normalized = uri
            for source_root in sorted(
                {catalog_root, self.redfish_default_prefix}, key=len, reverse=True
            ):
                normalized = self._replace_catalog_service_root(
                    normalized, source_root, target_root
                )
            return normalized
        return self._replace_catalog_service_root(uri, catalog_root, target_root)

    def reset_redfish_cache(self) -> None:
        """
        Reset Redfish cache (like legacy nvdebug).

        The implementation uses current instance state to reset Redfish cache
        (like legacy nvdebug). It updates ``__redfish_cache_bytes`` and
        ``__redfish_cache_sizes`` on the instance as part of that state
        transition.
        """
        self.__redfish_cache.clear()
        self.__redfish_cache_sizes = {}
        self.__redfish_cache_bytes = 0
        asyncio.create_task(self._log_runtime("INFO", "Redfish cache cleared"))

    def get_redfish_cache(self) -> Dict[str, Any]:
        """
        Get Redfish cache (like legacy nvdebug).

        After applying local validation, the function forwards current instance
        state to ``self.__redfish_cache.copy`` and preserves its return and
        exception contract.

        Returns:
            A mapping containing Redfish cache.
        """
        return self.__redfish_cache.copy()

    def _get_cached_response(self, uri: str) -> Optional[Any]:
        """
        Get cached response for URI.

        After applying local validation, the function forwards ``uri`` to
        ``self.__redfish_cache.get`` and preserves its return and exception
        contract.

        Args:
            uri: Validated remote resource identifier used for URI.

        Returns:
            The cached response value selected by the operation, or ``None``
            when the requested value is unavailable.
        """
        return self.__redfish_cache.get(uri)

    def _has_cached_response(self, uri: str) -> bool:
        """
        Return whether ``uri`` is cached, including falsey JSON payloads.

        The implementation uses ``uri`` to determine whether ``uri`` is cached,
        including falsey JSON payloads.

        Args:
            uri: Validated remote resource identifier used for URI.

        Returns:
            Whether ``uri`` is cached, including falsey JSON payloads.
        """
        return uri in self.__redfish_cache

    @staticmethod
    def _estimate_redfish_cache_size(response: Any) -> int:
        """
        Return the estimate Redfish cache size.

        The implementation uses ``response`` to produce the estimate Redfish
        cache size.

        Args:
            response: Transport response governed by the configured
                authentication and trust policy.

        Returns:
            The numeric estimate Redfish cache size.
        """
        if isinstance(response, bytes):
            return len(response)
        if isinstance(response, str):
            return len(response.encode("utf-8"))
        try:
            return len(
                json.dumps(
                    response,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
        except (TypeError, ValueError):
            return DUT.REDFISH_CACHE_MAX_ENTRY_BYTES + 1

    def _ensure_redfish_cache_accounting(self) -> None:
        """
        Ensure Redfish cache accounting.

        The implementation uses current instance state to ensure Redfish cache
        accounting. It updates ``__redfish_cache_bytes`` and
        ``__redfish_cache_sizes`` on the instance as part of that state
        transition.
        """
        sizes = getattr(self, "_DUT__redfish_cache_sizes", None)
        if not isinstance(sizes, dict) or set(sizes) != set(self.__redfish_cache):
            sizes = {
                uri: self._estimate_redfish_cache_size(response)
                for uri, response in self.__redfish_cache.items()
            }
            self.__redfish_cache_sizes = sizes
            self.__redfish_cache_bytes = sum(sizes.values())
        elif not hasattr(self, "_DUT__redfish_cache_bytes"):
            self.__redfish_cache_bytes = sum(sizes.values())

    def _cache_response(
        self,
        uri: str,
        response: Any,
        *,
        size_bytes: Optional[int] = None,
    ) -> bool:
        """
        Cache response for URI.

        The implementation uses ``uri``, ``response``, and ``size_bytes`` to
        cache response for URI. It updates ``__redfish_cache_bytes`` on the
        instance as part of that state transition. If the function cannot cache
        response for URI, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            uri: Validated remote resource identifier used for URI.
            response: Transport response governed by the configured
                authentication and trust policy.
            size_bytes: Optional size bytes; ``None`` selects the function's
                default behavior.

        Returns:
            Whether the cache response for URI operation succeeds.

        Raises:
            ValueError: If redfish cache size cannot be negative.
        """
        self._ensure_redfish_cache_accounting()
        if size_bytes is None:
            size_bytes = self._estimate_redfish_cache_size(response)
        if size_bytes < 0:
            raise ValueError("Redfish cache size cannot be negative")

        previous_size = self.__redfish_cache_sizes.pop(uri, 0)
        if uri in self.__redfish_cache:
            del self.__redfish_cache[uri]
            self.__redfish_cache_bytes -= previous_size

        if (
            size_bytes > self.REDFISH_CACHE_MAX_ENTRY_BYTES
            or size_bytes > self.REDFISH_CACHE_MAX_BYTES
        ):
            return False

        while self.__redfish_cache and (
            len(self.__redfish_cache) >= self.REDFISH_CACHE_MAX_ENTRIES
            or self.__redfish_cache_bytes + size_bytes > self.REDFISH_CACHE_MAX_BYTES
        ):
            oldest_key = next(iter(self.__redfish_cache))
            del self.__redfish_cache[oldest_key]
            self.__redfish_cache_bytes -= self.__redfish_cache_sizes.pop(oldest_key, 0)

        self.__redfish_cache[uri] = response
        self.__redfish_cache_sizes[uri] = size_bytes
        self.__redfish_cache_bytes += size_bytes
        return True

    async def setup_logging(self, base_log_dir: Path) -> None:
        """
        Setup logging directory for this DUT.

        The implementation uses ``base_log_dir`` to setup logging directory for
        this DUT. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. It updates
        ``log_dir`` on the instance as part of that state transition. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Args:
            base_log_dir: filesystem location used as the base log dir for this
                operation.
        """
        # Debug logging
        await self._log_runtime(
            "INFO",
            f"setup_logging: self.dut_id = {self.dut_id} (type: {type(self.dut_id)})",
        )
        await self._log_runtime(
            "INFO",
            f"setup_logging: base_log_dir = {base_log_dir} (type: {type(base_log_dir)})",
        )

        self.log_dir = base_log_dir / self.dut_id
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories for different log types
        for subdir in ["redfish", "ipmi", "host", "ssh", "error-logs"]:
            (self.log_dir / subdir).mkdir(exist_ok=True)

    def _get_live_ssh_proxy_tunnel_ports(
        self,
        *,
        strict: bool = False,
    ) -> Dict[str, int]:
        """
        Refresh cached ports from exact process-owned proxy routes.

        Absence is an explicit direct-route policy, not a wildcard which may
        reuse proxy ownership created under an older configuration.

        Args:
            strict: Whether strict is enabled or required for this operation.

        Returns:
            A mapping containing live SSH proxy tunnel ports.

        Raises:
            RuntimeError: If could not verify live SSH proxy routes for DUT
                ``dut_id``; live SSH proxy route verifier returned an awaitable;
                or live SSH proxy route verifier returned malformed evidence.
        """

        if not self.credentials.ssh_proxy_host:
            # Absence is an explicit direct-route policy, not a wildcard which
            # may reuse proxy ownership created under an older configuration.
            self.ssh_proxy_tunnel_ports = {}
            return {}
        proxy_service = getattr(self, "ssh_proxy_service", None)
        if not proxy_service:
            self.ssh_proxy_tunnel_ports = {}
            return {}
        try:
            live_ports = proxy_service.get_live_tunnel_ports(
                self.dut_id,
                expected_proxy_host=self.credentials.ssh_proxy_host,
                expected_proxy_port=self.credentials.ssh_proxy_port,
                expected_routes={
                    "redfish": {
                        "remote_host": self.credentials.bmc_ip,
                        "remote_port": self.credentials.bmc_rf_port,
                        "protocol": (
                            "https" if self.credentials.bmc_use_https else "http"
                        ),
                    },
                    "bmc_ssh": {
                        "remote_host": self.credentials.bmc_ip,
                        "remote_port": self.credentials.bmc_ssh_port,
                        "protocol": "tcp",
                    },
                    "host_ssh": {
                        "remote_host": self.credentials.host_ip,
                        "remote_port": self.credentials.host_ssh_port,
                        "protocol": "tcp",
                    },
                },
            )
        except Exception as exc:
            if strict:
                raise RuntimeError(
                    f"Could not verify live SSH proxy routes for DUT {self.dut_id}"
                ) from exc
            logger.warning(
                "Could not verify live SSH proxy routes for DUT %s: %s",
                self.dut_id,
                exc,
            )
            live_ports = {}
        if asyncio.iscoroutine(live_ports):
            # Some callers replace the synchronous proxy service with an
            # AsyncMock during teardown.  Never retain or leak that unawaited
            # object as connection metadata.
            live_ports.close()
            if strict:
                raise RuntimeError(
                    "Live SSH proxy route verifier returned an awaitable"
                )
            live_ports = {}
        if type(live_ports) is not dict:  # noqa: E721 - subclasses are rejected
            if strict:
                raise RuntimeError(
                    "Live SSH proxy route verifier returned malformed evidence"
                )
            live_ports = {}
        self.ssh_proxy_tunnel_ports = dict(live_ports)
        return self.ssh_proxy_tunnel_ports

    def _require_live_ssh_proxy_tunnel_port(
        self,
        route_name: str,
        expected_port: int,
    ) -> int:
        """
        Re-prove exact tunnel ownership immediately before credential use.

        The live proxy registry is re-read at the credential-bearing boundary,
        preventing a stale listener port from surviving tunnel replacement.

        Args:
            route_name: Owned proxy route key to verify.
            expected_port: Port selected when that route was established.

        Returns:
            The verified local listener port.

        Raises:
            RuntimeError: If the route is missing, malformed, or was replaced.
        """

        live_ports = self._get_live_ssh_proxy_tunnel_ports(strict=True)
        live_port = live_ports.get(route_name)
        if type(live_port) is not int or live_port != expected_port:  # noqa: E721
            self.ssh_proxy_tunnel_ports = {}
            raise RuntimeError(
                "SSH proxy route ownership changed before credential-bearing use"
            )
        return live_port

    async def test_redfish_connection(self) -> Tuple[bool, str]:
        """
        Test Redfish with a reachability hint and authoritative HTTP request.

        A hard address or route failure stops before transport setup. Soft ICMP
        failures still proceed to the bounded authenticated request because a
        BMC may intentionally ignore echo traffic. The operation follows the
        configured TLS and proxy policy, updates detected HMC and tunnel state,
        and closes temporary connection resources before returning.

        Returns:
            A tuple containing the connection-success flag and sanitized status
            message.
        """
        connector = None
        request_timeout = runtime_boundary_value(
            self.config, "redfish_preflight_total_timeout_seconds"
        )
        connect_timeout = runtime_boundary_value(
            self.config, "redfish_preflight_connect_timeout_seconds"
        )
        read_timeout = runtime_boundary_value(
            self.config, "redfish_preflight_read_timeout_seconds"
        )
        max_retries = runtime_boundary_value(
            self.config, "redfish_preflight_max_retries"
        )
        retry_delay = runtime_boundary_value(
            self.config, "redfish_preflight_retry_delay_seconds"
        )
        retry_budget = redfish_preflight_retry_budget(self.config)
        wait_timeout = redfish_preflight_wait_timeout(self.config)
        try:
            # Debug logging
            await self._log_runtime(
                "DEBUG",
                f"test_redfish_connection called for DUT {self.dut_id}",
            )
            await self._log_runtime("DEBUG", f"is_hmc_platform: {self.is_hmc_platform}")
            await self._log_runtime("DEBUG", f"hmc_ip: {self.credentials.hmc_ip}")
            await self._log_runtime(
                "DEBUG", f"execution_mode: {self.credentials.execution_mode}"
            )

            use_hmc_path = self.is_hmc_platform
            if not use_hmc_path and self._uses_host_bmc_tcp_port_forwarding():
                use_hmc_path = await self._detect_hmc_platform()
                self.is_hmc_platform = use_hmc_path
                await self._log_runtime(
                    "DEBUG",
                    f"Early HMC preflight detection result: {use_hmc_path}",
                )

            # Handle local mode
            if self.credentials.execution_mode == "local":
                await self._log_runtime(
                    "INFO",
                    "DUT is in local mode, skipping Redfish connection test",
                )
                self.connection_state.set_redfish_connected(True, self.dut_id)
                self.connection_state.last_redfish_check = datetime.now()
                return (
                    True,
                    "Local mode - Redfish connection assumed successful",
                )

            # Handle HMC mode with port forwarding (like legacy nvdebug)
            if use_hmc_path and self.credentials.hmc_ip:
                await self._log_runtime("DEBUG", "Using HMC port forwarding path")
                return await self._test_redfish_hmc_connection()
            else:
                await self._log_runtime(
                    "DEBUG",
                    f"Using standard BMC path (is_hmc_platform={use_hmc_path}, hmc_ip={self.credentials.hmc_ip})",
                )

            # Standard BMC connection
            # Check if SSH proxy is configured
            await self._log_runtime(
                "DEBUG",
                f"SSH proxy check: ssh_proxy_host={self.credentials.ssh_proxy_host}, ssh_proxy_username={self.credentials.ssh_proxy_username}",
            )
            proxy_redfish_port = None
            if self.credentials.ssh_proxy_host:
                await self._log_runtime(
                    "INFO",
                    f"Using SSH proxy {self.credentials.ssh_proxy_host} for Redfish connections",
                )

                try:
                    tunnel_ports = await self.ensure_bmc_redfish_proxy_route()
                except RuntimeError as error:
                    return False, str(error)
                proxy_redfish_port = tunnel_ports["redfish_port"]

                await self._log_runtime(
                    "INFO",
                    f"SSH proxy tunneling established for Redfish: localhost:{proxy_redfish_port} -> {self.credentials.bmc_ip}:{self.credentials.bmc_rf_port}",
                )
            else:
                # Collect a typed reachability hint only for the direct route.
                reachability = await self._ping_host(
                    self.credentials.bmc_ip, detailed=True
                )
                blocking_message = self._blocking_reachability_message(
                    reachability,
                    "BMC",
                    self.credentials.bmc_ip,
                )
                if blocking_message:
                    return False, blocking_message

            # The bounded HTTP request remains authoritative after a soft hint.
            # Determine protocol based on bmc_use_https flag
            protocol = "https" if self.credentials.bmc_use_https else "http"
            url_host = format_redfish_url_host(self.credentials.bmc_ip)
            service_root = self._get_redfish_service_root()

            if proxy_redfish_port is not None:
                # Use SSH proxy tunnel
                url = f"{protocol}://localhost:{proxy_redfish_port}{service_root}"
                await self._log_runtime(
                    "DEBUG",
                    f"Using SSH proxy tunnel for Redfish: {url}",
                )
            else:
                # Use direct connection
                url = (
                    f"{protocol}://{url_host}:"
                    f"{self.credentials.bmc_rf_port}{service_root}"
                )
                await self._log_runtime(
                    "DEBUG",
                    f"Using direct connection for Redfish: {url}",
                )

            username = self.credentials.rf_username or self.credentials.bmc_username
            password = self.credentials.rf_password or self.credentials.bmc_password
            use_auth = self.config.get("RF_AUTH", True) and bool(username and password)
            redfish_auth = (
                encode_basic_auth_header(username, password) if use_auth else None
            )

            # Use aiohttp with retry logic for reliability. BMC Redfish services
            # can pause for several seconds while collectors are active.
            timeout = aiohttp.ClientTimeout(
                total=request_timeout,
                connect=connect_timeout,
                sock_read=read_timeout,
            )

            # Use connector with minimal connection pooling for preflight
            # Determine SSL usage based on bmc_use_https flag (consistent with HMC pattern)
            use_ssl = self.credentials.bmc_use_https

            if use_ssl:
                ssl_context = self.redfish_ssl
                await self._log_runtime(
                    "DEBUG",
                    "Using HTTPS with Redfish TLS mode "
                    f"'{self.redfish_tls_policy.mode}' "
                    f"(port {self.credentials.bmc_rf_port})",
                )
            else:
                # HTTP connection - no SSL
                ssl_context = False
                await self._log_runtime(
                    "DEBUG",
                    f"Using HTTP (no SSL) for Redfish connection (port {self.credentials.bmc_rf_port})",
                )

            # Retry logic for transient failures
            for attempt in range(max_retries + 1):
                connector = aiohttp.TCPConnector(
                    ssl=ssl_context,
                    limit=1,  # Single connection limit
                    limit_per_host=1,  # Single connection per host
                    ttl_dns_cache=300,  # DNS cache TTL
                    use_dns_cache=True,
                    force_close=True,  # Force close after use
                    enable_cleanup_closed=True,  # Clean up closed connections
                )
                try:
                    async with aiohttp.ClientSession(
                        timeout=timeout,
                        connector=connector,
                        auto_decompress=False,
                        headers={"Accept-Encoding": "gzip, deflate"},
                    ) as session:
                        if proxy_redfish_port is not None:
                            self._require_live_ssh_proxy_tunnel_port(
                                "redfish_port", proxy_redfish_port
                            )
                        async with session.get(
                            url,
                            headers={
                                "User-Agent": "nvdebug-preflight/1.0",
                                "Accept-Encoding": "gzip, deflate",
                                **build_redfish_request_headers(redfish_auth),
                            },
                            allow_redirects=False,
                            auto_decompress=False,
                            **self.redfish_tls_request_kwargs(use_https=use_ssl),
                        ) as response:
                            if response.status == 200:
                                # Check if credential validation is enabled in tool_config
                                preflight_config = {}
                                if self.dut_manager and hasattr(
                                    self.dut_manager, "tool_config"
                                ):
                                    preflight_config = self.dut_manager.tool_config.get(
                                        "preflight_config", {}
                                    )

                                # Default to True if not specified
                                validate_creds = preflight_config.get(
                                    "validate_credentials_in_preflight", True
                                )

                                if validate_creds and use_auth:
                                    validation_uris = self._get_redfish_validation_uris(
                                        preflight_config
                                    )
                                    validation_failures = []

                                    for auth_uri in validation_uris:
                                        normalized_auth_uri = (
                                            self.normalize_redfish_uri(auth_uri)
                                        )
                                        # Fail closed at the concatenation site
                                        # like the transport boundary
                                        # (``_validate_persistent_post_request``):
                                        # re-assert that the normalized value is
                                        # an authority-free, path-only Redfish
                                        # target before it is concatenated onto
                                        # ``{host}:{port}``. ``normalize_redfish_uri``
                                        # is a prefix rewriter, not a URI
                                        # validator, so any scheme, authority,
                                        # userinfo, or non-``/``-anchored path
                                        # raises here rather than demoting the
                                        # request authority.
                                        normalized_auth_uri = (
                                            validate_redfish_request_uri(
                                                normalized_auth_uri,
                                                context=(
                                                    "preflight credential "
                                                    "validation URI"
                                                ),
                                            )
                                        )

                                        await self._log_runtime(
                                            "DEBUG",
                                            f"Validating credentials against authenticated endpoint: {auth_uri} (normalized: {normalized_auth_uri})",
                                        )

                                        if proxy_redfish_port is not None:
                                            auth_url = f"{protocol}://localhost:{proxy_redfish_port}{normalized_auth_uri}"
                                        else:
                                            auth_url = f"{protocol}://{url_host}:{self.credentials.bmc_rf_port}{normalized_auth_uri}"

                                        try:
                                            if proxy_redfish_port is not None:
                                                self._require_live_ssh_proxy_tunnel_port(
                                                    "redfish_port",
                                                    proxy_redfish_port,
                                                )
                                            async with session.get(
                                                auth_url,
                                                headers={
                                                    "User-Agent": "nvdebug-preflight/1.0",
                                                    "Accept-Encoding": "gzip, deflate",
                                                    **build_redfish_request_headers(
                                                        redfish_auth
                                                    ),
                                                },
                                                allow_redirects=False,
                                                auto_decompress=False,
                                                **self.redfish_tls_request_kwargs(
                                                    use_https=use_ssl
                                                ),
                                            ) as auth_response:
                                                response_text = _decode_redfish_body(
                                                    auth_response,
                                                    await _read_redfish_body_bounded(
                                                        auth_response,
                                                        _resolved_redfish_limit(
                                                            self,
                                                            "preflight_response_max_bytes",
                                                            REDFISH_PREFLIGHT_RESPONSE_MAX_BYTES,
                                                        ),
                                                        category="preflight response",
                                                    ),
                                                )
                                                response_payload = None
                                                if response_text:
                                                    try:
                                                        response_payload = json.loads(
                                                            response_text
                                                        )
                                                    except json.JSONDecodeError:
                                                        response_payload = None

                                                if auth_response.status == 401:
                                                    await self._log_runtime(
                                                        "ERROR",
                                                        f"Redfish credential validation failed: HTTP 401 Unauthorized at {normalized_auth_uri}",
                                                    )
                                                    if connector:
                                                        await connector.close()
                                                    return (
                                                        False,
                                                        "Redfish credentials invalid: HTTP 401 Unauthorized. Please verify BMC_USERNAME/BMC_PASSWORD or RF_User/RF_Pass are correct.",
                                                    )

                                                if auth_response.status == 403:
                                                    validation_failures.append(
                                                        f"{normalized_auth_uri} -> HTTP 403 Forbidden"
                                                    )
                                                    await self._log_runtime(
                                                        "DEBUG",
                                                        f"Redfish credential validation probe returned HTTP 403 Forbidden at {normalized_auth_uri}",
                                                    )
                                                    continue

                                                if auth_response.status != 200:
                                                    validation_failures.append(
                                                        f"{normalized_auth_uri} -> HTTP {auth_response.status}"
                                                    )
                                                    await self._log_runtime(
                                                        "DEBUG",
                                                        f"Redfish credential validation probe failed at {normalized_auth_uri}: HTTP {auth_response.status}",
                                                    )
                                                    continue

                                                if not self._is_valid_redfish_validation_payload(
                                                    response_payload
                                                ):
                                                    validation_failures.append(
                                                        f"{normalized_auth_uri} -> HTTP 200 with non-resource/error payload"
                                                    )
                                                    await self._log_runtime(
                                                        "DEBUG",
                                                        f"Redfish credential validation probe at {normalized_auth_uri} returned HTTP 200 but not a valid Redfish resource payload",
                                                    )
                                                    continue

                                                self.connection_state.set_redfish_connected(
                                                    True, self.dut_id
                                                )
                                                self.connection_state.last_redfish_check = (
                                                    datetime.now()
                                                )
                                                await self._log_runtime(
                                                    "INFO",
                                                    f"Redfish credentials validated successfully against {normalized_auth_uri}",
                                                )
                                                if connector:
                                                    await connector.close()
                                                return (
                                                    True,
                                                    "Redfish connection and credentials validated successfully",
                                                )
                                        except Exception as cred_error:
                                            validation_failures.append(
                                                f"{normalized_auth_uri} -> error: {str(cred_error)}"
                                            )
                                            await self._log_runtime(
                                                "DEBUG",
                                                f"Redfish credential validation probe error at {normalized_auth_uri}: {str(cred_error)}",
                                            )
                                            continue

                                    if connector:
                                        await connector.close()
                                    return (
                                        False,
                                        "Redfish credential validation failed for all candidate endpoints: "
                                        + "; ".join(validation_failures),
                                    )
                                else:
                                    # Credential validation disabled, just check service availability
                                    validation_reason = (
                                        "RF_AUTH disabled"
                                        if not use_auth
                                        else "credential validation disabled in preflight_config"
                                    )
                                    await self._log_runtime(
                                        "INFO",
                                        f"{validation_reason}; only checking Redfish service availability",
                                    )
                                    self.connection_state.set_redfish_connected(
                                        True, self.dut_id
                                    )
                                    self.connection_state.last_redfish_check = (
                                        datetime.now()
                                    )
                                    # Explicitly close connector before returning
                                    if connector:
                                        await connector.close()
                                    return (
                                        True,
                                        "Redfish connection successful (credential validation disabled)",
                                    )
                            else:
                                # Explicitly close connector before returning
                                if connector:
                                    await connector.close()
                                return (
                                    False,
                                    f"Redfish connection failed: HTTP {response.status}",
                                )
                except asyncio.TimeoutError:
                    if attempt < max_retries:
                        if connector:
                            await connector.close()
                        await asyncio.sleep(retry_delay)
                        continue
                    # Explicitly close connector before returning
                    if connector:
                        await connector.close()
                    return (
                        False,
                        f"Redfish connection timeout after retries ({retry_budget}s total)",
                    )
                except aiohttp.ClientConnectorError as e:
                    error_msg = str(e)
                    if "Connection refused" in error_msg:
                        detailed_error = f"Redfish connection refused - BMC may be unreachable or service not running: {error_msg}"
                    elif "Connection reset" in error_msg:
                        detailed_error = f"Redfish connection reset by peer - BMC may have closed the connection: {error_msg}"
                    elif "Timeout" in error_msg:
                        detailed_error = f"Redfish connection timeout - BMC may be slow to respond: {error_msg}"
                    else:
                        detailed_error = f"Redfish connection error: {error_msg}"

                    await self._log_runtime(
                        "WARNING",
                        f"Redfish connection attempt {attempt + 1} failed: {detailed_error}",
                    )

                    if attempt < max_retries:
                        if connector:
                            await connector.close()
                        await asyncio.sleep(retry_delay)
                        continue
                    # Explicitly close connector before returning
                    if connector:
                        await connector.close()
                    return (
                        False,
                        f"Redfish connection failed after {max_retries + 1} attempts: {detailed_error}",
                    )
                except Exception as e:
                    error_type = type(e).__name__
                    error_msg = str(e)

                    # Provide more context for common errors
                    if (
                        "Session is closed" in error_msg
                        or "session" in error_msg.lower()
                    ):
                        detailed_error = (
                            f"Redfish session error ({error_type}): {error_msg}. "
                            f"This may indicate: (1) BMC closed the connection prematurely, "
                            f"(2) Network instability, (3) BMC service restarted, or "
                            f"(4) Authentication/SSL issues. Check BMC logs and network connectivity."
                        )
                    else:
                        detailed_error = (
                            f"Redfish connection error ({error_type}): {error_msg}"
                        )

                    await self._log_runtime(
                        "WARNING",
                        f"Redfish connection attempt {attempt + 1} failed: {detailed_error}",
                    )

                    if attempt < max_retries:
                        if connector:
                            await connector.close()
                        await asyncio.sleep(retry_delay)
                        continue
                    # Explicitly close connector before returning
                    if connector:
                        await connector.close()
                    return (
                        False,
                        detailed_error,
                    )
        except asyncio.TimeoutError:
            # Explicitly close connector before returning
            if connector:
                await connector.close()
            return (
                False,
                f"Redfish connection timeout ({wait_timeout}s)",
            )
        except Exception as e:
            # Explicitly close connector before returning
            if connector:
                await connector.close()
            return False, f"Redfish connection error: {str(e)}"

    def _get_redfish_validation_uris(
        self, preflight_config: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Return catalog-owned Redfish credential probes in policy order.

        After applying local validation, the function forwards
        ``preflight_config`` to
        ``uri_config_manager.get_credential_validation_uris`` and preserves its
        return and exception contract.

        Args:
            preflight_config: Optional Preflight config governing catalog-owned
                Redfish credential probes in policy order.

        Returns:
            The Redfish validation URIs returned in operation-defined order.

        Raises:
            RuntimeError: If DUT ``dut_id`` has no URI configuration manager for
                credential validation.
        """
        preflight_config = preflight_config or {}
        baseboard = str(self.config.get("baseboard") or "").strip()
        platform = str(self.config.get("platform") or "").strip()
        node_type = str(
            self.config.get("NodeType") or self.config.get("node_type") or ""
        ).strip()

        baseboard_type = None
        baseboard_manager = (
            self.dut_manager._get_baseboard_manager() if self.dut_manager else None
        )
        if baseboard_manager and baseboard:
            baseboard_type = baseboard_manager.get_baseboard_type(baseboard)

        uri_config_manager = getattr(self.dut_manager, "uri_config_manager", None)
        if uri_config_manager is None:
            raise RuntimeError(
                f"DUT {self.dut_id} has no URI configuration manager for "
                "credential validation"
            )
        return uri_config_manager.get_credential_validation_uris(
            self.dut_id,
            baseboard=baseboard or None,
            baseboard_type=baseboard_type,
            platform=platform or None,
            node_type=node_type or None,
            configured_uri=preflight_config.get("credential_validation_uri"),
        )

    @staticmethod
    def _is_valid_redfish_validation_payload(
        payload: Optional[Dict[str, Any]],
    ) -> bool:
        """
        Accept only real Redfish resources or collections for auth validation.

        The implementation uses ``payload`` to accept only real Redfish
        resources or collections for auth validation.

        Args:
            payload: Mapping supplying fields for accept only real Redfish
                resources or collections for auth validation.

        Returns:
            Whether the accept only real Redfish resources or collections for
            auth validation operation succeeds.
        """
        if not isinstance(payload, dict):
            return False
        if payload.get("error"):
            return False
        odata_type = payload.get("@odata.type")
        if (
            isinstance(odata_type, str)
            and odata_type.rsplit(".", 1)[-1] == "ServiceRoot"
        ):
            return False
        if payload.get("@odata.id"):
            return True
        if "Members" in payload:
            return True
        return False

    def _selects_host_bmc_tcp_port_forwarding(self) -> bool:
        """
        Return whether configuration explicitly selects HMC TCP forwarding.

        After applying local validation, the function forwards current instance
        state to ``bool`` and preserves its return and exception contract.

        Returns:
            Whether configuration explicitly selects HMC TCP forwarding.
        """
        access_method = (
            self.credentials.rf_hmc_access_method
            or self.config.get("RF_HMC_ACCESS_METHOD")
            or ""
        )
        return bool(
            self.credentials.use_port_forwarding
            or str(access_method).strip().lower() == "hostbmctcpportforwarding"
        )

    def _uses_host_bmc_tcp_port_forwarding(self) -> bool:
        """
        Return True when the selected HMC forwarding path is usable.

        After applying local validation, the function forwards current instance
        state to ``bool`` and preserves its return and exception contract.

        Returns:
            Whether the true when the selected HMC forwarding path is usable
            operation succeeds.
        """
        hmc_ip = self.credentials.hmc_ip
        return bool(
            isinstance(hmc_ip, str)
            and hmc_ip.strip()
            and self._selects_host_bmc_tcp_port_forwarding()
        )

    def uses_hmc_port_forwarding(self) -> bool:
        """
        Return whether this DUT supports and selects the forwarded HMC path.

        After applying local validation, the function forwards current instance
        state to ``bool`` and preserves its return and exception contract.

        Returns:
            Whether this DUT supports and selects the forwarded HMC path.
        """
        return bool(
            self.config.get("supports_hmc") is True
            and self.config.get("supports_bmc_ssh") is True
            and self._uses_host_bmc_tcp_port_forwarding()
        )

    @staticmethod
    def _extract_allow_tcp_forwarding_value(output: str) -> Optional[str]:
        """
        Extract an AllowTcpForwarding value from sshd -T or sshd_config output.

        The implementation uses ``output`` to extract an AllowTcpForwarding
        value from sshd -T or sshd_config output.

        Args:
            output: Text supplied as output in the format accepted by this
                function.

        Returns:
            The canonical allow TCP forwarding value, or ``None`` when the
            requested value is unavailable.
        """
        allowed_values = {"yes", "no", "all", "local", "remote"}
        for raw_line in str(output or "").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue

            parts = line.split()
            if not parts:
                continue

            first = parts[0].lower()
            if first == "allowtcpforwarding" and len(parts) > 1:
                return parts[1].lower()
            if first in allowed_values:
                return first

        return None

    def _host_bmc_tcp_forwarding_disabled_message(self, value: str) -> str:
        """
        Return the host BMC tcp forwarding disabled message.

        The implementation uses ``value`` to produce the host BMC tcp forwarding
        disabled message.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The canonical host BMC TCP forwarding disabled message.
        """
        return (
            "HMC port forwarding preflight failed: BMC SSH has "
            f"AllowTcpForwarding={value}, so HostBmcTcpPortForwarding cannot "
            "establish the tunnel. Set AllowTcpForwarding yes in "
            "/etc/ssh/sshd_config and restart sshd on the BMC."
        )

    async def _check_host_bmc_tcp_port_forwarding_preflight(
        self,
    ) -> Tuple[bool, str]:
        """
        Check the BMC SSH setting required by HostBmcTcpPortForwarding.

        This is intentionally non-blocking when the setting cannot be read. The
        existing tunnel setup still provides the authoritative failure for auth,
        reachability, or non-OpenSSH BMC images.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        if not self._uses_host_bmc_tcp_port_forwarding():
            return True, ""

        ssh_username = (
            self.credentials.bmc_ssh_username or self.credentials.bmc_username or ""
        )
        if not ssh_username:
            return (
                True,
                "HostBmcTcpPortForwarding preflight could not determine the "
                "BMC SSH username; continuing with tunnel setup",
            )

        quoted_ssh_username = shlex.quote(str(ssh_username))
        commands = [
            (
                "effective sshd config",
                (
                    f"sshd -T -C user={quoted_ssh_username} 2>/dev/null | "
                    "awk 'tolower($1) == \"allowtcpforwarding\" {print $2; exit}'"
                ),
            ),
            (
                "sshd_config",
                (
                    "awk 'tolower($1) == \"allowtcpforwarding\" {print $2}' "
                    "/etc/ssh/sshd_config 2>/dev/null | tail -n 1"
                ),
            ),
        ]
        errors: List[str] = []

        for source, command in commands:
            try:
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    self.dut_id, command, timeout=10
                )
            except Exception as exc:
                errors.append(f"{source}: {exc}")
                continue

            value = self._extract_allow_tcp_forwarding_value(stdout)
            if not value:
                if exit_code != 0 or stderr:
                    detail = stderr or stdout or f"exit_code={exit_code}"
                    errors.append(f"{source}: {detail}")
                continue

            if value in {"no", "remote"}:
                return False, self._host_bmc_tcp_forwarding_disabled_message(value)
            if value in {"yes", "all", "local"}:
                return (
                    True,
                    f"HostBmcTcpPortForwarding preflight: AllowTcpForwarding={value}",
                )

        detail = "; ".join(errors) if errors else "setting was not present"
        return (
            True,
            "HostBmcTcpPortForwarding preflight could not determine "
            f"AllowTcpForwarding on the BMC ({detail}); continuing with tunnel setup",
        )

    async def _test_redfish_hmc_connection(self) -> Tuple[bool, str]:
        """
        Serialize and test Redfish through the DUT's selected HMC route.

        A single DUT may be checked during capability discovery and again during
        collector preflight. Serializing the complete setup and probe prevents
        concurrent checks from racing to allocate or register the same local
        forwarding endpoint.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        connection_lock = getattr(self, "_hmc_connection_lock", None)
        if connection_lock is None:
            connection_lock = asyncio.Lock()
            self._hmc_connection_lock = connection_lock
        async with connection_lock:
            return await self._test_redfish_hmc_connection_once()

    async def _test_redfish_hmc_connection_once(self) -> Tuple[bool, str]:
        """
        Test one serialized Redfish connection through HMC forwarding.

        The DUT retains its HMC service before any await point so repeated
        preflights, cancellation, and final cleanup all reference the same
        resource owner. Tool-owned tunnels may be safely reused, while an
        externally managed endpoint is only registered and never adopted.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        try:
            # Retain ownership before any await so cancellation and overlapping
            # checks cannot orphan a newly created forwarding service.
            hmc_service = self.hmc_service
            if hmc_service is None:
                hmc_service = HMCService(
                    logger=self.logger, dut_manager=self.dut_manager
                )
                self.hmc_service = hmc_service
            bmc_ssh_host = self.credentials.bmc_ip
            bmc_ssh_port = self.credentials.bmc_ssh_port
            setup_port_forwarding = bool(
                self.config.get("SETUP_PORT_FORWARDING", False)
            )

            if self.credentials.ssh_proxy_host and setup_port_forwarding:
                await self._log_runtime(
                    "INFO",
                    f"Using SSH proxy {self.credentials.ssh_proxy_host} for HMC Redfish port forwarding",
                )
                existing_proxy_service = getattr(self, "ssh_proxy_service", None)
                tunnel_ports = self._get_live_ssh_proxy_tunnel_ports()
                if "bmc_ssh_port" not in tunnel_ports:
                    ssh_proxy_service = existing_proxy_service or SSHProxyService(
                        logger=self.logger, dut_manager=self.dut_manager
                    )
                    self.ssh_proxy_service = ssh_proxy_service

                    (
                        success,
                        tunnel_ports,
                        message,
                    ) = await ssh_proxy_service.setup_ssh_proxy_tunneling(
                        dut_id=self.dut_id,
                        bmc_ip=self.credentials.bmc_ip,
                        host_ip=self.credentials.host_ip,
                        ssh_proxy_host=self.credentials.ssh_proxy_host,
                        ssh_proxy_username=self.credentials.ssh_proxy_username,
                        ssh_proxy_password=self.credentials.ssh_proxy_password,
                        ssh_proxy_key_path=self.credentials.ssh_proxy_key_path,
                        ssh_proxy_passwordless=self.credentials.ssh_proxy_passwordless,
                        ssh_proxy_port=self.credentials.ssh_proxy_port,
                        bmc_redfish_port=self.credentials.bmc_rf_port,
                        bmc_use_https=self.credentials.bmc_use_https,
                        bmc_ipmi_port=623,
                        bmc_ssh_port=self.credentials.bmc_ssh_port,
                        host_ssh_port=self.credentials.host_ssh_port,
                        force_setup=True,
                        required_tunnels=["bmc_ssh"],
                    )

                    if not success:
                        return (
                            False,
                            f"Failed to setup SSH proxy tunneling for HMC Redfish: {message}",
                        )

                    self.ssh_proxy_service = ssh_proxy_service
                    self.ssh_proxy_tunnel_ports = tunnel_ports

                bmc_ssh_host = "localhost"
                bmc_ssh_port = tunnel_ports["bmc_ssh_port"]
                await self._log_runtime(
                    "INFO",
                    f"Using BMC SSH tunnel for HMC forwarding: {bmc_ssh_host}:{bmc_ssh_port}",
                )

            if setup_port_forwarding:
                (
                    forwarding_ok,
                    forwarding_message,
                ) = await self._check_host_bmc_tcp_port_forwarding_preflight()
                if forwarding_message:
                    await self._log_runtime(
                        "INFO" if forwarding_ok else "ERROR",
                        forwarding_message,
                    )
                if not forwarding_ok:
                    return False, forwarding_message

            if setup_port_forwarding:
                # Create a tool-owned SSH route only when explicitly requested.
                if self.credentials.ssh_proxy_host:
                    self._require_live_ssh_proxy_tunnel_port(
                        "bmc_ssh_port", bmc_ssh_port
                    )
                success, bound_port, message = (
                    await hmc_service.ensure_hmc_port_forwarding(
                        dut_id=self.dut_id,
                        bmc_ip=bmc_ssh_host,
                        bmc_ssh_username=self.credentials.bmc_ssh_username,
                        bmc_ssh_password=self.credentials.bmc_ssh_password,
                        bmc_ssh_key_path=self.credentials.bmc_ssh_key_path,
                        bmc_ssh_passwordless=self.credentials.bmc_ssh_passwordless,
                        bmc_ssh_host_key_alias=canonical_openssh_host_key_alias(
                            self.credentials.bmc_ip,
                            self.credentials.bmc_ssh_port,
                        ),
                        hmc_ip=self.credentials.hmc_ip,
                        hmc_username=self.credentials.hmc_username,
                        hmc_password=self.credentials.hmc_password,
                        bmc_ssh_port=bmc_ssh_port,
                        hmc_http_port=self.credentials.hmc_http_port,
                        hmc_https_port=self.credentials.hmc_https_port,
                        hmc_use_https=self.credentials.hmc_use_https,
                        force_setup=self.config.get("FORCE_PORT_FW", False),
                        local_port=self.config.get("TUNNEL_TCP_PORT"),
                        tunnel_config={
                            "TUNNEL_LOCAL_HOST": self.config.get(
                                "TUNNEL_LOCAL_HOST", "localhost"
                            ),
                            "SSH_TUNNEL_OPTIONS": self.config.get("SSH_TUNNEL_OPTIONS"),
                            "ssh_host_key_policy": (
                                self.credentials.ssh_host_key_policy
                            ),
                            "ssh_known_hosts_file": (
                                self.credentials.ssh_known_hosts_file
                            ),
                            "ssh_host_key_alias": (
                                self.credentials.bmc_ip
                                if (
                                    bmc_ssh_host == "localhost"
                                    and self.credentials.ssh_host_key_policy == "strict"
                                )
                                else None
                            ),
                            "SSH_TUNNEL_PREFIX": self.config.get(
                                "SSH_TUNNEL_PREFIX", DEFAULT_SSH_TUNNEL_PREFIX
                            ),
                        },
                    )
                )
            else:
                remote_port = (
                    self.credentials.hmc_https_port
                    if self.credentials.hmc_use_https
                    else self.credentials.hmc_http_port
                )
                try:
                    bound_port = hmc_service.register_external_hmc_forwarding(
                        local_host=self.config.get("TUNNEL_LOCAL_HOST", "localhost"),
                        local_port=self.config.get("TUNNEL_TCP_PORT"),
                        hmc_ip=self.credentials.hmc_ip,
                        hmc_remote_port=remote_port,
                        hmc_use_https=self.credentials.hmc_use_https,
                        hmc_username=self.credentials.hmc_username,
                        hmc_password=self.credentials.hmc_password,
                    )
                except (RuntimeError, ValueError) as exc:
                    return False, f"Invalid external HMC forwarding endpoint: {exc}"
                success = True
                message = "Using externally managed HMC forwarding endpoint"
                await self._log_runtime(
                    "INFO",
                    f"Using externally managed HMC forwarding endpoint on port {bound_port}",
                )

            if not success:
                return False, f"HMC port forwarding setup failed: {message}"

            # Now test standard Redfish connection using forwarded connection
            # This uses the same logic as normal Redfish but through localhost:bound_port
            connection_info = hmc_service.get_redfish_connection_info()

            # Test the forwarded connection using standard HTTP client
            try:
                protocol = (
                    "https" if connection_info.get("use_https", False) else "http"
                )
                service_root = self._get_redfish_service_root(hmc=True)
                url_host = format_redfish_url_host(connection_info["host"])
                url = (
                    f"{protocol}://{url_host}:"
                    f"{connection_info['port']}{service_root}"
                )
                use_auth = self.config.get("RF_AUTH", True) and bool(
                    self.credentials.hmc_username and self.credentials.hmc_password
                )
                auth = (
                    encode_basic_auth_header(
                        self.credentials.hmc_username,
                        self.credentials.hmc_password,
                    )
                    if use_auth
                    else None
                )

                # Debug logging
                await self._log_runtime(
                    "DEBUG",
                    f"HMC Redfish test - URL: {url}, protocol: {protocol}, host: {connection_info['host']}, port: {connection_info['port']}",
                )

                timeout_config = aiohttp.ClientTimeout(total=10)

                async with aiohttp.ClientSession(
                    timeout=timeout_config,
                    auto_decompress=False,
                    headers={"Accept-Encoding": "gzip, deflate"},
                ) as session:
                    if self.credentials.ssh_proxy_host and setup_port_forwarding:
                        self._require_live_ssh_proxy_tunnel_port(
                            "bmc_ssh_port", bmc_ssh_port
                        )
                    async with session.get(
                        url,
                        allow_redirects=False,
                        auto_decompress=False,
                        headers=build_redfish_request_headers(
                            auth,
                            {"Accept-Encoding": "gzip, deflate"},
                        ),
                        **self.redfish_tls_request_kwargs(
                            use_https=connection_info.get("use_https", False)
                        ),
                    ) as response:
                        if response.status == 200:
                            self.connection_state.set_redfish_connected(
                                True, self.dut_id
                            )
                            self.connection_state.last_redfish_check = datetime.now()
                            self.connection_state.port_forwarding_active = True
                            self.connection_state.set_hmc_connected(True, self.dut_id)
                            await self._log_runtime(
                                "INFO",
                                "HMC Redfish connection successful via transparent forwarding",
                            )
                            return (
                                True,
                                f"HMC Redfish connection successful via port {bound_port}",
                            )
                        else:
                            return (
                                False,
                                f"HMC Redfish connection failed: HTTP {response.status}",
                            )

            except asyncio.TimeoutError:
                return False, "HMC Redfish connection timeout"
            except Exception as e:
                return False, f"HMC Redfish connection error: {str(e)}"

        except Exception as e:
            return False, f"HMC connection setup error: {str(e)}"

    async def test_ipmi_connection(self) -> Tuple[bool, str]:
        """
        Test IPMI with a reachability hint and authoritative ipmitool request.

        A hard address or route failure stops before process setup. Soft ICMP
        failures still proceed to bounded ipmitool execution because a BMC may
        intentionally ignore echo traffic. Owned asynchronous work is awaited
        before return, and the operation updates ``is_hmc_platform`` as part of
        its state transition.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        try:
            use_hmc_path = self.is_hmc_platform
            if (
                not use_hmc_path
                and self.credentials.use_port_forwarding
                and self.credentials.hmc_ip
            ):
                use_hmc_path = await self._detect_hmc_platform()
                self.is_hmc_platform = use_hmc_path
                await self._log_runtime(
                    "DEBUG",
                    f"Early HMC IPMI preflight detection result: {use_hmc_path}",
                )

            # Handle local mode
            if self.credentials.execution_mode == "local":
                await self._log_runtime(
                    "INFO",
                    "DUT is in local mode, skipping IPMI connection test",
                )
                self.connection_state.set_ipmi_connected(True, self.dut_id)
                self.connection_state.last_ipmi_check = datetime.now()
                return True, "Local mode - IPMI connection assumed successful"

            if use_hmc_path:
                await self._log_runtime(
                    "INFO",
                    "Using BMC-local IPMI preflight path for HMC platform",
                )
                ipmi_preflight_command = build_trusted_ipmitool_remote_command(
                    ["mc", "info"]
                )
                exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                    self.dut_id,
                    ipmi_preflight_command,
                    timeout=20,
                )
                if exit_code == 0:
                    self.connection_state.set_ipmi_connected(True, self.dut_id)
                    self.connection_state.last_ipmi_check = datetime.now()
                    return (
                        True,
                        "IPMI connection successful via BMC-local ipmitool",
                    )

                error_msg = self._process_command_output(
                    stderr
                ) or self._process_command_output(stdout)
                return (
                    False,
                    f"IPMI connection failed via BMC-local ipmitool: {error_msg}",
                )

            if self.credentials.ssh_proxy_host:
                await self._log_runtime(
                    "INFO",
                    "Testing IPMI from SSH proxy "
                    f"{self.credentials.ssh_proxy_host} with remote ipmitool",
                )
                (
                    exit_code,
                    stdout,
                    stderr,
                ) = await self.dut_manager._run_single_ipmi_command(
                    self,
                    "mc info",
                    30,
                )
                if exit_code == 0:
                    self.connection_state.set_ipmi_connected(True, self.dut_id)
                    self.connection_state.last_ipmi_check = datetime.now()
                    return (
                        True,
                        "IPMI connection successful via SSH-proxy remote ipmitool",
                    )

                error_msg = self._process_command_output(
                    stderr
                ) or self._process_command_output(stdout)
                if not error_msg:
                    error_msg = (
                        f"remote ipmitool exited with status {exit_code} "
                        "without diagnostic output"
                    )
                return (
                    False,
                    "IPMI connection failed via SSH-proxy remote ipmitool: "
                    f"{error_msg}",
                )
            else:
                # Collect a typed reachability hint only for the direct route.
                reachability = await self._ping_host(
                    self.credentials.bmc_ip, detailed=True
                )
                blocking_message = self._blocking_reachability_message(
                    reachability,
                    "BMC",
                    self.credentials.bmc_ip,
                )
                if blocking_message:
                    return False, blocking_message

            # The bounded ipmitool request remains authoritative after a soft hint.
            ipmitool_path = resolve_trusted_ipmitool_path()
            if ipmitool_path is None:
                return (
                    False,
                    f"IPMI connection failed: {TRUSTED_IPMITOOL_NOT_FOUND_MESSAGE}",
                )
            cmd = [
                ipmitool_path,
                "-I",
                "lanplus",
                "-U",
                self.credentials.bmc_username,
                self.credentials.ipmi_cipher,
                "mc",
                "info",
            ]

            cmd[3:3] = ["-H", self.credentials.bmc_ip]

            # Wait for completion with timeout (increased for async environment)
            try:
                returncode, stdout, stderr = await _run_ipmitool_subprocess(
                    cmd,
                    self.credentials.bmc_password,
                    timeout=30,
                    credential_parent=self.dut_manager._get_ipmi_credential_root(),
                )
            except asyncio.TimeoutError:
                return False, "IPMI connection timeout (30s)"

            # Decode the output using robust method
            stdout_text = self._process_command_output(stdout)
            stderr_text = self._process_command_output(stderr)

            if returncode == 0:
                self.connection_state.set_ipmi_connected(True, self.dut_id)
                self.connection_state.last_ipmi_check = datetime.now()
                return True, "IPMI connection successful"
            else:
                return False, f"IPMI connection failed: {stderr_text}"
        except Exception as e:
            return False, f"IPMI connection error: {str(e)}"

    async def test_ssh_connection(self) -> Tuple[bool, str]:
        """
        Test BMC SSH with a reachability hint and authoritative command probe.

        A hard address or route failure stops before connection setup. Soft
        ICMP failures still proceed to the bounded command probe because a BMC
        may intentionally ignore echo traffic. Owned asynchronous work is
        awaited before return, and cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        self.connection_state.set_ssh_connected(False, self.dut_id)

        try:
            # Handle local mode
            if self.credentials.execution_mode == "local":
                await self._log_runtime(
                    "INFO",
                    "DUT is in local mode, skipping SSH connection test",
                )
                self.connection_state.set_ssh_connected(True, self.dut_id)
                self.connection_state.last_ssh_check = datetime.now()
                return True, "Local mode - SSH connection assumed successful"

            # Check if SSH proxy is configured
            if self.credentials.ssh_proxy_host:
                await self._log_runtime(
                    "INFO",
                    f"Using SSH proxy {self.credentials.ssh_proxy_host} for BMC SSH connections",
                )
                username = (
                    self.credentials.bmc_ssh_username or self.credentials.bmc_username
                )
                password = (
                    self.credentials.bmc_ssh_password or self.credentials.bmc_password
                )
                proxy_client = await self.dut_manager.create_proxy_connection(
                    self.dut_id
                )
                if proxy_client is None:
                    return (
                        False,
                        "Failed to establish strict SSH proxy connection",
                    )
                try:
                    (
                        exit_code,
                        stdout,
                        stderr,
                    ) = await self.dut_manager.execute_ssh_command(
                        host=self.credentials.bmc_ip,
                        port=self.credentials.bmc_ssh_port,
                        username=username,
                        password=password,
                        command=BMC_SSH_PREFLIGHT_COMMAND,
                        timeout=BMC_SSH_PREFLIGHT_TIMEOUT_SECONDS,
                        ssh_key_path=self.credentials.bmc_ssh_key_path,
                        passwordless=self.credentials.bmc_ssh_passwordless,
                        max_retries=self.credentials.bmc_ssh_max_retries,
                        proxy_client=proxy_client,
                        host_key_policy=self.credentials.ssh_host_key_policy,
                        known_hosts_file=self.credentials.ssh_known_hosts_file,
                        host_key_alias=self.credentials.bmc_ip,
                        raw_ssh_capacity_scope=self.dut_id,
                    )
                finally:
                    await _close_raw_or_external_ssh_connection(
                        self.dut_manager,
                        proxy_client,
                    )
            else:
                # No proxy - use direct connection
                # Collect a typed reachability hint for the direct route.
                reachability = await self._ping_host(
                    self.credentials.bmc_ip, detailed=True
                )
                blocking_message = self._blocking_reachability_message(
                    reachability,
                    "BMC",
                    self.credentials.bmc_ip,
                )
                if blocking_message:
                    return False, blocking_message

                # The bounded SSH command probe remains authoritative.
                username = (
                    self.credentials.bmc_ssh_username or self.credentials.bmc_username
                )
                password = (
                    self.credentials.bmc_ssh_password or self.credentials.bmc_password
                )

                # Use the enhanced SSH method for connection testing
                exit_code, stdout, stderr = await self.dut_manager.execute_ssh_command(
                    host=self.credentials.bmc_ip,
                    port=self.credentials.bmc_ssh_port,
                    username=username,
                    password=password,
                    command=BMC_SSH_PREFLIGHT_COMMAND,
                    timeout=BMC_SSH_PREFLIGHT_TIMEOUT_SECONDS,
                    ssh_key_path=self.credentials.bmc_ssh_key_path,
                    passwordless=self.credentials.bmc_ssh_passwordless,
                    max_retries=self.credentials.bmc_ssh_max_retries,
                    host_key_policy=self.credentials.ssh_host_key_policy,
                    known_hosts_file=self.credentials.ssh_known_hosts_file,
                    raw_ssh_capacity_scope=self.dut_id,
                )

            combined_output = "\n".join(
                value for value in (stdout, stderr) if value
            ).strip()
            if is_bmc_command_failure_output(stdout, stderr):
                detail = f": {combined_output}" if combined_output else ""
                return (
                    False,
                    "SSH command execution failed: known failure diagnostic "
                    f"detected{detail}",
                )

            if exit_code != 0:
                error_msg = (
                    stderr if stderr else f"command exited with status {exit_code}"
                )
                return False, f"SSH command execution failed: {error_msg}"

            if BMC_SSH_PREFLIGHT_SENTINEL not in (stdout or ""):
                return (
                    False,
                    "SSH command execution failed: expected output marker "
                    f"{BMC_SSH_PREFLIGHT_SENTINEL!r} was not returned",
                )

            self.connection_state.set_ssh_connected(True, self.dut_id)
            self.connection_state.last_ssh_check = datetime.now()
            return True, "SSH command execution successful"
        except Exception as e:
            return False, f"SSH connection error: {str(e)}"

    async def test_host_connection(self) -> Tuple[bool, str]:
        """
        Test Host SSH with a reachability hint and authoritative connection.

        A hard address or route failure stops before connection setup. Soft
        ICMP failures still proceed to the bounded Host SSH route because a
        host may intentionally ignore echo traffic. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        try:
            # Handle local mode
            if self.credentials.execution_mode == "local":
                await self._log_runtime(
                    "INFO",
                    "DUT is in local mode, skipping host connection test",
                )
                self.connection_state.set_host_connected(True, self.dut_id)
                self.connection_state.last_host_check = datetime.now()
                return True, "Local mode - Host connection assumed successful"

            # Check if local mode is set in config
            is_local_mode = self.config and self.config.get("local", False)

            if not self.credentials.host_ip:
                if is_local_mode:
                    # Local mode explicitly requested - allow execution without host IP
                    await self._log_runtime(
                        "INFO",
                        "Local mode enabled (--local flag), skipping host connection test",
                    )
                    self.connection_state.set_host_connected(True, self.dut_id)
                    self.connection_state.last_host_check = datetime.now()
                    return True, "Local host execution (--local flag)"
                else:
                    # No host IP and no local flag - this is a configuration error
                    return (
                        False,
                        "No host IP configured and --local flag not set",
                    )

            if self.credentials.ssh_proxy_host:
                await self._log_runtime(
                    "INFO",
                    f"Using SSH proxy {self.credentials.ssh_proxy_host} for host connections",
                )
            else:
                # No proxy - use direct connection
                # Collect a typed reachability hint for the direct route.
                reachability = await self._ping_host(
                    self.credentials.host_ip, detailed=True
                )
                blocking_message = self._blocking_reachability_message(
                    reachability, "Host"
                )
                if blocking_message:
                    return False, blocking_message

            # Preflight and collection share the same route-owned transport.
            exit_code, stdout, stderr = await self.dut_manager.execute_ssh_command(
                host=self.credentials.host_ip,
                port=self.credentials.host_ssh_port,
                username=self.credentials.host_username,
                password=self.credentials.host_password,
                command="",
                timeout=10,
                ssh_key_path=self.credentials.host_ssh_key_path,
                passwordless=self.credentials.host_ssh_passwordless,
                max_retries=self.credentials.host_ssh_max_retries,
                host_key_policy=self.credentials.ssh_host_key_policy,
                known_hosts_file=self.credentials.ssh_known_hosts_file,
                host_key_alias=(
                    self.credentials.host_ip
                    if self.credentials.ssh_proxy_host
                    else None
                ),
                host_pool_dut_id=self.dut_id,
            )

            if exit_code == 0:
                self.connection_state.set_host_connected(True, self.dut_id)
                self.connection_state.last_host_check = datetime.now()
                return True, "Host SSH connection successful"
            else:
                error_msg = (
                    stderr
                    if stderr
                    else f"SSH connection failed with exit code {exit_code}"
                )
                return False, f"Host SSH connection failed: {error_msg}"
        except Exception as e:
            return False, f"Host connection error: {str(e)}"

    async def _detect_hmc_platform(self) -> bool:
        """
        Detect HMC platform.

        The implementation uses current instance state to detect HMC platform.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Returns:
            Whether the detect HMC platform operation succeeds.
        """
        # Debug logging - use regular logger since this is a sync method

        await self._log_runtime(
            "DEBUG",
            f"[HMC DEBUG] _detect_hmc_platform called for DUT {self.dut_id}",
        )
        await self._log_runtime(
            "DEBUG",
            f"[HMC DEBUG] supports_hmc: {self.config.get('supports_hmc', 'unspecified')}",
        )
        await self._log_runtime(
            "DEBUG",
            f"[HMC DEBUG] use_port_forwarding: {self.credentials.use_port_forwarding}",
        )
        await self._log_runtime(
            "DEBUG",
            f"[HMC DEBUG] rf_hmc_access_method: {self.credentials.rf_hmc_access_method}",
        )
        await self._log_runtime(
            "DEBUG",
            f"[HMC DEBUG] baseboard: {self.config.get('baseboard', 'None')}",
        )
        await self._log_runtime(
            "DEBUG",
            f"[HMC DEBUG] platform_detection: {self.config.get('platform_detection', 'None')}",
        )

        # HMC forwarding is enabled either explicitly or by the HMC access method.
        if not self._selects_host_bmc_tcp_port_forwarding():
            await self._log_runtime(
                "DEBUG",
                "[HMC DEBUG] HMC TCP port forwarding is not configured, returning False",
            )
            return False

        # Check if baseboard supports HMC
        if catalog_transport_support(self.config, "hmc") is False:
            await self._log_runtime(
                "DEBUG",
                "[HMC DEBUG] Baseboard catalog explicitly disables HMC, returning False",
            )
            return False

        # HostBmcTcpPortForwarding itself requires BMC SSH even though its
        # payload is HMC Redfish traffic.
        if catalog_transport_support(self.config, "ssh") is False:
            await self._log_runtime(
                "DEBUG",
                "[HMC DEBUG] Baseboard catalog explicitly disables BMC SSH "
                "required for HMC forwarding, returning False",
            )
            return False

        # If we get here, HMC TCP port forwarding is configured and baseboard supports HMC.
        await self._log_runtime(
            "DEBUG",
            "[HMC DEBUG] HMC TCP port forwarding is configured and baseboard supports HMC, returning True",
        )
        return True

    def _configure_hmc_settings(self) -> None:
        """
        Auto-configure HMC settings when USE_PORT_FORWARDING is enabled.

        Resolve the endpoint completely before mutating forwarding, tunnel, or
        Redfish-auth state. An explicit empty winner must not fall through to a
        lower-precedence catalog route.

        Raises:
            HMCForwardingConfigurationError: If hmc port forwarding lacks an
                explicit HMC endpoint from the DUT configuration or baseboard
                platform_detection.hmc_ip.
        """
        # Keep direct-BMC operation unchanged unless forwarding is selected and
        # the catalog has not explicitly disabled either required transport.
        if (
            not self._selects_host_bmc_tcp_port_forwarding()
            or self.config.get("supports_hmc") is not True
            or self.config.get("supports_bmc_ssh") is not True
        ):
            return

        # Resolve the endpoint completely before mutating forwarding, tunnel, or
        # Redfish-auth state. An explicit empty winner must not fall through to
        # a lower-precedence catalog route.
        resolved_hmc_ip: Optional[str] = None
        resolved_hmc_candidates: List[str] = []
        if self.credentials.hmc_ip_explicit or self.credentials.hmc_ip is not None:
            raw_hmc_ip = self.credentials.hmc_ip
            if isinstance(raw_hmc_ip, str) and raw_hmc_ip.strip():
                resolved_hmc_ip = raw_hmc_ip.strip()
        else:
            platform_detection = self.config.get("platform_detection", {})
            hmc_ip_value = (
                platform_detection.get("hmc_ip")
                if isinstance(platform_detection, dict)
                else None
            )
            if isinstance(hmc_ip_value, list):
                resolved_hmc_candidates = [
                    str(value).strip()
                    for value in hmc_ip_value
                    if isinstance(value, str) and value.strip()
                ]
                if resolved_hmc_candidates:
                    resolved_hmc_ip = resolved_hmc_candidates[0]
            elif isinstance(hmc_ip_value, str) and hmc_ip_value.strip():
                resolved_hmc_ip = hmc_ip_value.strip()

        if resolved_hmc_ip is None:
            raise HMCForwardingConfigurationError(
                "HMC port forwarding requires an explicit HMC endpoint from "
                "the DUT configuration or baseboard platform_detection.hmc_ip"
            )

        self.redfish_tls_policy.require_compatible_transport(
            use_https=self.credentials.hmc_use_https,
            endpoint_name="HMC",
        )

        self.credentials.hmc_ip = resolved_hmc_ip
        if resolved_hmc_candidates and not self.credentials.hmc_ip_candidates:
            self.credentials.hmc_ip_candidates = resolved_hmc_candidates

        # Handle port forwarding setup
        setup_port_forwarding = self.config.get("SETUP_PORT_FORWARDING", False)

        if setup_port_forwarding:
            # nvdebug will set up port forwarding - use default port if not specified
            if not self.config.get("TUNNEL_TCP_PORT"):
                self.config["TUNNEL_TCP_PORT"] = 18888
        else:
            # User sets up port forwarding manually - use their specified port
            # TUNNEL_TCP_PORT should already be set by user
            pass

        # Set HMC access method to port forwarding
        self.credentials.rf_hmc_access_method = "HostBmcTcpPortForwarding"

        # Keep the BMC policy when selecting an unauthenticated HMC route.
        # A collector may still need a resource served by the Host BMC.
        if not hasattr(self, "_bmc_redfish_auth_enabled"):
            self._bmc_redfish_auth_enabled = self.config.get("RF_AUTH", True)
        self.config["RF_AUTH"] = False

        # Use async logger for DUT-specific logging
        if hasattr(self, "logger") and hasattr(self.logger, "write_to_dut_runtime_log"):
            asyncio.create_task(
                self.logger.write_to_dut_runtime_log(
                    self.dut_id,
                    "INFO",
                    "DUT",
                    f"Auto-configured HMC port forwarding: IP={self.credentials.hmc_ip}, Port={self.config.get('TUNNEL_TCP_PORT')}, Setup={setup_port_forwarding}",
                )
            )
        else:
            # Fallback to regular logger if async logger not available
            asyncio.create_task(
                self._log_runtime(
                    "INFO",
                    f"Auto-configured HMC port forwarding: IP={self.credentials.hmc_ip}, Port={self.config.get('TUNNEL_TCP_PORT')}, Setup={setup_port_forwarding}",
                )
            )

    def get_redfish_connection_info(self) -> dict:
        """
        Return Redfish connection info.

        Get appropriate Redfish connection info - either direct BMC or forwarded
        HMC.

        This allows existing Redfish service calls to work transparently

        Returns:
            A mapping containing Redfish connection info.

        Raises:
            RuntimeError: If a tool-owned HMC route requires an SSH proxy but
                no live BMC SSH route matches the current proxy and BMC
                endpoint; or SSH proxy is configured for Redfish, but no live
                route matches the current proxy and BMC endpoint.
        """
        # Check if HMC mode is active (like legacy nvdebug)
        if (
            self.is_hmc_platform
            and self.hmc_service
            and self.hmc_service.is_hmc_active()
        ):
            hmc_route_is_tool_owned = (
                getattr(self.hmc_service, "forwarding_owned_by_tool", True) is not False
            )
            if (
                self.credentials.ssh_proxy_host
                and hmc_route_is_tool_owned
                and "bmc_ssh_port" not in self._get_live_ssh_proxy_tunnel_ports()
            ):
                raise RuntimeError(
                    "SSH proxy is configured for HMC Redfish, but no live BMC "
                    "SSH route matches the current proxy and BMC endpoint"
                )

            # Return forwarded connection info
            connection_info = self.hmc_service.get_redfish_connection_info()
            return self._validated_redfish_connection_info(
                {
                    "host": connection_info["host"],
                    "port": connection_info["port"],
                    "use_https": connection_info["use_https"],
                    "username": connection_info.get("username")
                    or self.credentials.hmc_username,
                    "password": connection_info.get("password")
                    or self.credentials.hmc_password,
                    "auth_enabled": self.config.get("RF_AUTH", True),
                    "is_hmc_forwarded": True,
                    "service_root": self._get_redfish_service_root(hmc=True),
                },
                endpoint_name="HMC",
            )
        return self.get_bmc_redfish_connection_info()

    async def ensure_bmc_redfish_proxy_route(self) -> Dict[str, int]:
        """
        Establish only the configured BMC Redfish proxy route when needed.

        A preceding HMC preflight may have requested only a BMC SSH tunnel.
        Reuse its registered service so adding Redfish preserves the existing
        route and shares the service's per-DUT setup lock. Ownership is retained
        before awaiting setup for cancellation and finalization cleanup.

        Returns:
            Verified current proxy ports, or an empty mapping for a direct BMC.

        Raises:
            RuntimeError: If the requested Redfish proxy tunnel cannot be created.

        Side Effects:
            May create one owned SSH proxy tunnel using the existing configured
            credential and host-key policy.
        """

        if not self.credentials.ssh_proxy_host:
            return {}
        tunnel_ports = self._get_live_ssh_proxy_tunnel_ports()
        if "redfish_port" in tunnel_ports:
            return tunnel_ports
        ssh_proxy_service = getattr(self, "ssh_proxy_service", None) or SSHProxyService(
            logger=self.logger, dut_manager=self.dut_manager
        )
        self.ssh_proxy_service = ssh_proxy_service
        success, tunnel_ports, message = (
            await ssh_proxy_service.setup_ssh_proxy_tunneling(
                dut_id=self.dut_id,
                bmc_ip=self.credentials.bmc_ip,
                host_ip=self.credentials.host_ip,
                ssh_proxy_host=self.credentials.ssh_proxy_host,
                ssh_proxy_username=self.credentials.ssh_proxy_username,
                ssh_proxy_password=self.credentials.ssh_proxy_password,
                ssh_proxy_key_path=self.credentials.ssh_proxy_key_path,
                ssh_proxy_passwordless=self.credentials.ssh_proxy_passwordless,
                ssh_proxy_port=self.credentials.ssh_proxy_port,
                bmc_redfish_port=self.credentials.bmc_rf_port,
                bmc_use_https=self.credentials.bmc_use_https,
                bmc_ipmi_port=623,
                bmc_ssh_port=self.credentials.bmc_ssh_port,
                host_ssh_port=self.credentials.host_ssh_port,
                force_setup=True,
                required_tunnels=["redfish"],
            )
        )
        if not success or "redfish_port" not in tunnel_ports:
            raise RuntimeError(
                f"Failed to setup SSH proxy tunneling for Redfish: {message}"
            )
        self.ssh_proxy_tunnel_ports = tunnel_ports
        return tunnel_ports

    def get_bmc_redfish_connection_info(self) -> dict:
        """
        Resolve the Host BMC endpoint independently of active HMC forwarding.

        The existing proxy ownership and TLS checks apply unchanged. BMC
        credentials and authentication policy are retained when an HMC route
        disables authentication for its own requests.

        Returns:
            Validated BMC transport, credentials, and service-root settings.

        Raises:
            RuntimeError: If the configured proxy has no matching live BMC route.
            ValueError: If the selected transport violates the DUT TLS policy.
        """

        live_proxy_ports = self._get_live_ssh_proxy_tunnel_ports()
        if "redfish_port" in live_proxy_ports:
            # Return SSH proxy tunnel connection info
            return self._validated_redfish_connection_info(
                {
                    "host": "localhost",  # Use localhost for tunnel
                    "port": live_proxy_ports["redfish_port"],
                    "use_https": self.credentials.bmc_use_https,
                    "username": self.credentials.rf_username
                    or self.credentials.bmc_username,
                    "password": self.credentials.rf_password
                    or self.credentials.bmc_password,
                    "auth_enabled": getattr(
                        self,
                        "_bmc_redfish_auth_enabled",
                        self.config.get("RF_AUTH", True),
                    ),
                    "is_hmc_forwarded": False,
                    "is_ssh_proxy_tunneled": True,
                    "service_root": self._get_redfish_service_root(),
                },
                endpoint_name="BMC",
            )
        elif self.credentials.ssh_proxy_host:
            raise RuntimeError(
                "SSH proxy is configured for Redfish, but no live route "
                "matches the current proxy and BMC endpoint"
            )
        else:
            # Return direct BMC connection info
            return self._validated_redfish_connection_info(
                {
                    "host": self.credentials.bmc_ip,
                    "port": self.credentials.bmc_rf_port,
                    "use_https": self.credentials.bmc_use_https,
                    "username": self.credentials.rf_username
                    or self.credentials.bmc_username,
                    "password": self.credentials.rf_password
                    or self.credentials.bmc_password,
                    "auth_enabled": getattr(
                        self,
                        "_bmc_redfish_auth_enabled",
                        self.config.get("RF_AUTH", True),
                    ),
                    "is_hmc_forwarded": False,
                    "is_ssh_proxy_tunneled": False,
                    "service_root": self._get_redfish_service_root(),
                },
                endpoint_name="BMC",
            )

    async def _probe_host_reachability(self, ip_address: str) -> _HostReachabilityProbe:
        """
        Probe one host with bounded ICMP and retain a stable failure category.

        The subprocess is bounded and receives a validated endpoint argument.
        Captured diagnostics are classified locally and never copied into the
        operator-facing result.

        Args:
            ip_address: Text supplied as IP address in the format accepted by
                this function.

        Returns:
            The typed reachability outcome.
        """
        try:
            # Use ping with 2 packets and 5 second timeout (like legacy tool)
            network_type = str(self.config.get("IP_NETWORK", "ipv4")).lower()
            network_arg = "-6" if network_type == "ipv6" else "-4"
            # ``ping`` implementations are not consistent about supporting an
            # end-of-options marker.  Use the common local-command builder so an
            # endpoint beginning with ``-`` fails closed before process creation.
            ping_cmd = build_local_cmd(
                ["ping", network_arg, "-c", "2", "-W", "5", "{ip_address}"],
                ip_address=ip_address,
            )

            # Use asyncio.create_subprocess_exec for true async execution
            # Note: asyncio.create_subprocess_exec doesn't support text=True
            process = await asyncio.create_subprocess_exec(
                *ping_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=scrubbed_child_environment(),
                start_new_session=os.name == "posix",
            )

            # Wait for completion with timeout
            try:
                stdout, stderr = await _communicate_subprocess(
                    process,
                    timeout=10,
                    terminate_process_group=os.name == "posix",
                )
            except asyncio.TimeoutError:
                return _HostReachabilityProbe(False, "probe_timeout")

            if process.returncode == 0:
                return _HostReachabilityProbe(True)
            return _HostReachabilityProbe(
                False,
                _classify_ping_probe_failure(
                    stdout,
                    stderr,
                    returncode=process.returncode,
                ),
            )
        except ValueError:
            return _HostReachabilityProbe(False, "invalid_target")
        except (FileNotFoundError, PermissionError):
            return _HostReachabilityProbe(False, "probe_unavailable")
        except OSError as error:
            failure_kind = _classify_ping_probe_failure(None, str(error))
            if failure_kind == "probe_error":
                failure_kind = "probe_unavailable"
            return _HostReachabilityProbe(False, failure_kind)
        except Exception:
            return _HostReachabilityProbe(False, "probe_error")

    async def _ping_host(
        self, ip_address: str, *, detailed: bool = False
    ) -> Union[bool, _HostReachabilityProbe]:
        """
        Ping a host with a compatibility boolean or typed result.

        Existing callers receive the historical boolean contract. Preflight
        callers request ``detailed=True`` so they can distinguish an invalid
        route from a service which merely does not answer ICMP.

        Args:
            ip_address: Endpoint address or hostname to probe.
            detailed: Whether to return the complete typed outcome.

        Returns:
            The typed probe when ``detailed`` is true; otherwise whether the
            ICMP probe succeeded.
        """
        probe = await self._probe_host_reachability(ip_address)
        return probe if detailed else probe.reachable

    @staticmethod
    def _blocking_reachability_message(
        probe: Union[bool, _HostReachabilityProbe],
        endpoint_name: str,
        endpoint_address: Optional[str] = None,
    ) -> Optional[str]:
        """
        Return a safe message only when reachability blocks transport setup.

        Boolean values preserve compatibility with tests and integrations that
        replace the legacy ping helper. Typed soft failures return ``None`` so
        the actual service transport supplies the authoritative result.

        Args:
            probe: Boolean compatibility value or typed probe outcome.
            endpoint_name: Safe endpoint role such as ``BMC`` or ``Host``.
            endpoint_address: Optional configured endpoint retained for the
                legacy ping-failure diagnostic.

        Returns:
            A stable blocking diagnostic, or ``None`` when transport should be
            attempted.
        """
        if isinstance(probe, bool):
            return (
                None
                if probe
                else f"{endpoint_name} did not pass the ICMP ping reachability probe"
            )
        if not probe.blocks_transport:
            return None
        details = {
            "invalid_target": f"{endpoint_name} address is invalid",
            "resolution_failure": f"{endpoint_name} address could not be resolved",
            "no_route": f"No network route to {endpoint_name}",
        }
        detail = details.get(
            probe.failure_kind,
            f"{endpoint_name} reachability probe failed",
        )
        if endpoint_address:
            return (
                f"{endpoint_name} {endpoint_address} not reachable via ping: "
                f"{detail}"
            )
        return detail

    def _process_command_output(
        self, output: Union[str, bytes, None], encoding: str = "utf-8"
    ) -> str:
        """
        Process command output to ensure it's in string format.

        Handles binary data gracefully with fallback strategies. Delegates to
        DUTManager if available, otherwise uses local implementation.

        Args:
            output: Optional output; ``None`` selects the function's default
                behavior.
            encoding: Character encoding used to decode or write the selected
                text.

        Returns:
            The canonical process command output text.
        """
        # If we have a DUTManager reference, use its method
        if self.dut_manager and hasattr(self.dut_manager, "_process_command_output"):
            return self.dut_manager._process_command_output(output, encoding)

        # Otherwise, use local implementation
        if output is None:
            return ""

        if isinstance(output, bytes):
            try:
                # First try UTF-8 with replace
                return output.decode(encoding, errors="replace")
            except Exception:
                try:
                    # Try latin1 as fallback - it can handle all byte values
                    return output.decode("latin1", errors="replace")
                except Exception:
                    # Last resort - hex representation
                    return f"hex:{output.hex()}"

        # Handle case where output is already a string
        if isinstance(output, str):
            return output

        # For any other type, try string conversion with error handling
        try:
            return str(output)
        except Exception:
            return f"<unconvertible output of type {type(output).__name__}>"

    async def cleanup_ssh_proxy_tunnels(self) -> bool:
        """
        Close and verify every proxy tunnel owned by this DUT.

        After applying local validation, the function forwards current instance
        state to ``cleanup_dut_ssh_proxy_tunnels`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Returns:
            Whether the close and verify every proxy tunnel owned by this DUT
            operation succeeds.
        """

        return await cleanup_dut_ssh_proxy_tunnels(self)


class DUTManager:
    """
    Manager for multiple DUTs.

    The type coordinates ``_get_session_registry``,
    ``_close_ssh_connection_bounded_facade``, ``_get_discovery_service``,
    ``_get_baseboard_manager``, and ``_make_redfish_http_engine`` and retains
    the state those operations share between calls. Resource ownership remains
    inside the instance until the matching close, exit, or cleanup operation
    completes.
    """

    def __init__(
        self,
        dut_configs: Dict[str, Any],
        base_log_dir: str,
        uri_config_manager=None,
        ssh_config: Dict[str, Any] = None,
        spreadsheet_path: Optional[str] = None,
        sanitized_console=None,
        debug_mode: bool = False,
        redfish_session_config: Optional[Dict[str, Any]] = None,
        tool_config: Optional[Dict[str, Any]] = None,
        logger: Optional[AsyncSafeLogger] = None,
        catalog_snapshot: Optional[CatalogSnapshot] = None,
    ) -> None:
        """
        Initialize DUT manager.

        The initializer records ``_baseboard_manager``, ``_discovery_service``,
        ``_dut_file_transfer``, ``_host_ssh_pool``, ``_ipmi_credential_root``,
        and ``_redfish_spool_dir`` for later operations and establishes the
        instance invariants before any public method runs.

        Args:
            dut_configs: DUT configs governing initialize DUT manager.
            base_log_dir: filesystem location used as the base log dir for this
                operation.
            uri_config_manager: Validated remote resource identifier used for
                URI config manager.
            ssh_config: Optional SSH config governing initialize DUT manager.
            spreadsheet_path: Optional filesystem location used as the
                spreadsheet path for this operation.
            sanitized_console: Optional sanitized console; ``None`` selects the
                function's default behavior.
            debug_mode: Whether debug mode is enabled or required for this
                operation.
            redfish_session_config: Optional Redfish session config governing
                initialize DUT manager.
            tool_config: Optional Tool config governing initialize DUT manager.
            logger: Sanitized logger used for operator-visible diagnostics.
            catalog_snapshot: Optional catalog snapshot; ``None`` selects the
                function's default behavior.
        """
        self.dut_configs = dut_configs
        self.base_log_dir = Path(base_log_dir)
        self.duts: Dict[str, DUT] = {}
        self.logger = logger or AsyncSafeLogger(
            str(self.base_log_dir), debug_mode=debug_mode
        )
        self.uri_config_manager = uri_config_manager
        self.tool_config = tool_config or {}

        # Spreadsheet configuration
        self.spreadsheet_path = spreadsheet_path
        self.catalog_snapshot = catalog_snapshot

        # Console for consistent output styling
        self.sanitized_console = sanitized_console

        # SSH implementation configuration with defaults
        self.ssh_config = ssh_config or {}
        self.host_ssh_pool_config = SSHConnectionPoolConfig.model_validate(
            self.tool_config.get("ssh_connection_pool", {})
        )
        self._host_ssh_pool: Optional[HostSSHConnectionPool] = None

        # Redfish session configuration with defaults
        self.redfish_session_config = dict(redfish_session_config or {})
        # Apply only the authentication default here. Materializing unrelated
        # TLS defaults would change the established source-presence precedence.
        authentication_values = {
            key: self.redfish_session_config[key]
            for key in ("authentication_mode",)
            if key in self.redfish_session_config
        }
        self.redfish_session_config["authentication_mode"] = (
            RedfishSessionConfig.model_validate(
                authentication_values
            ).authentication_mode
        )
        self.redfish_response_limits = RedfishResponseLimits.from_session_config(
            self.redfish_session_config
        )
        # Raw Redfish bodies are staged outside the collected run directory so
        # interrupted downloads cannot be mistaken for complete artifacts.
        # The directory is created lazily on the output filesystem, allowing a
        # complete staging file to be atomically promoted into collector output.
        self._redfish_spool_dir: Optional[Path] = None
        self._ipmi_credential_root: Optional[Path] = None
        self.redfish_connection_pool_limit = self.redfish_session_config.get(
            "connection_pool_limit", 20
        )
        self.redfish_connection_pool_limit_per_host = self.redfish_session_config.get(
            "connection_pool_limit_per_host", 8
        )
        self.redfish_session_timeout = self.redfish_session_config.get(
            "session_timeout", 300
        )
        self.redfish_keepalive_timeout = self.redfish_session_config.get(
            "keepalive_timeout", 300
        )
        self.redfish_tls_policy = RedfishTLSPolicy.from_session_config(
            self.redfish_session_config
        )
        self.redfish_ssl = self.redfish_tls_policy.build_ssl_parameter()
        self.redfish_ttl_dns_cache = self.redfish_session_config.get(
            "ttl_dns_cache", 300
        )
        self.redfish_use_dns_cache = self.redfish_session_config.get(
            "use_dns_cache", True
        )
        self.redfish_force_close = self.redfish_session_config.get("force_close", False)
        self.redfish_enable_cleanup_closed = self.redfish_session_config.get(
            "enable_cleanup_closed", True
        )
        self.redfish_fallback_connection_pool_limit = self.redfish_session_config.get(
            "fallback_connection_pool_limit", 15
        )
        self.redfish_fallback_connection_pool_limit_per_host = (
            self.redfish_session_config.get(
                "fallback_connection_pool_limit_per_host", 6
            )
        )
        # Warn about stale fallback config (paramiko removed)
        if self.ssh_config.get("fallback"):
            import warnings

            warnings.warn(
                "ssh_implementation.fallback config is deprecated — paramiko has been removed. "
                "asyncssh is the sole SSH backend. Remove the fallback section from your config.",
                DeprecationWarning,
                stacklevel=2,
            )

        # Shared DynamicDiscoveryService instance
        self._discovery_service = None

        # BaseboardManager for baseboard lookups and filtering
        self._baseboard_manager = None

        # File transfers are migrated incrementally behind this component.
        # The component receives an established session and never owns one.
        self._dut_file_transfer: Optional[DUTFileTransfer] = None

        # One registry owns persistent BMC/HMC routes, exact proxy ownership,
        # retryable orphans, and forwarded-HMC recovery serialization.  The
        # historical dictionaries remain facade aliases for compatibility.
        self._session_registry = DUTSessionRegistry().bind(self)

        # Note: Async initialization (logging, DUT creation) will be done in initialize() method

    def _get_session_registry(self) -> DUTSessionRegistry:
        """
        Return the registry after adopting legacy facade state replacements.

        After applying local validation, the function forwards current instance
        state to ``registry.bind`` and preserves its return and exception
        contract. It updates ``_session_registry`` on the instance as part of
        that state transition.

        Returns:
            The canonical session registry text.
        """

        registry = getattr(self, "_session_registry", None)
        if registry is None:
            registry = DUTSessionRegistry()
            self._session_registry = registry
        return registry.bind(self)

    async def _close_ssh_connection_bounded_facade(self, conn: Any) -> None:
        """
        Expose the local bounded-close primitive to the ownership registry.

        The implementation uses ``conn`` to expose the local bounded-close
        primitive to the ownership registry. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            conn: Connection consumed while the function attempts to expose the
                local bounded-close primitive to the ownership registry.
        """

        await _close_ssh_connection_bounded(conn)

    def _get_discovery_service(self):
        """
        Get or create the shared DynamicDiscoveryService instance.

        The implementation uses current instance state to get or create the
        shared DynamicDiscoveryService instance. It updates
        ``_discovery_service`` on the instance as part of that state transition.

        Returns:
            The shared dynamic-discovery service, created on first access.
        """
        if self._discovery_service is None:
            self._discovery_service = DynamicDiscoveryService(
                self, self.logger, self.uri_config_manager
            )
        return self._discovery_service

    def _get_baseboard_manager(self):
        """
        Get or create the shared BaseboardManager instance.

        The implementation uses current instance state to get or create the
        shared BaseboardManager instance. It updates ``_baseboard_manager`` on
        the instance as part of that state transition.

        Returns:
            The shared baseboard manager, created on first access.
        """
        if self._baseboard_manager is None:
            self._baseboard_manager = BaseboardManager(
                spreadsheet_path=self.spreadsheet_path,
                logger=self.logger,
                catalog_snapshot=self.catalog_snapshot,
            )
        return self._baseboard_manager

    @staticmethod
    def _format_redfish_url_host(host: str) -> str:
        """
        Apply URL host formatting at the manager-owned transport boundary.

        Keep IPv6 authority formatting shared with preflight and session
        authentication while the stateless HTTP executor owns request flow.

        Args:
            host: Configured socket host without its independently selected port.

        Returns:
            The HTTP authority host, bracketed when it is an IPv6 literal.
        """

        return format_redfish_url_host(host)

    @staticmethod
    def _encode_redfish_auth_header(username: str, password: str) -> str:
        """
        Encode credentials at the manager-owned Redfish transport boundary.

        Keeping authentication policy on the manager prevents the stateless
        HTTP executor from depending on version-specific authentication APIs.

        Args:
            username: Redfish account name supplied to Basic authentication.
            password: Redfish password supplied to Basic authentication.

        Returns:
            A complete HTTP Basic ``Authorization`` header value.
        """

        return encode_basic_auth_header(username, password)

    @staticmethod
    def _build_redfish_request_headers(
        auth_header: Optional[str],
        base_headers: Optional[Mapping[str, str]] = None,
        *,
        auth_token: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Build headers at the manager-owned Redfish transport boundary.

        The manager owns credential injection while the HTTP executor remains
        limited to request control flow and caller-supplied transport state.

        Args:
            auth_header: Encoded authorization value, or ``None``.
            base_headers: Non-authentication request headers to preserve.
            auth_token: Owned endpoint-bound session token, or ``None`` to retain
                the Basic or anonymous path.

        Returns:
            A copied request-header mapping with owned authentication state.

        Raises:
            ValueError: If the explicit token violates the shared header policy.
        """

        return build_redfish_request_headers(
            auth_header, base_headers, auth_token=auth_token
        )

    def _make_redfish_http_engine(self) -> RedfishHttpEngine:
        """
        Bind the stateless HTTP executor to the manager's live seams.

        Constructing this small immutable adapter per facade call is
        intentional. The executor owns no session or lifecycle state, and all
        manager callbacks remain dynamically monkeypatchable after
        ``DUTManager`` construction.

        Returns:
            A ``RedfishHttpEngine`` representing make Redfish HTTP engine.
        """

        return RedfishHttpEngine(
            owner=self,
            primitives=RedfishHttpPrimitives(
                resolve_limit=_resolved_redfish_limit,
                read_error_body_with_evidence=(_read_redfish_error_body_with_evidence),
                decode_body=_decode_redfish_body,
                read_body_bounded=_read_redfish_body_bounded,
                attach_oversized_error_evidence=(_attach_oversized_error_evidence),
                oversized_error_evidence_from_metadata=(
                    _oversized_error_evidence_from_metadata
                ),
                response_too_large=RedfishResponseTooLarge,
            ),
            limits=RedfishHttpLimits(
                structured_response_max_bytes=(REDFISH_STRUCTURED_RESPONSE_MAX_BYTES),
                error_response_max_bytes=REDFISH_ERROR_RESPONSE_MAX_BYTES,
                error_evidence_max_bytes=REDFISH_ERROR_EVIDENCE_MAX_BYTES,
                error_evidence_aggregate_max_bytes=(
                    REDFISH_ERROR_EVIDENCE_AGGREGATE_MAX_BYTES
                ),
                error_evidence_max_responses=(REDFISH_ERROR_EVIDENCE_MAX_RESPONSES),
                transport_content_length_max_bytes=(
                    REDFISH_TRANSPORT_CONTENT_LENGTH_MAX_BYTES
                ),
                safe_response_headers=SAFE_REDFISH_RESPONSE_HEADERS,
            ),
        )

    def _get_dut_file_transfer(self) -> DUTFileTransfer:
        """
        Get the file-transfer component used by compatibility facades.

        The implementation uses current instance state to get the file-transfer
        component used by compatibility facades. It updates
        ``_dut_file_transfer`` on the instance as part of that state transition.

        Returns:
            The validated ``component``.
        """

        component = getattr(self, "_dut_file_transfer", None)
        if component is None:
            component = DUTFileTransfer(logger=self.logger, scp=asyncssh.scp)
            self._dut_file_transfer = component
        return component

    async def _initialize_baseboard_manager_only(self):
        """
        Initialize only the BaseboardManager for simple mode operations.

        Used in simple mode for collector filtering without creating DUTs.
        """
        # This method initializes only the BaseboardManager without creating DUTs or connections
        # It's used in simple mode for collector filtering operations
        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            "Initializing BaseboardManager for simple mode operations",
        )

        # Initialize the BaseboardManager by calling _get_baseboard_manager
        # This will load the baseboard definitions from the spreadsheet
        baseboard_manager = self._get_baseboard_manager()

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"BaseboardManager initialized with {len(baseboard_manager.get_all_baseboard_names())} baseboards",
        )

    def _raw_ssh_capacity_semaphores(
        self,
        *,
        capacity_scope: str,
        role: str,
    ) -> Tuple[asyncio.BoundedSemaphore, asyncio.BoundedSemaphore]:
        """
        Return bounded run and scope capacity for a raw SSH connection.

        The state is initialized lazily as a compatibility measure for focused
        tests and integrations which construct ``DUTManager`` with ``__new__``.
        The registry itself is capped so a stream of attacker-controlled route
        labels cannot turn the limiter into an unbounded cache.

        Args:
            capacity_scope: Text supplied as capacity scope in the format
                accepted by this function.
            role: Text supplied as role in the format accepted by this function.

        Returns:
            A tuple containing ``asyncio.bounded semaphore`` and ``scope
            capacity`` in that order.

        Raises:
            ValueError: If unsupported raw SSH capacity role: ``role``; or raw
                SSH capacity scope must not be empty.
            RuntimeError: If raw SSH capacity route limit reached.
        """

        if role not in {"endpoint", "proxy"}:
            raise ValueError(f"Unsupported raw SSH capacity role: {role}")

        global_capacity = getattr(self, "_raw_ssh_global_capacity", None)
        if global_capacity is None:
            global_capacity = {
                "endpoint": asyncio.BoundedSemaphore(
                    RAW_SSH_MAX_ACTIVE_ENDPOINTS_PER_RUN
                ),
                "proxy": asyncio.BoundedSemaphore(RAW_SSH_MAX_ACTIVE_PROXIES_PER_RUN),
            }
            self._raw_ssh_global_capacity = global_capacity

        per_scope_capacity = getattr(self, "_raw_ssh_per_scope_capacity", None)
        if per_scope_capacity is None:
            per_scope_capacity = {}
            self._raw_ssh_per_scope_capacity = per_scope_capacity

        normalized_scope = str(capacity_scope or "").strip()
        if not normalized_scope:
            raise ValueError("Raw SSH capacity scope must not be empty")
        capacity_key = (role, normalized_scope)
        scope_capacity = per_scope_capacity.get(capacity_key)
        if scope_capacity is None:
            if len(per_scope_capacity) >= RAW_SSH_MAX_LIMITER_KEYS_PER_RUN:
                raise RuntimeError("Raw SSH capacity route limit reached")
            per_scope_limit = (
                RAW_SSH_MAX_ACTIVE_ENDPOINTS_PER_DUT
                if role == "endpoint"
                else RAW_SSH_MAX_ACTIVE_PROXIES_PER_DUT
            )
            scope_capacity = asyncio.BoundedSemaphore(per_scope_limit)
            per_scope_capacity[capacity_key] = scope_capacity

        return global_capacity[role], scope_capacity

    async def _connect_raw_ssh_bounded(
        self,
        *,
        capacity_scope: str,
        role: str,
        connect_kwargs: Dict[str, Any],
        capacity_wait_timeout: float = RAW_SSH_CAPACITY_WAIT_TIMEOUT_SECONDS,
    ) -> asyncssh.SSHClientConnection:
        """
        Open a raw AsyncSSH connection under lifetime capacity ownership.

        Shield transfers cancellation ownership to this method. If the caller is
        cancelled at the exact completion boundary, the result remains
        observable below and can be closed instead of leaked.

        Args:
            capacity_scope: Text supplied as capacity scope in the format
                accepted by this function.
            role: Text supplied as role in the format accepted by this function.
            connect_kwargs: Mapping supplying fields for open a raw AsyncSSH
                connection under lifetime capacity ownership.
            capacity_wait_timeout: Maximum duration in seconds allowed for
                capacity wait timeout.

        Returns:
            The validated ``conn``.
        """

        global_capacity, scope_capacity = self._raw_ssh_capacity_semaphores(
            capacity_scope=capacity_scope,
            role=role,
        )
        wait_timeout = max(0.001, float(capacity_wait_timeout))
        global_acquired = False
        scope_acquired = False
        connect_future: Optional[asyncio.Future] = None
        try:
            async with asyncio.timeout(wait_timeout):
                await global_capacity.acquire()
            global_acquired = True
            async with asyncio.timeout(wait_timeout):
                await scope_capacity.acquire()
            scope_acquired = True
            connect_future = asyncio.ensure_future(asyncssh.connect(**connect_kwargs))
            # Shield transfers cancellation ownership to this method. If the
            # caller is cancelled at the exact completion boundary, the result
            # remains observable below and can be closed instead of leaked.
            conn = await asyncio.shield(connect_future)
        except BaseException as primary_error:
            recovered_conn = None
            if connect_future is not None:
                if not connect_future.done():
                    connect_future.cancel()
                try:
                    recovered_conn = await connect_future
                except BaseException:
                    recovered_conn = None
            if recovered_conn is not None:
                self._retain_raw_ssh_connection_capacity(
                    recovered_conn,
                    global_capacity,
                    scope_capacity,
                )
                scope_acquired = False
                global_acquired = False
                await self._close_ssh_connection_chain_after_failure(
                    primary_error,
                    recovered_conn,
                )
            if scope_acquired:
                scope_capacity.release()
            if global_acquired:
                global_capacity.release()
            raise

        self._retain_raw_ssh_connection_capacity(
            conn,
            global_capacity,
            scope_capacity,
        )
        return conn

    def _retain_raw_ssh_connection_capacity(
        self,
        conn: asyncssh.SSHClientConnection,
        global_capacity: asyncio.BoundedSemaphore,
        scope_capacity: asyncio.BoundedSemaphore,
    ) -> None:
        """
        Record exact permit ownership for a successfully opened socket.

        The implementation uses ``conn``, ``global_capacity``, and
        ``scope_capacity`` to record exact permit ownership for a successfully
        opened socket. It updates ``_raw_ssh_connection_leases`` on the instance
        as part of that state transition. If the function cannot record exact
        permit ownership for a successfully opened socket, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            conn: Connection consumed while the function attempts to record
                exact permit ownership for a successfully opened socket.
            global_capacity: Global capacity object whose ``release`` state is
                read while performing record exact permit ownership for a
                successfully opened socket.
            scope_capacity: Scope capacity object whose ``release`` state is
                read while performing record exact permit ownership for a
                successfully opened socket.

        Raises:
            RuntimeError: If SSH connection factory reused an active connection.
        """

        leases = getattr(self, "_raw_ssh_connection_leases", None)
        if leases is None:
            leases = {}
            self._raw_ssh_connection_leases = leases
        existing = leases.get(id(conn))
        if existing is not None and existing[0] is conn:
            scope_capacity.release()
            global_capacity.release()
            raise RuntimeError("SSH connection factory reused an active connection")
        leases[id(conn)] = (conn, global_capacity, scope_capacity)

    def _release_raw_ssh_connection_capacity(self, conn: Any) -> None:
        """
        Release a raw connection lease after authoritative close succeeds.

        The implementation uses ``conn`` to release a raw connection lease after
        authoritative close succeeds.

        Args:
            conn: Connection consumed while the function attempts to release a
                raw connection lease after authoritative close succeeds.
        """

        leases = getattr(self, "_raw_ssh_connection_leases", None)
        if not leases:
            return
        lease = leases.pop(id(conn), None)
        if lease is None or lease[0] is not conn:
            return
        _, global_capacity, scope_capacity = lease
        scope_capacity.release()
        global_capacity.release()

    @staticmethod
    def _ssh_connection_lock_key(dut_id: str, hmc: bool) -> Tuple[str, str]:
        """
        Return the fixed-size cache-lock identity for a BMC/HMC route.

        The implementation uses ``dut_id`` and ``hmc`` to produce the fixed-size
        cache-lock identity for a BMC/HMC route.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether HMC is enabled or required for this operation.

        Returns:
            A tuple containing ``str`` and ``status text`` in that order.
        """

        return (str(dut_id), "hmc" if hmc else "bmc")

    @staticmethod
    def _ssh_connection_cache_limit() -> int:
        """
        Return the live, monkeypatchable per-run route registry bound.

        The implementation uses current instance state to produce the live,
        monkeypatchable per-run route registry bound.

        Returns:
            The validated ``BMC_HMC_SSH_MAX_CACHED_ROUTES_PER_RUN``.
        """

        return BMC_HMC_SSH_MAX_CACHED_ROUTES_PER_RUN

    async def get_ssh_connection(
        self, dut_id: str, hmc: bool = False
    ) -> Optional[asyncssh.SSHClientConnection]:
        """
        Get or create a persistent route-keyed BMC/HMC SSH connection.

        After applying local validation, the function forwards ``dut_id`` and
        ``hmc`` to ``get_ssh_connection`` and preserves its return and exception
        contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether HMC is enabled or required for this operation.

        Returns:
            The established ``SSHClientConnection`` used for SSH connection, or
            ``None`` when the requested value is unavailable.
        """

        return await self._get_session_registry().get_ssh_connection(self, dut_id, hmc)

    @staticmethod
    def _ssh_connection_cache_key(
        *,
        dut_id: str,
        hmc: bool,
        host: str,
        port: int,
        username: Optional[str],
        proxy_host: Optional[str],
        proxy_port: Optional[int],
        proxy_username: Optional[str],
        host_key_policy: str,
        known_hosts_file: Optional[str],
    ) -> Tuple[Any, ...]:
        """
        Return the SSH connection cache key.

        After applying local validation, the function forwards ``dut_id``,
        ``hmc``, ``host``, ``port``, and ``username`` to
        ``DUTSessionRegistry.connection_cache_key`` and preserves its return and
        exception contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether HMC is enabled or required for this operation.
            host: Text supplied as host in the format accepted by this function.
            port: Numeric port used while the operation performs bounded
                accounting.
            username: Text supplied as username in the format accepted by this
                function.
            proxy_host: Text supplied as proxy host in the format accepted by
                this function.
            proxy_port: Numeric proxy port used while the operation performs
                bounded accounting.
            proxy_username: Text supplied as proxy username in the format
                accepted by this function.
            host_key_policy: Host key policy governing SSH connection cache key.
            known_hosts_file: filesystem location used as the known hosts file
                for this operation.

        Returns:
            The SSH connection cache key returned in operation-defined order.
        """
        return DUTSessionRegistry.connection_cache_key(
            dut_id=dut_id,
            hmc=hmc,
            host=host,
            port=port,
            username=username,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            proxy_username=proxy_username,
            host_key_policy=host_key_policy,
            known_hosts_file=known_hosts_file,
        )

    @staticmethod
    def _ssh_connection_key_matches(
        connection_key: Any, dut_id: str, hmc: bool
    ) -> bool:
        """
        Return the SSH connection key matches.

        After applying local validation, the function forwards
        ``connection_key``, ``dut_id``, and ``hmc`` to
        ``DUTSessionRegistry.connection_key_matches`` and preserves its return
        and exception contract.

        Args:
            connection_key: Stable connection key used for lookup and
                operator-facing diagnostics.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether HMC is enabled or required for this operation.

        Returns:
            Whether the SSH connection key matches operation succeeds.
        """
        return DUTSessionRegistry.connection_key_matches(connection_key, dut_id, hmc)

    @staticmethod
    def _ssh_connection_label(connection_key: Any) -> str:
        """
        Return the SSH connection label.

        After applying local validation, the function forwards
        ``connection_key`` to ``DUTSessionRegistry.connection_label`` and
        preserves its return and exception contract.

        Args:
            connection_key: Stable connection key used for lookup and
                operator-facing diagnostics.

        Returns:
            The canonical SSH connection label.
        """
        return DUTSessionRegistry.connection_label(connection_key)

    @staticmethod
    def _has_ssh_auth_method(
        password: Optional[str],
        ssh_key_path: Optional[str],
        passwordless: bool,
    ) -> bool:
        """
        Return whether ``password`` has SSH auth method.

        After applying local validation, the function forwards ``password``,
        ``ssh_key_path``, and ``passwordless`` to
        ``DUTSessionRegistry.has_ssh_auth_method`` and preserves its return and
        exception contract.

        Args:
            password: Sensitive value supplied through the approved input
                boundary and never logged.
            ssh_key_path: filesystem location used as the SSH key path for this
                operation.
            passwordless: Sensitive value supplied through the approved input
                boundary and never logged.

        Returns:
            Whether ``password`` has SSH auth method.
        """
        return DUTSessionRegistry.has_ssh_auth_method(
            password, ssh_key_path, passwordless
        )

    @staticmethod
    def _build_ssh_connect_kwargs(
        host: str,
        port: int,
        username: Optional[str],
        password: Optional[str] = None,
        ssh_key_path: Optional[str] = None,
        passwordless: bool = False,
        connect_timeout: float = 30.0,
        keepalive_interval: Optional[int] = None,
        proxy_client: Optional[asyncssh.SSHClientConnection] = None,
        host_key_policy: str = "insecure",
        known_hosts_file: Optional[str] = None,
        host_key_alias: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build SSH connect kwargs.

        After applying local validation, the function forwards ``host``,
        ``port``, ``username``, ``password``, and ``ssh_key_path`` to
        ``DUTSessionRegistry.build_ssh_connect_kwargs`` and preserves its return
        and exception contract.

        Args:
            host: Text supplied as host in the format accepted by this function.
            port: Numeric port used while the operation performs bounded
                accounting.
            username: Text supplied as username in the format accepted by this
                function.
            password: Sensitive value supplied through the approved input
                boundary and never logged.
            ssh_key_path: Optional filesystem location used as the SSH key path
                for this operation.
            passwordless: Sensitive value supplied through the approved input
                boundary and never logged.
            connect_timeout: Maximum duration in seconds allowed for connect
                timeout.
            keepalive_interval: Maximum duration in seconds allowed for
                keepalive interval.
            proxy_client: Optional proxy client; ``None`` selects the function's
                default behavior.
            host_key_policy: Host key policy governing SSH connect kwargs.
            known_hosts_file: Optional filesystem location used as the known
                hosts file for this operation.
            host_key_alias: Optional host key alias; ``None`` selects the
                function's default behavior.

        Returns:
            A mapping containing SSH connect kwargs.
        """
        return DUTSessionRegistry.build_ssh_connect_kwargs(
            host=host,
            port=port,
            username=username,
            password=password,
            ssh_key_path=ssh_key_path,
            passwordless=passwordless,
            connect_timeout=connect_timeout,
            keepalive_interval=keepalive_interval,
            proxy_client=proxy_client,
            host_key_policy=host_key_policy,
            known_hosts_file=known_hosts_file,
            host_key_alias=host_key_alias,
        )

    async def close_ssh_connection(self, dut_id: str, hmc: bool = False) -> None:
        """
        Close all cached routes matching one DUT transport.

        The implementation uses ``dut_id`` and ``hmc`` to close all cached
        routes matching one DUT transport. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether HMC is enabled or required for this operation.
        """

        await self._get_session_registry().close_ssh_connection(self, dut_id, hmc)

    async def close_all_ssh_connections(self) -> None:
        """
        Drain all pooled SSH endpoints and exact proxy ownership.

        The implementation uses current instance state to drain all pooled SSH
        endpoints and exact proxy ownership. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        """

        await self._get_session_registry().close_all_ssh_connections(self)

    async def _recover_batched_ssh_connection(
        self,
        dut_id: str,
        hmc: bool,
        *,
        previous_connection: Optional[asyncssh.SSHClientConnection],
        attempts: int,
        backoff_seconds: float,
        cause: str,
    ) -> Tuple[Optional[asyncssh.SSHClientConnection], int]:
        """
        Recover one shared BMC/HMC SSH route through its session registry.

        ``get_ssh_connection`` owns the route health probe, retirement, proxy
        cleanup, replacement, and per-route serialization. Reusing that
        boundary prevents simultaneous collectors from closing or publishing
        competing replacements. The first recovery attempt is immediate; later
        attempts use a bounded exponential delay so a short transport
        disruption can clear before the final attempt.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether the shared route targets the HMC instead of the BMC.
            previous_connection: Connection which encountered the triggering
                failure, or ``None`` when initial acquisition failed.
            attempts: Maximum number of health-check or reconnection attempts.
            backoff_seconds: Base delay applied before recovery attempts after
                the first one.
            cause: Non-sensitive reason included in recovery diagnostics.

        Returns:
            A tuple containing the usable connection, or ``None`` after the
            recovery budget is exhausted, followed by the number of attempts
            consumed.

        Side Effects:
            Writes bounded recovery diagnostics and may cause the session
            registry to retire and replace an unhealthy route.
        """

        for attempt_index in range(attempts):
            attempt_number = attempt_index + 1
            if attempt_index:
                delay = min(
                    backoff_seconds * (2 ** (attempt_index - 1)),
                    BMC_SSH_BATCH_MAX_RETRY_BACKOFF_SECONDS,
                )
                if delay:
                    await asyncio.sleep(delay)

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "DUTManager",
                "Checking shared SSH route after "
                f"{cause} (recovery attempt {attempt_number}/{attempts})",
            )
            try:
                recovered_connection = await self.get_ssh_connection(dut_id, hmc)
            except Exception as error:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "DUTManager",
                    "Shared SSH route recovery attempt failed during registry "
                    f"handling: {type(error).__name__}",
                )
                continue
            if recovered_connection is None:
                continue

            recovery_action = (
                "health probe confirmed the existing connection is usable"
                if recovered_connection is previous_connection
                else "a usable connection was established"
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                "Shared SSH route recovered after "
                f"{cause}: {recovery_action} on attempt "
                f"{attempt_number}/{attempts}",
            )
            return recovered_connection, attempt_number

        return None, attempts

    @capture_command_diagnostics("bmc_ssh")
    async def _execute_bmc_batch_command(
        self,
        dut_id: str,
        connection: Any,
        command: str,
        timeout: float,
        *,
        hmc: bool,
    ) -> Tuple[int, str, str]:
        """
        Run and record one command on a batch-owned BMC or HMC connection.

        The caller owns connection recovery and replay policy. Each actual
        attempt crosses the same diagnostic boundary as an individual SSH
        command, including partial output on interruption.

        Args:
            dut_id: DUT owning the shared connection and diagnostic transcript.
            connection: Existing SSH connection owned by the enclosing batch.
            command: Command already normalized by the trusted command builder.
            timeout: Maximum duration for this attempt in seconds.
            hmc: Whether the batch targets the HMC instead of the BMC.

        Returns:
            The target exit code, standard output, and standard error.

        Raises:
            BaseException: A transport, cancellation, or diagnostic publication
                failure; the enclosing batch retains its existing recovery policy.
        """

        return await _run_ssh_process_bounded(connection, command, timeout=timeout)

    async def execute_bmc_commands_batched(
        self,
        dut_id: str,
        commands: List[str],
        timeout: int = 180,
        hmc: bool = False,
        include_timing: bool = False,
        connection_retries: int = BMC_SSH_BATCH_DEFAULT_CONNECTION_RETRIES,
        retry_backoff_seconds: float = BMC_SSH_BATCH_DEFAULT_RETRY_BACKOFF_SECONDS,
        commands_are_replay_safe: bool = False,
        consecutive_failure_limit: int = (
            BMC_SSH_BATCH_DEFAULT_CONSECUTIVE_FAILURE_LIMIT
        ),
    ) -> List[Union[Tuple[int, str, str], Tuple[int, str, str, float]]]:
        """
        Execute BMC commands batched.

        Commands run sequentially over a route owned by the session registry.
        After a timeout or typed transport failure, the registry probes the
        route and replaces it only when unhealthy. A recovered route lets later
        commands continue. The interrupted command is replayed only when
        process creation proved remote execution never began or when the caller
        explicitly declares every command replay safe. Exhausted connection
        recovery records the remaining commands as not attempted without
        changing result cardinality or order.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            commands: Entries supplied as ``commands`` without transferring
                container ownership.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            hmc: Whether HMC is enabled or required for this operation.
            include_timing: Whether include timing is enabled or required for
                this operation.
            connection_retries: Number of bounded route health-check or
                reconnection attempts after an initial acquisition or command
                transport failure.
            retry_backoff_seconds: Base delay before recovery attempts after
                the first attempt.
            commands_are_replay_safe: Whether commands whose remote execution
                may have begun can be replayed after successful recovery.
            consecutive_failure_limit: Number of consecutive timed-out or
                transport-failed logical commands allowed before the remaining
                batch is abandoned. Any completed command resets the count.

        Returns:
            The execute BMC commands batched returned in operation-defined
            order.

        Raises:
            ValueError: If the connection recovery policy is invalid.
        """
        results: List[Union[Tuple[int, str, str], Tuple[int, str, str, float]]] = []

        if (
            type(connection_retries) is not int
            or connection_retries < 0
            or connection_retries > BMC_SSH_BATCH_MAX_CONNECTION_RETRIES
        ):
            raise ValueError(
                "Batched SSH connection retries must be an integer between 0 "
                f"and {BMC_SSH_BATCH_MAX_CONNECTION_RETRIES}"
            )
        if (
            isinstance(retry_backoff_seconds, bool)
            or not isinstance(retry_backoff_seconds, (int, float))
            or not math.isfinite(float(retry_backoff_seconds))
            or retry_backoff_seconds < 0
            or retry_backoff_seconds > BMC_SSH_BATCH_MAX_RETRY_BACKOFF_SECONDS
        ):
            raise ValueError(
                "Batched SSH retry backoff must be a finite number between 0 "
                f"and {BMC_SSH_BATCH_MAX_RETRY_BACKOFF_SECONDS:g} seconds"
            )
        if type(commands_are_replay_safe) is not bool:
            raise ValueError("Batched SSH replay safety must be a boolean")
        if (
            type(consecutive_failure_limit) is not int
            or consecutive_failure_limit < 1
            or consecutive_failure_limit > BMC_SSH_BATCH_MAX_CONSECUTIVE_FAILURE_LIMIT
        ):
            raise ValueError(
                "Batched SSH consecutive failure limit must be an integer "
                "between 1 and "
                f"{BMC_SSH_BATCH_MAX_CONSECUTIVE_FAILURE_LIMIT}"
            )

        def command_result(
            exit_code: int,
            stdout: str,
            stderr: str,
            duration: float,
        ) -> Union[Tuple[int, str, str], Tuple[int, str, str, float]]:
            """
            Return the command result.

            The implementation uses ``exit_code``, ``stdout``, ``stderr``, and
            ``duration`` to produce the command result.

            Args:
                exit_code: Numeric exit code used while the operation performs
                    bounded accounting.
                stdout: Text supplied as stdout in the format accepted by this
                    function.
                stderr: Text supplied as stderr in the format accepted by this
                    function.
                duration: Numeric duration used while the operation performs
                    bounded accounting.

            Returns:
                A tuple containing ``integer count`` and ``duration`` in that
                order.
            """
            result = (exit_code, stdout, stderr)
            if include_timing:
                return (*result, duration)
            return result

        if not commands:
            return []

        # Get or create SSH connection
        conn = await self.get_ssh_connection(dut_id, hmc)
        if not conn and connection_retries:
            conn, _ = await self._recover_batched_ssh_connection(
                dut_id,
                hmc,
                previous_connection=None,
                attempts=connection_retries,
                backoff_seconds=float(retry_backoff_seconds),
                cause="initial connection failure",
            )
        if not conn:
            # If connection failed, return errors for all commands
            recorder = getattr(type(self.logger), "record_command_diagnostic", None)
            if recorder is not None:
                await recorder(
                    self.logger,
                    dut_id,
                    transport="bmc_ssh",
                    command="",
                    exit_code=None,
                    stdout="",
                    stderr="SSH connection failed after bounded recovery",
                    timeout=timeout,
                    duration_seconds=None,
                    operation="bmc_batch_connection",
                    target="hmc" if hmc else "bmc_ssh",
                    outcome="not_attempted",
                )
            return [
                command_result(
                    -1,
                    "",
                    "SSH connection failed after bounded recovery",
                    0.0,
                )
                for _ in commands
            ]

        batch_abort_reason: Optional[str] = None
        consecutive_transport_failures = 0
        try:
            # Execute all commands in sequence using the same connection
            for i, command in enumerate(commands):
                command_start = time.monotonic()
                trusted_command = build_trusted_remote_command(command)
                recovery_attempts_remaining = connection_retries
                while True:
                    try:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"Executing batched command {i + 1}/{len(commands)}: {command}",
                        )

                        exit_status, stdout, stderr = (
                            await self._execute_bmc_batch_command(
                                dut_id,
                                conn,
                                trusted_command,
                                timeout=timeout,
                                hmc=hmc,
                            )
                        )
                        results.append(
                            command_result(
                                exit_status,
                                stdout,
                                stderr,
                                time.monotonic() - command_start,
                            )
                        )
                        consecutive_transport_failures = 0
                        break

                    except asyncio.TimeoutError:
                        failed_result = command_result(
                            -1,
                            "",
                            f"Command timed out after {timeout} seconds",
                            time.monotonic() - command_start,
                        )
                        failure_cause = "command timeout"
                        replay_after_recovery = commands_are_replay_safe
                    except Exception as error:
                        failed_result = command_result(
                            -1,
                            "",
                            f"Command failed: {str(error)}",
                            time.monotonic() - command_start,
                        )
                        if not _is_terminal_batched_ssh_error(error):
                            results.append(failed_result)
                            consecutive_transport_failures = 0
                            break
                        failure_cause = type(error).__name__
                        replay_after_recovery = commands_are_replay_safe or isinstance(
                            error, HostSSHProcessCreationFailure
                        )

                    if (
                        not replay_after_recovery
                        and consecutive_transport_failures + 1
                        >= consecutive_failure_limit
                    ):
                        results.append(failed_result)
                        batch_abort_reason = (
                            "Command not attempted: the shared SSH batch reached "
                            f"{consecutive_failure_limit} consecutive transport "
                            "failures"
                        )
                        break

                    if recovery_attempts_remaining <= 0:
                        results.append(failed_result)
                        batch_abort_reason = (
                            "Command not attempted: the shared SSH batch exhausted "
                            "its connection recovery budget"
                        )
                        break

                    recovered_connection, attempts_used = (
                        await self._recover_batched_ssh_connection(
                            dut_id,
                            hmc,
                            previous_connection=conn,
                            attempts=recovery_attempts_remaining,
                            backoff_seconds=float(retry_backoff_seconds),
                            cause=failure_cause,
                        )
                    )
                    recovery_attempts_remaining -= attempts_used
                    if recovered_connection is None:
                        results.append(failed_result)
                        batch_abort_reason = (
                            "Command not attempted: the shared SSH batch could not "
                            "recover a usable connection"
                        )
                        break

                    conn = recovered_connection
                    if replay_after_recovery:
                        replay_reason = (
                            "the command was declared replay safe"
                            if commands_are_replay_safe
                            else "remote process creation had not completed"
                        )
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "DUTManager",
                            f"Retrying batched command {i + 1}/{len(commands)} because "
                            f"{replay_reason}",
                        )
                        continue

                    # The failed command may have started remotely, so retain
                    # its failure without replaying it. Recovery still protects
                    # all later commands from a transient route disruption.
                    results.append(failed_result)
                    consecutive_transport_failures += 1
                    break

                if batch_abort_reason is not None:
                    break

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DUTManager",
                f"Error in batched command execution: {str(e)}",
            )
            # Return errors for remaining commands
            while len(results) < len(commands):
                results.append(
                    command_result(
                        -1,
                        "",
                        f"Batched execution failed: {str(e)}",
                        0.0,
                    )
                )

        if batch_abort_reason is not None:
            while len(results) < len(commands):
                results.append(
                    command_result(
                        -1,
                        "",
                        batch_abort_reason,
                        0.0,
                    )
                )

        return results

    async def initialize(self) -> None:
        """
        Initialize DUT manager - create DUTs and setup logging.

        The implementation uses current instance state to initialize DUT manager
        - create DUTs and setup logging. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        """
        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"DUTManager: dut_configs type: {type(self.dut_configs)}",
        )
        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"DUTManager: base_log_dir type: {type(self.base_log_dir)}",
        )
        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"DUTManager: self.base_log_dir type: {type(self.base_log_dir)}",
        )
        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            "DUTManager: SSH backend: asyncssh",
        )
        if isinstance(self.dut_configs, dict):
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"DUTManager: dut_configs keys: {list(self.dut_configs.keys())}",
            )

        # Create DUT objects from configuration
        await self._create_duts()

    async def _apply_and_log_prefix_override(
        self,
        dut_id: str,
        config: Dict[str, Any],
        explicit_keys: Optional[Dict[str, bool]] = None,
    ) -> None:
        """
        Apply and log prefix override.

        ── BMC prefix
        ──────────────────────────────────────────────────────────.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            config: Config governing apply and log prefix override.
            explicit_keys: Optional explicit keys; ``None`` selects the
                function's default behavior.

        Raises:
            RuntimeError: If URIConfigManager must provide a non-empty
                service_root before DUT prefix overrides are applied;
                URIConfigManager must expose service-root value, provenance, and
                explicit DUT prefix state; DUT ``dut_id`` resolved an invalid
                effective Redfish service root; or DUT ``dut_id`` resolved
                unknown Redfish prefix provenance ``manager_rf_source``; or
                another input invariant is violated.
        """
        if explicit_keys is None:
            explicit_keys = {}
        catalog_service_root = getattr(self.uri_config_manager, "service_root", None)
        if not isinstance(catalog_service_root, str) or not catalog_service_root:
            raise RuntimeError(
                "URIConfigManager must provide a non-empty service_root before "
                "DUT prefix overrides are applied"
            )

        # ── BMC prefix ──────────────────────────────────────────────────────────
        get_effective_root = getattr(self.uri_config_manager, "get_service_root", None)
        get_root_provenance = getattr(
            self.uri_config_manager, "get_service_root_provenance", None
        )
        get_explicit_prefix = getattr(
            self.uri_config_manager, "get_explicit_dut_prefix_value", None
        )
        if (
            not callable(get_effective_root)
            or not callable(get_root_provenance)
            or not callable(get_explicit_prefix)
        ):
            raise RuntimeError(
                "URIConfigManager must expose service-root value, provenance, "
                "and explicit DUT prefix state"
            )
        manager_rf_prefix = get_effective_root(dut_id)
        if not isinstance(manager_rf_prefix, str) or not manager_rf_prefix:
            raise RuntimeError(
                f"DUT {dut_id} resolved an invalid effective Redfish service root"
            )
        manager_rf_source = get_root_provenance(dut_id)
        if manager_rf_source not in {"catalog", "tool", "dut"}:
            raise RuntimeError(
                f"DUT {dut_id} resolved unknown Redfish prefix provenance "
                f"{manager_rf_source!r}"
            )
        manager_prefix_is_explicit = manager_rf_source == "dut"
        configured_rf_prefix = config.get("RF_DEFAULT_PREFIX")
        config_prefix_is_explicit = bool(explicit_keys.get("RF_DEFAULT_PREFIX"))
        configured_rf_effective = configured_rf_prefix or catalog_service_root
        if (
            manager_prefix_is_explicit
            and config_prefix_is_explicit
            and configured_rf_effective != manager_rf_prefix
        ):
            raise RuntimeError(
                f"DUT {dut_id} has conflicting explicit Redfish service roots: "
                f"{configured_rf_prefix!r} and {manager_rf_prefix!r}"
            )

        if manager_prefix_is_explicit:
            final_rf_prefix = manager_rf_prefix
            rf_prefix_is_explicit = True
        elif config_prefix_is_explicit:
            # Empty/null explicitly clears lower-precedence policy and resolves
            # to the catalog service root; runtime request paths always receive
            # the effective non-empty value.
            final_rf_prefix = configured_rf_effective
            rf_prefix_is_explicit = True
        else:
            # URIConfigManager already resolved catalog and tool-level policy.
            # Recomputing from the flattened DUT config would erase inline/file
            # override provenance or resurrect a compatibility default.
            final_rf_prefix = manager_rf_prefix
            rf_prefix_is_explicit = False

        config["RF_DEFAULT_PREFIX"] = final_rf_prefix
        explicit_keys["RF_DEFAULT_PREFIX"] = rf_prefix_is_explicit

        # Preserve an already-loaded DUT URI policy verbatim. Direct DUT values
        # not seen by ConfigManager are committed here with their provenance.
        if not manager_prefix_is_explicit:
            self.uri_config_manager.update_dut_rf_prefix(dut_id, final_rf_prefix)
            self.uri_config_manager.set_dut_prefix_explicit(
                dut_id, "RF_DEFAULT_PREFIX", rf_prefix_is_explicit
            )

        # ── HMC prefix ──────────────────────────────────────────────────────────
        manager_hmc_prefix = get_effective_root(dut_id, hmc=True)
        manager_hmc_source = get_root_provenance(dut_id, hmc=True)
        if manager_hmc_source not in {
            "catalog",
            "tool",
            "dut",
            "tool_hmc",
            "dut_hmc",
        }:
            raise RuntimeError(
                f"DUT {dut_id} resolved unknown HMC prefix provenance "
                f"{manager_hmc_source!r}"
            )
        configured_hmc_prefix = config.get("RF_HMC_DEFAULT_PREFIX")
        config_hmc_is_explicit = bool(explicit_keys.get("RF_HMC_DEFAULT_PREFIX"))
        manager_hmc_is_explicit = manager_hmc_source == "dut_hmc"
        manager_has_hmc_policy = manager_hmc_source in {"dut_hmc", "tool_hmc"}
        configured_hmc_effective = configured_hmc_prefix or catalog_service_root
        if (
            manager_hmc_is_explicit
            and config_hmc_is_explicit
            and configured_hmc_effective != manager_hmc_prefix
        ):
            raise RuntimeError(
                f"DUT {dut_id} has conflicting explicit HMC Redfish service roots: "
                f"{configured_hmc_prefix!r} and {manager_hmc_prefix!r}"
            )

        if manager_hmc_is_explicit:
            config["RF_HMC_DEFAULT_PREFIX"] = get_explicit_prefix(dut_id, hmc=True)
            hmc_prefix_is_explicit = True
        elif config_hmc_is_explicit:
            config["RF_HMC_DEFAULT_PREFIX"] = configured_hmc_prefix
            hmc_prefix_is_explicit = True
        elif manager_has_hmc_policy:
            config["RF_HMC_DEFAULT_PREFIX"] = manager_hmc_prefix
            hmc_prefix_is_explicit = False
        else:
            config.pop("RF_HMC_DEFAULT_PREFIX", None)
            hmc_prefix_is_explicit = False
        explicit_keys["RF_HMC_DEFAULT_PREFIX"] = hmc_prefix_is_explicit

        # Preserve URIConfigManager's loaded HMC policy. Commit only a direct DUT
        # value that was not present when ConfigManager built the URI policy.
        final_hmc_prefix = config.get("RF_HMC_DEFAULT_PREFIX")
        if config_hmc_is_explicit and not manager_hmc_is_explicit:
            self.uri_config_manager.update_dut_hmc_prefix(dut_id, final_hmc_prefix)
            self.uri_config_manager.set_dut_prefix_explicit(
                dut_id, "RF_HMC_DEFAULT_PREFIX", True
            )

    async def _create_duts(self) -> None:
        """
        Create DUT objects from configuration.

        Pre-process: collect all unique config files to avoid repeated I/O.
        """
        defaults = self.dut_configs.get("DUT_Defaults", {})
        defaults_explicit_keys = _explicit_key_map(defaults)

        # Pre-process: collect all unique config files to avoid repeated I/O
        config_files_to_load = set()
        duts_needing_config = []
        duts_without_config = []

        # First pass: collect all DUTs and their config file requirements
        for dut_id, dut_config in self.dut_configs.items():
            if dut_id == "DUT_Defaults":
                continue

            # Debug logging
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"DUTManager: Creating DUT with dut_id: {dut_id} (type: {type(dut_id)})",
            )
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"DUTManager: dut_config type: {type(dut_config)}",
            )

            # Check if DUT needs config file loading
            config_file_to_use = dut_config.get("ConfigFileToUse")
            if config_file_to_use:
                config_files_to_load.add(config_file_to_use)
                duts_needing_config.append((dut_id, dut_config))
            else:
                duts_without_config.append((dut_id, dut_config))

        # Batch load all config files
        config_cache: Dict[str, Dict[str, Any]] = {}
        config_errors: Dict[str, str] = {}
        for config_file_path in config_files_to_load:
            try:
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"Loading config file: {config_file_path}",
                )
                retained_snapshot = next(
                    (
                        config.get("__referenced_config_data")
                        for _, config in duts_needing_config
                        if config.get("ConfigFileToUse") == config_file_path
                        and isinstance(config.get("__referenced_config_data"), dict)
                    ),
                    None,
                )
                if retained_snapshot is not None:
                    dut_specific_config = copy.deepcopy(retained_snapshot)
                else:
                    dut_specific_config = YAMLManager.load_yaml(
                        config_file_path, f"Config file: {config_file_path}"
                    )
                config_cache[config_file_path] = dut_specific_config
            except Exception as e:
                failure = f"linked configuration could not be loaded: {e}"
                await self.logger.log_runtime(
                    "ERROR",
                    "DUTManager",
                    f"Could not load config file '{config_file_path}': {e}",
                )
                config_errors[config_file_path] = failure

        # Process DUTs with Rich progress bar
        total_duts = len(duts_without_config) + len(duts_needing_config)
        processed_duts = 0

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"Creating {total_duts} DUT objects...",
        )

        # Process DUTs that don't need config files
        for dut_id, dut_config in duts_without_config:
            explicit_keys = {
                **defaults_explicit_keys,
                **_explicit_key_map(dut_config),
            }
            defaults_config = _strip_internal_config_keys(defaults)
            effective_dut_config = _drop_implicit_tool_like_defaults(
                dut_config, explicit_keys
            )

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Original YAML keys: {list(explicit_keys.keys())}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: dut_config keys: {set(effective_dut_config.keys())}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: defaults keys: {set(defaults_config.keys())}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: explicit_keys: {explicit_keys}",
            )
            # tool_config < DUT_Defaults < explicit per-DUT values. Implicit
            # DUTConfig model defaults are removed above so they cannot clobber
            # tool_config.yaml values.
            config = {
                **self.tool_config,
                **defaults_config,
                **effective_dut_config,
            }

            # Apply prefix_override to RF_DEFAULT_PREFIX and update URIConfigManager
            await self._apply_and_log_prefix_override(dut_id, config, explicit_keys)

            # Log skip flag values for debugging
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Skip flags after merge - SKIP_BMC_SSH_LOGS={config.get('SKIP_BMC_SSH_LOGS')}, SKIP_HOST_LOGS={config.get('SKIP_HOST_LOGS')}, SKIP_REDFISH_OOB_LOGS={config.get('SKIP_REDFISH_OOB_LOGS')}, SKIP_IPMI_LOGS={config.get('SKIP_IPMI_LOGS')}",
            )

            await self._create_single_dut_object(dut_id, config, explicit_keys)
            processed_duts += 1
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Created DUT {dut_id} ({processed_duts}/{total_duts})",
            )

        # Process DUTs that need config files
        for dut_id, dut_config in duts_needing_config:
            config_file_to_use = dut_config.get("ConfigFileToUse")
            dut_specific_config = config_cache.get(config_file_to_use, {})
            linked_config_error = config_errors.get(config_file_to_use)

            explicit_keys = {
                **defaults_explicit_keys,
                **_explicit_key_map(dut_config),
            }
            for key in dut_specific_config.keys():
                explicit_keys[key] = True

            defaults_config = _strip_internal_config_keys(defaults)
            dut_config_with_overrides = {
                **dut_specific_config,
                **_strip_internal_config_keys(dut_config),
            }
            effective_dut_config = _drop_implicit_tool_like_defaults(
                dut_config_with_overrides, explicit_keys
            )

            # tool_config < DUT_Defaults < ConfigFileToUse < DUT YAML. The
            # Pydantic default-only values are stripped before this merge.
            config = {
                **self.tool_config,
                **defaults_config,
                **effective_dut_config,
            }

            # Apply prefix_override to RF_DEFAULT_PREFIX and update URIConfigManager
            await self._apply_and_log_prefix_override(dut_id, config, explicit_keys)

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Tool config override check - tool_config keys: {list(self.tool_config.keys())}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Tool config FW_INVENTORY_TABLE_PROPERTIES: {self.tool_config.get('FW_INVENTORY_TABLE_PROPERTIES', 'NOT_FOUND')}",
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Tool config BMC_TEMP_DIR: {self.tool_config.get('BMC_TEMP_DIR', 'NOT_FOUND')}",
            )

            # Log final config values after override
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Final config BMC_TEMP_DIR: {config.get('BMC_TEMP_DIR', 'NOT_SET')}",
            )

            # Log skip flag values for debugging
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"DUT {dut_id}: Skip flags after merge - SKIP_BMC_SSH_LOGS={config.get('SKIP_BMC_SSH_LOGS')}, SKIP_HOST_LOGS={config.get('SKIP_HOST_LOGS')}, SKIP_REDFISH_OOB_LOGS={config.get('SKIP_REDFISH_OOB_LOGS')}, SKIP_IPMI_LOGS={config.get('SKIP_IPMI_LOGS')}",
            )

            await self._create_single_dut_object(dut_id, config, explicit_keys)
            if linked_config_error is not None and dut_id in self.duts:
                failed_dut = self.duts[dut_id]
                failed_dut.is_initialized = False
                failed_dut.initialization_error = linked_config_error
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DUTManager",
                    f"DUT {dut_id} initialization refused: {linked_config_error}",
                )
            processed_duts += 1
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Created DUT {dut_id} ({processed_duts}/{total_duts})",
            )

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"Successfully created {total_duts} DUT objects",
        )

        # Initialize all DUTs (call async_init on each DUT)
        await self.initialize_duts()

    async def _create_single_dut_object(
        self,
        dut_id: str,
        config: Dict[str, Any],
        explicit_keys: Optional[Dict[str, bool]] = None,
    ) -> None:
        """
        Create a single DUT object with the given configuration.

        Load baseboard configuration if baseboard is specified.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            config: Config governing single DUT object with the given
                configuration.
            explicit_keys: Optional explicit keys; ``None`` selects the
                function's default behavior.

        Raises:
            ValueError: If a verifying redfish tls policy lacks
                BMC_USE_HTTPS=true; or a verifying redfish tls policy lacks
                HMC_USE_HTTPS=true.
        """
        hmc_ip_is_explicit, configured_hmc_ip = _explicit_alias_value(
            config,
            explicit_keys or {},
            "hmc_ip",
            "HMC_IP",
        )
        hmc_transport_is_explicit = any(
            (explicit_keys or {}).get(field)
            for field in (
                "HMC_USE_HTTPS",
                "hmc_use_https",
                "HMC_RF_PROTOCOL",
                "HMC_TCP_PORT",
                "HMC_HTTP_PORT",
                "hmc_http_port",
            )
        )

        # Load baseboard configuration if baseboard is specified
        baseboard_name = config.get("baseboard")
        if baseboard_name:
            baseboard_manager = self._get_baseboard_manager()
            baseboard_config = baseboard_manager.get_baseboard_config(baseboard_name)
            if baseboard_config:
                platform_detection_config = baseboard_config.get("platform_detection")
                catalog_node_type = (
                    platform_detection_config.get("node_type")
                    if isinstance(platform_detection_config, dict)
                    else None
                )
                explicit_node_type_keys = explicit_keys or {}
                if explicit_node_type_keys.get("NodeType"):
                    configured_node_type = config.get("NodeType")
                elif explicit_node_type_keys.get("node_type"):
                    configured_node_type = config.get("node_type")
                else:
                    configured_node_type = config.get(
                        "NodeType", config.get("node_type")
                    )
                resolved_node_type = reconcile_baseboard_node_type(
                    baseboard_name,
                    configured_node_type,
                    catalog_node_type,
                    configured_explicitly=bool(
                        explicit_node_type_keys.get("NodeType")
                        or explicit_node_type_keys.get("node_type")
                    ),
                )
                if resolved_node_type is not None:
                    config["NodeType"] = resolved_node_type
                    if "node_type" in config:
                        config["node_type"] = resolved_node_type

                # Save i2c_config before baseboard merge overwrites it.
                # At this point config already has the correct precedence:
                # global tool_config < defaults < per-DUT ConfigFileToUse < DUT YAML
                pre_merge_i2c_config = config.get("i2c_config", {})

                # Merge baseboard config into DUT config (defaults only)
                config = {**config, **baseboard_config}

                # Special handling for i2c_config - deep merge with proper precedence:
                # baseboard (lowest) < tool_config / per-DUT config (higher)
                if pre_merge_i2c_config:
                    baseboard_i2c_config = baseboard_config.get("i2c_config", {})
                    merged_i2c_config = {
                        **baseboard_i2c_config,
                        **pre_merge_i2c_config,
                    }
                    config["i2c_config"] = merged_i2c_config
                    await self.logger.log_runtime(
                        "DEBUG",
                        "DUTManager",
                        f"Applied i2c_config overrides for DUT {dut_id}: {list(pre_merge_i2c_config.keys())}",
                    )

                platform_detection = config.get("platform_detection", {})

                hmc_ip_candidates: List[str] = []
                if isinstance(platform_detection, dict):
                    raw_hmc_ip = platform_detection.get("hmc_ip")
                    candidate_values: List[Any] = []

                    if isinstance(raw_hmc_ip, list):
                        candidate_values.extend(raw_hmc_ip)
                    else:
                        candidate_values.append(raw_hmc_ip)

                    existing_candidate_list = platform_detection.get(
                        "hmc_ip_candidates"
                    )
                    if isinstance(existing_candidate_list, list):
                        candidate_values.extend(existing_candidate_list)

                    for candidate in candidate_values:
                        if isinstance(candidate, str):
                            value = candidate.strip()
                            if value and value not in hmc_ip_candidates:
                                hmc_ip_candidates.append(value)

                    if hmc_ip_candidates:
                        platform_detection["hmc_ip_candidates"] = hmc_ip_candidates
                        platform_detection["hmc_ip"] = hmc_ip_candidates[0]
                        combined_candidates: List[str] = []
                        existing_config_candidates = config.get("HMC_IP_CANDIDATES", [])
                        if isinstance(existing_config_candidates, list):
                            for candidate in existing_config_candidates:
                                if (
                                    isinstance(candidate, str)
                                    and candidate
                                    and candidate not in combined_candidates
                                ):
                                    combined_candidates.append(candidate.strip())

                        for candidate in hmc_ip_candidates:
                            if candidate not in combined_candidates:
                                combined_candidates.append(candidate)

                        if combined_candidates and not hmc_ip_is_explicit:
                            config["HMC_IP_CANDIDATES"] = combined_candidates

                # Extract HMC_IP from platform_detection if not already at top level
                if not hmc_ip_is_explicit and hmc_ip_candidates:
                    config["HMC_IP"] = hmc_ip_candidates[0]
                    config["hmc_ip"] = hmc_ip_candidates[0]
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Extracted HMC_IP from baseboard platform_detection: {hmc_ip_candidates[0]}",
                    )

                # Preserve an explicit winner even when it is empty or null.
                if hmc_ip_is_explicit:
                    if config.get("HMC_IP") != configured_hmc_ip:
                        await self.logger.log_runtime(
                            "INFO",
                            "DUTManager",
                            "Preserving explicit CLI/DUT HMC_IP override over spreadsheet baseboard defaults",
                        )
                    config["HMC_IP"] = configured_hmc_ip
                    config["hmc_ip"] = configured_hmc_ip
                    if isinstance(configured_hmc_ip, str) and configured_hmc_ip.strip():
                        config["HMC_IP_CANDIDATES"] = [configured_hmc_ip.strip()]
                    else:
                        config.pop("HMC_IP_CANDIDATES", None)

                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"Loaded baseboard configuration for '{baseboard_name}' into DUT {dut_id}",
                )
                # Log key baseboard configuration values for debugging
                await self.logger.log_runtime(
                    "DEBUG",
                    "DUTManager",
                    f"Baseboard config - supports_hmc: {baseboard_config.get('supports_hmc', 'Not found')}, platform_detection: {baseboard_config.get('platform_detection', 'Not found')}",
                )
            else:
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"Baseboard '{baseboard_name}' not found in baseboard configuration for DUT {dut_id}",
                )

        # Create credentials
        # Ensure credentials.hmc_ip respects explicit config before any auto-configuration later
        effective_hmc_ip = (
            configured_hmc_ip
            if hmc_ip_is_explicit
            else config.get("HMC_IP") or config.get("hmc_ip")
        )

        bmc_username = config.get("BMC_USERNAME") or config.get("bmc_user") or ""
        bmc_password = config.get("BMC_PASSWORD") or config.get("bmc_pass") or ""
        # Redfish user/pass: if not provided, use BMC user/pass
        rf_username = config.get("RF_User") or config.get("bmc_rf_user")
        rf_password = config.get("RF_Pass") or config.get("bmc_rf_pass")
        if not rf_username and bmc_username:
            rf_username = bmc_username
        if not rf_password and bmc_password:
            rf_password = bmc_password
        # BMC SSH user/pass: if not provided, use BMC user/pass
        bmc_ssh_username = config.get("BMC_SSH_USERNAME") or config.get("bmc_ssh_user")
        bmc_ssh_password = config.get("BMC_SSH_PASSWORD") or config.get("bmc_ssh_pass")
        if not bmc_ssh_username and bmc_username:
            bmc_ssh_username = bmc_username
        if not bmc_ssh_password and bmc_password:
            bmc_ssh_password = bmc_password

        bmc_use_https = config.get("BMC_USE_HTTPS")
        if bmc_use_https is None:
            bmc_use_https = config.get("bmc_use_https", True)

        hmc_use_https = config.get("HMC_USE_HTTPS")
        if hmc_use_https is None:
            hmc_use_https = config.get("hmc_use_https", True)

        execution_mode = _resolve_execution_mode(config)
        config["ExecutionMode"] = execution_mode
        config["execution_mode"] = execution_mode
        if execution_mode == "local":
            config["local"] = True

        tool_explicit_fields = self.tool_config.get("__explicit_tool_config_fields")
        if isinstance(tool_explicit_fields, dict):
            tool_explicit_keys = {
                key
                for key, value in tool_explicit_fields.items()
                if isinstance(key, str) and value
            }
        else:
            tool_explicit_keys = {
                key for key in (tool_explicit_fields or []) if isinstance(key, str)
            }
        if tool_explicit_fields is None:
            # Compatibility for callers that construct DUTManager directly
            # without the newer provenance metadata.
            session_default_is_explicit = "tls_mode" in self.redfish_session_config
        else:
            session_default_is_explicit = "redfish_session_config" in tool_explicit_keys
        combined_explicit_keys = {key: True for key in tool_explicit_keys}
        combined_explicit_keys.update(explicit_keys or {})

        effective_redfish_tls_policy = _resolve_dut_redfish_tls_policy(
            config,
            combined_explicit_keys,
            self.redfish_tls_policy,
            session_default_is_explicit=session_default_is_explicit,
            session_override_keys=explicit_keys or {},
        )
        if (
            effective_hmc_ip
            and not hmc_use_https
            and effective_redfish_tls_policy.mode != "insecure"
            and not hmc_transport_is_explicit
        ):
            # A discovered/catalog HMC route has no user-authored plaintext
            # intent. Match the verifying Redfish default by selecting HTTPS;
            # explicit HTTP/false remains fail-closed below.
            hmc_use_https = True
            config["HMC_USE_HTTPS"] = True
            config["hmc_use_https"] = True
            config["HMC_RF_PROTOCOL"] = "https"
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                "Defaulted the discovered HMC route to HTTPS under the verifying "
                "Redfish TLS policy",
            )
        configured_bmc_ip = config.get("BMC_IP") or config.get("bmc_ip")
        if (
            configured_bmc_ip
            and not bmc_use_https
            and effective_redfish_tls_policy.mode != "insecure"
        ):
            raise ValueError(
                "A verifying Redfish TLS policy requires BMC_USE_HTTPS=true"
            )
        if (
            effective_hmc_ip
            and not hmc_use_https
            and effective_redfish_tls_policy.mode != "insecure"
        ):
            raise ValueError(
                "A verifying Redfish TLS policy requires HMC_USE_HTTPS=true"
            )
        effective_redfish_ssl = effective_redfish_tls_policy.build_ssl_parameter()

        credentials = DUTCredentials(
            bmc_ip=config.get("BMC_IP") or config.get("bmc_ip") or "",
            bmc_username=bmc_username,
            bmc_password=bmc_password,
            bmc_ssh_username=bmc_ssh_username,
            bmc_ssh_password=bmc_ssh_password,
            bmc_ssh_port=_first_non_none_config_value(
                config, "BMC_SSH_PORT", "bmc_ssh_port", default=22
            ),
            bmc_ssh_key_path=config.get("BMC_SSH_KEY_PATH")
            or config.get("bmc_ssh_key_path"),
            bmc_ssh_passwordless=config.get(
                "BMC_SSH_PASSWORDLESS",
                config.get("bmc_ssh_passwordless", False),
            ),
            bmc_ssh_max_retries=config.get(
                "BMC_SSH_MAX_RETRIES", config.get("bmc_ssh_max_retries", 3)
            ),
            bmc_rf_port=_first_non_none_config_value(
                config, "BMC_RF_PORT", "bmc_rf_port", default=443
            ),
            bmc_use_https=bmc_use_https,
            bmc_rf_verify_ssl=effective_redfish_tls_policy.is_verified(
                use_https=bmc_use_https
            ),
            host_ip=config.get("HOST_IP") or config.get("host_ip"),
            host_username=config.get("HOST_USERNAME") or config.get("host_user"),
            host_password=config.get("HOST_PASSWORD") or config.get("host_pass"),
            host_sudo_password=config.get("host_sudo_password"),
            host_ssh_port=_first_non_none_config_value(
                config, "HOST_SSH_PORT", "host_ssh_port", default=22
            ),
            host_ssh_key_path=config.get("HOST_SSH_KEY_PATH")
            or config.get("host_ssh_key_path"),
            host_ssh_passwordless=config.get(
                "HOST_SSH_PASSWORDLESS",
                config.get("host_ssh_passwordless", False),
            ),
            host_ssh_max_retries=config.get(
                "HOST_SSH_MAX_RETRIES", config.get("host_ssh_max_retries", 3)
            ),
            rf_username=rf_username,
            rf_password=rf_password,
            tunnel_tcp_port=config.get("TUNNEL_TCP_PORT")
            or config.get("tunnel_tcp_port"),
            ipmi_cipher=config.get("ipmi_cipher", "-C17"),
            # HMC Configuration
            hmc_ip=effective_hmc_ip,
            hmc_username=config.get("HMC_USERNAME") or config.get("hmc_user"),
            hmc_password=config.get("HMC_PASSWORD") or config.get("hmc_pass"),
            hmc_ssh_username=config.get("HMC_SSH_USERNAME")
            or config.get("hmc_ssh_user"),
            hmc_ssh_password=config.get("HMC_SSH_PASSWORD")
            or config.get("hmc_ssh_pass"),
            hmc_ssh_port=_first_non_none_config_value(
                config, "HMC_SSH_PORT", "hmc_ssh_port", default=22
            ),
            hmc_ssh_key_path=config.get("HMC_SSH_KEY_PATH")
            or config.get("hmc_ssh_key_path"),
            hmc_ssh_passwordless=config.get(
                "HMC_SSH_PASSWORDLESS",
                config.get("hmc_ssh_passwordless", False),
            ),
            hmc_ssh_max_retries=config.get(
                "HMC_SSH_MAX_RETRIES", config.get("hmc_ssh_max_retries", 3)
            ),
            hmc_http_port=config.get("HMC_HTTP_PORT", 80),
            hmc_https_port=config.get("HMC_HTTPS_PORT", 443),
            hmc_use_https=hmc_use_https,
            use_port_forwarding=config.get("USE_PORT_FORWARDING", False),
            rf_hmc_access_method=config.get("RF_HMC_ACCESS_METHOD"),
            execution_mode=execution_mode,
            hmc_ip_candidates=config.get("HMC_IP_CANDIDATES"),
            hmc_ip_explicit=hmc_ip_is_explicit,
            # SSH Proxy Configuration
            ssh_proxy_host=config.get("SSH_PROXY_HOST") or config.get("ssh_proxy_host"),
            ssh_proxy_port=config.get(
                "SSH_PROXY_PORT", config.get("ssh_proxy_port", 22)
            ),
            ssh_proxy_username=config.get(
                "SSH_PROXY_USERNAME", config.get("ssh_proxy_user")
            ),  # Map ssh_proxy_user to ssh_proxy_username
            ssh_proxy_password=config.get(
                "SSH_PROXY_PASSWORD", config.get("ssh_proxy_pass")
            ),  # Map ssh_proxy_pass to ssh_proxy_password
            ssh_proxy_key_path=config.get("SSH_PROXY_KEY_PATH")
            or config.get("ssh_proxy_key_path"),
            ssh_proxy_passwordless=config.get(
                "SSH_PROXY_PASSWORDLESS",
                config.get("ssh_proxy_passwordless", False),
            ),
            ssh_proxy_max_retries=config.get(
                "SSH_PROXY_MAX_RETRIES", config.get("ssh_proxy_max_retries", 3)
            ),
            ssh_host_key_policy=config.get("ssh_host_key_policy", "insecure"),
            ssh_known_hosts_file=config.get("ssh_known_hosts_file"),
        )

        dut = DUT(dut_id, credentials, config, self)
        dut.redfish_tls_policy = effective_redfish_tls_policy
        dut.redfish_ssl = effective_redfish_ssl
        dut.redfish_session_config = {
            **self.redfish_session_config,
            **effective_redfish_tls_policy.as_dict(),
            "ssl_verify": effective_redfish_tls_policy.is_verified(
                use_https=bmc_use_https
            ),
            "ssl": effective_redfish_ssl,
        }
        for holder in ("redfish_sessions", "redfish_session_config"):
            if not (explicit_keys or {}).get(holder):
                continue
            session_values = config.get(holder)
            if hasattr(session_values, "model_dump"):
                session_values = session_values.model_dump(exclude_unset=True)
            if (
                isinstance(session_values, dict)
                and "authentication_mode" in session_values
            ):
                dut.redfish_session_config["authentication_mode"] = (
                    RedfishSessionConfig.model_validate(
                        {"authentication_mode": session_values["authentication_mode"]}
                    ).authentication_mode
                )
        authentication_override = config.get("bmc_rf_authentication_mode")
        if authentication_override is not None:
            dut.redfish_session_config["authentication_mode"] = (
                RedfishSessionConfig.model_validate(
                    {"authentication_mode": authentication_override}
                ).authentication_mode
            )
        dut.redfish_response_limits = self.redfish_response_limits
        # Retain the established class attributes for API compatibility while
        # letting each initialized DUT use the resolved operator profile.
        dut.REDFISH_CACHE_MAX_BYTES = self.redfish_response_limits.cache_max_bytes
        dut.REDFISH_CACHE_MAX_ENTRY_BYTES = (
            self.redfish_response_limits.cache_entry_max_bytes
        )
        dut.redfish_session_timeout = self.redfish_session_timeout
        dut.redfish_keepalive_timeout = self.redfish_keepalive_timeout
        dut.redfish_ttl_dns_cache = self.redfish_ttl_dns_cache
        dut.redfish_use_dns_cache = self.redfish_use_dns_cache
        dut.redfish_force_close = self.redfish_force_close
        dut.redfish_enable_cleanup_closed = self.redfish_enable_cleanup_closed
        dut.redfish_fallback_connection_pool_limit = (
            self.redfish_fallback_connection_pool_limit
        )
        dut.redfish_fallback_connection_pool_limit_per_host = (
            self.redfish_fallback_connection_pool_limit_per_host
        )
        dut.logger = self.logger  # Give DUT access to the logger
        if self.redfish_response_limits != DEFAULT_REDFISH_RESPONSE_LIMITS:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                "Operator-configured finite Redfish byte ceilings active: "
                + ", ".join(
                    f"{name}={value}"
                    for name, value in self.redfish_response_limits.as_dict().items()
                ),
            )
        if credentials.ssh_host_key_policy != "strict" and (
            credentials.bmc_ip or credentials.host_ip or credentials.hmc_ip
        ):
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "DUTManager",
                INSECURE_SSH_HOST_KEY_WARNING_MESSAGE,
            )
        insecure_redfish_endpoint = (
            bool(credentials.bmc_ip)
            and not effective_redfish_tls_policy.is_verified(
                use_https=credentials.bmc_use_https
            )
        ) or (
            bool(credentials.hmc_ip)
            and not effective_redfish_tls_policy.is_verified(
                use_https=credentials.hmc_use_https
            )
        )
        if insecure_redfish_endpoint:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "DUTManager",
                INSECURE_REDFISH_TRANSPORT_WARNING_MESSAGE,
            )
        # Store explicit keys for configuration precedence
        dut.explicit_config_keys = combined_explicit_keys
        self.duts[dut_id] = dut

    async def apply_baseboard_defaults(self, dut_id: str, baseboard_name: str) -> bool:
        """
        Apply spreadsheet defaults after live baseboard detection.

        The DUT already exists when detection completes, so merge the detected
        catalog row without replacing higher-precedence DUT values. Explicit HMC
        values remain authoritative even when they intentionally clear the
        field.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            baseboard_name: Stable baseboard name used for lookup and
                operator-facing diagnostics.

        Returns:
            Whether the apply spreadsheet defaults after live baseboard
            detection operation succeeds.
        """
        dut = self.duts.get(dut_id)
        if dut is None or not baseboard_name:
            return False

        baseboard_config = self._get_baseboard_manager().get_baseboard_config(
            baseboard_name
        )
        if not baseboard_config:
            await self.logger.log_runtime(
                "WARNING",
                "DUTManager",
                f"Baseboard '{baseboard_name}' is not present in the spreadsheet catalog",
            )
            return False

        existing = dict(dut.config)
        merged = {**baseboard_config, **existing}
        merged["baseboard"] = baseboard_name
        merged["TargetBaseboard"] = baseboard_name

        # These are resolved catalog projections, not operator-authored DUT
        # settings.  If live detection replaces an earlier baseboard, never
        # retain that board's stale overrides or resolved boundary mapping.
        for catalog_key in (
            RUNTIME_BOUNDARY_OVERRIDES_KEY,
            RUNTIME_BOUNDARIES_KEY,
        ):
            if catalog_key in baseboard_config:
                merged[catalog_key] = baseboard_config[catalog_key]
            else:
                merged.pop(catalog_key, None)

        baseboard_i2c = baseboard_config.get("i2c_config", {})
        existing_i2c = existing.get("i2c_config", {})
        if dut.has_explicit_config_key("i2c_config") and existing_i2c == {}:
            # An explicit empty mapping clears the lower spreadsheet defaults.
            merged["i2c_config"] = {}
        elif isinstance(baseboard_i2c, dict) and isinstance(existing_i2c, dict):
            merged["i2c_config"] = {**baseboard_i2c, **existing_i2c}

        configured_hmc_present = False
        configured_hmc = None
        for alias in ("hmc_ip", "HMC_IP"):
            if dut.has_explicit_config_key(alias):
                configured_hmc_present = True
                configured_hmc = existing.get(alias)
                break

        platform_detection = baseboard_config.get("platform_detection", {})
        candidates: List[str] = []
        if isinstance(platform_detection, dict):
            for raw in (
                platform_detection.get("hmc_ip"),
                platform_detection.get("hmc_ip_candidates"),
            ):
                values = raw if isinstance(raw, list) else [raw]
                for value in values:
                    if isinstance(value, str):
                        normalized = value.strip()
                        if normalized and normalized not in candidates:
                            candidates.append(normalized)

        spreadsheet_hmc = baseboard_config.get("HMC_IP") or baseboard_config.get(
            "hmc_ip"
        )
        primary_hmc = (
            configured_hmc
            if configured_hmc_present
            else (candidates[0] if candidates else spreadsheet_hmc)
        )

        if primary_hmc:
            dut.redfish_tls_policy.require_compatible_transport(
                use_https=dut.credentials.hmc_use_https,
                endpoint_name="HMC",
            )

        ordered_candidates: List[str] = []
        candidate_sources = (
            (configured_hmc,)
            if configured_hmc_present
            else (primary_hmc, *candidates, spreadsheet_hmc)
        )
        for candidate in candidate_sources:
            if isinstance(candidate, str):
                normalized = candidate.strip()
                if normalized and normalized not in ordered_candidates:
                    ordered_candidates.append(normalized)

        if configured_hmc_present:
            merged["HMC_IP"] = configured_hmc
            merged["hmc_ip"] = configured_hmc
            merged.pop("HMC_IP_CANDIDATES", None)
        elif primary_hmc:
            merged["HMC_IP"] = primary_hmc
            merged["hmc_ip"] = primary_hmc
        if ordered_candidates:
            merged["HMC_IP_CANDIDATES"] = ordered_candidates

        # Preserve mapping identity for services that already reference it.
        dut.config.clear()
        dut.config.update(merged)
        if configured_hmc_present:
            dut.credentials.hmc_ip = configured_hmc
            dut.credentials.hmc_ip_candidates = ordered_candidates
        elif primary_hmc and not dut.credentials.hmc_ip:
            dut.credentials.hmc_ip = primary_hmc
        if ordered_candidates and not configured_hmc_present:
            dut.credentials.hmc_ip_candidates = ordered_candidates

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"Applied spreadsheet defaults for baseboard '{baseboard_name}' to DUT {dut_id}",
        )
        return True

    async def _load_dut_specific_config(
        self, dut_id: str, dut_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Load DUT-specific configuration file if ConfigFileToUse is specified.

        The implementation uses ``dut_id`` and ``dut_config`` to load
        DUT-specific configuration file if ConfigFileToUse is specified. Parsing
        or I/O must finish before the validated representation is made available
        to the caller. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            dut_config: DUT config governing DUT-specific configuration file if
                ConfigFileToUse is specified.

        Returns:
            A mapping containing DUT specific config.
        """
        try:
            config_file_to_use = dut_config.get("ConfigFileToUse")
            if not config_file_to_use:
                return dut_config

            # Load the DUT-specific config file
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Loading DUT-specific config for {dut_id}: {config_file_to_use}",
            )
            retained_snapshot = dut_config.get("__referenced_config_data")
            if isinstance(retained_snapshot, dict):
                dut_specific_config = copy.deepcopy(retained_snapshot)
            else:
                dut_specific_config = YAMLManager.load_yaml(
                    config_file_to_use, f"DUT-specific config for {dut_id}"
                )

            # Merge configurations: DUT config overrides DUT-specific config
            merged_config = merge_dut_config_layers(dut_specific_config, dut_config)

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Successfully loaded DUT-specific config for {dut_id}",
            )
            return merged_config

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DUTManager",
                f"Failed to load DUT-specific config for {dut_id}: {e}",
            )
            raise

    async def initialize_duts(self) -> None:
        """
        Initialize all DUTs (setup logging, test connections).

        The implementation uses current instance state to initialize all DUTs
        (setup logging, test connections). Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        If the function cannot initialize all DUTs (setup logging, test
        connections), its exception reaches the caller instead of being
        converted into a successful result.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to initialize all DUTs (setup logging, test
                connections).
        """
        tasks = [
            asyncio.create_task(
                capture_owned_awaitable(self._initialize_single_dut(dut_id, dut))
            )
            for dut_id, dut in self.duts.items()
            if getattr(dut, "initialization_error", None) is None
        ]
        outcomes = await drain_owned_tasks(
            tasks,
            cancel_on_error=lambda error: (
                isinstance(error, HMCForwardingConfigurationError)
                or not isinstance(error, Exception)
            ),
        )
        fatal_errors = [
            outcome.error
            for outcome in outcomes
            if outcome.error is not None
            and not outcome.owner_cancelled
            and (
                isinstance(outcome.error, HMCForwardingConfigurationError)
                or not isinstance(outcome.error, Exception)
            )
        ]
        if fatal_errors:
            raise select_authoritative_exception(fatal_errors)

    async def cleanup_all_ssh_proxy_tunnels(self) -> None:
        """
        Drain and verify all DUT-owned SSH proxy tunnels.

        The implementation uses current instance state to drain and verify all
        DUT-owned SSH proxy tunnels. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.
        """

        await self._get_session_registry().cleanup_all_ssh_proxy_tunnels(self)

    def cleanup_all_ssh_proxy_tunnels_sync(self) -> None:
        """
        Synchronously request exact proxy-owner cleanup for all DUTs.

        The implementation uses current instance state to synchronously request
        exact proxy-owner cleanup for all DUTs.
        """

        self._get_session_registry().cleanup_all_ssh_proxy_tunnels_sync(self)

    def _kill_all_ssh_tunnels_direct(self) -> None:
        """
        Deprecated unsafe fallback.

        Tunnel cleanup must flow through each PortForwardingService instance,
        which owns and verifies the exact child PID/PGID identity. Scanning or
        terminating unrelated SSH processes is intentionally unsupported.
        """

        logger.warning(
            "Broad SSH tunnel cleanup is disabled; tracked tunnel owners "
            "perform exact process-group cleanup"
        )

    async def _initialize_single_dut(self, dut_id: str, dut: DUT) -> None:
        """
        Initialize a single DUT.

        The implementation uses ``dut_id`` and ``dut`` to initialize a single
        DUT. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            dut: Stable DUT used to correlate configuration, logs, and results.
        """
        dut.is_initialized = False
        dut.initialization_error = None
        try:
            await dut.setup_logging(self.base_log_dir)
            await dut.async_init()  # Initialize HMC platform detection

            # Log SSH proxy configuration if present
            if dut.credentials.ssh_proxy_host:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DUTManager",
                    f"SSH proxy configured: {dut.credentials.ssh_proxy_host}:{dut.credentials.ssh_proxy_port} (user: {dut.credentials.ssh_proxy_username})",
                )
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"DUT {dut_id}: SSH proxy configured - {dut.credentials.ssh_proxy_host}:{dut.credentials.ssh_proxy_port}",
                )

            await self.logger.write_to_dut_runtime_log(
                dut_id, "INFO", "DUTManager", f"Initialized DUT {dut_id}"
            )
            dut.is_initialized = True
        except Exception as e:
            dut.initialization_error = str(e)
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DUTManager",
                f"Failed to initialize DUT {dut_id}: {e}",
            )
            if isinstance(e, HMCForwardingConfigurationError):
                raise

    def get_dut(self, dut_id: str) -> DUT:
        """
        Get a DUT by ID.

        The implementation uses ``dut_id`` to get a DUT by ID. If the function
        cannot get a DUT by ID, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``dut``.

        Raises:
            ValueError: If DUT ``dut_id`` not found.
            RuntimeError: If DUT ``dut_id`` failed initialization:
                ``initialization_error``.
        """
        if dut_id not in self.duts:
            raise ValueError(f"DUT {dut_id} not found")
        dut = self.duts[dut_id]
        initialization_error = self._dut_initialization_failure(dut)
        if initialization_error is not None:
            raise RuntimeError(
                f"DUT {dut_id} failed initialization: {initialization_error}"
            )
        return dut

    @staticmethod
    def _dut_initialization_failure(dut: DUT) -> Optional[str]:
        """
        Return the recorded failure for a DUT that did not initialize.

        The implementation uses ``dut`` to produce the recorded failure for a
        DUT that did not initialize.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.

        Returns:
            Whether the recorded failure for a DUT that did not initialize
            operation succeeds.
        """

        if getattr(dut, "is_initialized", None) is not False:
            return None
        error = getattr(dut, "initialization_error", None)
        if error is None:
            return None
        return str(error) or "unknown initialization error"

    def get_all_dut_ids(self) -> List[str]:
        """
        Get all DUT IDs.

        After applying local validation, the function forwards current instance
        state to ``list`` and preserves its return and exception contract.

        Returns:
            The all DUT identifiers returned in operation-defined order.
        """
        return list(self.duts.keys())

    def get_dut_config(self, dut_id: str) -> Dict[str, Any]:
        """
        Get DUT configuration by ID.

        The implementation uses ``dut_id`` to get DUT configuration by ID. If
        the function cannot get DUT configuration by ID, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing DUT config.

        Raises:
            ValueError: If DUT ``dut_id`` not found.
        """
        if dut_id not in self.duts:
            raise ValueError(f"DUT {dut_id} not found")
        return self.duts[dut_id].config

    async def run_preflight_checks(
        self,
        required_collector_groups: Optional[List[str]] = None,
        show_progress: bool = True,
        collector_definitions: Optional[Dict[str, Any]] = None,
        required_collector_groups_per_dut: Optional[Dict[str, List[str]]] = None,
        service_candidates: Optional[List[str]] = None,
        redfish_controllers_per_dut: Optional[Dict[str, set[str]]] = None,
    ) -> Dict[str, Any]:
        """
        Run preflight checks.

        Determine which services to check based on collector groups.

        Args:
            required_collector_groups: Optional required collector groups;
                ``None`` selects the function's default behavior.
            show_progress: Whether show progress is enabled or required for this
                operation.
            collector_definitions: Optional collector definitions; ``None``
                selects the function's default behavior.
            required_collector_groups_per_dut: Optional required collector
                groups per DUT; ``None`` selects the function's default
                behavior.
            service_candidates: Optional transport groups which are intersected
                with each DUT's configured endpoints instead of being inferred
                from collector groups.
            redfish_controllers_per_dut: Catalog-selected controller names for
                each DUT. Unspecified DUTs retain the default Redfish route.

        Returns:
            A mapping containing run preflight checks.

        Raises:
            ValueError: If ``service_candidates`` contains an unsupported
                transport.
        """
        if not self.duts:
            await self.logger.log_runtime("ERROR", "DUTManager", "No DUTs configured")
            return {}

        # Determine which services to check based on collector groups, or use a
        # caller-owned candidate scope for phases such as auto-detection. Keep
        # the canonical order stable for logs, progress, and rendered tables.
        if service_candidates is None:
            services_to_check = self._get_services_for_collector_groups(
                required_collector_groups
            )
        else:
            supported_services = ("redfish", "ipmi", "ssh", "host")
            requested_services = {
                str(service).strip().lower()
                for service in service_candidates
                if str(service).strip()
            }
            unsupported_services = requested_services.difference(supported_services)
            if unsupported_services:
                unsupported = ", ".join(sorted(unsupported_services))
                raise ValueError(
                    f"Unsupported preflight service candidate(s): {unsupported}"
                )
            services_to_check = [
                service
                for service in supported_services
                if service in requested_services
            ]

        def required_services_for_dut(dut_id: str) -> set:
            """
            Return the required services for DUT.

            The implementation uses ``dut_id`` to produce the required services
            for DUT.

            Args:
                dut_id: Stable DUT identifier used to correlate configuration,
                    logs, and results.

            Returns:
                The unique required services for DUT returned by the operation.
            """
            if service_candidates is not None:
                dut = self.duts[dut_id]
                return {
                    service
                    for service in services_to_check
                    if self._service_transport_configured(dut, service)
                }

            groups = required_collector_groups
            if (
                required_collector_groups_per_dut is not None
                and dut_id in required_collector_groups_per_dut
            ):
                groups = required_collector_groups_per_dut[dut_id]
            return {str(group).strip().lower() for group in (groups or []) if group}

        def services_for_dut(dut_id: str) -> List[str]:
            """
            Return the services for DUT.

            The implementation uses ``dut_id`` to produce the services for DUT.

            Args:
                dut_id: Stable DUT identifier used to correlate configuration,
                    logs, and results.

            Returns:
                The services for DUT returned in operation-defined order.
            """
            if service_candidates is not None:
                required_services = required_services_for_dut(dut_id)
                return [
                    service
                    for service in services_to_check
                    if service in required_services
                ]
            if (
                required_collector_groups_per_dut is None
                or dut_id not in required_collector_groups_per_dut
            ):
                return services_to_check
            required_services = required_services_for_dut(dut_id)
            return [
                service for service in services_to_check if service in required_services
            ]

        assigned_services = [
            service
            for service in services_to_check
            if any(service in services_for_dut(dut_id) for dut_id in self.duts)
        ]
        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"Running preflight checks on {len(self.duts)} DUT(s) for services: {', '.join(assigned_services)}",
        )

        # Use the same console setup as workflow orchestrator
        if hasattr(self.logger, "original_stdout") and self.logger.original_stdout:
            console = Console(file=self.logger.original_stdout, force_terminal=True)
        else:
            console = Console(force_terminal=True)

        # Build collector group mapping once for baseboard-aware preflight skipping
        collectors_by_group = self._build_collectors_by_group_map(collector_definitions)

        results = {}

        # Calculate only the service checks assigned to each DUT. A union-sized
        # total would include transports selected solely for a peer DUT.
        total_tasks = sum(len(services_for_dut(dut_id)) for dut_id in self.duts)

        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
                refresh_per_second=10,
                transient=True,
            ) as progress:
                main_task = progress.add_task(
                    f"[cyan]Preflight Checks ({len(self.duts)} DUTs, "
                    f"{total_tasks} assigned service checks) - "
                    "DUTs Parallel, Services Sequential",
                    total=total_tasks,
                )

                # Run DUTs in parallel, but services sequentially within each DUT
                dut_tasks = []
                for dut_id, dut in self.duts.items():
                    task = self._run_dut_preflight_parallel(
                        dut_id,
                        dut,
                        progress,
                        main_task,
                        services_for_dut(dut_id),
                        collectors_by_group,
                        required_services_for_dut(dut_id),
                        redfish_controllers=(redfish_controllers_per_dut or {}).get(
                            dut_id
                        ),
                    )
                    dut_tasks.append(task)

                # Wait for all DUTs to complete in parallel
                dut_results = await asyncio.gather(*dut_tasks, return_exceptions=True)

                # Process results
                for i, result in enumerate(dut_results):
                    dut_id = list(self.duts.keys())[i]
                    if isinstance(result, BaseException):
                        # Handle exception
                        results[dut_id] = {
                            "dut_id": dut_id,
                            "services": {},
                            "overall_status": "fail",
                            "timestamp": datetime.now().isoformat(),
                            "error": str(result),
                        }
                        await self.logger.log_runtime(
                            "ERROR",
                            f"DUT:{dut_id}",
                            f"Preflight failed with exception: {result}",
                        )
                    else:
                        results[dut_id] = result
        else:
            # Run without progress bar
            dut_tasks = []
            for dut_id, dut in self.duts.items():
                task = self._run_dut_preflight_no_progress(
                    dut_id,
                    dut,
                    services_for_dut(dut_id),
                    collectors_by_group,
                    required_services_for_dut(dut_id),
                    redfish_controllers=(redfish_controllers_per_dut or {}).get(dut_id),
                )
                dut_tasks.append(task)

            # Wait for all DUTs to complete in parallel
            dut_results = await asyncio.gather(*dut_tasks, return_exceptions=True)

            # Process results
            for i, result in enumerate(dut_results):
                dut_id = list(self.duts.keys())[i]
                if isinstance(result, BaseException):
                    # Handle exception
                    results[dut_id] = {
                        "dut_id": dut_id,
                        "services": {},
                        "overall_status": "fail",
                        "timestamp": datetime.now().isoformat(),
                        "error": str(result),
                    }
                    await self.logger.log_runtime(
                        "ERROR",
                        f"DUT:{dut_id}",
                        f"Preflight failed with exception: {result}",
                    )
                else:
                    results[dut_id] = result

        # A per-DUT plan can intentionally omit a service which is present in
        # the global scheduling union only for a peer DUT. Materialize that
        # known omission as a skip so reports do not render it as an unknown
        # result. Keep genuinely absent results unknown when no assignment map
        # exists (or when the DUT has no entry in that map).
        if required_collector_groups_per_dut is not None:
            for dut_id, dut_result in results.items():
                if dut_id not in required_collector_groups_per_dut:
                    continue
                assigned_services = set(services_for_dut(dut_id))
                service_results = dut_result.setdefault("services", {})
                for service_name in services_to_check:
                    if service_name in assigned_services:
                        continue
                    service_results.setdefault(
                        service_name,
                        {
                            "status": "skip",
                            "message": (
                                "Preflight check was not assigned or executed "
                                "for this DUT"
                            ),
                            "duration_seconds": 0.0,
                        },
                    )

        # Store preflight results in DUT objects for easy access by validation methods
        for dut_id, dut_result in results.items():
            if dut_id in self.duts:
                self.duts[dut_id].preflight_results = dut_result

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            "Preflight checks completed for all DUTs in parallel",
        )
        return results

    @staticmethod
    def _service_transport_configured(dut: "DUT", service_name: str) -> bool:
        """
        Return whether a DUT has a real endpoint for a preflight transport.

        The implementation uses ``dut`` and ``service_name`` to determine
        whether a DUT has a real endpoint for a preflight transport.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.

        Returns:
            Whether a DUT has a real endpoint for a preflight transport.
        """

        credentials = getattr(dut, "credentials", None)
        if credentials is None:
            return True

        def configured(value: Any) -> bool:
            """
            Return the configured.

            The implementation uses ``value`` to produce the configured.

            Args:
                value: Value object whose ``strip`` state is read while
                    performing configured.

            Returns:
                Whether the configured operation succeeds.
            """
            return isinstance(value, str) and bool(value.strip())

        config = getattr(dut, "config", {}) or {}
        execution_mode = getattr(credentials, "execution_mode", None)
        local_mode = execution_mode == "local" or bool(config.get("local"))
        if service_name == "host":
            return local_mode or configured(getattr(credentials, "host_ip", None))
        if service_name == "redfish":
            return configured(getattr(credentials, "bmc_ip", None))
        if service_name == "ipmi":
            return local_mode or configured(getattr(credentials, "bmc_ip", None))
        if service_name == "ssh":
            return configured(getattr(credentials, "bmc_ip", None))
        return False

    def _get_services_for_collector_groups(
        self, collector_groups: Optional[List[str]] = None
    ) -> List[str]:
        """
        Determine which services to check based on collector groups.

        Standalone preflight has no collector plan. Derive the union from real
        configured endpoints, while per-DUT filtering below ensures a mixed run
        never probes an absent transport on another DUT.

        Args:
            collector_groups: Optional collector groups; ``None`` selects the
                function's default behavior.

        Returns:
            The services for collector groups returned in operation-defined
            order.
        """
        if collector_groups is None:
            # Standalone preflight has no collector plan. Derive the union from
            # real configured endpoints, while per-DUT filtering below ensures
            # a mixed run never probes an absent transport on another DUT.
            return [
                service_name
                for service_name in ("redfish", "ipmi", "ssh", "host")
                if any(
                    self._service_transport_configured(dut, service_name)
                    for dut in self.duts.values()
                )
            ]

        requested_groups = {
            str(group).strip().lower() for group in collector_groups if group
        }

        # Redfish discovery is useful only when an actual BMC is configured and
        # the DUT still lacks an explicit platform identity. A host-only
        # SystemSIM/DCSIM endpoint must not be forced through an absent OOB
        # interface merely because platform discovery commonly uses Redfish.
        needs_redfish_discovery = False
        for dut in self.duts.values():
            credentials = getattr(dut, "credentials", None)
            bmc_ip = getattr(credentials, "bmc_ip", None)
            config = getattr(dut, "config", {}) or {}
            baseboard = config.get("baseboard") or config.get("TargetBaseboard")
            if bmc_ip and (
                not baseboard or str(baseboard).strip().lower() == "unknown"
            ):
                needs_redfish_discovery = True
                break

        services_to_check = []
        if "redfish" in requested_groups or needs_redfish_discovery:
            services_to_check.append("redfish")
        for group in ("ipmi", "ssh", "host"):
            if group in requested_groups:
                services_to_check.append(group)
        return services_to_check

    def _build_collectors_by_group_map(
        self, collector_definitions: Optional[Dict[str, Any]]
    ) -> Dict[str, List[Tuple[str, Dict[str, Any]]]]:
        """
        Build collectors by group map.

        The implementation uses ``collector_definitions`` to build collectors by
        group map.

        Args:
            collector_definitions: Mapping supplying fields for collectors by
                group map.

        Returns:
            A mapping containing collectors by group map.
        """
        group_map: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
        if not collector_definitions:
            return group_map

        collectors = collector_definitions.get("collectors", {})
        if not isinstance(collectors, dict):
            return group_map

        for collector_id, collector in collectors.items():
            if not isinstance(collector, dict):
                continue
            group = collector.get("group")
            if not group:
                continue
            group_key = str(group).strip().lower()
            if not group_key:
                continue
            group_map.setdefault(group_key, []).append((str(collector_id), collector))

        return group_map

    def _normalize_applicable_baseboards(
        self, applicable: Optional[Union[str, List[Any], Dict[str, Any]]]
    ) -> List[str]:
        """
        Normalize applicable_baseboards values into a flat list of strings.

        The implementation uses ``applicable`` to normalize
        applicable_baseboards values into a flat list of strings. The source
        value keeps its ownership while the normalized representation is
        returned separately.

        Args:
            applicable: Mapping supplying fields for applicable_baseboards
                values into a flat list of strings.

        Returns:
            The applicable baseboards returned in operation-defined order.
        """
        normalized: List[str] = []

        def _flatten(value):
            """
            Flatten nested values into deterministic processing order.

            The implementation uses ``value`` to flatten nested values into
            deterministic processing order.

            Args:
                value: Value object whose ``items`` and ``strip`` state is read
                    while performing flatten nested values into deterministic
                    processing order.
            """
            if value is None:
                return
            if isinstance(value, str):
                trimmed = value.strip()
                if trimmed:
                    normalized.append(trimmed)
                return
            if isinstance(value, list):
                for item in value:
                    _flatten(item)
                return
            if isinstance(value, dict):
                for key, flag in value.items():
                    include = True
                    if isinstance(flag, bool):
                        include = flag
                    elif isinstance(flag, str):
                        include = flag.strip().lower() not in (
                            "false",
                            "0",
                            "no",
                            "off",
                        )
                    elif isinstance(flag, (int, float)):
                        include = bool(flag)
                    if include:
                        normalized.append(str(key).strip())
                return
            normalized.append(str(value).strip())

        _flatten(applicable)
        return [spec for spec in normalized if spec]

    def _collector_matches_baseboard(
        self,
        collector_def: Dict[str, Any],
        baseboard_name: str,
        baseboard_type: Optional[str],
        baseboard_manager: Optional[BaseboardManager],
        node_type: Optional[str] = None,
    ) -> bool:
        """
        Determine if collector applies to given baseboard name/type.

        If no specification, assume collector applies broadly.

        Args:
            collector_def: Mapping supplying fields for determine if collector
                applies to given baseboard name/type.
            baseboard_name: Stable baseboard name used for lookup and
                operator-facing diagnostics.
            baseboard_type: Text supplied as baseboard type in the format
                accepted by this function.
            baseboard_manager: Baseboard manager consumed while the function
                attempts to determine if collector applies to given baseboard
                name/type.
            node_type: Optional node type; ``None`` selects the function's
                default behavior.

        Returns:
            Whether the determine if collector applies to given baseboard
            name/type operation succeeds.
        """
        applicable_specs = self._normalize_applicable_baseboards(
            collector_def.get("applicable_baseboards")
        )
        exclude_specs = self._normalize_applicable_baseboards(
            collector_def.get("exclude_baseboards")
        )

        # If no specification, assume collector applies broadly.
        if not applicable_specs:
            applicable_specs = ["all"]

        baseboard_type_lower = baseboard_type.lower() if baseboard_type else None
        node_type_lower = node_type.lower() if node_type else None
        effective_baseboard_names = [baseboard_name]
        effective_baseboard_names_lower = [
            member.lower() for member in effective_baseboard_names
        ]
        equivalent_group_names_lower: set[str] = set()
        if baseboard_manager and not baseboard_type:
            raw_group_names = baseboard_manager.get_all_baseboard_types()
            group_names = raw_group_names if isinstance(raw_group_names, list) else []
            selected_group = next(
                (
                    group_name
                    for group_name in group_names
                    if isinstance(group_name, str)
                    and group_name.casefold() == baseboard_name.casefold()
                ),
                None,
            )
            if selected_group is not None:
                raw_equivalent_groups = (
                    baseboard_manager.get_equivalent_baseboard_groups(selected_group)
                )
                if isinstance(raw_equivalent_groups, list):
                    equivalent_group_names_lower = {
                        group_name.casefold()
                        for group_name in raw_equivalent_groups
                        if isinstance(group_name, str)
                    }

        def spec_matches(spec: str) -> bool:
            """
            Return the spec matches.

            The implementation uses ``spec`` to produce the spec matches.

            Args:
                spec: Text supplied as spec in the format accepted by this
                    function.

            Returns:
                Whether the spec matches operation succeeds.
            """
            spec_lower = spec.lower()
            if spec_lower in {"all", "*"}:
                return True
            if spec_lower in effective_baseboard_names_lower:
                return True
            if baseboard_type_lower and baseboard_type_lower == spec_lower:
                return True
            if node_type_lower and node_type_lower == spec_lower:
                return True
            if spec.casefold() in equivalent_group_names_lower:
                return True
            if baseboard_manager:
                group_members = baseboard_manager.get_baseboards_in_group(spec)
                if group_members:
                    members_lower = [member.lower() for member in group_members]
                    if any(
                        effective_name in members_lower
                        for effective_name in effective_baseboard_names_lower
                    ):
                        return True
            return False

        if any(spec_matches(spec) for spec in exclude_specs):
            return False

        return any(spec_matches(spec) for spec in applicable_specs)

    def _should_run_service_for_dut(
        self,
        dut: "DUT",
        service_name: str,
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
        explicitly_required: bool = False,
    ) -> Tuple[bool, str]:
        """
        Return whether ``dut`` should run service for DUT.

        The implementation uses ``dut``, ``service_name``,
        ``collectors_by_group``, and ``explicitly_required`` to determine
        whether ``dut`` should run service for DUT.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.
            collectors_by_group: Optional collectors by group; ``None`` selects
                the function's default behavior.
            explicitly_required: Whether explicitly required is enabled or
                required for this operation.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        config = getattr(dut, "config", {}) or {}
        support_field = transport_support_field(service_name)
        if catalog_transport_support(config, service_name) is False:
            baseboard_name = config.get("baseboard") or config.get("TargetBaseboard")
            return (
                False,
                f"Baseboard '{baseboard_name or 'unknown'}' catalog declares "
                f"{support_field}=false; {service_name} is not applicable",
            )

        if not self._service_transport_configured(dut, service_name):
            if explicitly_required:
                return (
                    True,
                    f"Explicitly requested {service_name} preflight must fail closed",
                )
            return (
                False,
                f"No configured {service_name} endpoint for this DUT",
            )

        if not collectors_by_group:
            if not self._service_transport_configured(dut, service_name):
                return (
                    False,
                    f"No configured {service_name} endpoint for this DUT",
                )
            return True, "Collector definitions unavailable"

        service_collectors = collectors_by_group.get(service_name.lower(), [])
        if not service_collectors:
            return True, f"No {service_name} collectors defined"

        baseboard_name = None
        node_type = None
        if dut and getattr(dut, "config", None):
            baseboard_name = dut.config.get("baseboard") or dut.config.get(
                "TargetBaseboard"
            )
            node_type = dut.config.get("NodeType") or dut.config.get("node_type")

        if not baseboard_name:
            return (
                True,
                "Baseboard not specified; running preflight by default",
            )

        baseboard_name = str(baseboard_name).strip()
        if not baseboard_name or baseboard_name.lower() == "unknown":
            return (
                True,
                "Baseboard not specified; running preflight by default",
            )

        baseboard_manager = self._get_baseboard_manager()
        baseboard_type = (
            baseboard_manager.get_baseboard_type(baseboard_name)
            if baseboard_manager
            else None
        )

        for collector_id, collector_def in service_collectors:
            if self._collector_matches_baseboard(
                collector_def,
                baseboard_name,
                baseboard_type,
                baseboard_manager,
                node_type=node_type,
            ):
                return (
                    True,
                    f"Collector {collector_id} targets baseboard {baseboard_name}",
                )

        if baseboard_type:
            return (
                False,
                f"No applicable {service_name} collectors for baseboard '{baseboard_name}' ({baseboard_type})",
            )
        else:
            return (
                False,
                f"No applicable {service_name} collectors for baseboard '{baseboard_name}'",
            )

    async def _run_dut_preflight_parallel(
        self,
        dut_id: str,
        dut: "DUT",
        progress,
        main_task,
        services_to_check: List[str],
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
        explicitly_required_services: Optional[set] = None,
        redfish_controllers: Optional[set[str]] = None,
    ) -> Dict[str, Any]:
        """
        Run preflight checks for a single DUT with all services in parallel.

        The implementation uses ``dut_id``, ``dut``, ``progress``,
        ``main_task``, and ``services_to_check`` to run preflight checks for a
        single DUT with all services in parallel. Terminal status is emitted
        only after preflight checks for a single DUT with all services in
        parallel and its owned cleanup have completed. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind. The operation mutates ``progress`` in place; ownership of
        those objects remains with the caller.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            dut: Stable DUT used to correlate configuration, logs, and results.
            progress: Progress object whose ``advance`` and ``update`` state is
                read while performing preflight checks for a single DUT with all
                services in parallel.
            main_task: Main task consumed while the function attempts to run
                preflight checks for a single DUT with all services in parallel.
            services_to_check: Entries supplied as ``services_to_check`` without
                transferring container ownership.
            collectors_by_group: Optional collectors by group; ``None`` selects
                the function's default behavior.
            explicitly_required_services: Optional explicitly required services;
                ``None`` selects the function's default behavior.
            redfish_controllers: Catalog-selected Redfish routes, or ``None``
                to preserve the default controller check.

        Returns:
            A mapping containing run DUT preflight parallel.
        """
        initialization_error = self._dut_initialization_failure(dut)
        if initialization_error is not None:
            message = f"DUT initialization failed: {initialization_error}"
            progress.update(
                main_task,
                description=f"[red]Preflight blocked[/red] on [yellow]{dut_id}[/yellow]",
            )
            progress.advance(main_task, advance=len(services_to_check))
            await self.logger.log_runtime("ERROR", f"DUT:{dut_id}", message)
            return {
                "dut_id": dut_id,
                "services": {},
                "overall_status": "fail",
                "timestamp": datetime.now().isoformat(),
                "error": message,
            }

        await self.logger.log_runtime(
            "INFO",
            f"DUT:{dut_id}",
            f"Starting parallel preflight checks for DUT {dut_id}",
        )

        dut_result = {
            "dut_id": dut_id,
            "services": {},
            "overall_status": "pass",
            "timestamp": datetime.now().isoformat(),
        }

        controller_results: Dict[str, Any] = {}
        # Define all services to test
        all_services = [
            (
                "redfish",
                lambda d: (
                    self._fast_redfish_check(
                        d,
                        collectors_by_group,
                        controllers=redfish_controllers,
                        controller_results=controller_results,
                    )
                    if redfish_controllers
                    else self._fast_redfish_check(d, collectors_by_group)
                ),
                dut,
            ),
            (
                "ipmi",
                lambda d: self._fast_ipmi_check(d, collectors_by_group),
                dut,
            ),
            (
                "ssh",
                lambda d: self._fast_ssh_check(d, collectors_by_group),
                dut,
            ),
            (
                "host",
                lambda d: self._fast_host_check(d, collectors_by_group),
                dut,
            ),
        ]

        # Filter services based on what's needed
        services = [
            service for service in all_services if service[0] in services_to_check
        ]

        # Run services sequentially to avoid resource contention
        for service_name, test_func, dut_obj in services:
            # Check for shutdown request before each service
            if (
                hasattr(self.logger, "orchestrator")
                and self.logger.orchestrator
                and hasattr(self.logger.orchestrator, "is_shutdown_requested")
                and self.logger.orchestrator.is_shutdown_requested()
            ):
                await self.logger.log_runtime(
                    "WARN",
                    f"DUT:{dut_id}",
                    f"Shutdown requested, skipping {service_name} preflight check",
                )
                dut_result["services"][service_name] = {
                    "status": "interrupted",
                    "message": "Shutdown requested",
                    "duration_seconds": 0.0,
                }
                dut_result["overall_status"] = "interrupted"
                break

            should_run, skip_reason = self._should_run_service_for_dut(
                dut,
                service_name,
                collectors_by_group,
                explicitly_required=service_name
                in (explicitly_required_services or set()),
            )
            if not should_run:
                progress.update(
                    main_task,
                    description=f"[cyan]Preflight: {service_name}[/cyan] on [yellow]{dut_id}[/yellow] - skipped",
                )
                progress.advance(main_task)
                dut_result["services"][service_name] = {
                    "status": "skip",
                    "message": skip_reason,
                    "duration_seconds": 0.0,
                }
                await self.logger.log_runtime(
                    "INFO",
                    f"DUT:{dut_id}",
                    f"Skipping {service_name} preflight: {skip_reason}",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "PreflightChecks",
                    f"Skipping {service_name} preflight: {skip_reason}",
                )
                continue

            service_started = time.monotonic()
            try:
                success, message = await self._run_service_preflight_parallel(
                    service_name,
                    test_func,
                    dut_obj,
                    dut_id,
                    progress,
                    main_task,
                )
            except Exception as exc:
                dut_result["services"][service_name] = {
                    "status": "fail",
                    "message": f"Exception during {service_name} test: {str(exc)}",
                    "duration_seconds": round(
                        max(0.0, time.monotonic() - service_started), 6
                    ),
                }
                dut_result["overall_status"] = "fail"
                await self.logger.log_runtime(
                    "ERROR",
                    f"DUT:{dut_id}",
                    f"{service_name} service exception: {str(exc)}",
                )
                continue

            dut_result["services"][service_name] = {
                "status": "pass" if success else "fail",
                "message": message,
                "duration_seconds": round(
                    max(0.0, time.monotonic() - service_started), 6
                ),
            }

            if service_name == "redfish" and controller_results:
                dut_result["services"][service_name]["controllers"] = controller_results

            if not success:
                dut_result["overall_status"] = "fail"
                await self.logger.log_runtime(
                    "WARN",
                    f"DUT:{dut_id}",
                    f"{service_name} service failed: {message}",
                )
            else:
                await self.logger.log_runtime(
                    "INFO",
                    f"DUT:{dut_id}",
                    f"{service_name} service passed: {message}",
                )

        status_msg = "PASSED" if dut_result["overall_status"] == "pass" else "FAILED"
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "PreflightChecks",
            f"Preflight checks {status_msg} for DUT {dut_id}",
        )

        return dut_result

    async def _run_dut_preflight_no_progress(
        self,
        dut_id: str,
        dut: "DUT",
        services_to_check: List[str],
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
        explicitly_required_services: Optional[set] = None,
        redfish_controllers: Optional[set[str]] = None,
    ) -> Dict[str, Any]:
        """
        Run preflight checks for a single DUT without progress bar.

        The implementation uses ``dut_id``, ``dut``, ``services_to_check``,
        ``collectors_by_group``, and ``explicitly_required_services`` to run
        preflight checks for a single DUT without progress bar. Terminal status
        is emitted only after preflight checks for a single DUT without progress
        bar and its owned cleanup have completed. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            dut: Stable DUT used to correlate configuration, logs, and results.
            services_to_check: Entries supplied as ``services_to_check`` without
                transferring container ownership.
            collectors_by_group: Optional collectors by group; ``None`` selects
                the function's default behavior.
            explicitly_required_services: Optional explicitly required services;
                ``None`` selects the function's default behavior.
            redfish_controllers: Catalog-selected Redfish routes, or ``None``
                to preserve the default controller check.

        Returns:
            A mapping containing run DUT preflight no progress.
        """
        initialization_error = self._dut_initialization_failure(dut)
        if initialization_error is not None:
            message = f"DUT initialization failed: {initialization_error}"
            await self.logger.log_runtime("ERROR", f"DUT:{dut_id}", message)
            return {
                "dut_id": dut_id,
                "services": {},
                "overall_status": "fail",
                "timestamp": datetime.now().isoformat(),
                "error": message,
            }

        await self.logger.log_runtime(
            "INFO",
            f"DUT:{dut_id}",
            f"Starting preflight checks for DUT {dut_id}",
        )

        dut_result = {
            "dut_id": dut_id,
            "services": {},
            "overall_status": "pass",
            "timestamp": datetime.now().isoformat(),
        }

        controller_results: Dict[str, Any] = {}
        # Define all services to test
        all_services = [
            (
                "redfish",
                lambda d: (
                    self._fast_redfish_check(
                        d,
                        collectors_by_group,
                        controllers=redfish_controllers,
                        controller_results=controller_results,
                    )
                    if redfish_controllers
                    else self._fast_redfish_check(d, collectors_by_group)
                ),
                dut,
            ),
            (
                "ipmi",
                lambda d: self._fast_ipmi_check(d, collectors_by_group),
                dut,
            ),
            (
                "ssh",
                lambda d: self._fast_ssh_check(d, collectors_by_group),
                dut,
            ),
            (
                "host",
                lambda d: self._fast_host_check(d, collectors_by_group),
                dut,
            ),
        ]

        # Filter services based on what's needed
        services = [
            service for service in all_services if service[0] in services_to_check
        ]

        # Run services sequentially to avoid resource contention
        for service_name, test_func, dut_obj in services:
            should_run, skip_reason = self._should_run_service_for_dut(
                dut,
                service_name,
                collectors_by_group,
                explicitly_required=service_name
                in (explicitly_required_services or set()),
            )
            if not should_run:
                dut_result["services"][service_name] = {
                    "status": "skip",
                    "message": skip_reason,
                    "duration_seconds": 0.0,
                }
                await self.logger.log_runtime(
                    "INFO",
                    f"DUT:{dut_id}",
                    f"Skipping {service_name} preflight: {skip_reason}",
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "PreflightChecks",
                    f"Skipping {service_name} preflight: {skip_reason}",
                )
                continue

            service_started = time.monotonic()
            try:
                success, message = await self._run_service_preflight_no_progress(
                    service_name, test_func, dut_obj, dut_id
                )
            except Exception as exc:
                dut_result["services"][service_name] = {
                    "status": "fail",
                    "message": f"Exception during {service_name} test: {str(exc)}",
                    "duration_seconds": round(
                        max(0.0, time.monotonic() - service_started), 6
                    ),
                }
                dut_result["overall_status"] = "fail"
                await self.logger.log_runtime(
                    "ERROR",
                    f"DUT:{dut_id}",
                    f"{service_name} service exception: {str(exc)}",
                )
                continue

            dut_result["services"][service_name] = {
                "status": "pass" if success else "fail",
                "message": message,
                "duration_seconds": round(
                    max(0.0, time.monotonic() - service_started), 6
                ),
            }

            if service_name == "redfish" and controller_results:
                dut_result["services"][service_name]["controllers"] = controller_results

            if not success:
                dut_result["overall_status"] = "fail"
                await self.logger.log_runtime(
                    "WARN",
                    f"DUT:{dut_id}",
                    f"{service_name} service failed: {message}",
                )
            else:
                await self.logger.log_runtime(
                    "INFO",
                    f"DUT:{dut_id}",
                    f"{service_name} service passed: {message}",
                )

        status_msg = "PASSED" if dut_result["overall_status"] == "pass" else "FAILED"
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "PreflightChecks",
            f"Preflight checks {status_msg} for DUT {dut_id}",
        )

        return dut_result

    async def _run_service_preflight_parallel(
        self,
        service_name: str,
        test_func,
        dut_obj,
        dut_id: str,
        progress,
        main_task,
    ) -> Tuple[bool, str]:
        """
        Run a single service preflight check with progress updates.

        The implementation uses ``service_name``, ``test_func``, ``dut_obj``,
        ``dut_id``, and ``progress`` to run a single service preflight check
        with progress updates. Terminal status is emitted only after single
        service preflight check with progress updates and its owned cleanup have
        completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. The operation
        mutates ``progress`` in place; ownership of those objects remains with
        the caller. If the function cannot run a single service preflight check
        with progress updates, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.
            test_func: Test func consumed while the function attempts to run a
                single service preflight check with progress updates.
            dut_obj: DUT object consumed while the function attempts to run a
                single service preflight check with progress updates.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            progress: Progress object whose ``advance``, ``refresh``, and
                ``update`` state is read while performing single service
                preflight check with progress updates.
            main_task: Main task consumed while the function attempts to run a
                single service preflight check with progress updates.

        Returns:
            A tuple containing ``success`` and ``message`` in that order.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to run a single service preflight check with progress
                updates.
        """
        # Update progress description
        progress.update(
            main_task,
            description=f"[cyan]Preflight: {service_name}[/cyan] on [yellow]{dut_id}[/yellow]",
        )
        progress.refresh()

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "PreflightChecks",
            f"Testing {service_name} service in parallel...",
        )

        try:
            success, message = await test_func(dut_obj)

            # Update progress with status
            status_text = "pass" if success else "fail"
            progress.update(
                main_task,
                description=f"[cyan]Preflight: {service_name}[/cyan] on [yellow]{dut_id}[/yellow] - {status_text}",
            )
            progress.advance(main_task)

            return success, message

        except Exception as e:
            # Update progress with error status
            progress.update(
                main_task,
                description=f"[cyan]Preflight: {service_name}[/cyan] on [yellow]{dut_id}[/yellow] - error",
            )
            progress.advance(main_task)

            raise e

    async def _run_service_preflight_no_progress(
        self, service_name: str, test_func, dut_obj, dut_id: str
    ) -> Tuple[bool, str]:
        """
        Run a single service preflight check without progress updates.

        The implementation uses ``service_name``, ``test_func``, ``dut_obj``,
        and ``dut_id`` to run a single service preflight check without progress
        updates. Terminal status is emitted only after single service preflight
        check without progress updates and its owned cleanup have completed.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind. If the function cannot run a single
        service preflight check without progress updates, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.
            test_func: Test func consumed while the function attempts to run a
                single service preflight check without progress updates.
            dut_obj: DUT object consumed while the function attempts to run a
                single service preflight check without progress updates.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A tuple containing ``success`` and ``message`` in that order.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to run a single service preflight check without
                progress updates.
        """
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "PreflightChecks",
            f"Testing {service_name} service...",
        )

        try:
            success, message = await test_func(dut_obj)
            return success, message

        except Exception as e:
            raise e

    def _check_service_collector_applicability(
        self,
        dut: "DUT",
        service_name: str,
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
    ) -> Tuple[bool, str]:
        """
        Check service collector applicability.

        The implementation uses ``dut``, ``service_name``, and
        ``collectors_by_group`` to check service collector applicability. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.
            collectors_by_group: Optional collectors by group; ``None`` selects
                the function's default behavior.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        if not collectors_by_group:
            return False, ""

        service_collectors = collectors_by_group.get(service_name.lower(), [])
        if not service_collectors:
            return False, ""

        # Get baseboard information
        baseboard_name = None
        node_type = None
        if dut and getattr(dut, "config", None):
            baseboard_name = dut.config.get("baseboard") or dut.config.get(
                "TargetBaseboard"
            )
            node_type = dut.config.get("NodeType") or dut.config.get("node_type")

        if not baseboard_name:
            return False, ""

        baseboard_name = str(baseboard_name).strip()
        if not baseboard_name or baseboard_name.lower() == "unknown":
            return False, ""

        # Check if any collector is applicable for this baseboard
        baseboard_manager = self._get_baseboard_manager()
        baseboard_type = (
            baseboard_manager.get_baseboard_type(baseboard_name)
            if baseboard_manager
            else None
        )

        # Count applicable collectors
        applicable_count = 0
        for collector_id, collector_def in service_collectors:
            if self._collector_matches_baseboard(
                collector_def,
                baseboard_name,
                baseboard_type,
                baseboard_manager,
                node_type=node_type,
            ):
                applicable_count += 1

        # If no collectors are applicable, return skip signal
        if applicable_count == 0:
            if baseboard_type:
                return (
                    True,
                    f"No applicable {service_name.upper()} collectors for baseboard '{baseboard_name}' ({baseboard_type})",
                )
            else:
                return (
                    True,
                    f"No applicable {service_name.upper()} collectors for baseboard '{baseboard_name}'",
                )

        return False, ""

    async def _fast_redfish_check(
        self,
        dut: "DUT",
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
        *,
        controllers: Optional[set[str]] = None,
        controller_results: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """
        Run the bounded Redfish interface preflight.

        The DUT-owned check performs one typed reachability hint followed by
        the authoritative interface request. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            collectors_by_group: Optional collectors by group; ``None`` selects
                the function's default behavior.
            controllers: Catalog-selected routes. ``None`` checks the default
                interface using the established reachability and tunnel path.
            controller_results: Caller-owned evidence mapping populated only
                after each selected controller's probe and cleanup finish.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        if controllers:
            if not controllers <= {"default", "bmc"}:
                return False, "Unsupported preflight Redfish controller"
            outcomes = {}
            for controller in sorted(controllers):
                started = time.monotonic()
                try:
                    if controller == "default":
                        success, message = await self._fast_redfish_check(
                            dut, collectors_by_group
                        )
                    else:
                        async with redfish_controller_scope(dut, controller):
                            success, message = (
                                True,
                                "Host BMC Redfish interface accessible",
                            )
                except Exception as error:
                    success = False
                    message = (
                        f"Host BMC Redfish interface error ({type(error).__name__})"
                    )
                outcomes[controller] = {
                    "status": "pass" if success else "fail",
                    "message": message,
                    "duration_seconds": round(max(0.0, time.monotonic() - started), 6),
                }
            if controller_results is not None:
                controller_results.update(outcomes)
            return (
                all(outcome["status"] == "pass" for outcome in outcomes.values()),
                "; ".join(
                    f"{controller}: {outcome['message']}"
                    for controller, outcome in outcomes.items()
                ),
            )
        if not dut.credentials.bmc_ip:
            return False, "No BMC IP configured"

        # Check if SSH proxy is configured
        if dut.credentials.ssh_proxy_host:
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"Using SSH proxy {dut.credentials.ssh_proxy_host} for Redfish preflight check",
            )
            # Proxy routes are validated by the authoritative Redfish test.
        # The DUT method owns one typed reachability hint and the authoritative
        # Redfish transport check, avoiding duplicate ICMP probes.
        try:
            # Use the DUT's redfish method with timeout
            # Increase timeout for SSH proxy scenarios (tunnel setup takes time)
            timeout = redfish_preflight_wait_timeout(dut.config)
            if dut.credentials.ssh_proxy_host or dut.credentials.use_port_forwarding:
                timeout = max(timeout, 60.0)
            success, response = await asyncio.wait_for(
                dut.test_redfish_connection(), timeout=timeout
            )
            if success:
                return True, response or "Redfish interface accessible"
            else:
                return False, f"Redfish interface failed: {response}"
        except asyncio.TimeoutError:
            # Check if any Redfish collectors are applicable for this DUT's baseboard
            should_skip, skip_message = self._check_service_collector_applicability(
                dut, "redfish", collectors_by_group
            )
            if should_skip:
                return False, skip_message

            timeout_msg = f"Redfish interface timeout ({timeout}s)"
            return False, timeout_msg
        except Exception as e:
            return False, f"Redfish interface error: {str(e)}"

    async def _fast_ipmi_check(
        self,
        dut: "DUT",
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
    ) -> Tuple[bool, str]:
        """
        Run the bounded IPMI interface preflight.

        The DUT-owned check performs one typed reachability hint followed by
        the authoritative interface request. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        Remote I/O uses the configured transport policy and returns only after
        its response or failure has been observed.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            collectors_by_group: Optional collectors by group; ``None`` selects
                the function's default behavior.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        # In local mode, IPMI can work via sudo commands even without BMC IP
        if dut.config and dut.config.get("local", False):
            return True, "Local IPMI execution via sudo"

        if not dut.credentials.bmc_ip:
            return False, "No BMC IP configured"

        # Check if SSH proxy is configured
        if dut.credentials.ssh_proxy_host:
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"Using SSH proxy {dut.credentials.ssh_proxy_host} for IPMI preflight check",
            )
            # Proxy routes are validated by the authoritative IPMI test.
        # The DUT method owns one typed reachability hint and the authoritative
        # IPMI transport check, avoiding duplicate ICMP probes.
        try:
            timeout = (
                FORWARDED_IPMI_PREFLIGHT_TIMEOUT_SECONDS
                if dut.credentials.ssh_proxy_host or dut.credentials.use_port_forwarding
                else DIRECT_IPMI_PREFLIGHT_TIMEOUT_SECONDS
            )
            # Use the DUT's ipmi method with timeout
            success, response = await asyncio.wait_for(
                dut.test_ipmi_connection(), timeout=timeout
            )
            if success:
                return True, "IPMI interface accessible"
            else:
                return False, f"IPMI interface failed: {response}"
        except asyncio.TimeoutError:
            # Check if any IPMI collectors are applicable for this DUT's baseboard
            should_skip, skip_message = self._check_service_collector_applicability(
                dut, "ipmi", collectors_by_group
            )
            if should_skip:
                return False, skip_message

            return False, f"IPMI interface timeout ({timeout}s)"
        except Exception as e:
            return False, f"IPMI interface error: {str(e)}"

    async def _fast_ssh_check(
        self,
        dut: "DUT",
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
    ) -> Tuple[bool, str]:
        """
        Run the bounded BMC SSH interface preflight.

        The DUT-owned check performs one typed reachability hint followed by
        the authoritative command probe. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            collectors_by_group: Optional collectors by group; ``None`` selects
                the function's default behavior.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        if not dut.credentials.bmc_ip:
            return False, "No BMC IP configured"

        # Check if SSH proxy is configured
        if dut.credentials.ssh_proxy_host:
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"Using SSH proxy {dut.credentials.ssh_proxy_host} for SSH preflight check",
            )
            # Skip direct ping when using proxy - go straight to SSH test
            try:
                # Use the DUT's ssh method with timeout
                success, response = await asyncio.wait_for(
                    dut.test_ssh_connection(), timeout=30.0
                )
                if success:
                    return (
                        True,
                        f"SSH interface accessible via SSH proxy {dut.credentials.ssh_proxy_host}",
                    )
                else:
                    return False, f"SSH interface failed via proxy: {response}"
            except asyncio.TimeoutError:
                # Check if any SSH collectors are applicable for this DUT's baseboard
                should_skip, skip_message = self._check_service_collector_applicability(
                    dut, "ssh", collectors_by_group
                )
                if should_skip:
                    return False, skip_message

                return False, "SSH interface timeout (30s)"
            except Exception as e:
                return False, f"SSH interface error: {str(e)}"
        else:
            # The DUT method owns one typed reachability hint and the
            # authoritative SSH transport check, avoiding duplicate probes.
            try:
                # Use the DUT's ssh method with timeout
                success, response = await asyncio.wait_for(
                    dut.test_ssh_connection(), timeout=30.0
                )
                if success:
                    return True, "SSH interface accessible"
                else:
                    return False, f"SSH interface failed: {response}"
            except asyncio.TimeoutError:
                # Check if any SSH collectors are applicable for this DUT's baseboard
                should_skip, skip_message = self._check_service_collector_applicability(
                    dut, "ssh", collectors_by_group
                )
                if should_skip:
                    return False, skip_message

                return False, "SSH interface timeout (30s)"
            except Exception as e:
                return False, f"SSH interface error: {str(e)}"

    async def _fast_host_check(
        self,
        dut: "DUT",
        collectors_by_group: Optional[
            Dict[str, List[Tuple[str, Dict[str, Any]]]]
        ] = None,
    ) -> Tuple[bool, str]:
        """
        Run the bounded Host SSH interface preflight.

        Local mode explicitly requested - allow execution without host IP.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            collectors_by_group: Optional collectors by group; ``None`` selects
                the function's default behavior.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        # Check if local mode is enabled
        is_local_mode = dut.config and dut.config.get("local", False)

        if not dut.credentials.host_ip:
            if is_local_mode:
                # Local mode explicitly requested - allow execution without host IP
                return True, "Local host execution (--local flag)"
            else:
                # No host IP and no local flag - this is a configuration error
                return False, "No host IP configured and --local flag not set"

        # Check if SSH proxy is configured
        if dut.credentials.ssh_proxy_host:
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"Using SSH proxy {dut.credentials.ssh_proxy_host} for host preflight check",
            )
            # Skip direct ping when using proxy - go straight to SSH test
            try:
                # Use the DUT's host method with timeout
                success, response = await asyncio.wait_for(
                    dut.test_host_connection(), timeout=30.0
                )
                if success:
                    return (
                        True,
                        f"Host interface accessible via SSH proxy {dut.credentials.ssh_proxy_host}",
                    )
                else:
                    return (
                        False,
                        f"Host interface failed via proxy: {response}",
                    )
            except asyncio.TimeoutError:
                # Check if any Host collectors are applicable for this DUT's baseboard
                should_skip, skip_message = self._check_service_collector_applicability(
                    dut, "host", collectors_by_group
                )
                if should_skip:
                    return False, skip_message

                return False, "Host interface timeout (30s)"
            except Exception as e:
                return False, f"Host interface error: {str(e)}"
        else:
            # The DUT method owns one typed reachability hint and the
            # authoritative Host SSH transport check, avoiding duplicate probes.
            try:
                # Use the DUT's host method with timeout
                success, response = await asyncio.wait_for(
                    dut.test_host_connection(), timeout=30.0
                )
                if success:
                    return True, "Host interface accessible"
                else:
                    return False, f"Host interface failed: {response}"
            except asyncio.TimeoutError:
                # Check if any Host collectors are applicable for this DUT's baseboard
                should_skip, skip_message = self._check_service_collector_applicability(
                    dut, "host", collectors_by_group
                )
                if should_skip:
                    return False, skip_message

                return False, "Host interface timeout (30s)"
            except Exception as e:
                return False, f"Host interface error: {str(e)}"

    def _validate_persistent_post_request(
        self,
        *,
        dut: Any,
        dut_id: str,
        method: str,
        url: str,
        body: Any,
        retry_count: int,
        reservation: PersistentPostReservation | None,
    ) -> str:
        """
        Validate private authority and return the only normalized URI.

        DUT normalization historically returned a full URL in a few
        integrations. Discard its authority and route only the validated request
        target through the selected BMC/HMC connection.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            method: Text supplied as method in the format accepted by this
                function.
            url: Validated remote resource identifier used for URL.
            body: Body consumed while the function attempts to validate private
                authority and return the only normalized URI.
            retry_count: Numeric retry count used by the operation's bounded
                accounting.
            reservation: Optional reservation; ``None`` selects the function's
                default behavior.

        Returns:
            The canonical persistent post request text.

        Raises:
            ValueError: If redfish request URI failed URI policy; or redfish
                request URI failed URI policy: ``error``.
            PersistentPostGuardError: If persistent_target_dut_topology_invalid.
        """

        mode = validate_persistent_post_environment()
        normalized_url = dut.normalize_redfish_uri(url)
        try:
            parsed_url = urlsplit(normalized_url)
        except (TypeError, ValueError) as error:
            raise ValueError("Redfish request URI failed URI policy") from error
        if parsed_url.scheme or parsed_url.netloc:
            if (
                parsed_url.scheme.casefold() not in {"http", "https"}
                or not parsed_url.hostname
                or parsed_url.username is not None
                or parsed_url.password is not None
                or parsed_url.fragment
            ):
                raise ValueError("Redfish request URI failed URI policy")
            # DUT normalization historically returned a full URL in a few
            # integrations. Discard its authority and route only the validated
            # request target through the selected BMC/HMC connection.
            normalized_url = parsed_url.path + (
                f"?{parsed_url.query}" if parsed_url.query else ""
            )
        try:
            normalized_url = validate_redfish_request_uri(
                normalized_url, context="Redfish request URI"
            )
        except (RedfishTopologyProfileError, TypeError, ValueError) as error:
            raise ValueError(
                f"Redfish request URI failed URI policy: {error}"
            ) from None
        if mode is None:
            validate_persistent_post_network_request(
                mode=None,
                reservation=reservation,
                method=method,
                dut_slot=0,
                dut_count=1,
                normalized_uri=normalized_url,
                body=body,
                retry_count=retry_count,
            )
            return normalized_url

        dut_ids = self.get_all_dut_ids()
        raw_dut_count = os.environ.get(TARGET_DUT_COUNT_ENV, "")
        try:
            dut_count = int(raw_dut_count)
        except (TypeError, ValueError):
            raise PersistentPostGuardError(
                "persistent_target_dut_topology_invalid"
            ) from None
        if (
            not isinstance(dut_ids, list)
            or len(dut_ids) != dut_count
            or any(not isinstance(value, str) or not value for value in dut_ids)
            or len(set(dut_ids)) != len(dut_ids)
            or dut_id not in dut_ids
        ):
            raise PersistentPostGuardError("persistent_target_dut_topology_invalid")
        validate_persistent_post_network_request(
            mode=mode,
            reservation=reservation,
            method=method,
            dut_slot=tuple(sorted(dut_ids)).index(dut_id),
            dut_count=dut_count,
            normalized_uri=normalized_url,
            body=body,
            retry_count=retry_count,
        )
        return normalized_url

    async def execute_redfish_request(
        self,
        dut_id: str,
        method: str,
        url: str,
        body: Any = None,
        timeout: int = 300,
        get_raw_content: bool = False,
        bypass_cache: bool = False,
        retry_count: int = 3,  # Default retry count, can be overridden by collector definition
        expected_http_statuses: Any = None,
        multipart_parts: Optional[List[Dict[str, Any]]] = None,
        persistent_post_reservation: PersistentPostReservation | None = None,
        raw_content_max_bytes: Optional[int] = None,
    ) -> Tuple[bool, RedfishResponsePayload, dict, dict]:
        """
        Execute Redfish request.

        The implementation uses ``dut_id``, ``method``, ``url``, ``body``, and
        ``timeout`` to execute Redfish request. Terminal status is emitted only
        after redfish request and its owned cleanup have completed. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            method: Text supplied as method in the format accepted by this
                function.
            url: Validated remote resource identifier used for URL.
            body: Optional body; ``None`` selects the function's default
                behavior.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            get_raw_content: Whether get raw content is enabled or required for
                this operation.
            bypass_cache: Whether bypass cache is enabled or required for this
                operation.
            retry_count: Numeric retry count used by the operation's bounded
                accounting.
            expected_http_statuses: Optional expected HTTP statuses; ``None``
                selects the function's default behavior.
            multipart_parts: Optional multipart parts; ``None`` selects the
                function's default behavior.
            persistent_post_reservation: Optional persistent post reservation;
                ``None`` selects the function's default behavior.
            raw_content_max_bytes: Upper bound enforced for raw content max
                bytes; the consuming boundary rejects or truncates values that
                exceed it.

        Returns:
            A tuple containing ``success flag``, ``message``, ``metadata
            mapping``, and ``metadata mapping`` in that order.
        """
        if get_raw_content and hasattr(self, "duts"):
            dut = self.get_dut(dut_id)
            operator_attachment_limit = _resolved_redfish_limit(
                dut,
                "attachment_max_bytes",
                DEFAULT_REDFISH_ATTACHMENT_MAX_BYTES,
            )
            try:
                raw_content_max_bytes = clamp_redfish_attachment_limit(
                    raw_content_max_bytes,
                    operator_limit=operator_attachment_limit,
                    field_name="raw_content_max_bytes",
                )
            except ValueError as error:
                message = str(error)
                return (
                    False,
                    message,
                    {"error": "invalid_raw_content_limit", "message": message},
                    {},
                )
        request = self._make_redfish_http_engine().execute_request(
            dut_id=dut_id,
            method=method,
            url=url,
            body=body,
            timeout=timeout,
            get_raw_content=get_raw_content,
            bypass_cache=bypass_cache,
            retry_count=retry_count,
            expected_http_statuses=expected_http_statuses,
            multipart_parts=multipart_parts,
            persistent_post_reservation=persistent_post_reservation,
            raw_content_max_bytes=raw_content_max_bytes,
        )
        try:
            request_timeout = float(timeout)
        except (TypeError, ValueError):
            # Preserve the transport boundary's existing validation for legacy
            # callers that supply a non-numeric timeout.
            return await request
        if not math.isfinite(request_timeout) or request_timeout <= 0:
            return await request

        # The aiohttp request timeout is necessary but not sufficient: pooled
        # connection setup and response-body consumers live outside individual
        # socket reads.  Own one total deadline around the entire request so a
        # controller that sends headers and then stalls cannot pin a collector
        # indefinitely.  wait_for observes cancellation and does not leave an
        # untracked request task behind.
        try:
            return await asyncio.wait_for(request, timeout=request_timeout)
        except asyncio.TimeoutError:
            timeout_metadata: Dict[str, Any] = {
                "error": "request_timeout",
                "timeout_seconds": request_timeout,
            }
            if not getattr(body, "replay_safe", True):
                timeout_metadata.update(
                    {
                        "outcome_indeterminate": True,
                        "replay_suppressed": True,
                    }
                )
            return (
                False,
                f"Redfish request timed out after {request_timeout:g} seconds",
                timeout_metadata,
                {},
            )

    @staticmethod
    def _build_redfish_multipart_form(
        parts: List[Dict[str, Any]],
    ) -> Tuple[aiohttp.FormData, List[Any]]:
        """
        Build an ordered Redfish multipart form and return open handles.

        The implementation uses ``parts`` to build an ordered Redfish multipart
        form and return open handles. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. If the function
        cannot build an ordered Redfish multipart form and return open handles,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            parts: Mapping supplying fields for ordered Redfish multipart form
                and return open handles.

        Returns:
            A tuple containing ``form`` and ``opened files`` in that order.

        Raises:
            ValueError: If each multipart part lacks a name.
        """
        form = aiohttp.FormData()
        opened_files: List[Any] = []
        try:
            for part in parts:
                name = part.get("name")
                if not name:
                    raise ValueError("Each multipart part requires a name")
                content_type = part.get("content_type")
                filename = part.get("filename")
                if part.get("file_path"):
                    handle = open(part["file_path"], "rb")
                    opened_files.append(handle)
                    form.add_field(
                        name,
                        handle,
                        filename=filename or Path(part["file_path"]).name,
                        content_type=content_type or "application/octet-stream",
                    )
                    continue
                value = part.get("value", "")
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, separators=(",", ":"))
                form.add_field(
                    name,
                    str(value),
                    filename=filename,
                    content_type=content_type,
                )
            return form, opened_files
        except Exception:
            for handle in opened_files:
                handle.close()
            raise

    async def _execute_redfish_http_attempt(
        self,
        dut: "DUT",
        method: str,
        full_url: str,
        normalized_url: str,
        body: Any,
        request_auth: Optional[str],
        timeout: Union[int, float],
        get_raw_content: bool,
        attempt: int,
        max_retries: int,
        current_delay: float,
        retryable_status_codes: set,
        limited_retry_status_codes: set,
        max_retries_for_limited: int,
        allow_session_conflict_retry: bool,
        expected_http_statuses: Any = None,
        multipart_parts: Optional[List[Dict[str, Any]]] = None,
        raw_content_max_bytes: Optional[int] = None,
    ) -> Tuple[bool, RedfishResponsePayload, dict, dict]:
        """
        Delegate one attempt while retaining the manager monkeypatch seam.

        After applying local validation, the function forwards ``dut``,
        ``method``, ``full_url``, ``normalized_url``, and ``body`` to
        ``execute_http_attempt`` and preserves its return and exception
        contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            method: Text supplied as method in the format accepted by this
                function.
            full_url: Validated remote resource identifier used for full URL.
            normalized_url: Validated remote resource identifier used for
                normalized URL.
            body: Body consumed while the function attempts to delegate one
                attempt while retaining the manager monkeypatch seam.
            request_auth: Request auth consumed while the function attempts to
                delegate one attempt while retaining the manager monkeypatch
                seam.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            get_raw_content: Whether get raw content is enabled or required for
                this operation.
            attempt: Numeric attempt used while the operation performs bounded
                accounting.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.
            current_delay: Numeric current delay used while the operation
                performs bounded accounting.
            retryable_status_codes: Entries supplied as
                ``retryable_status_codes`` without transferring container
                ownership.
            limited_retry_status_codes: Entries supplied as
                ``limited_retry_status_codes`` without transferring container
                ownership.
            max_retries_for_limited: Upper bound enforced for max retries for
                limited; the consuming boundary rejects or truncates values that
                exceed it.
            allow_session_conflict_retry: Whether allow session conflict retry
                is enabled or required for this operation.
            expected_http_statuses: Optional expected HTTP statuses; ``None``
                selects the function's default behavior.
            multipart_parts: Optional multipart parts; ``None`` selects the
                function's default behavior.
            raw_content_max_bytes: Upper bound enforced for raw content max
                bytes; the consuming boundary rejects or truncates values that
                exceed it.

        Returns:
            A tuple containing the fields that represent execute Redfish HTTP
            attempt.
        """

        return await self._make_redfish_http_engine().execute_http_attempt(
            dut=dut,
            method=method,
            full_url=full_url,
            normalized_url=normalized_url,
            body=body,
            request_auth=request_auth,
            timeout=timeout,
            get_raw_content=get_raw_content,
            attempt=attempt,
            max_retries=max_retries,
            current_delay=current_delay,
            retryable_status_codes=retryable_status_codes,
            limited_retry_status_codes=limited_retry_status_codes,
            max_retries_for_limited=max_retries_for_limited,
            allow_session_conflict_retry=allow_session_conflict_retry,
            expected_http_statuses=expected_http_statuses,
            multipart_parts=multipart_parts,
            raw_content_max_bytes=raw_content_max_bytes,
        )

    async def _recover_and_replay_forwarded_hmc_request(
        self,
        dut: "DUT",
        failed_hmc_service: Optional[HMCService],
        method: str,
        normalized_url: str,
        body: Any,
        get_raw_content: bool,
        request_deadline: float,
        original_failure: Tuple[bool, RedfishResponsePayload, dict, dict],
        multipart_parts: Optional[List[Dict[str, Any]]] = None,
        raw_content_max_bytes: Optional[int] = None,
    ) -> Tuple[bool, RedfishResponsePayload, dict, dict]:
        """
        Rebuild a failed forwarded-HMC tunnel and replay exactly once.

        This path is called only after the normal connection retries are
        exhausted for an endpoint that was already identified as HMC-forwarded.
        Both rebuilding and replaying share the original caller timeout budget.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            failed_hmc_service: Failed HMC service consumed while the function
                attempts to rebuild a failed forwarded-HMC tunnel and replay
                exactly once.
            method: Text supplied as method in the format accepted by this
                function.
            normalized_url: Validated remote resource identifier used for
                normalized URL.
            body: Body consumed while the function attempts to rebuild a failed
                forwarded-HMC tunnel and replay exactly once.
            get_raw_content: Whether get raw content is enabled or required for
                this operation.
            request_deadline: Numeric request deadline used while the operation
                performs bounded accounting.
            original_failure: Mapping supplying fields for rebuild a failed
                forwarded-HMC tunnel and replay exactly once.
            multipart_parts: Optional multipart parts; ``None`` selects the
                function's default behavior.
            raw_content_max_bytes: Upper bound enforced for raw content max
                bytes; the consuming boundary rejects or truncates values that
                exceed it.

        Returns:
            A tuple containing ``success``, ``response``, ``updated metadata``,
            and ``headers`` in that order.
        """

        def with_recovery_metadata(message: str):
            """
            Return the with recovery metadata.

            The implementation uses ``message`` to produce the with recovery
            metadata.

            Args:
                message: Operator-facing text carried by the reported event or
                    failure.

            Returns:
                A tuple containing ``success``, ``response``, ``updated
                metadata``, and ``headers`` in that order.
            """
            success, response, metadata, headers = original_failure
            updated_metadata = _copy_redfish_metadata(
                metadata,
                {
                    "hmc_tunnel_recovery_attempted": True,
                    "hmc_tunnel_recovery_error": message,
                },
            )
            return success, response, updated_metadata, headers

        loop = asyncio.get_running_loop()
        remaining = request_deadline - loop.time()
        if remaining <= 0:
            return with_recovery_metadata(
                "Original request timeout budget was exhausted before recovery"
            )

        try:
            recovered, recovery_message = await asyncio.wait_for(
                self._recover_forwarded_hmc_redfish(
                    dut=dut,
                    failed_hmc_service=failed_hmc_service,
                ),
                timeout=remaining,
            )
        except asyncio.TimeoutError:
            return with_recovery_metadata(
                "HMC tunnel recovery exhausted the original request timeout budget"
            )
        except Exception as exc:
            return with_recovery_metadata(f"HMC tunnel recovery failed: {exc}")

        if not recovered:
            return with_recovery_metadata(recovery_message)

        remaining = request_deadline - loop.time()
        if remaining <= 0:
            return with_recovery_metadata(
                "HMC tunnel recovered, but no request timeout budget remained for replay"
            )

        try:
            result = await asyncio.wait_for(
                self._execute_forwarded_hmc_replay_once(
                    dut=dut,
                    method=method,
                    normalized_url=normalized_url,
                    body=body,
                    multipart_parts=multipart_parts,
                    get_raw_content=get_raw_content,
                    raw_content_max_bytes=raw_content_max_bytes,
                    timeout=remaining,
                ),
                timeout=remaining,
            )
        except asyncio.TimeoutError:
            return with_recovery_metadata(
                "Recovered HMC tunnel replay exhausted the original request timeout budget"
            )
        except Exception as exc:
            return with_recovery_metadata(f"Recovered HMC tunnel replay failed: {exc}")

        success, response, metadata, headers = result
        updated_metadata = _copy_redfish_metadata(
            metadata,
            {
                "hmc_tunnel_recovered": True,
                "hmc_tunnel_replay_attempted": True,
            },
        )
        return success, response, updated_metadata, headers

    async def _recover_forwarded_hmc_redfish(
        self,
        dut: "DUT",
        failed_hmc_service: Optional[HMCService],
    ) -> Tuple[bool, str]:
        """
        Serialize invalidation and rebuilding of one DUT's HMC tunnel.

        close_redfish_session logs and suppresses cleanup errors. Force stale
        handles out of the request path even when cleanup failed.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            failed_hmc_service: Failed HMC service consumed while the function
                attempts to serialize invalidation and rebuilding of one DUT's
                HMC tunnel.

        Returns:
            A tuple containing ``success flag`` and ``outcome message`` in that
            order.
        """
        lock = self._get_session_registry().hmc_recovery_lock(dut.dut_id)

        async with lock:
            current_info = dut.get_redfish_connection_info()
            if (
                dut.hmc_service is not failed_hmc_service
                and current_info.get("is_hmc_forwarded")
                and dut.connection_state.redfish_connected
            ):
                return (
                    True,
                    "HMC tunnel was already recovered by another request",
                )

            await dut._log_runtime(
                "WARNING",
                "Forwarded HMC Redfish endpoint is unreachable; rebuilding the tunnel",
            )

            dut.connection_state.set_redfish_connected(False, dut.dut_id)
            dut.connection_state.set_hmc_connected(False, dut.dut_id)
            dut.connection_state.port_forwarding_active = False
            await dut.close_redfish_session()
            # close_redfish_session logs and suppresses cleanup errors.  Force
            # stale handles out of the request path even when cleanup failed.
            dut.redfish_session_pool = None
            dut.redfish_session = None
            dut.redfish_connector = None

            old_hmc_service = dut.hmc_service
            if old_hmc_service is not None:
                cleanup_ok = await old_hmc_service.cleanup_hmc_access(dut.dut_id)
                if not cleanup_ok:
                    await dut._log_runtime(
                        "WARNING",
                        "Failed to fully clean up the stale HMC tunnel; attempting rebuild",
                    )
            if dut.hmc_service is old_hmc_service:
                dut.hmc_service = None

            recovered, message = await dut._test_redfish_hmc_connection()
            if not recovered:
                return False, message

            connection_info = dut.get_redfish_connection_info()
            if not connection_info.get("is_hmc_forwarded"):
                dut.connection_state.set_redfish_connected(False, dut.dut_id)
                return (
                    False,
                    "HMC tunnel rebuild did not produce a forwarded endpoint",
                )

            # Recreate the pool against the new tunnel.  A temporary session is
            # still available for the one replay if pool initialization fails.
            if not await dut.initialize_redfish_session_pool():
                # initialize_redfish_session_pool retains the failed pool
                # object.  Do not let the replay or later requests reuse it.
                dut.redfish_session_pool = None
                await dut._log_runtime(
                    "WARNING",
                    "HMC tunnel recovered but Redfish session pool initialization failed; replaying with a temporary session",
                )
            return True, message

    async def _execute_forwarded_hmc_replay_once(
        self,
        dut: "DUT",
        method: str,
        normalized_url: str,
        body: Any,
        get_raw_content: bool,
        timeout: float,
        multipart_parts: Optional[List[Dict[str, Any]]] = None,
        raw_content_max_bytes: Optional[int] = None,
    ) -> Tuple[bool, RedfishResponsePayload, dict, dict]:
        """
        Issue one request through a newly rebuilt HMC tunnel, without retries.

        The implementation uses ``dut``, ``method``, ``normalized_url``,
        ``body``, and ``get_raw_content`` to issue one request through a newly
        rebuilt HMC tunnel, without retries. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            method: Text supplied as method in the format accepted by this
                function.
            normalized_url: Validated remote resource identifier used for
                normalized URL.
            body: Body consumed while the function attempts to issue one request
                through a newly rebuilt HMC tunnel, without retries.
            get_raw_content: Whether get raw content is enabled or required for
                this operation.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            multipart_parts: Optional multipart parts; ``None`` selects the
                function's default behavior.
            raw_content_max_bytes: Upper bound enforced for raw content max
                bytes; the consuming boundary rejects or truncates values that
                exceed it.

        Returns:
            A tuple containing ``success flag``, ``Redfish response payload``,
            ``metadata mapping``, and ``metadata mapping`` in that order.
        """
        connection_info = dut.get_redfish_connection_info()
        if not connection_info.get("is_hmc_forwarded"):
            return (
                False,
                "Recovered endpoint is not HMC-forwarded",
                {"error": "hmc_forwarding_unavailable"},
                {},
            )

        protocol = "https" if connection_info["use_https"] else "http"
        url_host = format_redfish_url_host(connection_info["host"])
        full_url = f"{protocol}://{url_host}:{connection_info['port']}{normalized_url}"
        username = connection_info["username"]
        password = connection_info["password"]
        request_auth = (
            encode_basic_auth_header(username, password)
            if connection_info.get("auth_enabled", True) and username and password
            else None
        )
        retryable_status_codes = {502, 503, 504, 520, 521, 522, 523, 524}
        limited_retry_status_codes = {500}

        await dut._log_runtime(
            "INFO",
            f"Replaying {method} {normalized_url} once through the recovered HMC tunnel",
        )

        try:
            return await self._execute_redfish_http_attempt(
                dut=dut,
                method=method,
                full_url=full_url,
                normalized_url=normalized_url,
                body=body,
                request_auth=request_auth,
                timeout=timeout,
                get_raw_content=get_raw_content,
                attempt=0,
                max_retries=0,
                current_delay=0.0,
                retryable_status_codes=retryable_status_codes,
                limited_retry_status_codes=limited_retry_status_codes,
                max_retries_for_limited=0,
                allow_session_conflict_retry=False,
                multipart_parts=multipart_parts,
                raw_content_max_bytes=raw_content_max_bytes,
            )
        except (asyncio.TimeoutError, aiohttp.ClientConnectionError) as exc:
            return (
                False,
                f"Redfish connection error after recovered HMC replay: {exc}",
                {
                    "error": "connection_failed",
                    "message": str(exc),
                    "attempts": 1,
                },
                {},
            )
        except Exception as exc:
            return (
                False,
                f"Redfish request error after recovered HMC replay: {exc}",
                {"error": "exception", "message": str(exc)},
                {},
            )

    def _get_ipmi_credential_root(self) -> Path:
        """
        Create one run-owned private parent for transient IPMI credentials.

        A separate randomized child is created for each ipmitool invocation.
        Keeping those children below a mode-0700 run root prevents other local
        users from learning credential-file names or collection timing, while
        manager cleanup can reap residue from interrupted invocations.

        Returns:
            The private IPMI credential root owned by this manager.
        """
        existing = getattr(self, "_ipmi_credential_root", None)
        if existing is not None:
            return existing

        configured_parent = local_temp_dir(getattr(self, "tool_config", {}))
        base_log_dir = Path(
            getattr(self, "base_log_dir", Path(tempfile.gettempdir()) / "nvdebug")
        )
        parent = (
            Path(configured_parent)
            if configured_parent is not None
            else base_log_dir.parent
        )
        parent.mkdir(parents=True, exist_ok=True)
        credential_root = Path(
            tempfile.mkdtemp(prefix=".nvdebug-ipmi-root-", dir=parent)
        )
        os.chmod(credential_root, 0o700)
        self._ipmi_credential_root = credential_root
        return credential_root

    def _get_redfish_spool_dir(self) -> Path:
        """
        Create one private staging directory on the output filesystem.

        The implementation uses current instance state to create one private
        staging directory on the output filesystem. It updates
        ``_redfish_spool_dir`` on the instance as part of that state transition.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle.

        Returns:
            The validated Redfish spool dir filesystem path.
        """

        existing = getattr(self, "_redfish_spool_dir", None)
        if existing is not None:
            return existing

        base_log_dir = Path(
            getattr(self, "base_log_dir", Path(tempfile.gettempdir()) / "nvdebug")
        )
        spool_parent = base_log_dir.parent
        spool_parent.mkdir(parents=True, exist_ok=True)
        spool_dir = Path(
            tempfile.mkdtemp(prefix=".nvdebug-redfish-spool-", dir=spool_parent)
        )
        os.chmod(spool_dir, 0o700)
        self._redfish_spool_dir = spool_dir
        return spool_dir

    @staticmethod
    def _redfish_spool_usable_bytes(spool_dir: Path) -> int:
        """
        Return current writable bytes after the fixed recovery reserve.

        After applying local validation, the function forwards ``spool_dir`` to
        ``max`` and preserves its return and exception contract.

        Args:
            spool_dir: filesystem location used as the spool dir for this
                operation.

        Returns:
            The numeric Redfish spool usable bytes value.

        Raises:
            RedfishSpoolSpaceError: If unable to determine free space for
                Redfish response staging.
        """

        try:
            free_bytes = shutil.disk_usage(spool_dir).free
        except OSError as error:
            raise RedfishSpoolSpaceError(
                "Unable to determine free space for Redfish response staging"
            ) from error
        return max(0, free_bytes - REDFISH_SPOOL_FREE_SPACE_RESERVE_BYTES)

    @classmethod
    def _require_redfish_spool_capacity(
        cls,
        spool_dir: Path,
        incoming_bytes: int,
    ) -> None:
        """
        Keep a fixed recovery reserve while staging raw response bytes.

        The implementation uses ``spool_dir`` and ``incoming_bytes`` to keep a
        fixed recovery reserve while staging raw response bytes. If the function
        cannot keep a fixed recovery reserve while staging raw response bytes,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            spool_dir: filesystem location used as the spool dir for this
                operation.
            incoming_bytes: Numeric incoming bytes used while the operation
                performs bounded accounting.

        Raises:
            RedfishSpoolSpaceError: If insufficient private spool space for
                complete Redfish response: need at least ``incoming_bytes``
                bytes, ``usable_bytes`` bytes usable after the
                ``REDFISH_SPOOL_FREE_SPACE_RESERVE_BYTES``-byte reserve.
        """

        usable_bytes = cls._redfish_spool_usable_bytes(spool_dir)
        if incoming_bytes > usable_bytes:
            raise RedfishSpoolSpaceError(
                "Insufficient private spool space for complete Redfish response: "
                f"need at least {incoming_bytes} bytes, {usable_bytes} bytes usable "
                f"after the {REDFISH_SPOOL_FREE_SPACE_RESERVE_BYTES}-byte reserve"
            )

    async def _stream_redfish_body_to_spool(
        self,
        response: aiohttp.ClientResponse,
        max_bytes: Optional[int] = None,
    ) -> StreamedRedfishBody:
        """
        Stream a complete raw response to private storage without truncation.

        After applying local validation, the function forwards ``response`` and
        ``max_bytes`` to ``StreamedRedfishBody`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle. Remote I/O uses the configured transport policy and returns
        only after its response or failure has been observed.

        Args:
            response: Transport response governed by the configured
                authentication and trust policy.
            max_bytes: Upper bound enforced for max bytes; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            A ``StreamedRedfishBody`` representing stream Redfish body to spool.

        Raises:
            ValueError: If the raw content max_bytes are not a positive integer.
            RedfishResponseTooLarge: If redfish raw attachment exceeds
                ``max_bytes``-byte limit.
            aiohttp.ClientPayloadError: If redfish attachment length mismatch:
                declared ``declared_length`` bytes, received ``size_bytes``.
        """

        if max_bytes is not None:
            if (
                not isinstance(max_bytes, int)
                or isinstance(max_bytes, bool)
                or max_bytes <= 0
            ):
                raise ValueError("raw content max_bytes must be a positive integer")

        spool_dir = self._get_redfish_spool_dir()
        spool_decoded_budget = self._redfish_spool_usable_bytes(spool_dir)
        if max_bytes is not None:
            spool_decoded_budget = min(spool_decoded_budget, max_bytes)
        content_encoding = _redfish_content_encoding(response)
        headers = getattr(response, "headers", None)
        declared_length: Optional[int] = None
        if content_encoding is None and isinstance(headers, Mapping):
            raw_length = headers.get("Content-Length")
            if raw_length is None:
                raw_length = headers.get("content-length")
            try:
                parsed_length = int(raw_length) if raw_length is not None else None
            except (TypeError, ValueError):
                parsed_length = None
            if parsed_length is not None and parsed_length >= 0:
                declared_length = parsed_length
                if max_bytes is not None and declared_length > max_bytes:
                    raise RedfishResponseTooLarge(
                        f"Redfish raw attachment exceeds {max_bytes}-byte limit"
                    )
                self._require_redfish_spool_capacity(spool_dir, declared_length)

        descriptor, temporary_name = tempfile.mkstemp(
            prefix="body-",
            suffix=".part",
            dir=spool_dir,
        )
        temporary_path = Path(temporary_name)
        digest = hashlib.sha256()
        prefix = bytearray()
        size_bytes = 0
        try:
            with os.fdopen(descriptor, "wb") as staging_file:
                descriptor = -1
                try:
                    async for chunk in _iter_redfish_decoded_chunks(
                        response,
                        decoded_chunk_bytes=REDFISH_RESPONSE_CHUNK_BYTES,
                        encoded_max_bytes=(
                            _redfish_encoded_input_limit(max(1, spool_decoded_budget))
                            if content_encoding is not None
                            else None
                        ),
                        decoded_max_bytes=max_bytes,
                    ):
                        if not chunk:
                            continue
                        self._require_redfish_spool_capacity(spool_dir, len(chunk))
                        staging_file.write(chunk)
                        digest.update(chunk)
                        size_bytes += len(chunk)
                        if len(prefix) < REDFISH_SPOOL_PREFIX_BYTES:
                            prefix.extend(
                                chunk[: REDFISH_SPOOL_PREFIX_BYTES - len(prefix)]
                            )
                except RedfishDecodedResponseTooLarge:
                    raise RedfishResponseTooLarge(
                        f"Redfish raw attachment exceeds {max_bytes}-byte limit"
                    ) from None
                staging_file.flush()
                os.fsync(staging_file.fileno())

            if declared_length is not None and size_bytes != declared_length:
                raise aiohttp.ClientPayloadError(
                    "Redfish attachment length mismatch: declared "
                    f"{declared_length} bytes, received {size_bytes}"
                )
            return StreamedRedfishBody(
                temporary_path,
                size_bytes=size_bytes,
                sha256=digest.hexdigest(),
                prefix_bytes=bytes(prefix),
                content_type=normalize_redfish_content_type(
                    getattr(response, "content_type", None)
                ),
            )
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            raise

    @staticmethod
    def _safe_redfish_transport_metadata(
        response: aiohttp.ClientResponse,
        *,
        content_length_bytes: Optional[int] = None,
        max_content_length_bytes: int = REDFISH_TRANSPORT_CONTENT_LENGTH_MAX_BYTES,
        sha256: Optional[str] = None,
        body_storage: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return a bounded allowlist of non-sensitive response metadata.

        The implementation uses ``response``, ``content_length_bytes``,
        ``max_content_length_bytes``, ``sha256``, and ``body_storage`` to
        produce a bounded allowlist of non-sensitive response metadata.

        Args:
            response: Transport response governed by the configured
                authentication and trust policy.
            content_length_bytes: Optional content length bytes; ``None``
                selects the function's default behavior.
            max_content_length_bytes: Upper bound enforced for max content
                length bytes; the consuming boundary rejects or truncates values
                that exceed it.
            sha256: Optional SHA-256; ``None`` selects the function's default
                behavior.
            body_storage: Optional body storage; ``None`` selects the function's
                default behavior.

        Returns:
            The validated ``metadata``.
        """
        metadata: Dict[str, Any] = {"cache_hit": False}

        try:
            status = getattr(response, "status", None)
        except Exception:
            status = None
        if (
            isinstance(status, int)
            and not isinstance(status, bool)
            and 100 <= status <= 599
        ):
            metadata["http_status"] = status

        try:
            raw_content_type = getattr(response, "content_type", None)
        except Exception:
            raw_content_type = None
        content_type = normalize_redfish_content_type(raw_content_type)
        if content_type is not None:
            metadata["content_type"] = content_type

        if (
            isinstance(content_length_bytes, int)
            and not isinstance(content_length_bytes, bool)
            and 0 <= content_length_bytes <= max_content_length_bytes
        ):
            metadata["content_length_bytes"] = content_length_bytes

        if isinstance(sha256, str) and re.fullmatch(r"[0-9a-f]{64}", sha256):
            metadata["sha256"] = sha256
        if body_storage == "private_spool":
            metadata["body_storage"] = body_storage

        return metadata

    async def _handle_redfish_response(
        self,
        dut: "DUT",
        response: aiohttp.ClientResponse,
        uri: str,
        method: str,
        attempt: int,
        max_retries: int,
        current_delay: float,
        retryable_status_codes: set,
        get_raw_content: bool = False,
        limited_retry_status_codes: set = None,
        max_retries_for_limited: int = 1,
        expected_http_statuses: Any = None,
        sensitive_response: bool = False,
        raw_content_max_bytes: Optional[int] = None,
    ) -> Tuple[bool, RedfishResponsePayload, dict, dict]:
        """
        Handle Redfish response with caching and retry logic.

        After applying local validation, the function forwards ``dut``,
        ``response``, ``uri``, ``method``, and ``attempt`` to
        ``handle_response`` and preserves its return and exception contract.
        Terminal status is emitted only after redfish response with caching and
        retry logic and its owned cleanup have completed. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            response: Transport response governed by the configured
                authentication and trust policy.
            uri: Validated remote resource identifier used for URI.
            method: Text supplied as method in the format accepted by this
                function.
            attempt: Numeric attempt used while the operation performs bounded
                accounting.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.
            current_delay: Numeric current delay used while the operation
                performs bounded accounting.
            retryable_status_codes: Entries supplied as
                ``retryable_status_codes`` without transferring container
                ownership.
            get_raw_content: Whether get raw content is enabled or required for
                this operation.
            limited_retry_status_codes: Optional limited retry status codes;
                ``None`` selects the function's default behavior.
            max_retries_for_limited: Upper bound enforced for max retries for
                limited; the consuming boundary rejects or truncates values that
                exceed it.
            expected_http_statuses: Optional expected HTTP statuses; ``None``
                selects the function's default behavior.
            sensitive_response: Whether sensitive response is enabled or
                required for this operation.
            raw_content_max_bytes: Upper bound enforced for raw content max
                bytes; the consuming boundary rejects or truncates values that
                exceed it.

        Returns:
            A tuple containing the fields that represent handle Redfish
            response.
        """
        return await self._make_redfish_http_engine().handle_response(
            dut=dut,
            response=response,
            uri=uri,
            method=method,
            attempt=attempt,
            max_retries=max_retries,
            current_delay=current_delay,
            retryable_status_codes=retryable_status_codes,
            get_raw_content=get_raw_content,
            limited_retry_status_codes=limited_retry_status_codes,
            max_retries_for_limited=max_retries_for_limited,
            expected_http_statuses=expected_http_statuses,
            sensitive_response=sensitive_response,
            raw_content_max_bytes=raw_content_max_bytes,
        )

    async def create_redfish_sessions(self) -> None:
        """
        Create Redfish sessions for all DUTs.

        The implementation uses current instance state to create Redfish
        sessions for all DUTs. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind.
        """
        for dut_id, dut in self.duts.items():
            if dut.connection_state.redfish_connected:
                await dut.create_redfish_session()

    async def close_redfish_sessions(self) -> None:
        """
        Close independent DUT sessions with at most eight owned cleanup workers.

        A slow endpoint must not serialize the rack's bounded logout requests.
        Snapshot the roster before yielding, keep each pool's lifecycle ordering,
        and attempt every DUT even after failure or caller interruption. Drain all
        workers before propagating controls or an endpoint-specific error summary.

        Raises:
            _RedfishCleanupError: If any DUT or cleanup worker fails; full safe
                per-DUT details are retained in runtime logs.
            BaseException: A process control after every owned worker completes.
        """
        cleanup_errors: List[BaseException] = []
        failed_duts: Dict[str, str] = {}
        roster = tuple(self.duts.items())
        pending_duts = iter(roster)

        async def cleanup_worker() -> None:
            """
            Close successive DUT owners without cancelling independent cleanup.

            Side Effects:
                Consumes the shared roster iterator only between await points,
                records failures, and emits credential-free per-DUT diagnostics.
            """
            for dut_id, dut in pending_duts:
                try:
                    await close_all_owned_redfish_sessions(dut)
                except BaseException as error:
                    cleanup_errors.append(error)
                    detail = _redfish_cleanup_error_detail(error)
                    failed_duts[dut_id] = detail
                    try:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "DUTManager",
                            f"Redfish session cleanup did not complete: {detail}",
                        )
                    except BaseException as logging_error:
                        cleanup_errors.append(logging_error)

        tasks = [
            asyncio.create_task(capture_owned_awaitable(cleanup_worker()))
            for _ in range(min(len(roster), _REDFISH_CLEANUP_CONCURRENCY))
        ]
        try:
            outcomes = await drain_owned_tasks(tasks, cancel_on_wait_error=False)
        except BaseException as error:
            # The drain observes every worker before surfacing caller controls.
            cleanup_errors.append(error)
        else:
            cleanup_errors.extend(
                outcome.error for outcome in outcomes if outcome.error is not None
            )

        if cleanup_errors:
            authoritative = _authoritative_cleanup_error(cleanup_errors)
            if isinstance(
                authoritative, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)
            ):
                raise authoritative
            details = "; ".join(
                f"{dut_id[:96]}: {failed_duts[dut_id]}"
                for dut_id in sorted(failed_duts)[:4]
            )
            if len(failed_duts) > 4:
                details += f"; {len(failed_duts) - 4} more DUTs (see runtime logs)"
            if not details:
                details = _redfish_cleanup_error_detail(authoritative)
            raise _RedfishCleanupError(
                "Redfish session cleanup failed: " + details
            ) from authoritative

    async def reset_redfish_caches(self) -> None:
        """
        Reset Redfish caches for all DUTs.

        The implementation uses current instance state to reset Redfish caches
        for all DUTs. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.
        """
        for dut_id, dut in self.duts.items():
            dut.reset_redfish_cache()

    @capture_command_diagnostics("ipmi")
    async def execute_ipmi_command(
        self,
        dut_id: str,
        command: str,
        timeout: Union[int, float] = 180,
        *,
        return_verbose_failure_output: bool = False,
        retry_verbose_on_failure: bool = True,
    ) -> Tuple[int, str, str]:
        """
        Execute IPMI command on a DUT with legacy nvdebug retry logic.

        The implementation uses ``dut_id``, ``command``, ``timeout``,
        ``return_verbose_failure_output``, and ``retry_verbose_on_failure`` to
        execute IPMI command on a DUT with legacy nvdebug retry logic. Terminal
        status is emitted only after IPMI command on a DUT with legacy nvdebug
        retry logic and its owned cleanup have completed. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            return_verbose_failure_output: Whether return verbose failure output
                is enabled or required for this operation.
            retry_verbose_on_failure: Whether retry verbose on failure is
                enabled or required for this operation.

        Notes:
            - Automatically removes 'ipmitool' prefix if present.

            - If command fails, retries with -v flag to collect verbose debug
              data.
            - Handles sanitization of output when writing to file.
            - Provides comprehensive error logging.

        Returns:
            A tuple containing the exit status, standard output, and standard
            error.
        """
        dut = self.get_dut(dut_id)

        # Ensure IPMI connection is established
        success, message = await self._ensure_connection(
            dut_id, "ipmi", "test_ipmi_connection"
        )
        if not success:
            return -1, "", message

        try:
            command_start_time = time.monotonic()

            def _remaining_timeout_budget() -> float:
                """
                Return the seconds remaining in the active timeout budget.

                The implementation uses current instance state to produce the
                seconds remaining in the active timeout budget.

                Returns:
                    The numeric remaining timeout budget value.
                """
                return float(timeout) - (time.monotonic() - command_start_time)

            # Remove 'ipmitool' prefix if present since we handle that
            original_command = command
            if command.strip().startswith("ipmitool"):
                command = command.strip()[len("ipmitool") :].strip()
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"Warning IPMI.1: Removed redundant 'ipmitool' prefix from command: {original_command}",
                )

            # Run the original command
            exit_code, stdout, stderr = await self._run_single_ipmi_command(
                dut, command, timeout
            )

            # If command succeeded, return the result
            if exit_code == 0:
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"IPMI command ran successfully: {command}",
                )
                return exit_code, stdout, stderr

            # If command failed and doesn't already have -v flag, try verbose version
            if retry_verbose_on_failure and exit_code != 0 and "-v" not in command:
                remaining_timeout = _remaining_timeout_budget()
                if remaining_timeout <= 0:
                    await self.logger.log_runtime(
                        "WARNING",
                        "DUTManager",
                        f"Warning IPMI.4: Command failed with code {exit_code}, "
                        f"but timeout budget of {timeout} seconds is exhausted; "
                        "skipping -v retry",
                    )
                    return exit_code, stdout, stderr

                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"Warning IPMI.4: Command failed with code {exit_code}, "
                    f"retrying with -v flag using remaining timeout budget "
                    f"({remaining_timeout:.1f}s of {timeout}s)",
                )

                # Run verbose command
                verbose_command = f"{command} -v"
                (
                    verbose_exit_code,
                    verbose_stdout,
                    verbose_stderr,
                ) = await self._run_single_ipmi_command(
                    dut, verbose_command, remaining_timeout
                )

                # If verbose succeeded where original failed, return verbose result
                if verbose_exit_code == 0:
                    await self.logger.log_runtime(
                        "WARNING",
                        "DUTManager",
                        "Warning IPMI.7: Verbose command succeeded where original failed",
                    )
                    return verbose_exit_code, verbose_stdout, verbose_stderr

                # If verbose also failed, log the verbose errors
                if verbose_exit_code != 0:
                    await self.logger.log_runtime(
                        "ERROR",
                        "DUTManager",
                        f"Error IPMI.8: Verbose command also failed (code: {verbose_exit_code})",
                    )

                    # Log verbose error details
                    verbose_error_msg = self._format_ipmi_command_error(
                        verbose_command,
                        verbose_exit_code,
                        verbose_stdout,
                        verbose_stderr,
                        "IPMI (verbose)",
                    )
                    await self.logger.log_runtime(
                        "ERROR",
                        "DUTManager",
                        f"Verbose Error Output (-v):\n{verbose_error_msg}",
                    )

                    original_output_empty = (
                        not (stdout or "").strip() and not (stderr or "").strip()
                    )
                    verbose_output_available = bool(
                        (verbose_stdout or "").strip() or (verbose_stderr or "").strip()
                    )
                    if (
                        return_verbose_failure_output
                        and original_output_empty
                        and verbose_output_available
                    ):
                        await self.logger.log_runtime(
                            "WARNING",
                            "DUTManager",
                            "Warning IPMI.10: Returning verbose failure output "
                            "because the original command returned no output",
                        )
                        return (
                            verbose_exit_code,
                            verbose_stdout,
                            verbose_stderr,
                        )

            # Log result of original command
            if exit_code != 0:
                error_msg = self._format_ipmi_command_error(
                    command, exit_code, stdout, stderr, "IPMI"
                )
                await self.logger.log_runtime(
                    "ERROR", "DUTManager", f"IPMI command failed:\n{error_msg}"
                )

            return exit_code, stdout, stderr

        except Exception as e:
            await self.logger.log_runtime(
                "ERROR",
                "DUTManager",
                f"Error IPMI.9: Unexpected error in execute_ipmi_command: {e}",
            )
            return -1, "", f"IPMI command error: {str(e)}"

    @capture_command_diagnostics("ipmi")
    async def _run_single_ipmi_command(
        self, dut, command: str, timeout: Union[int, float]
    ) -> Tuple[int, str, str]:
        """
        Execute a single IPMI command without retry logic.

        Check if we're in local mode without BMC IP - if so, run locally via
        sudo.

        Args:
            dut: Stable DUT used to correlate configuration, logs, and results.
            command: Text supplied as command in the format accepted by this
                function.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.

        Returns:
            A tuple containing the exit status, standard output, and standard
            error.
        """
        try:
            command_args = shlex.split(command)
            ipmitool_password: Optional[str] = None
            is_local_mode = bool(dut.config and dut.config.get("local", False))
            uses_remote_ipmitool = bool(
                not is_local_mode and dut.credentials.ssh_proxy_host
            )
            local_ipmitool_path: Optional[str] = None
            if not uses_remote_ipmitool:
                local_ipmitool_path = resolve_trusted_ipmitool_path()
                if local_ipmitool_path is None:
                    await self.logger.log_runtime(
                        "ERROR",
                        "DUTManager",
                        TRUSTED_IPMITOOL_NOT_FOUND_MESSAGE,
                    )
                    return -1, "", TRUSTED_IPMITOOL_NOT_FOUND_MESSAGE

            # Check if we're in local mode without BMC IP - if so, run locally via sudo
            if is_local_mode:
                has_bmc_ip = dut.credentials and dut.credentials.bmc_ip
                if not has_bmc_ip:
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Running IPMI command locally via sudo (local mode without BMC IP): {command}",
                    )
                    # Run local IPMI through the same absolute, fixed-PATH
                    # privilege boundary as other local privileged commands.
                    cmd, _password_stdin = build_privileged_command_argv(
                        [local_ipmitool_path, *command_args],
                        password_available=False,
                        use_shell=False,
                        already_root=(hasattr(os, "geteuid") and os.geteuid() == 0),
                    )
                else:
                    # Local mode but with BMC IP - use BMC connection
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Running IPMI command via BMC connection (local mode with BMC IP): {command}",
                    )
                    cmd = [
                        local_ipmitool_path,
                        "-I",
                        "lanplus",
                        "-H",
                        dut.credentials.bmc_ip,
                        "-U",
                        dut.credentials.bmc_username,
                        dut.credentials.ipmi_cipher,
                    ] + command_args
                    ipmitool_password = dut.credentials.bmc_password
            else:
                # Normal mode - use BMC connection (direct or via SSH proxy)
                if dut.credentials.ssh_proxy_host:
                    # Use SSH proxy - run ipmitool on the proxy machine
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Running IPMI command via SSH proxy: {dut.credentials.ssh_proxy_host} -> {dut.credentials.bmc_ip}:623",
                    )

                    # Build the ipmitool command to run on the proxy
                    ipmitool_arguments = [
                        "-I",
                        "lanplus",
                        "-H",
                        dut.credentials.bmc_ip,
                        "-U",
                        dut.credentials.bmc_username,
                        dut.credentials.ipmi_cipher,
                    ] + command_args

                    # execute_ssh_command applies timeout per retry attempt; wrap
                    # the whole proxied IPMI command so the collector budget is
                    # enforced across connection retries and backoff as well.
                    try:
                        validate_password_stdin_line(
                            dut.credentials.bmc_password,
                            credential_name="IPMI password",
                        )
                        exit_code, stdout, stderr = await asyncio.wait_for(
                            self.execute_ssh_command(
                                host=dut.credentials.ssh_proxy_host,
                                port=dut.credentials.ssh_proxy_port,
                                username=dut.credentials.ssh_proxy_username,
                                password=dut.credentials.ssh_proxy_password,
                                command=_build_remote_ipmitool_command(
                                    ipmitool_arguments
                                ),
                                input_data=(
                                    f"{dut.credentials.bmc_password}\n"
                                    if dut.credentials.bmc_password is not None
                                    else "\n"
                                ),
                                timeout=timeout,
                                ssh_key_path=dut.credentials.ssh_proxy_key_path,
                                passwordless=dut.credentials.ssh_proxy_passwordless,
                                max_retries=dut.credentials.ssh_proxy_max_retries,
                                host_key_policy=dut.credentials.ssh_host_key_policy,
                                known_hosts_file=dut.credentials.ssh_known_hosts_file,
                                raw_ssh_capacity_scope=dut.dut_id,
                            ),
                            timeout=timeout,
                        )
                    except asyncio.TimeoutError:
                        timeout_message = (
                            f"Error IPMI.2: Command timed out after {timeout} seconds"
                        )
                        await self.logger.log_runtime(
                            "ERROR",
                            "DUTManager",
                            timeout_message,
                        )
                        await self.logger.write_to_dut_runtime_log(
                            dut.dut_id,
                            "ERROR",
                            "DUTManager",
                            timeout_message,
                        )
                        return (
                            -1,
                            "",
                            f"Command timed out after {timeout} seconds (IPMI)",
                        )

                    # Return the result directly since we already executed the command
                    return exit_code, stdout, stderr
                else:
                    # Use direct BMC connection
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Running IPMI command via direct BMC connection: {dut.credentials.bmc_ip}",
                    )
                    cmd = [
                        local_ipmitool_path,
                        "-I",
                        "lanplus",
                        "-H",
                        dut.credentials.bmc_ip,
                        "-U",
                        dut.credentials.bmc_username,
                        dut.credentials.ipmi_cipher,
                    ] + command_args
                    ipmitool_password = dut.credentials.bmc_password

            # Wait for completion with timeout
            try:
                returncode, stdout, stderr = await _run_ipmitool_subprocess(
                    cmd,
                    ipmitool_password,
                    timeout=timeout,
                    credential_parent=self._get_ipmi_credential_root(),
                )
            except asyncio.TimeoutError:
                timeout_message = (
                    f"Error IPMI.2: Command timed out after {timeout} seconds"
                )
                await self.logger.log_runtime(
                    "ERROR",
                    "DUTManager",
                    timeout_message,
                )
                await self.logger.write_to_dut_runtime_log(
                    dut.dut_id,
                    "ERROR",
                    "DUTManager",
                    timeout_message,
                )
                return (
                    -1,
                    "",
                    f"Command timed out after {timeout} seconds (IPMI)",
                )

            # Decode the output using robust method
            stdout_text = self._process_command_output(stdout)
            stderr_text = self._process_command_output(stderr)

            # Always capture both stdout and stderr (matching legacy nvdebug pattern)
            return returncode, stdout_text, stderr_text

        except Exception as e:
            await self.logger.log_runtime(
                "ERROR", "DUTManager", f"Error IPMI.3: Command failed: {e}"
            )
            return -1, "", f"IPMI command error: {str(e)}"

    def _process_command_output(
        self, output: Union[str, bytes, None], encoding: str = "utf-8"
    ) -> str:
        """
        Process command output to ensure it's in string format.

        Handles binary data gracefully with fallback strategies.

        Args:
            output: Optional output; ``None`` selects the function's default
                behavior.
            encoding: Character encoding used to decode or write the selected
                text.

        Returns:
            The canonical process command output text.
        """
        if output is None:
            return ""

        if isinstance(output, bytes):
            try:
                # First try UTF-8 with replace
                return output.decode(encoding, errors="replace")
            except Exception:
                try:
                    # Try latin1 as fallback - it can handle all byte values
                    return output.decode("latin1", errors="replace")
                except Exception:
                    # Last resort - hex representation
                    return f"hex:{output.hex()}"

        # Handle case where output is already a string
        if isinstance(output, str):
            return output

        # For any other type, try string conversion with error handling
        try:
            return str(output)
        except Exception:
            return f"<unconvertible output of type {type(output).__name__}>"

    def _format_ipmi_command_error(
        self,
        command: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        command_type: str = "",
    ) -> str:
        """
        Format error messages for IPMI command execution failures consistently.

        Matches legacy nvdebug implementation.

        The implementation uses ``command``, ``exit_code``, ``stdout``,
        ``stderr``, and ``command_type`` to format error messages for IPMI
        command execution failures consistently. The source value keeps its
        ownership while the normalized representation is returned separately.

        Args:
            command: Text supplied as command in the format accepted by this
                function.
            exit_code: Numeric exit code used while the operation performs
                bounded accounting.
            stdout: Text supplied as stdout in the format accepted by this
                function.
            stderr: Text supplied as stderr in the format accepted by this
                function.
            command_type: Text supplied as command type in the format accepted
                by this function.

        Returns:
            The canonical IPMI command error text.
        """
        try:
            # Process stdout and stderr
            stdout_msg = stdout if stdout else "<empty>"
            stderr_msg = stderr if stderr else "<empty>"
            cmd_type = f"{command_type}" if command_type else ""

            # Format the error message similar to legacy nvdebug
            error_msg = f"Command failed: {command}\n"
            error_msg += f"Exit code: {exit_code}\n"
            if cmd_type:
                error_msg += f"Command type: {cmd_type}\n"

            if stdout_msg:
                error_msg += f"STDOUT:\n{stdout_msg}\n"

            if stderr_msg:
                error_msg += f"STDERR:\n{stderr_msg}\n"

            return error_msg

        except Exception as e:
            return f"Error formatting command error: {str(e)}"

    async def _log_host_ssh_pool(self, level: str, message: str) -> None:
        """
        Write pool lifecycle diagnostics through the sanitized runtime logger.

        The implementation uses ``level`` and ``message`` to write pool
        lifecycle diagnostics through the sanitized runtime logger. Success is
        reported only after the owning output boundary has completed its
        required write or publication step. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """

        await self.logger.log_runtime(level, "DUTManager", message)

    def _get_host_ssh_pool(self) -> HostSSHConnectionPool:
        """
        Create the run-owned Host SSH pool lazily for lightweight test doubles.

        The implementation uses current instance state to create the run-owned
        Host SSH pool lazily for lightweight test doubles. It updates
        ``_host_ssh_pool`` and ``host_ssh_pool_config`` on the instance as part
        of that state transition.

        Returns:
            A ``HostSSHConnectionPool`` representing host SSH pool.
        """

        pool = getattr(self, "_host_ssh_pool", None)
        if pool is not None:
            return pool

        config = getattr(self, "host_ssh_pool_config", None)
        if config is None:
            tool_config = getattr(self, "tool_config", {}) or {}
            config = SSHConnectionPoolConfig.model_validate(
                tool_config.get("ssh_connection_pool", {})
            )
            self.host_ssh_pool_config = config

        pool = HostSSHConnectionPool(
            close_connection=self._close_ssh_connection_chain,
            max_sessions_per_endpoint=config.max_sessions_per_endpoint,
            max_channels_per_session=config.max_channels_per_session,
            max_commands_per_session=config.max_commands_per_session,
            backpressure_timeout_seconds=config.backpressure_timeout_seconds,
            connect_timeout_seconds=config.connect_timeout_seconds,
            retry_backoff_cap_seconds=config.retry_backoff_cap_seconds,
            shutdown_timeout_seconds=config.shutdown_timeout_seconds,
            log=self._log_host_ssh_pool,
        )
        self._host_ssh_pool = pool
        return pool

    def get_host_ssh_pool_metrics(self) -> Dict[str, int]:
        """
        Expose only the fixed-shape, label-free run aggregate.

        The implementation uses current instance state to expose only the
        fixed-shape, label-free run aggregate.

        Returns:
            A mapping containing host SSH pool metrics.
        """

        pool = getattr(self, "_host_ssh_pool", None)
        return (
            HostSSHConnectionPool.empty_metrics_snapshot()
            if pool is None
            else pool.metrics_snapshot()
        )

    @staticmethod
    def _host_ssh_route_key(
        *,
        snapshot: _HostSSHConnectSnapshot,
        credential_generation: CredentialGenerationFingerprint,
    ) -> Tuple[Any, ...]:
        """
        Return a normalized, secret-free identity for one Host SSH route.

        The implementation uses ``snapshot`` and ``credential_generation`` to
        produce a normalized, secret-free identity for one Host SSH route.

        Args:
            snapshot: Snapshot object whose ``dut_id``, ``host``,
                ``host_key_alias``, ``host_key_policy``, and
                ``known_hosts_file`` state is read while performing normalized,
                secret-free identity for one Host SSH route.
            credential_generation: Sensitive value supplied through the approved
                input boundary and never logged.

        Returns:
            A tuple containing ``DUT identifier``, ``status text``, ``normalize
            SSH endpoint host``, ``port``, ``username``, ``SSH key path``,
            ``passwordless``, ``host SSH route key value 8``, ``proxy port``,
            ``proxy username``, ``proxy key path``, ``proxy passwordless``,
            ``host key policy``, ``known hosts file``, ``host SSH route key
            value 15``, ``proxy host key policy``, ``proxy known hosts file``,
            and ``credential generation`` in that order.
        """

        return (
            snapshot.dut_id,
            "host",
            normalize_ssh_endpoint_host(snapshot.host),
            snapshot.port,
            snapshot.username,
            snapshot.ssh_key_path,
            snapshot.passwordless,
            (
                normalize_ssh_endpoint_host(snapshot.proxy_host)
                if snapshot.proxy_host
                else None
            ),
            snapshot.proxy_port,
            snapshot.proxy_username,
            snapshot.proxy_key_path,
            snapshot.proxy_passwordless,
            snapshot.host_key_policy,
            snapshot.known_hosts_file,
            (
                normalize_ssh_endpoint_host(snapshot.host_key_alias)
                if snapshot.host_key_alias
                else None
            ),
            snapshot.proxy_host_key_policy,
            snapshot.proxy_known_hosts_file,
            credential_generation,
        )

    async def _connect_host_ssh_proxy_snapshot(
        self,
        snapshot: _HostSSHConnectSnapshot,
        connect_timeout: float,
    ) -> Optional[asyncssh.SSHClientConnection]:
        """
        Connect a pooled route's proxy without rereading mutable DUT state.

        After applying local validation, the function forwards ``snapshot`` and
        ``connect_timeout`` to ``asyncssh.connect`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            snapshot: Snapshot object whose ``proxy_host``,
                ``proxy_host_key_policy``, ``proxy_key_path``,
                ``proxy_known_hosts_file``, and ``proxy_password`` state is read
                while performing connect a pooled route's proxy without
                rereading mutable DUT state.
            connect_timeout: Maximum duration in seconds allowed for connect
                timeout.

        Returns:
            The established ``SSHClientConnection`` used for connect host SSH
            proxy snapshot, or ``None`` when the requested value is unavailable.
        """

        if snapshot.proxy_host is None or snapshot.proxy_port is None:
            return None
        connect_kwargs = self._build_ssh_connect_kwargs(
            host=snapshot.proxy_host,
            port=snapshot.proxy_port,
            username=snapshot.proxy_username,
            password=snapshot.proxy_password,
            ssh_key_path=snapshot.proxy_key_path,
            passwordless=snapshot.proxy_passwordless,
            connect_timeout=max(0.001, connect_timeout),
            keepalive_interval=None,
            host_key_policy=snapshot.proxy_host_key_policy,
            known_hosts_file=snapshot.proxy_known_hosts_file,
        )
        return await asyncssh.connect(**connect_kwargs)

    async def _execute_host_ssh_pooled(
        self,
        *,
        dut_id: str,
        host: str,
        port: int,
        username: str,
        password: Optional[str],
        command: str,
        timeout: int,
        ssh_key_path: Optional[str],
        passwordless: bool,
        max_retries: int,
        use_sudo: bool,
        use_shell: bool,
        host_key_policy: str,
        known_hosts_file: Optional[str],
        host_key_alias: Optional[str],
        input_data: Optional[str],
        sudo_password: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """
        Execute a Host command through the normalized endpoint pool.

        The implementation uses ``dut_id``, ``host``, ``port``, ``username``,
        and ``password`` to execute a Host command through the normalized
        endpoint pool. Terminal status is emitted only after host command
        through the normalized endpoint pool and its owned cleanup have
        completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            host: Text supplied as host in the format accepted by this function.
            port: Numeric port used while the operation performs bounded
                accounting.
            username: Text supplied as username in the format accepted by this
                function.
            password: Sensitive value supplied through the approved input
                boundary and never logged.
            command: Text supplied as command in the format accepted by this
                function.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            ssh_key_path: filesystem location used as the SSH key path for this
                operation.
            passwordless: Sensitive value supplied through the approved input
                boundary and never logged.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.
            sudo_password: Explicit remote sudo credential; omission preserves
                login-password fallback without forwarding key passphrases.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            use_shell: Whether use shell is enabled or required for this
                operation.
            host_key_policy: Host key policy governing host command through the
                normalized endpoint pool.
            known_hosts_file: filesystem location used as the known hosts file
                for this operation.
            host_key_alias: Text supplied as host key alias in the format
                accepted by this function.
            input_data: Text supplied as input data in the format accepted by
                this function.

        Returns:
            A tuple containing ``integer count``, ``status text``, and ``status
            or message text`` in that order.
        """

        del use_shell  # AsyncSSH process channels retain remote-shell behavior.
        try:
            normalized_command, normalized_input = _prepare_remote_privileged_command(
                command,
                use_sudo=use_sudo,
                sudo_password=sudo_password,
                password=password,
                ssh_key_path=ssh_key_path,
                passwordless=passwordless,
                input_data=input_data,
            )
        except (TypeError, ValueError) as error:
            return -1, "", str(error)

        dut = self.get_dut(dut_id)
        credentials = dut.credentials
        proxy_host_value = getattr(credentials, "ssh_proxy_host", None)
        proxy_host = str(proxy_host_value) if proxy_host_value else None
        proxy_known_hosts = getattr(credentials, "ssh_known_hosts_file", None)
        snapshot = _HostSSHConnectSnapshot(
            dut_id=str(dut_id),
            host=str(host),
            port=int(port),
            username=str(username or ""),
            password=password,
            ssh_key_path=(str(ssh_key_path) if ssh_key_path is not None else None),
            passwordless=bool(passwordless),
            host_key_policy=normalize_ssh_host_key_policy(host_key_policy),
            known_hosts_file=(
                str(known_hosts_file) if known_hosts_file is not None else None
            ),
            host_key_alias=(
                str(host_key_alias) if host_key_alias is not None else None
            ),
            proxy_host=proxy_host,
            proxy_port=(
                int(getattr(credentials, "ssh_proxy_port", 22)) if proxy_host else None
            ),
            proxy_username=(
                str(getattr(credentials, "ssh_proxy_username", "") or "")
                if proxy_host
                else None
            ),
            proxy_password=(
                getattr(credentials, "ssh_proxy_password", None) if proxy_host else None
            ),
            proxy_key_path=(
                str(getattr(credentials, "ssh_proxy_key_path", "") or "") or None
                if proxy_host
                else None
            ),
            proxy_passwordless=(
                bool(getattr(credentials, "ssh_proxy_passwordless", False))
                if proxy_host
                else False
            ),
            proxy_host_key_policy=normalize_ssh_host_key_policy(
                getattr(credentials, "ssh_host_key_policy", None) or host_key_policy
            ),
            proxy_known_hosts_file=(
                str(proxy_known_hosts)
                if proxy_host and proxy_known_hosts is not None
                else None
            ),
        )
        pool = self._get_host_ssh_pool()
        route_label = f"{dut_id}:host"
        try:
            credential_generation = pool.credential_generation_fingerprint(
                snapshot.password,
                snapshot.proxy_password,
            )
        except HostSSHPoolShutdown:
            return (
                -1,
                "",
                f"Host SSH route={route_label} phase=shutdown rejected new command",
            )
        route_key = self._host_ssh_route_key(
            snapshot=snapshot,
            credential_generation=credential_generation,
        )
        endpoint_key = (
            "host",
            normalize_ssh_endpoint_host(snapshot.host),
            snapshot.port,
        )

        async def connect(
            connect_timeout: float,
        ) -> asyncssh.SSHClientConnection:
            """
            Return the connect.

            The implementation uses ``connect_timeout`` to produce the connect.
            Owned asynchronous work is awaited before return, so completion does
            not leave an unobserved task behind. It updates
            ``_owned_proxy_connections`` on the instance as part of that state
            transition. If the function cannot produce the connect, its
            exception reaches the caller instead of being converted into a
            successful result.

            Args:
                connect_timeout: Maximum duration in seconds allowed for connect
                    timeout.

            Returns:
                The validated ``conn``.

            Raises:
                ConnectionError: If failed to establish strict SSH proxy
                    connection.
                HostSSHConnectFailure: If the function cannot produce the
                    connect safely.
            """
            proxy_client: Optional[asyncssh.SSHClientConnection] = None
            conn: Optional[asyncssh.SSHClientConnection] = None
            loop = asyncio.get_running_loop()
            started = loop.time()
            try:
                async with asyncio.timeout(connect_timeout):
                    if snapshot.proxy_host:
                        proxy_remaining = max(
                            0.001, connect_timeout - (loop.time() - started)
                        )
                        proxy_client = await self._connect_host_ssh_proxy_snapshot(
                            snapshot,
                            proxy_remaining,
                        )
                        if proxy_client is None:
                            raise ConnectionError(
                                "Failed to establish strict SSH proxy connection"
                            )

                    remaining = max(0.001, connect_timeout - (loop.time() - started))
                    connect_kwargs = self._build_ssh_connect_kwargs(
                        host=snapshot.host,
                        port=snapshot.port,
                        username=snapshot.username,
                        password=snapshot.password,
                        ssh_key_path=snapshot.ssh_key_path,
                        passwordless=snapshot.passwordless,
                        connect_timeout=remaining,
                        keepalive_interval=None,
                        proxy_client=proxy_client,
                        host_key_policy=snapshot.host_key_policy,
                        known_hosts_file=snapshot.known_hosts_file,
                        host_key_alias=snapshot.host_key_alias,
                    )
                    conn = await asyncssh.connect(**connect_kwargs)
            except BaseException as error:
                if conn is None and proxy_client is None:
                    raise

                async def cleanup_partial_connection(
                    endpoint_connection: Optional[asyncssh.SSHClientConnection] = conn,
                    proxy_connection: Optional[
                        asyncssh.SSHClientConnection
                    ] = proxy_client,
                ) -> None:
                    """
                    Clean up partial connection.

                    The implementation uses ``endpoint_connection`` and
                    ``proxy_connection`` to clean up partial connection. Owned
                    asynchronous work is awaited before return, so completion
                    does not leave an unobserved task behind.

                    Args:
                        endpoint_connection: Validated remote resource
                            identifier used for endpoint connection.
                        proxy_connection: Proxy connection consumed while the
                            function attempts to clean up partial connection.
                    """
                    await self._close_ssh_connection_chain(
                        endpoint_connection,
                        proxy_connection,
                    )

                raise HostSSHConnectFailure(
                    error,
                    cleanup=cleanup_partial_connection,
                    connection=conn,
                    ownership_ids={
                        id(resource)
                        for resource in (conn, proxy_client)
                        if resource is not None
                    },
                ) from error

            if proxy_client is not None:
                owned_proxies = getattr(self, "_owned_proxy_connections", None)
                if owned_proxies is None:
                    owned_proxies = {}
                    self._owned_proxy_connections = owned_proxies
                owned_proxies[id(conn)] = proxy_client
            return conn

        async def run(
            conn: asyncssh.SSHClientConnection,
            command_timeout: float,
        ) -> Tuple[int, str, str]:
            """
            Run the configured operation.

            The implementation uses ``conn`` and ``command_timeout`` to run the
            configured operation. Terminal status is emitted only after
            configured and its owned cleanup have completed. Owned asynchronous
            work is awaited before return, so completion does not leave an
            unobserved task behind.

            Args:
                conn: Connection consumed while the function attempts to run the
                    configured operation.
                command_timeout: Maximum duration in seconds allowed for command
                    timeout.

            Returns:
                A tuple containing ``integer count``, ``status text``, and
                ``status text`` in that order.
            """
            if not normalized_command:
                return 0, "SSH connection successful", ""

            return await _run_ssh_process_bounded(
                conn,
                normalized_command,
                timeout=command_timeout,
                input_data=normalized_input,
            )

        return await pool.execute(
            endpoint_key=endpoint_key,
            route_key=route_key,
            route_label=route_label,
            connect=connect,
            run=run,
            timeout_seconds=timeout,
            max_attempts=max_retries,
        )

    async def _execute_ssh_command_async(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str] = None,
        command: str = "",
        timeout: int = 180,
        ssh_key_path: Optional[str] = None,
        passwordless: bool = False,
        max_retries: int = 3,
        proxy_client: Optional[asyncssh.SSHClientConnection] = None,
        use_sudo: bool = False,
        use_shell: bool = True,
        host_key_policy: str = "insecure",
        known_hosts_file: Optional[str] = None,
        host_key_alias: Optional[str] = None,
        input_data: Optional[str] = None,
        raw_ssh_capacity_scope: Optional[str] = None,
        redact_command: bool = False,
        *,
        sudo_password: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """
        Execute SSH command using asyncssh (async version).

        ``timeout`` is the budget for the complete SSH operation, not for each
        connect/command/retry step independently. Treating it as a per-step
        timeout can multiply one caller's budget by the retry count, which is
        especially harmful after a host has gone away.

        Args:
            host: Text supplied as host in the format accepted by this function.
            port: Numeric port used while the operation performs bounded
                accounting.
            username: Text supplied as username in the format accepted by this
                function.
            password: Sensitive value supplied through the approved input
                boundary and never logged.
            command: Text supplied as command in the format accepted by this
                function.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            ssh_key_path: Optional filesystem location used as the SSH key path
                for this operation.
            passwordless: Sensitive value supplied through the approved input
                boundary and never logged.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.
            proxy_client: Optional proxy client; ``None`` selects the function's
                default behavior.
            sudo_password: Explicit remote sudo credential; omission preserves
                login-password fallback without forwarding key passphrases.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            use_shell: Whether use shell is enabled or required for this
                operation.
            host_key_policy: Host key policy governing SSH command using
                asyncssh (async version).
            known_hosts_file: Optional filesystem location used as the known
                hosts file for this operation.
            host_key_alias: Optional host key alias; ``None`` selects the
                function's default behavior.
            input_data: Optional input data; ``None`` selects the function's
                default behavior.
            raw_ssh_capacity_scope: Optional raw SSH capacity scope; ``None``
                selects the function's default behavior.
            redact_command: Whether redact command is enabled or required for
                this operation.

        Returns:
            A tuple containing ``integer count``, ``status text``, and ``status
            or message text`` in that order.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to execute SSH command using asyncssh (async version).
        """
        try:
            normalized_command, normalized_input = _prepare_remote_privileged_command(
                command,
                use_sudo=use_sudo,
                sudo_password=sudo_password,
                password=password,
                ssh_key_path=ssh_key_path,
                passwordless=passwordless,
                input_data=input_data,
            )
        except (TypeError, ValueError) as error:
            return -1, "", str(error)

        last_error = ""
        # ``timeout`` is the budget for the complete SSH operation, not for
        # each connect/command/retry step independently.  Treating it as a
        # per-step timeout can multiply one caller's budget by the retry
        # count, which is especially harmful after a host has gone away.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(float(timeout), 0.0)

        def remaining_timeout() -> float:
            """
            Return the remaining timeout.

            After applying local validation, the function forwards current
            instance state to ``max`` and preserves its return and exception
            contract.

            Returns:
                The numeric remaining timeout value.
            """
            return max(0.0, deadline - loop.time())

        for attempt in range(max_retries):
            phase = "setup"
            try:
                remaining = remaining_timeout()
                if remaining <= 0:
                    return (
                        -1,
                        "",
                        f"SSH connection/retry budget timed out after {timeout} seconds",
                    )
                connect_kwargs = self._build_ssh_connect_kwargs(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    ssh_key_path=ssh_key_path,
                    passwordless=passwordless,
                    connect_timeout=remaining,
                    keepalive_interval=None,
                    proxy_client=proxy_client,
                    host_key_policy=host_key_policy,
                    known_hosts_file=known_hosts_file,
                    host_key_alias=host_key_alias,
                )

                # Attempt connection with explicit cleanup
                conn = None
                try:
                    capacity_scope = raw_ssh_capacity_scope or (
                        "route:" + normalize_ssh_endpoint_host(host)
                    )
                    phase = "connect"
                    conn = await self._connect_raw_ssh_bounded(
                        capacity_scope=capacity_scope,
                        role="endpoint",
                        connect_kwargs=connect_kwargs,
                        capacity_wait_timeout=remaining,
                    )

                    if redact_command:
                        phase = "logging_isolation"
                        _bind_managed_command_logger(conn)

                    # If no command specified, this is just a connection test
                    if not normalized_command:
                        return 0, "SSH connection successful", ""

                    # Execute command with timeout
                    try:
                        phase = "command"
                        command_timeout = remaining_timeout()
                        if command_timeout <= 0:
                            raise asyncio.TimeoutError
                        return await _run_ssh_process_bounded(
                            conn,
                            normalized_command,
                            timeout=command_timeout,
                            input_data=normalized_input,
                        )

                    except asyncio.TimeoutError:
                        return (
                            -1,
                            "",
                            f"SSH command timed out after {timeout} seconds",
                        )

                except BaseException as operation_error:
                    failed_conn = conn
                    conn = None
                    await self._close_ssh_connection_chain_after_failure(
                        operation_error,
                        failed_conn,
                    )
                    raise

                finally:
                    # Cleanup owns a separate finite budget. Once the command
                    # deadline expires, reusing a zero-second operation budget
                    # here would strand the connection transport.
                    if conn:
                        phase = "cleanup"
                        await self._close_ssh_connection_chain(
                            conn,
                            close_timeout=SSH_CONNECTION_CLOSE_TIMEOUT_SECONDS,
                        )

            except Exception as e:
                if redact_command:
                    last_error = (
                        f"Managed SSH attempt {attempt + 1}/{max_retries} failed "
                        f"(phase={phase}): {_managed_ssh_error_type(e)}"
                    )
                    await self.logger.log_runtime(
                        "WARNING",
                        "DUTManager",
                        last_error,
                    )
                    if attempt < max_retries - 1:
                        wait_time = 2**attempt
                        remaining = remaining_timeout()
                        if remaining <= wait_time:
                            return (
                                -1,
                                "",
                                "Managed SSH command retry budget timed out; "
                                + last_error,
                            )
                        await asyncio.sleep(wait_time)
                        continue
                    return -1, "", last_error

                if isinstance(e, ValueError):
                    return -1, "", str(e)

                error_detail = (
                    "SSH connection setup timed out"
                    if isinstance(e, TimeoutError)
                    else _exception_detail(e)
                )
                last_error = (
                    f"SSH attempt {attempt + 1}/{max_retries} failed: {error_detail}"
                )
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    (
                        f"AsyncSSH connection attempt {attempt + 1}/{max_retries} "
                        f"to {host}:{port} failed: {error_detail}"
                    ),
                )
                if attempt < max_retries - 1:
                    # Wait before retry (exponential backoff)
                    wait_time = 2**attempt
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Waiting {wait_time}s before retry {attempt + 2}/{max_retries}",
                    )
                    remaining = remaining_timeout()
                    if remaining <= wait_time:
                        return (
                            -1,
                            "",
                            f"SSH connection/retry budget timed out after {timeout} seconds",
                        )
                    await asyncio.sleep(wait_time)
                    continue
                else:
                    return -1, "", last_error

        return -1, "", f"SSH failed after {max_retries} attempts: {last_error}"

    async def execute_ssh_command(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str] = None,
        command: str = "",
        timeout: int = 180,
        ssh_key_path: Optional[str] = None,
        passwordless: bool = False,
        max_retries: int = 3,
        proxy_client=None,
        use_sudo: bool = False,
        use_shell: bool = True,
        host_key_policy: str = "insecure",
        known_hosts_file: Optional[str] = None,
        host_key_alias: Optional[str] = None,
        input_data: Optional[str] = None,
        host_pool_dut_id: Optional[str] = None,
        raw_ssh_capacity_scope: Optional[str] = None,
        redact_command: bool = False,
        *,
        sudo_password: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """
        Execute SSH command using asyncssh.

        The implementation uses ``host``, ``port``, ``username``, ``password``,
        and ``command`` to execute SSH command using asyncssh. Terminal status
        is emitted only after SSH command using asyncssh and its owned cleanup
        have completed. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            host: Text supplied as host in the format accepted by this function.
            port: Numeric port used while the operation performs bounded
                accounting.
            username: Text supplied as username in the format accepted by this
                function.
            password: Sensitive value supplied through the approved input
                boundary and never logged.
            command: Text supplied as command in the format accepted by this
                function.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            ssh_key_path: Optional filesystem location used as the SSH key path
                for this operation.
            passwordless: Sensitive value supplied through the approved input
                boundary and never logged.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.
            proxy_client: Optional proxy client; ``None`` selects the function's
                default behavior.
            sudo_password: Explicit remote sudo credential; omission preserves
                login-password fallback without forwarding key passphrases.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            use_shell: Whether use shell is enabled or required for this
                operation.
            host_key_policy: Host key policy governing SSH command using
                asyncssh.
            known_hosts_file: Optional filesystem location used as the known
                hosts file for this operation.
            host_key_alias: Optional host key alias; ``None`` selects the
                function's default behavior.
            input_data: Optional input data; ``None`` selects the function's
                default behavior.
            host_pool_dut_id: Stable host pool DUT identifier used to correlate
                configuration, logs, and results.
            raw_ssh_capacity_scope: Optional raw SSH capacity scope; ``None``
                selects the function's default behavior.
            redact_command: Whether redact command is enabled or required for
                this operation.

        Returns:
            A tuple containing ``integer count``, ``status text``, and ``status
            text`` in that order.
        """
        if redact_command:
            if proxy_client is not None:
                return (
                    -1,
                    "",
                    "Managed SSH commands cannot use an externally owned proxy",
                )

            owned_proxy_client: Optional[asyncssh.SSHClientConnection] = None
            try:
                if host_pool_dut_id is not None:
                    dut = self.get_dut(host_pool_dut_id)
                    if dut.credentials.ssh_proxy_host:
                        owned_proxy_client = await self.create_proxy_connection(
                            host_pool_dut_id
                        )
                        if owned_proxy_client is None:
                            return (
                                -1,
                                "",
                                "Failed to establish managed SSH proxy connection",
                            )
                        _bind_managed_command_logger(owned_proxy_client)

                return await self._execute_ssh_command_async(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    command=command,
                    timeout=timeout,
                    ssh_key_path=ssh_key_path,
                    passwordless=passwordless,
                    max_retries=max_retries,
                    proxy_client=owned_proxy_client,
                    use_sudo=use_sudo,
                    sudo_password=sudo_password,
                    use_shell=use_shell,
                    host_key_policy=host_key_policy,
                    known_hosts_file=known_hosts_file,
                    host_key_alias=host_key_alias,
                    input_data=input_data,
                    raw_ssh_capacity_scope=raw_ssh_capacity_scope,
                    redact_command=True,
                )
            except Exception as error:
                return (
                    -1,
                    "",
                    "Managed SSH command setup failed (phase=setup): "
                    + _managed_ssh_error_type(error),
                )
            finally:
                if owned_proxy_client is not None:
                    await _close_ssh_connection_bounded(owned_proxy_client)

        if host_pool_dut_id is not None:
            if proxy_client is not None:
                return (
                    -1,
                    "",
                    "Pooled Host SSH owns its proxy connection; "
                    "an external proxy_client is not supported",
                )
            return await self._execute_host_ssh_pooled(
                dut_id=host_pool_dut_id,
                host=host,
                port=port,
                username=username,
                password=password,
                command=command,
                timeout=timeout,
                ssh_key_path=ssh_key_path,
                passwordless=passwordless,
                max_retries=max_retries,
                use_sudo=use_sudo,
                sudo_password=sudo_password,
                use_shell=use_shell,
                host_key_policy=host_key_policy,
                known_hosts_file=known_hosts_file,
                host_key_alias=host_key_alias,
                input_data=input_data,
            )
        return await self._execute_ssh_command_async(
            host=host,
            port=port,
            username=username,
            password=password,
            command=command,
            timeout=timeout,
            ssh_key_path=ssh_key_path,
            passwordless=passwordless,
            max_retries=max_retries,
            proxy_client=proxy_client,
            use_sudo=use_sudo,
            sudo_password=sudo_password,
            use_shell=use_shell,
            host_key_policy=host_key_policy,
            known_hosts_file=known_hosts_file,
            host_key_alias=host_key_alias,
            input_data=input_data,
            raw_ssh_capacity_scope=raw_ssh_capacity_scope,
            redact_command=False,
        )

    async def create_proxy_connection(
        self, dut_id: str
    ) -> Optional[asyncssh.SSHClientConnection]:
        """
        Create SSH proxy connection using asyncssh.

        After applying local validation, the function forwards ``dut_id`` to
        ``self._create_proxy_connection_async`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The established ``SSHClientConnection`` used for proxy connection,
            or ``None`` when the requested value is unavailable.
        """
        return await self._create_proxy_connection_async(dut_id)

    async def _close_ssh_connection_chain(
        self,
        conn: Optional[asyncssh.SSHClientConnection],
        proxy_client: Optional[asyncssh.SSHClientConnection] = None,
        *,
        close_timeout: float = SSH_CONNECTION_CLOSE_TIMEOUT_SECONDS,
    ) -> None:
        """
        Close an endpoint and its exact owned jump connection.

        The implementation uses ``conn``, ``proxy_client``, and
        ``close_timeout`` to close an endpoint and its exact owned jump
        connection. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            conn: Connection consumed while the function attempts to close an
                endpoint and its exact owned jump connection.
            proxy_client: Optional proxy client; ``None`` selects the function's
                default behavior.
            close_timeout: Maximum duration in seconds allowed for close
                timeout.
        """

        await self._get_session_registry().close_connection_chain(
            self,
            conn,
            proxy_client,
            _close_ssh_connection_bounded,
        )

    async def _close_ssh_connection_chain_after_failure(
        self,
        primary_error: BaseException,
        conn: Optional[asyncssh.SSHClientConnection],
        proxy_client: Optional[asyncssh.SSHClientConnection] = None,
    ) -> None:
        """
        Retain cleanup failures without replacing control flow.

        The implementation uses ``primary_error``, ``conn``, and
        ``proxy_client`` to retain cleanup failures without replacing control
        flow. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            primary_error: Primary error consumed while the function attempts to
                retain cleanup failures without replacing control flow.
            conn: Connection consumed while the function attempts to retain
                cleanup failures without replacing control flow.
            proxy_client: Optional proxy client; ``None`` selects the function's
                default behavior.
        """

        await self._get_session_registry().close_connection_chain_after_failure(
            self, primary_error, conn, proxy_client
        )

    async def _create_proxy_connection_async(
        self, dut_id: str
    ) -> Optional[asyncssh.SSHClientConnection]:
        """
        Create async SSH connection to proxy for multi-hop access.

        The implementation uses ``dut_id`` to create async SSH connection to
        proxy for multi-hop access. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``conn``, or ``None`` when no value qualifies.
        """
        dut = self.get_dut(dut_id)

        # Check if proxy is configured
        if not dut.credentials.ssh_proxy_host:
            return None

        try:
            connect_kwargs = self._build_ssh_connect_kwargs(
                host=dut.credentials.ssh_proxy_host,
                port=dut.credentials.ssh_proxy_port,
                username=dut.credentials.ssh_proxy_username,
                password=dut.credentials.ssh_proxy_password,
                ssh_key_path=dut.credentials.ssh_proxy_key_path,
                passwordless=dut.credentials.ssh_proxy_passwordless,
                connect_timeout=30,
                keepalive_interval=None,
                host_key_policy=dut.credentials.ssh_host_key_policy,
                known_hosts_file=dut.credentials.ssh_known_hosts_file,
            )

            # Connect to proxy
            conn = await self._connect_raw_ssh_bounded(
                capacity_scope=str(dut_id),
                role="proxy",
                connect_kwargs=connect_kwargs,
            )
            return conn

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DUTManager",
                f"Failed to create async proxy connection: {e}",
            )
            return None

    @capture_command_diagnostics("bmc_ssh")
    async def execute_bmc_command(
        self,
        dut_id: str,
        command: str,
        timeout: float = 180,
        hmc: bool = False,
        *,
        execution_timeout_seconds: Optional[float] = None,
        input_data: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """
        Execute BMC SSH work and then publish its owned command transcript.

        The optional execution deadline covers connection admission, transport
        work and their cleanup inside the diagnostic decorator. Publication is
        awaited after that boundary, so a busy artifact worker cannot turn an
        already completed remote cleanup into an execution timeout. Callers that
        omit the option retain the existing transport timeout behavior.

        Args:
            dut_id: DUT whose configured BMC or HMC transport is selected.
            command: Command validated by the existing trusted shell boundary.
            timeout: Budget forwarded to the underlying SSH command transport.
            hmc: Whether to use the configured HMC route instead of the BMC.
            input_data: Optional text sent over SSH stdin, excluded from command
                diagnostics and never interpolated into the command line.
            execution_timeout_seconds: Optional finite positive deadline for the
                complete transport operation, excluding transcript publication.

        Returns:
            The original exit code, stdout and stderr after durable diagnostics.

        Raises:
            ValueError: If the optional execution deadline is not a finite,
                positive number or is a boolean.
            TimeoutError: If the selected transport execution deadline expires.
            asyncio.CancelledError: If the owner is cancelled after transport
                resources have been reconciled by the existing cleanup paths.
            CommandDiagnosticPublicationError: If the completed command's
                transcript cannot be published; the command is never replayed.
        """
        input_options = {"input_data": input_data} if input_data is not None else {}
        if execution_timeout_seconds is None:
            return await self._execute_bmc_command_transport(
                dut_id, command, timeout=timeout, hmc=hmc, **input_options
            )
        if (
            isinstance(execution_timeout_seconds, bool)
            or not isinstance(execution_timeout_seconds, (int, float))
            or not math.isfinite(execution_timeout_seconds)
            or execution_timeout_seconds <= 0
        ):
            raise ValueError("BMC execution timeout must be a finite positive number")
        deadline = asyncio.timeout(execution_timeout_seconds)
        try:
            async with deadline:
                return await self._execute_bmc_command_transport(
                    dut_id, command, timeout=timeout, hmc=hmc, **input_options
                )
        except TimeoutError:
            if deadline.expired():
                raise TimeoutError(
                    "BMC command execution exceeded "
                    f"{execution_timeout_seconds:g} seconds"
                ) from None
            raise

    async def _execute_bmc_command_transport(
        self,
        dut_id: str,
        command: str,
        timeout: float,
        hmc: bool,
        *,
        input_data: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """
        Run the existing BMC or HMC route and close every owned connection.

        The public wrapper owns optional execution deadlines and command
        diagnostics. This transport implementation preserves capability checks,
        proxy routing, host-key policy, retry budgets and bounded SSH cleanup.

        Args:
            dut_id: DUT providing the selected transport and credential binding.
            command: Trusted command validated before opening the SSH route.
            timeout: Existing timeout forwarded to connection and command work.
            hmc: Whether to select HMC credentials and capability policy.
            input_data: Optional text forwarded unchanged to bounded SSH stdin;
                this value is never included in the command transcript.

        Returns:
            The unchanged transport exit code, stdout and stderr.

        Raises:
            asyncio.CancelledError: If cancelled after owned SSH cleanup.
            Exception: If a transport operation cannot return a command result.
        """
        input_options = {"input_data": input_data} if input_data is not None else {}
        dut = self.get_dut(dut_id)
        command_to_run = build_trusted_remote_command(command)

        if hmc:
            # HMC execution
            if catalog_transport_support(dut.config, "hmc") is False:
                return -1, "", "HMC is not supported by the baseboard catalog"
            if not dut.credentials.hmc_ip:
                return -1, "", "HMC IP not configured"

            username = dut.credentials.hmc_ssh_username or dut.credentials.hmc_username
            password = dut.credentials.hmc_ssh_password or dut.credentials.hmc_password

            return await self.execute_ssh_command(
                host=dut.credentials.hmc_ip,
                port=dut.credentials.hmc_ssh_port,
                username=username,
                password=password,
                command=command_to_run,
                **input_options,
                timeout=timeout,
                ssh_key_path=dut.credentials.hmc_ssh_key_path,
                passwordless=dut.credentials.hmc_ssh_passwordless,
                max_retries=dut.credentials.hmc_ssh_max_retries,
                proxy_client=None,  # HMC doesn't use proxy
                host_key_policy=dut.credentials.ssh_host_key_policy,
                known_hosts_file=dut.credentials.ssh_known_hosts_file,
            )
        else:
            # Ensure BMC SSH connection is established
            success, message = await self._ensure_connection(
                dut_id, "ssh", "test_ssh_connection"
            )
            if not success:
                return -1, "", message

            # BMC execution
            username = dut.credentials.bmc_ssh_username or dut.credentials.bmc_username
            password = dut.credentials.bmc_ssh_password or dut.credentials.bmc_password

            if dut.credentials.ssh_proxy_host:
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"Running BMC SSH command through strict proxy {dut.credentials.ssh_proxy_host}",
                )
                proxy_client = await self.create_proxy_connection(dut_id)
                if proxy_client is None:
                    return (
                        -1,
                        "",
                        "Failed to establish strict SSH proxy connection",
                    )
                try:
                    return await self.execute_ssh_command(
                        host=dut.credentials.bmc_ip,
                        port=dut.credentials.bmc_ssh_port,
                        username=username,
                        password=password,
                        command=command_to_run,
                        **input_options,
                        timeout=timeout,
                        ssh_key_path=dut.credentials.bmc_ssh_key_path,
                        passwordless=dut.credentials.bmc_ssh_passwordless,
                        max_retries=dut.credentials.bmc_ssh_max_retries,
                        proxy_client=proxy_client,
                        host_key_policy=dut.credentials.ssh_host_key_policy,
                        known_hosts_file=dut.credentials.ssh_known_hosts_file,
                        host_key_alias=dut.credentials.bmc_ip,
                        raw_ssh_capacity_scope=dut_id,
                    )
                finally:
                    await _close_raw_or_external_ssh_connection(self, proxy_client)
            else:
                # Use direct BMC connection
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"Running BMC SSH command via direct BMC connection: {dut.credentials.bmc_ip}",
                )
                return await self.execute_ssh_command(
                    host=dut.credentials.bmc_ip,
                    port=dut.credentials.bmc_ssh_port,
                    username=username,
                    password=password,
                    command=command_to_run,
                    **input_options,
                    timeout=timeout,
                    ssh_key_path=dut.credentials.bmc_ssh_key_path,
                    passwordless=dut.credentials.bmc_ssh_passwordless,
                    max_retries=dut.credentials.bmc_ssh_max_retries,
                    host_key_policy=dut.credentials.ssh_host_key_policy,
                    known_hosts_file=dut.credentials.ssh_known_hosts_file,
                    raw_ssh_capacity_scope=dut_id,
                )

    @capture_command_diagnostics("host_ssh")
    async def execute_host_command(
        self,
        dut_id: str,
        command: str,
        timeout: int = 180,
        max_retries: Optional[int] = None,
        override_shell: Optional[bool] = None,
        input_val: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
        use_sudo: bool = False,
        use_shell: bool = True,
        redact_command: bool = False,
    ) -> Tuple[int, str, str]:
        """
        Execute host command on a DUT.

        The implementation uses ``dut_id``, ``command``, ``timeout``,
        ``max_retries``, and ``override_shell`` to execute host command on a
        DUT. Terminal status is emitted only after host command on a DUT and its
        owned cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.
            override_shell: Optional override shell; ``None`` selects the
                function's default behavior.
            input_val: Optional input val; ``None`` selects the function's
                default behavior.
            environment: Optional environment; ``None`` selects the function's
                default behavior.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            use_shell: Whether use shell is enabled or required for this
                operation.
            redact_command: Whether redact command is enabled or required for
                this operation.

        Returns:
            A tuple containing ``integer count``, ``status text``, and ``status
            or message text`` in that order.
        """
        dut = self.get_dut(dut_id)
        raw_max_retries = (
            max_retries
            if max_retries is not None
            else dut.credentials.host_ssh_max_retries
        )
        try:
            resolved_max_retries = max(0, int(raw_max_retries))
        except (TypeError, ValueError, OverflowError):
            resolved_max_retries = 0

        # Debug logging
        await self.logger.log_runtime(
            "DEBUG",
            "DUTManager",
            f"execute_host_command called with use_sudo={use_sudo}, use_shell={use_shell}",
        )
        if redact_command:
            await self.logger.log_runtime(
                "DEBUG", "DUTManager", "Managed command details redacted"
            )
        else:
            await self.logger.log_runtime(
                "DEBUG", "DUTManager", f"Original command: {command}"
            )
        await self.logger.log_runtime(
            "DEBUG",
            "DUTManager",
            f"Host connected: {dut.connection_state.host_connected}",
        )
        await self.logger.log_runtime(
            "DEBUG", "DUTManager", f"Host IP: {dut.credentials.host_ip}"
        )

        # Ensure host connection is established
        success, message = await self._ensure_connection(
            dut_id, "host", "test_host_connection"
        )
        if not success:
            return -1, "", message

        local_execution = not dut.credentials.host_ip

        # The local/SSH execution boundaries normalize ``use_sudo`` exactly
        # once. Keeping the original payload here preserves shell structure
        # and lets unsupported pre-supplied sudo options fail before execution.
        command_to_run = command

        try:
            if local_execution:
                # Local execution - use unified execute_bash_command
                await self.logger.log_runtime(
                    "DEBUG", "DUTManager", "Using local execution path"
                )

                # Honour the caller's explicit execution mode. The public
                # method keeps its catalog-compatible default, while callers
                # can obtain exec-form execution with use_shell=False.
                if override_shell is not None:
                    use_shell = bool(override_shell)
                if use_shell:
                    await self.logger.log_runtime(
                        "DEBUG",
                        "DUTManager",
                        "Local command will be executed through /bin/sh -c",
                    )

                sudo_password = None
                if use_sudo:
                    if dut.config and dut.config.get("local", False):
                        await self.logger.log_runtime(
                            "DEBUG",
                            "DUTManager",
                            "Local mode detected - using non-interactive local sudo behavior",
                        )
                        sudo_password = None
                    else:
                        # Try to get sudo password from credentials
                        sudo_password = getattr(
                            dut.credentials, "host_sudo_password", None
                        )
                        if not sudo_password:
                            # Fallback to SSH password if available
                            sudo_password = dut.credentials.host_password

                    await self.logger.log_runtime(
                        "DEBUG",
                        "DUTManager",
                        f"Sudo password available: {sudo_password is not None}",
                    )

                result = await self.execute_bash_command(
                    command=command_to_run,
                    timeout=timeout,
                    use_shell=use_shell,
                    input_val=input_val,
                    environment=environment,
                    use_sudo=use_sudo,
                    sudo_password=sudo_password,
                )

                if redact_command:
                    exit_code, stdout, stderr = result
                    await self.logger.log_runtime(
                        "DEBUG",
                        "DUTManager",
                        (
                            "Managed local command completed: "
                            f"exit_code={exit_code}, "
                            f"stdout_bytes={len(str(stdout).encode('utf-8'))}, "
                            f"stderr_bytes={len(str(stderr).encode('utf-8'))}"
                        ),
                    )
                else:
                    await self.logger.log_runtime(
                        "DEBUG",
                        "DUTManager",
                        f"Local execution result: {result}",
                    )
                return result
            else:
                # Remote execution via SSH
                has_host_auth = self._has_ssh_auth_method(
                    dut.credentials.host_password,
                    dut.credentials.host_ssh_key_path,
                    dut.credentials.host_ssh_passwordless,
                )
                if not dut.credentials.host_username or not has_host_auth:
                    return -1, "", "Host SSH credentials not configured"

                if dut.credentials.ssh_proxy_host:
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Running Host SSH command through strict proxy {dut.credentials.ssh_proxy_host}",
                    )
                else:
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Running Host SSH command via direct host connection: {dut.credentials.host_ip}",
                    )
                return await self.execute_ssh_command(
                    host=dut.credentials.host_ip,
                    port=dut.credentials.host_ssh_port,
                    username=dut.credentials.host_username,
                    password=dut.credentials.host_password,
                    sudo_password=dut.credentials.host_sudo_password,
                    command=build_trusted_remote_command(command_to_run),
                    timeout=timeout,
                    ssh_key_path=dut.credentials.host_ssh_key_path,
                    passwordless=dut.credentials.host_ssh_passwordless,
                    max_retries=resolved_max_retries,
                    use_sudo=use_sudo,
                    use_shell=use_shell,
                    host_key_policy=dut.credentials.ssh_host_key_policy,
                    known_hosts_file=dut.credentials.ssh_known_hosts_file,
                    host_key_alias=(
                        dut.credentials.host_ip
                        if dut.credentials.ssh_proxy_host
                        else None
                    ),
                    input_data=input_val,
                    host_pool_dut_id=dut_id,
                    redact_command=redact_command,
                )
        except Exception as e:
            if redact_command:
                return (
                    -1,
                    "",
                    "Managed Host command failed (phase=dispatch): "
                    + _managed_ssh_error_type(e),
                )
            return -1, "", f"Host command error: {str(e)}"

    async def execute_nvos_command(
        self,
        dut_id: str,
        command: str,
        timeout: int = 180,
        use_sudo: bool = False,
    ) -> Tuple[bool, Any]:
        """
        Execute NVOS command and return JSON output.

        If not JSON, return raw output (matching original run_nvos_command
        behavior).

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            use_sudo: Whether use sudo is enabled or required for this
                operation.

        Returns:
            A tuple containing the success flag and parsed JSON or raw command
            output.
        """
        # Add --output json to ensure JSON output (like the original run_nvos_command)
        nv_command = f"{command} --output json"

        await self.logger.log_runtime(
            "DEBUG", "DUTManager", f"Executing NVOS command: {nv_command}"
        )

        exit_code, stdout, stderr = await self.execute_host_command(
            dut_id, nv_command, timeout=timeout, use_sudo=use_sudo
        )

        if exit_code == 0:
            try:
                output = json.loads(stdout)
                await self.logger.log_runtime(
                    "DEBUG",
                    "DUTManager",
                    f"NVOS command successful: {command}",
                )
                return True, output
            except (json.JSONDecodeError, TypeError):
                # If not JSON, return raw output (matching original run_nvos_command behavior)
                await self.logger.log_runtime(
                    "WARN",
                    "DUTManager",
                    f"NVOS command output not JSON: {command}",
                )
                return True, stdout
        else:
            await self.logger.log_runtime(
                "ERROR",
                "DUTManager",
                f"NVOS command failed: {command}, exit_code: {exit_code}, stderr: {stderr}",
            )
            error_output = stderr or stdout or ""
            if exit_code == -1 and (
                "timeout" in error_output.lower() or "timed out" in error_output.lower()
            ):
                return False, error_output
            return False, None

    def is_hmc_present(self, dut_id: str) -> bool:
        """
        Check if HMC is present for a DUT.

        After applying local validation, the function forwards ``dut_id`` to
        ``bool`` and preserves its return and exception contract. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            Whether the if HMC is present for a DUT operation succeeds.
        """
        dut = self.get_dut(dut_id)
        return bool(
            catalog_transport_support(dut.config, "hmc") is not False
            and dut.credentials.hmc_ip is not None
        )

    async def download_bmc_file_bounded(
        self,
        dut_id: str,
        remote_path: str,
        local_path: Union[str, Path],
        *,
        max_bytes: int,
        read_chunk_bytes: int = SFTP_DOWNLOAD_READ_CHUNK_BYTES,
    ) -> BoundedBMCDownloadResult:
        """
        Download one BMC regular file to an exact local path with safe recovery.

        The destination is published as a complete mode-0600 regular file only
        after the remote path and opened handle retain the same identity and
        size across the bounded read. Any failure or cancellation removes the
        exact staging inode owned by this call. If a fresh SFTP channel is
        rejected before it opens, that dedicated raw transport is closed before
        one fresh, bounded binary exec-stream attempt reads the same remote
        artifact. Cached shared routes are left untouched, and other failures
        are never retried here.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            remote_path: filesystem location used as the remote path for this
                operation.
            local_path: filesystem location used as the local path for this
                operation.
            max_bytes: Upper bound enforced for max bytes; the consuming
                boundary rejects or truncates values that exceed it.
            read_chunk_bytes: Numeric read chunk bytes used while the operation
                performs bounded accounting.

        Returns:
            A receipt containing the exact byte count and the binary transport
            which atomically published the local artifact.

        Raises:
            ConnectionError: If the function cannot establish the required BMC
                or strict SSH proxy connection.
            SFTPDownloadError: If neither the SFTP boundary nor its narrowly
                admitted binary exec-stream recovery can safely publish the
                remote regular file.
        """

        _validate_sftp_download_limits(max_bytes, read_chunk_bytes)
        success, message = await self._ensure_connection(
            dut_id,
            "ssh",
            "test_ssh_connection",
        )
        if not success:
            raise ConnectionError(message)

        dut = self.get_dut(dut_id)
        username = dut.credentials.bmc_ssh_username or dut.credentials.bmc_username
        password = dut.credentials.bmc_ssh_password or dut.credentials.bmc_password
        use_exec_stream = False
        for _transfer_attempt in range(2):
            proxy_client = None
            conn = None
            try:
                if dut.credentials.ssh_proxy_host:
                    proxy_client = await self.create_proxy_connection(dut_id)
                    if proxy_client is None:
                        raise ConnectionError(
                            "Failed to establish strict SSH proxy connection"
                        )

                connect_kwargs = self._build_ssh_connect_kwargs(
                    host=dut.credentials.bmc_ip,
                    port=dut.credentials.bmc_ssh_port,
                    username=username,
                    password=password,
                    ssh_key_path=dut.credentials.bmc_ssh_key_path,
                    passwordless=dut.credentials.bmc_ssh_passwordless,
                    connect_timeout=30,
                    proxy_client=proxy_client,
                    host_key_policy=dut.credentials.ssh_host_key_policy,
                    known_hosts_file=dut.credentials.ssh_known_hosts_file,
                    host_key_alias=(dut.credentials.bmc_ip if proxy_client else None),
                )
                conn = await self._connect_raw_ssh_bounded(
                    capacity_scope=str(dut_id),
                    role="endpoint",
                    connect_kwargs=connect_kwargs,
                )
                if use_exec_stream:
                    _bind_managed_command_logger(conn)
                    return BoundedBMCDownloadResult(
                        bytes_transferred=(
                            await _download_ssh_exec_regular_file_bounded(
                                conn,
                                remote_path,
                                local_path,
                                max_bytes=max_bytes,
                                read_chunk_bytes=read_chunk_bytes,
                            )
                        ),
                        transport_method="SSH exec stream",
                    )

                async with conn.start_sftp_client() as sftp:
                    return BoundedBMCDownloadResult(
                        bytes_transferred=(
                            await _download_sftp_regular_file_bounded(
                                sftp,
                                remote_path,
                                local_path,
                                max_bytes=max_bytes,
                                read_chunk_bytes=read_chunk_bytes,
                            )
                        ),
                        transport_method="SFTP",
                    )
            except BaseException as error:
                failed_conn = conn
                failed_proxy = proxy_client
                conn = None
                proxy_client = None
                await self._close_ssh_connection_chain_after_failure(
                    error,
                    failed_conn,
                    failed_proxy,
                )
                if not isinstance(error, Exception):
                    raise
                if use_exec_stream or not _is_sftp_session_open_failure(error):
                    raise

                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "DUTManager",
                    "BMC rejected the SFTP session before transfer; closed the "
                    "rejected dedicated connection and opening a fresh "
                    "connection for the same bounded artifact over a binary "
                    "SSH exec stream",
                )
                use_exec_stream = True
            finally:
                if conn is not None or proxy_client is not None:
                    await self._close_ssh_connection_chain(conn, proxy_client)

        raise SFTPDownloadError("BMC bounded file transfer exhausted recovery")

    async def execute_bmc_command_with_hmc_detection(
        self,
        dut_id: str,
        command: str,
        timeout: int = 180,
        max_retries: int = 3,
    ) -> Tuple[int, str, str]:
        """
        Execute BMC command with automatic HMC detection.

        Wrapper around execute_bmc_command to let DUT decide if the command
        should be run on BMC or HMC.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            A tuple containing the fields that represent execute BMC command
            with HMC detection.
        """
        return await self.execute_bmc_command(
            dut_id, command, timeout, hmc=self.is_hmc_present(dut_id)
        )

    async def transfer_files(
        self,
        dut_id: str,
        sources: Union[str, List[str]],
        destination_directory: str,
        copy_to_destination: bool = True,
        max_retries: int = 3,
    ) -> Tuple[bool, str]:
        """
        Copy files from/to BMC via SSH (legacy method for BMC transfers).

        The implementation uses ``dut_id``, ``sources``,
        ``destination_directory``, ``copy_to_destination``, and ``max_retries``
        to copy files from/to BMC via SSH (legacy method for BMC transfers).
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind. If the function cannot copy files
        from/to BMC via SSH (legacy method for BMC transfers), its exception
        reaches the caller instead of being converted into a successful result.
        Cleanup in the ``finally`` path runs for successful, failed, and
        cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            sources: Entries supplied as ``sources`` without transferring
                container ownership.
            destination_directory: filesystem location used as the destination
                for this operation.
            copy_to_destination: Whether copy to destination is enabled or
                required for this operation.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.

        Raises:
            ConnectionError: If failed to establish strict SSH proxy connection.
        """
        dut = self.get_dut(dut_id)

        # Ensure BMC SSH connection is established
        success, message = await self._ensure_connection(
            dut_id, "ssh", "test_ssh_connection"
        )
        if not success:
            return False, message

        # Validate inputs
        if not isinstance(sources, (list, tuple, str)) or not isinstance(
            destination_directory, str
        ):
            return (
                False,
                "Invalid argument combination. Please provide either a single source or list of sources, and a single destination directory.",
            )

        if isinstance(sources, str):
            sources = [sources]

        username = dut.credentials.bmc_ssh_username or dut.credentials.bmc_username
        password = dut.credentials.bmc_ssh_password or dut.credentials.bmc_password

        for source in sources:
            retry_count = 0

            while retry_count < max_retries:
                proxy_client = None
                conn = None
                try:
                    if dut.credentials.ssh_proxy_host:
                        proxy_client = await self.create_proxy_connection(dut_id)
                        if proxy_client is None:
                            raise ConnectionError(
                                "Failed to establish strict SSH proxy connection"
                            )

                    connect_kwargs = self._build_ssh_connect_kwargs(
                        host=dut.credentials.bmc_ip,
                        port=dut.credentials.bmc_ssh_port,
                        username=username,
                        password=password,
                        ssh_key_path=dut.credentials.bmc_ssh_key_path,
                        passwordless=dut.credentials.bmc_ssh_passwordless,
                        connect_timeout=30,
                        proxy_client=proxy_client,
                        host_key_policy=dut.credentials.ssh_host_key_policy,
                        known_hosts_file=dut.credentials.ssh_known_hosts_file,
                        host_key_alias=(
                            dut.credentials.bmc_ip if proxy_client else None
                        ),
                    )

                    conn = await self._connect_raw_ssh_bounded(
                        capacity_scope=str(dut_id),
                        role="endpoint",
                        connect_kwargs=connect_kwargs,
                    )

                    await self._get_dut_file_transfer().transfer_bmc_file(
                        conn,
                        BMCTransferRequest(
                            source=source,
                            destination_directory=destination_directory,
                            copy_to_destination=copy_to_destination,
                            max_download_bytes=runtime_boundary_value(
                                getattr(dut, "config", {}),
                                "bmc_transfer_max_file_bytes",
                            ),
                        ),
                    )

                    break  # Transfer successful
                except Exception as e:
                    retry_count += 1
                    if retry_count < max_retries:
                        await self.logger.log_runtime(
                            "WARNING",
                            "DUTManager",
                            f"File transfer attempt {retry_count}/{max_retries} failed: {e}",
                        )
                        await asyncio.sleep(2**retry_count)  # Exponential backoff
                    else:
                        return (
                            False,
                            f"File transfer failed after {max_retries} attempts: {e}",
                        )
                finally:
                    await self._close_ssh_connection_chain(conn, proxy_client)

        return True, ""

    @staticmethod
    def _validate_managed_host_transfer_inputs(
        dut_id: str,
        source: str,
        destination: str,
        timeout_seconds: float,
        expected_size: int,
        max_bytes: int,
        *,
        max_timeout_seconds: float = DEFAULT_RUNTIME_BOUNDARIES[
            "managed_host_transfer_max_timeout_seconds"
        ],
        max_file_bytes: int = DEFAULT_RUNTIME_BOUNDARIES[
            "managed_host_transfer_max_file_bytes"
        ],
    ) -> Optional[Tuple[Path, float, int, int]]:
        """
        Validate the exact, bounded paths accepted by the managed transfer.

        The implementation uses ``dut_id``, ``source``, ``destination``,
        ``timeout_seconds``, ``expected_size``, ``max_bytes``,
        ``max_timeout_seconds``, and ``max_file_bytes`` to validate the exact,
        bounded paths accepted by the managed transfer. Every required invariant
        is checked before a successful value is returned; invalid input follows
        the function's explicit exception path. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            source: Text supplied as source in the format accepted by this
                function.
            destination: Text supplied as destination in the format accepted by
                this function.
            timeout_seconds: Maximum duration in seconds allowed for timeout
                seconds.
            expected_size: Exact regular-file size proven by the managed command
                inspection receipt.
            max_bytes: Collector-specific byte ceiling applied to this transfer.
            max_timeout_seconds: Maximum duration in seconds allowed for max
                timeout seconds.
            max_file_bytes: Runtime profile ceiling for managed Host transfers.

        Returns:
            A tuple containing ``destination path``, ``resolved timeout``,
            ``expected size``, and ``resolved max bytes`` in that order.
        """

        if not is_printable_identity(dut_id, maximum_bytes=MAX_DUT_ID_BYTES):
            return None
        if not isinstance(source, str) or not isinstance(destination, str):
            return None
        if not source or not destination:
            return None
        if any(ord(character) < 32 or ord(character) == 127 for character in source):
            return None
        if any(
            ord(character) < 32 or ord(character) == 127 for character in destination
        ):
            return None

        try:
            source_bytes = source.encode("utf-8", errors="strict")
            destination_bytes = destination.encode("utf-8", errors="strict")
        except UnicodeError:
            return None
        if not (0 < len(source_bytes) <= MANAGED_HOST_TRANSFER_MAX_PATH_BYTES):
            return None
        if not (0 < len(destination_bytes) <= MANAGED_HOST_TRANSFER_MAX_PATH_BYTES):
            return None

        if (
            not source.startswith("/")
            or source.startswith("//")
            or source == "/"
            or posixpath.normpath(source) != source
        ):
            return None

        destination_path = Path(destination)
        if (
            not destination_path.is_absolute()
            or str(destination_path) != destination
            or destination_path.name in {"", ".", ".."}
        ):
            return None
        try:
            parent_status = destination_path.parent.lstat()
            resolved_parent = destination_path.parent.resolve(strict=True)
        except OSError:
            return None
        if not stat.S_ISDIR(parent_status.st_mode):
            return None
        if resolved_parent != destination_path.parent:
            return None
        if os.path.lexists(destination_path):
            return None

        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or isinstance(max_file_bytes, bool)
            or not isinstance(max_file_bytes, int)
            or max_file_bytes <= 0
            or not 0 <= expected_size <= max_bytes <= max_file_bytes
        ):
            return None

        if isinstance(timeout_seconds, bool) or not isinstance(
            timeout_seconds, (int, float)
        ):
            return None
        if isinstance(max_timeout_seconds, bool) or not isinstance(
            max_timeout_seconds, (int, float)
        ):
            return None
        resolved_timeout = float(timeout_seconds)
        resolved_max_timeout = min(
            float(max_timeout_seconds),
            float(
                DEFAULT_RUNTIME_BOUNDARIES["managed_host_transfer_max_timeout_seconds"]
            ),
        )
        if (
            not math.isfinite(resolved_timeout)
            or not math.isfinite(resolved_max_timeout)
            or resolved_max_timeout <= 0
            or resolved_timeout <= 0
            or resolved_timeout > resolved_max_timeout
        ):
            return None

        return destination_path, resolved_timeout, expected_size, max_bytes

    @staticmethod
    async def _close_managed_host_transfer_resource(
        resource: Any,
        *,
        deadline: float,
        sftp: bool,
    ) -> None:
        """
        Close one transfer-owned resource within its assigned deadline.

        The implementation uses ``resource``, ``deadline``, and ``sftp`` to
        close one transfer-owned resource within its assigned deadline. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. If the function cannot close one
        transfer-owned resource within its assigned deadline, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            resource: Resource consumed while the function attempts to close one
                transfer-owned resource within its assigned deadline.
            deadline: Absolute monotonic deadline after which the operation must
                stop.
            sftp: Whether sftp is enabled or required for this operation.

        Raises:
            RuntimeError: If managed Host transfer resource cannot be closed; or
                managed Host transfer connection cannot be aborted.
            Exception: If the function cannot close one transfer-owned resource
                within its assigned deadline safely.
            BaseException: If a delegated failure occurs while the function
                attempts to close one transfer-owned resource within its
                assigned deadline.
        """

        close = getattr(resource, "exit" if sftp else "close", None)
        wait_closed = getattr(resource, "wait_closed", None)
        if not callable(close) or not callable(wait_closed):
            raise RuntimeError("Managed Host transfer resource cannot be closed")

        close_error: Optional[BaseException] = None
        try:
            close()
        except BaseException as error:
            close_error = error

        loop = asyncio.get_running_loop()
        remaining = max(0.0, deadline - loop.time())
        if not sftp and (close_error is not None or remaining <= 0):
            abort = getattr(resource, "abort", None)
            if callable(abort):
                try:
                    abort()
                except BaseException as error:
                    close_error = close_error or error

        if remaining <= 0:
            raise close_error or TimeoutError(
                "Managed Host transfer resource cleanup timed out"
            )

        graceful_budget = remaining if sftp else max(0.001, remaining / 2)
        try:
            await asyncio.wait_for(wait_closed(), timeout=graceful_budget)
        except asyncio.TimeoutError as error:
            if sftp:
                raise error
            abort = getattr(resource, "abort", None)
            if not callable(abort):
                raise RuntimeError(
                    "Managed Host transfer connection cannot be aborted"
                ) from error
            abort()
            abort_budget = max(0.0, deadline - loop.time())
            if abort_budget <= 0:
                raise error
            await asyncio.wait_for(wait_closed(), timeout=abort_budget)

        if close_error is not None:
            raise close_error

    async def _cleanup_managed_host_transfer_resources(
        self,
        sftp_client: Any,
        connection: Any,
        proxy_connection: Any,
        *,
        deadline: float,
    ) -> None:
        """
        Drain the exact SFTP/SSH resource chain without losing ownership.

        The implementation uses ``sftp_client``, ``connection``,
        ``proxy_connection``, and ``deadline`` to drain the exact SFTP/SSH
        resource chain without losing ownership. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. It updates ``_orphaned_ssh_connections`` and
        ``_owned_proxy_connections`` on the instance as part of that state
        transition. If the function cannot drain the exact SFTP/SSH resource
        chain without losing ownership, its exception reaches the caller instead
        of being converted into a successful result.

        Args:
            sftp_client: Sftp client consumed while the function attempts to
                drain the exact SFTP/SSH resource chain without losing
                ownership.
            connection: Connection consumed while the function attempts to drain
                the exact SFTP/SSH resource chain without losing ownership.
            proxy_connection: Proxy connection consumed while the function
                attempts to drain the exact SFTP/SSH resource chain without
                losing ownership.
            deadline: Absolute monotonic deadline after which the operation must
                stop.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to drain the exact SFTP/SSH resource chain without
                losing ownership.
        """

        owned_proxies = getattr(self, "_owned_proxy_connections", None)
        if owned_proxies is None:
            owned_proxies = {}
            self._owned_proxy_connections = owned_proxies
        orphaned_connections = getattr(self, "_orphaned_ssh_connections", None)
        if orphaned_connections is None:
            orphaned_connections = {}
            self._orphaned_ssh_connections = orphaned_connections

        ownership_key: Optional[int] = None
        if connection is not None:
            ownership_key = id(connection)
            orphaned_connections.setdefault(ownership_key, connection)
            if proxy_connection is not None:
                owned_proxies.setdefault(ownership_key, proxy_connection)
        elif proxy_connection is not None:
            ownership_key = id(proxy_connection)
            owned_proxies.setdefault(ownership_key, proxy_connection)

        resources = tuple(
            (resource, is_sftp)
            for resource, is_sftp in (
                (sftp_client, True),
                (connection, False),
                (proxy_connection, False),
            )
            if resource is not None
        )
        cleanup_errors: List[BaseException] = []
        connection_closed = connection is None
        proxy_closed = proxy_connection is None

        for index, (resource, is_sftp) in enumerate(resources):
            remaining_count = len(resources) - index
            loop = asyncio.get_running_loop()
            remaining = max(0.0, deadline - loop.time())
            resource_deadline = loop.time() + (
                remaining / remaining_count if remaining_count else 0.0
            )
            try:
                await self._close_managed_host_transfer_resource(
                    resource,
                    deadline=resource_deadline,
                    sftp=is_sftp,
                )
            except BaseException as error:
                cleanup_errors.append(error)
            else:
                if resource is connection:
                    connection_closed = True
                    orphaned_connections.pop(id(connection), None)
                if resource is proxy_connection:
                    proxy_closed = True

        if ownership_key is not None and proxy_closed:
            owned_proxies.pop(ownership_key, None)
        if connection_closed and connection is not None:
            orphaned_connections.pop(id(connection), None)

        if cleanup_errors:
            raise _authoritative_cleanup_error(cleanup_errors)

    @staticmethod
    def _remove_managed_host_transfer_destination(destination: Path) -> bool:
        """
        Remove only a transfer-created non-directory destination.

        The implementation uses ``destination`` to remove only a
        transfer-created non-directory destination.

        Args:
            destination: filesystem location used as the destination for this
                operation.

        Returns:
            Whether the remove only a transfer-created non-directory destination
            operation succeeds.
        """

        try:
            destination_status = destination.lstat()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        if stat.S_ISDIR(destination_status.st_mode):
            return False
        try:
            destination.unlink()
        except OSError:
            return False
        return True

    async def transfer_managed_host_file(
        self,
        dut_id: str,
        source: str,
        destination: str,
        *,
        timeout_seconds: float,
        expected_size: int,
        max_bytes: int,
    ) -> Tuple[bool, str]:
        """
        Transfer one managed Host artifact with no command or retry fallback.

        This path deliberately does not run Host preflight or diagnostic
        commands. It opens one direct AsyncSSH/SFTP route (plus one required
        jump connection), transfers one exact regular file to one exact new
        local destination, and returns only bounded, path-free failure
        categories.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            source: Text supplied as source in the format accepted by this
                function.
            destination: Text supplied as destination in the format accepted by
                this function.
            timeout_seconds: Maximum duration in seconds allowed for timeout
                seconds.
            expected_size: Exact regular-file size proven by the managed command
                inspection receipt.
            max_bytes: Collector-specific byte ceiling applied before opening
                or reading the remote file.

        Returns:
            A tuple containing ``success flag`` and ``status text`` in that
            order.

        Raises:
            RuntimeError: If managed Host SFTP logging cannot be safely
                redacted.
            ValueError: If managed Host source is not a regular file; managed
                Host source size is invalid; managed Host source link count is
                invalid; or managed Host destination is not a regular file; or
                another input invariant is violated.
            OSError: If managed Host transfer lacks local free space.
            FileExistsError: If managed Host destination already exists.
            BaseException: If a delegated failure occurs while the function
                attempts to transfer one managed Host artifact with no command
                or retry fallback.
        """

        limit_dut = self.duts.get(dut_id)
        limit_config = getattr(limit_dut, "config", {})
        max_timeout_seconds = runtime_boundary_value(
            limit_config, "managed_host_transfer_max_timeout_seconds"
        )
        max_file_bytes = min(
            runtime_boundary_value(
                limit_config, "managed_host_transfer_max_file_bytes"
            ),
            runtime_boundary_value(limit_config, "managed_artifact_max_file_bytes"),
        )
        free_space_reserve_bytes = runtime_boundary_value(
            limit_config, "managed_host_transfer_free_space_reserve_bytes"
        )
        validated = self._validate_managed_host_transfer_inputs(
            dut_id,
            source,
            destination,
            timeout_seconds,
            expected_size,
            max_bytes,
            max_timeout_seconds=max_timeout_seconds,
            max_file_bytes=max_file_bytes,
        )
        if validated is None:
            return False, "Managed Host transfer input validation failed"
        destination_path, resolved_timeout, expected_size, max_bytes = validated

        try:
            dut = self.get_dut(dut_id)
        except Exception:
            return False, "Managed Host transfer target is unavailable"
        if not dut.credentials.host_ip:
            return False, "Managed Host transfer is unsupported in local mode"

        loop = asyncio.get_running_loop()
        total_deadline = loop.time() + resolved_timeout
        cleanup_reserve = min(
            MANAGED_HOST_TRANSFER_CLEANUP_RESERVE_SECONDS,
            max(0.001, resolved_timeout * 0.2),
        )
        if cleanup_reserve >= resolved_timeout:
            cleanup_reserve = resolved_timeout / 2
        operation_deadline = total_deadline - cleanup_reserve

        proxy_connection = None
        connection = None
        sftp_client = None
        transfer_complete = False
        result: Tuple[bool, str] = (False, "Managed Host transfer failed")
        primary_control: Optional[BaseException] = None

        try:
            async with asyncio.timeout_at(operation_deadline):
                if dut.credentials.ssh_proxy_host:
                    proxy_kwargs = self._build_ssh_connect_kwargs(
                        host=dut.credentials.ssh_proxy_host,
                        port=dut.credentials.ssh_proxy_port,
                        username=dut.credentials.ssh_proxy_username,
                        password=dut.credentials.ssh_proxy_password,
                        ssh_key_path=dut.credentials.ssh_proxy_key_path,
                        passwordless=dut.credentials.ssh_proxy_passwordless,
                        connect_timeout=max(0.001, operation_deadline - loop.time()),
                        keepalive_interval=None,
                        host_key_policy=dut.credentials.ssh_host_key_policy,
                        known_hosts_file=dut.credentials.ssh_known_hosts_file,
                    )
                    proxy_connection = await asyncssh.connect(**proxy_kwargs)
                    _bind_managed_sftp_logger(proxy_connection)

                connect_kwargs = self._build_ssh_connect_kwargs(
                    host=dut.credentials.host_ip,
                    port=dut.credentials.host_ssh_port,
                    username=dut.credentials.host_username,
                    password=dut.credentials.host_password,
                    ssh_key_path=dut.credentials.host_ssh_key_path,
                    passwordless=dut.credentials.host_ssh_passwordless,
                    connect_timeout=max(0.001, operation_deadline - loop.time()),
                    keepalive_interval=None,
                    proxy_client=proxy_connection,
                    host_key_policy=dut.credentials.ssh_host_key_policy,
                    known_hosts_file=dut.credentials.ssh_known_hosts_file,
                    host_key_alias=(
                        dut.credentials.host_ip
                        if proxy_connection is not None
                        else None
                    ),
                )
                connection = await asyncssh.connect(**connect_kwargs)
                _bind_managed_sftp_logger(connection)
                if proxy_connection is not None:
                    owned_proxies = getattr(self, "_owned_proxy_connections", None)
                    if owned_proxies is None:
                        owned_proxies = {}
                        self._owned_proxy_connections = owned_proxies
                    owned_proxies[id(connection)] = proxy_connection

                sftp_client = await connection.start_sftp_client()
                if not _managed_sftp_handler_is_isolated(sftp_client):
                    raise RuntimeError(
                        "Managed Host SFTP logging cannot be safely redacted"
                    )

                remote_status = await sftp_client.lstat(source)
                remote_size = getattr(remote_status, "size", None)
                remote_links = getattr(remote_status, "nlink", None)
                if (
                    getattr(remote_status, "type", None)
                    != asyncssh.FILEXFER_TYPE_REGULAR
                ):
                    raise ValueError("Managed Host source is not a regular file")
                if (
                    isinstance(remote_size, bool)
                    or not isinstance(remote_size, int)
                    or remote_size < 0
                    or remote_size != expected_size
                    or remote_size > max_bytes
                ):
                    raise ValueError("Managed Host source size is invalid")
                if isinstance(remote_links, int) and not isinstance(remote_links, bool):
                    if remote_links != 1:
                        raise ValueError("Managed Host source link count is invalid")

                free_space = shutil.disk_usage(destination_path.parent).free
                if free_space < remote_size + free_space_reserve_bytes:
                    raise OSError("Managed Host transfer lacks local free space")

                if os.path.lexists(destination_path):
                    raise FileExistsError("Managed Host destination already exists")
                transferred_bytes = await _download_sftp_regular_file_bounded(
                    sftp_client,
                    source,
                    destination_path,
                    max_bytes=max_bytes,
                    read_chunk_bytes=SFTP_DOWNLOAD_READ_CHUNK_BYTES,
                    expected_size=expected_size,
                )
                if transferred_bytes != expected_size:
                    raise ValueError("Managed Host destination evidence is invalid")

                local_status = destination_path.lstat()
                if not stat.S_ISREG(local_status.st_mode):
                    raise ValueError("Managed Host destination is not a regular file")
                if local_status.st_nlink != 1 or local_status.st_size != remote_size:
                    raise ValueError("Managed Host destination evidence is invalid")

                transfer_complete = True
                result = (True, "")
        except asyncio.TimeoutError:
            result = (False, "Managed Host transfer timed out")
        except (
            asyncio.CancelledError,
            KeyboardInterrupt,
            SystemExit,
        ) as error:
            primary_control = error
        except Exception:
            result = (False, "Managed Host transfer failed")

        cleanup_task = asyncio.create_task(
            capture_owned_awaitable(
                self._cleanup_managed_host_transfer_resources(
                    sftp_client,
                    connection,
                    proxy_connection,
                    deadline=total_deadline,
                )
            )
        )
        drain_error: Optional[BaseException] = None
        cleanup_error: Optional[BaseException] = None
        try:
            (cleanup_outcome,) = await drain_owned_tasks(
                (cleanup_task,), cancel_on_wait_error=False
            )
        except BaseException as error:
            drain_error = error
            try:
                cleanup_outcome = cleanup_task.result()
            except BaseException as task_error:
                cleanup_error = task_error
            else:
                cleanup_error = cleanup_outcome.error
        else:
            cleanup_error = cleanup_outcome.error

        observed_controls = tuple(
            error
            for error in (primary_control, drain_error, cleanup_error)
            if isinstance(
                error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)
            )
        )
        cleanup_succeeded = cleanup_error is None
        preserve_destination = (
            transfer_complete
            and cleanup_succeeded
            and drain_error is None
            and not observed_controls
        )
        if not preserve_destination:
            cleanup_succeeded = (
                self._remove_managed_host_transfer_destination(destination_path)
                and cleanup_succeeded
            )

        if observed_controls:
            raise select_authoritative_exception(observed_controls)
        if drain_error is not None:
            raise drain_error
        if cleanup_error is not None or not cleanup_succeeded:
            return False, "Managed Host transfer cleanup failed"
        return result

    async def transfer_host_files(
        self,
        dut_id: str,
        sources: Union[str, List[str]],
        destination_directory: str,
        copy_to_destination: bool = True,
        max_retries: int = 3,
        max_bytes: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Copy files from/to host via SSH (for host file transfers).

        The implementation uses ``dut_id``, ``sources``,
        ``destination_directory``, ``copy_to_destination``, and ``max_retries``
        to copy files from/to host via SSH (for host file transfers). Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. If the function cannot copy files from/to
        host via SSH (for host file transfers), its exception reaches the caller
        instead of being converted into a successful result. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            sources: Entries supplied as ``sources`` without transferring
                container ownership.
            destination_directory: filesystem location used as the destination
                for this operation.
            copy_to_destination: Whether copy to destination is enabled or
                required for this operation.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.
            max_bytes: Upper bound enforced for max bytes; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.

        Raises:
            ConnectionError: If failed to establish strict SSH proxy connection.
        """
        dut = self.get_dut(dut_id)
        download_max_bytes = (
            SFTP_DOWNLOAD_DEFAULT_MAX_BYTES if max_bytes is None else max_bytes
        )
        try:
            _validate_sftp_download_limits(
                download_max_bytes,
                SFTP_DOWNLOAD_READ_CHUNK_BYTES,
            )
        except ValueError as error:
            return False, str(error)

        # Debug logging
        await self.logger.log_runtime(
            "DEBUG",
            "DUTManager",
            f"transfer_host_files called with sources={sources}, destination={destination_directory}, copy_to_destination={copy_to_destination}",
        )
        await self.logger.log_runtime(
            "DEBUG",
            "DUTManager",
            f"transfer_host_files: sources type={type(sources)}, destination type={type(destination_directory)}",
        )
        await self.logger.log_runtime(
            "DEBUG",
            "DUTManager",
            f"Host connected: {dut.connection_state.host_connected}",
        )
        await self.logger.log_runtime(
            "DEBUG", "DUTManager", f"Host IP: {dut.credentials.host_ip}"
        )

        # Ensure host connection is established
        success, message = await self._ensure_connection(
            dut_id, "host", "test_host_connection"
        )
        if not success:
            return False, message

        # Validate inputs
        if not isinstance(sources, (list, tuple, str)) or not isinstance(
            destination_directory, str
        ):
            return (
                False,
                "Invalid argument combination. Please provide either a single source or list of sources, and a single destination directory.",
            )

        if isinstance(sources, str):
            sources = [sources]

        if type(copy_to_destination) is not bool:
            return False, "copy_to_destination must be a boolean"

        # For downloading files (copy_to_destination=False), use enhanced fallback logic
        if not copy_to_destination:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                "Using enhanced fallback logic for host file transfer",
            )
            return await self._transfer_host_files_with_fallback(
                dut_id,
                sources,
                destination_directory,
                max_retries=max_retries,
                max_bytes=download_max_bytes,
            )

        # For uploading files (copy_to_destination=True), use original logic
        username = dut.credentials.host_username
        password = dut.credentials.host_password

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "DUTManager",
            f"Host credentials - username: {username}, password available: {'Yes' if password else 'No'}",
        )

        for source in sources:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"Attempting to transfer source: {source}",
            )
            retry_count = 0
            while retry_count < max_retries:
                proxy_client = None
                conn = None
                try:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DUTManager",
                        "Using asyncssh for host file transfer",
                    )
                    if dut.credentials.ssh_proxy_host:
                        proxy_client = await self.create_proxy_connection(dut_id)
                        if proxy_client is None:
                            raise ConnectionError(
                                "Failed to establish strict SSH proxy connection"
                            )

                    connect_kwargs = self._build_ssh_connect_kwargs(
                        host=dut.credentials.host_ip,
                        port=dut.credentials.host_ssh_port,
                        username=username,
                        password=password,
                        ssh_key_path=dut.credentials.host_ssh_key_path,
                        passwordless=dut.credentials.host_ssh_passwordless,
                        connect_timeout=30,
                        proxy_client=proxy_client,
                        host_key_policy=dut.credentials.ssh_host_key_policy,
                        known_hosts_file=dut.credentials.ssh_known_hosts_file,
                        host_key_alias=(
                            dut.credentials.host_ip if proxy_client else None
                        ),
                    )
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DUTManager",
                        f"asyncssh connect_kwargs: host={dut.credentials.host_ip}, port={dut.credentials.host_ssh_port}, username={username}",
                    )

                    if dut.credentials.host_ssh_key_path:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"Using SSH key authentication for host file transfer: {dut.credentials.host_ssh_key_path}",
                        )
                    elif dut.credentials.host_ssh_passwordless:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            "Using passwordless authentication for host file transfer",
                        )
                    else:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            "Using password authentication for host file transfer",
                        )

                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DUTManager",
                        f"Attempting asyncssh connection to {dut.credentials.host_ip}",
                    )
                    conn = await self._connect_raw_ssh_bounded(
                        capacity_scope=str(dut_id),
                        role="endpoint",
                        connect_kwargs=connect_kwargs,
                    )
                    async with conn.start_sftp_client() as sftp:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            "SFTP client started successfully",
                        )
                        file_name = os.path.basename(source)
                        remote_path = f"{destination_directory}/{file_name}"

                        # ``copy_to_destination=False`` returns through the
                        # bounded download/fallback implementation above, so
                        # this is deliberately upload-only. Keeping a second
                        # download branch here made its cleanup logic
                        # unreachable for every real boolean argument.
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"Copying local file {source} to remote {remote_path}",
                        )
                        await sftp.put(source, remote_path)
                        await self.logger.log_runtime(
                            "INFO",
                            "DUTManager",
                            f"Transferred {source} to {remote_path}",
                        )

                    # If we get here, transfer was successful
                    await self.logger.log_runtime(
                        "DEBUG",
                        "DUTManager",
                        f"File transfer successful for {source}",
                    )
                    break

                except Exception as e:
                    retry_count += 1
                    await self.logger.log_runtime(
                        "WARNING",
                        "DUTManager",
                        f"File transfer attempt {retry_count} failed for {source}: {e}",
                    )
                    await self.logger.log_runtime(
                        "DEBUG",
                        "DUTManager",
                        f"Exception details: {type(e).__name__}: {str(e)}",
                    )
                    if retry_count >= max_retries:
                        await self.logger.log_runtime(
                            "ERROR",
                            "DUTManager",
                            f"File transfer failed after {max_retries} attempts for {source}",
                        )
                        return (
                            False,
                            f"File transfer failed after {max_retries} attempts: {e}",
                        )
                finally:
                    await self._close_ssh_connection_chain(conn, proxy_client)

        return True, ""

    def _resolve_host_transfer_temp_root(self, dut_id: str) -> str:
        """
        Resolve ``TOOL_TEMP_DIR`` for generic Host transfer fallback scratch.

        The merged DUT configuration is interpreted on the Host endpoint, then
        passed through the same absolute-path boundary used to validate the
        endpoint's later ``mktemp`` receipt.

        Args:
            dut_id: Stable DUT identifier used to select merged configuration.

        Returns:
            The validated normalized remote Host temporary-directory root.

        Raises:
            ValueError: If the configured ``TOOL_TEMP_DIR`` is not a safe
                normalized absolute path.
        """

        dut = self.get_dut(dut_id)
        tool_config = getattr(dut, "config", {})
        if not isinstance(tool_config, dict):
            tool_config = {}
        return _normalize_remote_transfer_root(get_tool_temp_dir(tool_config, "/tmp"))

    async def _create_remote_transfer_directory(
        self,
        dut_id: str,
        remote_temp_root: Optional[str] = None,
    ) -> _RemoteTransferDirectory:
        """
        Create one endpoint-selected private directory and bind its inode.

        After applying local validation, the function forwards ``dut_id`` to
        ``_parse_remote_transfer_directory`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            remote_temp_root: Optional pre-resolved ``TOOL_TEMP_DIR`` value.

        Returns:
            A ``_RemoteTransferDirectory`` representing remote transfer
            directory.

        Raises:
            RuntimeError: If remote mktemp failed with status ``exit_code``; or
                the function cannot create one endpoint-selected private
                directory and bind its inode safely.
        """

        resolved_root = (
            self._resolve_host_transfer_temp_root(dut_id)
            if remote_temp_root is None
            else _normalize_remote_transfer_root(remote_temp_root)
        )
        command = _quote_remote_argv(
            [
                TRUSTED_POSIX_SHELL_PATH,
                "-c",
                REMOTE_TRANSFER_DIRECTORY_CREATE_SCRIPT,
                "nvdebug-host-transfer-mktemp",
                resolved_root,
            ]
        )
        exit_code, stdout, _stderr = await self.execute_host_command(
            dut_id,
            command,
            timeout=60,
            use_sudo=False,
        )
        if exit_code != 0:
            raise RuntimeError(f"Remote mktemp failed with status {exit_code}")
        try:
            return _parse_remote_transfer_directory(stdout, resolved_root)
        except ValueError as error:
            raise RuntimeError(str(error)) from error

    async def _cleanup_remote_transfer_directory(
        self,
        dut_id: str,
        directory: _RemoteTransferDirectory,
    ) -> None:
        """
        Remove only the validated path while it retains its original inode.

        The implementation uses ``dut_id`` and ``directory`` to remove only the
        validated path while it retains its original inode. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind. If the function cannot remove only the validated
        path while it retains its original inode, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            directory: filesystem location used as the directory for this
                operation.

        Raises:
            ValueError: If remote transfer directory receipt has an invalid
                type; or remote transfer directory receipt is invalid.
            RuntimeError: If remote transfer directory cleanup failed with
                status ``exit_code``.
        """

        if type(directory) is not _RemoteTransferDirectory:
            raise ValueError("Remote transfer directory receipt has an invalid type")
        if (
            not _remote_transfer_directory_path_is_valid(
                directory.path,
                directory.root,
            )
            or REMOTE_TRANSFER_DIRECTORY_IDENTITY_PATTERN.fullmatch(directory.identity)
            is None
        ):
            raise ValueError("Remote transfer directory receipt is invalid")
        command = _quote_remote_argv(
            [
                TRUSTED_POSIX_SHELL_PATH,
                "-c",
                REMOTE_TRANSFER_DIRECTORY_CLEANUP_SCRIPT,
                "nvdebug-host-transfer-cleanup",
                directory.path,
                directory.identity,
            ]
        )
        exit_code, _stdout, _stderr = await self.execute_host_command(
            dut_id,
            command,
            timeout=60,
            use_sudo=True,
        )
        if exit_code != 0:
            raise RuntimeError(
                f"Remote transfer directory cleanup failed with status {exit_code}"
            )

    async def _cleanup_remote_transfer_directory_shielded(
        self,
        dut_id: str,
        directory: _RemoteTransferDirectory,
    ) -> None:
        """
        Finish the exact cleanup task before preserving caller control flow.

        The implementation uses ``dut_id`` and ``directory`` to finish the exact
        cleanup task before preserving caller control flow. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind. If the function cannot finish the exact cleanup
        task before preserving caller control flow, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            directory: filesystem location used as the directory for this
                operation.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to finish the exact cleanup task before preserving
                caller control flow.
        """

        cleanup_task = asyncio.create_task(
            capture_owned_awaitable(
                self._cleanup_remote_transfer_directory(dut_id, directory)
            )
        )
        try:
            (outcome,) = await drain_owned_tasks(
                (cleanup_task,),
                cancel_on_wait_error=False,
            )
        except BaseException as wait_error:
            observed_errors: List[BaseException] = [wait_error]
            try:
                cleanup_outcome = cleanup_task.result()
            except BaseException as task_error:
                observed_errors.append(task_error)
            else:
                if cleanup_outcome.error is not None:
                    observed_errors.append(cleanup_outcome.error)
            raise select_authoritative_exception(observed_errors)
        if outcome.error is not None:
            raise outcome.error

    async def _transfer_host_files_with_fallback(
        self,
        dut_id: str,
        sources: List[str],
        destination_directory: str,
        max_retries: int = 3,
        max_bytes: int = SFTP_DOWNLOAD_DEFAULT_MAX_BYTES,
    ) -> Tuple[bool, str]:
        """
        Transfer host files with fallback.

        The implementation uses ``dut_id``, ``sources``,
        ``destination_directory``, ``max_retries``, and ``max_bytes`` to
        transfer host files with fallback. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle. If the function cannot transfer host files
        with fallback, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            sources: Entries supplied as ``sources`` without transferring
                container ownership.
            destination_directory: filesystem location used as the destination
                for this operation.
            max_retries: Upper bound enforced for max retries; the consuming
                boundary rejects or truncates values that exceed it.
            max_bytes: Upper bound enforced for max bytes; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.

        Raises:
            RuntimeError: If archive extraction returned no result.
        """
        _validate_sftp_download_limits(
            max_bytes,
            SFTP_DOWNLOAD_READ_CHUNK_BYTES,
        )
        dut = self.get_dut(dut_id)

        if dut.config and dut.config.get("local", False):
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                "Local mode detected - using local file copy instead of SFTP",
            )
            return await self._copy_local_files_to_destination(
                dut_id,
                sources,
                destination_directory,
                max_bytes=max_bytes,
            )

        username = dut.credentials.host_username
        password = dut.credentials.host_password

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "DUTManager",
            f"Starting enhanced file transfer with fallback for {len(sources)} files",
        )

        remote_transfer_directory: Optional[_RemoteTransferDirectory] = None
        remote_temp_root: Optional[str] = None
        temp_dir: Optional[str] = None

        try:
            # Ensure destination directory exists
            os.makedirs(destination_directory, exist_ok=True)

            successful_downloads = []
            failed_paths = []

            # Step 1: Try direct SFTP download first
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                "Attempting direct SFTP download...",
            )

            # Pre-transfer diagnostics
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                "Running pre-transfer diagnostics",
            )

            # Check SSH user context
            user_check_cmd = "whoami && id && groups"
            user_exit_code, user_stdout, _ = await self.execute_host_command(
                dut_id, user_check_cmd, timeout=30, use_sudo=False
            )
            if user_exit_code == 0:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DUTManager",
                    f"SSH user context: {user_stdout.strip()}",
                )

            for source in sources:
                try:
                    # Pre-download diagnostics for each file
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DUTManager",
                        f"Pre-download diagnostics for: {source}",
                    )

                    # Check file existence and permissions
                    file_check_cmd = f"test -f {shlex.quote(str(source))} && ls -la {shlex.quote(str(source))} || echo {shlex.quote('File does not exist: ' + str(source))}"
                    file_exit_code, file_stdout, _ = await self.execute_host_command(
                        dut_id, file_check_cmd, timeout=30, use_sudo=False
                    )
                    if file_exit_code == 0:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"File check result: {file_stdout.strip()}",
                        )

                    # Check if we can read the file
                    read_test_cmd = f"head -c 100 {shlex.quote(str(source))} > /dev/null 2>&1 && echo 'File readable' || echo 'File not readable'"
                    read_exit_code, read_stdout, _ = await self.execute_host_command(
                        dut_id, read_test_cmd, timeout=30, use_sudo=False
                    )
                    if read_exit_code == 0:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"File readability test: {read_stdout.strip()}",
                        )

                    # Try direct SFTP download
                    success, error_msg = await self._simple_sftp_download(
                        dut_id,
                        source,
                        destination_directory,
                        max_bytes=max_bytes,
                    )

                    if success:
                        successful_downloads.append(source)
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"Downloaded {source}",
                        )
                    else:
                        failed_paths.append(source)
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "DUTManager",
                            f"Direct download failed for {source}: {error_msg}",
                        )
                except Exception as e:
                    failed_paths.append(source)
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"Direct download exception for {source}: {str(e)}",
                    )

            if not failed_paths:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DUTManager",
                    "All files downloaded via SFTP",
                )
                return True, ""

            remote_temp_root = self._resolve_host_transfer_temp_root(dut_id)
            quoted_temp_root = shlex.quote(remote_temp_root)
            tmp_check_cmd = (
                f"ls -ld -- {quoted_temp_root} && df -h -- {quoted_temp_root}"
            )
            tmp_exit_code, tmp_stdout, _ = await self.execute_host_command(
                dut_id, tmp_check_cmd, timeout=30, use_sudo=False
            )
            if tmp_exit_code == 0:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DUTManager",
                    f"Configured temp directory status: {tmp_stdout.strip()}",
                )

            # Step 2: For failed files, try copying to temp location with readable permissions
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Attempting permission-based fallback for {len(failed_paths)} failed files",
            )

            # The endpoint selects the directory through atomic ``mktemp``.
            # Retain its device/inode receipt so final cleanup cannot remove a
            # preclaimed or subsequently replaced path.
            remote_transfer_directory = await self._create_remote_transfer_directory(
                dut_id,
                remote_temp_root,
            )
            temp_dir = remote_transfer_directory.path

            # Try to copy failed files to temp location with readable permissions
            for remote_path in failed_paths[:]:  # Copy list to allow modification
                unique_filename = os.path.basename(remote_path)
                temp_file = f"{temp_dir}/{unique_filename}"

                # Copy file to temporary location using sudo with better error handling
                cp_cmd = f"cp {shlex.quote(remote_path)} {shlex.quote(temp_file)}"
                exit_code, _, stderr_cp = await self.execute_host_command(
                    dut_id, cp_cmd, timeout=60, use_sudo=True
                )

                if exit_code != 0:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"Failed to copy {remote_path} to temp location: {stderr_cp}",
                    )
                    continue

                chown_file_cmd = (
                    f"chown {shlex.quote(str(username))} {shlex.quote(temp_file)}"
                )
                exit_code, _, stderr_file_chown = await self.execute_host_command(
                    dut_id, chown_file_cmd, timeout=60, use_sudo=True
                )

                if exit_code != 0:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"Failed to set file owner: {stderr_file_chown}",
                    )
                    continue

                chmod_file_cmd = f"chmod 600 {shlex.quote(temp_file)}"
                exit_code, _, stderr_file_chmod = await self.execute_host_command(
                    dut_id, chmod_file_cmd, timeout=60, use_sudo=True
                )

                if exit_code != 0:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"Failed to set file permissions: {stderr_file_chmod}",
                    )
                    continue

                # Empty regular files are valid transfer inputs. Verify object
                # identity without conflating zero bytes with absence.
                verify_cmd = (
                    f"test -f {shlex.quote(temp_file)} "
                    f"&& test ! -L {shlex.quote(temp_file)}"
                )
                exit_code, _, _ = await self.execute_host_command(
                    dut_id, verify_cmd, timeout=60, use_sudo=True
                )

                if exit_code != 0:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"Temporary transfer file is missing or unsafe: {temp_file}",
                    )
                    # Clean up only the transfer-owned temporary path.
                    await self.execute_host_command(
                        dut_id,
                        f"rm -f {shlex.quote(temp_file)}",
                        timeout=60,
                        use_sudo=True,
                    )
                    continue

                # Attempt download of the file from the temporary location
                try:
                    success, error_msg = await self._simple_sftp_download(
                        dut_id,
                        temp_file,
                        destination_directory,
                        max_bytes=max_bytes,
                    )

                    if success:
                        failed_paths.remove(remote_path)
                        successful_downloads.append(remote_path)
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "DUTManager",
                            f"Fallback download successful for {remote_path}",
                        )
                    else:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "DUTManager",
                            f"Fallback download failed for {remote_path}: {error_msg}",
                        )
                except Exception as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "DUTManager",
                        f"Fallback download exception for {remote_path}: {str(e)}",
                    )

                # Clean up temp file
                await self.execute_host_command(
                    dut_id,
                    f"rm -f {shlex.quote(temp_file)}",
                    timeout=60,
                    use_sudo=True,
                )

            if not failed_paths:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DUTManager",
                    "All files downloaded via permission-based fallback",
                )
                return True, ""

            # Step 3: If we still have failed files, try tar archive approach
            if len(failed_paths) > 1:  # Only create tar if multiple files
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DUTManager",
                    f"Attempting tar archive fallback for {len(failed_paths)} remaining failed files",
                )

                temp_tar = f"{temp_dir}/files_transfer.tar.gz"

                # Create tar in the temp directory to avoid permission issues
                # Use -h flag to follow symlinks (dereference) to ensure actual data is archived
                # Important: -h must come before -f, not after it

                tar_cmd = build_link_safe_tar_create_command(
                    os.path.basename(temp_tar),
                    failed_paths,
                    tar_command=TRUSTED_REMOTE_TAR_COMMAND,
                    change_dir=str(temp_dir),
                )

                await self.logger.write_to_dut_runtime_log(
                    dut_id, "DEBUG", "DUTManager", f"Tar command: {tar_cmd}"
                )

                exit_code, stdout, stderr = await self.execute_host_command(
                    dut_id, tar_cmd, timeout=300, use_sudo=True
                )

                if exit_code == 0:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "DUTManager",
                        "Remote tar creation successful",
                    )

                    chown_cmd = f"chown {shlex.quote(str(username))} {shlex.quote(str(temp_tar))}"
                    chown_exit_code, _, chown_stderr = await self.execute_host_command(
                        dut_id, chown_cmd, timeout=60, use_sudo=True
                    )

                    if chown_exit_code != 0:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "DUTManager",
                            f"Failed to set owner on tar file: {chown_stderr}",
                        )

                    chmod_cmd = f"chmod 600 {shlex.quote(str(temp_tar))}"
                    chmod_exit_code, _, chmod_stderr = await self.execute_host_command(
                        dut_id, chmod_cmd, timeout=60, use_sudo=True
                    )

                    if chmod_exit_code != 0:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "DUTManager",
                            f"Failed to set permissions on tar file: {chmod_stderr}",
                        )

                    # Try to download the tar file
                    success, error_msg = await self._simple_sftp_download(
                        dut_id,
                        temp_tar,
                        destination_directory,
                        max_bytes=max_bytes,
                    )

                    if success:
                        local_tar = os.path.join(
                            destination_directory, os.path.basename(temp_tar)
                        )

                        try:
                            # Extract into a private sibling tree. Direct
                            # extraction cannot safely overwrite zero-byte or
                            # truncated files left by failed SFTP attempts, and
                            # archive members can retain their remote parents.
                            with tempfile.TemporaryDirectory(
                                prefix=".nvdebug_tar_extract_",
                                dir=destination_directory,
                            ) as staging_directory:
                                extraction_result = await run_managed_filesystem_operation(
                                    partial(
                                        extract_tar_archive,
                                        local_tar,
                                        staging_directory,
                                        # Resolve the standard default or an
                                        # explicit operator opt-up inside the
                                        # extractor once.
                                        return_result=True,
                                    )
                                )
                                if extraction_result is None:
                                    raise RuntimeError(
                                        "archive extraction returned no result"
                                    )
                                if extraction_result.dropped_members:
                                    await self.logger.write_to_dut_runtime_log(
                                        dut_id,
                                        "WARNING",
                                        "DUTManager",
                                        "Tar fallback safely omitted unsupported "
                                        "members "
                                        f"(links={extraction_result.dropped_links}, "
                                        "other_special="
                                        f"{extraction_result.dropped_special_members})",
                                    )
                                if extraction_result.regular_files == 0:
                                    await self.logger.write_to_dut_runtime_log(
                                        dut_id,
                                        "WARNING",
                                        "DUTManager",
                                        "Tar fallback archive contained no "
                                        "materialized regular files",
                                    )
                                staging_root = Path(staging_directory)
                                staged_by_basename: Dict[str, List[Path]] = {}
                                if extraction_result.regular_files:
                                    for staged_path in staging_root.rglob("*"):
                                        if staged_path.is_file():
                                            staged_by_basename.setdefault(
                                                staged_path.name,
                                                [],
                                            ).append(staged_path)

                                requested_by_basename: Dict[str, int] = {}
                                for remote_path in failed_paths:
                                    basename = os.path.basename(remote_path)
                                    requested_by_basename[basename] = (
                                        requested_by_basename.get(basename, 0) + 1
                                    )
                                protected_basenames = {
                                    os.path.basename(remote_path)
                                    for remote_path in successful_downloads
                                }

                                # Publish only one-to-one, verified regular
                                # files. os.replace is atomic because staging is
                                # created on the destination filesystem.
                                published = []
                                for remote_path in failed_paths:
                                    basename = os.path.basename(remote_path)
                                    candidates = staged_by_basename.get(basename, [])
                                    if (
                                        requested_by_basename[basename] != 1
                                        or len(candidates) != 1
                                        or basename in protected_basenames
                                        or not self._verify_regular_file(
                                            str(candidates[0])
                                        )
                                    ):
                                        continue
                                    target = Path(destination_directory, basename)
                                    os.replace(candidates[0], target)
                                    if self._verify_regular_file(str(target)):
                                        published.append(remote_path)

                            newly_extracted = []
                            for remote_path in failed_paths[:]:
                                if remote_path in published:
                                    failed_paths.remove(remote_path)
                                    newly_extracted.append(remote_path)
                                    await self.logger.write_to_dut_runtime_log(
                                        dut_id,
                                        "INFO",
                                        "DUTManager",
                                        f"Successfully extracted: {os.path.basename(remote_path)}",
                                    )
                                else:
                                    await self.logger.write_to_dut_runtime_log(
                                        dut_id,
                                        "WARNING",
                                        "DUTManager",
                                        "Tar fallback did not yield one safe, "
                                        "unambiguous file for "
                                        f"{os.path.basename(remote_path)}",
                                    )

                            successful_downloads.extend(newly_extracted)

                        except Exception as e:
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "ERROR",
                                "DUTManager",
                                f"Failed to extract tar: {str(e)}",
                            )
                        finally:
                            try:
                                os.remove(local_tar)
                            except FileNotFoundError:
                                pass
                            except OSError as e:
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "WARNING",
                                    "DUTManager",
                                    f"Failed to remove local tar: {str(e)}",
                                )
                    else:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "DUTManager",
                            f"Failed to download tar: {error_msg}",
                        )

                    # Clean up remote tar
                    await self.execute_host_command(
                        dut_id,
                        f"rm -f -- {shlex.quote(str(temp_tar))}",
                        timeout=60,
                        use_sudo=True,
                    )
                else:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "DUTManager",
                        f"Remote tar creation failed: {stderr}",
                    )
                    if stdout:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "DUTManager",
                            f"Tar command output: {stdout}",
                        )

            # Final status
            if failed_paths:
                error_msg = f"Failed to download files: {', '.join(failed_paths)}"
                await self.logger.write_to_dut_runtime_log(
                    dut_id, "ERROR", "DUTManager", error_msg
                )
                return False, error_msg

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "DUTManager",
                f"Enhanced file transfer completed successfully. Downloaded {len(successful_downloads)} files.",
            )
            return True, ""

        except Exception as error:
            error_msg = f"Unexpected error in enhanced file transfer: {str(error)}"
            await self.logger.write_to_dut_runtime_log(
                dut_id, "ERROR", "DUTManager", error_msg
            )
            return False, error_msg
        finally:
            if remote_transfer_directory is not None:
                await self._cleanup_remote_transfer_directory_shielded(
                    dut_id,
                    remote_transfer_directory,
                )

    async def _copy_local_files_to_destination(
        self,
        dut_id: str,
        sources: List[str],
        destination_directory: str,
        *,
        max_bytes: int = SFTP_DOWNLOAD_DEFAULT_MAX_BYTES,
    ) -> Tuple[bool, str]:
        """
        Copy files locally when running in local mode (no SFTP required).

        The implementation uses ``dut_id``, ``sources``,
        ``destination_directory``, and ``max_bytes`` to copy files locally when
        running in local mode (no SFTP required). Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. Filesystem effects remain confined to the caller-selected paths
        and the owning resource lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            sources: Entries supplied as ``sources`` without transferring
                container ownership.
            destination_directory: filesystem location used as the destination
                for this operation.
            max_bytes: Upper bound enforced for max bytes; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        _validate_sftp_download_limits(
            max_bytes,
            SFTP_DOWNLOAD_READ_CHUNK_BYTES,
        )
        try:
            os.makedirs(destination_directory, exist_ok=True)
        except Exception as e:
            error_msg = (
                f"Failed to create destination directory {destination_directory}: {e}"
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id, "ERROR", "DUTManager", error_msg
            )
            return False, error_msg

        user = getpass.getuser()
        group = grp.getgrgid(os.getgid()).gr_name
        failed_paths = []

        for source in sources:
            try:
                source_metadata = os.lstat(source)
            except FileNotFoundError:
                failed_paths.append(source)
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DUTManager",
                    f"Source file does not exist: {source}",
                )
                continue
            except OSError as error:
                failed_paths.append(source)
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DUTManager",
                    f"Unable to inspect local source {source}: {error}",
                )
                continue

            if (
                not stat.S_ISREG(source_metadata.st_mode)
                or source_metadata.st_nlink < 1
                or source_metadata.st_size > max_bytes
            ):
                failed_paths.append(source)
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DUTManager",
                    f"Local source is not a bounded regular file: {source}",
                )
                continue

            dest_path = os.path.join(destination_directory, os.path.basename(source))
            cmd = f"install -m 0644 -o {shlex.quote(user)} -g {shlex.quote(group)} {shlex.quote(source)} {shlex.quote(dest_path)}"

            exit_code, _, stderr = await self.execute_host_command(
                dut_id, cmd, timeout=60, use_sudo=True
            )
            if exit_code != 0:
                failed_paths.append(source)
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DUTManager",
                    f"Local copy failed for {source}: {stderr}",
                )
            else:
                try:
                    destination_metadata = os.lstat(dest_path)
                except OSError as error:
                    failed_paths.append(source)
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "DUTManager",
                        f"Unable to verify local copy {dest_path}: {error}",
                    )
                    continue
                if (
                    not stat.S_ISREG(destination_metadata.st_mode)
                    or destination_metadata.st_size != source_metadata.st_size
                    or destination_metadata.st_size > max_bytes
                ):
                    failed_paths.append(source)
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "DUTManager",
                        f"Local copy failed bounded verification: {dest_path}",
                    )
                    continue
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "DUTManager",
                    f"Local copy successful: {source} -> {dest_path}",
                )

        if failed_paths:
            return (
                False,
                f"Failed to copy files locally: {', '.join(failed_paths)}",
            )

        return True, ""

    async def _create_connection_with_proxy(
        self,
        dut_id: str,
        use_proxy: bool = True,
    ) -> Tuple[asyncssh.SSHClientConnection, str]:
        """
        Create SSH connection with optional proxy support.

        The implementation uses ``dut_id`` and ``use_proxy`` to create SSH
        connection with optional proxy support. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. It updates ``_owned_proxy_connections`` on the instance as part
        of that state transition. If the function cannot create SSH connection
        with optional proxy support, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            use_proxy: Whether use proxy is enabled or required for this
                operation.

        Returns:
            A tuple containing ``connection`` and ``status text`` in that order.

        Raises:
            ConnectionError: If failed to establish strict SSH proxy connection.
        """
        dut = self.get_dut(dut_id)
        username = dut.credentials.host_username
        password = dut.credentials.host_password

        proxy_client = None
        conn = None

        try:
            if use_proxy and dut.credentials.ssh_proxy_host:
                proxy_client = await self.create_proxy_connection(dut_id)
                if proxy_client is None:
                    raise ConnectionError(
                        "Failed to establish strict SSH proxy connection"
                    )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "DUTManager",
                    "Using proxy connection for file transfer",
                )

            connect_kwargs = self._build_ssh_connect_kwargs(
                host=dut.credentials.host_ip,
                port=dut.credentials.host_ssh_port,
                username=username,
                password=password,
                ssh_key_path=dut.credentials.host_ssh_key_path,
                passwordless=dut.credentials.host_ssh_passwordless,
                connect_timeout=30,
                proxy_client=proxy_client,
                host_key_policy=dut.credentials.ssh_host_key_policy,
                known_hosts_file=dut.credentials.ssh_known_hosts_file,
                host_key_alias=(dut.credentials.host_ip if proxy_client else None),
            )

            conn = await self._connect_raw_ssh_bounded(
                capacity_scope=str(dut_id),
                role="endpoint",
                connect_kwargs=connect_kwargs,
            )
            if proxy_client is not None:
                owned_proxies = getattr(self, "_owned_proxy_connections", None)
                if owned_proxies is None:
                    owned_proxies = {}
                    self._owned_proxy_connections = owned_proxies
                owned_proxies[id(conn)] = proxy_client

            return conn, "asyncssh"

        except BaseException as e:
            await self._close_ssh_connection_chain_after_failure(
                e,
                conn,
                proxy_client,
            )
            if isinstance(e, Exception):
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "DUTManager",
                    f"Failed to create connection: {str(e)}",
                )
            raise

    async def _simple_sftp_download(
        self,
        dut_id: str,
        source: str,
        destination_directory: str,
        use_proxy: bool = True,
        *,
        max_bytes: int = SFTP_DOWNLOAD_DEFAULT_MAX_BYTES,
    ) -> Tuple[bool, str]:
        """
        Bounded SFTP download without retries (used by fallback methods).

        The implementation uses ``dut_id``, ``source``,
        ``destination_directory``, ``use_proxy``, and ``max_bytes`` to bounded
        SFTP download without retries (used by fallback methods). Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            source: Text supplied as source in the format accepted by this
                function.
            destination_directory: filesystem location used as the destination
                for this operation.
            use_proxy: Whether use proxy is enabled or required for this
                operation.
            max_bytes: Upper bound enforced for max bytes; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        try:
            _validate_sftp_download_limits(
                max_bytes,
                SFTP_DOWNLOAD_READ_CHUNK_BYTES,
            )
        except ValueError as error:
            return False, str(error)

        file_name = os.path.basename(source) if isinstance(source, str) else ""
        if not file_name or file_name in (".", ".."):
            return False, "SFTP source must identify one remote file"
        local_path = Path(destination_directory, file_name)
        conn = None
        try:
            conn, _connection_type = await self._create_connection_with_proxy(
                dut_id,
                use_proxy,
            )
            try:
                async with conn.start_sftp_client() as sftp:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "DUTManager",
                        f"Downloading {source} to {local_path}",
                    )
                    transferred_bytes = await _download_sftp_regular_file_bounded(
                        sftp,
                        source,
                        local_path,
                        max_bytes=max_bytes,
                        read_chunk_bytes=SFTP_DOWNLOAD_READ_CHUNK_BYTES,
                    )
            finally:
                await self._close_ssh_connection_chain(conn)

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "DUTManager",
                f"Successfully downloaded and verified {local_path} "
                f"({transferred_bytes} bytes)",
            )
            return True, ""
        except FileNotFoundError:
            error_msg = f"Source file {source} does not exist on remote system"
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "DUTManager",
                error_msg,
            )
            return False, error_msg
        except Exception as error:
            error_msg = f"SFTP download failed: {str(error)}"
            await self.logger.write_to_dut_runtime_log(
                dut_id, "ERROR", "DUTManager", error_msg
            )
            return False, error_msg

    def _verify_regular_file(self, file_path: str) -> bool:
        """
        Verify one path is an existing no-follow regular file.

        Zero-byte files remain valid because this helper proves filesystem
        identity rather than collector-specific content semantics. ``lstat``
        rejects symlinks without following them; archive or structured-artifact
        callers retain responsibility for any non-empty content requirement.

        Args:
            file_path: filesystem location used as the file path for this
                operation.

        Returns:
            Whether ``file_path`` identifies one regular file without following
            a symbolic link.
        """
        try:
            return stat.S_ISREG(os.lstat(file_path).st_mode)
        except OSError:
            return False

    def ssh_client_is_active(self, ssh_client) -> bool:
        """
        Check whether an SSH client is known to be active.

        The implementation uses ``ssh_client`` to check whether an SSH client is
        known to be active. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path.

        Args:
            ssh_client: SSH client consumed while the function attempts to check
                whether an SSH client is known to be active.

        Returns:
            Whether the whether an SSH client is known to be active operation
            succeeds.
        """
        if ssh_client is None:
            return False
        try:
            is_closed = getattr(ssh_client, "is_closed", None)
            return callable(is_closed) and not is_closed()
        except Exception:
            return False

    async def check_ping_status(
        self,
        ip_address: str,
        ssh_pass: bool = False,
        ssh_server_ip: Optional[str] = None,
        ssh_username: Optional[str] = None,
        ssh_password: Optional[str] = None,
        ssh_port: int = 22,
    ) -> bool:
        """
        Try pinging the IP address.

        Some ping implementations do not accept ``--``. The shared argv builder
        rejects an option-like endpoint before either the local subprocess or
        quoted remote command can interpret it.

        Args:
            ip_address: Text supplied as IP address in the format accepted by
                this function.
            ssh_pass: Whether SSH pass is enabled or required for this
                operation.
            ssh_server_ip: Optional SSH server IP; ``None`` selects the
                function's default behavior.
            ssh_username: Optional SSH username; ``None`` selects the function's
                default behavior.
            ssh_password: Sensitive value supplied through the approved input
                boundary and never logged.
            ssh_port: Numeric SSH port used while the operation performs bounded
                accounting.

        Returns:
            Whether the try pinging the IP address operation succeeds.
        """

        ping_option = "-n" if platform.system().lower() == "windows" else "-c"
        network_type = str(self.tool_config.get("IP_NETWORK", "ipv4")).lower()
        network_arg = "-6" if network_type == "ipv6" else "-4"
        try:
            # Some ping implementations do not accept ``--``. The shared
            # argv builder rejects an option-like endpoint before either the
            # local subprocess or quoted remote command can interpret it.
            ping_target = validate_ping_target(str(ip_address))
            ping_command = build_local_cmd(
                ["ping", network_arg, ping_option, "2", "{ip_address}"],
                ip_address=ping_target,
            )
        except (KeyError, TypeError, ValueError):
            await self.logger.log_runtime(
                "ERROR",
                "DUTManager",
                "Ping endpoint is invalid or option-like",
            )
            return False
        password_input: Optional[bytes] = None

        if ssh_pass:
            if not ssh_server_ip or not ssh_username or not ssh_password:
                await self.logger.log_runtime(
                    "ERROR",
                    "DUTManager",
                    "SSH ping requires server IP, username, and password",
                )
                return False
            host_key_options = shlex.split(
                openssh_host_key_options(
                    self.tool_config.get("ssh_host_key_policy", "insecure"),
                    self.tool_config.get("ssh_known_hosts_file"),
                )
            )
            command = [
                "sshpass",
                "-d",
                "0",
                "ssh",
                *host_key_options,
                "-p",
                str(int(ssh_port)),
                "--",
                f"{ssh_username}@{ssh_server_ip}",
                _quote_remote_argv(ping_command),
            ]
            password_input = f"{ssh_password}\n".encode()
        else:
            command = ping_command

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=(asyncio.subprocess.PIPE if password_input is not None else None),
                env=scrubbed_child_environment(),
                start_new_session=os.name == "posix",
            )
            stdout, stderr = await _communicate_subprocess(
                process,
                timeout=30,
                input_data=password_input,
                terminate_process_group=os.name == "posix",
            )

            if process.returncode == 0:
                return True
            else:
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"Ping failed for {ip_address}: {self._process_command_output(stderr)}",
                )
                return False
        except Exception as e:
            await self.logger.log_runtime(
                "ERROR", "DUTManager", f"Ping error for {ip_address}: {e}"
            )
            return False

    def get_info_from_ipmi_output(
        self, ipmi_response: str = None, keyword_phrase: str = None
    ) -> str:
        """
        Returns a response if keyword_phrase is present in the IPMI output.

        The implementation uses ``ipmi_response`` and ``keyword_phrase`` to
        returns a response if keyword_phrase is present in the IPMI output.

        Args:
            ipmi_response: Optional IPMI response; ``None`` selects the
                function's default behavior.
            keyword_phrase: Optional keyword phrase; ``None`` selects the
                function's default behavior.

        Returns:
            The canonical info from IPMI output text.
        """
        if not ipmi_response or not keyword_phrase:
            return ""

        pattern = re.compile(
            rf"\b{re.escape(keyword_phrase)}\s*:\s*([^<>\n]+)", re.IGNORECASE
        )
        match = pattern.search(ipmi_response)
        if match:
            return match.group(1).strip()
        else:
            return ""

    async def check_passwordless_ssh(
        self,
        ip: str,
        username: str,
        timeout: int = 5,
        host_key_policy: str = "insecure",
        known_hosts_file: Optional[str] = None,
    ) -> bool:
        """
        Check if passwordless SSH is set up correctly.

        The implementation uses ``ip``, ``username``, ``timeout``,
        ``host_key_policy``, and ``known_hosts_file`` to check if passwordless
        SSH is set up correctly. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            ip: Text supplied as IP in the format accepted by this function.
            username: Text supplied as username in the format accepted by this
                function.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            host_key_policy: Host key policy governing if passwordless SSH is
                set up correctly.
            known_hosts_file: Optional filesystem location used as the known
                hosts file for this operation.

        Returns:
            Whether the if passwordless SSH is set up correctly operation
            succeeds.
        """
        try:
            connect_kwargs = {
                "host": ip,
                "username": username,
                "connect_timeout": timeout,
                **asyncssh_host_key_options(host_key_policy, known_hosts_file),
            }
            conn = await asyncio.wait_for(
                self._connect_raw_ssh_bounded(
                    capacity_scope="probe:" + normalize_ssh_endpoint_host(ip),
                    role="endpoint",
                    connect_kwargs=connect_kwargs,
                    capacity_wait_timeout=timeout,
                ),
                timeout=timeout,
            )
            await self._close_ssh_connection_chain(
                conn,
                close_timeout=min(
                    float(timeout),
                    SSH_CONNECTION_CLOSE_TIMEOUT_SECONDS,
                ),
            )
            return True
        except Exception:
            return False

    async def execute_bash_command(
        self,
        command: Union[str, List[str]],
        timeout: Optional[float] = None,
        use_shell: bool = False,
        input_val: Optional[str] = None,
        environment: Optional[dict] = None,
        use_sudo: bool = False,
        sudo_password: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """
        Spawns a subprocess to run a command.

        The implementation uses ``command``, ``timeout``, ``use_shell``,
        ``input_val``, and ``environment`` to spawns a subprocess to run a
        command. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            command: Entries supplied as ``command`` without transferring
                container ownership.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            use_shell: Whether use shell is enabled or required for this
                operation.
            input_val: Optional input val; ``None`` selects the function's
                default behavior.
            environment: Optional environment; ``None`` selects the function's
                default behavior.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            sudo_password: Sensitive value supplied through the approved input
                boundary and never logged.

        Returns:
            A tuple containing the exit status, standard output, and standard
            error.
        """
        try:
            sudo_input = input_val
            if use_sudo:
                command, password_stdin = build_privileged_command_argv(
                    command,
                    password_available=bool(sudo_password),
                    use_shell=use_shell,
                    already_root=(
                        os.name == "posix"
                        and hasattr(os, "geteuid")
                        and os.geteuid() == 0
                    ),
                )
                if password_stdin:
                    validate_password_stdin_line(
                        sudo_password, credential_name="sudo password"
                    )
                    sudo_input = f"{sudo_password}\n{input_val or ''}"
                cmd = command
            elif not use_shell and not isinstance(command, list):
                cmd = shlex.split(command)
            else:
                cmd = command

            # Prepare environment
            env = scrubbed_child_environment(environment)
            if use_sudo:
                env["PATH"] = TRUSTED_PRIVILEGED_PATH

            # Create subprocess
            if use_sudo:
                terminate_process_group = os.name == "posix"
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    stdin=asyncio.subprocess.PIPE if sudo_input else None,
                    env=env,
                    start_new_session=terminate_process_group,
                )
            elif use_shell:
                terminate_process_group = os.name == "posix"
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    stdin=asyncio.subprocess.PIPE if sudo_input else None,
                    env=env,
                    start_new_session=terminate_process_group,
                )
            else:
                terminate_process_group = os.name == "posix"
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    stdin=asyncio.subprocess.PIPE if sudo_input else None,
                    env=env,
                    start_new_session=terminate_process_group,
                )

            # Wait for completion with timeout
            try:
                if sudo_input:
                    stdout, stderr = await _communicate_subprocess(
                        process,
                        timeout=timeout,
                        input_data=sudo_input.encode(),
                        terminate_process_group=terminate_process_group,
                    )
                else:
                    stdout, stderr = await _communicate_subprocess(
                        process,
                        timeout=timeout,
                        terminate_process_group=terminate_process_group,
                    )
            except asyncio.TimeoutError:
                return -1, "", f"Command timed out after {timeout} seconds"

            # Decode the output using robust method
            stdout_text = self._process_command_output(stdout)
            stderr_text = self._process_command_output(stderr)

            return process.returncode, stdout_text, stderr_text

        except Exception as e:
            return -1, "", f"Error: {e}"

    def get_prop_from_response(
        self, response_dict: dict, property_string: str
    ) -> Tuple[bool, Any]:
        """
        Extracts a property from the response dict and returns it.

        Returns prop_present = False if the property was not found

        Args:
            response_dict: Mapping supplying fields for extracts a property from
                the response dict and returns it.
            property_string: Text supplied as property string in the format
                accepted by this function.

        Returns:
            A tuple containing ``status flag`` and ``returned value`` in that
            order.
        """
        if not response_dict or not property_string:
            return False, None

        property_value = None
        prop_present = True
        property_list = list(filter(None, re.split(r"{|}", property_string)))
        curr_dict = response_dict

        for prop in property_list:
            # Check if the property is supposed to be a list
            prop_elements = list(filter(None, re.split(r"\[|\]", prop)))
            if prop_elements[0] in curr_dict:
                curr_dict = curr_dict.get(prop_elements[0])
            elif isinstance(curr_dict, list):
                property_value = []
                for item in curr_dict:  # item should be a dictionary
                    if isinstance(item, dict) and prop_elements[0] in item:
                        property_value.append(item.get(prop_elements[0]))
                    else:
                        property_value.append(None)
                return prop_present, property_value
            else:
                prop_present = False
                break

            # Handle array indexing if specified
            if len(prop_elements) > 1:
                try:
                    index = int(prop_elements[1])
                    if isinstance(curr_dict, list) and 0 <= index < len(curr_dict):
                        curr_dict = curr_dict[index]
                    else:
                        prop_present = False
                        break
                except (ValueError, IndexError):
                    prop_present = False
                    break

        property_value = curr_dict
        return prop_present, property_value

    async def get_preflight_results(self, dut_id: str) -> Dict[str, Any]:
        """
        Get preflight results for a specific DUT.

        After applying local validation, the function forwards ``dut_id`` to
        ``getattr`` and preserves its return and exception contract. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing preflight results.
        """
        dut = self.get_dut(dut_id)
        return getattr(dut, "preflight_results", {})

    async def gather_platform_info(
        self, dut_id: str, preflight_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """
        Gather platform information for a DUT.

        The implementation uses ``dut_id`` and ``preflight_results`` to gather
        platform information for a DUT. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.

        Returns:
            The validated ``platform_info``.
        """
        dut = self.get_dut(dut_id)

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"Starting platform detection for DUT: {dut_id}",
        )

        # Create platform detection service
        baseboard_manager = self._get_baseboard_manager()
        platform_service = PlatformDetectionService(
            self, self.logger, baseboard_manager
        )
        await platform_service.async_init()

        # Gather platform info
        async with redfish_controller_scope(
            dut, metadata_controller(preflight_results)
        ):
            platform_info = await platform_service.gather_platform_info(
                dut_id, preflight_results
            )

        await self.logger.log_runtime(
            "INFO",
            "DUTManager",
            f"Platform detection result for DUT {dut_id}: {platform_info}",
        )

        # Store in DUT object
        dut.platform_info = platform_info

        return platform_info

    async def get_platform_info(self, dut_id: str) -> Optional[Dict[str, str]]:
        """
        Get platform information for a DUT (returns cached if available).

        The implementation uses ``dut_id`` to get platform information for a DUT
        (returns cached if available). Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing platform info, or ``None`` when the requested
            value is unavailable.
        """
        dut = self.get_dut(dut_id)

        if dut.platform_info is None:
            # Gather platform info if not already cached
            dut.platform_info = await self.gather_platform_info(dut_id)

        return dut.platform_info

    async def detect_platform_and_baseboard(
        self,
        dut_id: str,
        preflight_results: Optional[Dict[str, Any]] = None,
        non_interactive: bool = False,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Detect platform and baseboard type from the DUT.

        After applying local validation, the function forwards ``dut_id``,
        ``preflight_results``, and ``non_interactive`` to
        ``detection_service.detect_platform_and_baseboard`` and preserves its
        return and exception contract. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.
            non_interactive: Whether non interactive is enabled or required for
                this operation.

        Returns:
            A tuple containing the fields that represent platform and baseboard.
        """
        detection_service = AutoDetectionService(
            self, self.logger, self.sanitized_console
        )
        await detection_service.async_init()
        return await detection_service.detect_platform_and_baseboard(
            dut_id, preflight_results, non_interactive
        )

    async def run_dynamic_discovery(
        self, dut_id: str, preflight_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Run dynamic discovery for Redfish resources on a DUT.

        After applying local validation, the function forwards ``dut_id`` and
        ``preflight_results`` to ``discovery.discover_all_resources`` and
        preserves its return and exception contract. Terminal status is emitted
        only after dynamic discovery for Redfish resources on a DUT and its
        owned cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.

        Returns:
            A mapping containing run dynamic discovery.
        """
        discovery = RedfishDiscoveryAdapter(self._get_discovery_service)
        controller = metadata_controller(preflight_results)
        dut = self.get_dut(dut_id) if controller != "default" else None
        async with redfish_controller_scope(dut, controller):
            return await discovery.discover_all_resources(dut_id, preflight_results)

    async def get_resource_members(self, dut_id: str, resource_type: str) -> List[str]:
        """
        Get cached resource members for a specific resource type.

        After applying local validation, the function forwards ``dut_id`` and
        ``resource_type`` to ``discovery.get_resource_members`` and preserves
        its return and exception contract. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            resource_type: Text supplied as resource type in the format accepted
                by this function.

        Returns:
            The resource members returned in operation-defined order.
        """
        discovery = RedfishDiscoveryAdapter(self._get_discovery_service)
        return await discovery.get_resource_members(dut_id, resource_type)

    async def get_resource_member_snapshot(
        self, dut_id: str, resource_type: str
    ) -> Dict[str, Any]:
        """
        Get cached resource members with their completeness metadata.

        After applying local validation, the function forwards ``dut_id`` and
        ``resource_type`` to ``discovery_service.get_resource_member_snapshot``
        and preserves its return and exception contract. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            resource_type: Text supplied as resource type in the format accepted
                by this function.

        Returns:
            A mapping containing resource member snapshot.
        """

        discovery_service = self._get_discovery_service()
        return await discovery_service.get_resource_member_snapshot(
            dut_id, resource_type
        )

    async def get_resource_details(
        self, dut_id: str, resource_type: str
    ) -> Dict[str, Any]:
        """
        Get cached resource details for a specific resource type.

        After applying local validation, the function forwards ``dut_id`` and
        ``resource_type`` to ``discovery.get_resource_details`` and preserves
        its return and exception contract. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            resource_type: Text supplied as resource type in the format accepted
                by this function.

        Returns:
            A mapping containing resource details.
        """
        discovery = RedfishDiscoveryAdapter(self._get_discovery_service)
        return await discovery.get_resource_details(dut_id, resource_type)

    async def get_discovery_results(self, dut_id: str) -> Optional[Dict[str, Any]]:
        """
        Get cached discovery results for a DUT.

        After applying local validation, the function forwards ``dut_id`` to
        ``discovery.get_discovery_results`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing discovery results, or ``None`` when the
            requested value is unavailable.
        """
        discovery = RedfishDiscoveryAdapter(self._get_discovery_service)
        return await discovery.get_discovery_results(dut_id)

    async def get_firmware_inventory(self, dut_id: str) -> Optional[Dict[str, Any]]:
        """
        Get cached firmware inventory for a DUT.

        After applying local validation, the function forwards ``dut_id`` to
        ``discovery.get_firmware_inventory`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing firmware inventory, or ``None`` when the
            requested value is unavailable.
        """
        discovery = RedfishDiscoveryAdapter(self._get_discovery_service)
        return await discovery.get_firmware_inventory(dut_id)

    async def cleanup(self) -> None:
        """
        Close dependent sessions before destroying their forwarding transports.

        Redfish logout and HMC teardown can still need pooled SSH connections or
        a proxy route. Drain those owners first, then close pooled SSH and finally
        the proxy tunnels. Every phase is attempted after errors or interruption;
        retained resources and failed diagnostics still prevent successful cleanup.
        Remove private staging only after resource teardown has been attempted.

        Raises:
            RuntimeError: If HMC cleanup returned incomplete success evidence;
                or the function cannot cleanup DUT manager resources safely.
            BaseException: If a delegated failure occurs while the function
                attempts to cleanup DUT manager resources.
        """
        cleanup_errors: List[Tuple[str, BaseException]] = []

        async def record_cleanup_error(
            cleanup_name: str,
            error: BaseException,
        ) -> None:
            """
            Record cleanup error.

            The implementation uses ``cleanup_name`` and ``error`` to record
            cleanup error. Owned asynchronous work is awaited before return, so
            completion does not leave an unobserved task behind.

            Args:
                cleanup_name: Stable cleanup name used for lookup and
                    operator-facing diagnostics.
                error: Exception or failure detail associated with the
                    operation.
            """
            cleanup_errors.append((cleanup_name, error))
            try:
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"Error cleaning up {cleanup_name}: {error}",
                )
            except BaseException as logging_error:
                cleanup_errors.append(
                    (f"{cleanup_name} failure logging", logging_error)
                )

        try:
            await self.close_redfish_sessions()
        except BaseException as error:
            await record_cleanup_error("Redfish sessions", error)

        # Close any other sessions that might be open
        for dut_id, dut in self.duts.items():
            # Close any other sessions the DUT might have
            if hasattr(dut, "session") and dut.session:
                try:
                    await dut.session.close()
                    dut.session = None
                except BaseException as error:
                    await record_cleanup_error(
                        f"session for {dut_id}",
                        error,
                    )

            # Close any redfish sessions
            if hasattr(dut, "redfish_session") and dut.redfish_session:
                try:
                    await dut.redfish_session.close()
                    dut.redfish_session = None
                except BaseException as error:
                    await record_cleanup_error(
                        f"Redfish session for {dut_id}",
                        error,
                    )

            # ✅ Clean up HMC port forwarding tunnels
            if hasattr(dut, "hmc_service") and dut.hmc_service:
                try:
                    hmc_cleanup_result = await dut.hmc_service.cleanup_hmc_access(
                        dut_id
                    )
                    if hmc_cleanup_result is not True:
                        raise RuntimeError(
                            "HMC cleanup returned incomplete success evidence"
                        )
                    await self.logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Cleaned up HMC port forwarding for {dut_id}",
                    )
                except BaseException as error:
                    await record_cleanup_error(
                        f"HMC port forwarding for {dut_id}",
                        error,
                    )

        # Release shared routes only after their dependent owners have drained.
        for cleanup_name, cleanup_method in (
            ("pooled SSH connections", self.close_all_ssh_connections),
            ("SSH proxy tunnels", self.cleanup_all_ssh_proxy_tunnels),
        ):
            try:
                await cleanup_method()
            except BaseException as error:
                await record_cleanup_error(cleanup_name, error)

        # Drain pending log tasks from the baseboard manager
        if self._baseboard_manager is not None:
            try:
                await self._baseboard_manager.drain_pending_logs()
            except BaseException as error:
                await record_cleanup_error("baseboard log tasks", error)

        spool_dir = getattr(self, "_redfish_spool_dir", None)
        if spool_dir is not None:
            try:
                shutil.rmtree(spool_dir)
            except BaseException as error:
                await record_cleanup_error(
                    "private Redfish response staging directory",
                    error,
                )
            else:
                self._redfish_spool_dir = None

        credential_root = getattr(self, "_ipmi_credential_root", None)
        if credential_root is not None:
            try:
                shutil.rmtree(credential_root)
            except BaseException as error:
                await record_cleanup_error(
                    "private IPMI credential staging directory",
                    error,
                )
            else:
                self._ipmi_credential_root = None

        if cleanup_errors:
            failed_resources = ", ".join(
                f"{name} ({error})" if isinstance(error, _RedfishCleanupError) else name
                for name, error in cleanup_errors
            )
            authoritative = _authoritative_cleanup_error(
                [error for _name, error in cleanup_errors]
            )
            if isinstance(
                authoritative,
                (asyncio.CancelledError, KeyboardInterrupt, SystemExit),
            ):
                raise authoritative
            raise RuntimeError(
                "DUT manager cleanup did not complete: " + failed_resources
            ) from authoritative

    async def _ensure_connection(
        self, dut_id: str, connection_type: str, test_method_name: str
    ) -> Tuple[bool, str]:
        """
        Ensure connection.

        Special handling for IPMI in local mode without BMC IP.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            connection_type: Text supplied as connection type in the format
                accepted by this function.
            test_method_name: Stable test method name used for lookup and
                operator-facing diagnostics.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        dut = self.get_dut(dut_id)

        # Special handling for IPMI in local mode without BMC IP
        if connection_type == "ipmi" and dut.config and dut.config.get("local", False):
            has_bmc_ip = dut.credentials and dut.credentials.bmc_ip
            if not has_bmc_ip:
                await self.logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    "IPMI connection check skipped for local mode without BMC IP - will execute locally via sudo",
                )
                return (
                    True,
                    "Local mode without BMC IP - IPMI will execute locally via sudo",
                )

        # Get the current connection state
        connection_state_attr = f"{connection_type}_connected"
        if not hasattr(dut.connection_state, connection_state_attr):
            return False, f"Invalid connection type: {connection_type}"

        is_connected = getattr(dut.connection_state, connection_state_attr)

        proxy_service = getattr(dut, "ssh_proxy_service", None)
        has_tracked_proxy = getattr(proxy_service, "has_tracked_tunnels", None)
        if (
            connection_type == "redfish"
            and not dut.credentials.ssh_proxy_host
            and callable(has_tracked_proxy)
            and has_tracked_proxy(dut_id) is True
        ):
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                "SSH proxy configuration was removed; cleaning exact-owned "
                "routes before switching Redfish to direct access",
            )
            cleanup_ok = await proxy_service.cleanup_tunnels(dut_id)
            if not cleanup_ok:
                return (
                    False,
                    "Redfish proxy removal cleanup did not complete; refusing "
                    "to switch transport",
                )
            dut.connection_state.set_redfish_connected(False, dut_id)
            await dut.close_redfish_session()
            dut.ssh_proxy_tunnel_ports = {}
            is_connected = False

        if (
            is_connected
            and connection_type == "redfish"
            and dut.credentials.ssh_proxy_host
        ):
            try:
                dut.get_redfish_connection_info()
            except RuntimeError as exc:
                await self.logger.log_runtime(
                    "WARNING",
                    "DUTManager",
                    f"Discarding stale Redfish connection state: {exc}",
                )
                dut.connection_state.set_redfish_connected(False, dut_id)
                await dut.close_redfish_session()
                is_connected = False

        if is_connected:
            return (
                True,
                f"{connection_type.capitalize()} connection is already established",
            )

        # Try to re-establish the connection
        await self.logger.log_runtime(
            "DEBUG",
            "DUTManager",
            f"{connection_type.capitalize()} connection state shows as disconnected, attempting to re-establish connection",
        )

        # Call the test method dynamically
        test_method = getattr(dut, test_method_name)
        success, message = await test_method()

        if not success:
            await self.logger.log_runtime(
                "ERROR",
                "DUTManager",
                f"Failed to re-establish {connection_type} connection: {message}",
            )
            return (
                False,
                f"{connection_type.capitalize()} not connected: {message}",
            )
        else:
            await self.logger.log_runtime(
                "INFO",
                "DUTManager",
                f"Successfully re-established {connection_type} connection: {message}",
            )
            return (
                True,
                f"{connection_type.capitalize()} connection re-established",
            )
