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
Host Service - Handles all Host-related collector operations.

Provides collectors for host OS-based log collection including system logs,
diagnostic commands, and file collection via SSH or local access.
"""

import asyncio
import base64
import bz2
import errno
import gzip
import hashlib
import json
import logging
import lzma
import math
import os
import re
import secrets
import shlex
import shutil
import stat
import tarfile
import tempfile
import threading
import time
import zipfile
import zlib
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from datetime import datetime
from fnmatch import fnmatchcase
from functools import partial
from pathlib import Path, PurePosixPath
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Tuple,
)

from ..core.collector_outcome import CollectorFailureCategory
from ..core.finalization_receipt import (
    capture_owned_awaitable,
    drain_owned_tasks,
    select_authoritative_exception,
)
from ..core.host_ssh_pool import HOST_SSH_SAFE_CONNECT_RETRIES
from ..utils.archive_member_policy import (
    MemberNamePolicyError,
    validate_distributable_member_name,
)
from ..utils.bounded_archive import (
    ArchiveLimits,
    ArchivePolicyError,
    archive_creation_limits_from_runtime_boundaries,
    collection_archive_size_advisory,
    extract_tar_archive,
    inspect_tar_archive_metadata,
    read_regular_file_bounded,
    resolve_archive_creation_limits,
    resolve_archive_limits,
    resolve_collection_archive_limits,
    validate_open_tar_stream_for_creation,
    validate_tar_archive,
    validate_xz_file,
    validate_zip_archive,
)
from ..utils.collector_attempt_policy import (
    CollectorAttemptPolicyError,
    EnforcedCollectorAttemptPolicy,
    attempt_record,
    build_attempt_policy_receipt,
    not_attempted_record,
    project_advanced_managed_receipt,
    project_attempt_policy,
    resolve_enforced_attempt_policy,
    resolve_enforced_attempt_policy_definition,
    run_first_success_attempt_policy,
)
from ..utils.collector_budget import (
    MAX_MANAGED_ARTIFACT_BYTES as _MAX_MANAGED_ARTIFACT_BYTES,
)
from ..utils.collector_budget import (
    ResolvedCollectorBudget,
)
from ..utils.command_result_ledger import (
    MAX_COMMAND_RESULT_ENTRIES,
    CommandResultCapture,
)
from ..utils.command_safety import (
    TRUSTED_POSIX_SHELL_PATH,
    TRUSTED_PRIVILEGED_PATH,
    build_remote_cmd,
    quote_arg,
)
from ..utils.device_discovery import bounded_device_matches as _bounded_device_matches
from ..utils.device_discovery import (
    safe_remote_output_component as _safe_remote_output_component,
)
from ..utils.filesystem_identity import directory_security_identity
from ..utils.managed_filesystem import (
    run_managed_filesystem_operation as _run_managed_filesystem_operation,
)
from ..utils.managed_host_command import (
    ManagedHostCleanupStatus,
    ManagedHostCommandConfigurationError,
    ManagedHostCommandOutcome,
    ManagedHostCommandResult,
    ManagedRemoteExecutorTimeout,
    run_managed_host_command,
)
from ..utils.runtime_boundary_profile import (
    RUNTIME_BOUNDARIES_KEY,
    runtime_boundary_value,
)
from ..utils.streaming import (
    format_host_stream_timestamp,
    normalize_stream_window,
)
from ..utils.tar_utils import (
    TRUSTED_REMOTE_TAR_COMMAND,
    build_link_safe_tar_create_command,
)
from ..utils.temp_dir_config import get_tool_temp_dir, local_temp_dir
from .base_service import BaseService

logger = logging.getLogger(__name__)

_HOST_STREAM_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: UTC)?\Z")
_DEFAULT_COMPOSITE_ARTIFACT_MAX_BYTES = 2 * 1024 * 1024 * 1024
_HARD_COMPOSITE_ARTIFACT_MAX_BYTES = 256 * 1024 * 1024 * 1024
_DEFAULT_HOST_ARTIFACT_MAX_BYTES = _DEFAULT_COMPOSITE_ARTIFACT_MAX_BYTES
_HARD_HOST_ARTIFACT_MAX_BYTES = _HARD_COMPOSITE_ARTIFACT_MAX_BYTES
_MAX_ADVANCED_TEXT_MATERIALIZATION_BYTES = 16 * 1024 * 1024
_COMPOSITE_COPY_CHUNK_BYTES = 1024 * 1024
_REMOTE_STAGING_COMMAND_TIMEOUT_SECONDS = 30
_REMOTE_STAGING_OUTER_TIMEOUT_GRACE_SECONDS = 5.0
_REMOTE_SNAPSHOT_MANAGED_CLEANUP_TIMEOUT_SECONDS = 30.0
_MANAGED_HOST_STDIN_COMMAND = shlex.join([TRUSTED_POSIX_SHELL_PATH, "-s"])
_REMOTE_STAGING_DIR_MODE = "0700"
_REMOTE_STAGING_FILE_MODE = "0600"
_MAX_REMOTE_STAGING_FILES = 256
_HOST_OVERSIZE_POLICIES = frozenset({"reject", "tail_snapshot"})
_BOUNDED_SNAPSHOT_STDERR_BYTES = 64 * 1024
_BOUNDED_SNAPSHOT_RECEIPT_RE = re.compile(
    r"\ANVDEBUG_BOUNDED_SNAPSHOT_V1 "
    r"raw_bytes=(?P<raw_bytes>[0-9]+) "
    r"collected_bytes=(?P<collected_bytes>[0-9]+) "
    r"omitted_bytes=(?P<omitted_bytes>[0-9]+)\n?\Z"
)
_BOUNDED_SNAPSHOT_EVIDENCE_DIRECTORY = "diagnostic"
_BOUNDED_SNAPSHOT_EVIDENCE_SUFFIX = "_bounded_snapshot_evidence.json"
_MAX_BOUNDED_SNAPSHOT_EVIDENCE_ENTRIES = _MAX_REMOTE_STAGING_FILES
_MAX_BOUNDED_SNAPSHOT_EVIDENCE_BYTES = 512 * 1024
_MAX_BOUNDED_SNAPSHOT_SOURCE_PATH_BYTES = 4096
_MAX_BOUNDED_SNAPSHOT_ARTIFACT_REFERENCE_BYTES = 1024
_BOUNDED_EVIDENCE_CANCELLATION_RECEIPT_ATTRIBUTE = (
    "_nvdebug_bounded_evidence_publication_receipt"
)
_GUARDED_PSEUDO_FILE_ALLOWED_ROOTS = (
    PurePosixPath("/sys"),
    PurePosixPath("/proc/sys"),
)
_GUARDED_PSEUDO_FILE_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_GUARDED_PSEUDO_FILE_RECEIPT = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json\Z")
_GUARDED_PSEUDO_FILE_VALUE = re.compile(r"\A[ -~]{1,128}\Z")
_GUARDED_PSEUDO_FILE_MAX_READ_PATHS = 32
_GUARDED_PSEUDO_FILE_MAX_TRANSACTIONS = 16
_GUARDED_PSEUDO_FILE_MAX_WRITES = 32
_MAX_DEVICE_COLLECTION_CONCURRENCY = 16


@dataclass(frozen=True)
class _GuardedPseudoFileWrite:
    """
    Describe one bounded pseudo-file write.

    Keeping the commit marker beside the normalized node and value lets the
    command builder remain independent of any collector or platform recipe.

    Attributes:
        node: Safe direct-child node name beneath the validated interface root.
        value: Bounded printable scalar written without shell evaluation.
        commit: Whether this is the transaction's irreversible final write.
    """

    node: str
    value: str
    commit: bool


@dataclass(frozen=True)
class _GuardedPseudoFileTransaction:
    """
    Hold one ordered pseudo-file transaction.

    Validation creates this immutable representation only after confirming
    that exactly one commit write is present and that it is the final write.

    Attributes:
        label: Stable catalog label used in logs and receipts.
        writes: Ordered writes whose single commit entry is always last.
    """

    label: str
    writes: Tuple[_GuardedPseudoFileWrite, ...]


@dataclass(frozen=True)
class _GuardedPseudoFileRecipe:
    """
    Hold one validated catalog-authored pseudo-file recipe.

    The record separates governed catalog data from the reusable execution
    policy so callers cannot bypass validation while constructing commands.

    Attributes:
        transaction_id: Stable identifier tying evidence to catalog intent.
        root_path: Canonical absolute interface directory under a safe prefix.
        required_read_nodes: Direct-child nodes that preflight must read.
        transactions: Ordered, non-retrying transaction definitions.
        receipt_file: Safe local artifact basename for bounded evidence.
        command_timeout_seconds: Per-command transport and execution deadline.
        post_transaction_settle_seconds: Delay after any attempted commit before
            the next ordered collector may start.
    """

    transaction_id: str
    root_path: PurePosixPath
    required_read_nodes: Tuple[str, ...]
    transactions: Tuple[_GuardedPseudoFileTransaction, ...]
    receipt_file: str
    command_timeout_seconds: int
    post_transaction_settle_seconds: int


def _validated_guarded_pseudo_file_node(value: Any, field_name: str) -> str:
    """
    Return one safe direct-child pseudo-file node name.

    Nested paths are deliberately rejected because root containment is
    established once and every configured node must remain its direct child.

    Args:
        value: Candidate catalog value to validate without shell evaluation.
        field_name: Stable field name used in configuration errors.

    Returns:
        The validated node name.

    Raises:
        ValueError: If the value is empty, nested, traversal-bearing, or
            otherwise outside the bounded identifier grammar.
    """

    if (
        not isinstance(value, str)
        or _GUARDED_PSEUDO_FILE_IDENTIFIER.fullmatch(value) is None
    ):
        raise ValueError(
            f"guarded pseudo-file {field_name} must be a safe direct-child name"
        )
    return value


def _validated_guarded_pseudo_file_value(value: Any) -> str:
    """
    Return one bounded printable scalar for a pseudo-file write.

    The accepted grammar is intentionally data-only. Shell quoting remains a
    second boundary applied later when the remote command is assembled.

    Args:
        value: Catalog scalar that will be quoted as data before execution.

    Returns:
        The validated string representation.

    Raises:
        ValueError: If the value is boolean, structured, blank, padded, or
            contains control or non-ASCII text.
    """

    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("guarded pseudo-file values must be strings or integers")
    normalized = str(value)
    if (
        normalized != normalized.strip()
        or _GUARDED_PSEUDO_FILE_VALUE.fullmatch(normalized) is None
    ):
        raise ValueError("guarded pseudo-file value is not a bounded scalar")
    return normalized


def _resolve_guarded_pseudo_file_recipe(
    values: Mapping[str, Any],
) -> _GuardedPseudoFileRecipe:
    """
    Validate a reusable, catalog-authored pseudo-file transaction recipe.

    Platform-specific paths, values, and transaction labels remain in the
    catalog. This source boundary supplies only generic path containment,
    scalar quoting, finite cardinality, one-attempt execution, and the rule
    that each transaction's irreversible commit write is last.

    Args:
        values: Hook parameters supplied by a collector definition.

    Returns:
        An immutable recipe safe for remote command construction.

    Raises:
        ValueError: If any path, scalar, timeout, or transaction is unsafe or
            incomplete.
    """

    transaction_id = values.get("transaction_id")
    if (
        not isinstance(transaction_id, str)
        or _GUARDED_PSEUDO_FILE_IDENTIFIER.fullmatch(transaction_id) is None
    ):
        raise ValueError(
            "guarded pseudo-file transaction_id must be a bounded identifier"
        )

    raw_root = values.get("root_path")
    if not isinstance(raw_root, str) or "\x00" in raw_root:
        raise ValueError("guarded pseudo-file root_path must be an absolute path")
    root_path = PurePosixPath(raw_root)
    within_allowed_root = any(
        root_path != allowed and root_path.is_relative_to(allowed)
        for allowed in _GUARDED_PSEUDO_FILE_ALLOWED_ROOTS
    )
    if (
        not root_path.is_absolute()
        or raw_root != str(root_path)
        or ".." in root_path.parts
        or not within_allowed_root
        or len(raw_root) > 512
    ):
        raise ValueError("guarded pseudo-file root_path is outside safe prefixes")

    raw_read_nodes = values.get("required_read_nodes", [])
    if (
        not isinstance(raw_read_nodes, list)
        or len(raw_read_nodes) > _GUARDED_PSEUDO_FILE_MAX_READ_PATHS
    ):
        raise ValueError("guarded pseudo-file required_read_nodes is not bounded")
    required_read_nodes = tuple(
        _validated_guarded_pseudo_file_node(node, "read node")
        for node in raw_read_nodes
    )
    if len(set(required_read_nodes)) != len(required_read_nodes):
        raise ValueError("guarded pseudo-file read nodes must be unique")

    raw_transactions = values.get("transactions")
    if (
        not isinstance(raw_transactions, list)
        or not raw_transactions
        or len(raw_transactions) > _GUARDED_PSEUDO_FILE_MAX_TRANSACTIONS
    ):
        raise ValueError(
            "guarded pseudo-file transactions must contain one to sixteen entries"
        )
    transactions: List[_GuardedPseudoFileTransaction] = []
    seen_labels = set()
    for raw_transaction in raw_transactions:
        if not isinstance(raw_transaction, Mapping):
            raise ValueError("guarded pseudo-file transaction must be a mapping")
        label = _validated_guarded_pseudo_file_node(
            raw_transaction.get("label"), "transaction label"
        )
        if label in seen_labels:
            raise ValueError("guarded pseudo-file transaction labels must be unique")
        seen_labels.add(label)

        raw_writes = raw_transaction.get("writes")
        if (
            not isinstance(raw_writes, list)
            or not raw_writes
            or len(raw_writes) > _GUARDED_PSEUDO_FILE_MAX_WRITES
        ):
            raise ValueError(
                "guarded pseudo-file writes must contain one to thirty-two entries"
            )
        writes: List[_GuardedPseudoFileWrite] = []
        seen_nodes = set()
        for raw_write in raw_writes:
            if not isinstance(raw_write, Mapping):
                raise ValueError("guarded pseudo-file write must be a mapping")
            node = _validated_guarded_pseudo_file_node(
                raw_write.get("node"), "write node"
            )
            if node in seen_nodes:
                raise ValueError(
                    "guarded pseudo-file write nodes must be unique per transaction"
                )
            seen_nodes.add(node)
            commit = raw_write.get("commit", False)
            if not isinstance(commit, bool):
                raise ValueError("guarded pseudo-file commit markers must be boolean")
            writes.append(
                _GuardedPseudoFileWrite(
                    node=node,
                    value=_validated_guarded_pseudo_file_value(raw_write.get("value")),
                    commit=commit,
                )
            )
        if not writes[-1].commit or any(write.commit for write in writes[:-1]):
            raise ValueError(
                "guarded pseudo-file transaction requires one final commit write"
            )
        transactions.append(
            _GuardedPseudoFileTransaction(label=label, writes=tuple(writes))
        )

    receipt_file = values.get("receipt_file", "transaction_receipt.json")
    if (
        not isinstance(receipt_file, str)
        or _GUARDED_PSEUDO_FILE_RECEIPT.fullmatch(receipt_file) is None
    ):
        raise ValueError("guarded pseudo-file receipt_file must be a safe JSON name")

    command_timeout = values.get("command_timeout_seconds", 30)
    if (
        not isinstance(command_timeout, int)
        or isinstance(command_timeout, bool)
        or command_timeout < 1
        or command_timeout > 120
    ):
        raise ValueError(
            "guarded pseudo-file command timeout must be an integer from 1 to 120"
        )
    settle_seconds = values.get("post_transaction_settle_seconds", 0)
    if (
        not isinstance(settle_seconds, int)
        or isinstance(settle_seconds, bool)
        or settle_seconds < 0
        or settle_seconds > 300
    ):
        raise ValueError(
            "guarded pseudo-file settle delay must be an integer from 0 to 300"
        )
    if values.get("use_sudo") is not True:
        raise ValueError(
            "guarded pseudo-file transactions require the governed sudo boundary"
        )

    return _GuardedPseudoFileRecipe(
        transaction_id=transaction_id,
        root_path=root_path,
        required_read_nodes=required_read_nodes,
        transactions=tuple(transactions),
        receipt_file=receipt_file,
        command_timeout_seconds=command_timeout,
        post_transaction_settle_seconds=settle_seconds,
    )


def _guarded_pseudo_file_recipe_sha256(recipe: _GuardedPseudoFileRecipe) -> str:
    """
    Return a deterministic digest of one normalized transaction recipe.

    Receipts expose this digest instead of raw values, binding evidence to the
    selected recipe without repeating potentially sensitive catalog content.

    Args:
        recipe: Validated recipe whose catalog values are bound to the receipt.

    Returns:
        Lowercase SHA-256 text covering paths, values, order, deadline, and
        commit marks.
    """

    normalized = {
        "transaction_id": recipe.transaction_id,
        "root_path": str(recipe.root_path),
        "required_read_nodes": list(recipe.required_read_nodes),
        "command_timeout_seconds": recipe.command_timeout_seconds,
        "post_transaction_settle_seconds": (recipe.post_transaction_settle_seconds),
        "transactions": [
            {
                "label": transaction.label,
                "writes": [
                    {
                        "node": write.node,
                        "value": write.value,
                        "commit": write.commit,
                    }
                    for write in transaction.writes
                ],
            }
            for transaction in recipe.transactions
        ],
    }
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _build_guarded_pseudo_file_preflight_command(
    recipe: _GuardedPseudoFileRecipe,
) -> str:
    """
    Build a read-only command that verifies a complete pseudo-file surface.

    Every read and write target is checked before any transaction command is
    issued, preventing a partially available interface from receiving writes.

    Args:
        recipe: Validated catalog recipe containing safe direct-child nodes.

    Returns:
        A shell-quoted command that performs no writes and emits one fixed
        readiness marker on success.
    """

    root = shlex.quote(str(recipe.root_path))
    checks = ["set -eu", f"[ -d {root} ]", f"[ ! -L {root} ]"]
    for node in recipe.required_read_nodes:
        path = shlex.quote(str(recipe.root_path / node))
        checks.extend((f"[ -e {path} ]", f"[ ! -L {path} ]", f"[ -r {path} ]"))
    write_nodes = dict.fromkeys(
        write.node
        for transaction in recipe.transactions
        for write in transaction.writes
    )
    for node in write_nodes:
        path = shlex.quote(str(recipe.root_path / node))
        checks.extend((f"[ -e {path} ]", f"[ ! -L {path} ]", f"[ -w {path} ]"))
    checks.append("printf '%s\\n' NVDEBUG_GUARDED_TRANSACTION_READY")
    return shlex.join(["sh", "-c", "; ".join(checks)])


def _build_guarded_pseudo_file_transaction_command(
    recipe: _GuardedPseudoFileRecipe,
    transaction: _GuardedPseudoFileTransaction,
) -> str:
    """
    Build one fail-fast pseudo-file transaction with a final commit write.

    Rechecking every target in the same privileged shell narrows the interval
    between capability probing and the final irreversible write. The caller
    must execute the returned command once and never replay it after an
    ambiguous transport failure.

    Args:
        recipe: Validated catalog recipe containing the interface root.
        transaction: Ordered writes whose single commit entry is last.

    Returns:
        A shell-quoted command for one sequential transaction attempt.
    """

    root = shlex.quote(str(recipe.root_path))
    checks = ["set -eu", f"[ -d {root} ]", f"[ ! -L {root} ]"]
    for write in transaction.writes:
        path = shlex.quote(str(recipe.root_path / write.node))
        checks.extend((f"[ -e {path} ]", f"[ ! -L {path} ]", f"[ -w {path} ]"))
    for write in transaction.writes:
        path = shlex.quote(str(recipe.root_path / write.node))
        checks.append(f"printf '%s\\n' {shlex.quote(write.value)} > {path}")
    return shlex.join(["sh", "-c", "; ".join(checks)])


@dataclass(frozen=True)
class _HostArchiveTransferPolicy:
    """
    Keep one Host collection archive's warning and hard limits aligned.

    The immutable record prevents a caller from applying the expected size as
    a transfer cap while using the independent collection ceiling for a later
    stage. Every archive stage receives its values from the same resolved
    policy instance.

    Attributes:
        expected_bytes: Operational threshold that emits a warning but does not
            truncate or reject the collection archive.
        max_transfer_bytes: Finite hard ceiling enforced during transfer and
            persistence.
        validation_limits: Matching finite limits used for complete archive
            validation or extraction.
    """

    expected_bytes: int
    max_transfer_bytes: int
    validation_limits: ArchiveLimits


def _resolve_host_artifact_max_bytes(
    *configs: Any,
    default: int = _DEFAULT_HOST_ARTIFACT_MAX_BYTES,
) -> int:
    """
    Resolve one explicit finite per-artifact host-download bound.

    The implementation uses ``default`` and ``configs`` to resolve one explicit
    finite per-artifact host-download bound. If the function cannot resolve one
    explicit finite per-artifact host-download bound, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        default: Fallback used when the requested value is absent or invalid.
        configs: Additional positional values forwarded in caller-provided
            order.

    Returns:
        The validated ``value``.

    Raises:
        ValueError: If the max_artifact_bytes are not a positive integer no
            greater than ``_HARD_HOST_ARTIFACT_MAX_BYTES``.
    """

    value: Any = default
    for config in configs:
        if isinstance(config, dict) and config.get("max_artifact_bytes") is not None:
            value = config["max_artifact_bytes"]
            break
    if type(value) is not int or value <= 0 or value > _HARD_HOST_ARTIFACT_MAX_BYTES:
        raise ValueError(
            "max_artifact_bytes must be a positive integer no greater than "
            f"{_HARD_HOST_ARTIFACT_MAX_BYTES}"
        )
    return value


def _resolve_host_oversize_policy(config: Any, transport: str) -> str:
    """
    Resolve and validate one authored Host oversize policy.

    ``reject`` preserves the legacy behavior. ``tail_snapshot`` is deliberately
    opt-in and is valid only with private ``staged_sftp`` transport, so an
    author cannot accidentally turn an in-memory command or direct SFTP read
    into a successful truncated artifact.

    Args:
        config: Collector command or target mapping containing the optional
            ``oversize_policy`` field.
        transport: Transport selected for the same command or target.

    Returns:
        The validated oversize policy name.

    Raises:
        ValueError: If the policy is unsupported or requests a tail snapshot
            without private staged SFTP transport and an explicit artifact
            byte bound.
    """
    value = (
        config.get("oversize_policy", "reject")
        if isinstance(config, dict)
        else "reject"
    )
    if not isinstance(value, str) or value not in _HOST_OVERSIZE_POLICIES:
        allowed = ", ".join(sorted(_HOST_OVERSIZE_POLICIES))
        raise ValueError(f"oversize_policy must be one of: {allowed}")
    if value == "tail_snapshot":
        if transport != "staged_sftp":
            raise ValueError(
                "oversize_policy=tail_snapshot requires transport=staged_sftp"
            )
        if not isinstance(config, dict) or config.get("max_artifact_bytes") is None:
            raise ValueError(
                "oversize_policy=tail_snapshot requires an explicit max_artifact_bytes"
            )
    return value


def _parse_bounded_snapshot_receipt(stdout: Any, max_bytes: int) -> Dict[str, Any]:
    """
    Validate the fixed receipt from one remote bounded snapshot pipeline.

    The producer's bytes never share this channel, so accepting only one exact
    machine receipt prevents command output from spoofing acquisition metadata.
    The arithmetic invariants prove that the staged file is the complete stream
    when it fits or exactly the authored newest-byte cap when it does not.

    Args:
        stdout: Remote staging command stdout containing the fixed receipt.
        max_bytes: Authored upper bound for the staged artifact.

    Returns:
        Canonical raw, collected, omitted, policy, and direction metadata.

    Raises:
        ValueError: If the receipt is absent, malformed, inconsistent, or
            reports bytes outside the authored bound.
    """
    match = _BOUNDED_SNAPSHOT_RECEIPT_RE.fullmatch(str(stdout or ""))
    if match is None:
        raise ValueError("bounded snapshot did not return a valid receipt")
    raw_bytes = int(match.group("raw_bytes"))
    collected_bytes = int(match.group("collected_bytes"))
    omitted_bytes = int(match.group("omitted_bytes"))
    expected_collected = min(raw_bytes, max_bytes)
    if (
        collected_bytes != expected_collected
        or omitted_bytes != raw_bytes - collected_bytes
        or collected_bytes > max_bytes
    ):
        raise ValueError("bounded snapshot receipt has inconsistent byte counts")
    return {
        "oversize_policy": "tail_snapshot",
        "snapshot_direction": "newest",
        "max_artifact_bytes": max_bytes,
        "raw_bytes": raw_bytes,
        "collected_bytes": collected_bytes,
        "omitted_bytes": omitted_bytes,
    }


def _resolve_host_archive_transfer_policy(
    *configs: Any,
) -> _HostArchiveTransferPolicy:
    """
    Resolve aligned warning, transfer, and validation limits for one archive.

    ``max_artifact_bytes`` remains the collector's expected archive size, but
    exceeding it no longer discards a complete diagnostic artifact. Tool-owned
    Host archives instead use the fixed finite collection boundary through
    transfer, validation, extraction, and persistence.

    Args:
        configs: Additional positional values forwarded in caller-provided
            order.

    Returns:
        The aligned Host collection archive policy.
    """

    active_limits = resolve_collection_archive_limits()
    expected_bytes = _resolve_host_artifact_max_bytes(
        *configs,
        default=_DEFAULT_HOST_ARTIFACT_MAX_BYTES,
    )
    max_transfer_bytes = min(
        active_limits.max_input_bytes,
        _HARD_HOST_ARTIFACT_MAX_BYTES,
    )
    expected_bytes = min(expected_bytes, max_transfer_bytes)
    return _HostArchiveTransferPolicy(
        expected_bytes=expected_bytes,
        max_transfer_bytes=max_transfer_bytes,
        validation_limits=replace(
            active_limits,
            max_input_bytes=max_transfer_bytes,
        ),
    )


@dataclass(frozen=True)
class _RemoteStagingDirectory:
    """
    One unpredictable endpoint directory owned by a collector invocation.

    The immutable record keeps ``path`` and ``use_sudo`` together so consumers
    observe one remote staging directory state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        use_sudo: Whether use sudo applies to this record.
    """

    path: str
    use_sudo: bool


_PUBLICATION_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


_publication_directory_identity = directory_security_identity


@dataclass
class _PinnedPublicationParent:
    """
    Descriptor chain pinning one destination parent without following links.

    The coherent record keeps ``destination``, ``components``, and
    ``descriptors`` together so consumers observe one pinned publication parent
    state. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        destination: Destination retained as part of the record's public state.
        components: Collection of components entries retained by this record.
        descriptors: Collection of descriptors entries retained by this record.
    """

    destination: Path
    components: List[str]
    descriptors: List[int]

    @property
    def leaf(self) -> str:
        """
        Return the leaf.

        Each access computes the value from ``destination`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The canonical leaf text.
        """
        return self.destination.name

    @property
    def descriptor(self) -> int:
        """
        Return the owned file descriptor.

        Each access computes the value from ``descriptors`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The numeric descriptor value.
        """
        return self.descriptors[-1]

    def assert_identity(self) -> None:
        """
        Verify identity.

        The implementation uses current instance state to verify identity. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Raises:
            OSError: If publication destination parent identity changed.
        """
        for index, component in enumerate(self.components):
            parent_descriptor = self.descriptors[index]
            child_descriptor = self.descriptors[index + 1]
            opened = os.fstat(child_descriptor)
            visible = os.stat(
                component,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if not stat.S_ISDIR(opened.st_mode) or _publication_directory_identity(
                opened
            ) != _publication_directory_identity(visible):
                raise OSError("publication destination parent identity changed")

    def close(self) -> None:
        """
        Close the _PinnedPublicationParent.

        The implementation uses current instance state to close the
        _PinnedPublicationParent.
        """
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)


@dataclass(frozen=True)
class _BoundedEvidencePublicationReceipt:
    """
    Describe a complete bounded evidence document committed durably.

    The receipt contains only the exact serialized byte count needed to report
    a committed artifact truthfully when caller cancellation races with the
    terminal publication boundary.

    Attributes:
        published_bytes: Exact serialized evidence bytes durably published.
    """

    published_bytes: int


@contextmanager
def _open_publication_parent(
    destination: str | Path,
) -> Iterator[_PinnedPublicationParent]:
    """
    Open publication parent.

    The implementation uses ``destination`` to open publication parent. If the
    function cannot open publication parent, its exception reaches the caller
    instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        destination: filesystem location used as the destination for this
            operation.

    Yields:
        Each open publication parent admitted by the operation, in deterministic
        iteration order.

    Raises:
        ValueError: If unsafe publication destination: ``destination``.
    """
    raw_destination = Path(destination)
    if not raw_destination.name or any(part == ".." for part in raw_destination.parts):
        raise ValueError(f"unsafe publication destination: {destination}")
    destination_path = Path(os.path.abspath(raw_destination))
    components = list(destination_path.parent.parts[1:])
    descriptors = [os.open(os.sep, _PUBLICATION_DIRECTORY_FLAGS)]
    pinned = _PinnedPublicationParent(destination_path, components, descriptors)
    try:
        for component in components:
            parent_descriptor = descriptors[-1]
            try:
                child_descriptor = os.open(
                    component,
                    _PUBLICATION_DIRECTORY_FLAGS,
                    dir_fd=parent_descriptor,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=parent_descriptor)
                except FileExistsError:
                    pass
                child_descriptor = os.open(
                    component,
                    _PUBLICATION_DIRECTORY_FLAGS,
                    dir_fd=parent_descriptor,
                )
            descriptors.append(child_descriptor)
        pinned.assert_identity()
        yield pinned
    finally:
        pinned.close()


def _remove_publication_entry(parent_descriptor: int, name: str) -> None:
    """
    Remove one anchored file or directory entry without following links.

    Lookup and deletion remain relative to the already pinned parent directory,
    so a concurrently replaced pathname cannot redirect cleanup elsewhere.

    Args:
        parent_descriptor: Open descriptor for the trusted publication parent.
        name: Single anchored entry name to remove when present.
    """

    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(metadata.st_mode):
        shutil.rmtree(name, dir_fd=parent_descriptor)
    else:
        os.unlink(name, dir_fd=parent_descriptor)


def _publish_extracted_directory(source: str | Path, destination: str | Path) -> str:
    """
    Publish one extracted tree through a pinned destination parent.

    The source is first moved or copied to an unpredictable sibling staging
    name. Any previous destination is quarantined, the staging name is renamed
    into place atomically, and the old tree is removed only after publication.
    Failures restore the previous destination where possible and retain at
    least one complete copy of the new extraction. Once publication commits,
    failure to delete an obsolete cross-device source is a cleanup warning;
    the complete published tree remains the authoritative result.

    Args:
        source: Tool-owned extracted directory to publish.
        destination: Final collector output directory.

    Returns:
        The absolute published destination path.

    Raises:
        OSError: If source/destination identity changes or publication fails.
        ValueError: If the source is not a plain directory.
    """

    source_path = Path(source)
    source_metadata = source_path.lstat()
    if not stat.S_ISDIR(source_metadata.st_mode) or stat.S_ISLNK(
        source_metadata.st_mode
    ):
        raise ValueError("extracted publication source is not a plain directory")

    with _open_publication_parent(destination) as parent:
        staging_name = f".{parent.leaf}.stage-{secrets.token_hex(12)}"
        backup_name = f".{parent.leaf}.previous-{secrets.token_hex(12)}"
        staged = False
        source_moved = False
        backup = False
        committed = False
        try:
            try:
                os.rename(
                    source_path,
                    staging_name,
                    dst_dir_fd=parent.descriptor,
                )
                source_moved = True
                staged = True
            except OSError as error:
                if error.errno != errno.EXDEV:
                    raise
                os.mkdir(staging_name, 0o700, dir_fd=parent.descriptor)
                staged = True
                anchored_staging = Path(
                    f"/proc/self/fd/{parent.descriptor}/{staging_name}"
                )
                shutil.copytree(
                    source_path,
                    anchored_staging,
                    symlinks=False,
                    dirs_exist_ok=True,
                )

            parent.assert_identity()
            try:
                os.stat(
                    parent.leaf,
                    dir_fd=parent.descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                os.rename(
                    parent.leaf,
                    backup_name,
                    src_dir_fd=parent.descriptor,
                    dst_dir_fd=parent.descriptor,
                )
                backup = True

            parent.assert_identity()
            os.rename(
                staging_name,
                parent.leaf,
                src_dir_fd=parent.descriptor,
                dst_dir_fd=parent.descriptor,
            )
            staged = False
            committed = True
            parent.assert_identity()
            if backup:
                try:
                    _remove_publication_entry(parent.descriptor, backup_name)
                    backup = False
                except OSError:
                    # The new extraction is already atomically published. A
                    # stale private backup is preferable to reporting a false
                    # publication failure or risking rollback data loss.
                    pass
            if not source_moved:
                try:
                    shutil.rmtree(source_path)
                except OSError as cleanup_error:
                    # Copy and atomic publication have already completed. A
                    # partially removed obsolete source cannot invalidate the
                    # complete destination or change the collector outcome.
                    try:
                        logger.warning(
                            "Published extracted logs; could not remove obsolete "
                            "extraction source (%s, errno=%s)",
                            type(cleanup_error).__name__,
                            cleanup_error.errno,
                        )
                    except Exception:
                        # A broken diagnostic handler also cannot undo commit.
                        pass
            return str(parent.destination)
        except BaseException:
            if backup and not committed:
                try:
                    os.rename(
                        backup_name,
                        parent.leaf,
                        src_dir_fd=parent.descriptor,
                        dst_dir_fd=parent.descriptor,
                    )
                    backup = False
                except OSError:
                    pass
            if staged and source_moved and not os.path.lexists(source_path):
                try:
                    os.rename(
                        staging_name,
                        source_path,
                        src_dir_fd=parent.descriptor,
                    )
                    staged = False
                except OSError:
                    pass
            if staged and not source_moved:
                try:
                    _remove_publication_entry(parent.descriptor, staging_name)
                except OSError:
                    pass
            raise


def _create_publication_staging_file(
    parent: _PinnedPublicationParent,
) -> Tuple[int, str]:
    """
    Create publication staging file.

    The implementation uses ``parent`` to create publication staging file.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. If the function cannot create publication staging
    file, its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        parent: Parent object whose ``descriptor`` and ``leaf`` state is read
            while performing publication staging file.

    Returns:
        A tuple containing ``descriptor`` and ``temporary name`` in that order.

    Raises:
        FileExistsError: If could not allocate publication staging file.
    """
    for _attempt in range(128):
        temporary_name = f".{parent.leaf}.{secrets.token_hex(12)}.tmp"
        try:
            descriptor = os.open(
                temporary_name,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent.descriptor,
            )
        except FileExistsError:
            continue
        return descriptor, temporary_name
    raise FileExistsError("could not allocate publication staging file")


def _assert_publication_leaf_safe(parent: _PinnedPublicationParent) -> None:
    """
    Verify publication leaf safe.

    The implementation uses ``parent`` to verify publication leaf safe. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path. Filesystem effects
    remain confined to the caller-selected paths and the owning resource
    lifecycle.

    Args:
        parent: Parent object whose ``descriptor``, ``destination``, and
            ``leaf`` state is read while performing publication leaf safe.

    Raises:
        ValueError: If the publication destination is not a regular file:
            ``destination``.
    """
    try:
        existing = os.stat(
            parent.leaf,
            dir_fd=parent.descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if not stat.S_ISREG(existing.st_mode):
        raise ValueError(
            f"publication destination must be a regular file: {parent.destination}"
        )


def _publish_staging_file(
    parent: _PinnedPublicationParent,
    temporary_name: str,
    temporary_metadata: os.stat_result,
) -> None:
    """
    Publish staging file.

    The implementation uses ``parent``, ``temporary_name``, and
    ``temporary_metadata`` to publish staging file. Success is reported only
    after the owning output boundary has completed its required write or
    publication step. If the function cannot publish staging file, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        parent: Parent object whose ``assert_identity``, ``descriptor``, and
            ``leaf`` state is read while performing staging file.
        temporary_name: Stable temporary name used for lookup and
            operator-facing diagnostics.
        temporary_metadata: Temporary metadata object whose ``st_dev``,
            ``st_ino``, and ``st_size`` state is read while performing staging
            file.

    Raises:
        OSError: If publication destination identity changed.
    """
    parent.assert_identity()
    _assert_publication_leaf_safe(parent)
    os.replace(
        temporary_name,
        parent.leaf,
        src_dir_fd=parent.descriptor,
        dst_dir_fd=parent.descriptor,
    )
    try:
        parent.assert_identity()
        published = os.stat(
            parent.leaf,
            dir_fd=parent.descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(published.st_mode)
            or published.st_dev != temporary_metadata.st_dev
            or published.st_ino != temporary_metadata.st_ino
            or published.st_size != temporary_metadata.st_size
        ):
            raise OSError("publication destination identity changed")
        os.fsync(parent.descriptor)
    except BaseException:
        try:
            visible = os.stat(
                parent.leaf,
                dir_fd=parent.descriptor,
                follow_symlinks=False,
            )
            if (
                visible.st_dev == temporary_metadata.st_dev
                and visible.st_ino == temporary_metadata.st_ino
            ):
                os.unlink(parent.leaf, dir_fd=parent.descriptor)
                os.fsync(parent.descriptor)
        except FileNotFoundError:
            pass
        raise


def _publish_staging_file_exclusively(
    parent: _PinnedPublicationParent,
    temporary_name: str,
    temporary_metadata: os.stat_result,
    cancellation_event: threading.Event,
) -> _BoundedEvidencePublicationReceipt:
    """
    Publish one staging inode without replacing an existing artifact.

    A same-directory hard link supplies an atomic no-clobber boundary: the
    operation either claims the absent destination leaf or fails with
    ``FileExistsError``. Cancellation is honored only before that irreversible
    commit. After the link succeeds, the function ignores cooperative
    cancellation, removes its private staging name, validates the visible
    single-link inode exactly, and synchronizes the directory. It never removes
    the destination by pathname after commit, including on validation or fsync
    failure.

    Args:
        parent: Pinned publication directory that owns both path names.
        temporary_name: Unpredictable private staging leaf to publish.
        temporary_metadata: Identity and size captured from the complete
            staging file.
        cancellation_event: Cooperative cancellation signal checked immediately
            before the atomic no-clobber link operation.

    Returns:
        Exact byte receipt for the complete durably committed document.

    Raises:
        FileExistsError: If the destination leaf already exists.
        OSError: If the directory or published inode fails identity validation.
        _ManagedFilesystemOperationStopped: If publication was cancelled.

    Side Effects:
        Creates the destination as a hard link to the owned staging inode,
        removes the staging link, and synchronizes the containing directory.
        Once linked, the destination is retained on success and failure; caller
        cleanup remains limited to the unpredictable private staging name.
    """
    parent.assert_identity()
    if cancellation_event.is_set():
        raise _ManagedFilesystemOperationStopped(
            "bounded snapshot evidence publication was cancelled"
        )
    try:
        os.link(
            temporary_name,
            parent.leaf,
            src_dir_fd=parent.descriptor,
            dst_dir_fd=parent.descriptor,
            follow_symlinks=False,
        )
    except FileExistsError as exc:
        raise FileExistsError(
            "bounded snapshot evidence destination already exists"
        ) from exc

    os.unlink(temporary_name, dir_fd=parent.descriptor)
    parent.assert_identity()
    published = os.stat(
        parent.leaf,
        dir_fd=parent.descriptor,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISREG(published.st_mode)
        or published.st_nlink != 1
        or published.st_dev != temporary_metadata.st_dev
        or published.st_ino != temporary_metadata.st_ino
        or published.st_size != temporary_metadata.st_size
    ):
        raise OSError("bounded snapshot evidence publication changed identity")
    os.fsync(parent.descriptor)
    return _BoundedEvidencePublicationReceipt(
        published_bytes=published.st_size,
    )


def _unlink_publication_staging_file(
    parent: _PinnedPublicationParent,
    temporary_name: str,
    expected_metadata: Optional[os.stat_result],
) -> None:
    """
    Remove publication staging file.

    The implementation uses ``parent``, ``temporary_name``, and
    ``expected_metadata`` to remove publication staging file.

    Args:
        parent: Parent object whose ``descriptor`` state is read while
            performing remove publication staging file.
        temporary_name: Stable temporary name used for lookup and
            operator-facing diagnostics.
        expected_metadata: Expected metadata object whose ``st_dev`` and
            ``st_ino`` state is read while performing remove publication staging
            file.
    """
    if expected_metadata is None:
        return
    try:
        visible = os.stat(
            temporary_name,
            dir_fd=parent.descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if (
        visible.st_dev == expected_metadata.st_dev
        and visible.st_ino == expected_metadata.st_ino
    ):
        os.unlink(temporary_name, dir_fd=parent.descriptor)


def _copy_regular_file_to_stream_bounded(
    source: str | Path,
    destination_handle: Any,
    *,
    max_bytes: int,
) -> int:
    """
    Copy regular file to stream bounded.

    The implementation uses ``source``, ``destination_handle``, and
    ``max_bytes`` to copy regular file to stream bounded. Filesystem effects
    remain confined to the caller-selected paths and the owning resource
    lifecycle. If the function cannot copy regular file to stream bounded, its
    exception reaches the caller instead of being converted into a successful
    result. Cleanup in the ``finally`` path runs for successful, failed, and
    cancelled execution.

    Args:
        source: filesystem location used as the source for this operation.
        destination_handle: Destination handle object whose ``write`` state is
            read while performing copy regular file to stream bounded.
        max_bytes: Upper bound enforced for max bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The validated ``copied_bytes``.

    Raises:
        OSError: If downloaded artifact is not a regular file; downloaded
            artifact is ``st_size`` bytes, exceeding the ``max_bytes``-byte
            bound; downloaded artifact exceeded its configured bound; or
            downloaded artifact changed while copying.
    """
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    source_flags |= getattr(os, "O_NOFOLLOW", 0)
    source_flags |= getattr(os, "O_NONBLOCK", 0)
    source_descriptor = os.open(source, source_flags)
    copied_bytes = 0
    try:
        initial = os.fstat(source_descriptor)
        if not stat.S_ISREG(initial.st_mode):
            raise OSError("downloaded artifact is not a regular file")
        if initial.st_size > max_bytes:
            raise OSError(
                f"downloaded artifact is {initial.st_size} bytes, "
                f"exceeding the {max_bytes}-byte bound"
            )
        with os.fdopen(source_descriptor, "rb", closefd=False) as source_handle:
            while True:
                chunk = source_handle.read(
                    min(
                        _COMPOSITE_COPY_CHUNK_BYTES,
                        max_bytes - copied_bytes + 1,
                    )
                )
                if not chunk:
                    break
                copied_bytes += len(chunk)
                if copied_bytes > max_bytes:
                    raise OSError("downloaded artifact exceeded its configured bound")
                destination_handle.write(chunk)
        final = os.fstat(source_descriptor)
        if copied_bytes != initial.st_size or (
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        ) != (
            initial.st_size,
            initial.st_mtime_ns,
            initial.st_ctime_ns,
        ):
            raise OSError("downloaded artifact changed while copying")
        return copied_bytes
    finally:
        os.close(source_descriptor)


def _copy_regular_file_bounded(
    source: str,
    destination: str,
    *,
    max_bytes: int,
) -> int:
    """
    Copy one staged regular file without following links or buffering it whole.

    The implementation uses ``source``, ``destination``, and ``max_bytes`` to
    copy one staged regular file without following links or buffering it whole.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. If the function cannot copy one staged regular
    file without following links or buffering it whole, its exception reaches
    the caller instead of being converted into a successful result. Cleanup in
    the ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        source: Text supplied as source in the format accepted by this function.
        destination: Text supplied as destination in the format accepted by this
            function.
        max_bytes: Upper bound enforced for max bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The validated ``copied_bytes``.

    Raises:
        OSError: If downloaded artifact is not a regular file; downloaded
            artifact is ``st_size`` bytes, exceeding the ``max_bytes``-byte
            bound; downloaded artifact exceeded its configured bound; or
            downloaded artifact changed while copying.
    """

    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    source_descriptor = os.open(source, source_flags)
    copied_bytes = 0
    try:
        initial = os.fstat(source_descriptor)
        if not stat.S_ISREG(initial.st_mode):
            raise OSError("downloaded artifact is not a regular file")
        if initial.st_size > max_bytes:
            raise OSError(
                f"downloaded artifact is {initial.st_size} bytes, "
                f"exceeding the {max_bytes}-byte bound"
            )
        with (
            os.fdopen(source_descriptor, "rb", closefd=False) as source_handle,
            open(destination, "wb") as destination_handle,
        ):
            while True:
                chunk = source_handle.read(
                    min(
                        _COMPOSITE_COPY_CHUNK_BYTES,
                        max_bytes - copied_bytes + 1,
                    )
                )
                if not chunk:
                    break
                copied_bytes += len(chunk)
                if copied_bytes > max_bytes:
                    raise OSError("downloaded artifact exceeded its configured bound")
                destination_handle.write(chunk)
        final = os.fstat(source_descriptor)
        if copied_bytes != initial.st_size or (
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        ) != (
            initial.st_size,
            initial.st_mtime_ns,
            initial.st_ctime_ns,
        ):
            raise OSError("downloaded artifact changed while copying")
        return copied_bytes
    finally:
        os.close(source_descriptor)


def _publish_regular_file_bounded(
    source: str | Path,
    destination: str | Path,
    *,
    max_bytes: int,
) -> int:
    """
    Stream one regular file into a sibling staging leaf and publish atomically.

    The implementation uses ``source``, ``destination``, and ``max_bytes`` to
    stream one regular file into a sibling staging leaf and publish atomically.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        source: filesystem location used as the source for this operation.
        destination: filesystem location used as the destination for this
            operation.
        max_bytes: Upper bound enforced for max bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The validated ``copied``.
    """

    with _open_publication_parent(destination) as parent:
        descriptor, temporary_name = _create_publication_staging_file(parent)
        temporary_metadata: Optional[os.stat_result] = os.fstat(descriptor)
        try:
            with os.fdopen(descriptor, "wb") as destination_handle:
                descriptor = -1
                copied = _copy_regular_file_to_stream_bounded(
                    source,
                    destination_handle,
                    max_bytes=max_bytes,
                )
                destination_handle.flush()
                os.fsync(destination_handle.fileno())
                temporary_metadata = os.fstat(destination_handle.fileno())
            _publish_staging_file(parent, temporary_name, temporary_metadata)
            temporary_metadata = None
            return copied
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            _unlink_publication_staging_file(
                parent,
                temporary_name,
                temporary_metadata,
            )


def _select_newest_timestamped_file(
    candidates: List[str],
    *,
    anchor_directories: List[str],
    file_pattern: str,
    case_sensitive: bool,
    selection_regex: str,
    capture: str,
    datetime_format: str,
    tie_breaker: str,
) -> Tuple[
    Optional[str],
    Optional[str],
    List[str],
    List[str],
    List[Dict[str, str]],
]:
    """
    Select one newest related file beneath configured anchor directories.

    A candidate must remain below one of the supplied anchors, match the
    catalog-declared filename, and have a parent directory whose named
    configured capture group parses with ``datetime_format``. The catalog also
    declares the deterministic tie-break policy.

    Args:
        candidates: Entries supplied as ``candidates`` without transferring
            container ownership.
        anchor_directories: Entries supplied as ``anchor_directories`` without
            transferring container ownership.
        file_pattern: Text supplied as file pattern in the format accepted by
            this function.
        case_sensitive: Whether case sensitive is enabled or required for this
            operation.
        selection_regex: Text supplied as selection regex in the format accepted
            by this function.
        capture: Text supplied as capture in the format accepted by this
            function.
        datetime_format: Text supplied as datetime format in the format accepted
            by this function.
        tie_breaker: Text supplied as tie breaker in the format accepted by this
            function.

    Returns:
        A tuple containing the selected path, captured timestamp, eligible
        paths, superseded paths, and rejected-candidate records.

    Raises:
        ValueError: If the related file pattern is not a non-empty basename
            pattern; the related file selection regex is not valid; related file
            selection regex must define its configured capture; or the related
            file tie_breaker is not 'path_ascending'; or another input invariant
            is violated.
    """

    if (
        not file_pattern
        or "/" in file_pattern
        or any(delimiter in file_pattern for delimiter in ("\x00", "\r", "\n"))
    ):
        raise ValueError("related file pattern must be a non-empty basename pattern")
    try:
        timestamp_pattern = re.compile(selection_regex)
    except re.error as exc:
        raise ValueError("related file selection regex must be valid") from exc
    if capture not in timestamp_pattern.groupindex:
        raise ValueError(
            "related file selection regex must define its configured capture"
        )
    if tie_breaker != "path_ascending":
        raise ValueError("related file tie_breaker must be 'path_ascending'")

    anchors: List[PurePosixPath] = []
    for value in anchor_directories:
        anchor = PurePosixPath(value)
        if (
            any(delimiter in value for delimiter in ("\x00", "\r", "\n"))
            or not anchor.is_absolute()
            or ".." in anchor.parts
            or anchor.as_posix() != value
        ):
            raise ValueError(
                "related-file anchors must be absolute paths without parent traversal"
            )
        if anchor not in anchors:
            anchors.append(anchor)

    eligible: List[Tuple[datetime, str, str]] = []
    rejected: List[Dict[str, str]] = []
    seen: set[str] = set()
    expected_pattern = file_pattern if case_sensitive else file_pattern.casefold()

    for raw_candidate in candidates:
        if raw_candidate in seen:
            continue
        seen.add(raw_candidate)
        if any(delimiter in raw_candidate for delimiter in ("\x00", "\r", "\n")):
            rejected.append(
                {
                    "path": raw_candidate,
                    "reason": "path contains an unsafe delimiter",
                }
            )
            continue

        candidate = PurePosixPath(raw_candidate)
        normalized_candidate = candidate.as_posix()
        if (
            not candidate.is_absolute()
            or ".." in candidate.parts
            or normalized_candidate != raw_candidate
        ):
            rejected.append(
                {
                    "path": raw_candidate,
                    "reason": (
                        "path is not a normalized absolute path or contains "
                        "parent traversal"
                    ),
                }
            )
            continue
        if not any(candidate.is_relative_to(anchor) for anchor in anchors):
            rejected.append(
                {
                    "path": normalized_candidate,
                    "reason": "path is outside configured anchor directories",
                }
            )
            continue

        candidate_name = candidate.name if case_sensitive else candidate.name.casefold()
        if not fnmatchcase(candidate_name, expected_pattern):
            rejected.append(
                {
                    "path": normalized_candidate,
                    "reason": "filename does not match the configured pattern",
                }
            )
            continue

        timestamp_match = timestamp_pattern.fullmatch(candidate.parent.name)
        if timestamp_match is None:
            rejected.append(
                {
                    "path": normalized_candidate,
                    "reason": "parent directory does not match the timestamp contract",
                }
            )
            continue
        captured_timestamp = timestamp_match.group(capture)
        if not isinstance(captured_timestamp, str) or not captured_timestamp:
            rejected.append(
                {
                    "path": normalized_candidate,
                    "reason": "parent timestamp capture is empty",
                }
            )
            continue
        try:
            parsed_timestamp = datetime.strptime(captured_timestamp, datetime_format)
        except (TypeError, ValueError):
            rejected.append(
                {
                    "path": normalized_candidate,
                    "reason": "parent timestamp is not a valid calendar time",
                }
            )
            continue
        eligible.append((parsed_timestamp, normalized_candidate, captured_timestamp))

    if not eligible:
        return None, None, [], [], rejected

    latest_timestamp = max(timestamp for timestamp, _, _ in eligible)
    latest_paths = sorted(
        path for timestamp, path, _ in eligible if timestamp == latest_timestamp
    )
    selected = latest_paths[0]
    eligible_paths = [
        path for _, path, _ in sorted(eligible, key=lambda item: (item[0], item[1]))
    ]
    superseded = [path for path in eligible_paths if path != selected]
    selected_timestamp = next(
        captured for _, path, captured in eligible if path == selected
    )
    return selected, selected_timestamp, eligible_paths, superseded, rejected


def _normalize_related_file_searches(value: Any) -> List[Dict[str, Any]]:
    """
    Validate catalog-declared searches that are anchored to primary files.

    The implementation uses ``value`` to validate catalog-declared searches that
    are anchored to primary files. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        value: Entries supplied as ``value`` and processed in caller-provided
            order.

    Returns:
        The validated ``normalized``.

    Raises:
        ValueError: If the search_config.related_file_searches are not a list;
            the ``context`` is not a mapping; the supplied input cannot be used
            to validate catalog-declared searches that are anchored to primary
            files; or the ``context``.id is not a non-empty stable identifier;
            or another input invariant is violated.
        BaseException: If a delegated failure occurs while the function attempts
            to validate catalog-declared searches that are anchored to primary
            files.
    """

    if value is None:
        raise ValueError("search_config.related_file_searches must be a list")
    if not isinstance(value, list):
        raise ValueError("search_config.related_file_searches must be a list")

    allowed_rule_fields = {
        "id",
        "anchor",
        "match",
        "selection",
        "search_timeout",
        "absence_policy",
        "malformed_only_policy",
    }
    allowed_anchor_fields = {"source", "path_regex", "root_capture"}
    allowed_match_fields = {"basename_glob", "case_sensitive"}
    allowed_selection_fields = {
        "strategy",
        "source",
        "regex",
        "capture",
        "format",
        "tie_breaker",
    }
    normalized: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()

    for index, raw_rule in enumerate(value):
        context = f"search_config.related_file_searches[{index}]"
        if not isinstance(raw_rule, dict):
            raise ValueError(f"{context} must be a mapping")
        unknown_fields = sorted(set(raw_rule) - allowed_rule_fields)
        if unknown_fields:
            raise ValueError(
                f"{context} has unsupported fields: {', '.join(unknown_fields)}"
            )

        rule_id = raw_rule.get("id")
        if (
            not isinstance(rule_id, str)
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", rule_id) is None
        ):
            raise ValueError(f"{context}.id must be a non-empty stable identifier")
        if rule_id in seen_ids:
            raise ValueError(
                f"search_config.related_file_searches repeats id '{rule_id}'"
            )
        seen_ids.add(rule_id)
        context = f"search_config.related_file_searches[{rule_id}]"

        raw_anchor = raw_rule.get("anchor")
        if not isinstance(raw_anchor, dict):
            raise ValueError(f"{context}.anchor must be a mapping")
        unknown_anchor_fields = sorted(set(raw_anchor) - allowed_anchor_fields)
        if unknown_anchor_fields:
            raise ValueError(
                f"{context}.anchor has unsupported fields: "
                f"{', '.join(unknown_anchor_fields)}"
            )
        if raw_anchor.get("source") != "trusted_primary":
            raise ValueError(f"{context}.anchor.source must be 'trusted_primary'")
        anchor_path_regex = raw_anchor.get("path_regex")
        if not isinstance(anchor_path_regex, str) or not anchor_path_regex:
            raise ValueError(f"{context}.anchor.path_regex must be a non-empty string")
        try:
            compiled_anchor_regex = re.compile(anchor_path_regex)
        except re.error as exc:
            raise ValueError(
                f"{context}.anchor.path_regex must be a valid regex"
            ) from exc
        root_capture = raw_anchor.get("root_capture")
        if (
            not isinstance(root_capture, str)
            or not root_capture
            or root_capture not in compiled_anchor_regex.groupindex
        ):
            raise ValueError(
                f"{context}.anchor.root_capture must name a path_regex group"
            )

        raw_match = raw_rule.get("match")
        if not isinstance(raw_match, dict):
            raise ValueError(f"{context}.match must be a mapping")
        unknown_match_fields = sorted(set(raw_match) - allowed_match_fields)
        if unknown_match_fields:
            raise ValueError(
                f"{context}.match has unsupported fields: "
                f"{', '.join(unknown_match_fields)}"
            )
        file_pattern = raw_match.get("basename_glob")
        if (
            not isinstance(file_pattern, str)
            or not file_pattern
            or "/" in file_pattern
            or any(delimiter in file_pattern for delimiter in ("\x00", "\r", "\n"))
        ):
            raise ValueError(
                f"{context}.match.basename_glob must be a non-empty basename pattern"
            )
        case_sensitive = raw_match.get("case_sensitive")
        if not isinstance(case_sensitive, bool):
            raise ValueError(f"{context}.match.case_sensitive must be a Boolean")

        raw_selection = raw_rule.get("selection")
        if not isinstance(raw_selection, dict):
            raise ValueError(f"{context}.selection must be a mapping")
        unknown_selection_fields = sorted(set(raw_selection) - allowed_selection_fields)
        if unknown_selection_fields:
            raise ValueError(
                f"{context}.selection has unsupported fields: "
                f"{', '.join(unknown_selection_fields)}"
            )
        if raw_selection.get("strategy") != "max_parsed_datetime":
            raise ValueError(
                f"{context}.selection.strategy must be 'max_parsed_datetime'"
            )
        if raw_selection.get("source") != "parent_name":
            raise ValueError(f"{context}.selection.source must be 'parent_name'")
        if raw_selection.get("tie_breaker") != "path_ascending":
            raise ValueError(
                f"{context}.selection.tie_breaker must be 'path_ascending'"
            )
        selection_regex = raw_selection.get("regex")
        if not isinstance(selection_regex, str) or not selection_regex:
            raise ValueError(f"{context}.selection.regex must be a non-empty string")
        try:
            timestamp_pattern = re.compile(selection_regex)
        except re.error as exc:
            raise ValueError(
                f"{context}.selection.regex must be a valid regex"
            ) from exc
        capture = raw_selection.get("capture")
        if (
            not isinstance(capture, str)
            or not capture
            or capture not in timestamp_pattern.groupindex
        ):
            raise ValueError(f"{context}.selection.capture must name a regex group")
        datetime_format = raw_selection.get("format")
        if not isinstance(datetime_format, str) or not datetime_format:
            raise ValueError(f"{context}.selection.format must be a non-empty string")
        try:
            sample_datetime = datetime(2004, 2, 29, 23, 58, 57, 123456)
            datetime.strptime(
                sample_datetime.strftime(datetime_format), datetime_format
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{context}.selection.format must be round-trip parseable"
            ) from exc

        if raw_rule.get("absence_policy") != "success":
            raise ValueError(f"{context}.absence_policy must be 'success'")
        if raw_rule.get("malformed_only_policy") != "error":
            raise ValueError(f"{context}.malformed_only_policy must be 'error'")

        raw_timeout = raw_rule.get("search_timeout")
        try:
            if isinstance(raw_timeout, bool):
                raise ValueError
            search_timeout = int(raw_timeout)
            if search_timeout <= 0 or (
                isinstance(raw_timeout, float) and not raw_timeout.is_integer()
            ):
                raise ValueError
        except (TypeError, ValueError, OverflowError):
            raise ValueError(
                f"{context}.search_timeout must be a positive integer"
            ) from None

        normalized.append(
            {
                "id": rule_id,
                "anchor": {
                    "source": "trusted_primary",
                    "path_regex": anchor_path_regex,
                    "root_capture": root_capture,
                    "compiled_regex": compiled_anchor_regex,
                },
                "match": {
                    "basename_glob": file_pattern,
                    "case_sensitive": case_sensitive,
                },
                "selection": {
                    "strategy": "max_parsed_datetime",
                    "source": "parent_name",
                    "regex": selection_regex,
                    "capture": capture,
                    "format": datetime_format,
                    "tie_breaker": "path_ascending",
                },
                "search_timeout": search_timeout,
                "absence_policy": "success",
                "malformed_only_policy": "error",
            }
        )

    return normalized


def _normalize_trusted_path_regexes(value: Any) -> List[re.Pattern[str]]:
    """
    Compile independently declared primary-path trust expressions.

    The implementation uses ``value`` to compile independently declared
    primary-path trust expressions. If the function cannot compile independently
    declared primary-path trust expressions, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        value: Entries supplied as ``value`` and processed in caller-provided
            order.

    Returns:
        The validated ``normalized``.

    Raises:
        ValueError: If the search_config.trusted_path_regexes are not a list;
            the ``context`` is not a non-empty single-line regex;
            search_config.trusted_path_regexes repeats ``raw_pattern``; or the
            ``context`` is not a valid regex.
    """

    if value is None or not isinstance(value, list):
        raise ValueError("search_config.trusted_path_regexes must be a list")

    normalized: List[re.Pattern[str]] = []
    seen: set[str] = set()
    for index, raw_pattern in enumerate(value):
        context = f"search_config.trusted_path_regexes[{index}]"
        if (
            not isinstance(raw_pattern, str)
            or not raw_pattern
            or any(delimiter in raw_pattern for delimiter in ("\x00", "\r", "\n"))
        ):
            raise ValueError(f"{context} must be a non-empty single-line regex")
        if raw_pattern in seen:
            raise ValueError(
                f"search_config.trusted_path_regexes repeats {raw_pattern!r}"
            )
        try:
            compiled = re.compile(raw_pattern)
        except re.error as exc:
            raise ValueError(f"{context} must be a valid regex") from exc
        seen.add(raw_pattern)
        normalized.append(compiled)
    return normalized


def _archive_source_fingerprint(details: os.stat_result) -> Tuple[int, ...]:
    """
    Return the identity and mutation fields bound to an authored TAR member.

    The implementation uses ``details`` to produce the identity and mutation
    fields bound to an authored TAR member.

    Args:
        details: Details object whose ``st_ctime_ns``, ``st_dev``, ``st_ino``,
            ``st_mode``, and ``st_mtime_ns`` state is read while performing
            identity and mutation fields bound to an authored TAR member.

    Returns:
        A tuple containing ``st dev``, ``st ino``, ``st mode``, ``st size``,
        ``st mtime ns``, and ``st ctime ns`` in that order.
    """

    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _validate_authored_tar_name(name: str, limits: ArchiveLimits) -> str:
    """
    Validate one authored TAR name under the shared archive member policy.

    The decision is delegated to ``utils.archive_member_policy`` so this
    producer and the ``utils.bounded_archive`` consumer that later reads the
    archive admit exactly the same names. The ceiling stays bound to the
    supplied ``limits`` rather than a module-local constant.

    Args:
        name: Candidate member name for an archive this process authors.
        limits: Archive limits in force, supplying ``max_path_depth``.

    Returns:
        The canonical authored TAR name, joined from the validated components.

    Raises:
        ValueError: If unsafe archive member name: ``name``.
    """

    try:
        parts = validate_distributable_member_name(
            name,
            max_path_depth=limits.max_path_depth,
        )
    except MemberNamePolicyError as error:
        raise ValueError(f"unsafe archive member name: {name!r}") from error
    return "/".join(parts)


def _snapshot_authored_tar_members(
    members: List[Tuple[Path, str, bool]],
    *,
    limits: ArchiveLimits,
    deadline: float,
) -> List[Tuple[Path, str, os.stat_result]]:
    """
    Build a finite, immutable-plan inventory for one authored TAR.

    The implementation uses ``members``, ``limits``, and ``deadline`` to build a
    finite, immutable-plan inventory for one authored TAR. Filesystem effects
    remain confined to the caller-selected paths and the owning resource
    lifecycle. If the function cannot build a finite, immutable-plan inventory
    for one authored TAR, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        members: Member values received from the source collection in their
            existing order.
        limits: Limits governing finite, immutable-plan inventory for one
            authored TAR.
        deadline: Absolute monotonic deadline after which the operation must
            stop.

    Returns:
        The validated ``snapshots``.

    Raises:
        ValueError: If archive source is unavailable: ``source``; recursive
            archive source is not a directory: ``source``; the archive source is
            not a regular file: ``source``; or archive contains duplicate member
            names.
    """

    snapshots: List[Tuple[Path, str, os.stat_result]] = []
    total_file_bytes = 0
    tracked_path_bytes = 0

    def visit(path: Path, archive_name: str) -> None:
        """
        Visit the current syntax or data node.

        The implementation uses ``path`` and ``archive_name`` to visit the
        current syntax or data node. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. If the function
        cannot visit the current syntax or data node, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            path: filesystem location used as the path for this operation.
            archive_name: Stable archive name used for lookup and
                operator-facing diagnostics.

        Raises:
            ArchivePolicyError: If time_limit; member_count_limit;
                member_size_limit; or total_size_limit; or another input
                invariant is violated.
            ValueError: If archive source is unavailable: ``path``; unsafe
                recursive archive source: ``path``; or cannot enumerate archive
                source: ``path``.
        """
        nonlocal total_file_bytes, tracked_path_bytes
        if time.monotonic() > deadline:
            raise ArchivePolicyError("time_limit")
        if len(snapshots) >= limits.max_members:
            raise ArchivePolicyError("member_count_limit")

        normalized_name = _validate_authored_tar_name(archive_name, limits)
        try:
            details = path.lstat()
        except OSError as error:
            raise ValueError(f"archive source is unavailable: {path}") from error
        if stat.S_ISLNK(details.st_mode) or not (
            stat.S_ISREG(details.st_mode) or stat.S_ISDIR(details.st_mode)
        ):
            raise ValueError(f"unsafe recursive archive source: {path}")

        if stat.S_ISREG(details.st_mode):
            if details.st_size > limits.max_member_bytes:
                raise ArchivePolicyError("member_size_limit")
            total_file_bytes += details.st_size
            if total_file_bytes > limits.max_total_bytes:
                raise ArchivePolicyError("total_size_limit")

        tracked_path_bytes += len(normalized_name.encode("utf-8"))
        if tracked_path_bytes > limits.max_tracked_path_bytes:
            raise ArchivePolicyError("tracked_path_bytes_limit")
        snapshots.append((path, normalized_name, details))

        if not stat.S_ISDIR(details.st_mode):
            return

        child_names: List[str] = []
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    if time.monotonic() > deadline:
                        raise ArchivePolicyError("time_limit")
                    if len(snapshots) + len(child_names) >= limits.max_members:
                        raise ArchivePolicyError("member_count_limit")
                    child_names.append(entry.name)
        except ArchivePolicyError:
            raise
        except OSError as error:
            raise ValueError(f"cannot enumerate archive source: {path}") from error

        for child_name in sorted(child_names):
            visit(path / child_name, f"{normalized_name}/{child_name}")

    for source, member_name, recursive in members:
        source = Path(source)
        normalized_name = _validate_authored_tar_name(member_name, limits)
        try:
            source_details = source.lstat()
        except OSError as error:
            raise ValueError(f"archive source is unavailable: {source}") from error
        if recursive:
            if stat.S_ISLNK(source_details.st_mode) or not stat.S_ISDIR(
                source_details.st_mode
            ):
                raise ValueError(
                    f"recursive archive source is not a directory: {source}"
                )
            visit(source, normalized_name)
        else:
            if stat.S_ISLNK(source_details.st_mode) or not stat.S_ISREG(
                source_details.st_mode
            ):
                raise ValueError(f"archive source must be a regular file: {source}")
            visit(source, normalized_name)

    names = [name for _path, name, _details in snapshots]
    if len(names) != len(set(names)):
        raise ValueError("archive contains duplicate member names")
    return snapshots


class _DeadlineCheckedArchiveReader:
    """
    Check the authored-archive wall-clock budget around every source read.

    The type coordinates ``read`` and retains the state those operations share
    between calls. Resource ownership remains inside the instance until the
    matching close, exit, or cleanup operation completes.
    """

    def __init__(self, stream: Any, deadline: float) -> None:
        """
        Initialize a ``_DeadlineCheckedArchiveReader`` instance.

        The initializer records ``_deadline`` and ``_stream`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            stream: Stream consumed while the function attempts to initialize a
                ``_DeadlineCheckedArchiveReader`` instance.
            deadline: Absolute monotonic deadline after which the operation must
                stop.
        """
        self._stream = stream
        self._deadline = deadline

    def read(self, size: int = -1) -> bytes:
        """
        Read bounded data from the owned source.

        The implementation uses ``size`` to read bounded data from the owned
        source. Parsing or I/O must finish before the validated representation
        is made available to the caller. If the function cannot read bounded
        data from the owned source, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            size: Numeric size used by the operation's bounded accounting.

        Returns:
            The validated ``data``.

        Raises:
            ArchivePolicyError: If time_limit.
        """
        if time.monotonic() > self._deadline:
            raise ArchivePolicyError("time_limit")
        data = self._stream.read(size)
        if time.monotonic() > self._deadline:
            raise ArchivePolicyError("time_limit")
        return data


def _publish_tar_gz_atomically(
    destination: Path,
    members: List[Tuple[Path, str, bool]],
    *,
    expected_members: Optional[List[str]] = None,
    archive_limits: Optional[ArchiveLimits] = None,
) -> List[str]:
    """
    Build, validate, and atomically publish one gzip tar artifact.

    The implementation uses ``destination``, ``members``, and
    ``expected_members`` to build, validate, and atomically publish one gzip tar
    artifact. Filesystem effects remain confined to the caller-selected paths
    and the owning resource lifecycle. If the function cannot build, validate,
    and atomically publish one gzip tar artifact, its exception reaches the
    caller instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        destination: filesystem location used as the destination for this
            operation.
        members: Member values received from the source collection in their
            existing order.
        expected_members: Optional expected members; ``None`` selects the
            function's default behavior.
        archive_limits: Optional catalog-resolved local creation limits.

    Returns:
        The validated ``actual_names``.

    Raises:
        ValueError: If atomic tar publication lacks at least one source; or
            unsafe recursive archive source: ``source``.
        ArchivePolicyError: If time_limit; source_changed; or
            source_open_failed.
        RuntimeError: If archive contains no regular-file payload; or archive
            member inventory differs from staged sources.
    """

    if not members:
        raise ValueError("atomic tar publication requires at least one source")
    # These members have already passed their individual live-transfer bounds
    # and now form a tool-owned local collector artifact.  Do not reapply the
    # much smaller untrusted-archive default to their aggregate size.
    limits = resolve_archive_creation_limits(archive_limits)
    deadline = time.monotonic() + limits.max_seconds
    snapshots = _snapshot_authored_tar_members(
        members,
        limits=limits,
        deadline=deadline,
    )
    with _open_publication_parent(destination) as parent:
        descriptor, temporary_name = _create_publication_staging_file(parent)
        temporary_metadata: Optional[os.stat_result] = os.fstat(descriptor)
        try:
            with os.fdopen(descriptor, "w+b") as staging_stream:
                descriptor = -1
                with tarfile.open(
                    fileobj=staging_stream,
                    mode="w:gz",
                ) as archive:
                    for source, member_name, expected_details in snapshots:
                        if time.monotonic() > deadline:
                            raise ArchivePolicyError("time_limit")
                        try:
                            before = source.lstat()
                        except OSError as error:
                            raise ArchivePolicyError("source_changed") from error
                        if _archive_source_fingerprint(
                            before
                        ) != _archive_source_fingerprint(expected_details):
                            raise ArchivePolicyError("source_changed")

                        member_info = archive.gettarinfo(
                            str(source), arcname=member_name
                        )
                        if member_info.name.rstrip("/") != member_name:
                            raise ArchivePolicyError("source_changed")
                        if (
                            stat.S_ISREG(expected_details.st_mode)
                            and not member_info.isfile()
                        ) or (
                            stat.S_ISDIR(expected_details.st_mode)
                            and not member_info.isdir()
                        ):
                            raise ValueError(
                                f"unsafe recursive archive source: {source}"
                            )

                        if stat.S_ISREG(expected_details.st_mode):
                            flags = (
                                os.O_RDONLY
                                | getattr(os, "O_CLOEXEC", 0)
                                | getattr(os, "O_NOFOLLOW", 0)
                                | getattr(os, "O_NONBLOCK", 0)
                            )
                            try:
                                source_descriptor = os.open(source, flags)
                                opened = os.fstat(source_descriptor)
                            except OSError as error:
                                if "source_descriptor" in locals():
                                    os.close(source_descriptor)
                                    del source_descriptor
                                raise ArchivePolicyError(
                                    "source_open_failed"
                                ) from error
                            if _archive_source_fingerprint(
                                opened
                            ) != _archive_source_fingerprint(expected_details):
                                os.close(source_descriptor)
                                del source_descriptor
                                raise ArchivePolicyError("source_changed")
                            with os.fdopen(source_descriptor, "rb") as source_stream:
                                del source_descriptor
                                archive.addfile(
                                    member_info,
                                    _DeadlineCheckedArchiveReader(
                                        source_stream, deadline
                                    ),
                                )
                                if _archive_source_fingerprint(
                                    os.fstat(source_stream.fileno())
                                ) != _archive_source_fingerprint(expected_details):
                                    raise ArchivePolicyError("source_changed")
                        else:
                            archive.addfile(member_info)

                        try:
                            after = source.lstat()
                        except OSError as error:
                            raise ArchivePolicyError("source_changed") from error
                        if _archive_source_fingerprint(
                            after
                        ) != _archive_source_fingerprint(expected_details):
                            raise ArchivePolicyError("source_changed")

                    for source, _member_name, expected_details in snapshots:
                        try:
                            final_details = source.lstat()
                        except OSError as error:
                            raise ArchivePolicyError("source_changed") from error
                        if _archive_source_fingerprint(
                            final_details
                        ) != _archive_source_fingerprint(expected_details):
                            raise ArchivePolicyError("source_changed")

                staging_stream.flush()
                os.fsync(staging_stream.fileno())
                temporary_metadata = os.fstat(staging_stream.fileno())
                validation = validate_open_tar_stream_for_creation(
                    staging_stream,
                    limits=limits,
                )

            actual_names = [name for _path, name, _details in snapshots]
            if not actual_names or validation.regular_files == 0:
                raise RuntimeError("archive contains no regular-file payload")
            if validation.members != len(actual_names):
                raise RuntimeError(
                    "Archive member inventory differs from staged sources"
                )
            if expected_members is not None and actual_names != expected_members:
                raise RuntimeError(
                    "Archive member inventory differs from staged sources"
                )

            _publish_staging_file(parent, temporary_name, temporary_metadata)
            temporary_metadata = None
            return actual_names
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            _unlink_publication_staging_file(
                parent,
                temporary_name,
                temporary_metadata,
            )


def _publish_file_atomically(source: Path, destination: Path) -> None:
    """
    Copy one validated file into place without exposing partial output.

    The implementation uses ``source`` and ``destination`` to copy one validated
    file into place without exposing partial output. Filesystem effects remain
    confined to the caller-selected paths and the owning resource lifecycle. If
    the function cannot copy one validated file into place without exposing
    partial output, its exception reaches the caller instead of being converted
    into a successful result. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        source: filesystem location used as the source for this operation.
        destination: filesystem location used as the destination for this
            operation.

    Raises:
        ValueError: If the publication source is not a regular file: ``source``.
        ArchivePolicyError: If source_changed.
    """
    source = Path(source)
    source_descriptor = -1
    with _open_publication_parent(destination) as parent:
        descriptor, temporary_name = _create_publication_staging_file(parent)
        temporary_metadata: Optional[os.stat_result] = os.fstat(descriptor)
        try:
            source_descriptor = os.open(
                source,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            source_metadata = os.fstat(source_descriptor)
            if not stat.S_ISREG(source_metadata.st_mode):
                raise ValueError(f"publication source must be a regular file: {source}")
            with (
                os.fdopen(source_descriptor, "rb") as source_stream,
                os.fdopen(descriptor, "wb") as destination_stream,
            ):
                source_descriptor = -1
                descriptor = -1
                copied_bytes = 0
                while True:
                    chunk = source_stream.read(
                        min(
                            _COMPOSITE_COPY_CHUNK_BYTES,
                            source_metadata.st_size - copied_bytes + 1,
                        )
                    )
                    if not chunk:
                        break
                    copied_bytes += len(chunk)
                    if copied_bytes > source_metadata.st_size:
                        raise ArchivePolicyError("source_changed")
                    destination_stream.write(chunk)
                destination_stream.flush()
                os.fsync(destination_stream.fileno())
                temporary_metadata = os.fstat(destination_stream.fileno())
                if (
                    copied_bytes != source_metadata.st_size
                    or _archive_source_fingerprint(os.fstat(source_stream.fileno()))
                    != _archive_source_fingerprint(source_metadata)
                ):
                    raise ArchivePolicyError("source_changed")

            _publish_staging_file(parent, temporary_name, temporary_metadata)
            temporary_metadata = None
        finally:
            if source_descriptor >= 0:
                os.close(source_descriptor)
            if descriptor >= 0:
                os.close(descriptor)
            _unlink_publication_staging_file(
                parent,
                temporary_name,
                temporary_metadata,
            )


def _publish_bounded_bytes_atomically(
    payload: bytes,
    destination: Path,
    max_bytes: int,
    cancellation_event: threading.Event,
) -> _BoundedEvidencePublicationReceipt:
    """
    Publish one bounded byte document without exposing partial output.

    The destination parent is pinned through the same no-symlink publication
    boundary used for collected Host artifacts. The payload is written to a
    private sibling, flushed to stable storage, and linked into place only after
    its type and exact size have been verified. Publication is exclusive so a
    later hook or retry cannot silently overwrite prior evidence. Cancellation
    observed before the exclusive link leaves no destination. Once the link
    succeeds, publication finishes validation and directory synchronization and
    belongs to the caller's retain-on-commit contract.

    Args:
        payload: Fully rendered byte document to publish.
        destination: Logger-selected artifact path receiving the document.
        max_bytes: Positive maximum accepted payload size.
        cancellation_event: Cooperative cancellation signal checked before
            filesystem work and around the atomic publication boundary.

    Returns:
        Exact published byte count for the durable committed document.

    Raises:
        TypeError: If ``payload`` is not bytes or ``cancellation_event`` is not
            a thread event.
        ValueError: If ``max_bytes`` is invalid or the payload is empty or
            exceeds the configured bound.
        FileExistsError: If the destination already contains evidence.
        OSError: If the private write, validation, or atomic publication fails.
        _ManagedFilesystemOperationStopped: If publication was cancelled.

    Side Effects:
        Creates ``destination`` only after the complete bounded payload is
        durable, and removes any owned temporary sibling on failure.
    """
    if not isinstance(payload, bytes):
        raise TypeError("bounded publication payload must be bytes")
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("bounded publication max_bytes must be a positive integer")
    if not payload or len(payload) > max_bytes:
        raise ValueError("bounded publication payload is empty or exceeds its limit")
    if not isinstance(cancellation_event, threading.Event):
        raise TypeError("bounded publication cancellation_event is invalid")
    if cancellation_event.is_set():
        raise _ManagedFilesystemOperationStopped(
            "bounded snapshot evidence publication was cancelled"
        )

    descriptor = -1
    with _open_publication_parent(destination) as parent:
        descriptor, temporary_name = _create_publication_staging_file(parent)
        temporary_metadata: Optional[os.stat_result] = os.fstat(descriptor)
        try:
            with os.fdopen(descriptor, "wb") as destination_stream:
                descriptor = -1
                written = destination_stream.write(payload)
                if written != len(payload):
                    raise OSError("bounded publication write was incomplete")
                destination_stream.flush()
                os.fsync(destination_stream.fileno())
                temporary_metadata = os.fstat(destination_stream.fileno())
            if (
                not stat.S_ISREG(temporary_metadata.st_mode)
                or temporary_metadata.st_nlink != 1
                or temporary_metadata.st_size != len(payload)
            ):
                raise OSError("bounded publication staging file failed validation")
            publication = _publish_staging_file_exclusively(
                parent,
                temporary_name,
                temporary_metadata,
                cancellation_event,
            )
            temporary_metadata = None
            return publication
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            _unlink_publication_staging_file(
                parent,
                temporary_name,
                temporary_metadata,
            )


REMOTE_TRANSFER_DIR_MODE = "775"
REMOTE_TRANSFER_FILE_MODE = "644"
# Compatibility budget for the older in-memory stream summarizer. Persisted
# host-command diagnostics now retain byte counts rather than stream content.
HOST_COMMAND_CAPTURE_STREAM_MAX_CHARS = 16 * 1024
_HOST_COMMAND_CAPTURE_SAFE_FIELDS = (
    "command_id",
    "command_name",
    "transport",
    "target",
    "captured_at",
    "exit_code",
    "status",
    "stdout_bytes",
    "stderr_bytes",
    "duration_ms",
    "timeout",
    "use_sudo",
)
_HOST_SSH_POOL_METRIC_FIELDS = (
    "normalized_endpoints",
    "active_sessions",
    "active_channels",
    "queued_commands",
    "connections_created",
    "connection_reuses",
    "commands_started",
    "command_failures",
    "backpressure_waits",
    "backpressure_timeouts",
    "peak_active_sessions",
    "peak_active_channels",
    "peak_queued_commands",
)
_HOST_COMMAND_CAPTURE_ID_RE = re.compile(r"\Ahost_ssh:[0-9]{6}\Z")
_HOST_COMMAND_CAPTURE_NAME_RE = re.compile(r"\A[A-Za-z0-9_.:-]{1,80}\Z")
_OUTPUT_VALIDATED_NONZERO_POLICIES = {
    (
        "coredumpctl list",
        (1, 127),
        (
            "No coredumps found",
            r"^\s*(?:[^\n:]+:\s*)?(?:(?:line )?\d+:\s*)?coredumpctl: (?:command )?not found\s*$",
        ),
    ): "host_coredumpctl_expected_nonzero",
    (
        "systemctl status systemd-coredump",
        (4,),
        (r"Unit systemd-coredump\.service could not be found",),
    ): "host_systemd_coredump_status_expected_nonzero",
}

_MANAGED_ARTIFACT_DIR_RE = re.compile(
    r"\A/(?:[A-Za-z0-9._-]+/)*\.nvdebug-managed-[a-f0-9]{64}/artifacts\Z"
)
_MANAGED_FILE_BASENAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_MANAGED_FILE_EXTENSION_RE = re.compile(r"\A(?:\.[A-Za-z0-9][A-Za-z0-9._-]{0,15})?\Z")
_MANAGED_MODE_NAME_RE = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")
_MAX_MANAGED_METADATA_COMMANDS = 8
_MANAGED_ARTIFACT_INSPECTION_TIMEOUT_SECONDS = 30
_MANAGED_ARTIFACT_TRANSFER_TIMEOUT_SECONDS = 300
_MANAGED_ARTIFACT_PERSIST_TIMEOUT_SECONDS = 300
_MAX_MANAGED_DECOMPRESSED_BYTES = 128 * 1024 * 1024 * 1024
_MANAGED_FILE_CHUNK_BYTES = 1024 * 1024
_MAX_MANAGED_STDOUT_BYTES = 64 * 1024
_ADVANCED_MANAGED_RECEIPT_SCHEMA_VERSION = "1.0"
_ADVANCED_MANAGED_RECEIPT_POLICY = "single_managed_advanced"


class _ManagedFilesystemOperationStopped(RuntimeError):
    """
    A private managed-artifact worker reached cancellation or its deadline.

    Callers receive this exception when the managed filesystem operation stopped
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


async def _run_owned_bounded_evidence_publication(
    payload: bytes,
    destination: Path,
    max_bytes: int,
) -> _BoundedEvidencePublicationReceipt:
    """
    Run evidence publication to a terminal, cancellation-consistent outcome.

    The shared managed filesystem worker normally returns cancellation promptly
    and observes its worker later. Required evidence needs a stronger boundary:
    this helper shields that worker, supplies cooperative cancellation directly,
    and does not return until the worker is terminal. Cancellation observed by
    the publisher before its exclusive commit leaves no destination. If a
    complete durable commit wins the race, the artifact is retained, its receipt
    is attached privately to the original cancellation, and that cancellation
    still propagates.

    Args:
        payload: Fully rendered bounded evidence document.
        destination: Logger-selected artifact path receiving the document.
        max_bytes: Positive maximum accepted serialized payload size.

    Returns:
        Exact byte receipt for an uncancelled durable publication.

    Raises:
        asyncio.CancelledError: If caller cancellation is observed; it is raised
            only after the publication worker is terminal. The exception may
            privately carry a durable publication receipt for timing closure.
        BaseException: If publication fails without a competing caller
            cancellation.

    Side Effects:
        Owns the bounded publication worker through terminal state. A canceled
        caller may retain a complete diagnostic artifact when the durable commit
        finishes before the cancellation boundary is resolved.
    """
    cancellation_event = threading.Event()
    worker = asyncio.create_task(
        _run_managed_filesystem_operation(
            _publish_bounded_bytes_atomically,
            payload,
            destination,
            max_bytes,
            cancellation_event,
            cancellation_event=cancellation_event,
        )
    )
    caller_failure: Optional[BaseException] = None

    while not worker.done():
        try:
            await asyncio.shield(worker)
        except asyncio.CancelledError as exc:
            if worker.cancelled():
                break
            if caller_failure is None:
                caller_failure = exc
            cancellation_event.set()
        except BaseException as exc:
            if worker.done():
                break
            if caller_failure is None:
                caller_failure = exc
            cancellation_event.set()

    try:
        publication = worker.result()
    except BaseException:
        if caller_failure is not None:
            raise caller_failure
        raise

    if caller_failure is not None:
        setattr(
            caller_failure,
            _BOUNDED_EVIDENCE_CANCELLATION_RECEIPT_ATTRIBUTE,
            publication,
        )
        raise caller_failure

    # Catch cancellation already queued when the publication worker completed.
    # A commit that reaches this asynchronous checkpoint remains truthful
    # evidence, but the enclosing cancellation still takes precedence over a
    # collector success result.
    try:
        await asyncio.sleep(0)
    except asyncio.CancelledError as exc:
        setattr(
            exc,
            _BOUNDED_EVIDENCE_CANCELLATION_RECEIPT_ATTRIBUTE,
            publication,
        )
        raise

    return publication


@dataclass(frozen=True)
class _ManagedPublication:
    """
    Implement the managed publication boundary used by the NVDebug runtime.

    The immutable record keeps its collector identity and exact inode together
    so rollback can remove the file and invalidate only matching inventory
    claims. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        dut_id: Stable DUT identifier owning the publication.
        collector_id: Stable collector identifier owning the publication.
        device: Numeric device retained by this record.
        inode: Numeric inode retained by this record.
    """

    path: Path
    dut_id: str
    collector_id: str
    device: int
    inode: int


@dataclass
class _ManagedPublicationOwner:
    """
    Implement the managed publication owner boundary used by the NVDebug runtime.

    Implement the managed publication owner boundary used by the NVDebug
    runtime.

    The coherent record keeps ``publications``, ``adopted``, and ``sealed``
    together so consumers observe one managed publication owner state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        publications: Collection of publications entries retained by this
            record.
        adopted: Whether adopted applies to this record.
        sealed: Whether sealed applies to this record.
    """

    publications: List[_ManagedPublication]
    adopted: bool = False
    sealed: bool = False


_MANAGED_PUBLICATION_OWNER: ContextVar[Optional[_ManagedPublicationOwner]] = ContextVar(
    "managed_host_publication_owner", default=None
)


def _register_managed_publication(
    path: str | Path,
    *,
    dut_id: str,
    collector_id: str,
) -> bool:
    """
    Register one exact regular single-link file with the active transaction.

    The implementation uses ``path``, ``dut_id``, and ``collector_id`` to
    register one exact regular single-link file with the active transaction.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle.

    Args:
        path: filesystem location used as the path for this operation.
        dut_id: Stable DUT identifier owning the publication.
        collector_id: Stable collector identifier owning the publication.

    Returns:
        Whether the register one exact regular single-link file with the active
        transaction operation succeeds.
    """

    owner = _MANAGED_PUBLICATION_OWNER.get()
    if owner is None:
        return True
    if owner.sealed:
        return False
    publication_path = Path(path)
    try:
        status = publication_path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        return False
    owner.publications.append(
        _ManagedPublication(
            path=publication_path,
            dut_id=dut_id,
            collector_id=collector_id,
            device=status.st_dev,
            inode=status.st_ino,
        )
    )
    return True


def _rollback_managed_publications(owner: _ManagedPublicationOwner) -> bool:
    """
    Remove only still-identical files from an unadopted managed run.

    The implementation uses ``owner`` to remove only still-identical files from
    an unadopted managed run.

    Args:
        owner: Owner object whose ``adopted``, ``publications``, and ``sealed``
            state is read while performing remove only still-identical files
            from an unadopted managed run.

    Returns:
        Whether every registered path was already absent or its still-identical
        inode was removed and verified absent.
    """

    owner.sealed = True
    if owner.adopted:
        return True
    rollback_verified = True
    for publication in reversed(owner.publications):
        try:
            status = publication.path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            rollback_verified = False
            continue
        if not (
            stat.S_ISREG(status.st_mode)
            and status.st_nlink == 1
            and status.st_dev == publication.device
            and status.st_ino == publication.inode
        ):
            rollback_verified = False
            continue
        try:
            publication.path.unlink()
        except FileNotFoundError:
            continue
        except OSError:
            rollback_verified = False
            continue
        try:
            publication.path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            rollback_verified = False
        else:
            rollback_verified = False
    return rollback_verified


@dataclass(frozen=True)
class _ManagedModeCollection:
    """
    Runtime-only mode result paired with its bounded public evidence.

    The immutable record keeps ``attempt``, ``output_file``,
    ``diagnostic_files``, ``error_files``, and ``error_message`` together so
    consumers observe one managed mode collection state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        attempt: Mapping that retains the attempt fields for this record.
        output_file: Canonical text used as output file.
        diagnostic_files: Collection of diagnostic files entries retained by
            this record.
        error_files: Collection of error files entries retained by this record.
        error_message: Canonical text used as error message.
    """

    attempt: Mapping[str, Any]
    output_file: Optional[str] = None
    diagnostic_files: Tuple[str, ...] = ()
    error_files: Tuple[str, ...] = ()
    error_message: Optional[str] = None


@dataclass(frozen=True)
class _DeviceCollectionOutput:
    """
    Pair one produced device artifact with its duplicate-path diagnostic.

    Device workers retain this immutable record until their owner aggregates
    results in discovery order. Keeping the diagnostic beside the path lets
    aggregation reject cross-device collisions without depending on task
    completion order or collector-specific command knowledge.

    Attributes:
        path: Persisted output path returned by the shared storage boundary.
        duplicate_error: Bounded operator-facing error used if another
            successful operation already claimed the same path.
        managed_attempt: Canonical lifecycle evidence for a managed artifact,
            or None for an ordinary command-output file.
    """

    path: str
    duplicate_error: str
    managed_attempt: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class _DeviceCollectionOutcome:
    """
    Retain one device worker's deterministic collection result.

    Each worker owns its device's ordered commands and returns only local
    immutable state. The parent can therefore run workers concurrently while
    preserving discovery-order output, error, and diagnostic aggregation.

    Attributes:
        device_id: Endpoint-discovered device identity for this worker.
        total_operations: Number of attempted or rejected device operations.
        outputs: Successful output candidates in per-device command order.
        diagnostic_files: Diagnostic artifacts emitted by managed operations.
        error_messages: Bounded failures observed for this device.
    """

    device_id: str
    total_operations: int
    outputs: Tuple[_DeviceCollectionOutput, ...] = ()
    diagnostic_files: Tuple[str, ...] = ()
    error_messages: Tuple[str, ...] = ()


@dataclass(frozen=True)
class _ManagedMetadataCollection:
    """
    Optional metadata artifacts plus the lifecycle safety decision.

    The immutable record keeps ``files``, ``warnings``, and
    ``lifecycle_uncertain`` together so consumers observe one managed metadata
    collection state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        files: Collection of files entries retained by this record.
        warnings: Collection of warnings entries retained by this record.
        lifecycle_uncertain: Whether lifecycle uncertain applies to this record.
    """

    files: Tuple[str, ...] = ()
    warnings: Tuple[str, ...] = ()
    lifecycle_uncertain: bool = False


def _resolve_device_collection_concurrency(values: Mapping[str, Any]) -> int:
    """
    Resolve the catalog-authored per-device worker limit.

    A value of one selects serial device work, while larger values opt into
    bounded concurrency. The fixed runtime ceiling prevents a malformed or
    unreviewed catalog from turning bounded device discovery into an unbounded
    set of active SSH and filesystem operations.

    Args:
        values: Hook parameters containing the optional ``device_concurrency``
            value.

    Returns:
        The validated positive concurrency limit.

    Raises:
        ValueError: If the configured value is boolean, non-integral, below
            one, or above the runtime safety ceiling.
    """

    value = values.get("device_concurrency", 1)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > _MAX_DEVICE_COLLECTION_CONCURRENCY
    ):
        raise ValueError(
            "device_concurrency must be an integer between 1 and "
            f"{_MAX_DEVICE_COLLECTION_CONCURRENCY}"
        )
    return value


def _relative_file_name_for_pattern(
    file_name: str, output_pattern: Optional[str]
) -> str:
    """
    Remove an exact static ``{file_name}`` wrapper already in the name.

    The implementation uses ``file_name`` and ``output_pattern`` to remove an
    exact static ``{file_name}`` wrapper already in the name.

    Args:
        file_name: Stable file name used for lookup and operator-facing
            diagnostics.
        output_pattern: Text supplied as output pattern in the format accepted
            by this function.

    Returns:
        The canonical relative file name for pattern text.
    """
    if not output_pattern or "{file_name}" not in output_pattern:
        return file_name

    prefix, suffix = output_pattern.split("{file_name}", 1)
    if not prefix or not file_name.startswith(prefix):
        return file_name

    candidate = file_name[len(prefix) :]
    if suffix:
        if not candidate.endswith(suffix):
            return file_name
        candidate = candidate[: -len(suffix)]
    return candidate or file_name


def _hours_to_since_until(stream_begin, stream_end, now_utc=None):
    """
    Resolve stream window values into absolute UTC timestamps for host tools.

    The implementation uses ``stream_begin``, ``stream_end``, and ``now_utc`` to
    resolve stream window values into absolute UTC timestamps for host tools.

    Args:
        stream_begin: Stream begin consumed while the function attempts to
            resolve stream window values into absolute UTC timestamps for host
            tools.
        stream_end: Stream end consumed while the function attempts to resolve
            stream window values into absolute UTC timestamps for host tools.
        now_utc: Optional now utc; ``None`` selects the function's default
            behavior.

    Returns:
        A tuple containing ``format host stream timestamp`` and ``format host
        stream timestamp`` in that order.
    """
    begin_dt, end_dt = normalize_stream_window(stream_begin, stream_end, now_utc)
    return (
        format_host_stream_timestamp(begin_dt),
        format_host_stream_timestamp(end_dt),
    )


def _safe_archive_member_name(
    remote_path: str,
    *,
    limits: Optional[ArchiveLimits] = None,
) -> str:
    """
    Map a remote POSIX path to a traversal-safe relative archive member.

    Redundant separators and ``.`` components are POSIX-equivalent spellings of
    the same operand, so they are still normalized away. The resulting name --
    the one the remote ``tar`` will write and the local extractor will later
    read -- is then judged by the shared ``utils.archive_member_policy``
    decision, which makes this producer gate a superset of that consumer. A
    device-chosen name carrying a backslash, a control character, or more
    components than the archive profile allows is therefore refused here, as one
    counted target failure, instead of being admitted and poisoning the archive
    that every other matched target shares.

    Args:
        remote_path: Remote source path, taken from collector configuration or
            from device-controlled glob output.
        limits: Optional archive limits; ``None`` resolves the operator-
            configured profile so the depth ceiling matches the extractor's.

    Returns:
        The canonical safe archive member name.

    Raises:
        ValueError: If the remote archive source path is not a non-empty string;
            or unsafe remote archive source path: ``remote_path``.
        ArchivePolicyError: If the configured archive limit profile is invalid.
    """
    if not isinstance(remote_path, str) or not remote_path or "\x00" in remote_path:
        raise ValueError("remote archive source path must be a non-empty string")

    remote = PurePosixPath(remote_path)
    parts = [part for part in remote.parts if part not in {"", ".", remote.anchor}]
    if not parts:
        raise ValueError(f"unsafe remote archive source path: {remote_path!r}")

    active_limits = resolve_archive_limits(limits)
    try:
        validated = validate_distributable_member_name(
            "/".join(parts),
            max_path_depth=active_limits.max_path_depth,
        )
    except MemberNamePolicyError as error:
        raise ValueError(
            f"unsafe remote archive source path: {remote_path!r}"
        ) from error

    return "/".join(validated)


class HostService(BaseService):
    """
    Service for Host operations.

    Provides collectors for host OS-based log collection including system logs,
    diagnostic commands, and file collection via SSH or local access.
    """

    _SAFE_REMOTE_GLOB_PATTERN = re.compile(r"\A/[A-Za-z0-9_./*\-]+\Z")
    _SAFE_NVOS_ARCHIVE_BASENAME = re.compile(
        r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,254}\.tar\.gz\Z"
    )

    def __init__(self, service_name: str, orchestrator: Any) -> None:
        """
        Initialize Host service.

        The initializer records ``_host_command_captures`` and
        ``_host_command_locks`` for later operations and establishes the
        instance invariants before any public method runs.

        Args:
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.
            orchestrator: Orchestrator consumed while the function attempts to
                initialize Host service.
        """
        super().__init__(service_name, orchestrator)
        self._host_command_captures: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        self._host_command_locks: Dict[Tuple[str, str], asyncio.Lock] = {}
        self._archive_validation_slots = asyncio.BoundedSemaphore(2)

    async def _log_collection_archive_size_advisory(
        self,
        dut_id: str,
        archive_path: str | Path,
        policy: _HostArchiveTransferPolicy,
    ) -> Optional[str]:
        """
        Warn when a complete Host archive exceeds its expected size.

        The local artifact has already crossed the bounded transport before
        this check. Exceeding the operational expectation records an explicit
        DUT runtime warning while allowing validation and persistence to
        continue under the independent hard collection ceiling.

        Args:
            dut_id: Stable DUT identifier used to correlate the runtime entry.
            archive_path: Local downloaded collection archive to measure.
            policy: Aligned expected and hard Host archive limits.

        Returns:
            The emitted advisory, or ``None`` when the archive remains within
            its expected size.

        Raises:
            ValueError: If the measured archive is already outside the hard
                collection ceiling.

        Side Effects:
            Writes one warning to the DUT runtime log when the expected size is
            exceeded.
        """

        try:
            observed_bytes = Path(archive_path).stat().st_size
        except OSError:
            # This advisory must never convert an otherwise valid collection
            # into a failure. The subsequent validation/persistence boundary
            # remains authoritative for missing or unstable local artifacts.
            return None
        if observed_bytes <= policy.expected_bytes:
            return None
        advisory = collection_archive_size_advisory(
            policy.expected_bytes,
            observed_bytes,
            policy.max_transfer_bytes,
        )
        if advisory is not None:
            await self._write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "HostService",
                advisory,
            )
        return advisory

    def _runtime_boundary(self, dut_id: str, key: str) -> int:
        """
        Resolve one validated baseboard boundary with safe legacy fallback.

        After applying local validation, the function forwards ``dut_id`` and
        ``key`` to ``runtime_boundary_value`` and preserves its return and
        exception contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            key: Stable key used for lookup and operator-facing diagnostics.

        Returns:
            The numeric runtime boundary value.
        """

        config: Any = {}
        manager = getattr(self, "dut_manager", None)
        if manager is not None:
            try:
                config = manager.get_dut_config(dut_id) or {}
            except Exception:
                config = {}
        return runtime_boundary_value(config, key)

    def _runtime_boundaries(self, dut_id: str) -> Mapping[str, Any]:
        """
        Return the resolved catalog boundaries attached to one DUT.

        Missing managers and malformed compatibility configurations produce an
        empty mapping, which the downstream resolver converts to safe defaults.

        Args:
            dut_id: Stable DUT identifier used to select its resolved config.

        Returns:
            The resolved runtime boundary mapping, or an empty mapping.
        """

        manager = getattr(self, "dut_manager", None)
        if manager is None:
            return {}
        try:
            config = manager.get_dut_config(dut_id) or {}
        except Exception:
            return {}
        if not isinstance(config, Mapping):
            return {}
        boundaries = config.get(RUNTIME_BOUNDARIES_KEY)
        return boundaries if isinstance(boundaries, Mapping) else {}

    @staticmethod
    def _managed_attempt_receipt_is_canonical(context: Any) -> bool:
        """
        Recognize only a complete, strictly projected attempt receipt.

        The implementation uses ``context`` to recognize only a complete,
        strictly projected attempt receipt.

        Args:
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            Whether the recognize only a complete, strictly projected attempt
            receipt operation succeeds.
        """

        if not isinstance(context, Mapping):
            return False
        receipt = context.get("attempt_policy")
        try:
            return project_attempt_policy(receipt) == receipt
        except CollectorAttemptPolicyError:
            return False

    @staticmethod
    def _project_advanced_managed_receipt(raw: Any) -> Dict[str, Any]:
        """
        Project one strict single-attempt advanced managed receipt.

        The projection deliberately excludes paths, timings, and arbitrary
        nested context. Its canonical attempt record proves command outcome,
        artifact integrity, and cgroup-v2 cleanup as one inseparable lifecycle.

        Args:
            raw: Candidate serialized receipt from an advanced collector.

        Returns:
            A canonical advanced managed receipt with exactly one attempt.

        Raises:
            CollectorAttemptPolicyError: If the receipt or its attempt is
                malformed, noncanonical, or not cgroup-v2 owned.
        """

        return project_advanced_managed_receipt(raw)

    @classmethod
    def _build_advanced_managed_receipt(
        cls, attempt: Mapping[str, Any]
    ) -> Dict[str, Any]:
        """
        Build one canonical receipt from a terminal advanced managed attempt.

        Projection through the strict validator ensures callers cannot attach
        an incomplete or noncanonical lifecycle claim to a persisted artifact.

        Args:
            attempt: Path-free terminal attempt produced by the managed mode.

        Returns:
            The strict single-attempt advanced managed receipt.

        Raises:
            CollectorAttemptPolicyError: If ``attempt`` is not canonical.
        """

        return cls._project_advanced_managed_receipt(
            {
                "schema_version": _ADVANCED_MANAGED_RECEIPT_SCHEMA_VERSION,
                "policy": _ADVANCED_MANAGED_RECEIPT_POLICY,
                "enforced": True,
                "attempt": dict(attempt),
            }
        )

    @staticmethod
    def _managed_device_publication_context_is_durable(
        context: Mapping[str, Any],
    ) -> bool:
        """
        Bind successful device receipts to the transaction's exact publications.

        Every retained artifact must carry a canonical successful command,
        valid-content verdict, and verified process-group or cgroup cleanup.
        The complete receipt inventory must match the active owner's files
        and their original inodes; unrelated fallback receipts cannot adopt
        device files. Failed sibling commands may still yield a partial result.

        Args:
            context: Final collector context containing device artifact receipts.

        Returns:
            Whether every owned publication has complete, matching evidence.
        """
        observation = context.get("collector_budget_observation")
        if isinstance(observation, Mapping) and observation.get(
            "wall_timeout_triggered"
        ):
            return False
        receipt = context.get("device_managed_receipt")
        if not isinstance(receipt, Mapping) or set(receipt) != {
            "schema_version",
            "policy",
            "enforced",
            "artifacts",
        }:
            return False
        if (
            receipt["schema_version"] != "1.0"
            or receipt["policy"] != "managed_device_artifacts"
            or receipt["enforced"] is not True
            or not isinstance(receipt["artifacts"], list)
            or not receipt["artifacts"]
        ):
            return False
        paths = set()
        for artifact in receipt["artifacts"]:
            if not isinstance(artifact, Mapping) or set(artifact) != {
                "output_file",
                "attempt",
            }:
                return False
            path = artifact["output_file"]
            candidate = artifact["attempt"]
            if (
                not isinstance(path, str)
                or not path
                or path in paths
                or not isinstance(candidate, Mapping)
                or not isinstance(candidate.get("cleanup"), Mapping)
                or not isinstance(candidate.get("command"), Mapping)
                or type(candidate["command"].get("exit_code")) is not int
            ):
                return False
            try:
                expected = attempt_record(
                    candidate.get("mode"),
                    disposition="success",
                    failure_category=None,
                    command_status="success",
                    exit_code=0,
                    artifact_status="valid",
                    cleanup_status="verified_absent",
                    cleanup_scope=candidate["cleanup"].get("scope"),
                )
            except CollectorAttemptPolicyError:
                return False
            if candidate != expected:
                return False
            paths.add(path)
        output_files = context.get("output_files")
        if (
            not isinstance(output_files, list)
            or any(not isinstance(path, str) for path in output_files)
            or not paths.issubset(output_files)
        ):
            return False
        owner = _MANAGED_PUBLICATION_OWNER.get()
        if owner is not None:
            if owner.sealed or paths != {str(item.path) for item in owner.publications}:
                return False
            for item in owner.publications:
                try:
                    status = item.path.lstat()
                except OSError:
                    return False
                if not (
                    stat.S_ISREG(status.st_mode)
                    and status.st_nlink == 1
                    and status.st_dev == item.device
                    and status.st_ino == item.inode
                ):
                    return False
        return True

    @classmethod
    def _managed_publication_context_is_durable(cls, context: Any) -> bool:
        """
        Accept only canonical evidence for the selected managed lifecycle.

        An explicitly present advanced receipt is authoritative: malformed or
        unsuccessful advanced evidence may never fall back to an unrelated
        legacy attempt-policy receipt in the same context.
        Device artifacts instead require a complete file-bound receipt set.

        Args:
            context: Final collector context controlling publication adoption.

        Returns:
            Whether the context carries lifecycle-complete publication proof.
        """

        if not isinstance(context, Mapping):
            return False
        if "device_managed_receipt" in context:
            if "advanced_managed_receipt" in context or "attempt_policy" in context:
                return False
            return cls._managed_device_publication_context_is_durable(context)
        if "advanced_managed_receipt" not in context:
            return cls._managed_attempt_receipt_is_canonical(context)
        receipt = context.get("advanced_managed_receipt")
        try:
            projected = cls._project_advanced_managed_receipt(receipt)
        except CollectorAttemptPolicyError:
            return False
        if projected != receipt:
            return False
        attempt = projected["attempt"]
        return bool(
            attempt["disposition"] == "success"
            and attempt["failure_category"] is None
            and attempt["command"] == {"status": "success", "exit_code": 0}
            and attempt["artifact"] == {"status": "valid"}
            and attempt["cleanup"]
            == {"scope": "cgroup_v2", "status": "verified_absent"}
        )

    @classmethod
    def _managed_publication_receipt_is_durable(cls, result: Any) -> bool:
        """
        Require a canonical non-timeout receipt before retaining publications.

        The implementation uses ``result`` to require a canonical non-timeout
        receipt before retaining publications. Every required invariant is
        checked before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Args:
            result: Result object whose ``get`` state is read while performing
                canonical non-timeout receipt before retaining publications.

        Returns:
            Whether the canonical non-timeout receipt before retaining
            publications operation succeeds.
        """

        if not isinstance(result, Mapping):
            return False
        context = result.get("context")
        if not isinstance(context, Mapping):
            return False
        if "device_managed_receipt" in context and (
            result.get("success") is not True
            or result.get("status") not in {"success", "partial"}
        ):
            return False
        observation = context.get("collector_budget_observation")
        if isinstance(observation, Mapping) and observation.get(
            "wall_timeout_triggered"
        ):
            return False
        return cls._managed_publication_context_is_durable(context)

    @staticmethod
    def _without_managed_publication_paths(
        paths: Any,
        excluded_paths: Tuple[str, ...],
    ) -> List[str]:
        """
        Remove exact transaction-owned names from one inventory sequence.

        Comparisons are lexical and absolute rather than symlink-resolving so a
        replacement at a registered name cannot escape exclusion by pointing
        somewhere else.

        Args:
            paths: Candidate sequence of output inventory values.
            excluded_paths: Exact registered publication names to omit.

        Returns:
            Ordered string paths which are not transaction exclusions.
        """

        if not isinstance(paths, (list, tuple)):
            return []
        excluded_keys = {
            os.path.abspath(os.path.normpath(path)) for path in excluded_paths
        }
        retained: List[str] = []
        for path in paths:
            if not isinstance(path, (str, os.PathLike)):
                continue
            candidate = str(path)
            if os.path.abspath(os.path.normpath(candidate)) in excluded_keys:
                continue
            retained.append(candidate)
        return list(dict.fromkeys(retained))

    @classmethod
    def _scrub_managed_publication_mapping(
        cls,
        value: Any,
        excluded_paths: Tuple[str, ...],
        *,
        mark_error: bool,
        reason: str,
    ) -> Any:
        """
        Copy and scrub managed paths from a result or context mapping.

        Known nested result envelopes are copied recursively so a rolled-back
        artifact cannot remain advertised below an otherwise-correct top-level
        inventory. Error projection also removes a stale successful status.

        Args:
            value: Candidate mapping crossing a finalization boundary.
            excluded_paths: Exact registered publication names to omit.
            mark_error: Whether to replace terminal success fields with an
                authoritative error projection.
            reason: Sanitized path-free failure reason for that projection.

        Returns:
            A scrubbed shallow mapping, or the original non-mapping value.
        """

        if not isinstance(value, Mapping):
            return value
        scrubbed = dict(value)
        for field_name in (
            "output_files",
            "diagnostic_files",
            "error_files",
            "all_files",
            "finalized_inventory",
        ):
            if field_name in scrubbed:
                scrubbed[field_name] = cls._without_managed_publication_paths(
                    scrubbed[field_name],
                    excluded_paths,
                )
        discovered = scrubbed.get("discovered_files")
        if isinstance(discovered, Mapping):
            scrubbed_discovered = {
                str(folder): cls._without_managed_publication_paths(
                    paths,
                    excluded_paths,
                )
                for folder, paths in discovered.items()
            }
            scrubbed["discovered_files"] = {
                folder: paths for folder, paths in scrubbed_discovered.items() if paths
            }
        for nested_field in ("context", "execution_result", "finalized_status"):
            nested_mapping = scrubbed.get(nested_field)
            if isinstance(nested_mapping, Mapping) and nested_mapping is not value:
                scrubbed[nested_field] = cls._scrub_managed_publication_mapping(
                    nested_mapping,
                    excluded_paths,
                    mark_error=mark_error,
                    reason=reason,
                )
        if mark_error:
            if "success" in scrubbed:
                scrubbed["success"] = False
            scrubbed["status"] = "error"
            scrubbed["reason"] = reason
            scrubbed["failure_category"] = CollectorFailureCategory.INTERNAL_ERROR.value
        return scrubbed

    def _scrub_managed_publication_inventory_claims(
        self,
        owner: _ManagedPublicationOwner,
        *,
        reason: str,
    ) -> Tuple[Tuple[str, str], ...]:
        """
        Exclude nondurable paths and scrub concrete logger inventory caches.

        The logger can cache both a reconciled file inventory and the terminal
        collector result before the outer execution transaction returns. This
        method first installs a run-scoped exact-name exclusion for every owner,
        including transactions cancelled before any cache existed. It then
        updates only those exact DUT/collector pairs and lexical paths so later
        status rewrites and physical refreshes cannot retain a rolled-back or
        inode-replaced publication.

        Args:
            owner: Managed transaction whose publications are no longer
                durable.
            reason: Path-free terminal reason projected into cached results.

        Returns:
            Ordered DUT/collector pairs owning nondurable publications,
            including owners which had not reached a logger cache yet.
        """

        publications_by_key: Dict[Tuple[str, str], List[str]] = {}
        for publication in owner.publications:
            publications_by_key.setdefault(
                (publication.dut_id, publication.collector_id),
                [],
            ).append(str(publication.path))

        logger = getattr(self, "logger", None)
        inventories = getattr(logger, "_collector_file_inventories", None)
        collector_results = getattr(logger, "collector_results", None)
        collector_status = getattr(logger, "collector_status", None)
        logger_root = getattr(logger, "base_log_dir", None)
        exclude_inventory_paths = getattr(
            logger,
            "exclude_collector_file_inventory_paths",
            None,
        )
        publication_keys: List[Tuple[str, str]] = []
        for (dut_id, collector_id), path_values in publications_by_key.items():
            excluded_paths = tuple(dict.fromkeys(path_values))
            if callable(exclude_inventory_paths):
                exclude_inventory_paths(
                    dut_id,
                    collector_id,
                    excluded_paths,
                )
            excluded_keys = {
                os.path.abspath(os.path.normpath(path)) for path in excluded_paths
            }
            cache_key = f"{dut_id}:{collector_id}"
            if isinstance(inventories, dict):
                cached_inventory = inventories.get(cache_key)
                if isinstance(cached_inventory, Mapping):
                    scrubbed_inventory = self._scrub_managed_publication_mapping(
                        cached_inventory,
                        excluded_paths,
                        mark_error=False,
                        reason=reason,
                    )
                    inventories[cache_key] = scrubbed_inventory
            if isinstance(collector_results, dict):
                cached_result = collector_results.get(cache_key)
                if isinstance(cached_result, Mapping):
                    scrubbed_result = self._scrub_managed_publication_mapping(
                        cached_result,
                        excluded_paths,
                        mark_error=True,
                        reason=reason,
                    )
                    collector_results[cache_key] = scrubbed_result
            if isinstance(collector_status, Mapping):
                for group_status in collector_status.values():
                    if not isinstance(group_status, Mapping):
                        continue
                    dut_status = group_status.get(dut_id)
                    if not isinstance(dut_status, Mapping):
                        continue
                    collectors = dut_status.get("collectors")
                    if not isinstance(collectors, Mapping):
                        continue
                    collector_record = collectors.get(collector_id)
                    if not isinstance(collector_record, dict):
                        continue
                    retained_files: List[str] = []
                    for path in collector_record.get("files", []):
                        if not isinstance(path, (str, os.PathLike)):
                            continue
                        raw_path = os.fspath(path)
                        candidate_keys = {os.path.abspath(os.path.normpath(raw_path))}
                        if logger_root is not None and not os.path.isabs(raw_path):
                            candidate_keys.add(
                                os.path.abspath(
                                    os.path.normpath(
                                        os.path.join(
                                            os.fspath(logger_root),
                                            dut_id,
                                            raw_path,
                                        )
                                    )
                                )
                            )
                        if candidate_keys & excluded_keys:
                            continue
                        retained_files.append(raw_path)
                    collector_record["files"] = list(dict.fromkeys(retained_files))
            publication_keys.append((dut_id, collector_id))
        return tuple(publication_keys)

    async def _rollback_managed_publication_transaction(
        self,
        owner: _ManagedPublicationOwner,
        *,
        reason: str,
    ) -> bool:
        """
        Roll back files and correct every already-written terminal claim.

        One owned task corrects logger, tracker, status-file, and execution
        summary projections after synchronous inode-safe rollback and cache
        scrubbing. Cancellation is deferred until that task reaches a terminal
        state, then re-raised so control flow stays authoritative without
        leaving a removed publication advertised as successful.

        Args:
            owner: Managed transaction which did not reach durable adoption.
            reason: Path-free terminal reason for rewritten status metadata.

        Returns:
            Whether exact file rollback and every required terminal correction
            completed.

        Raises:
            asyncio.CancelledError: After the single owned correction task has
                reached a terminal state when cancellation is requested.
        """

        rollback_verified = _rollback_managed_publications(owner)
        resolved_reason = (
            reason
            if rollback_verified
            else "Managed publication rollback could not be verified"
        )
        publication_keys = self._scrub_managed_publication_inventory_claims(
            owner,
            reason=resolved_reason,
        )
        if not publication_keys:
            return rollback_verified

        async def rewrite_terminal_claims() -> bool:
            """
            Correct all terminal surfaces from scrubbed cached inventory.

            Each affected collector is projected through the logger, tracker,
            status-file, and execution-summary owners in one task. Individual
            failures are recorded while the remaining corrections still run.

            Returns:
                Whether all authoritative error projections completed.
            """

            corrections_verified = True
            for dut_id, collector_id in publication_keys:
                cache_key = f"{dut_id}:{collector_id}"
                logger = getattr(self, "logger", None)
                inventories = getattr(logger, "_collector_file_inventories", {})
                collector_results = getattr(logger, "collector_results", {})
                cached_inventory = (
                    inventories.get(cache_key, {})
                    if isinstance(inventories, Mapping)
                    else {}
                )
                cached_result = (
                    collector_results.get(cache_key, {})
                    if isinstance(collector_results, Mapping)
                    else {}
                )
                output_files = self._without_managed_publication_paths(
                    cached_inventory.get("output_files", []),
                    tuple(str(item.path) for item in owner.publications),
                )
                diagnostic_files = self._without_managed_publication_paths(
                    cached_inventory.get("diagnostic_files", []),
                    tuple(str(item.path) for item in owner.publications),
                )
                error_files = self._without_managed_publication_paths(
                    cached_inventory.get("error_files", []),
                    tuple(str(item.path) for item in owner.publications),
                )
                all_files = list(
                    dict.fromkeys(output_files + diagnostic_files + error_files)
                )
                discovered_files = self._group_inventory_files(all_files)
                cached_context = (
                    cached_result.get("context", {})
                    if isinstance(cached_result, Mapping)
                    else {}
                )
                context = (
                    dict(cached_context) if isinstance(cached_context, Mapping) else {}
                )
                context.update(
                    {
                        "status": "error",
                        "reason": resolved_reason,
                        "failure_category": (
                            CollectorFailureCategory.INTERNAL_ERROR.value
                        ),
                    }
                )
                execution_time_value = (
                    cached_result.get("execution_time", 0.0)
                    if isinstance(cached_result, Mapping)
                    else 0.0
                )
                execution_time = (
                    float(execution_time_value)
                    if isinstance(execution_time_value, (int, float))
                    and not isinstance(execution_time_value, bool)
                    else 0.0
                )

                result_logger = getattr(logger, "log_collector_result", None)
                if callable(result_logger):
                    logger_kwargs: Dict[str, Any] = {}
                    if self._callable_accepts_keyword(
                        result_logger,
                        "failure_category",
                    ):
                        logger_kwargs["failure_category"] = (
                            CollectorFailureCategory.INTERNAL_ERROR.value
                        )
                    if self._callable_accepts_keyword(
                        result_logger,
                        "refresh_inventory",
                    ):
                        logger_kwargs["refresh_inventory"] = False
                    if self._callable_accepts_keyword(
                        result_logger,
                        "authoritative_projection",
                    ):
                        logger_kwargs["authoritative_projection"] = True
                    try:
                        await result_logger(
                            dut_id,
                            collector_id,
                            "error",
                            resolved_reason,
                            execution_time,
                            output_files,
                            context,
                            discovered_files,
                            **logger_kwargs,
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        corrections_verified = False

                tracker = getattr(
                    getattr(self, "orchestrator", None),
                    "status_tracker",
                    None,
                )
                complete_collector = getattr(tracker, "complete_collector", None)
                if callable(complete_collector):
                    try:
                        await complete_collector(
                            dut_id,
                            collector_id,
                            "error",
                            resolved_reason,
                            execution_time,
                            output_files,
                            discovered_files,
                            context,
                            diagnostic_files=diagnostic_files,
                            error_files=error_files,
                            all_files=all_files,
                            failure_category=(
                                CollectorFailureCategory.INTERNAL_ERROR.value
                            ),
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        corrections_verified = False

                try:
                    await self._write_collector_status_with_cached_inventory(
                        collector_id,
                        dut_id,
                        "error",
                        resolved_reason,
                        CollectorFailureCategory.INTERNAL_ERROR.value,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    corrections_verified = False

                orchestrator = getattr(self, "orchestrator", None)
                summary_manager = getattr(
                    orchestrator,
                    "execution_summary_manager",
                    None,
                )
                summary_corrector = getattr(
                    summary_manager,
                    "correct_collector_entry",
                    None,
                )
                summary_writer = getattr(
                    orchestrator,
                    "add_execution_summary_entry",
                    None,
                )
                if callable(summary_corrector) or callable(summary_writer):
                    try:
                        if callable(summary_corrector):
                            await summary_corrector(
                                dut_id,
                                collector_id,
                                "error",
                                all_files,
                                resolved_reason,
                                CollectorFailureCategory.INTERNAL_ERROR.value,
                            )
                        else:
                            await self._add_execution_summary_entry(
                                dut_id,
                                collector_id,
                                "error",
                                all_files,
                                resolved_reason,
                                CollectorFailureCategory.INTERNAL_ERROR.value,
                            )
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        corrections_verified = False
                    else:
                        setattr(
                            self,
                            f"execution_summary_added_{dut_id}_{collector_id}",
                            True,
                        )
                        setattr(
                            self,
                            f"execution_summary_status_{dut_id}_{collector_id}",
                            "error",
                        )
            return corrections_verified

        rewrite_task = asyncio.create_task(rewrite_terminal_claims())
        deferred_cancel = False
        while not rewrite_task.done():
            try:
                await asyncio.shield(rewrite_task)
            except asyncio.CancelledError:
                deferred_cancel = True
            except Exception:
                break
        try:
            rewrites_verified = rewrite_task.result()
        except (asyncio.CancelledError, Exception):
            rewrites_verified = False
        if deferred_cancel:
            raise asyncio.CancelledError
        return rollback_verified and rewrites_verified

    async def _collector_wall_timeout_result(
        self,
        dut_id: str,
        collector_id: str,
        collection_level: str,
        budget: ResolvedCollectorBudget,
        *,
        wall_started: float,
        cancellation_settled: bool,
        timed_out_run_token: object,
    ) -> Dict[str, Any]:
        """
        Rollback managed files before Base inventories a receiptless timeout.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``collection_level``, ``budget``, and ``wall_started``
        to ``_collector_wall_timeout_result`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            budget: Budget consumed while the function attempts to rollback
                managed files before Base inventories a receiptless timeout.
            wall_started: Numeric wall started used while the operation performs
                bounded accounting.
            cancellation_settled: Whether cancellation settled is enabled or
                required for this operation.
            timed_out_run_token: Timed out run token consumed while the function
                attempts to rollback managed files before Base inventories a
                receiptless timeout.

        Returns:
            A mapping containing collector wall timeout result.
        """

        publication_owner = _MANAGED_PUBLICATION_OWNER.get()
        if publication_owner is not None:
            _rollback_managed_publications(publication_owner)
        return await super()._collector_wall_timeout_result(
            dut_id,
            collector_id,
            collection_level,
            budget,
            wall_started=wall_started,
            cancellation_settled=cancellation_settled,
            timed_out_run_token=timed_out_run_token,
        )

    async def finalize_collector(
        self,
        dut_id: str,
        collector_id: str,
        status: str,
        reason: str,
        execution_time: float = 0.0,
        output_files: Optional[List[str]] = None,
        discovered_files: Optional[Dict[str, List[str]]] = None,
        detailed_context: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Prevent receiptless finalization from claiming managed publications.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``status``, ``reason``, and ``execution_time`` to
        ``finalize_collector`` and preserves its return and exception contract.
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
            discovered_files: Optional discovered files; ``None`` selects the
                function's default behavior.
            detailed_context: Optional detailed context; ``None`` selects the
                function's default behavior.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing finalize collector.
        """

        # Catalog post-processing hooks merge the execution context into kwargs,
        # while Base's terminal finalizer passes the same evidence through
        # detailed_context.  Treat an explicit detailed context as authoritative.
        receipt_context: Any = (
            detailed_context if detailed_context is not None else kwargs
        )
        advanced_receipt_present = bool(
            isinstance(receipt_context, Mapping)
            and "advanced_managed_receipt" in receipt_context
        )
        durable_receipt = self._managed_publication_context_is_durable(receipt_context)
        if advanced_receipt_present and status != "success":
            durable_receipt = False
        if (
            isinstance(receipt_context, Mapping)
            and "device_managed_receipt" in receipt_context
            and status not in {"success", "partial"}
        ):
            durable_receipt = False
        publication_owner = _MANAGED_PUBLICATION_OWNER.get()
        nondurable_publications = bool(
            publication_owner is not None
            and publication_owner.publications
            and not publication_owner.sealed
            and not durable_receipt
        )
        if nondurable_publications:
            assert publication_owner is not None
            excluded_paths = tuple(
                str(publication.path) for publication in publication_owner.publications
            )
            rollback_verified = _rollback_managed_publications(publication_owner)
            # The collector's reason identifies the actual failed invariant
            # (for example an unverified remote scratch cleanup).  Publication
            # rollback is a consequence of that failure, not a replacement
            # diagnosis.  Keep the causal reason on every terminal surface and
            # record rollback disposition as structured context.
            causal_reason = (
                "Managed device artifact publication lacks complete lifecycle evidence"
                if status == "success"
                and isinstance(receipt_context, Mapping)
                and "device_artifact_containment" in receipt_context
                else str(reason).strip() or "Collector did not reach durable completion"
            )
            rollback_status = "verified" if rollback_verified else "unverified"
            self._scrub_managed_publication_inventory_claims(
                publication_owner,
                reason=causal_reason,
            )
            status = "error"
            reason = causal_reason
            output_files = self._without_managed_publication_paths(
                output_files,
                excluded_paths,
            )
            if isinstance(discovered_files, Mapping):
                discovered_files = {
                    str(folder): self._without_managed_publication_paths(
                        paths,
                        excluded_paths,
                    )
                    for folder, paths in discovered_files.items()
                }
                discovered_files = {
                    folder: paths for folder, paths in discovered_files.items() if paths
                }
            if detailed_context is not None:
                detailed_context = self._scrub_managed_publication_mapping(
                    detailed_context,
                    excluded_paths,
                    mark_error=True,
                    reason=reason,
                )
                detailed_context["managed_publication_rollback"] = rollback_status
            execution_result = kwargs.get("execution_result")
            if isinstance(execution_result, Mapping):
                kwargs["execution_result"] = self._scrub_managed_publication_mapping(
                    execution_result,
                    excluded_paths,
                    mark_error=True,
                    reason=reason,
                )
            kwargs["_managed_publication_excluded_paths"] = list(excluded_paths)
            kwargs["managed_publication_rollback"] = rollback_status
        return await super().finalize_collector(
            dut_id,
            collector_id,
            status,
            reason,
            execution_time=execution_time,
            output_files=output_files,
            discovered_files=discovered_files,
            detailed_context=detailed_context,
            **kwargs,
        )

    async def execute_collector(
        self, dut_id: str, collector_id: str, collection_level: str = "L1"
    ) -> Dict[str, Any]:
        """
        Own managed publications through Base finalization and status writes.

        The implementation uses ``dut_id``, ``collector_id``, and
        ``collection_level`` to own managed publications through Base
        finalization and status writes. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        If the function cannot own managed publications through Base
        finalization and status writes, its exception reaches the caller instead
        of being converted into a successful result. Cleanup in the ``finally``
        path runs for successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collection_level: Text supplied as collection level in the format
                accepted by this function.

        Returns:
            A mapping containing execute collector.

        Raises:
            RuntimeError: If managed publication transaction is sealed.
        """

        inherited_owner = _MANAGED_PUBLICATION_OWNER.get()
        if inherited_owner is not None:
            if inherited_owner.sealed:
                raise RuntimeError("managed publication transaction is sealed")
            return await super().execute_collector(
                dut_id, collector_id, collection_level
            )

        publication_owner = _ManagedPublicationOwner(publications=[])
        publication_token = _MANAGED_PUBLICATION_OWNER.set(publication_owner)
        try:
            result = await super().execute_collector(
                dut_id, collector_id, collection_level
            )
            receipt_context = (
                result.get("context") if isinstance(result, Mapping) else None
            )
            advanced_receipt_present = bool(
                isinstance(receipt_context, Mapping)
                and "advanced_managed_receipt" in receipt_context
            )
            durable_receipt = self._managed_publication_receipt_is_durable(result)
            if advanced_receipt_present and (
                result.get("success") is not True or result.get("status") != "success"
            ):
                durable_receipt = False
            if durable_receipt:
                publication_owner.adopted = True
            elif publication_owner.publications and not publication_owner.sealed:
                excluded_paths = tuple(
                    str(publication.path)
                    for publication in publication_owner.publications
                )
                rollback_verified = (
                    await self._rollback_managed_publication_transaction(
                        publication_owner,
                        reason=(
                            "Managed publication execution did not reach "
                            "durable completion"
                        ),
                    )
                )
                result = self._scrub_managed_publication_mapping(
                    result,
                    excluded_paths,
                    mark_error=True,
                    reason=(
                        "Managed publication execution did not reach durable completion"
                        if rollback_verified
                        else "Managed publication rollback could not be verified"
                    ),
                )
            elif publication_owner.publications and publication_owner.sealed:
                # A finalizer or timeout boundary already performed the
                # inode-safe rollback before Base published terminal status.
                # Scrub the returned envelope locally so nested compatibility
                # projections remain complete, but do not invoke the terminal
                # correction workflow a second time.
                excluded_paths = tuple(
                    str(publication.path)
                    for publication in publication_owner.publications
                )
                result_reason = (
                    str(result.get("reason", "")).strip()
                    or "Collector did not reach durable completion"
                )
                result = self._scrub_managed_publication_mapping(
                    result,
                    excluded_paths,
                    mark_error=True,
                    reason=result_reason,
                )
            return result
        except BaseException:
            if (
                publication_owner.publications
                and not publication_owner.adopted
                and not publication_owner.sealed
            ):
                try:
                    await self._rollback_managed_publication_transaction(
                        publication_owner,
                        reason=(
                            "Managed publication execution did not reach "
                            "durable completion"
                        ),
                    )
                except BaseException:
                    pass
            raise
        finally:
            _rollback_managed_publications(publication_owner)
            _MANAGED_PUBLICATION_OWNER.reset(publication_token)

    @staticmethod
    def _create_advanced_staging_context(
        dut_id: str,
        collector_id: str,
        mode_name: str,
        local_parent: Optional[str] = None,
    ) -> tempfile.TemporaryDirectory:
        """
        Create an operation-private local staging directory.

        Advanced collectors commonly generate the same remote basename on every
        DUT (for example ``nvidia-bug-report_safe.log.gz``). A shared ``/tmp``
        destination lets concurrent DUTs overwrite or remove one another's
        downloads, so include the execution identity and a random suffix.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            mode_name: Stable mode name used for lookup and operator-facing
                diagnostics.
            local_parent: Optional validated collector-local directory beneath
                which the private staging directory is created.

        Returns:
            A ``TemporaryDirectory`` representing advanced staging context.
        """

        def safe_component(value: Any, fallback: str) -> str:
            """
            Return the safe component.

            The implementation uses ``value`` and ``fallback`` to produce the
            safe component.

            Args:
                value: Value evaluated while performing safe component.
                fallback: Text supplied as fallback in the format accepted by
                    this function.

            Returns:
                Whether the safe component operation succeeds.
            """
            normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or fallback))
            return normalized.strip("._-") or fallback

        prefix = "nvdebug_advanced_{}_{}_{}_".format(
            safe_component(dut_id, "dut"),
            safe_component(collector_id, "collector"),
            safe_component(mode_name, "mode"),
        )
        return tempfile.TemporaryDirectory(prefix=prefix, dir=local_parent)

    @staticmethod
    def _normalize_remote_staging_root(value: Any) -> str:
        """
        Return one absolute, traversal-free endpoint staging root.

        The implementation uses ``value`` to produce one absolute,
        traversal-free endpoint staging root. If the function cannot produce one
        absolute, traversal-free endpoint staging root, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            value: Value evaluated while performing one absolute, traversal-free
                endpoint staging root.

        Returns:
            The validated ``normalized``.

        Raises:
            ValueError: If the remote staging root is not a non-empty string;
                remote staging root contains unsafe characters; the remote
                staging root is not an absolute normalized path; or remote
                staging root must not be the filesystem root.
        """

        if not isinstance(value, str) or not value:
            raise ValueError("remote staging root must be a non-empty string")
        if (
            len(value) > 3072
            or "\x00" in value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("remote staging root contains unsafe characters")
        path = PurePosixPath(value)
        if not path.is_absolute() or any(part == ".." for part in path.parts):
            raise ValueError("remote staging root must be an absolute normalized path")
        normalized = path.as_posix().rstrip("/")
        if not normalized or normalized == "/":
            raise ValueError("remote staging root must not be the filesystem root")
        return normalized

    async def _resolve_remote_staging_root(
        self, dut_id: str, configured_root: Optional[str] = None
    ) -> str:
        """
        Resolve the data-driven endpoint temp root without weakening it.

        After applying local validation, the function forwards ``dut_id`` and
        ``configured_root`` to ``self._normalize_remote_staging_root`` and
        preserves its return and exception contract. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            configured_root: Optional filesystem location used as the configured
                root for this operation.

        Returns:
            The canonical remote staging root text.
        """

        root = configured_root
        if root is None:
            tool_config: Dict[str, Any] = {}
            try:
                tool_config = await self.orchestrator.get_dut_specific_tool_config(
                    dut_id
                )
            except Exception as exc:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "HostService",
                    f"Unable to resolve DUT-specific temp configuration: {exc}",
                )
            root = get_tool_temp_dir(tool_config, "/tmp")
        return self._normalize_remote_staging_root(root)

    async def _resolve_local_staging_parent(self, dut_id: str) -> Optional[str]:
        """
        Resolve the configured collector-local temporary directory safely.

        ``TOOL_TEMP_DIR`` is read through the same per-DUT merged tool
        configuration boundary used for Host scratch. Invalid or unusable local
        paths retain the established system-temporary fallback returned by
        ``local_temp_dir`` rather than weakening its symlink and permissions
        checks.

        Args:
            dut_id: Stable DUT identifier used to select the merged tool
                configuration for this collection.

        Returns:
            The validated absolute local staging parent, or ``None`` when the
            configured path cannot safely be used locally.

        Side Effects:
            May create the configured local parent with private permissions.
        """

        tool_config: Dict[str, Any] = {}
        try:
            tool_config = await self.orchestrator.get_dut_specific_tool_config(dut_id)
        except Exception as exc:
            await self._write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "HostService",
                f"Unable to resolve local temp configuration: {exc}",
            )
        return local_temp_dir(tool_config)

    async def _execute_remote_staging_command(
        self,
        dut_id: str,
        command: str,
        *,
        use_sudo: bool,
        timeout: float = _REMOTE_STAGING_COMMAND_TIMEOUT_SECONDS,
    ) -> Tuple[int, str, str]:
        """
        Execute one staging command under a pool-aware wall-clock bound.

        Small test doubles and legacy out-of-tree managers may not expose
        max_retries. Keep the same single call rather than making a
        non-idempotent mkdir retryable at this layer. The production pool may
        make one narrowly proven pre-execution connection retry, so the outer
        bound includes its configured Host SSH backpressure allowance and two
        fresh command budgets. A true outer timeout is converted to a nonzero
        command tuple, while caller cancellation remains observable.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            timeout: Maximum duration of each command budget. Queue
                backpressure, one safe pre-execution retry, and a small
                outer-bound grace are accounted separately.

        Returns:
            The command exit code, stdout, and stderr. Outer timeout returns
            exit code ``-1`` with a precise budget description in stderr.

        Raises:
            asyncio.CancelledError: If the owning collection is cancelled.
        """

        async def invoke() -> Tuple[int, str, str]:
            """
            Invoke the configured operation.

            Small test doubles and legacy out-of-tree managers may not expose
            max_retries. Keep the same single call rather than making a
            non-idempotent mkdir retryable.

            Returns:
                A tuple containing the fields that represent invoke.
            """
            try:
                return await self.dut_manager.execute_host_command(
                    dut_id,
                    command,
                    timeout=timeout,
                    max_retries=1,
                    use_sudo=use_sudo,
                )
            except TypeError as exc:
                # Small test doubles and legacy out-of-tree managers may not
                # expose max_retries. Keep the same single call rather than
                # making a non-idempotent mkdir retryable.
                if "unexpected keyword" not in str(exc):
                    raise
                return await self.dut_manager.execute_host_command(
                    dut_id,
                    command,
                    timeout=timeout,
                    use_sudo=use_sudo,
                )

        pool_config = getattr(self.dut_manager, "host_ssh_pool_config", None)
        if isinstance(pool_config, Mapping):
            configured_backpressure = pool_config.get(
                "backpressure_timeout_seconds", 0.0
            )
        else:
            configured_backpressure = getattr(
                pool_config, "backpressure_timeout_seconds", 0.0
            )
        try:
            backpressure_timeout = float(configured_backpressure)
        except (TypeError, ValueError, OverflowError):
            backpressure_timeout = 0.0
        if not math.isfinite(backpressure_timeout) or backpressure_timeout < 0:
            backpressure_timeout = 0.0

        command_timeout = max(0.0, float(timeout))
        outer_timeout = (
            backpressure_timeout
            + command_timeout * (1 + HOST_SSH_SAFE_CONNECT_RETRIES)
            + _REMOTE_STAGING_OUTER_TIMEOUT_GRACE_SECONDS
        )
        try:
            return await asyncio.wait_for(invoke(), timeout=outer_timeout)
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            return (
                -1,
                "",
                (
                    "Remote staging command timed out after "
                    f"{outer_timeout:g} seconds "
                    f"(command budgets={1 + HOST_SSH_SAFE_CONNECT_RETRIES}x"
                    f"{command_timeout:g}s, "
                    f"Host SSH backpressure={backpressure_timeout:g}s, "
                    "outer grace="
                    f"{_REMOTE_STAGING_OUTER_TIMEOUT_GRACE_SECONDS:g}s)"
                ),
            )

    async def _create_remote_staging_directory(
        self,
        dut_id: str,
        purpose: str,
        *,
        use_sudo: bool,
        owned_stages: List[_RemoteStagingDirectory],
        configured_root: Optional[str] = None,
    ) -> _RemoteStagingDirectory:
        """
        Atomically create and register an unpredictable mode-0700 directory.

        ``mkdir`` deliberately has no ``-p`` and no pre-cleanup. A preclaimed
        directory or symlink therefore makes creation fail without mutating the
        claimant or anything it points at. The unpredictable candidate is
        tentatively registered before dispatch because a lost response cannot
        prove whether ``mkdir`` executed; only a definitive positive shell exit
        relinquishes ownership without cleanup.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            purpose: Text supplied as purpose in the format accepted by this
                function.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            owned_stages: Entries supplied as ``owned_stages`` without
                transferring container ownership.
            configured_root: Optional filesystem location used as the configured
                root for this operation.

        Returns:
            The validated ``stage``.

        Raises:
            RuntimeError: If the function cannot atomically create and register
                an unpredictable mode-0700 directory safely.
        """

        root = await self._resolve_remote_staging_root(dut_id, configured_root)
        safe_purpose = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(purpose)).strip(".-")
        safe_purpose = (safe_purpose or "operation")[:48]
        stage_path = f"{root}/.nvdebug-{safe_purpose}-{secrets.token_hex(16)}"
        command = build_remote_cmd(
            "umask 077; mkdir -m {mode} -- {path} "
            "&& test -d {path} && test ! -L {path}",
            mode=_REMOTE_STAGING_DIR_MODE,
            path=stage_path,
        )
        stage = _RemoteStagingDirectory(path=stage_path, use_sudo=use_sudo)
        owned_stages.append(stage)
        return_code, _stdout, stderr = await self._execute_remote_staging_command(
            dut_id,
            command,
            use_sudo=use_sudo,
        )
        if return_code != 0:
            if return_code > 0:
                owned_stages[:] = [
                    owned for owned in owned_stages if owned is not stage
                ]
            raise RuntimeError(
                "failed to create private remote staging directory"
                + (f": {stderr}" if stderr else "")
            )
        return stage

    async def _stage_remote_tail_snapshot(
        self,
        dut_id: str,
        collector_id: str,
        stage: _RemoteStagingDirectory,
        staged_file: str,
        producer_command: str,
        *,
        max_bytes: int,
        timeout: int,
    ) -> Dict[str, Any]:
        """
        Stream one producer into an exact newest-byte remote snapshot.

        Private FIFOs split the producer stream between a byte counter and
        ``tail``. Only the bounded tail is written to disk, while producer
        output never crosses the SSH command-output channel. The complete
        pipeline runs through the target-owned managed Host lifecycle. Its
        tail readers open explicit FIFO operands once. Redirecting FIFO stdin
        can make a reader resolve and reopen that path after the writer exits,
        leaving the second open waiting for a writer that will never return.
        The fixed receipt is accepted only after every process succeeds, managed
        cleanup is verified absent, command diagnostics are published, exact
        managed scratch cleanup succeeds, and byte arithmetic is validated.
        Diagnostic publication failures reject only this snapshot target;
        cancellation still propagates after owned scratch cleanup.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration,
                logs, and results.
            collector_id: Stable collector identifier used for managed command
                timing and sanitized execution capture.
            stage: Owned private staging directory receiving the snapshot and
                control files.
            staged_file: Exact direct-child artifact path within ``stage``.
            producer_command: Safely constructed command whose stdout is the
                artifact stream.
            max_bytes: Maximum number of newest producer bytes retained.
            timeout: Maximum duration allowed for the remote pipeline.

        Returns:
            A mapping containing ``success``, validated ``metadata``, and a
            precise ``error`` when staging did not complete.

        Raises:
            asyncio.CancelledError: If the owning collection is cancelled after
                bounded managed reconciliation.
        """
        max_bytes = _resolve_host_artifact_max_bytes({"max_artifact_bytes": max_bytes})
        self._validate_remote_staging_files(stage, [staged_file])
        control_token = secrets.token_hex(8)
        control_paths = {
            name: self._remote_staging_file_path(stage, f"ctl-{control_token}-{name}")
            for name in (
                "producer.fifo",
                "counter.fifo",
                "tail.fifo",
                "stderr.fifo",
                "count.txt",
                "stderr.txt",
            )
        }
        producer_fifo = quote_arg(control_paths["producer.fifo"])
        counter_fifo = quote_arg(control_paths["counter.fifo"])
        tail_fifo = quote_arg(control_paths["tail.fifo"])
        stderr_fifo = quote_arg(control_paths["stderr.fifo"])
        count_file = quote_arg(control_paths["count.txt"])
        stderr_file = quote_arg(control_paths["stderr.txt"])
        quoted_staged_file = quote_arg(staged_file)
        fifo_inventory = " ".join(
            (
                producer_fifo,
                counter_fifo,
                tail_fifo,
                stderr_fifo,
            )
        )

        # The managed Host boundary deliberately admits only bounded
        # single-line commands. Keep shell control separators explicit so the
        # target-owned wrapper can validate this pipeline before launch.
        script = " ".join(
            (
                "umask 077;",
                "counter_pid=; stderr_pid=; tail_pid=; tee_pid=;",
                "cleanup_snapshot() {",
                'for owned_pid in "$counter_pid" "$stderr_pid" '
                '"$tail_pid" "$tee_pid"; do',
                'if test -n "$owned_pid"; then kill "$owned_pid" 2>/dev/null || :; fi;',
                "done;",
                f"rm -f -- {fifo_inventory};",
                "};",
                "trap 'cleanup_snapshot; exit 125' HUP INT TERM;",
                f"mkfifo -m 600 -- {fifo_inventory} || exit 120;",
                f"wc -c < {counter_fifo} > {count_file} & counter_pid=$!;",
                (
                    f"tail -c {_BOUNDED_SNAPSHOT_STDERR_BYTES} -- {stderr_fifo} "
                    f"> {stderr_file} & stderr_pid=$!;"
                ),
                (
                    f"tail -c {max_bytes} -- {tail_fifo} > {quoted_staged_file} "
                    "& tail_pid=$!;"
                ),
                (
                    f"tee {counter_fifo} {tail_fifo} < {producer_fifo} "
                    "> /dev/null & tee_pid=$!;"
                ),
                (
                    f"/bin/sh -c {quote_arg(producer_command)} > {producer_fifo} "
                    f"2> {stderr_fifo};"
                ),
                "producer_status=$?;",
                'wait "$tee_pid"; tee_status=$?; tee_pid=;',
                'wait "$counter_pid"; counter_status=$?; counter_pid=;',
                'wait "$tail_pid"; tail_status=$?; tail_pid=;',
                'wait "$stderr_pid"; stderr_status=$?; stderr_pid=;',
                "cleanup_snapshot;",
                "trap - HUP INT TERM;",
                (
                    'if test "$producer_status" -ne 0 '
                    '|| test "$tee_status" -ne 0 '
                    '|| test "$counter_status" -ne 0 '
                    '|| test "$tail_status" -ne 0 '
                    '|| test "$stderr_status" -ne 0; then'
                ),
                f"test ! -f {stderr_file} || cat -- {stderr_file} >&2;",
                "exit 121;",
                "fi;",
                f"raw_bytes=$(tr -d '[:space:]' < {count_file});",
                f"collected_bytes=$(wc -c < {quoted_staged_file});",
                "collected_bytes=$(printf '%s' \"$collected_bytes\" | "
                "tr -d '[:space:]');",
                'case "$raw_bytes:$collected_bytes" in *[!0-9:]*) exit 122;; esac;',
                'test -n "$raw_bytes" && test -n "$collected_bytes" || exit 122;',
                'test "$raw_bytes" -ge "$collected_bytes" || exit 122;',
                "omitted_bytes=$((raw_bytes - collected_bytes));",
                (
                    "printf 'NVDEBUG_BOUNDED_SNAPSHOT_V1 raw_bytes=%s "
                    "collected_bytes=%s omitted_bytes=%s\\n' "
                    '"$raw_bytes" "$collected_bytes" "$omitted_bytes";'
                ),
            )
        )
        compressed_script = gzip.compress(script.encode("utf-8"), mtime=0)
        encoded_script = base64.b64encode(compressed_script).decode("ascii")
        stage_command = (
            f"printf %s {quote_arg(encoded_script)} | base64 -d | gzip -d | /bin/sh"
        )
        managed = await self._run_managed_host_payload(
            dut_id,
            collector_id,
            stage_command,
            operation_name="bounded_remote_tail_snapshot",
            target_timeout_seconds=timeout,
            cleanup_timeout_seconds=(_REMOTE_SNAPSHOT_MANAGED_CLEANUP_TIMEOUT_SECONDS),
            use_sudo=stage.use_sudo,
            primary_pre_execution_grace_seconds=(
                self._host_pool_pre_execution_grace_seconds()
            ),
            output_limit_bytes=_BOUNDED_SNAPSHOT_STDERR_BYTES,
            remote_temp_root=str(PurePosixPath(stage.path).parent),
        )
        errors = []
        try:
            await self._record_managed_command_diagnostic(
                dut_id,
                collector_id,
                managed,
                command="[encoded bounded snapshot script]",
                operation="bounded_remote_tail_snapshot",
                timeout=timeout,
            )
        except Exception:
            errors.append(
                "bounded newest snapshot command diagnostic publication failed"
            )
        finally:
            if managed.cleanup.status is ManagedHostCleanupStatus.VERIFIED_ABSENT:
                scratch_cleaned = await self._cleanup_managed_artifact_directory(
                    dut_id,
                    collector_id,
                    managed.artifact_dir,
                    (),
                    use_sudo=stage.use_sudo,
                    timeout_seconds=_REMOTE_SNAPSHOT_MANAGED_CLEANUP_TIMEOUT_SECONDS,
                )
                if not scratch_cleaned:
                    errors.append(
                        "bounded newest snapshot managed scratch cleanup failed"
                    )
            else:
                errors.append("bounded newest snapshot producer cleanup was unverified")
        if errors:
            return {"success": False, "metadata": None, "error": "; ".join(errors)}
        if managed.outcome is not ManagedHostCommandOutcome.SUCCESS:
            detail = str(managed.target_stderr or "").strip()
            return {
                "success": False,
                "metadata": None,
                "error": "bounded newest snapshot producer failed"
                + (f": {detail}" if detail else f" ({managed.outcome.value})"),
            }
        if managed.stdout_truncated:
            return {
                "success": False,
                "metadata": None,
                "error": "bounded newest snapshot receipt was truncated",
            }
        try:
            metadata = _parse_bounded_snapshot_receipt(
                managed.target_stdout,
                max_bytes,
            )
        except ValueError as exc:
            return {"success": False, "metadata": None, "error": str(exc)}
        return {"success": True, "metadata": metadata, "error": None}

    def _host_pool_pre_execution_grace_seconds(self) -> Optional[float]:
        """
        Return the finite Host queue and connection allowance.

        Managed target deadlines begin only after the remote wrapper starts.
        The caller-side owner therefore separately accounts for configured
        endpoint backpressure and one bounded connection attempt. Invalid or
        absent lightweight-test configuration contributes no allowance.

        Returns:
            The positive combined pre-execution allowance, or ``None`` when no
            configured value qualifies.
        """

        pool_config = getattr(self.dut_manager, "host_ssh_pool_config", None)
        if isinstance(pool_config, Mapping):
            configured_values = (
                pool_config.get("backpressure_timeout_seconds", 0.0),
                pool_config.get("connect_timeout_seconds", 0.0),
            )
        else:
            configured_values = (
                getattr(pool_config, "backpressure_timeout_seconds", 0.0),
                getattr(pool_config, "connect_timeout_seconds", 0.0),
            )
        pre_execution_grace = 0.0
        for configured_value in configured_values:
            try:
                resolved_value = float(configured_value)
            except (TypeError, ValueError, OverflowError):
                continue
            if math.isfinite(resolved_value) and resolved_value > 0:
                pre_execution_grace += resolved_value
        return pre_execution_grace if pre_execution_grace > 0 else None

    @staticmethod
    def _remote_staging_file_path(
        stage: _RemoteStagingDirectory, file_name: Any
    ) -> str:
        """
        Return one exact direct-child path within ``stage``.

        The implementation uses ``stage`` and ``file_name`` to produce one exact
        direct-child path within ``stage``.

        Args:
            stage: Stage object whose ``path`` state is read while performing
                one exact direct-child path within ``stage``.
            file_name: Stable file name used for lookup and operator-facing
                diagnostics.

        Returns:
            The canonical remote staging file path.
        """

        component = _safe_remote_output_component(file_name)
        return f"{stage.path}/{component}"

    @staticmethod
    def _validate_remote_staging_files(
        stage: _RemoteStagingDirectory, remote_files: List[str]
    ) -> List[str]:
        """
        Validate a finite list of exact, direct staging children.

        The implementation uses ``stage`` and ``remote_files`` to validate a
        finite list of exact, direct staging children. Every required invariant
        is checked before a successful value is returned; invalid input follows
        the function's explicit exception path.

        Args:
            stage: Stage object whose ``path`` state is read while performing
                finite list of exact, direct staging children.
            remote_files: Entries supplied as ``remote_files`` without
                transferring container ownership.

        Returns:
            The validated ``validated``.

        Raises:
            ValueError: If remote staging file inventory is empty or too large;
                remote staging file path is invalid; the remote staging files
                are not direct stage children; or remote staging file inventory
                contains duplicates.
        """

        if not remote_files or len(remote_files) > _MAX_REMOTE_STAGING_FILES:
            raise ValueError("remote staging file inventory is empty or too large")
        stage_path = PurePosixPath(stage.path)
        validated: List[str] = []
        for remote_file in remote_files:
            if not isinstance(remote_file, str) or "\x00" in remote_file:
                raise ValueError("remote staging file path is invalid")
            candidate = PurePosixPath(remote_file)
            if candidate.parent != stage_path:
                raise ValueError("remote staging files must be direct stage children")
            _safe_remote_output_component(candidate.name)
            validated.append(candidate.as_posix())
        if len(validated) != len(set(validated)):
            raise ValueError("remote staging file inventory contains duplicates")
        return validated

    async def _prepare_remote_staging_files(
        self,
        dut_id: str,
        stage: _RemoteStagingDirectory,
        remote_files: List[str],
    ) -> Tuple[bool, str]:
        """
        Make only exact no-follow regular files readable by the SFTP user.

        The stage remains root-owned and mode 0700 while every file is checked,
        chowned and chmodded. Directory ownership is handed off last, so an
        unprivileged peer cannot swap a checked path before a privileged
        permission operation.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            stage: Stage object whose ``path`` and ``use_sudo`` state is read
                while performing make only exact no-follow regular files
                readable by the SFTP user.
            remote_files: Entries supplied as ``remote_files`` without
                transferring container ownership.

        Returns:
            A tuple containing ``comparison flag`` and ``stderr`` in that order.
        """

        validated = self._validate_remote_staging_files(stage, remote_files)
        quoted_stage = quote_arg(stage.path)
        segments = [
            f"test -d {quoted_stage}",
            f"test ! -L {quoted_stage}",
        ]
        for remote_file in validated:
            quoted_file = quote_arg(remote_file)
            segments.extend(
                [
                    f"test -f {quoted_file}",
                    f"test ! -L {quoted_file}",
                ]
            )

        sftp_username = self._resolve_sftp_username(dut_id)
        if stage.use_sudo and sftp_username:
            quoted_owner = quote_arg(f"{sftp_username}:{sftp_username}")
            for remote_file in validated:
                segments.append(f"chown -h -- {quoted_owner} {quote_arg(remote_file)}")
        elif stage.use_sudo:
            # The endpoint's sudo environment is the only safe fallback when
            # legacy credential objects do not expose host_username. It is
            # guarded and numeric; an absent identity fails closed.
            segments.extend(
                [
                    'test -n "${SUDO_UID:-}"',
                    'test -n "${SUDO_GID:-}"',
                    'case "$SUDO_UID:$SUDO_GID" in *[!0-9:]*) exit 1;; esac',
                ]
            )
            for remote_file in validated:
                segments.append(
                    f'chown -h -- "$SUDO_UID:$SUDO_GID" {quote_arg(remote_file)}'
                )

        for remote_file in validated:
            segments.append(
                f"chmod {_REMOTE_STAGING_FILE_MODE} -- {quote_arg(remote_file)}"
            )
        segments.append(f"chmod {_REMOTE_STAGING_DIR_MODE} -- {quoted_stage}")
        if stage.use_sudo and sftp_username:
            segments.append(f"chown -h -- {quoted_owner} {quoted_stage}")
        elif stage.use_sudo:
            segments.append(f'chown -h -- "$SUDO_UID:$SUDO_GID" {quoted_stage}')

        return_code, _stdout, stderr = await self._execute_remote_staging_command(
            dut_id,
            " && ".join(segments),
            use_sudo=stage.use_sudo,
        )
        return return_code == 0, stderr

    async def _cleanup_remote_staging_directories(
        self,
        dut_id: str,
        owned_stages: List[_RemoteStagingDirectory],
    ) -> bool:
        """
        Remove all owned paths exactly, even while the caller is cancelled.

        Exactly one owned task performs every exact cleanup command. Repeated
        cancellation requests are deferred until that task has reached a
        terminal state, after which cancellation is re-raised. Ordinary command
        failure, timeout, or exception returns ``False`` and may never be
        interpreted as successful collection.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            owned_stages: Entries supplied as ``owned_stages`` without
                transferring container ownership.

        Returns:
            Whether every exact remote staging cleanup completed with exit zero.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to remove all owned paths exactly, even while the
                caller is cancelled.
        """

        stages = list(dict.fromkeys(owned_stages))
        owned_stages.clear()
        if not stages:
            return True

        async def cleanup_all() -> Tuple[bool, Tuple[str, ...]]:
            """
            Execute each exact cleanup group under one task owner.

            Stages sharing a privilege boundary are removed in a single exact
            command, while bounded path-free error categories let the caller
            reject success without exposing remote paths.

            Returns:
                A success flag and bounded path-free diagnostic categories.
            """

            errors: List[str] = []
            for use_sudo in sorted({stage.use_sudo for stage in stages}):
                paths = [stage.path for stage in stages if stage.use_sudo == use_sudo]
                command = "rm -rf -- " + " ".join(quote_arg(path) for path in paths)
                try:
                    (
                        return_code,
                        _stdout,
                        _stderr,
                    ) = await self._execute_remote_staging_command(
                        dut_id,
                        command,
                        use_sudo=use_sudo,
                    )
                except Exception as error:
                    errors.append(type(error).__name__)
                else:
                    if return_code != 0:
                        errors.append(f"exit_{return_code}")
            return not errors, tuple(errors)

        cleanup_task = asyncio.create_task(cleanup_all())
        deferred_cancel = False
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError:
                deferred_cancel = True
            except Exception:
                break

        cleanup_succeeded = False
        diagnostic = "cleanup_task_failed"
        try:
            cleanup_succeeded, errors = cleanup_task.result()
            diagnostic = ",".join(errors) or "none"
        except asyncio.CancelledError:
            diagnostic = "cleanup_task_cancelled"
        except Exception as error:
            diagnostic = type(error).__name__

        if not cleanup_succeeded:
            try:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "HostService",
                    f"Failed to clean private remote staging: {diagnostic}",
                )
            except asyncio.CancelledError:
                deferred_cancel = True
            except Exception:
                pass

        if deferred_cancel:
            raise asyncio.CancelledError
        return cleanup_succeeded

    async def _validate_advanced_archive_async(
        self,
        file_path: str,
        source_name: Optional[str] = None,
        *,
        limits: Optional[ArchiveLimits] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate a downloaded archive while leaving bulk capacity for publication.

        Admit at most two archive validators across this run's shared Host
        service before entering the filesystem pool. Waiting archives consume
        no filesystem workers. An admitted cancelled owner retains its permit
        until the managed worker has drained, preserving cleanup ownership.

        Args:
            file_path: Local downloaded archive inspected without extraction.
            source_name: Optional original name used to recognize the format.
            limits: Existing bounded archive policy forwarded unchanged.

        Returns:
            The validator's unchanged success flag and optional error text.

        Raises:
            asyncio.CancelledError: After an admitted worker has drained, or
                immediately if cancellation occurs before archive admission.

        Side Effects:
            Reads the archive through the existing bounded validation path.
        """
        async with self._archive_validation_slots:
            return await _run_managed_filesystem_operation(
                partial(
                    self._validate_advanced_archive,
                    file_path,
                    source_name,
                    limits=limits,
                ),
                bulk=True,
            )

    @staticmethod
    def _validate_advanced_archive(
        file_path: str,
        source_name: Optional[str] = None,
        *,
        limits: Optional[ArchiveLimits] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate recognized compressed/archive content through end-of-stream.

        A non-empty file is not sufficient proof of a complete transfer. Read
        every compressed stream so CRC/footer and truncation failures are
        observed before the acquisition is counted. The resolved archive policy
        bounds input, member and aggregate output bytes, compression ratio,
        member count, and elapsed time. TAR validation uses the shared scan-only
        bounded-archive path so hostile metadata and decompressor working sets
        are bounded as well. Unrecognized extensions remain ordinary binary
        files and are not rejected by this archive-specific check.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            source_name: Stable source name used for lookup and operator-facing
                diagnostics.
            limits: Optional Limits governing recognized compressed/archive
                content through end-of-stream.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.

        Raises:
            ArchivePolicyError: If input_size_limit.
        """

        path = Path(file_path)
        lower_name = str(source_name or path.name).lower()
        tar_suffixes = (
            ".tar.gz",
            ".tgz",
            ".tar.xz",
            ".txz",
            ".tar.bz2",
            ".tbz",
            ".tbz2",
            ".tar",
        )
        recognized_suffixes = (*tar_suffixes, ".zip", ".gz", ".xz", ".bz2")
        if not lower_name.endswith(recognized_suffixes):
            return True, None

        try:
            if lower_name.endswith(tar_suffixes):
                # Let the shared validator resolve the environment policy once.
                # Passing the already-resolved object back through its public
                # API would incorrectly reclassify finite operator overrides as
                # programmatic limits.
                validate_tar_archive(path, limits=limits)
            elif lower_name.endswith(".zip"):
                validate_zip_archive(path, limits=limits)
            else:
                active_limits = resolve_archive_limits(limits)
                input_size = os.path.getsize(path)
                if input_size > active_limits.max_input_bytes:
                    raise ArchivePolicyError("input_size_limit")
                deadline = time.monotonic() + active_limits.max_seconds

                def drain(stream) -> None:
                    """
                    Drain all owned work before returning.

                    The implementation uses ``stream`` to drain all owned work
                    before returning. Filesystem effects remain confined to the
                    caller-selected paths and the owning resource lifecycle. If
                    the function cannot drain all owned work before returning,
                    its exception reaches the caller instead of being converted
                    into a successful result.

                    Args:
                        stream: Stream object whose ``read`` state is read while
                            performing drain all owned work before returning.

                    Raises:
                        ArchivePolicyError: If time_limit; member_size_limit;
                            total_size_limit; or compression_ratio_limit.
                    """
                    drained_bytes = 0
                    while True:
                        if time.monotonic() > deadline:
                            raise ArchivePolicyError("time_limit")
                        remaining_member = (
                            active_limits.max_member_bytes - drained_bytes
                        )
                        remaining_total = active_limits.max_total_bytes - drained_bytes
                        chunk = stream.read(
                            min(
                                1024 * 1024,
                                remaining_member + 1,
                                remaining_total + 1,
                            )
                        )
                        if time.monotonic() > deadline:
                            raise ArchivePolicyError("time_limit")
                        if not chunk:
                            break
                        drained_bytes += len(chunk)
                        if drained_bytes > active_limits.max_member_bytes:
                            raise ArchivePolicyError("member_size_limit")
                        if drained_bytes > active_limits.max_total_bytes:
                            raise ArchivePolicyError("total_size_limit")
                        if (
                            input_size > 0
                            and drained_bytes / input_size
                            > active_limits.max_compression_ratio
                        ):
                            raise ArchivePolicyError("compression_ratio_limit")

                if lower_name.endswith(".gz"):
                    with gzip.open(path, mode="rb") as stream:
                        drain(stream)
                elif lower_name.endswith(".xz"):
                    validate_xz_file(path, limits=limits)
                else:
                    with bz2.open(path, mode="rb") as stream:
                        drain(stream)
        except (
            OSError,
            EOFError,
            MemoryError,
            RuntimeError,
            ValueError,
            lzma.LZMAError,
            tarfile.TarError,
        ) as exc:
            return False, f"{type(exc).__name__}: {exc}"

        return True, None

    @staticmethod
    def _validate_managed_archive(
        file_path: str,
        source_name: str,
        cancellation_event: threading.Event,
        deadline: float,
        max_decompressed_bytes: int = _MAX_MANAGED_DECOMPRESSED_BYTES,
        max_input_bytes: int = _MAX_MANAGED_ARTIFACT_BYTES,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate managed content with time, expansion, and member bounds.

        The implementation uses ``file_path``, ``source_name``,
        ``cancellation_event``, ``deadline``, ``max_decompressed_bytes``, and
        ``max_input_bytes`` to validate managed content with time, expansion,
        and member bounds. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            source_name: Stable source name used for lookup and operator-facing
                diagnostics.
            cancellation_event: Cancellation event consumed while the function
                attempts to validate managed content with time, expansion, and
                member bounds.
            deadline: Absolute monotonic deadline after which the operation must
                stop.
            max_decompressed_bytes: Upper bound enforced for max decompressed
                bytes; the consuming boundary rejects or truncates values that
                exceed it.
            max_input_bytes: Collector-specific compressed-input byte ceiling.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.

        Raises:
            _ManagedFilesystemOperationStopped: Internally when cancellation
                or the deadline becomes observable; the boundary converts it
                into a stopped validation result.
            ArchivePolicyError: Internally for unsafe or duplicate TAR members;
                the boundary converts it into a failed validation result.
            EOFError: Internally for a truncated gzip stream; the boundary
                converts it into a failed validation result.
            ValueError: Internally for identity, structure, magic, expansion,
                or trailing-data violations; the boundary converts it into a
                failed validation result.
        """

        path = Path(file_path)
        lower_name = source_name.lower()
        tar_gzip_suffixes = (".tar.gz", ".tgz")
        unsupported_suffixes = (
            ".tar.xz",
            ".txz",
            ".tar.bz2",
            ".tbz",
            ".tbz2",
            ".tar",
            ".zip",
            ".xz",
        )
        decompressed_bytes = 0
        if (
            isinstance(max_input_bytes, bool)
            or not isinstance(max_input_bytes, int)
            or max_input_bytes <= 0
            or isinstance(max_decompressed_bytes, bool)
            or not isinstance(max_decompressed_bytes, int)
            or max_decompressed_bytes <= 0
        ):
            return False, "managed archive bounds are invalid"

        def checkpoint(increment: int = 0) -> None:
            """
            Record one managed-archive validation checkpoint.

            The implementation uses ``increment`` to record one managed-archive
            validation checkpoint. If the function cannot record one
            managed-archive validation checkpoint, its exception reaches the
            caller instead of being converted into a successful result.

            Args:
                increment: Numeric increment used while the operation performs
                    bounded accounting.

            Raises:
                _ManagedFilesystemOperationStopped: If managed archive
                    validation was cancelled; or managed archive validation
                    reached its deadline.
                ValueError: If managed archive expansion exceeded its bound.
            """
            nonlocal decompressed_bytes
            if cancellation_event.is_set():
                raise _ManagedFilesystemOperationStopped(
                    "managed archive validation was cancelled"
                )
            if time.monotonic() >= deadline:
                raise _ManagedFilesystemOperationStopped(
                    "managed archive validation reached its deadline"
                )
            decompressed_bytes += increment
            if decompressed_bytes > max_decompressed_bytes:
                raise ValueError("managed archive expansion exceeded its bound")

        def drain(stream: Any) -> None:
            """
            Drain all owned work before returning.

            The implementation uses ``stream`` to drain all owned work before
            returning. Filesystem effects remain confined to the caller-selected
            paths and the owning resource lifecycle.

            Args:
                stream: Stream object whose ``read`` state is read while
                    performing drain all owned work before returning.
            """
            while True:
                checkpoint()
                chunk = stream.read(_MANAGED_FILE_CHUNK_BYTES)
                if not chunk:
                    break
                checkpoint(len(chunk))

        try:
            checkpoint()
            initial_status = path.lstat()
            if (
                not stat.S_ISREG(initial_status.st_mode)
                or initial_status.st_nlink != 1
                or not 1 <= initial_status.st_size <= max_input_bytes
            ):
                raise ValueError("managed archive input identity is invalid")

            if lower_name.endswith(tar_gzip_suffixes):
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(path, flags)
                try:
                    opened_status = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(opened_status.st_mode)
                        or opened_status.st_nlink != 1
                        or opened_status.st_dev != initial_status.st_dev
                        or opened_status.st_ino != initial_status.st_ino
                        or opened_status.st_size != initial_status.st_size
                        or os.read(descriptor, 2) != b"\x1f\x8b"
                    ):
                        raise ValueError(
                            "managed tar/gzip identity or magic is invalid"
                        )

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    while True:
                        checkpoint()
                        compressed_chunk = os.read(
                            descriptor, _MANAGED_FILE_CHUNK_BYTES
                        )
                        if not compressed_chunk:
                            break
                        if decoder.eof:
                            raise ValueError(
                                "managed tar/gzip contains trailing gzip data"
                            )
                        pending = compressed_chunk
                        while pending:
                            remaining = max_decompressed_bytes - decompressed_bytes
                            decompressed_chunk = decoder.decompress(
                                pending,
                                min(_MANAGED_FILE_CHUNK_BYTES, remaining + 1),
                            )
                            checkpoint(len(decompressed_chunk))
                            if decoder.eof:
                                if decoder.unused_data or decoder.unconsumed_tail:
                                    raise ValueError(
                                        "managed tar/gzip contains trailing gzip data"
                                    )
                                pending = b""
                                break
                            next_pending = decoder.unconsumed_tail
                            if next_pending == pending and not decompressed_chunk:
                                raise ValueError(
                                    "managed tar/gzip decompression did not progress"
                                )
                            pending = next_pending
                    if not decoder.eof:
                        raise EOFError("managed tar/gzip stream is truncated")
                finally:
                    os.close(descriptor)

                remaining_seconds = deadline - time.monotonic()
                if remaining_seconds <= 0:
                    raise _ManagedFilesystemOperationStopped(
                        "managed archive validation reached its deadline"
                    )
                active_limits = resolve_archive_limits()
                tar_limits = replace(
                    active_limits,
                    max_input_bytes=min(active_limits.max_input_bytes, max_input_bytes),
                    max_member_bytes=min(
                        active_limits.max_member_bytes, max_decompressed_bytes
                    ),
                    max_total_bytes=min(
                        active_limits.max_total_bytes, max_decompressed_bytes
                    ),
                    max_seconds=min(active_limits.max_seconds, remaining_seconds),
                )

                def validate_member(member: Any) -> None:
                    """
                    Reject non-file payloads and duplicate TAR member names.

                    The shared scanner invokes this callback once per bounded
                    member, and the outer checkpoint remains authoritative for
                    cancellation and deadline enforcement.

                    Args:
                        member: Immutable bounded TAR metadata supplied by the
                            shared archive scanner.

                    Raises:
                        ArchivePolicyError: If the archive contains a link,
                            special member, or duplicate normalized name.
                        _ManagedFilesystemOperationStopped: If cancellation or
                            the caller deadline becomes observable.
                    """

                    checkpoint()
                    original_name = getattr(member, "original_name", "")
                    if (
                        not isinstance(original_name, str)
                        or original_name.startswith(("/", "\\"))
                        or re.match(r"^[A-Za-z]:[\\/]", original_name)
                    ):
                        raise ArchivePolicyError("unsafe_member_path")
                    if member.kind not in {"file", "directory"}:
                        raise ArchivePolicyError("unsafe_member_kind")
                    if member.duplicate:
                        raise ArchivePolicyError("duplicate_member")

                result = inspect_tar_archive_metadata(
                    path,
                    validate_member,
                    limits=tar_limits,
                )
                checkpoint()
                final_status = path.lstat()
                if (
                    final_status.st_dev != initial_status.st_dev
                    or final_status.st_ino != initial_status.st_ino
                    or final_status.st_size != initial_status.st_size
                    or result.members <= 0
                    or result.regular_files <= 0
                    or result.dropped_links != 0
                    or result.dropped_special_members != 0
                ):
                    raise ValueError("managed tar/gzip structure is invalid")
            elif lower_name.endswith(unsupported_suffixes):
                # The stdlib tar/zip parsers can allocate from hostile metadata,
                # and XZ headers can request an unbounded decoder dictionary.
                # Managed collection supports bounded tar/gzip, plain, gzip,
                # and bzip2 until the other formats have independent
                # metadata/memory-limited readers.
                return False, "managed archive format is unsupported"
            elif lower_name.endswith(".gz"):
                with gzip.open(path, mode="rb") as stream:
                    drain(stream)
            elif lower_name.endswith(".bz2"):
                with bz2.open(path, mode="rb") as stream:
                    drain(stream)
            else:
                checkpoint()
                return True, None
        except _ManagedFilesystemOperationStopped:
            return False, "managed archive validation stopped"
        except (
            OSError,
            EOFError,
            ValueError,
            tarfile.TarError,
            zipfile.BadZipFile,
            zlib.error,
        ) as exc:
            return (
                False,
                f"managed archive validation failed ({type(exc).__name__})",
            )

        return True, None

    async def _preserve_invalid_advanced_artifact(
        self,
        dut_id: str,
        collector_id: str,
        mode_name: str,
        staged_path: str,
        *,
        label: str = "corrupt",
    ) -> Optional[str]:
        """
        Copy a rejected staged artifact into collector output as evidence.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``mode_name``, ``staged_path``, and ``label`` to
        ``str`` and preserves its return and exception contract. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            mode_name: Stable mode name used for lookup and operator-facing
                diagnostics.
            staged_path: filesystem location used as the staged path for this
                operation.
            label: Text supplied as label in the format accepted by this
                function.

        Returns:
            The canonical preserve invalid advanced artifact text, or ``None``
            when the requested value is unavailable.
        """

        if not self.logger or not hasattr(self.logger, "create_collector_log_file"):
            return None

        safe_mode = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(mode_name or "mode"))
        safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(label or "invalid"))
        evidence_name = (
            f"{collector_id or 'collector'}_{safe_mode}_"
            f"{Path(staged_path).name}.{safe_label}"
        )
        try:
            evidence_path = await self.logger.create_collector_log_file(
                dut_id, "host", collector_id, evidence_name
            )
            if not evidence_path:
                return None
            shutil.copyfile(staged_path, evidence_path)
            return str(evidence_path)
        except Exception as exc:
            await self._log_runtime(
                "WARNING",
                "HostService",
                f"Failed to preserve rejected artifact {staged_path}: {exc}",
                dut_id,
            )
            return None

    async def validate_connection(self, dut_id: str) -> Tuple[bool, str]:
        """
        Validate Host connection.

        After applying local validation, the function forwards ``dut_id`` to
        ``test_host_connection`` and preserves its return and exception
        contract. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A tuple containing the connection-success flag and sanitized
            diagnostic message.
        """
        return await self.dut_manager.get_dut(dut_id).test_host_connection()

    async def _get_collector_output_dir(
        self, dut_id: str, collector_id: Optional[str]
    ) -> Optional[Path]:
        """
        Get the collector output directory path.

        Create a sentinel file to get the collector directory path.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The validated ``collector_dir``, or ``None`` when no value
            qualifies.
        """
        if not collector_id:
            return None

        # Create a sentinel file to get the collector directory path
        sentinel_path = await self.logger.create_collector_log_file(
            dut_id, "host", collector_id, ".collector_dir_sentinel"
        )

        if not sentinel_path:
            return None

        # Convert to Path and get parent directory
        collector_dir = Path(sentinel_path).parent

        # Remove the sentinel file if it exists
        sentinel_file = collector_dir / ".collector_dir_sentinel"
        if sentinel_file.exists():
            try:
                sentinel_file.unlink()
            except Exception:
                pass  # Ignore cleanup errors

        return collector_dir

    def _sanitize_bounded_snapshot_evidence_text(
        self,
        value: Any,
        *,
        field_name: str,
        max_bytes: int,
    ) -> str:
        """
        Sanitize and bound one device-derived snapshot evidence field.

        Evidence records intentionally never include the producer command.
        Target paths still originate at a remote boundary, so they pass through
        the run logger's sanitizer before publication. Control characters are
        rejected because they cannot identify a bundle artifact or remote path
        unambiguously.

        Args:
            value: Text value proposed for the evidence document.
            field_name: Stable field label used only in bounded validation
                errors.
            max_bytes: Maximum UTF-8 size accepted after sanitization.

        Returns:
            The sanitized, non-empty bounded text.

        Raises:
            ValueError: If the value is absent, changes type during
                sanitization, contains control characters, or exceeds its
                byte bound.
        """
        if not isinstance(value, str) or not value:
            raise ValueError(f"bounded snapshot {field_name} is invalid")
        sanitizer = getattr(self.logger, "_sanitize_text", None)
        sanitized = sanitizer(value) if callable(sanitizer) else value
        if not isinstance(sanitized, str) or not sanitized:
            raise ValueError(f"bounded snapshot {field_name} is invalid")
        if any(ord(character) < 32 or ord(character) == 127 for character in sanitized):
            raise ValueError(f"bounded snapshot {field_name} contains control text")
        encoded = sanitized.encode("utf-8", errors="strict")
        if len(encoded) > max_bytes:
            raise ValueError(f"bounded snapshot {field_name} exceeds its byte limit")
        return sanitized

    def _project_bounded_snapshot_evidence_record(
        self,
        record: Mapping[str, Any],
        *,
        collector_root: Path,
    ) -> Dict[str, Any]:
        """
        Project one internal snapshot receipt into a safe bundle record.

        The internal record carries the exact local output path only until this
        boundary. Publication stores a collector-relative artifact reference,
        a safe command filename or sanitized target path, and validated integer
        accounting. Command text and absolute local paths are never emitted.

        Args:
            record: Internal receipt and artifact association to project.
            collector_root: Logger-selected collector directory containing the
                associated primary artifact.

        Returns:
            A sanitized evidence record suitable for JSON publication.

        Raises:
            ValueError: If the source, artifact association, policy, direction,
                or byte accounting is unsafe or inconsistent.
            OSError: If the associated output is absent or not a regular file.
        """
        if not isinstance(record, Mapping):
            raise ValueError("bounded snapshot evidence record is invalid")

        output_value = record.get("output_file")
        if not isinstance(output_value, str) or not output_value:
            raise ValueError("bounded snapshot artifact association is missing")
        root = Path(os.path.abspath(collector_root))
        artifact_path = Path(os.path.abspath(output_value))
        resolved_root = root.resolve(strict=True)
        resolved_artifact = artifact_path.resolve(strict=True)
        if resolved_root != root or resolved_artifact != artifact_path:
            raise ValueError("bounded snapshot artifact path uses a symlink")
        try:
            relative_artifact = resolved_artifact.relative_to(resolved_root)
        except ValueError as exc:
            raise ValueError(
                "bounded snapshot artifact is outside its collector directory"
            ) from exc
        if relative_artifact == Path(".") or any(
            part in {"", ".", ".."} for part in relative_artifact.parts
        ):
            raise ValueError("bounded snapshot artifact reference is unsafe")
        artifact_status = artifact_path.lstat()
        if not stat.S_ISREG(artifact_status.st_mode) or artifact_status.st_nlink != 1:
            raise OSError("bounded snapshot artifact is not an owned regular file")
        artifact_reference = relative_artifact.as_posix()
        safe_artifact_reference = self._sanitize_bounded_snapshot_evidence_text(
            artifact_reference,
            field_name="artifact reference",
            max_bytes=_MAX_BOUNDED_SNAPSHOT_ARTIFACT_REFERENCE_BYTES,
        )
        if safe_artifact_reference != artifact_reference:
            raise ValueError(
                "bounded snapshot artifact reference required sanitization"
            )

        source_type = record.get("source_type")
        if source_type == "command":
            file_name = self._sanitize_bounded_snapshot_evidence_text(
                _safe_remote_output_component(record.get("file_name")),
                field_name="command file name",
                max_bytes=128,
            )
            source = {"type": "command", "file_name": file_name}
        elif source_type == "target":
            source_path = self._sanitize_bounded_snapshot_evidence_text(
                record.get("path"),
                field_name="source path",
                max_bytes=_MAX_BOUNDED_SNAPSHOT_SOURCE_PATH_BYTES,
            )
            parsed_source_path = PurePosixPath(source_path)
            if not parsed_source_path.is_absolute() or any(
                part in {"", ".", ".."} for part in parsed_source_path.parts[1:]
            ):
                raise ValueError("bounded snapshot source path is unsafe")
            source = {"type": "target", "path": source_path}
        else:
            raise ValueError("bounded snapshot source type is invalid")

        expected_text = {
            "oversize_policy": "tail_snapshot",
            "snapshot_direction": "newest",
        }
        for field_name, expected_value in expected_text.items():
            if record.get(field_name) != expected_value:
                raise ValueError(f"bounded snapshot {field_name} is inconsistent")

        integer_fields = (
            "max_artifact_bytes",
            "raw_bytes",
            "collected_bytes",
            "omitted_bytes",
        )
        integer_values: Dict[str, int] = {}
        for field_name in integer_fields:
            value = record.get(field_name)
            if type(value) is not int or value < 0:
                raise ValueError(
                    f"bounded snapshot {field_name} is not a non-negative integer"
                )
            integer_values[field_name] = value
        maximum = integer_values["max_artifact_bytes"]
        raw = integer_values["raw_bytes"]
        collected = integer_values["collected_bytes"]
        omitted = integer_values["omitted_bytes"]
        if (
            maximum <= 0
            or maximum > _HARD_HOST_ARTIFACT_MAX_BYTES
            or collected != min(raw, maximum)
            or omitted != raw - collected
        ):
            raise ValueError("bounded snapshot byte accounting is inconsistent")
        if artifact_status.st_size != collected:
            raise ValueError(
                "bounded snapshot artifact size differs from collected byte count"
            )

        return {
            "artifact": artifact_reference,
            "source": source,
            **expected_text,
            **integer_values,
        }

    async def _persist_bounded_snapshot_evidence(
        self,
        dut_id: str,
        collector_id: str,
        function_tag: str,
        records: List[Dict[str, Any]],
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Atomically persist bounded per-artifact snapshot accounting.

        The manifest is a diagnostic output owned by the same collector. Its
        finite schema associates each bounded primary artifact with a safe
        source identity and exact raw, collected, and omitted byte counts. An
        empty or oversized inventory fails before an artifact path is created.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration,
                logs, and results.
            collector_id: Stable collector identifier owning the output.
            function_tag: Safe authored hook identity used to give each
                file-log hook its own deterministic evidence artifact.
            records: Internal per-artifact snapshot receipts to persist.

        Returns:
            The absolute evidence artifact path and its safe projected records.

        Raises:
            asyncio.CancelledError: If the caller cancels persistence before it
                reaches a terminal result. When publication already committed,
                the complete diagnostic artifact is retained and its canceled
                timing span records the committed path, size, and state.
            RuntimeError: If the logger or collector identity is unavailable.
            ValueError: If the record inventory, projected fields, association,
                or serialized payload violates a configured bound.
            FileExistsError: If evidence for the same function tag already
                exists.
            OSError: If the evidence artifact cannot be published atomically.

        Side Effects:
            Creates one private diagnostic JSON artifact in the collector output
            and records its persistence timing when a timing manager exists. A
            canceled collector may retain this complete diagnostic artifact if
            durable publication won the cancellation race.
        """
        if not self.logger or not hasattr(self.logger, "create_collector_log_file"):
            raise RuntimeError("bounded snapshot evidence logger is unavailable")
        if not isinstance(collector_id, str) or collector_id in {"", "unknown"}:
            raise RuntimeError("bounded snapshot collector identity is unavailable")
        if not isinstance(function_tag, str) or not function_tag:
            raise RuntimeError("bounded snapshot function identity is unavailable")
        safe_function_tag = _safe_remote_output_component(function_tag)
        evidence_artifact = (
            f"{_BOUNDED_SNAPSHOT_EVIDENCE_DIRECTORY}/"
            f"{safe_function_tag}{_BOUNDED_SNAPSHOT_EVIDENCE_SUFFIX}"
        )
        if (
            not isinstance(records, list)
            or not records
            or len(records) > _MAX_BOUNDED_SNAPSHOT_EVIDENCE_ENTRIES
        ):
            raise ValueError("bounded snapshot evidence inventory is invalid")

        artifact_path = Path(
            await self.logger.create_collector_log_file(
                dut_id,
                "host",
                collector_id,
                evidence_artifact,
                apply_stream_window=False,
            )
        )
        if (
            artifact_path.name
            != f"{safe_function_tag}{_BOUNDED_SNAPSHOT_EVIDENCE_SUFFIX}"
            or artifact_path.parent.name != _BOUNDED_SNAPSHOT_EVIDENCE_DIRECTORY
        ):
            raise ValueError("bounded snapshot evidence destination is invalid")
        collector_root = artifact_path.parent.parent
        projected_records = [
            self._project_bounded_snapshot_evidence_record(
                record,
                collector_root=collector_root,
            )
            for record in records
        ]
        artifact_references = [record["artifact"] for record in projected_records]
        if len(set(artifact_references)) != len(artifact_references):
            raise ValueError("bounded snapshot artifact associations are duplicated")

        payload = (
            json.dumps(
                {
                    "schema": "nvdebug.host.bounded_snapshot_evidence.v1",
                    "records": projected_records,
                },
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        if len(payload) > _MAX_BOUNDED_SNAPSHOT_EVIDENCE_BYTES:
            raise ValueError("bounded snapshot evidence document exceeds its limit")

        timing_operation_id = None
        if self.timing_manager:
            timing_operation_id = self.timing_manager.start_operation(
                "artifact_persistence",
                evidence_artifact,
            )
        try:
            publication = await _run_owned_bounded_evidence_publication(
                payload,
                artifact_path,
                _MAX_BOUNDED_SNAPSHOT_EVIDENCE_BYTES,
            )
        except BaseException as exc:
            if self.timing_manager:
                timing_details: Dict[str, Any] = {
                    "status": (
                        "cancelled"
                        if isinstance(exc, asyncio.CancelledError)
                        else "error"
                    ),
                    "error": type(exc).__name__,
                }
                cancellation_publication = getattr(
                    exc,
                    _BOUNDED_EVIDENCE_CANCELLATION_RECEIPT_ATTRIBUTE,
                    None,
                )
                if isinstance(
                    exc,
                    asyncio.CancelledError,
                ) and isinstance(
                    cancellation_publication,
                    _BoundedEvidencePublicationReceipt,
                ):
                    timing_details.update(
                        {
                            "artifact_path": str(artifact_path),
                            "size_bytes": cancellation_publication.published_bytes,
                            "metadata": {
                                "publication_state": ("committed_during_cancellation")
                            },
                        }
                    )
                self.timing_manager.end_operation(
                    timing_operation_id,
                    **timing_details,
                )
            raise
        if self.timing_manager:
            self.timing_manager.end_operation(
                timing_operation_id,
                artifact_path=str(artifact_path),
                size_bytes=publication.published_bytes,
            )
        return str(artifact_path), projected_records

    async def _get_host_command_capture_key(
        self, dut_id: str, collector_id: Optional[str]
    ) -> Optional[Tuple[str, str]]:
        """
        Return the per-collector key used for host command capture.

        The implementation uses ``dut_id`` and ``collector_id`` to produce the
        per-collector key used for host command capture. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            A tuple containing ``DUT identifier`` and ``collector identifier``
            in that order.
        """
        if not dut_id or not collector_id or collector_id == "unknown":
            return None
        return dut_id, collector_id

    async def _start_host_command_capture(
        self, dut_id: str, collector_id: Optional[str] = None
    ) -> None:
        """
        Initialize host command capture for a collector execution.

        The implementation uses ``dut_id`` and ``collector_id`` to initialize
        host command capture for a collector execution. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
        """
        key = await self._get_host_command_capture_key(dut_id, collector_id)
        if key:
            lock = self._host_command_locks.setdefault(key, asyncio.Lock())
            async with lock:
                if key in self._host_command_captures:
                    logger.warning(
                        "Host command capture already initialized for %s/%s; "
                        "preserving existing capture entries",
                        key[0],
                        key[1],
                    )
                    return
                self._host_command_captures[key] = []

    async def _clear_host_command_capture(
        self, dut_id: str, collector_id: Optional[str] = None
    ) -> None:
        """
        Clear any pending host command capture state.

        The implementation uses ``dut_id`` and ``collector_id`` to clear any
        pending host command capture state. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
        """
        key = await self._get_host_command_capture_key(dut_id, collector_id)
        if key:
            lock = self._host_command_locks.setdefault(key, asyncio.Lock())
            async with lock:
                self._host_command_captures.pop(key, None)
                self._host_command_locks.pop(key, None)

    @staticmethod
    def _summarize_host_command_stream(
        value: Any,
        stream_name: str,
        artifact_reference: Optional[str] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Return bounded diagnostic text plus explicit truncation metadata.

        This legacy in-memory summary is not persisted by the current diagnostic
        ledger. Keep its optional marker compact regardless.

        Args:
            value: Value evaluated while performing bounded diagnostic text plus
                explicit truncation metadata.
            stream_name: Stable stream name used for lookup and operator-facing
                diagnostics.
            artifact_reference: Optional artifact reference; ``None`` selects
                the function's default behavior.

        Returns:
            A tuple containing ``status or message text`` and ``metadata`` in
            that order.
        """

        text = "" if value is None else str(value)
        original_chars = len(text)
        metadata = {
            f"{stream_name}_length_chars": original_chars,
            f"{stream_name}_truncated": False,
        }
        if original_chars <= HOST_COMMAND_CAPTURE_STREAM_MAX_CHARS:
            return text, metadata

        reference_note = ""
        if artifact_reference:
            # This legacy in-memory summary is not persisted by the current
            # diagnostic ledger. Keep its optional marker compact regardless.
            compact_reference = str(artifact_reference)[:256]
            reference_note = f"; full output artifact: {compact_reference}"
        marker = (
            f"\n... [{stream_name} truncated: {original_chars} characters total"
            f"{reference_note}] ...\n"
        )
        retained_budget = max(0, HOST_COMMAND_CAPTURE_STREAM_MAX_CHARS - len(marker))
        head_chars = (retained_budget + 1) // 2
        tail_chars = retained_budget - head_chars
        tail = text[-tail_chars:] if tail_chars else ""
        summarized = f"{text[:head_chars]}{marker}{tail}"

        metadata[f"{stream_name}_truncated"] = True
        metadata[f"{stream_name}_omitted_chars"] = max(
            0, original_chars - retained_budget
        )
        return summarized, metadata

    async def _record_host_command_execution(
        self,
        dut_id: str,
        command: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        *,
        operation_name: str,
        timeout: Optional[int] = None,
        use_sudo: Optional[bool] = None,
        collector_id: Optional[str] = None,
        output_file: Optional[str] = None,
        duration_seconds: Optional[float] = None,
    ) -> None:
        """
        Capture bounded, credential-free metadata for one host command.

        Reuse the command-result ledger's normalization and hard entry bound.
        The Host diagnostic intentionally retains only its raw completion
        status, not the ledger's policy disposition: output- validated
        expected-nonzero semantics are resolved by the caller after this
        transport result is recorded.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            exit_code: Numeric exit code used while the operation performs
                bounded accounting.
            stdout: Text supplied as stdout in the format accepted by this
                function.
            stderr: Text supplied as stderr in the format accepted by this
                function.
            operation_name: Stable operation name used for lookup and
                operator-facing diagnostics.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            output_file: Optional filesystem location used as the output file
                for this operation.
            duration_seconds: Maximum duration in seconds allowed for duration
                seconds.
        """
        resolved_collector_id = collector_id or self._get_current_collector_id()
        key = await self._get_host_command_capture_key(dut_id, resolved_collector_id)
        if not key:
            return

        lock = self._host_command_locks.setdefault(key, asyncio.Lock())
        async with lock:
            captures = self._host_command_captures.get(key)
            if captures is None:
                return

            # Reuse the command-result ledger's normalization and hard entry
            # bound.  The Host diagnostic intentionally retains only its raw
            # completion status, not the ledger's policy disposition: output-
            # validated expected-nonzero semantics are resolved by the caller
            # after this transport result is recorded.
            capture = CommandResultCapture(
                dut_id=str(dut_id),
                collector_id=key[1],
                transport="host_ssh",
                commands=captures,
                total_commands=len(captures),
            )
            previous_count = len(captures)
            capture.add(
                transport="host_ssh",
                dut_id=str(dut_id),
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration_seconds,
                target="host",
                command_kind=operation_name,
            )
            if len(captures) == previous_count:
                return

            entry = captures[-1]
            entry.pop("operation_role", None)
            entry.pop("semantic_disposition", None)
            entry.pop("raised", None)
            entry["captured_at"] = datetime.now().isoformat()
            entry["status"] = (
                "success" if entry["exit_code"] == 0 else "completed_nonzero"
            )
            if timeout is not None:
                entry["timeout"] = timeout
            if use_sudo is not None:
                entry["use_sudo"] = use_sudo

    @staticmethod
    def _safe_host_command_capture(entry: Any) -> Dict[str, Any]:
        """
        Project one in-memory entry onto the credential-free disk shape.

        The implementation uses ``entry`` to project one in-memory entry onto
        the credential-free disk shape.

        Args:
            entry: Entry object whose ``get`` state is read while performing
                project one in-memory entry onto the credential-free disk shape.

        Returns:
            A mapping containing safe host command capture.
        """

        if not isinstance(entry, dict):
            return {}

        safe: Dict[str, Any] = {}
        command_id = entry.get("command_id")
        if (
            isinstance(command_id, str)
            and _HOST_COMMAND_CAPTURE_ID_RE.fullmatch(command_id) is not None
        ):
            safe["command_id"] = command_id

        command_name = entry.get("command_name")
        if (
            isinstance(command_name, str)
            and _HOST_COMMAND_CAPTURE_NAME_RE.fullmatch(command_name) is not None
        ):
            safe["command_name"] = command_name

        if entry.get("transport") == "host_ssh":
            safe["transport"] = "host_ssh"
        if entry.get("target") == "host":
            safe["target"] = "host"

        captured_at = entry.get("captured_at")
        if isinstance(captured_at, str) and len(captured_at) <= 64:
            try:
                datetime.fromisoformat(captured_at)
            except ValueError:
                pass
            else:
                safe["captured_at"] = captured_at

        for field, maximum in (
            ("exit_code", (1 << 31) - 1),
            ("stdout_bytes", (1 << 63) - 1),
            ("stderr_bytes", (1 << 63) - 1),
            ("duration_ms", (1 << 31) - 1),
            ("timeout", (1 << 31) - 1),
        ):
            value = entry.get(field)
            minimum = -(1 << 31) if field == "exit_code" else 0
            if (
                isinstance(value, int)
                and not isinstance(value, bool)
                and minimum <= value <= maximum
            ):
                safe[field] = value

        status = entry.get("status")
        expected_status = (
            "success" if safe.get("exit_code") == 0 else "completed_nonzero"
        )
        if "exit_code" in safe and status == expected_status:
            safe["status"] = status
        use_sudo = entry.get("use_sudo")
        if isinstance(use_sudo, bool):
            safe["use_sudo"] = use_sudo

        # This assertion keeps the projection visibly fail-closed if a future
        # edit adds a field without updating the reviewed allowlist above.
        assert set(safe).issubset(_HOST_COMMAND_CAPTURE_SAFE_FIELDS)
        return safe

    @staticmethod
    def _safe_host_ssh_pool_metrics(value: Any) -> Optional[Dict[str, int]]:
        """
        Validate the fixed-shape label-free Host SSH pool aggregate.

        The projection accepts only the reviewed counter set and rejects the
        entire mapping when any counter is missing or invalid. This keeps
        connection labels and other unbounded runtime state out of published
        collector evidence.

        Args:
            value: Candidate mapping returned by the run-owned DUT manager.

        Returns:
            A detached metric mapping when every required counter is a bounded
            non-negative integer, otherwise ``None``.
        """

        if not isinstance(value, Mapping):
            return None
        metrics: Dict[str, int] = {}
        for field in _HOST_SSH_POOL_METRIC_FIELDS:
            metric = value.get(field)
            if (
                not isinstance(metric, int)
                or isinstance(metric, bool)
                or metric < 0
                or metric > (1 << 63) - 1
            ):
                return None
            metrics[field] = metric
        return metrics

    async def _execute_host_command_with_capture(
        self,
        dut_id: str,
        command: str,
        *,
        operation_name: str,
        timeout: int = 300,
        use_sudo: bool = False,
        collector_id: Optional[str] = None,
        output_file: Optional[str] = None,
        require_retry_control: bool = False,
        **kwargs,
    ) -> Tuple[int, str, str]:
        """
        Execute a host command and capture bounded execution details.

        Some external DUT-manager adapters predate the managed retry and
        redaction controls. Signature binding raises before the command runs, so
        managed execution can fail closed while unrelated legacy callers retain
        the retry-only fallback.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            operation_name: Stable operation name used for lookup and
                operator-facing diagnostics.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            output_file: Optional filesystem location used as the output file
                for this operation.
            require_retry_control: Whether require retry control is enabled or
                required for this operation.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A tuple containing ``exit code``, ``stdout``, and ``stderr`` in that
            order.

        Raises:
            RuntimeError: If host adapter does not support managed
                single-attempt and redacted execution.
        """
        timing_operation_id = None
        started_at = time.monotonic()
        if self.timing_manager:
            timing_operation_id = self.timing_manager.start_operation(
                "host_command",
                operation_name,
                metadata={"output_file": output_file} if output_file else None,
            )
        try:
            try:
                exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                    dut_id,
                    command,
                    timeout=timeout,
                    use_sudo=use_sudo,
                    **kwargs,
                )
            except TypeError as exc:
                # Some external DUT-manager adapters predate the managed retry
                # and redaction controls. Signature binding raises before the
                # command runs, so managed execution can fail closed while
                # unrelated legacy callers retain the retry-only fallback.
                if "max_retries" not in kwargs or "unexpected keyword" not in str(exc):
                    raise
                if require_retry_control:
                    raise RuntimeError(
                        "Host adapter does not support managed single-attempt "
                        "and redacted execution"
                    ) from exc
                fallback_kwargs = dict(kwargs)
                fallback_kwargs.pop("max_retries", None)
                exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                    dut_id,
                    command,
                    timeout=timeout,
                    use_sudo=use_sudo,
                    **fallback_kwargs,
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
                    error=(
                        "redacted managed host command failure"
                        if kwargs.get("redact_command") is True
                        else str(exc)
                    ),
                )
            raise
        if self.timing_manager:
            self.timing_manager.end_operation(
                timing_operation_id,
                # The raw command layer cannot know whether a non-zero code is
                # configured as an expected/ignored result by its caller.
                status="success" if exit_code == 0 else "completed_nonzero",
                metadata={"exit_code": exit_code, "raw_exit_code": exit_code},
            )
        await self._record_host_command_execution(
            dut_id,
            command,
            exit_code,
            stdout,
            stderr,
            operation_name=operation_name,
            timeout=timeout,
            use_sudo=use_sudo,
            collector_id=collector_id,
            output_file=output_file,
            duration_seconds=time.monotonic() - started_at,
        )
        return exit_code, stdout, stderr

    async def _attach_host_command_capture(
        self,
        dut_id: str,
        result: Dict[str, Any],
        collector_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Persist the host execution artifact and reference it from collector context.

        Capture state is internal, but project it again before persistence so a
        legacy adapter or test double cannot reintroduce command text, output
        bytes, paths, or arbitrary error summaries.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            result: Mapping supplying fields for host execution artifact and
                reference it from collector context.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            A mapping containing attach host command capture.
        """
        resolved_collector_id = collector_id or self._get_current_collector_id()
        key = await self._get_host_command_capture_key(dut_id, resolved_collector_id)
        captures = []
        if key:
            lock = self._host_command_locks.setdefault(key, asyncio.Lock())
            async with lock:
                captures = self._host_command_captures.pop(key, [])
                self._host_command_locks.pop(key, None)
        if not captures or not isinstance(result, dict):
            return result

        # Capture state is internal, but project it again before persistence so
        # a legacy adapter or test double cannot reintroduce command text,
        # output bytes, paths, or arbitrary error summaries.
        captures = [
            safe_capture
            for entry in captures[:MAX_COMMAND_RESULT_ENTRIES]
            if (safe_capture := self._safe_host_command_capture(entry))
        ]
        if not captures:
            return result

        collector_dir = await self._get_collector_output_dir(
            dut_id, resolved_collector_id
        )
        if not collector_dir or not self.logger:
            return result

        artifact_name = "diagnostic/host_execution_log.json"
        artifact_path = await self.logger.create_collector_log_file(
            dut_id, "host", resolved_collector_id, artifact_name
        )

        timing_operation_id = None
        if self.timing_manager:
            timing_operation_id = self.timing_manager.start_operation(
                "artifact_persistence",
                artifact_name,
                compact_artifact_on_limit=True,
            )
        try:
            metrics_provider = getattr(
                self.dut_manager, "get_host_ssh_pool_metrics", None
            )
            pool_metrics = (
                self._safe_host_ssh_pool_metrics(metrics_provider())
                if callable(metrics_provider)
                else None
            )
            dut_resource_artifact = (
                collector_dir.parent.parent / ".metadata" / "resource_usage.json"
            )
            resource_reference = Path(
                os.path.relpath(dut_resource_artifact, start=artifact_path.parent)
            ).as_posix()
            pool_accounting: Dict[str, Any] = {
                "schema_version": 1,
                "scope": "shared_run",
                "semantic_command_records": len(captures),
                "final_transport_snapshot": {
                    "artifact": resource_reference,
                    "json_path": "components.host_ssh_pool",
                },
                "counter_domains": {
                    "semantic_command_records": "collector_commands",
                    "commands_started": (
                        "transport_attempts_including_probes_staging_and_retries"
                    ),
                },
            }
            if pool_metrics is not None:
                pool_accounting["transport_snapshot_at_publication"] = pool_metrics

            with artifact_path.open("w", encoding="utf-8") as handle:
                # ``captures`` is already the allowlisted, credential-free
                # projection produced by ``_safe_host_command_capture`` above
                # (see the re-projection right before persistence); it is the
                # single load-bearing redaction step for this artifact.
                json.dump(
                    {
                        "commands": captures,
                        "pool_accounting": pool_accounting,
                    },
                    handle,
                    indent=2,
                )
        except Exception as exc:
            if self.timing_manager:
                self.timing_manager.end_operation(
                    timing_operation_id,
                    status="error",
                    error=str(exc),
                )
            await self._write_to_dut_runtime_log(
                dut_id,
                "WARN",
                "HostService",
                f"Failed to persist host execution log for {resolved_collector_id}: {exc}",
            )
            return result
        if self.timing_manager:
            self.timing_manager.end_operation(
                timing_operation_id,
                artifact_path=str(artifact_path),
            )

        context = result.setdefault("context", {})
        output_files = result.setdefault("output_files", [])
        artifact_path_str = str(artifact_path)
        if artifact_path_str not in output_files:
            output_files.append(artifact_path_str)

        context_output_files = context.setdefault("output_files", [])
        if artifact_path_str not in context_output_files:
            context_output_files.append(artifact_path_str)

        context["command_execution"] = {
            "artifact": artifact_name,
            "captured_commands": len(captures),
            "pool_accounting": {
                "json_path": "pool_accounting",
                "final_snapshot_artifact": resource_reference,
                "final_snapshot_json_path": "components.host_ssh_pool",
            },
        }
        return result

    # Validation methods
    async def _validate_host_connection(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Validate host connection.

        The implementation uses ``dut_id`` and ``kwargs`` to validate host
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
            A mapping containing the ``success``, ``reason``, and ``context``
            fields.
        """
        # First check if we have preflight results
        dut = self.dut_manager.get_dut(dut_id)
        preflight_results = getattr(dut, "preflight_results", {})

        if preflight_results:
            host_service_result = preflight_results.get("services", {}).get("host", {})
            if host_service_result:
                preflight_status = host_service_result.get("status", "unknown")
                preflight_message = host_service_result.get("message", "")

                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Found preflight results for host connection: status={preflight_status}, message={preflight_message}",
                    dut_id,
                )

                if preflight_status == "pass":
                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        "Using preflight results for host validation - connection already verified",
                        dut_id,
                    )
                    return {
                        "success": True,
                        "reason": f"Preflight verified: {preflight_message}",
                        "context": {
                            "host_available": True,
                            "preflight_used": True,
                            "successful_operations": 1,
                            "total_operations": 1,
                        },
                    }
                elif preflight_status == "fail":
                    await self._log_runtime(
                        "WARN",
                        "HostService",
                        f"Preflight failed for host connection: {preflight_message}",
                        dut_id,
                    )
                    return {
                        "success": False,
                        "reason": f"Preflight failed: {preflight_message}",
                        "context": {
                            "host_available": False,
                            "preflight_used": True,
                            "successful_operations": 0,
                            "total_operations": 1,
                        },
                    }

        # No preflight results or unknown status - run connection test
        await self._log_runtime(
            "DEBUG",
            "HostService",
            "No preflight results found or unknown status - running host connection test",
            dut_id,
        )

        success, message = await self.validate_connection(dut_id)

        # Log the validation result
        if success:
            await self._log_runtime(
                "INFO",
                "HostService",
                f"Host connection validation passed: {message}",
                dut_id,
            )
        else:
            await self._log_runtime(
                "ERROR",
                "HostService",
                f"Host connection validation failed: {message}",
                dut_id,
            )

        return {
            "success": success,
            "reason": message,
            "context": {
                "host_available": success,
                "preflight_used": False,
                "successful_operations": 1 if success else 0,
                "total_operations": 1,
            },
        }

    async def _validate_ssh_connection(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Validate SSH connection.

        The implementation uses ``dut_id`` and ``kwargs`` to validate SSH
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
            A mapping containing the ``success``, ``reason``, and ``context``
            fields.
        """
        # First check if we have preflight results
        dut = self.dut_manager.get_dut(dut_id)
        preflight_results = getattr(dut, "preflight_results", {})

        if preflight_results:
            ssh_service_result = preflight_results.get("services", {}).get("ssh", {})
            if ssh_service_result:
                preflight_status = ssh_service_result.get("status", "unknown")
                preflight_message = ssh_service_result.get("message", "")

                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Found preflight results for SSH connection: status={preflight_status}, message={preflight_message}",
                    dut_id,
                )

                if preflight_status == "pass":
                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        "Using preflight results for SSH validation - connection already verified",
                        dut_id,
                    )
                    return {
                        "success": True,
                        "reason": f"Preflight verified: {preflight_message}",
                        "context": {
                            "ssh_available": True,
                            "preflight_used": True,
                            "successful_operations": 1,
                            "total_operations": 1,
                        },
                    }
                elif preflight_status == "fail":
                    await self._log_runtime(
                        "WARN",
                        "HostService",
                        f"Preflight failed for SSH connection: {preflight_message}",
                        dut_id,
                    )
                    return {
                        "success": False,
                        "reason": f"Preflight failed: {preflight_message}",
                        "context": {
                            "ssh_available": False,
                            "preflight_used": True,
                            "successful_operations": 0,
                            "total_operations": 1,
                        },
                    }

        # No preflight results or unknown status - run connection test
        await self._log_runtime(
            "DEBUG",
            "HostService",
            "No preflight results found or unknown status - running SSH connection test",
            dut_id,
        )

        success, message = await self.dut_manager.get_dut(dut_id).test_ssh_connection()

        # Log the validation result
        if success:
            await self._log_runtime(
                "INFO",
                "HostService",
                f"SSH connection validation passed: {message}",
                dut_id,
            )
        else:
            await self._log_runtime(
                "ERROR",
                "HostService",
                f"SSH connection validation failed: {message}",
                dut_id,
            )

        return {
            "success": success,
            "reason": message,
            "context": {
                "ssh_available": success,
                "preflight_used": False,
                "successful_operations": 1 if success else 0,
                "total_operations": 1,
            },
        }

    async def collect_host_unified(
        self, dut_id: str, function_tag: str, collection_type: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Unified Host collection method that handles all core collection patterns.

        The implementation uses ``dut_id``, ``function_tag``,
        ``collection_type``, and ``kwargs`` to unified Host collection method
        that handles all core collection patterns. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            collection_type: Text supplied as collection type in the format
                accepted by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing host unified.
        """
        collector_name = f"{function_tag}_{collection_type}"
        await self._log_collection_start(dut_id, collector_name)
        collector_id = kwargs.get("collector_id") or self._get_current_collector_id()
        await self._start_host_command_capture(dut_id, collector_id)
        handler = self._get_host_collection_handler(collection_type)
        if not handler:
            await self._clear_host_command_capture(dut_id, collector_id)
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"Unknown collection_type: {collection_type}"],
                operation_name="host_unified_collection",
                additional_context={
                    "collection_type": collection_type,
                    "function_tag": function_tag,
                },
            )

        if collection_type == "generic_log":
            log_type = kwargs.get("log_type", "unknown")
            try:
                result = await handler(dut_id, log_type, **kwargs)
            except Exception:
                await self._clear_host_command_capture(dut_id, collector_id)
                raise
            return await self._attach_host_command_capture(dut_id, result, collector_id)

        try:
            result = await handler(dut_id, function_tag, **kwargs)
        except Exception:
            await self._clear_host_command_capture(dut_id, collector_id)
            raise
        return await self._attach_host_command_capture(dut_id, result, collector_id)

    def _get_host_collection_handler(
        self, collection_type: str
    ) -> Optional[Callable[..., Any]]:
        """
        Return the handler for a supported host collection type.

        After applying local validation, the function forwards
        ``collection_type`` to ``get`` and preserves its return and exception
        contract.

        Args:
            collection_type: Text supplied as collection type in the format
                accepted by this function.

        Returns:
            The handler for a supported host collection type, or ``None`` when
            the requested value is unavailable.
        """
        return {
            "commands": self._handle_host_commands_collection,
            "guarded_pseudo_file_transaction": (
                self._handle_host_guarded_pseudo_file_transaction
            ),
            "device_based": self._handle_host_device_based_collection,
            # Legacy keys route through translator shims to the
            # unified _handle_host_file_log_collection. The original
            # log/file/generic_log handler bodies have been removed; any YAML
            # still using these keys flows through the shim path. All in-tree
            # H-collectors (H6/H7/H9/H22/H23) migrated to
            # collection_type=file_log; shims only fire for out-of-tree YAML.
            "log_collection": self._legacy_log_collection_shim,
            "file_collection": self._legacy_file_collection_shim,
            "generic_log": self._legacy_generic_log_shim,
            "advanced": self._handle_host_advanced_collection,
            "managed_fallback": self._handle_host_managed_fallback_collection,
            "file_log": self._handle_host_file_log_collection,
            "file_search_and_archive": self._handle_host_file_search_and_archive,
            "device_based_log_collection": self._handle_host_device_based_log_collection,
            "system_info_collection": self._handle_host_system_info_collection,
            "nvos_commands": self._handle_host_nvos_commands,
            "composite": self._handle_host_composite_collection,
        }.get(collection_type)

    # ============================================================================
    # 10.3 COMMON UTILITY FUNCTIONS FOR HANDLERS
    # ============================================================================

    async def _get_host_stream_window(self) -> Tuple[str, str]:
        """
        Return resolved --since/--until values for stream-aware collectors.

        After applying local validation, the function forwards current instance
        state to ``_hours_to_since_until`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Returns:
            A tuple containing the fields that represent host stream window.
        """
        stream_begin_val = None
        stream_end_val = None
        if self.orchestrator and self.orchestrator.config_manager:
            try:
                tc = self.orchestrator.config_manager.get_tool_config()
                stream_begin_val = tc.get("stream_begin")
                stream_end_val = tc.get("stream_end")
            except Exception:
                pass
        return _hours_to_since_until(stream_begin_val, stream_end_val)

    def _apply_time_window(
        self, command: Optional[str], since_str: str, until_str: str
    ) -> Optional[str]:
        """
        Substitute stream window placeholders in a command template.

        The implementation uses ``command``, ``since_str``, and ``until_str`` to
        substitute stream window placeholders in a command template. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Args:
            command: Text supplied as command in the format accepted by this
                function.
            since_str: Text supplied as since str in the format accepted by this
                function.
            until_str: Text supplied as until str in the format accepted by this
                function.

        Returns:
            The canonical time window text, or ``None`` when the requested value
            is unavailable.

        Raises:
            ValueError: If a stream timestamp selected for interpolation does
                not match the output contract of
                ``streaming.format_host_stream_timestamp``.
        """
        if not command:
            return command

        adjusted_command = command
        adjusted_since = since_str
        adjusted_until = until_str

        # dmesg accepts timestamps like "YYYY-MM-DD HH:MM:SS" but can reject
        # the explicit " UTC" suffix on some hosts. Prefix with TZ=UTC so the
        # same absolute stream window is preserved without relying on suffix parsing.
        stripped_command = command.lstrip()
        if re.match(r"^(?:sudo\s+)?dmesg(?:\s|$)", stripped_command):
            adjusted_since = since_str.removesuffix(" UTC")
            adjusted_until = until_str.removesuffix(" UTC")
            if not re.match(r"^(?:sudo\s+)?TZ=", stripped_command):
                if stripped_command.startswith("sudo "):
                    adjusted_command = "sudo TZ=UTC " + stripped_command[len("sudo ") :]
                else:
                    adjusted_command = f"TZ=UTC {command}"

        if "{since}" in adjusted_command or "{until}" in adjusted_command:
            for field_name, field_value in (
                ("since", adjusted_since),
                ("until", adjusted_until),
            ):
                if not _HOST_STREAM_TIMESTAMP.fullmatch(field_value):
                    raise ValueError(
                        f"host stream {field_name} timestamp has an invalid format"
                    )
            return adjusted_command.replace("{since}", adjusted_since).replace(
                "{until}", adjusted_until
            )
        return adjusted_command

    def _resolve_host_platform(self, dut_id: str) -> str:
        """
        Resolve the current DUT's host platform/baseboard type.

        The implementation uses ``dut_id`` to resolve the current DUT's host
        platform/baseboard type.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The canonical host platform text.
        """
        if not self.dut_manager:
            return "default"

        try:
            dut = self.dut_manager.get_dut(dut_id)
        except Exception:
            return "default"

        config = getattr(dut, "config", {}) or {}
        baseboard = config.get("baseboard") or config.get("TargetBaseboard")
        if not baseboard:
            return "default"

        manager_getter = getattr(self.dut_manager, "_get_baseboard_manager", None)
        if not callable(manager_getter):
            manager_getter = getattr(self.dut_manager, "get_baseboard_manager", None)
        if not callable(manager_getter):
            return "default"

        try:
            baseboard_manager = manager_getter()
            if not baseboard_manager:
                return "default"
            return baseboard_manager.get_baseboard_type(baseboard) or "default"
        except Exception:
            return "default"

    def _resolve_platform_flag(self, value: Any, platform: str) -> bool:
        """
        Resolve a boolean or per-platform boolean mapping.

        The implementation uses ``value`` and ``platform`` to resolve a boolean
        or per-platform boolean mapping.

        Args:
            value: Value object whose ``get`` state is read while performing
                boolean or per-platform boolean mapping.
            platform: Text supplied as platform in the format accepted by this
                function.

        Returns:
            Whether the boolean or per-platform boolean mapping operation
            succeeds.
        """
        if isinstance(value, dict):
            return bool(value.get(platform, value.get("default", False)))
        return bool(value)

    async def _check_host_service_status(
        self, dut_id: str, service_name: str, use_sudo: bool
    ) -> Tuple[int, str]:
        """
        Check systemd service state for a host collector.

        The implementation uses ``dut_id``, ``service_name``, and ``use_sudo``
        to check systemd service state for a host collector. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.
            use_sudo: Whether use sudo is enabled or required for this
                operation.

        Returns:
            A tuple containing ``integer count`` and ``status or message text``
            in that order.
        """
        if not service_name:
            return 0, ""

        await self._log_runtime(
            "INFO",
            "HostService",
            f"Checking service status: {service_name}",
            dut_id,
        )
        exit_code, _, stderr = await self.dut_manager.execute_host_command(
            dut_id,
            build_remote_cmd("systemctl status {svc}", svc=service_name),
            timeout=60,
            use_sudo=use_sudo,
        )
        return exit_code, stderr

    async def _save_transferred_host_file(
        self,
        dut_id: str,
        remote_file: str,
        output_pattern: Optional[str],
        filtered_kwargs: Dict[str, Any],
        timeout: Optional[int] = None,
        destination_path: Optional[Path] = None,
        max_bytes: int = _DEFAULT_HOST_ARTIFACT_MAX_BYTES,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Transfer a remote host file and persist it or stage it for an archive.

        The implementation uses ``dut_id``, ``remote_file``, ``output_pattern``,
        ``filtered_kwargs``, and ``timeout`` to transfer a remote host file and
        persist it or stage it for an archive. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. Filesystem effects remain confined to the caller-selected paths
        and the owning resource lifecycle. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            remote_file: filesystem location used as the remote file for this
                operation.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            filtered_kwargs: Mapping supplying fields for transfer a remote host
                file and persist it or stage it for an archive.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            destination_path: Optional filesystem location used as the
                destination for this operation.
            max_bytes: Upper bound enforced for max bytes; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            A tuple containing the fields that represent save transferred host
            file, or ``None`` when the requested value is unavailable.
        """
        max_bytes = _resolve_host_artifact_max_bytes({"max_artifact_bytes": max_bytes})
        local_staging_parent = await self._resolve_local_staging_parent(dut_id)
        transfer_temp_dir = tempfile.TemporaryDirectory(
            prefix="nvdebug-host-transfer-",
            dir=local_staging_parent,
        )
        local_file = os.path.join(transfer_temp_dir.name, os.path.basename(remote_file))
        timing_operation_id = None
        if self.timing_manager:
            timing_operation_id = self.timing_manager.start_operation(
                "host_file_acquisition",
                os.path.basename(remote_file) or remote_file,
                metadata={"transport": "host_file_transfer"},
                compact_artifact_on_limit=True,
            )

        def _finish(
            success: bool, path: Optional[str], error: Optional[str]
        ) -> Tuple[bool, Optional[str], Optional[str]]:
            """
            Finalize the current operation.

            The implementation uses ``success``, ``path``, and ``error`` to
            finalize the current operation.

            Args:
                success: Whether success is enabled or required for this
                    operation.
                path: filesystem location used as the path for this operation.
                error: Exception or failure detail associated with the
                    operation.

            Returns:
                A tuple containing ``success``, ``path``, and ``error`` in that
                order.
            """
            if self.timing_manager:
                self.timing_manager.end_operation(
                    timing_operation_id,
                    status="success" if success else "error",
                    artifact_path=path,
                    error=error,
                )
            transfer_temp_dir.cleanup()
            return success, path, error

        async def transfer_bounded() -> Tuple[bool, str]:
            """
            Transfer bounded.

            The implementation uses current instance state to transfer bounded.
            Owned asynchronous work is awaited before return, so completion does
            not leave an unobserved task behind.

            Returns:
                A tuple containing the fields that represent transfer bounded.
            """
            try:
                return await self.dut_manager.transfer_host_files(
                    dut_id,
                    remote_file,
                    transfer_temp_dir.name,
                    copy_to_destination=False,
                    max_bytes=max_bytes,
                )
            except TypeError as exc:
                if "max_bytes" not in str(exc) or "unexpected keyword" not in str(exc):
                    raise
                return await self.dut_manager.transfer_host_files(
                    dut_id,
                    remote_file,
                    transfer_temp_dir.name,
                    copy_to_destination=False,
                )

        transfer = transfer_bounded()
        try:
            if timeout is None:
                transfer_success, transfer_error = await transfer
            else:
                transfer_success, transfer_error = await asyncio.wait_for(
                    transfer, timeout=timeout
                )
        except asyncio.TimeoutError:
            await self._log_runtime(
                "ERROR",
                "HostService",
                (
                    f"Timed out downloading host file {remote_file} "
                    f"after {timeout} seconds"
                ),
                dut_id,
            )
            return _finish(
                False,
                None,
                f"Timed out downloading file after {timeout} seconds: {remote_file}",
            )
        except BaseException as exc:
            _finish(False, None, str(exc))
            raise
        if not transfer_success:
            return _finish(
                False,
                None,
                f"Failed to download file: {remote_file} - {transfer_error}",
            )

        try:
            if destination_path is None and not self.logger:
                return _finish(
                    False,
                    None,
                    f"Logger unavailable; cannot save file {remote_file}",
                )
            if not os.path.exists(local_file):
                return _finish(
                    False,
                    None,
                    f"Downloaded file missing after transfer: {remote_file}",
                )

            if destination_path is not None:
                destination_path.parent.mkdir(parents=True, exist_ok=True)
                if destination_path.exists() or destination_path.is_symlink():
                    return _finish(
                        False,
                        None,
                        f"Archive staging path already exists: {destination_path}",
                    )
                file_path_out = destination_path
            else:
                final_filename = os.path.basename(remote_file)
                file_path_out = await self.logger.create_collector_log_file(
                    dut_id,
                    "host",
                    filtered_kwargs.get("collector_id", ""),
                    self.get_output_filename(
                        output_pattern,
                        final_filename,
                        "",
                        {"file_name": final_filename},
                    ),
                )
            _copy_regular_file_bounded(
                local_file,
                str(file_path_out),
                max_bytes=max_bytes,
            )
            return _finish(True, str(file_path_out), None)
        except BaseException as exc:
            _finish(False, None, str(exc))
            raise
        finally:
            try:
                if os.path.exists(local_file):
                    os.remove(local_file)
            except Exception:
                pass

    def _wrap_for_shell(self, cmd: str) -> str:
        """
        Return the wrap for shell.

        Quote the complete command as one opaque ``bash -lc`` operand so shell
        quoting applied by command builders survives the outer shell hop.

        Args:
            cmd: Text supplied as cmd in the format accepted by this function.

        Returns:
            The canonical wrap for shell text.
        """
        stripped = cmd.strip()
        needs_shell = (
            stripped.startswith("command ")
            or "|" in cmd
            or ";" in cmd
            or "&&" in cmd
            or "$(" in cmd
            or "`" in cmd
        )
        if needs_shell and not stripped.startswith("bash -lc"):
            return f"bash -lc {shlex.quote(cmd)}"
        return cmd

    @staticmethod
    def _matches_expected_nonzero_result(
        exit_code: int,
        stdout: str,
        stderr: str,
        expected_nonzero_exit_codes: Any,
        expected_output_patterns: Any,
    ) -> bool:
        """
        Return whether a configured non-zero result represents expected data.

        Both the exit code and at least one output pattern must match. Patterns
        are regular expressions searched case-insensitively across stdout and
        stderr; an invalid expression falls back to a literal substring match.

        Args:
            exit_code: Numeric exit code used while the operation performs
                bounded accounting.
            stdout: Text supplied as stdout in the format accepted by this
                function.
            stderr: Text supplied as stderr in the format accepted by this
                function.
            expected_nonzero_exit_codes: Expected nonzero exit codes consumed
                while the function attempts to determine whether a configured
                non-zero result represents expected data.
            expected_output_patterns: Expected output patterns consumed while
                the function attempts to determine whether a configured non-zero
                result represents expected data.

        Returns:
            Whether a configured non-zero result represents expected data.
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

    @staticmethod
    def _resolve_output_validated_nonzero_policy(
        command: str,
        expected_nonzero_exit_codes: Any,
        expected_output_patterns: Any,
    ) -> Optional[Tuple[str, Tuple[int, ...]]]:
        """
        Resolve an exact, reviewed output-aware expected-nonzero policy.

        The implementation uses ``command``, ``expected_nonzero_exit_codes``,
        and ``expected_output_patterns`` to resolve an exact, reviewed
        output-aware expected-nonzero policy. If the function cannot resolve an
        exact, reviewed output-aware expected-nonzero policy, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            command: Text supplied as command in the format accepted by this
                function.
            expected_nonzero_exit_codes: Expected nonzero exit codes consumed
                while the function attempts to resolve an exact, reviewed
                output-aware expected-nonzero policy.
            expected_output_patterns: Expected output patterns consumed while
                the function attempts to resolve an exact, reviewed output-aware
                expected-nonzero policy.

        Returns:
            A tuple containing ``operation role`` and ``exit codes`` in that
            order.

        Raises:
            ValueError: If unsupported output-validated nonzero policy.
        """
        if not expected_nonzero_exit_codes:
            return None
        if not isinstance(expected_nonzero_exit_codes, (list, tuple)) or not all(
            isinstance(value, int) and not isinstance(value, bool)
            for value in expected_nonzero_exit_codes
        ):
            raise ValueError("unsupported output-validated nonzero policy")
        if not isinstance(expected_output_patterns, (list, tuple)) or not all(
            isinstance(value, str) for value in expected_output_patterns
        ):
            raise ValueError("unsupported output-validated nonzero policy")

        exit_codes = tuple(expected_nonzero_exit_codes)
        patterns = tuple(expected_output_patterns)
        operation_role = _OUTPUT_VALIDATED_NONZERO_POLICIES.get(
            (command, exit_codes, patterns)
        )
        if operation_role is None:
            raise ValueError("unsupported output-validated nonzero policy")
        return operation_role, exit_codes

    async def _execute_command_and_save(
        self,
        dut_id: str,
        command: str,
        file_name: str,
        operation_name: str,
        operation_type: str,
        output_pattern: str,
        filtered_kwargs: Dict[str, Any],
        use_sudo: bool = False,
        timeout: int = 300,
        content_processor: Optional[Callable] = None,
        ignore_errors: bool = False,
        count_ignored_errors_as_failures: bool = False,
        suppress_failure_log: bool = False,
        execution_details: Optional[Dict[str, Any]] = None,
        expected_nonzero_exit_codes: Any = None,
        expected_output_patterns: Any = None,
        command_result_metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Tuple[bool, Optional[str]]:
        """
        Unified utility to execute a command with logging and save the output.

        Captured command artifacts retain their canonical privilege marker even
        though execution is delegated unchanged to DUTManager's single trusted
        sudo boundary.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            file_name: Stable file name used for lookup and operator-facing
                diagnostics.
            operation_name: Stable operation name used for lookup and
                operator-facing diagnostics.
            operation_type: Text supplied as operation type in the format
                accepted by this function.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            filtered_kwargs: Mapping supplying fields for unified utility to
                execute a command with logging and save the output.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            content_processor: Optional content processor; ``None`` selects the
                function's default behavior.
            ignore_errors: Whether ignore errors is enabled or required for this
                operation.
            count_ignored_errors_as_failures: Whether count ignored errors as
                failures is enabled or required for this operation.
            suppress_failure_log: Whether suppress failure log is enabled or
                required for this operation.
            execution_details: Optional execution details; ``None`` selects the
                function's default behavior.
            expected_nonzero_exit_codes: Optional expected nonzero exit codes;
                ``None`` selects the function's default behavior.
            expected_output_patterns: Optional expected output patterns;
                ``None`` selects the function's default behavior.
            command_result_metadata: Optional command result metadata; ``None``
                selects the function's default behavior.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.
        """
        self._resolve_output_validated_nonzero_policy(
            command,
            expected_nonzero_exit_codes,
            expected_output_patterns,
        )
        await self._log_collection_start(dut_id, operation_name)
        content_command = command
        if (
            use_sudo
            and re.match(r"\A\s*(?:sudo|/usr/bin/sudo)(?:\s|\Z)", command) is None
        ):
            # Captured command artifacts retain their canonical privilege
            # marker even though execution is delegated unchanged to
            # DUTManager's single trusted sudo boundary.
            content_command = f"sudo {command}"

        # INFO-level visibility before execution
        await self._write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "HostService",
            f"Executing command: {command} (timeout={timeout}, use_sudo={use_sudo})",
        )

        # Execute command
        acquisition_operation_id = None
        if self.timing_manager:
            acquisition_operation_id = self.timing_manager.start_operation(
                "host_command_acquisition",
                operation_name,
                metadata={"requested_output": file_name},
            )
        try:
            exit_code, stdout, stderr = await self._execute_host_command_with_capture(
                dut_id,
                command,
                operation_name=operation_name,
                timeout=timeout,
                use_sudo=use_sudo,
                output_file=file_name,
                **kwargs,
            )
        except BaseException as exc:
            if self.timing_manager:
                self.timing_manager.end_operation(
                    acquisition_operation_id,
                    status=(
                        "cancelled"
                        if isinstance(exc, asyncio.CancelledError)
                        else "error"
                    ),
                    error=str(exc),
                )
            raise

        # INFO-level visibility after execution
        await self._write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "HostService",
            f"Command completed: exit_code={exit_code}",
        )

        success = exit_code == 0
        if self._matches_expected_nonzero_result(
            exit_code,
            stdout,
            stderr,
            expected_nonzero_exit_codes,
            expected_output_patterns,
        ):
            success = True
            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"{operation_type} {operation_name} returned expected empty/no-data result (exit_code={exit_code})",
            )

        if execution_details is not None:
            execution_details.update(
                {
                    "exit_code": exit_code,
                    "command_succeeded": success,
                }
            )

        if success or ignore_errors:
            if not success:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "HostService",
                    f"{operation_type} {operation_name} exited with code {exit_code} (ignored due to ignore_errors=True)",
                )

            # Process content if processor provided, otherwise use stdout
            try:
                if content_processor:
                    content = content_processor(
                        content_command, exit_code, stdout, stderr
                    )
                else:
                    content = stdout

                # Save data
                file_path = await self._save_data_with_common_pattern(
                    dut_id,
                    content,
                    file_name,
                    output_pattern=output_pattern,
                    substitutions={"file_name": file_name},
                    **filtered_kwargs,
                )
            except BaseException as exc:
                if self.timing_manager:
                    self.timing_manager.end_operation(
                        acquisition_operation_id,
                        status=(
                            "cancelled"
                            if isinstance(exc, asyncio.CancelledError)
                            else "error"
                        ),
                        metadata={
                            "exit_code": exit_code,
                            "raw_exit_code": exit_code,
                        },
                        error=str(exc),
                    )
                raise

            if not file_path:
                persistence_error = (
                    f"Artifact persistence failed for {operation_name}: "
                    "no output path returned"
                )
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    persistence_error,
                )
                if self.timing_manager:
                    self.timing_manager.end_operation(
                        acquisition_operation_id,
                        status="error",
                        metadata={
                            "exit_code": exit_code,
                            "raw_exit_code": exit_code,
                            "semantic_success": False,
                            "ignored_nonzero": bool(exit_code != 0 and ignore_errors),
                        },
                        error=persistence_error,
                    )
                if not suppress_failure_log:
                    await self._log_collection_failure(
                        dut_id,
                        operation_type,
                        operation_name,
                        persistence_error,
                        collector_id=kwargs.get("collector_id"),
                    )
                return False, None

            if success:
                await self._log_collection_success(
                    dut_id, operation_type, operation_name
                )

            if self.timing_manager:
                self.timing_manager.end_operation(
                    acquisition_operation_id,
                    status=("success" if exit_code == 0 else "completed_nonzero"),
                    artifact_path=file_path,
                    metadata={
                        "exit_code": exit_code,
                        "raw_exit_code": exit_code,
                        "semantic_success": success,
                        "ignored_nonzero": bool(exit_code != 0 and ignore_errors),
                    },
                )

            if not success and count_ignored_errors_as_failures:
                return False, file_path
            return True, file_path
        else:
            if self.timing_manager:
                self.timing_manager.end_operation(
                    acquisition_operation_id,
                    status="error",
                    metadata={
                        "exit_code": exit_code,
                        "raw_exit_code": exit_code,
                        "semantic_success": False,
                    },
                )
            if not suppress_failure_log:
                await self._log_collection_failure(
                    dut_id,
                    operation_type,
                    operation_name,
                    f"exit_code: {exit_code}",
                    collector_id=kwargs.get("collector_id"),
                )
            return False, None

    # ============================================================================
    # 10.2 INTERNAL COLLECTION HANDLERS
    # ============================================================================

    async def _persist_guarded_pseudo_file_receipt(
        self,
        dut_id: str,
        recipe: _GuardedPseudoFileRecipe,
        receipt: Mapping[str, Any],
        output_pattern: Optional[str],
        collector_id: Optional[str],
    ) -> Optional[str]:
        """
        Persist one bounded credential-free pseudo-file transaction receipt.

        Publication uses the existing common output-store path so artifact
        naming, ownership, and collector attribution follow normal Host rules.

        Args:
            dut_id: Stable DUT identifier used to correlate output ownership.
            recipe: Validated recipe supplying the safe receipt basename.
            receipt: Fixed-shape evidence assembled from local values and
                bounded command outcomes.
            output_pattern: Optional catalog output pattern for the artifact.
            collector_id: Stable collector identifier used for attribution.

        Returns:
            The persisted artifact path, or ``None`` when publication fails.

        Side Effects:
            Writes one JSON artifact through the common output-store boundary.
        """

        return await self._save_data_with_common_pattern(
            dut_id,
            json.dumps(dict(receipt), indent=2, sort_keys=True),
            recipe.receipt_file,
            output_pattern=output_pattern,
            substitutions={"file_name": recipe.receipt_file},
            default_extension="",
            collector_id=collector_id,
        )

    async def _handle_host_guarded_pseudo_file_transaction(
        self, dut_id: str, function_tag: str, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Execute catalog-authored pseudo-file transactions sequentially.

        The handler performs a complete read-only capability check before its
        first write. Each transaction is attempted exactly once in catalog
        order, and processing stops immediately after any non-zero or ambiguous
        transport outcome. Each transaction has one catalog-marked commit
        write which validation requires to be last. Platform-specific paths,
        values, and labels never appear in this source implementation.

        Args:
            dut_id: Stable DUT identifier used to route Host SSH execution.
            function_tag: Catalog function tag recorded in result context.
            kwargs: Catalog-authored recipe values and output metadata.

        Returns:
            A standardized collector result with a bounded JSON receipt when
            persistence succeeds.

        Side Effects:
            Writes catalog-authored scalar values to validated Host pseudo-files.
            The final commit write may cause a platform-specific state change.
            An authored settle interval delays later ordered collectors after a
            transaction attempt.
        """

        collector_id = kwargs.get("collector_id") or self._get_current_collector_id()
        output_pattern = kwargs.get("output_pattern")
        try:
            recipe = _resolve_guarded_pseudo_file_recipe(kwargs)
        except ValueError as exc:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(exc)],
                operation_name="guarded_pseudo_file_configuration",
                additional_context={
                    "function_tag": function_tag,
                    "mutating": True,
                    "replay_policy": "single_attempt_no_retry",
                },
                dut_id=dut_id,
                collector_id=collector_id,
            )

        receipt: Dict[str, Any] = {
            "schema_version": "1.0",
            "operation": "guarded_pseudo_file_transaction",
            "transaction_id": recipe.transaction_id,
            "recipe_sha256": _guarded_pseudo_file_recipe_sha256(recipe),
            "mutating": True,
            "replay_policy": "single_attempt_no_retry",
            "post_transaction_settle_seconds": (recipe.post_transaction_settle_seconds),
            "post_transaction_settle_applied": False,
            "root_path": str(recipe.root_path),
            "preflight": {"status": "pending"},
            "transaction_results": [],
            "status": "pending",
        }

        await self._write_to_dut_runtime_log(
            dut_id,
            "WARNING",
            "HostService",
            (
                "Starting explicitly selected guarded pseudo-file operation "
                f"{recipe.transaction_id}: it may change DUT state; each "
                "transaction is attempted once and is never replayed"
            ),
        )

        try:
            (
                preflight_exit,
                preflight_stdout,
                _preflight_stderr,
            ) = await self._execute_host_command_with_capture(
                dut_id,
                _build_guarded_pseudo_file_preflight_command(recipe),
                operation_name="guarded_pseudo_file_preflight",
                timeout=recipe.command_timeout_seconds,
                use_sudo=True,
                collector_id=collector_id,
                require_retry_control=True,
                max_retries=1,
                redact_command=True,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            preflight_exit, preflight_stdout = -1, ""

        preflight_ready = (
            preflight_exit == 0
            and "NVDEBUG_GUARDED_TRANSACTION_READY" in preflight_stdout.splitlines()
        )
        preflight_resource_missing = preflight_exit == 1
        receipt["preflight"] = {
            "status": "passed" if preflight_ready else "failed",
            "exit_code": preflight_exit,
        }
        if not preflight_ready:
            receipt["status"] = (
                "resource_missing" if preflight_resource_missing else "preflight_failed"
            )
            output_files: List[str] = []
            try:
                receipt_path = await self._persist_guarded_pseudo_file_receipt(
                    dut_id,
                    recipe,
                    receipt,
                    output_pattern,
                    collector_id,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                receipt_path = None
            if receipt_path:
                output_files.append(receipt_path)
            persistence_errors = []
            if not preflight_resource_missing:
                persistence_errors.append(
                    "Guarded pseudo-file capability check did not complete successfully"
                )
            if not receipt_path:
                persistence_errors.append(
                    "Guarded pseudo-file capability check failed and its receipt was not persisted"
                )
            skipped_with_evidence = preflight_resource_missing and bool(receipt_path)
            return await self._create_standardized_collector_result(
                successful_operations=1 if skipped_with_evidence else 0,
                total_operations=1,
                output_files=output_files,
                error_messages=persistence_errors,
                operation_name="guarded_pseudo_file_preflight",
                additional_context={
                    "status": "skipped" if skipped_with_evidence else "error",
                    "reason": (
                        "Required pseudo-file interface is unavailable or inaccessible"
                        if preflight_resource_missing
                        else "Guarded pseudo-file capability check did not complete"
                    ),
                    "mutating": True,
                    "transaction_id": recipe.transaction_id,
                    "replay_policy": "single_attempt_no_retry",
                },
                dut_id=dut_id,
                collector_id=collector_id,
            )

        completed_transactions: List[str] = []
        error_messages: List[str] = []
        for transaction in recipe.transactions:
            await self._write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "HostService",
                f"Executing guarded pseudo-file transaction once: {transaction.label}",
            )
            try:
                (
                    exit_code,
                    _stdout,
                    _stderr,
                ) = await self._execute_host_command_with_capture(
                    dut_id,
                    _build_guarded_pseudo_file_transaction_command(recipe, transaction),
                    operation_name=(f"guarded_pseudo_file_{transaction.label}"),
                    timeout=recipe.command_timeout_seconds,
                    use_sudo=True,
                    collector_id=collector_id,
                    require_retry_control=True,
                    max_retries=1,
                    redact_command=True,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                exit_code = -1

            transaction_result = {
                "label": transaction.label,
                "write_count": len(transaction.writes),
                "commit_node": transaction.writes[-1].node,
                "exit_code": exit_code,
                "status": "committed" if exit_code == 0 else "failed",
                "ambiguous_completion": exit_code < 0,
            }
            receipt["transaction_results"].append(transaction_result)
            if exit_code == 0:
                completed_transactions.append(transaction.label)
                continue

            error_messages.append(
                "Guarded pseudo-file transaction "
                f"{transaction.label} did not return success; command was not retried"
            )
            break

        receipt["status"] = (
            "success"
            if len(completed_transactions) == len(recipe.transactions)
            else "partial" if completed_transactions else "failed"
        )
        settle_applied = False
        if (
            receipt["transaction_results"]
            and recipe.post_transaction_settle_seconds > 0
        ):
            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                (
                    "Waiting for downstream evidence to settle after the "
                    "guarded pseudo-file transaction"
                ),
            )
            await asyncio.sleep(recipe.post_transaction_settle_seconds)
            settle_applied = True
        receipt["post_transaction_settle_applied"] = settle_applied
        try:
            receipt_path = await self._persist_guarded_pseudo_file_receipt(
                dut_id,
                recipe,
                receipt,
                output_pattern,
                collector_id,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            receipt_path = None
        output_files = [receipt_path] if receipt_path else []
        if not receipt_path:
            error_messages.append(
                "Guarded pseudo-file transaction receipt was not persisted"
            )
        accounted_total_operations = len(recipe.transactions) + (
            0 if receipt_path else 1
        )

        return await self._create_standardized_collector_result(
            successful_operations=len(completed_transactions),
            total_operations=accounted_total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name="guarded_pseudo_file_transaction",
            additional_context={
                "function_tag": function_tag,
                "mutating": True,
                "transaction_id": recipe.transaction_id,
                "completed_transactions": completed_transactions,
                "attempted_transactions": len(receipt["transaction_results"]),
                "replay_policy": "single_attempt_no_retry",
                "receipt_persisted": bool(receipt_path),
                "post_transaction_settle_seconds": (
                    recipe.post_transaction_settle_seconds
                ),
                "post_transaction_settle_applied": settle_applied,
            },
            dut_id=dut_id,
            collector_id=collector_id,
        )

    async def _handle_host_commands_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle simple host commands collection.

        Extract output pattern parameters using common function.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing handle host commands collection.
        """

        async def _commands_collection():
            """
            Return the commands collection.

            Extract output pattern parameters using common function.

            Returns:
                The commands collection.
            """
            commands = kwargs.get("commands", [])
            collection_level = kwargs.get("collection_level", "L1")
            use_sudo = kwargs.get("use_sudo", False)
            count_ignored_errors_as_failures = bool(
                kwargs.get("count_ignored_errors_as_failures", False)
            )
            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            output_files = []
            results = []
            error_messages = []
            optional_failures: List[Dict[str, Any]] = []

            default_timeout = await self._resolve_collector_timeout(
                dut_id, kwargs, default_timeout=300
            )

            # Resolve streaming time-window variables for command substitution
            since_str, until_str = await self._get_host_stream_window()

            for i, command_item in enumerate(commands):
                # Handle both string commands and command dictionaries
                if isinstance(command_item, str):
                    command = command_item
                    file_name = f"host_command_{i + 1}.txt"
                    timeout = default_timeout
                    ignore_errors = False
                    expected_nonzero_exit_codes = None
                    expected_output_patterns = None
                else:
                    # Handle collection level variations
                    if "collection_level_handling" in command_item:
                        level_commands = command_item["collection_level_handling"]
                        command = level_commands.get(
                            collection_level, command_item["command"]
                        )
                    else:
                        command = command_item["command"]

                    file_name = command_item.get(
                        "file_name", f"host_command_{i + 1}.txt"
                    )
                    timeout = await self._resolve_collector_timeout(
                        dut_id,
                        kwargs,
                        default_timeout=300,
                        explicit_timeout_sources=[command_item, kwargs],
                    )
                    ignore_errors = command_item.get("ignore_errors", False)
                    expected_nonzero_exit_codes = command_item.get(
                        "expected_nonzero_exit_codes"
                    )
                    expected_output_patterns = command_item.get(
                        "expected_output_patterns"
                    )

                # Substitute {since} and {until} placeholders with resolved time strings
                command = self._apply_time_window(command, since_str, until_str)
                relative_file_name = _relative_file_name_for_pattern(
                    file_name, output_pattern
                )
                execution_metadata: Dict[str, Any] = {}

                # Execute command with logging and save using common utility
                execution_details: Dict[str, Any] = {}
                success, file_path = await self._execute_command_and_save(
                    dut_id=dut_id,
                    command=command,
                    file_name=relative_file_name,
                    operation_name=f"command_{i + 1}",
                    operation_type="command",
                    output_pattern=output_pattern,
                    filtered_kwargs=filtered_kwargs,
                    use_sudo=use_sudo,
                    timeout=timeout,
                    content_processor=self._create_command_output_content,
                    ignore_errors=ignore_errors,
                    count_ignored_errors_as_failures=(count_ignored_errors_as_failures),
                    execution_details=execution_details,
                    expected_nonzero_exit_codes=expected_nonzero_exit_codes,
                    expected_output_patterns=expected_output_patterns,
                    command_result_metadata=execution_metadata,
                )

                if file_path:
                    output_files.append(file_path)

                command_succeeded = bool(
                    execution_details.get("command_succeeded", success)
                )
                optional_failure = bool(
                    ignore_errors
                    and success
                    and not command_succeeded
                    and not count_ignored_errors_as_failures
                )
                result = {
                    "command": command,
                    "success": success,
                    "command_succeeded": command_succeeded,
                    "optional_failure": optional_failure,
                    "file_name": relative_file_name,
                    "collection_level": collection_level,
                }
                if "exit_code" in execution_details:
                    result["exit_code"] = execution_details["exit_code"]
                results.append(result)

                if execution_metadata.get("optional_failure"):
                    optional_failures.append(
                        {
                            "command": command,
                            "exit_code": execution_metadata.get("exit_code"),
                            "file_name": relative_file_name,
                        }
                    )

                # Handle ignore_errors
                if not success and (
                    not ignore_errors or count_ignored_errors_as_failures
                ):
                    error_messages.append(f"Command failed: {command}")

            # Determine success metrics
            successful_operations = sum(
                1
                for result in results
                if result.get("success", False)
                and result.get("command_succeeded", False)
            )
            total_operations = len(commands)
            optional_failures = [
                {
                    "command": result["command"],
                    "exit_code": result.get("exit_code"),
                    "file_name": result["file_name"],
                }
                for result in results
                if result.get("optional_failure", False)
            ]
            optional_failure_count = len(optional_failures)
            optional_failure_reason = None
            if optional_failure_count and not error_messages:
                failure_label = "failure" if optional_failure_count == 1 else "failures"
                optional_failure_reason = (
                    "Required collection complete: "
                    f"{successful_operations}/{total_operations} host commands "
                    f"succeeded; {optional_failure_count} optional command "
                    f"{failure_label} ignored"
                )

            summary_details = {
                "Total commands": len(commands),
                "Collection level": collection_level,
                "Commands executed": [
                    (cmd.get("command", cmd) if isinstance(cmd, dict) else cmd)
                    for cmd in commands
                ],
                "Optional command failures": optional_failure_count,
                "Optional failure details": optional_failures,
            }
            if optional_failure_reason:
                summary_details["status_note_override"] = optional_failure_reason

            # Handle summary generation using helper function
            output_files = await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=function_tag,
                collection_name=f"{function_tag} Commands",
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=total_operations - successful_operations,
                output_files=output_files,
                additional_details=summary_details,
                kwargs=kwargs,
                collection_type="commands",
                ignore_empty_results=True,
            )

            result_context = {
                "total_commands": len(commands),
                "collection_level": collection_level,
                "results": results,
                "optional_failure_count": optional_failure_count,
                "optional_failures": optional_failures,
            }
            if optional_failure_reason:
                result_context.update(
                    {
                        "status": "success",
                        "reason": optional_failure_reason,
                    }
                )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="host_commands",
                additional_context=result_context,
            )

        return await self._execute_with_error_handling(
            dut_id, "host_commands", _commands_collection
        )

    async def run_host_device_based_commands(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Run host device based commands.

        After applying local validation, the function forwards ``dut_id``,
        ``function_tag``, and ``kwargs`` to
        ``self._handle_host_device_based_collection`` and preserves its return
        and exception contract. Terminal status is emitted only after host
        device based commands and its owned cleanup have completed. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run host device based commands.
        """
        return await self._handle_host_device_based_collection(
            dut_id, function_tag, **kwargs
        )

    async def _collect_managed_device_artifact(
        self,
        dut_id: str,
        collector_id: str,
        device_id: str,
        command_config: Mapping[str, Any],
        *,
        resolved_timeout_seconds: float,
        use_sudo: bool,
        output_pattern: Optional[str],
        filtered_kwargs: Dict[str, Any],
        remote_temp_root: Optional[str] = None,
    ) -> _ManagedModeCollection:
        """
        Run one data-driven per-device file producer without replaying it.

        The command is rendered only after its device identifier and output
        basename pass the shared remote-component boundary. The existing
        managed Host lifecycle then owns target containment, exact artifact
        inspection, bounded transfer, local validation, publication, and
        cleanup. Product commands and file names remain catalog data.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration,
                logs, and results.
            collector_id: Stable collector identifier used to correlate the
                managed command and its artifact.
            device_id: Endpoint-reported device identifier used only as a
                safely quoted command operand and filename substitution.
            command_config: Catalog mapping containing ``type``,
                ``command_template``, ``artifact_file_template``, the enforced
                single-attempt policy, and an optional governed cleanup
                contract.
            resolved_timeout_seconds: Target-owned payload deadline selected by
                the collector timeout resolver.
            use_sudo: Whether privileged execution is required for the managed
                command and its cleanup boundary.
            output_pattern: Optional collector output naming pattern.
            filtered_kwargs: Mapping supplying bounded output substitutions.
            remote_temp_root: Optional explicit remote parent for managed
                scratch. When omitted, ``TOOL_TEMP_DIR`` is used.

        Returns:
            A managed mode result containing a published output path only after
            the complete non-replaying artifact lifecycle succeeds.

        Raises:
            ManagedHostCommandConfigurationError: If required fields,
                placeholders, identifiers, filenames, or artifact bounds are
                invalid.
            asyncio.CancelledError: If the owning collection is cancelled after
                managed cleanup reaches a terminal state.
        """

        command_type = command_config.get("type")
        command_template = command_config.get("command_template")
        artifact_file_template = command_config.get("artifact_file_template")
        if (
            not isinstance(command_type, str)
            or _MANAGED_MODE_NAME_RE.fullmatch(command_type) is None
            or not isinstance(command_template, str)
            or command_template.count("{device_index}") != 1
            or command_template.count("{remote_stage_dir}") != 1
            or command_template.count("{remote_output_file}") != 1
            or not isinstance(artifact_file_template, str)
            or artifact_file_template.count("{device_index}") != 1
        ):
            raise ManagedHostCommandConfigurationError(
                "managed device artifact configuration is invalid"
            )

        stage_token = "NVDEBUG_MANAGED_DEVICE_STAGE_TOKEN"
        output_token = "NVDEBUG_MANAGED_DEVICE_OUTPUT_TOKEN"
        if stage_token in command_template or output_token in command_template:
            raise ManagedHostCommandConfigurationError(
                "managed device artifact command contains a reserved token"
            )

        try:
            safe_device_id = _safe_remote_output_component(device_id)
            artifact_file = _safe_remote_output_component(
                artifact_file_template.format(device_index=safe_device_id)
            )
            rendered_command = build_remote_cmd(
                command_template,
                device_index=safe_device_id,
                remote_stage_dir=stage_token,
                remote_output_file=output_token,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ManagedHostCommandConfigurationError(
                "managed device artifact template could not be rendered safely"
            ) from exc
        rendered_command = rendered_command.replace(
            stage_token, "{remote_stage_dir}"
        ).replace(output_token, "{remote_output_file}")
        if (
            _MANAGED_FILE_BASENAME_RE.fullmatch(artifact_file) is None
            or rendered_command.count("{remote_stage_dir}") != 1
            or rendered_command.count("{remote_output_file}") != 1
        ):
            raise ManagedHostCommandConfigurationError(
                "managed device artifact output is invalid"
            )

        try:
            max_artifact_bytes = _resolve_host_artifact_max_bytes(command_config)
        except ValueError as exc:
            raise ManagedHostCommandConfigurationError(
                "managed device artifact byte ceiling is invalid"
            ) from exc
        if max_artifact_bytes > self._runtime_boundary(
            dut_id, "managed_artifact_max_file_bytes"
        ):
            raise ManagedHostCommandConfigurationError(
                "managed device artifact byte ceiling exceeds the runtime boundary"
            )

        if command_config.get("single_attempt", True) is not True:
            raise ManagedHostCommandConfigurationError(
                "managed device artifact must use the single-attempt contract"
            )

        raw_cleanup = command_config.get("cleanup")
        if raw_cleanup is None:
            containment = "cgroup_v2"
            cleanup_requirement = "verified_owned_cgroup_v2_exit"
            command_lifecycle = "cgroup_v2_contained"
        elif not isinstance(raw_cleanup, Mapping) or set(raw_cleanup) != {
            "containment",
            "requirement",
            "command_lifecycle",
        }:
            raise ManagedHostCommandConfigurationError(
                "managed device artifact cleanup contract is invalid"
            )
        else:
            containment = raw_cleanup.get("containment")
            cleanup_requirement = raw_cleanup.get("requirement")
            command_lifecycle = raw_cleanup.get("command_lifecycle")
        expected_cleanup_contract = {
            "process_group": (
                "verified_owned_process_group_exit",
                "foreground_non_daemonizing",
            ),
            "cgroup_v2": (
                "verified_owned_cgroup_v2_exit",
                "cgroup_v2_contained",
            ),
        }.get(containment)
        if expected_cleanup_contract != (
            cleanup_requirement,
            command_lifecycle,
        ):
            raise ManagedHostCommandConfigurationError(
                "managed device artifact cleanup contract is inconsistent"
            )

        mode_config: Dict[str, Any] = {
            "mode": command_type,
            "command": rendered_command,
            "file_name": artifact_file,
            "remote_file": "{remote_output_file}",
            "file_extensions": [""],
            "min_artifact_bytes": command_config.get("min_artifact_bytes", 1),
        }
        for timeout_field in (
            "cleanup_timeout",
            "transfer_timeout",
            "validation_timeout",
            "persistence_timeout",
        ):
            if timeout_field in command_config:
                mode_config[timeout_field] = command_config[timeout_field]

        return await self._collect_managed_private_advanced_mode(
            dut_id,
            collector_id,
            mode_config,
            resolved_timeout_seconds=resolved_timeout_seconds,
            max_artifact_bytes=max_artifact_bytes,
            use_sudo=use_sudo,
            containment=containment,
            output_pattern=output_pattern,
            filtered_kwargs=filtered_kwargs,
            remote_temp_root=remote_temp_root,
            primary_pre_execution_grace_seconds=(
                self._host_pool_pre_execution_grace_seconds()
            ),
        )

    async def _handle_host_device_based_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle device-based host commands collection.

        Extract output pattern parameters using common function.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing handle host device based collection.
        """

        async def _device_based_collection():
            """
            Execute one complete device-based collection invocation.

            Configuration, detection, bounded device workers, ordered result
            aggregation, and summary generation remain inside the enclosing
            collector lifecycle. Unexpected child failures cancel and drain all
            owned siblings before they propagate.

            Returns:
                The standardized device-based collection result.

            Raises:
                BaseException: If configuration is unsafe, a delegated worker
                    fails unexpectedly, or process control interrupts owned
                    device work.
            """
            device_detection = kwargs.get("device_detection", {})
            device_commands = kwargs.get("device_commands", [])
            device_artifact_commands = kwargs.get("device_artifact_commands", [])
            device_concurrency = _resolve_device_collection_concurrency(kwargs)
            use_sudo = kwargs.get("use_sudo", False)

            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            output_files = []
            detected_devices = []
            error_messages = []
            diagnostic_files = []
            successful_operations = 0
            total_operations = 0
            dut_config: Dict[str, Any] = {}
            baseboard_name = ""
            baseboard_type = ""

            initial_commands = kwargs.get("initial_commands", [])
            if initial_commands is not None and not isinstance(initial_commands, list):
                total_operations += 1
                error_messages.append("initial_commands must be a list")
                initial_commands = []
            if not isinstance(device_commands, list):
                total_operations += 1
                error_messages.append("device_commands must be a list")
                device_commands = []
            if not isinstance(device_artifact_commands, list):
                total_operations += 1
                error_messages.append("device_artifact_commands must be a list")
                device_artifact_commands = []

            device_artifact_containments = set()
            for artifact_config in device_artifact_commands:
                if not isinstance(artifact_config, Mapping):
                    continue
                cleanup_config = artifact_config.get("cleanup")
                if cleanup_config is None:
                    device_artifact_containments.add("cgroup_v2")
                elif isinstance(cleanup_config, Mapping) and isinstance(
                    cleanup_config.get("containment"), str
                ):
                    device_artifact_containments.add(str(cleanup_config["containment"]))
            if "process_group" in device_artifact_containments:
                await self._log_runtime(
                    "WARNING",
                    "HostService",
                    "Managed device artifacts are using process_group containment "
                    "under an explicit foreground_non_daemonizing contract",
                    dut_id,
                )

            for index, cmd_config in enumerate(initial_commands or [], start=1):
                total_operations += 1
                if not isinstance(cmd_config, dict):
                    error_messages.append(f"Initial command #{index} must be a mapping")
                    continue

                command = cmd_config.get("command")
                file_name = cmd_config.get("file_name")
                if not command or not file_name:
                    error_messages.append(
                        f"Initial command #{index} must define command and file_name"
                    )
                    continue

                timeout = await self._resolve_collector_timeout(
                    dut_id,
                    kwargs,
                    default_timeout=120,
                    explicit_timeout_sources=[cmd_config, kwargs],
                )
                description = cmd_config.get("description", f"initial_command_{index}")
                (
                    exit_code,
                    stdout,
                    stderr,
                ) = await self._execute_host_command_with_capture(
                    dut_id,
                    command,
                    operation_name=description,
                    timeout=timeout,
                    use_sudo=cmd_config.get("use_sudo", use_sudo),
                    collector_id=kwargs.get("collector_id"),
                    output_file=file_name,
                    **(
                        {"max_retries": 1, "require_retry_control": True}
                        if cmd_config.get("single_attempt") is True
                        else {}
                    ),
                )

                if exit_code != 0:
                    error_detail = (
                        f"Initial command failed (exit_code={exit_code}): {command}"
                    )
                    if stderr:
                        error_detail += f", stderr: {stderr.strip()}"
                    error_messages.append(error_detail)
                    await self._log_collection_failure(
                        dut_id,
                        "initial_command",
                        description,
                        error_detail,
                        collector_id=kwargs.get("collector_id"),
                    )
                    continue

                relative_file_name = _relative_file_name_for_pattern(
                    file_name, output_pattern
                )
                file_path = await self._save_data_with_common_pattern(
                    dut_id,
                    stdout,
                    relative_file_name,
                    output_pattern=output_pattern,
                    substitutions={"file_name": relative_file_name},
                    **filtered_kwargs,
                )
                if file_path:
                    output_files.append(file_path)
                    successful_operations += 1
                    await self._log_collection_success(
                        dut_id, "initial_command", description
                    )
                else:
                    error_messages.append(
                        f"Failed to persist initial command output: {command}"
                    )

            try:
                dut_config = self.dut_manager.get_dut_config(dut_id)
                if isinstance(dut_config, dict):
                    baseboard_name = str(dut_config.get("baseboard") or "")
                    baseboard_type = str(dut_config.get("type") or "")
            except Exception as exc:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"Unable to retrieve DUT config for pre-device command handling: {exc}",
                )

            def _normalize(value: str) -> str:
                """
                Normalize the supplied value.

                After applying local validation, the function forwards ``value``
                to ``lower`` and preserves its return and exception contract.
                The source value keeps its ownership while the normalized
                representation is returned separately.

                Args:
                    value: Text supplied as value in the format accepted by this
                        function.

                Returns:
                    The canonical result text.
                """
                return value.strip().lower()

            normalized_baseboard_name = (
                _normalize(baseboard_name) if baseboard_name else ""
            )
            normalized_baseboard_type = (
                _normalize(baseboard_type) if baseboard_type else ""
            )

            pre_device_commands = kwargs.get("pre_device_commands", [])
            if isinstance(pre_device_commands, list) and pre_device_commands:
                total_pre_commands = len(pre_device_commands)
                for index, cmd_config in enumerate(pre_device_commands, start=1):
                    command = cmd_config.get("command")
                    if not command:
                        continue

                    allowed_baseboards = cmd_config.get("run_if_baseboard_in")
                    if allowed_baseboards:
                        if isinstance(allowed_baseboards, (list, tuple, set)):
                            allowed_values = [
                                _normalize(str(item))
                                for item in allowed_baseboards
                                if isinstance(item, (str, bytes))
                            ]
                        else:
                            allowed_values = [_normalize(str(allowed_baseboards))]
                        if allowed_values and (
                            normalized_baseboard_name not in allowed_values
                            and normalized_baseboard_type not in allowed_values
                        ):
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "HostService",
                                (
                                    f"Skipping pre-device command '{command}' "
                                    f"due to baseboard filter {allowed_values} "
                                    f"(baseboard='{baseboard_name}', type='{baseboard_type}')."
                                ),
                            )
                            continue

                    skip_baseboards = cmd_config.get("skip_if_baseboard_in")
                    if skip_baseboards:
                        if isinstance(skip_baseboards, (list, tuple, set)):
                            skip_values = [
                                _normalize(str(item))
                                for item in skip_baseboards
                                if isinstance(item, (str, bytes))
                            ]
                        else:
                            skip_values = [_normalize(str(skip_baseboards))]
                        if (
                            normalized_baseboard_name in skip_values
                            or normalized_baseboard_type in skip_values
                        ):
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "HostService",
                                (
                                    f"Skipping pre-device command '{command}' because "
                                    f"baseboard matched skip list {skip_values}."
                                ),
                            )
                            continue

                    command_use_sudo = cmd_config.get("use_sudo", use_sudo)
                    ignore_errors = cmd_config.get("ignore_errors", True)
                    timeout = await self._resolve_collector_timeout(
                        dut_id,
                        kwargs,
                        default_timeout=120,
                        explicit_timeout_sources=[cmd_config, kwargs],
                    )
                    description = cmd_config.get(
                        "description", f"pre_device_command_{index}"
                    )

                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "HostService",
                        (
                            f"Executing pre-device command ({index}/{total_pre_commands}): "
                            f"{description} -> {command}"
                        ),
                    )

                    (
                        exit_code,
                        stdout,
                        stderr,
                    ) = await self._execute_host_command_with_capture(
                        dut_id,
                        command,
                        operation_name=description,
                        timeout=timeout,
                        use_sudo=command_use_sudo,
                        collector_id=kwargs.get("collector_id"),
                        **(
                            {"max_retries": 1, "require_retry_control": True}
                            if cmd_config.get("single_attempt") is True
                            else {}
                        ),
                    )

                    if exit_code != 0:
                        error_detail = f"Pre-device command failed (exit_code={exit_code}): {command}"
                        if stderr:
                            error_detail += f", stderr: {stderr.strip()}"
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "WARNING" if ignore_errors else "ERROR",
                            "HostService",
                            error_detail,
                        )

                        if not ignore_errors:
                            return await self._create_standardized_collector_result(
                                successful_operations=0,
                                total_operations=1,
                                output_files=[],
                                error_messages=[error_detail],
                                operation_name="pre_device_command",
                                additional_context={"command": command},
                            )
                    else:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "HostService",
                            (
                                f"Pre-device command completed successfully: {command}"
                                + (
                                    f", stdout preview: {stdout[:200]}"
                                    if stdout
                                    else ""
                                )
                            ),
                        )

            # Detect devices
            detection_cmd = device_detection["command"]
            device_pattern = device_detection["device_pattern"]
            skip_message = device_detection.get("skip_message", "No devices found")
            detection_timeout = await self._resolve_collector_timeout(
                dut_id,
                kwargs,
                default_timeout=120,
                explicit_timeout_sources=[device_detection, kwargs],
            )

            await self._log_collection_start(dut_id, "device_detection")

            (
                exit_code,
                detection_output,
                detection_stderr,
            ) = await self._execute_host_command_with_capture(
                dut_id,
                detection_cmd,
                operation_name="device_detection",
                timeout=detection_timeout,
                use_sudo=use_sudo,
                collector_id=kwargs.get("collector_id"),
            )

            await self._write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HostService",
                (
                    f"Device detection command: {detection_cmd}, exit_code: {exit_code}, "
                    f"output: {detection_output[:500] if detection_output else ''}, "
                    f"stderr: {detection_stderr[:500] if detection_stderr else ''}"
                ),
            )

            if exit_code != 0:
                detection_error = f"Device detection failed: {detection_stderr}"
                detection_context: Dict[str, Any] = {"detection_command": detection_cmd}
                if successful_operations:
                    detection_context.update(
                        {"status": "partial", "reason": detection_error}
                    )
                return await self._create_standardized_collector_result(
                    successful_operations=successful_operations,
                    total_operations=total_operations + 1,
                    output_files=output_files,
                    error_messages=[*error_messages, detection_error],
                    operation_name="device_detection",
                    additional_context=detection_context,
                )

            # Parse endpoint-controlled output through the shared bounded
            # scalar-match boundary.  In particular, patterns with capture
            # groups must not leak tuples into command construction.
            matches = _bounded_device_matches(device_pattern, detection_output)

            await self._write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HostService",
                f"Device pattern: {device_pattern}, matches found: {matches}",
            )

            if not matches:
                if error_messages:
                    empty_status = "partial" if successful_operations else "error"
                    empty_reason = (
                        f"{skip_message}; initial command errors: "
                        + "; ".join(error_messages)
                    )
                else:
                    empty_status = "skipped"
                    empty_reason = skip_message
                return await self._create_standardized_collector_result(
                    successful_operations=successful_operations,
                    total_operations=total_operations,
                    output_files=output_files,
                    error_messages=error_messages,
                    operation_name="device_based_collection",
                    additional_context={
                        "status": empty_status,
                        "reason": empty_reason,
                        "devices_found": 0,
                        "detection_pattern": device_pattern,
                    },
                )

            detected_devices.extend(matches)
            processed_devices = list(matches)

            async def _collect_device(device_id: str) -> _DeviceCollectionOutcome:
                """
                Execute one device's configured operations in authored order.

                The worker keeps all mutable state local and returns immutable
                candidates to its parent. Text commands always precede managed
                artifact commands for this device, regardless of concurrency
                selected for other devices.

                Args:
                    device_id: Endpoint-discovered identity used only after the
                        shared safe-component boundary accepts it.

                Returns:
                    The ordered local outcome for one detected device.

                Raises:
                    BaseException: If an unexpected delegated failure or process
                        control occurs; the parent owns and drains every worker
                        before propagating it.

                Side Effects:
                    Executes configured host operations, writes collector
                    artifacts, and emits runtime collection records.
                """

                device_outputs: List[_DeviceCollectionOutput] = []
                device_output_paths = set()
                device_diagnostics: List[str] = []
                device_errors: List[str] = []
                device_total_operations = 0

                try:
                    safe_device_id = _safe_remote_output_component(device_id)
                except ValueError as exc:
                    rejected_operations = len(device_commands) + len(
                        device_artifact_commands
                    )
                    return _DeviceCollectionOutcome(
                        device_id=device_id,
                        total_operations=max(1, rejected_operations),
                        error_messages=(
                            f"Rejected device identifier {device_id!r}: {exc}",
                        ),
                    )

                for cmd_config in device_commands:
                    cmd_type = cmd_config["type"]
                    command_template = cmd_config["command_template"]
                    file_template = cmd_config["file_template"]

                    # Detection output is controlled by the endpoint. Device
                    # identifiers are command operands, not trusted template
                    # fragments, so interpolate them only through the common
                    # remote-shell quoting boundary.
                    try:
                        filename = _safe_remote_output_component(
                            file_template.format(device_index=safe_device_id)
                        )
                    except (KeyError, ValueError) as exc:
                        device_total_operations += 1
                        device_errors.append(
                            f"Rejected device identifier {device_id!r}: {exc}"
                        )
                        continue
                    command = build_remote_cmd(
                        command_template, device_index=safe_device_id
                    )
                    command_timeout = await self._resolve_collector_timeout(
                        dut_id,
                        kwargs,
                        default_timeout=120,
                        explicit_timeout_sources=[cmd_config, kwargs],
                    )

                    await self._log_collection_start(
                        dut_id, f"device_command_{device_id}_{cmd_type}"
                    )

                    (
                        exit_code,
                        command_output,
                        stderr,
                    ) = await self._execute_host_command_with_capture(
                        dut_id,
                        command,
                        operation_name=f"device_command_{device_id}_{cmd_type}",
                        timeout=command_timeout,
                        use_sudo=use_sudo,
                        collector_id=kwargs.get("collector_id"),
                        output_file=filename,
                        **(
                            {"max_retries": 1, "require_retry_control": True}
                            if cmd_config.get("single_attempt") is True
                            else {}
                        ),
                    )

                    device_total_operations += 1

                    if exit_code == 0:
                        await self._log_collection_success(
                            dut_id, "device_command", f"{device_id}_{cmd_type}"
                        )

                        relative_file_name = _relative_file_name_for_pattern(
                            filename, output_pattern
                        )
                        file_path = await self._save_data_with_common_pattern(
                            dut_id,
                            command_output,
                            relative_file_name,
                            output_pattern=output_pattern,
                            substitutions={"file_name": relative_file_name},
                            **filtered_kwargs,
                        )
                        duplicate_error = (
                            "Artifact write failed or produced a duplicate path: "
                            f"{safe_device_id}_{cmd_type}"
                        )
                        if file_path and file_path not in device_output_paths:
                            device_output_paths.add(file_path)
                            device_outputs.append(
                                _DeviceCollectionOutput(
                                    path=file_path,
                                    duplicate_error=duplicate_error,
                                )
                            )
                        else:
                            device_errors.append(duplicate_error)
                    else:
                        await self._log_collection_failure(
                            dut_id,
                            "device_command",
                            f"{device_id}_{cmd_type}",
                            collector_id=kwargs.get("collector_id"),
                        )
                        device_errors.append(
                            f"Device command failed: {device_id}_{cmd_type} - exit_code: {exit_code}"
                        )

                for command_index, cmd_config in enumerate(
                    device_artifact_commands, start=1
                ):
                    device_total_operations += 1
                    if not isinstance(cmd_config, Mapping):
                        device_errors.append(
                            "Device artifact command "
                            f"#{command_index} must be a mapping"
                        )
                        continue

                    cmd_type = str(cmd_config.get("type") or "artifact")
                    safe_command_type = (
                        cmd_type
                        if _MANAGED_MODE_NAME_RE.fullmatch(cmd_type) is not None
                        else f"command_{command_index}"
                    )
                    operation_name = (
                        f"device_artifact_{safe_device_id}_{safe_command_type}"
                    )
                    command_timeout = await self._resolve_collector_timeout(
                        dut_id,
                        kwargs,
                        default_timeout=120,
                        explicit_timeout_sources=[cmd_config, kwargs],
                    )
                    command_use_sudo = cmd_config.get("use_sudo", use_sudo)
                    if not isinstance(command_use_sudo, bool):
                        device_errors.append(
                            "Device artifact command use_sudo must be a boolean"
                        )
                        continue
                    await self._log_collection_start(dut_id, operation_name)
                    try:
                        managed_artifact = await self._collect_managed_device_artifact(
                            dut_id,
                            str(kwargs.get("collector_id") or "unknown"),
                            safe_device_id,
                            cmd_config,
                            resolved_timeout_seconds=command_timeout,
                            use_sudo=command_use_sudo,
                            output_pattern=output_pattern,
                            filtered_kwargs=filtered_kwargs,
                            remote_temp_root=cmd_config.get(
                                "remote_staging_root",
                                kwargs.get("remote_staging_root"),
                            ),
                        )
                    except ManagedHostCommandConfigurationError as exc:
                        error_detail = (
                            "Device artifact command configuration was rejected: "
                            f"{safe_device_id}_{safe_command_type} ({exc})"
                        )
                        device_errors.append(error_detail)
                        await self._log_collection_failure(
                            dut_id,
                            "device_artifact",
                            f"{safe_device_id}_{safe_command_type}",
                            error_detail,
                            collector_id=kwargs.get("collector_id"),
                        )
                        continue

                    for diagnostic_file in managed_artifact.diagnostic_files:
                        if diagnostic_file not in device_diagnostics:
                            device_diagnostics.append(diagnostic_file)
                    if (
                        managed_artifact.attempt.get("disposition") == "success"
                        and managed_artifact.output_file
                    ):
                        duplicate_error = (
                            "Managed device artifact produced a duplicate path: "
                            f"{safe_device_id}_{safe_command_type}"
                        )
                        if managed_artifact.output_file not in device_output_paths:
                            device_output_paths.add(managed_artifact.output_file)
                            device_outputs.append(
                                _DeviceCollectionOutput(
                                    path=managed_artifact.output_file,
                                    duplicate_error=duplicate_error,
                                    managed_attempt=dict(managed_artifact.attempt),
                                )
                            )
                            await self._log_collection_success(
                                dut_id,
                                "device_artifact",
                                f"{safe_device_id}_{safe_command_type}",
                            )
                        else:
                            device_errors.append(duplicate_error)
                            await self._log_collection_failure(
                                dut_id,
                                "device_artifact",
                                f"{safe_device_id}_{safe_command_type}",
                                duplicate_error,
                                collector_id=kwargs.get("collector_id"),
                            )
                    else:
                        error_detail = managed_artifact.error_message or (
                            "Device artifact command did not produce a valid file: "
                            f"{safe_device_id}_{safe_command_type}"
                        )
                        device_errors.append(error_detail)
                        await self._log_collection_failure(
                            dut_id,
                            "device_artifact",
                            f"{safe_device_id}_{safe_command_type}",
                            error_detail,
                            collector_id=kwargs.get("collector_id"),
                        )

                return _DeviceCollectionOutcome(
                    device_id=device_id,
                    total_operations=device_total_operations,
                    outputs=tuple(device_outputs),
                    diagnostic_files=tuple(device_diagnostics),
                    error_messages=tuple(device_errors),
                )

            device_semaphore = asyncio.Semaphore(device_concurrency)

            async def _collect_bounded_device(
                device_id: str,
            ) -> _DeviceCollectionOutcome:
                """
                Run one device worker beneath the configured concurrency bound.

                The semaphore limits active workers without changing discovery
                order or the sequence of operations inside a worker.

                Args:
                    device_id: Endpoint-discovered identity assigned to the
                        worker.

                Returns:
                    The completed per-device collection outcome.

                Raises:
                    BaseException: If the delegated device worker fails or is
                        cancelled.

                Side Effects:
                    Acquires one shared worker slot for the duration of all
                    ordered operations belonging to this device.
                """

                async with device_semaphore:
                    return await _collect_device(device_id)

            def _cancel_device_siblings_on_error(_error: BaseException) -> bool:
                """
                Request fail-fast cancellation after any unexpected child error.

                The shared owned-task drain invokes this predicate only after a
                child exception has been captured as data.

                Args:
                    _error: Captured child exception whose contents do not alter
                        the fail-fast decision.

                Returns:
                    Always ``True`` so unstarted or active siblings are cancelled
                    and then drained by their owner.
                """

                return True

            owned_device_tasks = tuple(
                asyncio.create_task(
                    capture_owned_awaitable(_collect_bounded_device(device_id))
                )
                for device_id in matches
            )
            device_task_outcomes = await drain_owned_tasks(
                owned_device_tasks,
                cancel_on_error=_cancel_device_siblings_on_error,
            )
            device_worker_errors = tuple(
                outcome.error
                for outcome in device_task_outcomes
                if outcome.error is not None and not outcome.owner_cancelled
            )
            if device_worker_errors:
                raise select_authoritative_exception(device_worker_errors)

            device_outcomes: List[_DeviceCollectionOutcome] = []
            for task_outcome in device_task_outcomes:
                if not isinstance(task_outcome.value, _DeviceCollectionOutcome):
                    raise RuntimeError(
                        "Device collection worker returned invalid state"
                    )
                device_outcomes.append(task_outcome.value)

            managed_device_artifacts = []
            for device_outcome in device_outcomes:
                total_operations += device_outcome.total_operations
                error_messages.extend(device_outcome.error_messages)
                for diagnostic_file in device_outcome.diagnostic_files:
                    if diagnostic_file not in diagnostic_files:
                        diagnostic_files.append(diagnostic_file)
                for produced_output in device_outcome.outputs:
                    if produced_output.path in output_files:
                        error_messages.append(produced_output.duplicate_error)
                    else:
                        output_files.append(produced_output.path)
                        successful_operations += 1
                        if produced_output.managed_attempt is not None:
                            managed_device_artifacts.append(
                                {
                                    "output_file": produced_output.path,
                                    "attempt": produced_output.managed_attempt,
                                }
                            )

            # Handle summary generation using helper function
            output_files = await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=function_tag,
                collection_name=f"{function_tag} Device Collection",
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=len(error_messages),
                output_files=output_files,
                additional_details={
                    "Detection command": detection_cmd,
                    "Device pattern": device_pattern,
                    "Device commands": [
                        cmd.get("command_template", cmd.get("command", ""))
                        for cmd in [*device_commands, *device_artifact_commands]
                        if isinstance(cmd, Mapping)
                    ],
                    "Devices found": len(detected_devices),
                    "Devices processed": processed_devices,
                    "Device concurrency": device_concurrency,
                    "Device artifact containment": sorted(device_artifact_containments),
                },
                kwargs=kwargs,
                collection_type="device_based_collection",
                ignore_empty_results=False,  # Device-based collection should fail if no devices found
            )

            return await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=kwargs.get("collector_id", "unknown"),
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="device_based_collection",
                additional_context={
                    "devices_found": len(detected_devices),
                    "devices_processed": processed_devices,
                    "detection_pattern": device_pattern,
                    "diagnostic_files": diagnostic_files,
                    "device_concurrency": device_concurrency,
                    "device_artifact_containment": sorted(device_artifact_containments),
                    **(
                        {
                            "device_managed_receipt": {
                                "schema_version": "1.0",
                                "policy": "managed_device_artifacts",
                                "enforced": True,
                                "artifacts": managed_device_artifacts,
                            }
                        }
                        if device_artifact_commands
                        else {}
                    ),
                },
            )

        return await self._execute_with_error_handling(
            dut_id, "host_device_based", _device_based_collection
        )

    async def _handle_host_composite_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Execute a generic, YAML-driven composite host collection.

        This handler executes a sequence of optional stages defined entirely in
        the collector definition. Typical stages include hardware detection,
        dependency checks, selecting and running one or more command scenarios,
        and downloading any artifacts to the log directory. Behavior (commands,
        timeouts, flags, temp directories, and output naming) is controlled via
        kwargs populated from the YAML. The function aggregates results, counts
        each successful stage as a successful operation, and returns a
        standardized result payload.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing handle host composite collection.
        """

        def should_capture_artifact(remote_file: str, config: Dict[str, Any]) -> bool:
            """
            Apply the composite collector's artifact allow/deny policy.

            The implementation uses ``remote_file`` and ``config`` to apply the
            composite collector's artifact allow/deny policy.

            Args:
                remote_file: filesystem location used as the remote file for
                    this operation.
                config: Config governing apply the composite collector's
                    artifact allow/deny policy.

            Returns:
                Whether the apply the composite collector's artifact allow/deny
                policy operation succeeds.
            """
            basename = os.path.basename(remote_file).lower()
            skipped_tokens = [
                str(token).strip().lower()
                for token in (config.get("files_to_skip") or [])
                if str(token).strip()
            ]
            if any(token in basename for token in skipped_tokens):
                return False

            # Preserve the historical default for out-of-tree composite
            # collectors.  H20 explicitly sets capture_all_files=false, which
            # means retain only the distributable report and its checksum.
            if config.get("capture_all_files", True):
                return True
            report_suffixes = (
                ".tar",
                ".tar.gz",
                ".tgz",
                ".tar.xz",
                ".txz",
                ".sha256",
                ".sha512",
                ".md5",
            )
            return basename.endswith(report_suffixes)

        def is_report_archive(remote_file: str) -> bool:
            """
            Return whether an artifact is the primary SOS archive, not a digest.

            After applying local validation, the function forwards
            ``remote_file`` to ``basename.endswith`` and preserves its return
            and exception contract.

            Args:
                remote_file: filesystem location used as the remote file for
                    this operation.

            Returns:
                Whether an artifact is the primary SOS archive, not a digest.
            """
            basename = os.path.basename(remote_file).lower()
            return basename.endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz"))

        def composite_output_name(output_pattern: str, source_name: str) -> str:
            """
            Build an output name without lying about the source encoding.

            A configured archive suffix is a fallback for suffix-less artifacts.
            If the producer supplied a suffix (for example .tar.xz or .sha256),
            preserve it verbatim.

            Args:
                output_pattern: Text supplied as output pattern in the format
                    accepted by this function.
                source_name: Stable source name used for lookup and
                    operator-facing diagnostics.

            Returns:
                The canonical composite output name.
            """
            if output_pattern and "*" in output_pattern:
                prefix, configured_suffix = output_pattern.split("*", 1)
                # A configured archive suffix is a fallback for suffix-less
                # artifacts.  If the producer supplied a suffix (for example
                # .tar.xz or .sha256), preserve it verbatim.
                source_has_suffix = bool(Path(source_name).suffixes)
                suffix = (
                    ""
                    if configured_suffix.startswith(".") and source_has_suffix
                    else configured_suffix
                )
                return f"{prefix}{source_name}{suffix}"
            if output_pattern and "{" in output_pattern and "}" in output_pattern:
                return self.get_output_filename(
                    output_pattern,
                    None,
                    "",
                    {"file_name": source_name},
                )
            return output_pattern or source_name

        owned_stages: List[_RemoteStagingDirectory] = []

        async def _composite_collection():
            """
            Return the composite collection.

            Extract output pattern parameters using common function.

            Returns:
                The composite collection.

            Raises:
                ValueError: If the composite temp_dir is not an operation
                    basename or absolute path; or the config.max_artifact_bytes
                    are not a positive integer no greater than
                    ``_HARD_COMPOSITE_ARTIFACT_MAX_BYTES``.
            """
            use_sudo = kwargs.get("use_sudo", False)
            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            output_files: List[str] = []
            diagnostic_files: List[str] = []
            error_messages: List[str] = []
            successful_operations = 0
            total_operations = 0
            captured_archive_count = 0

            # 1) Hardware detection (generic, command configurable via YAML)
            hd = kwargs.get("hardware_detection", {})
            if hd.get("enabled"):
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    "composite: hardware_detection start",
                )
                total_operations += 1
                query = hd.get("query") or {}
                vendor_ids = set((query.get("vendor_ids") or []))
                device_classes = set((query.get("device_classes") or []))
                name_patterns = query.get("name_patterns") or []
                skip_message = hd.get(
                    "skip_message",
                    "Required hardware not detected. Skipping collection.",
                )

                # Run hardware probe command once and evaluate
                hd_cmd = hd.get("command", "lspci -nn")
                exit_code, hd_out, _ = await self.dut_manager.execute_host_command(
                    dut_id, hd_cmd, use_sudo=use_sudo
                )
                if exit_code != 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "HostService",
                        "composite: hardware_detection failed to run lspci",
                    )
                    return await self._create_standardized_collector_result(
                        successful_operations=0,
                        total_operations=1,
                        output_files=[],
                        error_messages=["Failed to run lspci for hardware detection"],
                        operation_name="composite_collection",
                        additional_context={"reason": "lspci failed"},
                    )

                lines = hd_out.splitlines()
                found = False
                for line in lines:
                    # Match vendor ids like [10de:xxxx]
                    lower_line = line.lower()
                    if vendor_ids and any(
                        f"[{vid}" in lower_line for vid in vendor_ids
                    ):
                        found = True
                    # Match class codes like '0200' (Ethernet)
                    if device_classes and any(
                        dc in lower_line for dc in device_classes
                    ):
                        found = True
                    # Match name patterns substrings
                    if name_patterns and any(
                        np.lower() in lower_line for np in name_patterns
                    ):
                        found = True
                    if found:
                        break

                if not found:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "HostService",
                        f"composite: hardware_detection skip - {skip_message}",
                    )
                    return await self._create_standardized_collector_result(
                        successful_operations=1,
                        total_operations=1,
                        output_files=[],
                        error_messages=[],
                        operation_name="composite_collection",
                        additional_context={
                            "status": "skipped",
                            "reason": skip_message,
                            "message": skip_message,
                            "precondition_failed": True,
                            "hardware_not_applicable": True,
                            "intentional_evidence_only_skip": True,
                        },
                    )

                # Count hardware detection as success when hardware is present
                successful_operations += 1
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    "composite: hardware_detection pass",
                )

            # 2) Dependency checks (generic, with shell wrapping)
            dep_checks = kwargs.get("dependency_checks", [])
            if isinstance(dep_checks, list) and dep_checks:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"composite: dependency_checks start - count={len(dep_checks)}",
                )
                total_operations += 1
                for check in dep_checks:
                    cmd = check.get("command")
                    if not cmd:
                        continue
                    wrapped_cmd = self._wrap_for_shell(cmd)
                    exit_code, _, _ = await self.dut_manager.execute_host_command(
                        dut_id, wrapped_cmd, use_sudo=use_sudo
                    )
                    if exit_code != 0:
                        desc = check.get("description", "Dependency check failed")
                        if not check.get("required", True):
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "WARNING",
                                "HostService",
                                "composite: optional dependency unavailable; "
                                f"continuing collection - cmd='{cmd}', desc='{desc}'",
                            )
                            continue
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "HostService",
                            "composite: required dependency unavailable; "
                            f"skipping collection - cmd='{cmd}', desc='{desc}'",
                        )
                        return await self._create_standardized_collector_result(
                            successful_operations=successful_operations,
                            total_operations=total_operations,
                            output_files=[],
                            error_messages=[],
                            operation_name="composite_collection",
                            additional_context={
                                "status": "skipped",
                                "reason": desc,
                                "message": desc,
                                "failed_check": cmd,
                                "precondition_failed": True,
                                "missing_required_dependency": True,
                                "intentional_evidence_only_skip": True,
                            },
                        )

                # All dependency checks passed
                successful_operations += 1
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    "composite: dependency_checks pass",
                )

            # 3) Determine scenario (config_exists / combined / individual)
            requested_temp_dir = kwargs.get("temp_dir", "nvdebug_composite")
            requested_path = PurePosixPath(str(requested_temp_dir))
            if requested_path.name in {"", ".", ".."} or (
                not requested_path.is_absolute() and len(requested_path.parts) != 1
            ):
                raise ValueError(
                    "composite temp_dir must be an operation basename or absolute path"
                )
            configured_root = kwargs.get("remote_staging_root")
            if configured_root is None and requested_path.is_absolute():
                # Preserve explicit extension-config behavior while allowing
                # governed basename-only definitions to inherit TOOL_TEMP_DIR.
                configured_root = requested_path.parent.as_posix()
            remote_stage = await self._create_remote_staging_directory(
                dut_id,
                requested_path.name,
                use_sudo=use_sudo,
                owned_stages=owned_stages,
                configured_root=configured_root,
            )
            temp_dir = remote_stage.path
            quoted_temp_dir = quote_arg(temp_dir)

            config_file_check = kwargs.get("config_file_check", {})
            config_exists = False
            test_cmd = config_file_check.get("test_command")
            if test_cmd:
                exit_code, _, _ = await self.dut_manager.execute_host_command(
                    dut_id, test_cmd, use_sudo=use_sudo
                )
                config_exists = exit_code == 0

            cfg = kwargs.get("config", {})
            max_artifact_bytes = cfg.get(
                "max_artifact_bytes",
                _DEFAULT_COMPOSITE_ARTIFACT_MAX_BYTES,
            )
            if (
                type(max_artifact_bytes) is not int
                or max_artifact_bytes <= 0
                or max_artifact_bytes > _HARD_COMPOSITE_ARTIFACT_MAX_BYTES
            ):
                raise ValueError(
                    "config.max_artifact_bytes must be a positive integer no greater "
                    f"than {_HARD_COMPOSITE_ARTIFACT_MAX_BYTES}"
                )
            use_combined_command = cfg.get("use_combined_command", True)
            flags_list = list(cfg.get("flags", []) or [])
            flags = " ".join(flags_list) if flags_list else ""
            options = cfg.get("sos_command_options", [])
            options_combined = ",".join(options) if options else ""

            scenarios = kwargs.get("command_scenarios", {})
            chosen = None
            if config_exists and scenarios.get("config_exists"):
                chosen = scenarios["config_exists"]
            elif (
                (not config_exists)
                and use_combined_command
                and scenarios.get("config_missing_combined")
            ):
                chosen = scenarios["config_missing_combined"]
            elif (not config_exists) and scenarios.get("config_missing_individual"):
                chosen = scenarios["config_missing_individual"]

            if not chosen:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=["No suitable command scenario found"],
                    operation_name="composite_collection",
                )

            # Build the command from template
            template = chosen.get("command_template", "")
            # Apply generic ensure_flags from YAML (e.g., ["--batch"]) to avoid interactivity
            ensure_flags = list((cfg.get("ensure_flags") or []))
            for required_flag in ensure_flags:
                if required_flag not in flags_list and required_flag not in template:
                    flags_list.append(required_flag)
            flags = " ".join(flags_list) if flags_list else ""
            scenario_key = (
                "config_exists"
                if config_exists
                else (
                    "config_missing_combined"
                    if use_combined_command
                    else "config_missing_individual"
                )
            )
            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"composite: command_scenarios chosen={scenario_key}",
            )
            command = (
                template.replace("{temp_dir}", quoted_temp_dir)
                .replace("{flags}", flags)
                .replace("{options}", options_combined)
            )

            # For individual scenario, we may need to run per-option
            commands_to_run: List[str] = []
            if "{option}" in template and options:
                for opt in options:
                    commands_to_run.append(
                        template.replace("{temp_dir}", quoted_temp_dir)
                        .replace("{flags}", flags)
                        .replace("{option}", opt)
                    )
            else:
                commands_to_run.append(command)

            # Execute commands
            aggregated_stdout: List[str] = []
            for cmd in commands_to_run:
                total_operations += 1
                wrapped_cmd = self._wrap_for_shell(cmd)
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    "composite: executing command",
                )
                (
                    exit_code,
                    stdout,
                    stderr,
                ) = await self._execute_host_command_with_capture(
                    dut_id,
                    wrapped_cmd,
                    operation_name="composite_command",
                    use_sudo=use_sudo,
                    timeout=chosen.get("timeout", 600),
                    collector_id=kwargs.get("collector_id"),
                )
                if exit_code != 0:
                    error_messages.append(f"Command failed: {cmd}")
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "HostService",
                        f"composite: command failed - exit_code={exit_code}",
                    )
                else:
                    successful_operations += 1
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "HostService",
                        "composite: command pass",
                    )
                if stdout:
                    aggregated_stdout.append(stdout)

            # 4) Download everything from temp_dir
            list_cmd = build_remote_cmd(
                "find -P {dir} -mindepth 1 -maxdepth 1 -type f -print",
                dir=temp_dir,
            )
            exit_code, out, _ = await self.dut_manager.execute_host_command(
                dut_id, list_cmd, use_sudo=use_sudo
            )
            if exit_code == 0 and out and out.strip():
                listed_files = []
                authored_listing_parents = {requested_path}
                if not requested_path.is_absolute():
                    # Before basename-only catalog entries inherited
                    # TOOL_TEMP_DIR, the default composite path was rooted at
                    # /tmp. Accept that producer spelling only as inventory
                    # evidence, then rebind its basename to our private stage.
                    authored_listing_parents.add(PurePosixPath("/tmp") / requested_path)
                for listed_file in [
                    line.strip() for line in out.strip().split("\n") if line.strip()
                ]:
                    listed_path = PurePosixPath(listed_file)
                    # Older sos wrappers may echo the authored temp_dir even
                    # when --tmp-dir was replaced with the private directory.
                    # Preserve only the basename and rebind it to our stage;
                    # never transfer the echoed external path.
                    if listed_path.parent in authored_listing_parents:
                        listed_file = self._remote_staging_file_path(
                            remote_stage, listed_path.name
                        )
                    listed_files.append(listed_file)
                files = self._validate_remote_staging_files(
                    remote_stage,
                    listed_files,
                )
                approved_files = []
                for remote_file in files:
                    if should_capture_artifact(remote_file, cfg):
                        approved_files.append(remote_file)
                    else:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "HostService",
                            "composite: artifact excluded by policy - "
                            f"{os.path.basename(remote_file)}",
                        )
                files = approved_files
                if files:
                    (
                        prepared,
                        preparation_error,
                    ) = await self._prepare_remote_staging_files(
                        dut_id,
                        remote_stage,
                        files,
                    )
                else:
                    prepared, preparation_error = True, ""
                if files and not prepared:
                    total_operations += 1
                    error_messages.append(
                        "Failed to prepare exact SOS report files for transfer: "
                        f"{preparation_error}"
                    )
                    files = []
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"composite: download start - files={len(files)}",
                )
                for remote_file in files:
                    archive_validation_limits: Optional[ArchiveLimits] = None
                    archive_policy: Optional[_HostArchiveTransferPolicy] = None
                    artifact_transfer_max_bytes = max_artifact_bytes
                    if is_report_archive(remote_file):
                        archive_policy = _resolve_host_archive_transfer_policy(cfg)
                        artifact_transfer_max_bytes = archive_policy.max_transfer_bytes
                        archive_validation_limits = archive_policy.validation_limits
                    acquisition_timing_id = None
                    if self.timing_manager:
                        acquisition_timing_id = self.timing_manager.start_operation(
                            "host_file_acquisition",
                            os.path.basename(remote_file) or remote_file,
                            metadata={"transport": "host_file_transfer"},
                            compact_artifact_on_limit=True,
                        )
                    (
                        transfer_success,
                        transfer_error,
                    ) = await self.dut_manager.transfer_host_files(
                        dut_id,
                        remote_file,
                        local_staging_context.name,
                        copy_to_destination=False,
                        max_bytes=artifact_transfer_max_bytes,
                    )
                    if not transfer_success:
                        if self.timing_manager:
                            self.timing_manager.end_operation(
                                acquisition_timing_id,
                                status="error",
                                error=str(transfer_error),
                            )
                        total_operations += 1
                        error_messages.append(
                            f"Failed to download: {remote_file} - {transfer_error}"
                        )
                        continue
                    local_file_candidates: List[str] = []
                    basename_local_file = os.path.join(
                        local_staging_context.name,
                        os.path.basename(remote_file),
                    )
                    local_file_candidates.append(basename_local_file)
                    temp_dir_parent = os.path.dirname(os.path.normpath(temp_dir))
                    try:
                        remote_path = os.path.normpath(remote_file)
                        temp_dir_path = os.path.normpath(temp_dir)
                        if (
                            os.path.commonpath([remote_path, temp_dir_path])
                            == temp_dir_path
                        ):
                            preserved_local_path = os.path.join(
                                local_staging_context.name,
                                os.path.relpath(remote_path, temp_dir_parent),
                            )
                            if preserved_local_path not in local_file_candidates:
                                local_file_candidates.append(preserved_local_path)
                    except ValueError:
                        pass

                    if not self.logger:
                        if self.timing_manager:
                            self.timing_manager.end_operation(
                                acquisition_timing_id,
                                status="error",
                                error="logger unavailable",
                            )
                        total_operations += 1
                        error_messages.append(
                            f"Logger unavailable; cannot save downloaded file: {remote_file}"
                        )
                        continue

                    local_file = None
                    for candidate in local_file_candidates:
                        if not os.path.exists(candidate):
                            continue
                        if os.path.isdir(candidate):
                            local_file = candidate
                            break
                        local_file = candidate
                        break

                    if not local_file:
                        if self.timing_manager:
                            self.timing_manager.end_operation(
                                acquisition_timing_id,
                                status="error",
                                error="downloaded file missing",
                            )
                        total_operations += 1
                        error_messages.append(
                            f"Downloaded file missing after transfer: {remote_file}"
                        )
                        continue

                    if os.path.isdir(local_file):
                        if self.timing_manager:
                            self.timing_manager.end_operation(
                                acquisition_timing_id,
                                status="skipped",
                                error="downloaded path is a directory",
                            )
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "HostService",
                            f"composite: skipping non-file artifact - {local_file}",
                        )
                        try:
                            shutil.rmtree(local_file)
                        except Exception:
                            pass
                        continue

                    if archive_policy is not None:
                        await self._log_collection_archive_size_advisory(
                            dut_id,
                            local_file,
                            archive_policy,
                        )

                    if archive_validation_limits is not None:
                        archive_valid, archive_error = (
                            await self._validate_advanced_archive_async(
                                local_file,
                                remote_file,
                                limits=archive_validation_limits,
                            )
                        )
                        if not archive_valid:
                            if self.timing_manager:
                                self.timing_manager.end_operation(
                                    acquisition_timing_id,
                                    status="error",
                                    error=str(archive_error or "invalid archive"),
                                )
                            total_operations += 1
                            error_messages.append(
                                "Rejected invalid downloaded report archive "
                                f"{remote_file}: {archive_error or 'invalid archive'}"
                            )
                            continue

                    final_name = os.path.basename(remote_file)
                    final_output_name = composite_output_name(
                        output_pattern, final_name
                    )

                    persistence_timing_id = None
                    if self.timing_manager:
                        persistence_timing_id = self.timing_manager.start_operation(
                            "artifact_persistence",
                            final_output_name,
                            metadata={"source": "host_composite_collection"},
                        )
                    file_path_out = None
                    try:
                        file_path_out = await self.logger.create_collector_log_file(
                            dut_id,
                            "host",
                            kwargs.get("collector_id", ""),
                            final_output_name,
                        )
                        copied_bytes = _copy_regular_file_bounded(
                            local_file,
                            file_path_out,
                            max_bytes=artifact_transfer_max_bytes,
                        )
                    except BaseException as exc:
                        if file_path_out is not None:
                            try:
                                Path(file_path_out).unlink()
                            except OSError:
                                pass
                        if self.timing_manager:
                            failure_status = (
                                "cancelled"
                                if isinstance(exc, asyncio.CancelledError)
                                else "error"
                            )
                            self.timing_manager.end_operation(
                                persistence_timing_id,
                                status=failure_status,
                                error=(
                                    "CancelledError"
                                    if isinstance(exc, asyncio.CancelledError)
                                    else str(exc)
                                ),
                            )
                            self.timing_manager.end_operation(
                                acquisition_timing_id,
                                status=failure_status,
                                error=(
                                    "CancelledError"
                                    if isinstance(exc, asyncio.CancelledError)
                                    else str(exc)
                                ),
                            )
                        # Persistence errors are recoverable only for ordinary
                        # exceptions. Preserve process controls and cancellation
                        # after closing their timing/partial-file state.
                        if not isinstance(exc, Exception):
                            raise
                        total_operations += 1
                        error_messages.append(
                            f"Failed to persist downloaded file {remote_file}: {exc}"
                        )
                        continue
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            persistence_timing_id,
                            artifact_path=str(file_path_out),
                            size_bytes=copied_bytes,
                        )
                        self.timing_manager.end_operation(
                            acquisition_timing_id,
                            artifact_path=str(file_path_out),
                            size_bytes=copied_bytes,
                        )
                    output_files.append(str(file_path_out))
                    total_operations += 1
                    successful_operations += 1
                    if is_report_archive(remote_file):
                        captured_archive_count += 1
                    try:
                        if local_file == basename_local_file:
                            os.remove(local_file)
                    except Exception:
                        pass
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"composite: download complete - files={len(output_files)}",
                )
            else:
                total_operations += 1
                error_messages.append(
                    "Composite staging inventory was empty or unavailable "
                    f"(exit_code={exit_code})"
                )
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    "composite: staging inventory was empty or unavailable - "
                    f"exit_code={exit_code}",
                )

            if captured_archive_count == 0 and not output_files:
                total_operations += 1
                error_messages.append(
                    "No approved report archive was collected; checksums, stdout, "
                    "and private-map files are not sufficient"
                )

            # Optionally write aggregated stdout to a file if requested
            stdout_file_name = (cfg or {}).get("stdout_file_name")
            if stdout_file_name and aggregated_stdout and self.logger:
                # Keep the configured basename as diagnostic evidence.
                stdout_content = "\n".join(aggregated_stdout)
                diagnostic_stdout_name = f"diagnostic/{stdout_file_name}"
                persistence_timing_id = None
                if self.timing_manager:
                    persistence_timing_id = self.timing_manager.start_operation(
                        "artifact_persistence",
                        diagnostic_stdout_name,
                        metadata={"source": "host_composite_stdout"},
                        compact_artifact_on_limit=True,
                    )
                file_path_out = None
                try:
                    file_path_out = await self.logger.create_collector_log_file(
                        dut_id,
                        "host",
                        kwargs.get("collector_id", ""),
                        diagnostic_stdout_name,
                    )
                    with open(
                        file_path_out, "w", encoding="utf-8", errors="ignore"
                    ) as f:
                        f.write(stdout_content)
                    diagnostic_files.append(str(file_path_out))
                except asyncio.CancelledError:
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            persistence_timing_id,
                            status="cancelled",
                            error="CancelledError",
                        )
                    raise
                except Exception as exc:
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            persistence_timing_id,
                            status="error",
                            error=str(exc),
                        )
                    error_messages.append("Failed to write aggregated stdout file")
                else:
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            persistence_timing_id,
                            artifact_path=str(file_path_out),
                            size_bytes=len(stdout_content.encode("utf-8")),
                        )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="composite_collection",
                additional_context={"diagnostic_files": diagnostic_files},
            )

        # Endpoint-named files are transferred only into this unpredictable,
        # mode-0700 directory.  The owning context also removes every staged
        # path on success, failure, or cancellation.
        local_staging_parent = await self._resolve_local_staging_parent(dut_id)
        local_staging_context = tempfile.TemporaryDirectory(
            prefix="nvdebug-composite-",
            dir=local_staging_parent,
        )
        try:
            return await self._execute_with_error_handling(
                dut_id, "host_composite_collection", _composite_collection
            )
        finally:
            local_staging_context.cleanup()
            await self._cleanup_remote_staging_directories(dut_id, owned_stages)

    async def _record_managed_command_diagnostic(
        self,
        dut_id: str,
        collector_id: str,
        managed: ManagedHostCommandResult,
        *,
        command: str,
        operation: str,
        timeout: float,
    ) -> Optional[str]:
        """
        Persist decoded target evidence independently of managed artifact adoption.

        Callers retain ownership of scratch cleanup if publication fails. Unlike
        primary managed artifacts, this transcript survives a failed attempt or
        later rollback of a report that did not reach durable completion.

        Args:
            dut_id: DUT owning the managed command.
            collector_id: Collector owning the transcript.
            managed: Decoded receipt containing the real target code and streams.
            command: Sanitizable payload text or a label for an encoded script.
            operation: Stable operation name distinguishing metadata and modes.
            timeout: Configured target deadline in seconds.

        Returns:
            The diagnostic path, or null for an embedder without a recorder.

        Raises:
            Exception: If sanitization or diagnostic publication fails.
        """

        recorder = getattr(type(self.logger), "record_command_diagnostic", None)
        if recorder is None:
            return None
        path = await recorder(
            self.logger,
            dut_id,
            collector_id=collector_id,
            transport="managed_host_target",
            target="host",
            command=command,
            exit_code=managed.target_exit_code,
            stdout=managed.target_stdout,
            stderr=managed.target_stderr,
            timeout=timeout,
            duration_seconds=None,
            operation=operation,
            outcome=managed.outcome.value,
            stdout_truncated=managed.stdout_truncated,
            stderr_truncated=managed.stderr_truncated,
        )
        return str(path) if path is not None else None

    async def _run_managed_host_payload(
        self,
        dut_id: str,
        collector_id: str,
        command: str,
        *,
        operation_name: str,
        target_timeout_seconds: float,
        cleanup_timeout_seconds: float,
        use_sudo: bool,
        containment: str = "process_group",
        primary_pre_execution_grace_seconds: Optional[float] = None,
        output_limit_bytes: int = 16 * 1024,
        remote_temp_root: Optional[str] = None,
        prepare_timeout_artifacts: bool = False,
        prepare_nonzero_artifacts: bool = False,
    ) -> ManagedHostCommandResult:
        """
        Run one payload through the non-replaying Host adapter boundary.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``command``, ``operation_name``, and
        ``target_timeout_seconds`` to ``run_managed_host_command`` and preserves
        its return and exception contract. Terminal status is emitted only after
        one payload through the non-replaying Host adapter boundary and its
        owned cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            command: Text supplied as command in the format accepted by this
                function.
            operation_name: Stable operation name used for lookup and
                operator-facing diagnostics.
            target_timeout_seconds: Maximum duration in seconds allowed for
                target timeout seconds.
            cleanup_timeout_seconds: Maximum duration in seconds allowed for
                cleanup timeout seconds.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            containment: Governed kernel ownership primitive for target-side
                lifecycle containment.
            primary_pre_execution_grace_seconds: Optional caller-side allowance
                for transport work proven to precede target execution.
            output_limit_bytes: Maximum retained bytes from each target output
                stream in the authenticated managed receipt.
            remote_temp_root: Optional explicit remote parent for the managed
                scratch directory. When omitted, ``TOOL_TEMP_DIR`` is used.
            prepare_timeout_artifacts: Whether bounded artifacts left by a
                verified target timeout should be prepared for diagnostic
                transfer. The timeout remains authoritative.
            prepare_nonzero_artifacts: Whether bounded artifacts left by a
                nonzero exit should be prepared for diagnostic transfer after
                verified target cleanup. The original failure remains terminal.

        Returns:
            A ``ManagedHostCommandResult`` representing run managed host
            payload.

        Raises:
            ManagedHostCommandConfigurationError: If cgroup-v2 containment is
                selected without the governed privileged execution route, or
                the Host temporary-directory configuration is invalid.
        """

        if containment == "cgroup_v2" and not use_sudo:
            raise ManagedHostCommandConfigurationError(
                "cgroup_v2 managed Host containment requires privileged execution"
            )
        try:
            resolved_remote_temp_root = await self._resolve_remote_staging_root(
                dut_id,
                remote_temp_root,
            )
        except (TypeError, ValueError) as exc:
            raise ManagedHostCommandConfigurationError(
                "managed Host temporary-directory configuration is invalid"
            ) from exc

        async def execute_remote(
            remote_command: str, *, timeout: float, max_retries: int
        ) -> Tuple[int, str, str]:
            """
            Stream one managed wrapper through the remote shell's standard input.

            The SSH command argument remains the fixed trusted POSIX-shell
            invocation while the bounded wrapper produced by
            ``run_managed_host_command`` is delivered over the existing input
            channel. This avoids the kernel's per-argument size limit without
            bypassing trusted-path setup, privileged execution, retry control,
            redaction, or the managed lifecycle receipt. Terminal status is
            emitted only after remote execution and its owned cleanup have
            completed.

            Args:
                remote_command: Text supplied as remote command in the format
                    accepted by this function. The text is sent as shell input,
                    not embedded in the SSH command argument.
                timeout: Maximum duration allowed before the operation is
                    cancelled or fails.
                max_retries: Upper bound enforced for max retries; the consuming
                    boundary rejects or truncates values that exceed it.

            Returns:
                A tuple containing the fields that represent execute remote.

            Raises:
                ManagedRemoteExecutorTimeout: If the Host adapter exhausts its
                    exact caller-side command or connection/retry deadline.
            """
            resolved_timeout = max(1, math.ceil(timeout))
            remote_script = (
                remote_command
                if remote_command.endswith("\n")
                else f"{remote_command}\n"
            )
            result = await self._execute_host_command_with_capture(
                dut_id,
                _MANAGED_HOST_STDIN_COMMAND,
                operation_name=operation_name,
                timeout=resolved_timeout,
                use_sudo=use_sudo,
                collector_id=collector_id,
                require_retry_control=True,
                max_retries=max_retries,
                redact_command=True,
                input_val=remote_script,
            )
            exit_code, _, stderr = result
            if exit_code == -1 and stderr in {
                f"SSH command timed out after {resolved_timeout} seconds",
                (
                    "SSH connection/retry budget timed out after "
                    f"{resolved_timeout} seconds"
                ),
                f"Command timed out after {resolved_timeout} seconds",
            }:
                raise ManagedRemoteExecutorTimeout
            return result

        return await run_managed_host_command(
            execute_remote,
            command,
            target_timeout_seconds=target_timeout_seconds,
            cleanup_timeout_seconds=cleanup_timeout_seconds,
            containment=containment,
            primary_pre_execution_grace_seconds=(primary_pre_execution_grace_seconds),
            output_limit_bytes=output_limit_bytes,
            remote_temp_root=resolved_remote_temp_root,
            prepare_timeout_artifacts=prepare_timeout_artifacts,
            prepare_nonzero_artifacts=prepare_nonzero_artifacts,
            command_via_stdin=True,
        )

    async def _cleanup_managed_artifact_directory(
        self,
        dut_id: str,
        collector_id: str,
        artifact_dir: str,
        candidate_paths: Tuple[str, ...],
        *,
        use_sudo: bool,
        timeout_seconds: float,
    ) -> bool:
        """
        Remove only reviewed files and the exact random run directories.

        The implementation uses ``dut_id``, ``collector_id``, ``artifact_dir``,
        ``candidate_paths``, and ``use_sudo`` to remove only reviewed files and
        the exact random run directories. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            artifact_dir: filesystem location used as the artifact dir for this
                operation.
            candidate_paths: Filesystem locations processed in caller-provided
                order.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            timeout_seconds: Maximum duration in seconds allowed for timeout
                seconds.

        Returns:
            Whether the remove only reviewed files and the exact random run
            directories operation succeeds.

        Raises:
            asyncio.CancelledError: After the single cleanup owner reaches a
                terminal state when caller cancellation is observed.
        """

        if not _MANAGED_ARTIFACT_DIR_RE.fullmatch(artifact_dir):
            return False
        attempt_dir = str(PurePosixPath(artifact_dir).parent)
        if any(
            str(PurePosixPath(path).parent) != artifact_dir for path in candidate_paths
        ):
            return False

        quoted_artifact_dir = shlex.quote(artifact_dir)
        quoted_attempt_dir = shlex.quote(attempt_dir)
        guarded_commands = [
            f"[ -d {quoted_artifact_dir} ]",
            f"[ ! -L {quoted_artifact_dir} ]",
        ]
        if candidate_paths:
            guarded_commands.append(
                "rm -f -- " + " ".join(shlex.quote(path) for path in candidate_paths)
            )
        guarded_commands.extend(
            [
                f"rmdir -- {quoted_artifact_dir}",
                f"rmdir -- {quoted_attempt_dir}",
            ]
        )
        cleanup_script = " ".join(
            (
                "set -f;",
                (
                    f"if [ ! -e {quoted_attempt_dir} ] && "
                    f"[ ! -L {quoted_attempt_dir} ]; then "
                    f"[ ! -e {quoted_artifact_dir} ] && "
                    f"[ ! -L {quoted_artifact_dir} ]; exit $?; fi;"
                ),
                f"[ -d {quoted_attempt_dir} ] && [ ! -L {quoted_attempt_dir} ] || exit 73;",
                (
                    f"if [ ! -e {quoted_artifact_dir} ] && "
                    f"[ ! -L {quoted_artifact_dir} ]; then "
                    f"rmdir -- {quoted_attempt_dir}; exit $?; fi;"
                ),
                " && ".join(guarded_commands),
            )
        )
        # Keep the complete guard and cleanup sequence in one shell invocation.
        # DUTManager applies sudo to the command as a whole; passing a bare
        # compound fragment here would otherwise elevate only its first command.
        cleanup_command = shlex.join(["sh", "-c", cleanup_script])
        cleanup_task = asyncio.create_task(
            self._execute_host_command_with_capture(
                dut_id,
                cleanup_command,
                operation_name="managed_artifact_cleanup",
                timeout=max(1, math.ceil(timeout_seconds)),
                use_sudo=use_sudo,
                collector_id=collector_id,
                require_retry_control=True,
                max_retries=1,
                redact_command=True,
            )
        )
        deferred_cancel = False
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError:
                deferred_cancel = True
            except Exception:
                break
        try:
            exit_code, _, _ = cleanup_task.result()
        except asyncio.CancelledError:
            cleanup_succeeded = False
        except Exception:
            cleanup_succeeded = False
        else:
            cleanup_succeeded = exit_code == 0
        if deferred_cancel:
            raise asyncio.CancelledError
        return cleanup_succeeded

    async def _inspect_managed_artifact_candidates(
        self,
        dut_id: str,
        collector_id: str,
        artifact_dir: str,
        remote_file: str,
        file_extensions: Tuple[str, ...],
        *,
        min_artifact_bytes: int,
        max_artifact_bytes: Optional[int] = None,
        use_sudo: bool,
    ) -> Tuple[str, Optional[str], Optional[int], Optional[str]]:
        """
        Resolve an exact-one regular artifact set without remote globs.

        The implementation uses ``dut_id``, ``collector_id``, ``artifact_dir``,
        ``remote_file``, and ``file_extensions`` to resolve an exact-one regular
        artifact set without remote globs. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            artifact_dir: filesystem location used as the artifact dir for this
                operation.
            remote_file: filesystem location used as the remote file for this
                operation.
            file_extensions: Entries supplied as ``file_extensions`` without
                transferring container ownership.
            min_artifact_bytes: Numeric min artifact bytes used while the
                operation performs bounded accounting.
            max_artifact_bytes: Optional collector-specific artifact ceiling;
                ``None`` selects the active platform runtime boundary.
            use_sudo: Whether use sudo is enabled or required for this
                operation.

        Returns:
            A tuple containing the validation status, selected path, byte size,
            and extension.
        """

        runtime_max_artifact_bytes = self._runtime_boundary(
            dut_id, "managed_artifact_max_file_bytes"
        )
        effective_max_artifact_bytes = (
            runtime_max_artifact_bytes
            if max_artifact_bytes is None
            else max_artifact_bytes
        )
        if (
            not _MANAGED_ARTIFACT_DIR_RE.fullmatch(artifact_dir)
            or isinstance(min_artifact_bytes, bool)
            or not isinstance(min_artifact_bytes, int)
            or isinstance(effective_max_artifact_bytes, bool)
            or not isinstance(effective_max_artifact_bytes, int)
            or not 1
            <= min_artifact_bytes
            <= effective_max_artifact_bytes
            <= runtime_max_artifact_bytes
        ):
            return "invalid", None, None, None
        attempt_dir = str(PurePosixPath(artifact_dir).parent)
        candidates = tuple(
            str(PurePosixPath(artifact_dir) / f"{remote_file}{extension}")
            for extension in file_extensions
        )
        quoted_attempt_dir = shlex.quote(attempt_dir)
        quoted_artifact_dir = shlex.quote(artifact_dir)
        clauses: List[str] = [
            "set -f",
            (
                f"[ -d {quoted_attempt_dir} ] && "
                f"[ ! -L {quoted_attempt_dir} ] && "
                f"[ -d {quoted_artifact_dir} ] && "
                f"[ ! -L {quoted_artifact_dir} ] || exit 73"
            ),
        ]
        for index, candidate in enumerate(candidates):
            quoted = shlex.quote(candidate)
            clauses.append(
                " ".join(
                    [
                        f"if [ -L {quoted} ]; then printf 'L:{index}\\n';",
                        f"elif [ -f {quoted} ]; then",
                        f"artifact_stat=$(stat -c '%s:%h' -- {quoted}) || exit 74;",
                        f"printf 'F:{index}:%s\\n' \"$artifact_stat\";",
                        f"elif [ -e {quoted} ]; then printf 'O:{index}\\n'; fi",
                    ]
                )
            )
        inspection_script = "; ".join(clauses)
        # As with cleanup above, preserve the compound fragment as one argv
        # element so a sudo prefix covers every inspection clause.
        inspection_command = shlex.join(["sh", "-c", inspection_script])
        try:
            exit_code, stdout, _ = await self._execute_host_command_with_capture(
                dut_id,
                inspection_command,
                operation_name="managed_artifact_inspection",
                timeout=_MANAGED_ARTIFACT_INSPECTION_TIMEOUT_SECONDS,
                use_sudo=use_sudo,
                collector_id=collector_id,
                require_retry_control=True,
                max_retries=1,
                redact_command=True,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return "transport_error", None, None, None
        if exit_code != 0:
            return (
                "invalid" if exit_code in {73, 74} else "transport_error",
                None,
                None,
                None,
            )

        records: List[Tuple[str, int, Optional[int], Optional[int]]] = []
        for line in stdout.splitlines():
            match = re.fullmatch(r"([FLO]):([0-7])(?::([0-9]+):([0-9]+))?", line)
            if match is None:
                return "invalid", None, None, None
            kind, raw_index, raw_size, raw_links = match.groups()
            index = int(raw_index)
            if index >= len(candidates):
                return "invalid", None, None, None
            records.append(
                (
                    kind,
                    index,
                    int(raw_size) if raw_size is not None else None,
                    int(raw_links) if raw_links is not None else None,
                )
            )
        if not records:
            return "missing", None, None, None
        if len(records) != 1:
            return "invalid", None, None, None
        kind, index, size_bytes, link_count = records[0]
        if (
            kind != "F"
            or size_bytes is None
            or link_count != 1
            or not min_artifact_bytes <= size_bytes <= effective_max_artifact_bytes
        ):
            return "invalid", None, None, None
        return "valid", candidates[index], size_bytes, file_extensions[index]

    def _managed_host_uses_local_transport(self, dut_id: str) -> bool:
        """
        Resolve the existing local Host execution mode without probing.

        The implementation uses ``dut_id`` to resolve the existing local Host
        execution mode without probing.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            Whether the existing local Host execution mode without probing
            operation succeeds.
        """

        try:
            dut = self.dut_manager.get_dut(dut_id)
        except Exception:
            return False
        config = getattr(dut, "config", None)
        credentials = getattr(dut, "credentials", None)
        execution_mode = getattr(credentials, "execution_mode", "")
        return bool(
            (isinstance(config, Mapping) and config.get("local", False))
            or (
                isinstance(execution_mode, str) and execution_mode.casefold() == "local"
            )
        )

    async def _transfer_managed_artifact_to_stage(
        self,
        dut_id: str,
        remote_path: str,
        staged_path: Path,
        *,
        expected_size: int,
        max_bytes: int,
        timeout_seconds: float,
    ) -> bool:
        """
        Acquire one exact managed artifact without legacy command fallbacks.

        The implementation uses ``dut_id``, ``remote_path``, ``staged_path``,
        ``expected_size``, ``max_bytes``, and ``timeout_seconds`` to acquire one
        exact managed artifact without legacy command fallbacks. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            remote_path: filesystem location used as the remote path for this
                operation.
            staged_path: filesystem location used as the staged path for this
                operation.
            expected_size: Numeric expected size used by the operation's bounded
                accounting.
            max_bytes: Collector-specific maximum accepted artifact size.
            timeout_seconds: Maximum duration in seconds allowed for timeout
                seconds.

        Returns:
            Whether the acquire one exact managed artifact without legacy
            command fallbacks operation succeeds.
        """

        max_artifact_bytes = self._runtime_boundary(
            dut_id, "managed_artifact_max_file_bytes"
        )
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or not 0 <= expected_size <= max_bytes <= max_artifact_bytes
        ):
            return False

        transfer_succeeded = False
        if self._managed_host_uses_local_transport(dut_id):
            cancellation_event = threading.Event()
            deadline = time.monotonic() + timeout_seconds
            try:
                await asyncio.wait_for(
                    _run_managed_filesystem_operation(
                        self._copy_managed_file_to_private_path,
                        Path(remote_path),
                        staged_path,
                        expected_size,
                        cancellation_event,
                        deadline,
                        cancellation_event=cancellation_event,
                    ),
                    timeout=timeout_seconds,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                return False
            transfer_succeeded = True
        else:
            transfer = getattr(self.dut_manager, "transfer_managed_host_file", None)
            if not callable(transfer):
                return False
            try:
                result = await transfer(
                    dut_id,
                    remote_path,
                    str(staged_path),
                    timeout_seconds=timeout_seconds,
                    expected_size=expected_size,
                    max_bytes=max_bytes,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                return False
            transfer_succeeded = (
                isinstance(result, tuple)
                and len(result) == 2
                and result[0] is True
                and isinstance(result[1], str)
            )

        if not transfer_succeeded:
            return False
        try:
            staged_status = staged_path.lstat()
        except OSError:
            return False
        return bool(
            stat.S_ISREG(staged_status.st_mode)
            and staged_status.st_nlink == 1
            and staged_status.st_size == expected_size
        )

    @staticmethod
    def _copy_managed_file_to_private_path(
        source: Path,
        destination: Path,
        expected_size: int,
        cancellation_event: threading.Event,
        deadline: float,
    ) -> None:
        """
        Copy one exact regular file; never publish or replace a destination.

        The implementation uses ``source``, ``destination``, ``expected_size``,
        ``cancellation_event``, and ``deadline`` to copy one exact regular file;
        never publish or replace a destination. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        If the function cannot copy one exact regular file; never publish or
        replace a destination, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            source: filesystem location used as the source for this operation.
            destination: filesystem location used as the destination for this
                operation.
            expected_size: Numeric expected size used by the operation's bounded
                accounting.
            cancellation_event: Cancellation event object whose ``is_set`` state
                is read while performing copy one exact regular file; never
                publish or replace a destination.
            deadline: Absolute monotonic deadline after which the operation must
                stop.

        Raises:
            ValueError: If managed artifact source evidence was invalid; managed
                artifact grew during copy; managed artifact changed during copy;
                or managed artifact destination evidence was invalid.
            _ManagedFilesystemOperationStopped: If managed artifact copy
                stopped.
            OSError: If managed artifact copy made no progress.
        """

        completed = False
        destination_created = False
        source_fd: Optional[int] = None
        destination_fd: Optional[int] = None
        try:
            source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            source_fd = os.open(source, source_flags)
            source_before = os.fstat(source_fd)
            if (
                not stat.S_ISREG(source_before.st_mode)
                or source_before.st_nlink != 1
                or source_before.st_size != expected_size
                or not 0 <= expected_size <= _MAX_MANAGED_ARTIFACT_BYTES
            ):
                raise ValueError("managed artifact source evidence was invalid")

            destination_flags = (
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            )
            destination_fd = os.open(destination, destination_flags, 0o600)
            destination_created = True
            copied = 0
            while True:
                if cancellation_event.is_set() or time.monotonic() >= deadline:
                    raise _ManagedFilesystemOperationStopped(
                        "managed artifact copy stopped"
                    )
                chunk = os.read(source_fd, _MANAGED_FILE_CHUNK_BYTES)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > expected_size:
                    raise ValueError("managed artifact grew during copy")
                view = memoryview(chunk)
                while view:
                    if cancellation_event.is_set() or time.monotonic() >= deadline:
                        raise _ManagedFilesystemOperationStopped(
                            "managed artifact copy stopped"
                        )
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise OSError("managed artifact copy made no progress")
                    view = view[written:]

            source_after = os.fstat(source_fd)
            if (
                copied != expected_size
                or source_after.st_size != source_before.st_size
                or source_after.st_mtime_ns != source_before.st_mtime_ns
                or source_after.st_ctime_ns != source_before.st_ctime_ns
            ):
                raise ValueError("managed artifact changed during copy")
            os.fsync(destination_fd)
            destination_status = os.fstat(destination_fd)
            if (
                not stat.S_ISREG(destination_status.st_mode)
                or destination_status.st_nlink != 1
                or destination_status.st_size != expected_size
            ):
                raise ValueError("managed artifact destination evidence was invalid")
            completed = True
        finally:
            if destination_fd is not None:
                os.close(destination_fd)
            if source_fd is not None:
                os.close(source_fd)
            if destination_created and not completed:
                try:
                    destination.unlink()
                except FileNotFoundError:
                    pass

    async def _persist_managed_artifact(
        self,
        dut_id: str,
        collector_id: str,
        staged_path: Path,
        *,
        file_name: str,
        extension: str,
        output_pattern: Optional[str],
        timeout_seconds: float = _MANAGED_ARTIFACT_PERSIST_TIMEOUT_SECONDS,
    ) -> Optional[str]:
        """
        Persist managed artifact.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``staged_path``, ``file_name``, and ``extension`` to
        ``str`` and preserves its return and exception contract. Success is
        reported only after the owning output boundary has completed its
        required write or publication step. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            staged_path: filesystem location used as the staged path for this
                operation.
            file_name: Stable file name used for lookup and operator-facing
                diagnostics.
            extension: Text supplied as extension in the format accepted by this
                function.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            timeout_seconds: Maximum duration in seconds allowed for timeout
                seconds.

        Returns:
            The canonical persist managed artifact text, or ``None`` when the
            requested value is unavailable.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to persist managed artifact.
        """
        if not self.logger:
            return None
        max_artifact_bytes = self._runtime_boundary(
            dut_id, "managed_artifact_max_file_bytes"
        )
        free_space_reserve_bytes = self._runtime_boundary(
            dut_id, "managed_artifact_persist_free_space_reserve_bytes"
        )
        base_filename = self.get_output_filename(
            output_pattern,
            file_name,
            "",
            {"file_name": file_name},
        )
        final_path = await self.logger.create_collector_log_file(
            dut_id,
            "host",
            collector_id,
            f"{base_filename}{extension}",
        )
        destination = Path(final_path)
        try:
            expected_size = staged_path.lstat().st_size
            if not 0 <= expected_size <= max_artifact_bytes:
                return None
            destination_free_bytes = shutil.disk_usage(destination.parent).free
            required_free_bytes = expected_size + free_space_reserve_bytes
            if destination_free_bytes < required_free_bytes:
                return None
        except Exception:
            return None
        timing_operation_id = None
        if self.timing_manager:
            timing_operation_id = self.timing_manager.start_operation(
                "artifact_persistence",
                destination.name,
                metadata={"artifact_kind": "managed_host_artifact"},
                compact_artifact_on_limit=True,
            )
        temporary = destination.with_name(
            f".{destination.name}.{secrets.token_hex(16)}.tmp"
        )
        cancellation_event = threading.Event()
        deadline = time.monotonic() + timeout_seconds
        timing_status = "error"
        timing_error: Optional[str] = "managed artifact was not published"
        published_path: Optional[str] = None
        try:
            await asyncio.wait_for(
                _run_managed_filesystem_operation(
                    self._copy_managed_file_to_private_path,
                    staged_path,
                    temporary,
                    expected_size,
                    cancellation_event,
                    deadline,
                    cancellation_event=cancellation_event,
                ),
                timeout=timeout_seconds,
            )
            current_task = asyncio.current_task()
            if current_task is not None and current_task.cancelling():
                cancellation_event.set()
                raise asyncio.CancelledError
            temporary_status = temporary.lstat()
            if (
                not stat.S_ISREG(temporary_status.st_mode)
                or temporary_status.st_nlink != 1
                or temporary_status.st_size != expected_size
            ):
                return None
            os.replace(temporary, destination)
            if not _register_managed_publication(
                destination,
                dut_id=dut_id,
                collector_id=collector_id,
            ):
                _rollback_managed_publications(
                    _ManagedPublicationOwner(
                        publications=[
                            _ManagedPublication(
                                path=destination,
                                dut_id=dut_id,
                                collector_id=collector_id,
                                device=temporary_status.st_dev,
                                inode=temporary_status.st_ino,
                            )
                        ]
                    )
                )
                timing_error = "managed artifact publication registration failed"
                return None
            timing_status = "success"
            timing_error = None
            published_path = str(final_path)
        except asyncio.CancelledError:
            timing_status = "cancelled"
            timing_error = "CancelledError"
            raise
        except Exception as exc:
            timing_error = str(exc)
            return None
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            if self.timing_manager:
                self.timing_manager.end_operation(
                    timing_operation_id,
                    status=timing_status,
                    artifact_path=published_path,
                    size_bytes=(expected_size if published_path is not None else None),
                    error=timing_error,
                )
        return published_path

    async def _persist_invalid_managed_artifact(
        self,
        dut_id: str,
        collector_id: str,
        staged_path: Path,
        *,
        file_name: str,
        extension: str,
        output_pattern: Optional[str],
        timeout_seconds: float,
    ) -> Optional[str]:
        """
        Retain exact rejected bytes as a marked diagnostic artifact.

        The helper derives the normal managed output basename, appends an
        ``.invalid`` marker after the source extension, and delegates the copy
        to the same bounded, fsynced, atomic publication boundary used for a
        valid managed artifact. The diagnostic path can therefore accompany a
        fallback result without being mistaken for a successful primary mode.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration,
                logs, and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            staged_path: Private local staging path containing the exact
                transferred artifact bytes.
            file_name: Catalog-bound basename used for the normal artifact.
            extension: Exact selected source extension, including its leading
                dot when one is present.
            output_pattern: Optional catalog-bound primary output pattern.
            timeout_seconds: Maximum duration allowed for diagnostic
                persistence.

        Returns:
            The published diagnostic path, or ``None`` when a safe name cannot
            be derived or publication fails.

        Raises:
            asyncio.CancelledError: If the owning collection is cancelled while
                diagnostic persistence is in progress.

        Side Effects:
            Atomically publishes one private diagnostic file through its own
            publication transaction. A later failed collector cannot roll back
            already complete evidence of the rejected artifact.
        """

        base_filename = self.get_output_filename(
            output_pattern,
            file_name,
            "",
            {"file_name": file_name},
        )
        if (
            not isinstance(base_filename, str)
            or _MANAGED_FILE_BASENAME_RE.fullmatch(base_filename) is None
        ):
            return None
        diagnostic_name = f"{base_filename}{extension}.invalid"
        if _MANAGED_FILE_BASENAME_RE.fullmatch(diagnostic_name) is None:
            return None
        parent_owner = _MANAGED_PUBLICATION_OWNER.get()
        if parent_owner is not None and parent_owner.sealed:
            return None
        diagnostic_owner = _ManagedPublicationOwner(publications=[])
        token = _MANAGED_PUBLICATION_OWNER.set(diagnostic_owner)
        try:
            path = await self._persist_managed_artifact(
                dut_id,
                collector_id,
                staged_path,
                file_name=diagnostic_name,
                extension="",
                output_pattern="diagnostic/{file_name}",
                timeout_seconds=timeout_seconds,
            )
            if path is not None and not (
                parent_owner is not None and parent_owner.sealed
            ):
                diagnostic_owner.adopted = True
                return path
            return None
        finally:
            if not diagnostic_owner.adopted:
                _rollback_managed_publications(diagnostic_owner)
            _MANAGED_PUBLICATION_OWNER.reset(token)

    async def _save_managed_stdout(
        self,
        dut_id: str,
        collector_id: str,
        stdout: str,
        *,
        file_name: str,
        output_pattern: Optional[str],
        filtered_kwargs: Dict[str, Any],
        diagnostic: bool,
    ) -> Optional[str]:
        """
        Save managed stdout.

        After applying local validation, the function forwards ``dut_id``,
        ``collector_id``, ``stdout``, ``file_name``, and ``output_pattern`` to
        ``str`` and preserves its return and exception contract. Success is
        reported only after the owning output boundary has completed its
        required write or publication step. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            stdout: Text supplied as stdout in the format accepted by this
                function.
            file_name: Stable file name used for lookup and operator-facing
                diagnostics.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            filtered_kwargs: Mapping supplying fields for managed stdout.
            diagnostic: Whether diagnostic is enabled or required for this
                operation.

        Returns:
            The canonical save managed stdout text, or ``None`` when the
            requested value is unavailable.

        Raises:
            OSError: If managed stdout write was incomplete.
        """
        if not stdout or not self.logger:
            return None
        try:
            sanitized_stdout = self.logger._sanitize_text(stdout)
        except Exception:
            return None
        if not isinstance(sanitized_stdout, str):
            return None
        try:
            payload = sanitized_stdout.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return None
        if not 1 <= len(payload) <= _MAX_MANAGED_STDOUT_BYTES:
            return None
        resolved_pattern = output_pattern
        if diagnostic:
            resolved_pattern = (
                f"diagnostic/{output_pattern}"
                if output_pattern
                else "diagnostic/{file_name}"
            )
        base_filename = self.get_output_filename(
            resolved_pattern,
            file_name,
            "",
            {"file_name": file_name},
        )
        del filtered_kwargs
        try:
            final_path = await self.logger.create_collector_log_file(
                dut_id,
                "host",
                collector_id,
                base_filename,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return None

        destination = Path(final_path)
        timing_operation_id = None
        if self.timing_manager:
            timing_operation_id = self.timing_manager.start_operation(
                "artifact_persistence",
                destination.name,
                metadata={"artifact_kind": "managed_host_stdout"},
                compact_artifact_on_limit=True,
            )
        temporary = destination.with_name(
            f".{destination.name}.{secrets.token_hex(16)}.tmp"
        )
        timing_status = "error"
        timing_error: Optional[str] = "managed stdout was not published"
        published_path: Optional[str] = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(temporary, flags, 0o600)
            try:
                with os.fdopen(descriptor, "wb", closefd=True) as stream:
                    descriptor = -1
                    if stream.write(payload) != len(payload):
                        raise OSError("managed stdout write was incomplete")
                    stream.flush()
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            temporary_status = temporary.lstat()
            if (
                not stat.S_ISREG(temporary_status.st_mode)
                or temporary_status.st_nlink != 1
                or temporary_status.st_size != len(payload)
            ):
                return None
            os.replace(temporary, destination)
            if not _register_managed_publication(
                destination,
                dut_id=dut_id,
                collector_id=collector_id,
            ):
                _rollback_managed_publications(
                    _ManagedPublicationOwner(
                        publications=[
                            _ManagedPublication(
                                path=destination,
                                dut_id=dut_id,
                                collector_id=collector_id,
                                device=temporary_status.st_dev,
                                inode=temporary_status.st_ino,
                            )
                        ]
                    )
                )
                timing_error = "managed stdout publication registration failed"
                return None
            timing_status = "success"
            timing_error = None
            published_path = str(destination)
            return published_path
        except asyncio.CancelledError:
            timing_status = "cancelled"
            timing_error = "CancelledError"
            raise
        except OSError as exc:
            timing_error = str(exc)
            return None
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            if self.timing_manager:
                self.timing_manager.end_operation(
                    timing_operation_id,
                    status=timing_status,
                    artifact_path=published_path,
                    size_bytes=(len(payload) if published_path is not None else None),
                    error=timing_error,
                )

    async def _collect_managed_fallback_metadata(
        self,
        dut_id: str,
        collector_id: str,
        initial_commands: Any,
        *,
        use_sudo: bool,
        output_pattern: Optional[str],
        filtered_kwargs: Dict[str, Any],
        cleanup_timeout_seconds: float,
        containment: str = "process_group",
        primary_pre_execution_grace_seconds: Optional[float] = None,
    ) -> _ManagedMetadataCollection:
        """
        Collect optional bounded metadata without deciding primary success.

        Run valid metadata commands in order and retain their available output.
        Diagnostic publication failures become warnings so later metadata and
        primary collection can proceed. Unverified process or scratch cleanup
        stops the loop and marks the lifecycle uncertain. Cancellation propagates
        after owned scratch cleanup when the producer is verified absent.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            initial_commands: Entries supplied as ``initial_commands`` and
                processed in caller-provided order.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            filtered_kwargs: Mapping supplying fields for optional bounded
                metadata without deciding primary success.
            cleanup_timeout_seconds: Maximum duration in seconds allowed for
                cleanup timeout seconds.
            containment: Governed kernel ownership primitive for target-side
                lifecycle containment.
            primary_pre_execution_grace_seconds: Configured local allowance for
                host-pool admission and connection proven to precede target
                execution. It does not extend target runtime.

        Returns:
            A ``_ManagedMetadataCollection`` representing managed fallback
            metadata.

        Raises:
            asyncio.CancelledError: If collection is cancelled, after any safely
                owned scratch cleanup has been awaited.
        """

        files: List[str] = []
        warnings: List[str] = []
        lifecycle_uncertain = False
        if not isinstance(initial_commands, list):
            return _ManagedMetadataCollection(
                warnings=("Optional metadata configuration was ignored",)
            )
        if len(initial_commands) > _MAX_MANAGED_METADATA_COMMANDS:
            return _ManagedMetadataCollection(
                warnings=("Optional metadata command count exceeded its bound",)
            )

        for index, command_config in enumerate(initial_commands):
            if not isinstance(command_config, Mapping):
                warnings.append("Optional metadata configuration was ignored")
                continue
            command = command_config.get("command")
            file_name = command_config.get("file_name")
            timeout = command_config.get("timeout")
            if (
                not isinstance(file_name, str)
                or not _MANAGED_FILE_BASENAME_RE.fullmatch(file_name)
                or command_config.get("expect_file") is not False
            ):
                warnings.append("Optional metadata configuration was ignored")
                continue
            try:
                managed = await self._run_managed_host_payload(
                    dut_id,
                    collector_id,
                    command,
                    operation_name=f"managed_metadata_{index}",
                    target_timeout_seconds=timeout,
                    cleanup_timeout_seconds=cleanup_timeout_seconds,
                    use_sudo=use_sudo,
                    containment=containment,
                    primary_pre_execution_grace_seconds=(
                        primary_pre_execution_grace_seconds
                    ),
                )
            except ManagedHostCommandConfigurationError:
                warnings.append("Optional metadata configuration was ignored")
                continue

            try:
                await self._record_managed_command_diagnostic(
                    dut_id,
                    collector_id,
                    managed,
                    command=command,
                    operation=f"managed_metadata_{index}",
                    timeout=timeout,
                )
            except Exception:
                warnings.append(
                    "Optional metadata command diagnostic publication failed"
                )
            finally:
                if managed.cleanup.status is ManagedHostCleanupStatus.VERIFIED_ABSENT:
                    cleaned = await self._cleanup_managed_artifact_directory(
                        dut_id,
                        collector_id,
                        managed.artifact_dir,
                        (),
                        use_sudo=use_sudo,
                        timeout_seconds=cleanup_timeout_seconds,
                    )
            if managed.cleanup.status is not ManagedHostCleanupStatus.VERIFIED_ABSENT:
                warnings.append("Optional metadata command cleanup was unverified")
                lifecycle_uncertain = True
                break
            if not cleaned:
                warnings.append("Optional metadata scratch cleanup was incomplete")
                lifecycle_uncertain = True
                break

            if managed.outcome is ManagedHostCommandOutcome.SUCCESS:
                metadata_file = await self._save_managed_stdout(
                    dut_id,
                    collector_id,
                    managed.target_stdout,
                    file_name=file_name,
                    output_pattern=output_pattern,
                    filtered_kwargs=filtered_kwargs,
                    diagnostic=False,
                )
                if metadata_file:
                    files.append(metadata_file)
                else:
                    warnings.append(
                        "Optional metadata command produced no saved output"
                    )
            else:
                warnings.append(
                    "Optional metadata command did not complete successfully"
                )
            if managed.stdout_truncated or managed.stderr_truncated:
                warnings.append("Optional metadata command output was truncated")

        return _ManagedMetadataCollection(
            files=tuple(files),
            warnings=tuple(warnings),
            lifecycle_uncertain=lifecycle_uncertain,
        )

    async def _collect_managed_private_advanced_mode(
        self,
        dut_id: str,
        collector_id: str,
        mode_config: Mapping[str, Any],
        *,
        resolved_timeout_seconds: float,
        max_artifact_bytes: int,
        use_sudo: bool,
        containment: str = "cgroup_v2",
        output_pattern: Optional[str],
        filtered_kwargs: Dict[str, Any],
        remote_temp_root: object,
        primary_pre_execution_grace_seconds: Optional[float],
    ) -> _ManagedModeCollection:
        """
        Run one placeholder-bound advanced file producer as a managed mode.

        The managed wrapper makes its private artifact directory the payload's
        working directory. Advanced ``remote_stage_dir`` and
        ``remote_output_file`` placeholders are therefore projected to ``.``
        and one validated basename. A directly delivered managed receipt,
        verified owned-scope absence, one exact artifact transfer, scratch
        removal, validation, and persistence are all required before success.
        This adapter invokes exactly one managed mode and has no fallback or
        command replay path.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration,
                logs, and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            mode_config: Advanced mode configuration containing the two private
                staging placeholders.
            resolved_timeout_seconds: Target-owned payload deadline selected by
                the existing collector timeout resolver.
            max_artifact_bytes: Collector-specific maximum accepted artifact
                size.
            use_sudo: Whether privileged execution is required for the managed
                command and its cleanup boundary.
            containment: Governed kernel ownership primitive selected by the
                validated caller contract.
            output_pattern: Optional collector output naming pattern.
            filtered_kwargs: Mapping supplying bounded output substitutions.
            remote_temp_root: Validated remote parent for managed scratch.
            primary_pre_execution_grace_seconds: Configured local allowance for
                host-pool admission and connection proven to precede target
                execution. It does not extend target runtime.

        Returns:
            A ``_ManagedModeCollection`` containing bounded attempt evidence
            and an output path only after the complete managed lifecycle.

        Raises:
            ManagedHostCommandConfigurationError: If the advanced mode cannot
                be projected to one bounded, relative managed artifact.
        """

        mode_name = mode_config.get("mode")
        command = mode_config.get("command")
        file_name = mode_config.get("file_name")
        remote_file_value = mode_config.get("remote_file")
        if (
            not isinstance(mode_name, str)
            or _MANAGED_MODE_NAME_RE.fullmatch(mode_name) is None
            or not isinstance(command, str)
            or command.count("{remote_stage_dir}") != 1
            or command.count("{remote_output_file}") != 1
            or not isinstance(file_name, str)
            or _MANAGED_FILE_BASENAME_RE.fullmatch(file_name) is None
        ):
            raise ManagedHostCommandConfigurationError(
                "managed private advanced mode configuration is invalid"
            )
        if remote_file_value == "{remote_output_file}":
            remote_file = file_name
        elif (
            isinstance(remote_file_value, str)
            and _MANAGED_FILE_BASENAME_RE.fullmatch(remote_file_value) is not None
        ):
            remote_file = remote_file_value
        else:
            raise ManagedHostCommandConfigurationError(
                "managed private advanced remote_file must be one basename"
            )

        raw_extensions = mode_config.get("file_extensions", [""])
        if (
            not isinstance(raw_extensions, list)
            or not 1 <= len(raw_extensions) <= 8
            or any(
                not isinstance(extension, str)
                or _MANAGED_FILE_EXTENSION_RE.fullmatch(extension) is None
                for extension in raw_extensions
            )
            or len(set(raw_extensions)) != len(raw_extensions)
        ):
            raise ManagedHostCommandConfigurationError(
                "managed private advanced file_extensions are invalid"
            )
        if (
            isinstance(max_artifact_bytes, bool)
            or not isinstance(max_artifact_bytes, int)
            or max_artifact_bytes <= 0
        ):
            raise ManagedHostCommandConfigurationError(
                "managed private advanced artifact ceiling is invalid"
            )
        min_artifact_bytes = mode_config.get("min_artifact_bytes", 1)
        if (
            isinstance(min_artifact_bytes, bool)
            or not isinstance(min_artifact_bytes, int)
            or not 1 <= min_artifact_bytes <= max_artifact_bytes
        ):
            raise ManagedHostCommandConfigurationError(
                "managed private advanced minimum artifact size is invalid"
            )
        if containment not in {"process_group", "cgroup_v2"}:
            raise ManagedHostCommandConfigurationError(
                "managed private advanced containment is invalid"
            )

        maximum_post_timeout = self._runtime_boundary(
            dut_id, "managed_host_transfer_max_timeout_seconds"
        )

        def post_timeout(field_name: str, default: int) -> float:
            """
            Resolve one bounded post-command timeout from the mode.

            The collector may tighten each local follow-up stage independently,
            but no authored value may exceed the active platform's managed
            transfer ceiling.

            Args:
                field_name: Configuration field naming the post-command stage.
                default: Positive default used when the field is absent.

            Returns:
                The validated finite timeout in seconds.

            Raises:
                ManagedHostCommandConfigurationError: If the configured value
                    is nonnumeric, nonfinite, nonpositive, or above the runtime
                    transfer ceiling.
            """

            raw_value = mode_config.get(field_name, default)
            try:
                value = float(raw_value)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ManagedHostCommandConfigurationError(
                    f"managed private advanced {field_name} is invalid"
                ) from exc
            if not math.isfinite(value) or not 0 < value <= maximum_post_timeout:
                raise ManagedHostCommandConfigurationError(
                    f"managed private advanced {field_name} is invalid"
                )
            return value

        try:
            target_timeout = float(resolved_timeout_seconds)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ManagedHostCommandConfigurationError(
                "managed private advanced target timeout is invalid"
            ) from exc
        if (
            not math.isfinite(target_timeout)
            or not 0 < target_timeout <= maximum_post_timeout
        ):
            raise ManagedHostCommandConfigurationError(
                "managed private advanced target timeout is invalid"
            )

        managed_command = command.replace("{remote_stage_dir}", quote_arg("."))
        managed_command = managed_command.replace(
            "{remote_output_file}", quote_arg(remote_file)
        )
        if (
            "{remote_stage_dir}" in managed_command
            or "{remote_output_file}" in managed_command
        ):
            raise ManagedHostCommandConfigurationError(
                "managed private advanced placeholders were unresolved"
            )
        normalized_mode = {
            "mode": mode_name,
            "command": managed_command,
            "file_name": file_name,
            "remote_file": remote_file,
            "timeout": target_timeout,
            "min_artifact_bytes": min_artifact_bytes,
            "max_artifact_bytes": max_artifact_bytes,
            "cleanup_timeout": post_timeout(
                "cleanup_timeout",
                _REMOTE_SNAPSHOT_MANAGED_CLEANUP_TIMEOUT_SECONDS,
            ),
            "transfer_timeout": post_timeout(
                "transfer_timeout", _MANAGED_ARTIFACT_TRANSFER_TIMEOUT_SECONDS
            ),
            "validation_timeout": post_timeout(
                "validation_timeout", _MANAGED_ARTIFACT_TRANSFER_TIMEOUT_SECONDS
            ),
            "persistence_timeout": post_timeout(
                "persistence_timeout", _MANAGED_ARTIFACT_PERSIST_TIMEOUT_SECONDS
            ),
            "file_extensions": list(raw_extensions),
            "preserve_invalid_artifact": mode_config.get("preserve_invalid_artifact")
            is True,
            "preserve_nonzero_artifact": mode_config.get("preserve_nonzero_artifact")
            is True,
        }
        return await self._collect_managed_fallback_mode(
            dut_id,
            collector_id,
            normalized_mode,
            use_sudo=use_sudo,
            output_pattern=output_pattern,
            filtered_kwargs=filtered_kwargs,
            cleanup_timeout_seconds=normalized_mode["cleanup_timeout"],
            containment=containment,
            primary_pre_execution_grace_seconds=(primary_pre_execution_grace_seconds),
            remote_temp_root=remote_temp_root,
        )

    async def _collect_managed_fallback_mode(
        self,
        dut_id: str,
        collector_id: str,
        mode_config: Mapping[str, Any],
        *,
        use_sudo: bool,
        output_pattern: Optional[str],
        filtered_kwargs: Dict[str, Any],
        cleanup_timeout_seconds: float,
        containment: str = "process_group",
        primary_pre_execution_grace_seconds: Optional[float] = None,
        remote_temp_root: Optional[str] = None,
    ) -> _ManagedModeCollection:
        """
        Execute, acquire, and validate one catalog-bound managed mode.

        The implementation uses ``dut_id``, ``collector_id``, ``mode_config``,
        ``use_sudo``, and ``output_pattern`` to execute, acquire, and validate
        one catalog-bound managed mode. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            mode_config: Mode config governing execute, acquire, and validate
                one catalog-bound managed mode.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            filtered_kwargs: Mapping supplying fields for execute, acquire, and
                validate one catalog-bound managed mode.
            cleanup_timeout_seconds: Maximum duration in seconds allowed for
                cleanup timeout seconds.
            containment: Governed kernel ownership primitive for target-side
                lifecycle containment.
            primary_pre_execution_grace_seconds: Optional caller-side allowance
                for transport work proven to precede target execution.
            remote_temp_root: Optional explicit remote parent for the managed
                scratch directory. When omitted, ``TOOL_TEMP_DIR`` is used.

        Returns:
            A ``_ManagedModeCollection`` representing managed fallback mode.
        """

        mode_name = str(mode_config["mode"])
        remote_file = str(mode_config["remote_file"])
        file_name = str(mode_config["file_name"])
        file_extensions = tuple(str(item) for item in mode_config["file_extensions"])
        min_artifact_bytes = mode_config["min_artifact_bytes"]
        preserve_invalid_artifact = mode_config.get("preserve_invalid_artifact") is True
        nonzero_retention_enabled = (
            preserve_invalid_artifact
            and mode_config.get("preserve_nonzero_artifact") is True
        )
        candidate_paths: Tuple[str, ...] = ()
        managed: Optional[ManagedHostCommandResult] = None
        diagnostic_files: List[str] = []
        scratch_cleanup_complete = False
        scratch_cleanup_verified = False

        try:
            resolved_remote_temp_root = await self._resolve_remote_staging_root(
                dut_id,
                remote_temp_root,
            )
        except (TypeError, ValueError):
            return _ManagedModeCollection(
                attempt=attempt_record(
                    mode_name,
                    disposition="failed",
                    failure_category="transport_error",
                    command_status="transport_error",
                    exit_code=None,
                    artifact_status="not_checked",
                    cleanup_status="verified_absent",
                    cleanup_scope=containment,
                ),
                error_message=f"Mode {mode_name} temp configuration was invalid",
            )
        local_staging_parent = await self._resolve_local_staging_parent(dut_id)

        try:
            managed = await self._run_managed_host_payload(
                dut_id,
                collector_id,
                str(mode_config["command"]),
                operation_name=f"managed_mode_{mode_name}",
                target_timeout_seconds=mode_config["timeout"],
                cleanup_timeout_seconds=cleanup_timeout_seconds,
                use_sudo=use_sudo,
                containment=containment,
                primary_pre_execution_grace_seconds=(
                    primary_pre_execution_grace_seconds
                ),
                remote_temp_root=resolved_remote_temp_root,
                prepare_timeout_artifacts=preserve_invalid_artifact,
                prepare_nonzero_artifacts=nonzero_retention_enabled,
            )
        except ManagedHostCommandConfigurationError:
            return _ManagedModeCollection(
                attempt=attempt_record(
                    mode_name,
                    disposition="failed",
                    failure_category="transport_error",
                    command_status="transport_error",
                    exit_code=None,
                    artifact_status="not_checked",
                    cleanup_status="verified_absent",
                    cleanup_scope=containment,
                ),
                error_message=f"Mode {mode_name} could not be started safely",
            )

        candidate_paths = tuple(
            str(PurePosixPath(managed.artifact_dir) / f"{remote_file}{extension}")
            for extension in file_extensions
        )

        async def save_diagnostic_stdout() -> None:
            """
            Persist bounded stdout without changing the command decision.

            The implementation uses current instance state to persist bounded
            stdout without changing the command decision. Success is reported
            only after the owning output boundary has completed its required
            write or publication step. Owned asynchronous work is awaited before
            return, so completion does not leave an unobserved task behind.
            """

            try:
                stdout_file = await self._save_managed_stdout(
                    dut_id,
                    collector_id,
                    managed.target_stdout,
                    file_name=f"{file_name}_stdout.log",
                    output_pattern=output_pattern,
                    filtered_kwargs=filtered_kwargs,
                    diagnostic=True,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                return
            if stdout_file:
                diagnostic_files.append(stdout_file)

        async def cleanup_scratch() -> bool:
            """
            Attempt exact scratch cleanup once to completion.

            The implementation uses current instance state to attempt exact
            scratch cleanup once to completion. Owned asynchronous work is
            awaited before return, so completion does not leave an unobserved
            task behind.

            Returns:
                Whether the attempt exact scratch cleanup once to completion
                operation succeeds.
            """

            nonlocal scratch_cleanup_complete, scratch_cleanup_verified
            if scratch_cleanup_complete:
                return scratch_cleanup_verified
            if (
                managed is None
                or managed.cleanup.status
                is not ManagedHostCleanupStatus.VERIFIED_ABSENT
            ):
                return False
            try:
                cleaned = await self._cleanup_managed_artifact_directory(
                    dut_id,
                    collector_id,
                    managed.artifact_dir,
                    candidate_paths,
                    use_sudo=use_sudo,
                    timeout_seconds=cleanup_timeout_seconds,
                )
            except asyncio.CancelledError:
                # The cleanup helper defers cancellation until its one remote
                # owner is terminal. Mark this lifecycle attempt consumed
                # before propagating control flow so the outer ``finally``
                # cannot start a second cleanup command.
                scratch_cleanup_complete = True
                scratch_cleanup_verified = False
                raise
            except Exception:
                cleaned = False
            scratch_cleanup_complete = True
            scratch_cleanup_verified = cleaned
            if not cleaned:
                await self._log_runtime(
                    "WARNING",
                    "HostService",
                    "Managed Host scratch cleanup was incomplete",
                    dut_id,
                )
            return scratch_cleanup_verified

        async def retain_timed_out_artifact() -> Tuple[Optional[str], bool]:
            """
            Retain one exact post-termination artifact as diagnostic evidence.

            This path is available only after the managed-command receipt has
            proved the target cgroup absent. It selects one bounded regular
            artifact, transfers the exact observed byte count, and atomically
            publishes the bytes with an ``.invalid`` marker. The caller removes
            remote scratch only after this persistence attempt completes. The
            timeout remains the authoritative mode outcome, so retained bytes
            can never satisfy the primary artifact.

            Returns:
                A tuple containing the retained diagnostic path, when
                publication succeeds, and whether one exact remote candidate
                was selected for retention.

            Raises:
                asyncio.CancelledError: If the owning collection is cancelled
                    during inspection, transfer, cleanup, or persistence.

            Side Effects:
                May transfer one bounded remote file and atomically publish one
                diagnostic file. The caller owns subsequent scratch cleanup.
            """

            if (
                managed is None
                or managed.cleanup.status
                is not ManagedHostCleanupStatus.VERIFIED_ABSENT
            ):
                return None, False
            (
                artifact_status,
                remote_path,
                remote_size,
                extension,
            ) = await self._inspect_managed_artifact_candidates(
                dut_id,
                collector_id,
                managed.artifact_dir,
                remote_file,
                file_extensions,
                min_artifact_bytes=min_artifact_bytes,
                max_artifact_bytes=mode_config.get("max_artifact_bytes"),
                use_sudo=use_sudo,
            )
            if (
                artifact_status != "valid"
                or not remote_path
                or remote_size is None
                or extension is None
            ):
                return None, False

            with self._create_advanced_staging_context(
                dut_id,
                collector_id,
                mode_name,
                local_staging_parent,
            ) as staging_dir:
                staged_path = Path(staging_dir) / PurePosixPath(remote_path).name
                runtime_max_artifact_bytes = self._runtime_boundary(
                    dut_id, "managed_artifact_max_file_bytes"
                )
                max_artifact_bytes = mode_config.get(
                    "max_artifact_bytes", runtime_max_artifact_bytes
                )
                transfer_timeout = max(
                    1,
                    math.ceil(
                        float(
                            mode_config.get(
                                "transfer_timeout",
                                _MANAGED_ARTIFACT_TRANSFER_TIMEOUT_SECONDS,
                            )
                        )
                    ),
                )
                transfer_success = await self._transfer_managed_artifact_to_stage(
                    dut_id,
                    remote_path,
                    staged_path,
                    expected_size=remote_size,
                    max_bytes=max_artifact_bytes,
                    timeout_seconds=transfer_timeout,
                )
                if not transfer_success:
                    return None, True
                retained_path = await self._persist_invalid_managed_artifact(
                    dut_id,
                    collector_id,
                    staged_path,
                    file_name=file_name,
                    extension=extension,
                    output_pattern=output_pattern,
                    timeout_seconds=float(mode_config["persistence_timeout"]),
                )
                return retained_path, True

        def scratch_cleanup_failure(
            *,
            command_status: str,
            exit_code: Optional[int],
            diagnostic_files: Tuple[str, ...],
            error_files: Tuple[str, ...] = (),
        ) -> _ManagedModeCollection:
            """
            Replace an outcome when owned scratch removal is unverified.

            After applying local validation, the function forwards
            ``command_status``, ``exit_code``, ``diagnostic_files``, and
            ``error_files`` to ``_ManagedModeCollection`` and preserves its
            return and exception contract.

            Args:
                command_status: Text supplied as command status in the format
                    accepted by this function.
                exit_code: Numeric exit code used while the operation performs
                    bounded accounting.
                diagnostic_files: Entries supplied as ``diagnostic_files``
                    without transferring container ownership.
                error_files: Entries supplied as ``error_files`` without
                    transferring container ownership.

            Returns:
                A ``_ManagedModeCollection`` representing scratch cleanup
                failure.
            """

            return _ManagedModeCollection(
                attempt=attempt_record(
                    mode_name,
                    disposition="failed",
                    failure_category="artifact_cleanup_unverified",
                    command_status=command_status,
                    exit_code=exit_code,
                    artifact_status="not_checked",
                    cleanup_status="verified_absent",
                    cleanup_scope=containment,
                ),
                diagnostic_files=diagnostic_files,
                error_files=error_files,
                error_message=f"Mode {mode_name} scratch cleanup could not be verified",
            )

        async def finalize_collection(
            collection: _ManagedModeCollection,
        ) -> _ManagedModeCollection:
            """
            Require exact scratch cleanup before exposing a mode outcome.

            The implementation uses ``collection`` to require exact scratch
            cleanup before exposing a mode outcome. Every required invariant is
            checked before a successful value is returned; invalid input follows
            the function's explicit exception path. Owned asynchronous work is
            awaited before return, so completion does not leave an unobserved
            task behind.

            Args:
                collection: Collection object whose ``attempt``,
                    ``diagnostic_files``, and ``error_files`` state is read
                    while performing exact scratch cleanup before exposing a
                    mode outcome.

            Returns:
                A ``_ManagedModeCollection`` representing finalize collection.
            """

            if (
                managed is None
                or managed.cleanup.status
                is not ManagedHostCleanupStatus.VERIFIED_ABSENT
            ):
                return collection
            if await cleanup_scratch():
                return collection
            command = collection.attempt["command"]
            return scratch_cleanup_failure(
                command_status=command["status"],
                exit_code=command["exit_code"],
                diagnostic_files=collection.diagnostic_files,
                error_files=collection.error_files,
            )

        try:
            cleanup_status = managed.cleanup.status.value
            transcript = await self._record_managed_command_diagnostic(
                dut_id,
                collector_id,
                managed,
                command=str(mode_config["command"]),
                operation=f"managed_mode_{mode_name}",
                timeout=mode_config["timeout"],
            )
            if transcript is not None:
                diagnostic_files.append(transcript)
            early_failure: Optional[Tuple[Mapping[str, Any], str]] = None
            if managed.cleanup.status is not ManagedHostCleanupStatus.VERIFIED_ABSENT:
                early_failure = (
                    attempt_record(
                        mode_name,
                        disposition="failed",
                        failure_category="cleanup_unverified",
                        command_status="cleanup_unverified",
                        exit_code=None,
                        artifact_status="not_checked",
                        cleanup_status=cleanup_status,
                        cleanup_scope=containment,
                    ),
                    (
                        f"Mode {mode_name} managed command deadline exceeded "
                        "before a terminal receipt; target cleanup could not be "
                        "verified"
                        if managed.primary_deadline_exceeded
                        else f"Mode {mode_name} cleanup could not be verified"
                    ),
                )
            elif managed.outcome is ManagedHostCommandOutcome.TARGET_TIMEOUT:
                early_failure = (
                    attempt_record(
                        mode_name,
                        disposition="failed",
                        failure_category="timeout",
                        command_status="timeout",
                        exit_code=None,
                        artifact_status="not_checked",
                        cleanup_status="verified_absent",
                        cleanup_scope=containment,
                    ),
                    f"Mode {mode_name} target deadline exceeded",
                )
            elif managed.outcome is ManagedHostCommandOutcome.NONZERO_EXIT:
                failure_reason = f"Mode {mode_name} returned a nonzero exit ({managed.target_exit_code})"
                if managed.target_stderr and managed.target_stderr.strip():
                    failure_reason += ": " + self._bounded_operator_reason(
                        "error", managed.target_stderr
                    )
                early_failure = (
                    attempt_record(
                        mode_name,
                        disposition="failed",
                        failure_category="nonzero_exit",
                        command_status="nonzero_exit",
                        exit_code=managed.target_exit_code,
                        artifact_status="not_checked",
                        cleanup_status="verified_absent",
                        cleanup_scope=containment,
                    ),
                    failure_reason,
                )
            elif managed.outcome is not ManagedHostCommandOutcome.SUCCESS:
                early_failure = (
                    attempt_record(
                        mode_name,
                        disposition="failed",
                        failure_category="transport_error",
                        command_status="transport_error",
                        exit_code=None,
                        artifact_status="not_checked",
                        cleanup_status="verified_absent",
                        cleanup_scope=containment,
                    ),
                    f"Mode {mode_name} transport was indeterminate",
                )

            if early_failure is not None:
                await save_diagnostic_stdout()
                retained_timeout_path = None
                timeout_candidate_selected = False
                if (
                    managed.cleanup.status is ManagedHostCleanupStatus.VERIFIED_ABSENT
                    and (
                        (
                            managed.outcome is ManagedHostCommandOutcome.TARGET_TIMEOUT
                            and preserve_invalid_artifact
                        )
                        or (
                            managed.outcome is ManagedHostCommandOutcome.NONZERO_EXIT
                            and nonzero_retention_enabled
                        )
                    )
                ):
                    try:
                        (
                            retained_timeout_path,
                            timeout_candidate_selected,
                        ) = await retain_timed_out_artifact()
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        timeout_candidate_selected = True
                        await self._log_runtime(
                            "WARNING",
                            "HostService",
                            "Timed-out Host artifact could not be retained",
                            dut_id,
                        )
                    if retained_timeout_path:
                        diagnostic_files.append(retained_timeout_path)
                return await finalize_collection(
                    _ManagedModeCollection(
                        attempt=early_failure[0],
                        diagnostic_files=tuple(diagnostic_files),
                        error_message=(
                            f"{early_failure[1]} and partial artifact could not "
                            "be retained"
                            if timeout_candidate_selected and not retained_timeout_path
                            else early_failure[1]
                        ),
                    )
                )

            await save_diagnostic_stdout()
            (
                artifact_status,
                remote_path,
                remote_size,
                extension,
            ) = await self._inspect_managed_artifact_candidates(
                dut_id,
                collector_id,
                managed.artifact_dir,
                remote_file,
                file_extensions,
                min_artifact_bytes=min_artifact_bytes,
                max_artifact_bytes=mode_config.get("max_artifact_bytes"),
                use_sudo=use_sudo,
            )
            if (
                artifact_status != "valid"
                or not remote_path
                or remote_size is None
                or extension is None
            ):
                if artifact_status == "transport_error":
                    failure_category = "transport_error"
                    command_status = "transport_error"
                    exit_code = None
                    projected_artifact_status = "not_checked"
                else:
                    failure_category = (
                        "missing_artifact"
                        if artifact_status == "missing"
                        else "invalid_artifact"
                    )
                    command_status = "success"
                    exit_code = 0
                    projected_artifact_status = (
                        "missing"
                        if failure_category == "missing_artifact"
                        else "invalid"
                    )
                return await finalize_collection(
                    _ManagedModeCollection(
                        attempt=attempt_record(
                            mode_name,
                            disposition="failed",
                            failure_category=failure_category,
                            command_status=command_status,
                            exit_code=exit_code,
                            artifact_status=projected_artifact_status,
                            cleanup_status="verified_absent",
                            cleanup_scope=containment,
                        ),
                        diagnostic_files=tuple(diagnostic_files),
                        error_message=(
                            f"Mode {mode_name} artifact inspection was indeterminate"
                            if failure_category == "transport_error"
                            else f"Mode {mode_name} did not produce one valid artifact"
                        ),
                    )
                )

            with self._create_advanced_staging_context(
                dut_id,
                collector_id,
                mode_name,
                local_staging_parent,
            ) as staging_dir:
                staged_path = Path(staging_dir) / PurePosixPath(remote_path).name
                runtime_max_artifact_bytes = self._runtime_boundary(
                    dut_id, "managed_artifact_max_file_bytes"
                )
                max_artifact_bytes = mode_config.get(
                    "max_artifact_bytes", runtime_max_artifact_bytes
                )
                max_decompressed_bytes = self._runtime_boundary(
                    dut_id, "managed_artifact_max_decompressed_bytes"
                )
                transfer_timeout = max(
                    1,
                    math.ceil(
                        float(
                            mode_config.get(
                                "transfer_timeout",
                                _MANAGED_ARTIFACT_TRANSFER_TIMEOUT_SECONDS,
                            )
                        )
                    ),
                )
                transfer_success = await self._transfer_managed_artifact_to_stage(
                    dut_id,
                    remote_path,
                    staged_path,
                    expected_size=remote_size,
                    max_bytes=max_artifact_bytes,
                    timeout_seconds=transfer_timeout,
                )
                if not transfer_success:
                    return await finalize_collection(
                        _ManagedModeCollection(
                            attempt=attempt_record(
                                mode_name,
                                disposition="failed",
                                failure_category="transport_error",
                                command_status="transport_error",
                                exit_code=None,
                                artifact_status="not_checked",
                                cleanup_status="verified_absent",
                                cleanup_scope=containment,
                            ),
                            diagnostic_files=tuple(diagnostic_files),
                            error_message=f"Mode {mode_name} artifact transfer failed",
                        )
                    )
                local_path = staged_path
                local_stat = local_path.lstat()
                local_artifact_integral = not (
                    local_path.is_symlink()
                    or not local_path.is_file()
                    or remote_size is None
                    or local_stat.st_nlink != 1
                    or local_stat.st_size != remote_size
                    or not min_artifact_bytes
                    <= local_stat.st_size
                    <= max_artifact_bytes
                )
                if not local_artifact_integral:
                    archive_valid = False
                else:
                    validation_cancellation = threading.Event()
                    validation_timeout = float(mode_config["validation_timeout"])
                    validation_deadline = time.monotonic() + validation_timeout
                    archive_valid, _ = await asyncio.wait_for(
                        _run_managed_filesystem_operation(
                            self._validate_managed_archive,
                            str(local_path),
                            PurePosixPath(remote_path).name,
                            validation_cancellation,
                            validation_deadline,
                            max_decompressed_bytes,
                            max_artifact_bytes,
                            cancellation_event=validation_cancellation,
                        ),
                        timeout=validation_timeout,
                    )
                if not archive_valid:
                    invalid_artifact_path = None
                    if (
                        local_artifact_integral
                        and mode_config.get("preserve_invalid_artifact") is True
                    ):
                        try:
                            invalid_artifact_path = (
                                await self._persist_invalid_managed_artifact(
                                    dut_id,
                                    collector_id,
                                    local_path,
                                    file_name=file_name,
                                    extension=extension,
                                    output_pattern=output_pattern,
                                    timeout_seconds=float(
                                        mode_config["persistence_timeout"]
                                    ),
                                )
                            )
                        except asyncio.CancelledError:
                            raise
                        except Exception:
                            await self._log_runtime(
                                "WARNING",
                                "HostService",
                                "Rejected Host artifact could not be retained",
                                dut_id,
                            )
                        if invalid_artifact_path:
                            diagnostic_files.append(invalid_artifact_path)
                    return await finalize_collection(
                        _ManagedModeCollection(
                            attempt=attempt_record(
                                mode_name,
                                disposition="failed",
                                failure_category="invalid_artifact",
                                command_status="success",
                                exit_code=0,
                                artifact_status="invalid",
                                cleanup_status="verified_absent",
                                cleanup_scope=containment,
                            ),
                            diagnostic_files=tuple(diagnostic_files),
                            error_message=(
                                f"Mode {mode_name} artifact failed integrity "
                                "validation"
                                if (
                                    mode_config.get("preserve_invalid_artifact")
                                    is not True
                                    or invalid_artifact_path
                                )
                                else (
                                    f"Mode {mode_name} artifact failed integrity "
                                    "validation and could not be retained"
                                )
                            ),
                        )
                    )
                final_path = await self._persist_managed_artifact(
                    dut_id,
                    collector_id,
                    local_path,
                    file_name=file_name,
                    extension=extension,
                    output_pattern=output_pattern,
                    timeout_seconds=float(mode_config["persistence_timeout"]),
                )
                if final_path is None:
                    return await finalize_collection(
                        _ManagedModeCollection(
                            attempt=attempt_record(
                                mode_name,
                                disposition="failed",
                                failure_category="transport_error",
                                command_status="transport_error",
                                exit_code=None,
                                artifact_status="not_checked",
                                cleanup_status="verified_absent",
                                cleanup_scope=containment,
                            ),
                            diagnostic_files=tuple(diagnostic_files),
                            error_message=f"Mode {mode_name} artifact could not be persisted",
                        )
                    )
                return await finalize_collection(
                    _ManagedModeCollection(
                        attempt=attempt_record(
                            mode_name,
                            disposition="success",
                            failure_category=None,
                            command_status="success",
                            exit_code=0,
                            artifact_status="valid",
                            cleanup_status="verified_absent",
                            cleanup_scope=containment,
                        ),
                        output_file=final_path,
                        diagnostic_files=tuple(diagnostic_files),
                    )
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            cleanup_status = managed.cleanup.status.value
            cleanup_verified = (
                managed.cleanup.status is ManagedHostCleanupStatus.VERIFIED_ABSENT
            )
            return await finalize_collection(
                _ManagedModeCollection(
                    attempt=attempt_record(
                        mode_name,
                        disposition="failed",
                        failure_category=(
                            "transport_error"
                            if cleanup_verified
                            else "cleanup_unverified"
                        ),
                        command_status=(
                            "transport_error"
                            if cleanup_verified
                            else "cleanup_unverified"
                        ),
                        exit_code=None,
                        artifact_status="not_checked",
                        cleanup_status=(
                            "verified_absent" if cleanup_verified else cleanup_status
                        ),
                        cleanup_scope=containment,
                    ),
                    diagnostic_files=tuple(diagnostic_files),
                    error_message=f"Mode {mode_name} artifact processing failed",
                )
            )
        finally:
            if not scratch_cleanup_complete:
                await cleanup_scratch()

    async def _handle_host_managed_fallback_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Run a catalog-bound first-success Host collection safely.

        The implementation uses ``dut_id``, ``function_tag``, and ``kwargs`` to
        run a catalog-bound first-success Host collection safely. Terminal
        status is emitted only after catalog-bound first-success Host collection
        safely and its owned cleanup have completed. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. If the function cannot run a catalog-bound first-success Host
        collection safely, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing handle host managed fallback collection.

        Raises:
            CollectorAttemptPolicyError: If managed_fallback lacks an enforced
                runtime fallback policy.
            RuntimeError: If managed publication transaction is sealed.
        """

        await self._log_collection_start(dut_id, "Managed Host Fallback Collection")
        collector_id = str(
            kwargs.get("collector_id") or self._get_current_collector_id() or ""
        )
        command_modes = kwargs.get("command_modes")
        runtime_budget = self._current_runtime_budget(collector_id)
        configured_pre_execution_allowance_seconds = (
            self._host_pool_pre_execution_grace_seconds()
        )
        managed_wait_context = {
            "configured_managed_pre_execution_allowance_seconds": (
                configured_pre_execution_allowance_seconds
            ),
            "managed_pre_execution_allowance_scope": (
                "local_host_pool_admission_and_connect"
            ),
            "managed_pre_execution_extends_target_runtime": False,
            "managed_pre_execution_ultimate_bound": "collector_wall_timeout",
        }
        policy_definition: Optional[EnforcedCollectorAttemptPolicy] = None
        try:
            policy_definition = resolve_enforced_attempt_policy_definition(
                runtime_budget
            )
            if policy_definition is None:
                raise CollectorAttemptPolicyError(
                    "managed_fallback requires an enforced runtime fallback policy"
                )
            policy = resolve_enforced_attempt_policy(
                runtime_budget, command_modes, kwargs.get("initial_commands")
            )
            if policy is None:
                raise CollectorAttemptPolicyError(
                    "managed_fallback requires an enforced runtime fallback policy"
                )
            if policy.containment == "cgroup_v2" and kwargs.get("use_sudo") is not True:
                raise CollectorAttemptPolicyError(
                    "cgroup_v2 managed fallback requires use_sudo: true"
                )
        except CollectorAttemptPolicyError as error:
            await self._log_collection_failure(
                dut_id,
                "managed_fallback_configuration",
                function_tag,
                str(error),
                collector_id=collector_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=["Managed fallback configuration is invalid"],
                operation_name="managed_host_fallback_collection",
                additional_context={
                    "failure_reason": "invalid_managed_fallback_configuration",
                    **(
                        {
                            "attempt_policy": build_attempt_policy_receipt(
                                policy_definition,
                                [
                                    not_attempted_record(
                                        mode,
                                        cleanup_scope=policy_definition.containment,
                                    )
                                    for mode in policy_definition.ordered_modes
                                ],
                                selected_mode=None,
                                fallback_used=False,
                                terminal_reason="internal_error",
                            )
                        }
                        if policy_definition is not None
                        else {}
                    ),
                    "metadata_files": [],
                    "diagnostic_files": [],
                    "error_files": [],
                    "additive_attempts": [
                        {"mode": mode, "disposition": "skipped_policy"}
                        for mode in (
                            policy_definition.additive_modes
                            if policy_definition is not None
                            else ()
                        )
                    ],
                    **managed_wait_context,
                },
                dut_id=dut_id,
                collector_id=collector_id,
            )

        modes_by_name = {
            str(mode["mode"]): mode
            for mode in command_modes
            if isinstance(mode, Mapping)
        }
        output_pattern, _, filtered_kwargs = self._extract_output_pattern_params(kwargs)
        additive_attempts: List[Dict[str, Any]] = []
        enabled_additive_modes: List[str] = []

        def ordered_additive_attempts() -> List[Dict[str, Any]]:
            """
            Return the ordered additive attempts.

            The implementation uses current instance state to produce the
            ordered additive attempts.

            Returns:
                The ordered additive attempts returned in operation-defined
                order.
            """
            by_mode = {str(item.get("mode")): item for item in additive_attempts}
            return [by_mode[mode] for mode in policy.additive_modes if mode in by_mode]

        if policy.additive_modes:
            for mode_name in policy.additive_modes:
                if policy.additive_enabled.get(mode_name) is not True:
                    additive_attempts.append(
                        {"mode": mode_name, "disposition": "skipped_config"}
                    )
                    continue
                enabled_additive_modes.append(mode_name)

        publication_owner = _MANAGED_PUBLICATION_OWNER.get()
        owns_publication_owner = publication_owner is None
        publication_token = None
        if publication_owner is None:
            publication_owner = _ManagedPublicationOwner(publications=[])
            publication_token = _MANAGED_PUBLICATION_OWNER.set(publication_owner)
        elif publication_owner.sealed:
            raise RuntimeError("managed publication transaction is sealed")
        try:
            metadata = await self._collect_managed_fallback_metadata(
                dut_id,
                collector_id,
                kwargs.get("initial_commands", []),
                use_sudo=bool(kwargs.get("use_sudo", False)),
                output_pattern=output_pattern,
                filtered_kwargs=filtered_kwargs,
                cleanup_timeout_seconds=policy.cleanup_timeout_seconds,
                containment=policy.containment,
                primary_pre_execution_grace_seconds=(
                    configured_pre_execution_allowance_seconds
                ),
            )
            metadata_files = list(metadata.files)
            metadata_warnings = list(metadata.warnings)
            if metadata.lifecycle_uncertain:
                additive_attempts.extend(
                    {"mode": mode, "disposition": "skipped_policy"}
                    for mode in enabled_additive_modes
                )
                receipt = build_attempt_policy_receipt(
                    policy,
                    [
                        not_attempted_record(
                            mode,
                            cleanup_scope=policy.containment,
                        )
                        for mode in policy.ordered_modes
                    ],
                    selected_mode=None,
                    fallback_used=False,
                    terminal_reason="internal_error",
                )
                await self._log_collection_failure(
                    dut_id,
                    "managed_fallback_metadata_cleanup",
                    function_tag,
                    "Optional metadata command cleanup could not be verified",
                    collector_id=collector_id,
                )
                result = await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[
                        "Managed metadata command cleanup could not be verified"
                    ],
                    operation_name="managed_host_fallback_collection",
                    additional_context={
                        "attempt_policy": receipt,
                        "selected_mode": None,
                        "fallback_used": False,
                        "metadata_files": metadata_files,
                        "metadata_warnings": metadata_warnings,
                        "diagnostic_files": [],
                        "error_files": [],
                        "additive_attempts": ordered_additive_attempts(),
                        **managed_wait_context,
                    },
                    dut_id=dut_id,
                    collector_id=collector_id,
                )
                if owns_publication_owner:
                    publication_owner.adopted = True
                return result

            collected_modes: Dict[str, _ManagedModeCollection] = {}

            async def execute_attempt(mode_name: str) -> Mapping[str, Any]:
                """
                Execute attempt.

                The implementation uses ``mode_name`` to execute attempt.
                Terminal status is emitted only after attempt and its owned
                cleanup have completed. Owned asynchronous work is awaited
                before return, so completion does not leave an unobserved task
                behind.

                Args:
                    mode_name: Stable mode name used for lookup and
                        operator-facing diagnostics.

                Returns:
                    A mapping containing execute attempt.
                """
                collected = await self._collect_managed_fallback_mode(
                    dut_id,
                    collector_id,
                    modes_by_name[mode_name],
                    use_sudo=bool(kwargs.get("use_sudo", False)),
                    output_pattern=output_pattern,
                    filtered_kwargs=filtered_kwargs,
                    cleanup_timeout_seconds=policy.cleanup_timeout_seconds,
                    containment=policy.containment,
                    primary_pre_execution_grace_seconds=(
                        configured_pre_execution_allowance_seconds
                    ),
                    remote_temp_root=kwargs.get("remote_staging_root"),
                )
                collected_modes[mode_name] = collected
                return collected.attempt

            policy_run = await run_first_success_attempt_policy(policy, execute_attempt)
            output_files: List[str] = []
            diagnostic_files: List[str] = []
            error_files: List[str] = []
            error_messages: List[str] = []
            lifecycle_uncertain = False

            for mode_name in policy_run.executed_modes:
                collected = collected_modes[mode_name]
                if collected.output_file:
                    output_files.append(collected.output_file)
                diagnostic_files.extend(collected.diagnostic_files)
                error_files.extend(collected.error_files)
                if collected.error_message:
                    error_messages.append(collected.error_message)
                if collected.attempt["cleanup"]["status"] in {
                    "failed",
                    "unverified",
                } or collected.attempt.get("failure_category") == (
                    "artifact_cleanup_unverified"
                ):
                    lifecycle_uncertain = True

            primary_attempts = len(policy_run.executed_modes)
            if policy_run.selected_mode is None:
                successful_operations = 0
                total_operations = max(primary_attempts, 1)
            else:
                successful_operations = 1
                total_operations = max(primary_attempts, 1)

            if policy_run.selected_mode == policy.preferred_mode:
                for mode_name in enabled_additive_modes:
                    collected = await self._collect_managed_fallback_mode(
                        dut_id,
                        collector_id,
                        modes_by_name[mode_name],
                        use_sudo=bool(kwargs.get("use_sudo", False)),
                        output_pattern=output_pattern,
                        filtered_kwargs=filtered_kwargs,
                        cleanup_timeout_seconds=policy.cleanup_timeout_seconds,
                        containment=policy.containment,
                        primary_pre_execution_grace_seconds=(
                            configured_pre_execution_allowance_seconds
                        ),
                        remote_temp_root=kwargs.get("remote_staging_root"),
                    )
                    total_operations += 1
                    additive_attempts.append(dict(collected.attempt))
                    if collected.output_file:
                        output_files.append(collected.output_file)
                    diagnostic_files.extend(collected.diagnostic_files)
                    error_files.extend(collected.error_files)
                    if collected.attempt["disposition"] == "success":
                        successful_operations += 1
                    elif collected.error_message:
                        error_messages.append(collected.error_message)
                    if collected.attempt["cleanup"]["status"] in {
                        "failed",
                        "unverified",
                    } or collected.attempt.get("failure_category") == (
                        "artifact_cleanup_unverified"
                    ):
                        lifecycle_uncertain = True
            else:
                for mode_name in enabled_additive_modes:
                    additive_attempts.append(
                        {"mode": mode_name, "disposition": "skipped_policy"}
                    )

            additional_context = {
                "attempt_policy": dict(policy_run.receipt),
                "selected_mode": policy_run.selected_mode,
                "fallback_used": bool(policy_run.receipt["fallback_used"]),
                "metadata_files": metadata_files,
                "metadata_warnings": metadata_warnings,
                "diagnostic_files": diagnostic_files,
                "error_files": error_files,
                "additive_attempts": ordered_additive_attempts(),
                **managed_wait_context,
            }
            result = await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="managed_host_fallback_collection",
                additional_context=additional_context,
                dut_id=dut_id,
                collector_id=collector_id,
            )
            if lifecycle_uncertain:
                uncertain_attempts = []
                for attempt in (
                    list(policy_run.receipt.get("attempts", ())) + additive_attempts
                ):
                    if not isinstance(attempt, Mapping):
                        continue
                    cleanup = attempt.get("cleanup", {})
                    cleanup_status = (
                        cleanup.get("status", "unknown")
                        if isinstance(cleanup, Mapping)
                        else "unknown"
                    )
                    failure_category = attempt.get("failure_category")
                    if cleanup_status not in {"failed", "unverified"} and (
                        failure_category != "artifact_cleanup_unverified"
                    ):
                        continue
                    artifact = attempt.get("artifact", {})
                    artifact_status = (
                        artifact.get("status", "unknown")
                        if isinstance(artifact, Mapping)
                        else "unknown"
                    )
                    uncertain_attempts.append(
                        "mode={mode}, failure={failure}, artifact={artifact}, "
                        "cleanup={cleanup}".format(
                            mode=attempt.get("mode", "unknown"),
                            failure=failure_category or "cleanup_unverified",
                            artifact=artifact_status,
                            cleanup=cleanup_status,
                        )
                    )
                diagnostic = "; ".join(uncertain_attempts) or (
                    "mode=unknown, failure=cleanup_unverified, "
                    "artifact=unknown, cleanup=unknown"
                )
                result["success"] = False
                result["status"] = "error"
                result["reason"] = (
                    "Managed command or artifact cleanup could not be verified: "
                    f"{diagnostic}"
                )
                result["context"]["status"] = "error"
                result["context"]["reason"] = result["reason"]

            await self._log_collection_summary(
                dut_id=dut_id,
                collection_name="Managed Host Fallback Collection",
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=total_operations - successful_operations,
                output_files_count=len(output_files),
                additional_details={
                    "Selected mode": policy_run.selected_mode,
                    "Fallback used": bool(policy_run.receipt["fallback_used"]),
                    "Metadata warnings": len(metadata_warnings),
                },
            )
            if owns_publication_owner:
                publication_owner.adopted = True
            return result
        finally:
            if owns_publication_owner:
                _rollback_managed_publications(publication_owner)
                assert publication_token is not None
                _MANAGED_PUBLICATION_OWNER.reset(publication_token)

    async def _handle_host_advanced_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle advanced host collection with file generation and retrieval.

        Track where sudo prompts were observed to report in context.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing handle host advanced collection.

        Raises:
            ValueError: If unresolved private remote staging placeholder.
        """
        await self._log_collection_start(dut_id, "Advanced Host Collection")

        output_files = []
        diagnostic_files: List[str] = []
        status_list = []
        error_messages = []
        successful_operations = 0
        total_operations = 0
        # Track where sudo prompts were observed to report in context
        sudo_prompt_locations: List[str] = []
        metadata_files: List[str] = []
        managed_attempts: List[Mapping[str, Any]] = []
        configured_pre_execution_allowance_seconds = (
            self._host_pool_pre_execution_grace_seconds()
        )

        def advanced_managed_context() -> Dict[str, Any]:
            """
            Return bounded advanced lifecycle and local-wait context.

            The configured allowance covers host-pool admission and connection
            only. It is surfaced separately from target execution, cleanup, and
            collector wall budgets so consumers cannot misread it as elapsed
            time or an authored runtime extension.

            Returns:
                Context fields including a strict receipt only when exactly one
                managed advanced attempt reached a terminal record.
            """

            context: Dict[str, Any] = {
                "configured_managed_pre_execution_allowance_seconds": (
                    configured_pre_execution_allowance_seconds
                ),
                "managed_pre_execution_allowance_scope": (
                    "local_host_pool_admission_and_connect"
                ),
                "managed_pre_execution_extends_target_runtime": False,
            }
            if len(managed_attempts) == 1:
                context["advanced_managed_receipt"] = (
                    self._build_advanced_managed_receipt(managed_attempts[0])
                )
            return context

        # Extract parameters from kwargs
        initial_commands = kwargs.get("initial_commands", [])
        command_modes = kwargs.get("command_modes", [])
        use_sudo = kwargs.get("use_sudo", False)
        owned_stages: List[_RemoteStagingDirectory] = kwargs.get(
            "_remote_staging_owner", []
        )

        # Extract output pattern parameters using common function
        output_pattern, substitutions, filtered_kwargs = (
            self._extract_output_pattern_params(kwargs)
        )

        # Run initial commands (typically help commands that don't generate files)
        if isinstance(initial_commands, list):
            for cmd_config in initial_commands:
                total_operations += 1
                command = cmd_config["command"]
                file_name = cmd_config["file_name"]
                expect_file = cmd_config.get("expect_file", False)

                # Execute command with detailed logging
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Executing initial command with use_sudo={use_sudo}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Initial command: {command}",
                    dut_id,
                )

                timeout = await self._resolve_collector_timeout(
                    dut_id,
                    kwargs,
                    default_timeout=300,
                    explicit_timeout_sources=[cmd_config, kwargs],
                )
                await self._log_runtime(
                    "INFO",
                    "HostService",
                    (
                        f"Executing initial host command for '{file_name}' "
                        f"with effective timeout {timeout}s"
                    ),
                    dut_id,
                )

                (
                    exit_code,
                    stdout,
                    stderr,
                ) = await self._execute_host_command_with_capture(
                    dut_id,
                    command,
                    operation_name=f"initial_command_{file_name}",
                    timeout=timeout,
                    use_sudo=use_sudo,
                    collector_id=kwargs.get("collector_id"),
                    output_file=file_name,
                )

                # Log detailed execution results
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Initial command completed - exit_code={exit_code}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"stdout length={len(stdout)}, stderr length={len(stderr)}",
                    dut_id,
                )
                if stdout:
                    await self._log_runtime(
                        "DEBUG",
                        "HostService",
                        f"stdout preview: {stdout[:200]}...",
                        dut_id,
                    )
                prompt_detected = False
                if stderr:
                    await self._log_runtime(
                        "DEBUG", "HostService", f"stderr: {stderr}", dut_id
                    )

                    # Check for sudo password prompt issues in initial commands
                    if "[sudo] password for" in stderr:
                        prompt_detected = True
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "WARN",
                            "HostService",
                            "Initial command detected sudo password prompt in stderr - this may indicate authentication issues",
                        )
                        # Treat as warning only; do not mark as error to avoid partial status
                        sudo_prompt_locations.append("initial")

                success = exit_code == 0

                if success:
                    await self._log_collection_success(
                        dut_id, "command", f"Initial: {command}"
                    )

                    # Initial help/version output is metadata, not a primary
                    # bug-report artifact.
                    if stdout:
                        file_path = await self._save_data_with_common_pattern(
                            dut_id,
                            stdout,
                            file_name,
                            output_pattern=output_pattern,
                            substitutions={"file_name": file_name},
                            **filtered_kwargs,
                        )
                        if file_path:
                            metadata_files.append(file_path)
                    successful_operations += 1
                else:
                    # Log both stdout and stderr for failed commands
                    error_details = f"exit_code: {exit_code}"
                    if stdout:
                        error_details += f", stdout: {stdout}"
                    if stderr:
                        error_details += f", stderr: {stderr}"
                    await self._log_collection_failure(
                        dut_id,
                        "command",
                        f"Initial: {command}",
                        error_details,
                        collector_id=kwargs.get("collector_id"),
                    )
                    error_messages.append(
                        f"Initial command failed: {command} - {error_details}"
                    )
                    # If sudo prompt was detected alongside failure, record it explicitly as an error context
                    if prompt_detected:
                        error_messages.append(
                            "Initial command encountered sudo password prompt"
                        )

                status_list.append(success)

        # Run command modes (typically generate files that need to be retrieved)
        if isinstance(command_modes, list):
            await self._log_runtime(
                "INFO",
                "HostService",
                f"Starting execution of {len(command_modes)} command modes",
                dut_id,
            )

            for i, mode_config in enumerate(command_modes, 1):
                total_operations += 1
                mode_name = mode_config.get("mode", f"mode_{i}")
                command = mode_config["command"]
                file_name = mode_config["file_name"]
                timeout = await self._resolve_collector_timeout(
                    dut_id,
                    kwargs,
                    default_timeout=1800,
                    explicit_timeout_sources=[mode_config, kwargs],
                )
                mode_max_artifact_bytes = _resolve_host_artifact_max_bytes(
                    mode_config,
                    kwargs,
                )
                expect_file = mode_config.get("expect_file", True)
                config_key = mode_config.get("config_key")
                decompress = mode_config.get(
                    "decompress", False
                )  # Default to preserving compression

                await self._log_runtime(
                    "INFO",
                    "HostService",
                    (
                        f"Starting host command mode {i}/{len(command_modes)}: "
                        f"{mode_name} (effective_timeout={timeout}s, "
                        f"expects_artifact={expect_file})"
                    ),
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Mode config: command='{command}', file_name='{file_name}', timeout={timeout}, expect_file={expect_file}, config_key={config_key}, decompress={decompress}",
                    dut_id,
                )

                # Check if this mode should be run based on config
                if config_key:
                    try:
                        dut_config = self.dut_manager.get_dut_config(dut_id)
                        tool_config = self.orchestrator.config_manager.get_tool_config()

                        # Determine if the DUT explicitly set this key in its YAML
                        is_explicit = False
                        try:
                            dut_obj = self.dut_manager.get_dut(dut_id)
                            is_explicit = dut_obj.has_explicit_config_key(config_key)
                        except Exception:
                            # Fallback heuristic: consider present in dut_config as explicit
                            is_explicit = config_key in dut_config

                        # Resolve effective value: DUT explicit setting wins; otherwise fallback to tool config
                        effective_value = (
                            dut_config.get(config_key)
                            if is_explicit
                            else dut_config.get(
                                config_key, tool_config.get(config_key, False)
                            )
                        )

                        if not bool(effective_value):
                            await self._log_runtime(
                                "INFO",
                                "HostService",
                                f"Skipping mode '{mode_name}' - config_key '{config_key}' is False",
                                dut_id,
                            )
                            continue
                        else:
                            await self._log_runtime(
                                "DEBUG",
                                "HostService",
                                f"Mode '{mode_name}' enabled - config_key '{config_key}' resolved to True (explicit={is_explicit})",
                                dut_id,
                            )
                    except Exception as e:
                        await self._log_runtime(
                            "WARN",
                            "HostService",
                            f"Could not access config for mode '{mode_name}', skipping: {str(e)}",
                            dut_id,
                        )
                        continue

                private_remote_staging = bool(
                    mode_config.get("private_remote_staging", False)
                    or kwargs.get("private_remote_staging", False)
                    or "{remote_stage_dir}" in command
                    or "{remote_output_file}" in command
                )
                managed_private_staging = bool(
                    private_remote_staging
                    and expect_file is True
                    and "{remote_stage_dir}" in command
                    and "{remote_output_file}" in command
                )
                if managed_private_staging:
                    collector_id = str(
                        filtered_kwargs.get("collector_id")
                        or kwargs.get("collector_id")
                        or ""
                    )
                    try:
                        managed_collection = (
                            await self._collect_managed_private_advanced_mode(
                                dut_id,
                                collector_id,
                                mode_config,
                                resolved_timeout_seconds=timeout,
                                max_artifact_bytes=mode_max_artifact_bytes,
                                use_sudo=bool(use_sudo),
                                output_pattern=output_pattern,
                                filtered_kwargs=filtered_kwargs,
                                remote_temp_root=mode_config.get(
                                    "remote_staging_root",
                                    kwargs.get("remote_staging_root"),
                                ),
                                primary_pre_execution_grace_seconds=(
                                    configured_pre_execution_allowance_seconds
                                ),
                            )
                        )
                    except ManagedHostCommandConfigurationError as exc:
                        managed_collection = _ManagedModeCollection(
                            attempt=attempt_record(
                                str(mode_name),
                                disposition="failed",
                                failure_category="transport_error",
                                command_status="transport_error",
                                exit_code=None,
                                artifact_status="not_checked",
                                cleanup_status="verified_absent",
                                cleanup_scope="cgroup_v2",
                            ),
                            error_message=(
                                f"Mode {mode_name} managed configuration was invalid"
                            ),
                        )
                        await self._log_runtime(
                            "WARNING",
                            "HostService",
                            f"Managed private advanced mode rejected: {type(exc).__name__}",
                            dut_id,
                        )

                    managed_attempts.append(dict(managed_collection.attempt))
                    diagnostic_files.extend(managed_collection.diagnostic_files)
                    managed_success = bool(
                        managed_collection.attempt.get("disposition") == "success"
                        and managed_collection.output_file
                    )
                    if managed_success:
                        output_files.append(managed_collection.output_file)
                        successful_operations += 1
                        await self._log_collection_success(
                            dut_id,
                            "managed_command",
                            f"Mode: {mode_name}",
                        )
                    else:
                        failure_message = managed_collection.error_message or (
                            f"Mode {mode_name} managed lifecycle failed"
                        )
                        error_messages.append(failure_message)
                        await self._log_collection_failure(
                            dut_id,
                            "managed_command",
                            f"Mode: {mode_name}",
                            failure_message,
                            collector_id=collector_id,
                        )
                    status_list.append(managed_success)
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "INFO" if managed_success else "ERROR",
                        "HostService",
                        f"=== Completed managed mode {i}/{len(command_modes)}: "
                        f"{mode_name} (success={managed_success}) ===",
                    )
                    continue

                remote_stage: Optional[_RemoteStagingDirectory] = None
                staged_output_file: Optional[str] = None
                configured_root = mode_config.get(
                    "remote_staging_root",
                    kwargs.get("remote_staging_root"),
                )
                if private_remote_staging:
                    remote_stage = await self._create_remote_staging_directory(
                        dut_id,
                        f"{kwargs.get('collector_id') or function_tag}-{mode_name}",
                        use_sudo=use_sudo,
                        owned_stages=owned_stages,
                        configured_root=configured_root,
                    )
                    staged_output_file = self._remote_staging_file_path(
                        remote_stage, file_name
                    )
                    command = command.replace(
                        "{remote_stage_dir}", quote_arg(remote_stage.path)
                    ).replace("{remote_output_file}", quote_arg(staged_output_file))
                    if (
                        "{remote_stage_dir}" in command
                        or "{remote_output_file}" in command
                    ):
                        raise ValueError(
                            "unresolved private remote staging placeholder"
                        )
                resolved_remote_root = (
                    remote_stage.path
                    if remote_stage is not None
                    else await self._resolve_remote_staging_root(
                        dut_id,
                        configured_root,
                    )
                )

                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Mode: {mode_name} - {command}",
                    dut_id,
                )

                # Execute command with detailed logging
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Executing command with use_sudo={use_sudo}, timeout={timeout}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG", "HostService", f"Command: {command}", dut_id
                )

                # Record start time for timing
                start_time = time.time()

                # Pre-execution diagnostics for H11
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Running pre-execution diagnostics for mode '{mode_name}'",
                    dut_id,
                )

                # Check current working directory and user context
                pwd_cmd = "pwd && whoami && id"
                (
                    pwd_exit_code,
                    pwd_stdout,
                    _,
                ) = await self.dut_manager.execute_host_command(
                    dut_id, pwd_cmd, timeout=30, use_sudo=False
                )
                if pwd_exit_code == 0:
                    await self._log_runtime(
                        "DEBUG",
                        "HostService",
                        f"Pre-execution context: {pwd_stdout.strip()}",
                        dut_id,
                    )

                # Check if nvidia-bug-report.sh exists and is executable
                if "nvidia-bug-report.sh" in command:
                    nv_check_cmd = "which nvidia-bug-report.sh && ls -la $(which nvidia-bug-report.sh) 2>/dev/null || echo 'nvidia-bug-report.sh not found'"
                    (
                        nv_exit_code,
                        nv_stdout,
                        _,
                    ) = await self.dut_manager.execute_host_command(
                        dut_id, nv_check_cmd, timeout=30, use_sudo=False
                    )
                    if nv_exit_code == 0:
                        await self._log_runtime(
                            "DEBUG",
                            "HostService",
                            f"nvidia-bug-report.sh availability: {nv_stdout.strip()}",
                            dut_id,
                        )

                # Permission handoff happens only after the producer exits and
                # only for an exact, no-follow file in its private stage.
                command_to_run = command

                (
                    exit_code,
                    stdout,
                    stderr,
                ) = await self._execute_host_command_with_capture(
                    dut_id,
                    command_to_run,
                    operation_name=f"command_mode_{mode_name}",
                    timeout=timeout,
                    use_sudo=use_sudo,
                    collector_id=kwargs.get("collector_id"),
                    output_file=file_name if not expect_file else None,
                )

                # Log detailed execution results
                end_time = time.time()
                execution_time = end_time - start_time
                await self._log_runtime(
                    "INFO",
                    "HostService",
                    f"Mode '{mode_name}' command completed in {execution_time:.2f} seconds",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Command completed - exit_code={exit_code}",
                    dut_id,
                )
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"stdout length={len(stdout)}, stderr length={len(stderr)}",
                    dut_id,
                )
                if stdout:
                    await self._log_runtime(
                        "DEBUG",
                        "HostService",
                        f"stdout preview: {stdout[:200]}...",
                        dut_id,
                    )
                prompt_detected = False
                if stderr:
                    await self._log_runtime(
                        "DEBUG", "HostService", f"stderr: {stderr}", dut_id
                    )

                    # Check for sudo password prompt issues
                    if "[sudo] password for" in stderr:
                        prompt_detected = True
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "WARN",
                            "HostService",
                            f"Mode '{mode_name}' detected sudo password prompt in stderr - this may indicate authentication issues",
                        )
                        # Treat as warning only; do not mark as error to avoid partial status
                        sudo_prompt_locations.append(f"mode:{mode_name}")

                success = exit_code == 0

                # Post-execution diagnostics
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Running post-execution diagnostics for mode '{mode_name}'",
                    dut_id,
                )

                # Check disk space and configured temporary-directory status.
                disk_check_cmd = build_remote_cmd(
                    "df -h {path} && ls -ld {path}",
                    path=resolved_remote_root,
                )
                (
                    disk_exit_code,
                    disk_stdout,
                    _,
                ) = await self.dut_manager.execute_host_command(
                    dut_id, disk_check_cmd, timeout=30, use_sudo=False
                )
                if disk_exit_code == 0:
                    await self._log_runtime(
                        "DEBUG",
                        "HostService",
                        "Disk space and configured temp status: "
                        f"{disk_stdout.strip()}",
                        dut_id,
                    )

                if success:
                    await self._log_collection_success(
                        dut_id, "command", f"Mode: {mode_name}"
                    )
                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        f"Mode '{mode_name}' command succeeded (exit_code=0)",
                        dut_id,
                    )

                    # Handle file transfer if expect_file is True
                    if expect_file:
                        await self._log_runtime(
                            "INFO",
                            "HostService",
                            f"Mode '{mode_name}' expects file output, starting file transfer process",
                            dut_id,
                        )

                    # Command stdout is diagnostic evidence, not the mode's
                    # primary artifact.
                    if stdout:
                        diagnostic_output_pattern = (
                            f"diagnostic/{output_pattern}"
                            if output_pattern
                            else "diagnostic/{file_name}"
                        )
                        stdout_file_path = await self._save_data_with_common_pattern(
                            dut_id,
                            stdout,
                            f"{file_name}_stdout.log",
                            output_pattern=diagnostic_output_pattern,
                            substitutions={"file_name": f"{file_name}_stdout.log"},
                            **filtered_kwargs,
                        )
                        if stdout_file_path:
                            diagnostic_files.append(stdout_file_path)
                    successful_operations += 1

                    # If we expect a file to be generated, try to retrieve it
                    if expect_file:
                        # Prefer an explicit generated-file path for tools whose
                        # CLI does not support an output-file option. Retain
                        # command parsing for existing advanced collectors.
                        if staged_output_file:
                            remote_file = staged_output_file
                            remote_file_source = "private remote staging"
                        else:
                            remote_file = mode_config.get("remote_file")
                        if remote_file and not staged_output_file:
                            remote_file = (
                                str(remote_file)
                                .replace(
                                    "{remote_stage_dir}",
                                    remote_stage.path if remote_stage else "",
                                )
                                .replace(
                                    "{remote_output_file}",
                                    staged_output_file or "",
                                )
                            )
                            remote_file = str(remote_file)
                            remote_file_source = "mode configuration"
                        elif not remote_file:
                            output_file_match = re.search(
                                r"--output-file\s+([^\s\"]+)", command
                            )
                            remote_file = (
                                output_file_match.group(1)
                                if output_file_match
                                else None
                            )
                            remote_file_source = "command"

                        if remote_file:
                            # Bind relative producer output to the configured
                            # Host scratch root.
                            if not remote_file.startswith("/"):
                                remote_file = str(
                                    PurePosixPath(resolved_remote_root) / remote_file
                                )

                            await self._log_runtime(
                                "DEBUG",
                                "HostService",
                                f"Resolved remote_file from {remote_file_source}: {remote_file}",
                                dut_id,
                            )

                            # Get file extensions to try from configuration
                            file_extensions = mode_config.get(
                                "file_extensions",
                                [
                                    ".gz",
                                    ".tar.gz",
                                    ".tgz",
                                    ".zip",
                                    ".bz2",
                                    ".xz",
                                    ".7z",
                                    ".rar",
                                    "",
                                ],
                            )  # Comprehensive default list
                            await self._log_runtime(
                                "DEBUG",
                                "HostService",
                                f"Will try file extensions: {file_extensions}",
                                dut_id,
                            )

                            # Try to download the file with multiple fallback methods
                            collector_id = str(
                                filtered_kwargs.get("collector_id")
                                or kwargs.get("collector_id")
                                or ""
                            )
                            local_staging_context = (
                                self._create_advanced_staging_context(
                                    dut_id,
                                    collector_id,
                                    mode_name,
                                    await self._resolve_local_staging_parent(dut_id),
                                )
                            )
                            local_staging_dir = Path(local_staging_context.name)
                            preserved_staging_paths = set()
                            download_success = False
                            downloaded_file_override = None
                            transfer_success = False
                            transfer_error = ""
                            final_acquired_path = None
                            acquisition_timing_id = None
                            if self.timing_manager:
                                acquisition_timing_id = (
                                    self.timing_manager.start_operation(
                                        "host_file_acquisition",
                                        mode_name,
                                        metadata={
                                            "transport": "host_file_transfer",
                                            "remote_path": remote_file,
                                            "source": "advanced_collection",
                                            "retry_extensions": list(file_extensions),
                                        },
                                    )
                                )

                            if remote_stage:
                                selected_extension = None
                                preparation_errors: List[str] = []
                                for extension in file_extensions:
                                    candidate = (
                                        f"{remote_file}{extension}"
                                        if extension
                                        else remote_file
                                    )
                                    try:
                                        candidate = self._remote_staging_file_path(
                                            remote_stage,
                                            PurePosixPath(candidate).name,
                                        )
                                        (
                                            prepared,
                                            preparation_error,
                                        ) = await self._prepare_remote_staging_files(
                                            dut_id,
                                            remote_stage,
                                            [candidate],
                                        )
                                    except ValueError as exc:
                                        prepared, preparation_error = (
                                            False,
                                            str(exc),
                                        )
                                    if prepared:
                                        selected_extension = extension
                                        break
                                    if preparation_error:
                                        preparation_errors.append(preparation_error)
                                if selected_extension is None:
                                    transfer_error = (
                                        "No exact regular staged output was available"
                                    )
                                    if preparation_errors:
                                        transfer_error += f": {preparation_errors[-1]}"
                                    file_extensions = []
                                else:
                                    file_extensions = [selected_extension]

                            async def _transfer_for_advanced_collection(
                                source_path: str,
                            ) -> Tuple[bool, str]:
                                """
                                Transfer for advanced collection.

                                After applying local validation, the function
                                forwards ``source_path`` to
                                ``self.dut_manager.transfer_host_files`` and
                                preserves its return and exception contract.
                                Owned asynchronous work is awaited before
                                return, so completion does not leave an
                                unobserved task behind.

                                Args:
                                    source_path: filesystem location used as the
                                        source for this operation.

                                Returns:
                                    A tuple containing the fields that represent
                                    transfer for advanced collection.
                                """
                                try:
                                    return await self.dut_manager.transfer_host_files(
                                        dut_id,
                                        source_path,
                                        str(local_staging_dir),
                                        copy_to_destination=False,
                                        max_bytes=mode_max_artifact_bytes,
                                    )
                                except BaseException as exc:
                                    local_staging_context.cleanup()
                                    if self.timing_manager:
                                        self.timing_manager.end_operation(
                                            acquisition_timing_id,
                                            status=(
                                                "cancelled"
                                                if isinstance(
                                                    exc, asyncio.CancelledError
                                                )
                                                else "error"
                                            ),
                                            error=(
                                                "CancelledError"
                                                if isinstance(
                                                    exc, asyncio.CancelledError
                                                )
                                                else str(exc)
                                            ),
                                        )
                                    raise

                            for extension in file_extensions:
                                if download_success:
                                    break

                                # Construct the remote file path with extension
                                if extension:
                                    extended_remote_file = f"{remote_file}{extension}"
                                else:
                                    extended_remote_file = remote_file

                                await self._log_runtime(
                                    "DEBUG",
                                    "HostService",
                                    f"Attempting to transfer file with extension '{extension}': {extended_remote_file}",
                                    dut_id,
                                )

                                # If running locally, copy file directly with sudo instead of SFTP
                                is_local_mode = False
                                try:
                                    dut = self.dut_manager.get_dut(dut_id)
                                    is_local_mode = bool(
                                        (
                                            dut
                                            and getattr(
                                                dut.config,
                                                "get",
                                                lambda k, d=None: d,
                                            )("local", False)
                                        )
                                        or (
                                            dut
                                            and getattr(
                                                dut.credentials,
                                                "execution_mode",
                                                "",
                                            ).lower()
                                            == "local"
                                        )
                                    )
                                except Exception:
                                    is_local_mode = False

                                if is_local_mode:
                                    await self._log_runtime(
                                        "INFO",
                                        "HostService",
                                        f"Local mode detected; copying file directly instead of SFTP: {extended_remote_file}",
                                        dut_id,
                                    )
                                    temp_dir = str(local_staging_dir)
                                    await self.dut_manager.execute_host_command(
                                        dut_id,
                                        build_remote_cmd(
                                            "dir={dir}; install -d -m 750 "
                                            '-o "${{SUDO_UID:-$(id -u)}}" '
                                            '-g "${{SUDO_GID:-$(id -g)}}" "$dir"',
                                            dir=temp_dir,
                                        ),
                                        timeout=60,
                                        use_sudo=True,
                                    )
                                    local_copy = str(
                                        local_staging_dir
                                        / os.path.basename(extended_remote_file)
                                    )
                                    copy_cmd = build_remote_cmd(
                                        "src={src}; dst={dst}; "
                                        'if test -f "$src" && test ! -L "$src"; then '
                                        'rm -f -- "$dst" && '
                                        "install -m 640 "
                                        '-o "${{SUDO_UID:-$(id -u)}}" '
                                        '-g "${{SUDO_GID:-$(id -g)}}" '
                                        '-- "$src" "$dst"; fi',
                                        src=extended_remote_file,
                                        dst=local_copy,
                                    )
                                    (
                                        copy_exit,
                                        _,
                                        _,
                                    ) = await self.dut_manager.execute_host_command(
                                        dut_id,
                                        copy_cmd,
                                        timeout=60,
                                        use_sudo=True,
                                    )
                                    transfer_success = False
                                    if copy_exit == 0:
                                        try:
                                            local_copy_status = os.lstat(local_copy)
                                            transfer_success = stat.S_ISREG(
                                                local_copy_status.st_mode
                                            )
                                        except OSError:
                                            transfer_success = False
                                    transfer_error = (
                                        ""
                                        if transfer_success
                                        else "Local copy failed or file missing/unsafe"
                                    )
                                    downloaded_file_override = (
                                        local_copy if transfer_success else None
                                    )
                                    if transfer_success:
                                        await self._log_runtime(
                                            "DEBUG",
                                            "HostService",
                                            f"Local copy succeeded: {local_copy}",
                                            dut_id,
                                        )
                                    else:
                                        await self._log_runtime(
                                            "WARNING",
                                            "HostService",
                                            f"Local copy failed or file missing after copy attempt: {local_copy}",
                                            dut_id,
                                        )
                                else:
                                    # Pre-transfer diagnostics
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        f"Running pre-transfer diagnostics for file: {extended_remote_file}",
                                        dut_id,
                                    )

                                    # Check file existence and permissions before transfer
                                    file_check_cmd = build_remote_cmd(
                                        "test -f {path} && ls -la {path} || echo 'File does not exist'",
                                        path=extended_remote_file,
                                    )
                                    (
                                        file_check_exit_code,
                                        file_check_stdout,
                                        _,
                                    ) = await self.dut_manager.execute_host_command(
                                        dut_id,
                                        file_check_cmd,
                                        timeout=30,
                                        use_sudo=False,
                                    )
                                    if file_check_exit_code == 0:
                                        await self._log_runtime(
                                            "DEBUG",
                                            "HostService",
                                            f"Pre-transfer file check: {file_check_stdout.strip()}",
                                            dut_id,
                                        )

                                    # Method 1: Direct transfer
                                    (
                                        transfer_success,
                                        transfer_error,
                                    ) = await _transfer_for_advanced_collection(
                                        extended_remote_file
                                    )
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        f"Method 1 (Direct) - success: {transfer_success}, error: {transfer_error}",
                                        dut_id,
                                    )

                                if not transfer_success:
                                    # Method 2: Check for one no-follow regular file.
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        "Method 1 failed, trying Method 2 (File check)",
                                        dut_id,
                                    )
                                    file_check_cmd = build_remote_cmd(
                                        "test -f {path} && test ! -L {path}",
                                        path=extended_remote_file,
                                    )
                                    (
                                        exit_code,
                                        _,
                                        stderr,
                                    ) = await self.dut_manager.execute_host_command(
                                        dut_id,
                                        file_check_cmd,
                                        timeout=60,
                                        use_sudo=use_sudo,
                                    )
                                    if exit_code == 0:
                                        await self._log_runtime(
                                            "DEBUG",
                                            "HostService",
                                            "Regular file exists, retrying transfer",
                                            dut_id,
                                        )
                                        (
                                            transfer_success,
                                            transfer_error,
                                        ) = await _transfer_for_advanced_collection(
                                            extended_remote_file
                                        )
                                        await self._log_runtime(
                                            "DEBUG",
                                            "HostService",
                                            f"Method 2 (Retry) - success: {transfer_success}, error: {transfer_error}",
                                            dut_id,
                                        )

                                if not transfer_success and not remote_stage:
                                    # Method 3: Copy to temp location with permissions
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        "Method 2 failed, trying Method 3 (Temp copy with permissions)",
                                        dut_id,
                                    )

                                    fallback_stage = await self._create_remote_staging_directory(
                                        dut_id,
                                        f"{collector_id or function_tag}-{mode_name}-transfer",
                                        use_sudo=use_sudo,
                                        owned_stages=owned_stages,
                                    )
                                    temp_file = self._remote_staging_file_path(
                                        fallback_stage,
                                        os.path.basename(extended_remote_file),
                                    )
                                    copy_cmd = build_remote_cmd(
                                        "test -f {src} && test ! -L {src} "
                                        "&& cp -P -- {src} {dst} "
                                        "&& test -f {dst} && test ! -L {dst}",
                                        src=extended_remote_file,
                                        dst=temp_file,
                                    )
                                    (
                                        exit_code,
                                        _,
                                        stderr,
                                    ) = await self._execute_remote_staging_command(
                                        dut_id,
                                        copy_cmd,
                                        use_sudo=use_sudo,
                                    )
                                    if exit_code == 0:
                                        (
                                            prepared,
                                            preparation_error,
                                        ) = await self._prepare_remote_staging_files(
                                            dut_id,
                                            fallback_stage,
                                            [temp_file],
                                        )
                                        if prepared:
                                            (
                                                transfer_success,
                                                transfer_error,
                                            ) = await _transfer_for_advanced_collection(
                                                temp_file
                                            )
                                        else:
                                            transfer_error = preparation_error
                                    else:
                                        transfer_error = stderr
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        f"Method 3 (private temp copy) - success: "
                                        f"{transfer_success}, error: {transfer_error}",
                                        dut_id,
                                    )

                                if transfer_success:
                                    # Read the downloaded file content and save it
                                    if downloaded_file_override:
                                        downloaded_file = downloaded_file_override
                                    else:
                                        downloaded_file = str(
                                            local_staging_dir
                                            / os.path.basename(extended_remote_file)
                                        )
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        f"Checking if downloaded file exists: {downloaded_file}",
                                        dut_id,
                                    )
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        f"File exists: {os.path.exists(downloaded_file)}",
                                        dut_id,
                                    )
                                    await self._log_runtime(
                                        "DEBUG",
                                        "HostService",
                                        f"File exists: {os.path.exists(downloaded_file)}",
                                        dut_id,
                                    )
                                    if os.path.exists(downloaded_file):
                                        try:
                                            (
                                                archive_valid,
                                                archive_error,
                                            ) = await self._validate_advanced_archive_async(
                                                downloaded_file, extended_remote_file
                                            )
                                            if not archive_valid:
                                                evidence_path = await self._preserve_invalid_advanced_artifact(
                                                    dut_id,
                                                    collector_id,
                                                    mode_name,
                                                    downloaded_file,
                                                )
                                                preserved_staging_paths.add(
                                                    os.path.abspath(downloaded_file)
                                                )
                                                transfer_error = (
                                                    "Archive integrity validation failed "
                                                    f"for {extended_remote_file}: "
                                                    f"{archive_error or 'invalid archive'}"
                                                )
                                                if evidence_path:
                                                    output_files.append(evidence_path)
                                                    transfer_error += (
                                                        "; rejected artifact preserved at "
                                                        f"{evidence_path}"
                                                    )
                                                error_messages.append(
                                                    f"Mode '{mode_name}' failed: "
                                                    f"{transfer_error}"
                                                )
                                                await self._log_collection_failure(
                                                    dut_id,
                                                    "archive_validation",
                                                    f"Mode: {mode_name}",
                                                    transfer_error,
                                                    collector_id=collector_id,
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "ERROR",
                                                    "HostService",
                                                    transfer_error,
                                                )
                                                transfer_success = False
                                                success = False
                                                continue

                                            if decompress:
                                                # Text-mode compatibility requires
                                                # materialization, but never at the
                                                # multi-gigabyte binary transport
                                                # ceiling used by advanced dumps.
                                                text_limit = min(
                                                    mode_max_artifact_bytes,
                                                    _MAX_ADVANCED_TEXT_MATERIALIZATION_BYTES,
                                                )
                                                file_content = (
                                                    read_regular_file_bounded(
                                                        downloaded_file,
                                                        maximum_bytes=text_limit,
                                                    )
                                                )
                                                # Decode bytes to string for text files.
                                                file_content_str = (
                                                    self._process_command_output(
                                                        file_content
                                                    )
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"Successfully decoded {len(file_content_str)} characters from bytes",
                                                )

                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"Saving decompressed file content with file_name: {file_name}",
                                                )
                                                final_path = await self._save_data_with_common_pattern(
                                                    dut_id,
                                                    file_content_str,
                                                    file_name,
                                                    output_pattern=output_pattern,
                                                    substitutions={
                                                        "file_name": file_name
                                                    },
                                                    **filtered_kwargs,
                                                )
                                            else:
                                                # Keep the file as binary/compressed (default behavior)
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"Preserving compression for file: {file_name}",
                                                )

                                                # Get the final filename using the same pattern logic
                                                # Extract the actual extension from the remote file (e.g., .gz, .log, etc.)
                                                # This makes it generic to handle any file extension
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    "=== Filename Generation Debug ===",
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"extended_remote_file: {extended_remote_file}",
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"file_name from config: {file_name}",
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"output_pattern: {output_pattern}",
                                                )

                                                actual_extension = os.path.splitext(
                                                    extended_remote_file
                                                )[1]
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"os.path.splitext result: {os.path.splitext(extended_remote_file)}",
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"extracted extension: '{actual_extension}'",
                                                )

                                                # Get base filename from pattern, then append the actual extension
                                                base_filename = (
                                                    self.get_output_filename(
                                                        output_pattern,
                                                        file_name,
                                                        "",
                                                        {"file_name": file_name},
                                                    )
                                                )
                                                final_filename = (
                                                    f"{base_filename}{actual_extension}"
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    f"get_output_filename result: {final_filename}",
                                                )
                                                await self._write_to_dut_runtime_log(
                                                    dut_id,
                                                    "DEBUG",
                                                    "HostService",
                                                    "=== End Filename Generation Debug ===",
                                                )

                                                # Preserve binary content without
                                                # creating a second in-memory copy.
                                                if self.logger:
                                                    file_path = await self.logger.create_collector_log_file(
                                                        dut_id,
                                                        "host",
                                                        filtered_kwargs.get(
                                                            "collector_id", ""
                                                        ),
                                                        final_filename,
                                                    )
                                                    timing_operation_id = None
                                                    if self.timing_manager:
                                                        timing_operation_id = self.timing_manager.start_operation(
                                                            "artifact_persistence",
                                                            final_filename,
                                                        )
                                                    try:
                                                        copied_bytes = _publish_regular_file_bounded(
                                                            downloaded_file,
                                                            file_path,
                                                            max_bytes=mode_max_artifact_bytes,
                                                        )
                                                    except BaseException as exc:
                                                        if self.timing_manager:
                                                            self.timing_manager.end_operation(
                                                                timing_operation_id,
                                                                status="error",
                                                                error=str(exc),
                                                            )
                                                        raise
                                                    if self.timing_manager:
                                                        self.timing_manager.end_operation(
                                                            timing_operation_id,
                                                            artifact_path=str(
                                                                file_path
                                                            ),
                                                            size_bytes=copied_bytes,
                                                        )
                                                    final_path = str(file_path)
                                                    await self._write_to_dut_runtime_log(
                                                        dut_id,
                                                        "DEBUG",
                                                        "HostService",
                                                        f"Binary file saved to: {final_path}",
                                                    )
                                                else:
                                                    await self._write_to_dut_runtime_log(
                                                        dut_id,
                                                        "ERROR",
                                                        "HostService",
                                                        "No logger available to save binary file",
                                                    )
                                                    final_path = None
                                            await self._write_to_dut_runtime_log(
                                                dut_id,
                                                "DEBUG",
                                                "HostService",
                                                f"File saved to: {final_path}",
                                            )
                                            output_files.append(final_path)
                                            final_acquired_path = final_path
                                            download_success = True

                                            # This path belongs exclusively to the
                                            # current operation's staging directory.
                                            Path(downloaded_file).unlink(
                                                missing_ok=True
                                            )

                                            # Clean up remote file
                                            await self.dut_manager.execute_host_command(
                                                dut_id,
                                                build_remote_cmd(
                                                    "rm -f {path}",
                                                    path=extended_remote_file,
                                                ),
                                                timeout=60,
                                                use_sudo=use_sudo,
                                            )
                                        except asyncio.CancelledError:
                                            local_staging_context.cleanup()
                                            if self.timing_manager:
                                                self.timing_manager.end_operation(
                                                    acquisition_timing_id,
                                                    status="cancelled",
                                                    error="CancelledError",
                                                )
                                            raise
                                        except Exception as e:
                                            await self._log_collection_failure(
                                                dut_id,
                                                "file_read",
                                                f"Mode: {mode_config.get('mode', 'unknown')}",
                                                f"Failed to read downloaded file {downloaded_file}: {str(e)}",
                                                collector_id=kwargs.get("collector_id"),
                                            )

                            if self.timing_manager:
                                acquisition_succeeded = bool(
                                    download_success and final_acquired_path
                                )
                                self.timing_manager.end_operation(
                                    acquisition_timing_id,
                                    status=(
                                        "success" if acquisition_succeeded else "error"
                                    ),
                                    artifact_path=(
                                        final_acquired_path
                                        if acquisition_succeeded
                                        else None
                                    ),
                                    error=(
                                        None
                                        if acquisition_succeeded
                                        else str(
                                            transfer_error
                                            or "No final collector artifact was produced"
                                        )
                                    ),
                                )

                            if not download_success and local_staging_dir.exists():
                                for staged_candidate in local_staging_dir.iterdir():
                                    candidate_key = os.path.abspath(staged_candidate)
                                    if (
                                        candidate_key in preserved_staging_paths
                                        or not staged_candidate.is_file()
                                    ):
                                        continue
                                    try:
                                        if staged_candidate.stat().st_size <= 0:
                                            continue
                                    except OSError:
                                        continue

                                    evidence_path = (
                                        await self._preserve_invalid_advanced_artifact(
                                            dut_id,
                                            collector_id,
                                            mode_name,
                                            str(staged_candidate),
                                            label="incomplete",
                                        )
                                    )
                                    if evidence_path:
                                        output_files.append(evidence_path)
                                        error_messages.append(
                                            f"Mode '{mode_name}' failed: Incomplete "
                                            "transfer evidence preserved at "
                                            f"{evidence_path}"
                                        )
                                    preserved_staging_paths.add(candidate_key)

                            # Remove only this operation's randomly named staging
                            # directory. Other DUTs and modes use different paths.
                            local_staging_context.cleanup()

                            if not download_success:
                                await self._write_to_dut_runtime_log(
                                    dut_id,
                                    "DEBUG",
                                    "HostService",
                                    f"All file extension attempts failed for {remote_file}",
                                )
                                await self._log_collection_failure(
                                    dut_id,
                                    "file_download",
                                    f"Mode: {mode_config.get('mode', 'unknown')}",
                                    f"Failed to download {remote_file} with any extension",
                                    collector_id=kwargs.get("collector_id"),
                                )
                                if expect_file:
                                    success = False
                                    await self._write_to_dut_runtime_log(
                                        dut_id,
                                        "ERROR",
                                        "HostService",
                                        f"Mode '{mode_name}' marked as FAILED due to file transfer failure",
                                    )
                                    error_messages.append(
                                        f"Mode '{mode_name}' failed: File transfer failed for {remote_file} with all extensions"
                                    )
                else:
                    # Log both stdout and stderr for failed commands
                    error_details = f"exit_code: {exit_code}"
                    if stdout:
                        error_details += f", stdout: {stdout}"
                    if stderr:
                        error_details += f", stderr: {stderr}"
                    await self._log_collection_failure(
                        dut_id,
                        "command",
                        f"Mode: {mode_name}",
                        error_details,
                        collector_id=kwargs.get("collector_id"),
                    )
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "HostService",
                        f"Mode '{mode_name}' command failed: {error_details}",
                    )
                    error_messages.append(
                        f"Mode command failed: {mode_name} - {error_details}"
                    )
                    if prompt_detected:
                        error_messages.append(
                            f"Mode '{mode_name}' encountered sudo password prompt"
                        )

                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"=== Completed Mode {i}/{len(command_modes)}: {mode_name} (success={success}) ===",
                )
                status_list.append(success)

        # Determine overall status
        # For collectors, we need to distinguish between command success and file transfer success
        # If any mode fails due to file transfer issues, we should report partial success or failure
        successful_modes = sum(status_list)
        total_modes = len(status_list)

        # Check if we have any file transfer failures in error messages
        has_file_transfer_failures = any(
            "File transfer failed" in msg for msg in error_messages
        )

        if successful_modes == 0:
            # Complete failure - no modes succeeded
            overall_success = False
        elif has_file_transfer_failures:
            # Some modes succeeded but file transfers failed - report as partial success
            if successful_modes == total_modes:
                # All commands succeeded but some file transfers failed - partial success
                overall_success = True
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "HostService",
                    "Collection completed with file transfer failures - reporting as partial success",
                )
            else:
                # Some commands failed AND some file transfers failed - failure
                overall_success = False
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    f"Collection failed - {successful_modes}/{total_modes} modes succeeded but file transfers also failed",
                )
        else:
            # All modes succeeded and no file transfer failures
            overall_success = True

        # Use the standardized collection summary from base service
        await self._log_collection_summary(
            dut_id=dut_id,
            collection_name="Advanced Host Collection",
            total_operations=total_modes,
            successful_operations=successful_modes,
            failed_operations=total_modes - successful_modes,
            output_files_count=len(output_files),
            additional_details={
                "Overall success": overall_success,
                "File transfer failures": has_file_transfer_failures,
                "Sudo prompt detected": bool(sudo_prompt_locations),
                "Sudo prompt locations": sudo_prompt_locations,
            },
        )

        if overall_success:
            # Determine if this is partial success due to file transfer failures
            if has_file_transfer_failures:
                await self._log_collection_success(
                    dut_id,
                    "advanced_collection",
                    "Advanced Host Collection (Partial)",
                )
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "HostService",
                    f"Advanced collection completed with PARTIAL SUCCESS - {successful_modes}/{total_modes} modes successful, but some file transfers failed",
                )
                return await self._create_standardized_collector_result(
                    successful_operations=successful_modes,
                    total_operations=total_modes,
                    output_files=output_files,
                    error_messages=error_messages,
                    operation_name="advanced_collection",
                    additional_context={
                        "message": "Advanced collection completed with partial success due to file transfer failures",
                        "status": "partial",
                        "reason": "Advanced collection completed with partial success due to file transfer failures",
                        "successful_modes": successful_modes,
                        "total_modes": total_modes,
                        "has_file_transfer_failures": True,
                        "diagnostic_files": diagnostic_files,
                        "sudo_prompt_detected": bool(sudo_prompt_locations),
                        "sudo_prompt_locations": sudo_prompt_locations,
                        "metadata_files": metadata_files,
                        "managed_attempts": managed_attempts,
                        **advanced_managed_context(),
                    },
                )
            else:
                await self._log_collection_success(
                    dut_id, "advanced_collection", "Advanced Host Collection"
                )
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"Advanced collection completed successfully with {successful_modes}/{total_modes} modes successful",
                )
                return await self._create_standardized_collector_result(
                    successful_operations=successful_modes,
                    total_operations=total_modes,
                    output_files=output_files,
                    error_messages=error_messages,
                    operation_name="advanced_collection",
                    additional_context={
                        "message": "Advanced collection completed successfully",
                        "successful_modes": successful_modes,
                        "total_modes": total_modes,
                        "diagnostic_files": diagnostic_files,
                        "sudo_prompt_detected": bool(sudo_prompt_locations),
                        "sudo_prompt_locations": sudo_prompt_locations,
                        "metadata_files": metadata_files,
                        "managed_attempts": managed_attempts,
                        **advanced_managed_context(),
                    },
                )
        else:
            # Collection failed - either all commands failed or file transfers failed
            failure_reason = (
                "All commands failed"
                if successful_modes == 0
                else "File transfer failures"
            )
            await self._log_collection_failure(
                dut_id,
                "advanced_collection",
                "Advanced Host Collection",
                failure_reason,
                collector_id=kwargs.get("collector_id"),
            )
            await self._write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "HostService",
                f"Advanced collection failed - {failure_reason}",
            )
            return await self._create_standardized_collector_result(
                successful_operations=successful_modes,
                total_operations=total_modes,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="advanced_collection",
                additional_context={
                    "message": f"Advanced collection failed: {failure_reason}",
                    "failure_reason": failure_reason,
                    "successful_modes": successful_modes,
                    "total_modes": total_modes,
                    "diagnostic_files": diagnostic_files,
                    "sudo_prompt_detected": bool(sudo_prompt_locations),
                    "sudo_prompt_locations": sudo_prompt_locations,
                    "metadata_files": metadata_files,
                    "managed_attempts": managed_attempts,
                    **advanced_managed_context(),
                },
            )

    # ============================================================================
    # 10.3 EXISTING METHODS (Keep for backward compatibility)
    # ============================================================================

    async def _handle_host_file_search_and_archive(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Generic handler for catalog-configured file search and archive operations.

        The implementation uses ``dut_id``, ``function_tag``, and ``kwargs`` to
        generic handler for catalog-configured file search and archive
        operations. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The validated ``result``.
        """

        acquisition_timing_id = None

        async def _file_search_and_archive():
            """
            Handle file search and archive operations.

            The implementation uses current instance state to handle file search
            and archive operations. Terminal status is emitted only after file
            search and archive operations and its owned cleanup have completed.
            Owned asynchronous work is awaited before return, so completion does
            not leave an unobserved task behind. Filesystem effects remain
            confined to the caller-selected paths and the owning resource
            lifecycle. If the function cannot handle file search and archive
            operations, its exception reaches the caller instead of being
            converted into a successful result.

            Returns:
                The terminal result of the bounded file-search and archive
                operation.

            Raises:
                ValueError: If the search_config.validate_headers are not a
                    Boolean; the search_config.ignore_empty_after_validation is
                    not a Boolean; or the search_config.max_results are not a
                    positive integer.
                BaseException: If a delegated failure occurs while the function
                    attempts to handle file search and archive operations.
            """

            nonlocal acquisition_timing_id

            def _normalize_header_text(text: str) -> str:
                """
                Normalize header text.

                The implementation uses ``text`` to normalize header text. The
                source value keeps its ownership while the normalized
                representation is returned separately. Filesystem effects remain
                confined to the caller-selected paths and the owning resource
                lifecycle.

                Args:
                    text: Text supplied as text in the format accepted by this
                        function.

                Returns:
                    The canonical header text.
                """
                if not text:
                    return ""
                normalized = text.lower().replace("_", " ")
                normalized = re.sub(r"[^a-z0-9 ]+", " ", normalized)
                return " ".join(normalized.split())

            async def _has_required_headers(
                file_path: str,
                required_headers: List[str],
                header_scan_lines: int,
            ) -> Tuple[bool, Optional[str]]:
                """
                Return whether ``file_path`` has required headers.

                Header validation was explicitly requested, but there is no
                contract to validate against. Fail closed so an unrelated file
                cannot bypass candidate filtering.

                Args:
                    file_path: filesystem location used as the file path for
                        this operation.
                    required_headers: Entries supplied as ``required_headers``
                        without transferring container ownership.
                    header_scan_lines: Numeric header scan lines used while the
                        operation performs bounded accounting.

                Returns:
                    A tuple containing ``success flag`` and ``status or message
                    text`` in that order.
                """
                if not required_headers:
                    # Header validation was explicitly requested, but there is
                    # no contract to validate against. Fail closed so an
                    # unrelated file cannot bypass candidate filtering.
                    return False, None
                header_cmd = (
                    f"head -n {max(1, int(header_scan_lines))} {shlex.quote(file_path)}"
                )
                exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                    dut_id, header_cmd, timeout=60, use_sudo=use_sudo
                )
                if exit_code != 0:
                    command_error = stderr.strip() or (
                        f"header read exited with status {exit_code}"
                    )
                    return (
                        False,
                        f"Header validation failed for {file_path}: {command_error}",
                    )
                if not stdout.strip():
                    return False, None
                normalized_required = [
                    _normalize_header_text(header) for header in required_headers
                ]
                for line in stdout.splitlines():
                    normalized_line = _normalize_header_text(line)
                    if all(req in normalized_line for req in normalized_required):
                        return True, None
                return False, None

            file_pattern = kwargs.get("file_pattern", "*")
            search_config = kwargs.get("search_config", {})
            archive_config = kwargs.get("archive_config", {})
            use_sudo = kwargs.get("use_sudo", True)
            ignore_empty_results = kwargs.get("ignore_empty_results", False)

            required_headers = search_config.get("required_headers", [])
            trusted_path_patterns = search_config.get("trusted_path_patterns", [])
            trusted_path_regexes = _normalize_trusted_path_regexes(
                search_config.get("trusted_path_regexes", [])
            )
            header_scan_lines = search_config.get("header_scan_lines", 200)
            raw_validate_headers = search_config.get("validate_headers", False)
            if not isinstance(raw_validate_headers, bool):
                raise ValueError("search_config.validate_headers must be a Boolean")
            validate_headers = bool(required_headers) or raw_validate_headers
            raw_ignore_empty_after_validation = search_config.get(
                "ignore_empty_after_validation", False
            )
            if not isinstance(raw_ignore_empty_after_validation, bool):
                raise ValueError(
                    "search_config.ignore_empty_after_validation must be a Boolean"
                )
            ignore_empty_after_validation = raw_ignore_empty_after_validation
            related_file_searches = _normalize_related_file_searches(
                search_config.get("related_file_searches", [])
            )
            related_file_search_details: Dict[str, Dict[str, Any]] = {
                rule["id"]: {
                    "id": rule["id"],
                    "anchor": {
                        key: value
                        for key, value in rule["anchor"].items()
                        if key != "compiled_regex"
                    },
                    "match": dict(rule["match"]),
                    "selection": dict(rule["selection"]),
                    "search_timeout": rule["search_timeout"],
                    "absence_policy": rule["absence_policy"],
                    "malformed_only_policy": rule["malformed_only_policy"],
                    "anchor_directories": [],
                    "candidate_files": [],
                    "eligible_files": [],
                    "superseded_files": [],
                    "rejected_files": [],
                    "selected_file": None,
                    "selected_timestamp": None,
                    "search_status": "not_run",
                    "search_error": None,
                }
                for rule in related_file_searches
            }

            # Read archive_files flag (defaults to True) and collector_id
            archive_files = kwargs.get("archive_files", True)
            collector_id = kwargs.get("collector_id")

            # Resolve collector output directory and prepare archived_dir if archiving is enabled
            collector_output_dir = await self._get_collector_output_dir(
                dut_id, collector_id
            )
            archived_dir = None

            if archive_files and collector_output_dir:
                # Name the subdirectory as <collector_name> for all collectors
                dir_name = collector_output_dir.name
                archived_dir = collector_output_dir / dir_name
                try:
                    archived_dir.mkdir(parents=True, exist_ok=True)
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "HostService",
                        f"Created archived files directory: {archived_dir}",
                    )
                except Exception as e:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "HostService",
                        f"Failed to create archived files directory: {e}",
                    )
                    archived_dir = None

            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"Starting file search and archive with pattern: {file_pattern}",
            )

            # Step 1: File search
            search_directories = search_config.get("directories", ["/"])
            search_exclusions = search_config.get("exclusions", [])
            # A result limit is opt-in.  The historical default of 10 silently
            # discarded matching files for collectors which did not declare a
            # limit.
            # Preserve the legacy ``max_depth`` alias for explicit callers, but
            # never invent a bound when neither key is present.
            raw_max_results = search_config.get(
                "max_results", search_config.get("max_depth")
            )
            max_results = None
            if raw_max_results is not None:
                try:
                    if isinstance(raw_max_results, bool):
                        raise ValueError
                    max_results = int(raw_max_results)
                    if max_results <= 0 or (
                        isinstance(raw_max_results, float)
                        and not raw_max_results.is_integer()
                    ):
                        raise ValueError
                except (TypeError, ValueError, OverflowError):
                    raise ValueError(
                        "search_config.max_results must be a positive integer"
                    ) from None
            same_filesystem = bool(search_config.get("same_filesystem", False))

            # Build find command. Exclusions must use ``-prune`` so find does not
            # walk excluded trees before filtering their results. Preserve the
            # legacy ``/*`` exclusion meaning while also pruning its parent.
            quoted_directories = " ".join(
                shlex.quote(str(directory)) for directory in search_directories
            )
            find_expression = f"find {quoted_directories}"
            if same_filesystem:
                find_expression += " -xdev"
            prune_patterns: List[str] = []
            if search_exclusions:
                for exclusion in search_exclusions:
                    exclusion = str(exclusion)
                    if exclusion.endswith("/*") and exclusion[:-2]:
                        prune_patterns.append(exclusion[:-2])
                    prune_patterns.append(exclusion)
                prune_patterns = list(dict.fromkeys(prune_patterns))
                prune_expression = " -o ".join(
                    f"-path {shlex.quote(pattern)}" for pattern in prune_patterns
                )
                find_expression += f" \\( {prune_expression} \\) -prune -o"
            find_expression += (
                f" \\( -name {shlex.quote(str(file_pattern))} -type f -print \\)"
            )

            if max_results is None:
                search_command = find_expression
            else:
                # Awk bounds an explicitly configured result set while
                # continuing to consume find's output, avoiding the SIGPIPE
                # ambiguity caused by head. Inspect both Bash pipeline statuses
                # so completed find errors are not mistaken for a valid empty
                # search.
                search_command = (
                    f"{find_expression} | awk 'NR <= {max_results}'; "
                    'pipeline_status=("${PIPESTATUS[@]}"); '
                    'find_status="${pipeline_status[0]}"; '
                    'output_status="${pipeline_status[1]}"; '
                    'if [ "$output_status" -ne 0 ]; then exit "$output_status"; fi; '
                    'exit "$find_status"'
                )
            find_command = f"bash -c {shlex.quote(search_command)}"

            exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                dut_id, find_command, timeout=300, use_sudo=use_sudo
            )

            search_failed = exit_code != 0
            if search_failed or not stdout.strip():
                empty_is_success = not search_failed and ignore_empty_results
                if search_failed:
                    search_error = stderr.strip() or (
                        f"File search command failed with exit code {exit_code}"
                    )
                    message = f"File search command failed: {search_error}"
                    log_level = "ERROR"
                else:
                    search_error = f"No files matching '{file_pattern}' found"
                    if empty_is_success:
                        message = f"{search_error}; treated as complete"
                        log_level = "INFO"
                    else:
                        message = f"{search_error}; collection incomplete"
                        log_level = "WARN"

                await self._write_to_dut_runtime_log(
                    dut_id,
                    log_level,
                    "HostService",
                    search_error,
                )

                # Handle summary generation using helper function
                output_files = await self._handle_collection_summary_generation(
                    dut_id=dut_id,
                    function_tag=function_tag,
                    collection_name=f"{function_tag} File Search",
                    total_operations=1,
                    successful_operations=1 if empty_is_success else 0,
                    failed_operations=0 if empty_is_success else 1,
                    output_files=[],
                    additional_details={
                        "file_pattern": file_pattern,
                        "search_directories": search_directories,
                        "found_files": [],  # No files found in this case
                        "error_messages": ([search_error] if search_failed else []),
                        **(
                            {"related_file_searches": related_file_search_details}
                            if related_file_search_details
                            else {}
                        ),
                    },
                    kwargs=kwargs,
                    collection_type="file_search_and_archive",
                    ignore_empty_results=empty_is_success,
                )

                return await self._create_standardized_collector_result(
                    successful_operations=1 if empty_is_success else 0,
                    total_operations=1,
                    output_files=output_files,
                    error_messages=[] if empty_is_success else [search_error],
                    operation_name="file_search_and_archive",
                    additional_context={
                        "message": message,
                        "file_pattern": file_pattern,
                        "search_directories": search_directories,
                        "ignore_empty_results": empty_is_success,
                        "search_exit_code": exit_code,
                        **(
                            {"related_file_searches": related_file_search_details}
                            if related_file_search_details
                            else {}
                        ),
                    },
                )

            found_files = [f.strip() for f in stdout.strip().split("\n") if f.strip()]
            candidate_files = list(found_files)
            rejected_files: List[str] = []
            trusted_primary_files: List[str] = []
            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"Found {len(found_files)} files: {found_files}",
            )

            def _matches_configured_trusted_path(file_path: str) -> bool:
                """
                Return whether ``file_path`` matches configured trusted path.

                The implementation uses ``file_path`` to determine whether
                ``file_path`` matches configured trusted path.

                Args:
                    file_path: filesystem location used as the file path for
                        this operation.

                Returns:
                    Whether ``file_path`` matches configured trusted path.
                """
                if any(delimiter in file_path for delimiter in ("\x00", "\r", "\n")):
                    return False
                primary_path = PurePosixPath(file_path)
                if (
                    not primary_path.is_absolute()
                    or ".." in primary_path.parts
                    or primary_path.as_posix() != file_path
                ):
                    return False
                matches_legacy_pattern = any(
                    fnmatchcase(file_path, str(pattern))
                    for pattern in trusted_path_patterns
                )
                return matches_legacy_pattern or any(
                    pattern.fullmatch(file_path) is not None
                    for pattern in trusted_path_regexes
                )

            header_validation_errors: List[str] = []
            if validate_headers:
                valid_files = []
                for file_path in found_files:
                    trusted_path = _matches_configured_trusted_path(file_path)
                    header_valid = False
                    header_error = None
                    if not trusted_path:
                        header_valid, header_error = await _has_required_headers(
                            file_path, required_headers, header_scan_lines
                        )
                    if trusted_path or header_valid:
                        valid_files.append(file_path)
                        if trusted_path:
                            trusted_primary_files.append(file_path)
                    else:
                        rejected_files.append(file_path)
                        if header_error:
                            header_validation_errors.append(header_error)
                if rejected_files:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "HostService",
                        "Skipping candidates that matched neither trusted "
                        "primary-path rules nor required headers: "
                        f"{rejected_files}",
                    )
                found_files = valid_files
                if not found_files:
                    validation_error = (
                        "No discovered files satisfied content/path validation"
                    )
                    empty_after_validation_is_success = bool(
                        ignore_empty_results
                        and ignore_empty_after_validation
                        and not header_validation_errors
                    )
                    validation_errors = (
                        []
                        if empty_after_validation_is_success
                        else [*header_validation_errors, validation_error]
                    )
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        ("INFO" if empty_after_validation_is_success else "ERROR"),
                        "HostService",
                        (
                            f"{validation_error}; treated as complete"
                            if empty_after_validation_is_success
                            else validation_error
                        ),
                    )
                    output_files = await self._handle_collection_summary_generation(
                        dut_id=dut_id,
                        function_tag=function_tag,
                        collection_name=f"{function_tag} File Search",
                        total_operations=1,
                        successful_operations=(
                            1 if empty_after_validation_is_success else 0
                        ),
                        failed_operations=(
                            0 if empty_after_validation_is_success else 1
                        ),
                        output_files=[],
                        additional_details={
                            "file_pattern": file_pattern,
                            "search_directories": search_directories,
                            "found_files": [],
                            "candidate_files": candidate_files,
                            "rejected_files": rejected_files,
                            "header_validation_errors": header_validation_errors,
                            "required_headers": required_headers,
                            "trusted_path_patterns": trusted_path_patterns,
                            "trusted_path_regexes": [
                                pattern.pattern for pattern in trusted_path_regexes
                            ],
                            "status_note_override": (
                                "All discovered candidates were rejected by "
                                "content/path validation"
                                + (
                                    "; treated as valid empty."
                                    if empty_after_validation_is_success
                                    else "."
                                )
                            ),
                            **(
                                {"related_file_searches": related_file_search_details}
                                if related_file_search_details
                                else {}
                            ),
                        },
                        kwargs=kwargs,
                        collection_type="file_search_and_archive",
                        ignore_empty_results=empty_after_validation_is_success,
                    )
                    return await self._create_standardized_collector_result(
                        successful_operations=(
                            1 if empty_after_validation_is_success else 0
                        ),
                        total_operations=1,
                        output_files=output_files,
                        error_messages=validation_errors,
                        operation_name="file_search_and_archive",
                        additional_context={
                            "message": (
                                f"{validation_error}; treated as complete"
                                if empty_after_validation_is_success
                                else validation_error
                            ),
                            "file_pattern": file_pattern,
                            "search_directories": search_directories,
                            "ignore_empty_results": empty_after_validation_is_success,
                            "ignore_empty_after_validation": (
                                ignore_empty_after_validation
                            ),
                            "header_validation_errors": header_validation_errors,
                            "required_headers": required_headers,
                            "trusted_path_patterns": trusted_path_patterns,
                            "trusted_path_regexes": [
                                pattern.pattern for pattern in trusted_path_regexes
                            ],
                            "candidate_files": candidate_files,
                            "rejected_files": rejected_files,
                            **(
                                {"related_file_searches": related_file_search_details}
                                if related_file_search_details
                                else {}
                            ),
                        },
                    )
            else:
                trusted_primary_files = [
                    file_path
                    for file_path in found_files
                    if _matches_configured_trusted_path(file_path)
                ]

            primary_found_files = list(found_files)
            related_search_successful_operations = 0
            related_search_total_operations = len(related_file_searches)
            related_search_error_messages: List[str] = []
            for related_search in related_file_searches:
                search_id = related_search["id"]
                search_details = related_file_search_details[search_id]
                anchor_directories: List[str] = []
                invalid_anchors: List[Dict[str, str]] = []
                for primary_file in trusted_primary_files:
                    primary_path = PurePosixPath(primary_file)
                    anchor_match = related_search["anchor"]["compiled_regex"].fullmatch(
                        primary_file
                    )
                    if anchor_match is None:
                        continue
                    anchor_value = anchor_match.group(
                        related_search["anchor"]["root_capture"]
                    )
                    if not isinstance(anchor_value, str) or not anchor_value:
                        invalid_anchors.append(
                            {
                                "path": primary_file,
                                "reason": "catalog anchor capture is empty",
                            }
                        )
                        continue
                    anchor_path = PurePosixPath(anchor_value)
                    if (
                        any(
                            delimiter in primary_file
                            for delimiter in ("\x00", "\r", "\n")
                        )
                        or not primary_path.is_absolute()
                        or ".." in primary_path.parts
                        or primary_path.as_posix() != primary_file
                        or not anchor_path.is_absolute()
                        or ".." in anchor_path.parts
                        or anchor_path.as_posix() != anchor_value
                        or primary_path == anchor_path
                        or not primary_path.is_relative_to(anchor_path)
                    ):
                        invalid_anchors.append(
                            {
                                "path": primary_file,
                                "reason": (
                                    "catalog anchor capture is not a normalized "
                                    "absolute ancestor"
                                ),
                            }
                        )
                        continue
                    anchor = anchor_path.as_posix()
                    if anchor not in anchor_directories:
                        anchor_directories.append(anchor)

                search_details["anchor_directories"] = anchor_directories
                search_details["rejected_anchors"] = invalid_anchors
                if invalid_anchors:
                    related_error = (
                        f"Related file search '{search_id}' produced an invalid "
                        "catalog anchor capture"
                    )
                    related_search_error_messages.append(related_error)
                    search_details["search_status"] = "error"
                    search_details["search_error"] = related_error
                    continue
                if not anchor_directories:
                    search_details["search_status"] = "not_run"
                    search_details["rejected_anchors"].extend(
                        {
                            "path": primary_file,
                            "reason": (
                                "accepted primary file is not independently trusted"
                                if primary_file not in trusted_primary_files
                                else (
                                    "accepted primary file did not match this related "
                                    "search's anchor rule"
                                )
                            ),
                        }
                        for primary_file in primary_found_files
                        if primary_file not in trusted_primary_files
                        or related_search["anchor"]["compiled_regex"].fullmatch(
                            primary_file
                        )
                        is None
                    )
                    # Header-validated primary files remain collectable, but
                    # they cannot expand a related search unless its catalog
                    # anchor expression explicitly matches and captures a root.
                    related_search_successful_operations += 1
                    continue

                quoted_anchors = " ".join(
                    shlex.quote(anchor) for anchor in anchor_directories
                )
                related_find_expression = f"find {quoted_anchors}"
                if same_filesystem:
                    related_find_expression += " -xdev"
                if prune_patterns:
                    related_prune_expression = " -o ".join(
                        f"-path {shlex.quote(pattern)}" for pattern in prune_patterns
                    )
                    related_find_expression += (
                        f" \\( {related_prune_expression} \\) -prune -o"
                    )
                match_config = related_search["match"]
                name_predicate = "-name" if match_config["case_sensitive"] else "-iname"
                related_find_expression += (
                    f" \\( {name_predicate} "
                    f"{shlex.quote(match_config['basename_glob'])} "
                    "-type f -print \\)"
                )
                related_find_command = f"bash -c {shlex.quote(related_find_expression)}"
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"Running related file search '{search_id}'",
                )
                (
                    related_exit_code,
                    related_stdout,
                    related_stderr,
                ) = await self.dut_manager.execute_host_command(
                    dut_id,
                    related_find_command,
                    timeout=related_search["search_timeout"],
                    use_sudo=use_sudo,
                )
                if related_exit_code != 0:
                    related_error = related_stderr.strip() or (
                        f"Related file search '{search_id}' failed with exit code "
                        f"{related_exit_code}"
                    )
                    related_search_error_messages.append(related_error)
                    search_details["search_status"] = "error"
                    search_details["search_error"] = related_error
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "HostService",
                        related_error,
                    )
                    continue

                related_candidates = list(
                    dict.fromkeys(
                        path.strip()
                        for path in related_stdout.splitlines()
                        if path.strip()
                    )
                )
                selection_config = related_search["selection"]
                (
                    selected_related_file,
                    selected_related_timestamp,
                    eligible_related_files,
                    superseded_related_files,
                    rejected_related_files,
                ) = _select_newest_timestamped_file(
                    related_candidates,
                    anchor_directories=anchor_directories,
                    file_pattern=match_config["basename_glob"],
                    case_sensitive=match_config["case_sensitive"],
                    selection_regex=selection_config["regex"],
                    capture=selection_config["capture"],
                    datetime_format=selection_config["format"],
                    tie_breaker=selection_config["tie_breaker"],
                )
                search_details.update(
                    {
                        "candidate_files": related_candidates,
                        "eligible_files": eligible_related_files,
                        "superseded_files": superseded_related_files,
                        "rejected_files": rejected_related_files,
                        "selected_file": selected_related_file,
                        "selected_timestamp": selected_related_timestamp,
                        "search_status": "success",
                    }
                )
                if rejected_related_files:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "HostService",
                        f"Related file search '{search_id}' rejected candidates: "
                        f"{rejected_related_files}",
                    )
                if related_candidates and not eligible_related_files:
                    related_error = (
                        f"Related file search '{search_id}' found candidates, but "
                        "none satisfied its selection contract"
                    )
                    related_search_error_messages.append(related_error)
                    search_details["search_status"] = "error"
                    search_details["search_error"] = related_error
                    continue

                related_search_successful_operations += 1
                if (
                    selected_related_file is not None
                    and selected_related_file not in found_files
                ):
                    found_files.append(selected_related_file)
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "HostService",
                        f"Related file search '{search_id}' selected: "
                        f"{selected_related_file}",
                    )

            # Step 2: Process files based on configuration
            output_files = []
            status_list = []
            error_messages = [
                *header_validation_errors,
                *related_search_error_messages,
            ]
            successful_operations = related_search_successful_operations
            total_operations = related_search_total_operations + len(
                header_validation_errors
            )
            processed_files: List[str] = []
            failed_files: List[str] = []
            if self.timing_manager:
                acquisition_timing_id = self.timing_manager.start_operation(
                    "host_file_acquisition",
                    function_tag,
                    metadata={
                        "transport": "host_file_transfer",
                        "source": "file_search_and_archive",
                        "source_file_count": len(found_files),
                    },
                    compact_artifact_on_limit=True,
                )

            for file_path in found_files:
                total_operations += 1
                source_timing_id = None
                if self.timing_manager:
                    source_timing_id = self.timing_manager.start_operation(
                        "host_source_file_acquisition",
                        file_path,
                        parent_id=acquisition_timing_id,
                        metadata={
                            "transport": "host_file_transfer",
                            "source": "file_search_and_archive",
                            "source_path": file_path,
                        },
                    )
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"Processing file: {file_path}",
                )

                # Get working directory
                dir_command = build_remote_cmd("dirname -- {path}", path=file_path)
                try:
                    exit_code, stdout, _ = await self.dut_manager.execute_host_command(
                        dut_id, dir_command, timeout=60, use_sudo=use_sudo
                    )
                except asyncio.CancelledError:
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            source_timing_id,
                            status="cancelled",
                            error="CancelledError",
                        )
                    raise
                except Exception as exc:
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            source_timing_id, status="error", error=str(exc)
                        )
                    raise

                if exit_code != 0:
                    source_error = f"Failed to get directory for {file_path}"
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            source_timing_id,
                            status="error",
                            error=source_error,
                        )
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "HostService",
                        source_error,
                    )
                    error_messages.append(source_error)
                    status_list.append(False)
                    failed_files.append(file_path)

                    # Create error log file for failed operations
                    error_log_path = await self._create_error_log_file(
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id"),
                        error_message=source_error,
                        context={
                            "file_path": file_path,
                            "operation": "file_collection",
                            "exit_code": exit_code,
                        },
                    )

                    # Add error log file to output files
                    if error_log_path:
                        output_files.append(error_log_path)
                    continue

                working_dir = stdout.strip()

                # Apply processing logic based on configuration
                # Pass archived_dir (or collector_output_dir) when archiving is enabled
                try:
                    (
                        processing_success,
                        saved_file_path,
                    ) = await self._process_file_with_config(
                        dut_id,
                        file_path,
                        working_dir,
                        search_config,
                        archive_config,
                        output_pattern,
                        filtered_kwargs,
                        use_sudo,
                        collector_output_dir=(archived_dir if archived_dir else None),
                    )
                except asyncio.CancelledError:
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            source_timing_id,
                            status="cancelled",
                            error="CancelledError",
                        )
                    raise
                except Exception as exc:
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            source_timing_id, status="error", error=str(exc)
                        )
                    raise

                source_error = (
                    None
                    if processing_success
                    else f"Failed to process file: {file_path}"
                )
                if self.timing_manager:
                    self.timing_manager.end_operation(
                        source_timing_id,
                        status="success" if processing_success else "error",
                        error=source_error,
                    )

                if processing_success:
                    status_list.append(True)
                    successful_operations += 1
                    # Track at least one data artifact so finalize doesn't mark as skipped
                    processed_files.append(file_path)
                    if saved_file_path:
                        output_files.append(saved_file_path)
                else:
                    status_list.append(False)
                    error_messages.append(source_error)
                    failed_files.append(file_path)

                    # Create error log file for failed operations
                    error_log_path = await self._create_error_log_file(
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id"),
                        error_message=source_error,
                        context={
                            "file_path": file_path,
                            "operation": "file_processing",
                        },
                    )

                    # Add error log file to output files
                    if error_log_path:
                        output_files.append(error_log_path)

            # Determine overall status
            successful_files = sum(status_list)
            total_files = len(found_files)
            successful_primary_files = [
                file_path
                for file_path in primary_found_files
                if file_path in processed_files
            ]
            all_primary_processing_failed = bool(primary_found_files) and not (
                successful_primary_files
            )

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"File search and archive completed: {successful_files}/{total_files} files successful",
            )

            # A requested aggregate archive is part of a successful collection,
            # not a best-effort afterthought.  Count publication as an explicit
            # operation whenever at least one primary artifact was staged so a
            # missing/empty staging directory or tar publication failure cannot
            # be reported as a successful collection.
            archive_required = archive_files and bool(successful_primary_files)
            final_archive_path = None
            archive_error = None
            if archive_required:
                total_operations += 1
                if archived_dir is None:
                    archive_error = (
                        "Failed to publish required archive: staging directory "
                        "is unavailable"
                    )
                elif not archived_dir.exists():
                    archive_error = (
                        "Failed to publish required archive: staging directory "
                        f"does not exist: {archived_dir}"
                    )

            if archive_required and archive_error is None:
                try:
                    # Check if directory has content (ignore status.json)
                    has_content = False
                    for item in archived_dir.iterdir():
                        if item.name != "status.json":
                            has_content = True
                            break

                    if has_content:
                        # Create tarball in the collector output directory
                        # Name tarball based on the archived subdirectory name
                        archive_path = (
                            collector_output_dir / f"{archived_dir.name}.tar.gz"
                        )

                        _publish_tar_gz_atomically(
                            archive_path,
                            [(archived_dir, archived_dir.name, True)],
                            archive_limits=(
                                archive_creation_limits_from_runtime_boundaries(
                                    self._runtime_boundaries(dut_id)
                                )
                            ),
                        )

                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "HostService",
                            f"Successfully created archive: {archive_path}",
                        )

                        # Append the tarball to output_files
                        output_files.append(str(archive_path))
                        final_archive_path = str(archive_path)
                        successful_operations += 1

                        # Cleanup staging directory after successful archive creation
                        total_operations += 1
                        try:
                            shutil.rmtree(str(archived_dir))
                            successful_operations += 1
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "HostService",
                                f"Cleaned up archived files directory: {archived_dir}",
                            )
                        except Exception as cleanup_err:
                            cleanup_error = (
                                "Failed to cleanup staging directory after archive "
                                f"publication: {cleanup_err}"
                            )
                            error_messages.append(cleanup_error)
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "WARN",
                                "HostService",
                                cleanup_error,
                            )
                    else:
                        archive_error = (
                            "Failed to publish required archive: staging directory "
                            f"contains no collected artifacts: {archived_dir}"
                        )
                except Exception as archive_err:
                    archive_error = f"Failed to publish required archive: {archive_err}"

            if archive_error:
                error_messages.append(archive_error)
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    archive_error,
                )

            # Generate the summary after publication so its operation counts and
            # errors describe whether the required aggregate archive exists.
            output_files = await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=function_tag,
                collection_name=f"{function_tag} File Search",
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=max(0, total_operations - successful_operations),
                output_files=output_files,
                additional_details={
                    "file_pattern": file_pattern,
                    "search_directories": search_directories,
                    "found_files": found_files,
                    "candidate_files": candidate_files,
                    "rejected_files": rejected_files,
                    "header_validation_errors": header_validation_errors,
                    "processed_files": processed_files,
                    "failed_files": failed_files,
                    "error_messages": error_messages,
                    **(
                        {
                            "processed_source_identities": [
                                hashlib.sha256(path.encode("utf-8")).hexdigest()
                                for path in processed_files
                            ]
                        }
                        if related_file_search_details and processed_files
                        else {}
                    ),
                    **(
                        {
                            "status_note_override": (
                                "All primary discovered files failed to process."
                            )
                        }
                        if all_primary_processing_failed
                        else {}
                    ),
                    **(
                        {"related_file_searches": related_file_search_details}
                        if related_file_search_details
                        else {}
                    ),
                },
                kwargs=kwargs,
                collection_type="file_search_and_archive",
                ignore_empty_results=ignore_empty_results,
            )

            if self.timing_manager:
                if archive_required and final_archive_path is None:
                    acquisition_status = "error"
                    acquisition_error = "No final archive was produced"
                    acquisition_artifacts = []
                else:
                    if all_primary_processing_failed:
                        acquisition_status = "error"
                    else:
                        acquisition_status = (
                            "success"
                            if successful_operations == total_operations
                            else ("partial" if successful_operations else "error")
                        )
                    acquisition_error = (
                        "; ".join(error_messages) if error_messages else None
                    )
                    acquisition_artifacts = (
                        [final_archive_path]
                        if final_archive_path
                        else [str(path) for path in output_files if path]
                    )
                self.timing_manager.end_operation(
                    acquisition_timing_id,
                    status=acquisition_status,
                    artifact_paths=acquisition_artifacts,
                    error=acquisition_error,
                )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="file_search_and_archive",
                additional_context={
                    "message": "File search and archive completed",
                    "files_found": total_files,
                    "successful_files": successful_files,
                    "total_files": total_files,
                    "ignore_empty_results": ignore_empty_results,
                    "processed_files": processed_files,
                    "failed_files": failed_files,
                    "candidate_files": candidate_files,
                    "rejected_files": rejected_files,
                    "header_validation_errors": header_validation_errors,
                    **(
                        {
                            "status": "error",
                            "reason": (
                                "All primary discovered files failed to process"
                            ),
                        }
                        if all_primary_processing_failed
                        else {}
                    ),
                    **(
                        {"related_file_searches": related_file_search_details}
                        if related_file_search_details
                        else {}
                    ),
                },
            )

        try:
            result = await self._execute_with_error_handling(
                dut_id, "file_search_and_archive", _file_search_and_archive
            )
        except asyncio.CancelledError:
            if self.timing_manager:
                self.timing_manager.end_operation(
                    acquisition_timing_id,
                    status="cancelled",
                    error="CancelledError",
                )
            raise

        # _execute_with_error_handling converts ordinary exceptions to an error
        # result. Close a span left open by that path; a normally completed span
        # is already closed, so TimingManager treats this as a no-op.
        if self.timing_manager:
            self.timing_manager.end_operation(
                acquisition_timing_id,
                status="error",
                error=str(result.get("reason") or result.get("error_message") or ""),
            )
        return result

    async def _handle_host_device_based_log_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Generic handler for device-based log collection (used by H17, etc.).

        After applying local validation, the function forwards ``dut_id``,
        ``function_tag``, and ``kwargs`` to
        ``self._execute_with_error_handling`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing handle host device based log collection.
        """

        owned_stages: List[_RemoteStagingDirectory] = []

        async def _device_based_log_collection():
            """
            Handle device-based log collection.

            The implementation uses current instance state to handle
            device-based log collection. Terminal status is emitted only after
            device-based log collection and its owned cleanup have completed.
            Owned asynchronous work is awaited before return, so completion does
            not leave an unobserved task behind. If the function cannot handle
            device-based log collection, its exception reaches the caller
            instead of being converted into a successful result. Cleanup in the
            ``finally`` path runs for successful, failed, and cancelled
            execution.

            Returns:
                The terminal result of the device-based log collection.

            Raises:
                FileNotFoundError: If no local device directory found for
                    ``device_name``; or no downloaded files found for
                    ``device_name``.
            """
            device_detection = kwargs.get("device_detection", {})
            log_commands = kwargs.get("log_commands", [])
            use_sudo = kwargs.get("use_sudo", True)
            collector_def = kwargs.get("collector_def", {}) or {}
            enforce_wall_timeout = bool(
                kwargs.get(
                    "enforce_wall_timeout",
                    collector_def.get("enforce_wall_timeout", False),
                )
            )
            deadline = None
            if enforce_wall_timeout:
                wall_timeout = await self._resolve_collector_timeout(
                    dut_id,
                    kwargs,
                    default_timeout=300,
                    explicit_timeout_sources=[collector_def, kwargs],
                    explicit_timeout_keys=("wall_timeout", "timeout"),
                )
                deadline = time.monotonic() + wall_timeout

            def bounded_timeout(requested_timeout: float) -> float:
                """
                Return the bounded timeout.

                The implementation uses ``requested_timeout`` to produce the
                bounded timeout.

                Args:
                    requested_timeout: Maximum duration in seconds allowed for
                        requested timeout.

                Returns:
                    The numeric bounded timeout value.
                """
                if deadline is None:
                    return requested_timeout
                return max(
                    0.0,
                    min(float(requested_timeout), deadline - time.monotonic()),
                )

            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                "Starting device-based log collection",
            )

            # Step 1: Device detection
            detection_command = device_detection.get("command", "")
            device_pattern = device_detection.get("device_pattern")
            skip_message = device_detection.get("skip_message", "No devices found")

            if not detection_command:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    "No device detection command specified",
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=["No device detection command specified"],
                    operation_name="device_based_log_collection",
                    additional_context={"device_detection": device_detection},
                )

            try:
                _bounded_device_matches(device_pattern, "")
            except ValueError as exc:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[str(exc)],
                    operation_name="device_based_log_collection",
                    additional_context={"status": "error", "reason": str(exc)},
                )

            detection_timeout = await self._resolve_collector_timeout(
                dut_id,
                kwargs,
                default_timeout=300,
                explicit_timeout_sources=[device_detection, kwargs],
            )
            detection_timeout = bounded_timeout(detection_timeout)
            if detection_timeout <= 0:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[
                        "Collector wall-clock deadline expired before device detection"
                    ],
                    operation_name="device_based_log_collection",
                )

            exit_code, stdout, stderr = await self._execute_host_command_with_capture(
                dut_id,
                detection_command,
                operation_name="device_based_log_detection",
                timeout=detection_timeout,
                use_sudo=use_sudo,
                collector_id=kwargs.get("collector_id"),
            )

            if exit_code != 0:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "WARN",
                    "HostService",
                    f"Device detection failed: {stderr}",
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[f"Device detection failed: {stderr}"],
                    operation_name="device_based_log_collection",
                    additional_context={
                        "message": skip_message,
                        "detection_command": detection_command,
                    },
                )

            # Parse a bounded device list. The pattern is mandatory so a catalog
            # omission cannot silently turn arbitrary endpoint tokens into shell
            # template values.
            try:
                matches = _bounded_device_matches(device_pattern, stdout)
            except ValueError as exc:
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=1,
                    output_files=[],
                    error_messages=[str(exc)],
                    operation_name="device_based_log_collection",
                    additional_context={"status": "error", "reason": str(exc)},
                )

            if not matches:
                await self._write_to_dut_runtime_log(
                    dut_id, "INFO", "HostService", "No devices found"
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[],
                    operation_name="device_based_log_collection",
                    additional_context={
                        "message": skip_message,
                        "device_pattern": device_pattern,
                    },
                )

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"Found {len(matches)} devices",
            )

            # Step 2: Prepare every target, then run cheap/required commands across
            # all devices before optional commands.  This prevents one slow
            # telemetry operation from starving later devices of basic logs.
            normalized_matches = matches
            output_files: List[str] = []
            error_messages: List[str] = []
            skipped_commands: List[Dict[str, str]] = []
            executed_commands: List[str] = []
            successful_operations = 0
            total_operations = 0
            deadline_exceeded = False
            host_lost = False

            configured_retry_budget = kwargs.get(
                "shared_retry_budget",
                collector_def.get("shared_retry_budget"),
            )
            try:
                retry_budget = (
                    max(0, int(configured_retry_budget))
                    if configured_retry_budget is not None
                    else None
                )
            except (TypeError, ValueError):
                retry_budget = 0

            def allocate_attempts(requested: Any) -> int:
                """
                Return the allocate attempts.

                The implementation uses ``requested`` to produce the allocate
                attempts.

                Args:
                    requested: Requested consumed while the function attempts to
                        produce the allocate attempts.

                Returns:
                    The validated ``attempts``.
                """
                nonlocal retry_budget
                try:
                    attempts = max(1, int(requested))
                except (TypeError, ValueError):
                    attempts = 1
                if retry_budget is not None:
                    attempts = min(attempts, 1 + retry_budget)
                return attempts

            def consume_failed_retries(attempts: int, exit_code: int) -> None:
                """
                Consume failed retries.

                The implementation uses ``attempts`` and ``exit_code`` to
                consume failed retries.

                Args:
                    attempts: Numeric attempts used while the operation performs
                        bounded accounting.
                    exit_code: Numeric exit code used while the operation
                        performs bounded accounting.
                """
                nonlocal retry_budget
                if retry_budget is not None and exit_code != 0:
                    retry_budget = max(0, retry_budget - max(0, attempts - 1))

            def looks_like_host_loss(exit_code: int, message: str) -> bool:
                """
                Return whether ``exit_code`` looks like host loss.

                Command/channel failures are not proof that the host itself is
                gone; the next independent SSH connection can recover.

                Args:
                    exit_code: Numeric exit code used while the operation
                        performs bounded accounting.
                    message: Operator-facing text carried by the reported event
                        or failure.

                Returns:
                    Whether ``exit_code`` looks like host loss.
                """
                if exit_code == 0:
                    return False
                lowered = (message or "").lower()
                # Command/channel failures are not proof that the host itself
                # is gone; the next independent SSH connection can recover.
                if (
                    "command timed out" in lowered
                    or "channel not open for sending" in lowered
                ):
                    return False
                markers = (
                    "not connected",
                    "not reachable",
                    "failed to connect",
                    "connection refused",
                    "connection reset",
                    "connection closed",
                    "connection timed out",
                    "connection timeout",
                    "connection/retry budget",
                    "no route to host",
                    "network is unreachable",
                    "ssh connection failed",
                )
                return exit_code == -1 and any(marker in lowered for marker in markers)

            def evaluate_capability(
                capability: Dict[str, Any], stdout_value: str
            ) -> bool:
                """
                Return the evaluate capability.

                The implementation uses ``capability`` and ``stdout_value`` to
                produce the evaluate capability.

                Args:
                    capability: Mapping supplying fields for evaluate
                        capability.
                    stdout_value: Text supplied as stdout value in the format
                        accepted by this function.

                Returns:
                    Whether the evaluate capability operation succeeds.
                """
                if "json_field" in capability:
                    try:
                        value: Any = json.loads(stdout_value)
                        for part in str(capability["json_field"]).split("."):
                            value = value[part]
                        if "bitmask" in capability:
                            numeric = (
                                int(value, 0) if isinstance(value, str) else int(value)
                            )
                            return bool(numeric & int(capability["bitmask"]))
                        if "equals" in capability:
                            return value == capability["equals"]
                        return bool(value)
                    except (
                        KeyError,
                        TypeError,
                        ValueError,
                        json.JSONDecodeError,
                    ):
                        return False
                supported_pattern = capability.get("supported_pattern")
                if supported_pattern:
                    return bool(
                        re.search(str(supported_pattern), stdout_value, re.MULTILINE)
                    )
                unsupported_pattern = capability.get("unsupported_pattern")
                if unsupported_pattern:
                    return not bool(
                        re.search(
                            str(unsupported_pattern),
                            stdout_value,
                            re.MULTILINE,
                        )
                    )
                return True

            base_temp_dir = await self._resolve_remote_staging_root(
                dut_id, kwargs.get("remote_staging_root")
            )
            device_states: List[Dict[str, Any]] = []
            for device in normalized_matches:
                try:
                    device_name = _safe_remote_output_component(
                        os.path.basename(device)
                    )
                except ValueError as exc:
                    total_operations += 1
                    error_messages.append(f"Rejected device identifier: {exc}")
                    continue
                state = {
                    "device": device,
                    "device_name": device_name,
                    "ready": True,
                    "errors": [],
                    "commands": [],
                    "transferred": 0,
                    "output_dir": None,
                }
                device_states.append(state)
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"Preparing log collection for device: {device_name}",
                )

            required_commands = [
                command
                for command in log_commands
                if not command.get("optional", False)
                and command.get("phase", "required") not in {"optional", "expensive"}
            ]
            optional_commands = [
                command for command in log_commands if command not in required_commands
            ]
            capability_cache: Dict[Tuple[str, str], Tuple[bool, str]] = {}
            command_failure_counts: Dict[int, int] = {}

            for command_index, cmd_config in enumerate(
                required_commands + optional_commands
            ):
                raw_max_failures = cmd_config.get("max_failures", 0)
                max_failures_is_valid = (
                    type(raw_max_failures) is int and raw_max_failures >= 0
                )
                max_failures = raw_max_failures if max_failures_is_valid else 0
                for state in device_states:
                    if not state["ready"] or host_lost or deadline_exceeded:
                        continue

                    device = state["device"]
                    device_name = state["device_name"]
                    description = cmd_config.get("description", "Log command")

                    if not max_failures_is_valid:
                        total_operations += 1
                        message = (
                            f"Invalid max_failures for {description} on {device_name}: "
                            "max_failures must be a non-negative integer"
                        )
                        state["errors"].append(message)
                        error_messages.append(message)
                        state["commands"].append(
                            {
                                "description": description,
                                "status": "error",
                                "reason": message,
                            }
                        )
                        continue

                    if (
                        max_failures > 0
                        and command_failure_counts.get(command_index, 0) >= max_failures
                    ):
                        circuit_reason = (
                            f"failure budget exhausted after {max_failures} "
                            "failed device command(s)"
                        )
                        skipped_commands.append(
                            {
                                "device": device_name,
                                "command": description,
                                "reason": circuit_reason,
                            }
                        )
                        state["commands"].append(
                            {
                                "description": description,
                                "status": "skipped",
                                "reason": circuit_reason,
                            }
                        )
                        continue

                    capability = cmd_config.get("capability_check")
                    if capability:
                        if not isinstance(capability, dict) or not capability.get(
                            "command_template"
                        ):
                            total_operations += 1
                            message = (
                                f"Invalid capability_check for {description} on "
                                f"{device_name}: command_template is required"
                            )
                            state["errors"].append(message)
                            error_messages.append(message)
                            state["commands"].append(
                                {
                                    "description": description,
                                    "status": "error",
                                    "reason": message,
                                }
                            )
                            continue
                        capability_key = (
                            device,
                            json.dumps(capability, sort_keys=True),
                        )
                        supported, capability_reason = capability_cache.get(
                            capability_key, (False, "")
                        )
                        if capability_key not in capability_cache:
                            capability_template = capability.get("command_template", "")
                            # Route through build_remote_cmd so the fail-closed
                            # template placeholder-context guard applies: raw
                            # values are shlex-quoted internally, and a template
                            # that ever placed a placeholder inside a quoted or
                            # nested shell context is rejected instead of quietly
                            # producing an injectable command.
                            try:
                                capability_command = build_remote_cmd(
                                    capability_template,
                                    device=device,
                                    device_name=device_name,
                                )
                            except (KeyError, IndexError, ValueError) as exc:
                                total_operations += 1
                                message = (
                                    f"Invalid capability_check for {description} on "
                                    f"{device_name}: {exc}"
                                )
                                state["errors"].append(message)
                                error_messages.append(message)
                                state["commands"].append(
                                    {
                                        "description": description,
                                        "status": "error",
                                        "reason": message,
                                    }
                                )
                                continue
                            capability_timeout = bounded_timeout(
                                capability.get("timeout", 15)
                            )
                            if capability_timeout <= 0:
                                deadline_exceeded = True
                                break
                            (
                                cap_exit,
                                cap_stdout,
                                cap_stderr,
                            ) = await self._execute_host_command_with_capture(
                                dut_id,
                                capability_command,
                                operation_name=(
                                    f"device_log_capability_{description}_{device_name}"
                                ),
                                timeout=capability_timeout,
                                max_retries=1,
                                use_sudo=use_sudo,
                                collector_id=kwargs.get("collector_id"),
                            )
                            supported = cap_exit == 0 and evaluate_capability(
                                capability, cap_stdout
                            )
                            capability_reason = (
                                "capability not advertised"
                                if cap_exit == 0
                                else f"capability probe failed: {cap_stderr}"
                            )
                            capability_cache[capability_key] = (
                                supported,
                                capability_reason,
                            )
                            if looks_like_host_loss(cap_exit, cap_stderr):
                                host_lost = True
                                break
                        if not supported:
                            skipped_commands.append(
                                {
                                    "device": device_name,
                                    "command": description,
                                    "reason": capability_reason,
                                }
                            )
                            state["commands"].append(
                                {
                                    "description": description,
                                    "status": "skipped",
                                    "reason": capability_reason,
                                }
                            )
                            continue

                    requested_timeout = await self._resolve_collector_timeout(
                        dut_id,
                        kwargs,
                        default_timeout=300,
                        explicit_timeout_sources=[cmd_config, kwargs],
                    )
                    command_max_artifact_bytes = _resolve_host_artifact_max_bytes(
                        cmd_config,
                        kwargs,
                    )
                    command_timeout = bounded_timeout(requested_timeout)
                    if command_timeout <= 0:
                        deadline_exceeded = True
                        break

                    try:
                        filename = _safe_remote_output_component(
                            cmd_config.get("file_template", "").format(
                                device=device,
                                device_name=device_name,
                            )
                        )
                    except (KeyError, ValueError) as exc:
                        total_operations += 1
                        message = f"Invalid output filename for {device_name}: {exc}"
                        state["errors"].append(message)
                        error_messages.append(message)
                        state["commands"].append(
                            {
                                "description": description,
                                "status": "error",
                                "reason": message,
                            }
                        )
                        continue
                    try:
                        command_stage = await self._create_remote_staging_directory(
                            dut_id,
                            f"{kwargs.get('collector_id') or function_tag}-{device_name}",
                            use_sudo=use_sudo,
                            owned_stages=owned_stages,
                            configured_root=base_temp_dir,
                        )
                        host_output_file = self._remote_staging_file_path(
                            command_stage, filename
                        )
                    except Exception as exc:
                        total_operations += 1
                        message = (
                            f"Failed to create private staging for {device_name}: {exc}"
                        )
                        state["errors"].append(message)
                        error_messages.append(message)
                        continue
                    # Assemble via build_remote_cmd (raw values quoted internally)
                    # so the same template placeholder-context guardrail used by
                    # the BMC device path and dependency_checker applies here: a
                    # mis-authored template with a placeholder in a quoted/nested
                    # shell context is refused rather than silently injectable.
                    try:
                        command = build_remote_cmd(
                            cmd_config.get("command_template", ""),
                            device=device,
                            device_name=device_name,
                            output_file=host_output_file,
                        )
                    except (KeyError, IndexError, ValueError) as exc:
                        total_operations += 1
                        message = (
                            f"Invalid command_template for {description} on "
                            f"{device_name}: {exc}"
                        )
                        state["errors"].append(message)
                        error_messages.append(message)
                        continue
                    direct_file_output = cmd_config.get("direct_file_output", False)
                    if direct_file_output:
                        command_to_run = command
                        readable_command = command
                    else:
                        readable_command = f"{command} > {quote_arg(host_output_file)}"
                        command_to_run = f"bash -c {shlex.quote(readable_command)}"

                    attempts = allocate_attempts(cmd_config.get("max_retries", 1))
                    total_operations += 1
                    try:
                        (
                            exit_code,
                            _,
                            stderr,
                        ) = await self._execute_host_command_with_capture(
                            dut_id,
                            command_to_run,
                            operation_name=(f"device_log_{description}_{device_name}"),
                            timeout=command_timeout,
                            max_retries=attempts,
                            use_sudo=use_sudo,
                            collector_id=kwargs.get("collector_id"),
                            output_file=filename,
                        )
                    finally:
                        executed_commands.append(readable_command)
                    consume_failed_retries(attempts, exit_code)

                    if exit_code != 0:
                        command_failure_counts[command_index] = (
                            command_failure_counts.get(command_index, 0) + 1
                        )
                        message = f"Failed to collect {description} for {device_name}: {stderr}"
                        state["errors"].append(message)
                        state["commands"].append(
                            {
                                "description": description,
                                "status": "error",
                                "reason": stderr,
                            }
                        )
                        error_messages.append(message)
                        await self._write_to_dut_runtime_log(
                            dut_id, "WARN", "HostService", message
                        )
                        host_lost = looks_like_host_loss(exit_code, stderr)
                        continue

                    (
                        prepared,
                        permission_error,
                    ) = await self._prepare_remote_staging_files(
                        dut_id,
                        command_stage,
                        [host_output_file],
                    )
                    if not prepared:
                        message = (
                            f"Failed to prepare exact output for {device_name}: "
                            f"{permission_error}"
                        )
                        state["errors"].append(message)
                        state["commands"].append(
                            {
                                "description": description,
                                "status": "error",
                                "reason": message,
                            }
                        )
                        error_messages.append(message)
                        await self._write_to_dut_runtime_log(
                            dut_id, "WARN", "HostService", message
                        )
                        continue

                    collector_id = kwargs.get("collector_id")
                    original_collector_id = await self._get_original_collector_id(
                        dut_id, collector_id
                    )
                    await self._log_runtime(
                        "DEBUG",
                        "HostService",
                        f"File path determination - collector_id: {collector_id}, original_collector_id: {original_collector_id}",
                    )
                    file_collector_id = (
                        original_collector_id
                        if original_collector_id != "unknown"
                        else collector_id
                    )
                    if (
                        original_collector_id != "unknown"
                        and original_collector_id != collector_id
                    ):
                        await self._log_runtime(
                            "WARNING",
                            "HostService",
                            f"Using original collector ID '{original_collector_id}' for file paths while current context is '{collector_id}'",
                        )

                    temp_file_path = await self.logger.create_collector_log_file(
                        dut_id, "host", file_collector_id, "temp.bin"
                    )
                    if not temp_file_path:
                        message = f"Unable to resolve local output directory for {device_name}"
                        state["errors"].append(message)
                        state["commands"].append(
                            {
                                "description": description,
                                "status": "error",
                                "reason": message,
                            }
                        )
                        error_messages.append(message)
                        continue
                    collector_output_dir = str(Path(temp_file_path).parent)
                    device_output_dir = os.path.join(
                        collector_output_dir, f"device_{device_name}"
                    )
                    os.makedirs(device_output_dir, exist_ok=True)
                    state["output_dir"] = device_output_dir
                    transfer_timeout = (
                        None
                        if deadline is None
                        else max(0.0, deadline - time.monotonic())
                    )
                    if transfer_timeout is not None and transfer_timeout <= 0:
                        deadline_exceeded = True
                        transfer_success = False
                        transfer_error = "Collector wall-clock deadline exceeded"
                    else:
                        local_artifact_path = os.path.join(
                            device_output_dir,
                            os.path.basename(host_output_file),
                        )
                        acquisition_timing_id = None
                        persistence_timing_id = None
                        if self.timing_manager:
                            acquisition_timing_id = self.timing_manager.start_operation(
                                "host_file_acquisition",
                                os.path.basename(host_output_file) or host_output_file,
                                metadata={"transport": "host_file_transfer"},
                                compact_artifact_on_limit=True,
                            )
                            persistence_timing_id = self.timing_manager.start_operation(
                                "artifact_persistence",
                                os.path.basename(local_artifact_path)
                                or local_artifact_path,
                                metadata={"source": "host_file_transfer"},
                            )
                        try:
                            transfer_coro = self.dut_manager.transfer_host_files(
                                dut_id,
                                host_output_file,
                                device_output_dir,
                                copy_to_destination=False,
                                max_bytes=command_max_artifact_bytes,
                            )
                            if transfer_timeout is None:
                                transfer_success, transfer_error = await transfer_coro
                            else:
                                (
                                    transfer_success,
                                    transfer_error,
                                ) = await asyncio.wait_for(
                                    transfer_coro, timeout=transfer_timeout
                                )
                        except asyncio.CancelledError:
                            if self.timing_manager:
                                self.timing_manager.end_operation(
                                    persistence_timing_id,
                                    status="cancelled",
                                    error="CancelledError",
                                )
                                self.timing_manager.end_operation(
                                    acquisition_timing_id,
                                    status="cancelled",
                                    error="CancelledError",
                                )
                            raise
                        except asyncio.TimeoutError:
                            deadline_exceeded = True
                            transfer_success = False
                            transfer_error = "Collector wall-clock deadline exceeded during file transfer"
                        except BaseException as exc:
                            if self.timing_manager:
                                self.timing_manager.end_operation(
                                    persistence_timing_id,
                                    status="error",
                                    error=str(exc),
                                )
                                self.timing_manager.end_operation(
                                    acquisition_timing_id,
                                    status="error",
                                    error=str(exc),
                                )
                            raise

                        if self.timing_manager:
                            if transfer_success:
                                try:
                                    artifact_size = os.path.getsize(local_artifact_path)
                                except OSError:
                                    artifact_size = None
                                self.timing_manager.end_operation(
                                    persistence_timing_id,
                                    status="success",
                                    artifact_path=local_artifact_path,
                                    size_bytes=artifact_size,
                                )
                                self.timing_manager.end_operation(
                                    acquisition_timing_id,
                                    status="success",
                                    artifact_path=local_artifact_path,
                                    size_bytes=artifact_size,
                                )
                            else:
                                self.timing_manager.end_operation(
                                    persistence_timing_id,
                                    status="error",
                                    error=str(transfer_error),
                                )
                                self.timing_manager.end_operation(
                                    acquisition_timing_id,
                                    status="error",
                                    error=str(transfer_error),
                                )
                    if not transfer_success:
                        message = f"Failed to download {filename}: {transfer_error}"
                        state["errors"].append(message)
                        state["commands"].append(
                            {
                                "description": description,
                                "status": "error",
                                "reason": transfer_error,
                            }
                        )
                        error_messages.append(message)
                        await self._write_to_dut_runtime_log(
                            dut_id, "WARN", "HostService", message
                        )
                        host_lost = host_lost or looks_like_host_loss(
                            -1, transfer_error
                        )
                        continue

                    state["transferred"] += 1
                    successful_operations += 1
                    state["commands"].append(
                        {"description": description, "status": "success"}
                    )

            if deadline_exceeded:
                if successful_operations == total_operations:
                    total_operations += 1
                deadline_message = "Collector wall-clock deadline exceeded"
                if deadline_message not in error_messages:
                    error_messages.append(deadline_message)
                await self._write_to_dut_runtime_log(
                    dut_id, "WARN", "HostService", deadline_message
                )

            successful_devices = 0
            for state in device_states:
                device_name = state["device_name"]
                device_output_dir = state["output_dir"]
                if state["transferred"] and device_output_dir:
                    try:
                        if not os.path.exists(device_output_dir):
                            raise FileNotFoundError(
                                f"No local device directory found for {device_name}"
                            )
                        device_files = sorted(
                            os.path.join(device_output_dir, filename)
                            for filename in os.listdir(device_output_dir)
                            if os.path.isfile(os.path.join(device_output_dir, filename))
                        )
                        if not device_files:
                            raise FileNotFoundError(
                                f"No downloaded files found for {device_name}"
                            )
                        # Output accounting and timing are file-semantic.  Do
                        # not publish the containing directory as a binary
                        # pseudo-artifact when the transferred files are known.
                        output_files.extend(device_files)
                        if not state["errors"]:
                            successful_devices += 1
                    except Exception as exc:
                        successful_operations = max(
                            0, successful_operations - state["transferred"]
                        )
                        message = f"Error processing device directory for {device_name}: {exc}"
                        state["errors"].append(message)
                        error_messages.append(message)

                if state["errors"]:
                    error_log_path = await self._create_error_log_file(
                        dut_id=dut_id,
                        collector_id=kwargs.get("collector_id"),
                        error_message="\n".join(state["errors"]),
                        context={
                            "device_name": device_name,
                            "operation": "device_log_collection",
                            "command_results": state["commands"],
                        },
                    )
                    if error_log_path:
                        output_files.append(error_log_path)

            total_devices = len(device_states)
            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                (
                    "Device-based log collection completed: "
                    f"{successful_operations}/{total_operations} command operations "
                    f"across {total_devices} devices"
                ),
            )

            output_files = await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=function_tag,
                collection_name=f"{function_tag} Device Log Collection",
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=max(0, total_operations - successful_operations),
                output_files=output_files,
                additional_details={
                    "Detection command": detection_command,
                    "Device pattern": device_pattern,
                    "Devices found": total_devices,
                    "Log commands": (
                        executed_commands
                        if executed_commands
                        else [
                            command.get("command_template", command.get("command", ""))
                            for command in log_commands
                        ]
                    ),
                    "Skipped commands": skipped_commands,
                },
                kwargs=kwargs,
                collection_type="device_based_log_collection",
                ignore_empty_results=False,
            )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="device_log_commands",
                additional_context={
                    "message": "Device-based log collection completed",
                    "devices_found": total_devices,
                    "successful_devices": successful_devices,
                    "total_devices": total_devices,
                    "command_results": {
                        state["device_name"]: state["commands"]
                        for state in device_states
                    },
                    "skipped_commands": skipped_commands,
                    "host_lost": host_lost,
                    "deadline_exceeded": deadline_exceeded,
                    "remaining_retry_budget": retry_budget,
                },
            )

        try:
            return await self._execute_with_error_handling(
                dut_id,
                "device_based_log_collection",
                _device_based_log_collection,
            )
        finally:
            await self._cleanup_remote_staging_directories(dut_id, owned_stages)

    async def _handle_host_system_info_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Generic handler for system information collection (used by H18, H19, etc.).

        Get collection level from DUT config or tool config, fallback to L1.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing handle host system info collection.
        """

        async def _system_info_collection():
            """
            Handle system information collection.

            Get collection level from DUT config or tool config, fallback to L1.

            Returns:
                The terminal result of the system-information collection.
            """
            system_info_type = kwargs.get("system_info_type", "basic")
            collection_type = (
                system_info_type  # Use system_info_type for backward compatibility
            )
            # Get collection level from DUT config or tool config, fallback to L1
            collection_level = kwargs.get("collection_level", "L1")

            # Try to get collection level from DUT manager if available
            if hasattr(self, "dut_manager") and self.dut_manager:
                try:
                    # Get collection level from the specific DUT being processed
                    dut_config = self.dut_manager.get_dut_config(dut_id)
                    if dut_config and "collection_level" in dut_config:
                        collection_level = dut_config["collection_level"]
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "HostService",
                            f"Using collection level from DUT config: {collection_level}",
                        )
                except Exception as e:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "HostService",
                        f"Could not get collection level from DUT config: {e}, using default: {collection_level}",
                    )

            use_sudo = kwargs.get("use_sudo", True)

            # Extract output pattern parameters using common function
            output_pattern, substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"Starting {collection_type} system information collection (Level: {collection_level})",
            )

            output_files = []
            status_list = []
            error_messages = []
            detailed_error_messages = (
                []
            )  # Track non-ignored failures for partial/error status
            ignored_error_messages = []
            successful_operations = 0
            total_operations = 0

            # Get collection configuration from YAML parameters (fully YAML-driven)
            collection_config = kwargs.get("collection_commands", [])

            if not collection_config:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    f"No collection_commands provided in YAML for {collection_type}. This collector must be fully YAML-driven.",
                )
                return await self._create_standardized_collector_result(
                    successful_operations=0,
                    total_operations=0,
                    output_files=[],
                    error_messages=[
                        f"No collection_commands provided in YAML for {collection_type}. This collector must be fully YAML-driven."
                    ],
                    operation_name="system_info_collection",
                    additional_context={"collection_type": collection_type},
                )

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"Using YAML-provided configuration with {len(collection_config)} commands",
            )

            # Execute collection commands with level-based filtering
            for cmd_config in collection_config:
                command = cmd_config.get("command")
                file_name = cmd_config.get("file_name")
                description = cmd_config.get("description", "System info command")
                timeout = await self._resolve_collector_timeout(
                    dut_id,
                    kwargs,
                    default_timeout=60,
                    explicit_timeout_sources=[cmd_config, kwargs],
                )
                ignore_errors = cmd_config.get("ignore_errors", False)
                level_requirement = cmd_config.get(
                    "level_requirement", "L1"
                )  # Default to L1

                if not command or not file_name:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "HostService",
                        f"Skipping command with missing 'command' or 'file_name': {cmd_config}",
                    )
                    continue

                # Check if command should run based on collection level
                # Level filtering logic:
                # - L1 level: Only runs L1 commands
                # - L2 level: Runs both L1 and L2 commands
                # - L3 level: Runs L1, L2, and L3 commands (future)
                if level_requirement == "L2" and collection_level not in [
                    "L2",
                    "L3",
                ]:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"Skipping L2 command '{description}' (current level: {collection_level})",
                    )
                    continue

                elif level_requirement == "L1" and collection_level not in [
                    "L1",
                    "L2",
                    "L3",
                ]:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"Skipping L1 command '{description}' (current level: {collection_level})",
                    )
                    continue

                # Only count operations that actually get executed
                total_operations += 1

                await self._write_to_dut_runtime_log(
                    dut_id, "DEBUG", "HostService", f"Executing: {description}"
                )

                success, file_path = await self._execute_command_and_save(
                    dut_id=dut_id,
                    command=command,
                    file_name=file_name,
                    operation_name="system_info",
                    operation_type="system_info",
                    output_pattern=output_pattern,
                    filtered_kwargs=filtered_kwargs,
                    use_sudo=use_sudo,
                    timeout=timeout,
                    suppress_failure_log=bool(ignore_errors),
                    collector_id=kwargs.get("collector_id"),
                )

                if success and file_path:
                    output_files.append(file_path)
                    status_list.append(True)
                    successful_operations += 1
                else:
                    if ignore_errors:
                        ignored_error = {
                            "description": description,
                            "command": command,
                        }
                        ignored_error_messages.append(ignored_error)
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "WARN",
                            "HostService",
                            f"Command failed (ignored): {description}",
                        )
                        # Ignored failures do not fail the collector, but they
                        # also did not produce the requested artifact and must
                        # not inflate successful operation accounting.
                        status_list.append(False)
                    else:
                        # Only record detailed errors when failures are not ignored
                        detailed_error_messages.append(f"{description}: {command}")
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "HostService",
                            f"Added to detailed_error_messages: {description}: {command}",
                        )
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "HostService",
                            f"Command failed: {description}",
                        )
                        error_messages.append(f"{description}: {command}")
                        status_list.append(False)

                        # Create error log file for failed operations
                        error_log_path = await self._create_error_log_file(
                            dut_id=dut_id,
                            collector_id=kwargs.get("collector_id"),
                            error_message=f"System info command failed: {description}",
                            context={
                                "command": command,
                                "description": description,
                                "operation": "system_info_command",
                            },
                        )

                        # Add error log file to output files
                        if error_log_path:
                            output_files.append(error_log_path)

            # Determine overall status
            successful_commands = sum(status_list)
            total_commands = total_operations  # Use actual executed operations count
            ignored_failure_count = len(ignored_error_messages)
            failed_commands = total_commands - successful_commands
            ignored_only_reason = None
            if ignored_failure_count and not detailed_error_messages:
                optional_label = "failure" if ignored_failure_count == 1 else "failures"
                ignored_only_reason = (
                    "Required collection complete: "
                    f"{successful_commands}/{total_commands} "
                    "system_info_collection commands produced artifacts; "
                    f"{ignored_failure_count} optional command "
                    f"{optional_label} ignored"
                )

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"System information collection completed: {successful_commands}/{total_commands} commands successful",
            )

            await self._write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HostService",
                f"detailed_error_messages count: {len(detailed_error_messages)}, content: {detailed_error_messages}",
            )

            summary_details = {
                "Collection type": collection_type,
                "Collection level": collection_level,
                "Total commands": total_commands,
                "Successful commands": successful_commands,
                "Failed commands": failed_commands,
                "Ignored optional failures": ignored_failure_count,
                "Ignored failure details": ignored_error_messages,
                "Collection commands": [
                    cmd.get("command", cmd) if isinstance(cmd, dict) else cmd
                    for cmd in collection_config
                ],
            }
            if ignored_only_reason:
                summary_details["status_note_override"] = ignored_only_reason

            # Handle summary generation using helper function
            output_files = await self._handle_collection_summary_generation(
                dut_id=dut_id,
                function_tag=function_tag,
                collection_name=f"{function_tag} System Info Collection",
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=max(0, failed_commands - ignored_failure_count),
                skipped_operations=ignored_failure_count,
                output_files=output_files,
                additional_details=summary_details,
                kwargs=kwargs,
                collection_type="system_info_collection",
                ignore_empty_results=True,
            )

            result_context = {
                "message": f"{collection_type.capitalize()} system information collection completed",
                "collection_type": collection_type,
                "collection_level": collection_level,
                "successful_commands": successful_commands,
                "total_commands": total_commands,
                "failed_commands": failed_commands,
                "ignored_failure_count": ignored_failure_count,
                "ignored_failures": ignored_error_messages,
                "detailed_errors": detailed_error_messages,
            }

            # ``ignore_errors`` denotes optional/best-effort evidence. If those
            # are the only failures, retain overall collector success while
            # reporting the actual produced/attempted count and warning. Hard
            # failures continue through the standard partial/error logic.
            if ignored_only_reason:
                result_context.update(
                    {
                        "status": "success",
                        "reason": ignored_only_reason,
                    }
                )

            return await self._create_standardized_collector_result(
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=detailed_error_messages,  # Use detailed errors for partial logs
                operation_name="system_info_collection",
                additional_context=result_context,
            )

        return await self._execute_with_error_handling(
            dut_id, "system_info_collection", _system_info_collection
        )

    async def _process_file_with_config(
        self,
        dut_id: str,
        file_path: str,
        working_dir: str,
        search_config: Dict,
        archive_config: Dict,
        output_pattern: str,
        filtered_kwargs: Dict,
        use_sudo: bool,
        collector_output_dir: Optional[Path] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Process one file and always release its local and remote scratch state.

        Cleanup belongs to the complete operation, rather than individual
        success/failure branches. In particular, preserve cancellation while
        preventing a timed-out collector from leaving a fresh nonce-named
        tarball on the DUT or a private download directory on the controller.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            file_path: filesystem location used as the file path for this
                operation.
            working_dir: filesystem location used as the working dir for this
                operation.
            search_config: Search config governing one file and always release
                its local and remote scratch state.
            archive_config: Archive config governing one file and always release
                its local and remote scratch state.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            filtered_kwargs: Mapping supplying fields for one file and always
                release its local and remote scratch state.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            collector_output_dir: Optional filesystem location used as the
                collector output dir for this operation.

        Returns:
            A tuple containing the fields that represent process file with
            config, or ``None`` when the requested value is unavailable.
        """

        scratch_state: Dict[str, Any] = {"owned_stages": []}
        try:
            return await self._process_file_with_config_impl(
                dut_id,
                file_path,
                working_dir,
                search_config,
                archive_config,
                output_pattern,
                filtered_kwargs,
                use_sudo,
                collector_output_dir=collector_output_dir,
                _scratch_state=scratch_state,
            )
        finally:
            # Cleanup belongs to the complete operation, rather than individual
            # success/failure branches.  In particular, preserve cancellation
            # while preventing a timed-out collector from leaving a fresh
            # nonce-named tarball on the DUT or a private download directory on
            # the controller.
            try:
                archive_name = scratch_state.get("archive_name")
                if archive_name:
                    try:
                        await self.dut_manager.execute_host_command(
                            dut_id,
                            build_remote_cmd("rm -f {path}", path=archive_name),
                            timeout=60,
                            use_sudo=use_sudo,
                        )
                    except Exception as cleanup_error:
                        logger.warning(
                            "Failed to remove host scratch archive %s: %s",
                            archive_name,
                            cleanup_error,
                        )
            finally:
                try:
                    await self._cleanup_remote_staging_directories(
                        dut_id,
                        scratch_state.get("owned_stages", []),
                    )
                finally:
                    local_download_temp = scratch_state.get("local_download_temp")
                    if local_download_temp is not None:
                        try:
                            local_download_temp.cleanup()
                        except Exception as cleanup_error:
                            logger.warning(
                                "Failed to remove local host-download scratch "
                                "directory: %s",
                                cleanup_error,
                            )

    async def _process_file_with_config_impl(
        self,
        dut_id: str,
        file_path: str,
        working_dir: str,
        search_config: Dict,
        archive_config: Dict,
        output_pattern: str,
        filtered_kwargs: Dict,
        use_sudo: bool,
        collector_output_dir: Optional[Path] = None,
        _scratch_state: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Process a single file according to configuration.

        archive_mode controls what gets archived once a matching file is found.
        - "log_dirs" (default): discover directories and archive them (original
        behavior) - "file_only": archive only the matched file_path.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            file_path: filesystem location used as the file path for this
                operation.
            working_dir: filesystem location used as the working dir for this
                operation.
            search_config: Search config governing single file according to
                configuration.
            archive_config: Archive config governing single file according to
                configuration.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            filtered_kwargs: Mapping supplying fields for single file according
                to configuration.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            collector_output_dir: Optional filesystem location used as the
                collector output dir for this operation.
            _scratch_state: Optional scratch state; ``None`` selects the
                function's default behavior.

        Returns:
            A tuple containing ``success flag`` and ``status or message text``
            in that order.

        Raises:
            RuntimeError: If archive extraction returned no result.
        """

        if _scratch_state is None:
            _scratch_state = {}

        folders_to_check = search_config.get("folders_to_check", [])
        sub_folder_name = search_config.get("sub_folder_name", "")
        log_dir_pattern = search_config.get("log_dir_pattern", "*logs*")
        # archive_mode controls what gets archived once a matching file is found.
        # - "log_dirs" (default): discover directories and archive them (original behavior)
        # - "file_only": archive only the matched file_path
        archive_mode = search_config.get("archive_mode", "log_dirs")
        # File-only collectors can opt into an optimistic direct transfer. A
        # successful transfer avoids the legacy preflight diagnostics, while a
        # failure retains the complete permission-repair/diagnostic fallback.
        fast_file_only_transfer = archive_mode == "file_only" and bool(
            search_config.get("fast_file_only_transfer", False)
        )
        archive_policy = _resolve_host_archive_transfer_policy(
            archive_config,
            search_config,
            filtered_kwargs,
        )
        archive_transfer_max_bytes = archive_policy.max_transfer_bytes

        # Check for specified folders in working directory
        for folder in folders_to_check:
            folder_path = f"{working_dir}/{folder}"

            # Check if folder exists
            test_cmd = build_remote_cmd("test -d {path}", path=folder_path)
            exit_code, _, _ = await self.dut_manager.execute_host_command(
                dut_id, test_cmd, timeout=60, use_sudo=use_sudo
            )

            if exit_code != 0:
                continue  # Folder doesn't exist, try next

            await self._write_to_dut_runtime_log(
                dut_id, "INFO", "HostService", f"Found folder: {folder_path}"
            )

            # Handle subdirectories
            if folder.startswith("dgx_"):
                sub_folder_path = f"{folder_path}/{sub_folder_name}"
                test_cmd = build_remote_cmd("test -d {path}", path=sub_folder_path)
                exit_code, _, _ = await self.dut_manager.execute_host_command(
                    dut_id, test_cmd, timeout=60, use_sudo=use_sudo
                )

                if exit_code != 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "HostService",
                        f"Subdirectory '{sub_folder_name}' not found in {folder_path}",
                    )
                    continue

                folder_path = sub_folder_path
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"Navigated to subdirectory: {folder_path}",
                )

            # Determine what to archive
            if archive_mode == "file_only":
                # Verify that file_path exists before archiving
                test_cmd = build_remote_cmd("test -f {path}", path=file_path)
                exit_code, _, _ = await self.dut_manager.execute_host_command(
                    dut_id, test_cmd, timeout=60, use_sudo=use_sudo
                )

                if exit_code != 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "HostService",
                        f"archive_mode=file_only: file does not exist or is inaccessible: {file_path}",
                    )
                    continue

                log_dirs = [file_path]
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"archive_mode=file_only: archiving only matched file: {file_path}",
                )
            else:
                # Find log directories
                find_cmd = build_remote_cmd(
                    "find {path} -type d -name {pattern} 2>/dev/null",
                    path=folder_path,
                    pattern=log_dir_pattern,
                )
                exit_code, stdout, _ = await self.dut_manager.execute_host_command(
                    dut_id, find_cmd, timeout=60, use_sudo=use_sudo
                )

                if exit_code != 0 or not stdout.strip():
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARN",
                        "HostService",
                        f"No '{log_dir_pattern}' directories found in {folder_path}",
                    )
                    continue

                log_dirs = [d.strip() for d in stdout.strip().split("\n") if d.strip()]

            # Create an archive without following symbolic links. Collection
            # roots can contain endpoint-controlled links, so materializing link
            # targets could copy data from outside the selected roots.
            tool_config = await self.orchestrator.get_dut_specific_tool_config(dut_id)
            base_temp_dir = get_tool_temp_dir(tool_config, "/tmp")
            # Derive every persisted artifact name from
            # the complete source path.  The digest prevents remote-download
            # and local-staging collisions when multiple source trees share the
            # same parent basename.  Keep the full digest because it is a
            # durable artifact identity, not a display-only suffix.
            path_hash = hashlib.sha256(file_path.encode("utf-8")).hexdigest()
            artifact_base = re.sub(
                r"[^A-Za-z0-9_.-]+",
                "_",
                f"logs_{os.path.basename(working_dir)}_{folder}",
            ).strip("._")
            artifact_identity = f"{(artifact_base or 'logs')[:120]}_{path_hash}"
            try:
                archive_stage = await self._create_remote_staging_directory(
                    dut_id,
                    "logs-archive",
                    use_sudo=use_sudo,
                    owned_stages=_scratch_state.setdefault("owned_stages", []),
                    configured_root=base_temp_dir,
                )
            except Exception as staging_error:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    "Failed to create private host archive staging: "
                    f"{staging_error}",
                )
                return False, None
            archive_name = self._remote_staging_file_path(
                archive_stage,
                f"logs_{path_hash}.tar.gz",
            )
            _scratch_state["archive_name"] = archive_name
            # Pre-clear any existing archive to avoid collisions/permissions issues
            await self._write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "HostService",
                f"Pre-clearing any existing archive '{archive_name}'",
            )
            await self.dut_manager.execute_host_command(
                dut_id,
                build_remote_cmd("rm -f {path}", path=archive_name),
                timeout=60,
                use_sudo=use_sudo,
            )

            tar_command = build_link_safe_tar_create_command(
                archive_name,
                log_dirs,
                tar_command=TRUSTED_REMOTE_TAR_COMMAND,
            )

            exit_code, _, stderr = await self.dut_manager.execute_host_command(
                dut_id, tar_command, timeout=300, use_sudo=use_sudo
            )

            if exit_code != 0:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    f"Failed to create archive '{archive_name}': {stderr}",
                )
                return False, None

            await self._write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "HostService",
                f"Created archive '{archive_name}' on host",
            )

            # Each operation downloads into a private local directory.  The
            # nonce also makes the remote scratch archive unique, preventing
            # concurrent DUTs (or overlapping runs on one DUT) from reading,
            # deleting, or overwriting one another's transient archive.  The
            # stable artifact_identity remains unchanged for persisted output.
            local_download_temp = tempfile.TemporaryDirectory(
                prefix=f"download_{path_hash[:16]}_",
                dir=local_temp_dir(tool_config),
            )
            _scratch_state["local_download_temp"] = local_download_temp
            local_download_dir = local_download_temp.name
            local_archive = os.path.join(
                local_download_dir, os.path.basename(archive_name)
            )

            transfer_success = False
            transfer_error = ""
            if fast_file_only_transfer:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"Attempting fast direct download of file-only archive: '{archive_name}'",
                )
                (
                    transfer_success,
                    transfer_error,
                ) = await self.dut_manager.transfer_host_files(
                    dut_id,
                    archive_name,
                    local_download_dir,
                    copy_to_destination=False,
                    max_bytes=archive_transfer_max_bytes,
                )
                if not transfer_success:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "HostService",
                        f"Fast direct download failed for '{archive_name}': "
                        f"{transfer_error}; running full transfer diagnostics and "
                        "permission fallback",
                    )

            # Diagnostic: Check archive details and system info
            if not transfer_success:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"Running diagnostic commands for archive: '{archive_name}'",
                )

            # Check current user and groups
            if not transfer_success:
                whoami_cmd = "whoami && id && groups"
                (
                    whoami_exit_code,
                    whoami_stdout,
                    _,
                ) = await self.dut_manager.execute_host_command(
                    dut_id, whoami_cmd, timeout=30, use_sudo=False
                )
                if whoami_exit_code == 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"Current user info: {whoami_stdout.strip()}",
                    )

            # Check the configured Host scratch directory permissions.
            if not transfer_success:
                tmp_perms_cmd = build_remote_cmd(
                    "ls -ld {path} && ls -la {path} | head -10",
                    path=base_temp_dir,
                )
                (
                    tmp_exit_code,
                    tmp_stdout,
                    _,
                ) = await self.dut_manager.execute_host_command(
                    dut_id, tmp_perms_cmd, timeout=30, use_sudo=False
                )
                if tmp_exit_code == 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"Configured Host temp directory info: {tmp_stdout.strip()}",
                    )

            # Check if archive exists and get detailed info
            if not transfer_success:
                archive_info_cmd = build_remote_cmd(
                    "test -f {path} && echo 'Archive exists' || echo 'Archive not found'",
                    path=archive_name,
                )
                (
                    archive_test_exit_code,
                    archive_test_stdout,
                    _,
                ) = await self.dut_manager.execute_host_command(
                    dut_id, archive_info_cmd, timeout=30, use_sudo=False
                )
                if archive_test_exit_code == 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"Archive existence check: {archive_test_stdout.strip()}",
                    )

            # Fix permissions for SFTP access (if using sudo)
            if not transfer_success and use_sudo:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"Archive created with sudo, fixing permissions for SFTP access: '{archive_name}'",
                )

                # First check current ownership
                ls_command = build_remote_cmd("ls -la {path}", path=archive_name)
                (
                    ls_exit_code,
                    ls_stdout,
                    _,
                ) = await self.dut_manager.execute_host_command(
                    dut_id, ls_command, timeout=30, use_sudo=False
                )
                if ls_exit_code == 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"Archive ownership before chown: {ls_stdout.strip()}",
                    )

                # Chown to the explicit SSH credential
                # username. Previously this used ``chown $USER:$USER`` under
                # sudo, but most sudoers policies reset ``$USER`` to ``root``,
                # leaving the archive owned by ``root:root``. The subsequent
                # non-root SFTP connection then cannot read it and
                # ``sftp.get`` surfaces a truncated 0-byte local file, which
                # the downstream verification reported as
                # "Downloaded file ... is empty or missing". Prefer, in order:
                #   1. the resolved DUT credential username (matches the SSH
                #      user we are about to connect as),
                #   2. ``$SUDO_USER`` (set by sudo to the *invoking* user,
                #      unlike ``$USER`` which most sudoers policies reset to
                #      ``root``),
                #   3. skip the chown entirely and warn loudly — never fall
                #      back to ``$USER`` under sudo, which reproduces the
                #      original bug.
                sftp_username = self._resolve_sftp_username(dut_id)
                chown_command = None
                chown_target_desc = None
                if sftp_username:
                    chown_command = build_remote_cmd(
                        "chown {user}:{user} {path}",
                        user=sftp_username,
                        path=archive_name,
                    )
                    chown_target_desc = sftp_username
                else:
                    # No credential username available (ad-hoc CLI runs with
                    # no DUT record). Use ``$SUDO_USER``, which sudo sets to
                    # the invoking user's login name and which does not get
                    # wiped by ``env_reset``. Guard with ``${SUDO_USER:-}``
                    # so the chown is skipped if the variable is absent
                    # (would otherwise run ``chown :<path>`` and fail).
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "HostService",
                        "No DUT credential username configured; falling back "
                        "to $SUDO_USER for archive chown. If SUDO_USER is "
                        "unset, the chown is skipped and the subsequent "
                        "SFTP download may fail with a permission error — "
                        "configure HOST_USERNAME in the DUT config to "
                        "avoid this degraded path.",
                    )
                    chown_command = (
                        'if [ -n "${SUDO_USER:-}" ]; then '
                        f'chown "$SUDO_USER:$SUDO_USER" {quote_arg(archive_name)}; '
                        "else "
                        'echo "SUDO_USER unset; skipping chown" >&2; '
                        "exit 0; "
                        "fi"
                    )
                    chown_target_desc = "$SUDO_USER (fallback)"

                (
                    chown_exit_code,
                    chown_stdout,
                    chown_stderr,
                ) = await self.dut_manager.execute_host_command(
                    dut_id, chown_command, timeout=60, use_sudo=use_sudo
                )

                if chown_exit_code != 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "HostService",
                        f"Failed to change ownership of archive '{archive_name}': {chown_stderr}",
                    )
                    # Continue anyway - the fallback mechanisms might still work
                else:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "HostService",
                        f"Successfully changed ownership of archive '{archive_name}' "
                        f"to '{chown_target_desc}' for SFTP access",
                    )

                    # Verify ownership change
                    (
                        ls_exit_code,
                        ls_stdout,
                        _,
                    ) = await self.dut_manager.execute_host_command(
                        dut_id, ls_command, timeout=30, use_sudo=False
                    )
                    if ls_exit_code == 0:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "HostService",
                            f"Archive ownership after chown: {ls_stdout.strip()}",
                        )

                        # Additional verification: Check if we can read the file
                        read_test_cmd = build_remote_cmd(
                            "head -c 100 {path} > /dev/null && echo 'File readable' || echo 'File not readable'",
                            path=archive_name,
                        )
                        (
                            read_test_exit_code,
                            read_test_stdout,
                            _,
                        ) = await self.dut_manager.execute_host_command(
                            dut_id,
                            read_test_cmd,
                            timeout=30,
                            use_sudo=False,
                        )
                        if read_test_exit_code == 0:
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "HostService",
                                f"Archive readability test: {read_test_stdout.strip()}",
                            )

                        # Check file size and type
                        file_info_cmd = build_remote_cmd(
                            "file {path} && stat {path}", path=archive_name
                        )
                        (
                            file_info_exit_code,
                            file_info_stdout,
                            _,
                        ) = await self.dut_manager.execute_host_command(
                            dut_id,
                            file_info_cmd,
                            timeout=30,
                            use_sudo=False,
                        )
                        if file_info_exit_code == 0:
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "HostService",
                                f"Archive file info: {file_info_stdout.strip()}",
                            )

            # Download the archive after the legacy diagnostics/permission
            # repair, unless the optimistic file-only transfer already worked.
            if not transfer_success:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"Attempting to download archive: '{archive_name}'",
                )
                (
                    transfer_success,
                    transfer_error,
                ) = await self.dut_manager.transfer_host_files(
                    dut_id,
                    archive_name,
                    local_download_dir,
                    copy_to_destination=False,
                    max_bytes=archive_transfer_max_bytes,
                )

            if not transfer_success:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    f"Failed to download archive '{archive_name}': {transfer_error}",
                )

                # Enhanced debugging for download failures
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"Running post-failure diagnostics for archive: '{archive_name}'",
                )

                # Check if file still exists and its current state
                final_check_cmd = build_remote_cmd(
                    "ls -la {path} 2>/dev/null || echo 'File no longer exists'",
                    path=archive_name,
                )
                (
                    final_check_exit_code,
                    final_check_stdout,
                    _,
                ) = await self.dut_manager.execute_host_command(
                    dut_id, final_check_cmd, timeout=30, use_sudo=False
                )
                if final_check_exit_code == 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"Final archive state: {final_check_stdout.strip()}",
                    )

                # Check SFTP service status and connectivity
                sftp_test_cmd = (
                    "which sftp && echo 'SFTP available' || echo 'SFTP not found'"
                )
                (
                    sftp_test_exit_code,
                    sftp_test_stdout,
                    _,
                ) = await self.dut_manager.execute_host_command(
                    dut_id, sftp_test_cmd, timeout=30, use_sudo=False
                )
                if sftp_test_exit_code == 0:
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"SFTP availability: {sftp_test_stdout.strip()}",
                    )

                # Log additional debugging info for permission issues
                if "Permission denied" in str(transfer_error):
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        "Permission denied error detected. Archive may still be owned by root or have incorrect permissions.",
                    )

                    # Try to get more detailed permission info
                    perm_debug_cmd = build_remote_cmd(
                        "getfacl -- {path} 2>/dev/null || echo 'ACL not available'",
                        path=archive_name,
                    )
                    perm_debug_exit_code, perm_debug_stdout, _ = (
                        await self.dut_manager.execute_host_command(
                            dut_id, perm_debug_cmd, timeout=30, use_sudo=False
                        )
                    )
                    if perm_debug_exit_code == 0:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "HostService",
                            f"Archive ACL info: {perm_debug_stdout.strip()}",
                        )

                return False, None
            else:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    f"Successfully downloaded archive: '{archive_name}'",
                )

            # Extract and save locally
            if os.path.exists(local_archive):
                extract_dir: Optional[str] = None
                remove_local_archive = True
                try:
                    await self._log_collection_archive_size_advisory(
                        dut_id,
                        local_archive,
                        archive_policy,
                    )
                    extract_dir = tempfile.mkdtemp(
                        prefix=f"extract_{artifact_identity[:80]}_",
                        dir=local_temp_dir(tool_config),
                    )
                    extraction_result = await _run_managed_filesystem_operation(
                        partial(
                            extract_tar_archive,
                            local_archive,
                            extract_dir,
                            limits=archive_policy.validation_limits,
                            return_result=True,
                        )
                    )
                    if extraction_result is None:
                        raise RuntimeError("archive extraction returned no result")
                    if extraction_result.dropped_members:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "HostService",
                            "Archive extraction safely omitted unsupported "
                            f"members (links={extraction_result.dropped_links}, "
                            "other_special="
                            f"{extraction_result.dropped_special_members})",
                        )
                    if extraction_result.regular_files == 0:
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "HostService",
                            "Archive contained no materialized regular files; "
                            "refusing to report extraction success",
                        )
                        shutil.rmtree(extract_dir, ignore_errors=True)
                        return False, None

                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "HostService",
                        "Extracted "
                        f"{extraction_result.regular_files} regular file(s) "
                        f"from archive to {extract_dir}",
                    )

                    # Move extracted logs into the designated output directory
                    # If archiving is enabled (collector_output_dir provided), skip creating the index text file
                    index_file_path = None
                    if not collector_output_dir:
                        index_file_path = await self._save_data_with_common_pattern(
                            dut_id,
                            f"Logs extracted to: {extract_dir}",
                            f"{artifact_identity}.txt",
                            output_pattern=output_pattern,
                            substitutions={"file_name": artifact_identity},
                            **filtered_kwargs,
                        )

                    # Derive destination directory and move extracted data there
                    saved_dir = None
                    if os.path.exists(extract_dir):
                        # Use collector_output_dir if provided (for archiving), else use index file location
                        if collector_output_dir:
                            base_dir = collector_output_dir
                        else:
                            base_dir = (
                                Path(index_file_path).parent
                                if index_file_path
                                else Path(self.logger.base_log_dir)
                            )

                        dest_dir = base_dir / artifact_identity

                        try:
                            saved_dir = await _run_managed_filesystem_operation(
                                _publish_extracted_directory,
                                extract_dir,
                                dest_dir,
                            )
                        except Exception as move_err:
                            # Preserve both the downloaded archive and the
                            # extraction tree for recovery. A publication
                            # failure is a collector failure, never success
                            # followed by silent deletion.
                            remove_local_archive = False
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "ERROR",
                                "HostService",
                                "Failed to publish extracted logs to the output "
                                "directory; downloaded archive retained and the "
                                "extracted recovery tree is retained when the "
                                f"commit did not complete ({extract_dir}): "
                                f"{move_err}",
                            )

                    # Do not remove extracted data if we successfully moved it
                    if not saved_dir:
                        return False, None

                    # Return success and the index file as a data artifact
                    return True, index_file_path

                except Exception as e:
                    remove_local_archive = False
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "ERROR",
                        "HostService",
                        "Error processing archive; downloaded archive retained "
                        f"for recovery: {str(e)}",
                    )
                    return False, None
                finally:
                    if remove_local_archive:
                        try:
                            os.remove(local_archive)
                        except FileNotFoundError:
                            pass
                        except OSError as cleanup_error:
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "WARN",
                                "HostService",
                                "Failed to remove downloaded temporary archive "
                                f"'{local_archive}': {cleanup_error}",
                            )
            else:
                return False, None

        return False, None

    async def _handle_host_nvos_commands(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Handle host nvos commands.

        Route through the shared resolver so DUT/tool overrides declared via
        ``timeout_config`` win over bundled hook defaults.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing handle host nvos commands.
        """

        command_entries = kwargs.get("commands", [])
        use_sudo = kwargs.get("use_sudo", False)
        # Route through the shared resolver so DUT/tool overrides declared via
        # ``timeout_config`` win over bundled hook defaults.
        timeout = await self._resolve_collector_timeout(
            dut_id, kwargs, default_timeout=300
        )

        # Extract output pattern parameters using common function
        output_pattern, substitutions, filtered_kwargs = (
            self._extract_output_pattern_params(kwargs)
        )

        output_files = []
        success_count = 0
        error_messages = []
        file_generating_errors: Dict[str, str] = {}
        successful_operations = 0
        total_operations = 0
        executed_commands = []
        skipped_commands = []

        baseboard_name = ""
        baseboard_type = ""
        if any(isinstance(entry, Mapping) for entry in command_entries):
            try:
                dut_config = self.dut_manager.get_dut_config(dut_id)
                if isinstance(dut_config, dict):
                    baseboard_name = str(dut_config.get("baseboard") or "")
                    baseboard_type = str(dut_config.get("type") or "")
            except Exception as exc:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"Unable to retrieve DUT config for NVOS command handling: {exc}",
                )

        def _normalized_filter_values(value: Any) -> List[str]:
            """
            Normalize one optional baseboard filter into comparable text.

            Scalars and sequences share one case-insensitive representation;
            blank and non-text values do not become catalog matches.

            Args:
                value: Scalar or sequence supplied by the authored command
                    filter.

            Returns:
                Ordered normalized non-empty filter values.
            """
            if isinstance(value, (list, tuple, set)):
                values = value
            else:
                values = [value]
            return [
                str(item).strip().lower()
                for item in values
                if isinstance(item, (str, bytes)) and str(item).strip()
            ]

        normalized_baseboard_name = baseboard_name.strip().lower()
        normalized_baseboard_type = baseboard_type.strip().lower()

        await self._write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "HostService",
            f"Starting NVOS commands collection with {len(command_entries)} commands",
        )

        for i, command_entry in enumerate(command_entries):
            if isinstance(command_entry, str):
                command = command_entry
                command_config: Mapping[str, Any] = {}
            elif isinstance(command_entry, Mapping):
                command_config = command_entry
                command = command_config.get("command")
                if not isinstance(command, str) or not command.strip():
                    total_operations += 1
                    error_messages.append(
                        f"Invalid NVOS command configuration at index {i + 1}"
                    )
                    continue

                allowed_values = _normalized_filter_values(
                    command_config.get("run_if_baseboard_in")
                )
                if allowed_values and (
                    normalized_baseboard_name not in allowed_values
                    and normalized_baseboard_type not in allowed_values
                ):
                    skipped_commands.append(command)
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        (
                            f"Skipping NVOS command '{command}' due to baseboard "
                            f"filter {allowed_values} (baseboard='{baseboard_name}', "
                            f"type='{baseboard_type}')."
                        ),
                    )
                    continue

                skip_values = _normalized_filter_values(
                    command_config.get("skip_if_baseboard_in")
                )
                if (
                    normalized_baseboard_name in skip_values
                    or normalized_baseboard_type in skip_values
                ):
                    skipped_commands.append(command)
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        (
                            f"Skipping NVOS command '{command}' because baseboard "
                            f"matched skip list {skip_values}."
                        ),
                    )
                    continue
            else:
                total_operations += 1
                error_messages.append(
                    f"Invalid NVOS command configuration at index {i + 1}"
                )
                continue

            total_operations += 1
            executed_commands.append(command)
            try:
                logged_command = self._bounded_operator_reason("success", command)
                # Create safe filename from command
                safe_cmd = command.replace(" ", "_").replace("/", "_")
                command_name = safe_cmd

                # Generate output filename
                if output_pattern:
                    filename = self.substitute_output_pattern_variables(
                        output_pattern,
                        {
                            **substitutions,
                            "command_name": command_name,
                            "index": i + 1,
                        },
                    )
                else:
                    filename = f"{function_tag}_{command_name}.txt"

                await self._write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "HostService",
                    (
                        f"Executing NVOS command {i + 1}/{len(command_entries)} "
                        f"with effective timeout {timeout}s: {logged_command}"
                    ),
                )

                # Check if this is a file-generating command based on YAML config
                file_generating_commands = kwargs.get("file_generating_commands", {})
                is_file_generating = file_generating_commands.get(command, False)

                await self._write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "HostService",
                    f"File-generating check: command='{command}', file_generating_commands={list(file_generating_commands.keys())}, is_file_generating={is_file_generating}",
                )

                if is_file_generating:
                    # Handle file-generating commands
                    file_path = await self._handle_nvos_file_generating_command(
                        dut_id,
                        command,
                        filename,
                        output_pattern,
                        substitutions,
                        filtered_kwargs,
                        use_sudo,
                        timeout,
                        kwargs.get("file_generating_commands", {}),
                        file_generating_errors,
                    )
                    failure_message = file_generating_errors.get(command)
                    if file_path:
                        output_files.append(file_path)
                        if failure_message:
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "ERROR",
                                "HostService",
                                failure_message,
                            )
                            error_messages.append(failure_message)
                        else:
                            success_count += 1
                            successful_operations += 1
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "INFO",
                                "HostService",
                                f"Successfully executed file-generating NVOS command: {command}",
                            )
                    else:
                        failure_message = (
                            failure_message
                            or f"Failed to execute file-generating NVOS command: {command}"
                        )
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "HostService",
                            failure_message,
                        )
                        error_messages.append(failure_message)
                else:
                    # Handle regular NVOS show commands using DUT manager
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"About to call execute_nvos_command for: {command}",
                    )
                    success, output = await self.dut_manager.execute_nvos_command(
                        dut_id, command, timeout=timeout, use_sudo=use_sudo
                    )
                    await self._write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "HostService",
                        f"execute_nvos_command returned: success={success}, output_type={type(output)}",
                    )

                    if success and output is not None:
                        # Save the output
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "HostService",
                            f"About to save output for command: {command}, filename: {filename}, output_type: {type(output)}, output_length: {len(str(output)) if output else 0}",
                        )
                        file_path = await self._save_data_with_common_pattern(
                            dut_id,
                            output,
                            filename,
                            output_pattern=output_pattern,
                            substitutions={
                                **substitutions,
                                "command_name": command_name,
                                "index": i + 1,
                            },
                            **filtered_kwargs,
                        )
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "HostService",
                            f"_save_data_with_common_pattern returned: {file_path}",
                        )
                        if file_path:
                            output_files.append(file_path)
                            success_count += 1
                            successful_operations += 1
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "INFO",
                                "HostService",
                                f"Successfully executed NVOS command: {command}",
                            )
                        else:
                            await self._write_to_dut_runtime_log(
                                dut_id,
                                "ERROR",
                                "HostService",
                                f"Failed to save output for NVOS command: {command}",
                            )
                            error_messages.append(
                                f"Failed to save output for NVOS command: {command}"
                            )
                    else:
                        failure_detail = self._bounded_operator_reason("error", output)
                        failure_message = (
                            f"NVOS command failed: {logged_command}; "
                            f"detail={failure_detail}"
                        )
                        await self._write_to_dut_runtime_log(
                            dut_id,
                            "ERROR",
                            "HostService",
                            failure_message,
                        )
                        error_messages.append(failure_message)

            except Exception as e:
                await self._write_to_dut_runtime_log(
                    dut_id,
                    "ERROR",
                    "HostService",
                    f"Exception executing NVOS command {command}: {str(e)}",
                )
                error_messages.append(
                    f"Exception executing NVOS command {command}: {str(e)}"
                )

        success = success_count > 0
        await self._write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "HostService",
            f"NVOS commands collection completed: {success_count}/{total_operations} successful",
        )

        # Handle summary generation using helper function
        output_files = await self._handle_collection_summary_generation(
            dut_id=dut_id,
            function_tag=function_tag,
            collection_name=f"{function_tag} NVOS Commands",
            total_operations=total_operations,
            successful_operations=successful_operations,
            failed_operations=len(error_messages),
            output_files=output_files,
            additional_details={
                "Total commands": total_operations,
                "Successful commands": success_count,
                "Commands executed": executed_commands,
                "Commands skipped by baseboard": skipped_commands,
                "File generating commands": kwargs.get("file_generating_commands", {}),
            },
            kwargs=kwargs,
            collection_type="nvos_commands",
            ignore_empty_results=True,
        )

        return await self._create_standardized_collector_result(
            successful_operations=successful_operations,
            total_operations=total_operations,
            output_files=output_files,
            error_messages=error_messages,
            operation_name="nvos_commands",
            additional_context={
                "total_commands": total_operations,
                "successful_commands": success_count,
                "failed_commands": total_operations - success_count,
                "skipped_commands": skipped_commands,
            },
        )

    async def _handle_nvos_file_generating_command(
        self,
        dut_id: str,
        command: str,
        filename: str,
        output_pattern: str,
        substitutions: Dict[str, Any],
        filtered_kwargs: Dict[str, Any],
        use_sudo: bool,
        timeout: int,
        file_generating_config: Dict[str, Any],
        failure_messages: Optional[Dict[str, str]] = None,
    ) -> Optional[str]:
        """
        Handle NVOS commands that generate files (like tech-support).

        The implementation uses ``dut_id``, ``command``, ``filename``,
        ``output_pattern``, and ``substitutions`` to handle NVOS commands that
        generate files (like tech-support). Terminal status is emitted only
        after NVOS commands that generate files (like tech-support) and its
        owned cleanup have completed. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle. If the function cannot handle NVOS commands
        that generate files (like tech-support), its exception reaches the
        caller instead of being converted into a successful result. Cleanup in
        the ``finally`` path runs for successful, failed, and cancelled
        execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            filename: Text supplied as filename in the format accepted by this
                function.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            substitutions: Mapping supplying fields for NVOS commands that
                generate files (like tech-support).
            filtered_kwargs: Mapping supplying fields for NVOS commands that
                generate files (like tech-support).
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            file_generating_config: File generating config governing NVOS
                commands that generate files (like tech-support).
            failure_messages: Optional failure messages; ``None`` selects the
                function's default behavior.

        Returns:
            The canonical handle nvos file generating command text, or ``None``
            when the requested value is unavailable.

        Raises:
            RuntimeError: If logger unavailable for NVOS archive persistence; or
                unable to allocate NVOS archive output path.
        """
        acquisition_timing_id = None
        local_staging_dir: Optional[str] = None
        try:
            command_config = file_generating_config.get(command, {})
            cleanup_use_sudo = command_config.get("cleanup_use_sudo", use_sudo)
            if not isinstance(cleanup_use_sudo, bool):
                raise ValueError("cleanup_use_sudo must be a boolean")
            archive_policy = _resolve_host_archive_transfer_policy(
                command_config,
                filtered_kwargs,
            )
            archive_max_bytes = archive_policy.max_transfer_bytes
            archive_limits = archive_policy.validation_limits
            logged_command = self._bounded_operator_reason("success", command)

            def record_failure(message: str) -> None:
                """
                Record failure.

                The implementation uses ``message`` to record failure.

                Args:
                    message: Operator-facing text carried by the reported event
                        or failure.
                """
                if failure_messages is not None:
                    failure_messages[command] = message

            timeout_sequence = self._build_nvos_timeout_backoff_sequence(
                timeout, command_config, filtered_kwargs
            )
            command_timeout = timeout_sequence[0]
            artifact_polling_enabled = len(timeout_sequence) > 1
            action_start = time.monotonic()
            baseline_artifacts = {}
            if artifact_polling_enabled:
                baseline_artifacts = await self._list_nvos_generated_artifacts(
                    dut_id=dut_id,
                    command_config=command_config,
                    use_sudo=use_sudo,
                )

            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"_handle_nvos_file_generating_command called with command='{command}', filename='{filename}', timeout={timeout}, use_sudo={use_sudo}",
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"File generating config: {file_generating_config}",
                dut_id,
            )

            # Execute the NVOS action exactly once. Reissuing this command queues
            # another tech-support action on NVOS, so timeout extension happens
            # by polling for the generated artifact instead of rerunning it.
            await self._log_runtime(
                "INFO",
                "HostService",
                (
                    "Starting file-generating NVOS action exactly once: "
                    f"command='{logged_command}', action_timeout={command_timeout}s, "
                    f"total_wait={max(timeout_sequence)}s, "
                    f"post_timeout_polling={artifact_polling_enabled}, "
                    f"configured_timeout_sequence={timeout_sequence}"
                ),
                dut_id,
            )
            success, output = await self.dut_manager.execute_nvos_command(
                dut_id, command, timeout=command_timeout, use_sudo=use_sudo
            )
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"execute_nvos_command returned: success={success}, output_type={type(output)}, output_length={len(str(output)) if output else 0}",
                dut_id,
            )

            remote_path_from_poll = None
            if not success:
                is_timeout_failure = self._is_nvos_timeout_failure(output)
                if is_timeout_failure and artifact_polling_enabled:
                    await self._log_runtime(
                        "WARNING",
                        "HostService",
                        (
                            "File-generating command timed out locally after "
                            f"{command_timeout}s; polling for queued NVOS "
                            f"tech-support artifact: {logged_command}"
                        ),
                        dut_id,
                    )
                    remote_path_from_poll = (
                        await self._wait_for_nvos_generated_artifact(
                            dut_id=dut_id,
                            command_config=command_config,
                            baseline_artifacts=baseline_artifacts,
                            timeout_sequence=timeout_sequence,
                            action_start=action_start,
                            use_sudo=use_sudo,
                        )
                    )
                    if remote_path_from_poll:
                        success = True

                if not success:
                    failure_detail = self._bounded_operator_reason("error", output)
                    failure_message = (
                        f"File-generating NVOS action failed: {logged_command}; "
                        f"detail={failure_detail}"
                    )
                    if is_timeout_failure and artifact_polling_enabled:
                        max_total_wait = max(timeout_sequence)
                        failure_message = (
                            "NVOS tech-support action did not produce a valid "
                            f"final archive within {max_total_wait}s total wait "
                            f"after nvdebug queued '{logged_command}' once. nvdebug did "
                            "not rerun the action; investigate NVOS action "
                            "duration/completion."
                        )
                        cleanup_verified = await self._cleanup_nvos_generated_artifacts(
                            dut_id=dut_id,
                            remote_paths=[
                                path
                                for path in (
                                    await self._list_nvos_generated_artifacts(
                                        dut_id=dut_id,
                                        command_config=command_config,
                                        use_sudo=use_sudo,
                                    )
                                )
                                if path not in baseline_artifacts
                            ],
                            use_sudo=cleanup_use_sudo,
                        )
                        if not cleanup_verified:
                            failure_message += (
                                " Remote generated artifact cleanup could not be "
                                "verified."
                            )
                    elif is_timeout_failure:
                        failure_message = (
                            "NVOS tech-support action timed out locally after "
                            f"{command_timeout}s. No post-timeout artifact polling "
                            "window was configured and nvdebug did not rerun the "
                            f"action. detail={failure_detail}"
                        )
                    record_failure(failure_message)
                    await self._log_runtime(
                        "ERROR",
                        "HostService",
                        failure_message,
                        dut_id,
                    )
                    return None

            if remote_path_from_poll:
                generated_file = os.path.basename(remote_path_from_poll)
                remote_path = remote_path_from_poll
                await self._log_runtime(
                    "INFO",
                    "HostService",
                    f"Using generated file discovered by polling: {generated_file}",
                    dut_id,
                )
            else:
                # For file-generating commands, output will be the raw stdout text
                stdout = output if isinstance(output, str) else str(output)
                await self._log_runtime(
                    "DEBUG", "HostService", f"Command stdout: {stdout}", dut_id
                )

                # Get file generation config for this command
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Command config for '{command}': {command_config}",
                    dut_id,
                )
                file_pattern = command_config.get(
                    "file_pattern", r"Generated tech-support (\S*)"
                )
                remote_path_template = command_config.get(
                    "remote_path_template", "/host/dump/{filename}"
                )
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Using file_pattern: '{file_pattern}', remote_path_template: '{remote_path_template}'",
                    dut_id,
                )

                # Parse the output to find the generated file

                file_match = re.search(file_pattern, stdout)
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Regex search result: {file_match}",
                    dut_id,
                )
                if not file_match:
                    output_detail = self._bounded_operator_reason("error", stdout)
                    failure_message = (
                        "NVOS tech-support action completed but nvdebug could "
                        "not parse the generated archive name from output: "
                        f"{output_detail}"
                    )
                    record_failure(failure_message)
                    await self._log_runtime(
                        "ERROR",
                        "HostService",
                        failure_message,
                        dut_id,
                    )
                    return None

                generated_file = file_match.group(1)
                remote_path = remote_path_template.format(filename=generated_file)

            if os.path.basename(
                generated_file
            ) != generated_file or not self._SAFE_NVOS_ARCHIVE_BASENAME.fullmatch(
                generated_file
            ):
                failure_message = (
                    "NVOS tech-support action returned an unsafe archive name; "
                    "expected a single .tar.gz basename"
                )
                record_failure(failure_message)
                await self._log_runtime(
                    "ERROR",
                    "HostService",
                    failure_message,
                    dut_id,
                )
                return None
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"Extracted generated_file: '{generated_file}', remote_path: '{remote_path}'",
                dut_id,
            )

            await self._log_runtime(
                "INFO",
                "HostService",
                f"File generated: {generated_file}",
                dut_id,
            )

            # Download into an operation-private directory. The DUT-controlled
            # value has already been reduced to a validated basename.
            local_staging_parent = await self._resolve_local_staging_parent(dut_id)
            local_staging_dir = tempfile.mkdtemp(
                prefix="nvdebug_h14_",
                dir=local_staging_parent,
            )
            await self._log_runtime(
                "INFO",
                "HostService",
                (
                    f"Starting bounded NVOS archive transfer from '{remote_path}' "
                    f"to private local staging (max_bytes={archive_max_bytes})"
                ),
                dut_id,
            )
            await self._log_runtime(
                "DEBUG",
                "HostService",
                (
                    "Calling dut_manager.transfer_host_files with "
                    f"dut_id='{dut_id}', remote_path='{remote_path}', "
                    "copy_to_destination=False"
                ),
                dut_id,
            )

            if self.timing_manager:
                acquisition_timing_id = self.timing_manager.start_operation(
                    "host_file_acquisition",
                    generated_file,
                    metadata={
                        "transport": "host_file_transfer",
                        "remote_path": remote_path,
                        "source": "nvos_generated_archive",
                    },
                )
            try:
                (
                    transfer_success,
                    transfer_error,
                ) = await self.dut_manager.transfer_host_files(
                    dut_id,
                    remote_path,
                    local_staging_dir,
                    copy_to_destination=False,
                    max_bytes=archive_max_bytes,
                )
            except BaseException as exc:
                if self.timing_manager:
                    self.timing_manager.end_operation(
                        acquisition_timing_id,
                        status=(
                            "cancelled"
                            if isinstance(exc, asyncio.CancelledError)
                            else "error"
                        ),
                        error=(
                            "CancelledError"
                            if isinstance(exc, asyncio.CancelledError)
                            else str(exc)
                        ),
                    )
                raise

            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"transfer_host_files returned: success={transfer_success}, error='{transfer_error}'",
                dut_id,
            )

            if not transfer_success:
                failure_message = (
                    f"Failed to transfer generated NVOS tech-support archive "
                    f"{remote_path}: {transfer_error}"
                )
                if self.timing_manager:
                    self.timing_manager.end_operation(
                        acquisition_timing_id,
                        status="error",
                        error=str(transfer_error or failure_message),
                    )
                record_failure(failure_message)
                await self._log_runtime(
                    "ERROR",
                    "HostService",
                    failure_message,
                    dut_id,
                )
                return None

            # Save the downloaded file
            local_file = str(Path(local_staging_dir) / generated_file)
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"Checking if local file exists: {local_file}",
                dut_id,
            )
            if os.path.exists(local_file):
                await self._log_collection_archive_size_advisory(
                    dut_id,
                    local_file,
                    archive_policy,
                )
                archive_valid, archive_error = (
                    await self._validate_advanced_archive_async(
                        local_file, generated_file, limits=archive_limits
                    )
                )
                if not archive_valid:
                    failure_message = (
                        "Rejected invalid downloaded NVOS tech-support archive "
                        f"{generated_file}: {archive_error or 'invalid archive'}"
                    )
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            acquisition_timing_id,
                            status="error",
                            error=failure_message,
                        )
                    record_failure(failure_message)
                    await self._log_runtime(
                        "ERROR",
                        "HostService",
                        failure_message,
                        dut_id,
                    )
                    await self._cleanup_remote_generated_file(
                        dut_id=dut_id,
                        remote_path=remote_path,
                        use_sudo=cleanup_use_sudo,
                    )
                    return None

                await self._log_runtime(
                    "INFO",
                    "HostService",
                    "Local archive passed bounded integrity validation",
                    dut_id,
                )
                if not self.logger:
                    raise RuntimeError(
                        "logger unavailable for NVOS archive persistence"
                    )
                final_filename = self.get_output_filename(
                    output_pattern,
                    generated_file,
                    ".txt",
                    substitutions,
                )
                file_path = await self.logger.create_collector_log_file(
                    dut_id,
                    "host",
                    filtered_kwargs.get("collector_id", ""),
                    final_filename,
                )
                if not file_path:
                    raise RuntimeError("unable to allocate NVOS archive output path")
                try:
                    copied_bytes = _copy_regular_file_bounded(
                        local_file,
                        str(file_path),
                        max_bytes=archive_max_bytes,
                    )
                except BaseException:
                    Path(file_path).unlink(missing_ok=True)
                    raise
                await self._log_runtime(
                    "INFO",
                    "HostService",
                    (
                        f"Persisted validated NVOS archive: {file_path} "
                        f"({copied_bytes} bytes)"
                    ),
                    dut_id,
                )

                # Clean up local file
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Cleaning up local file: {local_file}",
                    dut_id,
                )
                os.remove(local_file)

                cleanup_verified = await self._cleanup_remote_generated_file(
                    dut_id=dut_id,
                    remote_path=remote_path,
                    use_sudo=cleanup_use_sudo,
                )

                if not cleanup_verified:
                    failure_message = (
                        "Generated NVOS tech-support archive was saved, but "
                        "remote artifact cleanup could not be verified"
                    )
                    record_failure(failure_message)
                    await self._log_runtime(
                        "ERROR",
                        "HostService",
                        failure_message,
                        dut_id,
                    )
                    if self.timing_manager:
                        self.timing_manager.end_operation(
                            acquisition_timing_id,
                            status="error",
                            error=failure_message,
                            artifact_path=file_path,
                            size_bytes=copied_bytes,
                        )
                    return file_path

                await self._log_runtime(
                    "INFO",
                    "HostService",
                    (
                        f"NVOS archive collection completed: {generated_file}, "
                        f"bytes={copied_bytes}, remote_cleanup=verified"
                    ),
                    dut_id,
                )

                if self.timing_manager:
                    self.timing_manager.end_operation(
                        acquisition_timing_id,
                        artifact_path=file_path,
                        size_bytes=copied_bytes,
                    )

                return file_path
            else:
                failure_message = (
                    "Generated NVOS tech-support archive was not found locally "
                    f"after transfer: {local_file}"
                )
                if self.timing_manager:
                    self.timing_manager.end_operation(
                        acquisition_timing_id,
                        status="error",
                        error=failure_message,
                    )
                record_failure(failure_message)
                await self._log_runtime(
                    "ERROR",
                    "HostService",
                    failure_message,
                    dut_id,
                )
                return None

        except asyncio.CancelledError:
            if self.timing_manager:
                self.timing_manager.end_operation(
                    acquisition_timing_id,
                    status="cancelled",
                    error="CancelledError",
                )
            raise
        except Exception as e:
            if self.timing_manager:
                self.timing_manager.end_operation(
                    acquisition_timing_id,
                    status="error",
                    error=str(e),
                )
            if failure_messages is not None:
                failure_messages[command] = (
                    f"Exception during NVOS tech-support collection: {str(e)}"
                )
            await self._log_runtime(
                "ERROR",
                "HostService",
                f"Exception during file-generating command: {str(e)}",
                dut_id,
            )
            return None
        finally:
            if local_staging_dir:
                shutil.rmtree(local_staging_dir, ignore_errors=True)

    @staticmethod
    def _is_nvos_timeout_failure(output: Any) -> bool:
        """
        Return whether ``output`` is nvos timeout failure.

        The implementation uses ``output`` to determine whether ``output`` is
        nvos timeout failure.

        Args:
            output: Output consumed while the function attempts to determine
                whether ``output`` is nvos timeout failure.

        Returns:
            Whether ``output`` is nvos timeout failure.
        """
        message = str(output or "").lower()
        return "timeout" in message or "timed out" in message

    @staticmethod
    def _get_positive_int_config(
        value: Any, default: Optional[int] = None
    ) -> Optional[int]:
        """
        Return positive int config.

        The implementation uses ``value`` and ``default`` to produce positive
        int config.

        Args:
            value: Value evaluated while performing positive int config.
            default: Fallback used when the requested value is absent or
                invalid.

        Returns:
            The numeric positive int config value, or ``None`` when the
            requested value is unavailable.
        """
        try:
            int_value = int(value)
        except (TypeError, ValueError):
            return default

        if int_value <= 0:
            return default
        return int_value

    def _build_nvos_timeout_backoff_sequence(
        self,
        timeout: int,
        command_config: Dict[str, Any],
        filtered_kwargs: Dict[str, Any],
    ) -> List[int]:
        """
        Build nvos timeout backoff sequence.

        The resolved collector timeout comes from timeout_config, e.g.
        NVOS_TECH_DUMP_TIMEOUT for H14. Treat it as the total wait boundary
        while preserving catalog backoff milestones below it.

        Args:
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            command_config: Command config governing nvos timeout backoff
                sequence.
            filtered_kwargs: Mapping supplying fields for nvos timeout backoff
                sequence.

        Returns:
            The nvos timeout backoff sequence returned in operation-defined
            order.
        """
        base_timeout = self._get_positive_int_config(timeout, 1) or 1
        backoff_config = command_config.get("timeout_backoff")
        if backoff_config is None:
            backoff_config = filtered_kwargs.get("timeout_backoff")
        if not backoff_config:
            return [base_timeout]
        if not isinstance(backoff_config, dict):
            return [base_timeout]
        if backoff_config.get("enabled", True) is False:
            return [base_timeout]

        explicit_timeouts = backoff_config.get("timeouts")
        if isinstance(explicit_timeouts, (list, tuple)):
            timeout_values = []
            for timeout_value in explicit_timeouts:
                parsed_timeout = self._get_positive_int_config(timeout_value)
                if parsed_timeout is not None and parsed_timeout < base_timeout:
                    timeout_values.append(parsed_timeout)

            # The resolved collector timeout comes from timeout_config, e.g.
            # NVOS_TECH_DUMP_TIMEOUT for H14. Treat it as the total wait
            # boundary while preserving catalog backoff milestones below it.
            timeout_values.append(base_timeout)
            timeout_values = sorted(set(timeout_values))
            if len(timeout_values) <= 10:
                return timeout_values
            return timeout_values[:9] + [base_timeout]

        return [base_timeout]

    async def _list_nvos_generated_artifacts(
        self,
        dut_id: str,
        command_config: Dict[str, Any],
        use_sudo: bool,
    ) -> Dict[str, int]:
        """
        Return the list nvos generated artifacts.

        The implementation uses ``dut_id``, ``command_config``, and ``use_sudo``
        to produce the list nvos generated artifacts. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command_config: Command config governing list nvos generated
                artifacts.
            use_sudo: Whether use sudo is enabled or required for this
                operation.

        Returns:
            A mapping containing list nvos generated artifacts.
        """
        cleanup_glob = command_config.get(
            "cleanup_glob", "/host/dump/nvos_dump_*.tar.gz"
        )
        cleanup_dir, cleanup_pattern = self._split_remote_glob(cleanup_glob)
        stat_command = (
            f"find {shlex.quote(cleanup_dir)} -maxdepth 1 -type f "
            f"-name {shlex.quote(cleanup_pattern)} "
            "-exec stat -c '%s %n' {} \\;"
        )

        return_code, stdout, stderr = await self.dut_manager.execute_host_command(
            dut_id,
            stat_command,
            timeout=60,
            use_sudo=use_sudo,
        )
        if return_code != 0:
            await self._log_runtime(
                "WARNING",
                "HostService",
                f"Failed to list NVOS generated artifacts with {stat_command}: {stderr}",
                dut_id,
            )
            return {}

        artifacts: Dict[str, int] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                size_text, remote_path = line.split(maxsplit=1)
                artifacts[remote_path] = int(size_text)
            except (ValueError, TypeError):
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    f"Skipping unparsable NVOS artifact stat line: {line}",
                    dut_id,
                )
        return artifacts

    async def _wait_for_nvos_generated_artifact(
        self,
        dut_id: str,
        command_config: Dict[str, Any],
        baseline_artifacts: Dict[str, int],
        timeout_sequence: List[int],
        action_start: float,
        use_sudo: bool,
    ) -> Optional[str]:
        """
        Wait for nvos generated artifact.

        The implementation uses ``dut_id``, ``command_config``,
        ``baseline_artifacts``, ``timeout_sequence``, and ``action_start`` to
        wait for nvos generated artifact. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command_config: Command config governing wait for nvos generated
                artifact.
            baseline_artifacts: Mapping supplying fields for wait for nvos
                generated artifact.
            timeout_sequence: Maximum duration in seconds allowed for timeout
                sequence.
            action_start: Numeric action start used while the operation performs
                bounded accounting.
            use_sudo: Whether use sudo is enabled or required for this
                operation.

        Returns:
            The validated ``remote_path``, or ``None`` when no value qualifies.
        """
        max_total_wait = max(timeout_sequence) if timeout_sequence else 0
        deadline = action_start + max_total_wait
        poll_interval = self._get_non_negative_float_config(
            command_config.get(
                "artifact_poll_interval",
                command_config.get("cleanup_poll_interval"),
            ),
            5.0,
        )
        observed_sizes: Dict[str, int] = {}

        await self._log_runtime(
            "INFO",
            "HostService",
            (
                "Polling for queued NVOS tech-support artifact until total "
                f"wait reaches {max_total_wait}s (interval={poll_interval}s)"
            ),
            dut_id,
        )

        while True:
            artifacts = await self._list_nvos_generated_artifacts(
                dut_id=dut_id,
                command_config=command_config,
                use_sudo=use_sudo,
            )
            candidates = {
                path: size
                for path, size in artifacts.items()
                if path not in baseline_artifacts
            }

            for remote_path, size in sorted(candidates.items(), reverse=True):
                previous_size = observed_sizes.get(remote_path)
                if size > 0 and previous_size == size:
                    remaining_wait = deadline - time.monotonic()
                    if remaining_wait <= 0:
                        break

                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        (
                            "NVOS tech-support artifact size is stable; "
                            "validating archive before transfer: "
                            f"{remote_path} ({size} bytes)"
                        ),
                        dut_id,
                    )
                    validation_timeout = min(
                        self._get_positive_int_config(
                            command_config.get("artifact_validation_timeout"),
                            300,
                        )
                        or 300,
                        max(1, int(remaining_wait) + 1),
                    )
                    if await self._validate_nvos_generated_artifact(
                        dut_id=dut_id,
                        remote_path=remote_path,
                        command_config=command_config,
                        use_sudo=use_sudo,
                        timeout=validation_timeout,
                    ):
                        return remote_path
                observed_sizes[remote_path] = size
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    (
                        "Observed NVOS tech-support artifact candidate: "
                        f"{remote_path} ({size} bytes)"
                    ),
                    dut_id,
                )

            now = time.monotonic()
            if now >= deadline:
                break

            sleep_time = min(poll_interval, max(0.0, deadline - now))
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
            else:
                await asyncio.sleep(0)

        await self._log_runtime(
            "ERROR",
            "HostService",
            (
                "Timed out waiting for queued NVOS tech-support artifact "
                f"after {max_total_wait}s total wait"
            ),
            dut_id,
        )
        return None

    async def _validate_nvos_generated_artifact(
        self,
        dut_id: str,
        remote_path: str,
        command_config: Dict[str, Any],
        use_sudo: bool,
        timeout: int,
    ) -> bool:
        """
        Validate nvos generated artifact.

        The implementation uses ``dut_id``, ``remote_path``, ``command_config``,
        ``use_sudo``, and ``timeout`` to validate nvos generated artifact. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            remote_path: filesystem location used as the remote path for this
                operation.
            command_config: Command config governing nvos generated artifact.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.

        Returns:
            Whether the nvos generated artifact operation succeeds.
        """
        validation_template = command_config.get(
            "artifact_validation_command", "tar -tzf {path} >/dev/null"
        )
        if not validation_template:
            return True

        validation_command = build_remote_cmd(
            str(validation_template), path=remote_path
        )
        return_code, stdout, stderr = await self.dut_manager.execute_host_command(
            dut_id,
            validation_command,
            timeout=timeout,
            use_sudo=use_sudo,
        )
        if return_code == 0:
            await self._log_runtime(
                "INFO",
                "HostService",
                f"Validated NVOS tech-support archive: {remote_path}",
                dut_id,
            )
            return True

        await self._log_runtime(
            "DEBUG",
            "HostService",
            (
                "NVOS tech-support archive is not ready yet: "
                f"{remote_path}, rc={return_code}, stdout={stdout[:200]}, "
                f"stderr={stderr[:200]}"
            ),
            dut_id,
        )
        return False

    async def _cleanup_nvos_generated_artifacts(
        self, dut_id: str, remote_paths: List[str], use_sudo: bool
    ) -> bool:
        """
        Clean up nvos generated artifacts.

        The implementation uses ``dut_id``, ``remote_paths``, and ``use_sudo``
        to clean up nvos generated artifacts. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            remote_paths: Filesystem locations processed in caller-provided
                order.
            use_sudo: Whether use sudo is enabled or required for this
                operation.

        Returns:
            Whether the clean up nvos generated artifacts operation succeeds.
        """
        cleanup_verified = True
        for remote_path in remote_paths:
            cleaned = await self._cleanup_remote_generated_file(
                dut_id=dut_id,
                remote_path=remote_path,
                use_sudo=use_sudo,
            )
            cleanup_verified = cleaned and cleanup_verified
        return cleanup_verified

    @staticmethod
    def _split_remote_glob(cleanup_glob: str) -> Tuple[str, str]:
        """
        Return the split remote glob.

        The implementation uses ``cleanup_glob`` to produce the split remote
        glob.

        Args:
            cleanup_glob: Text supplied as cleanup glob in the format accepted
                by this function.

        Returns:
            A tuple containing the remote cleanup directory and the basename
            glob pattern to evaluate within that directory.
        """
        if "/" not in cleanup_glob:
            return ".", cleanup_glob

        cleanup_dir, cleanup_pattern = cleanup_glob.rsplit("/", 1)
        return cleanup_dir or "/", cleanup_pattern or "*"

    @staticmethod
    def _get_non_negative_float_config(value: Any, default: float) -> float:
        """
        Return non negative float config.

        The implementation uses ``value`` and ``default`` to produce non
        negative float config.

        Args:
            value: Value evaluated while performing non negative float config.
            default: Fallback used when the requested value is absent or
                invalid.

        Returns:
            The numeric non negative float config value.
        """
        try:
            float_value = float(value)
        except (TypeError, ValueError):
            return default

        if float_value < 0:
            return default
        return float_value

    async def _cleanup_remote_generated_file(
        self, dut_id: str, remote_path: str, use_sudo: bool
    ) -> bool:
        """
        Remove one generated remote file and verify that it is absent.

        The implementation uses ``dut_id``, ``remote_path``, and ``use_sudo`` to
        remove one generated remote file and verify that it is absent. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            remote_path: filesystem location used as the remote path for this
                operation.
            use_sudo: Whether use sudo is enabled or required for this
                operation.

        Returns:
            Whether the remove one generated remote file and verify that it is
            absent operation succeeds.
        """
        quoted_path = shlex.quote(remote_path)
        cleanup_command = f"rm -f -- {quoted_path} && test ! -e {quoted_path}"

        try:
            await self._log_runtime(
                "DEBUG",
                "HostService",
                f"Cleaning up remote generated file: {remote_path}",
                dut_id,
            )
            return_code, _stdout, stderr = await self.dut_manager.execute_host_command(
                dut_id,
                cleanup_command,
                timeout=60,
                use_sudo=use_sudo,
            )
            if return_code == 0:
                await self._log_runtime(
                    "INFO",
                    "HostService",
                    f"Removed and verified remote generated file: {remote_path}",
                    dut_id,
                )
                return True

            await self._log_runtime(
                "WARNING",
                "HostService",
                f"Failed to cleanup remote generated file {remote_path}: {stderr}",
                dut_id,
            )
            return False
        except Exception as exc:
            await self._log_runtime(
                "WARNING",
                "HostService",
                f"Failed to cleanup remote generated file {remote_path}: {exc}",
                dut_id,
            )
            return False

    def _extract_output_pattern_params(
        self, kwargs: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        """
        Extract output pattern parameters from kwargs.

        The implementation uses ``kwargs`` to extract output pattern parameters
        from kwargs.

        Args:
            kwargs: Mapping supplying fields for extract output pattern
                parameters from kwargs.

        Returns:
            A tuple containing the output pattern, substitution mapping, and
            remaining keyword arguments, in that order.
        """

        output_pattern = kwargs.get("output_pattern")
        substitutions = kwargs.get("substitutions", {})
        filtered_kwargs = {
            key: value
            for key, value in kwargs.items()
            if key
            not in {
                "output_pattern",
                "substitutions",
                "_remote_staging_owner",
            }
        }
        return output_pattern, substitutions, filtered_kwargs

    def _resolve_sftp_username(self, dut_id: str) -> Optional[str]:
        """
        Return the host SSH/SFTP username configured for ``dut_id``.

        Used to chown remote artifacts (created under sudo) to the user that
        will subsequently connect over SFTP, so the SFTP session can actually
        read them. Prefer this over shell-expanded ``$USER``, which depends on
        the remote sudoers env policy and often resolves to ``root`` under sudo,
        leaving the non-root SFTP session unable to read the artifact.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The canonical sftp username, or ``None`` when the requested value is
            unavailable.
        """
        try:
            dut = self.dut_manager.get_dut(dut_id)
        except Exception:
            return None
        username = getattr(getattr(dut, "credentials", None), "host_username", None)
        if isinstance(username, str) and username.strip():
            return username.strip()
        return None

    def _create_error_response(
        self,
        error_message: str,
        output_files: List[str] = None,
        context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Create a standardized error response.

        The implementation uses ``error_message``, ``output_files``, and
        ``context`` to create a standardized error response.

        Args:
            error_message: Text supplied as error message in the format accepted
                by this function.
            output_files: Optional output files; ``None`` selects the function's
                default behavior.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            A mapping containing the ``success``, ``error_message``,
            ``output_files``, and ``context`` fields.
        """
        reason = str(error_message).strip() or "Host collection failed"
        error_context = dict(context or {})
        error_context.setdefault("status", "error")
        error_context.setdefault("reason", reason)
        return {
            "success": False,
            "status": "error",
            "reason": reason,
            "error_message": reason,
            "output_files": output_files or [],
            "context": error_context,
        }

    # ============================================================================
    # Unified host-side file/log collection
    #
    # Replaces the deleted _handle_host_log_collection,
    # _handle_host_file_collection, and _handle_generic_log_collection
    # handlers. Legacy YAML keys (log_collection / file_collection /
    # generic_log) route through translator shims (_legacy_*_shim) into
    # this handler.
    # ============================================================================

    async def _handle_host_file_log_collection(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Unified host-side log/file collection.

        Replaces _handle_host_log_collection, _handle_host_file_collection, and
        _handle_generic_log_collection.

        YAML schema (summary):

            collection_type: file_log
            commands:
              - command: <shell producer>
                file_name: <basename>
                transport: command | staged_sftp      # default: command
                oversize_policy: tail_snapshot        # staged_sftp only
                max_artifact_bytes: <positive integer>
            targets:
              - path: <remote path or glob>
                transport: auto | sftp | command | staged_sftp  # default: auto
                oversize_policy: reject | tail_snapshot # default: reject;
                                                      # tail requires staged_sftp
                max_artifact_bytes: <positive integer>
                required: false                    # default: false
                platforms: [<baseboard...>]        # optional
            service_check:                         # optional
              service_name: <unit>
              required: true
              skip_on_not_found: true
              force_fallback: false | {default: false, <platform>: true}
            fallbacks:                             # optional
              - command: <shell>
                file_name: <basename>
                description: <text>
                timeout: <int>                     # optional; falls through to
                                                   # _resolve_collector_timeout()
                required: bool                     # default: true
                success_indicators: [<regex>, ...]
                failure_indicators: [<regex>, ...]
                match_mode: any | all              # default: any
            stop_on_first_success: bool            # default: false
            collect_all_available: bool            # default: true
            archive_targets: bool                  # default: false
            use_sudo: bool                         # default: true

        Behavior:
            1. Resolve the collector-level timeout via _resolve_collector_timeout().
            2. Optionally run the configured service check.
            3. For each target, pick a transport (sftp / command / staged_sftp /
               auto) and download. SFTP is the default for `auto`; staged_sftp
               supports privileged files without command-output materialization.
               An explicit tail_snapshot retains newest bounded bytes and
               reports raw, collected, and omitted counts without making the
               collector partial; the authored snapshot is the full contract.
            4. Run fallback commands when no target succeeded or
               force_fallback is set. Per-fallback success_indicators /
               failure_indicators (regex lists) augment exit-code success.
            5. Return the standardized collector result with
               `status: success | partial | error`.

        Status: success — at least one target collected; all required fallbacks
        (if force_fallback) also produced output. partial — at least one target
        collected with truncated bytes (SFTP interrupted by timeout), or some
        targets/fallbacks succeeded while others failed. The `context` dict
        records bytes_read, remote_size, and reason per partial target. error —
        no targets and no fallbacks succeeded.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing handle host file log collection.
        """

        async def _file_log_collection():
            # ---- 1. Resolve timeout via the unified resolver --------------------
            """
            Return the file log collection.

            After applying local validation, the function forwards current
            instance state to ``self._create_standardized_collector_result`` and
            preserves its return and exception contract. Owned asynchronous work
            is awaited before return, so completion does not leave an unobserved
            task behind.

            Returns:
                The file log collection.

            Raises:
                ValueError: If the remote archive source path is not absolute.
            """
            collector_timeout = await self._resolve_collector_timeout(
                dut_id, kwargs, default_timeout=300
            )

            platform = self._resolve_host_platform(dut_id)
            use_sudo = bool(kwargs.get("use_sudo", True))

            output_pattern, _substitutions, filtered_kwargs = (
                self._extract_output_pattern_params(kwargs)
            )
            since_str, until_str = await self._get_host_stream_window()

            commands = kwargs.get("commands") or []
            targets = kwargs.get("targets") or []
            service_check_cfg = kwargs.get("service_check") or {}
            fallbacks = kwargs.get("fallbacks") or []
            stop_on_first_success = bool(kwargs.get("stop_on_first_success", False))
            ignore_missing_targets = bool(kwargs.get("ignore_missing_targets", True))
            ignore_empty_results = bool(kwargs.get("ignore_empty_results", False))
            archive_targets = bool(kwargs.get("archive_targets", False))
            collector_config = kwargs.get("collector_config") or {}

            await self._log_runtime(
                "INFO",
                "HostService",
                (
                    f"Starting file_log collection for {function_tag} "
                    f"(platform={platform}, collector_timeout={collector_timeout}, "
                    f"targets={len(targets)}, fallbacks={len(fallbacks)})"
                ),
                dut_id,
            )

            output_files: List[str] = []
            error_messages: List[str] = []
            partial_metadata: List[Dict[str, Any]] = []
            bounded_snapshot_metadata: List[Dict[str, Any]] = []
            successful_operations = 0
            total_operations = 0
            any_target_collected = False
            archive_source_paths: List[str] = []
            archived_remote_paths: set[str] = set()

            # ---- 2. Service check (optional) ------------------------------------
            force_fallback = False
            proceed_with_targets = True
            service_not_found = False

            if service_check_cfg:
                ff_cfg = service_check_cfg.get("force_fallback", False)
                force_fallback = self._resolve_platform_flag(ff_cfg, platform)
                service_name = service_check_cfg.get("service_name")
                service_required = bool(service_check_cfg.get("required", False))
                skip_on_not_found = bool(
                    service_check_cfg.get("skip_on_not_found", False)
                )

                if service_required and service_name:
                    exit_code, stderr = await self._check_host_service_status(
                        dut_id, service_name, use_sudo
                    )
                    if exit_code == 4:  # Service not found
                        service_not_found = True
                        await self._log_runtime(
                            "WARN",
                            "HostService",
                            f"Service '{service_name}' not found",
                            dut_id,
                        )
                        if skip_on_not_found and not force_fallback:
                            proceed_with_targets = False
                            await self._log_runtime(
                                "INFO",
                                "HostService",
                                (
                                    f"Skipping targets for '{service_name}'; "
                                    "falling through to fallbacks (if any)"
                                ),
                                dut_id,
                            )
                    elif exit_code != 0:
                        await self._log_runtime(
                            "WARN",
                            "HostService",
                            (
                                f"Service '{service_name}' check failed "
                                f"(exit_code={exit_code}): {stderr}"
                            ),
                            dut_id,
                        )
                    else:
                        await self._log_runtime(
                            "INFO",
                            "HostService",
                            f"Service '{service_name}' is running",
                            dut_id,
                        )

            # ---- 3. Commands phase (primary, unconditional) -------------------
            # `commands` run before targets and are not gated by service_check.
            # They model log_commands from the legacy log_collection handler
            # and any non-file primary collection that must always execute.
            if commands:
                for cmd_idx, cmd_item in enumerate(commands, start=1):
                    total_operations += 1
                    if isinstance(cmd_item, str):
                        cmd_command = cmd_item
                        cmd_file_name = f"{function_tag}_cmd_{cmd_idx}.txt"
                        cmd_timeout = collector_timeout
                        cmd_ignore_errors = False
                        cmd_use_sudo = use_sudo
                        cmd_transport = "command"
                        cmd_oversize_policy = "reject"
                        cmd_success_indicators: List[str] = []
                        cmd_failure_indicators: List[str] = []
                        cmd_match_mode = "any"
                    elif isinstance(cmd_item, dict):
                        cmd_command = cmd_item.get("command")
                        if not cmd_command:
                            error_messages.append(
                                f"Command #{cmd_idx} missing 'command'"
                            )
                            continue
                        cmd_file_name = cmd_item.get(
                            "file_name", f"{function_tag}_cmd_{cmd_idx}.txt"
                        )
                        cmd_timeout = await self._resolve_collector_timeout(
                            dut_id,
                            kwargs,
                            default_timeout=300,
                            explicit_timeout_sources=[cmd_item, kwargs],
                        )
                        cmd_ignore_errors = bool(cmd_item.get("ignore_errors", False))
                        cmd_use_sudo = bool(cmd_item.get("use_sudo", use_sudo))
                        cmd_transport = cmd_item.get("transport", "command")
                        if cmd_transport not in ("command", "staged_sftp"):
                            error_messages.append(
                                f"Command {cmd_file_name}: invalid transport "
                                f"'{cmd_transport}' (expected 'command' or "
                                "'staged_sftp')"
                            )
                            continue
                        try:
                            cmd_oversize_policy = _resolve_host_oversize_policy(
                                cmd_item, cmd_transport
                            )
                        except ValueError as exc:
                            error_messages.append(
                                f"Command {cmd_file_name}: invalid bounded "
                                f"transport policy: {exc}"
                            )
                            continue
                        if (
                            cmd_transport == "staged_sftp"
                            and cmd_oversize_policy != "tail_snapshot"
                        ):
                            error_messages.append(
                                f"Command {cmd_file_name}: transport=staged_sftp "
                                "requires oversize_policy=tail_snapshot"
                            )
                            continue
                        cmd_success_indicators = (
                            cmd_item.get("success_indicators") or []
                        )
                        cmd_failure_indicators = (
                            cmd_item.get("failure_indicators") or []
                        )
                        cmd_match_mode = cmd_item.get("match_mode", "any")
                        if cmd_match_mode not in ("any", "all"):
                            error_messages.append(
                                f"Command {cmd_file_name}: invalid match_mode "
                                f"'{cmd_match_mode}' (expected 'any' or 'all')"
                            )
                            continue
                    else:
                        error_messages.append(
                            f"Command #{cmd_idx} must be a string or dict"
                        )
                        continue

                    resolved_cmd = self._apply_time_window(
                        cmd_command, since_str, until_str
                    )

                    if cmd_transport == "staged_sftp" and (
                        cmd_success_indicators or cmd_failure_indicators
                    ):
                        error_messages.append(
                            f"Command {cmd_file_name}: indicator matching is not "
                            "supported with bounded staged transport"
                        )
                        continue

                    if cmd_success_indicators or cmd_failure_indicators:
                        # Indicator-aware path: use the same helper as fallbacks.
                        cmd_result = await self._run_host_fallback_with_indicators(
                            dut_id=dut_id,
                            command=resolved_cmd,
                            file_name=cmd_file_name,
                            operation_name=f"{function_tag}_cmd_{cmd_idx}",
                            operation_type=f"{function_tag}_command",
                            output_pattern=output_pattern,
                            filtered_kwargs=filtered_kwargs,
                            use_sudo=cmd_use_sudo,
                            timeout=cmd_timeout,
                            success_indicators=cmd_success_indicators,
                            failure_indicators=cmd_failure_indicators,
                            match_mode=cmd_match_mode,
                        )
                        if cmd_result["success"]:
                            if cmd_result.get("file_path"):
                                output_files.append(cmd_result["file_path"])
                            successful_operations += 1
                        else:
                            error_messages.append(
                                f"Command failed: {cmd_command} "
                                f"({cmd_result.get('reason', 'unknown')})"
                            )
                    elif cmd_transport == "staged_sftp":
                        try:
                            command_max_artifact_bytes = (
                                _resolve_host_artifact_max_bytes(cmd_item, kwargs)
                            )
                        except ValueError as exc:
                            error_messages.append(f"Command {cmd_file_name}: {exc}")
                            continue
                        staged_command = (
                            await self._collect_bounded_staged_host_command(
                                dut_id=dut_id,
                                command=resolved_cmd,
                                file_name=cmd_file_name,
                                function_tag=function_tag,
                                output_pattern=output_pattern,
                                filtered_kwargs=filtered_kwargs,
                                use_sudo=cmd_use_sudo,
                                timeout=cmd_timeout,
                                max_bytes=command_max_artifact_bytes,
                            )
                        )
                        if staged_command["success"]:
                            output_files.append(staged_command["file_path"])
                            successful_operations += 1
                            bounded_snapshot_metadata.append(
                                {
                                    "source_type": "command",
                                    "file_name": cmd_file_name,
                                    "output_file": staged_command["file_path"],
                                    **staged_command["bounded_snapshot"],
                                }
                            )
                        else:
                            error_messages.append(
                                f"Command failed: {cmd_command} "
                                f"({staged_command.get('error') or 'unknown'})"
                            )
                    else:
                        # Exit-code path: reuse _execute_command_and_save for
                        # behavior-parity with the legacy commands handler.
                        success, file_path = await self._execute_command_and_save(
                            dut_id=dut_id,
                            command=resolved_cmd,
                            file_name=cmd_file_name,
                            operation_name=f"{function_tag}_cmd_{cmd_idx}",
                            operation_type=f"{function_tag}_command",
                            output_pattern=output_pattern,
                            filtered_kwargs=filtered_kwargs,
                            use_sudo=cmd_use_sudo,
                            timeout=cmd_timeout,
                            ignore_errors=cmd_ignore_errors,
                        )
                        if success and file_path:
                            output_files.append(file_path)
                            successful_operations += 1
                        else:
                            error_messages.append(f"Command failed: {cmd_command}")

            # ---- 4. Targets phase -----------------------------------------------
            if proceed_with_targets and targets:
                stop_targets = False
                for target_idx, target in enumerate(targets, start=1):
                    if stop_targets:
                        break

                    target_platforms = target.get("platforms")
                    if target_platforms and platform not in target_platforms:
                        await self._log_runtime(
                            "DEBUG",
                            "HostService",
                            (
                                f"Skipping target {target.get('path')} "
                                f"(platforms={target_platforms}, current={platform})"
                            ),
                            dut_id,
                        )
                        continue

                    path = target.get("path")
                    if not path:
                        total_operations += 1
                        error_messages.append(
                            f"Target #{target_idx} missing required 'path'"
                        )
                        continue

                    transport = target.get("transport", "auto")
                    if transport not in (
                        "auto",
                        "sftp",
                        "command",
                        "staged_sftp",
                    ):
                        total_operations += 1
                        error_messages.append(
                            f"Target {path} has invalid transport: {transport}"
                        )
                        continue
                    target_required = bool(target.get("required", False))
                    target_timeout = await self._resolve_collector_timeout(
                        dut_id,
                        kwargs,
                        default_timeout=300,
                        explicit_timeout_sources=[target, kwargs],
                    )

                    # Glob expansion (explicit flag, or auto-detected from path).
                    explicit_glob = target.get("glob")
                    has_wildcard = any(ch in path for ch in "*?[")
                    do_glob = (
                        bool(explicit_glob)
                        if explicit_glob is not None
                        else has_wildcard
                    )

                    if do_glob:
                        expanded_paths = await self._expand_remote_glob(
                            dut_id, path, use_sudo
                        )
                        if not expanded_paths:
                            # Legacy file_collection parity: empty glob pattern
                            # plus `ignore_empty_results=True` is counted as a
                            # success (the pattern was searched, intentionally
                            # produced nothing, and the collector tolerates it).
                            # H7 crash_dump on a healthy box hits this path.
                            if target_required:
                                total_operations += 1
                                error_messages.append(
                                    f"Required glob target produced no matches: {path}"
                                )
                            elif ignore_empty_results:
                                total_operations += 1
                                successful_operations += 1
                            elif not ignore_missing_targets:
                                total_operations += 1
                                error_messages.append(
                                    f"Glob target produced no matches: {path}"
                                )
                            # else: silent skip (matches legacy ignore_missing).
                            await self._log_runtime(
                                "DEBUG",
                                "HostService",
                                f"Glob target produced no matches: {path}",
                                dut_id,
                            )
                            continue
                    else:
                        expanded_paths = [path]

                    for expanded_idx, expanded_path in enumerate(expanded_paths):
                        if archive_targets:
                            try:
                                if not PurePosixPath(expanded_path).is_absolute():
                                    raise ValueError(
                                        "remote archive source path must be absolute"
                                    )
                                _safe_archive_member_name(expanded_path)
                            except (TypeError, ValueError) as exc:
                                total_operations += 1
                                error_messages.append(
                                    f"Unsafe archive target {expanded_path!r}: {exc}"
                                )
                                await self._log_runtime(
                                    "ERROR",
                                    "HostService",
                                    error_messages[-1],
                                    dut_id,
                                )
                                continue
                            if expanded_path in archived_remote_paths:
                                await self._log_runtime(
                                    "DEBUG",
                                    "HostService",
                                    f"Skipping duplicate archive source: {expanded_path}",
                                    dut_id,
                                )
                                continue

                        # Existence check (skip for already-expanded glob results
                        # since ls already proved they exist).
                        # Per legacy log_collection semantics, a
                        # target whose file is absent AND `ignore_missing_targets`
                        # is True is SILENTLY skipped — it does not contribute
                        # to total_operations. This keeps "all targets missing,
                        # ignore_missing=True" collectors as skipped/no-op
                        # rather than spurious "error" with 0/N succeeded.
                        if not do_glob:
                            check_cmd = build_remote_cmd(
                                (
                                    "test -e {path}"
                                    if archive_targets
                                    else "test -f {path}"
                                ),
                                path=expanded_path,
                            )
                            (
                                check_exit,
                                _,
                                _,
                            ) = await self.dut_manager.execute_host_command(
                                dut_id,
                                check_cmd,
                                timeout=30,
                                use_sudo=use_sudo,
                            )
                            if check_exit != 0:
                                if target_required:
                                    total_operations += 1
                                    error_messages.append(
                                        f"Required target not found: {expanded_path}"
                                    )
                                elif not ignore_missing_targets:
                                    total_operations += 1
                                    error_messages.append(
                                        f"Target not found: {expanded_path}"
                                    )
                                # else: ignore_missing_targets=True → silent skip
                                await self._log_runtime(
                                    "DEBUG",
                                    "HostService",
                                    f"Target file does not exist: {expanded_path}",
                                    dut_id,
                                )
                                continue

                        # Existence confirmed (or glob result) — count it.
                        total_operations += 1

                        if archive_targets:
                            archived_remote_paths.add(expanded_path)
                            archive_source_paths.append(expanded_path)
                            continue

                        # Per-target file name. For globs we derive from the
                        # remote basename; for fixed paths we let the YAML
                        # override or synthesize from index.
                        if do_glob:
                            file_name = os.path.basename(expanded_path)
                        else:
                            file_name = target.get(
                                "file_name",
                                f"{function_tag}_{target_idx}.log",
                            )
                        target_max_artifact_bytes = _resolve_host_artifact_max_bytes(
                            target,
                            kwargs,
                        )
                        if (
                            target.get("oversize_policy") == "tail_snapshot"
                            and target.get("max_artifact_bytes") is None
                        ):
                            error_messages.append(
                                f"Target {expanded_path}: "
                                "oversize_policy=tail_snapshot requires an "
                                "explicit max_artifact_bytes"
                            )
                            continue

                        download = await self._download_host_target(
                            dut_id=dut_id,
                            path=expanded_path,
                            transport=transport,
                            use_sudo=use_sudo,
                            timeout=target_timeout,
                            file_name=file_name,
                            function_tag=function_tag,
                            output_pattern=output_pattern,
                            filtered_kwargs=filtered_kwargs,
                            max_bytes=target_max_artifact_bytes,
                            oversize_policy=target.get("oversize_policy", "reject"),
                        )
                        if download["success"]:
                            output_files.append(download["file_path"])
                            successful_operations += 1
                            any_target_collected = True
                            if download.get("partial"):
                                partial_metadata.append(
                                    {
                                        "path": expanded_path,
                                        "bytes_read": download.get("bytes_read"),
                                        "remote_size": download.get("remote_size"),
                                        "reason": download.get("partial_reason"),
                                    }
                                )
                            if download.get("bounded_snapshot"):
                                bounded_snapshot_metadata.append(
                                    {
                                        "source_type": "target",
                                        "path": expanded_path,
                                        "output_file": download["file_path"],
                                        **download["bounded_snapshot"],
                                    }
                                )
                            await self._log_runtime(
                                "INFO",
                                "HostService",
                                (
                                    f"Collected target {expanded_path} via "
                                    f"{download.get('transport_used', transport)}"
                                ),
                                dut_id,
                            )
                            if stop_on_first_success:
                                stop_targets = True
                                break
                        else:
                            error_messages.append(
                                f"Failed to collect target {expanded_path}: "
                                f"{download.get('error', 'unknown')}"
                            )
                            await self._log_runtime(
                                "WARN",
                                "HostService",
                                f"Target collection failed: {expanded_path}",
                                dut_id,
                            )

            if archive_targets and archive_source_paths:
                archive_result = await self._archive_and_download_host_targets(
                    dut_id=dut_id,
                    source_paths=archive_source_paths,
                    function_tag=function_tag,
                    output_pattern=output_pattern,
                    filtered_kwargs=filtered_kwargs,
                    use_sudo=use_sudo,
                    timeout=collector_timeout,
                )
                if archive_result["success"]:
                    output_files.append(archive_result["file_path"])
                    successful_operations += len(archive_source_paths)
                    any_target_collected = True
                else:
                    error_messages.append(
                        "Failed to archive matched targets: "
                        f"{archive_result.get('error', 'unknown')}"
                    )

            # ---- 4. Fallbacks phase ---------------------------------------------
            should_try_fallbacks = bool(fallbacks) and (
                not any_target_collected or force_fallback
            )
            if should_try_fallbacks:
                if force_fallback:
                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        (
                            f"Running {len(fallbacks)} fallback(s) "
                            f"(force_fallback=True for platform {platform})"
                        ),
                        dut_id,
                    )
                else:
                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        f"No targets succeeded; running {len(fallbacks)} fallback(s)",
                        dut_id,
                    )

                for fb_idx, fb in enumerate(fallbacks, start=1):
                    fallback_required = bool(fb.get("required", True))
                    fb_command = fb.get("command")
                    if not fb_command:
                        if fallback_required:
                            total_operations += 1
                            error_messages.append(
                                f"Fallback #{fb_idx} missing 'command'"
                            )
                        continue
                    fb_file_name = fb.get(
                        "file_name", f"{function_tag}_fallback_{fb_idx}.log"
                    )
                    fb_description = fb.get(
                        "description", f"Fallback command #{fb_idx}"
                    )
                    fb_timeout = await self._resolve_collector_timeout(
                        dut_id,
                        kwargs,
                        default_timeout=300,
                        explicit_timeout_sources=[fb, kwargs],
                    )
                    fb_use_sudo = bool(fb.get("use_sudo", use_sudo))
                    resolved_cmd = self._apply_time_window(
                        fb_command, since_str, until_str
                    )

                    success_indicators = fb.get("success_indicators") or []
                    failure_indicators = fb.get("failure_indicators") or []
                    match_mode = fb.get("match_mode", "any")
                    if match_mode not in ("any", "all"):
                        if fallback_required:
                            total_operations += 1
                            error_messages.append(
                                f"Fallback {fb_description}: invalid match_mode "
                                f"'{match_mode}' (expected 'any' or 'all')"
                            )
                        continue

                    await self._log_runtime(
                        "INFO",
                        "HostService",
                        f"Executing fallback: {fb_description}",
                        dut_id,
                    )

                    fb_result = await self._run_host_fallback_with_indicators(
                        dut_id=dut_id,
                        command=resolved_cmd,
                        file_name=fb_file_name,
                        operation_name=f"{function_tag}_fallback_{fb_idx}",
                        operation_type=f"{function_tag}_fallback",
                        output_pattern=output_pattern,
                        filtered_kwargs=filtered_kwargs,
                        use_sudo=fb_use_sudo,
                        timeout=fb_timeout,
                        success_indicators=success_indicators,
                        failure_indicators=failure_indicators,
                        match_mode=match_mode,
                    )

                    if fb_result["success"]:
                        total_operations += 1
                        if fb_result.get("file_path"):
                            output_files.append(fb_result["file_path"])
                        successful_operations += 1
                        await self._log_runtime(
                            "INFO",
                            "HostService",
                            f"Fallback succeeded: {fb_description}",
                            dut_id,
                        )
                        if stop_on_first_success:
                            break
                    elif fallback_required:
                        total_operations += 1
                        error_messages.append(
                            f"Fallback failed: {fb_description} "
                            f"({fb_result.get('reason', 'unknown')})"
                        )
                        await self._log_runtime(
                            "WARN",
                            "HostService",
                            (
                                f"Fallback failed: {fb_description} — "
                                f"{fb_result.get('reason', 'unknown')}"
                            ),
                            dut_id,
                        )
                    else:
                        await self._log_runtime(
                            "INFO",
                            "HostService",
                            (
                                f"Optional fallback unavailable: {fb_description} — "
                                f"{fb_result.get('reason', 'unknown')}"
                            ),
                            dut_id,
                        )

            # Persist snapshot accounting before status determination. The
            # diagnostic artifact is required evidence for every successful
            # bounded snapshot, but it is not itself a source-file operation.
            data_output_file_count = len(output_files)
            bounded_snapshot_evidence: Optional[Dict[str, Any]] = None
            if bounded_snapshot_metadata:
                resolved_collector_id = (
                    filtered_kwargs.get("collector_id")
                    or kwargs.get("collector_id")
                    or self._get_current_collector_id()
                )
                try:
                    (
                        evidence_path,
                        projected_snapshot_metadata,
                    ) = await self._persist_bounded_snapshot_evidence(
                        dut_id,
                        resolved_collector_id,
                        function_tag,
                        bounded_snapshot_metadata,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    evidence_error = (
                        "Required bounded snapshot evidence could not be persisted"
                    )
                    error_messages.append(evidence_error)
                    bounded_snapshot_evidence = {
                        "status": "error",
                        "required": True,
                        "record_count": len(bounded_snapshot_metadata),
                    }
                    bounded_snapshot_metadata = []
                    await self._log_runtime(
                        "WARN",
                        "HostService",
                        f"{evidence_error} ({type(exc).__name__})",
                        dut_id,
                    )
                else:
                    output_files.append(evidence_path)
                    bounded_snapshot_metadata = projected_snapshot_metadata
                    bounded_snapshot_evidence = {
                        "status": "success",
                        "artifact": (
                            f"{_BOUNDED_SNAPSHOT_EVIDENCE_DIRECTORY}/"
                            f"{_safe_remote_output_component(function_tag)}"
                            f"{_BOUNDED_SNAPSHOT_EVIDENCE_SUFFIX}"
                        ),
                        "record_count": len(projected_snapshot_metadata),
                    }

            # ---- 5. Status determination ----------------------------------------
            collection_success = successful_operations > 0

            # ignore_empty_results: legacy file_collection treats zero outputs
            # as success when the collector is allowed to be empty (H7 crash
            # dumps on a healthy system). We honor it by promoting the empty
            # case from error -> success with a 1/1 dummy operation count, so
            # the standardized result helper computes status=success.
            if not collection_success and ignore_empty_results and not error_messages:
                effective_total = 1
                effective_successful = 1
                status_hint = "success"
                if total_operations == 0:
                    # No targets / commands / fallbacks even attempted —
                    # this matches the legacy "empty pattern result" flow.
                    pass
                message = collector_config.get(
                    "empty_expected_note",
                    f"{function_tag} collection produced no files "
                    "(empty result accepted)",
                )
            else:
                # Pass raw total_operations (no `max(..., 1)`
                # padding). When all targets are missing-but-ignored and there
                # are no commands/fallbacks, total_operations stays 0; the
                # standardized helper then returns status=skipped (success),
                # matching the legacy log_collection semantics for collectors
                # like H22/H6/H23 on platforms where their log paths don't
                # exist. Padding to 1 here turned that into a spurious "error".
                effective_total = total_operations
                effective_successful = successful_operations
                if collection_success:
                    status_hint = (
                        "partial"
                        if (
                            partial_metadata
                            or error_messages
                            or successful_operations < total_operations
                        )
                        else "success"
                    )
                else:
                    status_hint = "skipped" if total_operations == 0 else "error"
                if status_hint == "partial":
                    message = f"{function_tag} collection completed partially"
                elif collection_success:
                    message = collector_config.get(
                        "success_note",
                        f"{function_tag} collection completed",
                    )
                elif total_operations == 0:
                    message = (
                        f"{function_tag} collection skipped — "
                        "no targets, commands, or fallbacks needed execution"
                    )
                else:
                    message = collector_config.get(
                        "empty_unexpected_note",
                        f"{function_tag} collection failed",
                    )
                    if error_messages:
                        message += ": " + "; ".join(error_messages)

            # A successfully searched set of optional/glob targets can count as
            # completed work even when it produces no artifact. Preserve that
            # success, but report the configured expected-empty explanation
            # instead of the generic success note.
            if not output_files and ignore_empty_results and status_hint == "success":
                message = collector_config.get(
                    "empty_expected_note",
                    f"{function_tag} collection produced no files "
                    "(empty result accepted)",
                )

            if service_not_found:
                message += " (service not found)"

            return await self._create_standardized_collector_result(
                successful_operations=effective_successful,
                total_operations=effective_total,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="host_file_log_collection",
                additional_context={
                    "status": status_hint,
                    "reason": message,
                    "message": message,
                    "platform": platform,
                    "status_hint": status_hint,
                    "partial_metadata": partial_metadata,
                    "bounded_snapshot_metadata": bounded_snapshot_metadata,
                    "bounded_snapshot_evidence": bounded_snapshot_evidence,
                    "files_collected": data_output_file_count,
                    "source_files_collected": len(archive_source_paths),
                    "target_archive_created": bool(
                        archive_targets and archive_source_paths and output_files
                    ),
                    "archived_source_paths": archive_source_paths,
                    "function_tag": function_tag,
                    "service_not_found": service_not_found,
                    "force_fallback": force_fallback,
                    "ignore_empty_results": ignore_empty_results,
                },
            )

        return await self._execute_with_error_handling(
            dut_id, "host_file_log_collection", _file_log_collection
        )

    async def _expand_remote_glob(
        self, dut_id: str, pattern: str, use_sudo: bool
    ) -> List[str]:
        """
        Enumerate a validated remote glob inside a framed non-login shell.

        Returns the matched absolute paths in shell expansion order, or [] when
        nothing matches/the command fails. A POSIX loop ignores an unmatched
        pattern while retaining existing files, directories and symbolic links.
        The shell does not load login profiles. A per-call frame separates the
        exact path records from any banner emitted by the outer SSH shell.

        Matches are NUL-delimited, so every legal POSIX filename—including one
        containing a newline—is returned as one exact value. Nothing is
        stripped or rewritten: a name carrying a control character or
        surrounding whitespace stays intact so the caller's archive admission
        gate refuses that one target and records it, rather than silently
        turning it into a different operand.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            pattern: Text supplied as pattern in the format accepted by this
                function.
            use_sudo: Whether use sudo is enabled or required for this
                operation.

        Returns:
            The matched paths in shell expansion order, or an empty list when
            the pattern matched nothing or the enumeration command failed.

        Raises:
            ValueError: If unsafe remote glob pattern: ``pattern``.
            RuntimeError: If successful remote output lacks one complete path
                frame. Incomplete enumeration cannot authorize file collection.
        """
        path_parts = pattern.split("/")[1:] if isinstance(pattern, str) else []
        if (
            not isinstance(pattern, str)
            or self._SAFE_REMOTE_GLOB_PATTERN.fullmatch(pattern) is None
            or not path_parts
            or any(part in {"", ".", ".."} for part in path_parts)
        ):
            raise ValueError(f"Unsafe remote glob pattern: {pattern!r}")

        frame = f"NVDEBUG_GLOB_V1:{secrets.token_hex(16)}"
        frame_start = f"{frame}:BEGIN\0"
        frame_end = f"{frame}:END\0"
        inner_command = " ".join(
            (
                f"printf '%s\\0' {quote_arg(frame + ':BEGIN')};",
                f"for candidate in {pattern}; do",
                '[ -e "$candidate" ] || [ -L "$candidate" ] || continue;',
                "printf '%s\\0' \"$candidate\" || exit 1;",
                "done;",
                f"printf '%s\\0' {quote_arg(frame + ':END')}",
            )
        )
        list_command = shlex.join([TRUSTED_POSIX_SHELL_PATH, "-c", inner_command])
        exit_code, output, _ = await self.dut_manager.execute_host_command(
            dut_id, list_command, use_sudo=use_sudo
        )
        if exit_code != 0:
            return []
        if output.count(frame_start) != 1 or output.count(frame_end) != 1:
            raise RuntimeError("Remote glob enumeration frame is invalid")
        _banner, framed_output = output.split(frame_start, 1)
        if not framed_output.endswith(frame_end):
            raise RuntimeError("Remote glob enumeration frame is incomplete")
        records = framed_output[: -len(frame_end)]
        if records and not records.endswith("\0"):
            raise RuntimeError("Remote glob enumeration record is incomplete")
        if not records:
            return []
        candidates = records[:-1].split("\0")
        if any(not candidate.startswith("/") for candidate in candidates):
            raise RuntimeError("Remote glob enumeration path is not absolute")
        return candidates

    @staticmethod
    def _validate_downloaded_host_archive(
        archive_path: Path,
        source_paths: List[str],
        limits: Optional[ArchiveLimits] = None,
    ) -> None:
        """
        Validate the transferred gzip tar and its expected source roots.

        The implementation uses ``archive_path`` and ``source_paths`` to
        validate the transferred gzip tar and its expected source roots. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Args:
            archive_path: filesystem location used as the archive path for this
                operation.
            source_paths: Filesystem locations processed in caller-provided
                order.
            limits: Optional finite policy enforced while scanning every
                archive member and payload byte; ``None`` preserves the shared
                inbound default for direct compatibility callers.

        Raises:
            RuntimeError: If downloaded archive is empty; or the function cannot
                validate the transferred gzip tar and its expected source roots
                safely.
        """
        expected_roots = {
            _safe_archive_member_name(source_path) for source_path in source_paths
        }
        expected_prefixes = tuple(f"{root}/" for root in expected_roots)
        observed_roots: set[str] = set()

        def inspect_member(member: Any) -> None:
            """
            Inspect member.

            The implementation uses ``member`` to inspect member. If the
            function cannot inspect member, its exception reaches the caller
            instead of being converted into a successful result.

            Args:
                member: Member object whose ``duplicate``, ``kind``, and
                    ``name`` state is read while performing inspect member.

            Raises:
                RuntimeError: If the function cannot inspect member safely;
                    downloaded archive contains unsafe member: ``name``; or
                    downloaded archive contains unrequested member: ``name``.
            """
            if member.duplicate:
                raise RuntimeError(
                    "downloaded archive contains duplicate members: " + member.name
                )
            if member.kind not in {"file", "directory"}:
                raise RuntimeError(
                    f"downloaded archive contains unsafe member: {member.name}"
                )
            # Scope is checked in both directions.  ``member.name`` is the
            # consumer-normalized joined-parts form and ``expected_roots``
            # holds this collector's prediction of that same form, so the
            # comparison is like-for-like; the prefix arm keeps the subtree of
            # a legitimate directory operand admissible.
            if member.name not in expected_roots and not member.name.startswith(
                expected_prefixes
            ):
                raise RuntimeError(
                    f"downloaded archive contains unrequested member: {member.name}"
                )
            if member.name in expected_roots:
                observed_roots.add(member.name)

        # Structural validation, semantic inventory, and complete payload
        # hashing share one no-follow descriptor and one bounded TAR stream.
        # The path cannot be swapped between validation and inventory, and
        # tarfile never materializes an attacker-sized member object table.
        if limits is None:
            validation = inspect_tar_archive_metadata(archive_path, inspect_member)
        else:
            validation = inspect_tar_archive_metadata(
                archive_path,
                inspect_member,
                limits=limits,
            )

        if validation.members == 0:
            raise RuntimeError("downloaded archive is empty")
        missing_roots = sorted(expected_roots - observed_roots)
        if missing_roots:
            raise RuntimeError(
                "downloaded archive is missing matched targets: "
                + ", ".join(missing_roots)
            )

    async def _archive_and_download_host_targets(
        self,
        dut_id: str,
        source_paths: List[str],
        function_tag: str,
        output_pattern: Optional[str],
        filtered_kwargs: Dict[str, Any],
        use_sudo: bool,
        timeout: int,
    ) -> Dict[str, Any]:
        """
        Create and transfer one genuine archive containing all matched paths.

        The implementation uses ``dut_id``, ``source_paths``, ``function_tag``,
        ``output_pattern``, and ``filtered_kwargs`` to create and transfer one
        genuine archive containing all matched paths. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. If the function cannot create and transfer one genuine archive
        containing all matched paths, its exception reaches the caller instead
        of being converted into a successful result. Cleanup in the ``finally``
        path runs for successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            source_paths: Filesystem locations processed in caller-provided
                order.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            filtered_kwargs: Mapping supplying fields for and transfer one
                genuine archive containing all matched paths.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.

        Returns:
            A mapping containing the ``success``, ``file_path``, and ``error``
            fields.

        Raises:
            ValueError: If the remote archive source path is not absolute:
                ``source_path``.
        """
        if not source_paths:
            return {
                "success": False,
                "file_path": None,
                "error": "no source paths were provided",
            }
        if (
            not isinstance(output_pattern, str)
            or output_pattern != os.path.basename(output_pattern)
            or "{" in output_pattern
            or not output_pattern.endswith(".tar.gz")
        ):
            return {
                "success": False,
                "file_path": None,
                "error": ("archive_targets requires a static .tar.gz output_pattern"),
            }
        if not self.logger:
            return {
                "success": False,
                "file_path": None,
                "error": "logger unavailable; cannot publish target archive",
            }

        unique_paths = list(dict.fromkeys(source_paths))
        try:
            for source_path in unique_paths:
                if not PurePosixPath(source_path).is_absolute():
                    raise ValueError(
                        f"remote archive source path must be absolute: {source_path!r}"
                    )
                _safe_archive_member_name(source_path)
        except (TypeError, ValueError) as exc:
            return {"success": False, "file_path": None, "error": str(exc)}

        safe_tag = re.sub(r"[^A-Za-z0-9_.-]+", "_", function_tag).strip("._")
        safe_tag = safe_tag or "host_files"
        token = hashlib.sha256(
            f"{dut_id}:{function_tag}:{time.time_ns()}".encode("utf-8")
        ).hexdigest()[:16]
        owned_stages: List[_RemoteStagingDirectory] = []
        remote_archive: Optional[str] = None

        try:
            archive_stage = await self._create_remote_staging_directory(
                dut_id,
                f"host-files-{safe_tag}",
                use_sudo=use_sudo,
                owned_stages=owned_stages,
            )
            remote_archive = self._remote_staging_file_path(
                archive_stage,
                f"archive_{token}.tar.gz",
            )
            create_command = build_link_safe_tar_create_command(
                remote_archive,
                unique_paths,
                tar_command=TRUSTED_REMOTE_TAR_COMMAND,
            )
            create_exit, _, create_stderr = await self.dut_manager.execute_host_command(
                dut_id,
                create_command,
                timeout=timeout,
                use_sudo=use_sudo,
            )
            if create_exit != 0:
                return {
                    "success": False,
                    "file_path": None,
                    "error": (
                        f"tar creation failed with exit code {create_exit}: "
                        f"{create_stderr.strip()}"
                    ),
                }

            validate_command = (
                f"PATH={TRUSTED_PRIVILEGED_PATH}; export PATH; "
                f"{TRUSTED_REMOTE_TAR_COMMAND} -tzf "
                f"{quote_arg(remote_archive)} >/dev/null"
            )
            (
                validate_exit,
                _,
                validate_stderr,
            ) = await self.dut_manager.execute_host_command(
                dut_id,
                validate_command,
                timeout=timeout,
                use_sudo=use_sudo,
            )
            if validate_exit != 0:
                return {
                    "success": False,
                    "file_path": None,
                    "error": (
                        f"created archive failed validation: {validate_stderr.strip()}"
                    ),
                }

            prepared, preparation_error = await self._prepare_remote_staging_files(
                dut_id,
                archive_stage,
                [remote_archive],
            )
            if not prepared:
                return {
                    "success": False,
                    "file_path": None,
                    "error": (
                        "could not privately hand off archive to the SFTP user"
                        + (
                            f": {preparation_error.strip()}"
                            if preparation_error
                            else ""
                        )
                    ),
                }

            tool_config: Dict[str, Any] = {}
            try:
                tool_config = await self.orchestrator.get_dut_specific_tool_config(
                    dut_id
                )
            except Exception:
                pass
            with tempfile.TemporaryDirectory(
                prefix="nvdebug-host-archive-",
                dir=local_temp_dir(tool_config),
            ) as local_staging_dir:
                archive_policy = _resolve_host_archive_transfer_policy(filtered_kwargs)
                staged_archive = Path(local_staging_dir) / output_pattern
                (
                    transfer_success,
                    staged_path,
                    transfer_error,
                ) = await self._save_transferred_host_file(
                    dut_id,
                    remote_archive,
                    output_pattern,
                    filtered_kwargs,
                    timeout=timeout,
                    destination_path=staged_archive,
                    max_bytes=archive_policy.max_transfer_bytes,
                )
                if not transfer_success or not staged_path:
                    return {
                        "success": False,
                        "file_path": None,
                        "error": transfer_error or "archive transfer failed",
                    }

                await self._log_collection_archive_size_advisory(
                    dut_id,
                    staged_path,
                    archive_policy,
                )
                await _run_managed_filesystem_operation(
                    self._validate_downloaded_host_archive,
                    Path(staged_path),
                    unique_paths,
                    archive_policy.validation_limits,
                )
                final_archive = Path(
                    await self.logger.create_collector_log_file(
                        dut_id,
                        "host",
                        filtered_kwargs.get("collector_id", ""),
                        output_pattern,
                    )
                )
                _publish_file_atomically(Path(staged_path), final_archive)
                if self.timing_manager:
                    self.timing_manager.remap_current_collector_artifact_path(
                        staged_path, final_archive
                    )
                return {
                    "success": True,
                    "file_path": str(final_archive),
                    "error": None,
                }
        except Exception as exc:
            return {"success": False, "file_path": None, "error": str(exc)}
        finally:
            try:
                if remote_archive is not None:
                    cleanup_command = build_remote_cmd(
                        "rm -f {path}", path=remote_archive
                    )
                    try:
                        cleanup_exit, _, cleanup_stderr = (
                            await self.dut_manager.execute_host_command(
                                dut_id,
                                cleanup_command,
                                timeout=60,
                                use_sudo=use_sudo,
                            )
                        )
                    except Exception as cleanup_error:
                        await self._log_runtime(
                            "WARN",
                            "HostService",
                            (
                                "Failed to remove temporary H7 archive "
                                f"{remote_archive}: {cleanup_error}"
                            ),
                            dut_id,
                        )
                    else:
                        if cleanup_exit != 0:
                            await self._log_runtime(
                                "WARN",
                                "HostService",
                                (
                                    "Failed to remove temporary H7 archive "
                                    f"{remote_archive}: {cleanup_stderr.strip()}"
                                ),
                                dut_id,
                            )
            finally:
                try:
                    await self._cleanup_remote_staging_directories(
                        dut_id,
                        owned_stages,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as cleanup_error:
                    await self._log_runtime(
                        "WARN",
                        "HostService",
                        (
                            "Failed to remove private H7 archive staging: "
                            f"{cleanup_error}"
                        ),
                        dut_id,
                    )

    async def _collect_bounded_staged_host_command(
        self,
        dut_id: str,
        command: str,
        file_name: str,
        function_tag: str,
        output_pattern: Optional[str],
        filtered_kwargs: Dict[str, Any],
        use_sudo: bool,
        timeout: int,
        max_bytes: int,
    ) -> Dict[str, Any]:
        """
        Collect command stdout as an authored bounded newest-byte snapshot.

        The command runs inside a private remote stage whose producer stream is
        counted and tailed concurrently. The bounded artifact is handed to the
        SFTP identity only after a validated receipt, then transferred through
        the existing chunked local persistence path. Any producer, receipt,
        handoff, transfer, or cleanup failure remains an unsuccessful command.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration,
                logs, and results.
            command: Safely rendered command whose stdout is collected.
            file_name: Stable basename used for the collected artifact.
            function_tag: Collector function tag used in staging diagnostics.
            output_pattern: Optional output naming pattern for persistence.
            filtered_kwargs: Validated collector arguments forwarded to the
                persistence path.
            use_sudo: Whether the private producer runs through the trusted sudo
                boundary.
            timeout: Maximum duration allowed for remote production and transfer.
            max_bytes: Maximum newest stdout bytes retained.

        Returns:
            A mapping containing the success flag, file path, snapshot metadata,
            and precise failure reason.
        """
        owned_stages: List[_RemoteStagingDirectory] = []

        async def collect_from_stage() -> Dict[str, Any]:
            """
            Produce, hand off, and transfer the bounded staged artifact.

            The nested operation owns production and transfer only; its outer
            caller retains the stage and may override success when exact remote
            cleanup cannot be verified.

            Returns:
                The pre-cleanup collection outcome. The outer owner may replace
                a successful outcome when exact stage cleanup fails.
            """

            stage = await self._create_remote_staging_directory(
                dut_id,
                f"file-log-command-{function_tag}",
                use_sudo=use_sudo,
                owned_stages=owned_stages,
                configured_root=filtered_kwargs.get("remote_staging_root"),
            )
            staged_file = self._remote_staging_file_path(stage, file_name)
            snapshot = await self._stage_remote_tail_snapshot(
                dut_id,
                str(filtered_kwargs.get("collector_id") or ""),
                stage,
                staged_file,
                command,
                max_bytes=max_bytes,
                timeout=timeout,
            )
            if not snapshot["success"]:
                return {
                    "success": False,
                    "file_path": None,
                    "bounded_snapshot": None,
                    "error": snapshot["error"],
                }
            prepared, prepare_error = await self._prepare_remote_staging_files(
                dut_id,
                stage,
                [staged_file],
            )
            if not prepared:
                return {
                    "success": False,
                    "file_path": None,
                    "bounded_snapshot": snapshot["metadata"],
                    "error": "private staging ownership handoff failed"
                    + (f": {prepare_error.strip()}" if prepare_error else ""),
                }
            (
                transfer_success,
                transfer_file_path,
                transfer_error,
            ) = await self._save_transferred_host_file(
                dut_id,
                staged_file,
                output_pattern,
                filtered_kwargs,
                timeout=timeout,
                max_bytes=max_bytes,
            )
            return {
                "success": bool(transfer_success and transfer_file_path),
                "file_path": transfer_file_path,
                "bounded_snapshot": snapshot["metadata"],
                "error": transfer_error,
            }

        try:
            result = await collect_from_stage()
        finally:
            cleanup_succeeded = await self._cleanup_remote_staging_directories(
                dut_id, owned_stages
            )
        if not cleanup_succeeded:
            result["success"] = False
            result["error"] = "private remote staging cleanup failed"
        return result

    async def _download_host_target(
        self,
        dut_id: str,
        path: str,
        transport: str,
        use_sudo: bool,
        timeout: int,
        file_name: str,
        function_tag: str,
        output_pattern: Optional[str],
        filtered_kwargs: Dict[str, Any],
        max_bytes: int,
        oversize_policy: str = "reject",
    ) -> Dict[str, Any]:
        """
        Download a single target file using the requested transport.

        Returns a dict:
            {
              "success": bool,
              "file_path": str | None,
              "transport_used": "sftp" | "command" | "staged_sftp",
              "partial": bool,
              "bytes_read": int | None,
              "remote_size": int | None,
              "partial_reason": str | None,
              "error": str | None,
            }

        Transport semantics:
            command — `cat` over SSH stdout via _execute_command_and_save.
                      Preserves legacy behavior, supports sudo.
            sftp    — Use _save_transferred_host_file (whole-file SFTP via
                      dut_manager.transfer_host_files). The underlying SFTP
                      reader is bounded and chunked. Does not support sudo.
            staged_sftp — Under the default reject policy, stream at most
                      max_bytes + 1 into an owned private remote stage and
                      reject overflow. Under explicit tail_snapshot policy,
                      stream-count the source and retain its newest max_bytes.
                      Hand the resulting exact regular file to the SFTP
                      identity, then use bounded chunked SFTP. Supports
                      privileged sources without materializing their contents
                      in SSH command output.
            auto    — Try SFTP first; on failure, fall back to command. Used
                      when the YAML author wants SFTP if available without
                      hard-failing on permission/transport issues.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            path: Filesystem location used as the path for this operation.
            transport: Transfer strategy selected for this operation.
            use_sudo: Whether sudo is enabled or required for this operation.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            file_name: Stable file name used for lookup and operator-facing
                diagnostics.
            function_tag: Function tag used to identify the collector operation.
            output_pattern: Optional output naming pattern for the collected file.
            filtered_kwargs: Validated collector arguments forwarded to the
                selected transport helper.
            max_bytes: Upper bound enforced while transferring the remote file.
            oversize_policy: Authored behavior when a staged source exceeds
                ``max_bytes``. ``reject`` preserves complete-file semantics;
                ``tail_snapshot`` retains an explicitly bounded newest-byte
                snapshot.

        Returns:
            The validated transfer result.
        """
        result: Dict[str, Any] = {
            "success": False,
            "file_path": None,
            "transport_used": transport,
            "partial": False,
            "bytes_read": None,
            "remote_size": None,
            "partial_reason": None,
            "error": None,
        }
        try:
            resolved_oversize_policy = _resolve_host_oversize_policy(
                {
                    "oversize_policy": oversize_policy,
                    "max_artifact_bytes": max_bytes,
                },
                transport,
            )
        except ValueError as exc:
            result["error"] = str(exc)
            return result

        async def _via_command() -> Dict[str, Any]:
            """
            Return the via command.

            The implementation uses current instance state to produce the via
            command. Owned asynchronous work is awaited before return, so
            completion does not leave an unobserved task behind.

            Returns:
                A mapping containing the ``success``, ``file_path``,
                ``transport_used``, and ``error`` fields.
            """
            success, file_path = await self._execute_command_and_save(
                dut_id=dut_id,
                command=build_remote_cmd("cat {path}", path=path),
                file_name=file_name,
                operation_name=f"{function_tag}_target_{file_name}",
                operation_type="host_file_log_target",
                output_pattern=output_pattern,
                filtered_kwargs=filtered_kwargs,
                use_sudo=use_sudo,
                timeout=timeout,
            )
            return {
                "success": bool(success and file_path),
                "file_path": file_path,
                "transport_used": "command",
                "error": None if success else "cat over SSH failed",
            }

        async def _via_sftp() -> Dict[str, Any]:
            """
            Return the via sftp.

            The implementation uses current instance state to produce the via
            sftp. Owned asynchronous work is awaited before return, so
            completion does not leave an unobserved task behind.

            Returns:
                A mapping containing the ``success``, ``file_path``,
                ``transport_used``, and ``error`` fields.
            """
            (
                transfer_success,
                transfer_file_path,
                transfer_error,
            ) = await self._save_transferred_host_file(
                dut_id,
                path,
                output_pattern,
                filtered_kwargs,
                timeout=timeout,
                max_bytes=max_bytes,
            )
            return {
                "success": bool(transfer_success and transfer_file_path),
                "file_path": transfer_file_path,
                "transport_used": "sftp",
                "error": transfer_error,
            }

        async def _via_staged_sftp() -> Dict[str, Any]:
            """
            Transfer a bounded privileged file through private SFTP staging.

            The helper creates and owns a private remote staging directory.
            Under the default ``reject`` policy, it copies at most
            ``max_bytes + 1`` bytes to detect overflow. Under the explicit
            ``tail_snapshot`` policy, it streams and counts the source once,
            retaining only its newest bounded bytes. Both paths transfer the
            prepared regular file through bounded SFTP and clean up every
            owned stage before returning or propagating an exception.

            Returns:
                A mapping containing the ``success``, ``file_path``,
                ``transport_used``, and ``error`` fields.
            """
            owned_stages: List[_RemoteStagingDirectory] = []

            async def stage_and_transfer() -> Dict[str, Any]:
                """
                Produce and transfer one privately staged target.

                Production policy is selected before transfer, but stage
                cleanup remains with the surrounding owner so every return and
                exception crosses the same authoritative cleanup boundary.

                Returns:
                    The pre-cleanup staged transfer outcome. Exact cleanup is
                    evaluated separately by the owning outer function.
                """

                stage = await self._create_remote_staging_directory(
                    dut_id,
                    f"file-log-{function_tag}",
                    use_sudo=use_sudo,
                    owned_stages=owned_stages,
                    configured_root=filtered_kwargs.get("remote_staging_root"),
                )
                staged_file = self._remote_staging_file_path(stage, file_name)
                snapshot_metadata: Optional[Dict[str, Any]] = None
                if resolved_oversize_policy == "tail_snapshot":
                    snapshot = await self._stage_remote_tail_snapshot(
                        dut_id,
                        str(filtered_kwargs.get("collector_id") or ""),
                        stage,
                        staged_file,
                        build_remote_cmd("cat -- {source}", source=path),
                        max_bytes=max_bytes,
                        timeout=timeout,
                    )
                    if not snapshot["success"]:
                        return {
                            "success": False,
                            "file_path": None,
                            "transport_used": "staged_sftp",
                            "error": snapshot["error"],
                        }
                    snapshot_metadata = snapshot["metadata"]
                else:
                    # Capture one extra byte so an over-limit source is
                    # rejected before ownership handoff or download. The
                    # legacy/default policy remains complete-file-only.
                    stage_command = build_remote_cmd(
                        "source={source}; destination={destination}; "
                        "read_limit={read_limit}; max_bytes={max_bytes}; "
                        'umask 077; head -c "$read_limit" -- "$source" '
                        '> "$destination" && test "$(wc -c < "$destination")" '
                        '-le "$max_bytes"',
                        read_limit=max_bytes + 1,
                        source=path,
                        destination=staged_file,
                        max_bytes=max_bytes,
                    )
                    (
                        stage_exit,
                        _stage_stdout,
                        stage_stderr,
                    ) = await self._execute_remote_staging_command(
                        dut_id,
                        stage_command,
                        use_sudo=use_sudo,
                        timeout=timeout,
                    )
                    if stage_exit != 0:
                        return {
                            "success": False,
                            "file_path": None,
                            "transport_used": "staged_sftp",
                            "error": (
                                "source could not be privately staged within the "
                                f"configured {max_bytes}-byte bound"
                                + (f": {stage_stderr.strip()}" if stage_stderr else "")
                            ),
                        }

                prepared, prepare_error = await self._prepare_remote_staging_files(
                    dut_id,
                    stage,
                    [staged_file],
                )
                if not prepared:
                    return {
                        "success": False,
                        "file_path": None,
                        "transport_used": "staged_sftp",
                        "error": (
                            "private staging ownership handoff failed"
                            + (f": {prepare_error.strip()}" if prepare_error else "")
                        ),
                    }

                (
                    transfer_success,
                    transfer_file_path,
                    transfer_error,
                ) = await self._save_transferred_host_file(
                    dut_id,
                    staged_file,
                    output_pattern,
                    filtered_kwargs,
                    timeout=timeout,
                    max_bytes=max_bytes,
                )
                return {
                    "success": bool(transfer_success and transfer_file_path),
                    "file_path": transfer_file_path,
                    "transport_used": "staged_sftp",
                    "error": transfer_error,
                    **(
                        {"bounded_snapshot": snapshot_metadata}
                        if snapshot_metadata is not None
                        else {}
                    ),
                }

            try:
                staged_result = await stage_and_transfer()
            finally:
                cleanup_succeeded = await self._cleanup_remote_staging_directories(
                    dut_id, owned_stages
                )
            if not cleanup_succeeded:
                staged_result["success"] = False
                staged_result["error"] = "private remote staging cleanup failed"
            return staged_result

        if transport == "command":
            outcome = await _via_command()
        elif transport == "sftp":
            outcome = await _via_sftp()
        elif transport == "staged_sftp":
            outcome = await _via_staged_sftp()
        else:  # auto
            outcome = await _via_sftp()
            if not outcome["success"]:
                await self._log_runtime(
                    "DEBUG",
                    "HostService",
                    (
                        f"SFTP failed for {path} ({outcome.get('error')}), "
                        "falling back to command transport"
                    ),
                    dut_id,
                )
                outcome = await _via_command()

        result.update(outcome)
        return result

    async def _run_host_fallback_with_indicators(
        self,
        dut_id: str,
        command: str,
        file_name: str,
        operation_name: str,
        operation_type: str,
        output_pattern: Optional[str],
        filtered_kwargs: Dict[str, Any],
        use_sudo: bool,
        timeout: int,
        success_indicators: List[str],
        failure_indicators: List[str],
        match_mode: str,
    ) -> Dict[str, Any]:
        """
        Run host fallback with indicators.

        Apply failure_indicators first — they veto exit-code success.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            file_name: Stable file name used for lookup and operator-facing
                diagnostics.
            operation_name: Stable operation name used for lookup and
                operator-facing diagnostics.
            operation_type: Text supplied as operation type in the format
                accepted by this function.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            filtered_kwargs: Mapping supplying fields for host fallback with
                indicators.
            use_sudo: Whether use sudo is enabled or required for this
                operation.
            timeout: Maximum duration allowed before the operation is cancelled
                or fails.
            success_indicators: Entries supplied as ``success_indicators``
                without transferring container ownership.
            failure_indicators: Entries supplied as ``failure_indicators``
                without transferring container ownership.
            match_mode: Text supplied as match mode in the format accepted by
                this function.

        Returns:
            A mapping containing the ``success``, ``file_path``, and ``reason``
            fields.
        """
        await self._write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "HostService",
            f"Fallback command: {command} (timeout={timeout}, use_sudo={use_sudo})",
        )

        exit_code, stdout, stderr = await self._execute_host_command_with_capture(
            dut_id,
            command,
            operation_name=operation_name,
            timeout=timeout,
            use_sudo=use_sudo,
            output_file=file_name,
        )

        # Apply failure_indicators first — they veto exit-code success.
        if failure_indicators:
            haystack = (stdout or "") + "\n" + (stderr or "")
            for pat in failure_indicators:
                try:
                    if re.search(pat, haystack):
                        return {
                            "success": False,
                            "file_path": None,
                            "reason": (
                                f"failure_indicator matched: {pat!r} "
                                f"(exit_code={exit_code})"
                            ),
                        }
                except re.error as exc:
                    return {
                        "success": False,
                        "file_path": None,
                        "reason": (f"invalid failure_indicator regex {pat!r}: {exc}"),
                    }

        # Decide success.
        if success_indicators:
            haystack = (stdout or "") + "\n" + (stderr or "")
            matched = []
            for pat in success_indicators:
                try:
                    if re.search(pat, haystack):
                        matched.append(pat)
                except re.error as exc:
                    return {
                        "success": False,
                        "file_path": None,
                        "reason": (f"invalid success_indicator regex {pat!r}: {exc}"),
                    }
            if match_mode == "all":
                indicator_ok = len(matched) == len(success_indicators)
            else:  # any
                indicator_ok = bool(matched)
            if not indicator_ok:
                return {
                    "success": False,
                    "file_path": None,
                    "reason": (
                        f"no success_indicator matched (mode={match_mode}, "
                        f"matched={len(matched)}/{len(success_indicators)}, "
                        f"exit_code={exit_code})"
                    ),
                }
        else:
            if exit_code != 0:
                return {
                    "success": False,
                    "file_path": None,
                    "reason": f"exit_code={exit_code}",
                }

        # Save output regardless of how we decided success — the file is
        # evidence either way, and partial output is useful for triage.
        file_path = await self._save_data_with_common_pattern(
            dut_id,
            stdout if stdout is not None else "",
            file_name,
            output_pattern=output_pattern,
            substitutions={"file_name": file_name},
            **filtered_kwargs,
        )

        return {"success": True, "file_path": file_path, "reason": None}

    # --- Legacy → file_log translation shims ------------------------------------
    #
    # These shims preserve older collection_type keys while collector YAML
    # migrates to `collection_type: file_log`.

    async def _legacy_log_collection_shim(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Return the legacy log collection shim.

        After applying local validation, the function forwards ``dut_id``,
        ``function_tag``, and ``kwargs`` to
        ``self._handle_host_file_log_collection`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing legacy log collection shim.
        """
        await self._log_runtime(
            "INFO",
            "HostService",
            (
                "Legacy collection_type=log_collection routed through "
                "the unified file_log handler via shim. Please migrate this "
                "collector's YAML to collection_type=file_log."
            ),
            dut_id,
        )

        translated = self._translate_log_collection_kwargs(kwargs)
        return await self._handle_host_file_log_collection(
            dut_id, function_tag, **translated
        )

    async def _legacy_file_collection_shim(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Return the legacy file collection shim.

        After applying local validation, the function forwards ``dut_id``,
        ``function_tag``, and ``kwargs`` to
        ``self._handle_host_file_log_collection`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing legacy file collection shim.
        """
        await self._log_runtime(
            "INFO",
            "HostService",
            (
                "Legacy collection_type=file_collection routed through "
                "the unified file_log handler via shim. Please migrate this "
                "collector's YAML to collection_type=file_log."
            ),
            dut_id,
        )

        translated = self._translate_file_collection_kwargs(kwargs)
        return await self._handle_host_file_log_collection(
            dut_id, function_tag, **translated
        )

    async def _legacy_generic_log_shim(
        self, dut_id: str, function_tag: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Return the legacy generic log shim.

        After applying local validation, the function forwards ``dut_id``,
        ``function_tag``, and ``kwargs`` to
        ``self._handle_host_file_log_collection`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing legacy generic log shim.
        """
        await self._log_runtime(
            "INFO",
            "HostService",
            (
                "Legacy collection_type=generic_log routed through "
                "the unified file_log handler via shim. Please migrate this "
                "collector's YAML to collection_type=file_log."
            ),
            dut_id,
        )

        platform = self._resolve_host_platform(dut_id)
        translated = self._translate_generic_log_kwargs(kwargs, platform)
        return await self._handle_host_file_log_collection(
            dut_id, function_tag, **translated
        )

    # ----- Shim helpers (pure translation; no I/O) ---------------------------

    @staticmethod
    def _translate_log_collection_kwargs(
        kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        log_collection → file_log kwargs translator.

        Pure function.

        The implementation uses ``kwargs`` to log_collection → file_log kwargs
        translator.

        Args:
            kwargs: Mapping supplying fields for log_collection → file_log
                kwargs translator.

        Returns:
            The validated ``translated``.
        """
        log_commands = (
            kwargs.get("log_commands", kwargs.get("journalctl_commands", [])) or []
        )
        log_patterns = kwargs.get("log_patterns", []) or []
        ignore_missing = bool(kwargs.get("ignore_missing_log_files", False))

        commands = []
        for entry in log_commands:
            if isinstance(entry, dict):
                commands.append(
                    {
                        "command": entry.get("command"),
                        "file_name": entry.get("file_name"),
                        "timeout": entry.get("timeout"),
                        "ignore_errors": entry.get("ignore_errors", False),
                    }
                )
            elif isinstance(entry, str):
                commands.append({"command": entry})

        targets = [
            {"path": p, "transport": "command", "required": False} for p in log_patterns
        ]

        translated = dict(kwargs)  # preserve unknown / passthrough keys
        translated["commands"] = commands
        translated["targets"] = targets
        translated["ignore_missing_targets"] = ignore_missing
        # Strip translated-away keys so the new handler doesn't see noise.
        for k in (
            "log_commands",
            "journalctl_commands",
            "log_patterns",
            "ignore_missing_log_files",
        ):
            translated.pop(k, None)
        return translated

    @staticmethod
    def _translate_file_collection_kwargs(
        kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        file_collection → file_log kwargs translator.

        Pure function.

        file_patterns / use_glob_enumeration can live at top level OR nested.

        Args:
            kwargs: Mapping supplying fields for file_collection → file_log
                kwargs translator.

        Returns:
            The validated ``translated``.
        """
        file_collection_config = kwargs.get("file_collection_config", {}) or {}
        # file_patterns / use_glob_enumeration can live at top level OR nested.
        file_patterns = (
            file_collection_config.get("file_patterns", kwargs.get("file_patterns", []))
            or []
        )
        use_glob_enumeration = file_collection_config.get(
            "use_glob_enumeration",
            kwargs.get("use_glob_enumeration", False),
        )
        service_name = file_collection_config.get(
            "service_name", kwargs.get("service_name")
        )
        service_check_required = file_collection_config.get(
            "service_check_required",
            kwargs.get("service_check_required", False),
        )
        skip_on_service_not_found = file_collection_config.get(
            "skip_on_service_not_found",
            kwargs.get("skip_on_service_not_found", False),
        )
        fallback_commands = (
            file_collection_config.get(
                "fallback_commands", kwargs.get("fallback_commands", [])
            )
            or []
        )
        force_fallback = file_collection_config.get(
            "force_fallback",
            kwargs.get("force_fallback", {"default": False}),
        )
        stop_on_first_success = file_collection_config.get(
            "stop_on_first_success",
            kwargs.get("stop_on_first_success", False),
        )

        targets = []
        for pattern in file_patterns:
            target = {"path": pattern, "transport": "sftp", "required": False}
            # Auto-glob behavior matches legacy _handle_host_file_collection.
            has_wildcard = isinstance(pattern, str) and any(
                ch in pattern for ch in "*?["
            )
            if use_glob_enumeration or has_wildcard:
                target["glob"] = True
            targets.append(target)

        translated = dict(kwargs)
        translated["targets"] = targets
        translated["fallbacks"] = list(fallback_commands)
        translated["stop_on_first_success"] = stop_on_first_success
        if service_check_required or service_name:
            translated["service_check"] = {
                "service_name": service_name,
                "required": bool(service_check_required),
                "skip_on_not_found": bool(skip_on_service_not_found),
                "force_fallback": force_fallback,
            }
        # Strip translated-away keys.
        for k in (
            "file_patterns",
            "use_glob_enumeration",
            "service_name",
            "service_check_required",
            "skip_on_service_not_found",
            "fallback_commands",
            "force_fallback",
            "file_collection_config",
            "platform_overrides",
        ):
            translated.pop(k, None)
        return translated

    @staticmethod
    def _translate_generic_log_kwargs(
        kwargs: Dict[str, Any], platform: str
    ) -> Dict[str, Any]:
        """
        generic_log → file_log kwargs translator.

        Pure function.

        `platform` is required because legacy generic_log applied
        platform_overrides.log_paths at the handler level.

        Args:
            kwargs: Mapping supplying fields for generic_log → file_log kwargs
                translator.
            platform: Text supplied as platform in the format accepted by this
                function.

        Returns:
            The validated ``translated``.
        """
        platform_config = kwargs.get("platform_config", {}) or {}
        platform_overrides = platform_config.get("platform_overrides", {}) or {}
        platform_override = platform_overrides.get(platform, {}) or {}

        log_types = platform_config.get("log_types", {}) or {}
        # The legacy handler also accepted `log_type` as a kwarg pointing at
        # which entry of `log_types` to use.
        log_type = kwargs.get("log_type")
        log_type_config = (
            log_types.get(log_type, {})
            if log_type
            else (next(iter(log_types.values())) if log_types else {})
        )

        service_name = log_type_config.get("service_name")
        service_check_required = log_type_config.get("service_check_required", False)
        skip_on_service_not_found = log_type_config.get(
            "skip_on_service_not_found", False
        )

        # log_paths: base from log_type_config, overlaid by platform_override.
        base_paths = log_type_config.get("log_paths", []) or []
        override_paths = platform_override.get("log_paths")
        if override_paths:
            # Legacy `log_paths` could contain `{log_type}` placeholders.
            base_paths = [
                p.format(log_type=log_type) if isinstance(p, str) else p
                for p in override_paths
            ]
        targets = [
            {"path": p, "transport": "command", "required": False} for p in base_paths
        ]

        fallback_commands = log_type_config.get("fallback_commands", []) or []

        force_fallback = platform_config.get("force_fallback", {"default": False})
        if "force_fallback" in platform_override:
            force_fallback = platform_override["force_fallback"]

        stop_on_first_success = platform_config.get("stop_on_first_success", False)

        translated = dict(kwargs)
        translated["targets"] = targets
        translated["fallbacks"] = list(fallback_commands)
        translated["stop_on_first_success"] = stop_on_first_success
        translated["service_check"] = {
            "service_name": service_name,
            "required": bool(service_check_required),
            "skip_on_not_found": bool(skip_on_service_not_found),
            "force_fallback": force_fallback,
        }
        for k in ("platform_config", "log_type"):
            translated.pop(k, None)
        return translated
