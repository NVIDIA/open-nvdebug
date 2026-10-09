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
Generic target-plan guard for retained Redfish task-start POSTs.

The product boundary deliberately knows nothing about collector inventories.
An external safety controller decides which collector may receive the private
environment contract; this module binds that identity to an exact multiset of
``(DUT slot, normalized URI, JSON body)`` targets. With no contract present,
ordinary interactive/manual product behavior is unchanged.

Planning records targets without issuing a mutating request. Enforcement durably
reserves one planned occurrence before issuing an opaque, one-shot network
capability. The DUT transport consumes that capability immediately before any
connection or request can be attempted.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import threading
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, NoReturn

PLAN_SCHEMA_VERSION = "1.0"
EVIDENCE_SCHEMA_VERSION = "2.0"
MAX_DUT_COUNT = 500
MAX_TARGET_OCCURRENCES = 10_000
MAX_TARGET_PLAN_BYTES = 16 * 1024 * 1024
MAX_TARGET_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_TARGET_URI_BYTES = 4096
MAX_TARGET_BODY_BYTES = 64 * 1024
MAX_JSON_DEPTH = 32

COLLECTOR_ENV = "NVDEBUG_LIVE_COLLECTOR_ID"
BUDGET_ENV = "NVDEBUG_LIVE_PERSISTENT_TASK_MAX_START_POSTS"
COUNTER_ENV = "NVDEBUG_LIVE_PERSISTENT_TASK_COUNTER_FILE"
TARGET_MODE_ENV = "NVDEBUG_LIVE_PERSISTENT_TASK_TARGET_MODE"
TARGET_PLAN_OUTPUT_ENV = "NVDEBUG_LIVE_PERSISTENT_TASK_TARGET_PLAN_OUTPUT_FILE"
TARGET_PLAN_FILE_ENV = "NVDEBUG_LIVE_PERSISTENT_TASK_TARGET_PLAN_FILE"
TARGET_PLAN_SHA256_ENV = "NVDEBUG_LIVE_PERSISTENT_TASK_TARGET_PLAN_SHA256"
TARGET_PROFILE_ENV = "NVDEBUG_LIVE_PERSISTENT_TASK_TARGET_PROFILE_ID"
TARGET_PHASE_MANIFEST_SHA256_ENV = (
    "NVDEBUG_LIVE_PERSISTENT_TASK_TARGET_PHASE_MANIFEST_SHA256"
)
TARGET_CAMPAIGN_INPUT_SHA256_ENV = (
    "NVDEBUG_LIVE_PERSISTENT_TASK_TARGET_CAMPAIGN_INPUT_SHA256"
)
TARGET_PHASE_INVOCATION_SHA256_ENV = (
    "NVDEBUG_LIVE_PERSISTENT_TASK_TARGET_PHASE_INVOCATION_SHA256"
)
TARGET_DUT_COUNT_ENV = "NVDEBUG_LIVE_PERSISTENT_TASK_TARGET_DUT_COUNT"

TARGET_MODE_PLAN = "plan"
TARGET_MODE_ENFORCE = "enforce"

_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9_]{0,127}$")
_COLLECTOR_RE = re.compile(r"^[A-Z][1-9][0-9]*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_POSITIVE_INTEGER_RE = re.compile(r"^[1-9][0-9]*$")
_INVALID_PERCENT_ENCODING_RE = re.compile(r"%(?:2e|2f|5c)", re.IGNORECASE)
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")

_COMMON_ENV_KEYS = frozenset(
    {
        TARGET_MODE_ENV,
        COLLECTOR_ENV,
        TARGET_PROFILE_ENV,
        TARGET_PHASE_MANIFEST_SHA256_ENV,
        TARGET_CAMPAIGN_INPUT_SHA256_ENV,
        TARGET_PHASE_INVOCATION_SHA256_ENV,
        TARGET_DUT_COUNT_ENV,
    }
)
_PLAN_ENV_KEYS = _COMMON_ENV_KEYS | {TARGET_PLAN_OUTPUT_ENV}
_ENFORCE_ENV_KEYS = _COMMON_ENV_KEYS | {
    TARGET_PLAN_FILE_ENV,
    TARGET_PLAN_SHA256_ENV,
    BUDGET_ENV,
    COUNTER_ENV,
}
_CONTRACT_ENV_KEYS = _PLAN_ENV_KEYS | _ENFORCE_ENV_KEYS
_TRIGGER_ENV_KEYS = (_PLAN_ENV_KEYS | _ENFORCE_ENV_KEYS) - {COLLECTOR_ENV}
_TARGET_ENV_PREFIX = "NVDEBUG_LIVE_PERSISTENT_TASK_TARGET_"

_PLAN_KEYS = frozenset(
    {
        "schema_version",
        "collector_id",
        "profile_id",
        "phase_manifest_sha256",
        "campaign_input_fingerprint_sha256",
        "phase_invocation_fingerprint_sha256",
        "dut_count",
        "finalized",
        "targets",
    }
)
_TARGET_KEYS = frozenset({"dut_slot", "uri", "body", "occurrences"})


class PersistentPostGuardError(RuntimeError):
    """
    Stable, credential-free failure raised before network I/O.

    Callers receive this exception when the persistent post guard error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """

    def __init__(self, code: str) -> None:
        """
        Initialize a ``PersistentPostGuardError`` instance.

        The initializer records ``code`` for later operations and establishes
        the instance invariants before any public method runs.

        Args:
            code: Text supplied as code in the format accepted by this function.
        """
        super().__init__(f"[SAFETY_FAILURE:{code}]")
        self.code = code


def _fail(code: str) -> NoReturn:
    """
    Return the fail.

    The implementation uses ``code`` to produce the fail. If the function cannot
    produce the fail, its exception reaches the caller instead of being
    converted into a successful result.

    Args:
        code: Text supplied as code in the format accepted by this function.

    Raises:
        PersistentPostGuardError: If the function cannot produce the fail
            safely.
    """
    raise PersistentPostGuardError(code)


def _is_plain_int(value: Any) -> bool:
    """
    Return whether ``value`` is plain int.

    The implementation uses ``value`` to determine whether ``value`` is plain
    int.

    Args:
        value: Value evaluated while performing ``value`` is plain int.

    Returns:
        Whether ``value`` is plain int.
    """
    return isinstance(value, int) and not isinstance(value, bool)


def _is_sha256(value: Any) -> bool:
    """
    Return whether ``value`` is SHA-256.

    The implementation uses ``value`` to determine whether ``value`` is SHA-256.

    Args:
        value: Value evaluated while performing ``value`` is SHA-256.

    Returns:
        Whether ``value`` is SHA-256.
    """
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    """
    Validate JSON value.

    The implementation uses ``value`` and ``depth`` to validate JSON value.
    Every required invariant is checked before a successful value is returned;
    invalid input follows the function's explicit exception path.

    Args:
        value: Value object whose ``values`` state is read while performing JSON
            value.
        depth: Numeric depth used while the operation performs bounded
            accounting.
    """
    if depth > MAX_JSON_DEPTH:
        _fail("persistent_target_plan_invalid")
    if value is None or isinstance(value, (str, bool)):
        return
    if _is_plain_int(value):
        return
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            _fail("persistent_target_plan_invalid")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            _fail("persistent_target_plan_invalid")
        for item in value.values():
            _validate_json_value(item, depth=depth + 1)
        return
    _fail("persistent_target_plan_invalid")


def _canonical_json_bytes(value: Any) -> bytes:
    """
    Return the canonical JSON bytes.

    The implementation uses ``value`` to produce the canonical JSON bytes. If
    the function cannot produce the canonical JSON bytes, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        value: Value evaluated while performing canonical JSON bytes.

    Returns:
        The bounded canonical JSON bytes.

    Raises:
        PersistentPostGuardError: If persistent_target_plan_invalid.
    """
    _validate_json_value(value)
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise PersistentPostGuardError("persistent_target_plan_invalid") from None
    return rendered.encode("ascii") + b"\n"


def _decode_canonical_json(raw: bytes) -> dict[str, Any]:
    """
    Decode canonical JSON.

    The implementation uses ``raw`` to decode canonical JSON. Parsing or I/O
    must finish before the validated representation is made available to the
    caller. If the function cannot decode canonical JSON, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        raw: Bounded byte sequence supplied as raw.

    Returns:
        The validated ``document``.

    Raises:
        PersistentPostGuardError: If persistent_target_plan_invalid.
    """

    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """
        Reject duplicate.

        The implementation uses ``pairs`` to reject duplicate. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path.

        Args:
            pairs: Entries supplied as ``pairs`` without transferring container
                ownership.

        Returns:
            The validated ``result``.
        """
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail("persistent_target_plan_duplicate_key")
            result[key] = value
        return result

    try:
        document = json.loads(raw.decode("ascii"), object_pairs_hook=reject_duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise PersistentPostGuardError("persistent_target_plan_invalid") from None
    if not isinstance(document, dict) or _canonical_json_bytes(document) != raw:
        _fail("persistent_target_plan_noncanonical")
    return document


def _validate_uri(uri: Any) -> str:
    """
    Validate URI.

    The implementation uses ``uri`` to validate URI. Every required invariant is
    checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        uri: Validated remote resource identifier used for URI.

    Returns:
        The validated ``uri``.

    Raises:
        PersistentPostGuardError: If persistent_target_plan_invalid.
    """
    if not isinstance(uri, str):
        _fail("persistent_target_plan_invalid")
    try:
        raw = uri.encode("ascii")
    except UnicodeEncodeError:
        raise PersistentPostGuardError("persistent_target_plan_invalid") from None
    if (
        not 2 <= len(raw) <= MAX_TARGET_URI_BYTES
        or not uri.startswith("/")
        or uri.startswith("//")
        or uri.endswith("/")
        or "?" in uri
        or "#" in uri
        or "\\" in uri
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in uri)
    ):
        _fail("persistent_target_plan_invalid")
    segments = uri.split("/")[1:]
    if not segments or any(segment in {"", ".", ".."} for segment in segments):
        _fail("persistent_target_plan_invalid")
    if _INVALID_PERCENT_ENCODING_RE.search(uri):
        _fail("persistent_target_plan_invalid")
    if "%" in _PERCENT_ESCAPE_RE.sub("", uri):
        _fail("persistent_target_plan_invalid")
    return uri


def _canonical_body(body: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    """
    Return the canonical body.

    The implementation uses ``body`` to produce the canonical body.

    Args:
        body: Mapping supplying fields for canonical body.

    Returns:
        A tuple containing ``decode`` and ``detached`` in that order.
    """
    if not isinstance(body, Mapping) or not body:
        _fail("persistent_target_plan_invalid")
    document = dict(body)
    raw = _canonical_json_bytes(document)
    if len(raw) - 1 > MAX_TARGET_BODY_BYTES:
        _fail("persistent_target_plan_invalid")
    detached = json.loads(raw)
    return raw[:-1].decode("ascii"), detached


def _validate_binding(
    *,
    collector_id: Any,
    profile_id: Any,
    phase_manifest_sha256: Any,
    campaign_input_fingerprint_sha256: Any,
    phase_invocation_fingerprint_sha256: Any,
    dut_count: Any,
) -> None:
    # The external controller owns authorization. Product validates only the
    # shape and exact identity binding so no collector inventory is copied into
    # the runtime package.
    """
    Validate binding.

    The implementation uses ``collector_id``, ``profile_id``,
    ``phase_manifest_sha256``, ``campaign_input_fingerprint_sha256``, and
    ``phase_invocation_fingerprint_sha256`` to validate binding. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        collector_id: Stable collector identifier used to correlate
            configuration, logs, and results.
        profile_id: Stable profile identifier used to correlate configuration,
            logs, and results.
        phase_manifest_sha256: Phase manifest SHA-256 consumed while the
            function attempts to validate binding.
        campaign_input_fingerprint_sha256: Campaign input fingerprint SHA-256
            consumed while the function attempts to validate binding.
        phase_invocation_fingerprint_sha256: Phase invocation fingerprint
            SHA-256 consumed while the function attempts to validate binding.
        dut_count: Numeric DUT count used by the operation's bounded accounting.
    """
    if (
        not isinstance(collector_id, str)
        or _COLLECTOR_RE.fullmatch(collector_id) is None
        or not isinstance(profile_id, str)
        or _PROFILE_RE.fullmatch(profile_id) is None
        or not _is_sha256(phase_manifest_sha256)
        or not _is_sha256(campaign_input_fingerprint_sha256)
        or not _is_sha256(phase_invocation_fingerprint_sha256)
        or not _is_plain_int(dut_count)
        or not 1 <= dut_count <= MAX_DUT_COUNT
    ):
        _fail("persistent_target_plan_invalid")


@dataclass(frozen=True, order=True)
class PersistentPostTarget:
    """
    One canonical logical POST target, excluding its multiset count.

    The immutable record keeps ``dut_slot``, ``uri``, and ``body_json`` together
    so consumers observe one persistent post target state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        dut_slot: Numeric DUT slot retained by this record.
        uri: Canonical text used as URI.
        body_json: Canonical text used as body JSON.
    """

    dut_slot: int
    uri: str
    body_json: str = field(repr=False)

    @classmethod
    def create(
        cls,
        *,
        dut_slot: Any,
        normalized_uri: Any,
        body: Mapping[str, Any],
        dut_count: int,
    ) -> "PersistentPostTarget":
        """
        Create the configured resource.

        After applying local validation, the function forwards ``dut_slot``,
        ``normalized_uri``, ``body``, and ``dut_count`` to ``cls`` and preserves
        its return and exception contract.

        Args:
            dut_slot: Numeric DUT slot used while the operation performs bounded
                accounting.
            normalized_uri: Validated remote resource identifier used for
                normalized URI.
            body: Mapping supplying fields for configured resource.
            dut_count: Numeric DUT count used by the operation's bounded
                accounting.

        Returns:
            A validated ``PersistentPostTarget`` instance initialized from the
            supplied fields.
        """
        if (
            not _is_plain_int(dut_slot)
            or not _is_plain_int(dut_count)
            or not 1 <= dut_count <= MAX_DUT_COUNT
            or not 0 <= dut_slot < dut_count
        ):
            _fail("persistent_target_plan_invalid")
        body_json, _ = _canonical_body(body)
        return cls(
            dut_slot=dut_slot, uri=_validate_uri(normalized_uri), body_json=body_json
        )

    def body_document(self) -> dict[str, Any]:
        """
        Return the body document.

        The implementation uses current instance state to produce the body
        document.

        Returns:
            The validated ``value``.
        """
        value = json.loads(self.body_json)
        if not isinstance(value, dict):
            _fail("persistent_target_plan_invalid")
        return value

    def as_document(self, occurrences: int) -> dict[str, Any]:
        """
        Return the as document.

        The implementation uses ``occurrences`` to produce the as document.

        Args:
            occurrences: Numeric occurrences used while the operation performs
                bounded accounting.

        Returns:
            A mapping containing the ``dut_slot``, ``uri``, ``body``, and
            ``occurrences`` fields.
        """
        if (
            not _is_plain_int(occurrences)
            or not 1 <= occurrences <= MAX_TARGET_OCCURRENCES
        ):
            _fail("persistent_target_plan_invalid")
        return {
            "dut_slot": self.dut_slot,
            "uri": self.uri,
            "body": self.body_document(),
            "occurrences": occurrences,
        }

    @property
    def sha256(self) -> str:
        """
        Return the SHA-256.

        Each access computes the value from ``body_document``, ``dut_slot``, and
        ``uri`` on the current instance; the derived view is not stored as
        independent state.

        Returns:
            The canonical SHA-256 text.
        """
        identity = {
            "dut_slot": self.dut_slot,
            "uri": self.uri,
            "body": self.body_document(),
        }
        return hashlib.sha256(
            b"nvdebug-persistent-task-target/v1\0"
            + _canonical_json_bytes(identity)[:-1]
        ).hexdigest()


@dataclass(frozen=True)
class PersistentPostPlan:
    """
    Implement the persistent post plan boundary used by the NVDebug runtime.

    The immutable record keeps ``path``, ``sha256``, ``collector_id``,
    ``profile_id``, and ``phase_manifest_sha256`` together so consumers observe
    one persistent post plan state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        sha256: Lowercase SHA-256 digest binding the SHA-256 content.
        collector_id: Canonical text used as collector identifier.
        profile_id: Canonical text used as profile identifier.
        phase_manifest_sha256: Lowercase SHA-256 digest binding the phase
            manifest content.
        campaign_input_fingerprint_sha256: Lowercase SHA-256 digest binding the
            campaign input fingerprint content.
        phase_invocation_fingerprint_sha256: Lowercase SHA-256 digest binding
            the phase invocation fingerprint content.
        dut_count: Number of DUT entries represented by the record.
        targets: Mapping that retains the targets fields for this record.
    """

    path: Path = field(repr=False)
    sha256: str
    collector_id: str
    profile_id: str
    phase_manifest_sha256: str
    campaign_input_fingerprint_sha256: str
    phase_invocation_fingerprint_sha256: str
    dut_count: int
    targets: Mapping[PersistentPostTarget, int] = field(repr=False)

    @property
    def planned_post_count(self) -> int:
        """
        Return the planned post count.

        Each access computes the value from ``targets`` on the current instance;
        the derived view is not stored as independent state.

        Returns:
            The numeric planned post count.
        """
        return sum(self.targets.values())


def _validate_private_parent(parent: Path, *, code: str) -> None:
    """
    Validate private parent.

    The implementation uses ``parent`` and ``code`` to validate private parent.
    Every required invariant is checked before a successful value is returned;
    invalid input follows the function's explicit exception path. Filesystem
    effects remain confined to the caller-selected paths and the owning resource
    lifecycle.

    Args:
        parent: filesystem location used as the parent for this operation.
        code: Text supplied as code in the format accepted by this function.

    Raises:
        PersistentPostGuardError: If the function cannot validate private parent
            safely.
    """
    try:
        metadata = parent.lstat()
        resolved = parent.resolve(strict=True)
    except OSError:
        raise PersistentPostGuardError(code) from None
    if (
        not parent.is_absolute()
        or resolved != parent
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        _fail(code)


def _preflight_new_private_file(path: Path, *, code: str) -> None:
    """
    Validate a newly created private file before publication.

    The implementation uses ``path`` and ``code`` to validate a newly created
    private file before publication. Every required invariant is checked before
    a successful value is returned; invalid input follows the function's
    explicit exception path. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Args:
        path: filesystem location used as the path for this operation.
        code: Text supplied as code in the format accepted by this function.

    Raises:
        PersistentPostGuardError: If the function cannot validate a newly
            created private file before publication safely.
    """
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        _fail(code)
    _validate_private_parent(path.parent, code=code)
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise PersistentPostGuardError(code) from None
    _fail(code)


def _write_new_private_file(path: Path, raw: bytes, *, code: str) -> None:
    """
    Write new private file.

    The implementation uses ``path``, ``raw``, and ``code`` to write new private
    file. Success is reported only after the owning output boundary has
    completed its required write or publication step. If the function cannot
    write new private file, its exception reaches the caller instead of being
    converted into a successful result. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        path: filesystem location used as the path for this operation.
        raw: Bounded byte sequence supplied as raw.
        code: Text supplied as code in the format accepted by this function.

    Raises:
        PersistentPostGuardError: If the function cannot write new private file
            safely.
    """
    _preflight_new_private_file(path, code=code)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise PersistentPostGuardError(code) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _replace_private_file(path: Path, raw: bytes, *, code: str) -> None:
    """
    Replace a private file while preserving ownership and mode invariants.

    The implementation uses ``path``, ``raw``, and ``code`` to replace a private
    file while preserving ownership and mode invariants. Filesystem effects
    remain confined to the caller-selected paths and the owning resource
    lifecycle. If the function cannot replace a private file while preserving
    ownership and mode invariants, its exception reaches the caller instead of
    being converted into a successful result. Cleanup in the ``finally`` path
    runs for successful, failed, and cancelled execution.

    Args:
        path: filesystem location used as the path for this operation.
        raw: Bounded byte sequence supplied as raw.
        code: Text supplied as code in the format accepted by this function.

    Raises:
        PersistentPostGuardError: If the function cannot replace a private file
            while preserving ownership and mode invariants safely.
    """
    _validate_private_parent(path.parent, code=code)
    temporary: Path | None = None
    descriptor = -1
    try:
        descriptor, raw_path = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(raw_path)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    except OSError:
        raise PersistentPostGuardError(code) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def _read_private_file(path: Path, *, maximum_bytes: int, code: str) -> bytes:
    """
    Read private file.

    The implementation uses ``path``, ``maximum_bytes``, and ``code`` to read
    private file. Parsing or I/O must finish before the validated representation
    is made available to the caller. If the function cannot read private file,
    its exception reaches the caller instead of being converted into a
    successful result. Cleanup in the ``finally`` path runs for successful,
    failed, and cancelled execution.

    Args:
        path: filesystem location used as the path for this operation.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.
        code: Text supplied as code in the format accepted by this function.

    Returns:
        The validated ``raw``.

    Raises:
        PersistentPostGuardError: If the function cannot read private file
            safely.
    """
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        _fail(code)
    _validate_private_parent(path.parent, code=code)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= maximum_bytes
        ):
            _fail(code)
        raw = os.read(descriptor, maximum_bytes + 1)
        after = os.fstat(descriptor)
        if (
            len(raw) != before.st_size
            or len(raw) > maximum_bytes
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            _fail(code)
        return raw
    except OSError:
        raise PersistentPostGuardError(code) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_plan(
    path: Path,
    *,
    expected_sha256: str,
    expected_binding: Mapping[str, Any],
) -> PersistentPostPlan:
    """
    Load plan.

    After applying local validation, the function forwards ``path``,
    ``expected_sha256``, and ``expected_binding`` to ``PersistentPostPlan`` and
    preserves its return and exception contract. Parsing or I/O must finish
    before the validated representation is made available to the caller.

    Args:
        path: filesystem location used as the path for this operation.
        expected_sha256: Text supplied as expected SHA-256 in the format
            accepted by this function.
        expected_binding: Mapping supplying fields for plan.

    Returns:
        A ``PersistentPostPlan`` representing plan.
    """
    raw = _read_private_file(
        path, maximum_bytes=MAX_TARGET_PLAN_BYTES, code="persistent_target_plan_unsafe"
    )
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        _fail("persistent_target_plan_digest_mismatch")
    document = _decode_canonical_json(raw)
    if (
        set(document) != _PLAN_KEYS
        or document.get("schema_version") != PLAN_SCHEMA_VERSION
        or document.get("finalized") is not True
        or any(document.get(key) != value for key, value in expected_binding.items())
        or not isinstance(document.get("targets"), list)
        or not document["targets"]
    ):
        _fail("persistent_target_plan_invalid")

    _validate_binding(
        collector_id=document["collector_id"],
        profile_id=document["profile_id"],
        phase_manifest_sha256=document["phase_manifest_sha256"],
        campaign_input_fingerprint_sha256=document["campaign_input_fingerprint_sha256"],
        phase_invocation_fingerprint_sha256=document[
            "phase_invocation_fingerprint_sha256"
        ],
        dut_count=document["dut_count"],
    )
    targets: Counter[PersistentPostTarget] = Counter()
    previous: PersistentPostTarget | None = None
    for item in document["targets"]:
        if not isinstance(item, dict) or set(item) != _TARGET_KEYS:
            _fail("persistent_target_plan_invalid")
        target = PersistentPostTarget.create(
            dut_slot=item["dut_slot"],
            normalized_uri=item["uri"],
            body=item["body"],
            dut_count=document["dut_count"],
        )
        occurrences = item["occurrences"]
        if (
            not _is_plain_int(occurrences)
            or not 1 <= occurrences <= MAX_TARGET_OCCURRENCES
            or (previous is not None and target <= previous)
        ):
            _fail("persistent_target_plan_invalid")
        targets[target] = occurrences
        previous = target
    if sum(targets.values()) > MAX_TARGET_OCCURRENCES:
        _fail("persistent_target_plan_invalid")
    return PersistentPostPlan(
        path=path,
        sha256=expected_sha256,
        collector_id=document["collector_id"],
        profile_id=document["profile_id"],
        phase_manifest_sha256=document["phase_manifest_sha256"],
        campaign_input_fingerprint_sha256=document["campaign_input_fingerprint_sha256"],
        phase_invocation_fingerprint_sha256=document[
            "phase_invocation_fingerprint_sha256"
        ],
        dut_count=document["dut_count"],
        targets=dict(targets),
    )


_RESERVATION_ISSUER = object()


class PersistentPostReservation:
    """
    Opaque, process-local, single-use authority for one exact POST.

    The type coordinates ``consume`` and retains the state those operations
    share between calls. Resource ownership remains inside the instance until
    the matching close, exit, or cleanup operation completes.
    """

    __slots__ = ("__consumed", "__lock", "__target_sha256")

    def __init__(self, *, issuer: object, target_sha256: str) -> None:
        """
        Initialize a ``PersistentPostReservation`` instance.

        The initializer records ``__consumed``, ``__lock``, and
        ``__target_sha256`` for later operations and establishes the instance
        invariants before any public method runs.

        Args:
            issuer: Issuer consumed while the function attempts to initialize a
                ``PersistentPostReservation`` instance.
            target_sha256: Text supplied as target SHA-256 in the format
                accepted by this function.
        """
        if issuer is not _RESERVATION_ISSUER or not _is_sha256(target_sha256):
            _fail("persistent_target_network_reservation_invalid")
        self.__target_sha256 = target_sha256
        self.__consumed = False
        self.__lock = threading.Lock()

    def consume(self, *, expected_target_sha256: str) -> None:
        """
        Consume the supplied value under the current boundary.

        The implementation uses ``expected_target_sha256`` to consume the
        supplied value under the current boundary. It updates ``__consumed`` on
        the instance as part of that state transition.

        Args:
            expected_target_sha256: Text supplied as expected target SHA-256 in
                the format accepted by this function.
        """
        with self.__lock:
            if self.__consumed or self.__target_sha256 != expected_target_sha256:
                _fail("persistent_target_network_reservation_mismatch")
            self.__consumed = True

    def __repr__(self) -> str:
        """
        Return a developer-facing representation of the PersistentPostReservation.

        The implementation uses current instance state to produce a
        developer-facing representation of the PersistentPostReservation.

        Returns:
            The canonical repr text.
        """
        return "<PersistentPostReservation opaque>"


class PersistentPostRuntime:
    """
    Inert-by-default planning/enforcement adapter for the product runtime.

    The type coordinates ``from_environment``, ``is_planning``,
    ``is_enforcing``, ``record_post``, and ``_plan_document`` and retains the
    state those operations share between calls. Resource ownership remains
    inside the instance until the matching close, exit, or cleanup operation
    completes.
    """

    def __init__(
        self,
        *,
        mode: str,
        collector_id: str,
        profile_id: str,
        phase_manifest_sha256: str,
        campaign_input_fingerprint_sha256: str,
        phase_invocation_fingerprint_sha256: str,
        dut_count: int,
        output_path: Path | None = None,
        plan: PersistentPostPlan | None = None,
        maximum: int = 0,
        evidence_path: Path | None = None,
    ) -> None:
        """
        Initialize a ``PersistentPostRuntime`` instance.

        The initializer records ``_closed``, ``_evidence_path``, ``_lock``,
        ``_maximum``, and ``_output_path`` for later operations and establishes
        the instance invariants before any public method runs.

        Args:
            mode: Text supplied as mode in the format accepted by this function.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            profile_id: Stable profile identifier used to correlate
                configuration, logs, and results.
            phase_manifest_sha256: Text supplied as phase manifest SHA-256 in
                the format accepted by this function.
            campaign_input_fingerprint_sha256: Text supplied as campaign input
                fingerprint SHA-256 in the format accepted by this function.
            phase_invocation_fingerprint_sha256: Text supplied as phase
                invocation fingerprint SHA-256 in the format accepted by this
                function.
            dut_count: Numeric DUT count used by the operation's bounded
                accounting.
            output_path: Optional filesystem location used as the output path
                for this operation.
            plan: Optional plan; ``None`` selects the function's default
                behavior.
            maximum: Numeric maximum used while the operation performs bounded
                accounting.
            evidence_path: Optional filesystem location used as the evidence
                path for this operation.
        """
        self.mode = mode
        self.collector_id = collector_id
        self.profile_id = profile_id
        self.phase_manifest_sha256 = phase_manifest_sha256
        self.campaign_input_fingerprint_sha256 = campaign_input_fingerprint_sha256
        self.phase_invocation_fingerprint_sha256 = phase_invocation_fingerprint_sha256
        self.dut_count = dut_count
        self._output_path = output_path
        self._plan = plan
        self._maximum = maximum
        self._evidence_path = evidence_path
        self._planned: Counter[PersistentPostTarget] = Counter()
        self._remaining: Counter[PersistentPostTarget] = Counter(
            plan.targets if plan is not None else {}
        )
        self._reserved: Counter[PersistentPostTarget] = Counter()
        self._state = "active"
        self._closed = False
        self._lock = threading.Lock()
        if self.is_enforcing:
            if plan is None or evidence_path is None:
                _fail("persistent_target_environment_invalid")
            self._persist_evidence(create=True)

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> "PersistentPostRuntime | None":
        """
        Build a PersistentPostRuntime from environment.

        The implementation uses ``environment`` to build a PersistentPostRuntime
        from environment.

        Args:
            environment: Optional environment; ``None`` selects the function's
                default behavior.

        Returns:
            A ``PersistentPostRuntime`` initialized from environment.
        """
        source: Mapping[str, str] = os.environ if environment is None else environment
        mode = validate_persistent_post_environment(source)
        if mode is None:
            return None
        binding = _binding_from_environment(source)
        if mode == TARGET_MODE_PLAN:
            output_path = Path(source[TARGET_PLAN_OUTPUT_ENV])
            _preflight_new_private_file(
                output_path, code="persistent_target_plan_output_unsafe"
            )
            return cls(mode=mode, output_path=output_path, **binding)

        plan_path = Path(source[TARGET_PLAN_FILE_ENV])
        plan = _load_plan(
            plan_path,
            expected_sha256=source[TARGET_PLAN_SHA256_ENV],
            expected_binding=binding,
        )
        maximum = int(source[BUDGET_ENV])
        if maximum != max(1, plan.planned_post_count):
            _fail("persistent_target_budget_invalid")
        evidence_path = Path(source[COUNTER_ENV])
        _preflight_new_private_file(
            evidence_path, code="persistent_target_evidence_unsafe"
        )
        return cls(
            mode=mode,
            plan=plan,
            maximum=maximum,
            evidence_path=evidence_path,
            **binding,
        )

    @property
    def is_planning(self) -> bool:
        """
        Return whether ``the current value`` is planning.

        Each access computes the value from ``mode`` on the current instance;
        the derived view is not stored as independent state.

        Returns:
            Whether ``the current value`` is planning.
        """
        return self.mode == TARGET_MODE_PLAN

    @property
    def is_enforcing(self) -> bool:
        """
        Return whether ``the current value`` is enforcing.

        Each access computes the value from ``mode`` on the current instance;
        the derived view is not stored as independent state.

        Returns:
            Whether ``the current value`` is enforcing.
        """
        return self.mode == TARGET_MODE_ENFORCE

    def record_post(
        self,
        *,
        collector_id: str,
        dut_slot: int,
        normalized_uri: str,
        body: Mapping[str, Any],
    ) -> None:
        """
        Record post.

        The implementation uses ``collector_id``, ``dut_slot``,
        ``normalized_uri``, and ``body`` to record post.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_slot: Numeric DUT slot used while the operation performs bounded
                accounting.
            normalized_uri: Validated remote resource identifier used for
                normalized URI.
            body: Mapping supplying fields for record post.
        """
        if not self.is_planning or self._closed or collector_id != self.collector_id:
            _fail("persistent_target_runtime_mode_invalid")
        target = PersistentPostTarget.create(
            dut_slot=dut_slot,
            normalized_uri=normalized_uri,
            body=body,
            dut_count=self.dut_count,
        )
        with self._lock:
            if sum(self._planned.values()) >= MAX_TARGET_OCCURRENCES:
                _fail("persistent_target_plan_invalid")
            self._planned[target] += 1

    def _plan_document(self) -> dict[str, Any]:
        """
        Return the plan document.

        The implementation uses current instance state to produce the plan
        document.

        Returns:
            A mapping containing the ``schema_version``, ``collector_id``,
            ``profile_id``, ``phase_manifest_sha256``, and
            ``campaign_input_fingerprint_sha256`` fields.
        """
        return {
            "schema_version": PLAN_SCHEMA_VERSION,
            "collector_id": self.collector_id,
            "profile_id": self.profile_id,
            "phase_manifest_sha256": self.phase_manifest_sha256,
            "campaign_input_fingerprint_sha256": (
                self.campaign_input_fingerprint_sha256
            ),
            "phase_invocation_fingerprint_sha256": (
                self.phase_invocation_fingerprint_sha256
            ),
            "dut_count": self.dut_count,
            "finalized": True,
            "targets": [
                target.as_document(self._planned[target])
                for target in sorted(self._planned)
            ],
        }

    def _evidence_document(self) -> dict[str, Any]:
        """
        Return the evidence document.

        The implementation uses current instance state to produce the evidence
        document.

        Returns:
            A mapping containing the ``schema_version``, ``collector_id``,
            ``target_plan_sha256``, ``guard_state``, and
            ``maximum_post_reservations`` fields.
        """
        assert self._plan is not None
        return {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "collector_id": self.collector_id,
            "target_plan_sha256": self._plan.sha256,
            "guard_state": self._state,
            "maximum_post_reservations": self._maximum,
            "planned_post_count": self._plan.planned_post_count,
            "reserved_post_count": sum(self._reserved.values()),
            "reserved_targets": [
                {
                    "target_sha256": target.sha256,
                    "reserved_occurrences": self._reserved[target],
                }
                for target in sorted(self._reserved, key=lambda item: item.sha256)
                if self._reserved[target]
            ],
        }

    def _persist_evidence(self, *, create: bool = False) -> None:
        """
        Persist evidence.

        The implementation uses ``create`` to persist evidence. Success is
        reported only after the owning output boundary has completed its
        required write or publication step.

        Args:
            create: Whether create is enabled or required for this operation.
        """
        assert self._evidence_path is not None
        raw = _canonical_json_bytes(self._evidence_document())
        if len(raw) > MAX_TARGET_EVIDENCE_BYTES:
            _fail("persistent_target_evidence_invalid")
        if create:
            _write_new_private_file(
                self._evidence_path,
                raw,
                code="persistent_target_evidence_unavailable",
            )
        else:
            _replace_private_file(
                self._evidence_path,
                raw,
                code="persistent_target_evidence_unavailable",
            )

    def reserve_post(
        self,
        *,
        collector_id: str,
        dut_slot: int,
        normalized_uri: str,
        body: Mapping[str, Any],
        retry_count: int,
    ) -> PersistentPostReservation:
        """
        Reserve post.

        After applying local validation, the function forwards ``collector_id``,
        ``dut_slot``, ``normalized_uri``, ``body``, and ``retry_count`` to
        ``PersistentPostReservation`` and preserves its return and exception
        contract. It updates ``_state`` on the instance as part of that state
        transition.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            dut_slot: Numeric DUT slot used while the operation performs bounded
                accounting.
            normalized_uri: Validated remote resource identifier used for
                normalized URI.
            body: Mapping supplying fields for reserve post.
            retry_count: Numeric retry count used by the operation's bounded
                accounting.

        Returns:
            A ``PersistentPostReservation`` representing reserve post.
        """
        if not self.is_enforcing or self._closed or self._plan is None:
            _fail("persistent_target_runtime_mode_invalid")
        with self._lock:
            try:
                if self._state != "active":
                    _fail("persistent_target_evidence_unavailable")
                if collector_id != self.collector_id:
                    _fail("persistent_target_plan_identity_mismatch")
                if retry_count != 0:
                    _fail("persistent_target_post_retry_forbidden")
                target = PersistentPostTarget.create(
                    dut_slot=dut_slot,
                    normalized_uri=normalized_uri,
                    body=body,
                    dut_count=self.dut_count,
                )
                if target not in self._plan.targets:
                    _fail("persistent_target_unplanned")
                if self._remaining[target] <= 0:
                    _fail("persistent_target_multiplicity_exhausted")
                if sum(self._reserved.values()) >= self._maximum:
                    _fail("persistent_target_budget_exhausted")
            except PersistentPostGuardError:
                self._state = "poisoned"
                self._persist_evidence()
                raise
            self._remaining[target] -= 1
            self._reserved[target] += 1
            try:
                self._persist_evidence()
            except Exception:
                self._state = "poisoned"
                raise
        return PersistentPostReservation(
            issuer=_RESERVATION_ISSUER, target_sha256=target.sha256
        )

    def finish(self, *, planning_successful: bool, runtime_clean: bool) -> None:
        """
        Finalize the current operation.

        The implementation uses ``planning_successful`` and ``runtime_clean`` to
        finalize the current operation. It updates ``_closed`` and ``_state`` on
        the instance as part of that state transition.

        Args:
            planning_successful: Whether planning successful is enabled or
                required for this operation.
            runtime_clean: Whether runtime clean is enabled or required for this
                operation.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self.is_planning:
                if not planning_successful:
                    self._planned.clear()
                    return
                if not self._planned or self._output_path is None:
                    _fail("persistent_target_plan_invalid")
                raw = _canonical_json_bytes(self._plan_document())
                if len(raw) > MAX_TARGET_PLAN_BYTES:
                    _fail("persistent_target_plan_invalid")
                _write_new_private_file(
                    self._output_path,
                    raw,
                    code="persistent_target_plan_output_unavailable",
                )
                return
            if self._state == "poisoned":
                return
            self._state = "clean" if runtime_clean else "poisoned"
            self._persist_evidence()


def _binding_from_environment(environment: Mapping[str, str]) -> dict[str, Any]:
    """
    Return the binding from environment.

    The implementation uses ``environment`` to produce the binding from
    environment.

    Args:
        environment: Mapping supplying fields for binding from environment.

    Returns:
        The validated ``binding``.
    """
    binding = {
        "collector_id": environment[COLLECTOR_ENV],
        "profile_id": environment[TARGET_PROFILE_ENV],
        "phase_manifest_sha256": environment[TARGET_PHASE_MANIFEST_SHA256_ENV],
        "campaign_input_fingerprint_sha256": environment[
            TARGET_CAMPAIGN_INPUT_SHA256_ENV
        ],
        "phase_invocation_fingerprint_sha256": environment[
            TARGET_PHASE_INVOCATION_SHA256_ENV
        ],
        "dut_count": int(environment[TARGET_DUT_COUNT_ENV]),
    }
    _validate_binding(**binding)
    return binding


def validate_persistent_post_environment(
    environment: Mapping[str, str] | None = None,
) -> str | None:
    """
    Validate the all-or-nothing private contract without filesystem I/O.

    The implementation uses ``environment`` to validate the all-or-nothing
    private contract without filesystem I/O. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        environment: Optional environment; ``None`` selects the function's
            default behavior.

    Returns:
        The validated ``mode``, or ``None`` when no value qualifies.
    """

    source: Mapping[str, str] = os.environ if environment is None else environment
    unknown = {
        key
        for key in source
        if isinstance(key, str)
        and key.startswith(_TARGET_ENV_PREFIX)
        and key not in _CONTRACT_ENV_KEYS
    }
    if unknown:
        _fail("persistent_target_environment_invalid")
    if not any(key in source for key in _TRIGGER_ENV_KEYS):
        return None
    mode = source.get(TARGET_MODE_ENV)
    if mode not in {TARGET_MODE_PLAN, TARGET_MODE_ENFORCE}:
        _fail("persistent_target_environment_invalid")
    required = _PLAN_ENV_KEYS if mode == TARGET_MODE_PLAN else _ENFORCE_ENV_KEYS
    forbidden = (
        _ENFORCE_ENV_KEYS - _COMMON_ENV_KEYS
        if mode == TARGET_MODE_PLAN
        else _PLAN_ENV_KEYS - _COMMON_ENV_KEYS
    )
    present = {key for key in _CONTRACT_ENV_KEYS if key in source}
    if not required <= present:
        _fail("persistent_target_environment_incomplete")
    if forbidden & present:
        _fail("persistent_target_environment_mixed")
    for name in required:
        value = source.get(name)
        if not isinstance(value, str) or not value or "\x00" in value:
            _fail("persistent_target_environment_invalid")
    if (
        _POSITIVE_INTEGER_RE.fullmatch(source[TARGET_DUT_COUNT_ENV]) is None
        or int(source[TARGET_DUT_COUNT_ENV]) > MAX_DUT_COUNT
    ):
        _fail("persistent_target_environment_invalid")
    if mode == TARGET_MODE_ENFORCE and (
        _POSITIVE_INTEGER_RE.fullmatch(source[BUDGET_ENV]) is None
        or int(source[BUDGET_ENV]) > MAX_TARGET_OCCURRENCES
        or not _is_sha256(source[TARGET_PLAN_SHA256_ENV])
    ):
        _fail("persistent_target_environment_invalid")
    path_names = (
        (TARGET_PLAN_OUTPUT_ENV,)
        if mode == TARGET_MODE_PLAN
        else (TARGET_PLAN_FILE_ENV, COUNTER_ENV)
    )
    if any(
        not Path(source[name]).is_absolute()
        or Path(source[name]).name in {"", ".", ".."}
        for name in path_names
    ):
        _fail("persistent_target_environment_invalid")
    _binding_from_environment(source)
    return mode


def validate_persistent_post_network_request(
    *,
    mode: str | None,
    reservation: PersistentPostReservation | None,
    method: str,
    dut_slot: int,
    dut_count: int,
    normalized_uri: str,
    body: Any,
    retry_count: int,
) -> None:
    """
    Consume exact authority at the final boundary or fail before transport.

    The implementation uses ``mode``, ``reservation``, ``method``, ``dut_slot``,
    and ``dut_count`` to consume exact authority at the final boundary or fail
    before transport.

    Args:
        mode: Optional mode; ``None`` selects the function's default behavior.
        reservation: Optional reservation; ``None`` selects the function's
            default behavior.
        method: Text supplied as method in the format accepted by this function.
        dut_slot: Numeric DUT slot used while the operation performs bounded
            accounting.
        dut_count: Numeric DUT count used by the operation's bounded accounting.
        normalized_uri: Validated remote resource identifier used for normalized
            URI.
        body: Body consumed while the function attempts to consume exact
            authority at the final boundary or fail before transport.
        retry_count: Numeric retry count used by the operation's bounded
            accounting.
    """

    method_upper = str(method).upper()
    if mode is None:
        if reservation is not None:
            _fail("persistent_target_network_reservation_unexpected")
        return
    if mode == TARGET_MODE_PLAN:
        if method_upper != "GET" or reservation is not None:
            _fail("persistent_target_planning_non_get_forbidden")
        return
    if mode != TARGET_MODE_ENFORCE:
        _fail("persistent_target_environment_invalid")
    if method_upper == "GET":
        if reservation is not None:
            _fail("persistent_target_network_reservation_unexpected")
        return
    if method_upper != "POST":
        _fail("persistent_target_enforcement_method_forbidden")
    if reservation is None or retry_count != 0 or not isinstance(body, Mapping):
        _fail("persistent_target_network_reservation_invalid")
    target = PersistentPostTarget.create(
        dut_slot=dut_slot,
        normalized_uri=normalized_uri,
        body=body,
        dut_count=dut_count,
    )
    reservation.consume(expected_target_sha256=target.sha256)


__all__ = [
    "BUDGET_ENV",
    "COLLECTOR_ENV",
    "COUNTER_ENV",
    "EVIDENCE_SCHEMA_VERSION",
    "MAX_DUT_COUNT",
    "MAX_JSON_DEPTH",
    "MAX_TARGET_BODY_BYTES",
    "MAX_TARGET_EVIDENCE_BYTES",
    "MAX_TARGET_OCCURRENCES",
    "MAX_TARGET_PLAN_BYTES",
    "MAX_TARGET_URI_BYTES",
    "PLAN_SCHEMA_VERSION",
    "PersistentPostGuardError",
    "PersistentPostReservation",
    "PersistentPostRuntime",
    "TARGET_CAMPAIGN_INPUT_SHA256_ENV",
    "TARGET_DUT_COUNT_ENV",
    "TARGET_MODE_ENFORCE",
    "TARGET_MODE_ENV",
    "TARGET_MODE_PLAN",
    "TARGET_PHASE_INVOCATION_SHA256_ENV",
    "TARGET_PHASE_MANIFEST_SHA256_ENV",
    "TARGET_PLAN_FILE_ENV",
    "TARGET_PLAN_OUTPUT_ENV",
    "TARGET_PLAN_SHA256_ENV",
    "TARGET_PROFILE_ENV",
    "validate_persistent_post_environment",
    "validate_persistent_post_network_request",
]
