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
Seal secret-neutral run identity facts from authoritative runtime inputs.

This module owns the run identity builder boundary and exposes
``RunIdentityBuildError``, ``EffectiveConfigCohort``, ``PlanningPlanSnapshot``,
``_validate_effective_config_cohort``, and ``_config_value``. Keeping those
contracts together gives importers one source of truth for their validation,
lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any, Iterable

from ..utils.catalog_snapshot import CatalogSnapshotFacts
from ..utils.frozen_path import is_frozen
from ..utils.run_limits import (
    MAX_COLLECTOR_ID_BYTES,
    MAX_COLLECTORS_PER_RUN,
    MAX_DUT_ID_BYTES,
    MAX_DUTS,
    is_printable_identity,
)
from .finalization_receipt import (
    FinalizationReceipt,
    validate_structural_finalization_receipt,
)
from .run_identity import RunIdentity, RunPathIdentity

MAX_EFFECTIVE_CONFIG_FILE_BYTES = 16 * 1024 * 1024
MAX_EFFECTIVE_CONFIG_COHORT_BYTES = 256 * 1024 * 1024
MAX_PLANNING_PLAN_BYTES = 16 * 1024 * 1024
_CONFIG_COHORT_DOMAIN = b"NVDebug effective config cohort v1\0"
_PLAN_DOMAIN = b"NVDebug resolved collection plan v1\0"
_PLANNING_PLAN_DOMAIN = b"NVDebug resolved planning artifact v1\0"
_PATH_DOMAIN = b"NVDebug output path v1\0"
_SEMANTIC_VERSION_COMPONENT = re.compile(
    r"^v?(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)$",
    re.IGNORECASE,
)
_LEVEL_COMPONENT = re.compile(r"^L(?P<level>[123])$", re.IGNORECASE)
_PROFILE_COMPONENT = re.compile(
    r"^(?:profile[-_=])?(?P<profile>custom|level|planning|streaming)$",
    re.IGNORECASE,
)
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")
_BUILD_HASH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_BUILD_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_GIT_ENVIRONMENT = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": os.defpath,
    "TZ": "UTC",
}
_RUNTIME_IDENTITY_PATHS = (
    "src",
    "config",
    "default_config",
    "pyproject.toml",
    "requirements.txt",
)
_MAX_SOURCE_DIFF_BYTES = 64 * 1024 * 1024


class RunIdentityBuildError(RuntimeError):
    """
    An authoritative identity input could not be sealed safely.

    Callers receive this exception when the run identity build error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


@dataclass(frozen=True)
class EffectiveConfigCohort:
    """
    Transient exact-member evidence used by identity and archive owners.

    The immutable record keeps ``sha256`` and ``member_digests`` together so
    consumers observe one effective config cohort state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        sha256: Lowercase SHA-256 digest binding the SHA-256 content.
        member_digests: Collection of member digests entries retained by this
            record.
    """

    sha256: str
    member_digests: tuple[tuple[str, int, str], ...]


@dataclass(frozen=True)
class PlanningPlanSnapshot:
    """
    Bounded exact-byte evidence for the authoritative dry-run plan.

    The immutable record keeps ``sha256``, ``byte_count``, and ``dut_roster``
    together so consumers observe one planning plan state. Construction
    validates cross-field invariants before the instance is exposed.

    Attributes:
        sha256: Lowercase SHA-256 digest binding the SHA-256 content.
        byte_count: Number of byte entries represented by the record.
        dut_roster: Collection of DUT roster entries retained by this record.
    """

    sha256: str
    byte_count: int
    dut_roster: tuple[str, ...]

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized PlanningPlanSnapshot state.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Raises:
            ValueError: If planning plan digest is invalid; planning plan size
                is invalid; or planning plan DUT roster is invalid.
        """
        if (
            type(self.sha256) is not str  # noqa: E721 - subclasses are rejected
            or re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None
        ):
            raise ValueError("Planning plan digest is invalid")
        if (
            type(self.byte_count) is not int  # noqa: E721 - subclasses are rejected
            or self.byte_count <= 0
            or self.byte_count > MAX_PLANNING_PLAN_BYTES
        ):
            raise ValueError("Planning plan size is invalid")
        if (
            type(self.dut_roster) is not tuple
            or len(self.dut_roster) > MAX_DUTS
            or len(self.dut_roster) != len(set(self.dut_roster))
            or any(
                type(dut_id) is not str  # noqa: E721 - subclasses are rejected
                or not is_printable_identity(
                    dut_id,
                    maximum_bytes=MAX_DUT_ID_BYTES,
                )
                or dut_id in {".", ".."}
                or "/" in dut_id
                or "\\" in dut_id
                for dut_id in self.dut_roster
            )
        ):
            raise ValueError("Planning plan DUT roster is invalid")


_STABLE_IDENTITY_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _validate_effective_config_cohort(
    cohort: EffectiveConfigCohort,
    dut_roster: Iterable[str],
) -> EffectiveConfigCohort:
    """
    Validate effective config cohort.

    The implementation uses ``cohort`` and ``dut_roster`` to validate effective
    config cohort. Every required invariant is checked before a successful value
    is returned; invalid input follows the function's explicit exception path.

    Args:
        cohort: Cohort object whose ``member_digests`` and ``sha256`` state is
            read while performing effective config cohort.
        dut_roster: Entries supplied as ``dut_roster`` without transferring
            container ownership.

    Returns:
        The validated ``cohort``.

    Raises:
        RunIdentityBuildError: If effective configuration evidence is malformed;
            or effective configuration evidence is inconsistent.
    """
    if type(cohort) is not EffectiveConfigCohort:
        raise RunIdentityBuildError("Effective configuration evidence is malformed")
    roster = tuple(dut_roster)
    expected_paths = tuple(
        f"{dut_id}/{filename}"
        for dut_id in sorted(roster)
        for filename in ("config.json", "dut_config.json")
    )
    if (
        type(cohort.sha256) is not str  # noqa: E721 - subclasses are rejected
        or re.fullmatch(r"[0-9a-f]{64}", cohort.sha256) is None
        or type(cohort.member_digests) is not tuple
        or len(cohort.member_digests) != len(expected_paths)
    ):
        raise RunIdentityBuildError("Effective configuration evidence is malformed")
    digest = hashlib.sha256(_CONFIG_COHORT_DOMAIN)
    total_bytes = 0
    for expected_path, member in zip(
        expected_paths,
        cohort.member_digests,
        strict=True,
    ):
        if type(member) is not tuple or len(member) != 3:
            raise RunIdentityBuildError("Effective configuration evidence is malformed")
        relative, size, file_digest = member
        if (
            relative != expected_path
            or type(size) is not int  # noqa: E721 - subclasses are rejected
            or isinstance(size, bool)
            or size < 0
            or size > MAX_EFFECTIVE_CONFIG_FILE_BYTES
            or type(file_digest) is not str  # noqa: E721 - subclasses are rejected
            or re.fullmatch(r"[0-9a-f]{64}", file_digest) is None
        ):
            raise RunIdentityBuildError("Effective configuration evidence is malformed")
        total_bytes += size
        if total_bytes > MAX_EFFECTIVE_CONFIG_COHORT_BYTES:
            raise RunIdentityBuildError("Effective configuration evidence is malformed")
        encoded_path = relative.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(file_digest))
    if not hmac.compare_digest(digest.hexdigest(), cohort.sha256):
        raise RunIdentityBuildError("Effective configuration evidence is inconsistent")
    return cohort


def _config_value(holder: object, name: str, default: Any = None) -> Any:
    """
    Return the config value.

    The implementation uses ``holder``, ``name``, and ``default`` to produce the
    config value.

    Args:
        holder: Holder object whose ``get`` state is read while performing
            config value.
        name: Stable name used for lookup and operator-facing diagnostics.
        default: Fallback used when the requested value is absent or invalid.

    Returns:
        The config value selected by this operation.
    """
    if isinstance(holder, dict):
        return holder.get(name, default)
    return getattr(holder, name, default)


def _canonical_bytes(document: object) -> bytes:
    """
    Serialize an identity document into its canonical digest bytes.

    Keys are sorted, insignificant whitespace is removed, non-ASCII text is
    escaped, and non-finite numbers are rejected before ASCII encoding. The
    resulting bytes are stable input for identity digests.

    Args:
        document: Document consumed while the function attempts to serialize an
            identity document into its canonical digest bytes.

    Returns:
        The canonical ASCII bytes used as digest input.
    """
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _read_regular_file_at(
    directory_descriptor: int,
    name: str,
    *,
    maximum_bytes: int,
) -> tuple[int, str]:
    """
    Hash one stable direct child through a no-follow descriptor.

    The implementation uses ``directory_descriptor``, ``name``, and
    ``maximum_bytes`` to hash one stable direct child through a no-follow
    descriptor. Filesystem effects remain confined to the caller-selected paths
    and the owning resource lifecycle. If the function cannot hash one stable
    direct child through a no-follow descriptor, its exception reaches the
    caller instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        directory_descriptor: Numeric directory descriptor used while the
            operation performs bounded accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        A tuple containing ``observed`` and ``hexdigest`` in that order.

    Raises:
        RunIdentityBuildError: If effective configuration is not a regular file;
            effective configuration path changed; effective configuration
            exceeds its read bound; or effective configuration changed while it
            was hashed.
    """

    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
        dir_fd=directory_descriptor,
    )
    try:
        before = os.fstat(descriptor)
        path_before = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise RunIdentityBuildError("Effective configuration is not a regular file")
        if any(
            getattr(before, field) != getattr(path_before, field)
            for field in _STABLE_IDENTITY_FIELDS
        ):
            raise RunIdentityBuildError("Effective configuration path changed")
        if before.st_size < 0 or before.st_size > maximum_bytes:
            raise RunIdentityBuildError(
                "Effective configuration exceeds its read bound"
            )
        digest = hashlib.sha256()
        observed = 0
        while True:
            block = os.read(descriptor, min(64 * 1024, maximum_bytes - observed + 1))
            if not block:
                break
            observed += len(block)
            if observed > maximum_bytes:
                raise RunIdentityBuildError(
                    "Effective configuration exceeds its read bound"
                )
            digest.update(block)
        after = os.fstat(descriptor)
        path_after = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if observed != before.st_size or any(
            getattr(before, field) != getattr(after, field)
            or getattr(before, field) != getattr(path_after, field)
            for field in _STABLE_IDENTITY_FIELDS
        ):
            raise RunIdentityBuildError(
                "Effective configuration changed while it was hashed"
            )
        return observed, digest.hexdigest()
    finally:
        os.close(descriptor)


def _read_regular_file_bytes_at(
    directory_descriptor: int,
    name: str,
    *,
    maximum_bytes: int,
) -> bytes:
    """
    Read one stable bounded direct child without following a replacement.

    After applying local validation, the function forwards
    ``directory_descriptor``, ``name``, and ``maximum_bytes`` to ``join`` and
    preserves its return and exception contract. Parsing or I/O must finish
    before the validated representation is made available to the caller. Cleanup
    in the ``finally`` path runs for successful, failed, and cancelled
    execution.

    Args:
        directory_descriptor: Numeric directory descriptor used while the
            operation performs bounded accounting.
        name: Stable name used for lookup and operator-facing diagnostics.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The bounded regular file bytes at bytes.

    Raises:
        RunIdentityBuildError: If planning artifact is not a regular file;
            planning artifact path changed; planning artifact exceeds its read
            bound; or planning artifact changed while it was read.
    """

    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
        dir_fd=directory_descriptor,
    )
    try:
        before = os.fstat(descriptor)
        path_before = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise RunIdentityBuildError("Planning artifact is not a regular file")
        if any(
            getattr(before, field) != getattr(path_before, field)
            for field in _STABLE_IDENTITY_FIELDS
        ):
            raise RunIdentityBuildError("Planning artifact path changed")
        if before.st_size <= 0 or before.st_size > maximum_bytes:
            raise RunIdentityBuildError("Planning artifact exceeds its read bound")
        chunks: list[bytes] = []
        observed = 0
        while True:
            block = os.read(descriptor, min(64 * 1024, maximum_bytes - observed + 1))
            if not block:
                break
            observed += len(block)
            if observed > maximum_bytes:
                raise RunIdentityBuildError("Planning artifact exceeds its read bound")
            chunks.append(block)
        after = os.fstat(descriptor)
        path_after = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if observed != before.st_size or any(
            getattr(before, field) != getattr(after, field)
            or getattr(before, field) != getattr(path_after, field)
            for field in _STABLE_IDENTITY_FIELDS
        ):
            raise RunIdentityBuildError("Planning artifact changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _planning_plan_roster(document: object) -> tuple[str, ...]:
    """
    Validate the bounded product-owned dry-run plan and return its roster.

    After applying local validation, the function forwards ``document`` to
    ``tuple`` and preserves its return and exception contract. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        document: Mapping supplying fields for bounded product-owned dry-run
            plan and return its roster.

    Returns:
        The planning plan roster returned in operation-defined order.

    Raises:
        RunIdentityBuildError: If planning artifact has unexpected fields;
            planning artifact lifecycle is invalid; planning artifact collector
            request is invalid; or planning artifact DUT roster is invalid; or
            another input invariant is violated.
    """

    if type(document) is not dict or set(  # noqa: E721 - subclasses are rejected
        document
    ) != {  # noqa: E721 - subclasses are rejected
        "schema_version",
        "mode",
        "transport_calls",
        "collection_level",
        "requested_collectors",
        "duts",
    }:
        raise RunIdentityBuildError("Planning artifact has unexpected fields")
    if (
        document["schema_version"] != "1.0"
        or document["mode"] != "dry_run"
        or type(document["transport_calls"])  # noqa: E721 - subclasses are rejected
        is not int  # noqa: E721 - subclasses are rejected
        or document["transport_calls"] != 0
        or type(document["collection_level"])  # noqa: E721 - subclasses are rejected
        is not str  # noqa: E721 - subclasses are rejected
        or document["collection_level"] not in {"L1", "L2", "L3"}
    ):
        raise RunIdentityBuildError("Planning artifact lifecycle is invalid")

    requested = document["requested_collectors"]
    if (
        type(requested) is not list  # noqa: E721 - subclasses are rejected
        or len(requested) > MAX_COLLECTORS_PER_RUN
        or len(requested) != len(set(requested))
        or any(
            type(collector_id) is not str  # noqa: E721 - subclasses are rejected
            or not is_printable_identity(
                collector_id,
                maximum_bytes=MAX_COLLECTOR_ID_BYTES,
            )
            for collector_id in requested
        )
    ):
        raise RunIdentityBuildError("Planning artifact collector request is invalid")

    raw_duts = document["duts"]
    if (
        type(raw_duts) is not list  # noqa: E721 - subclasses are rejected
        or len(raw_duts) > MAX_DUTS  # noqa: E721 - subclasses are rejected
    ):  # noqa: E721 - subclasses are rejected
        raise RunIdentityBuildError("Planning artifact DUT roster is invalid")
    roster: list[str] = []
    for raw_dut in raw_duts:
        if type(raw_dut) is not dict or set(  # noqa: E721 - subclasses are rejected
            raw_dut
        ) != {  # noqa: E721 - subclasses are rejected
            "id",
            "baseboard",
            "selected_collectors",
            "skipped_collectors",
        }:
            raise RunIdentityBuildError("Planning artifact DUT entry is malformed")
        dut_id = raw_dut["id"]
        if (
            type(dut_id) is not str  # noqa: E721 - subclasses are rejected
            or not is_printable_identity(dut_id, maximum_bytes=MAX_DUT_ID_BYTES)
            or dut_id in {".", ".."}
            or "/" in dut_id
            or "\\" in dut_id
        ):
            raise RunIdentityBuildError("Planning artifact DUT identity is invalid")
        baseboard = raw_dut["baseboard"]
        if baseboard is not None and (
            type(baseboard) is not str  # noqa: E721 - subclasses are rejected
            or len(baseboard.encode("utf-8")) > 4096
            or not baseboard.isprintable()
        ):
            raise RunIdentityBuildError("Planning artifact baseboard is invalid")
        selected = raw_dut["selected_collectors"]
        skipped = raw_dut["skipped_collectors"]
        if (
            type(selected) is not list  # noqa: E721 - subclasses are rejected
            or len(selected) > MAX_COLLECTORS_PER_RUN
            or len(selected) != len(set(selected))
            or any(
                type(collector_id) is not str  # noqa: E721 - subclasses are rejected
                or not is_printable_identity(
                    collector_id,
                    maximum_bytes=MAX_COLLECTOR_ID_BYTES,
                )
                for collector_id in selected
            )
            or type(skipped) is not dict  # noqa: E721 - subclasses are rejected
            or len(skipped) > MAX_COLLECTORS_PER_RUN
            or any(
                type(collector_id) is not str  # noqa: E721 - subclasses are rejected
                or not is_printable_identity(
                    collector_id,
                    maximum_bytes=MAX_COLLECTOR_ID_BYTES,
                )
                for collector_id in skipped
            )
        ):
            raise RunIdentityBuildError("Planning artifact selection is invalid")
        roster.append(dut_id)
    if len(roster) != len(set(roster)):
        raise RunIdentityBuildError("Planning artifact DUT roster is invalid")
    return tuple(roster)


def capture_planning_plan_snapshot(
    output_root: str | Path,
) -> PlanningPlanSnapshot:
    """
    Capture exact stable bytes from the authoritative dry-run plan leaf.

    After applying local validation, the function forwards ``output_root`` to
    ``PlanningPlanSnapshot`` and preserves its return and exception contract.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        output_root: filesystem location used as the output root for this
            operation.

    Returns:
        A ``PlanningPlanSnapshot`` representing capture planning plan snapshot.

    Raises:
        RunIdentityBuildError: If planning artifact root could not be opened;
            planning artifact root changed; planning artifact directory changed;
            or planning artifact is invalid JSON; or another input invariant is
            violated.
    """

    try:
        root_descriptor = os.open(
            Path(output_root),
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except (OSError, TypeError, ValueError) as error:
        raise RunIdentityBuildError(
            "Planning artifact root could not be opened"
        ) from error

    metadata_descriptor = -1
    try:
        root_before = os.fstat(root_descriptor)
        root_path_before = os.stat(Path(output_root), follow_symlinks=False)
        if any(
            getattr(root_before, field) != getattr(root_path_before, field)
            for field in _STABLE_IDENTITY_FIELDS
        ):
            raise RunIdentityBuildError("Planning artifact root changed")
        metadata_descriptor = os.open(
            ".metadata",
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
        metadata_before = os.fstat(metadata_descriptor)
        metadata_path_before = os.stat(
            ".metadata",
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if any(
            getattr(metadata_before, field) != getattr(metadata_path_before, field)
            for field in _STABLE_IDENTITY_FIELDS
        ):
            raise RunIdentityBuildError("Planning artifact directory changed")

        content = _read_regular_file_bytes_at(
            metadata_descriptor,
            "collection_plan.json",
            maximum_bytes=MAX_PLANNING_PLAN_BYTES,
        )
        try:
            document = json.loads(content.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise RunIdentityBuildError("Planning artifact is invalid JSON") from error
        roster = _planning_plan_roster(document)

        metadata_after = os.fstat(metadata_descriptor)
        metadata_path_after = os.stat(
            ".metadata",
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if any(
            getattr(metadata_before, field) != getattr(metadata_after, field)
            or getattr(metadata_before, field) != getattr(metadata_path_after, field)
            for field in _STABLE_IDENTITY_FIELDS
        ):
            raise RunIdentityBuildError("Planning artifact directory changed")
        root_after = os.fstat(root_descriptor)
        root_path_after = os.stat(Path(output_root), follow_symlinks=False)
        if any(
            getattr(root_before, field) != getattr(root_after, field)
            or getattr(root_before, field) != getattr(root_path_after, field)
            for field in _STABLE_IDENTITY_FIELDS
        ):
            raise RunIdentityBuildError("Planning artifact root changed")
    except (OSError, UnicodeError) as error:
        raise RunIdentityBuildError(
            "Planning artifact could not be captured"
        ) from error
    finally:
        if metadata_descriptor >= 0:
            os.close(metadata_descriptor)
        os.close(root_descriptor)

    relative = b".metadata/collection_plan.json"
    raw_digest = hashlib.sha256(content).digest()
    digest = hashlib.sha256(_PLANNING_PLAN_DOMAIN)
    digest.update(len(relative).to_bytes(4, "big"))
    digest.update(relative)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(raw_digest)
    return PlanningPlanSnapshot(
        sha256=digest.hexdigest(),
        byte_count=len(content),
        dut_roster=roster,
    )


def capture_effective_config_cohort(
    output_root: str | Path,
    dut_roster: Iterable[str],
) -> EffectiveConfigCohort:
    """
    Capture the exact sorted post-sanitizer public configuration cohort.

    The digest is domain-separated and framed as ``relative path, size, file
    SHA-256`` records. Raw configuration bytes and paths never enter run
    metadata, while an offline verifier can recompute the same value.

    Args:
        output_root: filesystem location used as the output root for this
            operation.
        dut_roster: Entries supplied as ``dut_roster`` without transferring
            container ownership.

    Returns:
        An ``EffectiveConfigCohort`` representing capture effective config
        cohort.

    Raises:
        RunIdentityBuildError: If effective configuration DUT roster is invalid;
            effective configuration root could not be opened; effective
            configuration root changed; or effective configuration DUT path
            changed; or another input invariant is violated.
    """

    roster = tuple(dut_roster)
    if len(roster) != len(set(roster)):
        raise RunIdentityBuildError("Effective configuration DUT roster is invalid")
    try:
        root_descriptor = os.open(
            Path(output_root),
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except (OSError, TypeError, ValueError) as error:
        raise RunIdentityBuildError(
            "Effective configuration root could not be opened"
        ) from error
    digest = hashlib.sha256(_CONFIG_COHORT_DOMAIN)
    total_bytes = 0
    member_digests: list[tuple[str, int, str]] = []
    try:
        root_before = os.fstat(root_descriptor)
        root_path_before = os.stat(Path(output_root), follow_symlinks=False)
        if any(
            getattr(root_before, field) != getattr(root_path_before, field)
            for field in _STABLE_IDENTITY_FIELDS
        ):
            raise RunIdentityBuildError("Effective configuration root changed")
        for dut_id in sorted(roster):
            if (
                not isinstance(dut_id, str)
                or dut_id in {"", ".", ".."}
                or "/" in dut_id
                or "\\" in dut_id
            ):
                raise RunIdentityBuildError(
                    "Effective configuration DUT roster is invalid"
                )
            dut_descriptor = os.open(
                dut_id,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_descriptor,
            )
            try:
                dut_before = os.fstat(dut_descriptor)
                dut_path_before = os.stat(
                    dut_id,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
                if any(
                    getattr(dut_before, field) != getattr(dut_path_before, field)
                    for field in _STABLE_IDENTITY_FIELDS
                ):
                    raise RunIdentityBuildError(
                        "Effective configuration DUT path changed"
                    )
                for filename in ("config.json", "dut_config.json"):
                    size, file_digest = _read_regular_file_at(
                        dut_descriptor,
                        filename,
                        maximum_bytes=MAX_EFFECTIVE_CONFIG_FILE_BYTES,
                    )
                    total_bytes += size
                    if total_bytes > MAX_EFFECTIVE_CONFIG_COHORT_BYTES:
                        raise RunIdentityBuildError(
                            "Effective configuration cohort exceeds its read bound"
                        )
                    relative_text = f"{dut_id}/{filename}"
                    relative = relative_text.encode("utf-8")
                    digest.update(len(relative).to_bytes(4, "big"))
                    digest.update(relative)
                    digest.update(size.to_bytes(8, "big"))
                    digest.update(bytes.fromhex(file_digest))
                    member_digests.append((relative_text, size, file_digest))
                dut_after = os.fstat(dut_descriptor)
                dut_path_after = os.stat(
                    dut_id,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
                if any(
                    getattr(dut_before, field) != getattr(dut_after, field)
                    or getattr(dut_before, field) != getattr(dut_path_after, field)
                    for field in _STABLE_IDENTITY_FIELDS
                ):
                    raise RunIdentityBuildError(
                        "Effective configuration DUT path changed"
                    )
            finally:
                os.close(dut_descriptor)
        root_after = os.fstat(root_descriptor)
        root_path_after = os.stat(Path(output_root), follow_symlinks=False)
        if any(
            getattr(root_before, field) != getattr(root_after, field)
            or getattr(root_before, field) != getattr(root_path_after, field)
            for field in _STABLE_IDENTITY_FIELDS
        ):
            raise RunIdentityBuildError("Effective configuration root changed")
    except (OSError, UnicodeError) as error:
        raise RunIdentityBuildError(
            "Effective configuration cohort could not be hashed"
        ) from error
    finally:
        os.close(root_descriptor)
    return _validate_effective_config_cohort(
        EffectiveConfigCohort(
            sha256=digest.hexdigest(),
            member_digests=tuple(member_digests),
        ),
        roster,
    )


def hash_effective_config_cohort(
    output_root: str | Path,
    dut_roster: Iterable[str],
) -> str:
    """
    Return only the public cohort digest for offline verification.

    The implementation uses ``output_root`` and ``dut_roster`` to produce only
    the public cohort digest for offline verification.

    Args:
        output_root: filesystem location used as the output root for this
            operation.
        dut_roster: Entries supplied as ``dut_roster`` without transferring
            container ownership.

    Returns:
        The canonical effective config cohort text.
    """

    return capture_effective_config_cohort(output_root, dut_roster).sha256


def hash_resolved_plan(receipt: FinalizationReceipt) -> str:
    """
    Hash the exact sorted DUT/collector identities in the terminal plan.

    After applying local validation, the function forwards ``receipt`` to
    ``hexdigest`` and preserves its return and exception contract.

    Args:
        receipt: Receipt object whose ``collector_statuses`` and ``dut_roster``
            state is read while performing hash the exact sorted DUT/collector
            identities in the terminal plan.

    Returns:
        The canonical resolved plan text.

    Raises:
        TypeError: If a FinalizationReceipt is required to bind the plan.
    """

    if type(receipt) is not FinalizationReceipt:
        raise TypeError("A FinalizationReceipt is required to bind the plan")
    plan = {
        "schema_version": "1.0",
        "dut_roster": sorted(receipt.dut_roster),
        "collectors": sorted(
            [status.dut_id, status.collector_id]
            for status in receipt.collector_statuses
        ),
    }
    return hashlib.sha256(_PLAN_DOMAIN + _canonical_bytes(plan)).hexdigest()


def resolved_profile(tool_config: object) -> str:
    """
    Return the product-owned profile after runtime selection is resolved.

    The implementation uses ``tool_config`` to produce the product-owned profile
    after runtime selection is resolved.

    Args:
        tool_config: Tool config governing product-owned profile after runtime
            selection is resolved.

    Returns:
        The canonical resolved profile text.
    """

    if bool(_config_value(tool_config, "dry_run", False)):
        return "planning"
    if bool(_config_value(tool_config, "streaming_only", False)):
        return "streaming"
    selectors = (
        _config_value(tool_config, "collector_id"),
        _config_value(tool_config, "collector_group"),
        _config_value(tool_config, "include_collectors"),
        _config_value(tool_config, "skip_collectors"),
    )
    return "custom" if any(value for value in selectors) else "level"


def _canonical_path(path: str | Path) -> str:
    """
    Return the canonical path.

    After applying local validation, the function forwards ``path`` to
    ``os.path.abspath`` and preserves its return and exception contract.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        The canonical path.

    Raises:
        RunIdentityBuildError: If output path is malformed.
    """
    try:
        return os.path.abspath(os.path.normpath(os.fspath(path)))
    except (TypeError, ValueError, OSError) as error:
        raise RunIdentityBuildError("Output path is malformed") from error


def _path_digest(normalized: str) -> str:
    """
    Return the path digest.

    After applying local validation, the function forwards ``normalized`` to
    ``hexdigest`` and preserves its return and exception contract.

    Args:
        normalized: Text supplied as normalized in the format accepted by this
            function.

    Returns:
        The canonical path digest.
    """
    return hashlib.sha256(_PATH_DOMAIN + os.fsencode(normalized)).hexdigest()


def _alignment(claims: set[str], expected: str) -> str:
    """
    Return the alignment.

    The implementation uses ``claims`` and ``expected`` to produce the
    alignment.

    Args:
        claims: Entries supplied as ``claims`` without transferring container
            ownership.
        expected: Text supplied as expected in the format accepted by this
            function.

    Returns:
        The canonical alignment text.
    """
    if not claims:
        return "not_declared"
    return "aligned" if claims == {expected.casefold()} else "conflict"


def path_identity(
    path: str | Path | None,
    *,
    tool_version: str,
    level: str,
    profile: str,
) -> RunPathIdentity:
    """
    Hash a path and retain only disclosure-free semantic alignments.

    The implementation uses ``path``, ``tool_version``, ``level``, and
    ``profile`` to hash a path and retain only disclosure-free semantic
    alignments.

    Args:
        path: Optional filesystem location used as the path for this operation.
        tool_version: Text supplied as tool version in the format accepted by
            this function.
        level: Text supplied as level in the format accepted by this function.
        profile: Text supplied as profile in the format accepted by this
            function.

    Returns:
        The validated path identity filesystem path.
    """

    if path is None:
        return RunPathIdentity(
            path_sha256=None,
            version_alignment="not_declared",
            level_alignment="not_declared",
            profile_alignment="not_declared",
        )
    normalized = _canonical_path(path)
    components = tuple(str(part) for part in PurePath(normalized).parts)
    version_claims = {
        match.group("version").casefold()
        for component in components
        for match in (_SEMANTIC_VERSION_COMPONENT.fullmatch(component),)
        if match is not None
    }
    level_claims = {
        f"l{match.group('level')}"
        for component in components
        for match in (_LEVEL_COMPONENT.fullmatch(component),)
        if match is not None
    }
    profile_claims = {
        match.group("profile").casefold()
        for component in components
        for match in (_PROFILE_COMPONENT.fullmatch(component),)
        if match is not None
    }
    return RunPathIdentity(
        path_sha256=_path_digest(normalized),
        version_alignment=_alignment(version_claims, tool_version),
        level_alignment=_alignment(level_claims, level),
        profile_alignment=_alignment(profile_claims, profile),
    )


def _output_relation(
    selected_base: str | Path,
    output_root: str | Path,
    *,
    append: bool,
    caller_explicit: bool,
) -> str:
    """
    Prove containment before discarding raw output path material.

    The implementation uses ``selected_base``, ``output_root``, ``append``, and
    ``caller_explicit`` to prove containment before discarding raw output path
    material. Filesystem effects remain confined to the caller-selected paths
    and the owning resource lifecycle. If the function cannot prove containment
    before discarding raw output path material, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        selected_base: filesystem location used as the selected base for this
            operation.
        output_root: filesystem location used as the output root for this
            operation.
        append: Whether append is enabled or required for this operation.
        caller_explicit: Whether caller explicit is enabled or required for this
            operation.

    Returns:
        The canonical output relation text.

    Raises:
        RunIdentityBuildError: If resolved output is outside its configured
            base; or the generated output is not below its configured base.
    """

    try:
        base = Path(_canonical_path(selected_base)).resolve(strict=True)
        resolved = Path(_canonical_path(output_root)).resolve(strict=True)
        relative = resolved.relative_to(base)
    except (OSError, RuntimeError, ValueError) as error:
        raise RunIdentityBuildError(
            "Resolved output is outside its configured base"
        ) from error
    relation = "same" if not relative.parts else "descendant"
    if not append and relation != "descendant":
        raise RunIdentityBuildError(
            "Generated output must be below its configured base"
        )
    if not append and not caller_explicit:
        return "absent"
    return relation


def _source_checkout_root() -> Path | None:
    """
    Return the source checkout root.

    The implementation uses current instance state to produce the source
    checkout root. Filesystem effects remain confined to the caller-selected
    paths and the owning resource lifecycle.

    Returns:
        The validated ``candidate``, or ``None`` when no value qualifies.
    """
    for candidate in Path(__file__).resolve().parents:
        if (candidate / ".git").exists():
            return candidate
    return None


def _git_value(root: Path, *arguments: str) -> str:
    """
    Run a bounded Git query and return its standard output.

    The implementation uses ``root`` and ``arguments`` to run a bounded Git
    query and return its standard output. Terminal status is emitted only after
    bounded Git query and return its standard output and its owned cleanup have
    completed.

    Args:
        root: filesystem location used as the root for this operation.
        arguments: Additional positional values forwarded in caller-provided
            order.

    Returns:
        The canonical git value.
    """
    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                os.fspath(root),
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=3.0,
            env=_GIT_ENVIRONMENT,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if completed.returncode != 0 or len(completed.stdout) > 256:
        return "unknown"
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeError:
        return "unknown"


def _source_checkout_build_hash(root: Path, source_revision: str) -> str:
    """
    Bind a source run to its clean revision or relevant dirty-tree content.

    The hash covers tracked staged and unstaged changes plus the names and bytes
    of untracked files under runtime-bearing paths. Test-framework and
    source-authoring changes remain outside product identity until they alter a
    governed runtime artifact. Git output and untracked content are bounded; an
    unavailable or oversized identity returns ``unknown`` instead of delaying
    collection startup.

    Args:
        root: Source checkout root containing the authoritative Git metadata.
        source_revision: Validated 40-character revision for the source run.

    Returns:
        A build identifier carrying a clean revision or dirty content digest,
        or ``unknown`` when the checkout cannot be inspected safely.
    """
    git_prefix = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
        os.fspath(root),
    ]
    try:
        tracked = subprocess.run(
            [
                *git_prefix,
                "diff",
                "--binary",
                "--no-ext-diff",
                "HEAD",
                "--",
                *_RUNTIME_IDENTITY_PATHS,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5.0,
            env=_GIT_ENVIRONMENT,
        )
        untracked = subprocess.run(
            [
                *git_prefix,
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                *_RUNTIME_IDENTITY_PATHS,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5.0,
            env=_GIT_ENVIRONMENT,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if tracked.returncode != 0 or untracked.returncode != 0:
        return "unknown"
    if (
        len(tracked.stdout) > _MAX_SOURCE_DIFF_BYTES
        or len(untracked.stdout) > _MAX_SOURCE_DIFF_BYTES
    ):
        return "unknown"

    untracked_names = [name for name in untracked.stdout.split(b"\0") if name]
    if not tracked.stdout and not untracked_names:
        return f"source-clean.{source_revision}"

    digest = hashlib.sha256(b"NVDebug source checkout state v1\0")
    digest.update(len(tracked.stdout).to_bytes(8, "big"))
    digest.update(tracked.stdout)
    total_untracked_bytes = 0
    for encoded_name in sorted(untracked_names):
        try:
            relative_name = encoded_name.decode("utf-8", errors="strict")
            unresolved_candidate = root / relative_name
            if stat.S_ISLNK(unresolved_candidate.lstat().st_mode):
                return "unknown"
            candidate = unresolved_candidate.resolve(strict=True)
            candidate.relative_to(root.resolve(strict=True))
            file_stat = candidate.stat()
            if not stat.S_ISREG(file_stat.st_mode):
                return "unknown"
            total_untracked_bytes += file_stat.st_size
            if total_untracked_bytes > _MAX_SOURCE_DIFF_BYTES:
                return "unknown"
            content = candidate.read_bytes()
        except (OSError, UnicodeError, ValueError):
            return "unknown"
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"source-dirty.{digest.hexdigest()}"


def tool_identity_facts() -> dict[str, str]:
    """
    Resolve stamped build facts, with bounded source-checkout diagnostics.

    The implementation uses current instance state to resolve stamped build
    facts, with bounded source-checkout diagnostics.

    Returns:
        A mapping containing the ``tool_version``, ``build_hash``,
        ``source_mode``, ``source_revision``, and ``build_timestamp_utc``
        fields.
    """

    from ..version import (
        __build_hash__,
        __build_time__,
        __source_revision__,
        __version__,
    )

    source_mode = "frozen" if is_frozen() else "source"
    build_hash = str(__build_hash__).strip()
    if _BUILD_HASH.fullmatch(build_hash) is None:
        build_hash = "unknown"
    source_revision = str(__source_revision__).strip().lower()
    build_timestamp = str(__build_time__).strip()
    if source_mode == "source" and source_revision == "unknown":
        checkout = _source_checkout_root()
        if checkout is not None:
            candidate_revision = _git_value(
                checkout, "rev-parse", "--verify", "HEAD"
            ).lower()
            if _SOURCE_REVISION.fullmatch(candidate_revision) is not None:
                source_revision = candidate_revision
            candidate_timestamp = _git_value(
                checkout,
                "show",
                "-s",
                "--format=%cd",
                "--date=format:%Y-%m-%dT%H:%M:%SZ",
                "HEAD",
            )
            if _BUILD_TIMESTAMP.fullmatch(candidate_timestamp) is not None:
                build_timestamp = candidate_timestamp
    if (
        source_mode == "source"
        and build_hash == "unknown"
        and _SOURCE_REVISION.fullmatch(source_revision) is not None
    ):
        checkout = _source_checkout_root()
        if checkout is not None:
            build_hash = _source_checkout_build_hash(checkout, source_revision)
    if _SOURCE_REVISION.fullmatch(source_revision) is None:
        source_revision = "unknown"
    if _BUILD_TIMESTAMP.fullmatch(build_timestamp) is None:
        build_timestamp = "unknown"
    return {
        "tool_version": str(__version__).strip() or "unknown",
        "build_hash": build_hash,
        "source_mode": source_mode,
        "source_revision": source_revision,
        "build_timestamp_utc": build_timestamp,
    }


def _build_run_identity(
    *,
    tool_config: object,
    catalog_facts: CatalogSnapshotFacts,
    receipt: FinalizationReceipt,
    output_root: str | Path,
    resolved_plan_sha256: str,
    tool_facts: dict[str, str] | None = None,
    config_cohort: EffectiveConfigCohort | None = None,
) -> RunIdentity:
    """
    Seal shared identity fields from a mode-owned resolved-plan digest.

    After applying local validation, the function forwards ``tool_config``,
    ``catalog_facts``, ``receipt``, ``output_root``, and
    ``resolved_plan_sha256`` to ``RunIdentity`` and preserves its return and
    exception contract.

    Args:
        tool_config: Tool config governing seal shared identity fields from a
            mode-owned resolved-plan digest.
        catalog_facts: Catalog facts object whose ``catalog_binding``,
            ``catalog_byte_count``, ``catalog_name``, ``catalog_sha256``, and
            ``catalog_version`` state is read while performing seal shared
            identity fields from a mode-owned resolved-plan digest.
        receipt: Receipt object whose ``dut_roster`` state is read while
            performing seal shared identity fields from a mode-owned
            resolved-plan digest.
        output_root: filesystem location used as the output root for this
            operation.
        resolved_plan_sha256: Text supplied as resolved plan SHA-256 in the
            format accepted by this function.
        tool_facts: Optional tool facts; ``None`` selects the function's default
            behavior.
        config_cohort: Optional Config cohort governing seal shared identity
            fields from a mode-owned resolved-plan digest.

    Returns:
        A ``RunIdentity`` representing run identity.

    Raises:
        RunIdentityBuildError: If authoritative catalog facts are unavailable;
            or authoritative tool identity facts are malformed.
    """

    if type(catalog_facts) is not CatalogSnapshotFacts:
        raise RunIdentityBuildError("Authoritative catalog facts are unavailable")
    level_value = _config_value(tool_config, "collection_level", "unknown")
    level = str(getattr(level_value, "value", level_value) or "unknown").upper()
    profile = resolved_profile(tool_config)
    append = bool(_config_value(tool_config, "append", False))
    caller_explicit = bool(
        _config_value(tool_config, "caller_output_was_explicit", False)
    )
    selected_base = (
        _config_value(tool_config, "stream_destination")
        if bool(_config_value(tool_config, "streaming_only", False))
        and _config_value(tool_config, "stream_destination")
        else _config_value(tool_config, "output_directory")
    )
    caller_relation = _output_relation(
        selected_base,
        output_root,
        append=append,
        caller_explicit=caller_explicit,
    )
    if append:
        output_mode = "caller_supplied_append"
        caller_output: str | Path | None = selected_base
        generated_output: str | Path | None = None
    elif caller_explicit:
        output_mode = "caller_based_generated"
        caller_output = selected_base
        generated_output = output_root
    else:
        output_mode = "configured_generated"
        caller_output = None
        generated_output = output_root

    tool = dict(tool_facts) if tool_facts is not None else tool_identity_facts()
    if set(tool) != {
        "tool_version",
        "build_hash",
        "source_mode",
        "source_revision",
        "build_timestamp_utc",
    } or any(
        type(value) is not str  # noqa: E721 - subclasses are rejected
        for value in tool.values()  # noqa: E721 - subclasses are rejected
    ):  # noqa: E721 - subclasses are rejected
        raise RunIdentityBuildError("Authoritative tool identity facts are malformed")
    if config_cohort is None:
        config_cohort = capture_effective_config_cohort(
            output_root,
            receipt.dut_roster,
        )
    config_cohort = _validate_effective_config_cohort(
        config_cohort,
        receipt.dut_roster,
    )
    return RunIdentity(
        **tool,
        catalog_name=catalog_facts.catalog_name,
        catalog_version=catalog_facts.catalog_version,
        catalog_sha256=catalog_facts.catalog_sha256,
        catalog_size_bytes=catalog_facts.catalog_byte_count,
        catalog_binding=catalog_facts.catalog_binding,
        effective_config_sha256=config_cohort.sha256,
        resolved_level=level,
        resolved_profile=profile,
        resolved_plan_sha256=resolved_plan_sha256,
        output_mode=output_mode,
        caller_relation=caller_relation,
        caller_path=path_identity(
            caller_output,
            tool_version=tool["tool_version"],
            level=level,
            profile=profile,
        ),
        resolved_path=path_identity(
            output_root,
            tool_version=tool["tool_version"],
            level=level,
            profile=profile,
        ),
        generated_path=path_identity(
            generated_output,
            tool_version=tool["tool_version"],
            level=level,
            profile=profile,
        ),
    )


def build_run_identity(
    *,
    tool_config: object,
    catalog_facts: CatalogSnapshotFacts,
    receipt: FinalizationReceipt,
    output_root: str | Path,
    tool_facts: dict[str, str] | None = None,
    config_cohort: EffectiveConfigCohort | None = None,
) -> RunIdentity:
    """
    Seal one collection identity after terminal-plan finalization.

    After applying local validation, the function forwards ``tool_config``,
    ``catalog_facts``, ``receipt``, ``output_root``, and ``tool_facts`` to
    ``_build_run_identity`` and preserves its return and exception contract.

    Args:
        tool_config: Tool config governing seal one collection identity after
            terminal-plan finalization.
        catalog_facts: Catalog facts consumed while the function attempts to
            seal one collection identity after terminal-plan finalization.
        receipt: Receipt consumed while the function attempts to seal one
            collection identity after terminal-plan finalization.
        output_root: filesystem location used as the output root for this
            operation.
        tool_facts: Optional tool facts; ``None`` selects the function's default
            behavior.
        config_cohort: Optional Config cohort governing seal one collection
            identity after terminal-plan finalization.

    Returns:
        A ``RunIdentity`` representing run identity.
    """

    return _build_run_identity(
        tool_config=tool_config,
        catalog_facts=catalog_facts,
        receipt=receipt,
        output_root=output_root,
        resolved_plan_sha256=hash_resolved_plan(receipt),
        tool_facts=tool_facts,
        config_cohort=config_cohort,
    )


def build_planning_run_identity(
    *,
    tool_config: object,
    catalog_facts: CatalogSnapshotFacts,
    receipt: FinalizationReceipt,
    output_root: str | Path,
    planning_plan: PlanningPlanSnapshot,
    tool_facts: dict[str, str] | None = None,
    config_cohort: EffectiveConfigCohort | None = None,
) -> RunIdentity:
    """
    Seal a transport-free identity from the exact published planning artifact.

    The implementation uses ``tool_config``, ``catalog_facts``, ``receipt``,
    ``output_root``, and ``planning_plan`` to seal a transport-free identity
    from the exact published planning artifact. If the function cannot seal a
    transport-free identity from the exact published planning artifact, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        tool_config: Tool config governing seal a transport-free identity from
            the exact published planning artifact.
        catalog_facts: Catalog facts consumed while the function attempts to
            seal a transport-free identity from the exact published planning
            artifact.
        receipt: Receipt object whose ``archive_artifact_digests``,
            ``collector_counts``, ``collector_statuses``,
            ``committed_generation``, and ``dut_roster`` state is read while
            performing seal a transport-free identity from the exact published
            planning artifact.
        output_root: filesystem location used as the output root for this
            operation.
        planning_plan: Planning plan object whose ``byte_count``,
            ``dut_roster``, and ``sha256`` state is read while performing seal a
            transport-free identity from the exact published planning artifact.
        tool_facts: Optional tool facts; ``None`` selects the function's default
            behavior.
        config_cohort: Optional Config cohort governing seal a transport-free
            identity from the exact published planning artifact.

    Returns:
        The validated ``identity``.

    Raises:
        RunIdentityBuildError: If planning receipt is malformed; planning
            receipt contains collection evidence; planning identity lacks
            dry-run configuration; or authoritative planning evidence is
            malformed; or another input invariant is violated.
    """

    try:
        validate_structural_finalization_receipt(receipt)
    except (RuntimeError, TypeError, ValueError) as error:
        raise RunIdentityBuildError("Planning receipt is malformed") from error
    if (
        receipt.terminal_snapshot_committed
        or receipt.committed_generation is not None
        or receipt.collector_counts
        or receipt.collector_statuses
        or receipt.archive_artifact_digests
    ):
        raise RunIdentityBuildError("Planning receipt contains collection evidence")
    if not bool(_config_value(tool_config, "dry_run", False)):
        raise RunIdentityBuildError("Planning identity requires dry-run configuration")
    if type(planning_plan) is not PlanningPlanSnapshot:
        raise RunIdentityBuildError("Authoritative planning evidence is malformed")
    try:
        validated_plan = PlanningPlanSnapshot(
            sha256=planning_plan.sha256,
            byte_count=planning_plan.byte_count,
            dut_roster=planning_plan.dut_roster,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise RunIdentityBuildError(
            "Authoritative planning evidence is malformed"
        ) from error
    if (
        validated_plan != planning_plan
        or validated_plan.dut_roster != receipt.dut_roster
    ):
        raise RunIdentityBuildError(
            "Planning plan DUT roster differs from finalization"
        )

    identity = _build_run_identity(
        tool_config=tool_config,
        catalog_facts=catalog_facts,
        receipt=receipt,
        output_root=output_root,
        resolved_plan_sha256=validated_plan.sha256,
        tool_facts=tool_facts,
        config_cohort=config_cohort,
    )
    if identity.resolved_profile != "planning":
        raise RunIdentityBuildError("Planning identity resolved an invalid profile")
    return identity
