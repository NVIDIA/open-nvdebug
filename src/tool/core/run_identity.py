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
Immutable, secret-neutral facts identifying one resolved invocation.

The identity contains facts only. It deliberately has no validation verdict or
success state: terminal eligibility is derived from the canonical ``RunResult``
that carries this value.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from ..utils.catalog_snapshot import MAX_CATALOG_SNAPSHOT_BYTES

RUN_IDENTITY_SCHEMA_VERSION = "1.1"

_ALIGNMENTS = frozenset({"aligned", "conflict", "not_declared"})
_OUTPUT_MODES = frozenset(
    {
        "configured_generated",
        "caller_based_generated",
        "caller_supplied_append",
    }
)
_CALLER_RELATIONS = frozenset({"absent", "same", "descendant"})
_SOURCE_MODES = frozenset({"frozen", "source", "unknown"})
_RESOLVED_LEVELS = frozenset({"L1", "L2", "L3", "unknown"})
_RESOLVED_PROFILES = frozenset({"custom", "level", "planning", "streaming", "unknown"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SEMANTIC_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
_BUILD_HASH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_BUILD_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_CATALOG_NAME = re.compile(
    r"^Telemetry_Catalog_v(?P<version>[0-9]+\.[0-9]+(?:\.[0-9]+)?)\.xlsx$"
)


def _has_exact_type(value: object, expected_type: type) -> bool:
    """
    Return whether a value has exactly the required runtime type.

    The implementation uses ``value`` and ``expected_type`` to determine whether
    a value has exactly the required runtime type.

    Args:
        value: Value whose exact runtime type is inspected without accepting
            subclasses.
        expected_type: Exact runtime type required for ``value``.

    Returns:
        Whether a value has exactly the required runtime type.
    """
    return object.__getattribute__(value, "__class__") is expected_type


def _canonical_bytes(document: Mapping[str, Any]) -> bytes:
    """
    Return the sole byte representation used by identity digests.

    Keys are sorted, insignificant whitespace is removed, non-ASCII text is
    escaped, and non-finite numbers are rejected before ASCII encoding. The
    resulting bytes are stable input for identity digests.

    Args:
        document: Mapping supplying fields for sole byte representation used by
            identity digests.

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


def _valid_sha256(value: object) -> bool:
    """
    Return whether a value is a lowercase SHA-256 digest.

    The implementation uses ``value`` to determine whether a value is a
    lowercase SHA-256 digest.

    Args:
        value: Value evaluated while performing value is a lowercase SHA-256
            digest.

    Returns:
        Whether a value is a lowercase SHA-256 digest.
    """
    return _has_exact_type(value, str) and _SHA256.fullmatch(value) is not None


@dataclass(frozen=True)
class RunPathIdentity:
    """
    Hashed path identity plus disclosure-free label alignment facts.

    The immutable record keeps ``path_sha256``, ``version_alignment``,
    ``level_alignment``, and ``profile_alignment`` together so consumers observe
    one run path identity state. Construction validates cross-field invariants
    before the instance is exposed.

    Attributes:
        path_sha256: Lowercase SHA-256 digest binding the path content.
        version_alignment: Canonical text used as version alignment.
        level_alignment: Canonical text used as level alignment.
        profile_alignment: Canonical text used as profile alignment.
    """

    path_sha256: str | None
    version_alignment: str
    level_alignment: str
    profile_alignment: str

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized RunPathIdentity state.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Raises:
            ValueError: If run path digest is invalid; run path alignment is
                invalid; or absent run path cannot claim label alignment.
        """
        if self.path_sha256 is not None and not _valid_sha256(self.path_sha256):
            raise ValueError("Run path digest is invalid")
        if any(
            not _has_exact_type(value, str) or value not in _ALIGNMENTS
            for value in (
                self.version_alignment,
                self.level_alignment,
                self.profile_alignment,
            )
        ):
            raise ValueError("Run path alignment is invalid")
        if self.path_sha256 is None and any(
            value != "not_declared"
            for value in (
                self.version_alignment,
                self.level_alignment,
                self.profile_alignment,
            )
        ):
            raise ValueError("Absent run path cannot claim label alignment")

    def to_dict(self) -> dict[str, Any]:
        """
        Return a fresh JSON-compatible projection.

        The implementation uses current instance state to produce a fresh
        JSON-compatible projection.

        Returns:
            A mapping containing the ``path_sha256``, ``version_alignment``,
            ``level_alignment``, and ``profile_alignment`` fields.
        """

        return {
            "path_sha256": self.path_sha256,
            "version_alignment": self.version_alignment,
            "level_alignment": self.level_alignment,
            "profile_alignment": self.profile_alignment,
        }


@dataclass(frozen=True)
class RunIdentity:
    """
    Strict immutable identity derived after configuration and plan resolution.

    The immutable record keeps ``tool_version``, ``build_hash``,
    ``source_mode``, ``source_revision``, and ``build_timestamp_utc`` together
    so consumers observe one run identity state. Construction validates
    cross-field invariants before the instance is exposed.

    Attributes:
        tool_version: Canonical text used as tool version.
        build_hash: Canonical text used as build hash.
        source_mode: Canonical text used as source mode.
        source_revision: Canonical text used as source revision.
        build_timestamp_utc: Canonical text used as build timestamp utc.
        catalog_name: Canonical text used as catalog name.
        catalog_version: Canonical text used as catalog version.
        catalog_sha256: Lowercase SHA-256 digest binding the catalog content.
        catalog_size_bytes: Byte count recorded for catalog size.
        effective_config_sha256: Lowercase SHA-256 digest binding the effective
            config content.
        resolved_level: Canonical text used as resolved level.
        resolved_profile: Canonical text used as resolved profile.
        resolved_plan_sha256: Lowercase SHA-256 digest binding the resolved plan
            content.
        output_mode: Canonical text used as output mode.
        caller_relation: Canonical text used as caller relation.
        caller_path: Validated filesystem location associated with caller path.
        resolved_path: Validated filesystem location associated with resolved
            path.
        generated_path: Validated filesystem location associated with generated
            path.
        catalog_binding: Canonical text used as catalog binding.
        invocation_sha256: Lowercase SHA-256 digest binding the invocation
            content.
        identity_sha256: Lowercase SHA-256 digest binding the identity content.
    """

    tool_version: str
    build_hash: str
    source_mode: str
    source_revision: str
    build_timestamp_utc: str
    catalog_name: str
    catalog_version: str
    catalog_sha256: str
    catalog_size_bytes: int
    effective_config_sha256: str
    resolved_level: str
    resolved_profile: str
    resolved_plan_sha256: str
    output_mode: str
    caller_relation: str
    caller_path: RunPathIdentity
    resolved_path: RunPathIdentity
    generated_path: RunPathIdentity
    catalog_binding: str = "discovered"
    invocation_sha256: str = field(init=False)
    identity_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized RunIdentity state.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Raises:
            ValueError: If run identity tool version is invalid; run identity
                build hash is invalid; run identity source mode is invalid; or
                run identity source revision is invalid; or another input
                invariant is violated.
            TypeError: If the run identity path facts are not canonical.
        """
        if not _has_exact_type(self.tool_version, str) or not (
            self.tool_version == "unknown"
            or (
                len(self.tool_version.encode("ascii", errors="ignore")) <= 128
                and _SEMANTIC_VERSION.fullmatch(self.tool_version) is not None
            )
        ):
            raise ValueError("Run identity tool version is invalid")
        if (
            not _has_exact_type(self.build_hash, str)
            or _BUILD_HASH.fullmatch(self.build_hash) is None
        ):
            raise ValueError("Run identity build hash is invalid")
        if (
            not _has_exact_type(self.source_mode, str)
            or self.source_mode not in _SOURCE_MODES
        ):
            raise ValueError("Run identity source mode is invalid")
        if not _has_exact_type(self.source_revision, str) or not (
            self.source_revision == "unknown"
            or _SOURCE_REVISION.fullmatch(self.source_revision) is not None
        ):
            raise ValueError("Run identity source revision is invalid")
        if not _has_exact_type(self.build_timestamp_utc, str) or not (
            self.build_timestamp_utc == "unknown"
            or _BUILD_TIMESTAMP.fullmatch(self.build_timestamp_utc) is not None
        ):
            raise ValueError("Run identity build timestamp is invalid")
        if self.build_timestamp_utc != "unknown":
            try:
                datetime.strptime(self.build_timestamp_utc, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError as error:
                raise ValueError("Run identity build timestamp is invalid") from error

        catalog_match = (
            _CATALOG_NAME.fullmatch(self.catalog_name)
            if _has_exact_type(self.catalog_name, str)
            and len(self.catalog_name.encode("ascii", errors="ignore")) <= 128
            else None
        )
        if self.catalog_name == "unknown":
            if self.catalog_version != "unknown":
                raise ValueError("Run identity catalog name and version disagree")
        elif catalog_match is None or self.catalog_version != catalog_match.group(
            "version"
        ):
            raise ValueError("Run identity catalog name and version disagree")
        if not _valid_sha256(self.catalog_sha256):
            raise ValueError("Run identity catalog digest is invalid")
        if (
            not _has_exact_type(self.catalog_size_bytes, int)
            or self.catalog_size_bytes <= 0
            or self.catalog_size_bytes > MAX_CATALOG_SNAPSHOT_BYTES
        ):
            raise ValueError("Run identity catalog size is invalid")
        if self.catalog_binding not in {
            "manifest_bound",
            "operator_supplied",
            "discovered",
        }:
            raise ValueError("Run identity catalog binding is invalid")
        if not _valid_sha256(self.effective_config_sha256):
            raise ValueError("Run identity effective configuration digest is invalid")
        if (
            not _has_exact_type(self.resolved_level, str)
            or self.resolved_level not in _RESOLVED_LEVELS
        ):
            raise ValueError("Run identity resolved level is invalid")
        if (
            not _has_exact_type(self.resolved_profile, str)
            or self.resolved_profile not in _RESOLVED_PROFILES
        ):
            raise ValueError("Run identity resolved profile is invalid")
        if not _valid_sha256(self.resolved_plan_sha256):
            raise ValueError("Run identity resolved plan digest is invalid")
        if (
            not _has_exact_type(self.output_mode, str)
            or self.output_mode not in _OUTPUT_MODES
        ):
            raise ValueError("Run identity output mode is invalid")
        if (
            not _has_exact_type(self.caller_relation, str)
            or self.caller_relation not in _CALLER_RELATIONS
        ):
            raise ValueError("Run identity caller relation is invalid")
        for path_identity in (
            self.caller_path,
            self.resolved_path,
            self.generated_path,
        ):
            if type(path_identity) is not RunPathIdentity:
                raise TypeError("Run identity path facts must be canonical")
            try:
                reconstructed_path = RunPathIdentity(**path_identity.to_dict())
            except (AttributeError, TypeError, ValueError) as error:
                raise ValueError("Run identity path facts are inconsistent") from error
            if reconstructed_path != path_identity:
                raise ValueError("Run identity path facts are inconsistent")
        if self.resolved_path.path_sha256 is None:
            raise ValueError("Run identity resolved output path is missing")
        caller_required = self.output_mode != "configured_generated"
        if caller_required != (self.caller_path.path_sha256 is not None):
            raise ValueError("Run identity caller path contradicts output mode")
        if self.output_mode == "configured_generated":
            if self.caller_relation != "absent":
                raise ValueError("Configured output cannot claim a caller relation")
        elif self.output_mode == "caller_based_generated":
            if self.caller_relation != "descendant":
                raise ValueError("Generated caller output must be a descendant")
        elif self.caller_relation not in {"same", "descendant"}:
            raise ValueError("Append output has an invalid caller relation")
        if self.caller_relation == "same" and (
            self.caller_path.path_sha256 != self.resolved_path.path_sha256
        ):
            raise ValueError("Same caller relation contradicts output paths")
        if self.caller_relation == "descendant" and (
            self.caller_path.path_sha256 == self.resolved_path.path_sha256
        ):
            raise ValueError("Descendant caller relation contradicts output paths")
        if self.output_mode == "caller_supplied_append":
            if self.generated_path.path_sha256 is not None:
                raise ValueError("Append output cannot claim a generated path")
        elif (
            self.generated_path.path_sha256 is None
            or self.generated_path.path_sha256 != self.resolved_path.path_sha256
        ):
            raise ValueError("Generated output must equal its resolved path")

        invocation_sha256 = hashlib.sha256(
            _canonical_bytes(
                self._document(
                    include_invocation_digest=False,
                    include_identity_digest=False,
                )
            )
        ).hexdigest()
        object.__setattr__(self, "invocation_sha256", invocation_sha256)
        identity_sha256 = hashlib.sha256(
            _canonical_bytes(self._document(include_identity_digest=False))
        ).hexdigest()
        object.__setattr__(self, "identity_sha256", identity_sha256)

    def _document(
        self,
        *,
        include_invocation_digest: bool = True,
        include_identity_digest: bool = True,
    ) -> dict[str, Any]:
        """
        Return the document.

        The implementation uses ``include_invocation_digest`` and
        ``include_identity_digest`` to produce the document.

        Args:
            include_invocation_digest: Whether include invocation digest is
                enabled or required for this operation.
            include_identity_digest: Whether include identity digest is enabled
                or required for this operation.

        Returns:
            The validated ``document``.
        """
        invocation = {
            "resolved_level": self.resolved_level,
            "resolved_profile": self.resolved_profile,
            "resolved_plan_sha256": self.resolved_plan_sha256,
        }
        if include_invocation_digest:
            invocation["invocation_sha256"] = self.invocation_sha256
        document: dict[str, Any] = {
            "schema_version": RUN_IDENTITY_SCHEMA_VERSION,
            "tool": {
                "version": self.tool_version,
                "build_hash": self.build_hash,
                "source_mode": self.source_mode,
                "source_revision": self.source_revision,
                "build_timestamp_utc": self.build_timestamp_utc,
            },
            "catalog": {
                "name": self.catalog_name,
                "version": self.catalog_version,
                "sha256": self.catalog_sha256,
                "size_bytes": self.catalog_size_bytes,
                "binding": self.catalog_binding,
            },
            "effective_config_sha256": self.effective_config_sha256,
            "invocation": invocation,
            "output": {
                "mode": self.output_mode,
                "caller_relation": self.caller_relation,
                "caller_path": self.caller_path.to_dict(),
                "resolved_path": self.resolved_path.to_dict(),
                "generated_path": self.generated_path.to_dict(),
            },
        }
        if include_identity_digest:
            document["identity_sha256"] = self.identity_sha256
        return document

    def to_dict(self) -> dict[str, Any]:
        """
        Return a detached canonical document containing both checked hashes.

        After applying local validation, the function forwards current instance
        state to ``self._document`` and preserves its return and exception
        contract.

        Returns:
            A mapping containing dictionary.
        """

        return self._document()


def validate_run_identity_document(document: Mapping[str, Any]) -> RunIdentity:
    """
    Reconstruct a strict identity at an untrusted JSON boundary.

    The implementation uses ``document`` to reconstruct a strict identity at an
    untrusted JSON boundary. If the function cannot reconstruct a strict
    identity at an untrusted JSON boundary, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        document: Mapping supplying fields for reconstruct a strict identity at
            an untrusted JSON boundary.

    Returns:
        The validated ``identity``.

    Raises:
        ValueError: If run identity document has unexpected fields; unsupported
            run identity schema; run identity tool facts are malformed; or run
            identity catalog facts are malformed; or another input invariant is
            violated.
    """

    if type(document) is not dict or set(  # noqa: E721 - subclasses are rejected
        document
    ) != {  # noqa: E721 - subclasses are rejected
        "schema_version",
        "tool",
        "catalog",
        "effective_config_sha256",
        "invocation",
        "output",
        "identity_sha256",
    }:
        raise ValueError("Run identity document has unexpected fields")
    if document["schema_version"] != RUN_IDENTITY_SCHEMA_VERSION:
        raise ValueError("Unsupported run identity schema")
    tool = document["tool"]
    catalog = document["catalog"]
    invocation = document["invocation"]
    output = document["output"]
    if type(tool) is not dict or set(tool) != {  # noqa: E721 - subclasses are rejected
        "version",
        "build_hash",
        "source_mode",
        "source_revision",
        "build_timestamp_utc",
    }:
        raise ValueError("Run identity tool facts are malformed")
    if type(catalog) is not dict or set(  # noqa: E721 - subclasses are rejected
        catalog
    ) != {  # noqa: E721 - subclasses are rejected
        "name",
        "version",
        "sha256",
        "size_bytes",
        "binding",
    }:
        raise ValueError("Run identity catalog facts are malformed")
    if type(invocation) is not dict or set(  # noqa: E721 - subclasses are rejected
        invocation
    ) != {  # noqa: E721 - subclasses are rejected
        "resolved_level",
        "resolved_profile",
        "resolved_plan_sha256",
        "invocation_sha256",
    }:
        raise ValueError("Run identity invocation facts are malformed")
    if type(output) is not dict or set(  # noqa: E721 - subclasses are rejected
        output
    ) != {  # noqa: E721 - subclasses are rejected
        "mode",
        "caller_relation",
        "caller_path",
        "resolved_path",
        "generated_path",
    }:
        raise ValueError("Run identity output facts are malformed")

    def path_identity(value: object) -> RunPathIdentity:
        """
        Return the path identity.

        After applying local validation, the function forwards ``value`` to
        ``RunPathIdentity`` and preserves its return and exception contract.

        Args:
            value: Value evaluated while performing path identity.

        Returns:
            The validated path identity filesystem path.

        Raises:
            ValueError: If run identity path facts are malformed.
        """
        if type(value) is not dict or set(  # noqa: E721 - subclasses are rejected
            value
        ) != {  # noqa: E721 - subclasses are rejected
            "path_sha256",
            "version_alignment",
            "level_alignment",
            "profile_alignment",
        }:
            raise ValueError("Run identity path facts are malformed")
        return RunPathIdentity(**value)

    identity = RunIdentity(
        tool_version=tool["version"],
        build_hash=tool["build_hash"],
        source_mode=tool["source_mode"],
        source_revision=tool["source_revision"],
        build_timestamp_utc=tool["build_timestamp_utc"],
        catalog_name=catalog["name"],
        catalog_version=catalog["version"],
        catalog_sha256=catalog["sha256"],
        catalog_size_bytes=catalog["size_bytes"],
        catalog_binding=catalog["binding"],
        effective_config_sha256=document["effective_config_sha256"],
        resolved_level=invocation["resolved_level"],
        resolved_profile=invocation["resolved_profile"],
        resolved_plan_sha256=invocation["resolved_plan_sha256"],
        output_mode=output["mode"],
        caller_relation=output["caller_relation"],
        caller_path=path_identity(output["caller_path"]),
        resolved_path=path_identity(output["resolved_path"]),
        generated_path=path_identity(output["generated_path"]),
    )
    if not _valid_sha256(invocation["invocation_sha256"]) or not hmac.compare_digest(
        identity.invocation_sha256,
        invocation["invocation_sha256"],
    ):
        raise ValueError("Run identity invocation digest is inconsistent")
    if not _valid_sha256(document["identity_sha256"]) or not hmac.compare_digest(
        identity.identity_sha256,
        document["identity_sha256"],
    ):
        raise ValueError("Run identity digest is inconsistent")
    if identity.to_dict() != document:
        raise ValueError("Run identity document is noncanonical")
    return identity


def validate_sealed_run_identity(value: object) -> RunIdentity:
    """
    Return a reconstructed identity or reject an unsealed/forged owner.

    The implementation uses ``value`` to produce a reconstructed identity or
    reject an unsealed/forged owner. If the function cannot produce a
    reconstructed identity or reject an unsealed/forged owner, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        value: Value object whose ``to_dict`` state is read while performing
            reconstructed identity or reject an unsealed/forged owner.

    Returns:
        The validated ``validated``.

    Raises:
        TypeError: If a sealed RunIdentity is required.
        ValueError: If sealed RunIdentity is inconsistent.
    """

    if type(value) is not RunIdentity:
        raise TypeError("A sealed RunIdentity is required")
    try:
        validated = validate_run_identity_document(value.to_dict())
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("Sealed RunIdentity is inconsistent") from error
    if validated != value:
        raise ValueError("Sealed RunIdentity is inconsistent")
    return validated
