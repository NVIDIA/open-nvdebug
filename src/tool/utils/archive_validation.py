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
Shared schema and identity helpers for Redfish archive receipts.

This module owns the archive validation boundary and exposes
``archive_validation_is_sha256``, ``archive_validation_path_sha256``,
``archive_validation_receipt_id``, and ``archive_validation_load_json``. Keeping
those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

ARCHIVE_VALIDATION_SCHEMA = "open-nvdebug.archive-validation/v1"
ARCHIVE_VALIDATION_PRODUCER = "tool.services.redfish_service"
ARCHIVE_VALIDATION_PRIMARY_ROLE = "primary"
ARCHIVE_VALIDATION_REFERENCE_ROLE = "reference"
ARCHIVE_VALIDATION_SUPPORTED_SUFFIXES = (
    ".tar.gz",
    ".tgz",
    ".tar.xz",
    ".txz",
    ".tar.bz2",
    ".tbz2",
    ".tar.zst",
    ".tar",
    ".zip",
)


def archive_validation_is_sha256(value: Any) -> bool:
    """
    Return whether ``value`` is one canonical lowercase SHA-256 digest.

    The implementation uses ``value`` to determine whether ``value`` is one
    canonical lowercase SHA-256 digest.

    Args:
        value: Value evaluated while performing ``value`` is one canonical
            lowercase SHA-256 digest.

    Returns:
        Whether ``value`` is one canonical lowercase SHA-256 digest.
    """

    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def archive_validation_path_sha256(path: str) -> str:
    """
    Return a stable filename hash for one collector-relative artifact path.

    After applying local validation, the function forwards ``path`` to
    ``hexdigest`` and preserves its return and exception contract.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        The canonical archive validation path SHA-256 text.
    """

    return hashlib.sha256(path.encode("utf-8", errors="strict")).hexdigest()


def archive_validation_receipt_id(validation: dict[str, Any]) -> str:
    """
    Build the stable ID shared by one primary receipt and its references.

    After applying local validation, the function forwards ``validation`` to
    ``hexdigest`` and preserves its return and exception contract.

    Args:
        validation: Mapping supplying fields for stable ID shared by one primary
            receipt and its references.

    Returns:
        The canonical archive validation receipt identifier text.
    """

    prior_size = validation.get("pre_sanitization_saved_size")
    prior_sha256 = validation.get("pre_sanitization_saved_sha256")
    producer_saved_size = (
        prior_size if type(prior_size) is int else validation.get("saved_size")
    )
    producer_saved_sha256 = (
        prior_sha256
        if isinstance(prior_sha256, str)
        else validation.get("saved_sha256")
    )
    identity = {
        "schema": validation.get("schema"),
        "producer": validation.get("producer"),
        "receipt_role": validation.get("receipt_role"),
        "artifact_path_sha256": validation.get("artifact_path_sha256"),
        "requested_filename_sha256": validation.get("requested_filename_sha256"),
        "status": validation.get("status"),
        "normalization": validation.get("normalization"),
        "original_size": validation.get("original_size"),
        "original_sha256": validation.get("original_sha256"),
        "producer_saved_size": producer_saved_size,
        "producer_saved_sha256": producer_saved_sha256,
    }
    encoded = json.dumps(
        identity, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def archive_validation_load_json(data: bytes) -> Any:
    """
    Load receipt evidence while rejecting ambiguous duplicate object keys.

    After applying local validation, the function forwards ``data`` to
    ``json.loads`` and preserves its return and exception contract. Parsing or
    I/O must finish before the validated representation is made available to the
    caller.

    Args:
        data: Bounded byte sequence supplied as data.

    Returns:
        The archive validation load JSON value selected by the operation.
    """

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """
        Reject duplicate keys.

        The implementation uses ``pairs`` to reject duplicate keys. Every
        required invariant is checked before a successful value is returned;
        invalid input follows the function's explicit exception path.

        Args:
            pairs: Entries supplied as ``pairs`` without transferring container
                ownership.

        Returns:
            The validated ``document``.

        Raises:
            ValueError: If duplicate JSON key in archive evidence: ``key``.
        """
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError(f"duplicate JSON key in archive evidence: {key}")
            document[key] = value
        return document

    return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
