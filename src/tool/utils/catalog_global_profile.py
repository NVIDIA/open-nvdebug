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
Strict loading for versioned JSON profiles in the Telemetry Catalog.

This module owns the catalog global profile boundary and exposes
``CatalogGlobalProfileError``, ``_reject_nonfinite_json_constant``,
``_object_without_duplicate_keys``, and ``load_catalog_global_profile``. Keeping
those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from . import excel_reader
from .catalog_snapshot import CatalogSnapshot
from .spreadsheet_utils import decode_long_cell


class CatalogGlobalProfileError(ValueError):
    """
    Raised when an authoritative catalog-global profile cannot be loaded.

    Callers receive this exception when the catalog global profile error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


def _reject_nonfinite_json_constant(value: str) -> None:
    """
    Reject JavaScript-style constants that are not valid JSON numbers.

    The implementation uses ``value`` to reject JavaScript-style constants that
    are not valid JSON numbers. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Raises:
        ValueError: If non-finite JSON constant: ``value``.
    """

    raise ValueError(f"non-finite JSON constant: {value}")


def _object_without_duplicate_keys(
    pairs: List[Tuple[str, Any]],
) -> Dict[str, Any]:
    """
    Return the object without duplicate keys.

    The implementation uses ``pairs`` to produce the object without duplicate
    keys. If the function cannot produce the object without duplicate keys, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        pairs: Entries supplied as ``pairs`` without transferring container
            ownership.

    Returns:
        The validated ``result``.

    Raises:
        ValueError: If duplicate JSON key: ``key``.
    """
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_catalog_global_profile(
    spreadsheet_path: str | Path | CatalogSnapshot,
    profile_key: str,
    validator: Callable[..., Mapping[str, Any]],
    *,
    validator_kwargs: Optional[Dict[str, Any]] = None,
    required: bool = True,
) -> Optional[Dict[str, Any]]:
    """
    Load one exact ``Global Constants`` JSON row and validate it.

    A row that resembles ``profile_key`` after trimming/case folding is treated
    as an attempted profile row and must use the canonical section and spelling.
    This prevents a typo from silently selecting a second runtime authority.

    Args:
        spreadsheet_path: filesystem location used as the spreadsheet path for
            this operation.
        profile_key: Stable profile key used for lookup and operator-facing
            diagnostics.
        validator: Mapping supplying fields for one exact ``Global Constants``
            JSON row and validate it.
        validator_kwargs: Optional validator kwargs; ``None`` selects the
            function's default behavior.
        required: Whether required is enabled or required for this operation.

    Returns:
        A mapping containing catalog global profile, or ``None`` when the
        requested value is unavailable.

    Raises:
        CatalogGlobalProfileError: If unable to load ``profile_key`` from
            catalog '``catalog_label``': file does not exist; unable to read
            ``profile_key`` from catalog '``catalog_label``'; the function
            cannot load one exact ``Global Constants`` JSON row and validate it
            safely; or catalog '``catalog_label``' contains a malformed
            ``profile_key`` row; or another input invariant is violated.
    """

    catalog = (
        None
        if isinstance(spreadsheet_path, CatalogSnapshot)
        else Path(spreadsheet_path)
    )
    catalog_label = (
        spreadsheet_path.facts.catalog_name
        if isinstance(spreadsheet_path, CatalogSnapshot)
        else str(catalog)
    )
    if catalog is not None and not catalog.exists():
        raise CatalogGlobalProfileError(
            f"Unable to load {profile_key} from catalog '{catalog_label}': "
            "file does not exist"
        )

    try:
        if isinstance(spreadsheet_path, CatalogSnapshot):
            sheet = spreadsheet_path.read_excel("Log Collection Configuration")
        else:
            sheet = excel_reader.read_excel(
                catalog, sheet_name="Log Collection Configuration"
            )
    except Exception as error:
        if isinstance(error, ValueError) and "has duplicate columns:" in str(error):
            raise CatalogGlobalProfileError(
                f"Catalog '{catalog_label}' must contain exactly one of each "
                "required Log Collection Configuration column: Section, "
                "Configuration Item, Value"
            ) from error
        raise CatalogGlobalProfileError(
            f"Unable to read {profile_key} from catalog '{catalog_label}'"
        ) from error

    required_columns = ("Section", "Configuration Item", "Value")
    malformed_columns = [
        column for column in required_columns if sheet.columns.count(column) != 1
    ]
    if malformed_columns:
        raise CatalogGlobalProfileError(
            f"Catalog '{catalog_label}' must contain exactly one of each required "
            "Log Collection Configuration column: " + ", ".join(required_columns)
        )

    matching_rows = []
    canonical_identity = profile_key.casefold()
    for _, row in sheet.iterrows():
        raw_section = row.get("Section", "")
        raw_field_name = row.get("Configuration Item", "")
        normalized_field_name = str(raw_field_name).strip().casefold()
        if normalized_field_name != canonical_identity:
            continue
        if raw_section != "Global Constants" or raw_field_name != profile_key:
            raise CatalogGlobalProfileError(
                f"Catalog '{catalog_label}' contains a malformed {profile_key} row"
            )
        matching_rows.append(row)

    if not matching_rows:
        if required:
            raise CatalogGlobalProfileError(
                f"Catalog '{catalog_label}' is missing required {profile_key}"
            )
        return None
    if len(matching_rows) != 1:
        raise CatalogGlobalProfileError(
            f"Catalog '{catalog_label}' contains duplicate {profile_key} rows"
        )

    raw_value = matching_rows[0].get("Value", "")
    if (
        not excel_reader.notna(raw_value)
        or not isinstance(raw_value, str)
        or not raw_value.strip()
    ):
        raise CatalogGlobalProfileError(
            f"Catalog '{catalog_label}' contains a blank {profile_key} row"
        )

    try:
        decoded = decode_long_cell(raw_value)
        parsed = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_nonfinite_json_constant,
        )
        normalized = validator(parsed, **(validator_kwargs or {}))
    except Exception as error:
        raise CatalogGlobalProfileError(
            f"Catalog '{catalog_label}' contains an invalid {profile_key}: {error}"
        ) from error

    return dict(normalized)
