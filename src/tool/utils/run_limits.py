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
Supported topology and identity bounds for one collection run.

This module owns the run limits boundary and exposes ``is_printable_identity``.
Keeping those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

from typing import Any

MAX_DUTS = 500
MAX_COLLECTORS_PER_RUN = 512
MAX_TRACKED_COLLECTOR_RECORDS = 100_000
MAX_DUT_ID_BYTES = 255
MAX_COLLECTOR_ID_BYTES = 512
MAX_SNAPSHOT_ROOT_ENTRIES = 4_096
MAX_SNAPSHOT_CANDIDATE_ENTRIES = 8_192
# Root validation performs metadata reads as well as enumeration. This is the
# minimum scan budget; larger validated rosters receive one second per DUT plus
# the root. Entry and artifact-size limits independently bound untrusted input.
SNAPSHOT_DIRECTORY_SCAN_DEADLINE_SECONDS = 60.0

# Shipped catalogs contain fewer than 150 collector rows. These structural
# ceilings leave substantial authoring headroom while preventing a compressed
# workbook from materializing an unbounded table in the runtime process.
MAX_CATALOG_SHEET_ROWS = 10_000
MAX_CATALOG_SHEET_CELLS = 1_000_000


def snapshot_directory_scan_budget_seconds(dut_count: int) -> float:
    """
    Size a finite root metadata scan budget for the validated run topology.

    NFS may require a remote metadata read for every DUT directory. Allow one
    second per DUT and one for root overhead, retaining the existing minimum
    for small runs. The budget derives from the validated roster, never from
    arbitrary entries encountered while scanning, and cannot exceed 501 seconds.

    Args:
        dut_count: Number of DUTs in the already validated snapshot roster.

    Returns:
        Seconds available to one complete root scan without per-entry resets.

    Raises:
        ValueError: If the count is not an integer within the supported topology.
    """

    if type(dut_count) is not int or not 0 <= dut_count <= MAX_DUTS:
        raise ValueError("Snapshot DUT count is outside the supported topology")
    return max(SNAPSHOT_DIRECTORY_SCAN_DEADLINE_SECONDS, float(dut_count + 1))


def is_printable_identity(value: Any, *, maximum_bytes: int) -> bool:
    """
    Return whether an identity is printable and bounded when UTF-8 encoded.

    The implementation uses ``value`` and ``maximum_bytes`` to determine whether
    an identity is printable and bounded when UTF-8 encoded.

    Args:
        value: Value object whose ``encode`` and ``isprintable`` state is read
            while performing identity is printable and bounded when UTF-8
            encoded.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        Whether an identity is printable and bounded when UTF-8 encoded.
    """

    if not isinstance(value, str) or not value or not value.isprintable():
        return False
    try:
        return len(value.encode("utf-8")) <= maximum_bytes
    except UnicodeError:
        return False
