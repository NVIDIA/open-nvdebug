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
ID filtering utilities for open-nvdebugtool.

This module provides utilities for filtering system IDs, chassis IDs, and
manager IDs based on configuration settings.
"""

import re
from typing import Any, Dict, List, Optional


def should_skip_id(id_value: str, id_type: str, dut_config: Dict[str, Any]) -> bool:
    """
    Check if an ID should be skipped based on DUT configuration.

    The implementation uses ``id_value``, ``id_type``, and ``dut_config`` to
    check if an ID should be skipped based on DUT configuration. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        id_value: Text supplied as identifier value in the format accepted by
            this function.
        id_type: Text supplied as identifier type in the format accepted by this
            function.
        dut_config: DUT config governing if an ID should be skipped based on DUT
            configuration.

    Returns:
        Whether any configured case-sensitive regular expression fully matches
        the supplied Redfish identifier.

    Raises:
        ValueError: If a configured skip entry is not a valid regular
            expression.
    """
    if not dut_config:
        return False

    # Map ID types to configuration keys
    skip_key_mapping = {
        "system": "SYSTEM_ID_TO_SKIP",
        "chassis": "CHASSIS_ID_TO_SKIP",
        "manager": "MANAGER_ID_TO_SKIP",
    }

    skip_key = skip_key_mapping.get(id_type.lower())
    if not skip_key:
        return False

    skip_list = dut_config.get(skip_key, [])
    if not skip_list:
        return False

    for pattern in skip_list:
        try:
            if re.fullmatch(pattern, id_value) is not None:
                return True
        except (re.error, TypeError) as error:
            raise ValueError(
                f"{skip_key} contains an invalid regular expression: {pattern!r}"
            ) from error
    return False


def filter_ids(ids: List[str], id_type: str, dut_config: Dict[str, Any]) -> List[str]:
    """
    Filter a list of IDs based on DUT configuration.

    The implementation uses ``ids``, ``id_type``, and ``dut_config`` to filter a
    list of IDs based on DUT configuration.

    Args:
        ids: Entries supplied as ``ids`` without transferring container
            ownership.
        id_type: Text supplied as identifier type in the format accepted by this
            function.
        dut_config: DUT config governing filter a list of IDs based on DUT
            configuration.

    Returns:
        The filter identifiers returned in operation-defined order.
    """
    if not ids or not dut_config:
        return ids

    filtered_ids = []
    for id_value in ids:
        if not should_skip_id(id_value, id_type, dut_config):
            filtered_ids.append(id_value)

    return filtered_ids


def get_skip_reason(
    id_value: str, id_type: str, dut_config: Dict[str, Any]
) -> Optional[str]:
    """
    Get the reason why an ID was skipped.

    The implementation uses ``id_value``, ``id_type``, and ``dut_config`` to get
    the reason why an ID was skipped.

    Args:
        id_value: Text supplied as identifier value in the format accepted by
            this function.
        id_type: Text supplied as identifier type in the format accepted by this
            function.
        dut_config: DUT config governing get the reason why an ID was skipped.

    Returns:
        The canonical skip reason text, or ``None`` when the requested value is
        unavailable.
    """
    if should_skip_id(id_value, id_type, dut_config):
        skip_key_mapping = {
            "system": "SYSTEM_ID_TO_SKIP",
            "chassis": "CHASSIS_ID_TO_SKIP",
            "manager": "MANAGER_ID_TO_SKIP",
        }
        skip_key = skip_key_mapping.get(id_type.lower())
        return f"{id_value} skipped due to {skip_key} configuration"

    return None


async def log_filtered_ids(
    original_ids: List[str],
    filtered_ids: List[str],
    id_type: str,
    logger,
    dut_id: Optional[str] = None,
) -> None:
    """
    Log information about filtered IDs.

    The implementation uses ``original_ids``, ``filtered_ids``, ``id_type``,
    ``logger``, and ``dut_id`` to log information about filtered IDs. Owned
    asynchronous work is awaited before return, so completion does not leave an
    unobserved task behind.

    Args:
        original_ids: Entries supplied as ``original_ids`` without transferring
            container ownership.
        filtered_ids: Entries supplied as ``filtered_ids`` without transferring
            container ownership.
        id_type: Text supplied as identifier type in the format accepted by this
            function.
        logger: Sanitized logger used for operator-visible diagnostics.
        dut_id: Stable DUT identifier used to correlate configuration, logs, and
            results.
    """
    if not logger:
        return

    skipped_count = len(original_ids) - len(filtered_ids)
    if skipped_count > 0:
        skipped_ids = [id_val for id_val in original_ids if id_val not in filtered_ids]
        message = f"Filtered {skipped_count} {id_type} IDs: {skipped_ids}"
        if dut_id:
            await logger.log_runtime("INFO", "IDFiltering", message, dut_id)
        else:
            await logger.log_runtime("INFO", "IDFiltering", message)
