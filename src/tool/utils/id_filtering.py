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

This module provides utilities for filtering system IDs, chassis IDs, and manager IDs
based on configuration settings.
"""

from typing import Any, Dict, List, Optional


def should_skip_id(id_value: str, id_type: str, dut_config: Dict[str, Any]) -> bool:
    """
    Check if an ID should be skipped based on DUT configuration.

    Args:
        id_value: The ID value to check (e.g., "System_1", "Chassis_2")
        id_type: The type of ID ("system", "chassis", "manager")
        dut_config: DUT configuration dictionary

    Returns:
        bool: True if the ID should be skipped
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

    # Check if the ID is in the skip list
    return id_value in skip_list


def filter_ids(ids: List[str], id_type: str, dut_config: Dict[str, Any]) -> List[str]:
    """
    Filter a list of IDs based on DUT configuration.

    Args:
        ids: List of ID values to filter
        id_type: The type of IDs ("system", "chassis", "manager")
        dut_config: DUT configuration dictionary

    Returns:
        List[str]: Filtered list of IDs
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

    Args:
        id_value: The ID value that was skipped
        id_type: The type of ID ("system", "chassis", "manager")
        dut_config: DUT configuration dictionary

    Returns:
        Optional[str]: Reason for skipping, or None if not skipped
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


def log_filtered_ids(
    original_ids: List[str],
    filtered_ids: List[str],
    id_type: str,
    logger=None,
    dut_id: str = None,
) -> None:
    """
    Log information about filtered IDs.

    Args:
        original_ids: Original list of IDs
        filtered_ids: Filtered list of IDs
        id_type: Type of IDs being filtered
        logger: Logger instance (optional)
        dut_id: DUT ID for logging context (optional)
    """
    if not logger:
        return

    skipped_count = len(original_ids) - len(filtered_ids)
    if skipped_count > 0:
        skipped_ids = [id_val for id_val in original_ids if id_val not in filtered_ids]
        message = f"Filtered {skipped_count} {id_type} IDs: {skipped_ids}"
        if dut_id:
            logger.log_runtime("INFO", "IDFiltering", message, dut_id)
        else:
            logger.log_runtime("INFO", "IDFiltering", message)
