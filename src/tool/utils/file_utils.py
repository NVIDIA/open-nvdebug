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
File and directory utility functions for the NVDebug Tool.

Provides utilities for file system operations including directory management,
empty directory cleanup, and collector file organization.
"""

import os
import shutil
from typing import List

from .enums import CollectorServiceMapping


def is_directory_empty(directory: str) -> bool:
    """
    Check if a directory is empty or only contains empty subdirectories.

    Args:
        directory (str): Path to directory.

    Returns:
        bool: True if directory is empty, False otherwise.
    """
    try:
        if not os.path.exists(directory):
            return True

        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            if os.path.isfile(item_path):
                # If there's any file, directory is not empty
                return False
            elif os.path.isdir(item_path):
                # Recursively check subdirectories
                if not is_directory_empty(item_path):
                    return False

        return True
    except Exception:
        return False


def cleanup_empty_directories(base_dir: str, dut_ids: List[str]) -> List[str]:
    """
    Remove empty collector group directories and error-logs if no content.
    Also removes empty DUT directories if they become empty after cleanup.

    Args:
        base_dir: Base log directory
        dut_ids: List of DUT IDs to check

    Returns:
        List of removed directory paths
    """
    removed_dirs = []

    try:
        # For each DUT directory
        for dut_id in dut_ids:
            dut_dir = os.path.join(base_dir, dut_id)
            if not os.path.exists(dut_dir):
                continue

            # Check collector group directories
            collector_groups = [
                "redfish",
                "ipmi",
                "ssh",
                "host",
                "health_check",
            ]
            for group in collector_groups:
                group_dir = os.path.join(dut_dir, group)
                if os.path.exists(group_dir):
                    # Check if directory is empty or only contains empty subdirectories
                    if is_directory_empty(group_dir):
                        shutil.rmtree(group_dir)
                        removed_dirs.append(group_dir)

            # Check error-logs directory
            error_logs_dir = os.path.join(dut_dir, "error-logs")
            if os.path.exists(error_logs_dir):
                if is_directory_empty(error_logs_dir):
                    shutil.rmtree(error_logs_dir)
                    removed_dirs.append(error_logs_dir)

            # After removing empty subdirectories, check if the DUT directory itself is empty
            # Note: We don't remove .metadata directory as it contains important metadata files
            # We also don't remove runtime files like nvdebug_runtime_output.txt, config.json, etc.
            if is_directory_empty(dut_dir):
                shutil.rmtree(dut_dir)
                removed_dirs.append(dut_dir)

    except Exception as e:
        # Log error but don't fail
        print(f"Warning: Error during directory cleanup: {e}")

    return removed_dirs


def ensure_directory_exists(directory: str) -> None:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        directory (str): Path to directory.
    """
    os.makedirs(directory, exist_ok=True)


def get_collector_group_from_id(collector_id: str) -> str:
    """
    Get collector group from ID.

    Args:
        collector_id (str): Collector ID.

    Returns:
        str: Collector group.
    """
    return CollectorServiceMapping.get_service_from_collector_id(collector_id)
