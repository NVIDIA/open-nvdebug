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
Logging utilities for NVDebug Tool.

This module provides the timestamped log directory creation used during
tool startup.
"""

from datetime import datetime
from pathlib import Path


def create_timestamped_log_dir(base_folder: str) -> str:
    """
    Create a timestamped directory to store all results.

    Args:
        base_folder (str): Base directory where logs will be stored.

    Returns:
        str: Path to the created directory.

    Raises:
        IOError: If directory creation fails after multiple attempts.
    """
    try:
        now = datetime.now()
        dt_string = now.strftime("%d_%m_%Y_%H_%M_%S")
        base_folder_name = "/nvdebug_logs_" + dt_string
        base_new_dir = base_folder + base_folder_name
        new_dir = base_new_dir

        for retry in range(100):
            try:
                Path(new_dir).mkdir(parents=True, exist_ok=False)
                break
            except FileExistsError:
                new_dir = f"{base_new_dir}_{retry}"
        else:
            raise IOError("Could not create log folder")

        return new_dir
    except Exception as e:
        print(f"Error creating directory: {str(e)}")
        raise
