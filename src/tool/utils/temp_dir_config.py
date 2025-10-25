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
Temporary directory configuration utilities for open-nvdebugtool.

This module provides utilities for handling temporary directory configuration
and creation based on tool and DUT configuration.
"""

import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Union


def get_tool_temp_dir(
    tool_config: Dict[str, Any], default_temp_dir: str = "/tmp"
) -> str:
    """
    Get the tool temporary directory from configuration.

    Args:
        tool_config: Tool configuration dictionary
        default_temp_dir: Default temporary directory if not configured

    Returns:
        str: The tool temporary directory path
    """
    if not tool_config:
        return default_temp_dir

    tool_temp_dir = tool_config.get("TOOL_TEMP_DIR")
    if tool_temp_dir and isinstance(tool_temp_dir, str):
        return tool_temp_dir

    return default_temp_dir


def get_bmc_temp_dir(dut_config: Dict[str, Any], default_temp_dir: str = "/tmp") -> str:
    """
    Get the BMC temporary directory from DUT configuration.

    Args:
        dut_config: DUT configuration dictionary
        default_temp_dir: Default temporary directory if not configured

    Returns:
        str: The BMC temporary directory path
    """
    if not dut_config:
        return default_temp_dir

    bmc_temp_dir = dut_config.get("BMC_TEMP_DIR")
    if bmc_temp_dir and isinstance(bmc_temp_dir, str):
        return bmc_temp_dir

    return default_temp_dir


def create_temp_directory(
    base_dir: str,
    prefix: str = "nvdebug_",
    suffix: str = "",
    create_parents: bool = True,
) -> str:
    """
    Create a temporary directory with the specified configuration.

    Args:
        base_dir: Base directory for temporary directory creation
        prefix: Prefix for the temporary directory name
        suffix: Suffix for the temporary directory name
        create_parents: Whether to create parent directories if they don't exist

    Returns:
        str: Path to the created temporary directory

    Raises:
        OSError: If directory creation fails
    """
    # Ensure base directory exists
    base_path = Path(base_dir)
    if create_parents:
        base_path.mkdir(parents=True, exist_ok=True)
    elif not base_path.exists():
        raise OSError(f"Base directory does not exist: {base_dir}")

    # Create temporary directory
    temp_dir = tempfile.mkdtemp(prefix=prefix, suffix=suffix, dir=str(base_path))

    return temp_dir


def get_task_id_prefix(tool_config: Dict[str, Any], default_prefix: str = "") -> str:
    """
    Get the task ID prefix from tool configuration.

    Args:
        tool_config: Tool configuration dictionary
        default_prefix: Default prefix if not configured

    Returns:
        str: The task ID prefix
    """
    if not tool_config:
        return default_prefix

    task_prefix = tool_config.get("TASK_ID_PREFIX")
    if task_prefix and isinstance(task_prefix, str):
        return task_prefix

    return default_prefix


def create_task_temp_dir(
    tool_config: Dict[str, Any],
    task_id: Optional[str] = None,
    prefix: str = "nvdebug_",
    suffix: str = "",
) -> str:
    """
    Create a temporary directory for a specific task.

    Args:
        tool_config: Tool configuration dictionary
        task_id: Optional task ID to include in directory name
        prefix: Prefix for the temporary directory name
        suffix: Suffix for the temporary directory name

    Returns:
        str: Path to the created temporary directory
    """
    # Get tool temp directory
    tool_temp_dir = get_tool_temp_dir(tool_config)

    # Get task ID prefix
    task_prefix = get_task_id_prefix(tool_config)

    # Build directory name
    dir_name = prefix
    if task_prefix:
        dir_name += f"{task_prefix}_"
    if task_id:
        dir_name += f"{task_id}_"
    dir_name += suffix if suffix else "temp"

    # Create temporary directory
    return create_temp_directory(
        base_dir=tool_temp_dir, prefix=dir_name, create_parents=True
    )


def cleanup_temp_directory(temp_dir: str, logger=None) -> bool:
    """
    Clean up a temporary directory.

    Args:
        temp_dir: Path to the temporary directory to clean up
        logger: Optional logger for error reporting

    Returns:
        bool: True if cleanup was successful, False otherwise
    """
    try:
        import shutil

        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            if logger:
                logger.log_runtime(
                    "DEBUG",
                    "TempDirConfig",
                    f"Cleaned up temporary directory: {temp_dir}",
                )
            return True
    except Exception as e:
        if logger:
            logger.log_runtime(
                "WARNING",
                "TempDirConfig",
                f"Failed to clean up temporary directory {temp_dir}: {e}",
            )
        return False

    return True


def get_temp_file_path(
    base_dir: str, filename: str, create_parents: bool = True
) -> str:
    """
    Get a temporary file path within the specified base directory.

    Args:
        base_dir: Base directory for the temporary file
        filename: Name of the temporary file
        create_parents: Whether to create parent directories if they don't exist

    Returns:
        str: Full path to the temporary file
    """
    base_path = Path(base_dir)
    if create_parents:
        base_path.mkdir(parents=True, exist_ok=True)

    return str(base_path / filename)
