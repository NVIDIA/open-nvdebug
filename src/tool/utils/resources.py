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
Resource and configuration file discovery utilities.

Provides functions to automatically locate configuration files and resource
directories using multiple search strategies for different deployment scenarios.
"""

import os
import sys
from pathlib import Path
from typing import Optional, Tuple

from .frozen_path import get_base_path, is_frozen
from .resource_manager import ResourceManager


def find_config_directory() -> Path:
    """
    Find the config directory using multiple search strategies.

    Args:
        None

    Returns:
        Path: Path to the config directory.
    """

    search_locations = []

    # Strategy 1: PyInstaller bundle directory
    if is_frozen():
        search_locations.append(get_base_path() / "config")

    # Strategy 2: Binary directory (legacy approach)
    try:
        binary_dir = Path(os.path.dirname(os.path.abspath(sys.argv[0])))
        search_locations.append(binary_dir / "config")
    except (IndexError, OSError):
        pass

    # Strategy 3: Executable directory
    try:
        exec_dir = Path(sys.executable).parent
        search_locations.append(exec_dir / "config")
    except (OSError, AttributeError):
        pass

    # Strategy 4: Environment variable override
    config_env_path = os.environ.get("NVDEBUG_CONFIG_DIR")
    if config_env_path:
        search_locations.append(Path(config_env_path))

    # Strategy 5: Relative to this script file (for development)
    try:
        current_file = Path(__file__).resolve()
        search_locations.extend(
            [
                current_file.parent.parent.parent / "config",
                current_file.parent.parent / "config",
                current_file.parent / "config",
            ]
        )
    except (OSError, RuntimeError):
        pass

    # Strategy 6: Current working directory
    search_locations.append(Path.cwd() / "config")

    # Strategy 7: System locations
    search_locations.extend(
        [
            Path("/etc/nvdebug/config"),
            Path.home() / ".nvdebug" / "config",
        ]
    )

    # Find first existing directory
    for path in search_locations:
        try:
            if path.exists() and path.is_dir():
                return path
        except (OSError, PermissionError):
            continue

    # Fallback to current directory
    return Path.cwd() / "config"


def find_config_files() -> Tuple[Optional[Path], Optional[Path]]:
    """
    Automatically find dut_config.yaml and config.yaml files in the same directory as the executable.

    This function implements the same logic as the legacy nvdebug tool, which automatically
    found these configuration files if they were in the same relative path (same directory)
    as the executable.

    Args:
        None

    Returns:
        Tuple[Optional[Path], Optional[Path]]: (dut_config_path, config_path) where each can be None if not found
    """
    search_locations = []

    # Strategy 1: PyInstaller bundle directory
    if is_frozen():
        search_locations.append(get_base_path())

    # Strategy 2: Binary directory (legacy approach) - same directory as executable
    try:
        binary_dir = Path(os.path.dirname(os.path.abspath(sys.argv[0])))
        search_locations.append(binary_dir)
    except (IndexError, OSError):
        pass

    # Strategy 3: Executable directory
    try:
        exec_dir = Path(sys.executable).parent
        search_locations.append(exec_dir)
    except (OSError, AttributeError):
        pass

    # Strategy 4: Environment variable override
    config_env_path = os.environ.get("NVDEBUG_CONFIG_DIR")
    if config_env_path:
        search_locations.append(Path(config_env_path))

    # Strategy 5: Relative to this script file (for development)
    try:
        current_file = Path(__file__).resolve()
        search_locations.extend(
            [
                current_file.parent.parent.parent,
                current_file.parent.parent,
                current_file.parent,
            ]
        )
        try:
            repo_root = current_file.parents[3]
            search_locations.extend([repo_root, repo_root / "default_config"])
        except IndexError:
            pass
    except (OSError, RuntimeError):
        pass

    # Strategy 6: Current working directory
    search_locations.append(Path.cwd())

    # Strategy 7: System locations
    search_locations.extend(
        [
            Path("/etc/nvdebug"),
            Path.home() / ".nvdebug",
        ]
    )

    dut_config_path = None
    config_path = None

    # Find first existing files in order of preference
    for search_dir in search_locations:
        try:
            if not search_dir.exists() or not search_dir.is_dir():
                continue

            # Check for dut_config.yaml
            if dut_config_path is None:
                dut_config_candidate = search_dir / "dut_config.yaml"
                if dut_config_candidate.exists() and dut_config_candidate.is_file():
                    dut_config_path = dut_config_candidate

            # Check for config.yaml (legacy)
            if config_path is None:
                config_candidate = search_dir / "config.yaml"
                if config_candidate.exists() and config_candidate.is_file():
                    config_path = config_candidate

            # If we found both files, we can stop searching
            if dut_config_path is not None and config_path is not None:
                break

        except (OSError, PermissionError):
            continue

    # Strategy 8: Try to find config files as package resources (using ResourceManager)
    # Note: ModuleNotFoundError can occur when running from source (src.tool vs tool)
    if dut_config_path is None:
        try:
            dut_config_path = Path(
                ResourceManager.get_resource_path("tool", "dut_config.yaml")
            )
        except (FileNotFoundError, ModuleNotFoundError):
            pass

    if config_path is None:
        try:
            config_path = Path(ResourceManager.get_resource_path("tool", "config.yaml"))
        except (FileNotFoundError, ModuleNotFoundError):
            pass

    return dut_config_path, config_path


def find_all_config_files() -> Tuple[Optional[Path], Optional[Path], Optional[Path]]:
    """
    Automatically find dut_config.yaml, config.yaml, and tool_config.yaml files in the same directory as the executable.

    This is an enhanced version of find_config_files that also searches for tool_config.yaml.
    Use this function when you need access to all three config file types.

    Args:
        None

    Returns:
        Tuple[Optional[Path], Optional[Path], Optional[Path]]: (dut_config_path, config_path, tool_config_path) where each can be None if not found
    """
    search_locations = []

    # Strategy 1: PyInstaller bundle directory
    if is_frozen():
        search_locations.append(get_base_path())

    # Strategy 2: Binary directory (legacy approach) - same directory as executable
    try:
        binary_dir = Path(os.path.dirname(os.path.abspath(sys.argv[0])))
        search_locations.append(binary_dir)
    except (IndexError, OSError):
        pass

    # Strategy 3: Executable directory
    try:
        exec_dir = Path(sys.executable).parent
        search_locations.append(exec_dir)
    except (OSError, AttributeError):
        pass

    # Strategy 4: Environment variable override
    config_env_path = os.environ.get("NVDEBUG_CONFIG_DIR")
    if config_env_path:
        search_locations.append(Path(config_env_path))

    # Strategy 5: Relative to this script file (for development)
    try:
        current_file = Path(__file__).resolve()
        search_locations.extend(
            [
                current_file.parent.parent.parent,
                current_file.parent.parent,
                current_file.parent,
            ]
        )
        try:
            repo_root = current_file.parents[3]
            search_locations.extend([repo_root, repo_root / "default_config"])
        except IndexError:
            pass
    except (OSError, RuntimeError):
        pass

    # Strategy 6: Current working directory
    search_locations.append(Path.cwd())

    # Strategy 7: System locations
    search_locations.extend(
        [
            Path("/etc/nvdebug"),
            Path.home() / ".nvdebug",
        ]
    )

    dut_config_path = None
    config_path = None
    tool_config_path = None

    # Find first existing files in order of preference
    for search_dir in search_locations:
        try:
            if not search_dir.exists() or not search_dir.is_dir():
                continue

            # Check for dut_config.yaml
            if dut_config_path is None:
                dut_config_candidate = search_dir / "dut_config.yaml"
                if dut_config_candidate.exists() and dut_config_candidate.is_file():
                    dut_config_path = dut_config_candidate

            # Check for config.yaml (legacy)
            if config_path is None:
                config_candidate = search_dir / "config.yaml"
                if config_candidate.exists() and config_candidate.is_file():
                    config_path = config_candidate

            # Check for tool_config.yaml (new format)
            if tool_config_path is None:
                tool_config_candidate = search_dir / "tool_config.yaml"
                if tool_config_candidate.exists() and tool_config_candidate.is_file():
                    tool_config_path = tool_config_candidate

            # If we found all three files, we can stop searching
            if (
                dut_config_path is not None
                and config_path is not None
                and tool_config_path is not None
            ):
                break

        except (OSError, PermissionError):
            continue

    # Strategy 8: Try to find config files as package resources (using ResourceManager)
    # Note: ModuleNotFoundError can occur when running from source (src.tool vs tool)
    if dut_config_path is None:
        try:
            dut_config_path = Path(
                ResourceManager.get_resource_path("tool", "dut_config.yaml")
            )
        except (FileNotFoundError, ModuleNotFoundError):
            pass

    if config_path is None:
        try:
            config_path = Path(ResourceManager.get_resource_path("tool", "config.yaml"))
        except (FileNotFoundError, ModuleNotFoundError):
            pass

    if tool_config_path is None:
        try:
            tool_config_path = Path(
                ResourceManager.get_resource_path("tool", "tool_config.yaml")
            )
        except (FileNotFoundError, ModuleNotFoundError):
            pass

    return dut_config_path, config_path, tool_config_path
