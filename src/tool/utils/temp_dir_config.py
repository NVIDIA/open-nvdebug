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
Temporary directory management for open-nvdebugtool.

Provides:
- TempManager: Centralized temp dir creation, tracking, and cleanup
- get_tool_temp_dir(): Legacy helper (kept for backward compatibility)
"""

import os
import secrets
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional


class TempManager:
    """
    Single source of truth for all temporary directory operations.

    Creates temp dirs with restricted permissions (0o700), tracks them
    for cleanup, and provides standardized remote temp path generation.

    Usage:
        with TempManager(base_dir=Path("/tmp")) as mgr:
            local_dir = mgr.create_temp_dir("transfer")
            remote_path = mgr.get_remote_temp_path("collection")
        # All local temp dirs cleaned up automatically
    """

    def __init__(self, base_dir: Path, tool_name: str = "nvdebug"):
        self.base_dir = Path(base_dir)
        self.tool_name = tool_name
        self._tracked_dirs: List[Path] = []
        self.base_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.base_dir, 0o700)

    @property
    def tracked_dirs(self) -> List[Path]:
        return list(self._tracked_dirs)

    def create_temp_dir(self, purpose: str, permissions: int = 0o700) -> Path:
        """Create a tracked temporary directory with the given purpose label."""
        suffix = secrets.token_hex(4)
        dir_name = f"{self.tool_name}_{purpose}_{suffix}"
        temp_dir = self.base_dir / dir_name
        temp_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(temp_dir, permissions)
        self._tracked_dirs.append(temp_dir)
        return temp_dir

    def get_remote_temp_path(self, purpose: str, remote_temp_dir: str = "/tmp") -> str:
        """Generate a unique remote temp path string (does not create locally)."""
        suffix = secrets.token_hex(4)
        return f"{remote_temp_dir}/{self.tool_name}_{purpose}_{suffix}"

    def cleanup(self) -> None:
        """Remove all tracked temporary directories."""
        for d in self._tracked_dirs:
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
        self._tracked_dirs.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False


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
