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

- TempManager: Centralized temp dir creation, tracking, and cleanup.
- get_tool_temp_dir(): Legacy helper (kept for backward compatibility).
"""

import os
import secrets
import shutil
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional


class TempManager:
    """
    Single source of truth for all temporary directory operations.

    Creates temp dirs with restricted permissions (0o700), tracks them for
    cleanup, and provides standardized remote temp path generation.

    Example:
        with TempManager(base_dir=Path("/var/tmp/nvdebug-private")) as mgr:
            local_dir = mgr.create_temp_dir("transfer")
            remote_path = mgr.get_remote_temp_path("collection")
        # All local temp dirs cleaned up automatically
    """

    def __init__(self, base_dir: Path, tool_name: str = "nvdebug"):
        """
        Initialize a ``TempManager`` instance.

        The initializer records ``_tracked_dirs``, ``base_dir``, and
        ``tool_name`` for later operations and establishes the instance
        invariants before any public method runs. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.

        Args:
            base_dir: filesystem location used as the base dir for this
                operation.
            tool_name: Stable tool name used for lookup and operator-facing
                diagnostics.

        Raises:
            PermissionError: If an existing temporary base is not a private
                regular directory owned through the selected path.
        """
        self.base_dir = Path(base_dir)
        self.tool_name = tool_name
        self._tracked_dirs: List[Path] = []
        try:
            self.base_dir.mkdir(parents=True, mode=0o700)
        except FileExistsError:
            metadata = self.base_dir.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise PermissionError(
                    f"temporary base is not a regular directory: {self.base_dir}"
                )
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise PermissionError(
                    f"temporary base has group/other permissions: {self.base_dir}"
                )

    @property
    def tracked_dirs(self) -> List[Path]:
        """
        Return the tracked dirs.

        Each access computes the value from ``_tracked_dirs`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The tracked dirs returned in operation-defined order.
        """
        return list(self._tracked_dirs)

    def create_temp_dir(self, purpose: str, permissions: int = 0o700) -> Path:
        """
        Create a tracked temporary directory with the given purpose label.

        The implementation uses ``purpose`` and ``permissions`` to create a
        tracked temporary directory with the given purpose label. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Args:
            purpose: Text supplied as purpose in the format accepted by this
                function.
            permissions: Numeric permissions used while the operation performs
                bounded accounting.

        Returns:
            The validated ``temp_dir``.
        """
        suffix = secrets.token_hex(4)
        dir_name = f"{self.tool_name}_{purpose}_{suffix}"
        temp_dir = self.base_dir / dir_name
        temp_dir.mkdir(mode=permissions)
        self._tracked_dirs.append(temp_dir)
        return temp_dir

    def get_remote_temp_path(self, purpose: str, remote_temp_dir: str = "/tmp") -> str:
        """
        Generate a unique remote temp path string (does not create locally).

        The implementation uses ``purpose`` and ``remote_temp_dir`` to generate
        a unique remote temp path string (does not create locally).

        Args:
            purpose: Text supplied as purpose in the format accepted by this
                function.
            remote_temp_dir: filesystem location used as the remote temp dir for
                this operation.

        Returns:
            The canonical remote temp path.
        """
        suffix = secrets.token_hex(4)
        return f"{remote_temp_dir}/{self.tool_name}_{purpose}_{suffix}"

    def cleanup(self) -> None:
        """
        Remove all tracked temporary directories.

        The implementation uses current instance state to remove all tracked
        temporary directories.
        """
        for d in self._tracked_dirs:
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
        self._tracked_dirs.clear()

    def __enter__(self):
        """
        Enter the TempManager context.

        Entering the scope acquires or validates its owned resources and returns
        the value used until the matching exit method completes cleanup.

        Returns:
            The validated ``self``.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exit the TempManager context.

        Leaving the scope releases resources owned by the context while
        preserving the exception-propagation behavior declared by the
        context-manager protocol.

        Args:
            exc_type: Exception type consumed while the function attempts to
                exit the TempManager context.
            exc_val: Exception val consumed while the function attempts to exit
                the TempManager context.
            exc_tb: Exception tb consumed while the function attempts to exit
                the TempManager context.

        Returns:
            Whether the exit the TempManager context operation succeeds.
        """
        self.cleanup()
        return False


def get_tool_temp_dir(
    tool_config: Dict[str, Any], default_temp_dir: str = "/tmp"
) -> str:
    """
    Get the remote DUT staging root from configuration.

    The implementation uses ``tool_config`` and ``default_temp_dir`` to get the
    tool temporary directory from configuration.

    Args:
        tool_config: Tool config governing get the tool temporary directory from
            configuration.
        default_temp_dir: filesystem location used as the default temp dir for
            this operation.

    Returns:
        The canonical remote tool temp dir text. This path is interpreted on a
        DUT; it does not select local ``tempfile`` placement.
    """
    if not tool_config:
        return default_temp_dir

    tool_temp_dir = tool_config.get("TOOL_TEMP_DIR")
    if tool_temp_dir and isinstance(tool_temp_dir, str):
        return tool_temp_dir

    return default_temp_dir


def local_temp_dir(tool_config: Dict[str, Any]) -> Optional[str]:
    """
    Resolve a safe local parent for process-private temporary directories.

    ``TOOL_TEMP_DIR`` remains optional. An absolute configured directory is
    created privately when absent and accepted when an existing real directory
    can host a randomized mode-0700 child. Invalid, relative, symlinked, or
    unusable values return ``None`` so callers retain the standard local
    temporary-directory fallback without failing a collection.

    Args:
        tool_config: Tool configuration which may define ``TOOL_TEMP_DIR``.

    Returns:
        The validated absolute local parent path, or ``None`` when unset or
        unusable.
    """
    if not isinstance(tool_config, dict):
        return None
    configured = tool_config.get("TOOL_TEMP_DIR")
    if not isinstance(configured, str) or not configured.strip():
        return None
    candidate = Path(configured)
    if not candidate.is_absolute():
        return None
    try:
        candidate.mkdir(parents=True, mode=0o700)
        metadata = candidate.lstat()
    except (OSError, ValueError):
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        return None
    return os.fspath(candidate)
