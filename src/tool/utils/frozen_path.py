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
Centralized PyInstaller frozen-app path helpers.

All runtime code that needs to locate bundled resources should call
:func:`get_base_path` instead of probing ``sys._MEIPASS`` directly.
"""

import os
import sys
from pathlib import Path


def is_frozen() -> bool:
    """
    Return *True* when running inside a PyInstaller ``--onefile`` bundle.

    After applying local validation, the function forwards current instance
    state to ``hasattr`` and preserves its return and exception contract.

    Returns:
        Whether the *True* when running inside a PyInstaller ``--onefile``
        bundle operation succeeds.
    """
    return hasattr(sys, "_MEIPASS")


def get_base_path() -> Path:
    """
    Return the root directory for bundled resources.

    * **Frozen** (PyInstaller): ``sys._MEIPASS`` (the temp extraction dir). *
    **Development**: two levels up from this file
    (``src/tool/utils/frozen_path.py`` → ``src/``).

    Returns:
        The validated base path filesystem path.
    """
    if is_frozen():
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent.parent


def get_executable_dir() -> Path:
    """
    Return the directory containing the actual running executable.

    Frozen release resources live beside the one-file binary, not below the
    temporary PyInstaller extraction directory returned by
    :func:`get_base_path`.

    Returns:
        The validated executable dir filesystem path.
    """

    return Path(sys.executable).resolve().parent


def safe_resource_path(base: Path, *parts: str) -> Path:
    """
    Join *parts* under *base* and verify the result stays within *base*.

    Raises :class:`ValueError` if the resolved path escapes *base* (e.g. via
    ``..`` traversal).

    Args:
        base: filesystem location used as the base for this operation.
        parts: Additional positional values forwarded in caller-provided order.

    Returns:
        The validated ``resolved``.

    Raises:
        ValueError: If the supplied input cannot be used to join *parts* under
            *base* and verify the result stays within *base*.
    """
    resolved = (base / os.path.join(*parts)).resolve()
    base_resolved = base.resolve()
    if (
        not str(resolved).startswith(str(base_resolved) + os.sep)
        and resolved != base_resolved
    ):
        raise ValueError(
            f"Path traversal detected: {os.path.join(*parts)!r} escapes {base}"
        )
    return resolved
