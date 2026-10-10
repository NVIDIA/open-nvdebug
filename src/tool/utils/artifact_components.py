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
Validation helpers for user-controlled artifact path components.

This module owns the artifact components boundary and exposes
``require_safe_artifact_component``. Keeping those contracts together gives
importers one source of truth for their validation, lifecycle, and compatibility
behavior.
"""

from typing import Any


_PORTABLE_COMPONENT_PUNCTUATION = frozenset(" ._-'")


def require_safe_artifact_component(value: Any, label: str) -> str:
    """
    Require one portable path component without traversal semantics.

    The implementation uses ``value`` and ``label`` to require one portable path
    component without traversal semantics. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        value: Value evaluated while performing one portable path component
            without traversal semantics.
        label: Text supplied as label in the format accepted by this function.

    Returns:
        The validated ``component``.

    Raises:
        ValueError: If invalid ``label``: expected one portable path component
            containing only letters, digits, spaces, ``'``, ``.``, ``_``, or
            ``-``.
    """

    component = str(value or "")
    if (
        not component
        or component != component.strip(" .")
        or ".." in component
        or any(
            not char.isascii()
            or (not char.isalnum() and char not in _PORTABLE_COMPONENT_PUNCTUATION)
            for char in component
        )
    ):
        raise ValueError(
            f"Invalid {label}: expected one portable path component containing "
            "only letters, digits, spaces, apostrophes, '.', '_', or '-'"
        )
    return component
