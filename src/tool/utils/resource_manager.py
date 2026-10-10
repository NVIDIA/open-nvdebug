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
Provide the resource manager implementation for the NVDebug runtime.

This module owns the resource manager boundary and exposes ``ResourceManager``,
``get_tool_resource``, ``get_tool_resource_content``, and
``get_platforms_resource``. Keeping those contracts together gives importers one
source of truth for their validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import os
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, List

from .frozen_path import get_base_path, is_frozen, safe_resource_path


def _resource_parts(resource_name: str) -> tuple[str, ...]:
    """
    Validate a package-relative resource name and return its path components.

    Package resources use forward-slash separators on every platform. Absolute
    paths, traversal components, empty nested components, and backslashes are
    rejected before either a filesystem or traversable resource is consulted.
    An empty name intentionally selects the package root for the established
    path API.

    Args:
        resource_name: Package-relative resource name supplied by the caller.

    Returns:
        Validated resource path components, or an empty tuple for the package
        root.

    Raises:
        FileNotFoundError: If the resource name is not a safe relative path.
    """

    if resource_name == "":
        return ()
    if not isinstance(resource_name, str) or "\\" in resource_name:
        raise FileNotFoundError(f"Invalid package resource: {resource_name!r}")
    raw_parts = resource_name.split("/")
    path = PurePosixPath(resource_name)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in raw_parts)
        or tuple(raw_parts) != path.parts
    ):
        raise FileNotFoundError(f"Invalid package resource: {resource_name!r}")
    return path.parts


def _package_resource(package_name: str, resource_name: str) -> Any:
    """
    Resolve one importlib resource without assuming a filesystem-backed package.

    The returned traversable remains valid for both ordinary directories and
    packages imported directly from archives.

    Args:
        package_name: Importable package containing the resource.
        resource_name: Validated package-relative resource name.

    Returns:
        An ``importlib.resources`` traversable for the selected resource.

    Raises:
        FileNotFoundError: If the package or resource cannot be resolved.
    """

    parts = _resource_parts(resource_name)
    try:
        resource = resources.files(package_name).joinpath(*parts)
        if not resource.is_file() and not resource.is_dir():
            raise FileNotFoundError
        return resource
    except (ImportError, ModuleNotFoundError, AttributeError, TypeError) as error:
        raise FileNotFoundError(
            f"Resource not found: {package_name}/{resource_name}"
        ) from error
    except FileNotFoundError as error:
        raise FileNotFoundError(
            f"Resource not found: {package_name}/{resource_name}"
        ) from error


def _walk_resource_files(directory: Any, prefix: tuple[str, ...] = ()) -> Iterator[str]:
    """
    Yield file names recursively from an importlib traversable directory.

    Directories are traversed lexically so callers receive stable results
    regardless of the package loader's native iteration order.

    Args:
        directory: Traversable package directory to enumerate.
        prefix: Relative path components accumulated by recursive calls.

    Yields:
        Forward-slash-separated file names in deterministic lexical order.
    """

    for item in sorted(directory.iterdir(), key=lambda candidate: candidate.name):
        relative = (*prefix, item.name)
        if item.is_file():
            yield "/".join(relative)
        elif item.is_dir():
            yield from _walk_resource_files(item, relative)


class ResourceManager:
    """
    Manages access to package resources using importlib.resources.

    This class provides a unified interface for accessing resources that works
    both during development and when the application is bundled with
    PyInstaller.
    """

    @staticmethod
    def get_resource_path(package_name: str, resource_name: str) -> str:
        """
        Get the absolute path to a resource file.

        The implementation uses ``package_name`` and ``resource_name`` to get
        the absolute path to a resource file. If the function cannot get the
        absolute path to a resource file, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            package_name: Stable package name used for lookup and
                operator-facing diagnostics.
            resource_name: Stable resource name used for lookup and
                operator-facing diagnostics.

        Returns:
            The validated ``resource_path``.

        Raises:
            FileNotFoundError: If resource not found:
                ``package_name``/``resource_name``.
        """
        if is_frozen():
            resource_path = safe_resource_path(
                get_base_path(), package_name, *_resource_parts(resource_name)
            )
        else:
            resource = _package_resource(package_name, resource_name)
            try:
                resource_path = Path(os.fspath(resource))
            except TypeError as error:
                raise FileNotFoundError(
                    "Resource has no stable filesystem path; use the content "
                    f"API instead: {package_name}/{resource_name}"
                ) from error

        if not resource_path.exists():
            raise FileNotFoundError(
                f"Resource not found: {package_name}/{resource_name}"
            )

        return str(resource_path.resolve())

    @staticmethod
    def get_resource_content(
        package_name: str, resource_name: str, encoding: str = "utf-8"
    ) -> str:
        """
        Get the content of a resource file as a string.

        After applying local validation, the function forwards ``package_name``,
        ``resource_name``, and ``encoding`` to ``f.read`` and preserves its
        return and exception contract. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            package_name: Stable package name used for lookup and
                operator-facing diagnostics.
            resource_name: Stable resource name used for lookup and
                operator-facing diagnostics.
            encoding: Character encoding used to decode or write the selected
                text.

        Returns:
            The canonical resource content text.

        Raises:
            FileNotFoundError: If the resource is missing or is not a file.
        """
        if is_frozen():
            resource_path = ResourceManager.get_resource_path(
                package_name, resource_name
            )
            with open(resource_path, "r", encoding=encoding) as resource_file:
                return resource_file.read()

        resource = _package_resource(package_name, resource_name)
        if not resource.is_file():
            raise FileNotFoundError(
                f"Resource is not a file: {package_name}/{resource_name}"
            )
        return resource.read_text(encoding=encoding)

    @staticmethod
    def get_resource_bytes(package_name: str, resource_name: str) -> bytes:
        """
        Get the content of a resource file as bytes.

        After applying local validation, the function forwards ``package_name``
        and ``resource_name`` to ``f.read`` and preserves its return and
        exception contract. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            package_name: Stable package name used for lookup and
                operator-facing diagnostics.
            resource_name: Stable resource name used for lookup and
                operator-facing diagnostics.

        Returns:
            The bounded resource bytes.

        Raises:
            FileNotFoundError: If the resource is missing or is not a file.
        """
        if is_frozen():
            resource_path = ResourceManager.get_resource_path(
                package_name, resource_name
            )
            with open(resource_path, "rb") as resource_file:
                return resource_file.read()

        resource = _package_resource(package_name, resource_name)
        if not resource.is_file():
            raise FileNotFoundError(
                f"Resource is not a file: {package_name}/{resource_name}"
            )
        return resource.read_bytes()

    @staticmethod
    def list_resources(package_name: str, subdirectory: str = "") -> List[str]:
        """
        List all resources in a package or subdirectory.

        The implementation uses ``package_name`` and ``subdirectory`` to list
        all resources in a package or subdirectory.

        Args:
            package_name: Stable package name used for lookup and
                operator-facing diagnostics.
            subdirectory: Text supplied as subdirectory in the format accepted
                by this function.

        Returns:
            The list resources returned in operation-defined order.
        """
        if is_frozen():
            base_path = safe_resource_path(
                get_base_path(), package_name, *_resource_parts(subdirectory)
            )
            if not base_path.is_dir():
                return []

            resource_list = []
            for root, directories, files in os.walk(base_path):
                directories.sort()
                for file in sorted(files):
                    rel_path = os.path.relpath(Path(root) / file, base_path)
                    resource_list.append(rel_path.replace(os.sep, "/"))
            return resource_list

        try:
            package = _package_resource(package_name, subdirectory)
        except FileNotFoundError:
            return []
        if not package.is_dir():
            return []
        return list(_walk_resource_files(package))

    @staticmethod
    def resource_exists(package_name: str, resource_name: str) -> bool:
        """
        Check if a resource exists.

        The implementation uses ``package_name`` and ``resource_name`` to check
        if a resource exists. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path.

        Args:
            package_name: Stable package name used for lookup and
                operator-facing diagnostics.
            resource_name: Stable resource name used for lookup and
                operator-facing diagnostics.

        Returns:
            Whether the if a resource exists operation succeeds.
        """
        if is_frozen():
            try:
                resource_path = safe_resource_path(
                    get_base_path(), package_name, *_resource_parts(resource_name)
                )
            except (FileNotFoundError, ValueError):
                return False
            return resource_path.exists()

        try:
            resource = _package_resource(package_name, resource_name)
        except FileNotFoundError:
            return False
        return bool(resource.is_file() or resource.is_dir())


# Convenience functions for common use cases
def get_tool_resource(resource_name: str) -> str:
    """
    Get a resource from the 'tool' package.

    After applying local validation, the function forwards ``resource_name`` to
    ``ResourceManager.get_resource_path`` and preserves its return and exception
    contract.

    Args:
        resource_name: Stable resource name used for lookup and operator-facing
            diagnostics.

    Returns:
        The canonical tool resource text.
    """
    return ResourceManager.get_resource_path("tool", resource_name)


def get_tool_resource_content(resource_name: str, encoding: str = "utf-8") -> str:
    """
    Get the content of a resource from the 'tool' package.

    After applying local validation, the function forwards ``resource_name`` and
    ``encoding`` to ``ResourceManager.get_resource_content`` and preserves its
    return and exception contract.

    Args:
        resource_name: Stable resource name used for lookup and operator-facing
            diagnostics.
        encoding: Character encoding used to decode or write the selected text.

    Returns:
        The canonical tool resource content text.
    """
    return ResourceManager.get_resource_content("tool", resource_name, encoding)


def get_platforms_resource(resource_name: str) -> str:
    """
    Get a resource from the 'platforms' package.

    After applying local validation, the function forwards ``resource_name`` to
    ``ResourceManager.get_resource_path`` and preserves its return and exception
    contract.

    Args:
        resource_name: Stable resource name used for lookup and operator-facing
            diagnostics.

    Returns:
        The canonical platforms resource text.
    """
    return ResourceManager.get_resource_path("platforms", resource_name)
