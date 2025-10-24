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
Resource manager using importlib.resources for PyInstaller compatibility.

This module provides utilities for accessing package resources (files, data, etc.)
in a way that works both during development and when bundled with PyInstaller.
"""

import os
import sys
from importlib import resources
from pathlib import Path
from typing import Optional, Union


class ResourceManager:
    """
    Manages access to package resources using importlib.resources.

    This class provides a unified interface for accessing resources that works
    both during development and when the application is bundled with PyInstaller.
    """

    @staticmethod
    def get_resource_path(package_name: str, resource_name: str) -> str:
        """
        Get the absolute path to a resource file.

        Args:
            package_name: The package name (e.g., 'tool')
            resource_name: The resource name (e.g., 'config.yaml')

        Returns:
            The absolute path to the resource file

        Raises:
            FileNotFoundError: If the resource doesn't exist
        """
        if hasattr(sys, "_MEIPASS"):
            # PyInstaller: resources are extracted to _MEIPASS
            resource_path = os.path.join(sys._MEIPASS, package_name, resource_name)
        else:
            # Development: use importlib.resources
            try:
                resource_path = str(resources.files(package_name) / resource_name)
            except (ImportError, AttributeError):
                # Fallback for older Python versions
                import pkg_resources

                resource_path = pkg_resources.resource_filename(
                    package_name, resource_name
                )

        if not os.path.exists(resource_path):
            raise FileNotFoundError(
                f"Resource not found: {package_name}/{resource_name}"
            )

        return resource_path

    @staticmethod
    def get_resource_content(
        package_name: str, resource_name: str, encoding: str = "utf-8"
    ) -> str:
        """
        Get the content of a resource file as a string.

        Args:
            package_name: The package name
            resource_name: The resource name
            encoding: The file encoding (default: utf-8)

        Returns:
            The content of the resource file
        """
        resource_path = ResourceManager.get_resource_path(package_name, resource_name)
        with open(resource_path, "r", encoding=encoding) as f:
            return f.read()

    @staticmethod
    def get_resource_bytes(package_name: str, resource_name: str) -> bytes:
        """
        Get the content of a resource file as bytes.

        Args:
            package_name: The package name
            resource_name: The resource name

        Returns:
            The content of the resource file as bytes
        """
        resource_path = ResourceManager.get_resource_path(package_name, resource_name)
        with open(resource_path, "rb") as f:
            return f.read()

    @staticmethod
    def list_resources(package_name: str, subdirectory: str = "") -> list[str]:
        """
        List all resources in a package or subdirectory.

        Args:
            package_name: The package name
            subdirectory: Optional subdirectory within the package

        Returns:
            List of resource names
        """
        if hasattr(sys, "_MEIPASS"):
            # PyInstaller: list files in _MEIPASS
            base_path = os.path.join(sys._MEIPASS, package_name, subdirectory)
            if not os.path.exists(base_path):
                return []

            resources = []
            for root, dirs, files in os.walk(base_path):
                for file in files:
                    rel_path = os.path.relpath(os.path.join(root, file), base_path)
                    resources.append(rel_path)
            return resources
        else:
            # Development: use importlib.resources
            try:
                package = resources.files(package_name)
                if subdirectory:
                    package = package / subdirectory

                if not package.exists():
                    return []

                resources_list = []
                for item in package.iterdir():
                    if item.is_file():
                        resources_list.append(item.name)
                    elif item.is_dir():
                        # Recursively list subdirectory contents
                        for subitem in item.rglob("*"):
                            if subitem.is_file():
                                rel_path = subitem.relative_to(package)
                                resources_list.append(str(rel_path))

                return resources_list
            except (ImportError, AttributeError):
                # Fallback for older Python versions
                import pkg_resources

                try:
                    return pkg_resources.resource_listdir(package_name, subdirectory)
                except OSError:
                    return []

    @staticmethod
    def resource_exists(package_name: str, resource_name: str) -> bool:
        """
        Check if a resource exists.

        Args:
            package_name: The package name
            resource_name: The resource name

        Returns:
            True if the resource exists, False otherwise
        """
        try:
            ResourceManager.get_resource_path(package_name, resource_name)
            return True
        except FileNotFoundError:
            return False


# Convenience functions for common use cases
def get_tool_resource(resource_name: str) -> str:
    """
    Get a resource from the 'tool' package.

    Args:
        resource_name: The resource name

    Returns:
        The absolute path to the resource
    """
    return ResourceManager.get_resource_path("tool", resource_name)


def get_tool_resource_content(resource_name: str, encoding: str = "utf-8") -> str:
    """
    Get the content of a resource from the 'tool' package.

    Args:
        resource_name: The resource name
        encoding: The file encoding

    Returns:
        The content of the resource file
    """
    return ResourceManager.get_resource_content("tool", resource_name, encoding)


def get_platforms_resource(resource_name: str) -> str:
    """
    Get a resource from the 'platforms' package.

    Args:
        resource_name: The resource name

    Returns:
        The absolute path to the resource
    """
    return ResourceManager.get_resource_path("platforms", resource_name)
