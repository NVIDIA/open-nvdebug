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
Zip utilities for NVDebug Tool.

Implements zip archiving, splitting, and skip functionality with support
for large files and sanitized naming.
"""

import getpass
import logging
import os
import shutil
import zipfile
from pathlib import Path
from typing import Optional

from ..config import _global_sanitization_enabled
from .sanitizer import create_sanitizer_from_config

logger = logging.getLogger(__name__)


def fix_file_timestamps(directory: str) -> None:
    """
    Fix file timestamps in a directory to ensure consistent archiving.

    Args:
        directory: Directory path to fix timestamps for
    """
    try:
        min_timestamp = float("inf")

        # Find the minimum timestamp
        for root, _, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    timestamp = os.path.getmtime(filepath)
                    min_timestamp = min(min_timestamp, timestamp)
                except OSError:
                    continue

        if min_timestamp == float("inf"):
            return

        # Set all files to the minimum timestamp
        for root, _, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    os.utime(filepath, (min_timestamp, min_timestamp))
                except OSError:
                    continue

    except Exception as e:
        logger.warning(f"Failed to fix file timestamps in {directory}: {e}")


def create_zip(directory: str, name: Optional[str] = None) -> str:
    """
    Create a zip archive from a directory.

    Args:
        directory: The directory to be archived
        name: The base name of the zip archive (without .zip)

    Returns:
        str: Path to the created zip file
    """
    try:
        if not name:
            name = os.path.basename(directory)

        # Determine parent directory and base name (same logic as create_zip_split)
        parent_of_directory = os.path.dirname(os.path.abspath(directory))

        # Build the zip path in the parent directory
        zip_path = os.path.join(parent_of_directory, f"{name}.zip")

        fix_file_timestamps(directory)

        # Create the zip archive in the parent directory
        with zipfile.ZipFile(
            zip_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,  # Maximum compression
        ) as zf:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Ensure the top-level folder is preserved in the archive
                    arcname = os.path.relpath(file_path, os.path.dirname(directory))
                    zf.write(file_path, arcname)

        shutil.rmtree(directory)
        logger.info(f"Zip archive created at {os.path.abspath(zip_path)}")
        return zip_path

    except Exception as e:
        logger.error(f"Error creating zip: {str(e)}")
        raise


def create_zip_split(
    directory: str,
    name: Optional[str] = None,
    split: bool = False,
    max_size_mb: float = 200.0,
    compression_level: int = 9,
) -> str:
    """
    Create a zip archive and split it into parts if it exceeds a specified size.
    Uses maximum compression by default (ZIP_DEFLATED, compresslevel=9).

    Args:
        directory: The directory to be archived
        name: The base name of the zip archive (without .zip)
        split: Whether to split the zip if it exceeds max_size_mb
        max_size_mb: Max size for a split part in MB (float)
        compression_level: Compression level for ZIP_DEFLATED (0-9)

    Returns:
        str: Path to the created zip file(s)
    """
    # Determine parent directory and base name
    parent_of_directory = os.path.dirname(os.path.abspath(directory))
    if not name:
        # By default, name is just the basename of the directory being zipped
        name = os.path.basename(directory)

    # Build the zip path in the parent directory
    zip_path = os.path.join(parent_of_directory, f"{name}.zip")

    try:
        max_size_bytes = int(float(max_size_mb) * 1024 * 1024)  # Convert to bytes
        if max_size_bytes <= 0:
            raise ValueError("Threshold must be greater than 0")
    except (ValueError, TypeError) as e:
        logger.warning(
            f"Invalid threshold value: {max_size_mb}. Using default of 200MB"
        )
        max_size_bytes = 200 * 1024 * 1024

    # Create the zip archive
    with zipfile.ZipFile(
        zip_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=compression_level,
    ) as zf:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                # Ensure the top-level folder is preserved in the archive
                arcname = os.path.relpath(file_path, os.path.dirname(directory))
                zf.write(file_path, arcname)

    final_size = os.path.getsize(zip_path)

    # Check if we need to split
    if split and final_size > max_size_bytes:
        original_temp_path = zip_path + ".orig"
        os.rename(zip_path, original_temp_path)

        # Perform the split
        split_files = split_zip(original_temp_path, max_size_bytes)

        # Remove the single large zip
        os.remove(original_temp_path)
        print(f"Split zip archive created for {name}")
        return split_files
    else:
        # Sanitize path to avoid exposing usernames (respect global sanitization setting)
        current_username = getpass.getuser()
        sanitizer = create_sanitizer_from_config(
            {},
            enabled=_global_sanitization_enabled,
            extra_strings=[current_username] if current_username else [],
        )
        sanitized_path = sanitizer.sanitize(os.path.abspath(zip_path))
        print(f"Zip archive created at {sanitized_path}")

    # Remove original directory after successful zip creation/splitting
    shutil.rmtree(directory)

    return zip_path


def split_zip(zip_path: str, max_size_bytes: int) -> list:
    """
    Split a zip file into multiple parts, naming the parts .z01, .z02, ...,
    and naming the last chunk .zip.

    Args:
        zip_path: Path to the already-created .zip file
        max_size_bytes: Maximum size in bytes for each split chunk

    Returns:
        list: List of all created split file paths
    """
    base_dir = os.path.dirname(zip_path)
    base_name = os.path.basename(zip_path).replace(".zip.orig", "").replace(".zip", "")

    part_files = []
    part_number = 1

    with open(zip_path, "rb") as src:
        while True:
            chunk = src.read(max_size_bytes)
            if not chunk:
                break

            part_suffix = f".z{str(part_number).zfill(2)}"
            part_path = os.path.join(base_dir, f"{base_name}{part_suffix}")

            with open(part_path, "wb") as dst:
                dst.write(chunk)

            part_files.append(part_path)
            part_number += 1

    # Rename the last part to .zip
    if part_files:
        last_part = part_files[-1]
        final_zip_path = os.path.join(base_dir, f"{base_name}.zip")
        os.rename(last_part, final_zip_path)

        # Print information about the split files
        logger.info("\nSplit files created:")
        for i in range(1, part_number - 1):
            logger.info(f"  {base_name}.z{str(i).zfill(2)}")
        logger.info(f"  {base_name}.zip")

        logger.info("\nTo recombine the files:")
        logger.info("On Linux/macOS:")
        logger.info(f"  cat {base_name}.z* > {base_name}_combined.zip")
        logger.info("\nOn Windows (Command Prompt):")
        logger.info(f"  copy /b {base_name}.z* {base_name}_combined.zip")
        logger.info("\nOn Windows (PowerShell):")
        logger.info(
            f"  Get-Content {base_name}.z* -Raw -Encoding Byte | Set-Content {base_name}_combined.zip -Encoding Byte"
        )

        # Return list of all created files
        all_files = []
        for i in range(1, part_number - 1):
            all_files.append(os.path.join(base_dir, f"{base_name}.z{str(i).zfill(2)}"))
        all_files.append(os.path.join(base_dir, f"{base_name}.zip"))
        return all_files


def should_skip_collector(
    collector_id: str,
    skip_collectors: Optional[list] = None,
    include_collectors: Optional[list] = None,
) -> bool:
    """
    Determine if a collector should be skipped based on skip/include lists.

    Args:
        collector_id: The collector ID to check
        skip_collectors: List of collector IDs to skip
        include_collectors: List of collector IDs to include (if specified, only these run)

    Returns:
        bool: True if collector should be skipped
    """
    # If include_collectors is specified, it takes precedence
    if include_collectors:
        # Only run collectors that are in the include list
        return collector_id not in include_collectors

    # If no include_collectors specified, check skip_collectors
    if skip_collectors and collector_id in skip_collectors:
        return True

    return False


def should_skip_zip_creation(skip_zip: bool, skip_zip_split: bool) -> bool:
    """
    Determine if zip creation should be skipped.

    Args:
        skip_zip: Whether to skip zip creation
        skip_zip_split: Whether to skip zip splitting

    Returns:
        bool: True if zip creation should be skipped
    """
    return skip_zip
