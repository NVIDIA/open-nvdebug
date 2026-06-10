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
import math
import os
import re
import shutil
import zipfile
from pathlib import Path
from typing import Optional, Union

from ..config import _global_sanitization_enabled
from .sanitizer import create_sanitizer_from_config

logger = logging.getLogger(__name__)


def _print_sanitized_zip_path(zip_path: str) -> None:
    """Print a sanitized archive path for user-facing output."""
    current_username = getpass.getuser()
    sanitizer = create_sanitizer_from_config(
        {},
        enabled=_global_sanitization_enabled,
        extra_strings=[current_username] if current_username else [],
    )
    sanitized_path = sanitizer.sanitize(os.path.abspath(zip_path))
    print(f"Zip archive created at {sanitized_path}")


def _find_chunked_archive_parts(base_dir: Path, archive_name: str) -> list[str]:
    """Return raw chunked archive parts in lexical volume order."""
    part_pattern = re.compile(rf"^{re.escape(archive_name)}\.part(\d+)$")
    numbered_parts: list[tuple[int, str]] = []

    for entry in base_dir.iterdir():
        if not entry.is_file():
            continue
        match = part_pattern.fullmatch(entry.name)
        if match:
            numbered_parts.append((int(match.group(1)), str(entry)))

    numbered_parts.sort(key=lambda item: item[0])
    return [path for _, path in numbered_parts]


def _log_chunked_archive_instructions(archive_name: str, part_files: list[str]) -> None:
    """Log chunked archive part names and reconstruction instructions."""
    logger.info("\nChunked ZIP parts created:")
    for part in part_files:
        logger.info(f"  {os.path.basename(part)}")

    logger.info("\nTo recombine the archive on Linux:")
    logger.info(f"  cat {archive_name}.part* > {archive_name}")
    logger.info("\nThen extract the reconstructed ZIP:")
    logger.info(f"  unzip {archive_name}")


def _split_file_into_chunks(zip_path: str, max_size_bytes: int) -> list[str]:
    """
    Split a complete ZIP file into raw chunks that can be reassembled with cat.

    This fallback does not create a multi-volume ZIP. It creates numbered
    chunks named <archive>.part001, <archive>.part002, ... so very old Linux
    systems can always reconstruct the original ZIP without relying on Info-ZIP
    split-archive support.
    """
    source_path = Path(zip_path)
    if not source_path.exists():
        raise FileNotFoundError(zip_path)
    if max_size_bytes <= 0:
        raise ValueError("Split size must be greater than 0")

    base_dir = source_path.parent
    archive_name = source_path.name
    for stale_path in _find_chunked_archive_parts(base_dir, archive_name):
        os.remove(stale_path)

    total_parts = max(1, math.ceil(source_path.stat().st_size / max_size_bytes))
    part_width = max(3, len(str(total_parts)))
    part_files: list[str] = []

    with open(source_path, "rb") as src:
        part_number = 1
        while True:
            chunk = src.read(max_size_bytes)
            if not chunk:
                break

            part_name = f"{archive_name}.part{part_number:0{part_width}d}"
            part_path = base_dir / part_name
            with open(part_path, "wb") as dst:
                dst.write(chunk)

            part_files.append(str(part_path))
            part_number += 1

    _log_chunked_archive_instructions(archive_name, part_files)
    return part_files


def safe_extract_zip(zip_ref: zipfile.ZipFile, extract_path: Union[str, Path]) -> None:
    """
    Safely extract a zip file, preventing path traversal attacks.

    This function validates each zip member to ensure it extracts within
    the target directory, preventing malicious archives from writing files
    outside the intended location.

    Args:
        zip_ref: ZipFile object to extract from.
        extract_path: Target directory for extraction (str or Path).

    Raises:
        No exceptions - malicious entries are skipped with warnings logged.
    """
    MAX_EXTRACT_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB total extraction limit
    MAX_SINGLE_FILE = 500 * 1024 * 1024  # 500 MB per file

    extract_path = Path(extract_path) if isinstance(extract_path, str) else extract_path
    extract_path_resolved = extract_path.resolve()
    total_extracted = 0

    for member in zip_ref.infolist():
        # Skip directories (they'll be created as needed)
        if member.filename.endswith("/"):
            continue

        # Check compression ratio before extraction
        if member.file_size > 0 and member.compress_size > 0:
            ratio = member.file_size / member.compress_size
            if ratio > 1000:  # Suspicious compression ratio
                logger.warning(
                    f"Skipping suspicious zip entry {member.filename}: "
                    f"compression ratio {ratio:.0f}:1"
                )
                continue

        # Compute destination path
        member_path = extract_path / member.filename

        try:
            # Resolve to absolute path and verify it's within extract_path
            member_path_resolved = member_path.resolve()

            # Check if the resolved path is within the extraction directory
            try:
                member_path_resolved.relative_to(extract_path_resolved)
            except ValueError:
                # Path is outside extraction directory - skip with warning
                logger.warning(
                    f"Skipping potentially malicious zip entry: {member.filename}"
                )
                continue

            # Create parent directories
            member_path_resolved.parent.mkdir(parents=True, exist_ok=True)

            # Extract the file with size limits
            with zip_ref.open(member) as source, open(
                member_path_resolved, "wb"
            ) as target:
                file_extracted = 0
                while True:
                    chunk = source.read(65536)  # 64KB chunks
                    if not chunk:
                        break
                    file_extracted += len(chunk)
                    total_extracted += len(chunk)
                    if file_extracted > MAX_SINGLE_FILE:
                        raise ValueError(
                            f"ZIP member {member.filename} exceeds max file size "
                            f"({MAX_SINGLE_FILE // (1024*1024)} MB)"
                        )
                    if total_extracted > MAX_EXTRACT_SIZE:
                        raise ValueError(
                            f"ZIP extraction exceeds max total size "
                            f"({MAX_EXTRACT_SIZE // (1024*1024*1024)} GB)"
                        )
                    target.write(chunk)

        except Exception as e:
            logger.warning(f"Failed to extract {member.filename}: {e}")
            continue


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
) -> Union[str, list[str]]:
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
    except (ValueError, TypeError):
        logger.warning(
            f"Invalid threshold value: {max_size_mb}. Using default of 200MB"
        )
        max_size_bytes = 200 * 1024 * 1024

    fix_file_timestamps(directory)

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
        # Use raw chunking for distro-agnostic reconstruction with cat + unzip.
        split_files = _split_file_into_chunks(zip_path, max_size_bytes)

        # Remove the single large zip
        try:
            os.remove(zip_path)
        except OSError as e:
            logger.warning(
                f"Failed to remove temporary archive {zip_path}: {e}"
            )
        print(f"Split archive parts created for {name}")
        # Remove original directory after successful split
        try:
            shutil.rmtree(directory)
        except Exception as e:
            logger.warning(
                f"Failed to remove directory after zip split: {directory}. Error: {e}"
            )
        return split_files
    else:
        _print_sanitized_zip_path(zip_path)

    # Remove original directory after successful zip creation/splitting
    shutil.rmtree(directory)

    return zip_path


def split_zip(zip_path: str, max_size_bytes: int) -> list:
    """
    Split a ZIP archive into raw chunks that can be reassembled with cat.

    Args:
        zip_path: Path to the already-created .zip file
        max_size_bytes: Maximum size in bytes for each split chunk

    Returns:
        list: List of all created split file paths
    """
    source_path = Path(zip_path)
    if not source_path.exists():
        raise FileNotFoundError(zip_path)

    try:
        with zipfile.ZipFile(source_path, "r") as archive:
            if not archive.namelist():
                return [str(source_path)]
    except zipfile.BadZipFile:
        pass

    return _split_file_into_chunks(str(source_path), max_size_bytes)


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
