"""
Copyright (c) 2026, NVIDIA CORPORATION. All rights reserved.

Tar utility functions with bundled fallback for systems without tar.
"""

import logging
import os
import shlex
import shutil
import sys
from typing import Optional

from .frozen_path import get_base_path

logger = logging.getLogger(__name__)


def get_tar_command() -> str:
    """
    Get the tar command to use, with fallback to bundled busybox.

    This function first checks if system tar is available. If not, it falls back
    to a bundled busybox binary that includes tar functionality. This ensures
    nvdebug works on minimal systems like Amazon Linux 2 that don't include tar
    by default.

    Returns:
        str: The tar command to use (either 'tar' or path to bundled busybox tar)

    Raises:
        RuntimeError: If neither system tar nor bundled busybox is available
    """
    # First, try system tar
    if shutil.which("tar"):
        logger.debug("Using system tar command")
        return "tar"

    # Fall back to bundled busybox
    base = get_base_path()
    bundled_busybox = str(base / "bin" / "busybox")
    if os.path.exists(bundled_busybox) and os.access(bundled_busybox, os.X_OK):
        logger.debug(f"Using bundled busybox tar: {bundled_busybox}")
        return f"{bundled_busybox} tar"

    # If running from source (development), look for busybox in project
    dev_busybox = os.path.join(os.path.dirname(__file__), "..", "..", "bin", "busybox")
    if os.path.exists(dev_busybox) and os.access(dev_busybox, os.X_OK):
        logger.debug(f"Using development busybox tar: {dev_busybox}")
        return f"{dev_busybox} tar"

    # No tar available
    error_msg = (
        "tar command not available. Neither system tar nor bundled busybox found. "
        "Please install tar on your system: "
        "Amazon Linux: 'yum install tar', "
        "Ubuntu/Debian: 'apt-get install tar', "
        "SUSE: 'zypper install tar'"
    )
    logger.error(error_msg)
    raise RuntimeError(error_msg)


def build_tar_create_command(
    output_file: str,
    source_paths: list,
    dereference_symlinks: bool = True,
    change_dir: Optional[str] = None,
    use_sudo: bool = False,
) -> str:
    """
    Build a tar creation command with proper options.

    Args:
        output_file: Output tar.gz file path
        source_paths: List of source files/directories to archive
        dereference_symlinks: If True, follow symlinks (tar -h flag)
        change_dir: If specified, change to this directory before archiving (tar -C)
        use_sudo: If True, prepend sudo to the command

    Returns:
        str: Complete tar command string
    """
    tar_cmd = get_tar_command()

    # Build tar options
    options = "-czf"  # Always create gzipped archive
    if dereference_symlinks:
        options = f"-h {options}"

    # Build command
    if change_dir:
        cmd = f"cd {shlex.quote(change_dir)} && {tar_cmd} {options} {shlex.quote(output_file)}"
    else:
        cmd = f"{tar_cmd} {options} {shlex.quote(output_file)}"

    # Add source paths
    for path in source_paths:
        cmd += f" {shlex.quote(path)}"

    # Add sudo if requested
    if use_sudo and not cmd.startswith("sudo"):
        cmd = f"sudo {cmd}"

    return cmd
