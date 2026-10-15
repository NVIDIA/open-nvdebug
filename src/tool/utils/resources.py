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
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Optional, Tuple

from .frozen_path import get_base_path, is_frozen
from .resource_manager import ResourceManager

_CONFIG_FILENAMES = ("dut_config.yaml", "config.yaml")
_ALL_CONFIG_FILENAMES = (*_CONFIG_FILENAMES, "tool_config.yaml")
_MAX_UID = (1 << 32) - 1

CONFIG_DISCOVERY_TRUST_HELP = (
    "Auto-detection ignores symlinked config files, group-writable or "
    "world-writable files/directories, and paths with untrusted owners. "
    "Use --dut-config/-d and --config/-c to select intentional shared files, "
    "or place regular configs in a trusted directory without group/other "
    "write permission on the files or their non-sticky parent directories."
)


def _trusted_owner_ids(environment: Mapping[str, str] | None = None) -> frozenset[int]:
    """
    Return owners trusted for this invocation, including a sudo caller.

    The filesystem-root owner is an authority for the namespace even when a user
    namespace maps that owner to an overflow UID instead of numeric zero. If
    that owner is untrusted, it can replace top-level paths independently of
    this discovery policy.

    Args:
        environment: Optional environment; ``None`` selects the function's
            default behavior.

    Returns:
        The unique trusted owner identifiers returned by the operation.
    """

    trusted = {0, os.getuid(), os.geteuid()}
    try:
        root_info = Path("/").stat()
    except OSError:
        root_info = None
    if (
        root_info is not None
        and stat.S_ISDIR(root_info.st_mode)
        and not _is_group_or_other_writable(root_info.st_mode)
    ):
        trusted.add(root_info.st_uid)
    source = os.environ if environment is None else environment
    sudo_uid = source.get("SUDO_UID", "")
    if (
        os.geteuid() == 0
        and isinstance(sudo_uid, str)
        and sudo_uid.isascii()
        and sudo_uid.isdecimal()
        and len(sudo_uid) <= 10
    ):
        parsed_uid = int(sudo_uid)
        if parsed_uid <= _MAX_UID:
            trusted.add(parsed_uid)
    return frozenset(trusted)


def _is_group_or_other_writable(mode: int) -> bool:
    """
    Return whether ``mode`` is group or other writable.

    After applying local validation, the function forwards ``mode`` to ``bool``
    and preserves its return and exception contract.

    Args:
        mode: Numeric mode used while the operation performs bounded accounting.

    Returns:
        Whether ``mode`` is group or other writable.
    """
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def _record_discovery_rejection(
    path: Path, reason: str, rejections: list[str] | None
) -> None:
    """
    Append a metadata-only reason when a discovery caller requests diagnostics.

    Silent callers retain the same return contract. Quoting the path keeps
    control characters in a filename from becoming diagnostic line breaks.

    Args:
        path: File or directory responsible for the failed trust check.
        reason: Explanation derived from filesystem metadata, never file contents.
        rejections: Caller-owned destination, or ``None`` for silent validation.

    Side Effects:
        Appends one reason to the supplied list without changing the filesystem.
    """
    if rejections is not None:
        rejections.append(f"{str(path)!r}: {reason}")


def trusted_discovered_directory(
    path: Path, *, rejections: list[str] | None = None
) -> Path | None:
    """
    Resolve an implicit directory only when its path chain is trusted.

    Every directory owner can make that directory writable, so every owner in
    the resolved chain must be trusted. A trusted sticky shared root such as
    /tmp may contain a private child; any other group/other-writable ancestor
    permits an unrelated user to replace descendants.

    Args:
        path: filesystem location used as the path for this operation.
        rejections: Optional caller-owned list receiving the failed trust check.

    Returns:
        The validated ``resolved``, or ``None`` when no value qualifies.
    """

    try:
        resolved = Path(path).expanduser().resolve(strict=True)
        info = resolved.stat()
    except (OSError, RuntimeError):
        return None
    trusted_owners = _trusted_owner_ids()
    if not stat.S_ISDIR(info.st_mode):
        _record_discovery_rejection(resolved, "not a directory", rejections)
        return None
    if info.st_uid not in trusted_owners:
        _record_discovery_rejection(
            resolved, f"directory owner UID {info.st_uid} is not trusted", rejections
        )
        return None
    if _is_group_or_other_writable(info.st_mode):
        _record_discovery_rejection(
            resolved,
            f"directory is group- or other-writable (mode {stat.S_IMODE(info.st_mode):04o})",
            rejections,
        )
        return None

    # Every directory owner can make that directory writable, so every owner
    # in the resolved chain must be trusted. A trusted sticky shared root such
    # as /tmp may contain a private child; any other group/other-writable
    # ancestor permits an unrelated user to replace descendants.
    for ancestor in resolved.parents:
        try:
            ancestor_info = ancestor.stat()
        except OSError:
            return None
        if ancestor_info.st_uid not in trusted_owners:
            _record_discovery_rejection(
                ancestor,
                f"ancestor directory owner UID {ancestor_info.st_uid} is not trusted",
                rejections,
            )
            return None
        if (
            _is_group_or_other_writable(ancestor_info.st_mode)
            and not ancestor_info.st_mode & stat.S_ISVTX
        ):
            _record_discovery_rejection(
                ancestor,
                "ancestor directory is group- or other-writable "
                f"(mode {stat.S_IMODE(ancestor_info.st_mode):04o})",
                rejections,
            )
            return None
    return resolved


def trusted_discovered_file(
    path: Path, *, private: bool = False, rejections: list[str] | None = None
) -> Path | None:
    """
    Resolve an implicit regular file from a trusted containing directory.

    ``private`` additionally rejects group/other read and execute bits. It is
    suitable for credential-only files; ordinary configuration discovery needs
    integrity while retaining compatibility with read-only packaged defaults.

    Args:
        path: filesystem location used as the path for this operation.
        private: Whether private is enabled or required for this operation.
        rejections: Optional caller-owned list receiving the failed trust check.

    Returns:
        The validated ``resolved``, or ``None`` when no value qualifies.
    """

    try:
        expanded = Path(path).expanduser()
        visible = expanded.lstat()
        if stat.S_ISLNK(visible.st_mode):
            _record_discovery_rejection(
                expanded, "config file is a symlink", rejections
            )
            return None
        resolved = expanded.resolve(strict=True)
        info = resolved.stat()
    except (OSError, RuntimeError):
        return None
    if not stat.S_ISREG(info.st_mode):
        _record_discovery_rejection(resolved, "not a regular file", rejections)
        return None
    if (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)) != (
        visible.st_dev,
        visible.st_ino,
        stat.S_IFMT(visible.st_mode),
    ):
        _record_discovery_rejection(resolved, "file identity changed", rejections)
        return None
    if info.st_uid not in _trusted_owner_ids():
        _record_discovery_rejection(
            resolved, f"file owner UID {info.st_uid} is not trusted", rejections
        )
        return None
    forbidden_bits = 0o077 if private else (stat.S_IWGRP | stat.S_IWOTH)
    if info.st_mode & forbidden_bits:
        _record_discovery_rejection(
            resolved,
            (
                "private file permits group/other access"
                if private
                else "config file is group- or other-writable"
            )
            + f" (mode {stat.S_IMODE(info.st_mode):04o})",
            rejections,
        )
        return None
    if trusted_discovered_directory(resolved.parent, rejections=rejections) is None:
        return None
    return resolved


def find_config_directory() -> Path:
    """
    Find the config directory using multiple search strategies.

    The implementation uses current instance state to find the config directory
    using multiple search strategies. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle.

    Returns:
        The validated config directory filesystem path.
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

    # Implicit discovery must not select a directory another local user can
    # replace. Deliberately shared locations remain available through explicit
    # command-line paths, which follow their own validation boundary.
    for path in search_locations:
        try:
            trusted = trusted_discovered_directory(path)
            if trusted is not None:
                return trusted
        except (OSError, PermissionError):
            continue

    # Never return an untrusted current directory as an implicit creation root.
    return Path.home() / ".nvdebug" / "config"


def _discover_config_file(
    path: Path, rejections: dict[Path, str] | None
) -> Path | None:
    """
    Apply the shared trust guard and optionally retain a candidate's rejection.

    Missing candidates are ordinary search misses. Only an explicit reason
    from the trust guard is retained, so absence never becomes permission advice.

    Args:
        path: Candidate config whose metadata may be inspected, never its contents.
        rejections: Optional caller-owned mapping from candidate to first reason.

    Returns:
        Trusted file path, or ``None`` for an absent or rejected candidate.

    Side Effects:
        Records rejected candidates once even when search roots overlap.
    """
    if rejections is None:
        return trusted_discovered_file(path)
    reasons: list[str] = []
    result = trusted_discovered_file(path, rejections=reasons)
    if reasons:
        rejections.setdefault(path.absolute(), reasons[0])
    return result


def _find_config_files(
    filenames: Tuple[str, ...], *, rejections: dict[Path, str] | None = None
) -> Tuple[Optional[Path], ...]:
    """
    Discover trusted operator configuration before packaged defaults.

    External search roots retain their established order. Frozen extraction
    files are fallback templates, so they cannot hide an operator's DUT targets
    or tool settings. Source-tree discovery is limited to development runs;
    catalog/resource discovery uses its separate package-integrity boundary.
    Installed wheels keep defaults in the package's ``default_config`` directory;
    these templates are consulted only after all operator search roots.

    Args:
        filenames: Configuration basenames to resolve independently.
        rejections: Optional mapping receiving rejected candidates and their causes.

    Returns:
        One trusted path or ``None`` per requested basename, in input order.
    """
    search_locations = []

    frozen = is_frozen()

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

    # Development source roots are not operator configuration in a frozen build.
    if not frozen:
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

    # Packaged defaults must not shadow the real targets/settings in external
    # trusted files, including CWD. Do not change catalog discovery precedence.
    if frozen:
        search_locations.append(get_base_path())

    config_paths: list[Optional[Path]] = [None] * len(filenames)

    # Find first existing files in order of preference
    for search_dir in search_locations:
        try:
            trusted_dir = trusted_discovered_directory(search_dir)
            if trusted_dir is None and rejections is None:
                continue

            for index, filename in enumerate(filenames):
                if config_paths[index] is not None:
                    continue

                # Diagnostics may inspect metadata below an untrusted root,
                # but selection still requires the complete file/ancestor guard.
                candidate = _discover_config_file(
                    (trusted_dir or search_dir) / filename, rejections
                )
                if candidate is not None:
                    config_paths[index] = candidate

            # If we found all requested files, we can stop searching
            if all(path is not None for path in config_paths):
                break

        except (OSError, PermissionError):
            continue

    # Strategy 8: Try to find config files as package resources (using ResourceManager)
    # Note: ModuleNotFoundError can occur when running from source (src.tool vs tool)
    for index, filename in enumerate(filenames):
        if config_paths[index] is not None:
            continue

        for resource_name in (f"default_config/{filename}", filename):
            try:
                config_paths[index] = _discover_config_file(
                    Path(ResourceManager.get_resource_path("tool", resource_name)),
                    rejections,
                )
            except (FileNotFoundError, ModuleNotFoundError):
                continue
            if config_paths[index] is not None:
                break

    return tuple(config_paths)


def config_discovery_failure_details(*, include_tool: bool = True) -> str:
    """
    Explain existing rejected configs when the CLI reports a missing target.

    Recheck metadata with the same search order and trust guards as discovery.
    This diagnostic does not select a new configuration, read file contents,
    or change permissions. Absent candidates produce no permission advice.

    Args:
        include_tool: Include tool candidates only when no explicit tool locator
            was selected by CLI or environment.

    Returns:
        A leading-newline explanation with recovery options, or an empty string
        when no existing candidate has an identifiable trust rejection.
    """
    rejections: dict[Path, str] = {}
    filenames = _ALL_CONFIG_FILENAMES if include_tool else ("dut_config.yaml",)
    _find_config_files(filenames, rejections=rejections)
    if not rejections:
        return ""
    lines = ["", "", "Configuration files rejected by automatic discovery:"]
    for path, reason in rejections.items():
        lines.extend((f"  {str(path)!r}", f"    Reason: {reason}"))
    lines.extend(
        (
            "Select the intended files explicitly with --dut-config/-d and --config/-c,",
            "or correct the reported ownership/permissions and use regular, non-symlink",
            "configs in trusted directories before relying on automatic discovery.",
        )
    )
    return "\n".join(lines)


def find_config_files() -> Tuple[Optional[Path], Optional[Path]]:
    """
    Find config files.

    The implementation uses current instance state to find config files.

    Returns:
        A tuple containing ``DUT config path`` and ``config path`` in that
        order.
    """
    dut_config_path, config_path = _find_config_files(_CONFIG_FILENAMES)
    return dut_config_path, config_path


def find_all_config_files() -> Tuple[Optional[Path], Optional[Path], Optional[Path]]:
    """
    Find all config files.

    The implementation uses current instance state to find all config files.

    Returns:
        A tuple containing ``DUT config path``, ``config path``, and ``tool
        config path`` in that order.
    """
    dut_config_path, config_path, tool_config_path = _find_config_files(
        _ALL_CONFIG_FILENAMES
    )
    return dut_config_path, config_path, tool_config_path
