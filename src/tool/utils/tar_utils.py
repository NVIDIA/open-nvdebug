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
Tar utility functions with bundled fallback for systems without tar.

This module owns the tar utils boundary and exposes ``_tar_command_argv``,
``get_tar_command``, ``build_tar_create_command``,
``build_remote_tar_hardlink_probe_command``, ``build_remote_tar_create_command``,
and ``build_link_safe_tar_create_command``.
Keeping those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

import logging
import os
import posixpath
import shlex
import shutil
import sys
from typing import Optional

from .command_safety import (
    TRUSTED_POSIX_SHELL_PATH,
    TRUSTED_PRIVILEGED_PATH,
    build_privileged_command_argv,
)
from .frozen_path import get_base_path

logger = logging.getLogger(__name__)

_TRUSTED_POSIX_TAR_CANDIDATES = ("/usr/bin/tar", "/bin/tar")
TRUSTED_REMOTE_TAR_COMMAND = "tar"


def _tar_command_argv(command: str) -> list[str]:
    """
    Parse the supported TAR executable forms without accepting shell syntax.

    The implementation uses ``command`` to parse the supported TAR executable
    forms without accepting shell syntax. Parsing or I/O must finish before the
    validated representation is made available to the caller. If the function
    cannot parse the supported TAR executable forms without accepting shell
    syntax, its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        command: Text supplied as command in the format accepted by this
            function.

    Returns:
        The TAR command argument vector returned in operation-defined order.

    Raises:
        ValueError: If the tar_command is not a nonempty NUL-free string;
            tar_command contains invalid shell quoting; or tar_command must name
            TAR or a BusyBox TAR applet.
    """

    if not isinstance(command, str) or not command or "\x00" in command:
        raise ValueError("tar_command must be a nonempty NUL-free string")
    # An explicitly supplied executable path may itself contain whitespace.
    # get_tar_command() quotes bundled paths, while direct callers commonly
    # supply a real wrapper path in tests and local-only integrations.
    if os.path.isfile(command):
        return [command]
    try:
        arguments = shlex.split(command)
    except ValueError as exc:
        raise ValueError("tar_command contains invalid shell quoting") from exc
    if len(arguments) == 1:
        return arguments
    if len(arguments) == 2 and arguments[1] == "tar":
        return arguments
    raise ValueError("tar_command must name TAR or a BusyBox TAR applet")


def get_tar_command() -> str:
    """
    Get the tar command to use, with fallback to bundled busybox.

    This function first checks if system tar is available. If not, it falls back
    to a bundled busybox binary that includes tar functionality. This ensures
    nvdebug works on minimal systems like Amazon Linux 2 that don't include tar
    by default.

    Returns:
        The canonical TAR command text.

    Raises:
        RuntimeError: If the function cannot get the tar command to use, with
            fallback to bundled busybox safely.
    """
    # POSIX privilege paths must not depend on a caller-controlled PATH. Keep
    # Windows' platform resolver behavior because its system tar location is
    # not governed by the POSIX filesystem layout.
    if os.name == "posix":
        for candidate in _TRUSTED_POSIX_TAR_CANDIDATES:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                logger.debug("Using trusted system tar command: %s", candidate)
                return candidate
    else:
        system_tar = shutil.which("tar")
        if system_tar:
            logger.debug("Using system tar command: %s", system_tar)
            return system_tar

    # Fall back to bundled busybox
    base = get_base_path()
    bundled_busybox = str(base / "bin" / "busybox")
    if os.path.exists(bundled_busybox) and os.access(bundled_busybox, os.X_OK):
        logger.debug(f"Using bundled busybox tar: {bundled_busybox}")
        return shlex.join([bundled_busybox, "tar"])

    # If running from source (development), look for busybox in project
    dev_busybox = os.path.join(os.path.dirname(__file__), "..", "..", "bin", "busybox")
    if os.path.exists(dev_busybox) and os.access(dev_busybox, os.X_OK):
        logger.debug(f"Using development busybox tar: {dev_busybox}")
        return shlex.join([dev_busybox, "tar"])

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
    dereference_symlinks: bool = False,
    change_dir: Optional[str] = None,
    use_sudo: bool = False,
) -> str:
    """
    Build a tar creation command with proper options.

    The implementation uses ``output_file``, ``source_paths``,
    ``dereference_symlinks``, ``change_dir``, and ``use_sudo`` to build a tar
    creation command with proper options. If the function cannot build a tar
    creation command with proper options, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        output_file: filesystem location used as the output file for this
            operation.
        source_paths: Filesystem locations processed in caller-provided order.
        dereference_symlinks: Whether dereference symlinks is enabled or
            required for this operation.
        change_dir: Optional filesystem location used as the change dir for this
            operation.
        use_sudo: Whether use sudo is enabled or required for this operation.

    Returns:
        The validated ``cmd``.

    Raises:
        ValueError: If the output_file is not a nonempty NUL-free string;
            source_paths must contain nonempty strings; the change_dir is not a
            nonempty NUL-free string; or dereference_symlinks is unsafe without
            a root-bound traversal policy; or another input invariant is
            violated.
        RuntimeError: If privileged tar lacks an approved absolute system
            executable.
    """
    if not isinstance(output_file, str) or not output_file or "\x00" in output_file:
        raise ValueError("output_file must be a nonempty NUL-free string")
    if not source_paths or any(
        not isinstance(path, str) or not path for path in source_paths
    ):
        raise ValueError("source_paths must contain nonempty strings")
    if change_dir is not None and (
        not isinstance(change_dir, str) or not change_dir or "\x00" in change_dir
    ):
        raise ValueError("change_dir must be a nonempty NUL-free string")
    if dereference_symlinks:
        raise ValueError(
            "dereference_symlinks is unsafe without a root-bound traversal policy"
        )
    tar_arguments = _tar_command_argv(get_tar_command())
    if use_sudo and (
        os.name != "posix"
        or len(tar_arguments) != 1
        or tar_arguments[0] not in _TRUSTED_POSIX_TAR_CANDIDATES
    ):
        raise RuntimeError(
            "privileged TAR requires an approved absolute system executable"
        )
    tar_cmd = shlex.join(tar_arguments)

    # TAR's default traversal archives a symbolic link as a link and does not
    # open its target. Never add ``-h``/``--dereference`` here: endpoint-writable
    # collection trees may contain links to files outside the selected roots.
    options = "-czf"  # Always create gzipped archive

    # Build command
    if change_dir:
        cmd = (
            f"cd -- {shlex.quote(change_dir)} && {tar_cmd} {options} "
            f"{shlex.quote(output_file)}"
        )
    else:
        cmd = f"{tar_cmd} {options} {shlex.quote(output_file)}"

    # Prefix relative operands and place them after an option terminator so a
    # catalog-controlled name such as ``-I`` cannot become a TAR option.
    normalized_sources = []
    for path in source_paths:
        if "\x00" in path:
            raise ValueError("source_paths cannot contain NUL bytes")
        normalized = posixpath.normpath(path)
        if normalized == ".." or normalized.startswith("../"):
            raise ValueError("source_paths cannot escape change_dir")
        normalized_sources.append(
            normalized
            if posixpath.isabs(normalized) or normalized == "."
            else f"./{normalized}"
        )
    cmd += " -- " + " ".join(shlex.quote(path) for path in normalized_sources)

    # Add sudo if requested
    if use_sudo:
        privileged_argv, _password_stdin = build_privileged_command_argv(
            cmd,
            password_available=False,
            use_shell=True,
        )
        cmd = shlex.join(privileged_argv)

    return cmd


def build_remote_tar_hardlink_probe_command(
    *, tar_command: Optional[str] = None
) -> str:
    """
    Build a silent remote probe for TAR hard-link materialization support.

    The caller owns the bounded transport and interprets the process status.
    Keeping this probe separate lets callers retain capability advisories locally
    without adding informational commands to the remote archive producer.

    Args:
        tar_command: Optional TAR executable or BusyBox TAR applet command.

    Returns:
        A quoted shell command whose status is the TAR capability probe status.

    Raises:
        ValueError: If the TAR executable form contains invalid quoting or NUL.
    """
    tar_cmd = shlex.join(_tar_command_argv(tar_command or TRUSTED_REMOTE_TAR_COMMAND))
    script = (
        f"PATH={TRUSTED_PRIVILEGED_PATH}\nexport PATH\n"
        f"{tar_cmd} --hard-dereference --help >/dev/null 2>&1"
    )
    return f"{TRUSTED_POSIX_SHELL_PATH} -c {shlex.quote(script)}"


def _build_remote_tar_create_command(
    output_file: str,
    source_paths: list[str],
    *,
    tar_command: Optional[str] = None,
    change_dir: Optional[str] = None,
    use_sudo: bool = False,
    materialize_symbolic_links: bool,
    hardlink_dereference_supported: Optional[bool] = None,
) -> str:
    """
    Build a quoted remote TAR command for one fixed symbolic-link behavior.

    Public wrappers select whether TAR receives ``-h``. Keeping that selection
    inside this module prevents catalog data and runtime callers from changing
    the BMC file-transfer behavior while allowing other remote producers to
    retain the no-follow builder required by their contracts.

    Args:
        output_file: filesystem location used as the output file for this
            operation.
        source_paths: Filesystem locations processed in caller-provided order.
        tar_command: Optional TAR command; ``None`` selects the function's
            default behavior.
        change_dir: Optional filesystem location used as the change dir for this
            operation.
        use_sudo: Whether TAR reads the source through passwordless sudo. The
            caller-owned shell still creates the output file, so privilege is
            never extended to the staging artifact or its parent directory.
        materialize_symbolic_links: Whether TAR follows symbolic links while
            reading the selected source paths.
        hardlink_dereference_supported: A caller-observed capability result, or
            ``None`` to probe silently in the generated command.

    Returns:
        The canonical remote TAR create command text.

    Raises:
        ValueError: If the output_file is not a nonempty NUL-free string;
            source_paths must contain nonempty strings; the change_dir is not a
            nonempty NUL-free string; or source_paths cannot contain NUL bytes;
            use_sudo or materialize_symbolic_links is not a boolean; privileged
            TAR does not use an approved executable form; or another input
            invariant is violated.
    """
    if not isinstance(output_file, str) or not output_file or "\x00" in output_file:
        raise ValueError("output_file must be a nonempty NUL-free string")
    if not source_paths or any(
        not isinstance(path, str) or not path for path in source_paths
    ):
        raise ValueError("source_paths must contain nonempty strings")
    if change_dir is not None and (
        not isinstance(change_dir, str) or not change_dir or "\x00" in change_dir
    ):
        raise ValueError("change_dir must be a nonempty NUL-free string")
    if type(use_sudo) is not bool:
        raise ValueError("use_sudo must be a boolean")
    if type(materialize_symbolic_links) is not bool:
        raise ValueError("materialize_symbolic_links must be a boolean")
    if (
        hardlink_dereference_supported is not None
        and type(hardlink_dereference_supported) is not bool
    ):
        raise ValueError("hardlink_dereference_supported must be a boolean or None")

    tar_arguments = _tar_command_argv(tar_command or TRUSTED_REMOTE_TAR_COMMAND)
    tar_cmd = shlex.join(tar_arguments)
    # Prefix relative operands so TAR cannot interpret a config-controlled
    # name such as "-delete" as an option. TAR also receives an explicit
    # option terminator.
    normalized_sources = []
    for path in source_paths:
        if "\x00" in path:
            raise ValueError("source_paths cannot contain NUL bytes")
        normalized = posixpath.normpath(path)
        if normalized == ".." or normalized.startswith("../"):
            raise ValueError("source_paths cannot escape change_dir")
        absolute = posixpath.isabs(normalized)
        normalized_sources.append(
            normalized if absolute or normalized == "." else f"./{normalized}"
        )
    output = shlex.quote(output_file)
    if use_sudo:
        approved_tar_arguments = {
            (TRUSTED_REMOTE_TAR_COMMAND,),
            *((candidate,) for candidate in _TRUSTED_POSIX_TAR_CANDIDATES),
        }
        if tuple(tar_arguments) not in approved_tar_arguments:
            raise ValueError(
                "privileged remote TAR requires an approved TAR executable"
            )

        def privileged_tar_command(*, hard_dereference: bool) -> str:
            """
            Build one non-shell sudo TAR command with caller-owned redirection.

            Only the validated TAR argument vector crosses the sudo boundary.
            The surrounding unprivileged shell opens the private output path,
            preserving caller ownership and the enforced restrictive umask.

            Args:
                hard_dereference: Whether GNU TAR materializes hard-linked
                    regular files while preserving the caller's selected
                    symbolic-link policy.

            Returns:
                Shell text containing validated privileged argv followed by an
                unprivileged output redirection.
            """
            command_arguments = list(tar_arguments)
            if hard_dereference:
                command_arguments.append("--hard-dereference")
            if materialize_symbolic_links:
                command_arguments.append("-h")
            if change_dir:
                command_arguments.extend(["-C", change_dir])
            command_arguments.extend(["-czf", "-", "--", *normalized_sources])
            privileged_argv, _password_stdin = build_privileged_command_argv(
                command_arguments,
                password_available=False,
                use_shell=False,
            )
            return f"{shlex.join(privileged_argv)} > {output}"

        direct = privileged_tar_command(hard_dereference=False)
        gnu_direct = privileged_tar_command(hard_dereference=True)
        change_directory = ""
    else:
        sources = " ".join(shlex.quote(path) for path in normalized_sources)
        symlink_option = " -h" if materialize_symbolic_links else ""
        direct = f"{tar_cmd}{symlink_option} -czf {output} -- {sources}"
        # GNU ``--hard-dereference`` affects hard-linked regular files only. It
        # is intentionally retained so downstream validators do not receive
        # hard-link members; unlike ``-h``, it never follows symbolic-link
        # targets.
        gnu_direct = (
            f"{tar_cmd} --hard-dereference{symlink_option} "
            f"-czf {output} -- {sources}"
        )
        change_directory = (
            f"cd -- {shlex.quote(change_dir)} || exit 1\n" if change_dir else ""
        )

    if hardlink_dereference_supported is None:
        creation = (
            f"if {tar_cmd} --hard-dereference --help >/dev/null 2>&1; then\n"
            f"  {gnu_direct}\nelse\n  {direct}\nfi"
        )
    else:
        creation = gnu_direct if hardlink_dereference_supported else direct
    script = (
        f"PATH={TRUSTED_PRIVILEGED_PATH}\n"
        + "export PATH\n"
        + "umask 077\n"
        + change_directory
        + creation
    )
    return f"{TRUSTED_POSIX_SHELL_PATH} -c {shlex.quote(script)}"


def build_remote_tar_create_command(
    output_file: str,
    source_paths: list[str],
    *,
    tar_command: Optional[str] = None,
    change_dir: Optional[str] = None,
    use_sudo: bool = False,
    hardlink_dereference_supported: Optional[bool] = None,
) -> str:
    """
    Build a quoted BMC file-transfer TAR command that follows symbolic links.

    Every BMC file-transfer collector materializes linked diagnostic content,
    matching the behavior that preceded the no-follow hardening. The choice is
    deliberately not exposed as a collector parameter. Archive bounds,
    validation, sanitization, and truthful partial/error reporting remain the
    responsibility of the caller.

    Args:
        output_file: Filesystem location used as the output file.
        source_paths: Governed filesystem locations processed in caller order.
        tar_command: Optional TAR command; ``None`` selects remote TAR.
        change_dir: Optional directory selected before reading source operands.
        use_sudo: Whether TAR reads the source through passwordless sudo while
            the caller-owned shell creates the output file.
        hardlink_dereference_supported: Optional validated runtime capability.
            A boolean selects one TAR invocation; ``None`` retains a silent probe.

    Returns:
        The canonical symlink-dereferencing TAR create command text.

    Raises:
        ValueError: If an input violates the remote TAR command policy.
    """

    return _build_remote_tar_create_command(
        output_file,
        source_paths,
        tar_command=tar_command,
        change_dir=change_dir,
        use_sudo=use_sudo,
        materialize_symbolic_links=True,
        hardlink_dereference_supported=hardlink_dereference_supported,
    )


def build_link_safe_tar_create_command(
    output_file: str,
    source_paths: list[str],
    *,
    tar_command: Optional[str] = None,
    change_dir: Optional[str] = None,
    use_sudo: bool = False,
) -> str:
    """
    Build a quoted TAR command that never traverses symbolic links.

    This compatibility wrapper fixes the shared private builder to no-follow.
    Existing host and transport producers therefore retain their root-contained
    behavior while BMC file-transfer collectors use the dereferencing wrapper.

    Args:
        output_file: Filesystem location used as the output file.
        source_paths: Governed filesystem locations processed in caller order.
        tar_command: Optional TAR command; ``None`` selects remote TAR.
        change_dir: Optional directory selected before reading source operands.
        use_sudo: Whether TAR reads the source through passwordless sudo while
            the caller-owned shell creates the output file.

    Returns:
        The canonical no-follow TAR create command text.

    Raises:
        ValueError: If an input violates the generic remote TAR command policy.
    """

    return _build_remote_tar_create_command(
        output_file,
        source_paths,
        tar_command=tar_command,
        change_dir=change_dir,
        use_sudo=use_sudo,
        materialize_symbolic_links=False,
    )
