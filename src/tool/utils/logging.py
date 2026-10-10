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
Logging and secure output-directory utilities for NVDebug Tool.

This module creates the mutable base directory and timestamped run directory
used during tool startup. Every pathname component is opened without following
symlinks, pinned by descriptor, and revalidated before a pathname is returned.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

from ..utils.filesystem_identity import filesystem_owner_uid

_DIRECTORY_MODE: Final = 0o700
_SHARED_READ_DIRECTORY_MODE: Final = 0o755
_UNSAFE_WRITE_BITS: Final = stat.S_IWGRP | stat.S_IWOTH
_SECURE_DIRECTORY_APIS_AVAILABLE: Final = bool(
    hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "geteuid")
    and os.open in os.supports_dir_fd
    and os.mkdir in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
)


class OutputDirectorySecurityError(OSError):
    """
    Raised when an output directory cannot be established safely.

    Callers receive this exception when the output directory security error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


@dataclass
class _PinnedDirectoryChain:
    """
    Hold no-follow descriptors for every component of an absolute path.

    The descriptor chain keeps each ancestor alive while pathname identity and
    ownership checks run. Callers must invoke :meth:`close` when validation is
    complete.

    Attributes:
        path: Validated filesystem location associated with path.
        descriptors: Collection of descriptors entries retained by this record.
        component_names: Collection of component names entries retained by this
            record.
        allow_external_path_owners: Whether the collection boundary permits
            safe or sticky path components owned by another UID.
    """

    path: Path
    descriptors: list[int]
    component_names: list[str]
    allow_external_path_owners: bool

    @property
    def directory_fd(self) -> int:
        """
        Return the descriptor for the final directory component.

        Each access computes the value from ``descriptors`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            The numeric directory fd value.
        """

        return self.descriptors[-1]

    def close(self) -> None:
        """
        Close every held descriptor in child-to-parent order.

        The implementation uses current instance state to close every held
        descriptor in child-to-parent order.
        """

        for descriptor in reversed(self.descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _supports_secure_directory_operations() -> bool:
    """
    Return whether the platform exposes the required openat-style APIs.

    The implementation uses current instance state to determine whether the
    platform exposes the required openat-style APIs.

    Returns:
        Whether the platform exposes the required openat-style APIs.
    """

    return _SECURE_DIRECTORY_APIS_AVAILABLE


def _directory_open_flags() -> int:
    """
    Return flags for a close-on-exec, no-follow directory descriptor.

    The implementation uses current instance state to produce flags for a
    close-on-exec, no-follow directory descriptor.

    Returns:
        The numeric directory open flags value.
    """

    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _verify_open_component(
    parent_fd: int,
    component_name: str,
    component_fd: int,
) -> os.stat_result:
    """
    Verify that an opened directory is still the named no-follow entry.

    The implementation uses ``parent_fd``, ``component_name``, and
    ``component_fd`` to verify that an opened directory is still the named
    no-follow entry. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path. Filesystem effects remain confined to the caller-selected paths and
    the owning resource lifecycle.

    Args:
        parent_fd: Numeric parent fd used while the operation performs bounded
            accounting.
        component_name: Stable component name used for lookup and
            operator-facing diagnostics.
        component_fd: Numeric component fd used while the operation performs
            bounded accounting.

    Returns:
        The validated ``opened``.

    Raises:
        OutputDirectorySecurityError: If output path contains a non-directory;
            or output directory changed while it was being opened.
    """

    opened = os.fstat(component_fd)
    named = os.stat(component_name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(opened.st_mode) or not stat.S_ISDIR(named.st_mode):
        raise OutputDirectorySecurityError("Output path contains a non-directory")
    if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
        raise OutputDirectorySecurityError(
            "Output directory changed while it was being opened"
        )
    return opened


def _verify_trusted_ancestor(
    directory_stat: os.stat_result,
    *,
    root_owner_uid: int,
    component_path: Path,
    allow_external_path_owners: bool = False,
) -> None:
    """
    Require safe permissions and an allowed owner for one output ancestor.

    A user-namespaced host root can appear as an overflow UID. The owner of the
    pinned filesystem root is authoritative for this descriptor walk. A
    collection output boundary may opt into trusting the owner of an existing
    path component. Such an externally owned component must either grant no
    group or other write access or use sticky-bit replacement protection.
    Non-sticky shared-writable components remain untrusted because users other
    than the selected owner could replace active output entries.

    Args:
        directory_stat: Descriptor metadata for the ancestor being validated.
        root_owner_uid: Owner of the pinned filesystem root and the authority
            used for user-namespace-aware system ownership.
        component_path: Absolute lexical path for the pinned component, used in
            operator-facing diagnostics.
        allow_external_path_owners: Whether the collection output boundary may
            trust existing path components owned by another UID.

    Raises:
        OutputDirectorySecurityError: If output path contains a non-directory;
            output path contains a disallowed foreign-owned ancestor; or output
            path contains a group- or world-writable non-sticky ancestor.
    """

    if not stat.S_ISDIR(directory_stat.st_mode):
        raise OutputDirectorySecurityError("Output path contains a non-directory")

    effective_uid = os.geteuid()
    mode = stat.S_IMODE(directory_stat.st_mode)
    is_sticky_shared_directory = bool(directory_stat.st_mode & stat.S_ISVTX)
    if mode & _UNSAFE_WRITE_BITS and not is_sticky_shared_directory:
        raise OutputDirectorySecurityError(
            "Output path contains a group- or world-writable non-sticky ancestor: "
            f"path='{component_path}', owner_uid={directory_stat.st_uid}, "
            f"mode={mode:04o}, effective_uid={effective_uid}"
        )

    trusted_owner = directory_stat.st_uid in {0, root_owner_uid, effective_uid}
    if not trusted_owner and not allow_external_path_owners:
        raise OutputDirectorySecurityError(
            "Output path contains an ancestor not owned by root or the effective "
            f"user: path='{component_path}', owner_uid={directory_stat.st_uid}, "
            f"mode={mode:04o}, effective_uid={effective_uid}"
        )


def _repair_trusted_output_component_permissions(
    component_fd: int,
    directory_stat: os.stat_result,
    *,
    root_owner_uid: int,
    component_path: Path,
    permission_repairs: list[tuple[Path, int, int]] | None,
    allow_external_path_owners: bool,
) -> os.stat_result:
    """
    Safely harden one trusted-owner component in a pinned output chain.

    Existing QA and automation workspaces are commonly created beneath
    ``/tmp`` with a cooperative ``umask 002``. Once the parent chain has been
    verified, adding the sticky bit preserves that shared-write contract while
    preventing another user from replacing entries owned by the invoking user.
    The mutable run directory created below the selected base remains
    owner-controlled. Permission changes use the already pinned no-follow
    descriptor and are re-read before the path is accepted.

    Args:
        component_fd: Pinned descriptor for the directory being secured.
        directory_stat: Metadata captured from ``component_fd`` before repair.
        root_owner_uid: Owner of the pinned filesystem root and the authority
            used for user-namespace-aware system ownership.
        component_path: Absolute lexical path used for diagnostics and repair
            reporting.
        permission_repairs: Optional collection that receives path, previous
            mode, and resulting mode records for user-facing warnings.
        allow_external_path_owners: Whether this collection boundary accepts
            verified filesystem UID mapping when authorizing permission repair.

    Returns:
        Descriptor metadata after any required permission repair.

    Raises:
        OSError: If descriptor metadata or permissions cannot be changed.
        OutputDirectorySecurityError: If the component has an untrusted owner,
            cannot be changed through its pinned descriptor, or remains
            shared-writable without sticky-bit protection after repair.

    Side Effects:
        May add sticky-bit protection to a trusted-owner directory.
    """

    previous_mode = stat.S_IMODE(directory_stat.st_mode)
    shared_writable = bool(previous_mode & _UNSAFE_WRITE_BITS)
    already_sticky = bool(directory_stat.st_mode & stat.S_ISVTX)
    repair_required = shared_writable and not already_sticky
    if not repair_required:
        return directory_stat

    trusted_owners = {0, root_owner_uid, os.geteuid()}
    if directory_stat.st_uid not in trusted_owners and allow_external_path_owners:
        trusted_owners.add(
            filesystem_owner_uid(
                component_fd,
                observed_uid=directory_stat.st_uid,
                allow_shared_writable_parent=True,
            )
        )
    if directory_stat.st_uid not in trusted_owners:
        raise OutputDirectorySecurityError(
            "Cannot safely adjust shared-writable output path component with an "
            f"untrusted owner: path='{component_path}', "
            f"owner_uid={directory_stat.st_uid}, mode={previous_mode:04o}, "
            f"effective_uid={os.geteuid()}"
        )

    requested_mode = previous_mode | stat.S_ISVTX
    try:
        os.fchmod(component_fd, requested_mode)
    except OSError as error:
        raise OutputDirectorySecurityError(
            "Could not automatically secure shared-writable output path "
            f"component '{component_path}': {error}"
        ) from error
    repaired_stat = os.fstat(component_fd)
    repaired_mode = stat.S_IMODE(repaired_stat.st_mode)
    repair_succeeded = repaired_mode == requested_mode and (
        repaired_stat.st_dev,
        repaired_stat.st_ino,
        repaired_stat.st_uid,
        repaired_stat.st_gid,
    ) == (
        directory_stat.st_dev,
        directory_stat.st_ino,
        directory_stat.st_uid,
        directory_stat.st_gid,
    )
    if not repair_succeeded:
        raise OutputDirectorySecurityError(
            f"Could not secure shared-writable output path component: {component_path}"
        )

    if permission_repairs is not None:
        permission_repairs.append((component_path, previous_mode, repaired_mode))
    return repaired_stat


def _verify_pinned_chain(chain: _PinnedDirectoryChain) -> None:
    """
    Revalidate pathname identity and ancestor trust for a pinned chain.

    The implementation uses ``chain`` to revalidate pathname identity and
    ancestor trust for a pinned chain.

    Args:
        chain: Chain object whose ``component_names`` and ``descriptors`` state
            is read while performing revalidate pathname identity and ancestor
            trust for a pinned chain.

    Raises:
        OSError: If a named component can no longer be inspected.
        OutputDirectorySecurityError: If identity, type, ownership, or ancestor
            permissions no longer satisfy the output-path policy.
    """

    root_stat = os.fstat(chain.descriptors[0])
    root_owner_uid = root_stat.st_uid
    _verify_trusted_ancestor(
        root_stat,
        root_owner_uid=root_owner_uid,
        component_path=Path(os.sep),
        allow_external_path_owners=chain.allow_external_path_owners,
    )
    component_path = Path(os.sep)
    for index, component_name in enumerate(chain.component_names):
        component_path /= component_name
        opened = _verify_open_component(
            chain.descriptors[index],
            component_name,
            chain.descriptors[index + 1],
        )
        if index < len(chain.component_names) - 1:
            _verify_trusted_ancestor(
                opened,
                root_owner_uid=root_owner_uid,
                component_path=component_path,
                allow_external_path_owners=chain.allow_external_path_owners,
            )


def _open_directory_chain(
    base_folder: str,
    *,
    create: bool,
    create_mode: int = _DIRECTORY_MODE,
    repair_existing_permissions: bool = False,
    permission_repairs: list[tuple[Path, int, int]] | None = None,
    allow_external_path_owners: bool = False,
) -> _PinnedDirectoryChain:
    """
    Open an absolute directory path component-by-component without symlinks.

    Newly created components receive an explicit post-creation mode so a
    permissive process umask cannot turn a caller-selected output namespace
    into a writable shared directory. When compatibility repair is enabled,
    trusted-owner writable components are hardened in parent-to-child order
    through their pinned descriptors before validation continues.

    Args:
        base_folder: Text supplied as base folder in the format accepted by this
            function.
        create: Whether create is enabled or required for this operation.
        create_mode: Exact permission mode applied to components created by
            this call.
        repair_existing_permissions: Whether recoverable trusted-owner
            permissions should be secured instead of rejected.
        permission_repairs: Optional collection populated with path, previous
            mode, and resulting mode records for repaired components.
        allow_external_path_owners: Whether the collection output boundary may
            trust safe or sticky existing path components owned by another UID.

    Returns:
        A ``_PinnedDirectoryChain`` representing open directory chain.

    Raises:
        OutputDirectorySecurityError: If secure output directories require
            O_DIRECTORY, O_NOFOLLOW, and dir_fd support; or the filesystem root
            cannot be used as the mutable output directory.
    """

    if not _supports_secure_directory_operations():
        raise OutputDirectorySecurityError(
            "Secure output directories require O_DIRECTORY, O_NOFOLLOW, "
            "and dir_fd support"
        )

    base_path = Path(os.path.abspath(os.fspath(base_folder)))
    component_names = list(base_path.parts[1:])
    if not component_names:
        raise OutputDirectorySecurityError(
            "The filesystem root cannot be used as the mutable output directory"
        )

    descriptors = [os.open(os.sep, _directory_open_flags())]
    opened_names: list[str] = []
    try:
        root_stat = os.fstat(descriptors[0])
        root_owner_uid = root_stat.st_uid
        _verify_trusted_ancestor(
            root_stat,
            root_owner_uid=root_owner_uid,
            component_path=Path(os.sep),
            allow_external_path_owners=allow_external_path_owners,
        )
        component_path = Path(os.sep)
        for index, component_name in enumerate(component_names):
            component_path /= component_name
            parent_fd = descriptors[-1]
            created = False
            try:
                component_fd = os.open(
                    component_name,
                    _directory_open_flags(),
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component_name, create_mode, dir_fd=parent_fd)
                    created = True
                except FileExistsError:
                    # A concurrent creator won the race. The no-follow open and
                    # identity checks below decide whether it is acceptable.
                    pass
                component_fd = os.open(
                    component_name,
                    _directory_open_flags(),
                    dir_fd=parent_fd,
                )

            descriptors.append(component_fd)
            opened_names.append(component_name)
            if created:
                os.fchmod(component_fd, create_mode)
            opened = _verify_open_component(parent_fd, component_name, component_fd)
            is_leaf = index == len(component_names) - 1
            if repair_existing_permissions and not created:
                opened = _repair_trusted_output_component_permissions(
                    component_fd,
                    opened,
                    root_owner_uid=root_owner_uid,
                    component_path=component_path,
                    permission_repairs=permission_repairs,
                    allow_external_path_owners=allow_external_path_owners,
                )
            if not is_leaf:
                _verify_trusted_ancestor(
                    opened,
                    root_owner_uid=root_owner_uid,
                    component_path=component_path,
                    allow_external_path_owners=allow_external_path_owners,
                )
    except Exception:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise

    return _PinnedDirectoryChain(
        path=base_path,
        descriptors=descriptors,
        component_names=opened_names,
        allow_external_path_owners=allow_external_path_owners,
    )


def _verify_private_mutable_directory(
    directory_fd: int,
    *,
    component_path: Path,
) -> os.stat_result:
    """
    Require a directory owned and writable only by the effective user.

    The implementation uses ``directory_fd`` to require a directory owned and
    writable only by the effective user. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        directory_fd: Numeric directory fd used while the operation performs
            bounded accounting.
        component_path: Absolute lexical path used in operator-facing
            diagnostics.

    Returns:
        The validated ``directory_stat``.

    Raises:
        OutputDirectorySecurityError: If output path is not a directory; the
            output directory is not owned by the effective user; output
            directory must not be group- or world-writable; or output directory
            owner must have read, write, and execute permissions.
    """

    directory_stat = os.fstat(directory_fd)
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise OutputDirectorySecurityError("Output path is not a directory")
    effective_uid = os.geteuid()
    mode = stat.S_IMODE(directory_stat.st_mode)
    if directory_stat.st_uid != effective_uid:
        raise OutputDirectorySecurityError(
            "Output directory must be owned by the effective user: "
            f"path='{component_path}', owner_uid={directory_stat.st_uid}, "
            f"mode={mode:04o}, effective_uid={effective_uid}"
        )

    if mode & _UNSAFE_WRITE_BITS:
        raise OutputDirectorySecurityError(
            "Output directory must not be group- or world-writable: "
            f"path='{component_path}', owner_uid={directory_stat.st_uid}, "
            f"mode={mode:04o}, effective_uid={effective_uid}"
        )
    if mode & stat.S_IRWXU != stat.S_IRWXU:
        raise OutputDirectorySecurityError(
            "Output directory owner must have read, write, and execute permissions: "
            f"path='{component_path}', owner_uid={directory_stat.st_uid}, "
            f"mode={mode:04o}, effective_uid={effective_uid}"
        )
    return directory_stat


def _verify_run_directory(
    directory_stat: os.stat_result,
    *,
    component_path: Path,
    expected_owner_uid: int,
    expected_mode: int,
) -> None:
    """
    Require the selected read policy and verified filesystem ownership for a run.

    Validate metadata from the pinned run descriptor after creation and again
    before returning its pathname. Include the run path, reported owner UID,
    effective UID, and mode in failures so filesystem identity mapping can be
    diagnosed without confusing the run with an externally owned ancestor.

    Args:
        directory_stat: Descriptor metadata already checked against the named
            run entry for inode identity and directory type.
        component_path: Absolute lexical path identifying the rejected run in
            operator-facing diagnostics.
        expected_owner_uid: UID measured for caller-created files on this
            filesystem, or the effective UID under strict local ownership.
        expected_mode: Exact owner-writable mode selected at creation: 0700 for
            private output or 0755 for ordinary readable collection output.

    Raises:
        OutputDirectorySecurityError: If created run directory is not owned by
            the effective user or its mode differs from the selected policy.
    """

    effective_uid = os.geteuid()
    mode = stat.S_IMODE(directory_stat.st_mode)
    context = (
        f"path='{component_path}', owner_uid={directory_stat.st_uid}, "
        f"mode={mode:04o}, effective_uid={effective_uid}"
    )
    if expected_owner_uid != effective_uid:
        context += f", filesystem_owner_uid={expected_owner_uid}"
    if directory_stat.st_uid != expected_owner_uid:
        raise OutputDirectorySecurityError(
            "Created run directory is not owned by the effective user: " + context
        )
    if mode != expected_mode:
        raise OutputDirectorySecurityError(
            f"Created run directory does not have mode {expected_mode:04o}: " + context
        )


def _verify_run_parent_directory(
    chain: _PinnedDirectoryChain,
    *,
    allow_shared_writable: bool,
) -> None:
    """
    Allow a private, sticky, or opted-in external-owner run parent.

    Private effective-user directories retain their complete owner-mode check.
    A collection boundary which accepts external owners may use a safe
    directory owned by another UID; the caller's subsequent write operation
    still proves that filesystem permissions or ACLs permit the requested use.
    Sticky shared directories are accepted only when the caller will create a
    private run leaf. Direct append and streaming output must not expose fixed
    artifact names to pre-creation by unrelated directory users.

    Args:
        chain: Chain object whose ``descriptors`` and ``directory_fd`` state is
            read while performing allow a private base or trusted sticky
            directory for a new run leaf.
        allow_shared_writable: Whether sticky-bit replacement protection is
            sufficient because the caller will create a private run leaf.

    Raises:
        OutputDirectorySecurityError: If the parent ownership or mode is outside
            the selected collection output policy.
    """

    try:
        _verify_private_mutable_directory(
            chain.directory_fd,
            component_path=chain.path,
        )
        return
    except OutputDirectorySecurityError as private_error:
        directory_stat = os.fstat(chain.directory_fd)
        root_owner_uid = os.fstat(chain.descriptors[0]).st_uid
        _verify_trusted_ancestor(
            directory_stat,
            root_owner_uid=root_owner_uid,
            component_path=chain.path,
            allow_external_path_owners=chain.allow_external_path_owners,
        )
        mode = stat.S_IMODE(directory_stat.st_mode)
        shared_writable = bool(mode & _UNSAFE_WRITE_BITS)
        if shared_writable and not allow_shared_writable:
            raise OutputDirectorySecurityError(
                "Direct output directory must not be group- or world-writable: "
                f"path='{chain.path}', owner_uid={directory_stat.st_uid}, "
                f"mode={mode:04o}, effective_uid={os.geteuid()}"
            )
        if chain.allow_external_path_owners and directory_stat.st_uid != os.geteuid():
            return
        if not allow_shared_writable or not directory_stat.st_mode & stat.S_ISVTX:
            raise private_error


def ensure_secure_log_directory(
    base_folder: str,
    *,
    shared_read: bool = False,
    repair_existing_permissions: bool = False,
    allow_sticky_run_parent: bool = False,
    permission_repairs: list[tuple[Path, int, int]] | None = None,
    allow_external_path_owners: bool = False,
) -> str:
    """
    Create or validate a private mutable output directory without symlinks.

    Missing components are private by default. A selected output namespace may
    instead request traversal and read access for a separate report server.
    Existing components normally must already satisfy the same policy. A
    collection caller may secure recoverable trusted-owner shared components
    through their pinned descriptors and may explicitly accept safe or sticky
    components owned by another UID. A mutable run created beneath that
    namespace remains owner-only.

    Args:
        base_folder: Text supplied as base folder in the format accepted by this
            function.
        shared_read: Whether newly created components must be traversable and
            readable by a separate read-only report server.
        repair_existing_permissions: Whether safely recoverable permissions
            should be repaired instead of rejected.
        allow_sticky_run_parent: Whether a trusted sticky shared directory may
            be used as the parent of a subsequently created private run leaf.
            This does not permit callers to mutate files directly in that
            shared directory.
        permission_repairs: Optional collection populated with path, previous
            mode, and resulting mode records for repaired components.
        allow_external_path_owners: Whether the collection output boundary may
            trust safe or sticky existing components owned by another UID.
            A shared-writable selected base additionally requires
            ``allow_sticky_run_parent``.

    Returns:
        The canonical ensure secure log directory text.

    Raises:
        OSError: If a required component cannot be opened or created.
        OutputDirectorySecurityError: If pathname identity, ownership, or mode
            does not satisfy the private output-directory policy.
    """

    create_mode = _SHARED_READ_DIRECTORY_MODE if shared_read else _DIRECTORY_MODE
    chain = _open_directory_chain(
        base_folder,
        create=True,
        create_mode=create_mode,
        repair_existing_permissions=repair_existing_permissions,
        permission_repairs=permission_repairs,
        allow_external_path_owners=allow_external_path_owners,
    )
    try:
        _verify_pinned_chain(chain)
        if (
            repair_existing_permissions
            or allow_sticky_run_parent
            or allow_external_path_owners
        ):
            _verify_run_parent_directory(
                chain,
                allow_shared_writable=allow_sticky_run_parent,
            )
        else:
            _verify_private_mutable_directory(
                chain.directory_fd,
                component_path=chain.path,
            )
        return str(chain.path)
    finally:
        chain.close()


def create_timestamped_log_dir(
    base_folder: str,
    *,
    shared_read: bool = True,
    repair_existing_permissions: bool = False,
    permission_repairs: list[tuple[Path, int, int]] | None = None,
    allow_external_path_owners: bool = False,
) -> str:
    """
    Create one write-protected timestamped run directory beneath a trusted base.

    After applying local validation, the function forwards ``base_folder`` to
    ``str`` and preserves its return and exception contract. Filesystem effects
    remain confined to the caller-selected paths and the owning resource
    lifecycle. Cleanup in the ``finally`` path runs for successful, failed, and
    cancelled execution.

    Args:
        base_folder: Text supplied as base folder in the format accepted by this
            function.
        shared_read: Whether new output directories are readable and traversable
            during collection, matching the normal 2.1.0 output behavior. False
            selects private 0700 directories for callers handling private data.
        repair_existing_permissions: Whether safely recoverable permissions
            should be repaired before the run directory is created.
        permission_repairs: Optional collection populated with path, previous
            mode, and resulting mode records for repaired components.
        allow_external_path_owners: Whether the collection output boundary may
            trust safe or sticky existing components, including the selected
            output base, when they are owned by another UID.

    Returns:
        The canonical timestamped log dir text.

    Raises:
        IOError: If could not create log folder.
    """

    base_mode = _SHARED_READ_DIRECTORY_MODE if shared_read else _DIRECTORY_MODE
    chain = _open_directory_chain(
        base_folder,
        create=True,
        create_mode=base_mode,
        repair_existing_permissions=repair_existing_permissions,
        permission_repairs=permission_repairs,
        allow_external_path_owners=allow_external_path_owners,
    )
    leaf_fd: int | None = None
    try:
        _verify_pinned_chain(chain)
        _verify_run_parent_directory(chain, allow_shared_writable=True)
        base_name = f"nvdebug_logs_{datetime.now().strftime('%d_%m_%Y_%H_%M_%S')}"

        for retry in range(101):
            leaf_name = base_name if retry == 0 else f"{base_name}_{retry - 1}"
            try:
                os.mkdir(leaf_name, base_mode, dir_fd=chain.directory_fd)
            except FileExistsError:
                continue

            leaf_fd = os.open(
                leaf_name,
                _directory_open_flags(),
                dir_fd=chain.directory_fd,
            )
            os.fchmod(leaf_fd, base_mode)
            leaf_stat = _verify_open_component(
                chain.directory_fd,
                leaf_name,
                leaf_fd,
            )
            try:
                expected_owner_uid = (
                    filesystem_owner_uid(leaf_fd, observed_uid=leaf_stat.st_uid)
                    if allow_external_path_owners
                    else os.geteuid()
                )
            except OSError as error:
                raise OutputDirectorySecurityError(
                    "Could not verify created run directory ownership: "
                    f"path='{chain.path / leaf_name}', owner_uid={leaf_stat.st_uid}, "
                    f"mode={stat.S_IMODE(leaf_stat.st_mode):04o}, "
                    f"effective_uid={os.geteuid()}: {error}"
                ) from error
            _verify_run_directory(
                leaf_stat,
                component_path=chain.path / leaf_name,
                expected_owner_uid=expected_owner_uid,
                expected_mode=base_mode,
            )

            # Detect replacement of the output base or an ancestor before the
            # descriptors are released and a pathname is returned.
            _verify_pinned_chain(chain)
            _verify_run_parent_directory(chain, allow_shared_writable=True)
            leaf_stat = _verify_open_component(
                chain.directory_fd,
                leaf_name,
                leaf_fd,
            )
            _verify_run_directory(
                leaf_stat,
                component_path=chain.path / leaf_name,
                expected_owner_uid=expected_owner_uid,
                expected_mode=base_mode,
            )
            return str(chain.path / leaf_name)
        raise IOError("Could not create log folder")
    finally:
        if leaf_fd is not None:
            os.close(leaf_fd)
        chain.close()
