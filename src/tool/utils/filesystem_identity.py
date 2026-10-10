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
Shared filesystem identities for descriptor-anchored security checks.

The helper keeps directory replacement checks consistent across collection,
report, archive, and publication workflows.
"""

import os
import secrets
import stat
from pathlib import Path


def directory_security_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int]:
    """
    Return every stable security-relevant directory identity field.

    Child creation changes directory timestamps and size on some filesystems,
    so those fields cannot be part of an identity held across publication.
    Device, inode, full mode, owner, and group must remain unchanged.

    Args:
        metadata: Result from an anchored ``fstat`` or a no-follow ``stat``.

    Returns:
        Device, inode, full mode, owner UID, and owner GID in that order.
    """

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def filesystem_owner_uid(
    directory: int | str | os.PathLike[str],
    *,
    observed_uid: int,
    allow_shared_writable_parent: bool = False,
) -> int:
    """
    Resolve the current user's owner UID as reported by an output filesystem.

    Local ownership needs no additional I/O. When metadata reports another
    UID, create an exclusive private probe through a pinned directory and
    verify its bytes and identity before removing it. This measures NFS or
    namespace UID mapping without trusting the owner of an existing foreign
    inode. Callers compare their candidate with the returned UID and retain
    their existing mode, inode, link-count, and replacement checks.

    Args:
        directory: Pinned directory descriptor or path owning the candidate.
            Path components are opened without following symlinks. The caller
            must authorize writes to this output namespace.
        observed_uid: Candidate owner UID; matching the effective UID avoids
            allocating a probe on ordinary local filesystems.
        allow_shared_writable_parent: Permit the probe before repairing a
            shared directory's sticky bit. This narrow case still uses an
            unpredictable exclusive name, private mode, non-sensitive random
            bytes, and exact inode checks; replacement fails verification.

    Returns:
        The effective UID, or the owner UID reported for the verified probe.

    Raises:
        OSError: If no-follow access, private probe creation, verification, or
            exact cleanup fails, or the pinned directory changes identity.

    Side Effects:
        Temporarily creates a mode-0600 file only when ownership differs. The
        probe changes parent timestamps, so callers must resolve ownership
        before freezing a directory's content identity or inventory.
    """

    effective_uid = os.geteuid()
    if observed_uid == effective_uid:
        return effective_uid

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory_fd = -1
    probe_fd = -1
    probe_name = ""
    probe_identity: tuple[int, int] | None = None
    primary_error: BaseException | None = None
    try:
        if isinstance(directory, int):
            directory_fd = os.dup(directory)
        else:
            absolute = Path(os.path.abspath(os.fspath(directory)))
            directory_fd = os.open(absolute.anchor, flags)
            for component in absolute.parts[1:]:
                child_fd = os.open(component, flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = child_fd
        parent_before = os.fstat(directory_fd)
        if not stat.S_ISDIR(parent_before.st_mode):
            raise OSError("Filesystem ownership probe requires a directory")
        if (
            parent_before.st_mode & 0o022
            and not parent_before.st_mode & stat.S_ISVTX
            and not allow_shared_writable_parent
        ):
            raise OSError("Filesystem ownership probe requires a protected parent")

        for _attempt in range(8):
            candidate_name = f".nvdebug-owner-probe-{secrets.token_hex(18)}"
            try:
                probe_fd = os.open(
                    candidate_name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                continue
            probe_name = candidate_name
            break
        if probe_fd < 0:
            raise OSError("Could not allocate an exclusive filesystem ownership probe")
        created = os.fstat(probe_fd)
        probe_identity = (created.st_dev, created.st_ino)
        os.fchmod(probe_fd, 0o600)
        payload = secrets.token_bytes(16)
        if (
            os.write(probe_fd, payload) != len(payload)
            or os.pread(probe_fd, len(payload), 0) != payload
        ):
            raise OSError("Filesystem ownership probe did not preserve written bytes")
        opened = os.fstat(probe_fd)
        visible = os.stat(probe_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(visible.st_mode)
            or (opened.st_dev, opened.st_ino) != probe_identity
            or (visible.st_dev, visible.st_ino) != probe_identity
            or opened.st_dev != parent_before.st_dev
            or opened.st_uid != visible.st_uid
            or opened.st_uid != created.st_uid
            or opened.st_nlink != 1
            or visible.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or stat.S_IMODE(visible.st_mode) != 0o600
            or opened.st_size != len(payload)
            or visible.st_size != len(payload)
            or directory_security_identity(os.fstat(directory_fd))
            != directory_security_identity(parent_before)
            or os.geteuid() != effective_uid
        ):
            raise OSError("Filesystem ownership probe changed during verification")
        return opened.st_uid
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            if probe_fd >= 0 and probe_identity is None:
                # A transient first fstat may fail after O_EXCL created the
                # file. Recover identity only from our still-open descriptor;
                # never adopt the current pathname's inode for cleanup.
                retained = os.fstat(probe_fd)
                probe_identity = (retained.st_dev, retained.st_ino)
            if probe_identity is not None:
                try:
                    current = os.stat(
                        probe_name, dir_fd=directory_fd, follow_symlinks=False
                    )
                except FileNotFoundError:
                    pass
                else:
                    if (current.st_dev, current.st_ino) != probe_identity:
                        raise OSError(
                            "Filesystem ownership probe changed before cleanup"
                        )
                    os.unlink(probe_name, dir_fd=directory_fd)
        except OSError as error:
            if primary_error is None:
                raise
            primary_error.add_note(
                f"Filesystem ownership probe cleanup failed: {error}"
            )
        finally:
            if probe_fd >= 0:
                os.close(probe_fd)
            if directory_fd >= 0:
                os.close(directory_fd)
