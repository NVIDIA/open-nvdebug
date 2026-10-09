#!/usr/bin/env python3
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
File-transfer operations executed over caller-owned DUT sessions.

This module owns the dut file transfer boundary and exposes ``RuntimeLogger``,
``BMCTransferRequest``, ``BoundedBMCDownloadResult``, and ``DUTFileTransfer``.
Keeping those contracts together gives importers one source of truth for their
validation, lifecycle, and compatibility behavior.
"""

import os
import shlex
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from ..utils.runtime_boundary_profile import runtime_boundary_value
from ..utils.sftp_safety import (
    SFTPTransferSafetyError,
    bounded_transfer_progress_handler,
    discard_unsafe_local_path,
    prepare_local_destination,
    require_regular_remote_file,
    verify_local_regular_file,
)


class RuntimeLogger(Protocol):
    """
    Logging surface required by the transfer component.

    Implementations provide ``log_runtime`` while preserving the ownership,
    validation, and asynchronous behavior stated by the interface.
    """

    async def log_runtime(
        self,
        level: str,
        component: str,
        message: str,
    ) -> None:
        """
        Log runtime.

        The implementation uses ``level``, ``component``, and ``message`` to log
        runtime. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            level: Text supplied as level in the format accepted by this
                function.
            component: Text supplied as component in the format accepted by this
                function.
            message: Operator-facing text carried by the reported event or
                failure.
        """
        ...


TransferMethod = Literal["SFTP", "SCP"]
BoundedBMCDownloadTransport = Literal["SFTP", "SSH exec stream"]
SCPTransfer = Callable[..., Awaitable[Any]]


@dataclass(frozen=True)
class BMCTransferRequest:
    """
    One BMC file operation using the existing facade path contract.

    The immutable record keeps ``source``, ``destination_directory``,
    ``copy_to_destination``, and ``max_download_bytes`` together so consumers
    observe one BMC transfer request state. Consumers receive the fields as one
    unit instead of assembling partial state.

    Attributes:
        source: Canonical text used as source.
        destination_directory: Canonical text used as destination directory.
        copy_to_destination: Whether copy to destination applies to this record.
        max_download_bytes: Maximum download bytes admitted by this record.
    """

    source: str
    destination_directory: str
    copy_to_destination: bool
    max_download_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class BoundedBMCDownloadResult:
    """
    Receipt for one bounded binary download from a BMC.

    The receipt keeps byte accounting coupled to the transport which actually
    published the artifact. Consumers can therefore distinguish a direct SFTP
    transfer from the narrowly admitted SSH exec-stream recovery without
    inferring transport state from exception text or log messages.

    Attributes:
        bytes_transferred: Exact number of bytes published locally.
        transport_method: Binary transport which published the artifact.
    """

    bytes_transferred: int
    transport_method: BoundedBMCDownloadTransport


class DUTFileTransfer:
    """
    Transfer files over an injected SSH session without owning that session.

    Connection creation, retry timing, proxy ownership, and connection cleanup
    remain with :class:`DUTManager`. This component owns only the per-session
    BMC transfer operation and its established SFTP-to-SCP fallback order.
    """

    def __init__(
        self,
        *,
        logger: RuntimeLogger,
        scp: SCPTransfer,
        max_transfer_bytes: int | None = None,
    ) -> None:
        """
        Initialize a ``DUTFileTransfer`` instance.

        Bound a device-supplied download. Callers with a resolved DUT pass that
        baseboard's BMC ceiling on each request; this fallback preserves the
        governed default for direct/legacy component callers.

        Args:
            logger: Sanitized logger used for operator-visible diagnostics.
            scp: Scp consumed while the function attempts to initialize a
                ``DUTFileTransfer`` instance.
            max_transfer_bytes: Upper bound enforced for max transfer bytes; the
                consuming boundary rejects or truncates values that exceed it.
        """
        self._logger = logger
        self._scp = scp
        # Bound a device-supplied download. Callers with a resolved DUT pass
        # that baseboard's BMC ceiling on each request; this fallback preserves
        # the governed default for direct/legacy component callers.
        self._max_transfer_bytes = (
            runtime_boundary_value({}, "bmc_transfer_max_file_bytes")
            if max_transfer_bytes is None
            else max_transfer_bytes
        )

    async def transfer_bmc_file(
        self,
        connection: Any,
        request: BMCTransferRequest,
    ) -> TransferMethod:
        """
        Transfer one BMC file, trying SFTP before SCP on the same session.

        A device-supplied symlink must never be reproduced on the operator
        workstation; sftp.get does not resolve one by default, so reject
        anything that is not a regular file.

        Args:
            connection: Connection object whose ``start_sftp_client`` state is
                read while performing transfer one BMC file, trying SFTP before
                SCP on the same session.
            request: Transport request governed by the configured authentication
                and trust policy.

        Returns:
            A ``TransferMethod`` representing transfer BMC file.

        Raises:
            SFTPTransferSafetyError: If the remote or local object violates the
                configured transfer safety policy, or an unsafe partial local
                path cannot be removed after a failed fallback.
        """

        file_name = os.path.basename(request.source)
        remote_path = f"{request.destination_directory}/{file_name}"
        scp_remote_path = shlex.quote(remote_path)
        max_transfer_bytes = (
            self._max_transfer_bytes
            if request.max_download_bytes is None
            else request.max_download_bytes
        )

        try:
            async with connection.start_sftp_client() as sftp:
                if request.copy_to_destination:
                    await sftp.put(request.source, remote_path)
                    await self._logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Transferred {request.source} to {remote_path} via SFTP",
                    )
                else:
                    # A device-supplied symlink must never be reproduced on the
                    # operator workstation; sftp.get does not resolve one by
                    # default, so reject anything that is not a regular file.
                    prepare_local_destination(request.source)
                    transfer_size = await require_regular_remote_file(
                        sftp, remote_path, max_bytes=max_transfer_bytes
                    )
                    try:
                        await sftp.get(
                            remote_path,
                            request.source,
                            preserve=False,
                            recurse=False,
                            follow_symlinks=False,
                            progress_handler=bounded_transfer_progress_handler(
                                source=remote_path,
                                max_bytes=max_transfer_bytes,
                                expected_size=transfer_size,
                            ),
                        )
                        verify_local_regular_file(
                            request.source,
                            expected_size=transfer_size,
                            max_bytes=max_transfer_bytes,
                        )
                    except BaseException as transfer_error:
                        try:
                            discard_unsafe_local_path(request.source)
                        except SFTPTransferSafetyError as cleanup_error:
                            raise cleanup_error from transfer_error
                        raise
                    await self._logger.log_runtime(
                        "INFO",
                        "DUTManager",
                        f"Transferred {remote_path} to {request.source} via SFTP",
                    )
            return "SFTP"
        except SFTPTransferSafetyError:
            # A rejected remote object must not be retried over SCP: the
            # fallback would re-open the same primitive this guard closed.
            raise
        except Exception as sftp_error:
            await self._logger.log_runtime(
                "DEBUG",
                "DUTManager",
                f"SFTP failed ({sftp_error}), trying SCP fallback",
            )

            if request.copy_to_destination:
                await self._scp(request.source, (connection, scp_remote_path))
                await self._logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"Transferred {request.source} to {remote_path} via SCP",
                )
            else:
                probed_size: int | None = None
                try:
                    async with connection.start_sftp_client() as sftp_probe:
                        probed_size = await require_regular_remote_file(
                            sftp_probe,
                            remote_path,
                            max_bytes=max_transfer_bytes,
                        )
                except SFTPTransferSafetyError:
                    # A probe that affirmatively identifies an unsafe object is
                    # authoritative even though the transfer uses SCP.
                    raise
                except Exception:
                    # Some devices expose SCP without an SFTP subsystem. The
                    # callback and post-transfer checks remain authoritative in
                    # that compatibility case.
                    probed_size = None
                prepare_local_destination(request.source)
                expected_size = probed_size
                progress_observed = False

                def enforce_scp_progress(
                    _source: Any,
                    _destination: Any,
                    bytes_copied: int,
                    total_bytes: int,
                ) -> None:
                    """
                    Abort a fallback download before it crosses its budget.

                    The synchronous AsyncSSH progress callback validates each
                    reported counter and preserves the first declared size for
                    final local-file verification.

                    Args:
                        _source: AsyncSSH source identifier; unused because the
                            owning request already supplies the trusted path.
                        _destination: AsyncSSH destination identifier; unused
                            because the owning request supplies the local path.
                        bytes_copied: Number of bytes copied so far.
                        total_bytes: Remote size declared for this transfer.

                    Raises:
                        SFTPTransferSafetyError: If a counter is invalid, the
                            declared size changes, or the transfer exceeds its
                            configured byte budget.
                    """

                    nonlocal expected_size, progress_observed
                    progress_observed = True
                    for label, value in (
                        ("bytes copied", bytes_copied),
                        ("declared size", total_bytes),
                    ):
                        if (
                            isinstance(value, bool)
                            or not isinstance(value, int)
                            or value < 0
                        ):
                            raise SFTPTransferSafetyError(
                                f"SCP reported an invalid {label} for {remote_path}"
                            )
                    if bytes_copied > total_bytes:
                        raise SFTPTransferSafetyError(
                            f"SCP reported {bytes_copied} bytes copied from a "
                            f"{total_bytes} byte file"
                        )
                    if (
                        bytes_copied > max_transfer_bytes
                        or total_bytes > max_transfer_bytes
                    ):
                        raise SFTPTransferSafetyError(
                            f"Remote path {remote_path} is above the "
                            f"{max_transfer_bytes} byte ceiling"
                        )
                    if expected_size is None:
                        expected_size = total_bytes
                    elif expected_size != total_bytes:
                        raise SFTPTransferSafetyError(
                            f"SCP changed the declared size for {remote_path}"
                        )

                try:
                    await self._scp(
                        (connection, scp_remote_path),
                        request.source,
                        preserve=False,
                        recurse=False,
                        progress_handler=enforce_scp_progress,
                    )
                    if not progress_observed:
                        raise SFTPTransferSafetyError(
                            f"SCP transfer of {remote_path} sent no file record"
                        )
                    verify_local_regular_file(
                        request.source,
                        expected_size=expected_size,
                        max_bytes=max_transfer_bytes,
                    )
                except BaseException as transfer_error:
                    try:
                        discard_unsafe_local_path(request.source)
                    except SFTPTransferSafetyError as cleanup_error:
                        raise cleanup_error from transfer_error
                    raise
                await self._logger.log_runtime(
                    "INFO",
                    "DUTManager",
                    f"Transferred {remote_path} to {request.source} via SCP",
                )
            return "SCP"
