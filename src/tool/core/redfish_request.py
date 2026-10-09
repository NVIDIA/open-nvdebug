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
Typed Redfish request bodies with explicit capture and replay semantics.

This module owns the redfish request boundary and exposes
``NonReplayableJSONBody``, ``SensitiveMultipartTextField``, and
``SensitiveMultipartBody``. Keeping those contracts together gives importers one
source of truth for their validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, BinaryIO, Callable, Dict, Mapping, Optional, Tuple

import aiohttp


@dataclass(frozen=True)
class NonReplayableJSONBody:
    """
    JSON action payload that must not be automatically submitted twice.

    The immutable record keeps ``payload`` and ``replay_safe`` together so
    consumers observe one non replayable JSON body state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        payload: Mapping that retains the payload fields for this record.
        replay_safe: Whether replay safe applies to this record.
    """

    payload: Mapping[str, Any]
    replay_safe: bool = field(default=False, init=False)

    def capture_value(self) -> Dict[str, Any]:
        """
        Capture value.

        After applying local validation, the function forwards current instance
        state to ``dict`` and preserves its return and exception contract.

        Returns:
            A mapping containing capture value.
        """
        return dict(self.payload)


@dataclass(frozen=True)
class SensitiveMultipartTextField:
    """
    One ordered non-file field carried inside a sensitive multipart body.

    The immutable record keeps ``name``, ``value``, ``filename``, and
    ``content_type`` together so consumers observe one sensitive multipart text
    field state. Consumers receive the fields as one unit instead of assembling
    partial state.

    Attributes:
        name: Canonical text used as name.
        value: Canonical text used as value.
        filename: Canonical text used as filename.
        content_type: Canonical text used as content type.
    """

    name: str
    value: str = field(repr=False)
    filename: str
    content_type: str


@dataclass(frozen=True)
class SensitiveMultipartBody:
    """
    One multipart file upload whose contents must never be logged.

    A fresh form and file handle are constructed for each HTTP attempt. The file
    is revalidated against the preflight size and digest before bytes are handed
    to aiohttp. ``replay_safe`` is deliberately false because callers use this
    body for state-mutating uploads that cannot be retried safely.

    Attributes:
        file_path: Validated filesystem location associated with file path.
        size_bytes: Byte count recorded for size.
        sha256: Lowercase SHA-256 digest binding the SHA-256 content.
        blocking_runner: Blocking runner retained as part of the record's public
            state.
        field_name: Canonical text used as field name.
        remote_filename: Canonical text used as remote filename.
        content_type: Canonical text used as content type.
        text_fields_before_file: Collection of text fields before file entries
            retained by this record.
        text_fields_after_file: Collection of text fields after file entries
            retained by this record.
        sensitive: Whether sensitive applies to this record.
        replay_safe: Whether replay safe applies to this record.
    """

    file_path: Path = field(repr=False)
    size_bytes: int
    sha256: str = field(repr=False)
    blocking_runner: Optional[Callable[..., Awaitable[Any]]] = field(
        default=None,
        repr=False,
        compare=False,
    )
    field_name: str = "File"
    remote_filename: str = "payload.bin"
    content_type: str = "application/octet-stream"
    text_fields_before_file: Tuple[SensitiveMultipartTextField, ...] = ()
    text_fields_after_file: Tuple[SensitiveMultipartTextField, ...] = ()
    sensitive: bool = field(default=True, init=False)
    replay_safe: bool = field(default=False, init=False)

    def safe_summary(self) -> Dict[str, Any]:
        """
        Return the only representation allowed in logs and artifacts.

        The implementation uses current instance state to produce the only
        representation allowed in logs and artifacts.

        Returns:
            A mapping containing the ``kind``, ``fields``, ``filename``,
            ``content_type``, and ``size_bytes`` fields.
        """
        ordered_fields = [field.name for field in self.text_fields_before_file]
        ordered_fields.append(self.field_name)
        ordered_fields.extend(field.name for field in self.text_fields_after_file)
        return {
            "kind": "multipart",
            "fields": ordered_fields,
            "filename": self.remote_filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "content": "omitted",
        }

    def build(self) -> Tuple[aiohttp.FormData, BinaryIO]:
        """
        Build a one-shot form after checking the file did not change.

        The implementation uses current instance state to build a one-shot form
        after checking the file did not change. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        If the function cannot build a one-shot form after checking the file did
        not change, its exception reaches the caller instead of being converted
        into a successful result.

        Returns:
            A tuple containing ``form`` and ``handle`` in that order.

        Raises:
            OSError: If an owned resource fails while the function attempts to
                build a one-shot form after checking the file did not change.
            ValueError: If sensitive source is not a regular file; sensitive
                source changed size after preflight; or sensitive source changed
                after preflight.
        """
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.file_path, flags)
        except OSError as exc:
            raise OSError(
                exc.errno, "sensitive source is unavailable or unsafe"
            ) from None
        handle = os.fdopen(fd, "rb")
        try:
            file_stat = os.fstat(handle.fileno())
            if not stat.S_ISREG(file_stat.st_mode):
                raise ValueError("sensitive source is not a regular file")
            if file_stat.st_size != self.size_bytes:
                raise ValueError("sensitive source changed size after preflight")

            digest = hashlib.sha256()
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
            if digest.hexdigest() != self.sha256:
                raise ValueError("sensitive source changed after preflight")
            handle.seek(0)

            form = aiohttp.FormData()
            for text_field in self.text_fields_before_file:
                form.add_field(
                    text_field.name,
                    text_field.value,
                    filename=text_field.filename,
                    content_type=text_field.content_type,
                )
            form.add_field(
                self.field_name,
                handle,
                filename=self.remote_filename,
                content_type=self.content_type,
            )
            for text_field in self.text_fields_after_file:
                form.add_field(
                    text_field.name,
                    text_field.value,
                    filename=text_field.filename,
                    content_type=text_field.content_type,
                )
            return form, handle
        except Exception:
            handle.close()
            raise

    @staticmethod
    def _close_aborted_build(result: Any) -> None:
        """
        Close a retained file handle when an owned runner is interrupted.

        The implementation uses ``result`` to close a retained file handle when
        an owned runner is interrupted.

        Args:
            result: Mapping supplying fields for close a retained file handle
                when an owned runner is interrupted.
        """
        if not isinstance(result, tuple) or len(result) != 2:
            return
        handle = result[1]
        close = getattr(handle, "close", None)
        if callable(close):
            close()

    async def build_off_loop(self) -> Tuple[aiohttp.FormData, BinaryIO]:
        """
        Build through the caller's bounded, cancellation-owned worker.

        After applying local validation, the function forwards current instance
        state to ``self.blocking_runner`` and preserves its return and exception
        contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Returns:
            A tuple containing the fields that represent off loop.

        Raises:
            RuntimeError: If sensitive multipart body has no owned blocking
                runner.
        """
        if self.blocking_runner is None:
            raise RuntimeError("sensitive multipart body has no owned blocking runner")
        return await self.blocking_runner(
            self.build,
            _owned_result_cleanup=self._close_aborted_build,
        )

    def __str__(self) -> str:
        """
        Return the display representation of the SensitiveMultipartBody.

        The implementation uses current instance state to produce the display
        representation of the SensitiveMultipartBody.

        Returns:
            The canonical str text.
        """
        return "<sensitive multipart body omitted>"
