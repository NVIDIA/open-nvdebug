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
Bounded Redfish artifact download, validation, and persistence.

``RedfishService`` remains the compatibility facade and owns collector
lifecycle, request capture, transport, timing, and diagnostic logging. This
module owns the artifact-specific state machine: attachment readiness, content
classification, archive format validation, immutable provenance, and final
publication.

The facade is deliberately resolved for every side effect. Existing extensions
and tests can therefore continue to replace facade seams without reaching
through this boundary, while the storage rules themselves have one owner.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import gzip
import hashlib
import io
import json
import lzma
import math
import os
import re
import stat
import struct
import tarfile
import tempfile
import time
import traceback
import zipfile
import zlib
from asyncio import Lock
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, cast

from ..utils.archive_validation import ARCHIVE_VALIDATION_SUPPORTED_SUFFIXES
from ..utils.bounded_archive import ArchiveLimits, inspect_zip_central_directory_extent
from ..utils.redfish_download import StreamedRedfishBody
from ..utils.redfish_limits import DEFAULT_REDFISH_STRUCTURED_RESPONSE_MAX_BYTES
from ..utils.strict_zstd import StrictZstdError, StrictZstdReader
from .archive_publication import (
    ArchiveContentIdentity,
    canonical_invalid_validation,
    canonical_persisted_validation,
    identity_from_bytes,
    publish_archive_no_replace,
    restore_canonical_evidence,
    stable_file_identity,
    validate_accepted_provenance,
    validation_reference,
)

# Last two bytes of the 12-byte xz stream footer ("YZ"). A well-formed
# stream always ends with it, so a payload that does not carries trailing data.
_XZ_STREAM_FOOTER_MAGIC = b"\x59\x5a"


class RedfishArtifactStore:
    """
    Persist artifacts for one lazily supplied ``RedfishService`` facade.

    The type coordinates ``render_streamed_binary_mapping``,
    ``save_streamed_binary_mapping_with_pattern``,
    ``save_data_to_file_with_pattern``, ``save_data_with_common_pattern``, and
    ``download_dump_when_ready`` and retains the state those operations share
    between calls. Resource ownership remains inside the instance until the
    matching close, exit, or cleanup operation completes.
    """

    # Compression magic bytes -> canonical archive extension. Order matters:
    # check the longest/most-specific signatures first.
    ARCHIVE_MAGICS = (
        (b"\xfd7zXZ\x00", ".tar.xz"),
        (b"\x28\xb5\x2f\xfd", ".tar.zst"),
        (b"\x1f\x8b", ".tar.gz"),
        (b"BZh", ".tar.bz2"),
        (b"PK\x03\x04", ".zip"),
    )
    ARCHIVE_PATTERN_SUFFIXES = ARCHIVE_VALIDATION_SUPPORTED_SUFFIXES
    CPER_MAGIC = b"CPER"
    CPER_BASE64_DECODE_MAX_BYTES = DEFAULT_REDFISH_STRUCTURED_RESPONSE_MAX_BYTES
    CPER_DECODE_MAX_LAYERS = 4
    CPER_PHOSPHOR_V5_PREFIX = b"\x05\x00\x00\x00"
    CPER_PHOSPHOR_MAX_ITEMS = 1024
    ARCHIVE_VALIDATION_MAX_SECONDS = 120.0
    TAR_EXTENSION_HEADER_MAX_BYTES = ArchiveLimits().max_metadata_member_bytes
    # Shared archive policy for framing checks that must reject before any
    # member is materialized: the ZIP central-directory pre-check (finding 12)
    # and the per-branch TAR member-count ceiling (finding 13).
    _ARCHIVE_LIMITS = ArchiveLimits()

    class ArchiveExpansionBudget:
        """
        Bound decompression work for one staged archive validation.

        The type coordinates ``check_deadline`` and ``charge`` and retains the
        state those operations share between calls. Resource ownership remains
        inside the instance until the matching close, exit, or cleanup operation
        completes.
        """

        def __init__(self, source: Any, *, max_seconds: float | None = None) -> None:
            """
            Initialize an ``ArchiveExpansionBudget`` instance.

            In-memory stream (no descriptor): size it by seeking to the end,
            then restore the caller's position. Without this the ratio ceiling
            could not be computed for a payload validated from bytes rather than
            from a staged file.

            Args:
                source: Source object whose ``fileno``, ``seek``, and ``tell``
                    state is read while performing initialize an
                    ``ArchiveExpansionBudget`` instance.
                max_seconds: Maximum duration in seconds allowed for max
                    seconds.
            """
            limits = ArchiveLimits()
            if isinstance(source, (str, os.PathLike)):
                input_bytes = Path(source).stat().st_size
            else:
                try:
                    input_bytes = os.fstat(source.fileno()).st_size
                except (AttributeError, OSError, io.UnsupportedOperation):
                    # In-memory stream (no descriptor): size it by seeking to
                    # the end, then restore the caller's position. Without this
                    # the ratio ceiling could not be computed for a payload
                    # validated from bytes rather than from a staged file.
                    position = source.tell()
                    source.seek(0, os.SEEK_END)
                    input_bytes = source.tell()
                    source.seek(position)
            self._input_bytes = max(input_bytes, 1)
            self._limit = int(self._input_bytes * limits.max_compression_ratio)
            self.max_seconds = (
                RedfishArtifactStore.ARCHIVE_VALIDATION_MAX_SECONDS
                if max_seconds is None
                else float(max_seconds)
            )
            self._deadline = time.monotonic() + self.max_seconds
            self._expanded = 0

        def check_deadline(self) -> None:
            """
            Check deadline.

            The implementation uses current instance state to check deadline.
            Every required invariant is checked before a successful value is
            returned; invalid input follows the function's explicit exception
            path.

            Raises:
                ValueError: If archive validation exceeded its time budget.
            """
            if time.monotonic() > self._deadline:
                raise ValueError("archive validation exceeded its time budget")

        def charge(self, amount: int) -> None:
            """
            Charge resource use against the configured budget.

            The implementation uses ``amount`` to charge resource use against
            the configured budget. It updates ``_expanded`` on the instance as
            part of that state transition. If the function cannot charge
            resource use against the configured budget, its exception reaches
            the caller instead of being converted into a successful result.

            Args:
                amount: Numeric amount used while the operation performs bounded
                    accounting.

            Raises:
                ValueError: If archive expansion exceeds the permitted
                    compression ratio: ``_expanded`` bytes from ``_input_bytes``
                    input bytes.
            """
            self._expanded += amount
            if self._expanded > self._limit:
                raise ValueError(
                    "archive expansion exceeds the permitted compression ratio: "
                    f"{self._expanded} bytes from {self._input_bytes} input bytes"
                )
            self.check_deadline()

        @property
        def input_bytes(self) -> int:
            """
            Return the input size this budget was sized against.

            Each access computes the value from ``_input_bytes`` on the
            current instance; the derived view is not stored as independent
            state. Strict decompression readers bind their own input-size
            ceiling to this value instead of a second, potentially
            inconsistent measurement.

            Returns:
                The numeric input byte count used to size this budget.
            """
            return self._input_bytes

        @property
        def remaining_bytes(self) -> int:
            """
            Return the compression-ratio allowance not yet charged.

            Each access computes the value from ``_limit`` and ``_expanded``
            on the current instance; the derived view is not stored as
            independent state. Strict decompression readers bind their own
            output-size ceiling to this value so a single oversized frame
            cannot exceed the budget before ``charge`` next observes it.

            Returns:
                The numeric remaining byte allowance, never negative.
            """
            return max(self._limit - self._expanded, 0)

    def __init__(self, facade: Any) -> None:
        """
        Initialize a ``RedfishArtifactStore`` instance.

        The initializer records ``_facade`` for later operations and establishes
        the instance invariants before any public method runs.

        Args:
            facade: Facade consumed while the function attempts to initialize a
                ``RedfishArtifactStore`` instance.
        """
        self._facade = facade

    async def render_streamed_binary_mapping(
        self,
        data: Dict[str, Any],
    ) -> StreamedRedfishBody:
        """
        Render the legacy URI-to-base64 JSON schema without buffering bodies.

        After applying local validation, the function forwards ``data`` to
        ``StreamedRedfishBody`` and preserves its return and exception contract.
        The source value keeps its ownership while the normalized representation
        is returned separately. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle.

        Args:
            data: Mapping supplying fields for legacy URI-to-base64 JSON schema
                without buffering bodies.

        Returns:
            A ``StreamedRedfishBody`` representing streamed binary mapping.

        Raises:
            ValueError: If no streamed Redfish bodies were provided; or streamed
                Redfish bodies must share private staging.
            RuntimeError: If redfish private spool accounting is unavailable.
            OSError: If streamed Redfish body changed before JSON rendering.
        """

        streamed_values = [
            value for value in data.values() if isinstance(value, StreamedRedfishBody)
        ]
        if not streamed_values:
            raise ValueError("No streamed Redfish bodies were provided")

        spool_dir = streamed_values[0].private_path.parent
        if any(value.private_path.parent != spool_dir for value in streamed_values):
            raise ValueError("Streamed Redfish bodies must share private staging")
        capacity_checker = getattr(
            self._facade.dut_manager, "_require_redfish_spool_capacity", None
        )
        if not callable(capacity_checker):
            raise RuntimeError("Redfish private spool accounting is unavailable")

        descriptor, temporary_name = tempfile.mkstemp(
            prefix="binary-map-",
            suffix=".json.part",
            dir=spool_dir,
        )
        temporary_path = Path(temporary_name)
        digest = hashlib.sha256()
        prefix = bytearray()
        size_bytes = 0

        def write_checked(output_file: Any, payload: bytes) -> None:
            """
            Write checked.

            The implementation uses ``output_file`` and ``payload`` to write
            checked. Success is reported only after the owning output boundary
            has completed its required write or publication step.

            Args:
                output_file: filesystem location used as the output file for
                    this operation.
                payload: Bounded byte sequence supplied as payload.
            """
            nonlocal size_bytes
            if not payload:
                return
            capacity_checker(spool_dir, len(payload))
            output_file.write(payload)
            digest.update(payload)
            size_bytes += len(payload)
            if len(prefix) < 512:
                prefix.extend(payload[: 512 - len(prefix)])

        def encode_bounded_value(value: Any) -> str:
            """
            Encode bounded value.

            After applying local validation, the function forwards ``value`` to
            ``json.dumps`` and preserves its return and exception contract.

            Args:
                value: Value evaluated while performing encode bounded value.

            Returns:
                The canonical bounded value.
            """

            def encode_binary_json_value(binary_value: Any) -> Dict[str, Any]:
                """
                Encode binary JSON value.

                The implementation uses ``binary_value`` to encode binary JSON
                value. If the function cannot encode binary JSON value, its
                exception reaches the caller instead of being converted into a
                successful result.

                Args:
                    binary_value: Binary value consumed while the function
                        attempts to encode binary JSON value.

                Returns:
                    A mapping containing the ``encoding``, ``length``, and
                    ``value`` fields.

                Raises:
                    TypeError: If object of type ``__name__`` is not JSON
                        serializable.
                """
                if isinstance(binary_value, (bytes, bytearray)):
                    payload = bytes(binary_value)
                    return {
                        "encoding": "base64",
                        "length": len(payload),
                        "value": base64.b64encode(payload).decode("ascii"),
                    }
                raise TypeError(
                    f"Object of type {type(binary_value).__name__} "
                    "is not JSON serializable"
                )

            return json.dumps(value, indent=2, default=encode_binary_json_value)

        try:
            with os.fdopen(descriptor, "wb") as output_file:
                descriptor = -1
                write_checked(output_file, b"{")
                for index, (uri, value) in enumerate(data.items()):
                    write_checked(output_file, b",\n" if index else b"\n")
                    write_checked(
                        output_file,
                        ("  " + json.dumps(str(uri)) + ": ").encode("utf-8"),
                    )
                    if isinstance(value, StreamedRedfishBody):
                        write_checked(
                            output_file,
                            (
                                "{\n"
                                '    "encoding": "base64",\n'
                                f'    "length": {value.size_bytes},\n'
                                '    "value": "'
                            ).encode("utf-8"),
                        )
                        # 768 KiB is divisible by three, so independently
                        # encoding full chunks cannot insert early padding.
                        source_digest = hashlib.sha256()
                        source_size = 0
                        with value.open() as source_file:
                            while True:
                                source_chunk = source_file.read(768 * 1024)
                                if not source_chunk:
                                    break
                                source_digest.update(source_chunk)
                                source_size += len(source_chunk)
                                write_checked(
                                    output_file, base64.b64encode(source_chunk)
                                )
                                await asyncio.sleep(0)
                        if (
                            source_size != value.size_bytes
                            or source_digest.hexdigest() != value.sha256
                        ):
                            raise OSError(
                                "Streamed Redfish body changed before JSON rendering"
                            )
                        write_checked(output_file, b'"\n  }')
                    else:
                        sanitized_value = value
                        facade_logger = getattr(self._facade, "logger", None)
                        if facade_logger:
                            structured_sanitizer = getattr(
                                facade_logger,
                                "_sanitize_collector_json_value",
                                None,
                            )
                            if callable(structured_sanitizer):
                                sanitized_value, _changed = structured_sanitizer(value)
                        rendered = encode_bounded_value(sanitized_value).replace(
                            "\n", "\n  "
                        )
                        write_checked(output_file, rendered.encode("utf-8"))
                write_checked(output_file, b"\n}")
                output_file.flush()
                os.fsync(output_file.fileno())

            return StreamedRedfishBody(
                temporary_path,
                size_bytes=size_bytes,
                sha256=digest.hexdigest(),
                prefix_bytes=bytes(prefix),
                content_type="application/json",
            )
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            raise

    async def save_streamed_binary_mapping_with_pattern(
        self,
        *,
        dut_id: str,
        data: Dict[str, Any],
        function_tag: str,
        output_pattern: str,
        substitutions: Dict[str, Any],
        collector_id: str,
        request_timing_operation_ids: Optional[Union[str, List[str]]] = None,
    ) -> Optional[str]:
        """
        Atomically publish the legacy additional-data JSON artifact.

        After applying local validation, the function forwards ``dut_id``,
        ``data``, ``function_tag``, ``output_pattern``, and ``substitutions`` to
        ``str`` and preserves its return and exception contract. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            data: Mapping supplying fields for atomically publish the legacy
                additional-data JSON artifact.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            substitutions: Mapping supplying fields for atomically publish the
                legacy additional-data JSON artifact.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            request_timing_operation_ids: Optional request timing operation
                identifiers; ``None`` selects the function's default behavior.

        Returns:
            The canonical save streamed binary mapping with pattern text, or
            ``None`` when the requested value is unavailable.

        Raises:
            RuntimeError: If collector logger is unavailable.
        """

        facade = self._facade
        source_bodies = [
            value for value in data.values() if isinstance(value, StreamedRedfishBody)
        ]
        rendered_body: Optional[StreamedRedfishBody] = None
        timing_operation_id = None
        try:
            if not facade.logger:
                raise RuntimeError("Collector logger is unavailable")
            final_filename = facade.get_output_filename(
                output_pattern,
                function_tag,
                ".json",
                substitutions,
            )
            rendered_body = await self.render_streamed_binary_mapping(data)
            if facade.timing_manager:
                timing_operation_id = facade.timing_manager.start_operation(
                    "artifact_persistence",
                    str(final_filename),
                    compact_artifact_on_limit=True,
                )
            group = facade._get_collector_group(collector_id)
            file_path = await facade.logger.write_collector_output_file(
                dut_id,
                group,
                collector_id,
                final_filename,
                rendered_body.private_path,
            )
            rendered_body.mark_published()
            if facade.timing_manager:
                facade.timing_manager.end_operation(
                    timing_operation_id,
                    artifact_path=str(file_path),
                    size_bytes=len(rendered_body),
                )
            facade._attach_request_artifact_timing(
                request_timing_operation_ids, str(file_path)
            )
            await facade._log_runtime(
                "INFO",
                "RedfishService",
                f"Written streamed additional-data file: {file_path} "
                f"({len(rendered_body)} bytes)",
                dut_id,
            )
            return str(file_path)
        except BaseException as error:
            if facade.timing_manager and timing_operation_id:
                facade.timing_manager.end_operation(
                    timing_operation_id,
                    status="error",
                    error=str(error),
                )
            if isinstance(rendered_body, StreamedRedfishBody):
                rendered_body.cleanup()
            await facade._log_runtime(
                "ERROR",
                "RedfishService",
                f"Failed to save streamed additional-data mapping: {error}",
                dut_id,
            )
            if not isinstance(error, Exception):
                raise
            return None
        finally:
            for source_body in source_bodies:
                source_body.cleanup()

    async def _preserve_unvalidated_archive(
        self,
        *,
        dut_id: str,
        collector_id: str,
        filename: str,
        content: Union[bytes, StreamedRedfishBody],
        request_timing_operation_ids: Optional[Union[str, List[str]]],
    ) -> Optional[str]:
        """
        Preserve rejected archive bytes as opaque collector evidence.

        The extra suffix deliberately prevents downstream nested-archive
        inspection from treating bytes which failed validation as trusted
        archive input. Returning the evidence path is separate from collector
        success; the caller still returns ``None`` and records the validation
        failure so collection accounting remains partial/error.

        Args:
            dut_id: Stable DUT identifier used to correlate the evidence.
            collector_id: Collector which received the rejected payload.
            filename: Validated archive filename before the opaque suffix is
                appended.
            content: Exact in-memory or staged response bytes to preserve.
            request_timing_operation_ids: Optional request timing identifiers
                associated with the downloaded artifact.

        Returns:
            The published opaque evidence path, or ``None`` when no collector
            logger is available.
        """

        facade = self._facade
        if not facade.logger:
            if isinstance(content, StreamedRedfishBody):
                content.cleanup()
            return None

        evidence_filename = f"{filename}.unvalidated"
        group = facade._get_collector_group(collector_id)
        timing_operation_id = None
        if facade.timing_manager:
            timing_operation_id = facade.timing_manager.start_operation(
                "artifact_persistence",
                evidence_filename,
                compact_artifact_on_limit=True,
            )
        try:
            if isinstance(content, StreamedRedfishBody):
                file_path = await facade.logger.write_collector_output_file(
                    dut_id,
                    group,
                    collector_id,
                    evidence_filename,
                    content.private_path,
                )
                content.mark_published()
            else:
                file_path = await facade.logger.write_collector_output(
                    dut_id,
                    group,
                    collector_id,
                    evidence_filename,
                    content,
                )
        except BaseException as error:
            if facade.timing_manager:
                facade.timing_manager.end_operation(
                    timing_operation_id,
                    status="error",
                    error=str(error),
                )
            if isinstance(content, StreamedRedfishBody):
                content.cleanup()
            raise

        if facade.timing_manager:
            facade.timing_manager.end_operation(
                timing_operation_id,
                artifact_path=str(file_path),
                size_bytes=len(content),
            )
        facade._attach_request_artifact_timing(
            request_timing_operation_ids,
            str(file_path),
        )
        await facade._log_runtime(
            "WARNING",
            "RedfishService",
            f"Preserved unvalidated archive evidence: {file_path} "
            f"({len(content)} bytes)",
            dut_id,
        )
        return str(file_path)

    async def save_data_to_file_with_pattern(
        self,
        dut_id: str,
        data: Any,
        function_tag: str,
        request_timing_operation_ids: Optional[Union[str, List[str]]] = None,
        **kwargs: Any,
    ) -> Optional[str]:
        """
        Persist one Redfish value under the facade's compatibility contract.

        The implementation uses ``dut_id``, ``data``, ``function_tag``,
        ``request_timing_operation_ids``, and ``kwargs`` to persist one Redfish
        value under the facade's compatibility contract. Success is reported
        only after the owning output boundary has completed its required write
        or publication step. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind. If the function
        cannot persist one Redfish value under the facade's compatibility
        contract, its exception reaches the caller instead of being converted
        into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            data: Data object whose ``values`` state is read while performing
                one Redfish value under the facade's compatibility contract.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            request_timing_operation_ids: Optional request timing operation
                identifiers; ``None`` selects the function's default behavior.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The canonical save data to file with pattern text, or ``None`` when
            the requested value is unavailable.

        Raises:
            TypeError: If legacy archive publication channels are forbidden.
            ValueError: If archive publication capability lacks a binary
                payload; prevalidated archive did not resolve to a supported
                archive path; capability bytes failed independent archive
                validation; or published archive bytes differ from validated
                bytes.
            RuntimeError: If archive publication lacks a canonical logger path;
                or archive receipt publication returned no path.
        """

        facade = self._facade
        output_pattern = kwargs.get("output_pattern", "")
        substitutions = kwargs.get("substitutions", {})
        collector_id = kwargs.get("collector_id", "")
        filename = kwargs.get("filename", "")
        additional_data_pattern = kwargs.get("additional_data_pattern", "")
        publication_capability = kwargs.get("_archive_publication_capability")
        if not collector_id:
            collector_id = await facade._get_original_collector_id(
                dut_id, facade._get_current_collector_id()
            )
        if (
            not output_pattern
            and isinstance(function_tag, str)
            and function_tag.endswith(".json")
        ):
            output_pattern = function_tag
        try:
            if any(
                channel in kwargs
                for channel in (
                    "_archive_publication_context",
                    "_prevalidated_archive_validation",
                    "_archive_publication",
                )
            ):
                raise TypeError("legacy archive publication channels are forbidden")
            prevalidated_archive = (
                facade._consume_archive_publication_capability(publication_capability)
                if publication_capability is not None
                else None
            )

            if isinstance(data, dict) and any(
                isinstance(value, StreamedRedfishBody) for value in data.values()
            ):
                return await facade._save_streamed_binary_mapping_with_pattern(
                    dut_id=dut_id,
                    data=data,
                    function_tag=function_tag,
                    output_pattern=(additional_data_pattern or output_pattern),
                    substitutions=substitutions,
                    collector_id=collector_id,
                    request_timing_operation_ids=request_timing_operation_ids,
                )

            if isinstance(data, (bytes, StreamedRedfishBody)):
                content = data
                is_binary = True
            elif isinstance(data, (dict, list)):

                def encode_binary_json_value(value: Any) -> Dict[str, Any]:
                    """
                    Encode binary JSON value.

                    The implementation uses ``value`` to encode binary JSON
                    value. If the function cannot encode binary JSON value, its
                    exception reaches the caller instead of being converted into
                    a successful result.

                    Args:
                        value: Value evaluated while performing encode binary
                            JSON value.

                    Returns:
                        A mapping containing the ``encoding``, ``length``, and
                        ``value`` fields.

                    Raises:
                        TypeError: If object of type ``__name__`` is not JSON
                            serializable.
                    """
                    if isinstance(value, (bytes, bytearray)):
                        payload = bytes(value)
                        return {
                            "encoding": "base64",
                            "length": len(payload),
                            "value": base64.b64encode(payload).decode("ascii"),
                        }
                    raise TypeError(
                        f"Object of type {type(value).__name__} is not JSON serializable"
                    )

                content = json.dumps(data, indent=2, default=encode_binary_json_value)
                is_binary = False
            else:
                content = str(data)
                is_binary = False
            if prevalidated_archive is not None and not is_binary:
                raise ValueError(
                    "archive publication capability requires a binary payload"
                )

            if not is_binary:
                filename = function_tag
            else:
                effective_pattern = additional_data_pattern or output_pattern
                if effective_pattern:
                    resolved_filename = facade.substitute_output_pattern_variables(
                        effective_pattern, substitutions or {}
                    )
                    if re.search(r"\{[^{}]+\}", resolved_filename):
                        filename = f"{function_tag}.bin"
                    else:
                        filename = facade._archive_pattern_for_payload(
                            content, resolved_filename
                        )
                        await facade._log_runtime(
                            "DEBUG",
                            "RedfishService",
                            f"Generated filename: {filename} from pattern: "
                            f"{effective_pattern} with substitutions: {substitutions}",
                            dut_id,
                        )
                else:
                    filename = f"{function_tag}.bin"

            if is_binary:
                final_filename = filename
                archive_validation: Optional[Dict[str, Any]] = None
                published_identity: Optional[Tuple[int, str]] = None

                if (
                    prevalidated_archive is not None
                    and not final_filename.lower().endswith(
                        self.ARCHIVE_PATTERN_SUFFIXES
                    )
                ):
                    raise ValueError(
                        "prevalidated archive did not resolve to a supported archive path"
                    )

                if final_filename.lower().endswith(self.ARCHIVE_PATTERN_SUFFIXES):
                    archive_validator = (
                        facade._validate_and_normalize_streamed_archive_payload
                        if isinstance(content, StreamedRedfishBody)
                        else facade._validate_and_normalize_archive_payload
                    )
                    (
                        content,
                        actual_validation,
                    ) = await facade._run_blocking_redfish_operation(
                        archive_validator,
                        content,
                        final_filename,
                    )
                    archive_validation = (
                        dict(prevalidated_archive)
                        if prevalidated_archive is not None
                        else actual_validation
                    )
                    if (
                        prevalidated_archive is not None
                        and actual_validation.get("status") != "valid"
                    ):
                        raise ValueError(
                            "capability bytes failed independent archive validation"
                        )
                    if archive_validation["status"] == "invalid":
                        archive_validation = (
                            facade._canonical_invalid_archive_validation(
                                archive_validation
                            )
                        )
                        preserved_path = await self._preserve_unvalidated_archive(
                            dut_id=dut_id,
                            collector_id=collector_id,
                            filename=final_filename,
                            content=content,
                            request_timing_operation_ids=(request_timing_operation_ids),
                        )
                        await facade._record_archive_validation(
                            dut_id,
                            archive_validation,
                            collector_id=collector_id,
                            function_tag=function_tag,
                        )
                        error_context = dict(archive_validation)
                        if preserved_path:
                            error_context["preserved_evidence"] = os.path.basename(
                                preserved_path
                            )
                        await facade._create_error_log_file(
                            dut_id=dut_id,
                            collector_id=collector_id,
                            error_message=(
                                f"Rejected invalid archive payload for "
                                f"{final_filename}; exact bytes preserved as "
                                f"{os.path.basename(preserved_path) if preserved_path else 'unavailable'}: "
                                f"{archive_validation.get('validation_error', 'validation failed')}"
                            ),
                            context=error_context,
                        )
                        return None
                    (
                        actual_size,
                        actual_sha256,
                        appended_empty_array_sha256,
                    ) = facade._validated_archive_saved_identity(content)
                    facade._validate_accepted_archive_provenance(
                        archive_validation,
                        actual_size,
                        actual_sha256,
                        appended_empty_array_sha256,
                    )

                group = facade._get_collector_group(collector_id)
                if facade.logger:
                    timing_operation_id = None
                    if facade.timing_manager:
                        timing_operation_id = facade.timing_manager.start_operation(
                            "artifact_persistence",
                            str(final_filename),
                            compact_artifact_on_limit=True,
                        )
                    try:
                        if archive_validation is not None:
                            create_file = getattr(
                                facade.logger, "create_collector_log_file", None
                            )
                            if not callable(create_file):
                                raise RuntimeError(
                                    "archive publication requires a canonical logger path"
                                )
                            file_path = await create_file(
                                dut_id,
                                group,
                                collector_id,
                                final_filename,
                            )
                            artifact_path = facade._published_archive_relative_path(
                                dut_id=dut_id,
                                collector_id=collector_id,
                                group=group,
                                file_path=file_path,
                                fallback_filename=final_filename,
                            )
                            archive_validation = (
                                facade._canonical_persisted_archive_validation(
                                    archive_validation,
                                    artifact_path,
                                )
                            )
                            publication_locks = getattr(
                                facade, "_archive_publication_locks", None
                            )
                            if not isinstance(publication_locks, dict):
                                publication_locks = {}
                                facade._archive_publication_locks = publication_locks
                            publication_lock = publication_locks.setdefault(
                                str(Path(file_path).absolute()), Lock()
                            )
                            async with publication_lock:
                                evidence_path = await facade._record_archive_validation(
                                    dut_id,
                                    archive_validation,
                                    collector_id=collector_id,
                                    function_tag=function_tag,
                                )
                                if not evidence_path:
                                    raise RuntimeError(
                                        "archive receipt publication returned no path"
                                    )
                                published_identity = (
                                    await facade._run_blocking_redfish_operation(
                                        facade._publish_archive_no_replace,
                                        Path(file_path),
                                        content,
                                        int(archive_validation["saved_size"]),
                                        str(archive_validation["saved_sha256"]),
                                    )
                                )
                            if isinstance(content, StreamedRedfishBody):
                                content.mark_published()
                        elif isinstance(content, StreamedRedfishBody):
                            file_path = await facade.logger.write_collector_output_file(
                                dut_id,
                                group,
                                collector_id,
                                final_filename,
                                content.private_path,
                            )
                            content.mark_published()
                        else:
                            file_path = await facade.logger.write_collector_output(
                                dut_id,
                                group,
                                collector_id,
                                final_filename,
                                content,
                            )
                    except BaseException as error:
                        if facade.timing_manager:
                            facade.timing_manager.end_operation(
                                timing_operation_id,
                                status="error",
                                error=str(error),
                            )
                        raise
                    if facade.timing_manager:
                        facade.timing_manager.end_operation(
                            timing_operation_id,
                            artifact_path=str(file_path),
                            size_bytes=len(content),
                        )

                    await facade._log_runtime(
                        "INFO",
                        "RedfishService",
                        f"Written binary file: {file_path} ({len(content)} bytes)",
                        dut_id,
                    )
                    file_path = str(file_path)
                else:
                    if isinstance(content, StreamedRedfishBody):
                        content.cleanup()
                        return None
                    file_path = final_filename

                if archive_validation is not None:
                    if published_identity != (
                        archive_validation["saved_size"],
                        archive_validation["saved_sha256"],
                    ):
                        raise ValueError(
                            "published archive bytes differ from validated bytes"
                        )
                    if publication_capability is not None:
                        facade._complete_archive_publication_capability(
                            publication_capability,
                            facade._archive_validation_reference(archive_validation),
                        )
            else:
                effective_pattern = additional_data_pattern or output_pattern
                await facade._log_runtime(
                    "DEBUG",
                    "RedfishService",
                    "Calling write_output_with_generalization with "
                    f"effective_pattern='{effective_pattern}', "
                    f"function_tag='{function_tag}', substitutions={substitutions}",
                    dut_id,
                )
                file_path = await facade.write_output_with_generalization(
                    dut_id,
                    collector_id,
                    content,
                    output_pattern=effective_pattern,
                    function_tag=function_tag,
                    substitutions=substitutions,
                )
            facade._attach_request_artifact_timing(
                request_timing_operation_ids, file_path
            )
            return file_path
        except Exception as error:
            await facade._log_runtime(
                "ERROR",
                "RedfishService",
                f"Failed to save data to file: {str(error)}",
                dut_id,
            )
            await facade._log_runtime(
                "DEBUG",
                "RedfishService",
                f"Full traceback for file save failure: {traceback.format_exc()}",
                dut_id,
            )
            return None

    async def save_data_with_common_pattern(
        self,
        dut_id: str,
        data: Any,
        function_tag: str,
        output_pattern: Optional[str] = None,
        substitutions: Optional[Dict[str, Any]] = None,
        request_timing_operation_ids: Optional[Union[str, List[str]]] = None,
        **kwargs: Any,
    ) -> Optional[str]:
        """
        Apply a pattern and delegate persistence through the facade seam.

        After applying local validation, the function forwards ``dut_id``,
        ``data``, ``function_tag``, ``output_pattern``, and ``substitutions`` to
        ``self._facade._save_data_to_file_with_pattern`` and preserves its
        return and exception contract. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            data: Data consumed while the function attempts to apply a pattern
                and delegate persistence through the facade seam.
            function_tag: Text supplied as function tag in the format accepted
                by this function.
            output_pattern: Optional output pattern; ``None`` selects the
                function's default behavior.
            substitutions: Optional substitutions; ``None`` selects the
                function's default behavior.
            request_timing_operation_ids: Optional request timing operation
                identifiers; ``None`` selects the function's default behavior.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The canonical save data with common pattern text, or ``None`` when
            the requested value is unavailable.
        """

        try:
            return await self._facade._save_data_to_file_with_pattern(
                dut_id,
                data,
                function_tag,
                output_pattern=output_pattern,
                substitutions=substitutions or {},
                request_timing_operation_ids=request_timing_operation_ids,
                **kwargs,
            )
        except Exception as error:
            await self._facade._log_runtime(
                "ERROR",
                "RedfishService",
                f"Failed to save data for {function_tag}: {str(error)}",
                dut_id,
            )
            return None

    async def download_dump_when_ready(
        self,
        dut_id: str,
        dump_location: str,
        collector_deadline: float,
        readiness_timeout: float = 60.0,
        poll_interval: float = 5.0,
        max_attempts: Optional[int] = None,
        binary_download_timeout: float = 300.0,
        max_attachment_size_bytes: Optional[int] = None,
    ) -> Tuple[bool, Any, Any, List[Dict[str, Any]]]:
        """
        Poll and stream an attachment within explicit time and size bounds.

        ``dump_location`` is response-derived (a device-supplied ``Location``,
        ``@odata.id`` or ``AdditionalDataURI``), so it is validated against the
        host the request will actually be sent to before any request is issued.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            dump_location: Text supplied as dump location in the format accepted
                by this function.
            collector_deadline: Numeric collector deadline used while the
                operation performs bounded accounting.
            readiness_timeout: Maximum duration in seconds allowed for readiness
                timeout.
            poll_interval: Maximum duration in seconds allowed for poll
                interval.
            max_attempts: Upper bound enforced for max attempts; the consuming
                boundary rejects or truncates values that exceed it.
            binary_download_timeout: Maximum duration in seconds allowed for
                binary download timeout.
            max_attachment_size_bytes: Upper bound enforced for max attachment
                size bytes; the consuming boundary rejects or truncates values
                that exceed it.

        Returns:
            A tuple containing the success flag, downloaded payload or failure
            detail, response metadata, and request timing records, in that
            order.
        """

        # Imported lazily: utils.validation reaches core.config_manager, which
        # imports RedfishService, which imports this module. The same lazy
        # delegation is used at redfish_service.validate_redfish_uri.
        from ..utils.validation import validate_redfish_uri

        facade = self._facade

        expected_host = None
        try:
            dut = facade.dut_manager.get_dut(dut_id)
            expected_host = dut.get_redfish_connection_info().get("host")
        except Exception:
            # A falsy anchor fails CLOSED in validate_redfish_uri: every
            # absolute URI is rejected. Degrading to stricter is intentional.
            pass
        if not validate_redfish_uri(dump_location, expected_host=expected_host):
            # Controller-supplied; never echo the rejected value into evidence.
            return (
                False,
                None,
                None,
                [{"error": "rejected unsafe response-derived dump location"}],
            )

        try:
            readiness_timeout = max(0.0, float(readiness_timeout))
        except (TypeError, ValueError):
            readiness_timeout = 60.0
        try:
            poll_interval = max(0.0, float(poll_interval))
        except (TypeError, ValueError):
            poll_interval = 5.0
        try:
            binary_download_timeout = max(0.1, float(binary_download_timeout))
        except (TypeError, ValueError):
            binary_download_timeout = 300.0
        max_attachment_size_bytes = facade._clamped_attachment_limit(
            dut_id,
            max_attachment_size_bytes,
        )

        now = time.monotonic()
        readiness_deadline = min(collector_deadline, now + readiness_timeout)
        sleep_interval = max(0.1, poll_interval)
        available_window = max(0.0, readiness_deadline - now)
        if max_attempts is None:
            max_attempts = min(
                25,
                max(1, int(math.ceil(available_window / sleep_interval)) + 1),
            )
        else:
            try:
                max_attempts = max(1, int(max_attempts))
            except (TypeError, ValueError):
                max_attempts = 1

        attempts: List[Dict[str, Any]] = []
        last_result: Tuple[bool, Any, Any] = (False, None, {})
        transient_statuses = {404, 500, 502, 503}

        for attempt in range(1, max_attempts + 1):
            before_request = time.monotonic()
            collector_remaining = collector_deadline - before_request
            pre_request_terminal_reason = None
            if collector_remaining <= 0:
                pre_request_terminal_reason = "collector_deadline"
            elif attempts and readiness_deadline - before_request <= 0:
                pre_request_terminal_reason = "readiness_deadline"
            if pre_request_terminal_reason:
                terminal_metadata = (
                    dict(last_result[2]) if isinstance(last_result[2], dict) else {}
                )
                terminal_metadata["attachment_readiness_terminal_reason"] = (
                    pre_request_terminal_reason
                )
                last_result = (last_result[0], last_result[1], terminal_metadata)
                if (
                    attempts
                    and attempts[-1].get("terminal_reason") == "retry_scheduled"
                ):
                    attempts[-1]["will_retry"] = False
                    attempts[-1]["retry_delay_seconds"] = None
                    attempts[-1]["terminal_reason"] = pre_request_terminal_reason
                break

            request_timeout = max(
                0.001,
                min(binary_download_timeout, collector_remaining),
            )
            request_started = time.monotonic()
            success, response, metadata = await facade.dispatch_request(
                dut_id,
                "GET",
                dump_location,
                get_raw_content=True,
                bypass_cache=True,
                retry_count=0,
                timeout=request_timeout,
                raw_content_max_bytes=max_attachment_size_bytes,
            )
            now_after_request = time.monotonic()
            http_status = facade._http_status_from_response(response, metadata)
            response_headers = facade._response_headers_from_metadata(metadata)
            body_summary = facade._response_body_summary(response)
            declared_content_length = facade._content_length_from_headers(
                response_headers
            )
            attachment_size = None
            if success and isinstance(response, StreamedRedfishBody):
                attachment_size = response.size_bytes
            elif success and isinstance(response, bytes):
                attachment_size = len(response)

            rejection_reason = None
            if (
                not success
                and isinstance(metadata, dict)
                and metadata.get("error") == "raw_content_too_large"
            ):
                rejection_reason = "attachment_size_limit"
            elif success and now_after_request >= collector_deadline:
                rejection_reason = "collector_deadline"
            elif (
                success
                and max_attachment_size_bytes is not None
                and (
                    (
                        declared_content_length is not None
                        and declared_content_length > max_attachment_size_bytes
                    )
                    or (
                        attachment_size is not None
                        and attachment_size > max_attachment_size_bytes
                    )
                )
            ):
                rejection_reason = "attachment_size_limit"

            if rejection_reason is not None:
                if isinstance(response, StreamedRedfishBody):
                    response.cleanup()
                limit_metadata = dict(metadata) if isinstance(metadata, dict) else {}
                limit_metadata["attachment_download_terminal_reason"] = rejection_reason
                if max_attachment_size_bytes is not None:
                    limit_metadata["max_attachment_size_bytes"] = (
                        max_attachment_size_bytes
                    )
                response = {
                    "error": rejection_reason,
                    "attachment_size_bytes": attachment_size,
                }
                metadata = limit_metadata
                success = False

            last_result = (success, response, metadata)
            retryable = not success and http_status in transient_statuses
            readiness_remaining = readiness_deadline - now_after_request
            collector_remaining_after = collector_deadline - now_after_request
            retry_after = facade._retry_after_from_metadata(metadata)
            requested_retry_delay = (
                retry_after if retry_after is not None else sleep_interval
            )
            retry_delay = min(
                max(0.0, requested_retry_delay),
                max(0.0, readiness_remaining),
                max(0.0, collector_remaining_after),
            )
            will_retry = bool(
                retryable
                and attempt < max_attempts
                and readiness_remaining > 0
                and collector_remaining_after > 0
            )
            if rejection_reason is not None:
                terminal_reason = rejection_reason
                retryable = False
                will_retry = False
            elif success:
                terminal_reason = "success"
            elif not retryable:
                terminal_reason = "non_retryable_response"
            elif attempt >= max_attempts:
                terminal_reason = "attempt_limit"
            elif collector_remaining_after <= 0:
                terminal_reason = "collector_deadline"
            elif readiness_remaining <= 0:
                terminal_reason = "readiness_deadline"
            else:
                terminal_reason = "retry_scheduled"

            response_evidence: Any = body_summary.get("preview")
            if body_summary.get("type") in {"bytes", "streamed_body"}:
                response_evidence = {
                    "type": body_summary.get("type"),
                    "size_bytes": body_summary.get("size_bytes", 0),
                    "note": "binary content omitted",
                }
            attempt_evidence = {
                "attempt": attempt,
                "success": success,
                "http_status": http_status,
                "request_timeout_seconds": request_timeout,
                "request_duration_seconds": max(
                    0.0, now_after_request - request_started
                ),
                "response": response_evidence,
                "response_headers": response_headers,
                "response_body_summary": body_summary,
                "declared_content_length_bytes": declared_content_length,
                "attachment_size_bytes": attachment_size,
                "max_attachment_size_bytes": max_attachment_size_bytes,
                "retryable": retryable,
                "will_retry": will_retry,
                "retry_after_seconds": retry_after,
                "retry_delay_seconds": retry_delay if will_retry else None,
                "terminal_reason": terminal_reason,
                "readiness_remaining_seconds": max(0.0, readiness_remaining),
                "collector_remaining_seconds": max(0.0, collector_remaining_after),
                "timestamp": datetime.now().isoformat(),
            }
            if isinstance(metadata, dict) and metadata.get("retry_details"):
                attempt_evidence["transport_retry_details"] = (
                    facade._bounded_capture_auxiliary_mapping(metadata["retry_details"])
                )
            attempts.append(attempt_evidence)

            if success:
                return success, response, metadata, attempts
            if not will_retry:
                break

            await facade._log_runtime(
                "INFO",
                "RedfishService",
                "Attachment not ready at "
                f"{facade._sanitize_diagnostic_uri(dump_location)} "
                f"(HTTP {http_status}); retrying after {retry_delay:.1f}s",
                dut_id,
            )
            await asyncio.sleep(retry_delay)

        return (*last_result, attempts)

    @staticmethod
    def replace_output_pattern_extension(
        output_pattern: str, new_extension: str
    ) -> str:
        """
        Replace common artifact extensions while preserving templates.

        The implementation uses ``output_pattern`` and ``new_extension`` to
        replace common artifact extensions while preserving templates.

        Args:
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.
            new_extension: Text supplied as new extension in the format accepted
                by this function.

        Returns:
            The canonical replace output pattern extension text.
        """

        if not output_pattern:
            return output_pattern

        known_suffixes = (
            ".tar.gz",
            ".tar.xz",
            ".tar.bz2",
            ".tar.zst",
            ".tgz",
            ".txz",
            ".tbz2",
            ".tar",
            ".zip",
            ".gz",
            ".xz",
            ".bin",
            ".txt",
            ".json",
        )
        for suffix in known_suffixes:
            if output_pattern.lower().endswith(suffix):
                return output_pattern[: -len(suffix)] + new_extension
        return output_pattern + new_extension

    @classmethod
    def add_utc_timestamp_to_archive_pattern(
        cls,
        output_pattern: str,
        *,
        timestamp: Optional[datetime] = None,
    ) -> str:
        """
        Insert a filesystem-safe UTC timestamp before an archive suffix.

        The complete supported suffix is preserved, including multi-part forms
        such as ``.tar.xz`` and ``.tar.gz``. Patterns for non-archive artifacts
        are returned unchanged so diagnostic evidence, raw binary dumps, and
        ordinary Redfish responses retain their authored names. Supplying an
        explicit timestamp provides a deterministic seam for synthetic tests;
        production callers use the current UTC time.

        Args:
            output_pattern: Authored or content-corrected output filename
                pattern whose archive suffix may receive a timestamp.
            timestamp: Optional timezone-aware instant to render; ``None``
                selects the current UTC time.

        Returns:
            The output pattern with ``_YYYYMMDDTHHMMSSZ`` inserted immediately
            before a supported archive suffix, or the original pattern when it
            does not name a supported archive.

        Raises:
            ValueError: If an explicitly supplied timestamp has no timezone.
        """

        observed_at = timestamp or datetime.now(timezone.utc)
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("archive filename timestamp must be timezone-aware")
        timestamp_label = observed_at.astimezone(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )

        lowercase_pattern = output_pattern.lower()
        for suffix in cls.ARCHIVE_PATTERN_SUFFIXES:
            if not lowercase_pattern.endswith(suffix):
                continue
            suffix_start = len(output_pattern) - len(suffix)
            stem = output_pattern[:suffix_start]
            original_suffix = output_pattern[suffix_start:]
            marker = f"_{timestamp_label}"
            if stem.endswith(marker):
                return output_pattern
            return f"{stem}{marker}{original_suffix}"
        return output_pattern

    @classmethod
    def archive_pattern_for_payload(cls, dump_data: Any, output_pattern: str) -> str:
        """
        Correct an archive-shaped pattern using the payload's magic bytes.

        The implementation uses ``dump_data`` and ``output_pattern`` to correct
        an archive-shaped pattern using the payload's magic bytes.

        Args:
            dump_data: Dump data object whose ``prefix_bytes`` state is read
                while performing correct an archive-shaped pattern using the
                payload's magic bytes.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.

        Returns:
            The canonical archive pattern for payload text.
        """

        if isinstance(dump_data, StreamedRedfishBody):
            sniff_bytes = dump_data.prefix_bytes
        elif isinstance(dump_data, bytes):
            sniff_bytes = dump_data
        else:
            return output_pattern
        if not output_pattern.lower().endswith(cls.ARCHIVE_PATTERN_SUFFIXES):
            return output_pattern
        detected_ext = None
        for magic, extension in cls.ARCHIVE_MAGICS:
            if sniff_bytes.startswith(magic):
                detected_ext = extension
                break
        if detected_ext is None and sniff_bytes[257:262] == b"ustar":
            detected_ext = ".tar"
        if detected_ext is None:
            return output_pattern
        if output_pattern.endswith(detected_ext):
            return output_pattern
        return cls.replace_output_pattern_extension(output_pattern, detected_ext)

    @classmethod
    def prepare_downloaded_dump_for_save(
        cls, dump_data: Any, output_pattern: str
    ) -> Tuple[Any, str, str, int]:
        """
        Classify downloaded content and make its suffix truthful.

        The implementation uses ``dump_data`` and ``output_pattern`` to classify
        downloaded content and make its suffix truthful.

        Args:
            dump_data: Dump data object whose ``cleanup``, ``decode``,
                ``lstrip``, ``prefix_bytes``, and ``read_bytes`` state is read
                while performing classify downloaded content and make its suffix
                truthful.
            output_pattern: Text supplied as output pattern in the format
                accepted by this function.

        Returns:
            A tuple containing the content selected for storage, its
            ``"json"``, ``"text"``, or ``"binary"`` type label, the output
            pattern with a truthful suffix, and the original byte or item
            count.
        """

        if isinstance(dump_data, StreamedRedfishBody):
            data_size = dump_data.size_bytes
            stripped_prefix = dump_data.prefix_bytes.lstrip()
            if (
                stripped_prefix.startswith((b"{", b"["))
                and data_size <= DEFAULT_REDFISH_STRUCTURED_RESPONSE_MAX_BYTES
            ):
                try:
                    parsed_json = json.loads(
                        dump_data.read_bytes(
                            max_bytes=DEFAULT_REDFISH_STRUCTURED_RESPONSE_MAX_BYTES
                        ).decode("utf-8-sig")
                    )
                except (UnicodeDecodeError, json.JSONDecodeError):
                    pass
                else:
                    dump_data.cleanup()
                    return (
                        parsed_json,
                        "json",
                        cls.replace_output_pattern_extension(output_pattern, ".json"),
                        data_size,
                    )
            return (
                dump_data,
                "binary",
                cls.archive_pattern_for_payload(dump_data, output_pattern),
                data_size,
            )

        if not isinstance(dump_data, bytes):
            data_size = len(dump_data) if hasattr(dump_data, "__len__") else 0
            data_type = "json" if isinstance(dump_data, (dict, list)) else "text"
            return dump_data, data_type, output_pattern, data_size

        data_size = len(dump_data)
        stripped = dump_data.lstrip()
        if stripped.startswith((b"{", b"[")):
            try:
                parsed_json = json.loads(dump_data.decode("utf-8-sig"))
                return (
                    parsed_json,
                    "json",
                    cls.replace_output_pattern_extension(output_pattern, ".json"),
                    data_size,
                )
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass

        return (
            dump_data,
            "binary",
            cls.archive_pattern_for_payload(dump_data, output_pattern),
            data_size,
        )

    @classmethod
    def prepare_cper_attachment_for_save(
        cls, attachment_data: Any, output_pattern: str
    ) -> Tuple[Any, str, str, int]:
        """
        Classify one bounded R21 attachment without trusting its authored suffix.

        Redfish implementations may return CPER records as raw bytes, as strict
        Base64 text, in a diagnosticData JSON or phosphor-logging version-5
        binary envelope, or inside a real archive. Bounded envelope and Base64
        layers are unwrapped without searching unrelated fields or byte ranges.
        Only payloads carrying the CPER
        record signature are renamed to ``.cper``. Archive-shaped output keeps
        its authored suffix so the normal archive validator can accept genuine
        containers and reject every other unsupported representation. Streamed
        Base64 responses are decoded in memory only within the structured-body
        ceiling; larger responses remain archive-shaped and therefore fail
        closed at the existing validation boundary.

        Args:
            attachment_data: Raw bytes or an owned streamed Redfish response.
            output_pattern: Authored archive-shaped filename for the R21 entry.

        Returns:
            A tuple containing the selected content, the ``"binary"`` type
            label, a content-truthful output pattern, and the original response
            byte count.

        Raises:
            TypeError: If the transport did not return a binary response type.
        """

        if not isinstance(attachment_data, (bytes, StreamedRedfishBody)):
            raise TypeError("CPER attachment transport returned non-binary content")

        original_size = (
            attachment_data.size_bytes
            if isinstance(attachment_data, StreamedRedfishBody)
            else len(attachment_data)
        )
        sniff_bytes = (
            attachment_data.prefix_bytes
            if isinstance(attachment_data, StreamedRedfishBody)
            else attachment_data
        )
        is_archive = (
            any(sniff_bytes.startswith(magic) for magic, _ in cls.ARCHIVE_MAGICS)
            or sniff_bytes[257:262] == b"ustar"
        )
        if is_archive:
            return (
                attachment_data,
                "binary",
                cls.archive_pattern_for_payload(attachment_data, output_pattern),
                original_size,
            )
        decoded_cper: Optional[bytes] = None

        if isinstance(attachment_data, bytes):
            decoded_cper = cls._decode_cper_payload(attachment_data)
        elif attachment_data.prefix_bytes.startswith(cls.CPER_MAGIC):
            return (
                attachment_data,
                "binary",
                cls.replace_output_pattern_extension(output_pattern, ".cper"),
                original_size,
            )
        elif original_size <= cls.CPER_BASE64_DECODE_MAX_BYTES:
            encoded = attachment_data.read_bytes(
                max_bytes=cls.CPER_BASE64_DECODE_MAX_BYTES
            )
            decoded_cper = cls._decode_cper_payload(encoded)
            if decoded_cper is not None:
                attachment_data.cleanup()

        if decoded_cper is not None:
            return (
                decoded_cper,
                "binary",
                cls.replace_output_pattern_extension(output_pattern, ".cper"),
                original_size,
            )

        return (
            attachment_data,
            "binary",
            cls.archive_pattern_for_payload(attachment_data, output_pattern),
            original_size,
        )

    @classmethod
    def _decode_cper_payload(cls, payload: bytes) -> Optional[bytes]:
        """
        Unwrap bounded Base64 and diagnosticData envelopes into raw CPER bytes.

        ASCII whitespace is accepted because Redfish implementations may wrap
        Base64 response lines. Decoded data is trusted as CPER only when its
        first bytes carry the UEFI CPER record signature; arbitrary Base64 text
        therefore remains on the fail-closed archive path. Every wrapper counts
        toward a fixed layer budget, and each encoded body is size-limited.
        JSON objects must have unique keys and a string diagnosticData field;
        unrelated fields and arbitrary nested objects are never searched.
        Binary event envelopes must pass complete version-5 framing validation
        before their diagnosticData field is selected.

        Args:
            payload: Bounded response bytes to classify.

        Returns:
            Raw CPER bytes, or ``None`` when the payload is not a recognized
            CPER representation.
        """

        expect_base64 = False
        for layer in range(cls.CPER_DECODE_MAX_LAYERS + 1):
            if not expect_base64 and payload.startswith(cls.CPER_MAGIC):
                return payload
            if (
                layer == cls.CPER_DECODE_MAX_LAYERS
                or len(payload) > cls.CPER_BASE64_DECODE_MAX_BYTES
            ):
                return None
            try:
                if not expect_base64 and payload.startswith(
                    cls.CPER_PHOSPHOR_V5_PREFIX
                ):
                    payload = cls._cper_phosphor_v5_diagnostic_data(payload)
                    expect_base64 = True
                    continue
                text = payload.decode("utf-8-sig").strip()
                if not expect_base64 and text.startswith("{"):
                    envelope = json.loads(
                        text, object_pairs_hook=cls._cper_envelope_unique_keys
                    )
                    diagnostic_data = envelope.get("diagnosticData")
                    if not isinstance(diagnostic_data, str):
                        return None
                    payload = diagnostic_data.encode("ascii")
                    expect_base64 = True
                else:
                    compact = re.sub(rb"[\x09\x0a\x0d\x20]+", b"", payload)
                    if not compact or len(compact) % 4:
                        return None
                    payload = base64.b64decode(compact, validate=True)
                    expect_base64 = False
            except (UnicodeError, ValueError, binascii.Error, RecursionError):
                return None
        return None

    @classmethod
    def _cper_phosphor_v5_diagnostic_data(cls, payload: bytes) -> bytes:
        """
        Read CPER metadata from one complete little-endian Cereal event entry.

        OpenBMC phosphor-logging serializes version 5 as an ID, severity,
        timestamp, message, AdditionalData string vector, association triples,
        resolved boolean, firmware version, update timestamp, event ID, and
        resolution. Strings and vectors have unsigned 64-bit lengths. Parse
        every field in order; never scan a binary blob for a diagnosticData
        substring. Unknown versions, duplicate metadata, excessive counts,
        truncated fields, and trailing bytes remain unsupported evidence.

        Args:
            payload: Bounded event bytes, including the four-byte class version.

        Returns:
            The unique diagnosticData value, still encoded as Base64.

        Raises:
            ValueError: If framing, resource bounds, or explicit CPER metadata
                are invalid. The caller retains the original transport bytes.
        """

        if (
            not payload.startswith(cls.CPER_PHOSPHOR_V5_PREFIX)
            or len(payload) > cls.CPER_BASE64_DECODE_MAX_BYTES
        ):
            raise ValueError("Unsupported CPER event envelope")
        offset = 0

        def read(size: int) -> bytes:
            """
            Consume a bounded field without trusting its declared length.

            Check the remaining extent before slicing so oversized declarations
            cannot allocate memory or move the cursor outside the envelope.

            Args:
                size: Number of bytes requested by the enclosing field.

            Returns:
                The exact field bytes and advances the private cursor.

            Raises:
                ValueError: If the field exceeds the remaining envelope.
            """

            nonlocal offset
            if size > len(payload) - offset:
                raise ValueError("Truncated CPER event envelope")
            result = payload[offset : offset + size]
            offset += size
            return result

        def read_string() -> bytes:
            """
            Consume one length-prefixed string without interpreting its content.

            Cereal strings are byte sequences; unrelated metadata stays opaque
            while the caller selects only the explicitly named diagnostic field.

            Returns:
                String bytes after validating their declared extent.

            Raises:
                ValueError: If the length prefix or string is truncated.
            """

            return read(int.from_bytes(read(8), "little"))

        def read_count() -> int:
            """
            Bound a vector count by policy and the remaining length prefixes.

            Check before iteration to reject fabricated counts even when there
            are enough bytes for many empty strings.

            Returns:
                The validated number of strings or association triples.

            Raises:
                ValueError: If the count cannot fit or exceeds the work limit.
            """

            count = int.from_bytes(read(8), "little")
            if count > min(cls.CPER_PHOSPHOR_MAX_ITEMS, (len(payload) - offset) // 8):
                raise ValueError("Excessive CPER event field count")
            return count

        read(20)  # Class version, ID, severity, and timestamp.
        read_string()  # Message is not an authoritative CPER field.
        metadata: Dict[bytes, bytes] = {}
        for _ in range(read_count()):
            key, separator, value = read_string().partition(b"=")
            if not separator or not key or key in metadata:
                raise ValueError("Invalid or duplicate CPER event metadata")
            metadata[key] = value
        for _ in range(read_count()):
            for _ in range(3):
                read_string()
        if read(1) not in (b"\x00", b"\x01"):
            raise ValueError("Invalid CPER event resolved boolean")
        read_string()  # Firmware version.
        read(8)  # Update timestamp.
        read_string()  # Event ID.
        read_string()  # Resolution.
        if offset != len(payload):
            raise ValueError("Unexpected bytes after CPER event envelope")
        if (
            metadata.get(b"diagnosticDataType") != b"CPER"
            or b"diagnosticData" not in metadata
        ):
            raise ValueError("Missing explicit CPER event metadata")
        return metadata[b"diagnosticData"]

    @staticmethod
    def _cper_envelope_unique_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        """
        Reject ambiguous JSON fields before selecting diagnosticData content.

        The JSON decoder invokes this hook for every object, including metadata,
        so a duplicate cannot silently replace a value at any nesting level.

        Args:
            pairs: Ordered object entries supplied by the bounded JSON decoder.

        Returns:
            An object preserving every uniquely named field.

        Raises:
            ValueError: If an object contains duplicate keys at any depth.
        """

        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate key in CPER diagnostic envelope")
            result[key] = value
        return result

    @staticmethod
    def archive_payload_is_well_formed(payload: bytes, filename: str) -> None:
        """
        Consume an in-memory archive and reject invalid framing/checksums.

        Delegates to :meth:`archive_stream_is_well_formed` over a seekable view
        of the payload so both entry points share one policy: the same
        expansion-ratio ceiling, the same elapsed-work deadline, and the same
        bounded readers.

        Delegation -- rather than an early ``return`` in the previous xz branch
        -- is deliberate. That branch validates only LZMA framing; the tar
        structure was validated by the fall-through beneath it, so returning
        early would have silently stopped validating tar contents while leaving
        the payload decompressed twice. The stream twin does both in a single
        bounded pass.

        The xz trailing-bytes check previously duplicated here now lives in
        :meth:`archive_stream_is_well_formed`, so this wrapper and the
        streamed entry point that used to bypass it share the identical
        check instead of only the in-memory path being covered.

        Args:
            payload: Bounded byte sequence supplied as payload.
            filename: Text supplied as filename in the format accepted by this
                function.

        Raises:
            ValueError: If unexpected bytes after xz stream.
        """

        RedfishArtifactStore.archive_stream_is_well_formed(
            io.BytesIO(payload), filename
        )

    @staticmethod
    def streamed_archive_identity(metadata: os.stat_result) -> Tuple[int, ...]:
        """
        Return metadata fields which must remain stable during validation.

        The implementation uses ``metadata`` to produce metadata fields which
        must remain stable during validation.

        Args:
            metadata: Metadata object whose ``st_ctime_ns``, ``st_dev``,
                ``st_ino``, ``st_mode``, and ``st_mtime_ns`` state is read while
                performing metadata fields which must remain stable during
                validation.

        Returns:
            A tuple containing ``st dev``, ``st ino``, ``st mode``, ``st
            nlink``, ``st size``, ``st mtime ns``, and ``st ctime ns`` in that
            order.
        """

        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    @classmethod
    def sha256_open_stream(cls, source: Any, *, expected_size: int) -> str:
        """
        Hash one pinned stream while verifying its descriptor identity.

        After applying local validation, the function forwards ``source`` and
        ``expected_size`` to ``digest.hexdigest`` and preserves its return and
        exception contract. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            source: Source object whose ``fileno``, ``read``, and ``seek`` state
                is read while performing hash one pinned stream while verifying
                its descriptor identity.
            expected_size: Numeric expected size used by the operation's bounded
                accounting.

        Returns:
            The canonical SHA-256 open stream text.

        Raises:
            OSError: If the streamed archive is not a private regular file;
                streamed archive size metadata is stale; or streamed archive
                changed while hashing.
        """

        source.seek(0)
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OSError("streamed archive must be a private regular file")
        if before.st_size != expected_size:
            raise OSError("streamed archive size metadata is stale")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        after = os.fstat(source.fileno())
        if total != expected_size or cls.streamed_archive_identity(
            before
        ) != cls.streamed_archive_identity(after):
            raise OSError("streamed archive changed while hashing")
        return digest.hexdigest()

    @staticmethod
    def bounded_tarinfo_type(
        *,
        extension_header_limit: int | None = None,
        expansion_budget: Any = None,
    ) -> type[tarfile.TarInfo]:
        """
        Build a TarInfo type which bounds pre-yield extension payloads.

        Python's tar parser materializes PAX and GNU long-name records before
        yielding the logical member. Checking and charging the declared size in
        ``_proc_member`` keeps that hidden read behind the same expansion
        budget as ordinary member data without limiting the total archive size.

        Args:
            extension_header_limit: Maximum bytes admitted for any single PAX
                or GNU extension record; ``None`` selects the governed default.
            expansion_budget: Optional archive expansion budget charged before
                an extension record is materialized.

        Returns:
            A ``TarInfo`` subclass bound to the requested header controls.

        Raises:
            ValueError: If ``extension_header_limit`` is not a positive integer.
        """

        limit = (
            RedfishArtifactStore.TAR_EXTENSION_HEADER_MAX_BYTES
            if extension_header_limit is None
            else extension_header_limit
        )
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("tar extension header limit must be a positive integer")

        class _BoundedTarInfo(tarfile.TarInfo):
            """
            Parse TAR members while bounding hidden extension records.

            The type retains the enclosing header limit and expansion budget
            for every member parsed by one archive reader.
            """

            def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
                """
                Process one member after admitting its extension payload.

                Extension records are charged before the standard library
                reads them into memory; ordinary members retain stdlib parsing
                behavior.

                Args:
                    archive: TAR reader consuming this member.

                Returns:
                    The logical ``TarInfo`` member produced by the standard
                    parser.

                Raises:
                    ValueError: If an extension record has an invalid or
                        excessive declared size, or its expansion charge is
                        rejected.
                """
                extension_types = (
                    tarfile.GNUTYPE_LONGNAME,
                    tarfile.GNUTYPE_LONGLINK,
                    tarfile.XHDTYPE,
                    tarfile.XGLTYPE,
                    tarfile.SOLARIS_XHDTYPE,
                )
                if self.type in extension_types:
                    if self.size < 0 or self.size > limit:
                        raise ValueError(f"tar extension header exceeds {limit} bytes")
                    if expansion_budget is not None:
                        expansion_budget.charge(self.size)
                process_member = getattr(super(), "_proc_member")
                return cast(tarfile.TarInfo, process_member(archive))

        return _BoundedTarInfo

    @staticmethod
    def _walk_bounded_tar_stream(
        fileobj: Any,
        *,
        mode: str,
        tar_open: Any,
        tarinfo: type[tarfile.TarInfo],
        budget: "RedfishArtifactStore.ArchiveExpansionBudget",
        drain: Any,
        limits: ArchiveLimits,
    ) -> int:
        """
        Walk one streamed TAR body, bounding member count and evicting members.

        Applies identically to every compression leg of
        :meth:`archive_stream_is_well_formed` -- xz, zstd, gzip, and the
        auto-detecting fallback -- so their member-count ceiling, per-member
        header-block accounting, and member eviction cannot drift apart the
        way the four near-identical inline walks previously could.

        Args:
            fileobj: Decompressed (or raw) byte stream to parse as a TAR body.
            mode: TAR open mode forwarded to ``tar_open``.
            tar_open: TAR archive constructor, normally ``tarfile.open``.
            tarinfo: Bounded ``TarInfo`` subclass charging extension headers.
            budget: Expansion budget charged for header blocks and member
                content.
            drain: Callable draining and charging one open member's content.
            limits: Archive limits supplying the member-count ceiling.

        Returns:
            The number of members observed in the streamed TAR body.

        Raises:
            ValueError: If the archive declares more members than
                ``limits.max_members`` admits, or contains no members at all.
        """
        member_count = 0
        with tar_open(fileobj=fileobj, mode=mode, tarinfo=tarinfo) as archive:
            for member in archive:
                try:
                    member_count += 1
                    if member_count > limits.max_members:
                        raise ValueError(
                            "tar archive exceeds the configured member "
                            f"ceiling of {limits.max_members}"
                        )
                    budget.check_deadline()
                    # Charging the header block itself -- not only member
                    # content -- means a metadata-only archive (many members,
                    # each with little or no file content) still spends
                    # against the compression-ratio ceiling instead of
                    # costing nothing but CPU and wall time.
                    budget.charge(tarfile.BLOCKSIZE)
                    if member.isfile():
                        member_file = archive.extractfile(member)
                        if member_file is not None:
                            drain(member_file)
                finally:
                    # Mirrors utils/bounded_archive.py: TarFile.next() appends
                    # every parsed member to this list unconditionally, so a
                    # long-running validation would otherwise retain one
                    # TarInfo per member for the whole walk.
                    archive.members.clear()
        if member_count == 0:
            raise ValueError("archive contains no members")
        return member_count

    @staticmethod
    def _gzip_single_member_extent(
        source: Any,
        budget: "RedfishArtifactStore.ArchiveExpansionBudget",
    ) -> int:
        """
        Locate the byte offset immediately after one gzip member's trailer.

        Unlike the fixed-length xz stream footer, a gzip member has no
        constant-offset trailer: its length depends on the compressed
        payload. Locating the boundary therefore requires a bounded framing
        pass over the member's raw deflate stream rather than an O(1) tail
        read. The pass tracks expanded bytes locally so the subsequent archive
        validation charges the shared budget exactly once.

        Args:
            source: Seekable stream positioned anywhere; left rewound to the
                start of the archive on return.
            budget: Expansion budget supplying the remaining output ceiling
                and shared validation deadline.

        Returns:
            The absolute offset immediately following the first gzip
            member's 8-byte CRC32/ISIZE trailer.

        Raises:
            ValueError: If the stream is not a well-formed single gzip
                member, or a header field exceeds the configured metadata
                header limit.
        """
        header_limit = RedfishArtifactStore.TAR_EXTENSION_HEADER_MAX_BYTES
        source.seek(0)
        header = source.read(10)
        if len(header) != 10 or header[:2] != b"\x1f\x8b" or header[2] != 8:
            raise ValueError("archive is not a well-formed gzip stream")
        flags = header[3]
        if flags & 0xE0:
            raise ValueError("gzip stream uses reserved header flags")
        if flags & 0x04:  # FEXTRA
            extra_length_bytes = source.read(2)
            if len(extra_length_bytes) != 2:
                raise ValueError("truncated gzip extra field length")
            extra_length = struct.unpack("<H", extra_length_bytes)[0]
            if extra_length > header_limit:
                raise ValueError("gzip extra field exceeds the header limit")
            if len(source.read(extra_length)) != extra_length:
                raise ValueError("truncated gzip extra field")
        for flag_bit in (0x08, 0x10):  # FNAME, FCOMMENT
            if not flags & flag_bit:
                continue
            scanned = 0
            while True:
                byte = source.read(1)
                if not byte:
                    raise ValueError("truncated gzip header field")
                scanned += 1
                if scanned > header_limit:
                    raise ValueError("gzip header field exceeds the header limit")
                if byte == b"\x00":
                    break
        if flags & 0x02:  # FHCRC
            if len(source.read(2)) != 2:
                raise ValueError("truncated gzip header CRC16")

        decompressor = zlib.decompressobj(wbits=-15)
        pending = b""
        expanded = 0
        output_ceiling = budget.remaining_bytes
        try:
            while not decompressor.eof:
                chunk = pending or source.read(1024 * 1024)
                if not chunk:
                    raise ValueError("truncated gzip deflate stream")
                output = decompressor.decompress(chunk, 1024 * 1024)
                expanded += len(output)
                if expanded > output_ceiling:
                    raise ValueError(
                        "gzip framing pass exceeds the permitted compression ratio"
                    )
                pending = decompressor.unconsumed_tail
                if pending and len(pending) == len(chunk) and not output:
                    raise ValueError("gzip deflate stream made no progress")
                budget.check_deadline()
        except zlib.error as error:
            raise ValueError(f"gzip deflate stream is invalid: {error}") from error
        source.seek(source.tell() - len(decompressor.unused_data))
        trailer = source.read(8)
        if len(trailer) != 8:
            raise ValueError("truncated gzip trailer")
        extent = source.tell()
        source.seek(0)
        return extent

    @staticmethod
    def archive_stream_is_well_formed(
        source: Any,
        filename: str,
        *,
        budget_factory: Any = None,
        lzma_open: Any = None,
        tar_open: Any = None,
        zstd_decompressor: Any = None,
        zip_file: Any = None,
    ) -> None:
        """
        Validate one pinned archive stream with bounded decompression.

        The implementation uses ``source``, ``filename``, ``budget_factory``,
        ``lzma_open``, and ``tar_open`` to validate one pinned archive stream
        with bounded decompression. Every required invariant is checked before a
        successful value is returned; invalid input follows the function's
        explicit exception path. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle.

        Args:
            source: Source object whose ``seek`` state is read while performing
                one pinned archive stream with bounded decompression.
            filename: Text supplied as filename in the format accepted by this
                function.
            budget_factory: Callable invoked at the budget factory boundary.
            lzma_open: Optional lzma open; ``None`` selects the function's
                default behavior.
            tar_open: Optional TAR open; ``None`` selects the function's default
                behavior.
            zstd_decompressor: Optional zstd decompressor factory; ``None``
                selects the strict, single-frame ``StrictZstdReader`` policy.
                A caller-supplied factory is a test seam that restores the
                previous bare ``stream_reader`` behavior for that call only.
            zip_file: Optional filesystem location used as the ZIP file for this
                operation.

        Raises:
            ValueError: If archive contains no members; the archive exceeds
                its configured member-count ceiling; zip member failed CRC
                validation: ``filename``; the zip archive materializes more
                members than its declared central-directory count; the xz or
                gzip stream carries unexpected trailing bytes; the zstd
                stream is not well-formed; or another framing or
                resource-policy invariant is violated.
        """

        source.seek(0)
        lower_name = filename.lower()
        if lower_name.endswith((".tar.xz", ".txz")):
            # A well-formed xz stream ends with its 12-byte footer, whose last
            # two bytes are the magic below, so a stream ending in anything
            # else carries trailing data. This is an O(1) framing check, not a
            # full parse: LZMAFile silently ignores bytes after the stream and
            # reads ahead to EOF, so neither it nor the source position can
            # surface them otherwise. Moved here (finding 14) so the in-memory
            # wrapper and this streamed entry point share the identical check
            # instead of only the former being covered.
            footer_length = len(_XZ_STREAM_FOOTER_MAGIC)
            source.seek(0, os.SEEK_END)
            total_size = source.tell()
            if total_size >= footer_length:
                source.seek(-footer_length, os.SEEK_END)
                footer = source.read(footer_length)
                if footer != _XZ_STREAM_FOOTER_MAGIC:
                    source.seek(0)
                    raise ValueError("unexpected bytes after xz stream")
            source.seek(0)
        chunk_size = 1024 * 1024
        budget_factory = (
            RedfishArtifactStore.ArchiveExpansionBudget
            if budget_factory is None
            else budget_factory
        )
        lzma_open = lzma.open if lzma_open is None else lzma_open
        tar_open = tarfile.open if tar_open is None else tar_open
        zip_file = zipfile.ZipFile if zip_file is None else zip_file
        budget = budget_factory(source)
        bounded_tarinfo = RedfishArtifactStore.bounded_tarinfo_type(
            expansion_budget=budget
        )

        def drain(reader: Any) -> None:
            """
            Drain all owned work before returning.

            The implementation uses ``reader`` to drain all owned work before
            returning. Filesystem effects remain confined to the caller-selected
            paths and the owning resource lifecycle.

            Args:
                reader: Reader object whose ``read`` state is read while
                    performing drain all owned work before returning.
            """
            while True:
                block = reader.read(chunk_size)
                if not block:
                    return
                budget.charge(len(block))

        if lower_name.endswith((".tar.xz", ".txz")):
            with lzma_open(source, "rb") as reader:
                RedfishArtifactStore._walk_bounded_tar_stream(
                    reader,
                    mode="r|",
                    tar_open=tar_open,
                    tarinfo=bounded_tarinfo,
                    budget=budget,
                    drain=drain,
                    limits=RedfishArtifactStore._ARCHIVE_LIMITS,
                )
                drain(reader)
            return

        if lower_name.endswith((".tar.gz", ".tgz")):
            # A validated artifact is exactly one gzip member: seek past its
            # ISIZE trailer and require EOF, mirroring the xz trailing-bytes
            # check above so a smuggled concatenated member cannot ride along
            # as if it were ordinary trailing padding.
            end_of_member = RedfishArtifactStore._gzip_single_member_extent(
                source, budget
            )
            source.seek(0, os.SEEK_END)
            if source.tell() != end_of_member:
                source.seek(0)
                raise ValueError("unexpected bytes after gzip stream")
            source.seek(0)
            with gzip.GzipFile(fileobj=source) as reader:
                RedfishArtifactStore._walk_bounded_tar_stream(
                    reader,
                    mode="r|",
                    tar_open=tar_open,
                    tarinfo=bounded_tarinfo,
                    budget=budget,
                    drain=drain,
                    limits=RedfishArtifactStore._ARCHIVE_LIMITS,
                )
                drain(reader)
            return

        if lower_name.endswith((".tar.zst", ".tar.zstd")):
            if zstd_decompressor is None:
                # Bind bounds to already-configured budgets rather than new
                # constants: the window/input ceilings come from the shared
                # ArchiveLimits profile, the output ceiling from this
                # validation's own remaining compression-ratio allowance, and
                # the deadline from this validation's own budget. A validated
                # artifact is exactly one canonical frame; StrictZstdReader's
                # explicit per-frame ``eof`` accounting -- unlike
                # ``read_across_frames`` -- also closes the
                # truncated-final-frame gap, since a physically truncated
                # frame no longer reads as a clean decompressed EOF.
                strict_reader = StrictZstdReader(
                    source,
                    max_window_size=(
                        RedfishArtifactStore._ARCHIVE_LIMITS.max_decompressor_memory_bytes
                    ),
                    max_output_bytes=max(budget.remaining_bytes, 1),
                    max_input_bytes=budget.input_bytes,
                    max_frames=1,
                    check_deadline=budget.check_deadline,
                )
                try:
                    RedfishArtifactStore._walk_bounded_tar_stream(
                        strict_reader,
                        mode="r|",
                        tar_open=tar_open,
                        tarinfo=bounded_tarinfo,
                        budget=budget,
                        drain=drain,
                        limits=RedfishArtifactStore._ARCHIVE_LIMITS,
                    )
                    drain(strict_reader)
                except StrictZstdError as error:
                    raise ValueError(
                        f"zstd stream is not well-formed: {error.reason}"
                    ) from error
                finally:
                    strict_reader.close()
                return
            # A caller-injected decompressor is a test seam for exercising
            # this branch's own error handling; preserve the previous bare
            # reader for that path only.
            with zstd_decompressor().stream_reader(
                source,
                read_across_frames=True,
                closefd=False,
            ) as reader:
                RedfishArtifactStore._walk_bounded_tar_stream(
                    reader,
                    mode="r|",
                    tar_open=tar_open,
                    tarinfo=bounded_tarinfo,
                    budget=budget,
                    drain=drain,
                    limits=RedfishArtifactStore._ARCHIVE_LIMITS,
                )
                drain(reader)
            return

        if lower_name.endswith(".zip"):
            # Bound the declared member count and central-directory size from
            # the end-of-central-directory record before materializing
            # anything -- the same EOCD-extent helper bounded_archive.py's
            # own sanctioned ZIP reader uses -- so a hostile declared count
            # cannot reach infolist(). This pre-check is load-bearing; infos
            # is re-checked below only to catch disagreement between the
            # declared and materialized counts.
            inspect_zip_central_directory_extent(
                source,
                limits=RedfishArtifactStore._ARCHIVE_LIMITS,
                deadline=time.monotonic() + budget.max_seconds,
            )
            with zip_file(source) as archive:
                infos = archive.infolist()
                if not infos:
                    raise ValueError("archive contains no members")
                if len(infos) > RedfishArtifactStore._ARCHIVE_LIMITS.max_members:
                    raise ValueError(
                        "zip archive materialized more members than its "
                        "declared central-directory count admits"
                    )
                # Read each member through the budget rather than calling
                # testzip(), which inflates every member internally and so
                # charges nothing. Reading to EOF still verifies CRC-32 --
                # zipfile raises on mismatch when the member is exhausted --
                # so the integrity check is preserved and now bounded.
                for info in infos:
                    budget.check_deadline()
                    if info.is_dir():
                        continue
                    try:
                        with archive.open(info) as member_file:
                            drain(member_file)
                    except zipfile.BadZipFile as error:
                        raise ValueError(
                            f"zip member failed CRC validation: {info.filename}"
                        ) from error
            return

        RedfishArtifactStore._walk_bounded_tar_stream(
            source,
            mode="r|*",
            tar_open=tar_open,
            tarinfo=bounded_tarinfo,
            budget=budget,
            drain=drain,
            limits=RedfishArtifactStore._ARCHIVE_LIMITS,
        )

    @staticmethod
    def archive_file_is_well_formed(
        path: Path,
        filename: str,
        *,
        budget_factory: Any = None,
        lzma_open: Any = None,
        tar_open: Any = None,
        zstd_decompressor: Any = None,
        zip_file: Any = None,
    ) -> None:
        """
        Validate a private staged archive through one opened file handle.

        The implementation uses ``path``, ``filename``, ``budget_factory``,
        ``lzma_open``, and ``tar_open`` to validate a private staged archive
        through one opened file handle. Every required invariant is checked
        before a successful value is returned; invalid input follows the
        function's explicit exception path. Filesystem effects remain confined
        to the caller-selected paths and the owning resource lifecycle.

        Args:
            path: filesystem location used as the path for this operation.
            filename: Text supplied as filename in the format accepted by this
                function.
            budget_factory: Callable invoked at the budget factory boundary.
            lzma_open: Optional lzma open; ``None`` selects the function's
                default behavior.
            tar_open: Optional TAR open; ``None`` selects the function's default
                behavior.
            zstd_decompressor: Optional zstd decompressor; ``None`` selects the
                function's default behavior.
            zip_file: Optional filesystem location used as the ZIP file for this
                operation.

        Raises:
            OSError: If the staged archive cannot be opened or read.
            ValueError: If the archive violates framing or resource policy.
        """

        with Path(path).open("rb") as source:
            RedfishArtifactStore.archive_stream_is_well_formed(
                source,
                filename,
                budget_factory=budget_factory,
                lzma_open=lzma_open,
                tar_open=tar_open,
                zstd_decompressor=zstd_decompressor,
                zip_file=zip_file,
            )

    @classmethod
    def validate_and_normalize_archive_payload(
        cls, payload: bytes, filename: str
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Validate an archive and remove only a proven trailing ``[]`` defect.

        The implementation uses ``payload`` and ``filename`` to validate an
        archive and remove only a proven trailing ``[]`` defect. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path.

        Args:
            payload: Bounded byte sequence supplied as payload.
            filename: Text supplied as filename in the format accepted by this
                function.

        Returns:
            A tuple containing ``byte sequence`` and ``provenance`` in that
            order.
        """

        original_sha = hashlib.sha256(payload).hexdigest()
        provenance: Dict[str, Any] = {
            "filename": filename,
            "original_size": len(payload),
            "original_sha256": original_sha,
            "saved_size": len(payload),
            "saved_sha256": original_sha,
            "status": "invalid",
            "normalization": None,
        }
        try:
            cls.archive_payload_is_well_formed(payload, filename)
        except Exception as original_error:
            if payload.endswith(b"[]"):
                normalized = payload[:-2]
                try:
                    cls.archive_payload_is_well_formed(normalized, filename)
                except Exception:
                    pass
                else:
                    provenance.update(
                        {
                            "status": "normalized",
                            "normalization": "removed_exact_trailing_empty_json_array",
                            "saved_size": len(normalized),
                            "saved_sha256": hashlib.sha256(normalized).hexdigest(),
                            "validation_error": str(original_error),
                        }
                    )
                    return normalized, provenance
            provenance["validation_error"] = str(original_error)
            return payload, provenance

        provenance["status"] = "valid"
        return payload, provenance

    @classmethod
    def validate_and_normalize_streamed_archive_payload(
        cls,
        body: StreamedRedfishBody,
        filename: str,
        *,
        archive_stream_validator: Any = None,
        stream_hasher: Any = None,
        stream_identity: Any = None,
    ) -> Tuple[StreamedRedfishBody, Dict[str, Any]]:
        """
        Validate and conditionally normalize one pinned staging inode.

        The pinned descriptor is authoritative. Recompute identity.

        Args:
            body: Body object whose ``open_for_update``, ``prefix_bytes``,
                ``sha256``, and ``size_bytes`` state is read while performing
                and conditionally normalize one pinned staging inode.
            filename: Text supplied as filename in the format accepted by this
                function.
            archive_stream_validator: Optional archive stream validator;
                ``None`` selects the function's default behavior.
            stream_hasher: Optional stream hasher; ``None`` selects the
                function's default behavior.
            stream_identity: Optional stream identity; ``None`` selects the
                function's default behavior.

        Returns:
            A tuple containing ``body`` and ``provenance`` in that order.

        Raises:
            OSError: If streamed archive changed while reading prefix; streamed
                archive changed during validation; streamed archive changed
                during normalization; or streamed archive changed before
                rollback; or another input invariant is violated.
        """

        validate_stream = (
            cls.archive_stream_is_well_formed
            if archive_stream_validator is None
            else archive_stream_validator
        )
        hash_stream = cls.sha256_open_stream if stream_hasher is None else stream_hasher
        identify_stream = (
            cls.streamed_archive_identity
            if stream_identity is None
            else stream_identity
        )
        original_size = body.size_bytes
        original_sha256 = body.sha256
        provenance: Dict[str, Any] = {
            "filename": filename,
            "original_size": original_size,
            "original_sha256": original_sha256,
            "saved_size": original_size,
            "saved_sha256": original_sha256,
            "status": "invalid",
            "normalization": None,
        }
        try:
            with body.open_for_update() as source:
                computed_sha256 = hash_stream(
                    source,
                    expected_size=original_size,
                )
                if computed_sha256 != original_sha256:
                    raise OSError("streamed archive digest metadata is stale")
                hashed_details = os.fstat(source.fileno())
                source.seek(0)
                original_prefix = source.read(min(512, original_size))
                if identify_stream(os.fstat(source.fileno())) != identify_stream(
                    hashed_details
                ):
                    raise OSError("streamed archive changed while reading prefix")
                body.prefix_bytes = original_prefix
                baseline = hashed_details

                try:
                    validate_stream(source, filename)
                    if identify_stream(os.fstat(source.fileno())) != identify_stream(
                        baseline
                    ):
                        raise OSError("streamed archive changed during validation")
                except Exception as original_error:
                    if identify_stream(os.fstat(source.fileno())) != identify_stream(
                        baseline
                    ):
                        raise OSError(
                            "streamed archive changed during validation"
                        ) from original_error

                    trailing_empty_array = False
                    if original_size >= 2:
                        source.seek(original_size - 2)
                        trailing_empty_array = source.read(2) == b"[]"

                    if trailing_empty_array:
                        source.truncate(original_size - 2)
                        source.flush()
                        os.fsync(source.fileno())
                        normalized_size = original_size - 2
                        normalized_baseline = os.fstat(source.fileno())
                        try:
                            validate_stream(source, filename)
                            if identify_stream(
                                os.fstat(source.fileno())
                            ) != identify_stream(normalized_baseline):
                                raise OSError(
                                    "streamed archive changed during normalization"
                                )
                        except Exception as normalized_error:
                            if identify_stream(
                                os.fstat(source.fileno())
                            ) != identify_stream(normalized_baseline):
                                raise OSError(
                                    "streamed archive changed before rollback"
                                ) from normalized_error
                            source.seek(normalized_size)
                            if source.write(b"[]") != 2:
                                raise OSError(
                                    "streamed archive rollback write was incomplete"
                                )
                            source.truncate(original_size)
                            source.flush()
                            os.fsync(source.fileno())
                            if (
                                hash_stream(
                                    source,
                                    expected_size=original_size,
                                )
                                != original_sha256
                            ):
                                raise OSError(
                                    "streamed archive rollback digest mismatch"
                                )
                        else:
                            normalized_sha = hash_stream(
                                source,
                                expected_size=normalized_size,
                            )
                            normalized_details = os.fstat(source.fileno())
                            source.seek(0)
                            prefix = source.read(min(512, normalized_size))
                            if identify_stream(
                                os.fstat(source.fileno())
                            ) != identify_stream(normalized_details):
                                raise OSError(
                                    "streamed archive changed while reading prefix"
                                )
                            body.size_bytes = normalized_size
                            body.sha256 = normalized_sha
                            body.prefix_bytes = prefix
                            provenance.update(
                                {
                                    "status": "normalized",
                                    "normalization": (
                                        "removed_exact_trailing_empty_json_array"
                                    ),
                                    "saved_size": normalized_size,
                                    "saved_sha256": normalized_sha,
                                    "validation_error": str(original_error),
                                }
                            )
                            return body, provenance

                    provenance["validation_error"] = str(original_error)
                    return body, provenance

                provenance["status"] = "valid"
                return body, provenance
        except Exception as error:
            provenance["validation_error"] = str(error)
            return body, provenance

    @staticmethod
    def canonical_invalid_archive_validation(
        validation: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Return the canonical invalid archive validation.

        After applying local validation, the function forwards ``validation`` to
        ``canonical_invalid_validation`` and preserves its return and exception
        contract.

        Args:
            validation: Mapping supplying fields for canonical invalid archive
                validation.

        Returns:
            A mapping containing canonical invalid archive validation.
        """
        return canonical_invalid_validation(validation)

    @staticmethod
    def canonical_persisted_archive_validation(
        validation: Dict[str, Any], artifact_path: str
    ) -> Dict[str, Any]:
        """
        Return the canonical persisted archive validation.

        After applying local validation, the function forwards ``validation``
        and ``artifact_path`` to ``canonical_persisted_validation`` and
        preserves its return and exception contract.

        Args:
            validation: Mapping supplying fields for canonical persisted archive
                validation.
            artifact_path: filesystem location used as the artifact path for
                this operation.

        Returns:
            A mapping containing canonical persisted archive validation.
        """
        return canonical_persisted_validation(validation, artifact_path)

    @staticmethod
    def validate_accepted_archive_provenance(
        validation: Dict[str, Any],
        actual_size: int,
        actual_sha256: str,
        appended_empty_array_sha256: str,
    ) -> None:
        """
        Validate accepted archive provenance.

        The implementation uses ``validation``, ``actual_size``,
        ``actual_sha256``, and ``appended_empty_array_sha256`` to validate
        accepted archive provenance. Every required invariant is checked before
        a successful value is returned; invalid input follows the function's
        explicit exception path.

        Args:
            validation: Mapping supplying fields for accepted archive
                provenance.
            actual_size: Numeric actual size used by the operation's bounded
                accounting.
            actual_sha256: Text supplied as actual SHA-256 in the format
                accepted by this function.
            appended_empty_array_sha256: Text supplied as appended empty array
                SHA-256 in the format accepted by this function.
        """
        validate_accepted_provenance(
            validation,
            ArchiveContentIdentity(
                size=actual_size,
                sha256=actual_sha256,
                appended_empty_array_sha256=appended_empty_array_sha256,
            ),
        )

    @staticmethod
    def archive_validation_reference(validation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Archive validation reference.

        After applying local validation, the function forwards ``validation`` to
        ``validation_reference`` and preserves its return and exception
        contract. Success is reported only after the owning output boundary has
        completed its required write or publication step.

        Args:
            validation: Mapping supplying fields for validation reference.

        Returns:
            A mapping containing archive validation reference.
        """
        return validation_reference(validation)

    @staticmethod
    def restore_canonical_archive_evidence(
        source: Dict[str, Any], bounded: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Restore canonical archive evidence.

        After applying local validation, the function forwards ``source`` and
        ``bounded`` to ``restore_canonical_evidence`` and preserves its return
        and exception contract.

        Args:
            source: Mapping supplying fields for restore canonical archive
                evidence.
            bounded: Mapping supplying fields for restore canonical archive
                evidence.

        Returns:
            A mapping containing restore canonical archive evidence.
        """
        return restore_canonical_evidence(source, bounded)

    def published_archive_relative_path(
        self,
        *,
        dut_id: str,
        collector_id: str,
        group: str,
        file_path: str | Path,
        fallback_filename: str,
    ) -> str:
        """
        Derive the exact logger-published path relative to its collector.

        The implementation uses ``dut_id``, ``collector_id``, ``group``,
        ``file_path``, and ``fallback_filename`` to derive the exact
        logger-published path relative to its collector. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle. If the function cannot derive the exact logger-published path
        relative to its collector, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            group: Text supplied as group in the format accepted by this
                function.
            file_path: filesystem location used as the file path for this
                operation.
            fallback_filename: Text supplied as fallback filename in the format
                accepted by this function.

        Returns:
            The validated ``artifact_path``.

        Raises:
            ValueError: If published archive or collector directory is symbolic;
                published archive escaped its collector directory; or published
                archive path is not canonical.
        """

        relative: Optional[Path] = None
        collector_directory = getattr(
            self._facade.logger, "_collector_artifact_directory", None
        )
        if callable(collector_directory):
            root = collector_directory(
                dut_id,
                collector_id,
                group=group,
                reuse_recorded=True,
            )
            if isinstance(root, (str, Path)):
                try:
                    collector_root = Path(root).absolute()
                    published_path = Path(file_path).absolute()
                    if (
                        collector_root.resolve(strict=True) != collector_root
                        or published_path.parent.resolve(strict=True)
                        != published_path.parent
                        or (
                            (published_path.exists() or published_path.is_symlink())
                            and published_path.resolve(strict=True) != published_path
                        )
                    ):
                        raise ValueError(
                            "published archive or collector directory is symbolic"
                        )
                    relative = published_path.relative_to(collector_root)
                except ValueError as error:
                    raise ValueError(
                        "published archive escaped its collector directory"
                    ) from error
        if relative is None:
            relative = Path(fallback_filename)

        artifact_path = relative.as_posix()
        parts = artifact_path.split("/")
        if (
            not artifact_path
            or Path(artifact_path).is_absolute()
            or "\\" in artifact_path
            or any(part in {"", ".", ".."} for part in parts)
            or re.search(r"\{[^{}]+\}", artifact_path)
            or not artifact_path.lower().endswith(self.ARCHIVE_PATTERN_SUFFIXES)
        ):
            raise ValueError("published archive path is not canonical")
        return artifact_path

    @staticmethod
    def stable_archive_file_identity(path: Path) -> Tuple[int, str, str, bytes]:
        """
        Return the stable archive file identity.

        The implementation uses ``path`` to produce the stable archive file
        identity.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            A tuple containing ``size``, ``SHA-256``, ``appended empty array
            SHA-256``, and ``prefix`` in that order.
        """
        identity = stable_file_identity(path)
        return (
            identity.size,
            identity.sha256,
            identity.appended_empty_array_sha256,
            identity.prefix,
        )

    @classmethod
    def validated_archive_saved_identity(
        cls, content: Union[bytes, StreamedRedfishBody]
    ) -> Tuple[int, str, str]:
        """
        Return the validated archive saved identity.

        The implementation uses ``content`` to produce the validated archive
        saved identity.

        Args:
            content: Bounded byte sequence supplied as content.

        Returns:
            A tuple containing ``size``, ``SHA-256``, and ``appended empty array
            SHA-256`` in that order.
        """
        if isinstance(content, StreamedRedfishBody):
            identity = stable_file_identity(content.private_path)
            content.size_bytes = identity.size
            content.sha256 = identity.sha256
            content.prefix_bytes = identity.prefix
        else:
            identity = identity_from_bytes(content)
        return (
            identity.size,
            identity.sha256,
            identity.appended_empty_array_sha256,
        )

    @classmethod
    def publish_archive_no_replace(
        cls,
        destination: Path,
        content: Union[bytes, StreamedRedfishBody],
        expected_size: int,
        expected_sha256: str,
    ) -> Tuple[int, str]:
        """
        Publish archive no replace.

        The implementation uses ``destination``, ``content``, ``expected_size``,
        and ``expected_sha256`` to publish archive no replace. Success is
        reported only after the owning output boundary has completed its
        required write or publication step.

        Args:
            destination: filesystem location used as the destination for this
                operation.
            content: Bounded byte sequence supplied as content.
            expected_size: Numeric expected size used by the operation's bounded
                accounting.
            expected_sha256: Text supplied as expected SHA-256 in the format
                accepted by this function.

        Returns:
            A tuple containing ``size`` and ``SHA-256`` in that order.
        """
        if isinstance(content, StreamedRedfishBody):
            identity = publish_archive_no_replace(
                destination,
                expected_size=expected_size,
                expected_sha256=expected_sha256,
                source_path=content.private_path,
            )
        else:
            identity = publish_archive_no_replace(
                destination,
                expected_size=expected_size,
                expected_sha256=expected_sha256,
                payload=content,
            )
        return identity.size, identity.sha256

    async def record_archive_validation(
        self,
        dut_id: str,
        validation: Dict[str, Any],
        *,
        collector_id: str,
        function_tag: str,
    ) -> Optional[str]:
        """
        Persist archive integrity provenance as diagnostic evidence.

        After applying local validation, the function forwards ``dut_id``,
        ``validation``, ``collector_id``, and ``function_tag`` to
        ``self._facade._append_to_diagnostic_json_array`` and preserves its
        return and exception contract. Success is reported only after the owning
        output boundary has completed its required write or publication step.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            validation: Mapping supplying fields for archive integrity
                provenance as diagnostic evidence.
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            function_tag: Text supplied as function tag in the format accepted
                by this function.

        Returns:
            The canonical record archive validation text, or ``None`` when the
            requested value is unavailable.
        """

        return await self._facade._append_to_diagnostic_json_array(
            dut_id,
            validation,
            function_tag,
            "archive_validation",
            collector_id,
        )
