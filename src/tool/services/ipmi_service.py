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
IPMI Service - Handles all IPMI-related collector operations.

Provides IPMI-based collectors for BMC access including SEL logs, sensor data,
FRU information, and system diagnostics via ipmitool.
"""

import asyncio
import logging
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple, Union

from ..utils.managed_filesystem import (
    run_managed_filesystem_operation as _run_managed_operation,
)
from .base_service import BaseService

logger = logging.getLogger(__name__)


_FRU_BLOCK_HEADER_RE = re.compile(r"(?m)^FRU Device Description[^\r\n]*$")
_FRU_HEADER_RE = re.compile(r"^FRU Device Description\s*:\s*\S.*$", re.I)
_DEVICE_NOT_PRESENT = "Device not present"
_FRU_ABSENT_LINE_RE = re.compile(
    rf"^{re.escape(_DEVICE_NOT_PRESENT)}(?:\s*\((?:"
    r"Requested sensor, data, or record not found|"
    r"Command response 0xcb)\))?$",
    re.I,
)
_FRU_FIELD_LINE_RE = re.compile(r"^[ \t]+[^ \t:\r\n][^:\r\n]*:[ \t]*[^\r\n]*$")
_FRU_RECORD_HEADER_LINE_RE = re.compile(
    r"^[ \t]+[A-Za-z0-9][A-Za-z0-9 /+()._-]* Record(?:\s+\d+)?\s*$",
    re.I,
)
_FRU_SUCCESS_FIELD_RE = re.compile(
    r"^(?:Board Product|Product Name|Board Serial|Product Serial|"
    r"Board Part Number|Product Part Number)\s*:\s*\S.*$",
    re.I,
)
_FRU_DIAGNOSTIC_RE = re.compile(
    r"\b(?:error|failed|failure|unable|warning|timeout|authentication|invalid|"
    r"cannot|illegal|truncated|unavailable|unsupported|disabled|unknown|busy|"
    r"unexpected|malformed|denied|unauthorized|unreachable|refused)\b|"
    r"\b(?:timed out|could not|no response|insufficient privilege(?: level)?|"
    r"out of range|not supported|out of space|node busy|unspecified error|"
    r"not present|not found|lost arbitration|initialization in progress|"
    r"limit exceeded|reservation cancell?ed|completion code|duplicate request|"
    r"update mode|command response 0x[0-9a-f]+|"
    r"session (?:failure|failed|error))\b",
    re.I,
)
_IPMI_AUTH_OR_SESSION_FAILURE_RE = re.compile(
    r"(?:unable to establish IPMI(?: v2 / RMCP\+)? session|"
    r"password verification failed|invalid user name|authentication failed)",
    re.I,
)
_SDR_INFO_ERROR = "Error obtaining SDR info"
_SDR_INFO_ERROR_LINES = frozenset(
    {
        _SDR_INFO_ERROR.casefold(),
        "Unable to open SDR for reading".casefold(),
    }
)
_SDR_ELIST_ROW_RE = re.compile(r"(?m)^.+?\|\s*[0-9A-Fa-f]+h\s*\|")
_SDR_RECORD_ERROR = "ipmi_sdr_get_record() failed"
_SDR_RECORD_ERROR_LINES = frozenset(
    {
        _SDR_RECORD_ERROR,
        f"ipmitool: {_SDR_RECORD_ERROR}",
    }
)
_SEL_NO_ENTRIES = "SEL has no entries"
_SEL_INFO_ENTRIES_RE = re.compile(r"(?im)^[ \t]*Entries[ \t]*:[ \t]*(\d+)[ \t]*$")
_SEL_RAW_RECORD_SIZE = 16

# These ceilings govern only whether non-zero ``fru print`` output is promoted
# to a semantic partial success. The full bounded transport output is still
# persisted and reported on rejection. The aggregate value matches the local
# subprocess stdout admission boundary; the line ceiling prevents one record
# from monopolizing the shared parser path.
FRU_PARTIAL_PARSE_MAX_CHARACTERS = 64 * 1024 * 1024
FRU_PARTIAL_PARSE_MAX_LINE_CHARACTERS = 64 * 1024


def _is_fru_print_command(command: str) -> bool:
    """
    Return whether ``command`` is exactly the supported FRU-print form.

    The implementation uses ``command`` to determine whether ``command`` is
    exactly the supported FRU-print form.

    Args:
        command: Text supplied as command in the format accepted by this
            function.

    Returns:
        Whether ``command`` is exactly the supported FRU-print form.
    """

    try:
        command_tokens = [token.casefold() for token in shlex.split(command)]
    except (AttributeError, TypeError, ValueError):
        return False
    return command_tokens in (["fru", "print"], ["ipmitool", "fru", "print"])


def _fru_line_has_diagnostic(raw_line: str, stripped_line: str) -> bool:
    """
    Return whether a FRU body line carries authoritative failure text.

    The implementation uses ``raw_line`` and ``stripped_line`` to determine
    whether a FRU body line carries authoritative failure text.

    Args:
        raw_line: Text supplied as raw line in the format accepted by this
            function.
        stripped_line: Text supplied as stripped line in the format accepted by
            this function.

    Returns:
        Whether a FRU body line carries authoritative failure text.
    """

    if _FRU_ABSENT_LINE_RE.fullmatch(stripped_line) is not None:
        return False
    if _FRU_FIELD_LINE_RE.fullmatch(raw_line) is not None:
        field_name, _, field_value = stripped_line.partition(":")
        if _FRU_DIAGNOSTIC_RE.search(field_name) is not None:
            return True
        if _FRU_SUCCESS_FIELD_RE.fullmatch(stripped_line) is None:
            return False
        return _FRU_DIAGNOSTIC_RE.search(field_value) is not None
    return _FRU_DIAGNOSTIC_RE.search(stripped_line) is not None


def _fru_print_record_counts(stdout: str) -> Tuple[int, int] | None:
    """
    Parse a complete FRU transcript into successful and absent records.

    The implementation uses ``stdout`` to parse a complete FRU transcript into
    successful and absent records. Parsing or I/O must finish before the
    validated representation is made available to the caller.

    Args:
        stdout: Text supplied as stdout in the format accepted by this function.

    Returns:
        A tuple containing ``successful records`` and ``absent records`` in that
        order.
    """

    stdout_text = stdout if stdout is not None else ""
    if len(stdout_text) > FRU_PARTIAL_PARSE_MAX_CHARACTERS:
        return None
    transcript_lines = stdout_text.splitlines()
    if any(
        len(line) > FRU_PARTIAL_PARSE_MAX_LINE_CHARACTERS for line in transcript_lines
    ):
        return None
    if _IPMI_AUTH_OR_SESSION_FAILURE_RE.search(stdout_text) is not None:
        return None
    block_headers = list(_FRU_BLOCK_HEADER_RE.finditer(stdout_text))
    if not block_headers or stdout_text[: block_headers[0].start()].strip():
        return None
    successful_records = 0
    absent_records = 0
    for index, header_match in enumerate(block_headers):
        block_end = (
            block_headers[index + 1].start()
            if index + 1 < len(block_headers)
            else len(stdout_text)
        )
        block = stdout_text[header_match.start() : block_end]
        block_lines = block.splitlines()
        if (
            not block_lines
            or _FRU_HEADER_RE.fullmatch(block_lines[0]) is None
            or _FRU_DIAGNOSTIC_RE.search(block_lines[0]) is not None
        ):
            return None
        body_lines = [line for line in block_lines[1:] if line.strip()]
        lines = [line.strip() for line in body_lines]
        if not lines:
            return None
        if any(
            _fru_line_has_diagnostic(raw_line, stripped_line)
            for raw_line, stripped_line in zip(body_lines, lines)
        ):
            return None
        absent_lines = [
            line for line in lines if _FRU_ABSENT_LINE_RE.fullmatch(line) is not None
        ]
        if len(absent_lines) == len(lines):
            if any(not line[:1].isspace() for line in body_lines):
                return None
            absent_records += 1
        elif absent_lines:
            return None
        elif all(
            _FRU_FIELD_LINE_RE.fullmatch(line) is not None
            or _FRU_RECORD_HEADER_LINE_RE.fullmatch(line) is not None
            for line in body_lines
        ) and any(_FRU_SUCCESS_FIELD_RE.fullmatch(line) is not None for line in lines):
            successful_records += 1
        else:
            return None
    return successful_records, absent_records


def _fru_print_partial_success(command: str, stdout: str, stderr: str) -> bool:
    """
    Return the fru print partial success.

    The implementation uses ``command``, ``stdout``, and ``stderr`` to produce
    the fru print partial success.

    Args:
        command: Text supplied as command in the format accepted by this
            function.
        stdout: Text supplied as stdout in the format accepted by this function.
        stderr: Text supplied as stderr in the format accepted by this function.

    Returns:
        Whether the fru print partial success operation succeeds.
    """
    absent_fru_tolerated, _ = _classify_fru_partial_output(command, stdout, stderr)
    return absent_fru_tolerated


def _fru_print_sdr_partial_result(command: str, stdout: str, stderr: str) -> int:
    """
    Count useful FRU blocks when SDR enumeration fails.

    Some BMCs return the built-in FRU successfully, then exit non-zero because
    the SDR repository needed to discover additional FRUs is unavailable. The
    captured FRU data is useful, but the collection is incomplete and must be
    reported as partial rather than either a full success or a total failure.

    Args:
        command: Text supplied as command in the format accepted by this
            function.
        stdout: Text supplied as stdout in the format accepted by this function.
        stderr: Text supplied as stderr in the format accepted by this function.

    Returns:
        The numeric fru print sdr partial result value.
    """

    _, valid_partial_records = _classify_fru_partial_output(command, stdout, stderr)
    return valid_partial_records


def _classify_fru_partial_output(
    command: str, stdout: str, stderr: str
) -> Tuple[bool, int]:
    """
    Classify both governed FRU non-zero success forms with one parse.

    The result distinguishes tolerated absent FRUs from useful records retained
    when SDR enumeration fails after partial FRU output.

    Args:
        command: IPMI command associated with the captured output.
        stdout: Captured standard output from the IPMI process.
        stderr: Captured standard error from the IPMI process.

    Returns:
        A tuple containing the absent-FRU decision and valid partial-record
        count, in that order.
    """

    if not _is_fru_print_command(command):
        return False, 0
    record_counts = _fru_print_record_counts(stdout)
    if record_counts is None:
        return False, 0
    successful_records, absent_records = record_counts
    stderr_text = stderr if stderr is not None else ""
    stderr_lines = [line.strip() for line in stderr_text.splitlines() if line.strip()]
    absent_fru_tolerated = (
        successful_records > 0
        and absent_records > 0
        and all(
            _FRU_ABSENT_LINE_RE.fullmatch(line) is not None for line in stderr_lines
        )
    )
    folded_stderr_lines = [line.casefold() for line in stderr_lines]
    valid_partial_records = (
        successful_records
        if not absent_records
        and _SDR_INFO_ERROR.casefold() in folded_stderr_lines
        and all(line in _SDR_INFO_ERROR_LINES for line in folded_stderr_lines)
        else 0
    )
    return absent_fru_tolerated, valid_partial_records


def _sel_has_no_entries(stdout: str, stderr: str) -> bool:
    """
    Return True for an explicitly reported, valid empty SEL result.

    The implementation uses ``stdout`` and ``stderr`` to produce True for an
    explicitly reported, valid empty SEL result.

    Args:
        stdout: Text supplied as stdout in the format accepted by this function.
        stderr: Text supplied as stderr in the format accepted by this function.

    Returns:
        Whether the true for an explicitly reported, valid empty SEL result
        operation succeeds.
    """

    return any(
        line.strip() == _SEL_NO_ENTRIES
        for stream in (stdout, stderr)
        for line in (stream or "").splitlines()
    )


def _sel_writeraw_path(command: str) -> Path | None:
    """
    Return the artifact path for an ``ipmitool sel writeraw`` command.

    After applying local validation, the function forwards ``command`` to
    ``Path`` and preserves its return and exception contract.

    Args:
        command: Text supplied as command in the format accepted by this
            function.

    Returns:
        The validated sel writeraw path filesystem path, or ``None`` when the
        requested value is unavailable.
    """

    try:
        tokens = shlex.split(command or "")
    except ValueError:
        return None
    for index in range(len(tokens) - 2):
        if tokens[index : index + 2] == ["sel", "writeraw"]:
            return Path(tokens[index + 2])
    return None


def _sel_info_entry_count(stdout: str) -> int | None:
    """
    Parse the SEL entry count advertised by ``ipmitool sel info``.

    The implementation uses ``stdout`` to parse the SEL entry count advertised
    by ``ipmitool sel info``. Parsing or I/O must finish before the validated
    representation is made available to the caller.

    Args:
        stdout: Text supplied as stdout in the format accepted by this function.

    Returns:
        The numeric sel info entry count, or ``None`` when the requested value
        is unavailable.
    """

    match = _SEL_INFO_ENTRIES_RE.search(stdout or "")
    return int(match.group(1)) if match else None


def _sel_writeraw_failure_count(stdout: str, stderr: str) -> int:
    """
    Count exit-zero firmware/session failures in writeraw output.

    The implementation uses ``stdout`` and ``stderr`` to extract exit-zero
    firmware/session failures from writeraw output.

    Args:
        stdout: Text supplied as stdout in the format accepted by this function.
        stderr: Text supplied as stderr in the format accepted by this function.

    Returns:
        The number of matching diagnostic lines. Raw lines remain in the
        captured transcript and are never promoted into control metadata.
    """

    diagnostic_count = 0
    for line in f"{stdout or ''}\n{stderr or ''}".splitlines():
        stripped = line.strip()
        if stripped and re.search(
            r"\b(?:command failed|close session.*failed)\b", stripped, re.I
        ):
            diagnostic_count += 1
    return diagnostic_count


def _sdr_elist_partial_result(
    command: str, stdout: str, stderr: str
) -> Tuple[int, int]:
    """
    Return valid/failed SDR record counts for a useful non-zero ``sdr elist``.

    ipmitool exits non-zero when individual SDR records cannot be read even
    though it may have emitted hundreds of valid rows. Treat that outcome as
    partial rather than discarding the useful repository data as a total command
    failure.

    Args:
        command: Text supplied as command in the format accepted by this
            function.
        stdout: Text supplied as stdout in the format accepted by this function.
        stderr: Text supplied as stderr in the format accepted by this function.

    Returns:
        A tuple containing ``integer count`` and ``integer count`` in that
        order.
    """

    normalized_command = " ".join((command or "").lower().split())
    if not re.search(r"\bsdr elist\b", normalized_command):
        return 0, 0
    valid_records = sum(1 for _match in _SDR_ELIST_ROW_RE.finditer(stdout or ""))
    stderr_text = stderr if stderr is not None else ""
    stderr_lines = [line.strip() for line in stderr_text.splitlines() if line.strip()]
    if any(line not in _SDR_RECORD_ERROR_LINES for line in stderr_lines):
        return 0, 0
    failed_records = len(stderr_lines)
    if valid_records <= 0 or failed_records <= 0:
        return 0, 0
    return valid_records, failed_records


@dataclass(frozen=True)
class _IPMIOutputClassification:
    """
    Retain bounded semantic classifications for captured IPMI output.

    One immutable value transfers the worker-derived decisions back to the
    event-loop owner without retaining or promoting raw device text.

    Attributes:
        absent_fru_tolerated: Whether missing FRUs are the only tolerated error.
        valid_partial_fru_records: Number of useful FRU records captured before
            an SDR enumeration failure.
        valid_sdr_records: Number of valid SDR rows in a partial result.
        failed_sdr_records: Number of governed SDR failures in a partial result.
        empty_sel_result: Whether the transcript explicitly represents an empty
            SEL result.
    """

    absent_fru_tolerated: bool
    valid_partial_fru_records: int
    valid_sdr_records: int
    failed_sdr_records: int
    empty_sel_result: bool


def _classify_ipmi_output(
    command: str,
    stdout: str,
    stderr: str,
    exit_code: int,
    ignore_absent_fru: bool,
) -> _IPMIOutputClassification:
    """
    Classify a captured transcript outside the event-loop thread.

    CPU-bound pattern matching is grouped into one worker operation so large
    captured transcripts do not delay unrelated asynchronous services.

    Args:
        command: IPMI command associated with the captured transcript.
        stdout: Captured standard output from the IPMI process.
        stderr: Captured standard error from the IPMI process.
        exit_code: Exit status returned by the IPMI process.
        ignore_absent_fru: Whether governed absent-FRU errors may be tolerated.

    Returns:
        The immutable semantic classification of the captured transcript.
    """

    absent_fru_tolerated = False
    valid_partial_fru_records = 0
    if ignore_absent_fru and exit_code != 0:
        absent_fru_tolerated, valid_partial_fru_records = _classify_fru_partial_output(
            command, stdout, stderr
        )
    valid_sdr_records, failed_sdr_records = _sdr_elist_partial_result(
        command, stdout, stderr
    )
    return _IPMIOutputClassification(
        absent_fru_tolerated=absent_fru_tolerated,
        valid_partial_fru_records=valid_partial_fru_records,
        valid_sdr_records=valid_sdr_records,
        failed_sdr_records=failed_sdr_records,
        empty_sel_result=exit_code == 0 and _sel_has_no_entries(stdout, stderr),
    )


def _inspect_sel_writeraw_result(
    raw_path: Path,
    stdout: str,
    stderr: str,
    info_exit: int,
    info_stdout: str,
) -> Tuple[int | None, int | None, str | None, int]:
    """
    Inspect the SEL artifact and transcript on an owned blocking worker.

    Filesystem metadata and bounded diagnostic classification remain off the
    event loop while raw device lines stay confined to the captured transcript.

    Args:
        raw_path: Path to the locally captured raw SEL artifact.
        stdout: Captured standard output from the writeraw command.
        stderr: Captured standard error from the writeraw command.
        info_exit: Exit status returned by the SEL information command.
        info_stdout: Captured standard output from the SEL information command.

    Returns:
        A tuple containing the advertised entry count, raw record count,
        artifact error, and bounded failure-diagnostic count, in that order.
    """

    advertised_count = _sel_info_entry_count(info_stdout) if info_exit == 0 else None
    raw_record_count: int | None = None
    artifact_error: str | None = None
    try:
        artifact_size = raw_path.stat().st_size
        raw_record_count = artifact_size // _SEL_RAW_RECORD_SIZE
        if artifact_size % _SEL_RAW_RECORD_SIZE:
            artifact_error = (
                f"SEL writeraw artifact size {artifact_size} is not a multiple of "
                f"{_SEL_RAW_RECORD_SIZE} bytes"
            )
    except (FileNotFoundError, OSError):
        artifact_error = f"SEL writeraw artifact is unavailable at {raw_path}"
    return (
        advertised_count,
        raw_record_count,
        artifact_error,
        _sel_writeraw_failure_count(stdout, stderr),
    )


class IPMIService(BaseService):
    """
    Service for IPMI operations.

    The type coordinates ``validate_connection``, ``_validate_bmc_connection``,
    ``_resolve_ipmi_command_timeout``, ``run_ipmi_command``, and
    ``run_ipmi_command_with_nvbmc_handling`` and retains the state those
    operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    def __init__(self, service_name: str, orchestrator: Any) -> None:
        """
        Initialize IPMI service.

        The initializer establishes the instance invariants required by later
        operations before the object becomes visible to callers.

        Args:
            service_name: Stable service name used for lookup and
                operator-facing diagnostics.
            orchestrator: Orchestrator consumed while the function attempts to
                initialize IPMI service.
        """
        super().__init__(service_name, orchestrator)

    async def validate_connection(self, dut_id: str) -> Tuple[bool, str]:
        """
        Validate IPMI connection.

        After applying local validation, the function forwards ``dut_id`` to
        ``test_ipmi_connection`` and preserves its return and exception
        contract. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A tuple containing the connection-success flag and sanitized
            diagnostic message.
        """
        return await self.dut_manager.get_dut(dut_id).test_ipmi_connection()

    # Validation methods
    async def _validate_bmc_connection(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Validate BMC connection.

        Check if IPMI connection state indicates it's already connected.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing BMC connection.
        """
        try:
            # Check if IPMI connection state indicates it's already connected
            dut = self.dut_manager.get_dut(dut_id)

            # Check if we're in local mode without BMC IP - if so, skip BMC validation
            if dut.config and dut.config.get("local", False):
                has_bmc_ip = dut.credentials and dut.credentials.bmc_ip
                if not has_bmc_ip:
                    await self._log_runtime(
                        "INFO",
                        "IPMIService",
                        f"DUT {dut_id} is in local mode without BMC IP - skipping BMC validation for local IPMI execution",
                        dut_id,
                    )
                    return await self._create_standardized_collector_result(
                        successful_operations=1,
                        total_operations=1,
                        output_files=[],
                        error_messages=[],
                        operation_name="ipmi_validation",
                        additional_context={
                            "reason": "Local mode without BMC IP - BMC validation skipped for local IPMI execution",
                            "bmc_available": False,
                            "local_mode": True,
                        },
                    )

            # First check if we have preflight results
            preflight_results = getattr(dut, "preflight_results", {})

            if preflight_results:
                ipmi_service_result = preflight_results.get("services", {}).get(
                    "ipmi", {}
                )
                if ipmi_service_result:
                    preflight_status = ipmi_service_result.get("status", "unknown")
                    preflight_message = ipmi_service_result.get("message", "")

                    await self._log_runtime(
                        "DEBUG",
                        "IPMIService",
                        f"Found preflight results for IPMI connection: status={preflight_status}, message={preflight_message}",
                        dut_id,
                    )

                    if preflight_status == "pass":
                        await self._log_runtime(
                            "INFO",
                            "IPMIService",
                            "Using preflight results for IPMI validation - connection already verified",
                            dut_id,
                        )
                        return await self._create_standardized_collector_result(
                            successful_operations=1,
                            total_operations=1,
                            output_files=[],
                            error_messages=[],
                            operation_name="ipmi_validation",
                            additional_context={
                                "validation_message": f"Preflight verified: {preflight_message}",
                                "bmc_available": True,
                                "preflight_used": True,
                            },
                        )
                    elif preflight_status == "fail":
                        await self._log_runtime(
                            "WARN",
                            "IPMIService",
                            f"Preflight failed for IPMI connection: {preflight_message}",
                            dut_id,
                        )
                        return await self._create_standardized_collector_result(
                            successful_operations=0,
                            total_operations=1,
                            output_files=[],
                            error_messages=[f"Preflight failed: {preflight_message}"],
                            operation_name="ipmi_validation",
                            additional_context={
                                "validation_message": f"Preflight failed: {preflight_message}",
                                "bmc_available": False,
                                "preflight_used": True,
                            },
                        )

            # No preflight results or unknown status - run connection test
            await self._log_runtime(
                "DEBUG",
                "IPMIService",
                "No preflight results found or unknown status - running IPMI connection test",
                dut_id,
            )

            success, message = await self.validate_connection(dut_id)

            # Log the validation result
            if success:
                await self._log_runtime(
                    "INFO",
                    "IPMIService",
                    f"IPMI connection validation passed: {message}",
                    dut_id,
                )
            else:
                await self._log_runtime(
                    "ERROR",
                    "IPMIService",
                    f"IPMI connection validation failed: {message}",
                    dut_id,
                )

            return await self._create_standardized_collector_result(
                successful_operations=1 if success else 0,
                total_operations=1,
                output_files=[],
                error_messages=[] if success else [message],
                operation_name="ipmi_validation",
                additional_context={
                    "validation_message": message,
                    "bmc_available": success,
                    "preflight_used": False,
                },
            )
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "IPMIService",
                f"IPMI validation exception: {str(e)}",
                dut_id,
            )
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[f"IPMI validation error: {str(e)}"],
                operation_name="ipmi_validation",
                additional_context={"bmc_available": False},
                dut_id=dut_id,
                collector_id="ipmi_validation",
            )

    # Execution methods
    async def _resolve_ipmi_command_timeout(
        self, dut_id: str, kwargs: Dict[str, Any], default_timeout: int = 300
    ) -> int:
        """
        Resolve the timeout for a single IPMI command hook.

        After applying local validation, the function forwards ``dut_id``,
        ``kwargs``, and ``default_timeout`` to
        ``self._resolve_collector_timeout`` and preserves its return and
        exception contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            kwargs: Mapping supplying fields for timeout for a single IPMI
                command hook.
            default_timeout: Maximum duration in seconds allowed for default
                timeout.

        Returns:
            The numeric IPMI command timeout value.
        """
        return await self._resolve_collector_timeout(
            dut_id, kwargs, default_timeout=default_timeout
        )

    async def run_ipmi_command(
        self, dut_id: str, command: str, collection_level: str = "L1", **kwargs
    ) -> Dict[str, Any]:
        """
        Run IPMI command with collection level handling.

        The implementation uses ``dut_id``, ``command``, ``collection_level``,
        and ``kwargs`` to run IPMI command with collection level handling.
        Terminal status is emitted only after IPMI command with collection level
        handling and its owned cleanup have completed. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run IPMI command.
        """
        await self._log_runtime(
            "INFO", "IPMIService", f"Executing IPMI command: {command}", dut_id
        )
        timing_operation_id = None
        try:
            # Handle collection level variations if provided
            if "collection_level_handling" in kwargs:
                level_commands = kwargs["collection_level_handling"]
                if collection_level in level_commands:
                    command = level_commands[collection_level]

            timeout = await self._resolve_ipmi_command_timeout(dut_id, kwargs)
            if self.timing_manager:
                timing_operation_id = self.timing_manager.start_operation(
                    "ipmi_command",
                    kwargs.get("function_tag", "ipmi_command"),
                )
            try:
                exit_code, stdout, stderr = await self.dut_manager.execute_ipmi_command(
                    dut_id,
                    command,
                    timeout=timeout,
                    retry_verbose_on_failure=kwargs.get(
                        "retry_verbose_on_failure", True
                    ),
                )
            except BaseException as exc:
                if self.timing_manager:
                    self.timing_manager.end_operation(
                        timing_operation_id,
                        status=(
                            "cancelled"
                            if isinstance(exc, asyncio.CancelledError)
                            else "error"
                        ),
                        error=str(exc),
                    )
                raise
            # Log command result using common utility
            await self._log_command_result(
                command,
                exit_code,
                stdout,
                stderr,
                "ipmi",
                dut_id,
                kwargs.get("collector_id"),
                log_errors=True,
            )

            # Check if we should ignore command failures
            ignore_errors = kwargs.get("ignore_errors", False)
            ignore_absent_fru = kwargs.get("ignore_absent_fru", False)
            classification = await _run_managed_operation(
                _classify_ipmi_output,
                command,
                stdout,
                stderr,
                exit_code,
                ignore_absent_fru,
            )
            absent_fru_tolerated = classification.absent_fru_tolerated
            valid_partial_fru_records = classification.valid_partial_fru_records
            partial_fru_result = (
                ignore_absent_fru and exit_code != 0 and valid_partial_fru_records > 0
            )
            valid_sdr_records = classification.valid_sdr_records
            failed_sdr_records = classification.failed_sdr_records
            partial_sdr_result = (
                exit_code != 0 and valid_sdr_records > 0 and failed_sdr_records > 0
            )
            success = (
                exit_code == 0
                or ignore_errors
                or absent_fru_tolerated
                or partial_fru_result
                or partial_sdr_result
            )
            empty_sel_result = classification.empty_sel_result

            # Create output file with generalization using common utility
            content = self._create_command_output_content(
                command, exit_code, stdout, stderr
            )
            output_pattern = kwargs.get("filename")
            if not success:
                diagnostic_name = output_pattern or (
                    f"{kwargs.get('function_tag', 'ipmi_command')}.txt"
                )
                output_pattern = f"diagnostic/{diagnostic_name}"
            file_path = await self.write_output_with_generalization(
                dut_id,
                kwargs.get("collector_id", ""),
                content,
                output_pattern=output_pattern,
                function_tag=kwargs.get("function_tag", "ipmi_command"),
            )

            if self.timing_manager:
                self.timing_manager.end_operation(
                    timing_operation_id,
                    status=(
                        "success"
                        if success and exit_code == 0
                        else ("completed_nonzero" if success else "error")
                    ),
                    artifact_path=file_path,
                    metadata={
                        "exit_code": exit_code,
                        "raw_exit_code": exit_code,
                        "semantic_success": success,
                        "ignored_nonzero": bool(exit_code != 0 and ignore_errors),
                        "absent_fru_tolerated": absent_fru_tolerated,
                        "partial_fru_result": partial_fru_result,
                        "valid_partial_fru_records": valid_partial_fru_records,
                        "partial_sdr_result": partial_sdr_result,
                        "empty_sel_result": empty_sel_result,
                    },
                )

            if absent_fru_tolerated:
                await self._log_runtime(
                    "WARN",
                    "IPMIService",
                    f"IPMI command '{command}' exited {exit_code} but stdout "
                    "contained valid FRU data; remaining slots reported "
                    "'Device not present' — treating as partial success",
                    dut_id,
                )

            partial_fru_message = (
                f"Collected {valid_partial_fru_records} valid FRU record"
                f"{'s' if valid_partial_fru_records != 1 else ''}, but ipmitool "
                "could not query the SDR repository to discover all FRUs"
            )
            if partial_fru_result:
                await self._log_runtime(
                    "WARN",
                    "IPMIService",
                    f"IPMI command '{command}' exited {exit_code} after returning "
                    f"{valid_partial_fru_records} valid FRU record(s); SDR "
                    "enumeration failed — treating as partial",
                    dut_id,
                )

            if partial_sdr_result:
                await self._log_runtime(
                    "WARN",
                    "IPMIService",
                    f"IPMI command '{command}' exited {exit_code} after returning "
                    f"{valid_sdr_records} valid SDR records; {failed_sdr_records} "
                    "records could not be read — treating as partial",
                    dut_id,
                )

            await self._log_runtime(
                "INFO" if success else "ERROR",
                "IPMIService",
                f"IPMI command completed with exit code {exit_code}: {command} (ignore_errors={ignore_errors})",
                dut_id,
            )

            # Create detailed error log if command failed
            error_log_path = ""
            if not success:
                try:
                    error_context = {
                        "operation_name": "ipmi_command",
                        "error_messages": [
                            f"IPMI command failed with exit code {exit_code}"
                        ],
                        "additional_context": {
                            "command": command,
                            "collection_level": collection_level,
                            "exit_code": exit_code,
                            "stdout": self._process_command_output(stdout),
                            "stderr": self._process_command_output(stderr),
                        },
                    }
                    collector_id = (
                        kwargs.get("collector_id")
                        or self._get_current_collector_id()
                        or "ipmi_command"
                    )
                    error_log_path = await self._log_collector_error(
                        dut_id,
                        collector_id,
                        f"IPMI command failed with exit code {exit_code}",
                        error_context,
                    )
                except Exception as log_error:
                    await self._log_runtime(
                        "ERROR",
                        "IPMIService",
                        f"Failed to create error log: {log_error}",
                        dut_id,
                    )

            partial_sdr_message = (
                f"Collected {valid_sdr_records} valid SDR records, but "
                f"{failed_sdr_records} SDR records could not be read"
            )
            partial_result = partial_fru_result or partial_sdr_result
            partial_message = (
                partial_fru_message if partial_fru_result else partial_sdr_message
            )
            empty_sel_message = (
                "No SEL entries found; collection completed successfully"
            )
            return await self._create_standardized_collector_result(
                successful_operations=(1 if success else 0),
                total_operations=(2 if partial_result else 1),
                output_files=[file_path] if success and file_path else [],
                error_messages=(
                    [partial_message]
                    if partial_result
                    else (
                        []
                        if success
                        else [f"IPMI command failed with exit code {exit_code}"]
                    )
                ),
                operation_name="ipmi_command",
                additional_context={
                    "command": command,
                    "collection_level": collection_level,
                    "exit_code": exit_code,
                    "output": self._process_command_output(stdout),
                    "stderr": self._process_command_output(stderr),
                    "error_log_path": error_log_path,
                    "absent_fru_tolerated": absent_fru_tolerated,
                    "partial_fru_result": partial_fru_result,
                    "valid_partial_fru_records": valid_partial_fru_records,
                    "valid_sdr_records": valid_sdr_records,
                    "failed_sdr_records": failed_sdr_records,
                    **(
                        {"diagnostic_files": [file_path]}
                        if not success and file_path
                        else {}
                    ),
                    **(
                        {
                            "status": "partial",
                            "reason": partial_message,
                        }
                        if partial_result
                        else (
                            {
                                "status": "success",
                                "reason": empty_sel_message,
                                "empty_result": True,
                            }
                            if empty_sel_result
                            else {}
                        )
                    ),
                },
            )
        except asyncio.CancelledError as e:
            if self.timing_manager:
                self.timing_manager.end_operation(
                    timing_operation_id,
                    status="cancelled",
                    error=str(e),
                )
            raise
        except Exception as e:
            if self.timing_manager:
                self.timing_manager.end_operation(
                    timing_operation_id,
                    status="error",
                    error=str(e),
                )
            await self._log_runtime(
                "ERROR",
                "IPMIService",
                f"IPMI command failed with exception: {str(e)}",
                dut_id,
            )

            # Create detailed error log for exception
            error_log_path = ""
            try:
                error_context = {
                    "operation_name": "ipmi_command",
                    "error_messages": [f"IPMI command failed with exception: {str(e)}"],
                    "additional_context": {
                        "command": command,
                        "collection_level": collection_level,
                        "exception": str(e),
                        "exception_type": type(e).__name__,
                    },
                }
                collector_id = (
                    kwargs.get("collector_id")
                    or self._get_current_collector_id()
                    or "ipmi_command"
                )
                error_log_path = await self._log_collector_error(
                    dut_id,
                    collector_id,
                    f"IPMI command failed with exception: {str(e)}",
                    error_context,
                )
            except Exception as log_error:
                await self._log_runtime(
                    "ERROR",
                    "IPMIService",
                    f"Failed to create error log for exception: {log_error}",
                    dut_id,
                )

            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="ipmi_command",
                additional_context={
                    "command": command,
                    "error_log_path": error_log_path,
                },
                dut_id=dut_id,
                collector_id="ipmi_command",
            )

    async def run_ipmi_command_with_nvbmc_handling(
        self, dut_id: str, command: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Run IPMI command with NVBMC-specific handling (legacy-compatible).

        Run the original command once (like legacy code).

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run IPMI command with nvbmc handling.
        """
        try:
            # Run the original command once (like legacy code)
            timeout = await self._resolve_ipmi_command_timeout(dut_id, kwargs)
            exit_code, stdout, stderr = await self.dut_manager.execute_ipmi_command(
                dut_id,
                command,
                timeout=timeout,
                return_verbose_failure_output=True,
            )

            # A nonzero exit can be accepted only when stdout positively parses as
            # session-info data. Known NVBMC diagnostics mean the command is not
            # supported; endpoint-authored error text must never become success.
            success = exit_code == 0
            nonzero_success_reason = ""
            unsupported_command = False

            # Only a complete, canonical session-handle record can prove that
            # a nonzero command still returned usable session data.
            valid_session_data = bool(
                re.search(
                    r"(?im)^\s*session\s+handle\s*:\s*(?:0x)?[0-9a-f]+\s*$",
                    stdout or "",
                )
            )
            if not success and stdout:
                if valid_session_data:
                    success = True
                    nonzero_success_reason = (
                        "IPMI returned valid session data despite a nonzero exit; "
                        "collection completed successfully"
                    )
                elif any(
                    pattern in stdout
                    for pattern in [
                        "Invalid completion code received: Invalid command",
                        "Discovered IPMB address 0x0",
                    ]
                ):
                    # These diagnostics identify unsupported controller
                    # behavior. Preserve them as skipped evidence, not success.
                    unsupported_command = True

            # Create output file with generalization using common utility
            content = self._create_command_output_content(
                command, exit_code, stdout, stderr
            )
            output_pattern = kwargs.get("filename")
            if not success:
                diagnostic_name = output_pattern or (
                    f"{kwargs.get('function_tag', 'ipmi_command')}.txt"
                )
                output_pattern = f"diagnostic/{diagnostic_name}"
            file_path = await self.write_output_with_generalization(
                dut_id,
                kwargs.get("collector_id", ""),
                content,
                output_pattern=output_pattern,
                function_tag=kwargs.get("function_tag", "ipmi_command"),
            )

            return await self._create_standardized_collector_result(
                successful_operations=(
                    0 if unsupported_command else (1 if success else 0)
                ),
                total_operations=0 if unsupported_command else 1,
                output_files=[file_path] if success and file_path else [],
                error_messages=(
                    []
                    if success or unsupported_command
                    else [f"IPMI command failed with exit code {exit_code}"]
                ),
                operation_name="ipmi_command",
                additional_context={
                    "command": command,
                    "nvbmc_handling": True,
                    "exit_code": exit_code,
                    "raw_exit_code": exit_code,
                    "output": self._process_command_output(stdout),
                    "stderr": self._process_command_output(stderr),
                    **(
                        {"diagnostic_files": [file_path]}
                        if not success and file_path
                        else {}
                    ),
                    **(
                        {
                            "status": "success",
                            "reason": nonzero_success_reason,
                            "accepted_nonzero_exit": True,
                        }
                        if nonzero_success_reason
                        else {}
                    ),
                    **(
                        {
                            "status": "skipped",
                            "reason": (
                                "IPMI command is not supported by this BMC "
                                f"(exit {exit_code}); no data collected"
                            ),
                            "endpoint_signalled_unsupported": True,
                        }
                        if unsupported_command
                        else {}
                    ),
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="ipmi_command",
                additional_context={"command": command},
                dut_id=dut_id,
                collector_id="ipmi_command",
            )

    async def run_ipmi_command_with_file_output(
        self, dut_id: str, command: str, output_file: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Run IPMI command with specific file output.

        The implementation uses ``dut_id``, ``command``, ``output_file``, and
        ``kwargs`` to run IPMI command with specific file output. Terminal
        status is emitted only after IPMI command with specific file output and
        its owned cleanup have completed. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            command: Text supplied as command in the format accepted by this
                function.
            output_file: filesystem location used as the output file for this
                operation.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run IPMI command with file output.
        """
        try:
            timeout = await self._resolve_ipmi_command_timeout(dut_id, kwargs)
            exit_code, stdout, stderr = await self.dut_manager.execute_ipmi_command(
                dut_id, command, timeout=timeout
            )

            # Check if we should ignore command failures
            ignore_errors = kwargs.get("ignore_errors", False)
            success = exit_code == 0 or ignore_errors
            empty_sel_result = await _run_managed_operation(
                _sel_has_no_entries, stdout, stderr
            )
            empty_sel_result = exit_code == 0 and empty_sel_result
            empty_sel_message = (
                "No SEL entries found; collection completed successfully"
            )
            verification_context: Dict[str, Any] = {}
            verification_lines: List[str] = []

            # ``sel writeraw`` has historically returned exit zero after a partial
            # firmware/session failure.  Verify only this collector's artifact;
            # ordinary IPMI commands retain their single-request fast path.
            raw_path = _sel_writeraw_path(command)
            if raw_path is not None and exit_code == 0:
                info_exit, info_stdout, _ = await self.dut_manager.execute_ipmi_command(
                    dut_id, "sel info", timeout=timeout
                )
                (
                    advertised_count,
                    raw_record_count,
                    artifact_error,
                    failure_diagnostic_count,
                ) = await _run_managed_operation(
                    _inspect_sel_writeraw_result,
                    raw_path,
                    stdout,
                    stderr,
                    info_exit,
                    info_stdout,
                )
                verification_status = "verified"
                verification_reason = "SEL writeraw artifact record count verified"

                if (
                    empty_sel_result
                    and raw_record_count in {None, 0}
                    and advertised_count == 0
                ):
                    # Some conforming firmware does not create the writeraw
                    # destination when the SEL is empty.  The independent
                    # ``sel info`` count and the writeraw empty marker together
                    # prove the same zero-record result as a zero-byte file.
                    raw_record_count = 0
                    artifact_error = None
                    verification_reason = empty_sel_message
                elif artifact_error:
                    verification_status = "error"
                    verification_reason = artifact_error
                elif raw_record_count == 0 and advertised_count is None:
                    verification_status = "error"
                    verification_reason = (
                        "SEL writeraw artifact is empty and SEL entry count could "
                        "not be verified"
                    )
                elif failure_diagnostic_count:
                    verification_status = "partial"
                    verification_reason = (
                        "SEL writeraw reported firmware or session failures; "
                        "see the captured command transcript"
                    )
                elif advertised_count is None:
                    verification_status = "partial"
                    verification_reason = (
                        "SEL writeraw artifact was captured, but the advertised "
                        "SEL entry count could not be verified"
                    )
                elif raw_record_count != advertised_count:
                    verification_status = "partial"
                    verification_reason = (
                        f"SEL writeraw captured {raw_record_count} of "
                        f"{advertised_count} advertised records"
                    )

                success = verification_status != "error"
                verification_context = {
                    "status": (
                        "success"
                        if verification_status == "verified"
                        else verification_status
                    ),
                    "reason": verification_reason,
                    "verification_status": verification_status,
                    "raw_record_count": raw_record_count,
                    "advertised_sel_entry_count": advertised_count,
                    "writeraw_failure_diagnostic_count": failure_diagnostic_count,
                }
                verification_lines = [
                    f"Verification Status: {verification_status}",
                    f"Raw Record Count: {raw_record_count}",
                    f"Advertised SEL Entry Count: {advertised_count}",
                    f"Verification Reason: {verification_reason}",
                ]

            # Write a human-readable transcript after verification so the bundle
            # carries the same integrity result returned to the orchestrator.
            content = self._create_command_output_content(
                command, exit_code, stdout, stderr
            )
            if verification_lines:
                content = f"{content.rstrip()}\n\n" + "\n".join(verification_lines)
            output_pattern = kwargs.get("filename")
            if not success:
                diagnostic_name = output_pattern or (
                    f"{kwargs.get('function_tag', 'ipmi_command')}.txt"
                )
                output_pattern = f"diagnostic/{diagnostic_name}"
            file_path = await self.write_output_with_generalization(
                dut_id,
                kwargs.get("collector_id", ""),
                content,
                output_pattern=output_pattern,
                function_tag=kwargs.get("function_tag", "ipmi_command"),
            )

            return await self._create_standardized_collector_result(
                successful_operations=1 if success else 0,
                total_operations=1,
                output_files=[file_path] if success and file_path else [],
                error_messages=(
                    []
                    if success
                    else [f"IPMI command failed with exit code {exit_code}"]
                ),
                operation_name="ipmi_command",
                additional_context={
                    "command": command,
                    "output_file": output_file,
                    "ignore_errors": ignore_errors,
                    "exit_code": exit_code,
                    "output": self._process_command_output(stdout),
                    "stderr": self._process_command_output(stderr),
                    **(
                        {"diagnostic_files": [file_path]}
                        if not success and file_path
                        else {}
                    ),
                    **(
                        {
                            "status": "success",
                            "reason": empty_sel_message,
                            "empty_result": True,
                        }
                        if empty_sel_result
                        else {}
                    ),
                    **verification_context,
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="ipmi_command",
                additional_context={"command": command},
                dut_id=dut_id,
                collector_id="ipmi_command",
            )

    async def run_ipmi_commands(
        self,
        dut_id: str,
        commands: List[Union[str, Dict[str, Any]]],
        collection_level: str = "L1",
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Run multiple IPMI commands with collection level handling.

        Handle both string commands and command dictionaries.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            commands: Mapping supplying fields for multiple IPMI commands with
                collection level handling.
            collection_level: Text supplied as collection level in the format
                accepted by this function.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            A mapping containing run IPMI commands.
        """
        try:
            results = []
            output_files = []
            error_messages = []
            successful_operations = 0
            total_operations = 0

            await self._log_runtime(
                "INFO",
                "IPMIService",
                f"Starting IPMI command set with {len(commands)} commands",
                dut_id,
            )

            for i, command_item in enumerate(commands):
                total_operations += 1
                # Handle both string commands and command dictionaries
                if isinstance(command_item, str):
                    command = command_item
                    file_name = f"ipmi_command_{i+1}.txt"
                    timeout = await self._resolve_collector_timeout(
                        dut_id, kwargs, default_timeout=300
                    )
                    ignore_errors = False
                else:
                    # Handle collection level variations
                    if "collection_level_handling" in command_item:
                        level_commands = command_item["collection_level_handling"]
                        command = level_commands.get(
                            collection_level, command_item["command"]
                        )
                    else:
                        command = command_item["command"]

                    file_name = command_item.get("file_name", f"ipmi_command_{i+1}.txt")
                    timeout = await self._resolve_collector_timeout(
                        dut_id,
                        kwargs,
                        default_timeout=300,
                        explicit_timeout_sources=[command_item, kwargs],
                    )
                    ignore_errors = command_item.get("ignore_errors", False)

                logged_command = self._bounded_operator_reason("success", command)
                await self._log_runtime(
                    "INFO",
                    "IPMIService",
                    (
                        f"Executing IPMI command {i + 1}/{len(commands)} "
                        f"with effective timeout {timeout}s: {logged_command}"
                    ),
                    dut_id,
                )
                exit_code, stdout, stderr = await self.dut_manager.execute_ipmi_command(
                    dut_id, command, timeout=timeout
                )

                # Create output file with generalization using common utility
                content = self._create_command_output_content(
                    command, exit_code, stdout, stderr
                )
                file_path = await self.write_output_with_generalization(
                    dut_id,
                    kwargs.get("collector_id", ""),
                    content,
                    output_pattern=kwargs.get("filename"),
                    function_tag=file_name,
                    substitutions={"command_name": file_name},
                )
                if file_path:
                    output_files.append(file_path)

                command_success = exit_code == 0 and bool(file_path)
                await self._log_runtime(
                    "INFO" if command_success else "ERROR",
                    "IPMIService",
                    (
                        f"IPMI command {i + 1}/{len(commands)} finished: "
                        f"exit_code={exit_code}, artifact_persisted={bool(file_path)}, "
                        f"semantic_success={command_success}"
                    ),
                    dut_id,
                )
                if command_success:
                    successful_operations += 1
                else:
                    if exit_code != 0:
                        error_messages.append(
                            f"IPMI command failed: {command} (exit_code: {exit_code})"
                        )
                    else:
                        error_messages.append(
                            f"IPMI command output could not be persisted: {command}"
                        )

                results.append(
                    {
                        "command": command,
                        "success": command_success,
                        "output": self._process_command_output(stdout),
                        "stderr": self._process_command_output(stderr),
                        "exit_code": exit_code,
                        "file_name": file_name,
                        "collection_level": collection_level,
                    }
                )

                # Handle ignore_errors
                if exit_code != 0 and not ignore_errors:
                    return await self._create_standardized_collector_result(
                        successful_operations=successful_operations,
                        total_operations=total_operations,
                        output_files=output_files,
                        error_messages=error_messages,
                        operation_name="ipmi_commands",
                        additional_context={
                            "total_commands": len(commands),
                            "results": results,
                        },
                    )

            return await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=kwargs.get("collector_id", "unknown"),
                successful_operations=successful_operations,
                total_operations=total_operations,
                output_files=output_files,
                error_messages=error_messages,
                operation_name="ipmi_commands",
                additional_context={
                    "total_commands": len(commands),
                    "collection_level": collection_level,
                    "results": results,
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=len(commands),
                output_files=[],
                error_messages=[f"Exception in IPMI commands: {str(e)}"],
                operation_name="ipmi_commands",
                additional_context={"commands": commands},
                dut_id=dut_id,
                collector_id="ipmi_commands",
            )
