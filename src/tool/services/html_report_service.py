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
HTML Report Service.

Generates comprehensive multi-level HTML reports from structured log directories
with collector metadata, execution times, and interactive navigation.
"""

import asyncio
import json
import logging
import os
import re
import secrets
import shutil
import stat
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple
from urllib.parse import quote

from ..core.collector_outcome import normalize_collector_failure_category
from ..core.finalization_receipt import (
    FinalizationReceipt,
    validate_consumable_finalization_receipt,
)
from ..core.run_result import RunResult, validate_run_result_document
from ..utils.bounded_archive import (
    ArchiveLimits,
    archive_creation_limits_from_runtime_boundaries,
    resolve_archive_limits,
)
from ..utils.filesystem_identity import directory_security_identity
from ..utils.managed_filesystem import run_managed_filesystem_operation
from ..utils.status_snapshot import (
    RECEIPTLESS_SNAPSHOT_COMPATIBILITY_VERSION,
    SnapshotArtifactFormatError,
    SnapshotConsistencyError,
    TerminalSnapshotBinding,
    read_snapshot_status,
    read_snapshot_timing,
    validate_committed_terminal_snapshot,
)
from .html_report_execution_model import (
    combine_execution_statuses,
    create_execution_summary_from_metadata,
    execution_summary_to_legacy_dict,
    metadata_execution_summary_to_legacy_list,
    parse_execution_summary_lines,
    summary_diagnostics_to_legacy_list,
)
from .html_report_file_view import HTMLReportFileView
from .html_report_log_parser import (
    DEFAULT_RUNTIME_LOG_FORMAT,
    LOG_FIELD_ROLES,
    MAX_LOG_FORMAT_DIRECTIVES,
    PERCENT_LOG_DIRECTIVE,
    browser_log_parser_metadata,
    build_log_parser_specs,
    canonical_lifecycle_parser,
    compile_log_format_parser,
    escape_shared_regex_literal,
    parse_log_line,
)
from .html_report_log_viewer import (
    HTMLReportLogViewer,
    LogViewerRenderModel,
)
from .html_report_node_sidebar import (
    HTMLReportNodeSidebar,
    NodeSidebarLink,
    NodeSidebarLinkGroup,
    NodeSidebarRenderModel,
)
from .html_report_page_assets import (
    HTML_REPORT_PAGE_ASSETS,
    NavbarRenderModel,
)
from .html_report_renderer import (
    BackButtonRenderModel,
    HTMLPageRenderModel,
    HTMLReportRenderer,
    SystemDetailsRenderModel,
)
from .manifest_service import HARD_MAX_AUXILIARY_JSON_FILES, ManifestService

logger = logging.getLogger(__name__)

_REPORT_INPUT_READ_CHUNK_BYTES = 64 * 1024


class ReportInputSafetyError(RuntimeError):
    """
    A report source escaped its finite, no-follow input boundary.

    Callers receive this exception when the report input safety error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


@dataclass(frozen=True)
class _ReportInputEntry:
    """
    One identity-bound regular file or directory discovered for a report.

    The immutable record keeps ``path`` and ``metadata`` together so consumers
    observe one report input entry state. Consumers receive the fields as one
    unit instead of assembling partial state.

    Attributes:
        path: Validated filesystem location associated with path.
        metadata: Metadata retained as part of the record's public state.
    """

    path: Path
    metadata: os.stat_result

    @property
    def is_file(self) -> bool:
        """
        Return whether ``the current value`` is file.

        Each access computes the value from ``metadata`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            Whether ``the current value`` is file.
        """
        return stat.S_ISREG(self.metadata.st_mode)

    @property
    def is_dir(self) -> bool:
        """
        Return whether ``the current value`` is dir.

        Each access computes the value from ``metadata`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            Whether ``the current value`` is dir.
        """
        return stat.S_ISDIR(self.metadata.st_mode)


def _same_report_input(first: os.stat_result, second: os.stat_result) -> bool:
    """
    Compare the fields that expose replacement or in-place source drift.

    After applying local validation, the function forwards ``first`` and
    ``second`` to ``all`` and preserves its return and exception contract.

    Args:
        first: First consumed while the function attempts to compare the fields
            that expose replacement or in-place source drift.
        second: Second consumed while the function attempts to compare the
            fields that expose replacement or in-place source drift.

    Returns:
        Whether the compare the fields that expose replacement or in-place
        source drift operation succeeds.
    """

    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    return all(getattr(first, field) == getattr(second, field) for field in fields)


def _same_directory_identity(first: os.stat_result, second: os.stat_result) -> bool:
    """
    Compare stable directory identity without treating child writes as drift.

    After applying local validation, the function forwards ``first`` and
    ``second`` to ``all`` and preserves its return and exception contract.

    Args:
        first: First consumed while the function attempts to compare stable
            directory identity without treating child writes as drift.
        second: Second consumed while the function attempts to compare stable
            directory identity without treating child writes as drift.

    Returns:
        Whether the compare stable directory identity without treating child
        writes as drift operation succeeds.
    """

    return directory_security_identity(first) == directory_security_identity(second)


_HTML_RENDERER = HTMLReportRenderer()
escape = HTMLReportRenderer.escape_html_text
_HTML_LOG_VIEWER = HTMLReportLogViewer()
_HTML_NODE_SIDEBAR = HTMLReportNodeSidebar()


class HTMLReportService:
    """
    Manage HTML report service operations for the NVDebug runtime.

    The type coordinates ``_json_for_script``, ``_normalize_failure_category``,
    ``_has_unsafe_html_control``, ``_escape_html_text``, and
    ``_safe_external_url`` and retains the state those operations share between
    calls. Resource ownership remains inside the instance until the matching
    close, exit, or cleanup operation completes.
    """

    _DEFAULT_RUNTIME_LOG_FORMAT = DEFAULT_RUNTIME_LOG_FORMAT
    _PERCENT_LOG_DIRECTIVE = PERCENT_LOG_DIRECTIVE
    _LOG_FIELD_ROLES = LOG_FIELD_ROLES
    _MAX_LOG_FORMAT_DIRECTIVES = MAX_LOG_FORMAT_DIRECTIVES

    def __init__(
        self,
        log_dir: Path,
        total_runtime: float = None,
        logger=None,
        orchestrator=None,
        finalization_receipt: Optional[FinalizationReceipt] = None,
        enforce_snapshot_consistency: bool = True,
    ):
        """
        Initializes the HTMLReportService for nvdebug.

        Initialize missing attributes that are used in the report generation.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            total_runtime: Optional total runtime; ``None`` selects the
                function's default behavior.
            logger: Sanitized logger used for operator-visible diagnostics.
            orchestrator: Optional orchestrator; ``None`` selects the function's
                default behavior.
            finalization_receipt: Optional finalization receipt; ``None``
                selects the function's default behavior.
            enforce_snapshot_consistency: Whether enforce snapshot consistency
                is enabled or required for this operation.
        """
        # Set basic attributes that are needed before async initialization
        self.logger = logger
        self.orchestrator = orchestrator
        self.root_dir = log_dir
        self.total_runtime = total_runtime
        self._finalization_receipt = finalization_receipt
        self._enforce_snapshot_consistency = enforce_snapshot_consistency
        self._terminal_snapshot_generation: Optional[str] = None
        self._terminal_dut_roster: Optional[Tuple[str, ...]] = None
        self._snapshot_binding: Optional[TerminalSnapshotBinding] = None
        self._unbound_root_dir: Optional[Path] = None

        # Initialize missing attributes that are used in the report generation
        self.node_collector_json = {}
        self.node_execution_times = {}
        self.node_statuses_all = {}
        self.node_system_details = {}
        self.global_execution_entries = []
        self.informational_patterns = [
            r"\.json$",
            r"\.txt$",
            r"\.log$",
            r"\.yaml$",
            r"\.yml$",
        ]
        # Maximum file size for parsing (50 MB) - larger files will be download-only
        self.max_parseable_file_size = 50 * 1024 * 1024  # 50 MB in bytes
        self.max_json_tree_depth = 64
        config_manager = getattr(orchestrator, "config_manager", None)
        if config_manager is not None:
            try:
                report_tool_config = config_manager.get_tool_config()
                if isinstance(report_tool_config, Mapping):
                    output_config = report_tool_config.get("output", {})
                else:
                    output_config = getattr(report_tool_config, "output", {})
                if isinstance(output_config, Mapping):
                    configured_depth = output_config.get("max_json_tree_depth", 64)
                else:
                    configured_depth = getattr(output_config, "max_json_tree_depth", 64)
                if type(configured_depth) is int and 1 <= configured_depth <= 512:
                    self.max_json_tree_depth = configured_depth
            except Exception:
                # Configuration parsing owns diagnostics. Report construction
                # retains its documented safe default if an alternate test or
                # compatibility manager cannot expose the optional field.
                pass
        # A live orchestrator supplies the tool-owned completed collection tree;
        # it must not inherit the deliberately small inbound-archive default.
        # Receipt-less/offline callers retain the strict untrusted-input policy.
        finalization_boundaries = None
        boundary_resolver = getattr(
            orchestrator, "get_finalization_runtime_boundaries", None
        )
        if callable(boundary_resolver):
            try:
                candidate_boundaries = boundary_resolver()
            except Exception:
                candidate_boundaries = None
            if isinstance(candidate_boundaries, Mapping):
                finalization_boundaries = candidate_boundaries
        self._finalization_boundaries = finalization_boundaries
        self._report_input_limits: ArchiveLimits = (
            archive_creation_limits_from_runtime_boundaries(finalization_boundaries)
            if orchestrator is not None
            else resolve_archive_limits()
        )
        self._report_input_entries: Dict[str, os.stat_result] = {}
        self._report_input_file_count = 0
        self._report_input_total_bytes = 0
        self._report_output_root_path: Optional[Path] = None
        self._report_output_root_fd: Optional[int] = None
        self._report_output_root_identity: Optional[os.stat_result] = None
        self._report_output_dir_identity: Optional[os.stat_result] = None

    def __del__(self) -> None:
        """
        Release remaining resources owned by the HTMLReportService.

        The implementation uses current instance state to release remaining
        resources owned by the HTMLReportService. It updates
        ``_report_output_root_fd`` on the instance as part of that state
        transition.
        """
        descriptor = getattr(self, "_report_output_root_fd", None)
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
            self._report_output_root_fd = None

    @staticmethod
    def _json_for_script(value: Any, **kwargs) -> str:
        """
        Serialize JSON safely for direct embedding inside script tags.

        After applying local validation, the function forwards ``value`` and
        ``kwargs`` to ``_HTML_RENDERER.json_for_script`` and preserves its
        return and exception contract.

        Args:
            value: Value evaluated while performing serialize JSON safely for
                direct embedding inside script tags.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The canonical JSON for script text.
        """
        return _HTML_RENDERER.json_for_script(value, **kwargs)

    @staticmethod
    def _normalize_failure_category(status: Any, value: Any) -> Optional[str]:
        """
        Normalize categories after containing legacy HTML status aliases.

        After applying local validation, the function forwards ``status`` and
        ``value`` to ``normalize_collector_failure_category`` and preserves its
        return and exception contract. The source value keeps its ownership
        while the normalized representation is returned separately.

        Args:
            status: Status consumed while the function attempts to normalize
                categories after containing legacy HTML status aliases.
            value: Value evaluated while performing categories after containing
                legacy HTML status aliases.

        Returns:
            The canonical failure category text, or ``None`` when the requested
            value is unavailable.
        """
        status_value = str(getattr(status, "value", status) or "").strip().casefold()
        status_value = status_value.split()[0] if status_value else ""
        canonical_status = {
            "degraded": "degraded",
            "error": "error",
            "fail": "error",
            "failed": "error",
            "partial": "partial",
        }.get(status_value)
        if canonical_status is None:
            return None
        return normalize_collector_failure_category(canonical_status, value)

    @staticmethod
    def _has_unsafe_html_control(value: str) -> bool:
        """
        Return whether ``value`` has unsafe HTML control.

        After applying local validation, the function forwards ``value`` to
        ``_HTML_RENDERER.has_unsafe_html_control`` and preserves its return and
        exception contract.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            Whether ``value`` has unsafe HTML control.
        """
        return _HTML_RENDERER.has_unsafe_html_control(value)

    @classmethod
    def _escape_html_text(cls, value: Any) -> str:
        """
        Escape untrusted text and replace controls forbidden by HTML.

        After applying local validation, the function forwards ``value`` to
        ``_HTML_RENDERER.escape_html_text`` and preserves its return and
        exception contract.

        Args:
            value: Value evaluated while performing escape untrusted text and
                replace controls forbidden by HTML.

        Returns:
            The canonical escape HTML text.
        """
        return _HTML_RENDERER.escape_html_text(value)

    @classmethod
    def _safe_external_url(cls, value: str) -> Optional[str]:
        """
        Return an absolute HTTP(S) URL only when it is safe for navigation.

        After applying local validation, the function forwards ``value`` to
        ``_HTML_RENDERER.safe_external_url`` and preserves its return and
        exception contract.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The canonical safe external URL text, or ``None`` when the requested
            value is unavailable.
        """
        return _HTML_RENDERER.safe_external_url(value)

    @classmethod
    def _encoded_relative_report_link(
        cls, node_name: str, relative_link: str
    ) -> Optional[str]:
        """
        Encode a report-local link without permitting URL/path reinterpretation.

        After applying local validation, the function forwards ``node_name`` and
        ``relative_link`` to ``_HTML_RENDERER.encoded_relative_report_link`` and
        preserves its return and exception contract.

        Args:
            node_name: Stable node name used for lookup and operator-facing
                diagnostics.
            relative_link: Text supplied as relative link in the format accepted
                by this function.

        Returns:
            The canonical encoded relative report link text, or ``None`` when
            the requested value is unavailable.
        """
        return _HTML_RENDERER.encoded_relative_report_link(node_name, relative_link)

    @classmethod
    def _encoded_report_relative_path(cls, relative_link: str) -> Optional[str]:
        """
        Encode a report-relative path without permitting path reinterpretation.

        The renderer performs the authoritative segment validation and percent
        encoding; this facade preserves that result for legacy report callers.

        Args:
            relative_link: Text supplied as a report-local relative path.

        Returns:
            The encoded relative path, or ``None`` when it is unsafe.
        """
        return _HTML_RENDERER.encoded_report_relative_path(relative_link)

    @classmethod
    async def create(
        cls,
        log_dir: Path,
        total_runtime: float = None,
        logger=None,
        orchestrator=None,
        collector_ids: Optional[List[str]] = None,
        finalization_receipt: Optional[FinalizationReceipt] = None,
        enforce_snapshot_consistency: bool = True,
    ):
        """
        Factory method to create and initialize HTMLReportService asynchronously.

        The implementation uses ``log_dir``, ``total_runtime``, ``logger``,
        ``orchestrator``, and ``collector_ids`` to factory method to create and
        initialize HTMLReportService asynchronously. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            total_runtime: Optional total runtime; ``None`` selects the
                function's default behavior.
            logger: Sanitized logger used for operator-visible diagnostics.
            orchestrator: Optional orchestrator; ``None`` selects the function's
                default behavior.
            collector_ids: Optional collector identifiers; ``None`` selects the
                function's default behavior.
            finalization_receipt: Optional finalization receipt; ``None``
                selects the function's default behavior.
            enforce_snapshot_consistency: Whether enforce snapshot consistency
                is enabled or required for this operation.

        Returns:
            The validated ``instance``.
        """
        instance = cls(
            log_dir,
            total_runtime,
            logger,
            orchestrator,
            finalization_receipt,
            enforce_snapshot_consistency,
        )
        instance.requested_collector_ids = collector_ids
        await instance._initialize()
        return instance

    def _bind_terminal_snapshot(self) -> None:
        """
        Bind current-run reports to receipt evidence, or use offline discovery.

        The implementation uses current instance state to bind current-run
        reports to receipt evidence, or use offline discovery. It updates
        ``_snapshot_binding``, ``_terminal_dut_roster``,
        ``_terminal_snapshot_generation``, ``_unbound_root_dir``, and
        ``report_dir`` on the instance as part of that state transition.
        """

        if self._snapshot_binding is not None:
            return
        if not self._enforce_snapshot_consistency:
            self._terminal_snapshot_generation = None
            self._terminal_dut_roster = None
            return
        if self._finalization_receipt is None:
            self._terminal_snapshot_generation = validate_committed_terminal_snapshot(
                self.root_dir,
                compatibility_version=RECEIPTLESS_SNAPSHOT_COMPATIBILITY_VERSION,
            )
            self._terminal_dut_roster = None
            return
        (
            self._terminal_snapshot_generation,
            self._terminal_dut_roster,
        ) = validate_consumable_finalization_receipt(self._finalization_receipt)
        binding = TerminalSnapshotBinding(
            self.root_dir,
            self._terminal_dut_roster,
            expected_generation=self._terminal_snapshot_generation,
            expected_leaf_digests=self._finalization_receipt.snapshot_leaf_digests,
        )
        self._unbound_root_dir = self.root_dir
        self._snapshot_binding = binding
        self.root_dir = binding.root_path
        self.report_dir = self.root_dir / "reports"

    def _release_terminal_snapshot(self) -> None:
        """
        Release a current-run descriptor binding and restore lexical paths.

        The implementation uses current instance state to release a current-run
        descriptor binding and restore lexical paths. It updates
        ``_snapshot_binding``, ``_unbound_root_dir``, ``report_dir``, and
        ``root_dir`` on the instance as part of that state transition. Cleanup
        in the ``finally`` path runs for successful, failed, and cancelled
        execution.
        """

        binding = self._snapshot_binding
        if binding is None:
            return
        original_root = self._unbound_root_dir
        self._snapshot_binding = None
        self._unbound_root_dir = None
        try:
            binding.close()
        finally:
            if original_root is not None:
                self.root_dir = original_root
                self.report_dir = original_root / "reports"

    def _iter_node_directories(self) -> Tuple[Path, ...]:
        """
        Return the receipt roster for current runs without disk discovery.

        The implementation uses current instance state to produce the receipt
        roster for current runs without disk discovery. If the function cannot
        produce the receipt roster for current runs without disk discovery, its
        exception reaches the caller instead of being converted into a
        successful result.

        Returns:
            The iter node directories returned in operation-defined order.

        Raises:
            SnapshotConsistencyError: If receipt DUT binding is unavailable.
        """

        if self._snapshot_binding is not None:
            return self._snapshot_binding.dut_directories
        if self._terminal_dut_roster is None:
            return tuple(
                entry.path
                for entry in self._walk_report_inputs(
                    self.root_dir,
                    recursive=False,
                    excluded_directories=frozenset({"report", "reports"}),
                )
                if entry.is_dir
            )
        raise SnapshotConsistencyError("Receipt DUT binding is unavailable")

    def _read_terminal_status(
        self, dut_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Read status through the active receipt binding when present.

        The implementation uses ``dut_id`` to read status through the active
        receipt binding when present. Parsing or I/O must finish before the
        validated representation is made available to the caller.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing terminal status, or ``None`` when the requested
            value is unavailable.
        """

        if self._snapshot_binding is not None:
            return self._snapshot_binding.read_status(dut_id)
        return read_snapshot_status(
            self.root_dir,
            dut_id=dut_id,
            expected_generation=self._terminal_snapshot_generation,
            required=self._terminal_snapshot_generation is not None,
        )

    def _read_run_result(self) -> Optional[RunResult]:
        """
        Read the exact canonical result through the active snapshot binding.

        After applying local validation, the function forwards current instance
        state to ``validate_run_result_document`` and preserves its return and
        exception contract. Parsing or I/O must finish before the validated
        representation is made available to the caller.

        Returns:
            A ``RunResult`` representing run result, or ``None`` when the
            requested value is unavailable.

        Raises:
            SnapshotArtifactFormatError: If terminal status snapshot is missing
                canonical RunResult; or terminal status snapshot contains an
                invalid canonical RunResult.
        """

        document = self._read_terminal_status()
        if document is None:
            return None
        metadata = document.get("metadata")
        raw_result = metadata.get("run_result") if isinstance(metadata, dict) else None
        if raw_result is None:
            if self._terminal_snapshot_generation is not None:
                raise SnapshotArtifactFormatError(
                    "Terminal status snapshot is missing canonical RunResult"
                )
            return None
        try:
            return validate_run_result_document(raw_result)
        except (TypeError, ValueError) as error:
            raise SnapshotArtifactFormatError(
                "Terminal status snapshot contains an invalid canonical RunResult"
            ) from error

    def _read_terminal_timing(self, dut_id: str) -> Optional[Dict[str, Any]]:
        """
        Read timing through the active receipt binding when present.

        The implementation uses ``dut_id`` to read timing through the active
        receipt binding when present. Parsing or I/O must finish before the
        validated representation is made available to the caller.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing terminal timing, or ``None`` when the requested
            value is unavailable.
        """

        if self._snapshot_binding is not None:
            return self._snapshot_binding.read_timing(dut_id)
        return read_snapshot_timing(
            self.root_dir,
            dut_id,
            expected_generation=self._terminal_snapshot_generation,
            required=self._terminal_snapshot_generation is not None,
        )

    @staticmethod
    def _open_lexical_directory_without_links(
        path: Path,
    ) -> Tuple[Path, int, os.stat_result]:
        """
        Open an absolute directory one no-follow component at a time.

        The implementation uses ``path`` to open an absolute directory one
        no-follow component at a time. If the function cannot open an absolute
        directory one no-follow component at a time, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            A tuple containing ``absolute``, ``descriptor``, and ``identity`` in
            that order.

        Raises:
            ReportInputSafetyError: If the filesystem root cannot be used as a
                report collection root; report collection root traverses a link
                or non-directory; or report collection root identity changed
                while opening.
        """

        absolute = Path(os.path.abspath(os.fspath(path)))
        if absolute == Path(absolute.anchor):
            raise ReportInputSafetyError(
                "the filesystem root cannot be used as a report collection root"
            )

        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(absolute.anchor, flags)
        try:
            for part in absolute.parts[1:]:
                before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                    raise ReportInputSafetyError(
                        "report collection root traverses a link or non-directory"
                    )
                child_descriptor = os.open(part, flags, dir_fd=descriptor)
                try:
                    opened = os.fstat(child_descriptor)
                    if not _same_directory_identity(before, opened):
                        raise ReportInputSafetyError(
                            "report collection root identity changed while opening"
                        )
                except BaseException:
                    os.close(child_descriptor)
                    raise
                os.close(descriptor)
                descriptor = child_descriptor
            identity = os.fstat(descriptor)
            return absolute, descriptor, identity
        except BaseException:
            os.close(descriptor)
            raise

    def _prepare_report_output_root(self) -> None:
        """
        Pin the collection root and privately recreate only its reports child.

        The implementation uses current instance state to pin the collection
        root and privately recreate only its reports child. It updates
        ``_report_output_dir_identity``, ``_report_output_root_fd``,
        ``_report_output_root_identity``, and ``_report_output_root_path`` on
        the instance as part of that state transition. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        If the function cannot pin the collection root and privately recreate
        only its reports child, its exception reaches the caller instead of
        being converted into a successful result. Cleanup in the ``finally``
        path runs for successful, failed, and cancelled execution.

        Raises:
            ReportInputSafetyError: If existing report output is a link or
                non-directory; safe descriptor-relative report cleanup is
                unavailable; or report output directory is not a private stable
                directory.
        """

        root_path, root_descriptor, _identity = (
            self._open_lexical_directory_without_links(self.root_dir)
        )
        try:
            try:
                existing = os.stat(
                    "reports",
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                existing = None

            if existing is not None:
                if stat.S_ISLNK(existing.st_mode) or not stat.S_ISDIR(existing.st_mode):
                    raise ReportInputSafetyError(
                        "existing report output is a link or non-directory"
                    )
                if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
                    raise ReportInputSafetyError(
                        "safe descriptor-relative report cleanup is unavailable"
                    )
                shutil.rmtree("reports", dir_fd=root_descriptor)

            os.mkdir("reports", mode=0o700, dir_fd=root_descriptor)
            report_flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            before = os.stat(
                "reports",
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            report_descriptor = os.open(
                "reports",
                report_flags,
                dir_fd=root_descriptor,
            )
            try:
                opened = os.fstat(report_descriptor)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or not _same_directory_identity(before, opened)
                    or opened.st_mode & 0o077
                ):
                    raise ReportInputSafetyError(
                        "report output directory is not a private stable directory"
                    )
                self._report_output_dir_identity = opened
            finally:
                os.close(report_descriptor)

            previous_descriptor = self._report_output_root_fd
            self._report_output_root_path = root_path
            self._report_output_root_identity = os.fstat(root_descriptor)
            self._report_output_root_fd = root_descriptor
            root_descriptor = -1
            if previous_descriptor is not None:
                os.close(previous_descriptor)
        finally:
            if root_descriptor >= 0:
                os.close(root_descriptor)

    def _require_report_output_root(self) -> int:
        """
        Reauthorize the lexical root against the retained descriptor.

        The implementation uses current instance state to reauthorize the
        lexical root against the retained descriptor. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        If the function cannot reauthorize the lexical root against the retained
        descriptor, its exception reaches the caller instead of being converted
        into a successful result. Cleanup in the ``finally`` path runs for
        successful, failed, and cancelled execution.

        Returns:
            The validated ``descriptor``.

        Raises:
            ReportInputSafetyError: If report output root is not initialized;
                report output root identity changed; pinned report output root
                identity changed; or report output directory is unavailable; or
                another input invariant is violated.
        """

        descriptor = self._report_output_root_fd
        expected = self._report_output_root_identity
        root_path = self._report_output_root_path
        report_expected = self._report_output_dir_identity
        if (
            descriptor is None
            or expected is None
            or root_path is None
            or report_expected is None
        ):
            raise ReportInputSafetyError("report output root is not initialized")

        current_path, current_descriptor, current = (
            self._open_lexical_directory_without_links(root_path)
        )
        try:
            if current_path != root_path or not _same_directory_identity(
                expected, current
            ):
                raise ReportInputSafetyError("report output root identity changed")
        finally:
            os.close(current_descriptor)

        if not _same_directory_identity(expected, os.fstat(descriptor)):
            raise ReportInputSafetyError("pinned report output root identity changed")
        try:
            current_report = os.stat(
                "reports",
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ReportInputSafetyError(
                "report output directory is unavailable"
            ) from error
        if stat.S_ISLNK(current_report.st_mode) or not _same_directory_identity(
            report_expected, current_report
        ):
            raise ReportInputSafetyError("report output directory identity changed")
        return descriptor

    def _report_output_parts(self, path: Path) -> Tuple[str, ...]:
        """
        Authorize one output path lexically below the active reports directory.

        After applying local validation, the function forwards ``path`` to
        ``tuple`` and preserves its return and exception contract.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The report output parts returned in operation-defined order.

        Raises:
            ReportInputSafetyError: If report output path is unsafe; or report
                output is outside the reports directory.
        """

        raw_path = os.fspath(path)
        if "\x00" in raw_path:
            raise ReportInputSafetyError("report output path is unsafe")
        report_root = Path(os.path.abspath(os.fspath(self.report_dir)))
        candidate = Path(os.path.abspath(raw_path))
        try:
            relative = candidate.relative_to(report_root)
        except ValueError as error:
            raise ReportInputSafetyError(
                "report output is outside the reports directory"
            ) from error
        parts = relative.parts
        if (
            not parts
            or len(parts) > self._report_input_limits.max_path_depth
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ReportInputSafetyError("report output path is unsafe")
        return tuple(parts)

    @contextmanager
    def _open_report_output_directory(self, parts: Tuple[str, ...]) -> Iterator[int]:
        """
        Open or create a private report directory through retained descriptors.

        The implementation uses ``parts`` to open or create a private report
        directory through retained descriptors. If the function cannot open or
        create a private report directory through retained descriptors, its
        exception reaches the caller instead of being converted into a
        successful result. Cleanup in the ``finally`` path runs for successful,
        failed, and cancelled execution.

        Args:
            parts: Entries supplied as ``parts`` without transferring container
                ownership.

        Yields:
            Each open report output directory admitted by the operation, in
            deterministic iteration order.

        Raises:
            ReportInputSafetyError: If report output directory identity changed;
                report output traverses a link or non-directory; report output
                directory identity changed while opening; or report output
                directory is unavailable; or another input invariant is
                violated.
            BaseException: If a delegated failure occurs while the function
                attempts to open or create a private report directory through
                retained descriptors.
        """

        root_descriptor = self._require_report_output_root()
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        expected_report = self._report_output_dir_identity
        assert expected_report is not None
        report_descriptor = os.open("reports", flags, dir_fd=root_descriptor)
        descriptors: List[Tuple[int, os.stat_result, int, str]] = [
            (report_descriptor, expected_report, root_descriptor, "reports")
        ]
        try:
            if not _same_directory_identity(
                expected_report, os.fstat(report_descriptor)
            ):
                raise ReportInputSafetyError("report output directory identity changed")

            descriptor = report_descriptor
            for part in parts:
                try:
                    before = os.stat(
                        part,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    before = os.stat(
                        part,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                    raise ReportInputSafetyError(
                        "report output traverses a link or non-directory"
                    )
                child_descriptor = os.open(part, flags, dir_fd=descriptor)
                try:
                    opened = os.fstat(child_descriptor)
                    if not _same_directory_identity(before, opened):
                        raise ReportInputSafetyError(
                            "report output directory identity changed while opening"
                        )
                except BaseException:
                    os.close(child_descriptor)
                    raise
                descriptors.append((child_descriptor, opened, descriptor, part))
                descriptor = child_descriptor

            yield descriptor
        except ReportInputSafetyError:
            raise
        except OSError as error:
            raise ReportInputSafetyError(
                "report output directory is unavailable"
            ) from error
        finally:
            verification_error: Optional[BaseException] = None
            for descriptor, expected, parent_descriptor, name in reversed(descriptors):
                try:
                    opened = os.fstat(descriptor)
                    current = os.stat(
                        name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    if not _same_directory_identity(expected, opened) or not (
                        _same_directory_identity(expected, current)
                    ):
                        raise ReportInputSafetyError(
                            "report output directory changed during publication"
                        )
                except BaseException as error:
                    verification_error = verification_error or error
                finally:
                    os.close(descriptor)
            if verification_error is not None:
                raise verification_error

    def _publish_report_text(self, path: Path, text: str) -> None:
        """
        Atomically publish a private regular file beneath the reports root.

        The implementation uses ``path`` and ``text`` to atomically publish a
        private regular file beneath the reports root. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.
        If the function cannot atomically publish a private regular file beneath
        the reports root, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            path: filesystem location used as the path for this operation.
            text: Text supplied as text in the format accepted by this function.

        Raises:
            ReportInputSafetyError: If report output destination is not a
                single-link regular file; or published report output is not a
                private stable file.
            OSError: If short write while publishing report output.
        """

        parts = self._report_output_parts(path)
        directory_parts, filename = parts[:-1], parts[-1]
        data = text.encode("utf-8", errors="strict")
        with self._open_report_output_directory(directory_parts) as descriptor:
            try:
                destination = os.stat(
                    filename,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                destination = None
            if destination is not None and (
                not stat.S_ISREG(destination.st_mode) or destination.st_nlink != 1
            ):
                raise ReportInputSafetyError(
                    "report output destination is not a single-link regular file"
                )

            temporary_name = f".{filename}.{secrets.token_hex(16)}.tmp"
            temporary_descriptor: Optional[int] = None
            published = False
            try:
                temporary_descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=descriptor,
                )
                view = memoryview(data)
                while view:
                    written = os.write(temporary_descriptor, view)
                    if written <= 0:
                        raise OSError("short write while publishing report output")
                    view = view[written:]
                os.fsync(temporary_descriptor)
                os.close(temporary_descriptor)
                temporary_descriptor = None
                os.replace(
                    temporary_name,
                    filename,
                    src_dir_fd=descriptor,
                    dst_dir_fd=descriptor,
                )
                published = True
                current = os.stat(
                    filename,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_nlink != 1
                    or current.st_size != len(data)
                    or current.st_mode & 0o077
                ):
                    raise ReportInputSafetyError(
                        "published report output is not a private stable file"
                    )
                os.fsync(descriptor)
            finally:
                if temporary_descriptor is not None:
                    os.close(temporary_descriptor)
                if not published:
                    try:
                        os.unlink(temporary_name, dir_fd=descriptor)
                    except FileNotFoundError:
                        pass

    def _reset_report_input_budget(self) -> None:
        """
        Start one finite discovery/read budget for a report generation.

        The implementation uses current instance state to start one finite
        discovery/read budget for a report generation. It updates
        ``_report_input_file_count`` and ``_report_input_total_bytes`` on the
        instance as part of that state transition.
        """

        self._report_input_entries.clear()
        self._report_input_file_count = 0
        self._report_input_total_bytes = 0

    def _report_input_anchors(self) -> Tuple[Path, ...]:
        """
        Return lexical roots authorized for offline and receipt-bound inputs.

        After applying local validation, the function forwards current instance
        state to ``tuple`` and preserves its return and exception contract.

        Returns:
            The report input anchors returned in operation-defined order.
        """

        anchors = [Path(os.path.abspath(os.fspath(self.root_dir)))]
        if self._snapshot_binding is not None:
            anchors.extend(
                Path(os.path.abspath(os.fspath(path)))
                for path in self._snapshot_binding.dut_directories
            )
        return tuple(dict.fromkeys(anchors))

    def _report_input_anchor(self, path: Path) -> Tuple[Path, Tuple[str, ...]]:
        """
        Resolve a path lexically below an authorized root without resolving links.

        The implementation uses ``path`` to resolve a path lexically below an
        authorized root without resolving links. If the function cannot resolve
        a path lexically below an authorized root without resolving links, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            A tuple containing ``anchor`` and ``tuple`` in that order.

        Raises:
            ReportInputSafetyError: If report input is outside the collection
                root; report input path depth limit exceeded; or report input
                path is unsafe.
        """

        candidate = Path(os.path.abspath(os.fspath(path)))
        matches: List[Tuple[int, Path, Tuple[str, ...]]] = []
        for anchor in self._report_input_anchors():
            try:
                relative = candidate.relative_to(anchor)
            except ValueError:
                continue
            matches.append((len(anchor.parts), anchor, relative.parts))
        if not matches:
            raise ReportInputSafetyError("report input is outside the collection root")
        _length, anchor, parts = max(matches, key=lambda item: item[0])
        if len(parts) > self._report_input_limits.max_path_depth:
            raise ReportInputSafetyError("report input path depth limit exceeded")
        if any(part in {"", ".", ".."} for part in parts):
            raise ReportInputSafetyError("report input path is unsafe")
        return anchor, tuple(parts)

    def _logical_report_input_relative_path(self, path: Path) -> Path:
        """
        Map an authorized input anchor to one logical bundle-relative path.

        Receipt-bound rendering pins the bundle root and each DUT directory
        independently, so their ``/proc/self/fd`` paths are intentionally not
        ancestors of one another. This mapper first authorizes ``path`` through
        the existing no-follow anchor boundary, then restores the receipt DUT
        identity as the logical first component. It performs no path resolution
        and never consults the replaceable lexical DUT ancestor.

        Args:
            path: Input file or directory below the pinned root or one pinned
                DUT descriptor.

        Returns:
            The canonical logical path relative to the collection bundle root.

        Raises:
            ReportInputSafetyError: If the authorized anchor has no logical
                bundle mapping or the resulting logical path exceeds the
                configured depth bound.
        """

        anchor, relative_parts = self._report_input_anchor(path)
        root_anchor = Path(os.path.abspath(os.fspath(self.root_dir)))
        logical_parts = relative_parts if anchor == root_anchor else None

        binding = self._snapshot_binding
        if logical_parts is None and binding is not None:
            for dut_path in binding.dut_directories:
                dut_anchor = Path(os.path.abspath(os.fspath(dut_path)))
                if anchor == dut_anchor:
                    logical_parts = (dut_path.name, *relative_parts)
                    break

        if logical_parts is None:
            raise ReportInputSafetyError(
                "report input anchor has no logical bundle mapping"
            )
        if len(logical_parts) > self._report_input_limits.max_path_depth:
            raise ReportInputSafetyError("report input path depth limit exceeded")
        return Path(*logical_parts)

    @contextmanager
    def _open_report_input_directory(self, path: Path) -> Iterator[int]:
        """
        Open a directory through retained no-follow descriptors and revalidate it.

        The implementation uses ``path`` to open a directory through retained
        no-follow descriptors and revalidate it. If the function cannot open a
        directory through retained no-follow descriptors and revalidate it, its
        exception reaches the caller instead of being converted into a
        successful result. Cleanup in the ``finally`` path runs for successful,
        failed, and cancelled execution.

        Args:
            path: filesystem location used as the path for this operation.

        Yields:
            Each open report input directory admitted by the operation, in
            deterministic iteration order.

        Raises:
            ReportInputSafetyError: If report input root is unavailable; report
                input root is a symbolic link; report input root is not a
                directory; or report input root identity changed; or another
                input invariant is violated.
            BaseException: If a delegated failure occurs while the function
                attempts to open a directory through retained no-follow
                descriptors and revalidate it.
        """

        anchor, parts = self._report_input_anchor(path)
        snapshot_pinned_anchor = self._snapshot_binding is not None and str(
            anchor
        ).startswith("/proc/self/fd/")
        output_root_pinned_anchor = (
            self._report_output_root_fd is not None
            and self._report_output_root_path == anchor
        )
        try:
            if output_root_pinned_anchor:
                root_descriptor = self._require_report_output_root()
                anchor_before = os.fstat(root_descriptor)
            else:
                anchor_before = (
                    anchor.stat() if snapshot_pinned_anchor else anchor.lstat()
                )
        except FileNotFoundError:
            raise
        except OSError as error:
            raise ReportInputSafetyError("report input root is unavailable") from error
        if not (snapshot_pinned_anchor or output_root_pinned_anchor) and stat.S_ISLNK(
            anchor_before.st_mode
        ):
            raise ReportInputSafetyError("report input root is a symbolic link")
        if not stat.S_ISDIR(anchor_before.st_mode):
            raise ReportInputSafetyError("report input root is not a directory")

        directory_flags = (
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
        )
        if not snapshot_pinned_anchor:
            directory_flags |= getattr(os, "O_NOFOLLOW", 0)

        descriptors: List[Tuple[int, os.stat_result, Optional[int], Optional[str]]] = []
        try:
            if output_root_pinned_anchor:
                descriptor = os.dup(root_descriptor)
            else:
                descriptor = os.open(anchor, directory_flags)
            try:
                opened_anchor = os.fstat(descriptor)
            except BaseException:
                os.close(descriptor)
                raise
            descriptors.append((descriptor, opened_anchor, None, None))
            if not stat.S_ISDIR(opened_anchor.st_mode) or not _same_report_input(
                anchor_before, opened_anchor
            ):
                raise ReportInputSafetyError("report input root identity changed")

            child_flags = directory_flags | getattr(os, "O_NOFOLLOW", 0)
            for part in parts:
                parent_descriptor = descriptor
                before = os.stat(
                    part,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                    raise ReportInputSafetyError(
                        "report input directory traverses a link or non-directory"
                    )
                descriptor = os.open(
                    part,
                    child_flags,
                    dir_fd=parent_descriptor,
                )
                try:
                    opened = os.fstat(descriptor)
                except BaseException:
                    os.close(descriptor)
                    raise
                descriptors.append((descriptor, opened, parent_descriptor, part))
                if not _same_report_input(before, opened):
                    raise ReportInputSafetyError(
                        "report input directory identity changed"
                    )

            yield descriptor
        except (FileNotFoundError, ReportInputSafetyError):
            raise
        except OSError as error:
            raise ReportInputSafetyError(
                "report input directory is unavailable"
            ) from error
        finally:
            verification_error: Optional[BaseException] = None
            for descriptor, expected, parent_descriptor, name in reversed(descriptors):
                try:
                    if not _same_report_input(expected, os.fstat(descriptor)):
                        raise ReportInputSafetyError(
                            "report input directory changed during traversal"
                        )
                    if parent_descriptor is not None and name is not None:
                        current = os.stat(
                            name,
                            dir_fd=parent_descriptor,
                            follow_symlinks=False,
                        )
                        if not _same_report_input(expected, current):
                            raise ReportInputSafetyError(
                                "report input directory path changed during traversal"
                            )
                except BaseException as error:
                    verification_error = verification_error or error
                finally:
                    os.close(descriptor)
            if descriptors and not (
                snapshot_pinned_anchor or output_root_pinned_anchor
            ):
                try:
                    if not _same_report_input(anchor_before, anchor.lstat()):
                        raise ReportInputSafetyError(
                            "report input root changed during traversal"
                        )
                except BaseException as error:
                    verification_error = verification_error or error
            if verification_error is not None:
                raise verification_error

    def _record_report_input(self, entry: _ReportInputEntry) -> None:
        """
        Charge a unique discovered path to member and aggregate limits.

        The implementation uses ``entry`` to charge a unique discovered path to
        member and aggregate limits. It updates ``_report_input_file_count`` and
        ``_report_input_total_bytes`` on the instance as part of that state
        transition. If the function cannot charge a unique discovered path to
        member and aggregate limits, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            entry: Entry object whose ``is_file``, ``metadata``, ``path``,
                ``st_nlink``, and ``st_size`` state is read while performing
                charge a unique discovered path to member and aggregate limits.

        Raises:
            ReportInputSafetyError: If report input identity changed; report
                input path count limit exceeded; report input file has multiple
                links; or report input per-file limit exceeded; or another input
                invariant is violated.
        """

        key = os.path.abspath(os.fspath(entry.path))
        previous = self._report_input_entries.get(key)
        if previous is not None:
            if not _same_report_input(previous, entry.metadata):
                raise ReportInputSafetyError("report input identity changed")
            return

        if len(self._report_input_entries) >= self._report_input_limits.max_path_nodes:
            raise ReportInputSafetyError("report input path count limit exceeded")
        if entry.is_file:
            if entry.metadata.st_nlink != 1:
                raise ReportInputSafetyError("report input file has multiple links")
            if entry.metadata.st_size > self._report_input_limits.max_member_bytes:
                raise ReportInputSafetyError("report input per-file limit exceeded")
            if self._report_input_file_count >= self._report_input_limits.max_members:
                raise ReportInputSafetyError("report input file count limit exceeded")
            if (
                self._report_input_total_bytes + entry.metadata.st_size
                > self._report_input_limits.max_total_bytes
            ):
                raise ReportInputSafetyError(
                    "report input aggregate byte limit exceeded"
                )
            self._report_input_file_count += 1
            self._report_input_total_bytes += entry.metadata.st_size
        self._report_input_entries[key] = entry.metadata

    def _walk_report_inputs(
        self,
        root: Path,
        *,
        recursive: bool,
        excluded_directories: frozenset[str] = frozenset(),
    ) -> List[_ReportInputEntry]:
        """
        Discover a finite regular-file tree without following any link.

        After applying local validation, the function forwards ``root``,
        ``recursive``, and ``excluded_directories`` to ``sorted`` and preserves
        its return and exception contract. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            root: filesystem location used as the root for this operation.
            recursive: Whether recursive is enabled or required for this
                operation.
            excluded_directories: Entries supplied as ``excluded_directories``
                without transferring container ownership.

        Returns:
            The walk report inputs returned in operation-defined order.
        """

        root_path = Path(root)
        discovered: List[_ReportInputEntry] = []
        with self._open_report_input_directory(root_path) as root_descriptor:

            def visit(descriptor: int, directory: Path, depth: int) -> None:
                """
                Visit the current syntax or data node.

                The implementation uses ``descriptor``, ``directory``, and
                ``depth`` to visit the current syntax or data node. Filesystem
                effects remain confined to the caller-selected paths and the
                owning resource lifecycle. If the function cannot visit the
                current syntax or data node, its exception reaches the caller
                instead of being converted into a successful result. Cleanup in
                the ``finally`` path runs for successful, failed, and cancelled
                execution.

                Args:
                    descriptor: Numeric descriptor used while the operation
                        performs bounded accounting.
                    directory: filesystem location used as the directory for
                        this operation.
                    depth: Numeric depth used while the operation performs
                        bounded accounting.

                Raises:
                    ReportInputSafetyError: If report input entry is unreadable;
                        report input tree contains a symbolic link; report input
                        tree contains a special file; or report input path depth
                        limit exceeded; or another input invariant is violated.
                """
                before = os.fstat(descriptor)
                try:
                    with os.scandir(descriptor) as iterator:
                        for child in iterator:
                            try:
                                metadata = child.stat(follow_symlinks=False)
                            except OSError as error:
                                raise ReportInputSafetyError(
                                    "report input entry is unreadable"
                                ) from error
                            if stat.S_ISLNK(metadata.st_mode):
                                raise ReportInputSafetyError(
                                    "report input tree contains a symbolic link"
                                )
                            if not (
                                stat.S_ISREG(metadata.st_mode)
                                or stat.S_ISDIR(metadata.st_mode)
                            ):
                                raise ReportInputSafetyError(
                                    "report input tree contains a special file"
                                )
                            if (
                                stat.S_ISDIR(metadata.st_mode)
                                and child.name in excluded_directories
                            ):
                                continue
                            path = directory / child.name
                            entry = _ReportInputEntry(path, metadata)
                            self._record_report_input(entry)
                            discovered.append(entry)
                            if (
                                recursive
                                and entry.is_dir
                                and child.name not in excluded_directories
                            ):
                                if depth >= self._report_input_limits.max_path_depth:
                                    raise ReportInputSafetyError(
                                        "report input path depth limit exceeded"
                                    )
                                flags = (
                                    os.O_RDONLY
                                    | getattr(os, "O_CLOEXEC", 0)
                                    | getattr(os, "O_DIRECTORY", 0)
                                    | getattr(os, "O_NOFOLLOW", 0)
                                )
                                child_descriptor = os.open(
                                    child.name,
                                    flags,
                                    dir_fd=descriptor,
                                )
                                try:
                                    opened = os.fstat(child_descriptor)
                                    if not _same_report_input(metadata, opened):
                                        raise ReportInputSafetyError(
                                            "report input directory identity changed"
                                        )
                                    visit(child_descriptor, path, depth + 1)
                                    current = os.stat(
                                        child.name,
                                        dir_fd=descriptor,
                                        follow_symlinks=False,
                                    )
                                    if not _same_report_input(metadata, current):
                                        raise ReportInputSafetyError(
                                            "report input directory path changed"
                                        )
                                finally:
                                    os.close(child_descriptor)
                except ReportInputSafetyError:
                    raise
                except OSError as error:
                    raise ReportInputSafetyError(
                        "report input directory is unreadable"
                    ) from error
                if not _same_report_input(before, os.fstat(descriptor)):
                    raise ReportInputSafetyError(
                        "report input directory changed during discovery"
                    )

            visit(root_descriptor, root_path, 0)
        return sorted(discovered, key=lambda entry: os.fspath(entry.path))

    def _inspect_report_input(self, path: Path) -> Optional[_ReportInputEntry]:
        """
        Inspect one no-follow descendant and bind its current identity.

        The implementation uses ``path`` to inspect one no-follow descendant and
        bind its current identity. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. If the function
        cannot inspect one no-follow descendant and bind its current identity,
        its exception reaches the caller instead of being converted into a
        successful result.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            A ``_ReportInputEntry`` representing inspect report input, or
            ``None`` when the requested value is unavailable.

        Raises:
            ReportInputSafetyError: If report input is a symbolic link; or
                report input is a special file.
        """

        candidate = Path(os.path.abspath(os.fspath(path)))
        anchor, parts = self._report_input_anchor(candidate)
        if not parts:
            try:
                with self._open_report_input_directory(candidate) as descriptor:
                    entry = _ReportInputEntry(candidate, os.fstat(descriptor))
                    self._record_report_input(entry)
                    return entry
            except ReportInputSafetyError:
                raise
        parent = anchor.joinpath(*parts[:-1])
        try:
            with self._open_report_input_directory(parent) as descriptor:
                metadata = os.stat(
                    parts[-1],
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if stat.S_ISLNK(metadata.st_mode):
                    raise ReportInputSafetyError("report input is a symbolic link")
                if not (
                    stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
                ):
                    raise ReportInputSafetyError("report input is a special file")
                entry = _ReportInputEntry(candidate, metadata)
                self._record_report_input(entry)
                return entry
        except FileNotFoundError:
            return None

    def _read_report_input(self, path: Path, *, maximum_bytes: int) -> bytes:
        """
        Read one exact, stable regular file beneath an authorized input root.

        After applying local validation, the function forwards ``path`` and
        ``maximum_bytes`` to ``join`` and preserves its return and exception
        contract. Parsing or I/O must finish before the validated representation
        is made available to the caller. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            path: filesystem location used as the path for this operation.
            maximum_bytes: Upper bound enforced for bytes; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            The bounded report input bytes.

        Raises:
            FileNotFoundError: If the function cannot read one exact, stable
                regular file beneath an authorized input root safely.
            ReportInputSafetyError: If report input is not a regular file;
                report input parse byte limit exceeded; report input identity
                changed before read; or report input identity changed while
                opening; or another input invariant is violated.
        """

        entry = self._inspect_report_input(path)
        if entry is None:
            raise FileNotFoundError(path)
        if not entry.is_file:
            raise ReportInputSafetyError("report input is not a regular file")
        if entry.metadata.st_size > maximum_bytes:
            raise ReportInputSafetyError("report input parse byte limit exceeded")

        candidate = Path(os.path.abspath(os.fspath(path)))
        anchor, parts = self._report_input_anchor(candidate)
        parent = anchor.joinpath(*parts[:-1])
        with self._open_report_input_directory(parent) as parent_descriptor:
            before = os.stat(
                parts[-1],
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if not _same_report_input(entry.metadata, before):
                raise ReportInputSafetyError(
                    "report input identity changed before read"
                )
            descriptor = os.open(
                parts[-1],
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or not _same_report_input(
                    before, opened
                ):
                    raise ReportInputSafetyError(
                        "report input identity changed while opening"
                    )
                chunks: List[bytes] = []
                observed = 0
                while True:
                    chunk = os.read(
                        descriptor,
                        min(
                            _REPORT_INPUT_READ_CHUNK_BYTES,
                            entry.metadata.st_size - observed + 1,
                        ),
                    )
                    if not chunk:
                        break
                    chunks.append(chunk)
                    observed += len(chunk)
                    if observed > entry.metadata.st_size or observed > maximum_bytes:
                        raise ReportInputSafetyError(
                            "report input changed size while being read"
                        )
                after = os.fstat(descriptor)
                current = os.stat(
                    parts[-1],
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (
                    observed != entry.metadata.st_size
                    or not _same_report_input(entry.metadata, after)
                    or not _same_report_input(entry.metadata, current)
                ):
                    raise ReportInputSafetyError(
                        "report input changed while being read"
                    )
                return b"".join(chunks)
            finally:
                os.close(descriptor)

    def _read_report_text(self, path: Path) -> str:
        """
        Read report text.

        After applying local validation, the function forwards ``path`` to
        ``decode`` and preserves its return and exception contract. Parsing or
        I/O must finish before the validated representation is made available to
        the caller.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The canonical report text.
        """
        return self._read_report_input(
            path,
            maximum_bytes=self.max_parseable_file_size,
        ).decode("utf-8", errors="strict")

    def _read_report_json(self, path: Path) -> Any:
        """
        Read report JSON.

        After applying local validation, the function forwards ``path`` to
        ``json.loads`` and preserves its return and exception contract. Parsing
        or I/O must finish before the validated representation is made available
        to the caller.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The report JSON value selected by the operation.
        """
        return json.loads(self._read_report_text(path))

    def _report_input_is_file(self, path: Path) -> bool:
        """
        Return the report input is file.

        After applying local validation, the function forwards ``path`` to
        ``bool`` and preserves its return and exception contract.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            Whether the report input is file operation succeeds.
        """
        entry = self._inspect_report_input(path)
        return bool(entry and entry.is_file)

    def _report_input_is_dir(self, path: Path) -> bool:
        """
        Return the report input is dir.

        After applying local validation, the function forwards ``path`` to
        ``bool`` and preserves its return and exception contract.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            Whether the report input is dir operation succeeds.
        """
        entry = self._inspect_report_input(path)
        return bool(entry and entry.is_dir)

    def _safe_node_input_path(self, node_path: Path, value: Any) -> Optional[Path]:
        """
        Resolve metadata-provided POSIX paths without crossing the DUT root.

        The implementation uses ``node_path`` and ``value`` to resolve
        metadata-provided POSIX paths without crossing the DUT root. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle.

        Args:
            node_path: filesystem location used as the node path for this
                operation.
            value: Value evaluated while performing metadata-provided POSIX
                paths without crossing the DUT root.

        Returns:
            The validated ``candidate``, or ``None`` when no value qualifies.
        """

        raw = str(value).strip().replace("\\", "/").lstrip("/")
        if not raw or "\x00" in raw:
            return None
        parts = Path(raw).parts
        if any(part in {"", ".", ".."} for part in parts):
            return None
        candidate = Path(os.path.abspath(os.fspath(node_path.joinpath(*parts))))
        node_root = Path(os.path.abspath(os.fspath(node_path)))
        try:
            candidate.relative_to(node_root)
        except ValueError:
            return None
        self._report_input_anchor(candidate)
        return candidate

    async def _initialize(self):
        """
        Async initialization method.

        Sets up logging, directories, and initializes data structures.
        """
        # Normalize lexically only. Root and every ancestor are authorized with
        # no-follow descriptors before the reports subtree can be removed.
        self.root_dir = Path(os.path.abspath(os.fspath(self.root_dir)))

        # Helper method for async logging
        async def log_message(level: str, message: str, dut_id: str = None):
            """
            Helper to log messages using async logger if available.

            Use system-level logging instead of DUT-specific logging.

            Args:
                level: Text supplied as level in the format accepted by this
                    function.
                message: Operator-facing text carried by the reported event or
                    failure.
                dut_id: Stable DUT identifier used to correlate configuration,
                    logs, and results.
            """
            # dut_id parameter is kept for compatibility but ignored since we use system-level logging
            if self.logger:
                # Use system-level logging instead of DUT-specific logging
                await self.logger.log_runtime(level, "HTMLReportService", message)
            else:
                # Fallback to print if no logger
                print(f"[{level}] HTMLReportService: {message}")

        self._log = log_message

        self.report_dir = self.root_dir / "reports"

        # Set default parameters for nvdebug
        log_path_threshold = 5
        json_collapsible = True
        theme_toggle = False
        hide_na_status = True
        na_string = "N/A"

        # Define root-level files to display in the top-level report
        self.root_level_files = [
            {
                "path": ".nvdebug_stdout.log",
                "display_name": "Runtime Output Log",
            },
            {"path": ".log_signature.txt", "display_name": "Log Signature"},
            {
                "path": "log_signature.txt",
                "display_name": "Log Signature (Legacy)",
            },
            {"path": "config.json", "display_name": "Tool Configuration"},
            {"path": "dut_config.json", "display_name": "DUT Configuration"},
            {
                "path": "nvdebug_runtime_output_structured.txt",
                "display_name": "Structured Runtime Output",
            },
        ]

        try:
            self._prepare_report_output_root()
            await self._log(
                "DEBUG",
                f"Privately recreated reports directory at {self.report_dir}",
            )
        except Exception as e:
            await self._log("ERROR", f"Error preparing reports directory: {e}")
            raise

        self.json_collapsible = json_collapsible
        self.theme_toggle = theme_toggle
        self.hide_na_status = hide_na_status
        self.na_string = na_string
        # total_runtime is already set in __init__
        self.common_navbar = self._get_common_navbar()
        self.html_header_template = self._get_html_header()
        self.html_footer = "</body></html>"

        # Data structures for final statuses
        self.node_statuses: Dict[str, str] = {}
        self.node_statuses_all: Dict[str, List[str]] = {}
        self.node_execution_times: Dict[str, float] = {}

        # For building file map
        self.global_file_map_data: List[dict] = []

        # System info for each node
        self.node_system_details: Dict[str, Dict[str, str]] = {}

        # Threshold for log paths to show inline vs. modal
        self.log_path_threshold = log_path_threshold

        self.node_collector_json: Dict[str, Dict[str, Dict[str, dict]]] = {}

        # Known collector groups (lowercase => Capitalized) - includes both legacy and new naming schemes
        self.known_collector_groups = {
            "healthcheck": "HealthCheck",
            "health_check": "HealthCheck",
            "host": "Host",
            "ipmi": "IPMI",
            "redfish": "Redfish",
            "ssh": "SSH",
            "bmc_ssh": "SSH",
        }

        # Define excluded collector groups
        self.excluded_collector_groups = {
            "error_logs",
            "error-logs",
            "report",
            "reports",
            "metadata",
            ".metadata",
        }

        # Define known informational messages
        self.informational_patterns = [
            r"Not included in current collection map",
            r"disabled from config file",
        ]

        self.log_files_with_viewer = [
            "nvdebug_runtime_output.txt",
            "nvdebug_runtime_output_structured.txt",
            ".nvdebug_stdout.log",
        ]

        # A preferred order for sorting groups (Execution Summary)
        self._group_order = ["HealthCheck", "Host", "IPMI", "Redfish", "SSH"]

        # Initialize global execution entries to store all execution data across nodes
        self.global_execution_entries: List[dict] = []

        # --- File Categorization for Node Report Left Column ---
        self.node_config_files = {
            "config.json",
            "dut_config.json",
            "log_signature.txt",
            ".log_signature.txt",
        }
        self.runtime_log_files = {
            "Execution_Summary_Report.txt",
            "nvdebug_runtime_output.txt",
            "nvdebug_runtime_output_structured.txt",
            "redfish_request.log",
            "collection_status_summary.txt",
        }
        # -------------------------------------------------------

        # Define base log files to ignore and their patterns
        self.log_files_to_ignore = {
            "redfish.log",
            "redfish_request.log",
            "redfish_info.log",
        }

        # Create regex patterns for log rotations
        self.log_ignore_patterns = [
            re.compile(rf"^{base}(\.\d+)?$") for base in self.log_files_to_ignore
        ]

        self.hide_error_logs_row = True

    def _get_legacy_group_name(self, group_name: str) -> str:
        """
        Convert new group name to legacy group name for metadata file lookup.

        After applying local validation, the function forwards ``group_name`` to
        ``group_name_mapping.get`` and preserves its return and exception
        contract. The source value keeps its ownership while the normalized
        representation is returned separately.

        Args:
            group_name: Stable group name used for lookup and operator-facing
                diagnostics.

        Returns:
            The canonical legacy group name.
        """
        # Mapping from new naming scheme to legacy naming scheme for metadata files
        group_name_mapping = {"health_check": "healthcheck", "bmc_ssh": "ssh"}
        return group_name_mapping.get(group_name, group_name)

    def _make_links_clickable(self, text: str) -> str:
        """
        Convert URLs in text to clickable HTML links.

        After applying local validation, the function forwards ``text`` to
        ``_HTML_RENDERER.make_links_clickable`` and preserves its return and
        exception contract. The source value keeps its ownership while the
        normalized representation is returned separately.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical make links clickable text.
        """

        return _HTML_RENDERER.make_links_clickable(text)

    def _get_total_log_size(self, node_path: Path) -> int:
        """
        Return total log size.

        After applying local validation, the function forwards ``node_path`` to
        ``sum`` and preserves its return and exception contract.

        Args:
            node_path: filesystem location used as the node path for this
                operation.

        Returns:
            The numeric total log size.
        """
        return sum(
            entry.metadata.st_size
            for entry in self._walk_report_inputs(
                node_path,
                recursive=True,
                excluded_directories=frozenset({"report", "reports"}),
            )
            if entry.is_file and "reports" not in entry.path.parts
        )

    def _format_bytes(self, size: float) -> str:
        """
        Convert a byte count into a human-readable string.

        After applying local validation, the function forwards ``size`` to
        ``_HTML_RENDERER.format_bytes`` and preserves its return and exception
        contract. The source value keeps its ownership while the normalized
        representation is returned separately.

        Args:
            size: Numeric size used by the operation's bounded accounting.

        Returns:
            The canonical bytes text.
        """
        return _HTML_RENDERER.format_bytes(size)

    def _finalize_page(
        self,
        target_file: Path,
        page_title: str,
        main_content: str,
        breadcrumb_links: Optional[List[Tuple[str, str]]] = None,
        breadcrumb_active_text: str = "",
        modals: Optional[List[str]] = None,
    ) -> None:
        """
        Finalize page.

        The implementation uses ``target_file``, ``page_title``,
        ``main_content``, ``breadcrumb_links``, and ``breadcrumb_active_text``
        to finalize page.

        Args:
            target_file: filesystem location used as the target file for this
                operation.
            page_title: Text supplied as page title in the format accepted by
                this function.
            main_content: Text supplied as main content in the format accepted
                by this function.
            breadcrumb_links: Optional breadcrumb links; ``None`` selects the
                function's default behavior.
            breadcrumb_active_text: Text supplied as breadcrumb active text in
                the format accepted by this function.
            modals: Optional modals; ``None`` selects the function's default
                behavior.
        """
        if breadcrumb_links is None:
            breadcrumb_links = []
        if modals is None:
            modals = []

        # Build breadcrumbs if needed
        breadcrumbs = ""
        if breadcrumb_links:
            breadcrumbs = self._build_breadcrumbs(
                breadcrumb_links, breadcrumb_active_text
            )

        # Combine all parts
        content = f"{breadcrumbs}{main_content}"
        for m in modals:
            content += m

        # Finally, write out the page
        self._write_html_report(target_file, page_title, content)

    def _build_system_details_html(self, node_name: str) -> str:
        """
        Build system details HTML.

        After applying local validation, the function forwards ``node_name`` to
        ``_HTML_RENDERER.build_system_details`` and preserves its return and
        exception contract.

        Args:
            node_name: Stable node name used for lookup and operator-facing
                diagnostics.

        Returns:
            The canonical system details HTML text.
        """
        details = self.node_system_details.get(
            node_name,
            {"Model": "Unknown", "Partno": "Unknown", "Serialno": "Unknown"},
        )
        model = SystemDetailsRenderModel(
            model=details["Model"],
            part_number=details["Partno"],
            serial_number=details["Serialno"],
        )
        return _HTML_RENDERER.build_system_details(model)

    def _build_modal_html(
        self, modal_id: str, modal_title: str, body_content: str
    ) -> str:
        """
        Returns the standard Bootstrap modal HTML snippet.

        After applying local validation, the function forwards ``modal_id``,
        ``modal_title``, and ``body_content`` to ``_HTML_RENDERER.build_modal``
        and preserves its return and exception contract.

        Args:
            modal_id: Stable modal identifier used to correlate configuration,
                logs, and results.
            modal_title: Text supplied as modal title in the format accepted by
                this function.
            body_content: Text supplied as body content in the format accepted
                by this function.

        Returns:
            The canonical modal HTML text.
        """
        return _HTML_RENDERER.build_modal(modal_id, modal_title, body_content)

    def _render_link_list_with_modal(
        self,
        link_objs: List[str],
        threshold: int,
        modal_id: str,
        modal_title: str,
        modal_store_list: Optional[List[str]] = None,
    ) -> str:
        """
        Render link list with modal.

        The implementation uses ``link_objs``, ``threshold``, ``modal_id``,
        ``modal_title``, and ``modal_store_list`` to render link list with
        modal. The source value keeps its ownership while the normalized
        representation is returned separately. The operation mutates
        ``modal_store_list`` in place; ownership of those objects remains with
        the caller.

        Args:
            link_objs: Entries supplied as ``link_objs`` without transferring
                container ownership.
            threshold: Numeric threshold used while the operation performs
                bounded accounting.
            modal_id: Stable modal identifier used to correlate configuration,
                logs, and results.
            modal_title: Text supplied as modal title in the format accepted by
                this function.
            modal_store_list: Optional modal store list; ``None`` selects the
                function's default behavior.

        Returns:
            The canonical link list with modal text.
        """
        rendered = _HTML_RENDERER.render_link_list_with_modal(
            tuple(link_objs),
            threshold,
            modal_id,
            modal_title,
        )
        if modal_store_list is not None and rendered.modal_html is not None:
            modal_store_list.append(rendered.modal_html)
        return rendered.html

    def _parse_from_collection_name(self, coll_name: str) -> Tuple[str, str, str]:
        """
        Parse from collection name.

        The implementation uses ``coll_name`` to parse from collection name.
        Parsing or I/O must finish before the validated representation is made
        available to the caller.

        Args:
            coll_name: Stable coll name used for lookup and operator-facing
                diagnostics.

        Returns:
            A tuple containing the collector group, collector identifier, and
            display name.
        """
        parts = coll_name.split("_")
        if len(parts) == 1:
            return ("N/A", "N/A", coll_name)
        elif len(parts) == 2:
            return (parts[0], "N/A", parts[1])
        else:
            return (parts[0], parts[1], "_".join(parts[2:]))

    def _parse_human_time_to_seconds(self, time_str) -> float:
        """
        Parse human time to seconds.

        The implementation uses ``time_str`` to parse human time to seconds.
        Parsing or I/O must finish before the validated representation is made
        available to the caller.

        Args:
            time_str: Time str object whose ``lower`` and ``strip`` state is
                read while performing human time to seconds.

        Returns:
            The numeric human time to seconds.
        """
        # If it's already a number, return it directly
        if isinstance(time_str, (int, float)):
            return float(time_str)

        # Convert to string if it's not already
        time_str = str(time_str)

        total_seconds = 0.0

        # First try to extract time from "Log collection took X.XX seconds" format
        log_collection_match = re.search(
            r"log collection took (\d+(?:\.\d+)?)\s*seconds?", time_str.lower()
        )
        if log_collection_match:
            return float(log_collection_match.group(1))

        # Try to extract time from "Total execution time: X.XX seconds" format
        total_execution_match = re.search(
            r"total execution time:\s*[^(]*\((\d+(?:\.\d+)?)\s*seconds\)",
            time_str.lower(),
        )
        if total_execution_match:
            return float(total_execution_match.group(1))

        # Try standard time patterns like "2m 59.59s", "1h 3m 10s", "30.0s"
        pattern = re.findall(r"(\d+(?:\.\d+)?)([hms])", time_str.lower())
        if pattern:
            for val, unit in pattern:
                fval = float(val)
                if unit == "h":
                    total_seconds += fval * 3600
                elif unit == "m":
                    total_seconds += fval * 60
                elif unit == "s":
                    total_seconds += fval
        else:
            # Try to extract any number from the string
            number_match = re.search(r"(\d+(?:\.\d+)?)", time_str)
            if number_match:
                try:
                    total_seconds = float(number_match.group(1))
                except ValueError:
                    pass
            else:
                try:
                    total_seconds = float(time_str.strip())
                except ValueError:
                    pass
        return total_seconds

    def _natural_sort_key_for_id(self, cid: str) -> tuple:
        """
        Splits a collector ID like 'I10' into (alpha_part, numeric_part, suffix).

        The implementation uses ``cid`` to splits a collector ID like 'I10' into
        (alpha_part, numeric_part, suffix).

        Args:
            cid: Text supplied as cid in the format accepted by this function.

        Returns:
            A tuple containing ``natural sort key for identifier value 1``,
            ``natural sort key for identifier value 2``, and ``natural sort key
            for identifier value 3`` in that order.
        """
        cid = cid.strip().upper()
        match = re.match(r"^([A-Z]+)(\d+)(.*)$", cid)
        if match:
            return (match.group(1), int(match.group(2)), match.group(3))
        else:
            return (chr(255), 999999, cid)

    def _format_time(self, seconds: float) -> str:
        """
        Convert float seconds to a human-readable time like 'Xh Ym Z.zzs'.

        The implementation uses ``seconds`` to convert float seconds to a
        human-readable time like 'Xh Ym Z.zzs'. The source value keeps its
        ownership while the normalized representation is returned separately.

        Args:
            seconds: Numeric seconds used while the operation performs bounded
                accounting.

        Returns:
            The canonical time text.
        """
        if seconds <= 0:
            return "0.00s"
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        parts = []
        if hours >= 1:
            parts.append(f"{int(hours)}h")
        if minutes >= 1:
            parts.append(f"{int(minutes)}m")
        parts.append(f"{secs:.2f}s")
        return " ".join(parts)

    def _normalize_group_name(self, g: str) -> str:
        """
        Maps known collector groups to a capitalized form if recognized.

        Otherwise returns the given name as-is.

        After applying local validation, the function forwards ``g`` to
        ``self.known_collector_groups.get`` and preserves its return and
        exception contract.

        Args:
            g: Text supplied as g in the format accepted by this function.

        Returns:
            The canonical group name.
        """
        return self.known_collector_groups.get(g.lower(), g)

    def _get_group_from_collector_id(self, collector_id: str) -> str:
        """
        Get the correct group name based on collector ID prefix.

        This ensures proper classification regardless of directory structure.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The canonical group from collector identifier text.
        """
        if not collector_id:
            return "N/A"

        prefix = collector_id[0].upper()
        mapping = {
            "R": "Redfish",
            "I": "IPMI",
            "S": "SSH",
            "H": "Host",
            "C": "HealthCheck",
        }
        return mapping.get(prefix, "N/A")

    def _get_status_class(self, status: str) -> str:
        """
        Returns a CSS class name based on the status string.

        Handle legacy status format (Passed, Failed, Skipped, NotRan).

        Args:
            status: Text supplied as status in the format accepted by this
                function.

        Returns:
            The canonical status class text.
        """
        s = status.lower()
        # Handle legacy status format (Passed, Failed, Skipped, NotRan)
        if s == "passed":
            return "status-complete"
        elif s == "failed":
            return "status-error"
        elif s == "skipped":
            return "status-skipped"
        elif s == "notran":
            return "status-notran"
        # Handle current status format
        elif s in ("success", "complete"):
            return "status-complete"
        elif s == "error":
            return "status-error"
        elif s == "degraded":
            return "status-degraded"
        elif s == "partial":
            return "status-partial"
        elif s == "n/a":
            return "status-na"
        return ""

    def _render_run_identity_navbar(self, run_result: Optional[RunResult]) -> str:
        """
        Render canonical identity facts without consulting another authority.

        After applying local validation, the function forwards ``run_result`` to
        ``HTML_REPORT_PAGE_ASSETS.render_run_identity_navbar`` and preserves its
        return and exception contract. The source value keeps its ownership
        while the normalized representation is returned separately.

        Args:
            run_result: Run result consumed while the function attempts to
                render canonical identity facts without consulting another
                authority.

        Returns:
            The canonical run identity navbar text.
        """

        return HTML_REPORT_PAGE_ASSETS.render_run_identity_navbar(
            run_result,
            escape_html_text=self._escape_html_text,
        )

    def _get_common_navbar(self, run_result: Optional[RunResult] = None) -> str:
        """
        Returns a shared navbar snippet that will appear on all pages.

        After applying local validation, the function forwards ``run_result`` to
        ``HTML_REPORT_PAGE_ASSETS.render_common_navbar`` and preserves its
        return and exception contract.

        Args:
            run_result: Optional run result; ``None`` selects the function's
                default behavior.

        Returns:
            The canonical common navbar text.
        """

        return HTML_REPORT_PAGE_ASSETS.render_common_navbar(
            NavbarRenderModel(
                theme_toggle=self.theme_toggle,
                identity_html=self._render_run_identity_navbar(run_result),
            )
        )

    def _refresh_common_navbar_from_bound_result(self) -> None:
        """
        Refresh the header from the strictly reconstructed bound result.

        The implementation uses current instance state to refresh the header
        from the strictly reconstructed bound result. It updates
        ``common_navbar`` on the instance as part of that state transition.
        """

        self.common_navbar = self._get_common_navbar(self._read_run_result())

    def _get_html_header(self) -> str:
        """
        Returns the HTML header template with placeholders for title and content.

        The implementation uses current instance state to returns the HTML
        header template with placeholders for title and content.

        Returns:
            The canonical HTML header text.
        """

        return HTML_REPORT_PAGE_ASSETS.html_header_template

    def _build_breadcrumbs(self, links: List[Tuple[str, str]], active_text: str) -> str:
        """
        Build breadcrumbs.

        After applying local validation, the function forwards ``links`` and
        ``active_text`` to ``_HTML_RENDERER.build_breadcrumbs`` and preserves
        its return and exception contract.

        Args:
            links: Entries supplied as ``links`` without transferring container
                ownership.
            active_text: Text supplied as active text in the format accepted by
                this function.

        Returns:
            The canonical breadcrumbs text.
        """
        return _HTML_RENDERER.build_breadcrumbs(tuple(links), active_text)

    def _write_html_report(
        self,
        html_file_path: Path,
        page_title: str,
        content: str,
        page_icon: str = None,
        back_button: dict = None,
        subtitle: str = None,
    ) -> str:
        """
        Write HTML report.

        After applying local validation, the function forwards
        ``html_file_path``, ``page_title``, ``content``, ``page_icon``, and
        ``back_button`` to ``replace`` and preserves its return and exception
        contract. Success is reported only after the owning output boundary has
        completed its required write or publication step.

        Args:
            html_file_path: filesystem location used as the HTML file path for
                this operation.
            page_title: Text supplied as page title in the format accepted by
                this function.
            content: Text supplied as content in the format accepted by this
                function.
            page_icon: Optional page icon; ``None`` selects the function's
                default behavior.
            back_button: Optional back button; ``None`` selects the function's
                default behavior.
            subtitle: Optional subtitle; ``None`` selects the function's default
                behavior.

        Returns:
            The canonical write HTML report text.
        """
        back_button_model = None
        if back_button:
            back_button_model = BackButtonRenderModel(
                url=back_button.get("url", "index.html"),
                text=back_button.get("text", "← Back"),
            )
        final_html = _HTML_RENDERER.render_page(
            HTMLPageRenderModel(
                template=self.html_header_template,
                navbar=self.common_navbar,
                page_title=page_title,
                content=content,
                page_icon=page_icon,
                back_button=back_button_model,
                subtitle=subtitle,
            )
        )
        self._publish_report_text(html_file_path, final_html)
        return os.path.relpath(html_file_path, self.report_dir).replace("\\", "/")

    async def _parse_collector_json_metadata(self, node_path: Path) -> None:
        """
        Parse collector JSON metadata.

        Check for both metadata and .metadata directories.

        Args:
            node_path: filesystem location used as the node path for this
                operation.
        """
        await self._log(
            "DEBUG", f"Starting _parse_collector_json_metadata for {node_path}"
        )
        node_name = node_path.name

        # Check for both metadata and .metadata directories
        metadata_dirs = []
        for metadata_dir_name in ["metadata", ".metadata"]:
            metadata_dir = node_path / metadata_dir_name
            if self._report_input_is_dir(metadata_dir):
                metadata_dirs.append(metadata_dir)

        if not metadata_dirs:
            return

        if node_name not in self.node_collector_json:
            self.node_collector_json[node_name] = {}

        # Process all metadata directories found
        # Prioritize group-specific metadata files (redfish.json, ipmi.json, etc.) over general files
        for metadata_dir in metadata_dirs:
            metadata_files = [
                entry.path
                for entry in self._walk_report_inputs(
                    metadata_dir,
                    recursive=False,
                )
                if entry.is_file and entry.path.suffix == ".json"
            ]
            # First pass: process group-specific metadata files
            for meta_json in metadata_files:
                group_name = meta_json.stem
                if group_name.lower() == "metadata":
                    continue
                # Skip timing report files as they have a different structure
                if group_name.startswith("timing_report"):
                    continue
                # Skip general metadata files that are not collector groups
                if group_name in [
                    "dependency_check",
                    "preflight",
                    "collection_status",  # Skip collection_status.json - it's not a collector group
                    "metadata",  # Skip metadata.json - it's general node metadata
                    "timing",  # Skip timing.json - it's timing metadata, not a collector group
                ]:
                    continue
                if group_name not in self.node_collector_json[node_name]:
                    self.node_collector_json[node_name][group_name] = {}

                try:
                    data = self._read_report_json(meta_json)
                    collectors_data = data.get("collectors", {})
                    for collector_id, cinfo in collectors_data.items():
                        raw_time = cinfo.get("execution_time", 0.0)
                        # Handle both string and numeric execution times
                        if isinstance(raw_time, (int, float)):
                            exec_seconds = float(raw_time)
                        else:
                            exec_seconds = self._parse_human_time_to_seconds(raw_time)
                        status_val = cinfo.get("status", "NotRan")
                        reason_val = cinfo.get("reason", "")
                        files_val = cinfo.get("files", [])
                        failure_category = self._normalize_failure_category(
                            status_val, cinfo.get("failure_category")
                        )
                        collector_data = {
                            "execution_time_seconds": exec_seconds,
                            "status": status_val,
                            "reason": reason_val,
                            "group_name": group_name,
                            "id": cinfo.get("id", ""),
                            "name": cinfo.get("name", ""),
                            "files": files_val,
                        }
                        if failure_category is not None:
                            collector_data["failure_category"] = failure_category
                        self.node_collector_json[node_name][group_name][
                            collector_id
                        ] = collector_data
                except ReportInputSafetyError:
                    raise
                except Exception as ex:
                    await self._log(
                        "ERROR",
                        f"Error reading collector JSON {meta_json}: {ex}",
                    )

            # Second pass: process general metadata files (only if collector not already processed)
            for meta_json in metadata_files:
                group_name = meta_json.stem
                if group_name.lower() == "metadata":
                    continue
                # Skip timing report files as they have a different structure
                if group_name.startswith("timing_report"):
                    continue
                # Only process general metadata files in second pass
                if group_name not in [
                    "dependency_check",
                    "health_check",
                    "preflight",
                ]:
                    continue

                if group_name not in self.node_collector_json[node_name]:
                    self.node_collector_json[node_name][group_name] = {}

                try:
                    data = self._read_report_json(meta_json)
                    collectors_data = data.get("collectors", {})
                    await self._log(
                        "DEBUG",
                        f"Processing {group_name} metadata (second pass), found collectors: {list(collectors_data.keys())}",
                    )
                    for collector_id, cinfo in collectors_data.items():
                        # Only process if collector not already processed by group-specific metadata
                        if (
                            group_name in self.node_collector_json[node_name]
                            and collector_id
                            in self.node_collector_json[node_name][group_name]
                        ):
                            continue

                        raw_time = cinfo.get("execution_time", 0.0)
                        # Handle both string and numeric execution times
                        if isinstance(raw_time, (int, float)):
                            exec_seconds = float(raw_time)
                        else:
                            exec_seconds = self._parse_human_time_to_seconds(raw_time)
                        status_val = cinfo.get("status", "NotRan")
                        reason_val = cinfo.get("reason", "")
                        files_val = cinfo.get("files", [])
                        failure_category = self._normalize_failure_category(
                            status_val, cinfo.get("failure_category")
                        )
                        collector_data = {
                            "execution_time_seconds": exec_seconds,
                            "status": status_val,
                            "reason": reason_val,
                            "group_name": group_name,
                            "id": cinfo.get("id", ""),
                            "name": cinfo.get("name", ""),
                            "files": files_val,
                        }
                        if failure_category is not None:
                            collector_data["failure_category"] = failure_category
                        self.node_collector_json[node_name][group_name][
                            collector_id
                        ] = collector_data
                except ReportInputSafetyError:
                    raise
                except Exception as ex:
                    await self._log(
                        "ERROR",
                        f"Error reading collector JSON {meta_json}: {ex}",
                    )

    async def generate_reports(self) -> bool:
        """
        Main method to generate all HTML reports.

        The implementation uses current instance state to main method to
        generate all HTML reports. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind. Cleanup
        in the ``finally`` path runs for successful, failed, and cancelled
        execution.

        Returns:
            Whether the main method to generate all HTML reports operation
            succeeds.
        """
        try:
            await self._log("INFO", "Generating HTML reports...")
            await self._log("DEBUG", f"Root directory: {self.root_dir}")
            node_reports = []
            excluded_dirs = {
                "report",
                "reports",
                "temp",
                "backup",
                ".metadata",
            }

            if not self._report_input_is_dir(self.root_dir):
                await self._log(
                    "ERROR",
                    f"Root directory {self.root_dir} is not a directory.",
                )
                return False

            self._bind_terminal_snapshot()
            self._refresh_common_navbar_from_bound_result()

            for node in self._iter_node_directories():
                if node.is_dir() and node.name not in excluded_dirs:
                    await self._parse_collector_json_metadata(node)
                    node_report = await self._generate_node_report(node)
                    if node_report:
                        node_reports.append(node_report)

            await self._generate_global_file_map()
            await self._generate_timing_analysis_page()
            await self._generate_top_level_report(node_reports)
            await self._log("INFO", f"HTML reports generated in {self.report_dir}")
            return True

        except SnapshotConsistencyError:
            raise
        except ReportInputSafetyError:
            raise
        except Exception as e:
            await self._log("ERROR", f"Error generating HTML reports: {e}")
            return False
        finally:
            self._release_terminal_snapshot()

    async def _parse_execution_summary(self, file_path: Path) -> Dict:
        """
        Parses the Execution_Summary_Report.txt file.

        The implementation uses ``file_path`` to parses the
        Execution_Summary_Report.txt file. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle.

        Args:
            file_path: filesystem location used as the file path for this
                operation.

        Returns:
            The validated ``summary``.
        """
        with file_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()

        parsed_summary, parsed_diagnostics = parse_execution_summary_lines(lines)
        summary = execution_summary_to_legacy_dict(parsed_summary)
        diagnostics = summary_diagnostics_to_legacy_list(parsed_diagnostics)
        for diagnostic in diagnostics:
            code = diagnostic["code"]
            if code == "empty":
                await self._log("DEBUG", f"{file_path} is empty.")
            elif code == "missing_path_columns":
                await self._log(
                    "ERROR",
                    f"Path columns not found in {file_path}. Headers: {diagnostic['headers']}",
                )
            elif code == "missing_required_columns":
                await self._log(
                    "ERROR",
                    f"Required columns missing in {file_path}. Headers: {diagnostic['headers']}",
                )
            elif code == "missing_columns":
                await self._log(
                    "DEBUG",
                    f"Line {diagnostic['line_number']} in {file_path} missing columns.",
                )
        return summary

    def _combine_statuses(self, summary_status: str, json_status: str) -> str:
        """
        Return the combine statuses.

        After applying local validation, the function forwards
        ``summary_status`` and ``json_status`` to ``combine_execution_statuses``
        and preserves its return and exception contract.

        Args:
            summary_status: Text supplied as summary status in the format
                accepted by this function.
            json_status: Text supplied as JSON status in the format accepted by
                this function.

        Returns:
            The canonical combine statuses text.
        """
        return combine_execution_statuses(summary_status, json_status)

    def _merge_status_and_failure_category(
        self,
        current_status: str,
        current_category: Optional[str],
        incoming_status: str,
        incoming_category: Optional[str],
    ) -> Tuple[str, Optional[str]]:
        """
        Merge an outcome while keeping the category from its worst status.

        The implementation uses ``current_status``, ``current_category``,
        ``incoming_status``, and ``incoming_category`` to merge an outcome while
        keeping the category from its worst status.

        Args:
            current_status: Text supplied as current status in the format
                accepted by this function.
            current_category: Text supplied as current category in the format
                accepted by this function.
            incoming_status: Text supplied as incoming status in the format
                accepted by this function.
            incoming_category: Text supplied as incoming category in the format
                accepted by this function.

        Returns:
            A tuple containing ``merged status`` and ``normalize failure
            category`` in that order.
        """
        merged_status = self._combine_statuses(current_status, incoming_status)
        current_category = self._normalize_failure_category(
            current_status, current_category
        )
        incoming_category = self._normalize_failure_category(
            incoming_status, incoming_category
        )
        current_normalized_status = self._combine_statuses("Unknown", current_status)
        incoming_normalized_status = self._combine_statuses("Unknown", incoming_status)
        if current_normalized_status == incoming_normalized_status:
            winning_category = current_category or incoming_category
        elif merged_status == current_normalized_status:
            winning_category = current_category
        elif merged_status == incoming_normalized_status:
            winning_category = incoming_category
        else:
            winning_category = None
        return merged_status, self._normalize_failure_category(
            merged_status, winning_category
        )

    def _merge_error_entries_into_node_json(
        self, node_name: str, grouped_entries: Dict
    ) -> None:
        """
        Merge error entries into node JSON.

        The implementation uses ``node_name`` and ``grouped_entries`` to merge
        error entries into node JSON.

        Args:
            node_name: Stable node name used for lookup and operator-facing
                diagnostics.
            grouped_entries: Mapping supplying fields for merge error entries
                into node JSON.
        """
        error_key = ("error", "logs", "N/A")
        error_entries = grouped_entries.get(error_key, [])
        if not error_entries:
            return

        for err_ent in error_entries:
            err_coll_name = err_ent.get("name") or err_ent.get("collection name")
            err_paths = err_ent.get("log path", [])

            for (cg, cid, cname), entries_list in grouped_entries.items():
                if (cg, cid, cname) == error_key:
                    continue
                for e in entries_list:
                    if e.get("name") == err_coll_name:
                        # Skip if the collector is marked as Skipped
                        if e.get("execution status", "").lower() == "skipped":
                            continue

                        group_json_map = None
                        node_data = self.node_collector_json.get(node_name, {})
                        for g_raw, c_map in node_data.items():
                            if g_raw.lower() == cg.lower():
                                group_json_map = c_map
                                break
                        if not group_json_map:
                            continue

                        if cid.lower() in group_json_map:
                            collector_json = group_json_map[cid.lower()]
                            if not collector_json.get("error_log_paths"):
                                collector_json["error_log_paths"] = []
                            collector_json["error_log_paths"].extend(err_paths)

    def _merge_error_entries(self, grouped_entries: Dict) -> None:
        """
        Merge error entries.

        Only allow real collector groups (not 'dependency_check').

        Args:
            grouped_entries: Mapping supplying fields for merge error entries.
        """
        error_key = ("error", "logs", "N/A")
        error_entry = grouped_entries.get(error_key, [])
        if not error_entry:
            return

        for err_line in error_entry:
            error_collection_name = err_line.get("collection name")
            error_log_path = err_line.get("log path", [])
            found = False
            for key, value_list in grouped_entries.items():
                if key == error_key:
                    continue
                # Only allow real collector groups (not 'dependency_check')
                real_group = key[0].lower() not in (
                    "dependency_check",
                    "error",
                    "metadata",
                    ".metadata",
                )
                if not real_group:
                    continue
                for entry in value_list:
                    if entry.get("name") == error_collection_name:
                        # If the collector is skipped, still append the error log path
                        if "log path" in entry and isinstance(entry["log path"], list):
                            entry["log path"].extend(error_log_path)
                        else:
                            entry["log path"] = error_log_path
                        found = True
            # if not found:
            #     await self._log("WARNING", f"[ReportGenerator] Could not match error log for '{error_collection_name}' to a real collector group. Skipping adding to summary table.")

    async def _build_file_links(
        self, node_path: Path, path_str: str, from_status_page: bool = False
    ) -> List[str]:
        """
        A helper that converts a single path_str into one or more HTML <a> links.

        Handles placeholders, directories, etc.

        The implementation uses ``node_path``, ``path_str``, and
        ``from_status_page`` to a helper that converts a single path_str into
        one or more HTML <a> links. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.

        Args:
            node_path: filesystem location used as the node path for this
                operation.
            path_str: Text supplied as path str in the format accepted by this
                function.
            from_status_page: Whether from status page is enabled or required
                for this operation.

        Returns:
            The file links returned in operation-defined order.
        """
        results = []
        node_name = node_path.name  # Get the node name from the path

        def render_file_link(file_view: str, display_text: str) -> str:
            """
            Render file link.

            The implementation uses ``file_view`` and ``display_text`` to render
            file link. The source value keeps its ownership while the normalized
            representation is returned separately.

            Args:
                file_view: Text supplied as file view in the format accepted by
                    this function.
                display_text: Text supplied as display text in the format
                    accepted by this function.

            Returns:
                The canonical file link text.
            """
            link = (
                self._encoded_relative_report_link(node_name, file_view)
                if from_status_page
                else self._encoded_report_relative_path(file_view)
            )
            if link is None:
                return self._escape_html_text(display_text)
            return (
                f'<a href="{self._escape_html_text(link)}">'
                f"{self._escape_html_text(display_text)}</a>"
            )

        # Skip strings that are clearly not file paths (e.g., error reason messages)
        # These are typically long messages containing colons and spaces, or starting with "Collector"
        if not path_str:
            return results
        # Skip if path would be too long for filesystem (typically 255 chars for filename, 4096 for full path)
        if len(path_str) > 255:
            # This is likely an error message, not a file path - display it as text
            results.append(
                f"<span class='text-muted'>{escape(path_str[:200])}...</span>"
            )
            return results
        # Skip reason messages that start with common error prefixes
        if path_str.startswith("Collector not executed") or path_str.startswith(
            "Error:"
        ):
            results.append(f"<span class='text-muted'>{escape(path_str)}</span>")
            return results

        # Check for placeholder pattern (e.g., "{some_dir}")
        if "{" in path_str and "}" in path_str:
            relative_path = Path(path_str.lstrip("/\\"))
            search_dir = (
                node_path
                if relative_path.parent == Path(".")
                else self._safe_node_input_path(node_path, relative_path.parent)
            )
            if search_dir is not None and self._report_input_is_dir(search_dir):
                for entry in self._walk_report_inputs(
                    search_dir,
                    recursive=False,
                ):
                    if entry.is_file:
                        relp = str(entry.path.relative_to(node_path))
                        fv = await self._generate_file_view(entry.path)
                        results.append(render_file_link(fv, relp))
            else:
                results.append(f"{escape(path_str)} (directory not found)")
        else:
            try:
                abs_path = self._safe_node_input_path(node_path, path_str)
                if abs_path is None:
                    results.append(
                        f"<span class='text-muted'>{escape(path_str)}</span>"
                    )
                    return results
                abs_entry = self._inspect_report_input(abs_path)

                # Check if this is a tar.xz file that was auto-parsed and removed
                if path_str.endswith(".tar.xz") and abs_entry is None:
                    # Look for extracted directory with same base name
                    base_name = path_str[:-7]  # Remove .tar.xz
                    extracted_dir = self._safe_node_input_path(node_path, base_name)

                    if extracted_dir is not None and self._report_input_is_dir(
                        extracted_dir
                    ):
                        # List all files in the extracted directory
                        for entry in self._walk_report_inputs(
                            extracted_dir,
                            recursive=True,
                        ):
                            if entry.is_file:
                                fv = await self._generate_file_view(entry.path)
                                relp = str(entry.path.relative_to(node_path))
                                results.append(render_file_link(fv, relp))

                        # If no files found, show the directory itself
                        if not results:
                            results.append(f"{escape(base_name)} (extracted directory)")
                    else:
                        # Original tar.xz file not found and no extracted directory
                        results.append(f"{escape(path_str)} (file not found)")
                elif abs_entry is not None:
                    if abs_entry.is_dir:
                        for entry in self._walk_report_inputs(
                            abs_path,
                            recursive=True,
                        ):
                            if entry.is_file:
                                fv = await self._generate_file_view(entry.path)
                                relp = str(entry.path.relative_to(node_path))
                                results.append(render_file_link(fv, relp))
                    elif abs_entry.is_file:
                        fv = await self._generate_file_view(abs_path)
                        results.append(render_file_link(fv, path_str))
                else:
                    # not found
                    results.append(f"{escape(path_str)}")
            except OSError:
                # Path too long or other filesystem error - display as text
                results.append(
                    f"<span class='text-muted'>{escape(path_str[:200] + '...' if len(path_str) > 200 else path_str)}</span>"
                )
        return results

    async def _build_left_column_for_node(
        self,
        node_name: str,
        node_path: Path,
        log_collection_time: str,
        node_execution_seconds: float = None,
    ) -> str:
        """
        Build left column for node.

        After applying local validation, the function forwards ``node_name``,
        ``node_path``, ``log_collection_time``, and ``node_execution_seconds``
        to ``_HTML_NODE_SIDEBAR.render`` and preserves its return and exception
        contract. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle.

        Args:
            node_name: Stable node name used for lookup and operator-facing
                diagnostics.
            node_path: filesystem location used as the node path for this
                operation.
            log_collection_time: Text supplied as log collection time in the
                format accepted by this function.
            node_execution_seconds: Maximum duration in seconds allowed for node
                execution seconds.

        Returns:
            The canonical left column for node text.
        """
        system_details_html = self._build_system_details_html(node_name)
        collector_groups = self._get_collector_groups(node_path)
        collector_links: List[NodeSidebarLink] = []
        node_report_dir = self.report_dir / node_name
        for group_folder in collector_groups:
            if not group_folder.is_dir():
                continue
            group_name = group_folder.name
            group_report_path = node_report_dir / f"{group_name}_report.html"
            await self._generate_collector_group_report(
                group_folder, node_path, group_report_path
            )
            relative_report = os.path.relpath(
                group_report_path, node_report_dir
            ).replace("\\", "/")
            collector_links.append(
                NodeSidebarLink(
                    href=relative_report,
                    display_text=group_name,
                    icon="bi-folder",
                )
            )

        all_files = [
            f for f in node_path.rglob("*") if f.is_file() and "reports" not in f.parts
        ]
        collector_group_dirs = {gp.name for gp in collector_groups if gp.is_dir()}
        inventory = _HTML_NODE_SIDEBAR.classify_files(
            node_path=node_path,
            files=all_files,
            collector_group_names=frozenset(collector_group_dirs),
            node_config_names=frozenset(self.node_config_files),
            runtime_log_names=frozenset(self.runtime_log_files),
        )

        async def file_link(
            path: Path, display_text: str, icon: str
        ) -> NodeSidebarLink:
            """
            Return the file link.

            After applying local validation, the function forwards ``path``,
            ``display_text``, and ``icon`` to ``NodeSidebarLink`` and preserves
            its return and exception contract. Owned asynchronous work is
            awaited before return, so completion does not leave an unobserved
            task behind.

            Args:
                path: filesystem location used as the path for this operation.
                display_text: Text supplied as display text in the format
                    accepted by this function.
                icon: Text supplied as icon in the format accepted by this
                    function.

            Returns:
                A ``NodeSidebarLink`` representing file link.
            """
            return NodeSidebarLink(
                href=await self._generate_file_view(path),
                display_text=display_text,
                icon=icon,
            )

        metadata_paths: Dict[str, List[Tuple[Path, str]]] = {}
        standalone_metadata_paths: List[Tuple[Path, str]] = []
        for path in inventory.metadata_files:
            display_path = _HTML_NODE_SIDEBAR.metadata_display_path(node_path, path)
            group_name = _HTML_NODE_SIDEBAR.metadata_group_name(node_path, path)
            if group_name is None:
                standalone_metadata_paths.append((path, display_path))
            else:
                metadata_paths.setdefault(group_name, []).append((path, display_path))

        metadata_groups: List[NodeSidebarLinkGroup] = []
        for group_name in sorted(metadata_paths):
            links = tuple(
                [
                    await file_link(path, display_path, "bi-file-earmark")
                    for path, display_path in sorted(
                        metadata_paths[group_name], key=lambda item: item[1]
                    )
                ]
            )
            metadata_groups.append(NodeSidebarLinkGroup(group_name, links))

        standalone_metadata = tuple(
            [
                await file_link(path, display_path, "bi-file-earmark")
                for path, display_path in sorted(
                    standalone_metadata_paths, key=lambda item: item[1]
                )
            ]
        )

        config_links = tuple(
            [
                await file_link(
                    path,
                    str(path.relative_to(node_path)),
                    "bi-file-earmark-text",
                )
                for path in sorted(inventory.config_files, key=lambda item: item.name)
            ]
        )
        runtime_links = tuple(
            [
                await file_link(path, str(path.relative_to(node_path)), "bi-file-text")
                for path in sorted(inventory.runtime_logs, key=lambda item: item.name)
            ]
        )
        error_links = tuple(
            [
                await file_link(
                    path,
                    str(path.relative_to(node_path)),
                    "bi-exclamation-triangle",
                )
                for path in sorted(
                    inventory.error_logs,
                    key=_HTML_NODE_SIDEBAR.error_log_sort_key,
                )
            ]
        )
        misc_links = tuple(
            [
                await file_link(path, path.name, "bi-file")
                for path in sorted(inventory.misc_files, key=lambda item: item.name)
            ]
        )

        return _HTML_NODE_SIDEBAR.render(
            NodeSidebarRenderModel(
                node_name=node_name,
                log_collection_time=log_collection_time,
                node_execution_seconds=node_execution_seconds,
                system_details_html=system_details_html,
                show_collector_groups=bool(collector_groups),
                collector_groups=tuple(collector_links),
                metadata_groups=tuple(metadata_groups),
                standalone_metadata=standalone_metadata,
                config_files=config_links,
                runtime_logs=runtime_links,
                error_logs=error_links,
                misc_files=misc_links,
            )
        )

    async def _generate_node_report(self, node_path: Path) -> Optional[Path]:
        """
        Generates an HTML report for a single node.

        For nvdebug, we'll create a simple execution summary if the file doesn't
        exist.

        Args:
            node_path: filesystem location used as the node path for this
                operation.

        Returns:
            The validated ``node_report_path``, or ``None`` when no value
            qualifies.
        """
        node_name = node_path.name
        summary_file = node_path / "Execution_Summary_Report.txt"

        # For nvdebug, we'll create a simple execution summary if the file doesn't exist
        if not summary_file.exists():
            await self._log(
                "DEBUG",
                f"Execution Summary not found for {node_name}, creating from metadata.",
            )
            execution_summary = []
            log_collection_time = "Log collection took 0.0 seconds"
        else:
            parsed_summary = await self._parse_execution_summary(summary_file)
            execution_summary = parsed_summary["entries"]
            log_collection_time = parsed_summary["log_collection_time"]

        # If no execution summary from file, try to create from metadata
        if not execution_summary:
            await self._log(
                "DEBUG",
                f"No valid execution summary entries found for {node_name}, creating from metadata.",
            )
            execution_summary = self._create_execution_summary_from_metadata(node_name)
            if not log_collection_time:
                log_collection_time = "Log collection took 0.0 seconds"

        # Calculate total execution time from the actual log collection time
        # This represents the real wall-clock time it took to run all collectors
        node_execution_seconds = 0.0

        # Check if this is an all_collectors_filtered case
        has_all_collectors_filtered = any(
            entry.get("collection name") == "all_collectors_filtered"
            for entry in execution_summary
        )

        if has_all_collectors_filtered:
            node_execution_seconds = 0.0
            await self._log(
                "DEBUG",
                "All collectors were filtered out, setting execution time to 0.0",
            )
        else:
            # Use the execution time from the execution summary (now correctly populated)
            node_execution_seconds = self._parse_human_time_to_seconds(
                log_collection_time
            )
            await self._log(
                "DEBUG",
                f"Using execution summary time: {log_collection_time} -> {node_execution_seconds}s",
            )

        grouped_entries: Dict[(str, str, str), List[dict]] = {}
        for entry in execution_summary:
            paths = entry["log path"]

            # Special handling for all_collectors_filtered entry
            collection_name = entry.get("collection name", "")
            if collection_name == "all_collectors_filtered":
                cg_raw, cid_raw, cname_raw = (
                    "System",
                    "N/A",
                    "All Collectors Filtered",
                )
            else:
                # First, try to get collector info from the orchestrator if available
                collector_id = entry.get("collector_id")
                if collector_id and hasattr(self, "orchestrator") and self.orchestrator:
                    try:
                        collector_info = self.orchestrator.get_collector_info(
                            collector_id
                        )
                        if collector_info:
                            cg_raw = collector_info.get("group", "N/A")
                            cid_raw = collector_id
                            cname_raw = collector_info.get("name", collector_id)
                        else:
                            # Fall back to path parsing
                            if paths:
                                cg_raw, cid_raw, cname_raw = (
                                    self._parse_collector_info_from_path(paths[0])
                                )
                            else:
                                cg_raw, cid_raw, cname_raw = (
                                    "N/A",
                                    "N/A",
                                    "N/A",
                                )
                    except Exception:
                        # Fall back to path parsing
                        if paths:
                            cg_raw, cid_raw, cname_raw = (
                                self._parse_collector_info_from_path(paths[0])
                            )
                        else:
                            cg_raw, cid_raw, cname_raw = ("N/A", "N/A", "N/A")
                else:
                    # No collector ID available, use path parsing
                    if paths:
                        cg_raw, cid_raw, cname_raw = (
                            self._parse_collector_info_from_path(paths[0])
                        )
                    else:
                        # Try to extract collector info from collection name when no log paths
                        cg_raw, cid_raw, cname_raw = (
                            self._parse_collector_info_from_name(collection_name)
                        )

            cg = self._normalize_group_name(cg_raw)
            grouped_key = (cg, cid_raw, cname_raw)
            grouped_entries.setdefault(grouped_key, []).append(entry)

        node_json_data = self.node_collector_json.get(node_name, {})

        # Merge log paths from JSON into grouped_entries.
        for group_name, cdict in node_json_data.items():
            group_cap = self._normalize_group_name(group_name)
            for collector_id, info_dict in cdict.items():
                for (cg, cid, _cname), entries in grouped_entries.items():
                    if (
                        cg.lower() == group_cap.lower()
                        and cid.lower() == collector_id.lower()
                    ):
                        for e in entries:
                            if not e["log path"]:
                                json_log_paths = info_dict.get("log path", [])
                                if json_log_paths:
                                    e["log path"] = json_log_paths
                        break

        # Scan disk for collectors that may not be in the execution summary
        # This ensures we capture all collectors that have files on disk
        collector_groups = self._get_collector_groups(node_path)
        for group_path in collector_groups:
            group_name_orig = group_path.name
            group_cap = self._normalize_group_name(group_name_orig)

            # Scan disk for collectors in this group
            disk_dict = await self._scan_collectors_from_disk(
                group_path, node_path, include_files=False
            )

            # Merge disk files into grouped_entries (add new collectors or extend existing ones)
            for c_id_lower, disk_info in disk_dict.items():
                c_id = disk_info["collector_id_orig"]
                c_name = disk_info["collector_name_orig"]
                log_paths = disk_info["paths"]  # List of path strings

                # Check if this collector already exists in grouped_entries
                found_key = None
                for key in grouped_entries.keys():
                    cg, cid, cname = key
                    if cg.lower() == group_cap.lower() and cid.lower() == c_id.lower():
                        found_key = key
                        break

                if found_key:
                    # Collector exists - merge disk files into existing log paths
                    for entry in grouped_entries[found_key]:
                        # Ensure log path is a list before appending
                        if not isinstance(entry["log path"], list):
                            entry["log path"] = (
                                [] if entry["log path"] is None else [entry["log path"]]
                            )

                        existing_paths = set(entry["log path"])
                        # Add disk paths that aren't already present
                        for path in log_paths:
                            if path not in existing_paths:
                                entry["log path"].append(path)
                else:
                    # Collector doesn't exist - add it
                    # Get status from JSON if available
                    status = "Unknown"
                    failure_category = None
                    if (
                        group_name_orig in node_json_data
                        or group_name_orig.lower() in node_json_data
                    ):
                        group_json = node_json_data.get(
                            group_name_orig,
                            node_json_data.get(group_name_orig.lower(), {}),
                        )
                        if c_id.lower() in group_json:
                            collector_info = group_json[c_id.lower()]
                            status = collector_info.get("status", "Unknown")
                            failure_category = self._normalize_failure_category(
                                status,
                                collector_info.get("failure_category"),
                            )

                    disk_entry = {
                        "collection name": f"{group_cap}_{c_id}_{c_name}",
                        "execution status": status,
                        "log path": log_paths,
                        "id": c_id,
                        "name": c_name,
                        "group": group_name_orig,
                    }
                    if failure_category is not None:
                        disk_entry["failure_category"] = failure_category
                    grouped_entries.setdefault(
                        (group_cap, c_id, c_name),
                        [],
                    ).append(disk_entry)

        # Handle collectors present in JSON but missing from the text summary
        requested_collector_ids = getattr(self, "requested_collector_ids", None)

        # Check if all collectors were filtered out - if so, don't add any from JSON
        has_all_collectors_filtered = any(
            entry.get("collection name") == "all_collectors_filtered"
            for entry in execution_summary
        )

        if not has_all_collectors_filtered:
            # Get the list of collectors that actually executed (from execution summary)
            executed_collector_ids = set()
            for entry in execution_summary:
                collector_id = entry.get("collector_id")
                if collector_id and collector_id != "all_collectors_filtered":
                    executed_collector_ids.add(collector_id.upper())

            for group_name, cdict in node_json_data.items():
                group_cap = self._normalize_group_name(group_name)
                for collector_id, info_dict in cdict.items():
                    # Skip collectors filtered out before execution
                    if self._is_preexecution_filtered_reason(
                        info_dict.get("reason", "")
                    ):
                        await self._log(
                            "DEBUG",
                            f"Skipping collector {collector_id} - filtered out before execution",
                        )
                        continue

                    # Only add this collector if it was requested to run AND actually executed
                    if requested_collector_ids and collector_id.upper() not in [
                        cid.upper() for cid in requested_collector_ids
                    ]:
                        await self._log(
                            "DEBUG",
                            f"Skipping collector {collector_id} - not in requested list",
                        )
                        continue

                    # Only add if it was actually executed
                    if collector_id.upper() not in executed_collector_ids:
                        await self._log(
                            "DEBUG",
                            f"Skipping collector {collector_id} - not in executed list",
                        )
                        continue

                    found_any = False
                    for cg, cid, cname in grouped_entries.keys():
                        if (
                            cg.lower() == group_cap.lower()
                            and cid.lower() == collector_id.lower()
                        ):
                            found_any = True
                            break
                    if not found_any:
                        json_status = info_dict.get("status", "NotRan")
                        json_entry = {
                            "collection name": f"{group_cap}_{collector_id}_{info_dict.get('name', 'N/A')}",
                            "execution status": json_status,
                            "log path": info_dict.get("log path", []),
                            "id": info_dict.get("id", ""),
                            "name": info_dict.get("name", ""),
                            "group": info_dict.get("group_name", ""),
                        }
                        failure_category = self._normalize_failure_category(
                            json_status, info_dict.get("failure_category")
                        )
                        if failure_category is not None:
                            json_entry["failure_category"] = failure_category
                        grouped_entries.setdefault(
                            (
                                group_cap,
                                collector_id,
                                info_dict.get("name", "N/A"),
                            ),
                            [],
                        ).append(json_entry)
        else:
            await self._log(
                "DEBUG",
                "All collectors were filtered out, skipping JSON metadata additions",
            )

        # Merge error entries from text summary
        self._merge_error_entries(grouped_entries)
        # Merge error entries into node_collector_json so we know who they belong to
        self._merge_error_entries_into_node_json(node_name, grouped_entries)

        # Remove any grouped_entries with a non-real collector group (e.g., 'dependency_check')
        real_groups = set(self.known_collector_groups.values())
        keys_to_remove = [
            k for k in grouped_entries if k[0] not in real_groups and k[0] != "N/A"
        ]
        for k in keys_to_remove:
            del grouped_entries[k]

        # Final pass: ensure log paths from group_json reflect in grouped_entries
        for group_name, cdict in node_json_data.items():
            group_cap = self._normalize_group_name(group_name)
            for collector_id, info_dict in cdict.items():
                for (cg, cid, cname), entries in grouped_entries.items():
                    if (
                        cg.lower() == group_cap.lower()
                        and cid.lower() == collector_id.lower()
                    ):
                        for e in entries:
                            if not e["log path"]:
                                error_paths = info_dict.get("error_log_paths", [])
                                if error_paths:
                                    e["log path"] = error_paths
                        break

        details = await self._parse_runtime_output(node_path)
        self.node_system_details[node_name] = details

        node_report_dir = self.report_dir / node_name
        node_report_dir.mkdir(parents=True, exist_ok=True)

        # Build the left column
        left_col_html = await self._build_left_column_for_node(
            node_name, node_path, log_collection_time, node_execution_seconds
        )

        def _group_sort_key(g: str) -> int:
            """
            Return the group sort key.

            The implementation uses ``g`` to produce the group sort key.

            Args:
                g: Text supplied as g in the format accepted by this function.

            Returns:
                The numeric group sort key value.
            """
            glower = g.lower()
            if glower in self.known_collector_groups:
                capital = self.known_collector_groups[glower]
                if capital in self._group_order:
                    return self._group_order.index(capital)
            return 9999

        sorted_keys = sorted(
            grouped_entries.keys(),
            key=lambda x: (
                _group_sort_key(x[0]),
                self._natural_sort_key_for_id(x[1]),
                x[2],
            ),
        )

        es_table = """
        <h3>Execution Summary</h3>
        <table class='table table-striped table-bordered table-shadow'>
        <thead class='table-dark'>
            <tr>
            <th>Collector Group</th>
            <th>Collector ID</th>
            <th>Collector Name</th>
            <th>Collector Exec Time</th>
            <th>Execution Status</th>
            <th>Failure Category</th>
            <th>Log Size</th>
            <th>Log Path(s)</th>
            </tr>
        </thead>
        <tbody>
        """

        all_node_statuses = []
        modals: List[str] = []
        processed_collectors = set()
        any_rows_shown_in_node_report = False  # Flag to track if any rows are displayed

        for idx, (cg, cid, cname) in enumerate(sorted_keys):
            collector_key = (cg.lower(), cid.lower(), cname.lower())
            if collector_key in processed_collectors:
                await self._log(
                    "DEBUG",
                    f"Collector {cg}, {cid}, {cname} already processed. Skipping duplication.",
                )
                continue
            processed_collectors.add(collector_key)

            entries = grouped_entries[(cg, cid, cname)]
            # --- SKIP N/A/N/A/N/A with no log path ---
            all_log_paths = [p for ent in entries for p in ent["log path"]]
            if cg == "N/A" and cid == "N/A" and cname == "N/A" and not all_log_paths:
                continue
            worst_status = "Unknown"
            failure_category = None
            log_paths_collected = []
            summary_durations = []
            summary_reason = ""
            for ent in entries:
                worst_status, failure_category = (
                    self._merge_status_and_failure_category(
                        worst_status,
                        failure_category,
                        ent["execution status"],
                        ent.get("failure_category"),
                    )
                )
                log_paths_collected.extend(ent["log path"])
                if ent.get("duration_seconds") is not None:
                    summary_durations.append(float(ent["duration_seconds"]))
                if not summary_reason and ent.get("reason"):
                    summary_reason = str(ent["reason"])

            # JSON execution time (if any)
            j_exec_time = 0.0
            j_reason = ""
            j_status = ""
            j_failure_category = None
            group_json = None

            for g_lc, c_map in node_json_data.items():
                if g_lc.lower() == cg.lower():
                    group_json = c_map
                    break
            if group_json:
                for c_lc, c_info in group_json.items():
                    if c_lc.lower() == cid.lower():
                        j_exec_time = c_info.get("execution_time_seconds", 0.0)
                        j_reason = c_info.get("reason", "")
                        status_value = str(c_info.get("status", ""))
                        normalized_status = status_value.lower()
                        if normalized_status == "skipped":
                            j_status = "Skipped"
                        elif normalized_status in {"degraded", "partial"}:
                            # These usable failure-bearing states commonly own an
                            # error-log artifact. The artifact is evidence for the
                            # terminal state; it must not upgrade that state to Error.
                            j_status = status_value
                        elif c_info.get("error_log_paths"):
                            j_status = "Error"
                        else:
                            j_status = status_value or "NotRan"
                        j_failure_category = c_info.get("failure_category")
                        break

            worst_status, failure_category = self._merge_status_and_failure_category(
                worst_status,
                failure_category,
                j_status,
                j_failure_category,
            )
            if cg.lower() == "error":
                if self._combine_statuses("Unknown", worst_status) != "Error":
                    failure_category = None
                worst_status = "Error"
                failure_category = self._normalize_failure_category(
                    worst_status, failure_category
                )
            final_exec_time = max(
                0.0,
                max(summary_durations) if summary_durations else j_exec_time,
            )
            if not j_reason:
                j_reason = summary_reason
            collector_exec_time_str = self._format_time(final_exec_time)

            if worst_status.lower() in ("notran", "n/a", "skipped") and j_reason:
                log_paths_collected.insert(0, f"{j_reason}")

            # Skip collectors filtered out due to baseboard constraints
            is_baseboard_filtered = self._is_baseboard_filtered_reason(j_reason)
            if not is_baseboard_filtered:
                for log_path in log_paths_collected:
                    if isinstance(log_path, str) and self._is_baseboard_filtered_reason(
                        log_path
                    ):
                        is_baseboard_filtered = True
                        break

            if is_baseboard_filtered:
                continue

            # Skip collectors that were filtered out before execution
            is_preexecution_filtered = self._is_preexecution_filtered_reason(j_reason)
            if not is_preexecution_filtered:
                for log_path in log_paths_collected:
                    if isinstance(
                        log_path, str
                    ) and self._is_preexecution_filtered_reason(log_path):
                        is_preexecution_filtered = True
                        break

            if is_preexecution_filtered:
                continue

            all_node_statuses.append(worst_status)
            status_class = self._get_status_class(worst_status)

            # Skip entries with N/A status if hide_na_status is True
            if self.hide_na_status and worst_status.lower() == self.na_string.lower():
                continue

            if self.hide_error_logs_row:
                # Skip the error logs row
                if cg.lower() == "error" and cid.lower() == "logs":
                    continue

                # # Skip entries with status in hide_statuses
                # if worst_status.lower() in self.hide_statuses:
                #     continue

                # # Skip entries with collector group in hide_collector_groups
                # if cg.lower() in self.hide_collector_groups:
                #     continue

            # If we reach here, at least one row will be shown
            any_rows_shown_in_node_report = True

            # Build link objects
            link_objs = []
            for pstr in log_paths_collected:
                link_objs.extend(await self._build_file_links(node_path, pstr))

            modal_id = self._generate_safe_id("logModal", f"{node_name}_{cid}_{idx}")
            log_path_display = self._render_link_list_with_modal(
                link_objs,
                self.log_path_threshold,
                modal_id,
                f"All Log Files for {cg} - {cid}",
                modals,
            )

            # Calculate log size for this collector
            log_size = self._get_collector_log_size(node_path, log_paths_collected)
            log_size_str = str(self._format_bytes(log_size)).replace(" ", "")

            es_table += f"""
            <tr>
            <td>{escape(cg)}</td>
            <td>{escape(cid.upper())}</td>
            <td>{escape(cname)}</td>
            <td data-sort="{final_exec_time}">{escape(collector_exec_time_str)}</td>
            <td class="{status_class}">{escape(worst_status)}</td>
            <td>{escape(failure_category or "N/A")}</td>
            <td data-sort="{log_size}">{log_size_str}</td>
            <td>{log_path_display}</td>
            </tr>
            """

            self.global_execution_entries.append(
                {
                    "Node Name": node_name,
                    "Collector Group": cg,
                    "Collector ID": cid.upper(),
                    "Collector Name": cname,
                    "Collector Exec Time": collector_exec_time_str,
                    "Execution Status": worst_status,
                    "Failure Category": failure_category or "",
                    "Log Size": log_size_str,
                    "NodePath": node_path,
                    "Log Path(s)": log_paths_collected,
                }
            )

        # Check if no rows were shown due to filtering
        if not any_rows_shown_in_node_report and self.hide_na_status:
            es_table += '<tr><td colspan="8" style="text-align: center;">No collections were found in collector map for this group.</td></tr>'

        es_table += "</tbody></table>"

        # Final node status
        if any(s == "Error" for s in all_node_statuses):
            node_status = "Error"
        elif any(s == "Partial" for s in all_node_statuses):
            node_status = "Partial"
        elif any(s == "Degraded" for s in all_node_statuses):
            node_status = "Degraded"
        elif all(s == "Complete" for s in all_node_statuses):
            node_status = "Complete"
        elif any(s == "Skipped" for s in all_node_statuses):
            node_status = "Skipped"
        elif any(s == "N/A" for s in all_node_statuses):
            node_status = "N/A"
        else:
            node_status = "Unknown"

        self.node_statuses_all[node_name] = all_node_statuses
        self.node_statuses[node_name] = node_status
        if node_execution_seconds > 0:
            self.node_execution_times[node_name] = node_execution_seconds

        # Add preflight and dependency check tables
        preflight_table = await self._build_preflight_table(
            node_path
        )  # No group_name for all checks
        dependency_table = await self._build_dependency_table(
            node_path
        )  # No group_name for all checks

        # Write dependencies.txt for this DUT (plain-text summary)
        dependencies_text = self._build_dependency_text_table(node_path)
        if dependencies_text:
            dependencies_path = node_report_dir / "dependencies.txt"
            self._publish_report_text(dependencies_path, dependencies_text)

        # Build right column content with all tables
        main_content = f"""
        <div class="row">
            <div class="col-xl-2 col-lg-2 col-md-3">
                {left_col_html}
            </div>
            <div class="col-xl-10 col-lg-10 col-md-9">
                {preflight_table}
                {es_table}
            </div>
        </div>
        """

        node_report_path = node_report_dir / "report.html"
        self._finalize_page(
            target_file=node_report_path,
            page_title=f"Node Report: {node_name}",
            main_content=main_content,
            breadcrumb_links=[("Home", "../index.html")],
            breadcrumb_active_text=node_name,
            modals=modals,
        )

        return node_report_path

    def _get_collector_log_size(self, node_path: Path, log_paths: List[str]) -> int:
        """
        Calculate total size of log files for a specific collector.

        Track dirs and files separately to avoid double counting.

        Args:
            node_path: filesystem location used as the node path for this
                operation.
            log_paths: Filesystem locations processed in caller-provided order.

        Returns:
            The validated ``total``.
        """
        total = 0
        # Track dirs and files separately to avoid double counting
        dir_paths: List[Path] = []
        file_paths: List[Path] = []
        for log_path in log_paths:
            # Skip if the path is a reason message (not a valid file path)
            if not isinstance(log_path, str) or not log_path:
                continue
            # Skip paths that are too long (likely error messages)
            if len(log_path) > 255:
                continue
            # Skip known error message prefixes
            if log_path.startswith("Collector not executed") or log_path.startswith(
                "Error:"
            ):
                continue
            # Skip if the path starts with a non-path character
            if not log_path[0].isalnum() and log_path[0] not in "./":
                continue

            # Clean up the path
            clean_path = log_path.strip().lstrip("/\\")
            if not clean_path:
                continue

            try:
                full_path = self._safe_node_input_path(node_path, clean_path)
                if full_path is None:
                    continue
                entry = self._inspect_report_input(full_path)
            except (OSError, ReportInputSafetyError):
                continue
            if entry is not None and entry.is_file:
                file_paths.append(full_path)
            elif entry is not None and entry.is_dir:
                dir_paths.append(full_path)

        # Collect files from directories
        counted_files: Dict[Path, int] = {}
        for dir_path in dir_paths:
            try:
                entries = self._walk_report_inputs(dir_path, recursive=True)
            except (OSError, ReportInputSafetyError):
                continue
            for entry in entries:
                if entry.is_file:
                    counted_files[entry.path] = entry.metadata.st_size

        # Add explicit files that are not already covered by a directory
        for file_path in file_paths:
            if any(file_path.is_relative_to(dir_path) for dir_path in dir_paths):
                continue
            try:
                entry = self._inspect_report_input(file_path)
            except (OSError, ReportInputSafetyError):
                continue
            if entry is not None and entry.is_file:
                counted_files[file_path] = entry.metadata.st_size

        # Sum sizes (one pass, unique files only)
        for size in counted_files.values():
            total += size
        return total

    def _build_preflight_status_cell(self, check_type: str, check_info: dict) -> tuple:
        """
        Build a single preflight check cell with icon and modal.

        Returns (cell_html, modal_html)

        The implementation uses ``check_type`` and ``check_info`` to build a
        single preflight check cell with icon and modal.

        Args:
            check_type: Text supplied as check type in the format accepted by
                this function.
            check_info: Mapping supplying fields for single preflight check cell
                with icon and modal.

        Returns:
            A tuple containing ``cell HTML`` and ``modal content`` in that
            order.
        """
        status = check_info.get("status", "Unknown")
        reason = check_info.get("reason", "")

        # Create modal for reason if it exists
        modal_content = ""
        if reason:
            modal_id = f"preflight_{check_type}_modal"
            modal_content = self._build_modal_html(
                modal_id,
                f"{check_type} Preflight Details",
                f"<p>{escape(reason)}</p>",
            )

        # Determine icon and color based on status
        if status.lower() == "passed":
            icon = '<i class="bi bi-check-circle-fill text-success fs-4"></i>'
        elif status.lower() == "skipped":
            icon = '<i class="bi bi-dash-circle-fill text-warning fs-4"></i>'
        else:
            icon = '<i class="bi bi-x-circle-fill text-danger fs-4"></i>'

        # Add modal trigger if there's a reason
        if reason:
            cell_html = f"""
            <td class="text-center">
                {icon}
                <br>
                <button class="btn btn-sm btn-link" data-bs-toggle="modal" data-bs-target="#{modal_id}">
                    Details
                </button>
            </td>
            """
        else:
            cell_html = f"""
            <td class="text-center">
                {icon}
            </td>
            """

        return cell_html, modal_content

    def _build_dependency_row(self, collector_id: str, collector_info: dict) -> str:
        """
        Build a single dependency check row.

        The implementation uses ``collector_id`` and ``collector_info`` to build
        a single dependency check row.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.
            collector_info: Mapping supplying fields for single dependency check
                row.

        Returns:
            The canonical dependency row text.
        """
        collector_name = collector_info.get("name", "")
        dependencies = collector_info.get("dependencies", [])

        # Build dependency status list
        dep_html = "<ul class='list-unstyled mb-0'>"
        for dep in dependencies:
            if isinstance(dep, str):
                dep = {"name": dep, "status": "Unknown"}
            dep_name = dep.get("name", "")
            dep_status = dep.get("status", "Unknown")
            dep_message = dep.get("message", "")
            dep_required = dep.get("required", True)

            # Use same icons as preflight
            if dep_status.lower() == "passed":
                icon = '<i class="bi bi-check-circle-fill text-success"></i>'
            elif dep_status.lower() == "skipped":
                icon = '<i class="bi bi-dash-circle-fill text-warning"></i>'
            else:
                icon = '<i class="bi bi-x-circle-fill text-danger"></i>'

            dep_html += f"""
            <li>
                {icon} <strong>{escape(dep_name)}</strong>
                {' (Optional)' if not dep_required else ''}
                {f'<br><small class="text-muted">{self._make_links_clickable(dep_message)}</small>' if dep_message else ''}
            </li>
            """
        dep_html += "</ul>"

        return f"""
        <tr>
            <td>{escape(collector_id.upper())}</td>
            <td>{escape(collector_name)}</td>
            <td>{dep_html}</td>
        </tr>
        """

    async def _build_preflight_table(
        self, node_path: Path, group_name: str = None
    ) -> str:
        """
        Build HTML table for preflight checks.

        If group_name is provided, only show that group's check.

        Args:
            node_path: filesystem location used as the node path for this
                operation.
            group_name: Stable group name used for lookup and operator-facing
                diagnostics.

        Returns:
            The canonical preflight table text.
        """
        # Check for preflight.json in both metadata and .metadata directories
        preflight_json = None
        for metadata_dir_name in ["metadata", ".metadata"]:
            potential_path = node_path / metadata_dir_name / "preflight.json"
            if potential_path.exists():
                preflight_json = potential_path
                break

        if not preflight_json:
            return ""

        try:
            with preflight_json.open("r") as f:
                data = json.load(f)

            preflights = data.get("preflights", {})
            if not preflights:
                return ""

            # Map group name to preflight check name
            group_to_check = {
                "redfish": "REDFISH",
                "ipmi": "IPMI",
                "ssh": "SSH",
                "host": "HOST",
            }

            table = """
            <h3>Preflight Checks</h3>
            <table class='table table-striped table-bordered table-shadow'>
            <thead class='table-dark'>
            """

            modals = []
            node_name = node_path.name

            # Create dependency check modal
            dependency_modal_id = self._generate_safe_id("dependency_modal", node_name)
            dependency_modal = self._build_modal_html(
                dependency_modal_id,
                f"Dependency Checks: {node_name}",
                await self._build_dependency_table(node_path),
            )
            modals.append(dependency_modal)

            if group_name:
                # Single group view
                check_type = group_to_check.get(group_name.lower())
                if not check_type or check_type not in preflights:
                    return ""

                table += """
                    <tr>
                        <th>Status</th>
                        <th>Dependencies</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                """

                cell_html, modal_html = self._build_preflight_status_cell(
                    check_type, preflights[check_type]
                )
                table += cell_html
                if modal_html:
                    modals.append(modal_html)

                # Add dependency check button
                table += f"""
                <td class="text-center">
                    <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#{dependency_modal_id}">
                        <i class="bi bi-list-check"></i> View Dependencies
                    </button>
                </td>
                """

            else:
                # All groups view
                table += """
                    <tr>
                        <th>Host</th>
                        <th>IPMI</th>
                        <th>Redfish</th>
                        <th>SSH</th>
                        <th>Dependencies</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                """

                for check_type in ["HOST", "IPMI", "REDFISH", "SSH"]:
                    check_info = preflights.get(check_type, {})
                    cell_html, modal_html = self._build_preflight_status_cell(
                        check_type, check_info
                    )
                    table += cell_html
                    if modal_html:
                        modals.append(modal_html)

                # Add dependency check button
                table += f"""
                <td class="text-center">
                    <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#{dependency_modal_id}">
                        <i class="bi bi-list-check"></i> View Dependencies
                    </button>
                </td>
                """

            table += """
                </tr>
            </tbody>
            </table>
            """

            # Add all modals
            for modal in modals:
                table += modal

            return table
        except Exception as e:
            await self._log("ERROR", f"Error reading preflight.json: {e}")
            return ""

    async def _build_dependency_table(
        self, node_path: Path, group_name: str = None
    ) -> str:
        """
        Build HTML table for dependency checks.

        If group_name is provided, only show that group's checks.

        Args:
            node_path: filesystem location used as the node path for this
                operation.
            group_name: Stable group name used for lookup and operator-facing
                diagnostics.

        Returns:
            The canonical dependency table text.
        """
        # Check for dependency_check.json in both metadata and .metadata directories
        dependency_json = None
        for metadata_dir_name in ["metadata", ".metadata"]:
            potential_path = node_path / metadata_dir_name / "dependency_check.json"
            if potential_path.exists():
                dependency_json = potential_path
                break

        if not dependency_json:
            return ""

        try:
            with dependency_json.open("r") as f:
                data = json.load(f)

            collectors = data.get("collectors", {})
            if not collectors:
                return ""

            # Get the node's collector execution status
            node_name = node_path.name
            node_execution_data = self.node_collector_json.get(node_name, {})

            # Filter collectors that have dependencies AND were actually executed
            if group_name:
                # Filter by group prefix (r for redfish, i for ipmi, etc.)
                group_prefix = group_name[0].lower()
                collectors_with_deps = {}
                for cid, info in collectors.items():
                    if cid.startswith(group_prefix) and info.get("dependencies"):
                        # Check if this collector was actually executed
                        was_executed = False
                        for group_data in node_execution_data.values():
                            if cid in group_data:
                                status = group_data[cid].get("status", "")
                                if status and status.lower() not in [
                                    "notran",
                                    "n/a",
                                    "",
                                ]:
                                    was_executed = True
                                    break
                        if was_executed:
                            collectors_with_deps[cid] = info
            else:
                # All collectors with dependencies that were executed
                collectors_with_deps = {}
                for cid, info in collectors.items():
                    if info.get("dependencies"):
                        # Check if this collector was actually executed
                        was_executed = False
                        for group_data in node_execution_data.values():
                            if cid in group_data:
                                status = group_data[cid].get("status", "")
                                if status and status.lower() not in [
                                    "notran",
                                    "n/a",
                                    "",
                                ]:
                                    was_executed = True
                                    break
                        if was_executed:
                            collectors_with_deps[cid] = info

            if not collectors_with_deps:
                return """
                <div class='alert alert-info' role='alert'>
                    <strong>No dependencies found.</strong> None of the collectors for this node/group have any dependencies to check.
                </div>
                """

            table = """
            <table class='table table-striped table-bordered table-shadow'>
            <thead class='table-dark'>
                <tr>
                    <th>Collector ID</th>
                    <th>Name</th>
                    <th>Dependencies</th>
                </tr>
            </thead>
            <tbody>
            """

            for collector_id, collector_info in sorted(collectors_with_deps.items()):
                table += self._build_dependency_row(collector_id, collector_info)

            table += "</tbody></table>"
            return table
        except Exception as e:
            await self._log("ERROR", f"Error reading dependency_check.json: {e}")
            return ""

    def _build_dependency_text_table(
        self, node_path: Path, group_name: str = None
    ) -> str:
        """
        Build plain-text table for dependency checks.

        The implementation uses ``node_path`` and ``group_name`` to build
        plain-text table for dependency checks. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.

        Args:
            node_path: filesystem location used as the node path for this
                operation.
            group_name: Stable group name used for lookup and operator-facing
                diagnostics.

        Returns:
            The canonical dependency text table text.
        """
        dependency_json = None
        for metadata_dir_name in ["metadata", ".metadata"]:
            potential_path = node_path / metadata_dir_name / "dependency_check.json"
            if potential_path.exists():
                dependency_json = potential_path
                break

        if not dependency_json:
            return "Dependency check data not found.\n"

        try:
            with dependency_json.open("r") as f:
                data = json.load(f)

            collectors = data.get("collectors", {})
            if not collectors:
                return "No dependency data available.\n"

            node_name = node_path.name
            node_execution_data = self.node_collector_json.get(node_name, {})

            def _was_executed(collector_id: str) -> bool:
                """
                Return the was executed.

                The implementation uses ``collector_id`` to produce the was
                executed.

                Args:
                    collector_id: Stable collector identifier used to correlate
                        configuration, logs, and results.

                Returns:
                    Whether the was executed operation succeeds.
                """
                for group_data in node_execution_data.values():
                    if collector_id in group_data:
                        status = group_data[collector_id].get("status", "")
                        if status and status.lower() not in [
                            "notran",
                            "n/a",
                            "",
                        ]:
                            return True
                return False

            collectors_with_deps = {}
            if group_name:
                group_prefix = group_name[0].lower()
                for cid, info in collectors.items():
                    if cid.startswith(group_prefix) and info.get("dependencies"):
                        if _was_executed(cid):
                            collectors_with_deps[cid] = info
            else:
                for cid, info in collectors.items():
                    if info.get("dependencies"):
                        if _was_executed(cid):
                            collectors_with_deps[cid] = info

            if not collectors_with_deps:
                return (
                    "No dependencies found. None of the collectors for this node/group "
                    "have any dependencies to check.\n"
                )

            def _status_text(status: str) -> str:
                """
                Map one dependency status to its report-table label.

                The implementation uses ``status`` to map one dependency status
                to its report-table label.

                Args:
                    status: Text supplied as status in the format accepted by
                        this function.

                Returns:
                    The canonical status text.
                """
                if status.lower() == "passed":
                    return "OK"
                if status.lower() == "skipped":
                    return "SKIPPED"
                if status.lower() == "not_applicable":
                    return "N/A"
                if status.lower() == "failed":
                    return "MISSING"
                return "UNKNOWN"

            headers = ["Collector", "Name", "Dependencies (status)"]
            rows = []
            for collector_id, collector_info in sorted(collectors_with_deps.items()):
                collector_name = collector_info.get("name", "")
                dependencies = collector_info.get("dependencies", [])
                dep_items = []
                for dep in dependencies:
                    if isinstance(dep, str):
                        dep = {"name": dep, "status": "Unknown"}
                    dep_name = dep.get("name", "")
                    dep_status = dep.get("status", "Unknown")
                    dep_required = dep.get("required", True)
                    requirement = "required" if dep_required else "optional"
                    dep_items.append(
                        f"{dep_name} ({requirement}): {_status_text(dep_status)}"
                    )
                dep_text = "; ".join(dep_items) if dep_items else "None"
                rows.append([collector_id.upper(), collector_name, dep_text])

            widths = [len(h) for h in headers]
            for row in rows:
                for idx, value in enumerate(row):
                    widths[idx] = max(widths[idx], len(value))

            def _separator() -> str:
                """
                Return the separator.

                The implementation uses current instance state to produce the
                separator.

                Returns:
                    The canonical separator text.
                """
                parts = ["-" * (width + 2) for width in widths]
                return f"+{'+'.join(parts)}+"

            def _format_row(values: List[str]) -> str:
                """
                Format row.

                The implementation uses ``values`` to format row. The source
                value keeps its ownership while the normalized representation is
                returned separately.

                Args:
                    values: Entries supplied as ``values`` without transferring
                        container ownership.

                Returns:
                    The canonical row text.
                """
                padded = [values[i].ljust(widths[i]) for i in range(len(values))]
                return f"| {' | '.join(padded)} |"

            lines = [_separator(), _format_row(headers), _separator()]
            for row in rows:
                lines.append(_format_row(row))
            lines.append(_separator())
            return "\n".join(lines) + "\n"
        except Exception:
            return "Error reading dependency_check.json.\n"

    async def _build_group_preflight_table(
        self, node_path: Path, group_name: str
    ) -> str:
        """
        Build HTML table for a specific group's preflight check.

        The implementation uses ``node_path`` and ``group_name`` to build HTML
        table for a specific group's preflight check. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. Filesystem effects remain confined to the caller-selected paths
        and the owning resource lifecycle.

        Args:
            node_path: filesystem location used as the node path for this
                operation.
            group_name: Stable group name used for lookup and operator-facing
                diagnostics.

        Returns:
            The canonical group preflight table text.
        """
        # Check for preflight.json in both metadata and .metadata directories
        preflight_json = None
        for metadata_dir_name in ["metadata", ".metadata"]:
            potential_path = node_path / metadata_dir_name / "preflight.json"
            if potential_path.exists():
                preflight_json = potential_path
                break

        if not preflight_json:
            return ""

        try:
            with preflight_json.open("r") as f:
                data = json.load(f)

            preflights = data.get("preflights", {})
            if not preflights:
                return ""

            # Map group name to preflight check name
            group_to_check = {
                "redfish": "REDFISH",
                "ipmi": "IPMI",
                "ssh": "SSH",
                "host": "HOST",
            }

            check_type = group_to_check.get(group_name.lower())
            if not check_type or check_type not in preflights:
                return ""

            check_info = preflights[check_type]
            status = check_info.get("status", "Unknown")
            reason = check_info.get("reason", "")

            table = """
            <h3>Preflight Check</h3>
            <table class='table table-striped table-bordered table-shadow'>
            <thead class='table-dark'>
                <tr>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <tr>
            """

            # Create modal for reason if it exists
            modal_content = ""
            if reason:
                modal_id = f"preflight_{check_type}_modal"
                modal_content = self._build_modal_html(
                    modal_id,
                    f"{check_type} Preflight Details",
                    f"<p>{escape(reason)}</p>",
                )

            # Determine icon and color based on status
            if status.lower() == "passed":
                icon = '<i class="bi bi-check-circle-fill text-success fs-4"></i>'
            elif status.lower() == "skipped":
                icon = '<i class="bi bi-dash-circle-fill text-warning fs-4"></i>'
            else:
                icon = '<i class="bi bi-x-circle-fill text-danger fs-4"></i>'

            # Add modal trigger if there's a reason
            if reason:
                table += f"""
                <td class="text-center">
                    {icon}
                    <br>
                    <button class="btn btn-sm btn-link" data-bs-toggle="modal" data-bs-target="#{modal_id}">
                        Details
                    </button>
                </td>
                """
            else:
                table += f"""
                <td class="text-center">
                    {icon}
                </td>
                """

            table += """
                </tr>
            </tbody>
            </table>
            """

            if modal_content:
                table += modal_content

            return table
        except Exception as e:
            await self._log("ERROR", f"Error reading preflight.json: {e}")
            return ""

    async def _build_group_dependency_table(
        self, node_path: Path, group_name: str
    ) -> str:
        """
        Build HTML table for dependency checks specific to a collector group.

        Filter collectors by group and those that have dependencies.

        Args:
            node_path: filesystem location used as the node path for this
                operation.
            group_name: Stable group name used for lookup and operator-facing
                diagnostics.

        Returns:
            The canonical group dependency table text.
        """
        # Check for dependency_check.json in both metadata and .metadata directories
        dependency_json = None
        for metadata_dir_name in ["metadata", ".metadata"]:
            potential_path = node_path / metadata_dir_name / "dependency_check.json"
            if potential_path.exists():
                dependency_json = potential_path
                break

        if not dependency_json:
            return ""

        try:
            with dependency_json.open("r") as f:
                data = json.load(f)

            collectors = data.get("collectors", {})
            if not collectors:
                return ""

            # Filter collectors by group and those that have dependencies
            group_prefix = group_name[0].lower()  # r for redfish, i for ipmi, etc.
            collectors_with_deps = {
                cid: info
                for cid, info in collectors.items()
                if cid.startswith(group_prefix) and info.get("dependencies")
            }

            if not collectors_with_deps:
                return ""

            table = """
            <h3>Dependency Checks</h3>
            <table class='table table-striped table-bordered table-shadow'>
            <thead class='table-dark'>
                <tr>
                    <th>Collector ID</th>
                    <th>Name</th>
                    <th>Dependencies</th>
                </tr>
            </thead>
            <tbody>
            """

            for collector_id, collector_info in sorted(collectors_with_deps.items()):
                collector_name = collector_info.get("name", "")
                dependencies = collector_info.get("dependencies", [])

                # Build dependency status list
                dep_html = "<ul class='list-unstyled mb-0'>"
                for dep in dependencies:
                    dep_name = dep.get("name", "")
                    dep_status = dep.get("status", "Unknown")
                    dep_message = dep.get("message", "")
                    dep_required = dep.get("required", True)

                    # Use same icons as preflight
                    if dep_status.lower() == "passed":
                        icon = '<i class="bi bi-check-circle-fill text-success"></i>'
                    elif dep_status.lower() == "skipped":
                        icon = '<i class="bi bi-dash-circle-fill text-warning"></i>'
                    else:
                        icon = '<i class="bi bi-x-circle-fill text-danger"></i>'

                    dep_html += f"""
                    <li>
                        {icon} <strong>{escape(dep_name)}</strong>
                        {' (Optional)' if not dep_required else ''}
                        {f'<br><small class="text-muted">{self._make_links_clickable(dep_message)}</small>' if dep_message else ''}
                    </li>
                    """
                dep_html += "</ul>"

                table += f"""
                <tr>
                    <td>{escape(collector_id.upper())}</td>
                    <td>{escape(collector_name)}</td>
                    <td>{dep_html}</td>
                </tr>
                """

            table += "</tbody></table>"
            return table
        except Exception as e:
            await self._log("ERROR", f"Error reading dependency_check.json: {e}")
            return ""

    async def _scan_collectors_from_disk(
        self, group_path: Path, node_path: Path, include_files: bool = True
    ) -> Dict[str, Dict[str, Any]]:
        """
        Scan collectors from disk.

        The implementation uses ``group_path``, ``node_path``, and
        ``include_files`` to scan collectors from disk. Owned asynchronous work
        is awaited before return, so completion does not leave an unobserved
        task behind.

        Args:
            group_path: filesystem location used as the group path for this
                operation.
            node_path: filesystem location used as the node path for this
                operation.
            include_files: Whether include files is enabled or required for this
                operation.

        Returns:
            A mapping containing scan collectors from disk.
        """
        if not self._report_input_is_dir(group_path):
            return {}

        try:
            items = self._walk_report_inputs(group_path, recursive=False)
        except (PermissionError, OSError) as e:
            await self._log(
                "WARNING",
                f"Failed to scan directory {group_path}: {e}",
            )
            return {}
        collectors = [
            entry
            for entry in items
            if not any(
                pattern.match(entry.path.name) for pattern in self.log_ignore_patterns
            )
        ]

        requested_collector_ids = getattr(self, "requested_collector_ids", None)
        disk_dict = {}

        for collector_entry in collectors:
            it = collector_entry.path
            name_parts = it.name.split("_")
            c_id = "N/A"
            c_name = "N/A"

            # Look for standard collector ID pattern (e.g., R1, H2, S3)
            collector_id_pattern = re.compile(r"^[A-Z]+\d+$")
            for i, part in enumerate(name_parts):
                if collector_id_pattern.match(part):
                    c_id = part
                    # Everything after the ID is the collector name
                    if i + 1 < len(name_parts):
                        c_name = "_".join(name_parts[i + 1 :])
                    break

            # Fallback parsing if no standard pattern found
            if c_id == "N/A":
                if len(name_parts) == 1:
                    c_id, c_name = ("N/A", name_parts[0])
                elif len(name_parts) == 2:
                    c_id, c_name = (name_parts[1], "N/A")
                else:
                    c_id, c_name = (name_parts[1], "_".join(name_parts[2:]))

            # Only process collectors that were requested to run
            if requested_collector_ids and c_id.upper() not in [
                cid.upper() for cid in requested_collector_ids
            ]:
                continue

            # Collect file paths
            files_list = []
            try:
                if collector_entry.is_dir:
                    for entry in self._walk_report_inputs(it, recursive=True):
                        if entry.is_file:
                            subf = entry.path
                            try:
                                relp = str(subf.relative_to(node_path))
                                if include_files:
                                    fv = await self._generate_file_view(subf)
                                    files_list.append((relp, fv))
                                else:
                                    files_list.append(relp)
                            except (PermissionError, OSError) as e:
                                await self._log(
                                    "DEBUG",
                                    f"Skipping file {subf}: {e}",
                                )
                                continue
                else:
                    relp = str(it.relative_to(node_path))
                    if include_files:
                        fv = await self._generate_file_view(it)
                        files_list.append((relp, fv))
                    else:
                        files_list.append(relp)
            except (PermissionError, OSError) as e:
                await self._log(
                    "WARNING",
                    f"Failed to scan collector {it.name}: {e}",
                )
                continue

            disk_dict[c_id.lower()] = {
                "collector_id_orig": c_id,
                "collector_name_orig": c_name,
                "paths": files_list,
            }

        return disk_dict

    async def _generate_collector_group_report(
        self, group_path: Path, node_path: Path, group_report_path: Path
    ) -> None:
        """
        Generates an HTML report for a collector group folder.

        The implementation uses ``group_path``, ``node_path``, and
        ``group_report_path`` to generates an HTML report for a collector group
        folder. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.

        Args:
            group_path: filesystem location used as the group path for this
                operation.
            node_path: filesystem location used as the node path for this
                operation.
            group_report_path: filesystem location used as the group report path
                for this operation.
        """
        node_name = node_path.name
        group_name_orig = group_path.name
        group_display = self._normalize_group_name(group_name_orig)

        # Build the left content with cards
        left_content = f"""
        <div class="card mb-3">
            <div class="card-body">
                <h4>Node: {escape(node_name)}</h4>
                <p>Group: {escape(group_display)}</p>
        """
        left_content += self._build_system_details_html(node_name)
        left_content += """
            </div>
        </div>
        """

        collector_groups = self._get_collector_groups(node_path)
        if collector_groups:
            left_content += """
            <div class="card mb-3">
                <div class="card-body">
                    <h5>Collector Groups</h5>
                    <ul class="list-unstyled">
            """
            for g in collector_groups:
                gname = g.name
                if gname == group_name_orig:
                    left_content += f'<li class="d-block py-1"><strong><i class="bi bi-folder-fill"></i> {escape(gname)} (current)</strong></li>'
                else:
                    sibling_rep = self.report_dir / node_name / f"{gname}_report.html"
                    rel_sibling = os.path.relpath(
                        sibling_rep, group_report_path.parent
                    ).replace("\\", "/")
                    encoded_sibling = self._encoded_report_relative_path(rel_sibling)
                    if encoded_sibling is None:
                        left_content += (
                            '<li><span class="d-block py-1">'
                            f'<i class="bi bi-folder"></i> {escape(gname)}'
                            "</span></li>"
                        )
                    else:
                        left_content += (
                            f'<li><a href="{self._escape_html_text(encoded_sibling)}" '
                            'class="d-block py-1"><i class="bi bi-folder"></i> '
                            f"{escape(gname)}</a></li>"
                        )
            left_content += """
                    </ul>
                </div>
            </div>
            """

        # Add preflight and dependency check tables for this group
        preflight_table = await self._build_preflight_table(
            node_path, group_name_orig
        )  # Pass group_name for specific check
        dependency_table = await self._build_dependency_table(
            node_path, group_name_orig
        )  # Pass group_name for specific checks

        content_right = f"""
        <h2>Collector Group: {escape(group_display)}</h2>
        {preflight_table}
        """

        # Scan disk for collectors in this group
        disk_dict = await self._scan_collectors_from_disk(
            group_path, node_path, include_files=True
        )

        node_json = self.node_collector_json.get(node_name, {})
        group_json = node_json.get(group_name_orig, {})
        if not group_json and (group_name_orig.lower() in node_json):
            group_json = node_json[group_name_orig.lower()]

        merged_dict = {}
        for c_id_lower, ddict in disk_dict.items():
            merged_dict[c_id_lower] = {
                "collector_id": ddict["collector_id_orig"],
                "collector_name": ddict["collector_name_orig"],
                "files": ddict["paths"],
                "exec_time": 0.0,
                "status": "Unknown",
                "reason": "",
            }

        # Get requested collector IDs for filtering
        requested_collector_ids = getattr(self, "requested_collector_ids", None)

        # Get executed collector IDs from execution summary
        executed_collector_ids = set()
        execution_summary_path = node_path / "Execution_Summary_Report.txt"
        if execution_summary_path.exists():
            try:
                parsed_summary = await self._parse_execution_summary(
                    execution_summary_path
                )
                executed_collector_ids.update(
                    str(entry["collector_id"]).upper()
                    for entry in parsed_summary["entries"]
                    if entry.get("collector_id")
                )
            except Exception as e:
                await self._log("WARNING", f"Error reading execution summary: {e}")

        valid_collectors = set()
        for cid_key, jinfo in group_json.items():
            # Only process collectors that were requested to run AND actually executed
            if requested_collector_ids and cid_key.upper() not in [
                cid.upper() for cid in requested_collector_ids
            ]:
                await self._log(
                    "DEBUG",
                    f"Group report: Skipping collector {cid_key} - not in requested list",
                )
                continue

            # Only process collectors that were actually executed when list is available
            if executed_collector_ids and cid_key.upper() not in executed_collector_ids:
                await self._log(
                    "DEBUG",
                    f"Group report: Skipping collector {cid_key} - not in executed list",
                )
                continue

            # Skip collectors that were filtered out before execution
            jreason_check = jinfo.get("reason", "")
            if self._is_preexecution_filtered_reason(jreason_check):
                await self._log(
                    "DEBUG",
                    f"Group report: Skipping collector {cid_key} - filtered out before execution",
                )
                continue

            await self._log(
                "DEBUG",
                f"Group report: Processing collector {cid_key} - requested and executed",
            )

            cid_l = cid_key.lower()
            valid_collectors.add(cid_l)
            jstat = jinfo.get("status", "NotRan")
            jreason = jinfo.get("reason", "")
            jtime = jinfo.get("execution_time_seconds", 0.0)
            error_paths = jinfo.get("error_log_paths", [])
            real_name = jinfo.get("name", "") or "N/A"

            # Get files from metadata
            metadata_files = jinfo.get("files", [])

            if cid_l not in merged_dict:
                merged_dict[cid_l] = {
                    "collector_id": cid_key,
                    "collector_name": real_name,
                    "files": [],
                    "exec_time": jtime,
                    "status": self._combine_statuses(jstat, jstat),
                    "reason": jreason,
                }
            else:
                existing = merged_dict[cid_l]
                existing["exec_time"] = max(existing["exec_time"], jtime)
                old_st = existing["status"]
                merged_st = self._combine_statuses(old_st, jstat)
                existing["status"] = merged_st
                if jreason:
                    existing["reason"] = jreason

            # Add files from metadata if not already in the files list
            for file_path in metadata_files:
                # Metadata files are now stored as relative paths from DUT directory
                # Construct absolute path: node_path / relative_path
                abs_file = node_path / file_path

                if abs_file.exists():
                    fv = await self._generate_file_view(abs_file)
                    try:
                        relp = str(abs_file.relative_to(node_path))
                    except ValueError:
                        # If relative_to fails, use the original relative path
                        relp = file_path
                    # Avoid duplicates
                    if not any(fp == relp for fp, _ in merged_dict[cid_l]["files"]):
                        merged_dict[cid_l]["files"].append((relp, fv))

            # Merge any error log paths
            for ep in error_paths:
                abs_err = node_path / ep.lstrip("/")
                if abs_err.exists():
                    fv = await self._generate_file_view(abs_err)
                    relp = str(abs_err.relative_to(node_path))
                    merged_dict[cid_l]["files"].append((relp, fv))
                else:
                    merged_dict[cid_l]["files"].append((ep, f"{ep} (not found)"))

        if not merged_dict:
            content_right += "<p>No collectors found in this group.</p>"
        else:
            # If we have a non-empty set of valid collectors, drop any others from merged_dict
            if valid_collectors:
                merged_dict = {
                    k: v for k, v in merged_dict.items() if k in valid_collectors
                }
            sorted_keys = sorted(
                merged_dict.keys(),
                key=lambda x: self._natural_sort_key_for_id(x),
            )
            content_right += """
            <table class='table table-striped table-bordered table-shadow'>
                <thead class='table-dark'>
                <tr>
                    <th>Collector ID</th>
                    <th>Collector Name</th>
                    <th>Collector Exec Time</th>
                    <th>Status</th>
                    <th>Log Path(s)</th>
                </tr>
                </thead>
                <tbody>
            """
            modals = []
            idx = 0
            any_rows_shown_in_group_report = (
                False  # Flag to track if any rows are displayed
            )
            for cid_lc in sorted_keys:
                rowdata = merged_dict[cid_lc]
                cid_real = rowdata["collector_id"].upper()
                cname_real = rowdata["collector_name"]
                ctime = rowdata["exec_time"]
                cstatus = rowdata["status"]
                creason = rowdata["reason"]
                ftime_str = self._format_time(ctime)
                status_class = self._get_status_class(cstatus)
                row_id = self._generate_safe_id("collector", cid_real)

                # Skip entries with N/A status if hide_na_status is True
                if self.hide_na_status and cstatus.lower() == self.na_string.lower():
                    continue

                if self.hide_error_logs_row:
                    # Skip the error logs row
                    if cid_lc.lower() == "logs":
                        continue

                    # # Skip entries with status in hide_statuses
                    # if cstatus.lower() in self.hide_statuses:
                    #     continue

                    # # Skip entries with collector group in hide_collector_groups
                    # if cid_lc.lower() in self.hide_collector_groups:
                    #     continue

                # If we reach here, at least one row will be shown
                any_rows_shown_in_group_report = True

                link_objs = []
                for fp, link in rowdata["files"]:
                    encoded_link = self._encoded_report_relative_path(link)
                    if encoded_link is None:
                        link_objs.append(self._escape_html_text(fp))
                    else:
                        link_objs.append(
                            f'<a href="{self._escape_html_text(encoded_link)}">'
                            f"{self._escape_html_text(fp)}</a>"
                        )
                    self.global_file_map_data.append(
                        {
                            "Node Name": node_name,
                            "Collector Group": group_name_orig,
                            "Collector ID/Name": (
                                f"{cid_real}_{cname_real}"
                                if cname_real != "N/A"
                                else cid_real
                            ),
                            "File Path": fp,
                            "Link": link,
                        }
                    )

                if cstatus.lower() in ("notran", "n/a", "skipped") and creason:
                    link_objs.insert(0, self._make_links_clickable(str(creason)))

                modal_id = self._generate_safe_id(
                    "modal", f"{node_name}_{group_name_orig}_{cid_real}_{idx}"
                )
                log_path_display = self._render_link_list_with_modal(
                    link_objs,
                    self.log_path_threshold,
                    modal_id,
                    f"{group_name_orig} - {cid_real}",
                    modals,
                )

                content_right += f"""
                <tr id=\"{row_id}\">
                    <td>{escape(cid_real)}</td>
                    <td>{escape(cname_real)}</td>
                    <td>{escape(ftime_str)}</td>
                    <td class="{status_class}">{escape(cstatus)}</td>
                    <td>{log_path_display if log_path_display else "N/A"}</td>
                </tr>
                """
                idx += 1

            # Check if no rows were shown due to filtering
            if not any_rows_shown_in_group_report and self.hide_na_status:
                content_right += '<tr><td colspan="5" style="text-align: center;">No collections were found in collector map for this group.</td></tr>'

            content_right += "</tbody></table>"
            for mmm in modals:
                content_right += mmm

        final_html = f"""
        <div class="row">
            <div class="col-xl-2 col-lg-2 col-md-3">
            {left_content}
            </div>
            <div class="col-xl-10 col-lg-10 col-md-9">
            {content_right}
            </div>
        </div>
        """

        self._finalize_page(
            target_file=group_report_path,
            page_title=f"Collector Group: {group_display}",
            main_content=final_html,
            breadcrumb_links=[
                ("Home", "../index.html"),
                (node_name, "report.html"),
            ],
            breadcrumb_active_text=group_display,
            modals=[],
        )

    async def _generate_timing_breakdown_table(
        self, total_runtime: Optional[float] = None
    ) -> str:
        """
        Generate a comprehensive timing breakdown table from all DUT metadata files.

        Scan all DUT directories for metadata.json files.

        Args:
            total_runtime: Optional total runtime; ``None`` selects the
                function's default behavior.

        Returns:
            The canonical generate timing breakdown table text.
        """
        try:
            timing_data = {}

            # Scan all DUT directories for metadata.json files
            for node in self._iter_node_directories():
                if (
                    node.is_dir()
                    and not node.name.startswith(".")
                    and node.name not in ["reports", "temp", "backup"]
                ):
                    metadata_file = node / ".metadata" / "metadata.json"
                    if metadata_file.exists():
                        try:
                            with open(metadata_file, "r") as f:
                                metadata = json.load(f)

                            dut_id = metadata.get("payload", {}).get(
                                "DUT_ID", node.name
                            )
                            timing_info = metadata.get("payload", {}).get(
                                "timing_data", {}
                            )

                            if timing_info:
                                timing_data[dut_id] = timing_info
                        except Exception as e:
                            await self._log(
                                "WARN",
                                f"Error reading metadata from {metadata_file}: {e}",
                            )

            if not timing_data:
                return "<p>No timing data available.</p>"

            # Calculate detailed timing metrics
            total_runtime_display = (
                f"{total_runtime:.3f}s" if total_runtime is not None else "N/A"
            )

            # Calculate collector timing breakdown
            # Since collectors run in parallel, we need the maximum time, not the sum
            all_collector_times = []
            for data in timing_data.values():
                for c in data.get("collectors", {}).values():
                    all_collector_times.append(c.get("total_time", 0))

            total_collector_time = (
                max(all_collector_times) if all_collector_times else 0
            )

            # Calculate stage breakdown
            # Since collectors run in parallel, we need the maximum time for each stage, not the sum
            all_validation_times = []
            all_execution_times = []
            all_post_processing_times = []

            for data in timing_data.values():
                for c in data.get("collectors", {}).values():
                    stages = c.get("stages", {})
                    all_validation_times.append(
                        stages.get("validation", {}).get("total_time", 0)
                    )
                    all_execution_times.append(
                        stages.get("execution", {}).get("total_time", 0)
                    )
                    all_post_processing_times.append(
                        stages.get("post_processing", {}).get("total_time", 0)
                    )

            total_validation_time = (
                max(all_validation_times) if all_validation_times else 0
            )
            total_execution_time = (
                max(all_execution_times) if all_execution_times else 0
            )
            total_post_processing_time = (
                max(all_post_processing_times) if all_post_processing_times else 0
            )

            # Get component timing data if available
            component_timing = {}
            if (
                hasattr(self, "orchestrator")
                and self.orchestrator
                and hasattr(self.orchestrator, "timing_manager")
            ):
                component_timing = (
                    self.orchestrator.timing_manager.get_component_timing()
                )

            # Calculate detailed overhead breakdown
            tool_init_time = component_timing.get("tool_initialization", {}).get(
                "total_time", 0
            )
            config_loading_time = component_timing.get("configuration_loading", {}).get(
                "total_time", 0
            )
            dut_init_time = component_timing.get("dut_initialization", {}).get(
                "total_time", 0
            )
            preflight_time = component_timing.get("preflight_checks", {}).get(
                "total_time", 0
            )
            html_generation_time = component_timing.get(
                "html_report_generation", {}
            ).get("total_time", 0)
            metadata_time = component_timing.get("metadata_creation", {}).get(
                "total_time", 0
            )
            cleanup_time = component_timing.get("cleanup", {}).get("total_time", 0)

            # Calculate remaining overhead (total runtime - all tracked components)
            tracked_components_time = (
                total_collector_time
                + tool_init_time
                + config_loading_time
                + dut_init_time
                + preflight_time
                + html_generation_time
                + metadata_time
                + cleanup_time
            )
            # Calculate remaining overhead (total runtime - all tracked components)
            # Note: If tracked_components_time > total_runtime, this indicates timing measurement overlap
            # or precision issues. We cap it at 0 to avoid negative values.
            remaining_overhead = max(
                0,  # Ensure it's never negative
                (
                    (total_runtime - tracked_components_time)
                    if total_runtime is not None
                    else 0
                ),
            )

            # Log timing discrepancy if significant (for debugging)
            if total_runtime and tracked_components_time > total_runtime:
                timing_discrepancy = tracked_components_time - total_runtime
                if (
                    timing_discrepancy > 1.0
                ):  # Only log if discrepancy is more than 1 second
                    await self.logger.log_runtime(
                        "WARN",
                        "HTMLReportService",
                        f"Timing discrepancy detected: tracked_components_time ({tracked_components_time:.3f}s) > total_runtime ({total_runtime:.3f}s), difference: {timing_discrepancy:.3f}s",
                    )

            # Generate HTML table
            html = f"""
            <div class="timing-breakdown">
                <div class="overall-timing">
                    <table class='table table-striped table-bordered table-shadow'>
                        <thead class='table-dark'>
                            <tr>
                                <th>Metric</th>
                                <th>Value</th>
                                <th>Percentage</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr class="table-primary">
                                <td><strong>Total nvdebug Execution Time</strong></td>
                                <td><strong>{total_runtime_display}</strong></td>
                                <td><strong>100%</strong></td>
                            </tr>
                            <tr class="table-info">
                                <td>Collector Execution Time</td>
                                <td>{total_collector_time:.3f}s</td>
                                <td>{f"{(total_collector_time/total_runtime*100):.1f}%" if total_runtime else "N/A"}</td>
                            </tr>
                            <tr class="table-info">
                                <td>Tool Initialization</td>
                                <td>{tool_init_time:.3f}s</td>
                                <td>{f"{(tool_init_time/total_runtime*100):.1f}%" if total_runtime else "N/A"}</td>
                            </tr>
                            <tr class="table-info">
                                <td>Configuration Loading</td>
                                <td>{config_loading_time:.3f}s</td>
                                <td>{f"{(config_loading_time/total_runtime*100):.1f}%" if total_runtime else "N/A"}</td>
                            </tr>
                            <tr class="table-info">
                                <td>DUT Initialization</td>
                                <td>{dut_init_time:.3f}s</td>
                                <td>{f"{(dut_init_time/total_runtime*100):.1f}%" if total_runtime else "N/A"}</td>
                            </tr>
                            <tr class="table-info">
                                <td>Preflight Checks</td>
                                <td>{preflight_time:.3f}s</td>
                                <td>{f"{(preflight_time/total_runtime*100):.1f}%" if total_runtime else "N/A"}</td>
                            </tr>
                            <tr class="table-info">
                                <td>HTML Report Generation</td>
                                <td>{html_generation_time:.3f}s</td>
                                <td>{f"{(html_generation_time/total_runtime*100):.1f}%" if total_runtime else "N/A"}</td>
                            </tr>
                            <tr class="table-info">
                                <td>Metadata Creation</td>
                                <td>{metadata_time:.3f}s</td>
                                <td>{f"{(metadata_time/total_runtime*100):.1f}%" if total_runtime else "N/A"}</td>
                            </tr>
                            <tr class="table-info">
                                <td>Cleanup</td>
                                <td>{cleanup_time:.3f}s</td>
                                <td>{f"{(cleanup_time/total_runtime*100):.1f}%" if total_runtime else "N/A"}</td>
                            </tr>
                            <tr class="table-warning">
                                <td>Other Overhead</td>
                                <td>{remaining_overhead:.3f}s</td>
                                <td>{f"{(remaining_overhead/total_runtime*100):.1f}%" if total_runtime else "N/A"}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <script>
            // Add sorting functionality to the timing table
            document.addEventListener('DOMContentLoaded', function() {{
                const table = document.querySelector('.detailed-timing table');
                if (table) {{
                    const headers = table.querySelectorAll('thead th');
                    headers.forEach((header, index) => {{
                        header.style.cursor = 'pointer';
                        header.addEventListener('click', () => sortTable(table, index));
                    }});
                }}
            }});

            function sortTable(table, columnIndex) {{
                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                const isNumeric = columnIndex >= 3; // Time columns are numeric

                rows.sort((a, b) => {{
                    let aVal = a.cells[columnIndex].textContent.trim();
                    let bVal = b.cells[columnIndex].textContent.trim();

                    if (isNumeric) {{
                        // Extract numeric value from time strings (e.g., "2.345s" -> 2.345)
                        aVal = parseFloat(aVal.replace('s', '')) || 0;
                        bVal = parseFloat(bVal.replace('s', '')) || 0;
                        return aVal - bVal;
                    }} else {{
                        return aVal.localeCompare(bVal);
                    }}
                }});

                // Clear and re-append sorted rows
                rows.forEach(row => tbody.appendChild(row));
            }}
            </script>
            """

            return html

        except Exception as e:
            await self._log("ERROR", f"Error generating timing breakdown: {e}")
            return f"<p>Error generating timing breakdown: {escape(str(e))}</p>"

    def _generate_safe_id(self, prefix: str, node_name: str) -> str:
        """
        Generate a safe, unique ID for modals and other HTML elements.

        Replaces spaces and special characters with underscores.

        Args:
            prefix: Text supplied as prefix in the format accepted by this
                function.
            node_name: Stable node name used for lookup and operator-facing
                diagnostics.

        Returns:
            The canonical generate safe identifier text.
        """
        # Replace spaces and special characters with underscores
        safe_name = re.sub(r"[^a-zA-Z0-9]", "_", node_name)
        if not safe_name:
            safe_name = "node"
        # Ensure the ID starts with a letter
        safe_name = "n" + safe_name if not safe_name[0].isalpha() else safe_name
        return f"{prefix}_{safe_name}"

    def _is_baseboard_filtered_reason(self, reason: Optional[str]) -> bool:
        """
        Determine whether a reason string indicates baseboard-based filtering.

        The implementation uses ``reason`` to determine whether a reason string
        indicates baseboard-based filtering.

        Args:
            reason: Text supplied as reason in the format accepted by this
                function.

        Returns:
            Whether the reason string indicates baseboard-based filtering
            operation succeeds.
        """
        if not reason:
            return False
        reason_lower = reason.lower()
        if "baseboardconstraint" in reason_lower:
            return True
        if "baseboard" in reason_lower and "not applicable" in reason_lower:
            return True
        return False

    def _is_preexecution_filtered_reason(self, reason: Optional[str]) -> bool:
        """
        Return whether ``reason`` is preexecution filtered reason.

        The implementation uses ``reason`` to determine whether ``reason`` is
        preexecution filtered reason.

        Args:
            reason: Text supplied as reason in the format accepted by this
                function.

        Returns:
            Whether ``reason`` is preexecution filtered reason.
        """
        if not reason:
            return False
        reason_lower = reason.lower()
        if "filtered out" in reason_lower and (
            "before execution" in reason_lower or "not executed" in reason_lower
        ):
            return True
        return False

    def _create_execution_summary_from_metadata(self, node_name: str) -> List[Dict]:
        """
        Create execution summary entries from metadata for nvdebug.

        Only includes collectors that were requested to run.

        Args:
            node_name: Stable node name used for lookup and operator-facing
                diagnostics.

        Returns:
            The execution summary from metadata returned in operation-defined
            order.
        """
        node_data = self.node_collector_json.get(node_name, {})
        requested_collector_ids = getattr(self, "requested_collector_ids", None)
        records = create_execution_summary_from_metadata(
            node_data,
            requested_collector_ids,
        )
        return metadata_execution_summary_to_legacy_list(records)

    async def _generate_timing_analysis_page(self) -> None:
        """
        Generate timing analysis page.

        Collect timing data from both metadata.json and timing.json files.
        """
        try:
            await self._log("INFO", "Generating timing analysis page...")

            # Collect timing data from both metadata.json and timing.json files
            metadata_timing_data = {}
            timing_data_by_dut = {}

            for node in self._iter_node_directories():
                if (
                    node.is_dir()
                    and not node.name.startswith(".")
                    and node.name not in ["reports", "temp", "backup"]
                ):
                    # Load timing.json for DUT/collector details
                    timing_json_path = node / ".metadata" / "timing.json"
                    try:
                        timing_data = self._read_terminal_timing(node.name)
                        if timing_data is not None:
                            dut_id = timing_data.get("dut_id", node.name)
                            timing_data_by_dut[dut_id] = timing_data
                    except SnapshotArtifactFormatError:
                        if self._terminal_snapshot_generation is not None:
                            raise
                    except SnapshotConsistencyError:
                        raise
                    except Exception as e:
                        await self._log(
                            "WARN",
                            f"Error reading timing data from {timing_json_path}: {e}",
                        )

                    # Load metadata.json for stage-level timing
                    metadata_file = node / ".metadata" / "metadata.json"
                    if metadata_file.exists():
                        try:
                            with open(metadata_file, "r") as f:
                                metadata = json.load(f)
                                dut_id = metadata.get("payload", {}).get(
                                    "DUT_ID", node.name
                                )
                                timing_info = metadata.get("payload", {}).get(
                                    "timing_data", {}
                                )
                                if timing_info:
                                    metadata_timing_data[dut_id] = timing_info
                        except Exception as e:
                            await self._log(
                                "WARN",
                                f"Error reading metadata from {metadata_file}: {e}",
                            )

            if not timing_data_by_dut:
                await self._log("WARN", "No timing data found for analysis page")
                return

            # Build data structures for visualizations
            all_collectors = []
            service_stats = {}
            dut_summaries = {}

            for dut_id, timing_data in timing_data_by_dut.items():
                overall = timing_data.get("overall", {})
                collectors = timing_data.get("collectors", {})
                by_service = timing_data.get("by_service", {})

                # Store DUT summary
                dut_summaries[dut_id] = {
                    "start_time": overall.get("start_time"),
                    "end_time": overall.get("end_time"),
                    "duration": overall.get("wall_clock_duration_seconds", 0),
                    "total_collectors": overall.get("total_collectors", 0),
                    "completed": overall.get("completed", 0),
                    "failed": overall.get("failed", 0),
                    "skipped": overall.get("skipped", 0),
                }

                # Collect all collector execution data for timeline
                for collector_id, collector_data in collectors.items():
                    if collector_data.get("start_time") and collector_data.get(
                        "end_time"
                    ):
                        all_collectors.append(
                            {
                                "dut_id": dut_id,
                                "collector_id": collector_id,
                                "collector_name": collector_data.get(
                                    "collector_name", collector_id
                                ),
                                "group": collector_data.get("group", "unknown"),
                                "status": collector_data.get("status", "unknown"),
                                "start_time": collector_data.get("start_time"),
                                "end_time": collector_data.get("end_time"),
                                "duration": collector_data.get("duration_seconds", 0),
                            }
                        )

                # Aggregate service statistics
                for service, service_data in by_service.items():
                    if service not in service_stats:
                        service_stats[service] = {
                            "total_collectors": 0,
                            "completed": 0,
                            "degraded": 0,
                            "failed": 0,
                            "partial": 0,
                            "skipped": 0,
                            "total_duration": 0.0,
                        }
                    service_stats[service]["total_collectors"] += service_data.get(
                        "total_collectors", 0
                    )
                    service_stats[service]["completed"] += service_data.get(
                        "completed", 0
                    )
                    service_stats[service]["degraded"] += service_data.get(
                        "degraded", 0
                    )
                    service_stats[service]["failed"] += service_data.get("failed", 0)
                    service_stats[service]["partial"] += service_data.get("partial", 0)
                    service_stats[service]["skipped"] += service_data.get("skipped", 0)
                    service_stats[service]["total_duration"] += service_data.get(
                        "total_duration_seconds", 0.0
                    )

            # Sort collectors by start time for timeline visualization
            all_collectors.sort(key=lambda x: x["start_time"])

            # Calculate stage timing from metadata
            all_validation_times = []
            all_execution_times = []
            all_post_processing_times = []

            for data in metadata_timing_data.values():
                for c in data.get("collectors", {}).values():
                    stages = c.get("stages", {})
                    all_validation_times.append(
                        stages.get("validation", {}).get("total_time", 0)
                    )
                    all_execution_times.append(
                        stages.get("execution", {}).get("total_time", 0)
                    )
                    all_post_processing_times.append(
                        stages.get("post_processing", {}).get("total_time", 0)
                    )

            total_validation_time = (
                max(all_validation_times) if all_validation_times else 0
            )
            total_execution_time = (
                max(all_execution_times) if all_execution_times else 0
            )
            total_post_processing_time = (
                max(all_post_processing_times) if all_post_processing_times else 0
            )

            # Get component timing from orchestrator
            component_timing = {}
            if (
                hasattr(self, "orchestrator")
                and self.orchestrator
                and hasattr(self.orchestrator, "timing_manager")
            ):
                component_timing = (
                    self.orchestrator.timing_manager.get_component_timing()
                )

            tool_init_time = component_timing.get("tool_initialization", {}).get(
                "total_time", 0
            )
            config_loading_time = component_timing.get("configuration_loading", {}).get(
                "total_time", 0
            )
            dut_init_time = component_timing.get("dut_initialization", {}).get(
                "total_time", 0
            )
            preflight_time = component_timing.get("preflight_checks", {}).get(
                "total_time", 0
            )
            html_generation_time = component_timing.get(
                "html_report_generation", {}
            ).get("total_time", 0)
            metadata_time = component_timing.get("metadata_creation", {}).get(
                "total_time", 0
            )
            cleanup_time = component_timing.get("cleanup", {}).get("total_time", 0)

            # Prepare data for JavaScript
            timeline_data_json = self._json_for_script(all_collectors, indent=2)
            dut_summaries_json = self._json_for_script(dut_summaries, indent=2)
            service_stats_json = self._json_for_script(service_stats, indent=2)

            # Add stage and component timing
            stage_timing_json = self._json_for_script(
                {
                    "validation": total_validation_time,
                    "execution": total_execution_time,
                    "post_processing": total_post_processing_time,
                },
                indent=2,
            )

            component_timing_json = self._json_for_script(
                {
                    "tool_initialization": tool_init_time,
                    "configuration_loading": config_loading_time,
                    "dut_initialization": dut_init_time,
                    "preflight_checks": preflight_time,
                    "html_report_generation": html_generation_time,
                    "metadata_creation": metadata_time,
                    "cleanup": cleanup_time,
                },
                indent=2,
            )

            # Calculate summary statistics
            total_duts = len(timing_data_by_dut)
            total_collectors_executed = len(all_collectors)
            total_completed = sum(s["completed"] for s in dut_summaries.values())

            # Aggregate overall collector statuses for cards
            total_collectors_overall = 0
            total_success = 0
            total_degraded = 0
            total_failed = 0
            total_partial = 0
            total_skipped = 0

            for timing_data in timing_data_by_dut.values():
                for c in timing_data.get("collectors", {}).values():
                    total_collectors_overall += 1
                    status = str(c.get("status", "")).lower()
                    if status in ("complete", "success", "completed"):
                        total_success += 1
                    elif status == "degraded":
                        total_degraded += 1
                    elif status in ("error", "failed", "fail"):
                        total_failed += 1
                    elif status == "partial":
                        total_partial += 1
                    elif status in ("skipped", "skip"):
                        total_skipped += 1

            # Calculate actual wall-clock time (parallel execution, not sum)
            all_start_times = [
                s["start_time"] for s in dut_summaries.values() if s["start_time"]
            ]
            all_end_times = [
                s["end_time"] for s in dut_summaries.values() if s["end_time"]
            ]

            if all_start_times and all_end_times:
                from datetime import datetime

                earliest_start = min(datetime.fromisoformat(t) for t in all_start_times)
                latest_end = max(datetime.fromisoformat(t) for t in all_end_times)
                total_wall_clock_time = (latest_end - earliest_start).total_seconds()
            else:
                total_wall_clock_time = 0.0

            # Generate page content with custom styles for timing analysis
            content = f"""
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3.0.0/dist/chartjs-adapter-date-fns.bundle.min.js" integrity="sha384-cVMg8E3QFwTvGCDuK+ET4PD341jF3W8nO1auiXfuZNQkzbUUiBGLsIQUE+b1mxws" crossorigin="anonymous"></script> <!-- pragma: allowlist secret -->
    <style>
        /* Custom styles for timing analysis page */
        body {{
            padding-left: 225px; /* 220px sidebar + 5px page margin */
        }}
        .sidebar-nav {{
            position: fixed;
            top: 80px;
            left: 5px; /* Account for 5px page margin */
            width: 220px;
            height: calc(100vh - 80px);
            background: white;
            border-right: 1px solid #dee2e6;
            padding: 20px 10px;
            overflow-y: auto;
            z-index: 1020;
        }}
        .sidebar-nav h6 {{
            font-size: 0.75rem;
            text-transform: uppercase;
            color: #6c757d;
            font-weight: bold;
            margin-bottom: 10px;
            padding: 0 10px;
        }}
        .sidebar-nav a {{
            display: block;
            padding: 8px 10px;
            color: #495057;
            text-decoration: none;
            font-size: 0.9rem;
            border-radius: 4px;
            transition: all 0.2s;
        }}
        .sidebar-nav a:hover {{
            background-color: #e9ecef;
            color: #0056b3;
        }}
        .sidebar-nav a.active {{
            background-color: #0d6efd;
            color: white;
        }}
        /* .section already defined in base template */
        .chart-container {{
            position: relative;
            height: 400px;
            margin: 20px 0;
        }}
        .timeline-container {{
            position: relative;
            height: 600px;
            margin: 20px 0;
            overflow-y: auto;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
        }}
        .stat-number {{
            font-size: 2.5rem;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 0.9rem;
            opacity: 0.9;
        }}
        .collector-row {{
            padding: 5px 10px;
            margin: 2px 0;
            border-radius: 4px;
            font-size: 0.85rem;
            display: flex;
            align-items: center;
        }}
        .status-success {{ background-color: #d4edda; border-left: 4px solid #28a745; }}
        .status-degraded {{ background-color: #ffe8a1; border-left: 4px solid #f59e0b; }}
        .status-error {{ background-color: #f8d7da; border-left: 4px solid #dc3545; }}
        .status-skipped {{ background-color: #fff3cd; border-left: 4px solid #ffc107; }}
        .status-partial {{ background-color: #cce5ff; border-left: 4px solid #0056b3; }}
        .service-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: bold;
            margin-right: 8px;
        }}
        /* Timing page uses same service colors as base */

        /* Fullscreen modal styles */
        .modal-fullscreen {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: white;
            z-index: 2000;
            display: none;
            padding: 20px;
        }}
        .modal-fullscreen.active {{
            display: flex;
            flex-direction: column;
        }}
        .modal-fullscreen-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #dee2e6;
        }}
        .modal-fullscreen-content {{
            flex: 1;
            position: relative;
            overflow: auto;
        }}
        .zoom-controls {{
            position: absolute;
            top: 10px;
            right: 10px;
            z-index: 10;
        }}
        .zoom-controls button {{
            margin-left: 5px;
        }}
    </style>

    <!-- Sidebar Navigation -->
    <div class="sidebar-nav">
        <h6>Navigation</h6>
        <a href="#summary">Executive Summary</a>
        <a href="#dut-performance">Per-DUT Performance</a>
        <a href="#service-breakdown">Service Breakdown</a>
        <a href="#stage-breakdown">Stage Breakdown</a>
        <a href="#timeline">Execution Timeline</a>
        <a href="#dut-details">DUT Details</a>
        <a href="#collector-timing">Collector Timing</a>
        <a href="#collector-log">Collector Log</a>
    </div>

    <div class="container-fluid">
        <!-- Executive Summary -->
        <div class="section" id="summary">
            <h2>Executive Summary</h2>
            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-number">{total_duts}</div>
                        <div class="stat-label">Total DUTs</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                        <div class="stat-number">{total_collectors_executed}</div>
                        <div class="stat-label">Total Collectors Executed</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
                        <div class="stat-number">{total_completed}</div>
                        <div class="stat-label">Completed Successfully</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
                        <div class="stat-number">{total_wall_clock_time:.1f}s</div>
                        <div class="stat-label">Total Wall-Clock Time</div>
                    </div>
                </div>
            </div>
            <div class="row mb-4">
                <div class="col">
                    <div class="stat-card" style="background: linear-gradient(135deg, #28a745 0%, #43e97b 100%);">
                        <div class="stat-number">{total_success}</div>
                        <div class="stat-label">Passed Collectors</div>
                        <div class="stat-label">of {total_collectors_overall} total</div>
                    </div>
                </div>
                <div class="col">
                    <div class="stat-card" style="background: linear-gradient(135deg, #f59e0b 0%, #fbbf24 100%); color: #ffffff;">
                        <div class="stat-number">{total_degraded}</div>
                        <div class="stat-label">Degraded Collectors</div>
                        <div class="stat-label">of {total_collectors_overall} total</div>
                    </div>
                </div>
                <div class="col">
                    <div class="stat-card" style="background: linear-gradient(135deg, #f5576c 0%, #ff4b2b 100%);">
                        <div class="stat-number">{total_failed}</div>
                        <div class="stat-label">Failed Collectors</div>
                        <div class="stat-label">of {total_collectors_overall} total</div>
                    </div>
                </div>
                <div class="col">
                    <div class="stat-card" style="background: linear-gradient(315deg, #ffd54f 0%, #fff176 100%); color: #ffffff;">
                        <div class="stat-number">{total_partial}</div>
                        <div class="stat-label">Partial Collectors</div>
                        <div class="stat-label">of {total_collectors_overall} total</div>
                    </div>
                </div>
                <div class="col">
                    <div class="stat-card" style="background: linear-gradient(135deg, #ff9800 0%, #ffc107 100%); color: #ffffff;">
                        <div class="stat-number">{total_skipped}</div>
                        <div class="stat-label">Skipped Collectors</div>
                        <div class="stat-label">of {total_collectors_overall} total</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Per-DUT Performance -->
        <div class="section" id="dut-performance">
            <h2>Per-DUT Performance</h2>
            <div class="chart-container">
                <canvas id="dutPerformanceChart"></canvas>
            </div>
        </div>

        <!-- Service Breakdown -->
        <div class="section" id="service-breakdown">
            <h2>Service-Level Breakdown</h2>
            <div class="row">
                <div class="col-md-6">
                    <div class="chart-container">
                        <canvas id="serviceDistributionChart"></canvas>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="chart-container">
                        <canvas id="serviceTimeChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Collector Stage Breakdown -->
        <div class="section" id="stage-breakdown">
            <h2>Collector Stage Breakdown</h2>
            <p class="text-muted">Shows timing breakdown by collector execution stage (validation, execution, post-processing).</p>
            <div class="chart-container">
                <canvas id="stageBreakdownChart"></canvas>
            </div>
        </div>

        <!-- Execution Timeline -->
        <div class="section" id="timeline">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <div>
                    <h2>Execution Timeline</h2>
                    <p class="text-muted mb-0">Shows when each collector executed. Use zoom buttons or scroll wheel to zoom. Hover over bars for details.</p>
                    <div class="mt-2">
                        <span class="badge" style="background-color: rgba(75, 192, 192, 0.7);">SUCCESS</span>
                        <span class="badge" style="background-color: rgba(245, 158, 11, 0.7);">DEGRADED</span>
                        <span class="badge" style="background-color: rgba(255, 99, 132, 0.7);">ERROR</span>
                        <span class="badge" style="background-color: rgba(255, 206, 86, 0.7);">SKIPPED</span>
                        <span class="badge" style="background-color: rgba(54, 162, 235, 0.7);">PARTIAL</span>
                    </div>
                </div>
                <div class="d-flex gap-2 align-items-center">
                    <div class="btn-group" role="group" aria-label="Zoom controls">
                        <button class="btn btn-sm btn-outline-secondary" onclick="zoomTimelineOut()" title="Zoom Out">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                                <path d="M4 8a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 0 1h-7A.5.5 0 0 1 4 8z"/>
                                <path d="M11.5 1a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zM7 5.5a4.5 4.5 0 1 1 7.95 2.85l3.35 3.35a.5.5 0 0 1-.708.708l-3.35-3.35A4.5 4.5 0 0 1 7 5.5z"/>
                            </svg>
                        </button>
                        <button class="btn btn-sm btn-outline-secondary" onclick="resetTimelineZoom()" title="Fit to Width">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                                <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/>
                                <path d="M8 4a.5.5 0 0 1 .5.5v3h3a.5.5 0 0 1 0 1h-3v3a.5.5 0 0 1-1 0v-3h-3a.5.5 0 0 1 0-1h3v-3A.5.5 0 0 1 8 4z"/>
                            </svg>
                        </button>
                        <button class="btn btn-sm btn-outline-secondary" onclick="zoomTimelineIn()" title="Zoom In">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                                <path d="M4 8a.5.5 0 0 1 .5-.5h3v-3a.5.5 0 0 1 1 0v3h3a.5.5 0 0 1 0 1h-3v3a.5.5 0 0 1-1 0v-3h-3A.5.5 0 0 1 4 8z"/>
                                <path d="M11.5 1a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zM7 5.5a4.5 4.5 0 1 1 7.95 2.85l3.35 3.35a.5.5 0 0 1-.708.708l-3.35-3.35A4.5 4.5 0 0 1 7 5.5z"/>
                            </svg>
                        </button>
                    </div>
                    <span id="zoomLevel" class="text-muted small" style="min-width: 100px;">Fit to Width</span>
                    <button class="btn btn-sm btn-primary" onclick="openFullscreenTimeline()">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-arrows-fullscreen" viewBox="0 0 16 16">
                            <path fill-rule="evenodd" d="M5.828 10.172a.5.5 0 0 0-.707 0l-4.096 4.096V11.5a.5.5 0 0 0-1 0v3.975a.5.5 0 0 0 .5.5H4.5a.5.5 0 0 0 0-1H1.732l4.096-4.096a.5.5 0 0 0 0-.707zm4.344 0a.5.5 0 0 1 .707 0l4.096 4.096V11.5a.5.5 0 1 1 1 0v3.975a.5.5 0 0 1-.5.5H11.5a.5.5 0 0 1 0-1h2.768l-4.096-4.096a.5.5 0 0 1 0-.707zm0-4.344a.5.5 0 0 0 .707 0l4.096-4.096V4.5a.5.5 0 1 0 1 0V.525a.5.5 0 0 0-.5-.5H11.5a.5.5 0 0 0 0 1h2.768l-4.096 4.096a.5.5 0 0 0 0 .707zm-4.344 0a.5.5 0 0 1-.707 0L1.025 1.732V4.5a.5.5 0 0 1-1 0V.525a.5.5 0 0 1 .5-.5H4.5a.5.5 0 0 1 0 1H1.732l4.096 4.096a.5.5 0 0 1 0 .707z"/>
                        </svg>
                        Fullscreen
                    </button>
                </div>
            </div>
            <div class="timeline-container" style="position: relative; overflow-x: auto; overflow-y: visible;">
                <div id="timelineChart"></div>
            </div>
        </div>

        <!-- Collector Summary by DUT -->
        <div class="section" id="dut-details">
            <h2>Collector Summary by DUT</h2>
            <p class="text-muted">Detailed breakdown of collector execution for each DUT.</p>
            <div id="dutDetailsContent"></div>
        </div>

        <!-- Detailed Collector Timing -->
        <div class="section" id="collector-timing">
            <h2>Detailed Collector Timing</h2>
            <p class="text-muted">Sortable table with granular timing for each collector execution.</p>
            <div class="table-responsive">
                <table class="table table-striped table-bordered table-sm" id="collectorTimingTable">
                    <thead class="table-dark">
                        <tr>
                            <th onclick="sortTable(0)" style="cursor: pointer;">DUT ▼</th>
                            <th onclick="sortTable(1)" style="cursor: pointer;">Collector ▼</th>
                            <th onclick="sortTable(2)" style="cursor: pointer;">Service ▼</th>
                            <th onclick="sortTable(3)" style="cursor: pointer;">Status ▼</th>
                            <th onclick="sortTable(4)" style="cursor: pointer;">Duration (s) ▼</th>
                            <th onclick="sortTable(5)" style="cursor: pointer;">Start Time ▼</th>
                            <th onclick="sortTable(6)" style="cursor: pointer;">End Time ▼</th>
                        </tr>
                    </thead>
                    <tbody id="collectorTimingBody"></tbody>
                </table>
            </div>
        </div>

        <!-- Detailed Collector Execution Log -->
        <div class="section" id="collector-log">
            <h2>Detailed Collector Execution Log</h2>
            <div class="mb-3">
                <input type="text" id="collectorSearch" class="form-control" placeholder="Search collectors by name, DUT, or service...">
            </div>
            <div id="collectorList"></div>
        </div>
    </div>

    <!-- Fullscreen Timeline Modal -->
    <div id="fullscreenModal" class="modal-fullscreen">
        <div class="modal-fullscreen-header">
            <h3>Execution Timeline</h3>
            <button class="btn btn-danger" onclick="closeFullscreenTimeline()">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-x-lg" viewBox="0 0 16 16">
                    <path d="M2.146 2.854a.5.5 0 1 1 .708-.708L8 7.293l5.146-5.147a.5.5 0 0 1 .708.708L8.707 8l5.147 5.146a.5.5 0 0 1-.708.708L8 8.707l-5.146 5.147a.5.5 0 0 1-.708-.708L7.293 8 2.146 2.854Z"/>
                </svg>
                Close
            </button>
        </div>
        <div class="modal-fullscreen-content">
            <div class="zoom-controls">
                <button class="btn btn-sm btn-secondary" onclick="zoomTimeline(0.8)">−</button>
                <button class="btn btn-sm btn-secondary" onclick="zoomTimeline(1.2)">+</button>
                <button class="btn btn-sm btn-secondary" onclick="resetZoom()">Reset</button>
            </div>
            <div style="height: 100%; min-height: 600px; overflow: auto;">
                <div id="timelineChartFullscreen"></div>
            </div>
        </div>
    </div>

    <script>
        // Navbar search stub functions (not used on this page but required by navbar)
        function globalSearchHandler(value) {{
            // Not applicable for timing analysis page
        }}
        function clearSearch() {{
            // Not applicable for timing analysis page
        }}

        // Data from Python
        const timelineData = {timeline_data_json};
        const dutSummaries = {dut_summaries_json};
        const serviceStats = {service_stats_json};
        const stageTiming = {stage_timing_json};
        const componentTiming = {component_timing_json};

        // Timing documents are untrusted JSON. Escape values before placing them
        // into HTML templates, and use text nodes for tooltip content.
        function escapeHTML(value) {{
            return String(value === null || value === undefined ? '' : value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#x27;');
        }}

        function appendTimingTooltipRow(container, label, value, color = null) {{
            const row = document.createElement('div');
            const heading = document.createElement('strong');
            heading.textContent = `${{label}}:`;
            row.appendChild(heading);
            row.appendChild(document.createTextNode(' '));
            if (color) {{
                const coloredValue = document.createElement('span');
                coloredValue.style.color = color;
                coloredValue.textContent = String(value ?? '');
                row.appendChild(coloredValue);
            }} else {{
                row.appendChild(document.createTextNode(String(value ?? '')));
            }}
            container.appendChild(row);
        }}

        function renderTimingTooltip(
            tooltip,
            info,
            statusColor,
            startTime,
            endTime
        ) {{
            tooltip.replaceChildren();
            const title = document.createElement('div');
            title.style.cssText = 'font-weight: bold; margin-bottom: 6px; color: #4fc3f7; font-size: 13px;';
            title.textContent = `DUT: ${{String(info.dut_id ?? '')}}`;
            tooltip.appendChild(title);
            appendTimingTooltipRow(tooltip, 'Collector', info.collector_name);
            appendTimingTooltipRow(tooltip, 'Service', info.group);
            appendTimingTooltipRow(tooltip, 'Status', info.status, statusColor);
            appendTimingTooltipRow(tooltip, 'Duration', `${{Number(info.duration).toFixed(2)}}s`);
            appendTimingTooltipRow(tooltip, 'Start', startTime);
            appendTimingTooltipRow(tooltip, 'End', endTime);
        }}

        // Consistent service color mapping
        function getServiceColor(serviceName) {{
            const colors = {{
                'redfish': 'rgba(220, 105, 118, 0.8)',      // #dc6976 - Pink/Red
                'ssh': 'rgba(255, 193, 7, 0.8)',             // #ffc107 - Yellow/Gold
                'ipmi': 'rgba(13, 202, 240, 0.8)',          // #0dcaf0 - Cyan
                'health_check': 'rgba(111, 66, 193, 0.8)',  // #6f42c1 - Purple
                'healthcheck': 'rgba(111, 66, 193, 0.8)',   // #6f42c1 - Purple
                'host': 'rgba(40, 167, 69, 0.8)',           // #28a745 - Green
                'bmc': 'rgba(253, 126, 20, 0.8)',           // #fd7e14 - Orange
                'preflight': 'rgba(32, 201, 151, 0.8)'      // #20c997 - Teal
            }};
            const key = serviceName.toLowerCase().replace(/[^a-z_]/g, '_');
            return colors[key] || 'rgba(108, 117, 125, 0.8)'; // Default gray
        }}

        function getServiceBorderColor(serviceName) {{
            const colors = {{
                'redfish': 'rgba(220, 105, 118, 1)',
                'ssh': 'rgba(255, 193, 7, 1)',
                'ipmi': 'rgba(13, 202, 240, 1)',
                'health_check': 'rgba(111, 66, 193, 1)',
                'healthcheck': 'rgba(111, 66, 193, 1)',
                'host': 'rgba(40, 167, 69, 1)',
                'bmc': 'rgba(253, 126, 20, 1)',
                'preflight': 'rgba(32, 201, 151, 1)'
            }};
            const key = serviceName.toLowerCase().replace(/[^a-z_]/g, '_');
            return colors[key] || 'rgba(108, 117, 125, 1)';
        }}

        // Per-DUT Performance Chart
        const dutLabels = Object.keys(dutSummaries);
        const dutDurations = dutLabels.map(dut => dutSummaries[dut].duration);
        const dutCompleted = dutLabels.map(dut => dutSummaries[dut].completed);

        new Chart(document.getElementById('dutPerformanceChart'), {{
            type: 'bar',
            data: {{
                labels: dutLabels,
                datasets: [{{
                    label: 'Execution Time (seconds)',
                    data: dutDurations,
                    backgroundColor: 'rgba(75, 192, 192, 0.6)',
                    borderColor: 'rgba(75, 192, 192, 1)',
                    borderWidth: 1,
                    yAxisID: 'y'
                }}, {{
                    label: 'Completed Collectors',
                    data: dutCompleted,
                    backgroundColor: 'rgba(54, 162, 235, 0.6)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1,
                    yAxisID: 'y1'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        type: 'linear',
                        display: true,
                        position: 'left',
                        title: {{
                            display: true,
                            text: 'Time (seconds)'
                        }}
                    }},
                    y1: {{
                        type: 'linear',
                        display: true,
                        position: 'right',
                        title: {{
                            display: true,
                            text: 'Collector Count'
                        }},
                        grid: {{
                            drawOnChartArea: false
                        }}
                    }}
                }}
            }}
        }});

        // Service Distribution Chart
        const serviceLabels = Object.keys(serviceStats);
        const serviceCollectorCounts = serviceLabels.map(s => serviceStats[s].total_collectors);

        // Generate colors for each service
        const serviceColors = serviceLabels.map(service => getServiceColor(service));
        const serviceBorderColors = serviceLabels.map(service => getServiceBorderColor(service));

        new Chart(document.getElementById('serviceDistributionChart'), {{
            type: 'doughnut',
            data: {{
                labels: serviceLabels,
                datasets: [{{
                    label: 'Collectors per Service',
                    data: serviceCollectorCounts,
                    backgroundColor: serviceColors,
                    borderColor: serviceBorderColors,
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'right'
                    }},
                    title: {{
                        display: true,
                        text: 'Collector Distribution by Service'
                    }}
                }}
            }}
        }});

        // Service Time Chart
        const serviceTimes = serviceLabels.map(s => serviceStats[s].total_duration);

        new Chart(document.getElementById('serviceTimeChart'), {{
            type: 'bar',
            data: {{
                labels: serviceLabels,
                datasets: [{{
                    label: 'Total Execution Time (seconds)',
                    data: serviceTimes,
                    backgroundColor: serviceColors,
                    borderColor: serviceBorderColors,
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    title: {{
                        display: true,
                        text: 'Total Execution Time by Service'
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        title: {{
                            display: true,
                            text: 'Time (seconds)'
                        }}
                    }}
                }}
            }}
        }});

        // Collector Stage Breakdown Chart (using real data from metadata.json)
        const stageCtx = document.getElementById('stageBreakdownChart');
        if (stageCtx) {{
            const stageDataAvailable = stageTiming.validation > 0 || stageTiming.execution > 0 || stageTiming.post_processing > 0;

            new Chart(stageCtx, {{
                type: 'bar',
                data: {{
                    labels: ['Validation', 'Execution', 'Post-Processing'],
                    datasets: [{{
                        label: 'Maximum Stage Duration (seconds)',
                        data: [
                            stageTiming.validation,
                            stageTiming.execution,
                            stageTiming.post_processing
                        ],
                        backgroundColor: [
                            'rgba(54, 162, 235, 0.6)',
                            'rgba(255, 99, 132, 0.6)',
                            'rgba(255, 206, 86, 0.6)'
                        ],
                        borderColor: [
                            'rgba(54, 162, 235, 1)',
                            'rgba(255, 99, 132, 1)',
                            'rgba(255, 206, 86, 1)'
                        ],
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        title: {{
                            display: !stageDataAvailable,
                            text: stageDataAvailable ? '' : 'No stage-level timing data available'
                        }},
                        legend: {{
                            display: true
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            title: {{
                                display: true,
                                text: 'Time (seconds)'
                            }}
                        }}
                    }}
                }}
            }});
        }}

        // Timeline Chart (HTML/CSS Gantt Chart - Simple and Reliable)
        let dutList = [];
        let earliestStart = 0;
        let latestEnd = 0;
        let chartData = []; // Make chartData accessible to fullscreen function

        // Color map for statuses (handle both cases)
        function getStatusColor(status) {{
            const statusUpper = status.toUpperCase();
            switch(statusUpper) {{
                case 'SUCCESS': return '#4db8a8';
                case 'DEGRADED': return '#f59e0b';
                case 'ERROR': return '#ff6384';
                case 'SKIPPED': return '#ffce56';
                case 'PARTIAL': return '#36a2eb';
                default: return '#808080';
            }}
        }}

        if (timelineData && timelineData.length > 0) {{
            earliestStart = Math.min(...timelineData.map(d => new Date(d.start_time).getTime()));
            latestEnd = Math.max(...timelineData.map(d => new Date(d.end_time).getTime()));

            // Group by DUT
            const dutGroups = {{}};
            timelineData.forEach(item => {{
                if (!dutGroups[item.dut_id]) {{
                    dutGroups[item.dut_id] = [];
                }}
                dutGroups[item.dut_id].push(item);
            }});

            // Create datasets - one per collector, positioned by DUT row and time
            dutList = Object.keys(dutGroups).sort();

            // Build chart data structure
            chartData = [];

            dutList.forEach((dutId, dutIndex) => {{
                const collectors = dutGroups[dutId];

                // Sort collectors by start time
                collectors.sort((a, b) => new Date(a.start_time) - new Date(b.start_time));

                collectors.forEach(collector => {{
                    const startOffset = (new Date(collector.start_time).getTime() - earliestStart) / 1000;
                    const duration = collector.duration;

                    chartData.push({{
                        x: startOffset,
                        y: dutIndex,
                        duration: duration,
                        label: collector.collector_name,
                        color: getStatusColor(collector.status),
                        info: collector
                    }});
                }});
            }});

            // Create HTML/CSS Gantt Chart with lane assignment for overlapping collectors
            const container = document.getElementById('timelineChart');
            if (container) {{
                // Calculate dimensions
                const totalDuration = (latestEnd - earliestStart) / 1000;

                // NEW APPROACH: Start with fit-to-width, allow zoom to expand
                const leftLabelWidth = 200;
                const containerWidth = container.parentElement.clientWidth - leftLabelWidth - 40; // Account for padding and labels
                const minChartWidth = Math.max(800, containerWidth); // Minimum width for fit-to-width view

                // Calculate "detailed" scale for zoom (when user wants to see more detail)
                let detailedPixelsPerSecond;
                if (totalDuration <= 120) detailedPixelsPerSecond = 15;      // < 2 min: 15px/s (very detailed)
                else if (totalDuration <= 600) detailedPixelsPerSecond = 10; // < 10 min: 10px/s (detailed)
                else if (totalDuration <= 1800) detailedPixelsPerSecond = 5; // < 30 min: 5px/s (moderate)
                else detailedPixelsPerSecond = 2;                             // > 30 min: 2px/s (compact, relies on zoom)
                const detailedChartWidth = Math.max(1200, totalDuration * detailedPixelsPerSecond);

                // Start with fit-to-width (compressed view showing entire timeline)
                let chartWidth = minChartWidth;

                // Store both widths for zoom functionality
                window.timelineWidths = {{
                    fit: minChartWidth,
                    detailed: detailedChartWidth,
                    current: minChartWidth
                }};

                const baseLaneHeight = 22; // Height per lane/track
                const laneGap = 4; // Gap between lanes
                const dutPadding = 15; // Padding top/bottom for each DUT row

                // Assign lanes to collectors to avoid overlap
                function assignLanes(collectors) {{
                    // Sort by start time
                    const sorted = collectors.sort((a, b) => a.x - b.x);
                    const lanes = [];

                    sorted.forEach(collector => {{
                        const collectorEnd = collector.x + collector.duration;

                        // Find first available lane
                        let assignedLane = -1;
                        for (let i = 0; i < lanes.length; i++) {{
                            const lane = lanes[i];
                            // Check if this lane is free (last item ends before this one starts)
                            if (lane.length === 0 || lane[lane.length - 1].x + lane[lane.length - 1].duration <= collector.x) {{
                                assignedLane = i;
                                break;
                            }}
                        }}

                        // If no lane found, create new one
                        if (assignedLane === -1) {{
                            assignedLane = lanes.length;
                            lanes.push([]);
                        }}

                        collector.lane = assignedLane;
                        lanes[assignedLane].push(collector);
                    }});

                    return Math.max(1, lanes.length);
                }}

                // Group collectors by DUT and assign lanes
                const dutLanes = {{}};
                dutList.forEach((dutId, dutIndex) => {{
                    const dutCollectors = chartData.filter(d => d.y === dutIndex);
                    dutLanes[dutId] = assignLanes(dutCollectors);
                }});

                // Calculate row heights based on lane count
                const dutRowHeights = {{}};
                let chartHeight = 0;
                dutList.forEach(dutId => {{
                    const laneCount = dutLanes[dutId];
                    const rowHeight = (laneCount * baseLaneHeight) + ((laneCount - 1) * laneGap) + (2 * dutPadding);
                    dutRowHeights[dutId] = rowHeight;
                    chartHeight += rowHeight;
                }});

                // Create chart HTML
                let chartHTML = `
                    <div style="display: flex; background: white; border: 1px solid #dee2e6; border-radius: 8px; overflow: hidden;">
                        <!-- Left: DUT Labels -->
                        <div style="width: ${{leftLabelWidth}}px; background: #f8f9fa; border-right: 2px solid #dee2e6; flex-shrink: 0;">
                            <div style="height: 40px; padding: 10px; font-weight: bold; border-bottom: 2px solid #dee2e6; background: #e9ecef;">
                                DUT
                            </div>
                `;

                dutList.forEach(dutId => {{
                    chartHTML += `
                        <div style="height: ${{dutRowHeights[dutId]}}px; padding: 15px 10px; border-bottom: 1px solid #dee2e6; font-weight: 600; color: #2c3e50; display: flex; align-items: center; font-size: 13px;">
                            ${{escapeHTML(dutId)}}
                        </div>
                    `;
                }});

                chartHTML += `
                        </div>
                        <!-- Right: Timeline -->
                        <div style="flex: 1; overflow-x: auto;">
                            <div style="width: ${{chartWidth}}px;">
                                <!-- Timeline Header -->
                                <div style="height: 40px; background: #e9ecef; border-bottom: 2px solid #dee2e6; position: relative;">
                `;

                // Add time markers with adaptive granularity based on total duration
                // Aim for 10-20 markers total for good visibility, prefer round numbers
                let markerInterval;
                if (totalDuration <= 30) markerInterval = 5;           // 30s: every 5s
                else if (totalDuration <= 60) markerInterval = 10;      // 1m: every 10s
                else if (totalDuration <= 120) markerInterval = 15;     // 2m: every 15s
                else if (totalDuration <= 300) markerInterval = 30;     // 5m: every 30s
                else if (totalDuration <= 600) markerInterval = 60;     // 10m: every 1m
                else if (totalDuration <= 1200) markerInterval = 120;   // 20m: every 2m
                else if (totalDuration <= 1800) markerInterval = 180;   // 30m: every 3m
                else if (totalDuration <= 3600) markerInterval = 300;   // 1h: every 5m
                else if (totalDuration <= 7200) markerInterval = 600;   // 2h: every 10m
                else if (totalDuration <= 14400) markerInterval = 900;  // 4h: every 15m
                else if (totalDuration <= 28800) markerInterval = 1800; // 8h: every 30m
                else markerInterval = 3600;                              // >8h: every 1h

                for (let t = 0; t <= totalDuration; t += markerInterval) {{
                    const xPos = (t / totalDuration) * chartWidth;
                    // Format time display based on duration (hours, minutes, seconds)
                    let timeDisplay;
                    if (t >= 3600) {{
                        const hours = Math.floor(t / 3600);
                        const mins = Math.floor((t % 3600) / 60);
                        const secs = t % 60;
                        if (mins === 0 && secs === 0) {{
                            timeDisplay = `${{hours}}h`;
                        }} else if (secs === 0) {{
                            timeDisplay = `${{hours}}h ${{mins}}m`;
                        }} else {{
                            timeDisplay = `${{hours}}h ${{mins}}m ${{secs}}s`;
                        }}
                    }} else if (t >= 60) {{
                        const mins = Math.floor(t / 60);
                        const secs = t % 60;
                        timeDisplay = secs === 0 ? `${{mins}}m` : `${{mins}}m ${{secs}}s`;
                    }} else {{
                        timeDisplay = `${{t}}s`;
                    }}
                    chartHTML += `
                        <div style="position: absolute; left: ${{xPos}}px; top: 0; height: 100%; border-left: 1px solid #adb5bd; padding: 8px 4px; font-size: 11px; color: #6c757d; font-weight: 500; white-space: nowrap;">
                            ${{timeDisplay}}
                        </div>
                    `;
                }}

                chartHTML += `
                                </div>

                                <!-- Timeline Overview Bar -->
                                <div style="height: 30px; background: #f8f9fa; border-bottom: 1px solid #dee2e6; position: relative; display: flex; align-items: center; padding: 0 10px;">
                                    <div style="flex: 1; position: relative; height: 12px; background: #e9ecef; border-radius: 6px; overflow: hidden; box-shadow: inset 0 1px 3px rgba(0,0,0,0.1);">
                                        <div style="position: absolute; left: 0; top: 0; width: 100%; height: 100%; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); opacity: 0.6;"></div>
                                        <div style="position: absolute; left: 0; top: -3px; font-size: 10px; color: #495057; font-weight: 600;">
                                            ${{new Date(earliestStart).toLocaleTimeString()}}
                                        </div>
                                        <div style="position: absolute; right: 0; top: -3px; font-size: 10px; color: #495057; font-weight: 600;">
                                            ${{new Date(latestEnd).toLocaleTimeString()}}
                                        </div>
                                    </div>
                                    <div style="margin-left: 15px; font-size: 11px; color: #6c757d; font-weight: 600; white-space: nowrap;">
                                        Total: ${{totalDuration.toFixed(1)}}s
                                    </div>
                                </div>

                                <!-- Timeline Rows -->
                                <div style="position: relative; height: ${{chartHeight}}px;">
                `;

                // Draw grid lines for each DUT row
                let cumulativeHeight = 0;
                dutList.forEach(dutId => {{
                    const rowHeight = dutRowHeights[dutId];
                    chartHTML += `
                        <div style="position: absolute; left: 0; top: ${{cumulativeHeight}}px; width: 100%; height: ${{rowHeight}}px; border-bottom: 1px solid #e9ecef;"></div>
                    `;
                    cumulativeHeight += rowHeight;
                }});

                // Draw vertical grid lines matching the time markers
                for (let t = 0; t <= totalDuration; t += markerInterval) {{
                    const xPos = (t / totalDuration) * chartWidth;
                    chartHTML += `
                        <div style="position: absolute; left: ${{xPos}}px; top: 0; width: 1px; height: 100%; background: #e3e6ea; opacity: 0.5;"></div>
                    `;
                }}

                // Draw collector bars with lane positioning
                cumulativeHeight = 0;
                dutList.forEach((dutId, dutIndex) => {{
                    const dutCollectors = chartData.filter(d => d.y === dutIndex);
                    const rowHeight = dutRowHeights[dutId];

                    dutCollectors.forEach(dataPoint => {{
                        const lane = dataPoint.lane;
                        const yPos = cumulativeHeight + dutPadding + (lane * (baseLaneHeight + laneGap));
                        const xStart = (dataPoint.x / totalDuration) * chartWidth;
                        const width = Math.max(2, (dataPoint.duration / totalDuration) * chartWidth); // Minimum 2px width for visibility
                        const color = getStatusColor(dataPoint.info.status);

                        const info = dataPoint.info;
                        const startTime = new Date(info.start_time).toLocaleTimeString();
                        const endTime = new Date(info.end_time).toLocaleTimeString();

                        // Format duration like Chrome DevTools (e.g., "2.5s", "123ms")
                        const duration = info.duration;
                        const durationText = duration >= 1
                            ? `${{duration.toFixed(duration >= 10 ? 1 : 2)}}s`
                            : `${{Math.round(duration * 1000)}}ms`;

                        // Determine if we can fit text inside the bar
                        const canFitName = width > 80;
                        const canFitDuration = width > 40;

                        // Build bar content
                        let barContent = '';
                        if (canFitName) {{
                            barContent = `${{escapeHTML(info.collector_name)}} <span style="opacity: 0.7; margin-left: 6px;">(${{durationText}})</span>`;
                        }} else if (canFitDuration) {{
                            barContent = durationText;
                        }}

                        chartHTML += `
                            <div class="gantt-bar"
                                 data-dut="${{escapeHTML(info.dut_id)}}"
                                 data-collector="${{escapeHTML(info.collector_name)}}"
                                 data-service="${{escapeHTML(info.group)}}"
                                 data-status="${{escapeHTML(info.status)}}"
                                 data-duration="${{info.duration.toFixed(2)}}"
                                 data-start="${{escapeHTML(startTime)}}"
                                 data-end="${{escapeHTML(endTime)}}"
                                 style="position: absolute;
                                        left: ${{xStart}}px;
                                        top: ${{yPos}}px;
                                        width: ${{width}}px;
                                        height: ${{baseLaneHeight}}px;
                                        background: ${{color}};
                                        border: 1px solid ${{color}}dd;
                                        border-radius: 4px;
                                        cursor: pointer;
                                        transition: all 0.2s;
                                        overflow: visible;
                                        display: flex;
                                        align-items: center;
                                        padding: 0 6px;
                                        font-size: 10px;
                                        font-weight: 500;
                                        color: #000;">
                                <span style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                                    ${{barContent}}
                                </span>
                            </div>
                            ${{!canFitDuration ? `
                                <div style="position: absolute;
                                           left: ${{xStart + width + 4}}px;
                                           top: ${{yPos}}px;
                                           height: ${{baseLaneHeight}}px;
                                           display: flex;
                                           align-items: center;
                                           font-size: 10px;
                                           color: #6c757d;
                                           font-weight: 600;
                                           background: rgba(255,255,255,0.9);
                                           padding: 0 4px;
                                           border-radius: 2px;
                                           white-space: nowrap;">
                                    ${{durationText}}
                                </div>
                            ` : ''}}
                        `;
                    }});

                    cumulativeHeight += rowHeight;
                }});

                chartHTML += `
                                </div>
                            </div>
                        </div>
                    </div>
                `;

                // Wrap in a transformable container for pan/zoom
                container.innerHTML = '<div id="mainTimelineZoomable" style="transform-origin: top left; transition: transform 0.1s ease-out;">' +
                                     chartHTML +
                                     '</div>';

                // Add hover effects and tooltips
                const bars = container.querySelectorAll('.gantt-bar');
                bars.forEach(bar => {{
                    bar.addEventListener('mouseenter', function() {{
                        this.style.filter = 'brightness(1.1)';
                        this.style.transform = 'scaleY(1.1)';
                        this.style.zIndex = '10';
                        this.style.boxShadow = '0 4px 8px rgba(0,0,0,0.2)';

                        // Show tooltip
                        const tooltip = document.createElement('div');
                        tooltip.className = 'gantt-tooltip';
                        tooltip.style.cssText = `
                            position: fixed;
                            background: rgba(0, 0, 0, 0.9);
                            color: white;
                            padding: 12px;
                            border-radius: 6px;
                            font-size: 12px;
                            z-index: 10000;
                            pointer-events: none;
                            max-width: 300px;
                            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                            line-height: 1.6;
                        `;

                        renderTimingTooltip(
                            tooltip,
                            {{
                                dut_id: this.dataset.dut,
                                collector_name: this.dataset.collector,
                                group: this.dataset.service,
                                status: this.dataset.status,
                                duration: Number(this.dataset.duration)
                            }},
                            getStatusColor(this.dataset.status),
                            this.dataset.start,
                            this.dataset.end
                        );

                        document.body.appendChild(tooltip);
                        this._tooltip = tooltip;
                    }});

                    bar.addEventListener('mousemove', function(e) {{
                        if (this._tooltip) {{
                            this._tooltip.style.left = (e.clientX + 15) + 'px';
                            this._tooltip.style.top = (e.clientY + 15) + 'px';
                        }}
                    }});

                    bar.addEventListener('mouseleave', function() {{
                        this.style.filter = '';
                        this.style.transform = '';
                        this.style.zIndex = '';
                        this.style.boxShadow = '';

                        if (this._tooltip) {{
                            this._tooltip.remove();
                            this._tooltip = null;
                        }}
                    }});
                }});

                // Store for fullscreen and zoom
                window.timelineChartData = {{
                    dutList: dutList,
                    chartData: chartData,
                    earliestStart: earliestStart,
                    latestEnd: latestEnd,
                    totalDuration: totalDuration
                }};

                // Setup pan/zoom for main timeline
                setupMainTimelinePanZoom(container);
            }}
        }} else {{
            const container = document.getElementById('timelineChart');
            if (container) {{
                container.innerHTML = '<p class="text-muted text-center p-4">No timeline data available</p>';
            }}
        }}

        // Zoom control functions - actually resize the chart (like Google Maps)
        window.currentTimelineZoomLevel = 0; // 0 = fit-to-width, positive = zoomed in
        const minZoomLevel = -5; // Can zoom out from fit-to-width
        const maxZoomLevel = 25; // Maximum zoom in (30 total levels for smooth zooming)

        window.zoomTimelineIn = function() {{
            if (!window.timelineWidths || !timelineData || timelineData.length === 0) return;
            if (window.currentTimelineZoomLevel < maxZoomLevel) {{
                window.currentTimelineZoomLevel++;
                rerenderTimeline();
            }}
        }};

        window.zoomTimelineOut = function() {{
            if (!window.timelineWidths || !timelineData || timelineData.length === 0) return;
            if (window.currentTimelineZoomLevel > minZoomLevel) {{
                window.currentTimelineZoomLevel--;
                rerenderTimeline();
            }}
        }};

        window.resetTimelineZoom = function() {{
            if (!window.timelineWidths || !timelineData || timelineData.length === 0) return;
            window.currentTimelineZoomLevel = 0;
            rerenderTimeline();
        }};

        // Re-render timeline with new zoom level
        function rerenderTimeline() {{
            if (!window.timelineWidths || !timelineData || timelineData.length === 0) return;

            // Calculate new chart width based on zoom level - GOOGLE MAPS style
            const zoomLevel = window.currentTimelineZoomLevel;
            const fitWidth = window.timelineWidths.fit;

            // Smooth exponential zoom like Google Maps: each level multiplies by 1.15 (15% change)
            // With 30 levels (-5 to 25), this gives a ~55x total zoom range
            const zoomMultiplier = Math.pow(1.15, zoomLevel);
            const newChartWidth = fitWidth * zoomMultiplier;

            console.log('Zoom Debug - Level:', zoomLevel, 'Multiplier:', zoomMultiplier.toFixed(2), 'Width:', Math.round(newChartWidth), 'px');

            // Update zoom label
            let zoomLabel;
            if (zoomLevel === 0) {{
                zoomLabel = 'Fit to Width';
            }} else {{
                const percentage = Math.round(zoomMultiplier * 100);
                zoomLabel = `${{percentage}}%`;
            }}

            // Update zoom level display
            const zoomLevelElement = document.getElementById('zoomLevel');
            if (zoomLevelElement) {{
                zoomLevelElement.textContent = zoomLabel;
            }}

            // Re-render the timeline with new width
            const container = document.getElementById('timelineChart');
            if (!container) return;

            const totalDuration = window.timelineChartData.totalDuration;
            const earliestStart = window.timelineChartData.earliestStart;
            const latestEnd = window.timelineChartData.latestEnd;
            const dutList = window.timelineChartData.dutList;
            const chartData = window.timelineChartData.chartData;

            const chartWidth = newChartWidth;
            window.timelineWidths.current = chartWidth;

            const baseLaneHeight = 22;
            const laneGap = 4;
            const dutPadding = 15;
            const leftLabelWidth = 200;

            // Re-assign lanes (same logic as before)
            function assignLanes(collectors) {{
                const sorted = collectors.sort((a, b) => a.x - b.x);
                const lanes = [];
                sorted.forEach(collector => {{
                    const collectorEnd = collector.x + collector.duration;
                    let assignedLane = -1;
                    for (let i = 0; i < lanes.length; i++) {{
                        const lane = lanes[i];
                        const canFit = lane.every(c => {{
                            const cEnd = c.x + c.duration;
                            return collectorEnd <= c.x || collector.x >= cEnd;
                        }});
                        if (canFit) {{
                            assignedLane = i;
                            break;
                        }}
                    }}
                    if (assignedLane === -1) {{
                        assignedLane = lanes.length;
                        lanes.push([]);
                    }}
                    collector.lane = assignedLane;
                    lanes[assignedLane].push(collector);
                }});
                return Math.max(1, lanes.length);
            }}

            const dutLanes = {{}};
            dutList.forEach((dutId, dutIndex) => {{
                const dutCollectors = chartData.filter(d => d.y === dutIndex);
                dutLanes[dutId] = assignLanes(dutCollectors);
            }});

            const dutRowHeights = {{}};
            let chartHeight = 0;
            dutList.forEach(dutId => {{
                const laneCount = dutLanes[dutId];
                const rowHeight = (laneCount * baseLaneHeight) + ((laneCount - 1) * laneGap) + (2 * dutPadding);
                dutRowHeights[dutId] = rowHeight;
                chartHeight += rowHeight;
            }});

            // Regenerate chart HTML (abbreviated version of original code)
            let chartHTML = `
                <div style="display: flex; background: white; border: 1px solid #dee2e6; border-radius: 8px; overflow: hidden;">
                    <div style="width: ${{leftLabelWidth}}px; background: #f8f9fa; border-right: 2px solid #dee2e6; flex-shrink: 0;">
                        <div style="height: 40px; padding: 10px; font-weight: bold; border-bottom: 2px solid #dee2e6; background: #e9ecef;">DUT</div>
            `;

            dutList.forEach(dutId => {{
                chartHTML += `<div style="height: ${{dutRowHeights[dutId]}}px; padding: 15px 10px; border-bottom: 1px solid #dee2e6; font-weight: 600; color: #2c3e50; display: flex; align-items: center; font-size: 13px;">${{escapeHTML(dutId)}}</div>`;
            }});

            chartHTML += `
                    </div>
                    <div style="flex: 1; overflow-x: auto;">
                        <div style="width: ${{chartWidth}}px;">
                            <div style="height: 40px; background: #e9ecef; border-bottom: 2px solid #dee2e6; position: relative;">
            `;

            // Time markers (same logic as before)
            let markerInterval;
            if (totalDuration <= 30) markerInterval = 5;
            else if (totalDuration <= 60) markerInterval = 10;
            else if (totalDuration <= 120) markerInterval = 15;
            else if (totalDuration <= 300) markerInterval = 30;
            else if (totalDuration <= 600) markerInterval = 60;
            else if (totalDuration <= 1200) markerInterval = 120;
            else if (totalDuration <= 1800) markerInterval = 180;
            else if (totalDuration <= 3600) markerInterval = 300;
            else if (totalDuration <= 7200) markerInterval = 600;
            else if (totalDuration <= 14400) markerInterval = 900;
            else if (totalDuration <= 28800) markerInterval = 1800;
            else markerInterval = 3600;

            for (let t = 0; t <= totalDuration; t += markerInterval) {{
                const xPos = (t / totalDuration) * chartWidth;
                let timeDisplay;
                if (t >= 3600) {{
                    const hours = Math.floor(t / 3600);
                    const mins = Math.floor((t % 3600) / 60);
                    const secs = t % 60;
                    if (mins === 0 && secs === 0) timeDisplay = `${{hours}}h`;
                    else if (secs === 0) timeDisplay = `${{hours}}h ${{mins}}m`;
                    else timeDisplay = `${{hours}}h ${{mins}}m ${{secs}}s`;
                }} else if (t >= 60) {{
                    const mins = Math.floor(t / 60);
                    const secs = t % 60;
                    timeDisplay = secs === 0 ? `${{mins}}m` : `${{mins}}m ${{secs}}s`;
                }} else {{
                    timeDisplay = `${{t}}s`;
                }}
                chartHTML += `<div style="position: absolute; left: ${{xPos}}px; top: 0; height: 100%; border-left: 1px solid #adb5bd; padding: 8px 4px; font-size: 11px; color: #6c757d; font-weight: 500; white-space: nowrap;">${{timeDisplay}}</div>`;
            }}

            chartHTML += `
                            </div>
                            <div style="height: 30px; background: #f8f9fa; border-bottom: 1px solid #dee2e6; position: relative; display: flex; align-items: center; padding: 0 10px;">
                                <div style="flex: 1; position: relative; height: 12px; background: #e9ecef; border-radius: 6px; overflow: hidden; box-shadow: inset 0 1px 3px rgba(0,0,0,0.1);">
                                    <div style="position: absolute; left: 0; top: 0; width: 100%; height: 100%; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); opacity: 0.6;"></div>
                                    <div style="position: absolute; left: 0; top: -3px; font-size: 10px; color: #495057; font-weight: 600;">${{new Date(earliestStart).toLocaleTimeString()}}</div>
                                    <div style="position: absolute; right: 0; top: -3px; font-size: 10px; color: #495057; font-weight: 600;">${{new Date(latestEnd).toLocaleTimeString()}}</div>
                                </div>
                                <div style="margin-left: 15px; font-size: 11px; color: #6c757d; font-weight: 600; white-space: nowrap;">Total: ${{totalDuration.toFixed(1)}}s</div>
                            </div>
                            <div style="position: relative; height: ${{chartHeight}}px;">
            `;

            // Draw grid lines and bars (abbreviated - same logic)
            let cumulativeHeight = 0;
            dutList.forEach(dutId => {{
                const rowHeight = dutRowHeights[dutId];
                chartHTML += `<div style="position: absolute; left: 0; top: ${{cumulativeHeight}}px; width: 100%; height: ${{rowHeight}}px; border-bottom: 1px solid #e9ecef;"></div>`;
                cumulativeHeight += rowHeight;
            }});

            // Vertical grid lines
            for (let t = 0; t <= totalDuration; t += markerInterval) {{
                const xPos = (t / totalDuration) * chartWidth;
                chartHTML += `<div style="position: absolute; left: ${{xPos}}px; top: 0; width: 1px; height: 100%; background: #e3e6ea; opacity: 0.5;"></div>`;
            }}

            // Draw bars
            cumulativeHeight = 0;
            dutList.forEach((dutId, dutIndex) => {{
                const rowHeight = dutRowHeights[dutId];
                const dutCollectors = chartData.filter(d => d.y === dutIndex);
                dutCollectors.forEach(dataPoint => {{
                    const lane = dataPoint.lane || 0;
                    const yPos = cumulativeHeight + dutPadding + (lane * (baseLaneHeight + laneGap));
                    const xStart = (dataPoint.x / totalDuration) * chartWidth;
                    const width = Math.max(2, (dataPoint.duration / totalDuration) * chartWidth);
                    const info = dataPoint.info;
                    const color = dataPoint.color;
                    const startTime = new Date(info.start_time).toLocaleTimeString();
                    const endTime = new Date(info.end_time).toLocaleTimeString();
                    const durationText = info.duration < 1 ? `${{(info.duration * 1000).toFixed(0)}}ms` : `${{info.duration.toFixed(1)}}s`;
                    const canFitName = width > 120;
                    const canFitDuration = width > 40;
                    let barContent = '';
                    if (canFitName) barContent = `${{escapeHTML(info.collector_name)}} <span style="opacity: 0.7; margin-left: 6px;">(${{durationText}})</span>`;
                    else if (canFitDuration) barContent = durationText;
                    chartHTML += `
                        <div class="gantt-bar"
                             data-dut="${{escapeHTML(info.dut_id)}}"
                             data-collector="${{escapeHTML(info.collector_name)}}"
                             data-service="${{escapeHTML(info.group)}}"
                             data-status="${{escapeHTML(info.status)}}"
                             data-duration="${{info.duration.toFixed(2)}}"
                             data-start="${{escapeHTML(startTime)}}"
                             data-end="${{escapeHTML(endTime)}}"
                             style="position: absolute; left: ${{xStart}}px; top: ${{yPos}}px; width: ${{width}}px; height: ${{baseLaneHeight}}px; background: ${{color}}; border: 1px solid ${{color}}dd; border-radius: 4px; cursor: pointer; transition: all 0.2s; overflow: visible; display: flex; align-items: center; padding: 0 6px; font-size: 10px; font-weight: 500; color: #000;">
                            <span style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${{barContent}}</span>
                        </div>
                    `;
                }});
                cumulativeHeight += rowHeight;
            }});

            chartHTML += `
                            </div>
                        </div>
                    </div>
                </div>
            `;

            container.innerHTML = '<div id="mainTimelineZoomable" style="transform-origin: top left; transition: transform 0.1s ease-out;">' + chartHTML + '</div>';

            // Re-attach event listeners for bars (same tooltip logic)
            const bars = container.querySelectorAll('.gantt-bar');
            bars.forEach(bar => {{
                bar.addEventListener('mouseenter', function() {{
                    this.style.filter = 'brightness(1.1)';
                    this.style.transform = 'scaleY(1.1)';
                    this.style.zIndex = '10';
                    this.style.boxShadow = '0 4px 8px rgba(0,0,0,0.2)';
                    const tooltip = document.createElement('div');
                    tooltip.className = 'gantt-tooltip';
                    tooltip.style.cssText = `position: fixed; background: rgba(0, 0, 0, 0.9); color: white; padding: 12px; border-radius: 6px; font-size: 12px; z-index: 10000; pointer-events: none; max-width: 300px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); line-height: 1.6;`;
                    renderTimingTooltip(
                        tooltip,
                        {{
                            dut_id: this.dataset.dut,
                            collector_name: this.dataset.collector,
                            group: this.dataset.service,
                            status: this.dataset.status,
                            duration: Number(this.dataset.duration)
                        }},
                        getStatusColor(this.dataset.status),
                        this.dataset.start,
                        this.dataset.end
                    );
                    document.body.appendChild(tooltip);
                    this._tooltip = tooltip;
                }});
                bar.addEventListener('mousemove', function(e) {{
                    if (this._tooltip) {{
                        this._tooltip.style.left = (e.clientX + 15) + 'px';
                        this._tooltip.style.top = (e.clientY + 15) + 'px';
                    }}
                }});
                bar.addEventListener('mouseleave', function() {{
                    this.style.filter = '';
                    this.style.transform = '';
                    this.style.zIndex = '';
                    this.style.boxShadow = '';
                    if (this._tooltip) {{
                        this._tooltip.remove();
                        this._tooltip = null;
                    }}
                }});
            }});

            // Re-setup pan/zoom
            setupMainTimelinePanZoom(container);
        }}

        // Remove old Chart.js code - using HTML/CSS instead
        window.timelineChartInstance = null; // Placeholder for compatibility

        // Skip the old Chart.js implementation
        if (false) {{
            window.timelineChartInstance = new Chart(ctx, {{
                type: 'scatter',
                data: {{
                    datasets: [{{
                        data: chartData,
                        pointRadius: 0,
                        showLine: false
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    onHover: function(event, activeElements) {{
                        const canvas = event.native.target;
                        const rect = canvas.getBoundingClientRect();
                        const x = event.native.clientX - rect.left;
                        const y = event.native.clientY - rect.top;

                        // Check if hovering over any bar
                        hoveredBarIndex = null;
                        const chart = this;
                        const yAxis = chart.scales.y;
                        const xAxis = chart.scales.x;

                        chartData.forEach((dataPoint, idx) => {{
                            const yPos = yAxis.getPixelForValue(dataPoint.y);
                            const xStart = xAxis.getPixelForValue(dataPoint.x);
                            const xEnd = xAxis.getPixelForValue(dataPoint.x + dataPoint.duration);
                            const barHeight = Math.abs(yAxis.getPixelForValue(0) - yAxis.getPixelForValue(1)) * 0.85;

                            if (x >= xStart && x <= xEnd &&
                                y >= yPos - barHeight/2 && y <= yPos + barHeight/2) {{
                                hoveredBarIndex = idx;
                                canvas.style.cursor = 'pointer';
                            }}
                        }});

                        if (hoveredBarIndex === null) {{
                            canvas.style.cursor = 'default';
                        }}

                        chart.update('none');
                    }},
                    plugins: {{
                        legend: {{
                            display: false
                        }},
                        tooltip: {{
                            enabled: false,
                            external: function(context) {{
                                if (hoveredBarIndex !== null) {{
                                    const dataPoint = chartData[hoveredBarIndex];
                                    const info = dataPoint.info;

                                    let tooltipEl = document.getElementById('chartjs-tooltip');
                                    if (!tooltipEl) {{
                                        tooltipEl = document.createElement('div');
                                        tooltipEl.id = 'chartjs-tooltip';
                                        tooltipEl.style.cssText = `
                                            position: absolute;
                                            background: rgba(0, 0, 0, 0.9);
                                            color: white;
                                            padding: 10px;
                                            border-radius: 6px;
                                            font-size: 12px;
                                            pointer-events: none;
                                            z-index: 1000;
                                            max-width: 300px;
                                            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
                                        `;
                                        document.body.appendChild(tooltipEl);
                                    }}

                                    const startTime = new Date(info.start_time).toLocaleTimeString();
                                    const endTime = new Date(info.end_time).toLocaleTimeString();

                                    renderTimingTooltip(
                                        tooltipEl,
                                        info,
                                        dataPoint.color.replace('0.8', '1'),
                                        startTime,
                                        endTime
                                    );

                                    const position = context.chart.canvas.getBoundingClientRect();
                                    tooltipEl.style.left = position.left + window.pageXOffset + context.tooltip.caretX + 'px';
                                    tooltipEl.style.top = position.top + window.pageYOffset + context.tooltip.caretY + 'px';
                                    tooltipEl.style.opacity = '1';
                                }} else {{
                                    const tooltipEl = document.getElementById('chartjs-tooltip');
                                    if (tooltipEl) {{
                                        tooltipEl.style.opacity = '0';
                                    }}
                                }}
                            }}
                        }}
                    }},
                    scales: {{
                        x: {{
                            type: 'linear',
                            position: 'bottom',
                            min: 0,
                            max: (latestEnd - earliestStart) / 1000,
                            grid: {{
                                color: 'rgba(0, 0, 0, 0.05)',
                                drawBorder: true,
                                drawOnChartArea: true,
                                drawTicks: true
                            }},
                            title: {{
                                display: true,
                                text: 'Time (seconds from start)',
                                font: {{
                                    size: 14,
                                    weight: 'bold'
                                }}
                            }},
                            ticks: {{
                                callback: function(value) {{
                                    return value.toFixed(0) + 's';
                                }},
                                font: {{
                                    size: 11
                                }}
                            }}
                        }},
                        y: {{
                            type: 'linear',
                            min: -0.5,
                            max: dutList.length - 0.5,
                            grid: {{
                                color: 'rgba(0, 0, 0, 0.1)',
                                drawBorder: true,
                                drawOnChartArea: true,
                                lineWidth: 1
                            }},
                            ticks: {{
                                stepSize: 1,
                                padding: 10,
                                callback: function(value) {{
                                    return dutList[value] || '';
                                }},
                                font: {{
                                    size: 13,
                                    weight: 'bold'
                                }},
                                color: '#2c3e50'
                            }},
                            title: {{
                                display: true,
                                text: 'Device Under Test (DUT)',
                                font: {{
                                    size: 14,
                                    weight: 'bold'
                                }}
                            }}
                        }}
                    }},
                    layout: {{
                        padding: {{
                            left: 20,
                            right: 20,
                            top: 10,
                            bottom: 10
                        }}
                    }}
                }},
                plugins: [{{
                    id: 'ganttBars',
                    afterDatasetsDraw: function(chart) {{
                        const ctx = chart.ctx;
                        const yAxis = chart.scales.y;
                        const xAxis = chart.scales.x;

                        // Draw horizontal grid lines for each DUT row
                        ctx.save();
                        ctx.strokeStyle = 'rgba(0, 0, 0, 0.08)';
                        ctx.lineWidth = 1;
                        for (let i = 0; i < dutList.length; i++) {{
                            const yPos = yAxis.getPixelForValue(i);
                            ctx.beginPath();
                            ctx.moveTo(xAxis.left, yPos);
                            ctx.lineTo(xAxis.right, yPos);
                            ctx.stroke();
                        }}
                        ctx.restore();

                        // Draw bars
                        chartData.forEach((dataPoint, idx) => {{
                            const yPos = yAxis.getPixelForValue(dataPoint.y);
                            const xStart = xAxis.getPixelForValue(dataPoint.x);
                            const xEnd = xAxis.getPixelForValue(dataPoint.x + dataPoint.duration);
                            const barHeight = Math.abs(yAxis.getPixelForValue(0) - yAxis.getPixelForValue(1)) * 0.85;
                            const width = xEnd - xStart;

                            // Highlight hovered bar
                            const isHovered = hoveredBarIndex === idx;

                            // Draw bar
                            ctx.fillStyle = isHovered ? dataPoint.color.replace('0.8', '0.95') : dataPoint.color;
                            ctx.fillRect(xStart, yPos - barHeight/2, width, barHeight);

                            // Draw border
                            ctx.strokeStyle = isHovered ? '#000' : dataPoint.color.replace('0.8', '1');
                            ctx.lineWidth = isHovered ? 2 : 1;
                            ctx.strokeRect(xStart, yPos - barHeight/2, width, barHeight);

                            // Draw collector name on wider bars
                            if (width > 40 && barHeight > 15) {{
                                ctx.save();
                                ctx.fillStyle = '#000';
                                ctx.font = isHovered ? 'bold 11px sans-serif' : '10px sans-serif';
                                ctx.textAlign = 'left';
                                ctx.textBaseline = 'middle';

                                const text = dataPoint.label;
                                const textWidth = ctx.measureText(text).width;

                                if (textWidth < width - 6) {{
                                    ctx.fillText(text, xStart + 3, yPos);
                                }}
                                ctx.restore();
                            }}
                        }});
                    }}
                }}]
            }});
        }}

        // Populate DUT Details Section (as table)
        const dutDetailsContent = document.getElementById('dutDetailsContent');
        if (dutDetailsContent) {{
            let tableHTML = `
                <table class="table table-striped table-bordered table-hover">
                    <thead class="table-dark">
                        <tr>
                            <th>DUT</th>
                            <th>Duration</th>
                            <th>Start Time</th>
                            <th>End Time</th>
                            <th>Total Collectors</th>
                            <th class="text-success">Completed</th>
                            <th class="text-warning">Degraded</th>
                            <th class="text-danger">Failed</th>
                            <th class="text-info">Partial</th>
                            <th class="text-warning">Skipped</th>
                        </tr>
                    </thead>
                    <tbody>
            `;

            for (const [dutId, summary] of Object.entries(dutSummaries)) {{
                const dutCollectors = timelineData.filter(c => c.dut_id === dutId);
                // Match status strings from timing.json
                const successCount = dutCollectors.filter(c => c.status.toUpperCase() === 'SUCCESS').length;
                const degradedCount = dutCollectors.filter(c => c.status.toUpperCase() === 'DEGRADED').length;
                const errorCount = dutCollectors.filter(c => c.status.toUpperCase() === 'ERROR').length;
                const partialCount = dutCollectors.filter(c => c.status.toUpperCase() === 'PARTIAL').length;
                const skippedCount = dutCollectors.filter(c => c.status.toUpperCase() === 'SKIPPED').length;

                tableHTML += `
                    <tr>
                        <td><strong>${{escapeHTML(dutId)}}</strong></td>
                        <td>${{summary.duration.toFixed(2)}}s</td>
                        <td>${{new Date(summary.start_time).toLocaleString()}}</td>
                        <td>${{new Date(summary.end_time).toLocaleString()}}</td>
                        <td>${{escapeHTML(summary.total_collectors)}}</td>
                        <td class="text-success"><strong>${{successCount}}</strong></td>
                        <td class="text-warning"><strong>${{degradedCount}}</strong></td>
                        <td class="text-danger"><strong>${{errorCount}}</strong></td>
                        <td class="text-info"><strong>${{partialCount}}</strong></td>
                        <td class="text-warning"><strong>${{skippedCount}}</strong></td>
                    </tr>
                `;
            }}

            tableHTML += `
                    </tbody>
                </table>
            `;
            dutDetailsContent.innerHTML = tableHTML;
        }}

        // Populate Collector Timing Table
        const collectorTimingBody = document.getElementById('collectorTimingBody');
        if (collectorTimingBody) {{
            let tableHTML = '';
            timelineData.forEach(item => {{
                const statusUpper = item.status.toUpperCase();
                const statusClass = statusUpper === 'SUCCESS' ? 'table-success' :
                                  statusUpper === 'DEGRADED' ? 'table-warning' :
                                  statusUpper === 'ERROR' ? 'table-danger' :
                                  statusUpper === 'PARTIAL' ? 'table-info' :
                                  statusUpper === 'SKIPPED' ? 'table-secondary' : '';

                // Map service to color class
                const serviceClass = 'badge service-badge service-' + item.group.toLowerCase().replace(/[^a-z0-9]/g, '_');

                tableHTML += `
                    <tr class="${{statusClass}}">
                        <td>${{escapeHTML(item.dut_id)}}</td>
                        <td>${{escapeHTML(item.collector_name)}}</td>
                        <td><span class="${{serviceClass}}">${{escapeHTML(item.group)}}</span></td>
                        <td>${{escapeHTML(item.status)}}</td>
                        <td>${{item.duration.toFixed(2)}}</td>
                        <td>${{new Date(item.start_time).toLocaleTimeString()}}</td>
                        <td>${{new Date(item.end_time).toLocaleTimeString()}}</td>
                    </tr>
                `;
            }});
            collectorTimingBody.innerHTML = tableHTML;
        }}

        // Table sorting function
        let sortDirection = {{}};
        function sortTable(columnIndex) {{
            const table = document.getElementById('collectorTimingTable');
            const tbody = table.getElementsByTagName('tbody')[0];
            const rows = Array.from(tbody.getElementsByTagName('tr'));

            // Toggle sort direction
            sortDirection[columnIndex] = !sortDirection[columnIndex];
            const isAscending = sortDirection[columnIndex];

            rows.sort((a, b) => {{
                let aValue = a.getElementsByTagName('td')[columnIndex].textContent;
                let bValue = b.getElementsByTagName('td')[columnIndex].textContent;

                // Handle numeric sorting for duration
                if (columnIndex === 4) {{
                    aValue = parseFloat(aValue);
                    bValue = parseFloat(bValue);
                }}

                if (aValue < bValue) return isAscending ? -1 : 1;
                if (aValue > bValue) return isAscending ? 1 : -1;
                return 0;
            }});

            // Clear tbody and append sorted rows
            tbody.innerHTML = '';
            rows.forEach(row => tbody.appendChild(row));
        }}

        // Populate detailed collector list
        const collectorList = document.getElementById('collectorList');
        const searchInput = document.getElementById('collectorSearch');

        function renderCollectorList(filter = '') {{
            const filteredData = filter
                ? timelineData.filter(item =>
                    item.collector_name.toLowerCase().includes(filter.toLowerCase()) ||
                    item.dut_id.toLowerCase().includes(filter.toLowerCase()) ||
                    item.group.toLowerCase().includes(filter.toLowerCase())
                  )
                : timelineData;

            collectorList.innerHTML = filteredData.map(item => {{
                const statusUpper = item.status.toUpperCase();
                const statusClass = statusUpper === 'SUCCESS' ? 'status-success' :
                                  statusUpper === 'DEGRADED' ? 'status-degraded' :
                                  statusUpper === 'ERROR' ? 'status-error' :
                                  statusUpper === 'SKIPPED' ? 'status-skipped' :
                                  'status-partial';
                // Map service to color class (consistent with table)
                const serviceClass = 'badge service-badge service-' + item.group.toLowerCase().replace(/[^a-z0-9]/g, '_');
                const startTime = new Date(item.start_time);
                const endTime = new Date(item.end_time);

                return `
                    <div class="collector-row ${{statusClass}}">
                        <span class="${{serviceClass}}">${{escapeHTML(item.group)}}</span>
                        <strong>${{escapeHTML(item.collector_name)}}</strong>
                        <span class="text-muted ms-2">[${{escapeHTML(item.dut_id)}}]</span>
                        <span class="ms-auto">
                            ${{startTime.toLocaleTimeString()}} - ${{endTime.toLocaleTimeString()}}
                            (${{item.duration.toFixed(2)}}s)
                        </span>
                    </div>
                `;
            }}).join('');
        }}

        // Initialize the list after DOM is ready
        if (collectorList && searchInput) {{
            searchInput.addEventListener('input', (e) => renderCollectorList(e.target.value));
            renderCollectorList();
        }} else {{
            console.error('Collector list elements not found');
        }}

        // Log data for debugging
        console.log('Timeline data loaded:', timelineData.length, 'collectors');
        console.log('DUT summaries:', Object.keys(dutSummaries).length, 'DUTs');
        console.log('Service stats:', Object.keys(serviceStats).length, 'services');

        // Sidebar navigation active state and smooth scrolling
        document.querySelectorAll('.sidebar-nav a').forEach(link => {{
            link.addEventListener('click', function(e) {{
                e.preventDefault();
                const targetId = this.getAttribute('href').substring(1);
                const targetElement = document.getElementById(targetId);

                if (targetElement) {{
                    // Smooth scroll to section
                    targetElement.scrollIntoView({{
                        behavior: 'smooth',
                        block: 'start'
                    }});

                    // Update active state
                    document.querySelectorAll('.sidebar-nav a').forEach(l => l.classList.remove('active'));
                    this.classList.add('active');
                }}
            }});
        }});

        // Highlight active section on scroll
        window.addEventListener('scroll', () => {{
            const sections = ['summary', 'dut-performance', 'service-breakdown', 'stage-breakdown', 'timeline', 'dut-details', 'collector-timing', 'collector-log'];
            let currentSection = '';

            sections.forEach(sectionId => {{
                const section = document.getElementById(sectionId);
                if (section) {{
                    const rect = section.getBoundingClientRect();
                    if (rect.top <= 150 && rect.bottom >= 150) {{
                        currentSection = sectionId;
                    }}
                }}
            }});

            if (currentSection) {{
                document.querySelectorAll('.sidebar-nav a').forEach(link => {{
                    link.classList.remove('active');
                    if (link.getAttribute('href') === `#${{currentSection}}`) {{
                        link.classList.add('active');
                    }}
                }});
            }}
        }});

        // Main Timeline Pan & Zoom
        let mainZoom = 1.0;
        let mainPanX = 0;
        let mainPanY = 0;
        let mainPanning = false;

        function setupMainTimelinePanZoom(container) {{
            const zoomable = container.querySelector('#mainTimelineZoomable');
            if (!zoomable) return;

            // Smooth zoom with limits - handle trackpad smooth scrolling
            let lastWheelTime = 0;
            const wheelCooldown = 250; // Minimum time between zoom actions (ms) - higher for trackpads

            // Mouse wheel zoom - smooth and gradual
            container.addEventListener('wheel', function(e) {{
                e.preventDefault();

                const now = Date.now();
                if (now - lastWheelTime < wheelCooldown) {{
                    return; // Ignore rapid scroll events (trackpads generate many events per gesture)
                }}
                lastWheelTime = now;

                // Get current zoom level and limits
                const currentLevel = window.currentTimelineZoomLevel || 0;
                const minZoom = -5; // Can zoom out from fit-to-width
                const maxZoom = 25; // Maximum zoom in (30 total levels)

                // Small delta = one zoom step
                if (e.deltaY < 0 && currentLevel < maxZoom) {{
                    // Scroll up = zoom in (but not past max)
                    if (window.zoomTimelineIn) window.zoomTimelineIn();
                }} else if (e.deltaY > 0 && currentLevel > minZoom) {{
                    // Scroll down = zoom out (but not past min)
                    if (window.zoomTimelineOut) window.zoomTimelineOut();
                }}
            }}, {{ passive: false }});

            // Note: Panning is now handled by native scrolling (overflow-x: auto on the timeline container)
            // No need for custom drag-to-pan logic
        }}

        // Fullscreen Timeline Functionality with Pan & Zoom
        let fullscreenChart = null;
        let currentZoom = 1.0;
        let panX = 0;
        let panY = 0;
        let isPanning = false;
        let startPanX = 0;
        let startPanY = 0;

        function setupPanZoom(container) {{
            const zoomable = container.querySelector('#zoomableTimeline');
            if (!zoomable) return;

            // Mouse wheel zoom
            container.addEventListener('wheel', function(e) {{
                e.preventDefault();

                const rect = container.getBoundingClientRect();
                const mouseX = e.clientX - rect.left;
                const mouseY = e.clientY - rect.top;

                // Zoom factor
                const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
                const oldZoom = currentZoom;
                currentZoom = Math.max(0.5, Math.min(5, currentZoom * zoomFactor));

                // Adjust pan to zoom towards mouse position
                const zoomChange = currentZoom / oldZoom;
                panX = mouseX - (mouseX - panX) * zoomChange;
                panY = mouseY - (mouseY - panY) * zoomChange;

                updateTransform(zoomable);
            }});

            // Mouse drag pan
            container.addEventListener('mousedown', function(e) {{
                // Only pan if not clicking on a bar
                if (!e.target.classList.contains('gantt-bar')) {{
                    isPanning = true;
                    startPanX = e.clientX - panX;
                    startPanY = e.clientY - panY;
                    container.style.cursor = 'grabbing';
                    e.preventDefault();
                }}
            }});

            container.addEventListener('mousemove', function(e) {{
                if (isPanning) {{
                    panX = e.clientX - startPanX;
                    panY = e.clientY - startPanY;
                    updateTransform(zoomable);
                    e.preventDefault();
                }}
            }});

            container.addEventListener('mouseup', function() {{
                if (isPanning) {{
                    isPanning = false;
                    container.style.cursor = 'default';
                }}
            }});

            container.addEventListener('mouseleave', function() {{
                if (isPanning) {{
                    isPanning = false;
                    container.style.cursor = 'default';
                }}
            }});
        }}

        function updateTransform(element) {{
            if (!element) return;
            element.style.transform = `translate(${{panX}}px, ${{panY}}px) scale(${{currentZoom}})`;
        }}

        function openFullscreenTimeline() {{
            const modal = document.getElementById('fullscreenModal');
            modal.classList.add('active');

            // Reset zoom and pan
            currentZoom = 1.0;
            panX = 0;
            panY = 0;

            // Use HTML/CSS version for fullscreen
            const container = document.getElementById('timelineChartFullscreen');
            if (container && window.timelineChartData) {{
                // Clone the main timeline into fullscreen
                const mainTimeline = document.getElementById('timelineChart');
                if (mainTimeline) {{
                    // Wrap in a transformable container
                    container.innerHTML = '<div id="zoomableTimeline" style="transform-origin: top left; transition: transform 0.2s ease-out;">' +
                                         mainTimeline.innerHTML +
                                         '</div>';

                    // Setup pan and zoom handlers
                    setupPanZoom(container);

                    // Re-attach event listeners
                    const bars = container.querySelectorAll('.gantt-bar');
                    bars.forEach(bar => {{
                        bar.addEventListener('mouseenter', function() {{
                            this.style.filter = 'brightness(1.1)';
                            this.style.transform = 'scaleY(1.1)';
                            this.style.zIndex = '10';
                            this.style.boxShadow = '0 4px 8px rgba(0,0,0,0.2)';

                            const tooltip = document.createElement('div');
                            tooltip.className = 'gantt-tooltip-fs';
                            tooltip.style.cssText = `
                                position: fixed;
                                background: rgba(0, 0, 0, 0.9);
                                color: white;
                                padding: 12px;
                                border-radius: 6px;
                                font-size: 12px;
                                z-index: 10000;
                                pointer-events: none;
                                max-width: 300px;
                                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                                line-height: 1.6;
                            `;

                            renderTimingTooltip(
                                tooltip,
                                {{
                                    dut_id: this.dataset.dut,
                                    collector_name: this.dataset.collector,
                                    group: this.dataset.service,
                                    status: this.dataset.status,
                                    duration: Number(this.dataset.duration)
                                }},
                                getStatusColor(this.dataset.status),
                                this.dataset.start,
                                this.dataset.end
                            );

                            document.body.appendChild(tooltip);
                            this._tooltip = tooltip;
                        }});

                        bar.addEventListener('mousemove', function(e) {{
                            if (this._tooltip) {{
                                this._tooltip.style.left = (e.clientX + 15) + 'px';
                                this._tooltip.style.top = (e.clientY + 15) + 'px';
                            }}
                        }});

                        bar.addEventListener('mouseleave', function() {{
                            this.style.filter = '';
                            this.style.transform = '';
                            this.style.zIndex = '';
                            this.style.boxShadow = '';

                            if (this._tooltip) {{
                                this._tooltip.remove();
                                this._tooltip = null;
                            }}
                        }});
                    }});
                }}
            }}

            // Old Chart.js version - skip it
            if (false) {{
                let hoveredBarIndexFS = null;

                fullscreenChart = new Chart(ctx, {{
                    type: 'scatter',
                    data: {{
                        datasets: [{{
                            data: chartData,
                            pointRadius: 0,
                            showLine: false
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        onHover: function(event, activeElements) {{
                            const canvas = event.native.target;
                            const rect = canvas.getBoundingClientRect();
                            const x = event.native.clientX - rect.left;
                            const y = event.native.clientY - rect.top;

                            hoveredBarIndexFS = null;
                            const chart = this;
                            const yAxis = chart.scales.y;
                            const xAxis = chart.scales.x;

                            chartData.forEach((dataPoint, idx) => {{
                                const yPos = yAxis.getPixelForValue(dataPoint.y);
                                const xStart = xAxis.getPixelForValue(dataPoint.x);
                                const xEnd = xAxis.getPixelForValue(dataPoint.x + dataPoint.duration);
                                const barHeight = Math.abs(yAxis.getPixelForValue(0) - yAxis.getPixelForValue(1)) * 0.85;

                                if (x >= xStart && x <= xEnd &&
                                    y >= yPos - barHeight/2 && y <= yPos + barHeight/2) {{
                                    hoveredBarIndexFS = idx;
                                    canvas.style.cursor = 'pointer';
                                }}
                            }});

                            if (hoveredBarIndexFS === null) {{
                                canvas.style.cursor = 'default';
                            }}

                            chart.update('none');
                        }},
                        plugins: {{
                            legend: {{
                                display: false
                            }},
                            tooltip: {{
                                enabled: false,
                                external: function(context) {{
                                    if (hoveredBarIndexFS !== null) {{
                                        const dataPoint = chartData[hoveredBarIndexFS];
                                        const info = dataPoint.info;

                                        let tooltipEl = document.getElementById('chartjs-tooltip-fs');
                                        if (!tooltipEl) {{
                                            tooltipEl = document.createElement('div');
                                            tooltipEl.id = 'chartjs-tooltip-fs';
                                            tooltipEl.style.cssText = `
                                                position: absolute;
                                                background: rgba(0, 0, 0, 0.9);
                                                color: white;
                                                padding: 10px;
                                                border-radius: 6px;
                                                font-size: 12px;
                                                pointer-events: none;
                                                z-index: 3000;
                                                max-width: 300px;
                                                box-shadow: 0 4px 6px rgba(0,0,0,0.3);
                                            `;
                                            document.body.appendChild(tooltipEl);
                                        }}

                                        const startTime = new Date(info.start_time).toLocaleTimeString();
                                        const endTime = new Date(info.end_time).toLocaleTimeString();

                                        renderTimingTooltip(
                                            tooltipEl,
                                            info,
                                            dataPoint.color.replace('0.8', '1'),
                                            startTime,
                                            endTime
                                        );

                                        const position = context.chart.canvas.getBoundingClientRect();
                                        tooltipEl.style.left = position.left + window.pageXOffset + context.tooltip.caretX + 'px';
                                        tooltipEl.style.top = position.top + window.pageYOffset + context.tooltip.caretY + 'px';
                                        tooltipEl.style.opacity = '1';
                                    }} else {{
                                        const tooltipEl = document.getElementById('chartjs-tooltip-fs');
                                        if (tooltipEl) {{
                                            tooltipEl.style.opacity = '0';
                                        }}
                                    }}
                                }}
                            }}
                        }},
                        scales: {{
                            x: {{
                                type: 'linear',
                                position: 'bottom',
                                min: 0,
                                max: (latestEnd - earliestStart) / 1000,
                                grid: {{
                                    color: 'rgba(0, 0, 0, 0.05)',
                                    drawBorder: true,
                                    drawOnChartArea: true,
                                    drawTicks: true
                                }},
                                title: {{
                                    display: true,
                                    text: 'Time (seconds from start)',
                                    font: {{
                                        size: 14,
                                        weight: 'bold'
                                    }}
                                }},
                                ticks: {{
                                    callback: function(value) {{
                                        return value.toFixed(0) + 's';
                                    }},
                                    font: {{
                                        size: 11
                                    }}
                                }}
                            }},
                            y: {{
                                type: 'linear',
                                min: -0.5,
                                max: dutList.length - 0.5,
                                grid: {{
                                    color: 'rgba(0, 0, 0, 0.1)',
                                    drawBorder: true,
                                    drawOnChartArea: true,
                                    lineWidth: 1
                                }},
                                ticks: {{
                                    stepSize: 1,
                                    padding: 10,
                                    callback: function(value) {{
                                        return dutList[value] || '';
                                    }},
                                    font: {{
                                        size: 13,
                                        weight: 'bold'
                                    }},
                                    color: '#2c3e50'
                                }},
                                title: {{
                                    display: true,
                                    text: 'Device Under Test (DUT)',
                                    font: {{
                                        size: 14,
                                        weight: 'bold'
                                    }}
                                }}
                            }}
                        }},
                        layout: {{
                            padding: {{
                                left: 20,
                                right: 20,
                                top: 10,
                                bottom: 10
                            }}
                        }}
                    }},
                    plugins: [{{
                        id: 'ganttBarsFullscreen',
                        afterDatasetsDraw: function(chart) {{
                            const ctx = chart.ctx;
                            const yAxis = chart.scales.y;
                            const xAxis = chart.scales.x;

                            // Draw horizontal grid lines
                            ctx.save();
                            ctx.strokeStyle = 'rgba(0, 0, 0, 0.08)';
                            ctx.lineWidth = 1;
                            for (let i = 0; i < dutList.length; i++) {{
                                const yPos = yAxis.getPixelForValue(i);
                                ctx.beginPath();
                                ctx.moveTo(xAxis.left, yPos);
                                ctx.lineTo(xAxis.right, yPos);
                                ctx.stroke();
                            }}
                            ctx.restore();

                            // Draw bars
                            chartData.forEach((dataPoint, idx) => {{
                                const yPos = yAxis.getPixelForValue(dataPoint.y);
                                const xStart = xAxis.getPixelForValue(dataPoint.x);
                                const xEnd = xAxis.getPixelForValue(dataPoint.x + dataPoint.duration);
                                const barHeight = Math.abs(yAxis.getPixelForValue(0) - yAxis.getPixelForValue(1)) * 0.85;
                                const width = xEnd - xStart;

                                const isHovered = hoveredBarIndexFS === idx;

                                ctx.fillStyle = isHovered ? dataPoint.color.replace('0.8', '0.95') : dataPoint.color;
                                ctx.fillRect(xStart, yPos - barHeight/2, width, barHeight);

                                ctx.strokeStyle = isHovered ? '#000' : dataPoint.color.replace('0.8', '1');
                                ctx.lineWidth = isHovered ? 2 : 1;
                                ctx.strokeRect(xStart, yPos - barHeight/2, width, barHeight);

                                if (width > 40 && barHeight > 15) {{
                                    ctx.save();
                                    ctx.fillStyle = '#000';
                                    ctx.font = isHovered ? 'bold 11px sans-serif' : '10px sans-serif';
                                    ctx.textAlign = 'left';
                                    ctx.textBaseline = 'middle';

                                    const text = dataPoint.label;
                                    const textWidth = ctx.measureText(text).width;

                                    if (textWidth < width - 6) {{
                                        ctx.fillText(text, xStart + 3, yPos);
                                    }}
                                    ctx.restore();
                                }}
                            }});
                        }}
                    }}]
                }});
            }} // End of skipped Chart.js fullscreen code
        }}

        function closeFullscreenTimeline() {{
            const modal = document.getElementById('fullscreenModal');
            modal.classList.remove('active');
            currentZoom = 1.0;
        }}

        function zoomTimeline(factor) {{
            const zoomable = document.querySelector('#zoomableTimeline');
            if (!zoomable) return;

            const container = document.getElementById('timelineChartFullscreen');
            const rect = container.getBoundingClientRect();

            // Zoom towards center
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;

            const oldZoom = currentZoom;
            currentZoom = Math.max(0.5, Math.min(5, currentZoom * factor));

            // Adjust pan to zoom towards center
            const zoomChange = currentZoom / oldZoom;
            panX = centerX - (centerX - panX) * zoomChange;
            panY = centerY - (centerY - panY) * zoomChange;

            updateTransform(zoomable);
        }}

        function resetZoom() {{
            const zoomable = document.querySelector('#zoomableTimeline');
            if (!zoomable) return;

            currentZoom = 1.0;
            panX = 0;
            panY = 0;

            updateTransform(zoomable);
        }}

        // Close fullscreen on Escape key
        document.addEventListener('keydown', (e) => {{
            if (e.key === 'Escape') {{
                closeFullscreenTimeline();
            }}
        }});
    </script>
"""

            # Write timing analysis page using common template with custom header
            timing_page_path = self.report_dir / "timing_analysis.html"

            # Define the clock icon SVG
            clock_icon = """
                <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="bi bi-clock-history ms-3 me-2" viewBox="0 0 16 16">
                    <path d="M8.515 1.019A7 7 0 0 0 8 1V0a8 8 0 0 1 .589.022l-.074.997zm2.004.45a7.003 7.003 0 0 0-.985-.299l.219-.976c.383.086.76.2 1.126.342l-.36.933zm1.37.71a7.01 7.01 0 0 0-.439-.27l.493-.87a8.025 8.025 0 0 1 .979.654l-.615.789a6.996 6.996 0 0 0-.418-.302zm1.834 1.79a6.99 6.99 0 0 0-.653-.796l.724-.69c.27.285.52.59.747.91l-.818.576zm.744 1.352a7.08 7.08 0 0 0-.214-.468l.893-.45a7.976 7.976 0 0 1 .45 1.088l-.95.313a7.023 7.023 0 0 0-.179-.483zm.53 2.507a6.991 6.991 0 0 0-.1-1.025l.985-.17c.067.386.106.778.116 1.17l-1 .025zm-.131 1.538c.033-.17.06-.339.081-.51l.993.123a7.957 7.957 0 0 1-.23 1.155l-.964-.267c.046-.165.086-.332.12-.501zm-.952 2.379c.184-.29.346-.594.486-.908l.914.405c-.16.36-.345.706-.555 1.038l-.845-.535zm-.964 1.205c.122-.122.239-.248.35-.378l.758.653a8.073 8.073 0 0 1-.401.432l-.707-.707z"/>
                    <path d="M8 1a7 7 0 1 0 4.95 11.95l.707.707A8.001 8.001 0 1 1 8 0v1z"/>
                    <path d="M7.5 3a.5.5 0 0 1 .5.5v5.21l3.248 1.856a.5.5 0 0 1-.496.868l-3.5-2A.5.5 0 0 1 7 9V3.5a.5.5 0 0 1 .5-.5z"/>
                </svg>
            """

            self._write_html_report(
                timing_page_path,
                "Timing Analysis",
                content,
                page_icon=clock_icon,
                back_button={"url": "index.html", "text": "← Back to Reports"},
            )

            await self._log("INFO", f"Timing analysis page created: {timing_page_path}")

        except SnapshotConsistencyError:
            raise
        except Exception as e:
            await self._log("ERROR", f"Error generating timing analysis page: {e}")
            import traceback

            await self._log("ERROR", traceback.format_exc())

    async def _generate_top_level_report(self, node_reports: List[Path]) -> None:
        """
        Generate top level report.

        The implementation uses ``node_reports`` to generate top level report.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind. Filesystem effects remain confined to
        the caller-selected paths and the owning resource lifecycle. If the
        function cannot generate top level report, its exception reaches the
        caller instead of being converted into a successful result.

        Args:
            node_reports: filesystem location used as the node reports for this
                operation.

        Raises:
            FileNotFoundError: If the function cannot generate top level report
                safely.
        """
        status_counts = {
            "Complete": 0,
            "Degraded": 0,
            "Error": 0,
            "Skipped": 0,
            "N/A": 0,
        }
        execution_times: List[(str, float)] = []
        modals: List[str] = []  # Initialize modals list

        # Sort node_reports by node name
        node_reports_sorted = sorted(node_reports, key=lambda p: p.parent.name.lower())
        node_input_paths = {
            node_path.name: node_path for node_path in self._iter_node_directories()
        }
        missing_node_inputs = {
            report_path.parent.name for report_path in node_reports_sorted
        } - set(node_input_paths)
        if missing_node_inputs:
            raise FileNotFoundError(
                "Node report source is unavailable: "
                + ", ".join(sorted(missing_node_inputs))
            )

        # Calculate executive summary stats (prefer collection_status.json for alignment)
        total_duts = len(node_reports)
        total_log_size = 0
        total_collectors_pass = 0
        total_collectors_degraded = 0
        total_collectors_fail = 0
        total_collectors_partial = 0
        total_collectors_skipped = 0  # runtime-skipped only
        total_collectors_to_run = 0  # collectors_to_run (excludes filtered-out)
        total_collectors_all = 0  # includes filtered-out
        total_filtered_out = 0
        # Collect per-status details for executive-summary modals
        status_collectors = {
            "pass": defaultdict(list),
            "degraded": defaultdict(list),
            "fail": defaultdict(list),
            "partial": defaultdict(list),
            "skipped": defaultdict(list),
        }

        # Build a per-DUT map of collector-group aliases to their report filenames
        node_group_report_map: Dict[str, Dict[str, str]] = {}
        for rep in node_reports_sorted:
            _dut_name = rep.parent.name
            _dut_path = node_input_paths[_dut_name]
            alias_map: Dict[str, str] = {}
            try:
                for group_folder in self._get_collector_groups(_dut_path):
                    folder_name = group_folder.name
                    report_filename = f"{folder_name}_report.html"
                    aliases = set()
                    aliases.add(folder_name)
                    aliases.add(folder_name.lower())
                    aliases.add(folder_name.replace("_", "").lower())
                    norm_name = self._normalize_group_name(folder_name)
                    if norm_name:
                        aliases.add(norm_name)
                        aliases.add(norm_name.lower())
                        aliases.add(norm_name.replace(" ", "_").lower())
                        aliases.add(norm_name.replace("_", "").lower())
                    # Special-case to tolerate healthcheck/health_check
                    if folder_name.lower() == "health_check":
                        aliases.add("healthcheck")
                        aliases.add("health_check")
                    for a in aliases:
                        alias_map[a] = report_filename
            except Exception:
                alias_map = {}
            node_group_report_map[_dut_name] = alias_map

        # Aggregate log sizes and compute counts from per-DUT collection_status.json when present
        for report_html in node_reports_sorted:
            node_name = report_html.parent.name
            node_path = node_input_paths[node_name]
            log_size = self._get_total_log_size(node_path)
            total_log_size += log_size

            # Prefer per-DUT JSON if available
            dut_json = node_path / ".metadata" / "collection_status.json"
            if dut_json.exists() or self._terminal_snapshot_generation is not None:
                try:
                    dut_status = self._read_terminal_status(node_name)
                    if dut_status is None:
                        raise FileNotFoundError(dut_json)
                    collectors = dut_status.get("collectors", {})
                    total_collectors_all += len(collectors)
                    for _key, entry in collectors.items():
                        status_text = (entry.get("status") or "").lower()
                        start_time = entry.get("start_time")
                        # Capture details for the tables
                        collector_id = (
                            entry.get("collector_id") or _key.split(":", 1)[-1]
                        )
                        collector_name = (
                            entry.get("collector_name") or entry.get("name") or "N/A"
                        )
                        group_name_raw = entry.get(
                            "group"
                        ) or self._normalize_group_name(
                            self._get_group_from_collector_id(collector_id)
                        )
                        # Resolve report file using alias map for this DUT
                        report_file = None
                        if group_name_raw and str(group_name_raw).strip():
                            gm = node_group_report_map.get(node_name, {})
                            g = str(group_name_raw)
                            candidates = [
                                g,
                                g.lower(),
                                g.replace(" ", "_"),
                                g.replace("_", "").lower(),
                            ]
                            gn = self._normalize_group_name(g)
                            if gn:
                                candidates.extend(
                                    [
                                        gn,
                                        gn.lower(),
                                        gn.replace(" ", "_").lower(),
                                        gn.replace("_", "").lower(),
                                    ]
                                )
                            if g.lower() == "healthcheck":
                                candidates.append("health_check")
                            for cand in candidates:
                                if cand in gm:
                                    report_file = gm[cand]
                                    break
                        anchor_id = self._generate_safe_id("collector", collector_id)
                        if status_text in ["complete", "success"]:
                            total_collectors_pass += 1
                            if report_file:
                                status_collectors["pass"][node_name].append(
                                    (
                                        collector_id,
                                        collector_name,
                                        report_file,
                                        anchor_id,
                                    )
                                )
                        elif status_text == "degraded":
                            total_collectors_degraded += 1
                            if report_file:
                                status_collectors["degraded"][node_name].append(
                                    (
                                        collector_id,
                                        collector_name,
                                        report_file,
                                        anchor_id,
                                    )
                                )
                        elif status_text == "error":
                            total_collectors_fail += 1
                            if report_file:
                                status_collectors["fail"][node_name].append(
                                    (
                                        collector_id,
                                        collector_name,
                                        report_file,
                                        anchor_id,
                                    )
                                )
                        elif status_text == "partial":
                            total_collectors_partial += 1
                            if report_file:
                                status_collectors["partial"][node_name].append(
                                    (
                                        collector_id,
                                        collector_name,
                                        report_file,
                                        anchor_id,
                                    )
                                )
                        elif status_text == "skipped":
                            if start_time is None:
                                total_filtered_out += 1
                            else:
                                total_collectors_skipped += 1
                                if report_file:
                                    status_collectors["skipped"][node_name].append(
                                        (
                                            collector_id,
                                            collector_name,
                                            report_file,
                                            anchor_id,
                                        )
                                    )
                except SnapshotArtifactFormatError:
                    if self._terminal_snapshot_generation is not None:
                        raise
                    statuses_for_node = self.node_statuses_all.get(node_name, [])
                    for status in statuses_for_node:
                        status_text = status.split()[0].lower()
                        total_collectors_all += 1
                        if status_text in ["complete", "success"]:
                            total_collectors_pass += 1
                        elif status_text == "degraded":
                            total_collectors_degraded += 1
                        elif status_text == "error":
                            total_collectors_fail += 1
                        elif status_text == "partial":
                            total_collectors_partial += 1
                        elif status_text == "skipped":
                            total_collectors_skipped += 1
                except SnapshotConsistencyError:
                    raise
                except Exception:
                    # Fallback to node_statuses_all if JSON parsing fails
                    statuses_for_node = self.node_statuses_all.get(node_name, [])
                    for status in statuses_for_node:
                        status_text = status.split()[0].lower()
                        total_collectors_all += 1
                        if status_text in ["complete", "success"]:
                            total_collectors_pass += 1
                        elif status_text == "degraded":
                            total_collectors_degraded += 1
                        elif status_text == "error":
                            total_collectors_fail += 1
                        elif status_text == "partial":
                            total_collectors_partial += 1
                        elif status_text == "skipped":
                            total_collectors_skipped += 1
            else:
                # Fallback path when JSON is missing
                statuses_for_node = self.node_statuses_all.get(node_name, [])
                for status in statuses_for_node:
                    status_text = status.split()[0].lower()
                    total_collectors_all += 1
                    if status_text in ["complete", "success"]:
                        total_collectors_pass += 1
                    elif status_text == "degraded":
                        total_collectors_degraded += 1
                    elif status_text == "error":
                        total_collectors_fail += 1
                    elif status_text == "partial":
                        total_collectors_partial += 1
                    elif status_text == "skipped":
                        total_collectors_skipped += 1

        # Helper to build status tables for modal bodies
        def build_status_table(
            data: Dict[str, List[Tuple[str, str, str, str]]],
        ) -> str:
            """
            Build status table.

            The implementation uses ``data`` to build status table.

            Args:
                data: Mapping supplying fields for status table.

            Returns:
                The canonical status table text.
            """
            if not data or not any(data.values()):
                return '<p class="text-muted mb-0">No collectors found.</p>'
            rows = []
            # Sort DUTs by name
            for dut in sorted(data.keys(), key=lambda x: x.lower()):
                collectors_for_dut = data.get(dut, [])
                if not collectors_for_dut:
                    continue
                # Sort collectors by ID
                collectors_for_dut_sorted = sorted(
                    collectors_for_dut, key=lambda t: (t[0] or "").lower()
                )
                collector_links = []
                for (
                    collector_id,
                    collector_name,
                    report_file,
                    anchor_id,
                ) in collectors_for_dut_sorted:
                    label = self._escape_html_text(f"{collector_id} - {collector_name}")
                    report_link = self._encoded_relative_report_link(dut, report_file)
                    if report_link is None:
                        collector_links.append(label)
                        continue
                    href = f"{report_link}#" f"{quote(str(anchor_id), safe='-._~')}"
                    collector_links.append(
                        f'<a href="{self._escape_html_text(href)}">{label}</a>'
                    )
                links = "<br>".join(collector_links)
                rows.append(
                    f"<tr><td>{self._escape_html_text(dut)}</td>"
                    f"<td>{links}</td></tr>"
                )
            if not rows:
                return '<p class="text-muted mb-0">No collectors found.</p>'
            return (
                '<div class="table-responsive">'
                '<table class="table table-sm table-striped">'
                '<thead class="table-dark"><tr><th>DUT ID</th><th>Collectors</th></tr></thead>'
                f"<tbody>{''.join(rows)}</tbody>"
                "</table>"
                "</div>"
            )

        # Exclude filtered-out from denominator used in charts
        total_collectors_to_run = max(total_collectors_all - total_filtered_out, 0)

        # Generate executive summary cards
        overall_percent = 0
        if total_collectors_to_run > 0:
            overall_percent = total_collectors_pass / total_collectors_to_run * 100
        run_result = self._read_run_result()
        if run_result is None:
            outcome_projection = ""
        else:
            result_document = run_result.to_dict()
            outcome_projection = f"""
            <div class="alert alert-secondary" role="status" data-run-result-schema="1.0">
                <strong>Runtime outcome:</strong> {escape(run_result.runtime_status.value)}
                <span class="mx-3">|</span>
                <strong>Collection outcome:</strong> {escape(run_result.collection_status.value)}
            </div>
            <script id="nvdebug-run-result" type="application/json">{self._json_for_script(result_document, sort_keys=True)}</script>
            """
        executive_summary = f"""
        <div class="mb-3">
            <h2 class="mb-4">Executive Summary</h2>
            {outcome_projection}
            <div class="row mb-3">
                <div class="col-md-4">
                    <div class="card text-white bg-primary mb-3 h-100" style="cursor: pointer;" data-bs-toggle="modal" data-bs-target="#dutModal">
                        <div class="card-body text-center">
                            <h5 class="card-title">Total DUTs</h5>
                            <p class="display-4">{total_duts}</p>
                            <small><i class="bi bi-hand-index"></i> Click for details</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-white bg-info mb-3 h-100" style="cursor: pointer;" data-bs-toggle="modal" data-bs-target="#logSizeModal">
                        <div class="card-body text-center">
                            <h5 class="card-title">Total Log Size</h5>
                            <p class="display-4" style="font-size: 2rem;">{self._format_bytes(total_log_size)}</p>
                            <small><i class="bi bi-hand-index"></i> Click for details</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card mb-3 h-100" style="cursor: default; background: linear-gradient(135deg, #6f42c1 0%, #b28dff 100%); color: #ffffff;">
                        <div class="card-body text-center">
                            <h5 class="card-title">Overall Collection %</h5>
                            <p class="display-4">{overall_percent:.1f}%</p>
                            <small>Passed / Collectors to run</small>
                        </div>
                    </div>
                </div>
            </div>
            <div class="row mb-3">
                <div class="col">
                    <div class="card text-white bg-success mb-3 h-100" style="cursor: pointer;" data-bs-toggle="modal" data-bs-target="#passedModal">
                        <div class="card-body text-center">
                            <h5 class="card-title">Passed Collectors</h5>
                            <p class="display-4">{total_collectors_pass}</p>
                            <small>of {total_collectors_to_run} to run</small>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card mb-3 h-100" style="cursor: pointer; background: linear-gradient(135deg, #f59e0b 0%, #fbbf24 100%); color: #ffffff;" data-bs-toggle="modal" data-bs-target="#degradedModal">
                        <div class="card-body text-center">
                            <h5 class="card-title">Degraded Collectors</h5>
                            <p class="display-4">{total_collectors_degraded}</p>
                            <small>of {total_collectors_to_run} to run</small>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card text-white bg-danger mb-3 h-100" style="cursor: pointer;" data-bs-toggle="modal" data-bs-target="#failedModal">
                        <div class="card-body text-center">
                            <h5 class="card-title">Failed Collectors</h5>
                            <p class="display-4">{total_collectors_fail}</p>
                            <small>of {total_collectors_to_run} to run</small>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card mb-3 h-100" style="cursor: pointer; background: linear-gradient(315deg, #ffd54f 0%, #fff176 100%); color: #ffffff;" data-bs-toggle="modal" data-bs-target="#partialModal">
                        <div class="card-body text-center">
                            <h5 class="card-title">Partial Collectors</h5>
                            <p class="display-4">{total_collectors_partial}</p>
                            <small>of {total_collectors_to_run} to run</small>
                        </div>
                    </div>
                </div>
                <div class="col">
                    <div class="card mb-3 h-100" style="cursor: pointer; background: linear-gradient(135deg, #ff9800 0%, #ffc107 100%); color: #ffffff;" data-bs-toggle="modal" data-bs-target="#skippedModal">
                        <div class="card-body text-center">
                            <h5 class="card-title">Skipped Collectors</h5>
                            <p class="display-4">{total_collectors_skipped}</p>
                            <small>of {total_collectors_to_run} to run</small>
                        </div>
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-md-6">
                    <div class="card mb-3">
                        <div class="card-body">
                            <h5 class="card-title">Quick Actions</h5>
                            <div class="d-grid gap-2 mb-3">
                                <a href="timing_analysis.html" class="btn btn-outline-primary">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clock-history me-2" viewBox="0 0 16 16">
                                        <path d="M8.515 1.019A7 7 0 0 0 8 1V0a8 8 0 0 1 .589.022l-.074.997zm2.004.45a7.003 7.003 0 0 0-.985-.299l.219-.976c.383.086.76.2 1.126.342l-.36.933zm1.37.71a7.01 7.01 0 0 0-.439-.27l.493-.87a8.025 8.025 0 0 1 .979.654l-.615.789a6.996 6.996 0 0 0-.418-.302zm1.834 1.79a6.99 6.99 0 0 0-.653-.796l.724-.69c.27.285.52.59.747.91l-.818.576zm.744 1.352a7.08 7.08 0 0 0-.214-.468l.893-.45a7.976 7.976 0 0 1 .45 1.088l-.95.313a7.023 7.023 0 0 0-.179-.483zm.53 2.507a6.991 6.991 0 0 0-.1-1.025l.985-.17c.067.386.106.778.116 1.17l-1 .025zm-.131 1.538c.033-.17.06-.339.081-.51l.993.123a7.957 7.957 0 0 1-.23 1.155l-.964-.267c.046-.165.086-.332.12-.501zm-.952 2.379c.184-.29.346-.594.486-.908l.914.405c-.16.36-.345.706-.555 1.038l-.845-.535zm-.964 1.205c.122-.122.239-.248.35-.378l.758.653a8.073 8.073 0 0 1-.401.432l-.707-.707z"/>
                                        <path d="M8 1a7 7 0 1 0 4.95 11.95l.707.707A8.001 8.001 0 1 1 8 0v1z"/>
                                        <path d="M7.5 3a.5.5 0 0 1 .5.5v5.21l3.248 1.856a.5.5 0 0 1-.496.868l-3.5-2A.5.5 0 0 1 7 9V3.5a.5.5 0 0 1 .5-.5z"/>
                                    </svg>
                                    View Detailed Timing Analysis
                                </a>
                                <a href="file_map.html" class="btn btn-outline-secondary">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-file-earmark-text me-2" viewBox="0 0 16 16">
                                        <path d="M5.5 7a.5.5 0 0 0 0 1h5a.5.5 0 0 0 0-1h-5zM5 9.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5zm0 2a.5.5 0 0 1 .5-.5h2a.5.5 0 0 1 0 1h-2a.5.5 0 0 1-.5-.5z"/>
                                        <path d="M9.5 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V4.5L9.5 0zm0 1v2A1.5 1.5 0 0 0 11 4.5h2V14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h5.5z"/>
                                    </svg>
                                    Browse Global File Map
                                </a>
                            </div>
                            <hr>
                            <h6 class="text-muted mb-2">Runtime Logs</h6>
                            <div class="list-group" id="runtimeLogsList">
                                __NVDEBUG_RUNTIME_LOG_LINKS__
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card mb-3">
                        <div class="card-body">
                            <h5 class="card-title">Collection Status</h5>
                                <div class="progress" style="height: 30px;">
                                <div class="progress-bar bg-success" role="progressbar" style="width: {(total_collectors_pass/total_collectors_to_run*100) if total_collectors_to_run > 0 else 0:.1f}%"
                                     aria-valuenow="{total_collectors_pass}" aria-valuemin="0" aria-valuemax="{total_collectors_to_run}">
                                    {total_collectors_pass} Pass
                                </div>
                                <div class="progress-bar" role="progressbar" style="background-color: #f59e0b; color: #fff; width: {(total_collectors_degraded/total_collectors_to_run*100) if total_collectors_to_run > 0 else 0:.1f}%"
                                     aria-valuenow="{total_collectors_degraded}" aria-valuemin="0" aria-valuemax="{total_collectors_to_run}">
                                    {total_collectors_degraded} Degraded
                                </div>
                                <div class="progress-bar bg-danger" role="progressbar" style="width: {(total_collectors_fail/total_collectors_to_run*100) if total_collectors_to_run > 0 else 0:.1f}%"
                                     aria-valuenow="{total_collectors_fail}" aria-valuemin="0" aria-valuemax="{total_collectors_to_run}">
                                    {total_collectors_fail} Fail
                                </div>
                                <div class="progress-bar" role="progressbar" style="background-color: #fffacd; color: #000; width: {(total_collectors_partial/total_collectors_to_run*100) if total_collectors_to_run > 0 else 0:.1f}%"
                                     aria-valuenow="{total_collectors_partial}" aria-valuemin="0" aria-valuemax="{total_collectors_to_run}">
                                    {total_collectors_partial} Partial
                                </div>
                                <div class="progress-bar bg-warning" role="progressbar" style="width: {(total_collectors_skipped/total_collectors_to_run*100) if total_collectors_to_run > 0 else 0:.1f}%"
                                     aria-valuenow="{total_collectors_skipped}" aria-valuemin="0" aria-valuemax="{total_collectors_to_run}">
                                    {total_collectors_skipped} Skip
                                </div>
                            </div>
                            <small class="text-muted mt-2 d-block">Total: {total_collectors_all} collectors across {total_duts} DUTs</small>
                            <small class="text-muted d-block">Collectors to run: {total_collectors_to_run} &nbsp;&nbsp; FilteredOut: {total_filtered_out}</small>
                            <hr>
                            <h6 class="text-muted mb-0">Total Runtime</h6>
                            <p class="h4 mb-0 mt-1">{self._format_time(self.total_runtime) if self.total_runtime is not None else 'N/A'}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Modals for Executive Summary Cards -->
        <div class="modal fade" id="dutModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">DUT Details</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <table class="table table-sm table-striped">
                            <thead class="table-dark">
                                <tr><th>DUT Name</th><th>Status</th><th>Execution Time</th></tr>
                            </thead>
                            <tbody>
        """

        # Add DUT rows
        for report_html in node_reports_sorted:
            node_name = report_html.parent.name
            status = self.node_statuses.get(node_name, "Unknown")
            exec_time = self.node_execution_times.get(node_name, 0)
            exec_time_str = self._format_time(exec_time) if exec_time > 0 else "N/A"
            status_class = "status-" + re.sub(r"[^a-z0-9_-]", "-", str(status).lower())
            node_report_link = self._encoded_relative_report_link(
                node_name, "report.html"
            )
            if node_report_link is None:
                node_link_cell = self._escape_html_text(node_name)
            else:
                node_link_cell = (
                    f'<a href="{self._escape_html_text(node_report_link)}">'
                    f"{self._escape_html_text(node_name)}</a>"
                )
            executive_summary += f"""
                                <tr>
                                    <td>{node_link_cell}</td>
                                    <td><span class="badge {status_class}">{self._escape_html_text(status)}</span></td>
                                    <td>{self._escape_html_text(exec_time_str)}</td>
                                </tr>
            """

        # Calculate success rate for passed modal
        success_rate = (
            (total_collectors_pass / total_collectors_to_run * 100)
            if total_collectors_to_run > 0
            else 0
        )
        failure_rate = (
            (
                (total_collectors_fail + total_collectors_partial)
                / total_collectors_to_run
                * 100
            )
            if total_collectors_to_run > 0
            else 0
        )

        executive_summary += f"""
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div class="modal fade" id="passedModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header bg-success text-white">
                        <h5 class="modal-title">Passed Collectors</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <p class="lead">{total_collectors_pass} collectors passed out of {total_collectors_to_run} total</p>
                        <p>Success Rate: {success_rate:.1f}%</p>
                        {build_status_table(status_collectors["pass"]) }
                    </div>
                </div>
            </div>
        </div>

        <div class="modal fade" id="degradedModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header" style="background: #f59e0b; color: #ffffff;">
                        <h5 class="modal-title">Degraded Collectors</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <p class="lead">Degraded: {total_collectors_degraded} collectors completed with usable primary evidence and optional failures out of {total_collectors_all} total</p>
                        <p>Degraded rate: {((total_collectors_degraded/total_collectors_to_run)*100) if total_collectors_to_run > 0 else 0:.1f}%</p>
                        {build_status_table(status_collectors["degraded"]) }
                    </div>
                </div>
            </div>
        </div>

        <div class="modal fade" id="failedModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header bg-danger text-white">
                        <h5 class="modal-title">Failed & Partial Collectors</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <p class="lead">Failed: {total_collectors_fail} collectors failed out of {total_collectors_to_run} total</p>
                        <p>Failure rate: {failure_rate:.1f}%</p>
                        {build_status_table(status_collectors["fail"]) }
                    </div>
                </div>
            </div>
        </div>

        <div class="modal fade" id="partialModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header" style="background: linear-gradient(315deg, #ffd54f 0%, #fff176 100%); color: #ffffff;">
                        <h5 class="modal-title">Partial Collectors</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <p class="lead">Partial: {total_collectors_partial} collectors partially completed out of {total_collectors_all} total</p>
                        <p>Partial rate: {((total_collectors_partial/total_collectors_to_run)*100) if total_collectors_to_run > 0 else 0:.1f}%</p>
                        {build_status_table(status_collectors["partial"]) }
                    </div>
                </div>
            </div>
        </div>

        <div class="modal fade" id="skippedModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header" style="background: linear-gradient(135deg, #ff9800 0%, #ffc107 100%); color: #ffffff;">
                        <h5 class="modal-title">Skipped Collectors</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <p class="lead">Skipped: {total_collectors_skipped} collectors skipped out of {total_collectors_all} total</p>
                        <p>Skipped rate: {((total_collectors_skipped/total_collectors_to_run)*100) if total_collectors_to_run > 0 else 0:.1f}%</p>
                        {build_status_table(status_collectors["skipped"]) }
                    </div>
                </div>
            </div>
        </div>

        <div class="modal fade" id="logSizeModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header bg-info text-white">
                        <h5 class="modal-title">Log Size Breakdown</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <p class="lead">Total: {self._format_bytes(total_log_size)}</p>
                        <table class="table table-sm table-striped">
                            <thead class="table-dark"><tr><th>DUT</th><th>Log Size</th></tr></thead>
                            <tbody>
        """

        # Add per-DUT log sizes
        for report_html in node_reports_sorted:
            node_name = report_html.parent.name
            node_path = node_input_paths[node_name]
            log_size = self._get_total_log_size(node_path)
            executive_summary += f"""
                                <tr>
                                    <td>{escape(node_name)}</td>
                                    <td>{self._format_bytes(log_size)}</td>
                                </tr>
            """

        executive_summary += """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        """

        node_table = (
            executive_summary
            + """
        <div class="mb-4">
            <h2>DUT Reports</h2>
        </div>
        <table class='table table-striped table-bordered table-shadow'>
        <thead class='table-dark'>
            <tr>
                <th class="text-center">Node Name</th>
                <th class="text-center">Report</th>
                <th class="text-center">Log Collection Time</th>
                <th class="text-center">System FRU</th>
                <th class="text-center">System Firmware</th>
                <th class="text-center">Total Log Size</th>
            </tr>
        </thead>
        <tbody>
        """
        )

        for report_html in node_reports_sorted:
            node_name = report_html.parent.name
            node_report_link = self._encoded_relative_report_link(
                node_name, "report.html"
            )
            if node_report_link is None:
                report_link_control = (
                    '<span class="text-muted">Report unavailable</span>'
                )
            else:
                report_link_control = (
                    f'<a href="{self._escape_html_text(node_report_link)}" '
                    'class="btn btn-dark btn-sm d-inline-block">View Report</a>'
                )
            exec_time = self.node_execution_times.get(node_name, 0.0)
            tdisp = self._format_time(exec_time) if exec_time else "N/A"

            # --- Compute total log size for the node (excluding its report directory) ---
            node_path = node_input_paths[node_name]
            log_size = self._get_total_log_size(node_path)
            log_size_str = self._format_bytes(log_size)

            # Count statuses, but don't count skipped collectors as errors
            statuses_for_node = self.node_statuses_all.get(node_name, [])
            for st in statuses_for_node:
                st_l = st.split()[0]
                if st_l not in status_counts:
                    status_counts.setdefault(st_l, 0)
                # if st_l in status_counts:
                #    # Only increment error count if it's not a skipped collector
                #    if st_l == "Error" and "Skipped" in statuses_for_node:
                #        continue
                #    status_counts[st_l] += 1
                # Count all statuses independently
                status_counts[st_l] += 1

            if exec_time and exec_time > 0:
                execution_times.append((node_name, exec_time))

            sys_info = self.node_system_details.get(
                node_name,
                {
                    "Model": "Unknown",
                    "Partno": "Unknown",
                    "Serialno": "Unknown",
                },
            )
            sys_display = (
                f"Model: {escape(sys_info['Model'])}<br>"
                f"Partno: {escape(sys_info['Partno'])}<br>"
                f"Serialno: {escape(sys_info['Serialno'])}"
            )

            # Get firmware information
            firmware_info, detailed_firmware_info = self._get_firmware_info(node_path)

            # Add firmware modal with safe ID
            firmware_modal_id = self._generate_safe_id("firmware_modal", node_name)
            firmware_modal = f"""
            <div class="modal fade" id="{firmware_modal_id}" tabindex="-1" aria-labelledby="{firmware_modal_id}Label" aria-hidden="true">
                <div class="modal-dialog modal-xl">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="{firmware_modal_id}Label">Firmware Information - {self._escape_html_text(node_name)}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            {detailed_firmware_info}
                        </div>
                    </div>
                </div>
            </div>
            """
            modals.append(firmware_modal)

            # Add firmware info with button to open modal
            firmware_display = f"""
            <div style='position: relative; min-height: 2.5em;'>
                {firmware_info}
                <button class=\"btn btn-sm btn-outline-secondary details-btn-topright\" style=\"position: absolute; top: 0.25em; right: 0.5em;\" onclick=\"openFullscreenModal('{firmware_modal_id}')\">
                    Details
                </button>
            </div>
            """

            node_table += f"""
            <tr>
            <td>{self._escape_html_text(node_name)}</td>
            <td class="text-center">{report_link_control}</td>
            <td>{self._escape_html_text(tdisp)}</td>
            <td>{sys_display}</td>
            <td>{firmware_display}</td>
            <td>{escape(log_size_str)}</td>
            </tr>
            """

        # Generate runtime logs links for the Quick Actions card
        runtime_logs_list = ""
        for file_info in self.root_level_files:
            file_path = self.root_dir / file_info["path"]
            if self._report_input_is_file(file_path):
                try:
                    fv = await self._generate_file_view(
                        file_path, file_info["display_name"]
                    )
                    encoded_fv = self._encoded_report_relative_path(f"reports/{fv}")
                    if encoded_fv is None:
                        runtime_logs_list += (
                            '<span class="list-group-item">'
                            f"{self._escape_html_text(file_info['display_name'])}"
                            "</span>"
                        )
                        continue
                    runtime_logs_list += f"""
                    <a href="{self._escape_html_text(encoded_fv)}" class="list-group-item list-group-item-action">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-file-text me-2" viewBox="0 0 16 16">
                            <path d="M5 4a.5.5 0 0 0 0 1h6a.5.5 0 0 0 0-1H5zm-.5 2.5A.5.5 0 0 1 5 6h6a.5.5 0 0 1 0 1H5a.5.5 0 0 1-.5-.5zM5 8a.5.5 0 0 0 0 1h6a.5.5 0 0 0 0-1H5zm0 2a.5.5 0 0 0 0 1h3a.5.5 0 0 0 0-1H5z"/>
                            <path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2zm10-1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1z"/>
                        </svg>
                        {escape(file_info['display_name'])}
                    </a>
                    """
                except ReportInputSafetyError:
                    raise
                except Exception as e:
                    await self._log(
                        "ERROR",
                        f"Error generating view for {file_info['path']}: {e}",
                    )

        # Insert authored, escaped markup directly. Re-parsing it through a JavaScript
        # template literal would create a second and unnecessary injection context.
        node_table = node_table.replace(
            "__NVDEBUG_RUNTIME_LOG_LINKS__", runtime_logs_list, 1
        )

        node_table += "</tbody></table>"

        # Summarize statuses
        unique_statuses = set(
            [s.split()[0] for v in self.node_statuses_all.values() for s in v]
        )
        for us in unique_statuses:
            if us not in status_counts:
                count_val = sum(
                    [
                        1
                        for v in self.node_statuses_all.values()
                        if us in [x.split()[0] for x in v]
                    ]
                )
                status_counts[us] = count_val

        # If hide_na_status is True, remove the N/A count before generating chart data
        if self.hide_na_status and self.na_string in status_counts:
            del status_counts[self.na_string]

        # Remove any status with zero count
        status_counts = {k: v for k, v in status_counts.items() if v > 0}

        chart_data_status = {
            "labels": list(status_counts.keys()),
            "counts": list(status_counts.values()),
        }

        tooltip_labels_time = [
            f"{escape(n)}: {self._format_time(t)}" for (n, t) in execution_times
        ]
        execution_times_in_minutes = [(n, t / 60) for (n, t) in execution_times]
        chart_data_time = {
            "labels": [escape(n) for (n, _) in execution_times_in_minutes],
            "times": [round(x, 2) for (_, x) in execution_times_in_minutes],
        }

        # Compute dynamic color mapping for status chart
        color_mapping = {
            "complete": "#28a745",
            "error": "#dc3545",
            "n/a": "#d3d3d3",
            "notran": "#d3d3d3",
            "skipped": "#ffc107",
            "degraded": "#f59e0b",
            "partial": "#fffacd",
            "unknown": "#17a2b8",
        }
        status_colors = [
            color_mapping.get(label.lower(), "#999999")
            for label in chart_data_status["labels"]
        ]

        # Prepare data for stacked bar chart
        collector_groups = set()
        node_collector_times = {}

        # First pass: collect all collector groups and initialize data structure
        for node_name, group_data in self.node_collector_json.items():
            node_collector_times[node_name] = {}
            for group_name, collectors in group_data.items():
                # Skip preflight group
                if group_name.lower() == "preflight":
                    continue

                total_time = 0
                for collector_data in collectors.values():
                    total_time += (
                        collector_data.get("execution_time_seconds", 0) / 60
                    )  # Convert to minutes

                # Only add groups that have non-zero execution time
                if total_time > 0:
                    collector_groups.add(group_name)
                    node_collector_times[node_name][group_name] = total_time

        # Sort collector groups for consistent colors
        sorted_groups = sorted(list(collector_groups))

        # Define consistent service colors matching badge/chart styling
        collector_group_colors = {
            "redfish": "#dc6976",  # Pink/Red for Redfish
            "ssh": "#ffc107",  # Yellow/Gold for SSH
            "ipmi": "#0dcaf0",  # Cyan for IPMI
            "health_check": "#6f42c1",  # Purple for Health Check
            "healthcheck": "#6f42c1",  # Purple for HealthCheck
            "host": "#28a745",  # Green for Host
            "bmc": "#fd7e14",  # Orange for BMC
            "preflight": "#20c997",  # Teal for Preflight
        }

        # Prepare datasets for each collector group
        datasets = []
        for group in sorted_groups:
            # Use predefined color if available, otherwise use a fallback color
            color = collector_group_colors.get(
                group.lower(), "#6c757d"
            )  # Gray as fallback
            datasets.append(
                {
                    "label": group,
                    "data": [
                        node_collector_times.get(node, {}).get(group, 0)
                        for node, _ in execution_times
                    ],
                    "backgroundColor": color,
                    "stack": "stack0",
                }
            )

        chart_data_time = {
            "labels": [escape(n) for (n, _) in execution_times],
            "datasets": datasets,
        }
        status_labels_json = self._json_for_script(chart_data_status["labels"])
        status_counts_json = self._json_for_script(chart_data_status["counts"])
        status_colors_json = self._json_for_script(status_colors)
        time_tooltip_labels_json = self._json_for_script(tooltip_labels_time)
        chart_data_time_json = self._json_for_script(chart_data_time)
        size_labels_json = self._json_for_script(
            [escape(name) for name, _duration in execution_times]
        )
        size_data_json = self._json_for_script(
            [
                round(
                    self._get_total_log_size(node_input_paths[name]) / (1024 * 1024),
                    2,
                )
                for name, _duration in execution_times
            ]
        )

        charts_script = f"""
        <div class="section">
            <h3>Execution Status Summary</h3>
            <div class="chart-container pie-chart">
                <button class="btn btn-sm btn-outline-secondary float-end" onclick="openFullscreenModal('statusChart')">
                    <i class="bi bi-arrows-fullscreen"></i>
                </button>
                <canvas id="statusChart" width="300" height="200"></canvas>
            </div>
        </div>
        <div class="section">
            <h3>Execution Time per Node</h3>
            <div class="chart-container">
                <button class="btn btn-sm btn-outline-secondary float-end" onclick="openFullscreenModal('timeChart')">
                    <i class="bi bi-arrows-fullscreen"></i>
                </button>
                <canvas id="timeChart" width="300" height="200"></canvas>
            </div>
        </div>
        <div class="section">
            <h3>Log Size per Node</h3>
            <div class="chart-container">
                <button class="btn btn-sm btn-outline-secondary float-end" onclick="openFullscreenModal('sizeChart')">
                    <i class="bi bi-arrows-fullscreen"></i>
                </button>
                <canvas id="sizeChart" width="300" height="200"></canvas>
            </div>
        </div>

        <!-- Fullscreen Modal -->
        <div class="modal fade" id="fullscreenModal" tabindex="-1" aria-labelledby="fullscreenModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-fullscreen">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="fullscreenModalLabel">Chart View</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <canvas id="fullscreenChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <script>
        // Chart instances storage
        var chartInstances = {{}};
        var fullscreenModal = null;

        // Initialize the modal when the document is ready
        document.addEventListener('DOMContentLoaded', function() {{
            var modalElement = document.getElementById('fullscreenModal');
            fullscreenModal = new bootstrap.Modal(modalElement);

            // Handle modal hidden event
            modalElement.addEventListener('hidden.bs.modal', function () {{
                if (chartInstances.fullscreen) {{
                    chartInstances.fullscreen.destroy();
                    chartInstances.fullscreen = null;
                }}
            }});
        }});

        function openFullscreenModal(modalId) {{
            console.log('openFullscreenModal called with ID:', modalId);

            // Check if this is a chart modal
            if (modalId === 'statusChart' || modalId === 'timeChart' || modalId === 'sizeChart') {{
                console.log('Handling chart modal');
                if (!fullscreenModal) {{
                    var modalElement = document.getElementById('fullscreenModal');
                    fullscreenModal = new bootstrap.Modal(modalElement);
                }}

                var fullscreenCanvas = document.getElementById('fullscreenChart');
                var ctx = fullscreenCanvas.getContext('2d');

                // Destroy existing chart if it exists
                if (chartInstances.fullscreen) {{
                    chartInstances.fullscreen.destroy();
                }}

                // Get the original chart
                var originalChart = chartInstances[modalId];
                if (!originalChart) {{
                    console.error('Chart not found:', modalId);
                    return;
                }}

                // Create new configuration
                var newConfig = {{
                    type: originalChart.config.type,
                    data: JSON.parse(JSON.stringify(originalChart.config.data)),
                    options: JSON.parse(JSON.stringify(originalChart.config.options))
                }};

                // Adjust options for fullscreen
                newConfig.options.responsive = true;
                newConfig.options.maintainAspectRatio = false;

                // Add click handler for pie chart in fullscreen
                if (modalId === 'statusChart') {{
                    newConfig.options.onClick = function(evt, elements) {{
                        if (elements.length > 0) {{
                            var chartElement = elements[0];
                            var label = this.data.labels[chartElement.index];
                            var status = label.toLowerCase();
                            window.location.href = 'status_' + status + '.html';
                        }}
                    }};
                }}

                // Create new chart in fullscreen canvas
                chartInstances.fullscreen = new Chart(ctx, newConfig);

                // Update modal title with more descriptive text
                var titleMap = {{
                    'statusChart': 'Execution Status Summary',
                    'timeChart': 'Execution Time per Node',
                    'sizeChart': 'Log Size per Node'
                }};
                document.getElementById('fullscreenModalLabel').textContent = titleMap[modalId] || 'Chart View';

                fullscreenModal.show();
            }} else {{
                // Handle regular modals (like firmware)
                console.log('Handling regular modal');
                var modalElement = document.getElementById(modalId);
                console.log('Modal element:', modalElement);
                if (modalElement) {{
                    try {{
                        var modal = new bootstrap.Modal(modalElement);
                        console.log('Modal instance created');
                        modal.show();
                        console.log('Modal show called');
                    }} catch (error) {{
                        console.error('Error creating/showing modal:', error);
                    }}
                }} else {{
                    console.error('Modal element not found:', modalId);
                }}
            }}
        }}

        // Function to handle window resize
        function handleResize() {{
            if (chartInstances.fullscreen) {{
                chartInstances.fullscreen.resize();
            }}
        }}

        // Add resize event listener
        window.addEventListener('resize', handleResize);

        const statusPercentagePlugin = {{
            id: 'statusPercentagePlugin',
            afterDatasetsDraw(chart, _args, pluginOptions) {{
                const dataset = chart.data.datasets[0];
                if (!dataset || dataset.data.length === 0) {{
                    return;
                }}
                const meta = chart.getDatasetMeta(0);
                if (!meta || !meta.data || chart.config.type !== 'pie') {{
                    return;
                }}
                const total = dataset.data.reduce((sum, value) => {{
                    const numericValue = typeof value === 'number' ? value : Number(value);
                    return sum + (Number.isFinite(numericValue) ? numericValue : 0);
                }}, 0);
                if (!total) {{
                    return;
                }}

                const cfg = Object.assign({{
                    labelOffset: 24,
                    leaderLineLength: 26,
                    textPadding: 6,
                    labelBackgroundPadding: 4,
                    canvasPadding: 8,
                    drawLabelBackground: true,
                    backgroundColor: '#ffffff',
                    backgroundBorderColor: '#ced4da',
                    lineColor: '#495057',
                    textColor: '#212529',
                    lineWidth: 1,
                    decimals: 1,
                    font: '12px "Segoe UI", system-ui, -apple-system, sans-serif'
                }}, pluginOptions || {{}});

                const ctx = chart.ctx;
                ctx.save();
                ctx.font = cfg.font;
                ctx.fillStyle = cfg.textColor;
                ctx.strokeStyle = cfg.lineColor;
                ctx.lineWidth = cfg.lineWidth;

                meta.data.forEach((arc, index) => {{
                    const rawValue = typeof dataset.data[index] === 'number'
                        ? dataset.data[index]
                        : Number(dataset.data[index]);
                    if (!rawValue || !Number.isFinite(rawValue)) {{
                        return;
                    }}

                    const angle = (arc.startAngle + arc.endAngle) / 2;
                    const sinAngle = Math.sin(angle);
                    const cosAngle = Math.cos(angle);
                    const radius = arc.outerRadius;

                    const percentValue = (rawValue / total) * 100;
                    const formattedPercent = (percentValue % 1 === 0)
                        ? percentValue.toFixed(0)
                        : percentValue.toFixed(cfg.decimals);
                    const text = `${{formattedPercent}}%`;
                    const metrics = ctx.measureText(text);
                    const textWidth = metrics.width;
                    const textHeight = (metrics.actualBoundingBoxAscent || 8) + (metrics.actualBoundingBoxDescent || 2);
                    const totalPadding = cfg.labelBackgroundPadding * 2;
                    const chartArea = chart.chartArea || {{
                        left: 0,
                        right: chart.width,
                        top: 0,
                        bottom: chart.height
                    }};
                    const isRightSide = cosAngle >= 0;

                    const startX = arc.x + cosAngle * radius * 0.92;
                    const startY = arc.y + sinAngle * radius * 0.92;
                    const elbowX = arc.x + cosAngle * (radius + cfg.labelOffset);
                    const elbowY = arc.y + sinAngle * (radius + cfg.labelOffset);

                    const minX = chartArea.left + cfg.canvasPadding;
                    const maxX = chartArea.right - textWidth - cfg.canvasPadding;
                    const minY = chartArea.top + cfg.canvasPadding + textHeight / 2;
                    const maxY = chartArea.bottom - cfg.canvasPadding - textHeight / 2;
                    let textY = Math.min(Math.max(elbowY, minY), maxY);

                    const leaderTargetX = elbowX + (isRightSide ? cfg.leaderLineLength : -cfg.leaderLineLength);
                    let textX = isRightSide
                        ? leaderTargetX + cfg.textPadding
                        : leaderTargetX - cfg.textPadding - textWidth;
                    textX = Math.min(Math.max(textX, minX), maxX);

                    const horizontalEndX = isRightSide
                        ? Math.min(textX - cfg.textPadding, chartArea.right - cfg.canvasPadding)
                        : Math.max(textX + textWidth + cfg.textPadding, chartArea.left + cfg.canvasPadding);

                    ctx.beginPath();
                    ctx.moveTo(startX, startY);
                    ctx.lineTo(elbowX, textY);
                    ctx.lineTo(horizontalEndX, textY);
                    ctx.stroke();

                    if (cfg.drawLabelBackground) {{
                        ctx.save();
                        ctx.fillStyle = cfg.backgroundColor;
                        ctx.strokeStyle = cfg.backgroundBorderColor;
                        ctx.lineWidth = 1;
                        ctx.beginPath();
                        ctx.rect(
                            textX - cfg.labelBackgroundPadding,
                            textY - textHeight / 2 - cfg.labelBackgroundPadding,
                            textWidth + totalPadding,
                            textHeight + totalPadding
                        );
                        ctx.fill();
                        ctx.stroke();
                        ctx.restore();
                    }}

                    ctx.textAlign = 'left';
                    ctx.textBaseline = 'middle';
                    ctx.fillStyle = cfg.textColor;
                    ctx.fillText(text, textX, textY);
                }});

                ctx.restore();
            }}
        }};

        var ctxStatus = document.getElementById('statusChart').getContext('2d');
        var statusChart = new Chart(ctxStatus,{{
            type:'pie',
            data:{{
            labels:{status_labels_json},
            datasets:[{{
                data:{status_counts_json},
                backgroundColor:{status_colors_json},
                borderWidth:1
            }}]
            }},
            options:{{
            responsive:true,
            plugins:{{
                tooltip:{{
                callbacks:{{
                    label:function(ctx){{
                    var label = ctx.label||'';
                    var value = ctx.parsed||0;
                    return label+': '+value;
                    }}
                }}
                }},
                statusPercentagePlugin:{{
                    labelOffset: 28,
                    leaderLineLength: 30,
                    textPadding: 6,
                    decimals: 1,
                    lineColor: '#343a40',
                    textColor: '#212529'
                }}
            }},
            onClick: function(evt, elements) {{
                if (elements.length > 0) {{
                    var chartElement = elements[0];
                    var label = this.data.labels[chartElement.index];
                    var status = label.toLowerCase();
                    window.location.href = 'status_' + status + '.html';
                }}
            }}
            }},
            plugins: [statusPercentagePlugin]
        }});
        chartInstances.statusChart = statusChart;

        // Store tooltip labels for time chart
        var timeTooltipLabels = {time_tooltip_labels_json};

        var ctxTime = document.getElementById('timeChart').getContext('2d');
        var timeChart = new Chart(ctxTime,{{
            type: 'bar',
            data: {chart_data_time_json},
            options: {{
                responsive: true,
                interaction: {{
                    mode: 'index',
                    intersect: false
                }},
                plugins: {{
                    tooltip: {{
                        enabled: true,
                        callbacks: {{
                            title: function(tooltipItems) {{
                                return tooltipItems[0].label;
                            }},
                            label: function(context) {{
                                var label = context.dataset.label || '';
                                var value = context.parsed.y;
                                if (value > 0) {{
                                    return label + ': ' + value.toFixed(2) + ' minutes';
                                }}
                                return null;
                            }},
                            footer: function(tooltipItems) {{
                                var total = tooltipItems.reduce((sum, item) => sum + item.parsed.y, 0);
                                return 'Total: ' + total.toFixed(2) + ' minutes';
                            }}
                        }}
                    }}
                }},
                scales: {{
                    x: {{
                        stacked: true,
                        title: {{
                            display: true,
                            text: 'Nodes'
                        }},
                        ticks: {{
                            autoSkip: false,
                            maxRotation: 90,
                            minRotation: 45
                        }}
                    }},
                    y: {{
                        stacked: true,
                        beginAtZero: true,
                        title: {{
                            display: true,
                            text: 'Time (minutes)'
                        }}
                    }}
                }}
            }}
        }});
        chartInstances.timeChart = timeChart;

        var ctxSize = document.getElementById('sizeChart').getContext('2d');
        var sizeChart = new Chart(ctxSize,{{
            type:'bar',
            data:{{
            labels:{size_labels_json},
            datasets:[{{
                label:'Log Size (MB)',
                data:{size_data_json},
                backgroundColor:'#28a745',
                borderColor:'#28a745',
                borderWidth:1
            }}]
            }},
            options:{{
            responsive:true,
            interaction: {{
                mode: 'index',
                intersect: false
            }},
            plugins:{{
                tooltip:{{
                    enabled: true,
                    callbacks:{{
                        label:function(context){{
                            var size = context.parsed.y;
                            if (size >= 1024) {{
                                return 'Log Size: ' + (size/1024).toFixed(2) + ' GB';
                            }} else {{
                                return 'Log Size: ' + size.toFixed(2) + ' MB';
                            }}
                        }}
                    }}
                }}
            }},
            scales:{{
                y:{{
                    beginAtZero:true,
                    title:{{
                        display:true,
                        text:'Size (MB)'
                    }}
                }},
                x:{{
                    title:{{
                        display:true,
                        text:'Nodes'
                    }},
                    ticks:{{
                        autoSkip:false,
                        maxRotation:90,
                        minRotation:45
                    }}
                }}
            }}
            }}
        }});
        chartInstances.sizeChart = sizeChart;
        </script>

        <style>
        .chart-container {{
            position: relative;
            margin-bottom: 2rem;
            box-shadow: none !important;
        }}
        .chart-container.pie-chart {{
            max-width: 300px;
            margin: 0 auto 2rem auto;
        }}
        .chart-container button {{
            position: absolute;
            top: 0;
            right: 0;
            z-index: 1;
        }}
        #fullscreenModal .modal-body {{
            padding: 1rem;
            height: calc(100vh - 120px);
        }}
        #fullscreenChart {{
            width: 100% !important;
            height: 100% !important;
        }}
        </style>
        """

        await self._generate_status_detail_pages()

        # Generate timing breakdown table
        timing_breakdown = await self._generate_timing_breakdown_table(
            self.total_runtime
        )

        content = f"""
        <div class="row">
            <div class="col-xl-2 col-lg-2 col-md-3">
                {charts_script}
            </div>
            <div class="col-xl-10 col-lg-10 col-md-9">
                {node_table}
                {timing_breakdown}
            </div>
        </div>

        <style>
        .details-btn-topright {{
            position: absolute;
            top: 0.25em;
            right: 0.5em;
            z-index: 2;
        }}
        </style>
        """

        index_html_path = self.report_dir / "index.html"

        self._finalize_page(
            target_file=index_html_path,
            page_title="NVDebug Top-Level Report",
            main_content=content,
            breadcrumb_links=[],  # top-level usually doesn't have breadcrumbs
            breadcrumb_active_text="",
            modals=modals,  # Pass the modals list we've been building
        )
        await self._log("DEBUG", "Generated top-level report.")

    async def _generate_status_detail_pages(self) -> None:
        """
        Generate status detail pages.

        The implementation uses current instance state to generate status detail
        pages. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Raises:
            FileNotFoundError: If a status entry names a node outside the
                authorized report input roster.
        """
        # Get unique statuses and their counts
        status_counts = {}
        node_input_paths = {
            node_path.name: node_path for node_path in self._iter_node_directories()
        }
        for entry in self.global_execution_entries:
            status = entry["Execution Status"]
            status_counts[status] = status_counts.get(status, 0) + 1

        for status, count in status_counts.items():
            # Skip N/A status page if hide_na_status is True
            if self.hide_na_status and status.lower() == self.na_string.lower():
                continue

            # Skip if no entries for this status
            if count == 0:
                continue

            status_normalized = re.sub(r"\s+", "_", status.lower())
            status_filename = f"status_{status_normalized}.html"
            status_file_path = self.report_dir / status_filename

            filtered_entries = [
                entry
                for entry in self.global_execution_entries
                if entry["Execution Status"] == status
            ]

            table_html = f"""
            <h2>Execution Details for Status: {escape(status)}</h2>
            <table class='table table-bordered table-shadow'>
            <thead class='table-dark'>
                <tr>
                <th>Node Name</th>
                <th>Collector Group</th>
                <th>Collector ID</th>
                <th>Collector Name</th>
                <th>Collector Exec Time</th>
                <th>Failure Category</th>
                <th>Log Path(s)</th>
                </tr>
            </thead>
            <tbody>
            """

            modals_for_status = []
            for idx, entry in enumerate(filtered_entries):
                node_name = entry["Node Name"]
                log_paths = entry["Log Path(s)"]
                node_path = node_input_paths.get(node_name)
                if node_path is None:
                    raise FileNotFoundError(
                        f"Status detail source is unavailable: {node_name}"
                    )

                modal_id_prefix = f"logModal_status_{status_normalized}_{idx}"
                link_objs = []
                for lp in log_paths:
                    # If it matches an informational pattern, treat raw
                    if any(
                        re.search(pat, lp, re.IGNORECASE)
                        for pat in self.informational_patterns
                    ):
                        link_objs.append(f"{escape(lp)}")
                    else:
                        # Pass from_status_page=True to properly handle paths
                        link_objs.extend(
                            await self._build_file_links(
                                node_path, lp, from_status_page=True
                            )
                        )

                log_path_display = self._render_link_list_with_modal(
                    link_objs,
                    self.log_path_threshold,
                    f"{modal_id_prefix}_modal_{len(modals_for_status)}",
                    "Remaining Log Files",
                    modals_for_status,
                )

                table_html += f"""
                <tr>
                <td>{escape(node_name)}</td>
                <td>{escape(entry["Collector Group"])}</td>
                <td>{escape(entry["Collector ID"])}</td>
                <td>{escape(entry["Collector Name"])}</td>
                <td>{escape(entry["Collector Exec Time"])}</td>
                <td>{escape(str(entry.get("Failure Category") or "N/A"))}</td>
                <td>{log_path_display}</td>
                </tr>
                """

            table_html += "</tbody></table>"

            self._finalize_page(
                target_file=status_file_path,
                page_title=f"Status Detail: {status}",
                main_content=table_html,
                breadcrumb_links=[("Home", "index.html")],
                breadcrumb_active_text=f"Status: {status}",
                modals=modals_for_status,
            )
            await self._log("DEBUG", f"Generated status detail page: {status_filename}")

    async def _generate_global_file_map(self) -> None:
        """
        Generate global file map.

        The implementation uses current instance state to generate global file
        map. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.
        """
        tree_data = {}
        for item in self.global_file_map_data:
            node_val = item["Node Name"]
            group_val = item["Collector Group"]
            cid_val = item["Collector ID/Name"]
            file_val = item["File Path"]
            base_link = item["Link"]
            link_val = self._encoded_relative_report_link(node_val, base_link)

            parts = []
            if node_val and node_val != "N/A":
                parts.append(node_val)
            if group_val and group_val != "N/A":
                parts.append(group_val)
            if cid_val and cid_val != "N/A":
                parts.append(cid_val)
            if file_val:
                sub_parts = file_val.split("/")
                parts.extend(sub_parts)

            current = tree_data
            for p in parts[:-1]:
                current = current.setdefault(p, {})
            current[parts[-1]] = link_val

        # Count statistics
        total_files = len(self.global_file_map_data)
        nodes_set = set(item["Node Name"] for item in self.global_file_map_data)
        groups_set = set(item["Collector Group"] for item in self.global_file_map_data)

        table_html = f"""
        <div class="mb-4">
            <div class="row">
                <div class="col-md-4">
                    <div class="card text-white bg-primary mb-3">
                        <div class="card-body text-center">
                            <h5 class="card-title">Total Files</h5>
                            <p class="display-4">{total_files}</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-white bg-success mb-3">
                        <div class="card-body text-center">
                            <h5 class="card-title">DUTs</h5>
                            <p class="display-4">{len(nodes_set)}</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-white bg-info mb-3">
                        <div class="card-body text-center">
                            <h5 class="card-title">Collector Groups</h5>
                            <p class="display-4">{len(groups_set)}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <h2>Global File Map - Table View</h2>
        <div class="mb-3 row">
            <div class="col-md-6">
                <label for="fileMapSearch" class="form-label">Search Files</label>
                <input type="text" class="form-control" id="fileMapSearch" placeholder="Filter by file name, path, collector, or DUT..." onkeyup="filterFileMap()">
            </div>
            <div class="col-md-3">
                <label for="dutFilter" class="form-label">Filter by DUT</label>
                <select class="form-select" id="dutFilter" onchange="filterFileMap()">
                    <option value="">All DUTs</option>
                    {"".join(f'<option value="{self._escape_html_text(node)}">{self._escape_html_text(node)}</option>' for node in sorted(nodes_set))}
                </select>
            </div>
            <div class="col-md-3">
                <label for="groupFilter" class="form-label">Filter by Group</label>
                <select class="form-select" id="groupFilter" onchange="filterFileMap()">
                    <option value="">All Groups</option>
                    {"".join(f'<option value="{self._escape_html_text(group)}">{self._escape_html_text(group)}</option>' for group in sorted(groups_set))}
                </select>
            </div>
        </div>
        <div id="fileMapStats" class="alert alert-info mb-3">
            Showing <span id="visibleCount">{total_files}</span> of {total_files} files
        </div>
        <table class='table table-striped table-bordered table-shadow table-hover table-sm' id="fileMapTable">
        <thead class='table-dark'>
            <tr>
                <th onclick="sortFileMapTable(0)" style="cursor: pointer;">Node Name ▼</th>
                <th onclick="sortFileMapTable(1)" style="cursor: pointer;">Collector Group ▼</th>
                <th onclick="sortFileMapTable(2)" style="cursor: pointer;">Collector ID/Name ▼</th>
                <th onclick="sortFileMapTable(3)" style="cursor: pointer;">File Path ▼</th>
            </tr>
        </thead>
        <tbody>
        """
        file_map_links: List[str] = []
        for row in self.global_file_map_data:

            node_val = row["Node Name"]
            group_val = row["Collector Group"]
            cid_val = row["Collector ID/Name"]
            file_val = row["File Path"]
            base_link = row["Link"]
            link_val = self._encoded_relative_report_link(node_val, base_link)
            if link_val is None:
                file_link_control = (
                    '<span class="text-muted file-link-disabled">'
                    f"{self._escape_html_text(file_val)}</span>"
                )
            else:
                link_index = len(file_map_links)
                file_map_links.append(link_val)
                file_link_control = f"""
                  <button type="button" class="btn btn-link p-0 file-link"
                          data-file-index="{link_index}">
                    {self._escape_html_text(file_val)}
                  </button>
                """
            table_html += f"""
            <tr>
            <td>{self._escape_html_text(node_val)}</td>
            <td>{self._escape_html_text(group_val)}</td>
            <td>{self._escape_html_text(cid_val)}</td>
            <td>
              {file_link_control}
            </td>
            </tr>
            """
        table_html += "</tbody></table>"

        def build_tree_html(obj):
            """
            Build tree HTML.

            The implementation uses ``obj`` to build tree HTML.

            Args:
                obj: Object whose ``keys`` state is read while performing
                    tree HTML.

            Returns:
                The validated ``html``.
            """
            html = "<ul>"
            for k in sorted(obj.keys()):
                val_obj = obj[k]
                if isinstance(val_obj, dict):
                    html += (
                        '<li class="folder"><span>'
                        f"{self._escape_html_text(k)}</span>"
                    )
                    html += build_tree_html(val_obj)
                    html += "</li>"
                elif val_obj is None:
                    html += (
                        '<li class="file"><span class="text-muted">'
                        f"{self._escape_html_text(k)}</span></li>"
                    )
                else:
                    html += (
                        '<li class="file">'
                        f'<a href="{self._escape_html_text(val_obj)}">'
                        f"{self._escape_html_text(k)}</a></li>"
                    )
            html += "</ul>"
            return html

        tree_html = """
        <h2>Global File Map - Tree View</h2>
        <p class="text-muted">Expandable tree view of all collected files organized by DUT, collector group, and collector.</p>
        <div id="treeview">
        """
        tree_html += build_tree_html(tree_data)
        tree_html += "</div>"

        # Add JavaScript for filtering and sorting
        file_map_link_data = (
            '<script id="fileMapLinks" type="application/json">'
            f"{self._json_for_script(file_map_links)}"
            "</script>"
        )
        js_script = (
            file_map_link_data
            + """
        <script>
        // File map filtering
        function filterFileMap() {
            const searchValue = document.getElementById('fileMapSearch').value.toLowerCase();
            const dutFilter = document.getElementById('dutFilter').value;
            const groupFilter = document.getElementById('groupFilter').value;
            const table = document.getElementById('fileMapTable');
            const rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
            let visibleCount = 0;

            for (let row of rows) {
                const cells = row.getElementsByTagName('td');
                const node = cells[0].textContent;
                const group = cells[1].textContent;
                const collector = cells[2].textContent;
                const filePath = cells[3].textContent;

                const matchesSearch = searchValue === '' ||
                    node.toLowerCase().includes(searchValue) ||
                    group.toLowerCase().includes(searchValue) ||
                    collector.toLowerCase().includes(searchValue) ||
                    filePath.toLowerCase().includes(searchValue);

                const matchesDut = dutFilter === '' || node === dutFilter;
                const matchesGroup = groupFilter === '' || group === groupFilter;

                if (matchesSearch && matchesDut && matchesGroup) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            }

            document.getElementById('visibleCount').textContent = visibleCount;
        }

        // Table sorting
        let sortDirection = {};
        function sortFileMapTable(columnIndex) {
            const table = document.getElementById('fileMapTable');
            const tbody = table.getElementsByTagName('tbody')[0];
            const rows = Array.from(tbody.getElementsByTagName('tr'));

            sortDirection[columnIndex] = !sortDirection[columnIndex];
            const isAscending = sortDirection[columnIndex];

            rows.sort(function(a, b) {
                const aValue = a.getElementsByTagName('td')[columnIndex].textContent;
                const bValue = b.getElementsByTagName('td')[columnIndex].textContent;

                if (aValue < bValue) return isAscending ? -1 : 1;
                if (aValue > bValue) return isAscending ? 1 : -1;
                return 0;
            });

            tbody.innerHTML = '';
            rows.forEach(function(row) { tbody.appendChild(row); });
        }

        // Tree view expand/collapse
        document.addEventListener('DOMContentLoaded', function() {
            const linkDataElement = document.getElementById('fileMapLinks');
            let fileMapLinks = [];
            if (linkDataElement) {
                try {
                    const parsedLinks = JSON.parse(linkDataElement.textContent);
                    if (Array.isArray(parsedLinks)) fileMapLinks = parsedLinks;
                } catch (_error) {
                    fileMapLinks = [];
                }
            }
            document.querySelectorAll('.file-link[data-file-index]').forEach(function(button) {
                const index = Number(button.getAttribute('data-file-index'));
                const target = Number.isSafeInteger(index) ? fileMapLinks[index] : null;
                if (typeof target !== 'string') return;
                button.addEventListener('click', function() {
                    window.location.assign(target);
                });
            });

            console.log('Setting up tree view...');

            // Get the root UL (direct child of #treeview)
            const rootUl = document.querySelector('#treeview > ul');

            // Get all folders
            const folders = document.querySelectorAll('#treeview .folder > span');
            console.log('Found folders:', folders.length);

            folders.forEach(function(folder, index) {
                // Store original text without icon
                const originalText = folder.textContent.trim();
                folder.setAttribute('data-original-text', originalText);

                // Find the UL - it should be the next sibling
                let ul = folder.nextElementSibling;
                // Skip text nodes
                while (ul && ul.nodeType !== 1) {
                    ul = ul.nextSibling;
                }

                // Check if this is a top-level DUT folder (parent is root UL)
                const isTopLevel = folder.parentElement.parentElement === rootUl;

                if (ul && ul.tagName === 'UL') {
                    if (isTopLevel) {
                        // Top-level DUT folders: expand by default
                        ul.style.display = 'block';
                        folder.textContent = '📂 ' + originalText;
                        console.log('Folder', index, ':', originalText, '- Top level, expanded');
                    } else {
                        // Nested folders: collapse by default
                        ul.style.display = 'none';
                        folder.textContent = '📁 ' + originalText;
                        console.log('Folder', index, ':', originalText, '- Nested, collapsed');
                    }
                } else {
                    console.log('Folder', index, ':', originalText, '- NO UL found!', ul);
                }

                folder.style.cursor = 'pointer';
                folder.style.fontWeight = 'bold';

                // Add click handler
                folder.addEventListener('click', function(e) {
                    e.stopPropagation(); // Prevent event bubbling

                    let ul = this.nextElementSibling;
                    // Skip text nodes
                    while (ul && ul.nodeType !== 1) {
                        ul = ul.nextSibling;
                    }

                    if (ul && ul.tagName === 'UL') {
                        const originalText = this.getAttribute('data-original-text');
                        if (ul.style.display === 'none' || ul.style.display === '') {
                            ul.style.display = 'block';
                            this.textContent = '📂 ' + originalText;
                        } else {
                            ul.style.display = 'none';
                            this.textContent = '📁 ' + originalText;
                        }
                    }
                });
            });

            // Add file icons
            const files = document.querySelectorAll('#treeview .file a');
            files.forEach(function(link) {
                const currentText = link.textContent.trim();
                if (!currentText.startsWith('📄')) {
                    link.textContent = '📄 ' + currentText;
                }
            });
        });
        </script>
        <style>
        #treeview ul {
            list-style-type: none;
            padding-left: 20px;
            margin-left: 0;
        }
        #treeview .folder > span {
            color: #0056b3;
            user-select: none; /* Prevent text selection on click */
        }
        #treeview .folder > span:hover {
            color: #003d82;
        }
        #treeview .file {
            color: #333;
            padding: 2px 0;
            margin-left: 0;
        }
        #treeview .file a {
            text-decoration: none;
            color: #0066cc;
        }
        #treeview .file a:hover {
            text-decoration: underline;
            color: #0052a3;
        }
        #treeview > ul {
            padding-left: 0; /* Remove padding from root ul */
        }
        </style>
        """
        )

        content = table_html + tree_html + js_script
        file_map_html_path = self.report_dir / "file_map.html"
        self._write_html_report(file_map_html_path, "Global File Map", content)

    async def _parse_runtime_output(self, node_path: Path) -> Dict[str, str]:
        """
        Parse runtime output.

        Check for metadata.json in both metadata and .metadata directories.

        Args:
            node_path: filesystem location used as the node path for this
                operation.

        Returns:
            A mapping containing runtime output.
        """
        details = {
            "Model": "Unknown",
            "Partno": "Unknown",
            "Serialno": "Unknown",
        }

        # Check for metadata.json in both metadata and .metadata directories
        meta_json = None
        for metadata_dir_name in ["metadata", ".metadata"]:
            potential_path = node_path / metadata_dir_name / "metadata.json"
            if potential_path.is_file():
                meta_json = potential_path
                break

        runtime_txt = node_path / "nvdebug_runtime_output.txt"

        # metadata.json
        if meta_json:
            try:
                with meta_json.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                payload = data.get("payload", {})
                details["Model"] = payload.get("PlatformModel", "Unknown").strip()
                details["Partno"] = payload.get("PartNumber", "Unknown").strip()
                details["Serialno"] = payload.get("SerialNumber", "Unknown").strip()

                # Handle collectors section - support both legacy and new formats
                collectors = data.get("collectors", {})
                if collectors:
                    collector_list = []
                    for group, collector_data in collectors.items():
                        if isinstance(collector_data, list):
                            # Legacy format: {"Redfish": ["r1", "r2", ...]}
                            collector_list.extend(collector_data)
                        elif isinstance(collector_data, dict):
                            # New format: {"R8": {"total_time": 0.31, "status": "completed", ...}}
                            collector_list.append(group)
                    if collector_list:
                        details["Collectors"] = ", ".join(collector_list)

                return details
            except ReportInputSafetyError:
                raise
            except Exception as e:
                await self._log("ERROR", f"Error reading {meta_json}: {e}")

        # fallback runtime
        if self._report_input_is_file(runtime_txt):
            try:
                for line_str in self._read_report_text(runtime_txt).splitlines():
                    match_line = re.search(
                        r"Identified system as Model:\s*(?P<model>[^,]+),\s*Partno:\s*(?P<part>[^,]+),\s*Serialno:\s*(?P<ser>\d+)",
                        line_str,
                    )
                    if match_line:
                        details["Model"] = match_line.group("model").strip()
                        details["Partno"] = match_line.group("part").strip()
                        details["Serialno"] = match_line.group("ser").strip()
                        return details
            except ReportInputSafetyError:
                raise
            except Exception as e:
                await self._log("ERROR", f"Error reading {runtime_txt}: {e}")
        await self._log("DEBUG", f"No system details found for {node_path.name}")
        return details

    def _get_collector_groups(self, node_path: Path) -> List[Path]:
        """
        Identifies collector-group directories for a node.

        Returns groups that have collected data (either from directory contents
        or JSON metadata) to avoid 404 errors in navigation.

        Args:
            node_path: filesystem location used as the node path for this
                operation.

        Returns:
            The validated ``result``.
        """
        excluded = self.excluded_collector_groups
        node_entries = self._walk_report_inputs(node_path, recursive=False)
        found_dirs = [
            entry.path
            for entry in node_entries
            if entry.is_dir and entry.path.name not in excluded
        ]
        result = []
        node_name = node_path.name

        # Get the node's collector JSON data to check for actual collections
        node_json_data = self.node_collector_json.get(node_name, {})

        # Include known collector groups that have collected data (prioritize JSON metadata)
        for k_lc in self.known_collector_groups.keys():
            group_path = node_path / k_lc

            # Check if this group has any collected data
            group_has_data = False

            # First priority: Check if there's JSON metadata for this group with meaningful statuses
            group_json = node_json_data.get(k_lc, node_json_data.get(k_lc.lower(), {}))
            if group_json:
                # Check if any collectors have meaningful statuses (not empty or "NotRan")
                for collector_data in group_json.values():
                    status = collector_data.get("status", "")
                    if status and status.lower() not in ["", "notran", "n/a"]:
                        group_has_data = True
                        break

            # Second priority: Check if the directory exists and has files (actual collected data)
            if (
                not group_has_data
                and self._report_input_is_dir(group_path)
                and bool(self._walk_report_inputs(group_path, recursive=False))
            ):
                group_has_data = True

            if group_has_data:
                result.append(group_path)

        # Include any other directories that aren't known collector groups
        # But only if they contain files (to avoid empty directory reports)
        known_lowers = set(self.known_collector_groups.keys())
        for d in found_dirs:
            if d.name.lower() not in known_lowers:
                # Only include directories that actually contain files
                if self._walk_report_inputs(d, recursive=False):
                    result.append(d)
        return result

    def _parse_collector_info_from_path(self, lp: str) -> Tuple[str, str, str]:
        """
        Parse collector information from path.

        Supports both legacy format and new format where service name comes from
        parent directory. Prioritizes collector ID prefix over directory name
        for proper group classification.

        Args:
            lp: Text supplied as lp in the format accepted by this function.

        Returns:
            A tuple containing ``cg``, ``cid``, and ``cname`` in that order.
        """
        normalized = lp.lstrip("/")
        parts = normalized.split("/")

        if len(parts) >= 2:
            # Get the service name from parent directory (e.g., "redfish" from "redfish/R8_firmware_inventory")
            service_name = parts[-2].capitalize()  # Convert "redfish" to "Redfish"

            last_part = parts[-1]
            if "." in last_part:
                # Try to parse from the directory name first
                cg, cid, cname = self._parse_from_name(parts[-2])
                if cg == "N/A" and cid != "N/A":
                    # New format: service name comes from parent directory
                    cg = service_name
                if (cid, cname) == ("N/A", "N/A"):
                    cg, cid, cname = self._parse_from_name(last_part.split(".", 1)[0])
                    if cg == "N/A" and cid != "N/A":
                        cg = service_name
                if (cg, cid, cname) == ("N/A", "N/A", "N/A"):
                    cg, cid, cname = self._parse_from_name(last_part.split(".", 1)[0])
                    if cg == "N/A" and cid != "N/A":
                        cg = service_name

                # CRITICAL FIX: Override group classification based on collector ID prefix
                if cid != "N/A" and len(cid) > 0:
                    correct_group = self._get_group_from_collector_id(cid)
                    if correct_group != "N/A":
                        cg = correct_group

                return (cg, cid, cname)
            else:
                cg, cid, cname = self._parse_from_name(last_part)
                if cg == "N/A" and cid != "N/A":
                    cg = service_name

                # CRITICAL FIX: Override group classification based on collector ID prefix
                if cid != "N/A" and len(cid) > 0:
                    correct_group = self._get_group_from_collector_id(cid)
                    if correct_group != "N/A":
                        cg = correct_group

                return (cg, cid, cname)
        else:
            single_part = parts[-1]
            if "." in single_part:
                cg, cid, cname = self._parse_from_name(single_part.split(".", 1)[0])
                # CRITICAL FIX: Override group classification based on collector ID prefix
                if cid != "N/A" and len(cid) > 0:
                    correct_group = self._get_group_from_collector_id(cid)
                    if correct_group != "N/A":
                        cg = correct_group
                return (cg, cid, cname)
            else:
                cg, cid, cname = self._parse_from_name(single_part)
                # CRITICAL FIX: Override group classification based on collector ID prefix
                if cid != "N/A" and len(cid) > 0:
                    correct_group = self._get_group_from_collector_id(cid)
                    if correct_group != "N/A":
                        cg = correct_group
                return (cg, cid, cname)

    def _parse_from_name(self, base_name: str) -> Tuple[str, str, str]:
        """
        Parse collector information from directory name.

        Supports both legacy format (Redfish_R8_firmware_inventory) and new
        format (R8_firmware_inventory).

        Args:
            base_name: Stable base name used for lookup and operator-facing
                diagnostics.

        Returns:
            A tuple containing the collector group, collector identifier, and
            display name.
        """
        cparts = base_name.split("_")

        # Check if this is the legacy format (service_collector_id_name)
        if len(cparts) >= 3 and cparts[0].lower() in [
            "redfish",
            "host",
            "ipmi",
            "ssh",
            "healthcheck",
        ]:
            # Legacy format: Redfish_R8_firmware_inventory
            service_name = cparts[0]
            collector_id = cparts[1]
            collector_name = "_".join(cparts[2:])
            return (service_name, collector_id, collector_name)
        elif len(cparts) >= 2:
            # New format: R8_firmware_inventory (service name comes from parent directory)
            collector_id = cparts[0]
            collector_name = "_".join(cparts[1:])
            # We'll need to get the service name from the parent directory context
            return ("N/A", collector_id, collector_name)
        elif len(cparts) == 1:
            return (cparts[0], "N/A", "N/A")
        else:
            return ("N/A", "N/A", "N/A")

    def _parse_collector_info_from_name(
        self, collection_name: str
    ) -> Tuple[str, str, str]:
        """
        Parse collector group, ID, and name from a collection name.

        Returns (group, id, name) tuple.

        Use the orchestrator to get collector information from the actual
        definitions.

        Args:
            collection_name: Stable collection name used for lookup and
                operator-facing diagnostics.

        Returns:
            A tuple containing the collector group, collector identifier, and
            display name.
        """
        if not collection_name:
            return ("N/A", "N/A", "N/A")

        # Use the orchestrator to get collector information from the actual definitions
        if hasattr(self, "orchestrator") and self.orchestrator:
            try:
                all_collectors = self.orchestrator.get_all_collectors()

                # Search for collector by name
                for collector_id, collector_info in all_collectors.items():
                    collector_name = collector_info.get("name", "")
                    if collector_name.lower() == collection_name.lower():
                        group = collector_info.get("group", "N/A")
                        # CRITICAL FIX: Override group classification based on collector ID prefix
                        if collector_id and len(collector_id) > 0:
                            correct_group = self._get_group_from_collector_id(
                                collector_id
                            )
                            if correct_group != "N/A":
                                group = correct_group.lower()
                        return (
                            group.lower(),
                            collector_id.lower(),
                            collector_name,
                        )

                # If not found by name, try to find by ID (collection name might be the ID)
                if collection_name.upper() in all_collectors:
                    collector_info = all_collectors[collection_name.upper()]
                    group = collector_info.get("group", "N/A")
                    # CRITICAL FIX: Override group classification based on collector ID prefix
                    if collection_name and len(collection_name) > 0:
                        correct_group = self._get_group_from_collector_id(
                            collection_name
                        )
                        if correct_group != "N/A":
                            group = correct_group.lower()
                    collector_name = collector_info.get("name", collection_name)
                    return (
                        group.lower(),
                        collection_name.lower(),
                        collector_name,
                    )

            except ReportInputSafetyError:
                raise
            except Exception as e:
                # Log error but continue with fallback
                print(f"Warning: Could not get collector info from orchestrator: {e}")

        # If orchestrator is not available, try to parse from collection name
        # CRITICAL FIX: Try to extract collector ID from collection name and use prefix mapping
        cg, cid, cname = self._parse_from_name(collection_name)
        if cid != "N/A" and len(cid) > 0:
            correct_group = self._get_group_from_collector_id(cid)
            if correct_group != "N/A":
                cg = correct_group
        return (cg, cid, cname)

    def _file_view_renderer(self) -> HTMLReportFileView:
        """
        Bind the synchronous file-view boundary to current service state.

        After applying local validation, the function forwards current instance
        state to ``HTMLReportFileView`` and preserves its return and exception
        contract.

        Returns:
            A ``HTMLReportFileView`` representing file view renderer.
        """

        return HTMLReportFileView(
            root_dir=self.root_dir,
            report_dir=self.report_dir,
            max_parseable_file_size=self.max_parseable_file_size,
            log_files_with_viewer=self.log_files_with_viewer,
            format_bytes=self._format_bytes,
            logical_relative_path=self._logical_report_input_relative_path,
            get_html_output_path=self._get_html_output_path,
            get_html_output_path_for_file=self._get_html_output_path_for_file,
            write_html_report=self._write_html_report,
            json_tree_html=self._json_tree_html,
            generate_log_viewer=self._generate_log_viewer,
            inspect_input=self._inspect_report_input,
            read_json=self._read_report_json,
            read_text=self._read_report_text,
            fail_closed_exceptions=(ReportInputSafetyError,),
        )

    async def _generate_file_view(
        self, file_path: Path, display_name: str = None
    ) -> str:
        """
        Generate file view.

        The implementation uses ``file_path`` and ``display_name`` to generate
        file view. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            display_name: Stable display name used for lookup and
                operator-facing diagnostics.

        Returns:
            The canonical generate file view text.
        """
        ext = file_path.suffix.lower()
        if ext == ".json":
            return await run_managed_filesystem_operation(
                self._generate_json_view, file_path, display_name
            )
        elif ext in (".txt", ".log"):
            return await self._generate_text_view(file_path, display_name)
        else:
            return await run_managed_filesystem_operation(
                self._generate_download_view, file_path, display_name
            )

    def _generate_download_view(
        self, file_path: Path, display_name: str = None, message: str = None
    ) -> str:
        """
        Generates an HTML page that offers a direct download link for files.

        After applying local validation, the function forwards ``file_path``,
        ``display_name``, and ``message`` to ``generate_download_view`` and
        preserves its return and exception contract.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            display_name: Stable display name used for lookup and
                operator-facing diagnostics.
            message: Operator-facing text carried by the reported event or
                failure.

        Returns:
            The canonical generate download view text.
        """
        return self._file_view_renderer().generate_download_view(
            file_path, display_name, message
        )

    def _download_view_if_too_large(
        self, file_path: Path, display_name: str
    ) -> Optional[str]:
        """
        Return the download view if too large.

        After applying local validation, the function forwards ``file_path`` and
        ``display_name`` to ``download_view_if_too_large`` and preserves its
        return and exception contract.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            display_name: Stable display name used for lookup and
                operator-facing diagnostics.

        Returns:
            The canonical download view if too large text, or ``None`` when the
            requested value is unavailable.
        """
        return self._file_view_renderer().download_view_if_too_large(
            file_path, display_name
        )

    def _generate_json_view(self, file_path: Path, display_name: str = None) -> str:
        """
        Generate JSON view.

        After applying local validation, the function forwards ``file_path`` and
        ``display_name`` to ``generate_json_view`` and preserves its return and
        exception contract.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            display_name: Stable display name used for lookup and
                operator-facing diagnostics.

        Returns:
            The canonical generate JSON view text.
        """
        return self._file_view_renderer().generate_json_view(file_path, display_name)

    async def _generate_text_view(
        self, file_path: Path, display_name: str = None
    ) -> str:
        """
        Generate text view.

        The implementation uses ``file_path`` and ``display_name`` to generate
        text view. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            display_name: Stable display name used for lookup and
                operator-facing diagnostics.

        Returns:
            The canonical generate text view text.
        """
        renderer = self._file_view_renderer()
        prepared = await run_managed_filesystem_operation(
            renderer.prepare_text_view,
            file_path,
            display_name,
        )
        if prepared.read_error is not None:
            await self._log(
                "ERROR", f"Error reading {file_path}: {prepared.read_error}"
            )
        if prepared.link is not None:
            return prepared.link
        result = await run_managed_filesystem_operation(
            renderer.render_text_view, file_path, prepared
        )
        return result.link

    @staticmethod
    def _escape_shared_regex_literal(value: str) -> str:
        """
        Escape a literal for both Python and JavaScript regular expressions.

        After applying local validation, the function forwards ``value`` to
        ``escape_shared_regex_literal`` and preserves its return and exception
        contract.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The canonical escape shared regex literal text.
        """
        return escape_shared_regex_literal(value)

    @classmethod
    def _compile_log_format_parser(
        cls, log_format: Any, parser_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Compile a percent-style logging format into shared parser metadata.

        After applying local validation, the function forwards ``log_format``
        and ``parser_name`` to ``compile_log_format_parser`` and preserves its
        return and exception contract.

        Args:
            log_format: Log format consumed while the function attempts to
                compile a percent-style logging format into shared parser
                metadata.
            parser_name: Stable parser name used for lookup and operator-facing
                diagnostics.

        Returns:
            A mapping containing compile log format parser, or ``None`` when the
            requested value is unavailable.
        """
        return compile_log_format_parser(log_format, parser_name)

    @classmethod
    def _canonical_lifecycle_parser(cls) -> Dict[str, Any]:
        """
        Return the strict parser for lifecycle lines that stay canonical.

        After applying local validation, the function forwards current instance
        state to ``canonical_lifecycle_parser`` and preserves its return and
        exception contract.

        Returns:
            A mapping containing canonical lifecycle parser.
        """
        return canonical_lifecycle_parser()

    def _get_log_parser_specs(self) -> List[Dict[str, Any]]:
        """
        Build parsers for the effective diagnostic and lifecycle formats.

        After applying local validation, the function forwards current instance
        state to ``build_log_parser_specs`` and preserves its return and
        exception contract.

        Returns:
            The log parser specs returned in operation-defined order.
        """
        try:
            log_format = getattr(self.logger, "log_format", None)
        except ReportInputSafetyError:
            raise
        except Exception:
            log_format = None
        return build_log_parser_specs(log_format)

    @staticmethod
    def _parse_log_line(
        line: str, parsers: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Optional[str]]]:
        """
        Parse one line, preferring the match with the richest structure.

        After applying local validation, the function forwards ``line`` and
        ``parsers`` to ``parse_log_line`` and preserves its return and exception
        contract. Parsing or I/O must finish before the validated representation
        is made available to the caller.

        Args:
            line: Text supplied as line in the format accepted by this function.
            parsers: Mapping supplying fields for one line, preferring the match
                with the richest structure.

        Returns:
            A mapping containing log line, or ``None`` when the requested value
            is unavailable.
        """
        return parse_log_line(line, parsers)

    @staticmethod
    def _browser_log_parser_metadata(
        parsers: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Drop Python-only compiled expressions before embedding metadata.

        After applying local validation, the function forwards ``parsers`` to
        ``browser_log_parser_metadata`` and preserves its return and exception
        contract.

        Args:
            parsers: Mapping supplying fields for drop Python-only compiled
                expressions before embedding metadata.

        Returns:
            A mapping containing browser log parser metadata.
        """
        return browser_log_parser_metadata(parsers)

    def _generate_log_viewer(self, text_data: str, display_name: str) -> str:
        """
        Generates an interactive log viewer with filtering and syntax highlighting.

        After applying local validation, the function forwards ``text_data`` and
        ``display_name`` to ``_HTML_LOG_VIEWER.render`` and preserves its return
        and exception contract.

        Args:
            text_data: Text supplied as text data in the format accepted by this
                function.
            display_name: Stable display name used for lookup and
                operator-facing diagnostics.

        Returns:
            The canonical generate log viewer text.
        """
        parsers = self._get_log_parser_specs()
        parser_metadata = self._browser_log_parser_metadata(parsers)
        components = set()
        levels = set()

        for line in text_data.split("\n"):
            parsed = self._parse_log_line(line, parsers)
            if parsed is not None:
                if parsed["level"]:
                    levels.add(parsed["level"])
                if parsed["component"]:
                    components.add(parsed["component"])

        components = sorted(components)
        levels = sorted(levels)
        parser_metadata_json = self._json_for_script(
            parser_metadata, separators=(",", ":")
        )
        return _HTML_LOG_VIEWER.render(
            LogViewerRenderModel(
                text_data=text_data,
                display_name=display_name,
                parser_metadata_json=parser_metadata_json,
                levels=tuple(levels),
                components=tuple(components),
            )
        )

    def _get_html_output_path_for_file(self, file_path: Path) -> Path:
        """
        Return HTML output path for file.

        The implementation uses ``file_path`` to produce HTML output path for
        file.

        Args:
            file_path: filesystem location used as the file path for this
                operation.

        Returns:
            The validated HTML output path for file filesystem path.
        """
        rel_path = self._logical_report_input_relative_path(file_path)
        html_file_relative = rel_path.with_suffix(rel_path.suffix + ".html")
        return self.report_dir / html_file_relative

    def _get_html_output_path(self, parent_dir: Path, filename: str) -> Path:
        """
        Return HTML output path.

        The implementation uses ``parent_dir`` and ``filename`` to produce HTML
        output path.

        Args:
            parent_dir: filesystem location used as the parent dir for this
                operation.
            filename: Text supplied as filename in the format accepted by this
                function.

        Returns:
            The validated HTML output path filesystem path.
        """
        relative_dir = self._logical_report_input_relative_path(parent_dir)
        return self.report_dir / relative_dir / filename

    def _json_tree_html(self, data) -> str:
        """
        Return the renderer-owned colorized, collapsible JSON tree.

        After applying local validation, the function forwards ``data`` to
        ``_HTML_RENDERER.json_tree_html`` and preserves its return and exception
        contract.

        Args:
            data: Data consumed while the function attempts to produce the
                renderer-owned colorized, collapsible JSON tree.

        Returns:
            The canonical JSON tree HTML text.
        """

        return _HTML_RENDERER.json_tree_html(data, self.max_json_tree_depth)

    def _get_firmware_info(self, node_path: Path) -> Tuple[str, str]:
        """
        Get firmware information for a node.

        The implementation uses ``node_path`` to get firmware information for a
        node.

        Args:
            node_path: filesystem location used as the node path for this
                operation.

        Returns:
            A tuple containing ``summary`` and ``modal content`` in that order.
        """
        firmware_versions = {
            "BMC": [],
            "HMC": [],
            "GPU": [],
            "NVSwitch": [],
            "Software": [],
            "CPLD": [],
            "CPU": [],
            "ERoT": [],
        }

        collector_definitions = None
        if self.orchestrator:
            try:
                collector_definitions = self.orchestrator.get_all_collectors()
            except ReportInputSafetyError:
                raise
            except Exception:
                collector_definitions = None

        try:
            firmware_items = ManifestService(
                self.root_dir,
                finalization_receipt=self._finalization_receipt,
                enforce_snapshot_consistency=self._enforce_snapshot_consistency,
                max_auxiliary_json_files=(self._finalization_boundaries or {}).get(
                    "finalization_manifest_max_auxiliary_json_files",
                    HARD_MAX_AUXILIARY_JSON_FILES,
                ),
            )._extract_firmware_from_redfish(
                node_path,
                collector_definitions=collector_definitions,
            )
        except ReportInputSafetyError:
            raise
        except Exception as exc:
            # A malformed or unreadable inventory belongs to this node.  Keep
            # generating the multi-node report and render the normal empty
            # firmware state for the affected node.
            logger.warning(
                "Failed to extract firmware inventory for node %s: %s",
                node_path,
                exc,
            )
            firmware_items = []
        raw_firmware_data = []
        for item in firmware_items:
            raw_item = {
                "Id": item.get("id", ""),
                "Name": item.get("name", item.get("id", "")),
                "Version": item.get("version", ""),
            }
            for source, target in (
                ("description", "Description"),
                ("manufacturer", "Manufacturer"),
                ("status", "Status"),
            ):
                if source in item:
                    raw_item[target] = item[source]
            raw_firmware_data.append(raw_item)

        for item in firmware_items:
            item_id = str(item.get("id", ""))
            item_name = str(item.get("name", ""))
            version = str(item.get("version", "")) or "Available"

            if item_id.startswith("FW_BMC_0"):
                firmware_versions["BMC"].append(version)
            elif item_id.startswith("HGX_FW_BMC_0"):
                firmware_versions["HMC"].append(version)
            elif item_id.startswith("HGX_FW_GPU_"):
                firmware_versions["GPU"].append(version)
            elif item_id.startswith("MGX_FW_NVSwitch_"):
                firmware_versions["NVSwitch"].append(version)
            elif item_id == "Software Inventory" or item_name == "Software Inventory":
                firmware_versions["Software"].append(version)
            elif item_id.startswith("CPLD_"):
                firmware_versions["CPLD"].append(version)
            elif item_id.startswith("MGX_FW_BMC_"):
                firmware_versions["BMC"].append(version)
            elif item_id.startswith("MGX_FW_CPU_"):
                firmware_versions["CPU"].append(version)
            elif item_id.startswith("MGX_FW_ERoT_"):
                firmware_versions["ERoT"].append(version)

        # Generate summary display
        summary_parts = []
        for key, versions in firmware_versions.items():
            if versions:
                # The summary is interpolated into the report body without
                # further escaping, so device-supplied versions must be escaped
                # here. The per-device modal path escapes separately.
                safe_key = self._escape_html_text(key)
                if len(set(versions)) == 1:
                    safe_version = self._escape_html_text(versions[0])
                    summary_parts.append(f"{safe_key}: {safe_version}")
                else:
                    summary_parts.append(f"{safe_key}: Multiple versions")

        summary = (
            "<br>".join(summary_parts)
            if summary_parts
            else "Firmware data not collected"
        )

        # Generate detailed info for modal
        if not raw_firmware_data:
            modal_content = """
            <div class="alert alert-warning" role="alert">
                <h4 class="alert-heading">No Firmware Data Available</h4>
                <p>Firmware information could not be collected. This could be due to one of the following reasons:</p>
                <ul>
                    <li>The firmware inventory collector was not specified in the collector list</li>
                    <li>The firmware inventory collector failed to run</li>
                    <li>The Redfish endpoint was not accessible</li>
                    <li>The system does not support firmware inventory collection</li>
                    <li>There was an error parsing the firmware data</li>
                </ul>
                <hr>
                <p class="mb-0">Please check the collector logs for more details about why the firmware data collection failed.</p>
            </div>
            """
        else:
            # First, determine which columns are actually present in the data
            available_columns = set()
            for item in raw_firmware_data:
                for key in [
                    "Name",
                    "Id",
                    "Version",
                    "Description",
                    "Manufacturer",
                    "Status",
                ]:
                    if key in item:
                        available_columns.add(key)

            # Build the table header based on available columns
            modal_content = """
            <table class="table table-striped table-bordered table-shadow">
                <thead class="table-dark">
                    <tr>
            """

            # Add columns in a specific order, but only if they exist in the data
            column_order = [
                "Name",
                "Id",
                "Version",
                "Description",
                "Status",
                "Manufacturer",
            ]
            for col in column_order:
                if col in available_columns:
                    modal_content += f"<th>{escape(col)}</th>"

            modal_content += """
                    </tr>
                </thead>
                <tbody>
            """

            for item in raw_firmware_data:
                modal_content += "<tr>"

                # Add cells in the same order as headers
                for col in column_order:
                    if col in available_columns:
                        # Special handling for Name/Id
                        if col == "Name":
                            value = item.get("Name", item.get("Id", "N/A"))
                        else:
                            value = item.get(col, "N/A")

                        # Convert boolean values to Yes/No for better readability
                        if isinstance(value, bool):
                            value = "Yes" if value else "No"

                        modal_content += f"<td>{escape(str(value))}</td>"

                modal_content += "</tr>"

            modal_content += """
                </tbody>
            </table>
            """

        return summary, modal_content

    async def _generate_dependency_check_page(self, node_path: Path) -> str:
        """
        Generate a dedicated page for dependency checks for a DUT.

        Returns the relative path to the generated HTML file.

        Args:
            node_path: filesystem location used as the node path for this
                operation.

        Returns:
            The canonical generate dependency check page text.
        """
        node_name = node_path.name
        dependency_html_path = self.report_dir / node_name / "dependency_checks.html"

        # Build the content
        content = f"""
        <div class="row">
            <div class="col-xl-2 col-lg-2 col-md-3">
                <h4>Node: {escape(node_name)}</h4>
                {self._build_system_details_html(node_name)}
            </div>
            <div class="col-xl-10 col-lg-10 col-md-9">
                <h2>Dependency Checks</h2>
                {await self._build_dependency_table(node_path)}
            </div>
        </div>
        """

        self._finalize_page(
            target_file=dependency_html_path,
            page_title=f"Dependency Checks: {node_name}",
            main_content=content,
            breadcrumb_links=[
                ("Home", "../index.html"),
                (node_name, "report.html"),
            ],
            breadcrumb_active_text="Dependency Checks",
        )

        return os.path.relpath(
            dependency_html_path, self.report_dir / node_name
        ).replace("\\", "/")

    async def generate_reports_with_progress(self, progress, main_task) -> bool:
        """
        Main method to generate all HTML reports with progress tracking.

        The implementation uses ``progress`` and ``main_task`` to main method to
        generate all HTML reports with progress tracking. Owned asynchronous
        work is awaited before return, so completion does not leave an
        unobserved task behind. The operation mutates ``progress`` in place;
        ownership of those objects remains with the caller. Cleanup in the
        ``finally`` path runs for successful, failed, and cancelled execution.

        Args:
            progress: Progress object whose ``advance`` and ``update`` state is
                read while performing main method to generate all HTML reports
                with progress tracking.
            main_task: Main task consumed while the function attempts to main
                method to generate all HTML reports with progress tracking.

        Returns:
            Whether the main method to generate all HTML reports with progress
            tracking operation succeeds.
        """
        try:
            self._reset_report_input_budget()
            await self._log("INFO", "Generating HTML reports...")
            await self._log("DEBUG", f"Root directory: {self.root_dir}")

            # Update progress for initialization
            progress.update(
                main_task,
                completed=5,
                description="Initializing HTML report generation...",
            )

            node_reports = []
            excluded_dirs = {
                "report",
                "reports",
                "temp",
                "backup",
                ".metadata",
            }

            if not self._report_input_is_dir(self.root_dir):
                await self._log(
                    "ERROR",
                    f"Root directory {self.root_dir} is not a directory.",
                )
                return False

            self._bind_terminal_snapshot()
            self._refresh_common_navbar_from_bound_result()

            # Scan directory contents
            progress.update(
                main_task,
                completed=10,
                description="Scanning directory contents...",
            )

            # Count total nodes to process
            nodes_to_process = []
            for node in self._iter_node_directories():
                if self._report_input_is_dir(node) and node.name not in excluded_dirs:
                    nodes_to_process.append(node)

            total_nodes = len(nodes_to_process)
            if total_nodes == 0:
                progress.update(
                    main_task,
                    completed=65,
                    description="No nodes to process, generating final reports...",
                )
                await self._log("INFO", "No nodes found to process")
            else:
                # Process each node with progress updates
                progress.update(
                    main_task,
                    completed=15,
                    description=f"Processing {total_nodes} nodes...",
                )

                for i, node in enumerate(nodes_to_process):
                    await self._log(
                        "DEBUG",
                        f"Processing node: {node}",
                    )

                    # Update progress for each node
                    node_progress = 15 + (i * 50 / total_nodes)  # 15% to 65%
                    progress.update(
                        main_task,
                        completed=int(node_progress),
                        description=f"Processing node {i+1}/{total_nodes}: {node.name}",
                    )

                    await self._parse_collector_json_metadata(node)
                    node_report = await self._generate_node_report(node)
                    if node_report:
                        node_reports.append(node_report)

                progress.update(
                    main_task,
                    completed=65,
                    description="Node processing completed, generating final reports...",
                )

            # Generate final reports
            progress.update(
                main_task,
                completed=75,
                description="Generating global file map...",
            )
            await self._generate_global_file_map()

            progress.update(
                main_task,
                completed=80,
                description="Generating timing analysis page...",
            )
            await self._generate_timing_analysis_page()

            progress.update(
                main_task,
                completed=85,
                description="Generating top-level report...",
            )
            await self._generate_top_level_report(node_reports)

            progress.update(
                main_task,
                completed=95,
                description="Finalizing HTML reports...",
            )
            await self._log("INFO", f"HTML reports generated in {self.report_dir}")

            # Complete the progress by advancing to 100%
            progress.advance(main_task, 5)
            progress.update(main_task, description="HTML reports completed!")

            return True

        except SnapshotConsistencyError:
            raise
        except ReportInputSafetyError:
            raise
        except Exception as e:
            await self._log("ERROR", f"Error generating HTML reports: {e}")
            return False
        finally:
            self._release_terminal_snapshot()
