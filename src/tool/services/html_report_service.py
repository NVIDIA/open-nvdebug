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

import json
import os
import re
import shutil
from collections import defaultdict
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class HTMLReportService:
    """
    A class to generate comprehensive multi-level HTML reports from a structured directory containing
    node logs and configurations, including collector JSON metadata for execution times.
    """

    def __init__(
        self,
        log_dir: Path,
        total_runtime: float = None,
        logger=None,
        orchestrator=None,
    ):
        """
        Initializes the HTMLReportService for nvdebug.

        Args:
            log_dir: Path to the log directory containing DUT directories.
            total_runtime: Total runtime of the collection.
            logger: Async logger instance for writing to runtime logs.
            orchestrator: WorkflowOrchestrator instance for accessing collector definitions.
        """
        # Set basic attributes that are needed before async initialization
        self.logger = logger
        self.orchestrator = orchestrator
        self.root_dir = log_dir
        self.total_runtime = total_runtime

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

    @staticmethod
    def _json_for_script(value: Any, **kwargs) -> str:
        """Serialize JSON safely for direct embedding inside script tags."""
        return (
            json.dumps(value, **kwargs)
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029")
        )

    @classmethod
    async def create(
        cls,
        log_dir: Path,
        total_runtime: float = None,
        logger=None,
        orchestrator=None,
        collector_ids: Optional[List[str]] = None,
    ):
        """
        Factory method to create and initialize HTMLReportService asynchronously.

        Args:
            log_dir: Path to the log directory containing DUT directories.
            total_runtime: Total runtime of the collection.
            logger: Async logger instance for writing to runtime logs.
            orchestrator: WorkflowOrchestrator instance for accessing collector definitions.
            collector_ids: List of collector IDs that were requested to run.
        """
        instance = cls(log_dir, total_runtime, logger, orchestrator)
        instance.requested_collector_ids = collector_ids
        await instance._initialize()
        return instance

    async def _initialize(self):
        """
        Async initialization method.

        Sets up logging, directories, and initializes data structures.
        """
        # These are already set in __init__, just need to set up logging
        self.root_dir = self.root_dir.resolve()

        # Helper method for async logging
        async def log_message(level: str, message: str, dut_id: str = None):
            """
            Helper to log messages using async logger if available.

            Args:
                level: Log level.
                message: Log message.
                dut_id: DUT ID (ignored, kept for compatibility).
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

        # Remove existing reports directory if it exists
        if self.report_dir.exists() and self.report_dir.is_dir():
            try:
                shutil.rmtree(self.report_dir)
                await self._log(
                    "DEBUG",
                    f"Removed existing reports directory at {self.report_dir}",
                )
            except Exception as e:
                await self._log(
                    "ERROR", f"Error removing existing reports directory: {e}"
                )
                raise

        # Recreate the reports directory
        try:
            self.report_dir.mkdir(exist_ok=True)
            await self._log(
                "DEBUG",
                f"Created or found existing reports directory at {self.report_dir}",
            )
        except FileNotFoundError as e:
            await self._log("ERROR", f"Error creating reports directory: {e}")
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

        # Remove existing reports directory if it exists
        if self.report_dir.exists() and self.report_dir.is_dir():
            try:
                shutil.rmtree(self.report_dir)
            except Exception:
                raise

        # Recreate the reports directory
        try:
            self.report_dir.mkdir(exist_ok=True)
        except FileNotFoundError:
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

        Args:
            group_name: Group name in new format.

        Returns:
            Group name in legacy format.
        """
        # Mapping from new naming scheme to legacy naming scheme for metadata files
        group_name_mapping = {"health_check": "healthcheck", "bmc_ssh": "ssh"}
        return group_name_mapping.get(group_name, group_name)

    def _make_links_clickable(self, text: str) -> str:
        """
        Convert URLs in text to clickable HTML links.

        Args:
            text: Text that may contain URLs

        Returns:
            Text with URLs converted to clickable links
        """

        # Pattern to match URLs (http/https)
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'

        def replace_url(match):
            url = match.group(0)
            # Escape the URL for HTML attributes
            escaped_url = escape(url)
            return f'<a href="{escaped_url}" target="_blank" rel="noopener noreferrer">{escape(url)}</a>'

        return re.sub(url_pattern, replace_url, text)

    def _get_total_log_size(self, node_path: Path) -> int:
        """
        Recursively sums the sizes of all files in node_path excluding the 'report' directory.
        """
        total = 0
        for root, dirs, files in os.walk(node_path):
            # Exclude the report directory from size calculation
            if "report" in dirs:
                dirs.remove("report")
            for f in files:
                try:
                    fp = os.path.join(root, f)
                    total += os.path.getsize(fp)
                except Exception:
                    pass
        return total

    def _format_bytes(self, size: float) -> str:
        """
        Convert a byte count into a human-readable string.
        """
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"

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
        Renders a page by optionally building breadcrumbs, appending main_content,
        appending modals, and then writing the final HTML via _write_html_report().
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
        Returns an HTML snippet showing the system details (Model, Partno, Serialno)
        for the given node.
        """
        details = self.node_system_details.get(
            node_name,
            {"Model": "Unknown", "Partno": "Unknown", "Serialno": "Unknown"},
        )
        return f"""
        <h5>System Details</h5>
        <ul>
            <li><strong>Model:</strong> {escape(details['Model'])}</li>
            <li><strong>Partno:</strong> {escape(details['Partno'])}</li>
            <li><strong>Serialno:</strong> {escape(details['Serialno'])}</li>
        </ul>
        """

    def _build_modal_html(
        self, modal_id: str, modal_title: str, body_content: str
    ) -> str:
        """
        Returns the standard Bootstrap modal HTML snippet.

        Args:
            modal_id (str): The unique ID for the modal.
            modal_title (str): The title text for the modal.
            body_content (str): The HTML content to be displayed inside the modal body.

        Returns:
            str: The complete Bootstrap modal HTML markup.
        """
        return f"""
        <div class="modal fade" id="{modal_id}" tabindex="-1" aria-labelledby="{modal_id}Label" aria-hidden="true">
            <div class="modal-dialog modal-xl">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="{modal_id}Label">{escape(modal_title)}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        {body_content}
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
        """

    def _render_link_list_with_modal(
        self,
        link_objs: List[str],
        threshold: int,
        modal_id: str,
        modal_title: str,
        modal_store_list: Optional[List[str]] = None,
    ) -> str:
        """
        Renders the given link objects, and if they exceed the threshold, creates a Bootstrap
        modal and returns a partial list plus a button to open the modal.

        Args:
            link_objs (List[str]): The list of links or text items to display.
            threshold (int): The threshold after which a modal should be used.
            modal_id (str): Unique ID for the modal.
            modal_title (str): Title to display on the modal.
            modal_store_list (List[str], optional): A list to which we can append the modal HTML.
                                                    Defaults to None if not needed.

        Returns:
            str: HTML string that shows either all links inline or partial links with "Show remaining" button.
        """
        # De-duplicate identical rendered link strings while preserving order.
        # This prevents repeated links in the Execution Summary "Log Paths" column
        # when the same output file is recorded multiple times upstream.
        if link_objs:
            seen = set()
            deduped: List[str] = []
            for item in link_objs:
                if item in seen:
                    continue
                seen.add(item)
                deduped.append(item)
            link_objs = sorted(deduped)

        total_links = len(link_objs)
        if total_links <= threshold:
            return "<br>".join(link_objs) if link_objs else "N/A"

        displayed_links = "<br>".join(link_objs[:threshold])
        remainder_links = link_objs[threshold:]
        modal_body = "<br>".join(remainder_links)
        modal_html = self._build_modal_html(modal_id, modal_title, modal_body)

        if modal_store_list is not None:
            modal_store_list.append(modal_html)

        return (
            f"{displayed_links}"
            f'<br><a href="#" class="btn btn-secondary" data-bs-toggle="modal" '
            f'data-bs-target="#{modal_id}">'
            f"Show remaining {total_links - threshold} file(s)</a>"
        )

    def _parse_from_collection_name(self, coll_name: str) -> Tuple[str, str, str]:
        """
        Tries to parse the collector group, ID, and name from the "collection name" field.
        If not possible, return ("N/A", "N/A", coll_name).
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
        Convert strings like "2m 59.59s", "1h 3m 10s", "30.0s", "30.0", "Log collection took 11.92 seconds" -> float seconds.
        Also handles numeric values directly.
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
        """
        return self.known_collector_groups.get(g.lower(), g)

    def _get_group_from_collector_id(self, collector_id: str) -> str:
        """
        Get the correct group name based on collector ID prefix.
        This ensures proper classification regardless of directory structure.
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
        elif s == "partial":
            return "status-partial"
        elif s == "n/a":
            return "status-na"
        return ""

    def _get_common_navbar(self) -> str:
        """
        Returns a shared navbar snippet that will appear on all pages.
        """
        theme_toggle_html = (
            """
        <div class="form-check form-switch">
            <input class="form-check-input" type="checkbox" id="themeToggle">
            <label class="form-check-label" for="themeToggle">Dark Mode</label>
        </div>"""
            if self.theme_toggle
            else ""
        )

        return f"""
        <header class="py-3 mb-3 border-bottom navbar-fixed-top bg-white">
            <div class="container-fluid d-grid gap-3 align-items-center" style="grid-template-columns: 1fr 2fr;">
                <div class="d-flex">
                    <div class="nv-logo">
                        <svg viewBox="0 0 164 30"><defs><path id="a" d="M157.725 29.99H.01V.048h157.715z"></path></defs><g fill="none" fill-rule="evenodd"><path d="M160.352 24.069v-.449h.288c.157 0 .371.012.371.204 0 .208-.11.245-.296.245h-.363m0 .315h.192l.447.784h.49l-.494-.816c.255-.019.465-.14.465-.484 0-.427-.295-.565-.793-.565h-.721v1.865h.414v-.784m2.098-.146c0-1.095-.851-1.73-1.8-1.73-.955 0-1.805.635-1.805 1.73s.85 1.733 1.805 1.733c.948 0 1.8-.638 1.8-1.733m-.52 0c0 .798-.587 1.334-1.28 1.334v-.006c-.713.006-1.289-.53-1.289-1.328 0-.797.577-1.331 1.289-1.331.694 0 1.28.534 1.28 1.331" fill="#1A1919"></path><mask id="b" fill="#fff"><use href="#a"></use></mask><path d="m96.374 5.707.002 19.66h5.552V5.707h-5.554zm-43.677-.026v19.686H58.3V10.086l4.37.014c1.437 0 2.43.345 3.123 1.084.879.936 1.237 2.444 1.237 5.205v8.978h5.427V14.49c0-7.763-4.948-8.81-9.789-8.81h-9.97zm52.617.027v19.659h9.006c4.798 0 6.364-.798 8.057-2.587 1.198-1.256 1.971-4.014 1.971-7.027 0-2.763-.655-5.228-1.797-6.763-2.057-2.745-5.02-3.282-9.445-3.282h-7.792zm5.508 4.28h2.387c3.463 0 5.703 1.556 5.703 5.591 0 4.037-2.24 5.592-5.703 5.592h-2.387V9.989zm-22.453-4.28-4.634 15.58-4.44-15.579-5.993-.001 6.34 19.659h8.003l6.391-19.659H88.37zm38.563 19.659h5.553V5.709l-5.555-.001.002 19.659zm15.564-19.652-7.753 19.645h5.475l1.227-3.472h9.175l1.161 3.472h5.944l-7.812-19.646-7.417.001zM146.1 9.3l3.364 9.204h-6.833l3.47-9.204z" fill="#000" mask="url(#b)"></path><path d="M16.889 8.985V6.28c.262-.02.528-.033.798-.042 7.4-.232 12.255 6.359 12.255 6.359s-5.244 7.282-10.866 7.282a6.82 6.82 0 0 1-2.187-.35v-8.204c2.88.348 3.46 1.62 5.192 4.508l3.852-3.248s-2.812-3.688-7.552-3.688c-.515 0-1.008.036-1.492.088zm0-8.938V4.09c.265-.021.531-.038.798-.048 10.29-.346 16.995 8.44 16.995 8.44s-7.7 9.364-15.723 9.364c-.735 0-1.424-.068-2.07-.183v2.498c.553.07 1.126.112 1.724.112 7.465 0 12.864-3.812 18.092-8.325.867.694 4.416 2.383 5.145 3.123-4.971 4.16-16.555 7.515-23.123 7.515a18.89 18.89 0 0 1-1.838-.096V30h28.375V.047H16.89zm0 19.482v2.133c-6.905-1.23-8.822-8.408-8.822-8.408s3.316-3.674 8.822-4.269v2.34l-.011-.001c-2.89-.347-5.147 2.353-5.147 2.353s1.265 4.544 5.158 5.852zM4.625 12.943s4.092-6.04 12.264-6.663V4.088C7.838 4.815 0 12.48 0 12.48s4.439 12.833 16.889 14.008V24.16C7.753 23.011 4.625 12.943 4.625 12.943z" fill="#76B900" mask="url(#b)"></path></g></svg>
                    </div>
                    <a class="navbar-brand" href="#">NVDebug Reports</a>
                    {theme_toggle_html}
                </div>
                <div class="d-flex justify-content-end">
                    <form class="row me-3" role="search" onsubmit="return false;">
                        <div class="col-auto">
                            <input id="globalSearchBox" type="search" class="form-control" placeholder="Search..." aria-label="Search" onkeyup="globalSearchHandler(this.value)">
                        </div>
                        <div class="col-auto">
                            <button class="btn btn-outline-success my-2 my-sm-0" type="button" onclick="clearSearch()">Clear</button>
                        </div>
                    </form>
                </div>
            </div>
        </header>
        """

    def _get_html_header(self) -> str:
        """
        Returns the HTML header template with placeholders for title and content.
        """
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>{title}</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                /* Base styles with modern polish */
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                    margin: 0;
                    padding: 0 1rem;
                    padding-top: 80px;
                    background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                    min-height: 100vh;
                }}

                /* Container with card style */
                .container {{
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
                    padding: 2rem;
                    margin-top: 1rem !important;
                    margin-bottom: 2rem !important;
                    margin-left: auto !important;
                    margin-right: auto !important;
                }}

                .navbar-fixed-top {{
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    z-index: 1030;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}

                /* Enhanced table styling */
                table {{
                    border-collapse: collapse;
                    width: 100%;
                    margin-bottom: 20px;
                    background: white;
                }}
                th, td {{
                    border: 1px solid #e0e0e0;
                    padding: 12px;
                    text-align: left;
                }}
                th {{
                    font-weight: 600;
                }}
                thead:not(.table-dark) th {{
                    background: linear-gradient(180deg, #f8f9fa 0%, #e9ecef 100%);
                    color: #495057;
                }}
                thead.table-dark th {{
                    background: linear-gradient(180deg, #343a40 0%, #23272b 100%) !important;
                    color: #fff !important;
                    border-color: #454d55 !important;
                }}
                .table-dark tbody tr {{
                    background-color: transparent;
                }}
                .table-striped.table-dark tbody tr:nth-of-type(odd) {{
                    background-color: rgba(255, 255, 255, 0.05);
                }}
                tbody tr:hover {{ background-color: #f8f9fa; }}
                .table-dark tbody tr:hover {{ background-color: rgba(255, 255, 255, 0.075); }}
                a {{
                    text-decoration: none;
                    color: #0066cc;
                    transition: color 0.2s ease;
                }}
                a:hover {{ color: #0052a3; }}

                /* Status badges with modern colors */
                .status-complete {{ background-color: #d4edda !important; color: #155724 !important; }}
                .status-error {{ background-color: #f8d7da !important; color: #721c24 !important; }}
                .status-partial {{ background-color: #fff3cd !important; color: #856404 !important; }}
                .status-skipped {{ background-color: #ffc107 !important; color: #212529 !important; }}
                .status-na {{ background-color: #e9ecef !important; color: #6c757d !important; }}
                .status-notran {{ background-color: #e9ecef !important; color: #6c757d !important; }}

                /* Cards and sections */
                .card {{
                    border: none;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.08);
                    transition: transform 0.2s ease, box-shadow 0.2s ease;
                }}
                .card:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 8px rgba(0,0,0,0.12);
                }}
                /* Only gradient cards should be equal height */
                .card.bg-primary, .card.bg-success, .card.bg-danger, .card.bg-info, .card.bg-warning {{
                    height: 100%;
                }}
                .card.bg-primary .card-body,
                .card.bg-success .card-body,
                .card.bg-danger .card-body,
                .card.bg-info .card-body,
                .card.bg-warning .card-body {{
                    display: flex;
                    flex-direction: column;
                    height: 100%;
                }}

                .section {{
                    background: white;
                    border-radius: 8px;
                    padding: 1.5rem;
                    margin-bottom: 1.5rem;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.06);
                }}

                /* Enhanced buttons */
                .btn {{
                    border-radius: 6px;
                    font-weight: 500;
                    transition: all 0.2s ease;
                }}
                .btn:hover {{
                    transform: translateY(-1px);
                    box-shadow: 0 4px 8px rgba(0,0,0,0.15);
                }}

                /* Breadcrumb */
                .breadcrumb {{
                    background: #f8f9fa;
                    padding: 0.75rem;
                    border-radius: 6px;
                    margin-bottom: 1rem;
                }}

                /* Accordion */
                .accordion {{
                    background-color: #f8f9fa;
                    cursor: pointer;
                    padding: 12px;
                    width: 100%;
                    border: none;
                    border-radius: 6px;
                    text-align: left;
                    outline: none;
                    transition: all 0.3s ease;
                    font-weight: 500;
                }}
                .accordion.active, .accordion:hover {{
                    background-color: #e9ecef;
                }}
                .panel {{
                    padding: 0 15px;
                    display: none;
                    background-color: white;
                    overflow: auto;
                    max-height: 600px;
                    border-radius: 0 0 6px 6px;
                }}

                /* Tree view */
                ul {{ list-style-type: none; }}
                li.folder > span {{
                    font-weight: bold;
                    cursor: pointer;
                    color: #0066cc;
                }}
                #treeview ul {{ margin-left: 20px; }}

                .highlight {{
                    background-color: #fff3cd;
                    padding: 2px 4px;
                    border-radius: 3px;
                }}

                .nv-logo {{
                    display: inline-flex;
                    height: 25px;
                    padding-right: 20px;
                }}

                .table-shadow {{
                    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
                    border-radius: 8px;
                    overflow: hidden;
                }}

                /* Progress bars */
                .progress {{
                    border-radius: 8px;
                    overflow: hidden;
                }}

                /* Headings */
                h1, h2, h3, h4, h5, h6 {{
                    color: #2c3e50;
                    font-weight: 600;
                }}

                /* Badge improvements */
                .badge {{
                    padding: 0.35em 0.65em;
                    border-radius: 6px;
                    font-weight: 500;
                }}

                /* Service color scheme - consistent across all reports */
                .service-redfish,
                span.badge.service-redfish,
                span.badge.service-badge.service-redfish {{
                    background-color: #f8d7da !important;
                    color: #721c24 !important;
                    border: 1px solid #f5c2c7 !important;
                }}
                .service-ssh,
                span.badge.service-ssh,
                span.badge.service-badge.service-ssh {{
                    background-color: #fff3cd !important;
                    color: #856404 !important;
                    border: 1px solid #ffecb5 !important;
                }}
                .service-ipmi,
                span.badge.service-ipmi,
                span.badge.service-badge.service-ipmi {{
                    background-color: #d4edda !important;
                    color: #155724 !important;
                    border: 1px solid #c3e6cb !important;
                }}
                .service-host,
                span.badge.service-host,
                span.badge.service-badge.service-host {{
                    background-color: #cfe2ff !important;
                    color: #084298 !important;
                    border: 1px solid #b6d4fe !important;
                }}
                .service-health_check,
                span.badge.service-health_check,
                span.badge.service-badge.service-health_check {{
                    background-color: #e2d9f3 !important;
                    color: #4a148c !important;
                    border: 1px solid #d4c4e8 !important;
                }}
                .service-preflight,
                span.badge.service-preflight,
                span.badge.service-badge.service-preflight {{
                    background-color: #e9ecef !important;
                    color: #495057 !important;
                    border: 1px solid #dee2e6 !important;
                }}

                /* Service badges (inline display) */
                .service-badge {{
                    display: inline-block !important;
                    padding: 6px 12px !important;
                    border-radius: 12px !important;
                    font-size: 0.8rem !important;
                    font-weight: 600 !important;
                    margin-right: 8px !important;
                }}

                /* Gradient cards for summary boxes */
                .card.bg-primary {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
                }}
                .card.bg-success {{
                    background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%) !important;
                }}
                .card.bg-danger {{
                    background: linear-gradient(135deg, #ee0979 0%, #ff6a00 100%) !important;
                }}
                .card.bg-info {{
                    background: linear-gradient(135deg, #3a7bd5 0%, #00d2ff 100%) !important;
                }}
                .card.bg-warning {{
                    background: linear-gradient(135deg, #f2994a 0%, #f2c94c 100%) !important;
                }}

                /* Chart containers */
                .chart-container {{
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: none !important;
                    margin-bottom: 20px;
                }}

                /* Sortable table headers */
                th.sortable {{
                    cursor: pointer;
                    user-select: none;
                    position: relative;
                }}
                thead:not(.table-dark) th.sortable:hover {{
                    background: linear-gradient(180deg, #e9ecef 0%, #d3d7da 100%) !important;
                }}
                thead.table-dark th.sortable:hover {{
                    background: linear-gradient(180deg, #454d55 0%, #343a40 100%) !important;
                }}
                th.sortable:after {{
                    content: '⇅';
                    position: absolute;
                    right: 8px;
                    opacity: 0.5;
                }}
                #logView {{
                    background: #1e1e1e !important;
                }}
            </style>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/themes/prism.min.css" rel="stylesheet" />
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/prism.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <script>
                // Initialize all modals when the document is ready
                document.addEventListener('DOMContentLoaded', function() {{
                    // Initialize all modals
                    var modalElements = document.querySelectorAll('.modal');
                    modalElements.forEach(function(modalElement) {{
                        new bootstrap.Modal(modalElement);
                    }});

                    // Initialize all tooltips
                    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
                    tooltipTriggerList.map(function (tooltipTriggerEl) {{
                        return new bootstrap.Tooltip(tooltipTriggerEl);
                    }});

                    // Initialize all popovers
                    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
                    popoverTriggerList.map(function (popoverTriggerEl) {{
                        return new bootstrap.Popover(popoverTriggerEl);
                    }});
                }});

                // Function to open a modal by ID
                function openModal(modalId) {{
                    var modalElement = document.getElementById(modalId);
                    if (modalElement) {{
                        var modal = bootstrap.Modal.getInstance(modalElement) || new bootstrap.Modal(modalElement);
                        modal.show();
                    }}
                }}

                function filterTable(query) {{
                    query = query.toLowerCase();
                    var tables = document.getElementsByTagName('table');
                    for (var t = 0; t < tables.length; t++) {{
                        var rows = tables[t].getElementsByTagName('tr');
                        for (var i = 1; i < rows.length; i++) {{
                            var cells = rows[i].getElementsByTagName('td');
                            var match = false;
                            for (var c = 0; c < cells.length; c++) {{
                                var cellText = cells[c].innerText.toLowerCase();
                                if (cellText.indexOf(query) > -1) {{
                                    match = true;
                                    break;
                                }}
                            }}
                            rows[i].style.display = (match || query === '') ? '' : 'none';
                        }}
                    }}
                }}

                function clearSearch() {{
                    var input = document.getElementById("globalSearchBox");
                    if (input) {{
                        input.value = '';
                        globalSearchHandler('');
                    }}
                }}

                function globalSearchHandler(value) {{
                    var tables = document.getElementsByTagName('table');
                    if (tables.length > 0) {{
                        filterTable(value);
                    }} else if (document.getElementById("jsonTree")) {{
                        jsonGlobalSearch(value);
                    }} else if (document.getElementById("textView")) {{
                        textGlobalSearch(value);
                    }} else if (document.getElementById("stdoutView")) {{
                        stdoutGlobalSearch(value);
                    }}
                }}

                // Universal table sorting with unique state per table
                var tableSortStates = {{}};

                function makeTableSortable(tableId) {{
                    var table = document.getElementById(tableId);
                    if (!table) return;

                    // Initialize sort state for this table
                    tableSortStates[tableId] = {{}};

                    var headers = table.getElementsByTagName('th');

                    for (var i = 0; i < headers.length; i++) {{
                        (function(index, tId) {{
                            headers[index].classList.add('sortable');
                            headers[index].addEventListener('click', function() {{
                                sortTableByColumn(tId, index);
                            }});
                        }})(i, tableId);
                    }}
                }}

                function sortTableByColumn(tableId, columnIndex) {{
                    var table = document.getElementById(tableId);
                    if (!table) return;

                    var tbody = table.getElementsByTagName('tbody')[0];
                    if (!tbody) return;

                    var rows = Array.from(tbody.getElementsByTagName('tr'));
                    if (rows.length === 0) return;

                    // Toggle sort direction
                    var sortStates = tableSortStates[tableId];
                    sortStates[columnIndex] = !sortStates[columnIndex];
                    var isAscending = sortStates[columnIndex];

                    rows.sort(function(a, b) {{
                        var aCell = a.getElementsByTagName('td')[columnIndex];
                        var bCell = b.getElementsByTagName('td')[columnIndex];
                        if (!aCell || !bCell) return 0;

                        var aValue = aCell.textContent.trim();
                        var bValue = bCell.textContent.trim();

                        // Prefer data-sort attribute for unit-aware numeric sorting
                        var aNum = aCell.hasAttribute('data-sort') ? parseFloat(aCell.getAttribute('data-sort')) : parseFloat(aValue.replace(/[^0-9.-]/g, ''));
                        var bNum = bCell.hasAttribute('data-sort') ? parseFloat(bCell.getAttribute('data-sort')) : parseFloat(bValue.replace(/[^0-9.-]/g, ''));
                        if (!isNaN(aNum) && !isNaN(bNum)) {{
                            return isAscending ? aNum - bNum : bNum - aNum;
                        }}

                        // Fall back to string comparison
                        if (aValue < bValue) return isAscending ? -1 : 1;
                        if (aValue > bValue) return isAscending ? 1 : -1;
                        return 0;
                    }});

                    tbody.innerHTML = '';
                    rows.forEach(function(row) {{ tbody.appendChild(row); }});
                }}

                document.addEventListener('DOMContentLoaded', function() {{
                    // Initialize all modals
                    const modalElements = document.querySelectorAll('.modal');
                    modalElements.forEach(function(modalElement) {{
                        new bootstrap.Modal(modalElement);
                    }});

                    // Make all tables with class 'table' sortable
                    const allTables = document.querySelectorAll('table.table');
                    allTables.forEach(function(table) {{
                        if (table.id) {{
                            makeTableSortable(table.id);
                        }} else {{
                            // Assign an ID if it doesn't have one
                            table.id = 'table_' + Math.random().toString(36).substr(2, 9);
                            makeTableSortable(table.id);
                        }}
                    }});

                    /*/
                    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                        document.documentElement.setAttribute('data-bs-theme', prefersDark ? 'dark' : 'light');
                        themeToggle.checked = prefersDark;
                        themeToggle.addEventListener('change', function() {{
                            document.documentElement.setAttribute('data-bs-theme', this.checked ? 'dark' : 'light');
                    }});
                    /**/

                    var acc = document.getElementsByClassName("accordion");
                    for (var i = 0; i < acc.length; i++) {{
                        acc[i].addEventListener("click", function() {{
                            this.classList.toggle("active");
                            var panel = this.nextElementSibling;
                            if (panel.style.display === "block") {{
                                panel.style.display = "none";
                            }} else {{
                                panel.style.display = "block";
                            }}
                        }});
                    }}
                }});
            </script>
        </head>
        <body>
        {navbar}
        {content}
        </body>
        </html>
        """

    def _build_breadcrumbs(self, links: List[Tuple[str, str]], active_text: str) -> str:
        """
        Builds a breadcrumb navigation block with zero or more links and a final active item.

        Args:
            links (List[Tuple[str,str]]): Each tuple is (Link Text, Link Href).
            active_text (str): The text for the active breadcrumb item (no link).

        Returns:
            str: HTML for the breadcrumbs.
        """
        out = ['<nav aria-label="breadcrumb"><ol class="breadcrumb">']
        for link_text, link_href in links:
            out.append(
                f'<li class="breadcrumb-item"><a href="{escape(link_href)}">{escape(link_text)}</a></li>'
            )
        out.append(
            f'<li class="breadcrumb-item active" aria-current="page">{escape(active_text)}</li>'
        )
        out.append("</ol></nav>")
        return "".join(out)

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
        Writes a complete HTML page to 'html_file_path' using the shared template,
        and returns its relative path from self.report_dir.

        Args:
            html_file_path (Path): The destination HTML path.
            page_title (str): Title of the HTML page.
            content (str): The body content for the page.
            page_icon (str, optional): SVG icon HTML to display before the title.
            back_button (dict, optional): Dict with 'url' and 'text' for back button.
            subtitle (str, optional): Subtitle text to display under the title.

        Returns:
            str: The relative path from self.report_dir to the newly written HTML file.
        """
        # Build page header - always include H1, optionally with icon and back button
        page_header = ""

        # If we have a back button, wrap in flex layout
        if back_button:
            page_header = (
                '<div class="d-flex justify-content-between align-items-center mb-4">'
            )
            page_header += "<div>"

        # Always add H1 with optional icon
        page_header += "<h1>"
        if page_icon:
            page_header += page_icon
        page_header += page_title
        page_header += "</h1>"

        # Add subtitle if provided
        if subtitle:
            page_header += f'<p class="text-muted mb-0">{subtitle}</p>'

        # Close wrapper div and add back button if needed
        if back_button:
            page_header += "</div>"
            back_url = back_button.get("url", "index.html")
            back_text = back_button.get("text", "← Back")
            page_header += (
                f'<a href="{back_url}" class="btn btn-outline-primary">{back_text}</a>'
            )
            page_header += "</div>"

        # Combine page header with content
        full_content = page_header + content

        final_html = self.html_header_template.format(
            title=page_title, navbar=self.common_navbar, content=full_content
        )
        html_file_path.parent.mkdir(parents=True, exist_ok=True)
        with html_file_path.open("w", encoding="utf-8") as f:
            f.write(final_html)
        return os.path.relpath(html_file_path, self.report_dir).replace("\\", "/")

    async def _parse_collector_json_metadata(self, node_path: Path) -> None:
        """
        For each <group>.json in node_path/metadata or node_path/.metadata, parse the collector "execution_time"
        and store it in self.node_collector_json[node_name][group_name][collector_id].
        """
        await self._log(
            "DEBUG", f"Starting _parse_collector_json_metadata for {node_path}"
        )
        node_name = node_path.name

        # Check for both metadata and .metadata directories
        metadata_dirs = []
        for metadata_dir_name in ["metadata", ".metadata"]:
            metadata_dir = node_path / metadata_dir_name
            if metadata_dir.is_dir():
                metadata_dirs.append(metadata_dir)

        if not metadata_dirs:
            return

        if node_name not in self.node_collector_json:
            self.node_collector_json[node_name] = {}

        # Process all metadata directories found
        # Prioritize group-specific metadata files (redfish.json, ipmi.json, etc.) over general files
        for metadata_dir in metadata_dirs:
            # First pass: process group-specific metadata files
            for meta_json in metadata_dir.glob("*.json"):
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
                    with meta_json.open("r", encoding="utf-8") as f:
                        data = json.load(f)
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
                        collector_data = {
                            "execution_time_seconds": exec_seconds,
                            "status": status_val,
                            "reason": reason_val,
                            "group_name": group_name,
                            "id": cinfo.get("id", ""),
                            "name": cinfo.get("name", ""),
                            "files": files_val,
                        }
                        self.node_collector_json[node_name][group_name][
                            collector_id
                        ] = collector_data
                except Exception as ex:
                    await self._log(
                        "ERROR",
                        f"Error reading collector JSON {meta_json}: {ex}",
                    )

            # Second pass: process general metadata files (only if collector not already processed)
            for meta_json in metadata_dir.glob("*.json"):
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
                    with meta_json.open("r", encoding="utf-8") as f:
                        data = json.load(f)
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
                        collector_data = {
                            "execution_time_seconds": exec_seconds,
                            "status": status_val,
                            "reason": reason_val,
                            "group_name": group_name,
                            "id": cinfo.get("id", ""),
                            "name": cinfo.get("name", ""),
                            "files": files_val,
                        }
                        self.node_collector_json[node_name][group_name][
                            collector_id
                        ] = collector_data
                except Exception as ex:
                    await self._log(
                        "ERROR",
                        f"Error reading collector JSON {meta_json}: {ex}",
                    )

    async def generate_reports(self) -> bool:
        """
        Main method to generate all HTML reports.
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

            if not self.root_dir.is_dir():
                await self._log(
                    "ERROR",
                    f"Root directory {self.root_dir} is not a directory.",
                )
                return False

            for node in self.root_dir.iterdir():
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

        except Exception as e:
            await self._log("ERROR", f"Error generating HTML reports: {e}")
            return False

    async def _parse_execution_summary(self, file_path: Path) -> Dict:
        """
        Parses the Execution_Summary_Report.txt file.

        Args:
            file_path (Path): Path to the Execution_Summary_Report.txt file.

        Returns:
            Dict: Dictionary containing execution summary entries and log collection time.
        """
        summary = []
        log_collection_time = ""
        seen_entries = set()

        with file_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
            if not lines:
                await self._log("DEBUG", f"{file_path} is empty.")
                return {
                    "entries": summary,
                    "log_collection_time": log_collection_time,
                }

            header_line = lines[0].strip()
            headers = re.split(r"\s{2,}|\t+", header_line.lower())

            possible_log_path_headers = {
                "log path",
                "log_paths",
                "log_path",
                "log paths",
            }
            log_path_header = None
            for possible_header in possible_log_path_headers:
                if possible_header in headers:
                    log_path_header = possible_header
                    break

            if not log_path_header:
                await self._log(
                    "ERROR",
                    f"Log Path column not found in {file_path}. Headers: {headers}",
                )
                return {
                    "entries": summary,
                    "log_collection_time": log_collection_time,
                }

            # Handle case-insensitive header matching
            collection_name_idx = None
            collector_id_idx = None
            execution_status_idx = None

            for i, header in enumerate(headers):
                if "collection name" in header.lower():
                    collection_name_idx = i
                elif header.lower() in ["id", "collector id"]:
                    collector_id_idx = i
                elif "execution status" in header.lower():
                    execution_status_idx = i
            log_path_idx = headers.index(log_path_header)

            if collection_name_idx is None or execution_status_idx is None:
                await self._log(
                    "ERROR",
                    f"Required columns missing in {file_path}. Headers: {headers}",
                )
                return {
                    "entries": summary,
                    "log_collection_time": log_collection_time,
                }

            if collection_name_idx is None or execution_status_idx is None:
                await self._log("ERROR", f"Required columns missing in {file_path}")
                return {
                    "entries": summary,
                    "log_collection_time": log_collection_time,
                }

            for line_num, line_str in enumerate(lines[1:], start=2):
                line_str = line_str.strip()
                if not line_str:
                    continue
                if "log collection took" in line_str.lower():
                    log_collection_time = line_str
                    continue
                elif "total execution time:" in line_str.lower():
                    log_collection_time = line_str
                    continue

                parts = re.split(r"\s{2,}|\t+", line_str)
                if len(parts) < len(headers):
                    await self._log(
                        "DEBUG",
                        f"Line {line_num} in {file_path} missing columns.",
                    )
                    parts += [""] * (len(headers) - len(parts))

                collection_name_val = parts[collection_name_idx]
                execution_status_val = parts[execution_status_idx]
                log_path_val = [
                    p.strip() for p in parts[log_path_idx].split(",") if p.strip()
                ]

                # Get collector ID if available
                collector_id_val = None
                if collector_id_idx is not None and collector_id_idx < len(parts):
                    collector_id_val = parts[collector_id_idx].strip()
                    if collector_id_val == "N/A":
                        collector_id_val = None

                entry = {
                    "collection name": collection_name_val,
                    "execution status": execution_status_val,
                    "log path": log_path_val,
                    "collector_id": collector_id_val,
                }
                entry_tuple = (
                    collection_name_val,
                    execution_status_val,
                    tuple(log_path_val),
                )
                if entry_tuple not in seen_entries:
                    summary.append(entry)
                    seen_entries.add(entry_tuple)

        return {"entries": summary, "log_collection_time": log_collection_time}

    def _combine_statuses(self, summary_status: str, json_status: str) -> str:
        """
        Combines two status strings with priority: Error > Partial > Complete > Skipped > NotRan > Unknown.
        If either status is "Skipped", return "Skipped" to prevent it from being counted as an error.
        """
        priority = [
            "Error",
            "Partial",
            "Complete",
            "Skipped",
            "NotRan",
            "Unknown",
        ]
        if not summary_status:
            summary_status = "Unknown"
        if not json_status:
            json_status = "Unknown"

        s_list = summary_status.split()[0]
        j_list = json_status.split()[0]

        # Convert "Passed" => "Complete", "Failed" => "Error", etc.
        j_lower = j_list.lower()
        if j_lower == "passed":
            j_list = "Complete"
        elif j_lower == "failed":
            j_list = "Error"
        elif j_lower == "partial":
            j_list = "Partial"
        elif j_lower == "skipped":
            j_list = "Skipped"
        elif j_lower == "notran":
            j_list = "NotRan"

        if s_list not in priority:
            s_list = "Unknown"
        if j_list not in priority:
            j_list = "Unknown"

        # If either status is "Skipped", return "Skipped"
        if s_list == "Skipped" or j_list == "Skipped":
            return "Skipped"

        s_idx = priority.index(s_list)
        j_idx = priority.index(j_list)
        final_idx = min(s_idx, j_idx)
        final_status = priority[final_idx]
        if final_status.lower() == "notran":
            final_status = "N/A"
        return final_status

    def _merge_error_entries_into_node_json(
        self, node_name: str, grouped_entries: Dict
    ) -> None:
        """
        Locate ('error','logs','N/A') in grouped_entries, unify its log paths with
        the correct collector in self.node_collector_json[node_name].
        Skip merging error logs for collectors marked as Skipped.
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
        Looks for a grouped entry with key ('error', 'logs', 'N/A') and merges
        its log paths into any collectors whose name field matches the same collection name.
        If a match cannot be found in a real collector group, do NOT create a synthetic group (like 'dependency_check').
        If a collector is skipped and there is an error log, append the error log path to the 'log path' for that entry.
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

        Args:
            node_path (Path): Path to the node directory
            path_str (str): The path string to process
            from_status_page (bool): If True, prepend node name to links as they're viewed from status pages
        """
        results = []
        node_name = node_path.name  # Get the node name from the path

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
            search_dir = node_path / relative_path.parent
            if search_dir.exists() and search_dir.is_dir():
                for file_path in search_dir.iterdir():
                    if file_path.is_file():
                        relp = str(file_path.relative_to(node_path))
                        fv = await self._generate_file_view(file_path)
                        # Only prepend node name if viewing from status page
                        link = (
                            f"{escape(node_name)}/{escape(fv)}"
                            if from_status_page
                            else escape(fv)
                        )
                        results.append(f'<a href="{link}">{escape(relp)}</a>')
            else:
                results.append(f"{escape(path_str)} (directory not found)")
        else:
            try:
                abs_path = node_path / path_str.lstrip("/\\")

                # Check if this is a tar.xz file that was auto-parsed and removed
                if path_str.endswith(".tar.xz") and not abs_path.exists():
                    # Look for extracted directory with same base name
                    base_name = path_str[:-7]  # Remove .tar.xz
                    extracted_dir = node_path / base_name

                    if extracted_dir.exists() and extracted_dir.is_dir():
                        # List all files in the extracted directory
                        for subfile in extracted_dir.rglob("*"):
                            if subfile.is_file():
                                fv = await self._generate_file_view(subfile)
                                relp = str(subfile.relative_to(node_path))
                                # Only prepend node name if viewing from status page
                                link = (
                                    f"{escape(node_name)}/{escape(fv)}"
                                    if from_status_page
                                    else escape(fv)
                                )
                                results.append(f'<a href="{link}">{escape(relp)}</a>')

                        # If no files found, show the directory itself
                        if not results:
                            results.append(f"{escape(base_name)} (extracted directory)")
                    else:
                        # Original tar.xz file not found and no extracted directory
                        results.append(f"{escape(path_str)} (file not found)")
                elif abs_path.exists():
                    if abs_path.is_dir():
                        for subfile in abs_path.rglob("*"):
                            if subfile.is_file():
                                fv = await self._generate_file_view(subfile)
                                relp = str(subfile.relative_to(node_path))
                                # Only prepend node name if viewing from status page
                                link = (
                                    f"{escape(node_name)}/{escape(fv)}"
                                    if from_status_page
                                    else escape(fv)
                                )
                                results.append(f'<a href="{link}">{escape(relp)}</a>')
                    else:
                        fv = await self._generate_file_view(abs_path)
                        # Only prepend node name if viewing from status page
                        link = (
                            f"{escape(node_name)}/{escape(fv)}"
                            if from_status_page
                            else escape(fv)
                        )
                        results.append(f'<a href="{link}">{escape(path_str)}</a>')
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
        Renders Node name, log collection time, system details, collector groups, and categorized file listings.
        """
        # Node Info Card
        left_html = f"""
        <div class="card mb-3">
            <div class="card-body">
                <h4>Node: {escape(node_name)}</h4>
        """

        # Use corrected execution time if available, otherwise fall back to log_collection_time
        if node_execution_seconds is not None and node_execution_seconds > 0:
            left_html += f"<p><strong>Total execution time: {node_execution_seconds:.3f}s</strong></p>"
        elif log_collection_time:
            left_html += f"<p><strong>{escape(log_collection_time)}</strong></p>"

        # Insert system details snippet
        left_html += self._build_system_details_html(node_name)
        left_html += """
            </div>
        </div>
        """

        # --- Collector Groups Links ---
        collector_groups = self._get_collector_groups(node_path)
        if collector_groups:
            left_html += """
            <div class="card mb-3">
                <div class="card-body">
                    <h5>Collector Groups</h5>
                    <ul class="list-unstyled">
            """
            node_report_dir = self.report_dir / node_name
            for group_folder in collector_groups:
                # Only generate link if the directory actually exists
                if group_folder.is_dir():
                    group_name = group_folder.name
                    group_report_filename = f"{group_name}_report.html"
                    group_report_path = node_report_dir / group_report_filename
                    # Generate that group page if not already done (might be redundant but safe)
                    await self._generate_collector_group_report(
                        group_folder, node_path, group_report_path
                    )
                    rel_group_rep = os.path.relpath(
                        group_report_path, node_report_dir
                    ).replace("\\", "/")
                    left_html += f'<li><a href="{escape(rel_group_rep)}" class="d-block py-1"><i class="bi bi-folder"></i> {escape(group_name)}</a></li>'
            left_html += """
                    </ul>
                </div>
            </div>
            """

        # --- Categorize all files within the node directory recursively ---
        all_files = [
            f for f in node_path.rglob("*") if f.is_file() and "reports" not in f.parts
        ]

        metadata_files_found = []
        config_files_found = []
        runtime_logs_found = []
        error_logs_found = []
        misc_files_found = []
        collector_group_dirs = {gp.name for gp in collector_groups if gp.is_dir()}

        for f in all_files:
            relative_parts = f.relative_to(node_path).parts
            # Check parent directories first
            if len(relative_parts) > 1:
                parent_dir_name = relative_parts[0]
                if parent_dir_name in ["metadata", ".metadata"]:
                    metadata_files_found.append(f)
                    continue
                if parent_dir_name == "error-logs" or parent_dir_name == "error_logs":
                    error_logs_found.append(f)
                    continue
                # Exclude files within actual collector group directories from file lists
                # unless they are explicitly runtime/config logs we want to show.
                if (
                    parent_dir_name in collector_group_dirs
                    and f.name not in self.node_config_files
                    and f.name not in self.runtime_log_files
                ):
                    continue

            # Check file names for specific categories
            if f.name in self.node_config_files:
                config_files_found.append(f)
            elif f.name in self.runtime_log_files:
                runtime_logs_found.append(f)
            # If not categorized above and not excluded, it's misc
            elif (
                len(relative_parts) == 1
            ):  # Only consider files at the root as potentially misc
                misc_files_found.append(f)

        # --- Render Node Metadata Files ---
        if metadata_files_found:
            left_html += """
            <div class="card mb-3">
                <div class="card-body">
                    <h5>Node Metadata Files</h5>
            """

            # Group metadata files by their subdirectory structure
            metadata_groups = {}
            standalone_metadata = []

            for mf in metadata_files_found:
                relative_path = mf.relative_to(node_path)
                relative_parts = relative_path.parts

                # Replace .metadata with metadata on display
                display_path = str(relative_path).replace(".metadata", "metadata")

                if (
                    len(relative_parts) > 2
                ):  # Has subdirectory structure like metadata/detection_logs/file.json
                    group_name = relative_parts[1]  # e.g., "detection_logs"
                    if group_name not in metadata_groups:
                        metadata_groups[group_name] = []
                    metadata_groups[group_name].append((mf, display_path))
                else:  # Standalone metadata file like metadata/file.json
                    standalone_metadata.append((mf, display_path))

            # Render grouped metadata files
            for group_name in sorted(metadata_groups.keys()):
                group_files = metadata_groups[group_name]
                # Use a more readable group name
                readable_group_name = group_name.replace("_", " ").title()
                left_html += (
                    f"<h6>{escape(readable_group_name)}</h6><ul class='list-unstyled'>"
                )
                for mf, display_path in sorted(group_files, key=lambda x: x[1]):
                    file_view = await self._generate_file_view(mf)
                    left_html += f'<li><a href="{escape(file_view)}" class="d-block py-1"><i class="bi bi-file-earmark"></i> {escape(display_path)}</a></li>'
                left_html += "</ul>"

            # Render standalone metadata files
            if standalone_metadata:
                left_html += "<h6>General Metadata</h6><ul class='list-unstyled'>"
                for mf, display_path in sorted(standalone_metadata, key=lambda x: x[1]):
                    file_view = await self._generate_file_view(mf)
                    left_html += f'<li><a href="{escape(file_view)}" class="d-block py-1"><i class="bi bi-file-earmark"></i> {escape(display_path)}</a></li>'
                left_html += "</ul>"

            left_html += """
                </div>
            </div>
            """

        # --- Render Node Config Files ---
        if config_files_found:
            left_html += """
            <div class="card mb-3">
                <div class="card-body">
                    <h5>Node Config</h5>
                    <ul class='list-unstyled'>
            """
            for cf in sorted(config_files_found, key=lambda x: x.name):
                file_view = await self._generate_file_view(cf)
                relative_display = str(cf.relative_to(node_path))
                left_html += f'<li><a href="{escape(file_view)}" class="d-block py-1"><i class="bi bi-file-earmark-text"></i> {escape(relative_display)}</a></li>'
            left_html += """
                    </ul>
                </div>
            </div>
            """

        # --- Render Runtime Logs ---
        if runtime_logs_found:
            left_html += """
            <div class="card mb-3">
                <div class="card-body">
                    <h5>Runtime Logs</h5>
                    <ul class='list-unstyled'>
            """
            for rf in sorted(runtime_logs_found, key=lambda x: x.name):
                file_view = await self._generate_file_view(rf)
                relative_display = str(rf.relative_to(node_path))
                left_html += f'<li><a href="{escape(file_view)}" class="d-block py-1"><i class="bi bi-file-text"></i> {escape(relative_display)}</a></li>'
            left_html += """
                    </ul>
                </div>
            </div>
            """

        # --- Render Error Logs ---
        if error_logs_found:
            left_html += """
            <div class="card mb-3">
                <div class="card-body">
                    <h5>Error Logs</h5>
                    <ul class='list-unstyled'>
            """

            # Define sorting key inside here if only used here
            def alphanumeric_sort_key(filepath):
                parts = re.split(r"(\d+)", filepath.name)
                return [int(part) if part.isdigit() else part for part in parts]

            for ef in sorted(error_logs_found, key=alphanumeric_sort_key):
                fv = await self._generate_file_view(ef)
                relative_display = str(ef.relative_to(node_path))
                left_html += f'<li><a href="{escape(fv)}" class="d-block py-1"><i class="bi bi-exclamation-triangle"></i> {escape(relative_display)}</a></li>'
            left_html += """
                    </ul>
                </div>
            </div>
            """

        # --- Render Misc Files (only those at the node root) ---
        if misc_files_found:
            left_html += """
            <div class="card mb-3">
                <div class="card-body">
                    <h5>Misc Files</h5>
                    <ul class='list-unstyled'>
            """
            for misc_f in sorted(misc_files_found, key=lambda x: x.name):
                file_view = await self._generate_file_view(misc_f)
                # For misc files at root, just show the name
                left_html += f'<li><a href="{escape(file_view)}" class="d-block py-1"><i class="bi bi-file"></i> {escape(misc_f.name)}</a></li>'
            left_html += """
                    </ul>
                </div>
            </div>
            """

        return left_html

    async def _generate_node_report(self, node_path: Path) -> Optional[Path]:
        """
        Generates an HTML report for a single node.
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
                    if (
                        group_name_orig in node_json_data
                        or group_name_orig.lower() in node_json_data
                    ):
                        group_json = node_json_data.get(
                            group_name_orig,
                            node_json_data.get(group_name_orig.lower(), {}),
                        )
                        if c_id.lower() in group_json:
                            status = group_json[c_id.lower()].get("status", "Unknown")

                    grouped_entries.setdefault(
                        (group_cap, c_id, c_name),
                        [],
                    ).append(
                        {
                            "collection name": f"{group_cap}_{c_id}_{c_name}",
                            "execution status": status,
                            "log path": log_paths,
                            "id": c_id,
                            "name": c_name,
                            "group": group_name_orig,
                        }
                    )

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
                        grouped_entries.setdefault(
                            (
                                group_cap,
                                collector_id,
                                info_dict.get("name", "N/A"),
                            ),
                            [],
                        ).append(
                            {
                                "collection name": f"{group_cap}_{collector_id}_{info_dict.get('name', 'N/A')}",
                                "execution status": info_dict.get("status", "NotRan"),
                                "log path": info_dict.get("log path", []),
                                "id": info_dict.get("id", ""),
                                "name": info_dict.get("name", ""),
                                "group": info_dict.get("group_name", ""),
                            }
                        )
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
            log_paths_collected = []
            for ent in entries:
                worst_status = self._combine_statuses(
                    worst_status, ent["execution status"]
                )
                log_paths_collected.extend(ent["log path"])

            # JSON execution time (if any)
            j_exec_time = 0.0
            j_reason = ""
            j_status = ""
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
                        if c_info.get("status", "").lower() == "skipped":
                            j_status = "Skipped"
                        elif c_info.get("error_log_paths"):
                            j_status = "Error"
                        else:
                            j_status = c_info.get("status", "NotRan")
                        break

            worst_status = self._combine_statuses(worst_status, j_status)
            if cg.lower() == "error":
                worst_status = "Error"
            final_exec_time = max(0.0, j_exec_time)
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
                    if isinstance(log_path, str) and self._is_preexecution_filtered_reason(
                        log_path
                    ):
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

            modal_id = f"logModal_{node_name}_{cid}_{idx}"
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
                    "Log Size": log_size_str,
                    "NodePath": node_path,
                    "Log Path(s)": log_paths_collected,
                }
            )

        # Check if no rows were shown due to filtering
        if not any_rows_shown_in_node_report and self.hide_na_status:
            es_table += '<tr><td colspan="7" style="text-align: center;">No collections were found in collector map for this group.</td></tr>'

        es_table += "</tbody></table>"

        # Final node status
        if any(s == "Error" for s in all_node_statuses):
            node_status = "Error"
        elif any(s == "Partial" for s in all_node_statuses):
            node_status = "Partial"
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
            try:
                dependencies_path = node_path / "dependencies.txt"
                dependencies_path.write_text(dependencies_text, encoding="utf-8")
            except Exception:
                pass

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

        Args:
            node_path (Path): Path to the node directory
            log_paths (List[str]): List of log file paths relative to node_path

        Returns:
            int: Total size in bytes
        """
        total = 0
        # Track dirs and files separately to avoid double counting
        dir_paths: List[str] = []
        file_paths: List[str] = []
        for log_path in log_paths:
            # Skip if the path is a reason message (not a valid file path)
            if not log_path:
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

            full_path = node_path / clean_path
            if full_path.exists():
                if full_path.is_file():
                    file_paths.append(os.path.abspath(str(full_path)))
                elif full_path.is_dir():
                    dir_paths.append(os.path.abspath(str(full_path)))

        # Collect files from directories
        counted_files = set()
        for dir_path in dir_paths:
            try:
                for root, _, files in os.walk(dir_path):
                    for f in files:
                        file_path = os.path.join(root, f)
                        counted_files.add(os.path.abspath(file_path))
            except Exception:
                pass

        # Add explicit files that are not already covered by a directory
        for file_path in file_paths:
            if any(
                file_path.startswith(dir_path + os.sep) or file_path == dir_path
                for dir_path in dir_paths
            ):
                continue
            counted_files.add(file_path)

        # Sum sizes (one pass, unique files only)
        for file_path in counted_files:
            try:
                total += os.path.getsize(file_path)
            except Exception:
                pass
        return total

    def _build_preflight_status_cell(self, check_type: str, check_info: dict) -> tuple:
        """
        Build a single preflight check cell with icon and modal.
        Returns (cell_html, modal_html)
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
        Build HTML table for preflight checks. If group_name is provided, only show that group's check.
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

            # Add Bootstrap Icons CSS
            table = """
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
            <h3>Preflight Checks</h3>
            <table class='table table-striped table-bordered table-shadow'>
            <thead class='table-dark'>
            """

            modals = []
            node_name = node_path.name

            # Create dependency check modal
            dependency_modal_id = f"dependency_modal_{node_name}"
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
        Build HTML table for dependency checks. If group_name is provided, only show that group's checks.
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

        Args:
            node_path: DUT directory path.
            group_name: Optional group filter (redfish/ipmi/ssh/host/health_check).

        Returns:
            Plain-text table string.
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
                for group_data in node_execution_data.values():
                    if collector_id in group_data:
                        status = group_data[collector_id].get("status", "")
                        if status and status.lower() not in ["notran", "n/a", ""]:
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
                parts = ["-" * (width + 2) for width in widths]
                return f"+{'+'.join(parts)}+"

            def _format_row(values: List[str]) -> str:
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
        Build HTML table for a specific group's preflight check
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

            # Add Bootstrap Icons CSS
            table = """
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
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
        Build HTML table for dependency checks specific to a collector group
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
        Scans a collector group directory and returns information about collectors found on disk.

        Args:
            group_path: Path to the collector group directory
            node_path: Path to the node/DUT directory
            include_files: Whether to include file paths and generate file views

        Returns:
            Dictionary mapping collector_id (lowercase) to collector info:
            {
                "collector_id_orig": str,  # Original case collector ID
                "collector_name_orig": str,  # Original collector name
                "paths": List[Tuple[str, str]] or List[str],  # File paths (with or without views)
            }
        """
        if not group_path.is_dir():
            return {}

        try:
            items = list(group_path.iterdir())
        except (PermissionError, OSError) as e:
            await self._log(
                "WARNING",
                f"Failed to scan directory {group_path}: {e}",
            )
            return {}
        collectors = [
            x
            for x in items
            if (x.is_dir() or x.is_file())
            and not any(pattern.match(x.name) for pattern in self.log_ignore_patterns)
        ]

        requested_collector_ids = getattr(self, "requested_collector_ids", None)
        disk_dict = {}

        for it in collectors:
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
                if it.is_dir():
                    for subf in it.rglob("*"):
                        if subf.is_file():
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
                    left_content += f'<li><a href="{escape(rel_sibling)}" class="d-block py-1"><i class="bi bi-folder"></i> {escape(gname)}</a></li>'
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
                with open(execution_summary_path, "r") as f:
                    for line in f:
                        if line.strip() and not line.startswith("Collection Name"):
                            parts = line.split()
                            if len(parts) >= 3:
                                collector_id = parts[1]  # ID is the second column
                                executed_collector_ids.add(collector_id.upper())
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
                    link_objs.append(f'<a href="{escape(link)}">{escape(fp)}</a>')
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
                    link_objs.insert(0, f"{creason}")

                modal_id = f"modal_{node_name}_{group_name_orig}_{cid_real}_{idx}"
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

        Args:
            total_runtime: Optional total runtime in seconds.

        Returns:
            HTML string containing timing breakdown table.
        """
        try:
            timing_data = {}

            # Scan all DUT directories for metadata.json files
            for node in self.root_dir.iterdir():
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
        """
        # Replace spaces and special characters with underscores
        safe_name = re.sub(r"[^a-zA-Z0-9]", "_", node_name)
        # Ensure the ID starts with a letter
        safe_name = "n" + safe_name if not safe_name[0].isalpha() else safe_name
        return f"{prefix}_{safe_name}"

    def _is_baseboard_filtered_reason(self, reason: Optional[str]) -> bool:
        """
        Determine whether a reason string indicates baseboard-based filtering.
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
        Determine whether a reason string indicates the collector was filtered
        out before execution (e.g., due to preflight failures or collection
        level filtering).
        """
        if not reason:
            return False
        reason_lower = reason.lower()
        if "filtered out" in reason_lower and (
            "before execution" in reason_lower
            or "not executed" in reason_lower
        ):
            return True
        return False

    def _create_execution_summary_from_metadata(self, node_name: str) -> List[Dict]:
        """
        Create execution summary entries from metadata for nvdebug.
        Only includes collectors that were requested to run.
        """
        execution_summary = []

        # Get collector data from metadata
        node_data = self.node_collector_json.get(node_name, {})

        # Get the list of requested collector IDs to filter entries
        requested_collector_ids = getattr(self, "requested_collector_ids", None)

        for group_name, collectors in node_data.items():
            for collector_id, collector_info in collectors.items():
                # Skip collectors that weren't requested to run
                if requested_collector_ids and collector_id.upper() not in [
                    cid.upper() for cid in requested_collector_ids
                ]:
                    continue

                # Create execution summary entry
                entry = {
                    "collection name": f"{group_name}_{collector_id}_{collector_info.get('name', 'N/A')}",
                    "execution status": collector_info.get("status", "NotRan"),
                    "log path": [
                        f"{group_name.lower()}/{collector_id}_{collector_info.get('name', 'N/A')}"
                    ],
                    "collector_id": collector_id,  # Use "collector_id" to match what other code expects
                    "name": collector_info.get("name", "N/A"),
                    "group_name": group_name,
                }
                execution_summary.append(entry)

        return execution_summary

    async def _generate_timing_analysis_page(self) -> None:
        """
        Generate a comprehensive timing analysis page with interactive visualizations,
        timelines, and granular performance insights.
        """
        try:
            await self._log("INFO", "Generating timing analysis page...")

            # Collect timing data from both metadata.json and timing.json files
            metadata_timing_data = {}
            timing_data_by_dut = {}

            for node in self.root_dir.iterdir():
                if (
                    node.is_dir()
                    and not node.name.startswith(".")
                    and node.name not in ["reports", "temp", "backup"]
                ):
                    # Load timing.json for DUT/collector details
                    timing_json_path = node / ".metadata" / "timing.json"
                    if timing_json_path.exists():
                        try:
                            with open(timing_json_path, "r") as f:
                                timing_data = json.load(f)
                                dut_id = timing_data.get("dut_id", node.name)
                                timing_data_by_dut[dut_id] = timing_data
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
            total_failed = 0
            total_partial = 0
            total_skipped = 0

            for timing_data in timing_data_by_dut.values():
                for c in timing_data.get("collectors", {}).values():
                    total_collectors_overall += 1
                    status = str(c.get("status", "")).lower()
                    if status in ("complete", "success", "completed"):
                        total_success += 1
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
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3.0.0/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
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
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(135deg, #28a745 0%, #43e97b 100%);">
                        <div class="stat-number">{total_success}</div>
                        <div class="stat-label">Passed Collectors</div>
                        <div class="stat-label">of {total_collectors_overall} total</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(135deg, #f5576c 0%, #ff4b2b 100%);">
                        <div class="stat-number">{total_failed}</div>
                        <div class="stat-label">Failed Collectors</div>
                        <div class="stat-label">of {total_collectors_overall} total</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card" style="background: linear-gradient(315deg, #ffd54f 0%, #fff176 100%); color: #ffffff;">
                        <div class="stat-number">{total_partial}</div>
                        <div class="stat-label">Partial Collectors</div>
                        <div class="stat-label">of {total_collectors_overall} total</div>
                    </div>
                </div>
                <div class="col-md-3">
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
                            ${{dutId}}
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
                            barContent = `${{info.collector_name}} <span style="opacity: 0.7; margin-left: 6px;">(${{durationText}})</span>`;
                        }} else if (canFitDuration) {{
                            barContent = durationText;
                        }}

                        chartHTML += `
                            <div class="gantt-bar"
                                 data-dut="${{info.dut_id}}"
                                 data-collector="${{info.collector_name}}"
                                 data-service="${{info.group}}"
                                 data-status="${{info.status}}"
                                 data-duration="${{info.duration.toFixed(2)}}"
                                 data-start="${{startTime}}"
                                 data-end="${{endTime}}"
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

                        tooltip.innerHTML = `
                            <div style="font-weight: bold; margin-bottom: 6px; color: #4fc3f7; font-size: 13px;">DUT: ${{this.dataset.dut}}</div>
                            <div><strong>Collector:</strong> ${{this.dataset.collector}}</div>
                            <div><strong>Service:</strong> ${{this.dataset.service}}</div>
                            <div><strong>Status:</strong> <span style="color: ${{getStatusColor(this.dataset.status)}}">${{this.dataset.status}}</span></div>
                            <div><strong>Duration:</strong> ${{this.dataset.duration}}s</div>
                            <div><strong>Start:</strong> ${{this.dataset.start}}</div>
                            <div><strong>End:</strong> ${{this.dataset.end}}</div>
                        `;

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
                chartHTML += `<div style="height: ${{dutRowHeights[dutId]}}px; padding: 15px 10px; border-bottom: 1px solid #dee2e6; font-weight: 600; color: #2c3e50; display: flex; align-items: center; font-size: 13px;">${{dutId}}</div>`;
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
                    if (canFitName) barContent = `${{info.collector_name}} <span style="opacity: 0.7; margin-left: 6px;">(${{durationText}})</span>`;
                    else if (canFitDuration) barContent = durationText;
                    chartHTML += `
                        <div class="gantt-bar"
                             data-dut="${{info.dut_id}}"
                             data-collector="${{info.collector_name}}"
                             data-service="${{info.group}}"
                             data-status="${{info.status}}"
                             data-duration="${{info.duration.toFixed(2)}}"
                             data-start="${{startTime}}"
                             data-end="${{endTime}}"
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
                    tooltip.innerHTML = `
                        <div style="font-weight: bold; margin-bottom: 6px; color: #4fc3f7; font-size: 13px;">DUT: ${{this.dataset.dut}}</div>
                        <div><strong>Collector:</strong> ${{this.dataset.collector}}</div>
                        <div><strong>Service:</strong> ${{this.dataset.service}}</div>
                        <div><strong>Status:</strong> <span style="color: ${{getStatusColor(this.dataset.status)}}">${{this.dataset.status}}</span></div>
                        <div><strong>Duration:</strong> ${{this.dataset.duration}}s</div>
                        <div><strong>Start:</strong> ${{this.dataset.start}}</div>
                        <div><strong>End:</strong> ${{this.dataset.end}}</div>
                    `;
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

                                    tooltipEl.innerHTML = `
                                        <div style="font-weight: bold; margin-bottom: 5px; color: #4fc3f7;">DUT: ${{info.dut_id}}</div>
                                        <div><strong>Collector:</strong> ${{info.collector_name}}</div>
                                        <div><strong>Service:</strong> ${{info.group}}</div>
                                        <div><strong>Status:</strong> <span style="color: ${{dataPoint.color.replace('0.8', '1')}}">${{info.status}}</span></div>
                                        <div><strong>Duration:</strong> ${{info.duration.toFixed(2)}}s</div>
                                        <div><strong>Start:</strong> ${{startTime}}</div>
                                        <div><strong>End:</strong> ${{endTime}}</div>
                                    `;

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
                const errorCount = dutCollectors.filter(c => c.status.toUpperCase() === 'ERROR').length;
                const partialCount = dutCollectors.filter(c => c.status.toUpperCase() === 'PARTIAL').length;
                const skippedCount = dutCollectors.filter(c => c.status.toUpperCase() === 'SKIPPED').length;

                tableHTML += `
                    <tr>
                        <td><strong>${{dutId}}</strong></td>
                        <td>${{summary.duration.toFixed(2)}}s</td>
                        <td>${{new Date(summary.start_time).toLocaleString()}}</td>
                        <td>${{new Date(summary.end_time).toLocaleString()}}</td>
                        <td>${{summary.total_collectors}}</td>
                        <td class="text-success"><strong>${{successCount}}</strong></td>
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
                                  statusUpper === 'ERROR' ? 'table-danger' :
                                  statusUpper === 'SKIPPED' ? 'table-warning' : '';

                // Map service to color class
                const serviceClass = 'badge service-badge service-' + item.group.toLowerCase().replace(/[^a-z0-9]/g, '_');

                tableHTML += `
                    <tr class="${{statusClass}}">
                        <td>${{item.dut_id}}</td>
                        <td>${{item.collector_name}}</td>
                        <td><span class="${{serviceClass}}">${{item.group}}</span></td>
                        <td>${{item.status}}</td>
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
                                  statusUpper === 'ERROR' ? 'status-error' :
                                  statusUpper === 'SKIPPED' ? 'status-skipped' :
                                  'status-partial';
                // Map service to color class (consistent with table)
                const serviceClass = 'badge service-badge service-' + item.group.toLowerCase().replace(/[^a-z0-9]/g, '_');
                const startTime = new Date(item.start_time);
                const endTime = new Date(item.end_time);

                return `
                    <div class="collector-row ${{statusClass}}">
                        <span class="${{serviceClass}}">${{item.group}}</span>
                        <strong>${{item.collector_name}}</strong>
                        <span class="text-muted ms-2">[${{item.dut_id}}]</span>
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

                            tooltip.innerHTML = `
                                <div style="font-weight: bold; margin-bottom: 6px; color: #4fc3f7; font-size: 13px;">DUT: ${{this.dataset.dut}}</div>
                                <div><strong>Collector:</strong> ${{this.dataset.collector}}</div>
                                <div><strong>Service:</strong> ${{this.dataset.service}}</div>
                                <div><strong>Status:</strong> <span style="color: ${{getStatusColor(this.dataset.status)}}">${{this.dataset.status}}</span></div>
                                <div><strong>Duration:</strong> ${{this.dataset.duration}}s</div>
                                <div><strong>Start:</strong> ${{this.dataset.start}}</div>
                                <div><strong>End:</strong> ${{this.dataset.end}}</div>
                            `;

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

                                        tooltipEl.innerHTML = `
                                            <div style="font-weight: bold; margin-bottom: 5px; color: #4fc3f7;">DUT: ${{info.dut_id}}</div>
                                            <div><strong>Collector:</strong> ${{info.collector_name}}</div>
                                            <div><strong>Service:</strong> ${{info.group}}</div>
                                            <div><strong>Status:</strong> <span style="color: ${{dataPoint.color.replace('0.8', '1')}}">${{info.status}}</span></div>
                                            <div><strong>Duration:</strong> ${{info.duration.toFixed(2)}}s</div>
                                            <div><strong>Start:</strong> ${{startTime}}</div>
                                            <div><strong>End:</strong> ${{endTime}}</div>
                                        `;

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

        except Exception as e:
            await self._log("ERROR", f"Error generating timing analysis page: {e}")
            import traceback

            await self._log("ERROR", traceback.format_exc())

    async def _generate_top_level_report(self, node_reports: List[Path]) -> None:
        """
        Generates the top-level HTML report linking to individual node reports and the file map.
        """
        status_counts = {"Complete": 0, "Error": 0, "Skipped": 0, "N/A": 0}
        execution_times: List[(str, float)] = []
        modals: List[str] = []  # Initialize modals list

        # Sort node_reports by node name
        node_reports_sorted = sorted(node_reports, key=lambda p: p.parent.name.lower())

        # Calculate executive summary stats (prefer collection_status.json for alignment)
        total_duts = len(node_reports)
        total_log_size = 0
        total_collectors_pass = 0
        total_collectors_fail = 0
        total_collectors_partial = 0
        total_collectors_skipped = 0  # runtime-skipped only
        total_collectors_to_run = 0  # collectors_to_run (excludes filtered-out)
        total_collectors_all = 0  # includes filtered-out
        total_filtered_out = 0
        # Collect per-status details for executive-summary modals
        status_collectors = {
            "pass": defaultdict(list),
            "fail": defaultdict(list),
            "partial": defaultdict(list),
            "skipped": defaultdict(list),
        }

        # Build a per-DUT map of collector-group aliases to their report filenames
        node_group_report_map: Dict[str, Dict[str, str]] = {}
        for rep in node_reports_sorted:
            _dut_name = rep.parent.name
            _dut_path = self.root_dir / _dut_name
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
            node_path = self.root_dir / node_name
            log_size = self._get_total_log_size(node_path)
            total_log_size += log_size

            # Prefer per-DUT JSON if available
            dut_json = node_path / ".metadata" / "collection_status.json"
            if dut_json.exists():
                try:
                    with open(dut_json, "r", encoding="utf-8") as f:
                        dut_status = json.load(f)
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
                except Exception:
                    # Fallback to node_statuses_all if JSON parsing fails
                    statuses_for_node = self.node_statuses_all.get(node_name, [])
                    for status in statuses_for_node:
                        status_text = status.split()[0].lower()
                        total_collectors_all += 1
                        if status_text in ["complete", "success"]:
                            total_collectors_pass += 1
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
                    elif status_text == "error":
                        total_collectors_fail += 1
                    elif status_text == "partial":
                        total_collectors_partial += 1
                    elif status_text == "skipped":
                        total_collectors_skipped += 1

        # Helper to build status tables for modal bodies
        def build_status_table(data: Dict[str, List[Tuple[str, str, str, str]]]) -> str:
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
                links = "<br>".join(
                    f'<a href="{escape(dut)}/{escape(report_file)}#{escape(anchor_id)}">{escape(collector_id)} - {escape(collector_name)}</a>'
                    for collector_id, collector_name, report_file, anchor_id in collectors_for_dut_sorted
                )
                rows.append(f"<tr><td>{escape(dut)}</td><td>{links}</td></tr>")
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
        executive_summary = f"""
        <div class="mb-3">
            <h2 class="mb-4">Executive Summary</h2>
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
                <div class="col-md-3">
                    <div class="card text-white bg-success mb-3 h-100" style="cursor: pointer;" data-bs-toggle="modal" data-bs-target="#passedModal">
                        <div class="card-body text-center">
                            <h5 class="card-title">Passed Collectors</h5>
                            <p class="display-4">{total_collectors_pass}</p>
                            <small>of {total_collectors_to_run} to run</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-white bg-danger mb-3 h-100" style="cursor: pointer;" data-bs-toggle="modal" data-bs-target="#failedModal">
                        <div class="card-body text-center">
                            <h5 class="card-title">Failed Collectors</h5>
                            <p class="display-4">{total_collectors_fail}</p>
                            <small>of {total_collectors_to_run} to run</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card mb-3 h-100" style="cursor: pointer; background: linear-gradient(315deg, #ffd54f 0%, #fff176 100%); color: #ffffff;" data-bs-toggle="modal" data-bs-target="#partialModal">
                        <div class="card-body text-center">
                            <h5 class="card-title">Partial Collectors</h5>
                            <p class="display-4">{total_collectors_partial}</p>
                            <small>of {total_collectors_to_run} to run</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
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
                                <!-- Will be populated dynamically -->
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
            status_class = f"status-{status.lower()}"
            executive_summary += f"""
                                <tr>
                                    <td><a href="{node_name}/report.html">{escape(node_name)}</a></td>
                                    <td><span class="badge {status_class}">{escape(status)}</span></td>
                                    <td>{escape(exec_time_str)}</td>
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
            node_path = self.root_dir / node_name
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
            relative_path = os.path.relpath(report_html, self.report_dir).replace(
                "\\", "/"
            )
            exec_time = self.node_execution_times.get(node_name, 0.0)
            tdisp = self._format_time(exec_time) if exec_time else "N/A"

            # --- Compute total log size for the node (excluding its report directory) ---
            node_path = self.root_dir / node_name
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
                            <h5 class="modal-title" id="{firmware_modal_id}Label">Firmware Information - {node_name}</h5>
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
            <td>{escape(node_name)}</td>
            <td class="text-center"><a href=\"{escape(relative_path)}\" class=\"btn btn-dark btn-sm d-inline-block\">View Report</a></td>
            <td>{escape(tdisp)}</td>
            <td>{sys_display}</td>
            <td>{firmware_display}</td>
            <td>{escape(log_size_str)}</td>
            </tr>
            """

        # Generate runtime logs links for the Quick Actions card
        runtime_logs_list = ""
        for file_info in self.root_level_files:
            file_path = self.root_dir / file_info["path"]
            if file_path.exists():
                try:
                    fv = await self._generate_file_view(
                        file_path, file_info["display_name"]
                    )
                    runtime_logs_list += f"""
                    <a href="reports/{escape(fv)}" class="list-group-item list-group-item-action">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-file-text me-2" viewBox="0 0 16 16">
                            <path d="M5 4a.5.5 0 0 0 0 1h6a.5.5 0 0 0 0-1H5zm-.5 2.5A.5.5 0 0 1 5 6h6a.5.5 0 0 1 0 1H5a.5.5 0 0 1-.5-.5zM5 8a.5.5 0 0 0 0 1h6a.5.5 0 0 0 0-1H5zm0 2a.5.5 0 0 0 0 1h3a.5.5 0 0 0 0-1H5z"/>
                            <path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2zm10-1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1z"/>
                        </svg>
                        {escape(file_info['display_name'])}
                    </a>
                    """
                except Exception as e:
                    await self._log(
                        "ERROR",
                        f"Error generating view for {file_info['path']}: {e}",
                    )

        # Add script to populate runtime logs
        runtime_logs_script = f"""
        <script>
            document.addEventListener('DOMContentLoaded', function() {{
                const runtimeLogsList = document.getElementById('runtimeLogsList');
                if (runtimeLogsList) {{
                    runtimeLogsList.innerHTML = `{runtime_logs_list}`;
                }}
            }});
        </script>
        """
        node_table = node_table + runtime_logs_script

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
        // Add Bootstrap Icons CSS
        var link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = 'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css';
        document.head.appendChild(link);

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
            labels:{json.dumps(chart_data_status['labels'])},
            datasets:[{{
                data:{json.dumps(chart_data_status['counts'])},
                backgroundColor:{json.dumps(status_colors)},
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
        var timeTooltipLabels = {json.dumps(tooltip_labels_time)};

        var ctxTime = document.getElementById('timeChart').getContext('2d');
        var timeChart = new Chart(ctxTime,{{
            type: 'bar',
            data: {json.dumps(chart_data_time)},
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
            labels:{json.dumps([escape(n) for n, _ in execution_times])},
            datasets:[{{
                label:'Log Size (MB)',
                data:{json.dumps([round(self._get_total_log_size(self.root_dir / n) / (1024*1024), 2) for n, _ in execution_times])},
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
        Generates separate HTML pages for each execution status,
        using the same file-link logic as _generate_node_report.
        """
        # Get unique statuses and their counts
        status_counts = {}
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
                <th>Log Path(s)</th>
                </tr>
            </thead>
            <tbody>
            """

            modals_for_status = []
            for idx, entry in enumerate(filtered_entries):
                node_name = entry["Node Name"]
                log_paths = entry["Log Path(s)"]
                node_path = self.root_dir / node_name

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
                <td>{escape(entry['Collector Group'])}</td>
                <td>{escape(entry['Collector ID'])}</td>
                <td>{escape(entry['Collector Name'])}</td>
                <td>{escape(entry['Collector Exec Time'])}</td>
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
        Generates a global File Map page (file_map.html) with both a Table and Tree view.
        """
        tree_data = {}
        for item in self.global_file_map_data:
            node_val = item["Node Name"]
            group_val = item["Collector Group"]
            cid_val = item["Collector ID/Name"]
            file_val = item["File Path"]
            # link_val = item["Link"]
            base_link = item["Link"]
            link_val = f"{node_val}/{base_link}"

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
                    {"".join(f'<option value="{escape(node)}">{escape(node)}</option>' for node in sorted(nodes_set))}
                </select>
            </div>
            <div class="col-md-3">
                <label for="groupFilter" class="form-label">Filter by Group</label>
                <select class="form-select" id="groupFilter" onchange="filterFileMap()">
                    <option value="">All Groups</option>
                    {"".join(f'<option value="{escape(group)}">{escape(group)}</option>' for group in sorted(groups_set))}
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
        for row in self.global_file_map_data:

            node_val = row["Node Name"]
            group_val = row["Collector Group"]
            cid_val = row["Collector ID/Name"]
            file_val = row["File Path"]
            base_link = row["Link"]
            link_val = f"{node_val}/{base_link}"
            table_html += f"""
            <tr>
            <td>{escape(node_val)}</td>
            <td>{escape(group_val)}</td>
            <td>{escape(cid_val)}</td>
            <!--
              NOTE: This page also includes a Tree View with normal <a> links.
              Using <a href> here too creates duplicate href targets in the HTML.
              To keep the Table View navigable while avoiding duplicate hrefs, we render
              a button that navigates via JS.
            -->
            <td>
              <button type="button" class="btn btn-link p-0 file-link"
                      onclick='window.location.href={json.dumps(link_val)}'>
                {escape(row['File Path'])}
              </button>
            </td>
            </tr>
            """
        table_html += "</tbody></table>"

        def build_tree_html(obj):
            html = "<ul>"
            for k in sorted(obj.keys()):
                val_obj = obj[k]
                if isinstance(val_obj, dict):
                    html += f'<li class="folder"><span>{escape(k)}</span>'
                    html += build_tree_html(val_obj)
                    html += "</li>"
                else:
                    html += f'<li class="file"><a href="{escape(val_obj)}">{escape(k)}</a></li>'
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
        js_script = """
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

        content = table_html + tree_html + js_script
        file_map_html_path = self.report_dir / "file_map.html"
        self._write_html_report(file_map_html_path, "Global File Map", content)

    async def _parse_runtime_output(self, node_path: Path) -> Dict[str, str]:
        """
        Parses metadata/metadata.json or nvdebug_runtime_output.txt to extract system details.

        Args:
            node_path (Path): Path to the node directory.

        Returns:
            Dict[str, str]: Dictionary containing 'Model', 'Partno', and 'Serialno'.
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
            except Exception as e:
                await self._log("ERROR", f"Error reading {meta_json}: {e}")

        # fallback runtime
        if runtime_txt.is_file():
            try:
                with runtime_txt.open("r", encoding="utf-8") as f:
                    for line_str in f:
                        match_line = re.search(
                            r"Identified system as Model:\s*(?P<model>[^,]+),\s*Partno:\s*(?P<part>[^,]+),\s*Serialno:\s*(?P<ser>\d+)",
                            line_str,
                        )
                        if match_line:
                            details["Model"] = match_line.group("model").strip()
                            details["Partno"] = match_line.group("part").strip()
                            details["Serialno"] = match_line.group("ser").strip()
                            return details
            except Exception as e:
                await self._log("ERROR", f"Error reading {runtime_txt}: {e}")
        await self._log("DEBUG", f"No system details found for {node_path.name}")
        return details

    def _get_collector_groups(self, node_path: Path) -> List[Path]:
        """
        Identifies collector-group directories for a node. Returns groups that have collected data
        (either from directory contents or JSON metadata) to avoid 404 errors in navigation.
        """
        excluded = self.excluded_collector_groups
        found_dirs = [
            d for d in node_path.iterdir() if d.is_dir() and d.name not in excluded
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
            if not group_has_data and group_path.is_dir() and any(group_path.iterdir()):
                group_has_data = True

            if group_has_data:
                result.append(group_path)

        # Include any other directories that aren't known collector groups
        # But only if they contain files (to avoid empty directory reports)
        known_lowers = set(self.known_collector_groups.keys())
        for d in found_dirs:
            if d.name.lower() not in known_lowers:
                # Only include directories that actually contain files
                if any(d.iterdir()):
                    result.append(d)
        return result

    def _parse_collector_info_from_path(self, lp: str) -> Tuple[str, str, str]:
        """
        Parse collector information from path.
        Supports both legacy format and new format where service name comes from parent directory.
        Prioritizes collector ID prefix over directory name for proper group classification.
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
        Supports both legacy format (Redfish_R8_firmware_inventory) and new format (R8_firmware_inventory).
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

    async def _generate_file_view(
        self, file_path: Path, display_name: str = None
    ) -> str:
        """
        Generates an HTML view for a given file (json/text/log) or a direct download page for binary, etc.

        Args:
            file_path (Path): Path to the file to generate view for
            display_name (str, optional): Display name to use for the view title. If None, uses file_path.name
        """
        ext = file_path.suffix.lower()
        if ext == ".json":
            return self._generate_json_view(file_path, display_name)
        elif ext in (".txt", ".log"):
            return await self._generate_text_view(file_path, display_name)
        else:
            return self._generate_download_view(file_path, display_name)

    def _generate_download_view(
        self, file_path: Path, display_name: str = None, message: str = None
    ) -> str:
        """
        Generates an HTML page that offers a direct download link for files.

        Args:
            file_path: Path to the file
            display_name: Display name for the file
            message: Custom message to show (default: generic message)
        """
        display_name = display_name or file_path.name

        # Default message if none provided
        if message is None:
            message = "Unable to parse this file. Please download to view."

        download_html_name = f"{file_path.name}_download.html"
        html_file_path = self._get_html_output_path(
            file_path.parent, download_html_name
        )
        # Compute relative path from the download HTML file's directory to the original file.
        relative_file = os.path.relpath(
            file_path, os.path.dirname(html_file_path)
        ).replace("\\", "/")

        # Get file size for display
        try:
            file_size = file_path.stat().st_size
            file_size_str = self._format_bytes(file_size)
        except Exception:
            file_size_str = "Unknown size"

        content = f"""
        <div class="card">
            <div class="card-body">
                <h2>File: {escape(display_name)}</h2>
                <div class="alert alert-info" role="alert">
                    <i class="bi bi-info-circle"></i> {escape(message)}
                </div>
                <p><strong>File Size:</strong> {file_size_str}</p>
                <p><a href="{escape(relative_file)}" download class="btn btn-primary btn-lg">
                    <i class="bi bi-download"></i> Download {escape(display_name)}
                </a></p>
            </div>
        </div>
        """
        rel_html_path = self._write_html_report(
            html_file_path, f"Download: {display_name}", content
        )
        node_name = file_path.relative_to(self.root_dir).parts[0]
        base_dir = self.report_dir / node_name
        link = os.path.relpath(self.report_dir / rel_html_path, base_dir).replace(
            "\\", "/"
        )
        return link

    def _download_view_if_too_large(
        self, file_path: Path, display_name: str
    ) -> Optional[str]:
        """
        If file exceeds max_parseable_file_size, return a download-only HTML link; otherwise None.

        Args:
            file_path: Path to the file to check
            display_name: Label to display in the generated page

        Returns:
            Link to the generated download view, or None if size is acceptable or check fails
        """
        try:
            file_size = file_path.stat().st_size
            if file_size > self.max_parseable_file_size:
                file_size_mb = file_size / (1024 * 1024)
                message = (
                    f"This file is too large ({file_size_mb:.1f} MB) to parse and display in the browser. "
                    f"Files larger than {self.max_parseable_file_size / (1024 * 1024):.0f} MB are download-only for performance. "
                    f"Please download the file to view it locally."
                )
                return self._generate_download_view(file_path, display_name, message)
        except Exception:
            # If size check fails, just fall through and attempt to parse
            pass
        return None

    def _generate_json_view(self, file_path: Path, display_name: str = None) -> str:
        """
        Generates an HTML page with JSON syntax highlighting, or fallback to download if unreadable.
        Large files (>50MB) are automatically set to download-only for performance.
        """
        display_name = display_name or file_path.name

        # Check file size - if too large, create download view instead
        maybe = self._download_view_if_too_large(file_path, display_name)
        if maybe:
            return maybe

        try:
            with file_path.open("r", encoding="utf-8", errors="strict") as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._generate_download_view(file_path, display_name)
        except Exception as e:
            data = {"error": f"Error reading file: {e}"}
        tree_html = self._json_tree_html(data)
        content = f"""
        <div class="card">
            <div class="card-body">
                <h2>File: {escape(display_name)}</h2>
                <div id="jsonTree" class="json-tree">{tree_html}</div>
            </div>
        </div>
        """
        content += """
        <script>
        function toggleChildren(event) {
          event.stopPropagation();
          var next = this.nextElementSibling;
          if (next) {
             if (next.style.display === "none") {
                 next.style.display = "block";
             } else {
                 next.style.display = "none";
             }
          }
        }
        document.addEventListener("DOMContentLoaded", function() {
          var toggles = document.getElementsByClassName("json-toggle");
          for (var i = 0; i < toggles.length; i++) {
             toggles[i].addEventListener("click", toggleChildren);
          }
        });
        function jsonGlobalSearch(query) {
          var tree = document.getElementById("jsonTree");
          if(!tree) return;
          var spans = tree.getElementsByTagName("span");
          for (var i = 0; i < spans.length; i++) {
             spans[i].style.backgroundColor = "";
          }
          if(query === "") return;
          query = query.toLowerCase();
          for (var i = 0; i < spans.length; i++) {
             var txt = spans[i].innerText || spans[i].textContent;
             if(txt.toLowerCase().indexOf(query) > -1) {
                spans[i].style.backgroundColor = "yellow";
                var li = spans[i].closest("li");
                if(li) li.style.display = "";
             }
          }
        }
        </script>
        <style>
        .json-tree ul { list-style-type: none; margin-left: 20px; padding-left: 10px; border-left: 1px solid #ccc; }
        .json-toggle { cursor: pointer; font-weight: bold; }
        .json-value { color: #555; }
        </style>
        """
        html_file_path = self._get_html_output_path_for_file(file_path)
        node_name = file_path.relative_to(self.root_dir).parts[0]
        rel_html_path = self._write_html_report(
            html_file_path, f"View: {display_name}", content
        )
        base_dir = self.report_dir / node_name
        link = os.path.relpath(self.report_dir / rel_html_path, base_dir).replace(
            "\\", "/"
        )
        return link

    async def _generate_text_view(
        self, file_path: Path, display_name: str = None
    ) -> str:
        """
        Generates an HTML page with text/log syntax highlighting, or fallback to download if unreadable.
        Large files (>50MB) are automatically set to download-only for performance.
        """
        display_name = display_name or file_path.name

        # Check file size - if too large, create download view instead
        maybe = self._download_view_if_too_large(file_path, display_name)
        if maybe:
            return maybe

        try:
            with file_path.open("r", encoding="utf-8") as f:
                text_data = f.read()
        except UnicodeDecodeError:
            return self._generate_download_view(file_path, display_name)
        except Exception as e:
            text_data = f"Error reading file: {e}"
            await self._log("ERROR", f"Error reading {file_path}: {e}")

        # Check if this is a runtime/structured log and use interactive viewer
        if file_path.name in self.log_files_with_viewer or file_path.name.endswith(
            "_stdout.log"
        ):
            content = self._generate_log_viewer(text_data, display_name)
        else:
            content = f"""
            <div class="card">
                <div class="card-body">
                    <h2>File: {escape(display_name)}</h2>
                    <div class="file-view"><pre id="textView"><code class="language-json">{escape(text_data)}</code></pre></div>
                </div>
            </div>
            """
            content += """
            <script>
            function textGlobalSearch(query) {
               var pre = document.getElementById("textView");
               if(!pre) return;
               pre.innerHTML = pre.innerText;
               if(query === "") return;
               var regex = new RegExp('('+query+')', 'gi');
               pre.innerHTML = pre.innerHTML.replace(regex, '<mark>$1</mark>');
            }
            </script>
            """

        html_file_path = self._get_html_output_path_for_file(file_path)
        node_name = file_path.relative_to(self.root_dir).parts[0]
        rel_html_path = self._write_html_report(
            html_file_path, f"View: {display_name}", content
        )
        base_dir = self.report_dir / node_name
        link = os.path.relpath(self.report_dir / rel_html_path, base_dir).replace(
            "\\", "/"
        )
        return link

    def _generate_log_viewer(self, text_data: str, display_name: str) -> str:
        """
        Generates an interactive log viewer with filtering and syntax highlighting.
        """
        # Parse log to extract unique components and levels
        import re

        log_pattern = re.compile(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)")
        components = set()
        levels = set()

        for line in text_data.split("\n"):
            match = log_pattern.match(line)
            if match:
                level = match.group(2)
                component = match.group(3)
                levels.add(level)
                components.add(component)

        components = sorted(components)
        levels = sorted(levels)

        content = f"""
        <div class="card mb-3">
            <div class="card-body">
                <h2>Runtime Log Viewer: {escape(display_name)}</h2>
                <p class="text-muted">Interactive log viewer with filtering and syntax highlighting</p>

                <!-- Filter Controls -->
                <div class="row mb-3">
                    <div class="col-md-4">
                        <label class="form-label fw-bold">Search</label>
                        <input type="text" id="logSearch" class="form-control" placeholder="Search logs...">
                    </div>
                    <div class="col-md-4">
                        <label class="form-label fw-bold">Log Level</label>
                        <select id="levelFilter" class="form-select">
                            <option value="">All Levels</option>
                            {''.join(f'<option value="{escape(level)}">{escape(level)}</option>' for level in levels)}
                        </select>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label fw-bold">Component</label>
                        <select id="componentFilter" class="form-select">
                            <option value="">All Components</option>
                            {''.join(f'<option value="{escape(comp)}">{escape(comp)}</option>' for comp in components)}
                        </select>
                    </div>
                </div>

                <!-- Stats -->
                <div class="d-flex gap-3 mb-3">
                    <span class="badge bg-secondary">Total: <span id="totalLines">0</span> lines</span>
                    <span class="badge bg-primary">Visible: <span id="visibleLines">0</span> lines</span>
                    <button class="btn btn-sm btn-outline-secondary" onclick="copyLog()">
                        <i class="bi bi-clipboard"></i> Copy Filtered
                    </button>
                    <button class="btn btn-sm btn-outline-secondary" onclick="downloadLog()">
                        <i class="bi bi-download"></i> Download Filtered
                    </button>
                    <button class="btn btn-sm btn-outline-secondary" onclick="toggleWrap()">
                        <i class="bi bi-text-wrap"></i> Toggle Wrap
                    </button>
                </div>

                <!-- Log Content -->
                <div id="logContainer" class="border rounded" style="background: #1e1e1e !important; max-height: 600px; overflow: auto;">
                    <pre id="logView" style="margin: 0; padding: 15px; color: #f0f0f0 !important; background: #1e1e1e !important; font-family: 'Consolas', 'Monaco', 'Courier New', monospace; font-size: 13px; line-height: 1.5; text-shadow: none !important; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;"><code class="language-nvdebug" style="background: #1e1e1e !important; color: #f0f0f0 !important; text-shadow: none !important;">{escape(text_data)}</code></pre>
                </div>
            </div>
        </div>

        <style>
        /* Log viewer custom styles - Force dark theme and crisp rendering */
        /* Override Prism.js default styles completely */
        #logContainer *,
        #logContainer,
        #logContainer pre,
        #logContainer code,
        #logContainer pre[class*="language-"],
        #logContainer code[class*="language-"],
        #logContainer .token,
        #logContainer span {{
            background: #1e1e1e !important;
            color: #f0f0f0 !important;
            text-shadow: none !important;
            -webkit-font-smoothing: antialiased !important;
            -moz-osx-font-smoothing: grayscale !important;
            text-rendering: optimizeLegibility !important;
        }}
        .log-line {{
            display: block;
            border-left: 3px solid transparent;
            padding-left: 8px;
            margin: 2px 0;
        }}
        .log-line.log-ERROR {{
            background-color: rgba(249, 117, 131, 0.1);
            border-left-color: #f97583;
        }}
        .log-line.log-WARNING {{
            background-color: rgba(255, 171, 112, 0.1);
            border-left-color: #ffab70;
        }}
        .log-line.log-INFO {{
            background-color: rgba(86, 182, 194, 0.05);
            border-left-color: #56b6c2;
        }}
        .log-line.log-DEBUG {{
            background-color: rgba(158, 158, 158, 0.05);
            border-left-color: #9e9e9e;
        }}
        .log-line.hidden {{
            display: none !important;
        }}
        #logContainer .log-timestamp {{
            color: #999999 !important;
            text-shadow: none !important;
        }}
        .log-level {{
            font-weight: bold;
            padding: 2px 6px;
            border-radius: 3px;
            text-shadow: none !important;
        }}
        #logContainer .log-level-INFO {{
            color: #56b6c2 !important;
            text-shadow: none !important;
        }}
        #logContainer .log-level-DEBUG {{
            color: #9e9e9e !important;
            text-shadow: none !important;
        }}
        #logContainer .log-level-ERROR {{
            color: #f97583 !important;
            text-shadow: none !important;
        }}
        #logContainer .log-level-WARNING {{
            color: #ffab70 !important;
            text-shadow: none !important;
        }}
        #logContainer .log-component {{
            color: #4db8a8 !important;
            font-weight: 600;
            text-shadow: none !important;
        }}
        #logContainer .log-message {{
            color: #f0f0f0 !important;
            text-shadow: none !important;
        }}
        #logContainer .log-separator {{
            color: #888888 !important;
            opacity: 0.5;
            border-top: 1px solid #555;
            margin: 10px 0;
            text-shadow: none !important;
        }}
        #logContainer mark {{
            background-color: #ffeb3b !important;
            color: #000 !important;
            padding: 2px 4px;
            border-radius: 2px;
            text-shadow: none !important;
        }}
        </style>

        <script>
        // Define custom Prism language for nvdebug logs
        Prism.languages.nvdebug = {{
            'timestamp': /\\[\\d{{4}}-\\d{{2}}-\\d{{2}}\\s+\\d{{2}}:\\d{{2}}:\\d{{2}}\\.\\d{{3}}\\]/,
            'level-error': /\\[ERROR\\]/,
            'level-warning': /\\[WARNING\\]/,
            'level-info': /\\[INFO\\]/,
            'level-debug': /\\[DEBUG\\]/,
            'component': /\\]\\s+\\[([^\\]]+)\\]/,
            'separator': /^[=+\\-]{{2,}}.*$/m,
            'string': /"(?:\\\\.|[^"\\\\])*"/
        }};

        // Parse and render logs with structure
        document.addEventListener('DOMContentLoaded', function() {{
            parseAndRenderLogs();

            document.getElementById('logSearch').addEventListener('input', filterLogs);
            document.getElementById('levelFilter').addEventListener('change', filterLogs);
            document.getElementById('componentFilter').addEventListener('change', filterLogs);

            // Apply Prism highlighting after DOM is ready
            Prism.highlightAll();
        }});

        let logLines = [];
        let wrapEnabled = false;
        let renderChunkSize = 500; // Render 500 lines at a time for performance
        let currentRenderIndex = 0;
        let isRendering = false;

        function parseAndRenderLogs() {{
            const logView = document.getElementById('logView');
            const code = logView.querySelector('code');
            const text = code.textContent;
            const lines = text.split('\\n');

            // Show loading indicator for large logs
            if (lines.length > 5000) {{
                code.innerHTML = '<span style="color: #0dcaf0;">Parsing ' + lines.length + ' log lines...</span>';
            }}

            // Parse in chunks to avoid blocking UI
            const chunkSize = 1000;
            let chunkIndex = 0;

            function parseChunk() {{
                const start = chunkIndex * chunkSize;
                const end = Math.min(start + chunkSize, lines.length);

                for (let i = start; i < end; i++) {{
                    const line = lines[i];
                    const match = line.match(/\\[([^\\]]+)\\]\\s+\\[([^\\]]+)\\]\\s+\\[([^\\]]+)\\]\\s+(.*)/);
                    if (match) {{
                        logLines.push({{
                            raw: line,
                            timestamp: match[1],
                            level: match[2],
                            component: match[3],
                            message: match[4],
                            visible: true
                        }});
                    }} else {{
                        logLines.push({{
                            raw: line,
                            timestamp: null,
                            level: null,
                            component: null,
                            message: line,
                            visible: true
                        }});
                    }}
                }}

                chunkIndex++;

                if (end < lines.length) {{
                    // Continue parsing in next frame
                    setTimeout(parseChunk, 0);
                }} else {{
                    // Done parsing, now render
                    updateStats();
                    renderLogs();
                }}
            }}

            parseChunk();
        }}

        function filterLogs() {{
            const search = document.getElementById('logSearch').value.toLowerCase();
            const levelFilter = document.getElementById('levelFilter').value;
            const componentFilter = document.getElementById('componentFilter').value;

            logLines.forEach(log => {{
                let visible = true;

                // Apply search filter
                if (search && !log.raw.toLowerCase().includes(search)) {{
                    visible = false;
                }}

                // Apply level filter
                if (levelFilter && log.level !== levelFilter) {{
                    visible = false;
                }}

                // Apply component filter
                if (componentFilter && log.component !== componentFilter) {{
                    visible = false;
                }}

                log.visible = visible;
            }});

            renderLogs();
            updateStats();

            // Highlight search terms
            if (search) {{
                highlightSearch(search);
            }}
        }}

        function renderLogs() {{
            const logView = document.getElementById('logView');
            const code = logView.querySelector('code');

            // Filter visible logs
            const visibleLogs = logLines.filter(log => log.visible);

            // For large logs (>2000 lines), render in chunks
            if (visibleLogs.length > 2000) {{
                code.innerHTML = '<span style="color: #0dcaf0;">Rendering ' + visibleLogs.length + ' log lines...</span>';

                // Render in chunks to avoid UI freeze
                let rendered = [];
                let chunkIdx = 0;
                const chunkSize = 500;

                function renderChunk() {{
                    const start = chunkIdx * chunkSize;
                    const end = Math.min(start + chunkSize, visibleLogs.length);

                    for (let i = start; i < end; i++) {{
                        const log = visibleLogs[i];
                        if (log.timestamp) {{
                            const levelClass = `log-level-${{log.level}}`;
                            rendered.push(`<span class="log-timestamp">[${{log.timestamp}}]</span> <span class="log-level ${{levelClass}}">[${{log.level}}]</span> <span class="log-component">[${{log.component}}]</span> <span class="log-message">${{log.message}}</span>`);
                        }} else if (log.raw.match(/^[=+\\-]{{2,}}/)) {{
                            rendered.push(`<span class="log-separator">${{log.raw}}</span>`);
                        }} else {{
                            rendered.push(`<span class="log-message">${{log.raw}}</span>`);
                        }}
                    }}

                    chunkIdx++;

                    if (end < visibleLogs.length) {{
                        // Update progress and continue
                        const progress = Math.round((end / visibleLogs.length) * 100);
                        code.innerHTML = `<span style="color: #0dcaf0;">Rendering ${{progress}}%...</span>`;
                        setTimeout(renderChunk, 0);
                    }} else {{
                        // Done rendering
                        code.innerHTML = rendered.join('\\n');
                    }}
                }}

                renderChunk();
            }} else {{
                // Small log, render immediately
                const html = visibleLogs.map(log => {{
                    if (log.timestamp) {{
                        const levelClass = `log-level-${{log.level}}`;
                        return `<span class="log-timestamp">[${{log.timestamp}}]</span> <span class="log-level ${{levelClass}}">[${{log.level}}]</span> <span class="log-component">[${{log.component}}]</span> <span class="log-message">${{log.message}}</span>`;
                    }} else if (log.raw.match(/^[=+\\-]{{2,}}/)) {{
                        return `<span class="log-separator">${{log.raw}}</span>`;
                    }} else {{
                        return `<span class="log-message">${{log.raw}}</span>`;
                    }}
                }}).join('\\n');

                code.innerHTML = html;
            }}
        }}

        function highlightSearch(search) {{
            const logView = document.getElementById('logView');
            const code = logView.querySelector('code');
            const regex = new RegExp(`(${{search}})`, 'gi');
            code.innerHTML = code.innerHTML.replace(regex, '<mark>$1</mark>');
        }}

        function updateStats() {{
            const total = logLines.length;
            const visible = logLines.filter(l => l.visible).length;
            document.getElementById('totalLines').textContent = total;
            document.getElementById('visibleLines').textContent = visible;
        }}

        function copyLog() {{
            const filtered = logLines.filter(l => l.visible).map(l => l.raw).join('\\n');
            navigator.clipboard.writeText(filtered).then(() => {{
                alert('Filtered log copied to clipboard!');
            }});
        }}

        function downloadLog() {{
            const filtered = logLines.filter(l => l.visible).map(l => l.raw).join('\\n');
            const blob = new Blob([filtered], {{ type: 'text/plain' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'filtered_log.txt';
            a.click();
            URL.revokeObjectURL(url);
        }}

        function toggleWrap() {{
            const pre = document.getElementById('logView');
            wrapEnabled = !wrapEnabled;
            pre.style.whiteSpace = wrapEnabled ? 'pre-wrap' : 'pre';
        }}
        </script>
        """

        return content

    def _get_html_output_path_for_file(self, file_path: Path) -> Path:
        """
        Return the HTML file path under the 'reports' directory, preserving subdir structure.
        """
        try:
            rel_path = file_path.relative_to(self.root_dir)
        except ValueError:
            rel_path = Path(file_path.name)
        html_file_relative = rel_path.with_suffix(rel_path.suffix + ".html")
        return self.report_dir / html_file_relative

    def _get_html_output_path(self, parent_dir: Path, filename: str) -> Path:
        """
        Given a parent directory + desired HTML filename, returns a path under 'reports' with the same structure.
        """
        try:
            relative_dir = parent_dir.relative_to(self.root_dir)
        except ValueError:
            relative_dir = Path("")
        return self.report_dir / relative_dir / filename

    def _json_tree_html(self, data) -> str:
        """
        Returns HTML for a colorized, collapsible JSON tree, similar to the Chrome JSON Formatter.
        """

        # Convert the Python object to a direct HTML structure.
        # We'll represent objects and arrays with curly/straight brackets,
        # plus toggles that expand/collapse children.

        def render_json(obj) -> str:
            """
            Recursively build the HTML representation of 'obj'.

            Args:
                obj: Object to render as HTML.

            Returns:
                HTML string.
            """
            if isinstance(obj, dict):
                # For objects: { key: value, ... }
                # We'll show braces, and each item on a new line.
                if not obj:
                    # Empty dict
                    return '<span class="json-brace">{}</span>'
                html = []
                html.append('<span class="json-brace">{</span>')
                html.append('<div class="json-block" style="display: block;">')
                # Insert each key/value
                items = list(obj.items())
                count = len(items)
                for i, (k, v) in enumerate(items):
                    # Key
                    html.append('<div class="json-item">')
                    html.append(f'<span class="json-key">"{escape(str(k))}"</span>')
                    html.append('<span class="json-colon">: </span>')
                    # Value
                    html.append('<span class="json-value">')
                    html.append(render_json(v))
                    html.append("</span>")
                    # Comma if not last item
                    if i < count - 1:
                        html.append('<span class="json-comma">,</span>')
                    html.append("</div>")
                html.append("</div>")
                html.append('<span class="json-brace">}</span>')
                return "".join(html)
            elif isinstance(obj, list):
                # For arrays: [ item, ... ]
                if not obj:
                    return '<span class="json-bracket">[]</span>'
                html = []
                html.append('<span class="json-bracket">[</span>')
                html.append('<div class="json-block" style="display: block;">')
                count = len(obj)
                for i, val in enumerate(obj):
                    html.append('<div class="json-item">')
                    # Render each item
                    html.append(render_json(val))
                    # Comma if not last item
                    if i < count - 1:
                        html.append('<span class="json-comma">,</span>')
                    html.append("</div>")
                html.append("</div>")
                html.append('<span class="json-bracket">]</span>')
                return "".join(html)
            else:
                # Scalar (string, int, float, bool, None)
                return _render_scalar(obj)

        def _render_scalar(value) -> str:
            """
            Return a color-coded span for a JSON scalar.

            Args:
                value: Scalar value to render.

            Returns:
                HTML span element.
            """
            if value is None:
                return '<span class="json-literal json-null">null</span>'
            elif isinstance(value, bool):
                return f'<span class="json-literal json-boolean">{"true" if value else "false"}</span>'
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                return f'<span class="json-literal json-number">{escape(str(value))}</span>'
            else:
                # treat everything else as string
                # be sure to escape properly
                return f'<span class="json-string">"{escape(str(value))}"</span>'

        # Build the main content
        tree_html = render_json(data)

        # Wrap the entire tree in a container that has toggle scripts and styles:
        # Notice we add clickable toggles on the curly braces and brackets themselves,
        # to replicate that "Chrome extension" style of collapsing.
        # (You can also put the toggle on a little '+' or '–' symbol if you prefer.)
        return f"""
        <div class="json-container">
            {tree_html}
        </div>
        <script>
        // Collapsing/expanding logic:
        // We'll let users click on the brace/bracket to toggle the block that follows it.
        document.addEventListener('DOMContentLoaded', function() {{
            const braces = document.querySelectorAll('.json-brace, .json-bracket');
            braces.forEach(function(braceEl) {{
                braceEl.style.cursor = 'pointer';
                braceEl.addEventListener('click', function(e) {{
                    e.stopPropagation();
                    // The ".json-block" that immediately follows
                    const sibling = braceEl.nextElementSibling;
                    if(sibling && sibling.classList.contains('json-block')) {{
                        if(sibling.style.display === 'none') {{
                            sibling.style.display = 'block';
                        }} else {{
                            sibling.style.display = 'none';
                        }}
                    }}
                }});
            }});
        }});
        </script>
        <style>
        .json-container {{
            font-family: monospace;
            line-height: 1.4em;
            font-size: 14px;
            color: #333;
        }}
        .json-block {{
            margin-left: 1.5em;
            border-left: 1px dotted #ccc;
            padding-left: 1em;
        }}
        .json-item {{
            margin: 2px 0;
        }}
        .json-key {{
            color: #92278f;  /* purple-ish for keys */
        }}
        .json-literal.json-boolean {{
            color: #1a01cc;  /* bluish for booleans */
        }}
        .json-literal.json-null {{
            color: #777;     /* gray for null */
        }}
        .json-literal.json-number {{
            color: #0086b3;  /* teal-like for numbers */
        }}
        .json-string {{
            color: #c41a16;  /* dark red for strings */
        }}
        .json-colon {{
            color: #555;
        }}
        .json-comma {{
            color: #555;
            margin-left: 1px;
        }}
        .json-brace, .json-bracket {{
            color: #4b6eaf;
            font-weight: bold;
            margin-right: 3px;
        }}
        </style>
        """

    def _get_firmware_info(self, node_path: Path) -> Tuple[str, str]:
        """
        Get firmware information for a node.

        Args:
            node_path: Path to node directory.

        Returns:
            Tuple of (firmware_str, firmware_json_str).
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

        raw_firmware_data = []

        # Try R20 format first (table format)
        r20_path = (
            node_path
            / "redfish"
            / "Redfish_R20_firmware_inventory_table"
            / "firmware_inventory_table.json"
        )
        if r20_path.exists():
            try:
                with open(r20_path, "r") as f:
                    r20_data = json.load(f)
                    raw_firmware_data = r20_data
                    for item in r20_data:
                        item_id = item.get("Id", "")
                        version = item.get("Version", "")

                        # Compute node components
                        if item_id.startswith("FW_BMC_0"):
                            firmware_versions["BMC"].append(version)
                        elif item_id.startswith("HGX_FW_BMC_0"):
                            firmware_versions["HMC"].append(version)
                        elif item_id.startswith("HGX_FW_GPU_"):
                            firmware_versions["GPU"].append(version)
                        elif item_id.startswith("MGX_FW_NVSwitch_"):
                            firmware_versions["NVSwitch"].append(version)
                        elif item_id == "Software Inventory":
                            firmware_versions["Software"].append(version)

                        # Switch tray components
                        elif item_id.startswith("CPLD_"):
                            firmware_versions["CPLD"].append(version)
                        elif item_id.startswith("MGX_FW_BMC_"):
                            firmware_versions["BMC"].append(version)
                        elif item_id.startswith("MGX_FW_CPU_"):
                            firmware_versions["CPU"].append(version)
                        elif item_id.startswith("MGX_FW_ERoT_"):
                            firmware_versions["ERoT"].append(version)
            except Exception as e:
                print(f"Error reading R20 firmware data: {e}")

        # Try R9 format if R20 didn't provide data (expanded query format)
        if not any(firmware_versions.values()):
            r9_path = (
                node_path
                / "redfish"
                / "Redfish_R9_firmware_inventory_expand_query"
                / "Redfish_R9_firmware_inventory_expand_query.json"
            )
            if r9_path.exists():
                try:
                    with open(r9_path, "r") as f:
                        r9_data = json.load(f)
                        raw_firmware_data = r9_data.get("Members", [])
                        for member in raw_firmware_data:
                            member_id = member.get("Id", "")
                            version = member.get("Version", "")

                            # Compute node components
                            if member_id.startswith("FW_BMC_0"):
                                firmware_versions["BMC"].append(version)
                            elif member_id.startswith("HGX_FW_BMC_0"):
                                firmware_versions["HMC"].append(version)
                            elif member_id.startswith("HGX_FW_GPU_"):
                                firmware_versions["GPU"].append(version)
                            elif member_id.startswith("MGX_FW_NVSwitch_"):
                                firmware_versions["NVSwitch"].append(version)
                            elif member.get("Name", "") == "Software Inventory":
                                firmware_versions["Software"].append(version)

                            # Switch tray components
                            elif member_id.startswith("CPLD_"):
                                firmware_versions["CPLD"].append(version)
                            elif member_id.startswith("MGX_FW_BMC_"):
                                firmware_versions["BMC"].append(version)
                            elif member_id.startswith("MGX_FW_CPU_"):
                                firmware_versions["CPU"].append(version)
                            elif member_id.startswith("MGX_FW_ERoT_"):
                                firmware_versions["ERoT"].append(version)
                except Exception as e:
                    print(f"Error reading R9 firmware data: {e}")

        # Try R8 format if R9 didn't provide data (basic inventory format)
        if not any(firmware_versions.values()):
            r8_path = (
                node_path
                / "redfish"
                / "Redfish_R8_firmware_inventory"
                / "Redfish_R8_firmware_inventory.json"
            )
            if r8_path.exists():
                try:
                    with open(r8_path, "r") as f:
                        r8_data = json.load(f)
                        raw_firmware_data = r8_data.get("Members", [])
                        # R8 format only has references, not full details
                        # We'll show the available firmware items but without versions
                        for member in raw_firmware_data:
                            member_id = (
                                member.get("@odata.id", "").split("/")[-1]
                                if member.get("@odata.id")
                                else ""
                            )

                            # Categorize by ID patterns (without versions since R8 doesn't have them)
                            if member_id.startswith("FW_BMC_0"):
                                firmware_versions["BMC"].append("Available")
                            elif member_id.startswith("HGX_FW_BMC_0"):
                                firmware_versions["HMC"].append("Available")
                            elif member_id.startswith("HGX_FW_GPU_"):
                                firmware_versions["GPU"].append("Available")
                            elif member_id.startswith("MGX_FW_NVSwitch_"):
                                firmware_versions["NVSwitch"].append("Available")
                            elif member_id.startswith("CPLD_"):
                                firmware_versions["CPLD"].append("Available")
                            elif member_id.startswith("MGX_FW_BMC_"):
                                firmware_versions["BMC"].append("Available")
                            elif member_id.startswith("MGX_FW_CPU_"):
                                firmware_versions["CPU"].append("Available")
                            elif member_id.startswith("MGX_FW_ERoT_"):
                                firmware_versions["ERoT"].append("Available")
                except Exception as e:
                    print(f"Error reading R8 firmware data: {e}")

        # Generate summary display
        summary_parts = []
        for key, versions in firmware_versions.items():
            if versions:
                if len(set(versions)) == 1:
                    summary_parts.append(f"{key}: {versions[0]}")
                else:
                    summary_parts.append(f"{key}: Multiple versions")

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

        Args:
            progress: Rich progress object for displaying progress
            main_task: Main progress task ID

        Returns:
            bool: True if reports were generated successfully
        """
        try:
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

            if not self.root_dir.is_dir():
                await self._log(
                    "ERROR",
                    f"Root directory {self.root_dir} is not a directory.",
                )
                return False

            # Scan directory contents
            progress.update(
                main_task,
                completed=10,
                description="Scanning directory contents...",
            )

            # Count total nodes to process
            nodes_to_process = []
            for node in self.root_dir.iterdir():
                if node.is_dir() and node.name not in excluded_dirs:
                    nodes_to_process.append(node)

            total_nodes = len(nodes_to_process)
            if total_nodes == 0:
                progress.update(
                    main_task,
                    completed=90,
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

        except Exception as e:
            await self._log("ERROR", f"Error generating HTML reports: {e}")
            return False
