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
Timing Manager for NVDebug Tool.

Handles collection and storage of detailed timing information for collector
execution, including stage timing, component timing, and performance reporting.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .console_output import create_sanitized_console


class TimingManager:
    """
    Manages timing information for collector execution.

    Tracks timing at multiple levels including collector stages, hooks, and
    high-level tool components for performance analysis and reporting.

    Attributes:
        output_dir (Path): Directory for timing reports.
        debug_mode (bool): Whether debug mode is enabled.
        timing_data (dict): Collector timing data.
        component_timing (dict): High-level component timing.
    """

    def __init__(self, output_dir: Path, debug_mode: bool = False):
        """
        Initialize timing manager.

        Args:
            output_dir (Path): Output directory for timing reports.
            debug_mode (bool): Enable debug mode for detailed reports.
        """
        self.output_dir = output_dir
        self.debug_mode = debug_mode
        self.timing_data = {}
        self.current_collector = None
        self.current_stage = None
        self.current_hook = None

        # High-level component timing
        self.component_timing = {
            "tool_initialization": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "configuration_loading": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "dut_initialization": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "preflight_checks": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "collector_execution": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "html_report_generation": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "metadata_creation": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "cleanup": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
            "overall_runtime": {
                "start_time": None,
                "end_time": None,
                "total_time": 0.0,
            },
        }

        # Always collect timing, but only print/save detailed reports with debug
        self.always_collect = True

    def start_collector(self, collector_id: str, dut_id: str) -> None:
        """
        Start timing for a collector.

        Args:
            collector_id (str): Collector identifier.
            dut_id (str): DUT identifier.
        """
        if not self.always_collect:
            return

        self.current_collector = collector_id
        self.timing_data[collector_id] = {
            "collector_id": collector_id,
            "dut_id": dut_id,
            "start_time": time.time(),
            "stages": {},
            "total_time": 0.0,
            "status": "running",
        }

    def end_collector(self, collector_id: str, status: str = "completed") -> None:
        """
        End timing for a collector.

        Args:
            collector_id (str): Collector identifier.
            status (str): Completion status.
        """
        if not self.always_collect or collector_id not in self.timing_data:
            return

        self.timing_data[collector_id]["end_time"] = time.time()
        self.timing_data[collector_id]["total_time"] = (
            self.timing_data[collector_id]["end_time"]
            - self.timing_data[collector_id]["start_time"]
        )
        self.timing_data[collector_id]["status"] = status
        self.current_collector = None

    def start_stage(self, stage_name: str) -> None:
        """
        Start timing for a stage.

        Args:
            stage_name (str): Stage name.
        """
        if not self.always_collect or not self.current_collector:
            return

        self.current_stage = stage_name
        if stage_name not in self.timing_data[self.current_collector]["stages"]:
            self.timing_data[self.current_collector]["stages"][stage_name] = {
                "start_time": time.time(),
                "hooks": {},
                "total_time": 0.0,
            }

    def end_stage(self, stage_name: str) -> None:
        """
        End timing for a stage.

        Args:
            stage_name (str): Stage name.
        """
        if not self.always_collect or not self.current_collector:
            return

        if stage_name in self.timing_data[self.current_collector]["stages"]:
            stage_data = self.timing_data[self.current_collector]["stages"][stage_name]
            stage_data["end_time"] = time.time()
            stage_data["total_time"] = stage_data["end_time"] - stage_data["start_time"]
        self.current_stage = None

    def start_hook(self, hook_name: str) -> None:
        """
        Start timing for a hook.

        Args:
            hook_name (str): Hook name.
        """
        if (
            not self.always_collect
            or not self.current_collector
            or not self.current_stage
        ):
            return

        # Check if stage exists in timing data before accessing it
        if self.current_stage not in self.timing_data[self.current_collector]["stages"]:
            return

        self.current_hook = hook_name
        stage_data = self.timing_data[self.current_collector]["stages"][
            self.current_stage
        ]
        if hook_name not in stage_data["hooks"]:
            stage_data["hooks"][hook_name] = {
                "start_time": time.time(),
                "requests": {},
                "total_time": 0.0,
            }

    def end_hook(self, hook_name: str) -> None:
        """
        End timing for a hook.

        Args:
            hook_name (str): Hook name.
        """
        if (
            not self.always_collect
            or not self.current_collector
            or not self.current_stage
        ):
            return

        # Check if stage exists in timing data before accessing it
        if self.current_stage not in self.timing_data[self.current_collector]["stages"]:
            return

        stage_data = self.timing_data[self.current_collector]["stages"][
            self.current_stage
        ]
        if hook_name in stage_data["hooks"]:
            hook_data = stage_data["hooks"][hook_name]
            hook_data["end_time"] = time.time()
            hook_data["total_time"] = hook_data["end_time"] - hook_data["start_time"]
        self.current_hook = None

    def start_request(self, request_name: str) -> None:
        """
        Start timing for a Redfish/IPMI request.

        Args:
            request_name (str): Request name.
        """
        if (
            not self.always_collect
            or not self.current_collector
            or not self.current_stage
            or not self.current_hook
        ):
            return

        # Check if stage exists in timing data before accessing it
        if self.current_stage not in self.timing_data[self.current_collector]["stages"]:
            return

        stage_data = self.timing_data[self.current_collector]["stages"][
            self.current_stage
        ]
        if self.current_hook not in stage_data["hooks"]:
            return

        hook_data = stage_data["hooks"][self.current_hook]
        if request_name not in hook_data["requests"]:
            hook_data["requests"][request_name] = {
                "start_time": time.time(),
                "total_time": 0.0,
            }

    def end_request(self, request_name: str) -> None:
        """
        End timing for a Redfish/IPMI request.

        Args:
            request_name (str): Request name.
        """
        if (
            not self.always_collect
            or not self.current_collector
            or not self.current_stage
            or not self.current_hook
        ):
            return

        # Check if stage exists in timing data before accessing it
        if self.current_stage not in self.timing_data[self.current_collector]["stages"]:
            return

        stage_data = self.timing_data[self.current_collector]["stages"][
            self.current_stage
        ]
        if self.current_hook not in stage_data["hooks"]:
            return

        hook_data = stage_data["hooks"][self.current_hook]
        if request_name in hook_data["requests"]:
            request_data = hook_data["requests"][request_name]
            request_data["end_time"] = time.time()
            request_data["total_time"] = (
                request_data["end_time"] - request_data["start_time"]
            )

    def start_component(self, component_name: str) -> None:
        """
        Start timing for a high-level component.

        Args:
            component_name (str): Component name.
        """
        if component_name in self.component_timing:
            self.component_timing[component_name]["start_time"] = time.time()

    def end_component(self, component_name: str) -> None:
        """
        End timing for a high-level component.

        Args:
            component_name (str): Component name.
        """
        if (
            component_name in self.component_timing
            and self.component_timing[component_name]["start_time"] is not None
        ):
            self.component_timing[component_name]["end_time"] = time.time()
            self.component_timing[component_name]["total_time"] = (
                self.component_timing[component_name]["end_time"]
                - self.component_timing[component_name]["start_time"]
            )

    def get_component_timing(self) -> Dict[str, Any]:
        """
        Get the component timing data.

        Returns:
            Dict[str, Any]: Component timing dictionary.
        """
        return self.component_timing.copy()

    def log_timing(self, message: str) -> None:
        """
        Log a timing message (for debug output).

        Args:
            message (str): Timing message.
        """
        if self.debug_mode:
            print(f"TIMING: {message}")

    def print_timing_summary(self, sanitizer=None) -> None:
        """
        Print timing summary to console (debug mode only).

        Args:
            sanitizer: Sanitizer instance for output.
        """
        if not self.debug_mode or not self.timing_data:
            return

        console = create_sanitized_console(sanitizer)

        # Create a clear separator
        console.print_separator()
        console.print_header("TIMING SUMMARY")
        console.print_separator()

        for collector_id, data in self.timing_data.items():
            total_time = data.get("total_time", 0.0)
            status = data.get("status", "unknown")

            if status == "completed":
                console.print_success(
                    f"\nCollector {collector_id}: {total_time:.2f}s ({status})"
                )
            else:
                console.print_error(
                    f"\nCollector {collector_id}: {total_time:.2f}s ({status})"
                )

            for stage_name, stage_data in data.get("stages", {}).items():
                stage_time = stage_data.get("total_time", 0.0)
                console.print(f"  └─ {stage_name}: {stage_time:.2f}s", "cyan")

                for hook_name, hook_data in stage_data.get("hooks", {}).items():
                    hook_time = hook_data.get("total_time", 0.0)
                    console.print(f"    └─ {hook_name}: {hook_time:.2f}s", "yellow")

                    for request_name, request_data in hook_data.get(
                        "requests", {}
                    ).items():
                        request_time = request_data.get("total_time", 0.0)
                        console.print(
                            f"      └─ {request_name}: {request_time:.2f}s",
                            "white",
                        )

        console.print_separator()

    def save_timing_report(
        self, dut_id: str, dut_metadata_dir: Optional[Path] = None
    ) -> Optional[Path]:
        """
        Save timing report to JSON file in DUT metadata directory.

        Args:
            dut_id (str): DUT identifier.
            dut_metadata_dir (Optional[Path]): DUT metadata directory path.

        Returns:
            Optional[Path]: Path to saved report file, or None if not saved.
        """
        if not self.debug_mode or not self.timing_data:
            return None

        # Use provided DUT metadata directory or create timing_reports directory as fallback
        if dut_metadata_dir:
            timing_dir = dut_metadata_dir
        else:
            timing_dir = self.output_dir / "timing_reports"
            timing_dir.mkdir(exist_ok=True)

        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"timing_report_{dut_id}_{timestamp}.json"
        file_path = timing_dir / filename

        # Prepare report data
        report_data = {
            "metadata": {
                "dut_id": dut_id,
                "timestamp": datetime.now().isoformat(),
                "debug_mode": self.debug_mode,
                "total_collectors": len(self.timing_data),
            },
            "collectors": self.timing_data,
        }

        # Save to file
        with open(file_path, "w") as f:
            json.dump(report_data, f, indent=2)

        return file_path

    def get_summary(self) -> Dict[str, Any]:
        """
        Get timing summary.

        Returns:
            Dict[str, Any]: Timing summary dictionary.
        """
        if not self.debug_mode or not self.timing_data:
            return {}

        summary = {"total_collectors": len(self.timing_data), "collectors": {}}

        for collector_id, data in self.timing_data.items():
            summary["collectors"][collector_id] = {
                "total_time": data.get("total_time", 0.0),
                "status": data.get("status", "unknown"),
                "stages": {},
            }

            for stage_name, stage_data in data.get("stages", {}).items():
                summary["collectors"][collector_id]["stages"][stage_name] = {
                    "total_time": stage_data.get("total_time", 0.0),
                    "hooks": {},
                }

                for hook_name, hook_data in stage_data.get("hooks", {}).items():
                    summary["collectors"][collector_id]["stages"][stage_name]["hooks"][
                        hook_name
                    ] = {
                        "total_time": hook_data.get("total_time", 0.0),
                        "requests": {},
                    }

                    for request_name, request_data in hook_data.get(
                        "requests", {}
                    ).items():
                        summary["collectors"][collector_id]["stages"][stage_name][
                            "hooks"
                        ][hook_name]["requests"][request_name] = {
                            "total_time": request_data.get("total_time", 0.0)
                        }

        return summary

    def get_timing_summary_for_metadata(self) -> Dict[str, Any]:
        """
        Get timing summary for metadata storage (always available).

        Returns:
            Dict[str, Any]: Timing summary for metadata.
        """
        if not self.timing_data:
            return {}

        summary = {"total_collectors": len(self.timing_data), "collectors": {}}

        for collector_id, data in self.timing_data.items():
            summary["collectors"][collector_id] = {
                "total_time": data.get("total_time", 0.0),
                "status": data.get("status", "unknown"),
                "stages": {},
            }

            for stage_name, stage_data in data.get("stages", {}).items():
                summary["collectors"][collector_id]["stages"][stage_name] = {
                    "total_time": stage_data.get("total_time", 0.0)
                }

        return summary
