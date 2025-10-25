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
Output Formatter Utility for CLI Commands.

Handles JSON and table output formatting for various commands including
collector lists, baseboard information, and configuration data.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from rich.console import Console
from rich.table import Table


class OutputFormatter:
    """
    Utility class for formatting command output in JSON or table format.
    Handles JSON and table output formatting for various commands including
    collector lists, baseboard information, and configuration data.
    """

    def __init__(self, sanitized_console=None):
        """
        Initialize the OutputFormatter.

        Args:
            sanitized_console: Sanitized console instance.
        """
        self.sanitized_console = sanitized_console
        self.console = Console()

    def output_collectors(
        self,
        filtered_collectors: List[tuple],
        sequential_collectors: Set[str],
        json_output: bool = False,
        output_file: Optional[str] = None,
    ) -> None:
        """
        Output collectors in JSON or table format.

        Args:
            filtered_collectors: List of filtered collectors
            sequential_collectors: Set of sequential collectors
            json_output: Whether to output in JSON format
            output_file: File path to output to
        """
        if json_output:
            if output_file:
                self._output_json_to_file(
                    filtered_collectors, sequential_collectors, Path(output_file)
                )
            else:
                self._output_json_to_stdout(filtered_collectors, sequential_collectors)
        else:
            if output_file:
                self._output_table_to_file(
                    filtered_collectors, sequential_collectors, Path(output_file)
                )
            else:
                self._output_table_to_stdout(filtered_collectors, sequential_collectors)

    def output_preflight_results(
        self,
        results: Dict[str, Any],
        json_output: bool = False,
        output_file: Optional[str] = None,
    ) -> None:
        """
        Output preflight results in JSON or table format.

        Args:
            results: Results to output
            json_output: Whether to output in JSON format
            output_file: File path to output to
        """
        if json_output:
            if output_file:
                self._output_preflight_json_to_file(results, Path(output_file))
            else:
                self._output_preflight_json_to_stdout(results)
        else:
            if output_file:
                self._output_preflight_table_to_file(results, Path(output_file))
            else:
                self._output_preflight_table_to_stdout(results)

    def _output_json_to_stdout(
        self, filtered_collectors: List[tuple], sequential_collectors: Set[str]
    ) -> None:
        """
        Print JSON output directly to stdout.

        Args:
            filtered_collectors: List of filtered collectors
            sequential_collectors: Set of sequential collectors
        """
        collectors_data = []

        for collector_id, collector_info in filtered_collectors:
            collector_type = (
                "Sequential" if collector_id in sequential_collectors else "Parallel"
            )

            collectors_data.append(
                {
                    "id": collector_id,
                    "name": collector_info.get("name", ""),
                    "group": collector_info.get("group", ""),
                    "type": collector_type,
                    "level": collector_info.get("collection_level", "L1"),
                    "supported_baseboards": collector_info.get(
                        "applicable_baseboards", []
                    ),
                }
            )

        output_data = {
            "total_collectors": len(collectors_data),
            "collectors": collectors_data,
        }

        print(json.dumps(output_data, indent=2))

    def _output_json_to_file(
        self,
        filtered_collectors: List[tuple],
        sequential_collectors: Set[str],
        output_path: Path,
    ) -> None:
        """
        Write JSON output to a specified file.

        Args:
            filtered_collectors: List of filtered collectors
            sequential_collectors: Set of sequential collectors
            output_path: Path to the output file
        """
        # Validate and create output directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)

        collectors_data = []

        for collector_id, collector_info in filtered_collectors:
            collector_type = (
                "Sequential" if collector_id in sequential_collectors else "Parallel"
            )

            collectors_data.append(
                {
                    "id": collector_id,
                    "name": collector_info.get("name", ""),
                    "group": collector_info.get("group", ""),
                    "type": collector_type,
                    "level": collector_info.get("collection_level", "L1"),
                    "supported_baseboards": collector_info.get(
                        "applicable_baseboards", []
                    ),
                }
            )

        output_data = {
            "total_collectors": len(collectors_data),
            "collectors": collectors_data,
        }

        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2)

        if self.sanitized_console:
            self.sanitized_console.print_info(f"JSON output written to: {output_path}")
        else:
            print(f"JSON output written to: {output_path}")

    def _output_table_to_stdout(
        self, filtered_collectors: List[tuple], sequential_collectors: Set[str]
    ) -> None:
        """
        Print rich table output to stdout.

        Args:
            filtered_collectors: List of filtered collectors
            sequential_collectors: Set of sequential collectors
        """
        table = Table(title="Available Collectors")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Group", style="blue")
        table.add_column("Type", style="yellow")
        table.add_column("Level", style="magenta")
        table.add_column("Supported Baseboards", style="white")

        for collector_id, collector_info in filtered_collectors:
            collector_type = (
                "Sequential" if collector_id in sequential_collectors else "Parallel"
            )

            # Format supported baseboards
            supported_baseboards = collector_info.get("applicable_baseboards", [])
            if isinstance(supported_baseboards, list):
                baseboards_str = ", ".join(supported_baseboards)
            else:
                baseboards_str = (
                    str(supported_baseboards) if supported_baseboards else "None"
                )

            table.add_row(
                collector_id,
                collector_info.get("name", ""),
                collector_info.get("group", ""),
                collector_type,
                collector_info.get("collection_level", "L1"),
                baseboards_str,
            )

        self.console.print(table)

    def _output_table_to_file(
        self,
        filtered_collectors: List[tuple],
        sequential_collectors: Set[str],
        output_path: Path,
    ) -> None:
        """
        Write plain text table output to a specified file.

        Args:
            filtered_collectors: List of filtered collectors
            sequential_collectors: Set of sequential collectors
            output_path: Path to the output file
        """
        # Validate and create output directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            f.write("Available Collectors\n")
            f.write("=" * 80 + "\n\n")
            f.write(
                f"{'ID':<8} {'Name':<30} {'Group':<12} {'Type':<10} {'Level':<6} {'Supported Baseboards'}\n"
            )
            f.write("-" * 80 + "\n")

            for collector_id, collector_info in filtered_collectors:
                collector_type = (
                    "Sequential"
                    if collector_id in sequential_collectors
                    else "Parallel"
                )

                # Format supported baseboards
                supported_baseboards = collector_info.get("applicable_baseboards", [])
                if isinstance(supported_baseboards, list):
                    baseboards_str = ", ".join(supported_baseboards)
                else:
                    baseboards_str = (
                        str(supported_baseboards) if supported_baseboards else "None"
                    )

                f.write(
                    f"{collector_id:<8} {collector_info.get('name', ''):<30} {collector_info.get('group', ''):<12} {collector_type:<10} {collector_info.get('collection_level', 'L1'):<6} {baseboards_str}\n"
                )

        if self.sanitized_console:
            self.sanitized_console.print_info(f"Table output written to: {output_path}")
        else:
            print(f"Table output written to: {output_path}")

    def _output_preflight_json_to_stdout(self, results: Dict[str, Any]) -> None:
        """
        Print preflight results as JSON to stdout.

        Args:
            results: Results to output
        """
        print(json.dumps(results, indent=2))

    def _output_preflight_json_to_file(
        self, results: Dict[str, Any], output_path: Path
    ) -> None:
        """
        Write preflight results as JSON to a specified file.

        Args:
            results: Results to output
            output_path: Path to the output file
        """
        # Validate and create output directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

        if self.sanitized_console:
            self.sanitized_console.print_info(
                f"Preflight JSON output written to: {output_path}"
            )
        else:
            print(f"Preflight JSON output written to: {output_path}")

    def _output_preflight_table_to_stdout(self, results: Dict[str, Any]) -> None:
        """
        Print preflight results as rich table to stdout.

        Args:
            results: Results to output
        """

        # Get all unique service groups from the results
        all_groups = set()
        for dut_results in results.values():
            services = dut_results.get("services", {})
            all_groups.update(services.keys())

        # Sort groups for consistent display
        sorted_groups = sorted(all_groups)

        # Create the matrix-style table: DUT | Redfish | IPMI | SSH | Host | ...
        matrix_table = Table(title="Preflight Results Summary")
        matrix_table.add_column("DUT", style="cyan", width=20)

        # Add a column for each service group
        for group in sorted_groups:
            matrix_table.add_column(group.title(), justify="center", width=10)

        # Create rows for each DUT
        failure_details = []  # Store failure details for the second table

        for dut_id, dut_results in results.items():
            services = dut_results.get("services", {})
            row_data = [dut_id]

            # Add status for each service group
            for group in sorted_groups:
                service_result = services.get(group, {})
                status = service_result.get("status", "unknown")
                message = service_result.get("message", "")

                # Color code the status using Rich Text objects
                from rich.text import Text

                if status == "pass":
                    status_text = Text("PASS", style="green")
                elif status == "partial":
                    status_text = Text("PARTIAL", style="yellow")
                elif status == "skipped":
                    status_text = Text("SKIPPED", style="dim")
                elif status == "notran":
                    status_text = Text("NOT RAN", style="dim")
                elif status == "fail":
                    status_text = Text("FAIL", style="red")
                    # Store failure details
                    failure_details.append((dut_id, group.title(), message))
                else:
                    status_text = Text("? UNK", style="yellow")

                row_data.append(status_text)

            matrix_table.add_row(*row_data)

        # Print matrix table to console
        self.console.print(matrix_table)

        # Create failure details table if there are any failures
        if failure_details:
            self.console.print("")  # Add spacing

            failure_table = Table(title="Preflight Failure Details")
            failure_table.add_column("DUT", style="cyan", width=20)
            failure_table.add_column("Service", style="cyan", width=12)
            failure_table.add_column("Failure Reason", style="red")

            for dut_id, service, reason in failure_details:
                failure_table.add_row(dut_id, service, reason)

            self.console.print(failure_table)

    def _output_preflight_table_to_file(
        self, results: Dict[str, Any], output_path: Path
    ) -> None:
        """
        Write preflight results as plain text table to a specified file.

        Args:
            results: Results to output
            output_path: Path to the output file
        """
        # Validate and create output directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            f.write("Preflight Check Results\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"{'DUT':<20} {'Overall Status':<15} {'Services'}\n")
            f.write("-" * 50 + "\n")

            for dut_name, result in results.items():
                overall_status = result.get("overall_status", "unknown")
                services = result.get("services", {})

                # Format services status
                service_statuses = []
                for service_name, service_result in services.items():
                    status = service_result.get("status", "unknown")
                    service_statuses.append(f"{service_name}: {status}")

                service_details = "; ".join(service_statuses)

                # Format status for plain text
                if overall_status == "pass":
                    status_display = "PASS"
                elif overall_status == "partial":
                    status_display = "PARTIAL"
                else:
                    status_display = "FAIL"

                f.write(f"{dut_name:<20} {status_display:<15} {service_details}\n")

        if self.sanitized_console:
            self.sanitized_console.print_info(
                f"Preflight table output written to: {output_path}"
            )
        else:
            print(f"Preflight table output written to: {output_path}")

    def _output_baseboards_json_to_stdout(self, data: Dict[str, Any]) -> None:
        """
        Print baseboards as JSON to stdout.

        Args:
            data: Data to output
        """
        print(json.dumps(data, indent=2))

    def _output_baseboards_json_to_file(
        self, data: Dict[str, Any], output_path: Path
    ) -> None:
        """
        Write baseboards as JSON to a specified file.

        Args:
            data: Data to output
            output_path: Path to the output file
        """
        # Validate and create output directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

        if self.sanitized_console:
            self.sanitized_console.print_info(
                f"Baseboards JSON output written to: {output_path}"
            )
        else:
            print(f"Baseboards JSON output written to: {output_path}")

    def _output_baseboards_table_to_stdout(self, data: Dict[str, Any]) -> None:
        """
        Print baseboards as rich table to stdout.

        Args:
            data: Data to output
        """
        baseboards = data.get("baseboards", [])

        table = Table(title="Available Baseboards")
        table.add_column("Baseboard", style="cyan")
        table.add_column("Type", style="blue")
        table.add_column("Group", style="green")
        table.add_column("Description", style="white")

        for baseboard_info in baseboards:
            table.add_row(
                baseboard_info.get("name", ""),
                baseboard_info.get("type", ""),
                baseboard_info.get("group", ""),
                baseboard_info.get("description", ""),
            )

        self.console.print(table)

        if self.sanitized_console:
            self.sanitized_console.print_success(f"Total baseboards: {len(baseboards)}")
        else:
            print(f"Total baseboards: {len(baseboards)}")

    def _output_baseboards_table_to_file(
        self, data: Dict[str, Any], output_path: Path
    ) -> None:
        """
        Write baseboards as plain text table to a specified file.

        Args:
            data: Data to output
            output_path: Path to the output file
        """
        # Validate and create output directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)

        baseboards = data.get("baseboards", [])

        with open(output_path, "w") as f:
            f.write("Available Baseboards\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"{'Baseboard':<25} {'Type':<15} {'Group':<15} {'Description'}\n")
            f.write("-" * 80 + "\n")

            for baseboard_info in baseboards:
                f.write(
                    f"{baseboard_info.get('name', ''):<25} {baseboard_info.get('type', ''):<15} {baseboard_info.get('group', ''):<15} {baseboard_info.get('description', '')}\n"
                )

            f.write("-" * 80 + "\n")
            f.write(f"Total baseboards: {len(baseboards)}\n")

        if self.sanitized_console:
            self.sanitized_console.print_info(
                f"Baseboards table output written to: {output_path}"
            )
        else:
            print(f"Baseboards table output written to: {output_path}")

    @staticmethod
    def format_time(seconds: float) -> str:
        """
        Convert float seconds to a human-readable time format like 'Xh Ym Z.zzs'.

        Args:
            seconds: Time in seconds as a float

        Returns:
            str: Human-readable time string (e.g., "12m 35.48s", "1h 23m 45.67s")
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
