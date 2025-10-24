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
Execution Summary Management.

This module handles the generation of execution summary files in the legacy
nvdebug format with per-DUT summary tracking and status reporting.
"""

import fcntl
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class ExecutionSummaryManager:
    """
    Manages execution summary file generation.

    Handles per-DUT execution summary tracking with collector status,
    timing information, and file paths.

    Attributes:
        log_dir (Path): Base log directory.
        summary_file (str): Summary file name.
        summary_files (Dict[str, Path]): DUT-specific summary file paths.
        entries (Dict[str, List[Dict[str, Any]]]): DUT-specific log entries.
        start_time (datetime): Global start time.
        dut_start_times (Dict[str, datetime]): Per-DUT start times.
    """

    def __init__(self, log_dir: Path):
        """
        Initialize execution summary manager.

        Args:
            log_dir (Path): Base log directory.
        """
        self.log_dir = log_dir
        self.summary_file = "Execution_Summary_Report.txt"
        self.summary_files: Dict[str, Path] = {}  # DUT-specific summary files
        self.entries: Dict[str, List[Dict[str, Any]]] = {}  # DUT-specific entries
        self.start_time = (
            datetime.now()
        )  # Keep global start time for backward compatibility
        self.dut_start_times: Dict[str, datetime] = {}  # DUT-specific start times

    def set_dut_start_time(self, dut_id: str, start_time: datetime) -> None:
        """
        Set the start time for a specific DUT.
        This should be called when the collection actually starts for the DUT.

        Args:
            dut_id: DUT identifier
            start_time: The actual start time when collection began for this DUT
        """
        self.dut_start_times[dut_id] = start_time

    async def add_entry(
        self,
        dut_id: str,
        collection_name: str,
        status: str,
        log_paths: List[str],
        custom_reason: Optional[str] = None,
        collector_id: Optional[str] = None,
    ) -> None:
        """
        Add an entry to the execution summary for a specific DUT

        Args:
            dut_id: DUT identifier
            collection_name: Name of the collector (e.g., "system_event_log")
            status: Status of execution ("Complete", "Error", "Skipped")
            log_paths: List of log file paths generated
            custom_reason: Optional custom reason for the status
            collector_id: Optional collector ID (e.g., "S1", "R8")
        """
        # Initialize DUT-specific data structures
        if dut_id not in self.entries:
            self.entries[dut_id] = []
            # Only set start time if not already set via set_dut_start_time
            if dut_id not in self.dut_start_times:
                self.dut_start_times[dut_id] = datetime.now()
        if dut_id not in self.summary_files:
            dut_log_dir = self.log_dir / dut_id
            self.summary_files[dut_id] = dut_log_dir / self.summary_file

        # Normalize status text
        status_text = self._normalize_status(status)

        # Clean up log paths
        cleaned_paths = self._clean_log_paths(log_paths, dut_id)

        # Discover files in the cleaned paths
        try:
            discovered_files = self._discover_files_in_paths(cleaned_paths, dut_id)
        except Exception:
            # If file discovery fails, continue without discovered files
            discovered_files = {}

        # Create entry
        entry = {
            "collection_name": collection_name,
            "status": status_text,
            "log_paths": cleaned_paths,
            "discovered_files": discovered_files,
            "reason": custom_reason,
            "collector_id": collector_id,
        }

        self.entries[dut_id].append(entry)

        # Write to file immediately
        try:
            self._write_entry_to_file(dut_id, entry)
            # Update collector status in metadata with discovered files
            self._update_collector_metadata_with_files(dut_id, entry)

        except Exception:
            # Silently fail if file write fails, entry is still in memory
            pass

    def _deduplicate_log_paths(self, log_paths: List[str]) -> List[str]:
        """
        Deduplicate log paths, handling comma-separated strings.

        Args:
            log_paths: List of log paths (may contain comma-separated strings)

        Returns:
            List of unique log paths
        """
        if not log_paths:
            return []

        # Collect all individual paths
        all_paths = []
        for path in log_paths:
            if not path:
                continue
            # Split by comma in case this is a comma-separated string
            if "," in path:
                parts = [p.strip() for p in path.split(",") if p.strip()]
                all_paths.extend(parts)
            else:
                all_paths.append(path.strip())

        # Use dict to preserve order while removing duplicates (Python 3.7+)
        unique_paths = list(dict.fromkeys(all_paths))
        return unique_paths

    def _normalize_status(self, status: str) -> str:
        """
        Normalize status to legacy format.

        Args:
            status: Status string to normalize.

        Returns:
            Normalized status string.
        """
        # print(
        #     f"DEBUG: _normalize_status called with status='{status}' (type: {type(status)})"
        # )
        if status is None:
            result = "Unknown"
        elif status == "partial":
            result = "Partial"
        elif status is True or status == "success" or status == "pass":
            result = "Complete"
        elif status is False or status == "error" or status == "fail":
            result = "Error"
        elif status == "skipped" or status == "not_ran":
            result = "Skipped"
        else:
            result = str(status)
        # print(f"DEBUG: _normalize_status returning '{result}'")
        return result

    def _clean_log_paths(self, log_paths: List[str], dut_id: str) -> List[str]:
        """
        Clean and normalize log paths to parent directories.

        Args:
            log_paths: List of log file paths.
            dut_id: DUT ID for path resolution.

        Returns:
            List of cleaned log paths.
        """
        if not log_paths:
            return [""]

        # Convert to list if single path
        if isinstance(log_paths, str):
            log_paths = [log_paths]

        # Remove empty or None values
        cleaned_paths = [p for p in log_paths if p]
        if not cleaned_paths:
            return [""]

        # Convert to relative paths from DUT log directory
        dut_log_dir = self.log_dir / dut_id
        result_paths = set()

        for path in cleaned_paths:
            if os.path.exists(path):
                # Make path relative to DUT log directory
                try:
                    rel_path = os.path.relpath(path, dut_log_dir)

                    # For error logs, keep the specific file path
                    if "error-logs" in rel_path:
                        result_paths.add(rel_path)
                    else:
                        # For other files, get parent directory
                        parent_dir = str(Path(rel_path).parent)
                        if parent_dir and parent_dir != ".":
                            result_paths.add(parent_dir)
                        else:
                            result_paths.add(rel_path)
                except ValueError:
                    # If paths are on different drives or outside DUT directory, use absolute path
                    if "error-logs" in path:
                        result_paths.add(path)
                    else:
                        result_paths.add(str(Path(path).parent))
            else:
                # For non-existent paths, check if they're outside DUT directory
                try:
                    rel_path = os.path.relpath(path, dut_log_dir)
                    # If path is outside DUT directory, keep as absolute path
                    if rel_path.startswith(".."):
                        if "error-logs" in path:
                            result_paths.add(path)
                        else:
                            result_paths.add(str(Path(path).parent))
                    else:
                        # For paths within DUT directory, get parent directory
                        if "error-logs" in path:
                            result_paths.add(path)
                        else:
                            parent_dir = str(Path(rel_path).parent)
                            if parent_dir and parent_dir != ".":
                                result_paths.add(parent_dir)
                            else:
                                result_paths.add(rel_path)
                except ValueError:
                    # If paths are on different drives, use absolute path
                    if "error-logs" in path:
                        result_paths.add(path)
                    else:
                        result_paths.add(str(Path(path).parent))

        # Return unique paths
        result = list(result_paths) if result_paths else cleaned_paths
        return result if result else [""]

    def _discover_files_in_paths(
        self, log_paths: List[str], dut_id: str
    ) -> Dict[str, List[str]]:
        """
        Discover all files in the given log paths and return a mapping of folder paths to file lists.
        Handles both individual files (like error logs) and directories.

        Args:
            log_paths: List of folder paths or individual file paths to discover files in
            dut_id: DUT identifier for relative path calculation

        Returns:
            Dict mapping folder paths to lists of discovered file paths
        """
        dut_log_dir = self.log_dir / dut_id
        discovered_files = {}

        for path in log_paths:
            if not path or path == "":
                continue

            # Convert to absolute path if needed
            if os.path.isabs(path):
                abs_path = Path(path)
            else:
                abs_path = dut_log_dir / path

            # Skip if path doesn't exist
            if not abs_path.exists():
                continue

            # Handle individual files (like error logs)
            if abs_path.is_file():
                try:
                    # Make path relative to DUT log directory
                    rel_file_path = os.path.relpath(abs_path, dut_log_dir)
                    # Use the parent directory as the key for consistency
                    parent_dir = str(Path(rel_file_path).parent)
                    if parent_dir == ".":
                        parent_dir = (
                            rel_file_path  # If file is in root, use file path as key
                        )

                    if parent_dir not in discovered_files:
                        discovered_files[parent_dir] = []
                    discovered_files[parent_dir].append(rel_file_path)

                except ValueError:
                    # If paths are on different drives, use absolute path
                    parent_dir = str(abs_path.parent)
                    if parent_dir not in discovered_files:
                        discovered_files[parent_dir] = []
                    discovered_files[parent_dir].append(str(abs_path))
                continue

            # Handle directories
            if not abs_path.is_dir():
                continue

            # Discover files in the directory with safety limits
            files_in_folder = []
            try:
                file_count = 0
                max_files = 1000  # Safety limit to prevent memory issues

                for file_path in abs_path.rglob("*"):
                    if file_path.is_file():
                        file_count += 1
                        if file_count > max_files:
                            # Log warning and stop discovering files
                            if hasattr(self, "logger") and self.logger:
                                import asyncio

                                try:
                                    asyncio.create_task(
                                        self.logger.write_to_dut_runtime_log(
                                            dut_id,
                                            "WARN",
                                            "ExecutionSummary",
                                            f"File discovery limit reached ({max_files}) for {path}",
                                        )
                                    )
                                except Exception:
                                    pass
                            break

                        # Make path relative to DUT log directory
                        try:
                            rel_file_path = os.path.relpath(file_path, dut_log_dir)
                            files_in_folder.append(rel_file_path)
                        except ValueError:
                            # If paths are on different drives, use absolute path
                            files_in_folder.append(str(file_path))

                # Sort files for consistent output
                files_in_folder.sort()

                if files_in_folder:
                    discovered_files[path] = files_in_folder

            except (OSError, PermissionError) as e:
                # Skip directories that can't be accessed
                continue

        return discovered_files

    def _update_collector_metadata_with_files(
        self, dut_id: str, entry: Dict[str, Any]
    ) -> None:
        """
        Update collector metadata with discovered files.

        Args:
            dut_id: DUT ID.
            entry: Entry containing discovered files.
        """
        try:
            collector_id = entry.get("collector_id")
            discovered_files = entry.get("discovered_files", {})

            if not collector_id or not discovered_files:
                return

            # Store discovered files for later integration
            # This avoids race conditions by not calling _update_collector_status here
            if not hasattr(self, "_pending_file_updates"):
                self._pending_file_updates = {}

            key = f"{dut_id}:{collector_id}"
            self._pending_file_updates[key] = discovered_files

        except Exception:
            # Silently fail if metadata update fails
            pass

    def _write_entry_to_file(self, dut_id: str, entry: Dict[str, str]) -> None:
        """
        Write a single entry to the DUT-specific summary file.

        Args:
            dut_id: DUT ID.
            entry: Entry dictionary to write.
        """
        summary_file_path = self.summary_files[dut_id]

        # Ensure DUT log directory exists
        summary_file_path.parent.mkdir(parents=True, exist_ok=True)

        # Format entry line with collector ID
        collector_id = entry.get("collector_id", "N/A")
        if collector_id is None:
            collector_id = "N/A"

        # Clean log paths to prevent tab characters from breaking parsing
        cleaned_log_paths = [path.replace("\t", " ") for path in entry["log_paths"]]
        # Deduplicate log paths before joining
        unique_log_paths = self._deduplicate_log_paths(cleaned_log_paths)
        log_path_str = ", ".join(unique_log_paths)

        discovered_files = entry.get("discovered_files", {})

        # Ensure status is not None
        status = entry.get("status", "Unknown")
        if status is None:
            status = "Unknown"

        # Ensure collection_name is not None
        collection_name = entry.get("collection_name", "Unknown")
        if collection_name is None:
            collection_name = "Unknown"

        entry_line = f"{collection_name:<35} \t {collector_id:<8} \t {status:<16} \t {log_path_str}\n"

        # Use file locking to prevent race conditions
        try:
            with open(summary_file_path, "a+") as summary_file:
                # Get exclusive lock
                fcntl.flock(summary_file.fileno(), fcntl.LOCK_EX)
                try:
                    # Check if file is empty or needs header
                    summary_file.seek(0)
                    content = summary_file.read()

                    if not content.strip():
                        # Write header
                        header = f"{'Collection Name':<35} \t {'ID':<8} \t {'Execution Status':<16} \t Log Path\n"
                        summary_file.write(header)

                    # Write entry
                    summary_file.write(entry_line)

                    # Force flush to ensure data is written
                    summary_file.flush()

                finally:
                    # Release lock
                    fcntl.flock(summary_file.fileno(), fcntl.LOCK_UN)
        except Exception:
            # Silently fail if file write fails, entry is still in memory
            pass

    def finalize(self) -> None:
        """
        Finalize all execution summary files and write completion markers.
        """
        for dut_id, summary_file_path in self.summary_files.items():
            if not summary_file_path.exists():
                continue

            # Read all entries
            with open(summary_file_path, "r") as summary_file:
                lines = summary_file.readlines()
                if not lines:
                    continue

            entries = []
            log_collection_line = None

            # Process lines, skipping empty lines and handling header
            for line in lines:
                line_stripped = line.strip()
                if not line_stripped:  # Skip empty lines
                    continue
                if "Collection Name" in line_stripped:  # Skip header lines
                    continue
                if "Log collection took" in line_stripped:
                    log_collection_line = line_stripped + "\n"
                    continue
                entries.append(line_stripped + "\n")

            # Merge entries for the same collector, combining paths and using most severe status
            collector_entries = {}
            # Handle case-insensitive status matching
            status_priority = {
                "error": 4,
                "Error": 4,
                "ERROR": 4,
                "partial": 3,
                "Partial": 3,
                "PARTIAL": 3,
                "complete": 2,
                "Complete": 2,
                "COMPLETE": 2,
                "success": 2,
                "Success": 2,
                "skipped": 1,
                "Skipped": 1,
                "SKIPPED": 1,
                "unknown": 0,
                "Unknown": 0,
                "UNKNOWN": 0,
            }

            for entry in entries:
                parts = entry.split("\t")
                # Handle both 3-part entries (no log path) and 4+ part entries
                if len(parts) >= 3:
                    collection_name = parts[0].strip()
                    collector_id = parts[1].strip()
                    status = parts[2].strip()
                    # Join remaining parts in case log path contains tabs
                    # If there's no 4th part, log_path will be empty
                    log_path = "\t".join(parts[3:]).strip() if len(parts) > 3 else ""

                    # Split and deduplicate log paths (handles comma-separated paths)
                    log_paths_list = (
                        self._deduplicate_log_paths([log_path]) if log_path else []
                    )

                    # Use collector_id if available, otherwise fall back to collection_name
                    unique_key = (
                        collector_id if collector_id != "N/A" else collection_name
                    )

                    if unique_key not in collector_entries:
                        collector_entries[unique_key] = {
                            "collection_name": collection_name,
                            "collector_id": collector_id,
                            "status": status,
                            "log_paths": log_paths_list,
                            "discovered_files": {},  # Will be populated from memory if available
                        }
                    else:
                        # Merge with existing entry
                        existing = collector_entries[unique_key]

                        # Use the most severe status
                        current_priority = status_priority.get(status, 0)
                        existing_priority = status_priority.get(existing["status"], 0)
                        if current_priority > existing_priority:
                            existing["status"] = status

                        # Add new log paths (avoid duplicates)
                        for path in log_paths_list:
                            if path and path not in existing["log_paths"]:
                                existing["log_paths"].append(path)

            # Merge discovered files from in-memory entries if available
            if dut_id in self.entries:
                for memory_entry in self.entries[dut_id]:
                    collector_id = memory_entry.get("collector_id", "N/A")
                    collection_name = memory_entry.get("collection_name", "Unknown")
                    unique_key = (
                        collector_id if collector_id != "N/A" else collection_name
                    )

                    if unique_key in collector_entries:
                        discovered_files = memory_entry.get("discovered_files", {})
                        if discovered_files:
                            # Merge discovered files
                            existing_discovered = collector_entries[unique_key][
                                "discovered_files"
                            ]
                            for path, files in discovered_files.items():
                                if path not in existing_discovered:
                                    existing_discovered[path] = files
                                else:
                                    # Merge file lists, avoiding duplicates
                                    existing_files = set(existing_discovered[path])
                                    new_files = set(files)
                                    existing_discovered[path] = list(
                                        existing_files | new_files
                                    )

            # Convert back to entries format
            final_entries = []
            for unique_key in collector_entries:
                entry_data = collector_entries[unique_key]
                log_path_str = (
                    ", ".join(entry_data["log_paths"])
                    if entry_data["log_paths"]
                    else ""
                )
                entry_line = f"{entry_data['collection_name']:<35} \t {entry_data['collector_id']:<8} \t {entry_data['status']:<16} \t {log_path_str}\n"
                final_entries.append(entry_line)

            # Get actual execution time - prioritize DUT total time over individual collector times
            execution_time_str = "Total execution time: 0.000000s"  # Default fallback

            # Method 1: Try to get total DUT execution time from runtime log timestamps
            # (This is per-DUT timing, which is what users expect in per-DUT reports)
            total_dut_time = self._get_total_dut_execution_time(dut_id)
            if total_dut_time > 0:
                execution_time_str = f"Total execution time: {total_dut_time:.6f}s"
            else:
                # Method 2: Try to get total tool execution time from stdout log
                # (Fallback for single-DUT scenarios where tool time ≈ DUT time)
                total_tool_time = self._get_total_tool_execution_time()
                if total_tool_time > 0:
                    execution_time_str = f"Total execution time: {total_tool_time:.6f}s"
                else:
                    # Method 3: Try to read the actual execution time from the runtime log
                    runtime_log_path = (
                        self.log_dir / dut_id / "nvdebug_runtime_output.txt"
                    )
                    if runtime_log_path.exists():
                        try:
                            with runtime_log_path.open("r", encoding="utf-8") as f:
                                content = f.read()
                            # Look for "Total execution time: X.XX seconds" in the runtime log
                            runtime_match = re.search(
                                r"Total execution time:\s*[^(]*\((\d+(?:\.\d+)?)\s*seconds\)",
                                content,
                            )
                            if runtime_match:
                                actual_execution_time = float(runtime_match.group(1))
                                execution_time_str = f"Total execution time: {actual_execution_time:.6f}s"
                            else:
                                # Method 3: Try to get execution time from metadata JSON files (individual collector times)
                                max_time = self._get_execution_time_from_metadata(
                                    dut_id
                                )
                                if max_time > 0:
                                    execution_time_str = (
                                        f"Total execution time: {max_time:.6f}s"
                                    )
                                else:
                                    # Method 4: Try to extract execution time from individual collector results in runtime log
                                    collector_time_matches = re.findall(
                                        r"Time:\s*(\d+(?:\.\d+)?)s|(\d+(?:\.\d+)?)s\s*$",
                                        content,
                                        re.MULTILINE,
                                    )
                                    if collector_time_matches:
                                        # Get the maximum execution time from all collectors
                                        max_time = 0.0
                                        for match in collector_time_matches:
                                            # match is a tuple, get the non-empty value
                                            time_str = (
                                                match[0] if match[0] else match[1]
                                            )
                                            if time_str:
                                                try:
                                                    time_val = float(time_str)
                                                    max_time = max(max_time, time_val)
                                                except ValueError:
                                                    continue
                                        if max_time > 0:
                                            execution_time_str = (
                                                f"Total execution time: {max_time:.6f}s"
                                            )
                        except Exception:
                            # If reading runtime log fails, fall back to wall-clock calculation
                            end_time = datetime.now()
                            dut_start_time = self.dut_start_times.get(
                                dut_id, self.start_time
                            )
                            execution_time = end_time - dut_start_time
                            execution_time_str = f"Total execution time: {execution_time.total_seconds():.6f}s"
                    else:
                        # If no runtime log, fall back to wall-clock calculation
                        end_time = datetime.now()
                        dut_start_time = self.dut_start_times.get(
                            dut_id, self.start_time
                        )
                        execution_time = end_time - dut_start_time
                        execution_time_str = f"Total execution time: {execution_time.total_seconds():.6f}s"

            # Write back entries
            with open(summary_file_path, "w") as summary_file:
                # Write header
                summary_file.write(
                    f"{'Collection Name':<35} \t {'ID':<8} \t {'Execution Status':<16} \t Log Path\n"
                )

                # Write sorted entries
                for entry in sorted(
                    final_entries, key=lambda x: x.split("\t")[0].strip().lower()
                ):
                    summary_file.write(entry)

                # Write execution time
                summary_file.write(f"\n{execution_time_str}\n")

    def _get_total_tool_execution_time(self) -> float:
        """
        Get total tool execution time from stdout log.

        Returns:
            float: Total tool execution time in seconds, or 0.0 if not found
        """
        try:
            stdout_log_path = self.log_dir / ".nvdebug_stdout.log"
            if not stdout_log_path.exists():
                return 0.0

            with stdout_log_path.open("r", encoding="utf-8") as f:
                content = f.read()

            # Look for "Total execution time: Xm Y.ZZs (Z.ZZ seconds)"
            tool_time_match = re.search(
                r"Total execution time:\s*\d+m\s*\d+\.\d+s\s*\((\d+(?:\.\d+)?)\s*seconds\)",
                content,
            )

            if tool_time_match:
                return float(tool_time_match.group(1))

            return 0.0
        except Exception:
            return 0.0

    def _get_total_dut_execution_time(self, dut_id: str) -> float:
        """
        Get total DUT execution time from timing.json (collector execution time only).

        Args:
            dut_id: DUT identifier

        Returns:
            float: Total DUT execution time in seconds, or 0.0 if not found
        """
        try:
            # Method 1: Try to get wall-clock time from timing.json (most accurate)
            timing_json_path = self.log_dir / dut_id / ".metadata" / "timing.json"
            if timing_json_path.exists():
                with timing_json_path.open("r", encoding="utf-8") as f:
                    timing_data = json.load(f)
                wall_clock_duration = timing_data.get("overall", {}).get(
                    "wall_clock_duration_seconds", 0.0
                )
                if wall_clock_duration > 0:
                    return wall_clock_duration

            # Method 2: Fallback to runtime log timestamps (includes initialization overhead)
            runtime_log_path = self.log_dir / dut_id / "nvdebug_runtime_output.txt"
            if not runtime_log_path.exists():
                return 0.0

            with runtime_log_path.open("r", encoding="utf-8") as f:
                content = f.read()

            # Look for start and end timestamps
            # Start: "Started at: 2025-09-08T23:43:58.119244"
            start_match = re.search(
                r"Started at:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)", content
            )
            # End: "Completed at: 2025-09-08T23:46:07.411536"
            end_match = re.search(
                r"Completed at:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)", content
            )

            if start_match and end_match:
                from datetime import datetime

                start_time = datetime.fromisoformat(start_match.group(1))
                end_time = datetime.fromisoformat(end_match.group(1))
                execution_time = (end_time - start_time).total_seconds()
                return execution_time

            return 0.0
        except Exception:
            return 0.0

    def _get_execution_time_from_metadata(self, dut_id: str) -> float:
        """
        Get execution time from metadata JSON files as a backup method.

        Args:
            dut_id: DUT identifier

        Returns:
            float: Maximum execution time from all collectors, or 0.0 if not found
        """
        try:
            import json

            # Check all metadata files for execution times
            metadata_files = [
                "redfish.json",
                "ssh.json",
                "ipmi.json",
                "host.json",
                "health_check.json",
            ]
            max_time = 0.0

            for metadata_file in metadata_files:
                metadata_path = self.log_dir / dut_id / ".metadata" / metadata_file
                if metadata_path.exists():
                    try:
                        with metadata_path.open("r", encoding="utf-8") as f:
                            metadata = json.load(f)

                        collectors = metadata.get("collectors", {})
                        for collector_id, collector_info in collectors.items():
                            if isinstance(collector_info, dict):
                                execution_time = collector_info.get(
                                    "execution_time", ""
                                )
                                if execution_time and execution_time != "":
                                    try:
                                        if isinstance(execution_time, (int, float)):
                                            time_val = float(execution_time)
                                        else:
                                            time_val = float(execution_time)
                                        max_time = max(max_time, time_val)
                                    except (ValueError, TypeError):
                                        continue
                    except Exception:
                        # Skip this metadata file if there's an error
                        continue

            return max_time
        except Exception:
            return 0.0

    def get_summary_file_paths(self) -> Dict[str, Path]:
        """
        Get the paths to all summary files.

        Returns:
            Dictionary mapping DUT IDs to summary file paths.
        """
        return self.summary_files
