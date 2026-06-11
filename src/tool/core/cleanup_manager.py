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
Cleanup Manager for NVDebug Tool.

Handles directory cleanup, empty directory removal, and zip archive creation
for collected logs with support for split archives.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from ..utils.file_utils import cleanup_empty_directories
from ..utils.zip_utils import (
    create_zip,
    create_zip_split,
    should_skip_zip_creation,
)

logger = logging.getLogger(__name__)


class CleanupManager:
    """
    Manages cleanup operations and resource finalization.

    Handles post-collection cleanup including empty directory removal and
    archive creation for collected logs.

    Attributes:
        logger: AsyncSafeLogger instance for logging.
    """

    def __init__(self, logger):
        """
        Initialize cleanup manager.

        Args:
            logger: AsyncSafeLogger instance.
        """
        self.logger = logger

    async def cleanup_empty_directories(
        self, log_dir: Path, dut_ids: list[str] | None = None
    ) -> None:
        """
        Clean up empty directories in the log directory.

        Args:
            log_dir (Path): Log directory path.
            dut_ids (list[str] | None): Optional list of DUT IDs to scope cleanup.
        """
        try:
            await self.logger.log_runtime(
                "INFO", "CleanupManager", "Cleaning up empty directories..."
            )

            # Clean up empty directories (scoped to known DUT IDs if provided)
            removed = []
            try:
                if (
                    dut_ids is None
                    and hasattr(self.logger, "orchestrator")
                    and self.logger.orchestrator
                    and getattr(self.logger.orchestrator, "dut_manager", None)
                ):
                    dut_ids = self.logger.orchestrator.dut_manager.get_all_dut_ids()
                    await self.logger.log_runtime(
                        "DEBUG",
                        "CleanupManager",
                        f"Retrieved DUT IDs from manager: {dut_ids}",
                    )
            except Exception as e:
                await self.logger.log_runtime(
                    "WARN",
                    "CleanupManager",
                    f"Failed to get DUT IDs from manager: {e}",
                )
                dut_ids = []

            # If we still don't have DUT IDs, try to discover them from the log directory
            if not dut_ids:
                try:
                    discovered_dut_ids = []
                    for item in os.listdir(str(log_dir)):
                        item_path = os.path.join(str(log_dir), item)
                        if os.path.isdir(item_path) and not item.startswith("."):
                            discovered_dut_ids.append(item)
                    dut_ids = discovered_dut_ids
                    await self.logger.log_runtime(
                        "DEBUG",
                        "CleanupManager",
                        f"Discovered DUT IDs from log directory: {dut_ids}",
                    )
                except Exception as e:
                    await self.logger.log_runtime(
                        "WARN",
                        "CleanupManager",
                        f"Failed to discover DUT IDs from log directory: {e}",
                    )

            if dut_ids:
                dut_ids = sorted(dut_ids)

            await self.logger.log_runtime(
                "DEBUG",
                "CleanupManager",
                f"Final DUT IDs for cleanup: {dut_ids}",
            )

            removed = cleanup_empty_directories(str(log_dir), dut_ids or [])

            await self.logger.log_runtime(
                "INFO",
                "CleanupManager",
                f"Empty directory cleanup completed; removed {len(removed)} directories: {removed}",
            )

        except Exception as e:
            await self.logger.log_runtime(
                "ERROR",
                "CleanupManager",
                f"Failed to cleanup empty directories: {e}",
            )

    async def create_zip_archive(
        self,
        log_dir: Path,
        skip_zip: bool = False,
        skip_zip_split: bool = False,
        zip_split_threshold: float = 200.0,
    ) -> Optional[str]:
        """
        Create zip archive of the log directory.

        Args:
            log_dir: Log directory to archive
            skip_zip: Whether to skip zip creation
            skip_zip_split: Whether to skip zip splitting
            zip_split_threshold: Size threshold for splitting in MB

        Returns:
            Optional[str]: Path to the created zip archive, or None if skipped/failed
        """
        try:
            # Check if zip creation should be skipped
            if should_skip_zip_creation(skip_zip, skip_zip_split):
                await self.logger.log_runtime(
                    "INFO",
                    "CleanupManager",
                    "Zip creation skipped by configuration",
                )
                return None

            if not log_dir.exists():
                await self.logger.log_runtime(
                    "WARNING",
                    "CleanupManager",
                    f"Log directory {log_dir} does not exist, skipping zip creation",
                )
                return None

            await self.logger.log_runtime(
                "INFO", "CleanupManager", "Creating zip archive..."
            )

            # Get the base name for the zip file
            zip_name = log_dir.name

            if skip_zip_split:
                # Create regular zip without splitting
                zip_path = create_zip(str(log_dir), zip_name)
                await self.logger.log_runtime(
                    "INFO",
                    "CleanupManager",
                    f"Zip archive created: {zip_path}",
                )
                return zip_path
            else:
                # Create zip with potential splitting
                zip_result = create_zip_split(
                    str(log_dir),
                    zip_name,
                    split=True,
                    max_size_mb=zip_split_threshold,
                )

                # Handle both single file and split files cases
                if isinstance(zip_result, list):
                    # Files were split - return the list of all files
                    await self.logger.log_runtime(
                        "INFO",
                        "CleanupManager",
                        f"Split archive created with {len(zip_result)} files",
                    )
                    return zip_result
                else:
                    # Single file - return the path
                    await self.logger.log_runtime(
                        "INFO",
                        "CleanupManager",
                        f"Zip archive created (with splitting): {zip_result}",
                    )
                    return zip_result

        except Exception as e:
            await self.logger.log_runtime(
                "ERROR", "CleanupManager", f"Failed to create zip archive: {e}"
            )
            # Don't raise the exception - zip creation failure shouldn't stop cleanup
            return None

    async def cleanup(self, log_dir: Path) -> None:
        """
        Perform comprehensive cleanup operations.

        Args:
            log_dir: Path to the log directory
        """
        try:
            await self.logger.log_runtime(
                "INFO", "CleanupManager", "Starting cleanup operations..."
            )

            # Clean up empty directories
            await self.cleanup_empty_directories(log_dir)

            # Clean up DUT manager resources (including Redfish sessions)
            if (
                hasattr(self.logger, "orchestrator")
                and self.logger.orchestrator
                and getattr(self.logger.orchestrator, "dut_manager", None)
            ):
                await self.logger.log_runtime(
                    "INFO",
                    "CleanupManager",
                    "Cleaning up DUT manager resources...",
                )
                await self.logger.orchestrator.dut_manager.cleanup()

            # Create metadata files (but don't finalize logger yet)
            await self.logger._create_root_metadata_aggregator()
            await self.logger._create_all_group_files()

            await self.logger.log_runtime(
                "INFO",
                "CleanupManager",
                "Cleanup operations completed successfully",
            )

        except Exception as e:
            await self.logger.log_runtime(
                "ERROR", "CleanupManager", f"Cleanup failed: {e}"
            )
            raise

    async def finalize_logger(self) -> None:
        """
        Finalize the logger (call this after HTML generation).

        Args:
            None
        """
        try:
            await self.logger.log_runtime(
                "INFO", "CleanupManager", "Finalizing logger..."
            )
            await self.logger.finalize()
        except Exception as e:
            await self.logger.log_runtime(
                "ERROR", "CleanupManager", f"Failed to finalize logger: {e}"
            )
            raise

    async def create_final_zip_archive(self, log_dir: Path) -> Optional[str]:
        """
        Create zip archive after logger finalization (all files are closed).

        Args:
            log_dir: Path to the log directory
        """
        try:
            # Get tool config for zip settings
            if hasattr(self.logger, "orchestrator") and self.logger.orchestrator:
                # For cleanup operations, we use the global tool config since this affects the entire run
                # DUT-specific tool config overrides would not apply to cleanup operations
                tool_config = self.logger.orchestrator.config_manager.get_tool_config()

                # Check both possible key names for skip_zip - check both top level and output section
                output_config = tool_config.get("output", {})
                skip_zip = output_config.get(
                    "skip_zip", tool_config.get("skip_zip", False)
                ) or output_config.get("skipzip", tool_config.get("skipzip", False))

                skip_zip_split = output_config.get(
                    "skip_zip_split", tool_config.get("skip_zip_split", False)
                ) or output_config.get(
                    "skipzipsplit", tool_config.get("skipzipsplit", False)
                )
                zip_split_threshold = output_config.get(
                    "zip_split_threshold", tool_config.get("zip_split_threshold", 200.0)
                )

                # Use existing console if available and debug mode is enabled
                # debug_message = f"Zip settings - skip_zip: {skip_zip}, skip_zip_split: {skip_zip_split}, zip_split_threshold: {zip_split_threshold}"
                # if hasattr(self.logger, "orchestrator") and self.logger.orchestrator:
                #     if hasattr(self.logger.orchestrator, "sanitized_console"):
                #         self.logger.orchestrator.sanitized_console.print_debug(
                #             debug_message
                #         )
                #     elif hasattr(self.logger.orchestrator, "console"):
                #         self.logger.orchestrator.console.print(
                #             f"[DEBUG] CleanupManager: {debug_message}"
                #         )
                #     else:
                #         print(f"[DEBUG] CleanupManager: {debug_message}")
                # else:
                #     print(f"[DEBUG] CleanupManager: {debug_message}")

                if not skip_zip:
                    # Create zip archive (all files are now closed and flushed)
                    zip_path = await self.create_zip_archive(
                        log_dir,
                        skip_zip=skip_zip,
                        skip_zip_split=skip_zip_split,
                        zip_split_threshold=zip_split_threshold,
                    )
                    return zip_path
            return None
        except Exception as e:
            # Log error but don't raise - zip creation failure shouldn't stop the process
            print(f"Warning: Failed to create final zip archive: {e}")
            return None
