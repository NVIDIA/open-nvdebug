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
Baseboard Manager for NVDebug Tool

This module provides baseboard management functionality that works exclusively with:
1. Spreadsheet-based configuration (primary approach)

The BaseboardManager provides lookup methods for baseboard types, groups, and filtering rules.
"""

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd

from .async_logger import AsyncSafeLogger


class BaseboardManager:
    """
    Manages baseboard definitions and provides lookup functionality.

    Supports only spreadsheet-based configurations.
    """

    def __init__(
        self,
        spreadsheet_path: Optional[Union[str, Path]] = None,
        logger: Optional[AsyncSafeLogger] = None,
    ):
        """
        Initialize the BaseboardManager.

        Args:
            spreadsheet_path: Path to spreadsheet file (required for spreadsheet approach)
            logger: AsyncSafeLogger instance for logging
        """
        self.baseboards: Dict[str, Any] = {}
        self.baseboard_types: Dict[str, str] = {}  # baseboard_name -> type
        self.baseboard_groups: Dict[str, List[str]] = (
            {}
        )  # group_name -> [baseboard_names]
        self.logger = logger

        if spreadsheet_path:
            if self._has_spreadsheet_baseboard_definitions(spreadsheet_path):
                self._load_from_spreadsheet(spreadsheet_path)
            else:
                if self.logger:
                    asyncio.create_task(
                        self.logger.log_runtime(
                            "WARNING",
                            "BaseboardManager",
                            f"No baseboard definitions found in spreadsheet: {spreadsheet_path}",
                        )
                    )
                # Initialize with empty baseboards if no definitions found
                self.baseboards = {}
        else:
            if self.logger:
                asyncio.create_task(
                    self.logger.log_runtime(
                        "WARNING",
                        "BaseboardManager",
                        "No spreadsheet path provided - initializing with empty baseboards",
                    )
                )
            self.baseboards = {}

    def _has_spreadsheet_baseboard_definitions(
        self, spreadsheet_path: Union[str, Path]
    ) -> bool:
        """
        Check if spreadsheet has baseboard definitions.

        Args:
            spreadsheet_path: Path to the spreadsheet file
        """
        try:
            spreadsheet_path = Path(spreadsheet_path)
            if not spreadsheet_path.exists():
                return False

            # Try to read the configuration sheet
            df = pd.read_excel(
                spreadsheet_path, sheet_name="Log Collection Configuration"
            )

            # Check if there are baseboard definition rows
            baseboard_rows = df[df["Section"] == "Baseboard Definitions"]
            return len(baseboard_rows) > 0

        except Exception:
            return False

    def _load_from_spreadsheet(self, spreadsheet_path: Union[str, Path]) -> None:
        """
        Load baseboard definitions from spreadsheet.

        Args:
            spreadsheet_path: Path to the spreadsheet file
        """
        try:

            spreadsheet_path = Path(spreadsheet_path)
            if not spreadsheet_path.exists():
                if self.logger:
                    asyncio.create_task(
                        self.logger.log_runtime(
                            "ERROR",
                            "BaseboardManager",
                            f"Spreadsheet file not found: {spreadsheet_path}",
                        )
                    )
                return

            # Read the configuration sheet
            df = pd.read_excel(
                spreadsheet_path, sheet_name="Log Collection Configuration"
            )

            # Extract global constants
            global_constants = {}
            global_rows = df[df["Section"] == "Global Constants"]
            for _, row in global_rows.iterrows():
                config_item = row.get("Configuration Item", "")
                value = row.get("Value", "")
                global_constants[config_item] = value

            # Extract baseboard definitions
            baseboards = {}
            baseboard_rows = df[df["Section"] == "Baseboard Definitions"]

            # Get all baseboard columns (skip Section, Configuration Item, Value, Description)
            baseboard_columns = [
                col
                for col in df.columns
                if col
                not in [
                    "Section",
                    "Configuration Item",
                    "Value",
                    "Description",
                ]
            ]

            # Initialize baseboard dictionaries
            for baseboard_name in baseboard_columns:
                baseboards[baseboard_name] = {}

            # Process each field row
            for _, row in baseboard_rows.iterrows():
                field_name = row.get("Configuration Item", "")

                for baseboard_name in baseboard_columns:
                    value = row.get(baseboard_name, "")

                    # Handle different field types
                    if field_name in ["type", "platform", "description"]:
                        baseboards[baseboard_name][field_name] = (
                            str(value) if pd.notna(value) else ""
                        )
                    elif field_name in [
                        "supports_redfish",
                        "supports_ipmi",
                        "supports_bmc_ssh",
                        "supports_hmc",
                    ]:
                        baseboards[baseboard_name][field_name] = (
                            bool(value) if pd.notna(value) else False
                        )
                    elif field_name == "i2c_config":
                        try:
                            if pd.notna(value) and value:
                                baseboards[baseboard_name][field_name] = json.loads(
                                    str(value)
                                )
                            else:
                                baseboards[baseboard_name][field_name] = {}
                        except json.JSONDecodeError:
                            baseboards[baseboard_name][field_name] = {}
                    elif field_name == "platform_detection":
                        try:
                            if pd.notna(value) and value:
                                platform_detection = json.loads(str(value))
                                # Resolve YAML anchors for HMC IP
                                if isinstance(platform_detection.get("hmc_ip"), str):
                                    hmc_ip_value = platform_detection["hmc_ip"]
                                    if hmc_ip_value.startswith("*"):
                                        anchor_name = hmc_ip_value[
                                            1:
                                        ]  # Remove the * prefix
                                        # Get the value from global constants (these should have the correct defaults)
                                        resolved_value = global_constants.get(
                                            anchor_name, hmc_ip_value
                                        )
                                        platform_detection["hmc_ip"] = resolved_value

                                        # Log the resolution for debugging
                                        if self.logger:
                                            asyncio.create_task(
                                                self.logger.log_runtime(
                                                    "DEBUG",
                                                    "BaseboardManager",
                                                    f"Resolved YAML anchor {hmc_ip_value} -> {resolved_value} for baseboard {baseboard_name}",
                                                )
                                            )
                                        else:
                                            # Fallback logging if logger not available
                                            print(
                                                f"[DEBUG] Resolved YAML anchor {hmc_ip_value} -> {resolved_value} for baseboard {baseboard_name}"
                                            )
                                    else:
                                        # Log when no anchor resolution is needed
                                        if self.logger:
                                            asyncio.create_task(
                                                self.logger.log_runtime(
                                                    "DEBUG",
                                                    "BaseboardManager",
                                                    f"No YAML anchor resolution needed for {baseboard_name}.hmc_ip = {hmc_ip_value}",
                                                )
                                            )
                                baseboards[baseboard_name][
                                    field_name
                                ] = platform_detection
                            else:
                                baseboards[baseboard_name][field_name] = {}
                        except json.JSONDecodeError:
                            baseboards[baseboard_name][field_name] = {}

            # Add global constants to each baseboard
            for baseboard_name in baseboards:
                baseboards[baseboard_name].update(global_constants)

            self.baseboards = baseboards
            self._build_lookup_tables()

            if self.logger:
                asyncio.create_task(
                    self.logger.log_runtime(
                        "INFO",
                        "BaseboardManager",
                        f"Loaded {len(baseboards)} baseboards from spreadsheet: {spreadsheet_path}",
                    )
                )

        except Exception as e:
            if self.logger:
                asyncio.create_task(
                    self.logger.log_runtime(
                        "ERROR",
                        "BaseboardManager",
                        f"Failed to load baseboards from spreadsheet: {e}",
                    )
                )
            # Initialize with empty baseboards if loading fails
            self.baseboards = {}

    def _build_lookup_tables(self) -> None:
        """
        Build lookup tables for efficient baseboard queries.

        Args:
            None
        """
        self.baseboard_types.clear()
        self.baseboard_groups.clear()

        # Build baseboard_name -> type mapping
        for baseboard_name, baseboard_config in self.baseboards.items():
            baseboard_type = baseboard_config.get("type", "unknown")
            self.baseboard_types[baseboard_name] = baseboard_type

            # Build group -> baseboard_names mapping
            if baseboard_type not in self.baseboard_groups:
                self.baseboard_groups[baseboard_type] = []
            self.baseboard_groups[baseboard_type].append(baseboard_name)

    def get_baseboard_type(self, baseboard_name: str) -> Optional[str]:
        """
        Get the type of a baseboard.

        Args:
            baseboard_name: Name of the baseboard (e.g., "GB200 NVL")

        Returns:
            Baseboard type (e.g., "NVL", "HGX", "GH200") or None if not found
        """
        baseboard_type = self.baseboard_types.get(baseboard_name)
        return baseboard_type

    async def log_baseboard_info(self, dut_id: str) -> None:
        """
        Log baseboard information for debugging.

        Args:
            dut_id: DUT ID for logging
        """
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "BaseboardManager",
            f"Loaded {len(self.baseboards)} baseboards: {list(self.baseboards.keys())}",
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "BaseboardManager",
            f"Baseboard types: {self.baseboard_types}",
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "BaseboardManager",
            f"Baseboard groups: {self.baseboard_groups}",
        )

    def get_baseboard_group(self, baseboard_name: str) -> Optional[str]:
        """
        Get the group of a baseboard for filtering purposes.

        This is typically the same as the type, but can be customized if needed.

        Args:
            baseboard_name: Name of the baseboard (e.g., "GB200 NVL")

        Returns:
            Baseboard group for filtering (e.g., "NVL", "HGX") or None if not found
        """
        return self.get_baseboard_type(baseboard_name)

    def is_baseboard_in_group(self, baseboard_name: str, group_name: str) -> bool:
        """
        Check if a baseboard belongs to a specific group.

        Args:
            baseboard_name: Name of the baseboard (e.g., "GB200 NVL")
            group_name: Name of the group (e.g., "NVL", "HGX")

        Returns:
            True if baseboard belongs to the group, False otherwise
        """
        baseboard_type = self.get_baseboard_type(baseboard_name)
        return baseboard_type == group_name

    def get_baseboards_in_group(self, group_name: str) -> List[str]:
        """
        Get all baseboards that belong to a specific group.

        Args:
            group_name: Name of the group (e.g., "NVL", "HGX")

        Returns:
            List of baseboard names in the group
        """
        return self.baseboard_groups.get(group_name, [])

    def get_all_baseboard_names(self) -> List[str]:
        """
        Get all baseboard names.

        Args:
            None
        """
        return list(self.baseboards.keys())

    def get_all_baseboard_types(self) -> List[str]:
        """
        Get all baseboard types.

        Args:
            None
        """
        return list(self.baseboard_groups.keys())

    def get_baseboard_config(self, baseboard_name: str) -> Optional[Dict[str, Any]]:
        """
        Get the full configuration for a baseboard.

        Args:
            baseboard_name: Name of the baseboard

        Returns:
            Baseboard configuration dictionary or None if not found
        """
        return self.baseboards.get(baseboard_name)

    def validate_baseboard_filtering_rules(
        self, filtering_rules: Dict[str, str]
    ) -> Dict[str, List[str]]:
        """
        Validate baseboard filtering rules against known baseboards.

        Args:
            filtering_rules: Dictionary of baseboard/group -> filter_mode mappings

        Returns:
            Dictionary of valid and invalid rules
        """
        valid_rules = {}
        invalid_rules = []

        all_baseboard_names = self.get_all_baseboard_names()
        all_baseboard_types = self.get_all_baseboard_types()

        for rule_key, filter_mode in filtering_rules.items():
            # Check if rule_key is a specific baseboard name
            if rule_key in all_baseboard_names:
                valid_rules[rule_key] = filter_mode
            # Check if rule_key is a baseboard type/group
            elif rule_key in all_baseboard_types:
                valid_rules[rule_key] = filter_mode
            # Check if rule_key is "default"
            elif rule_key == "default":
                valid_rules[rule_key] = filter_mode
            else:
                invalid_rules.append(rule_key)

        return {"valid": valid_rules, "invalid": invalid_rules}

    async def apply_baseboard_filtering(
        self,
        dut_id: str,
        dut_baseboard: str,
        filtering_rules: Dict[str, str],
        default_filter_mode: str = "all_platforms",
    ) -> str:
        """
        Apply baseboard filtering rules to determine the effective filter mode.

        Args:
            dut_id: DUT ID for logging
            dut_baseboard: The DUT's baseboard name
            filtering_rules: Dictionary of baseboard/group -> filter_mode mappings
            default_filter_mode: Default filter mode if no rules match

        Returns:
            The effective filter mode to apply
        """
        if not filtering_rules:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "BaseboardManager",
                f"No filtering rules provided, using default: {default_filter_mode}",
            )
            return default_filter_mode

        # Priority order: exact baseboard match > group match > default
        dut_type = self.get_baseboard_type(dut_baseboard)

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "BaseboardManager",
            f"Applying baseboard filtering: dut_baseboard='{dut_baseboard}', dut_type='{dut_type}', rules={filtering_rules}",
        )

        # 1. Check for exact baseboard match (highest priority)
        if dut_baseboard in filtering_rules:
            effective_filter = filtering_rules[dut_baseboard]
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "BaseboardManager",
                f"Exact baseboard match '{dut_baseboard}' -> filter_mode='{effective_filter}'",
            )
            return effective_filter

        # 2. Check for group/type match (medium priority)
        if dut_type and dut_type in filtering_rules:
            effective_filter = filtering_rules[dut_type]
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "BaseboardManager",
                f"Group match '{dut_type}' -> filter_mode='{effective_filter}'",
            )
            return effective_filter

        # 3. Check for "default" rule (lowest priority)
        if "default" in filtering_rules:
            effective_filter = filtering_rules["default"]
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "BaseboardManager",
                f"Default rule -> filter_mode='{effective_filter}'",
            )
            return effective_filter

        # 4. Use provided default
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "BaseboardManager",
            f"No rules matched, using provided default: {default_filter_mode}",
        )
        return default_filter_mode
