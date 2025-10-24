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
Auto Detection Service.

Builds platform-baseboard mapping from spreadsheet configuration and provides
interactive user prompts for platform and baseboard selection.
"""

import asyncio
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from ..utils import get_tool_resource_content
from ..utils.console_output import create_sanitized_console
from ..utils.resources import find_config_directory

logger = logging.getLogger(__name__)


class AutoDetectionService:
    """
    Service for detecting platform and baseboard types from DUTs.
    Builds platform-baseboard mapping from spreadsheet configuration.
    """

    def __init__(self, dut_manager, logger, sanitized_console=None):
        """
        Initialize the AutoDetectionService.

        Args:
            dut_manager: DUT manager instance
            logger: Logger instance
            sanitized_console: Sanitized console instance
        """
        self.dut_manager = dut_manager
        self.logger = logger
        self.console = (
            sanitized_console.console
            if sanitized_console
            else create_sanitized_console()
        )
        self.platform_mappings = []  # Will be populated in async_init

    async def async_init(self):
        """
        Async initialization to build platform mappings.

        Args:
            None
        """
        self.platform_mappings = await self._build_platform_mappings_from_spreadsheet()

    async def _build_platform_mappings_from_spreadsheet(
        self,
    ) -> List[Dict[str, Any]]:
        """
        Build platform mappings from spreadsheet.

        Args:
            None
        """
        try:
            # Get platform mappings from the baseboard manager (spreadsheet)
            await self.logger.log_runtime(
                "DEBUG",
                "AutoDetectionService",
                "Starting platform mapping build from spreadsheet",
            )

            # DUTManager has _get_baseboard_manager() method, not config_manager.get_baseboard_manager()
            if not hasattr(self.dut_manager, "_get_baseboard_manager"):
                await self.logger.log_runtime(
                    "WARNING",
                    "AutoDetectionService",
                    "DUT manager has no _get_baseboard_manager method",
                )
                return []

            baseboard_manager = self.dut_manager._get_baseboard_manager()
            if not baseboard_manager:
                await self.logger.log_runtime(
                    "WARNING",
                    "AutoDetectionService",
                    "No baseboard manager available",
                )
                return []

            if not baseboard_manager.baseboards:
                await self.logger.log_runtime(
                    "WARNING",
                    "AutoDetectionService",
                    "Baseboard manager has no baseboards data",
                )
                return []

            await self.logger.log_runtime(
                "DEBUG",
                "AutoDetectionService",
                f"Found {len(baseboard_manager.baseboards)} baseboards in spreadsheet",
            )
            return self._convert_baseboards_to_mappings(baseboard_manager.baseboards)

        except Exception as e:
            await self.logger.log_runtime(
                "WARNING",
                "AutoDetectionService",
                f"Failed to build platform mappings from spreadsheet: {e}",
            )
            return []

    def _convert_baseboards_to_mappings(
        self, baseboards: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Convert baseboard configurations to legacy mapping format.

        Args:
            baseboards: Baseboard configurations
        """
        mappings = []

        for baseboard_name, baseboard_config in baseboards.items():
            platform_detection = baseboard_config.get("platform_detection", {})
            if platform_detection:
                mapping = {
                    "platform": baseboard_config.get("platform", "x86_64"),
                    "node_type": platform_detection.get("node_type", "Compute"),
                    "manufacturer": platform_detection.get("manufacturer", []),
                    "models": platform_detection.get("models", []),
                    "baseboards": [baseboard_name],
                    "HMC_IP": platform_detection.get("hmc_ip"),
                    "product_family": platform_detection.get("product_family"),
                }
                mappings.append(mapping)

        return mappings

    def build_platform_baseboard_combinations(
        self,
    ) -> List[Tuple[str, str, str]]:
        """
        Build a list of valid platform-baseboard combinations from spreadsheet.

        Returns:
            list: List of tuples (platform, baseboard, node_type) representing valid combinations
        """
        combinations = []
        for mapping in self.platform_mappings:
            platform = mapping["platform"]
            node_type = mapping["node_type"]
            for baseboard in mapping["baseboards"]:
                combinations.append((platform, baseboard, node_type))

        # Sort by platform, then by baseboard for consistent display
        combinations.sort(key=lambda x: (x[0], x[1]))
        return combinations

    def display_manual_selection_prompt(self) -> Tuple[str, str]:
        """
        Display manual selection prompt using Rich console.

        Returns:
            tuple: (selected_platform, selected_baseboard) - the user's selection
        """
        combinations = self.build_platform_baseboard_combinations()

        if not combinations:
            self.console.print(
                Panel(
                    "[red]No platform-baseboard combinations found in spreadsheet configuration![/red]",
                    title="Error",
                )
            )
            raise ValueError("No platform-baseboard combinations available")

        # Create Rich table for display
        table = Table(title="Available Platform-Baseboard Combinations")
        table.add_column("Option", style="cyan", no_wrap=True)
        # table.add_column("Platform", style="green")
        table.add_column("Baseboard", style="yellow")
        table.add_column("Node Type", style="blue")

        # Group by platform for better display
        platform_groups = {}
        for platform, baseboard, node_type in combinations:
            if platform not in platform_groups:
                platform_groups[platform] = []
            platform_groups[platform].append((baseboard, node_type))

        # Display numbered options
        option_number = 1
        option_map = {}

        for platform in sorted(platform_groups.keys()):
            # Add platform header
            table.add_row(
                # f"[bold]{platform.upper()} PLATFORM:[/bold]", "", "", "", style="bold"
                f"[bold]{platform.upper()} PLATFORM:[/bold]",
                "",
                "",
                style="bold",
            )

            for baseboard, node_type in platform_groups[platform]:
                # table.add_row(f"  {option_number}", platform, baseboard, node_type)
                table.add_row(f"  {option_number}", baseboard, node_type)
                option_map[option_number] = (platform, baseboard)
                option_number += 1

        # Display the table
        self.console.print(table)

        # Get user selection
        while True:
            try:
                choice = Prompt.ask(
                    f"\n[bold]Enter your choice[/bold] (1-{len(combinations)})",
                    default="1",
                )

                if not choice:
                    self.console.print("[red]Please enter a valid choice.[/red]")
                    continue

                try:
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(combinations):
                        selected_platform, selected_baseboard = option_map[choice_num]
                        self.console.print(
                            f"[green]✓ Selected: {selected_platform} - {selected_baseboard}[/green]"
                        )
                        return selected_platform, selected_baseboard
                    else:
                        self.console.print(
                            f"[red]Please enter a number between 1 and {len(combinations)}.[/red]"
                        )
                except ValueError:
                    self.console.print("[red]Please enter a valid number.[/red]")

            except KeyboardInterrupt:
                self.console.print("\n\n[red]Exiting program...[/red]")
                raise
            except EOFError:
                self.console.print("\n\n[red]Exiting program...[/red]")
                raise

    def prompt_for_detection_confirmation(
        self,
        detected_platform: Optional[str],
        detected_baseboard: Optional[str],
        detected_node_type: Optional[str],
        non_interactive: bool = False,
    ) -> Tuple[str, str]:
        """
        Prompt the user to confirm or override the detected baseboard.
        Platform and node_type are derived from the baseboard mapping.

        Args:
            detected_platform: The detected platform (derived from baseboard)
            detected_baseboard: The detected baseboard (primary detection target)
            detected_node_type: The detected node type (derived from baseboard)
            non_interactive: If True, use detected values or exit

        Returns:
            tuple: (confirmed_platform, confirmed_baseboard) - the final platform and baseboard to use
        """
        # Check if detection was successful (we primarily care about baseboard)
        detection_successful = detected_baseboard is not None

        if detection_successful:
            # Create detection results panel
            detection_text = Text()
            detection_text.append("Detection Results\n", style="bold")
            # detection_text.append(f"Platform:     {detected_platform}\n")
            detection_text.append(f"Baseboard:    {detected_baseboard}\n")
            if detected_node_type:
                detection_text.append(f"Node Type:    {detected_node_type}")

            self.console.print(" ")
            self.console.print(" \n ")
            self.console.print(" \n ")
            self.console.print(" \n ")

            self.console.print(
                Panel(
                    detection_text,
                    title="Platform and Baseboard Detection",
                    border_style="green",
                )
            )

            if non_interactive:
                self.console.print(
                    "[green]Non-interactive mode: Using detected values[/green]"
                )
                return detected_platform, detected_baseboard

            # Interactive mode - ask for confirmation
            if Confirm.ask(
                "\n[bold]Do you want to proceed with these detected values?[/bold]"
            ):
                self.console.print("[green]✓ Proceeding with detected values[/green]")
                return detected_platform, detected_baseboard
            else:
                self.console.print("[yellow]Manual selection required[/yellow]")
                return self.display_manual_selection_prompt()
        else:
            # Detection failed
            detection_text = Text()
            detection_text.append("Baseboard Detection Failed\n", style="bold red")
            if detected_baseboard:
                detection_text.append(
                    f"Partially detected baseboard: {detected_baseboard}\n"
                )
            else:
                detection_text.append("Baseboard detection failed\n")

            if detected_platform:
                detection_text.append(f"Derived platform: {detected_platform}\n")
            if detected_node_type:
                detection_text.append(f"Derived node type: {detected_node_type}")

            self.console.print(
                Panel(
                    detection_text,
                    title="Platform and Baseboard Detection",
                    border_style="red",
                )
            )

            if non_interactive:
                self.console.print(
                    "[red]Non-interactive mode: Detection failed, exiting[/red]"
                )
                raise ValueError("Baseboard detection failed in non-interactive mode")

            # Interactive mode - prompt for manual selection
            self.console.print(
                "[yellow]Please manually select your baseboard.[/yellow]"
            )
            return self.display_manual_selection_prompt()

    # Helper function to validate against mapping
    async def validate_against_mapping(
        self,
        dut_id: str,
        platform=None,
        baseboard=None,
        node_type=None,
        manufacturer=None,
    ):
        """
        Validate against platform mappings.

        Args:
            dut_id: The DUT identifier
            platform: The platform to validate against
            baseboard: The baseboard to validate against
            node_type: The node type to validate against
            manufacturer: The manufacturer to validate against
        """
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AutoDetection",
            f"Validating against mappings: platform={platform}, node_type={node_type}, manufacturer={manufacturer}",
        )
        for mapping in self.platform_mappings:
            # Check if all provided values match the mapping
            if platform and mapping["platform"] != platform:
                continue
            if node_type and mapping["node_type"] != node_type:
                continue
            if manufacturer and manufacturer not in mapping["manufacturer"]:
                continue
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AutoDetection",
                f"Found matching mapping: {mapping}",
            )
            return mapping
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AutoDetection",
            "No matching mapping found",
        )
        return None

    # Helper function to try model matching
    async def try_model_matching(
        self, dut_id: str, model: str, info_dict: Dict[str, Any]
    ) -> bool:
        """
        Try to match a model against the platform mapping.

        Args:
            dut_id: The DUT identifier
            model: The model to match
            info_dict: The info dictionary to update
        """
        if not model:
            return False

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AutoDetection",
            f"Trying to match model: '{model}'",
        )

        # Phase 1: Try exact matches first
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AutoDetection",
            "Phase 1: Checking for exact matches across all mappings",
        )

        for mapping in self.platform_mappings:
            # Skip power shelf entries
            if mapping["node_type"] == "PowerShelf":
                continue

            # Skip entries with empty models array
            if not mapping["models"]:
                continue

            # Check for exact matches first
            for model_pattern in mapping["models"]:
                if not model_pattern:
                    continue

                # Check if this is an exact match (no regex special characters)
                if model_pattern == model:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "AutoDetection",
                        f"EXACT MATCH FOUND! Model '{model}' exactly matches pattern '{model_pattern}' in mapping for platform: {mapping['platform']}, node_type: {mapping['node_type']}",
                    )
                    info_dict["platform"] = mapping["platform"]
                    info_dict["node_type"] = mapping["node_type"]
                    # Use the first baseboard from the mapping
                    if mapping["baseboards"]:
                        info_dict["baseboard"] = mapping["baseboards"][0]
                    return True

        # Phase 2: Try regex patterns only if no exact match was found
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AutoDetection",
            "Phase 2: No exact matches found, trying regex patterns",
        )

        for mapping in self.platform_mappings:
            # Skip entries with empty models array
            if not mapping["models"]:
                continue

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AutoDetection",
                f"Checking mapping for platform: {mapping['platform']}, node_type: {mapping['node_type']}",
            )

            # Check if model matches any patterns in this mapping
            for model_pattern in mapping["models"]:
                if not model_pattern:
                    continue

                # Skip exact matches (already handled in Phase 1)
                if model_pattern == model:
                    continue

                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "AutoDetection",
                    f"Trying regex pattern: '{model_pattern}'",
                )

                try:
                    if re.search(model_pattern, model, re.IGNORECASE):
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "AutoDetection",
                            f"REGEX MATCH FOUND! Pattern '{model_pattern}' matches model '{model}'",
                        )
                        info_dict["platform"] = mapping["platform"]
                        info_dict["node_type"] = mapping["node_type"]
                        # Use the first baseboard from the mapping
                        if mapping["baseboards"]:
                            info_dict["baseboard"] = mapping["baseboards"][0]
                        return True
                except re.error as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "AutoDetection",
                        f"Invalid regex pattern '{model_pattern}' in platform mapping: {e}",
                    )
                    continue
        return False

    async def detect_platform_and_baseboard(
        self,
        dut_id: str,
        preflight_results: Optional[Dict[str, Any]] = None,
        non_interactive: bool = False,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Detect platform and baseboard type from the DUT.

        Args:
            dut_id: The DUT identifier
            preflight_results: Optional preflight results for the DUT
            non_interactive: If True, use detected values or exit

        Returns:
            tuple: (success, info_dict) where:
                - success (bool): True if detection was successful
                - info_dict (dict): Dictionary containing platform, baseboard, and node_type
        """
        info_dict = {"platform": None, "baseboard": None, "node_type": None}

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "AutoDetection",
            "Starting platform and baseboard detection...",
        )

        # Simple console output for autodetection start
        # self.console.print(f"[bold blue]Auto-detecting platform and baseboard for {dut_id}...[/bold blue]")

        # Use provided preflight results or empty dict if none provided
        if preflight_results is None:
            preflight_results = {}

        host_preflight_passed = (
            preflight_results.get("host", {}).get("status") == "pass"
        )
        redfish_preflight_passed = (
            preflight_results.get("redfish", {}).get("status") == "pass"
        )

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AutoDetection",
            f"Preflight status - Host: {'Passed' if host_preflight_passed else 'Failed'}, Redfish: {'Passed' if redfish_preflight_passed else 'Failed'}",
        )

        # Debug: Log platform mappings
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AutoDetection",
            f"Loaded {len(self.platform_mappings)} platform mappings",
        )

        for i, mapping in enumerate(self.platform_mappings[:3]):  # Log first 3 mappings
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AutoDetection",
                f"Mapping {i}: platform={mapping.get('platform')}, node_type={mapping.get('node_type')}, baseboards={mapping.get('baseboards', [])}",
            )

        # Get DUT config for all detection strategies
        try:
            dut_config = self.dut_manager.get_dut_config(dut_id)
        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARN",
                "AutoDetection",
                f"Could not get DUT config: {e}",
            )
            dut_config = {}

        # Detection Strategy 1: Host-based detection
        # Try host detection even if preflight didn't pass - preflight is just an optimization
        if True:  # Always try host detection
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AutoDetection",
                "Attempting host-based detection",
            )

            # First try to detect if it's a switch
            try:
                exit_code, output, stderr = await self.dut_manager.execute_host_command(
                    dut_id, "which nv"
                )
                if exit_code == 0 and output:
                    # This is a switch node
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "AutoDetection",
                        "NVIDIA GPU detected via 'which nv' command - this is a switch node",
                    )

                    # Look for NVSwitch mappings in platform mappings
                    for mapping in self.platform_mappings:
                        if (
                            mapping["node_type"] == "SwitchTray"
                            and mapping["platform"] == "NVSwitch"
                        ):
                            info_dict["node_type"] = mapping["node_type"]
                            info_dict["platform"] = mapping["platform"]
                            if mapping["baseboards"]:
                                info_dict["baseboard"] = mapping["baseboards"][0]

                                # Show detection results in the same panel format
                                detection_text = Text()
                                detection_text.append(
                                    "Detection Results\n", style="bold"
                                )
                                detection_text.append(
                                    f"Baseboard:    {info_dict['baseboard']}\n"
                                )
                                if info_dict.get("node_type"):
                                    detection_text.append(
                                        f"Node Type:    {info_dict['node_type']}"
                                    )

                                self.console.print(" ")
                                self.console.print(" \n ")
                                self.console.print(" \n ")
                                self.console.print(" \n ")

                                self.console.print(
                                    Panel(
                                        detection_text,
                                        title="Platform and Baseboard Detection",
                                        border_style="green",
                                    )
                                )

                                if non_interactive:
                                    self.console.print(
                                        f"[green]Non-interactive mode: Using detected values - Platform: {info_dict.get('platform', 'Unknown')}, Baseboard: {info_dict['baseboard']}[/green]"
                                    )

                            return True, info_dict

                    # Fallback if no specific mapping found
                    if not info_dict.get("baseboard"):
                        info_dict["node_type"] = "SwitchTray"
                        info_dict["platform"] = "NVSwitch"

                        # Show detection results in the same panel format
                        detection_text = Text()
                        detection_text.append("Detection Results\n", style="bold")
                        detection_text.append(
                            f"Baseboard:    {info_dict.get('baseboard', 'SwitchTray (Generic)')}\n"
                        )
                        if info_dict.get("node_type"):
                            detection_text.append(
                                f"Node Type:    {info_dict['node_type']}"
                            )

                        self.console.print(" ")
                        self.console.print(" \n ")
                        self.console.print(" \n ")
                        self.console.print(" \n ")

                        self.console.print(
                            Panel(
                                detection_text,
                                title="Platform and Baseboard Detection",
                                border_style="green",
                            )
                        )

                        if non_interactive:
                            self.console.print(
                                f"[green]Non-interactive mode: Using detected values - Platform: {info_dict.get('platform', 'Unknown')}, Baseboard: {info_dict.get('baseboard', 'SwitchTray (Generic)')}[/green]"
                            )

                        return True, info_dict
            except Exception as e:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "AutoDetection",
                    f"Error checking for switch: {e}",
                )

            # If not a switch, it must be a compute node
            try:
                exit_code, output, stderr = await self.dut_manager.execute_host_command(
                    dut_id, "uname -m"
                )
                if exit_code == 0 and output:
                    arch = output.strip()
                    info_dict["node_type"] = "Compute"
                    if arch == "x86_64":
                        info_dict["platform"] = "x86_64"
                    elif arch == "aarch64":
                        info_dict["platform"] = "arm64"

                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "AutoDetection",
                        f"Detected compute node with architecture: {arch}, platform: {info_dict['platform']}",
                    )

                    # Validate against mapping
                    mapping = await self.validate_against_mapping(
                        dut_id, platform=info_dict["platform"], node_type="Compute"
                    )
                    if mapping:
                        # Set baseboard from mapping first (fallback)
                        if mapping.get("baseboards"):
                            info_dict["baseboard"] = mapping["baseboards"][0]
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "AutoDetection",
                                f"Set baseboard from mapping: {info_dict['baseboard']}",
                            )

                        # Try to detect baseboard via host for more specific matching
                        try:
                            exit_code, output, stderr = (
                                await self.dut_manager.execute_host_command(
                                    dut_id, "dmidecode -t 2", use_sudo=True
                                )
                            )
                            success = exit_code == 0
                            if success and output:
                                # Parse dmidecode output for baseboard info
                                for line in output.split("\n"):
                                    if "Product Name:" in line:
                                        detected_baseboard = line.split(
                                            "Product Name:"
                                        )[1].strip()
                                        if detected_baseboard:
                                            await self.logger.write_to_dut_runtime_log(
                                                dut_id,
                                                "DEBUG",
                                                "AutoDetection",
                                                f"Detected model via dmidecode: {detected_baseboard}",
                                            )

                                            # Try model matching for more specific baseboard
                                            if await self.try_model_matching(
                                                dut_id, detected_baseboard, info_dict
                                            ):
                                                await self.logger.write_to_dut_runtime_log(
                                                    dut_id,
                                                    "INFO",
                                                    "AutoDetection",
                                                    f"Successfully matched model '{detected_baseboard}' to platform '{info_dict['platform']}' and baseboard '{info_dict['baseboard']}'",
                                                )
                                                # Don't return here - let it flow to confirmation prompt
                                            else:
                                                # Model matching failed, but we still have a baseboard from mapping
                                                await self.logger.write_to_dut_runtime_log(
                                                    dut_id,
                                                    "INFO",
                                                    "AutoDetection",
                                                    f"Model '{detected_baseboard}' didn't match specific patterns, but using baseboard from platform mapping: '{info_dict['baseboard']}'",
                                                )
                                                # Don't return here - let it flow to confirmation prompt
                        except Exception as e:
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "WARNING",
                                "AutoDetection",
                                f"Error detecting compute baseboard: {e}",
                            )
                            # Even if dmidecode fails, we still have baseboard from mapping
                            if info_dict.get("baseboard"):
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "INFO",
                                    "AutoDetection",
                                    f"Using baseboard from platform mapping despite dmidecode error: '{info_dict['baseboard']}'",
                                )
                                # Don't return here - let it flow to confirmation prompt
            except Exception as e:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "AutoDetection",
                    f"Error detecting CPU architecture: {e}",
                )

        # Detection Strategy 2: BMC/Redfish detection
        # Try Redfish detection if BMC_IP is configured, regardless of preflight status
        if dut_config.get("BMC_IP"):
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AutoDetection",
                "BMC IP is present - attempting Redfish detection",
            )

            if redfish_preflight_passed:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "AutoDetection",
                    "Redfish preflight passed - attempting Redfish detection",
                )

                # Try Redfish detection for both platform and baseboard
                chassis_id_list = [
                    "HGX_BMC_0",
                    "Chassis_0",
                    "HGX",
                    "BMC_0",
                    "HMC_0",
                    "MGX_NVSwitch_0",
                    "MGX_NVSwitch_1",
                    "MGX_BMC_0",
                    "DGX",
                ]

                success, chassis_collection, _, _ = (
                    await self.dut_manager.execute_redfish_request(
                        dut_id, "GET", "/redfish/v1/Chassis/"
                    )
                )
                if success and chassis_collection:
                    # First look for BMC_0 or HGX_BMC_0
                    bmc_chassis = None
                    for member in chassis_collection.get("Members", []):
                        chassis_uri = member.get("@odata.id")
                        if not chassis_uri:
                            continue

                        chassis_id = chassis_uri.split("/")[-1]
                        if chassis_id in chassis_id_list:
                            # Get details for this chassis
                            success, chassis_info, _, _ = (
                                await self.dut_manager.execute_redfish_request(
                                    dut_id, "GET", chassis_uri
                                )
                            )
                            if success and chassis_info:
                                model = chassis_info.get("Model")
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "DEBUG",
                                    "AutoDetection",
                                    f"Redfish chassis {chassis_id} detected model: '{model}'",
                                )
                                if await self.try_model_matching(
                                    dut_id, model, info_dict
                                ):
                                    bmc_chassis = chassis_info
                                    break

                    # If we didn't find BMC_0/HGX_BMC_0 or couldn't determine platform/baseboard,
                    # check other chassis members for power shelf
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "AutoDetection",
                        "Checking other chassis members for power shelf",
                    )

                    if not info_dict["platform"]:
                        for member in chassis_collection.get("Members", []):
                            chassis_uri = member.get("@odata.id")
                            if not chassis_uri:
                                continue

                            # Skip chassis we already tried in the primary detection
                            chassis_id = chassis_uri.split("/")[-1]
                            if chassis_id in chassis_id_list:
                                continue

                            # Get details for this chassis
                            success, chassis_info, _, _ = (
                                await self.dut_manager.execute_redfish_request(
                                    dut_id, "GET", chassis_uri
                                )
                            )
                            if not success or not chassis_info:
                                continue

                            # Check if this is a power shelf (DELTA manufacturer)
                            manufacturer = chassis_info.get("Manufacturer")
                            if manufacturer and manufacturer.upper() == "DELTA":
                                # Look for PowerShelf mappings in platform mappings
                                for mapping in self.platform_mappings:
                                    if (
                                        mapping["node_type"] == "PowerShelf"
                                        and mapping["platform"] == "PowerShelf"
                                        and manufacturer.upper()
                                        in [
                                            m.upper()
                                            for m in mapping.get("manufacturer", [])
                                        ]
                                    ):
                                        info_dict["node_type"] = mapping["node_type"]
                                        info_dict["platform"] = mapping["platform"]
                                        if mapping["baseboards"]:
                                            info_dict["baseboard"] = mapping[
                                                "baseboards"
                                            ][0]
                                        # Don't return here - let it flow to confirmation prompt
                                        break

                                # Fallback if no specific mapping found
                                if not info_dict.get("baseboard"):
                                    info_dict["node_type"] = "PowerShelf"
                                    info_dict["platform"] = "PowerShelf"
                                    # Don't return here - let it flow to confirmation prompt

                            # Try model matching for non-power shelf chassis
                            model = chassis_info.get("Model")
                            if model:
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "DEBUG",
                                    "AutoDetection",
                                    f"Redfish chassis {chassis_id} detected model: '{model}'",
                                )
                                if await self.try_model_matching(
                                    dut_id, model, info_dict
                                ):
                                    bmc_chassis = chassis_info
                                    break
            else:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "AutoDetection",
                    "Redfish preflight failed - skipping Redfish-based detection",
                )

        # Check if detection was successful
        self.console.print("[green]Detection completed, processing results...[/green]")
        detection_successful = bool(info_dict["platform"] and info_dict["baseboard"])

        if not detection_successful:
            # Provide specific error information
            if not host_preflight_passed and not redfish_preflight_passed:
                info_dict["error"] = (
                    "All preflight checks failed - cannot connect to DUT for detection"
                )
            elif not host_preflight_passed:
                info_dict["error"] = (
                    "Host preflight check failed - cannot perform host-based detection"
                )
            elif not redfish_preflight_passed:
                info_dict["error"] = (
                    "Redfish preflight check failed - cannot perform Redfish-based detection"
                )
            else:
                info_dict["error"] = (
                    "Detection completed but could not identify platform/baseboard from available information"
                )

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "AutoDetection",
            f"Detection complete - Platform: {info_dict['platform']}, Baseboard: {info_dict['baseboard']}, NodeType: {info_dict['node_type']}",
        )

        # If detection was successful or failed, prompt user for confirmation (unless non-interactive)
        # This allows user to confirm detected values or manually select if detection failed
        try:
            confirmed_platform, confirmed_baseboard = (
                self.prompt_for_detection_confirmation(
                    info_dict["platform"],
                    info_dict["baseboard"],
                    info_dict["node_type"],
                    non_interactive,
                )
            )

            # Update info_dict with confirmed values
            info_dict["platform"] = confirmed_platform
            info_dict["baseboard"] = confirmed_baseboard

            # For confirmed values, we need to look up the node_type from the mapping
            for mapping in self.platform_mappings:
                if (
                    confirmed_platform == mapping["platform"]
                    and confirmed_baseboard in mapping["baseboards"]
                ):
                    info_dict["node_type"] = mapping["node_type"]
                    break

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "AutoDetection",
                f"User confirmed - Platform: {confirmed_platform}, Baseboard: {confirmed_baseboard}, NodeType: {info_dict['node_type']}",
            )

            self.console.print("[green]Auto-detection completed successfully![/green]")

            return True, info_dict  # Always return success if user confirmed

        except (KeyboardInterrupt, EOFError):
            # User cancelled
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "AutoDetection",
                "User cancelled auto-detection process",
            )
            info_dict["error"] = "User cancelled auto-detection process"
            return False, info_dict
        except ValueError as e:
            # Non-interactive mode failure
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "AutoDetection",
                f"Non-interactive mode failure: {str(e)}",
            )
            info_dict["error"] = str(e)
            return False, info_dict
