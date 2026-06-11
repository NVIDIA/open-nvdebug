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

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from ..utils.console_output import create_sanitized_console

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

    @staticmethod
    def _identity_is_present(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        normalized = value.strip()
        return normalized not in ("", "$", "null", "NULL")

    @staticmethod
    def _model_is_generic(model: str) -> bool:
        normalized = model.strip().lower()
        return normalized in {
            "",
            "$",
            "null",
            "na",
            "n/a",
            "none",
            "unknown",
            "openbmc",
            "ami redfish server",
            "gb hmc",
            "gb bmc",
        } or normalized.startswith("unknownmodel")

    def _extract_first_string_field(
        self, payload: Any, field_name: str
    ) -> Optional[str]:
        if isinstance(payload, dict):
            value = payload.get(field_name)
            if isinstance(value, str) and value.strip():
                return value.strip()
            for nested in payload.values():
                found = self._extract_first_string_field(nested, field_name)
                if found:
                    return found
        elif isinstance(payload, list):
            for item in payload:
                found = self._extract_first_string_field(item, field_name)
                if found:
                    return found
        return None

    @staticmethod
    def _candidate_score(uri: str, signal: str) -> int:
        if uri.startswith("/redfish/v1/Systems/HGX_Baseboard_"):
            score = 700
        elif "/Systems/" in uri and "HGX_Baseboard" in uri:
            score = 690
        elif uri.startswith("/redfish/v1/Chassis/HGX_Chassis_") and uri.endswith(
            "/Assembly"
        ):
            score = 610
        elif uri.startswith("/redfish/v1/Chassis/HGX_Chassis_"):
            score = 620
        elif uri.startswith("/redfish/v1/Systems/System_"):
            score = 560
        elif uri.startswith("/redfish/v1/Systems/"):
            score = 520
        elif uri.startswith("/redfish/v1/Chassis/Chassis_") and uri.endswith(
            "/Assembly"
        ):
            score = 490
        elif uri.startswith("/redfish/v1/Chassis/Chassis_"):
            score = 500
        elif uri.startswith("/redfish/v1/Chassis/") and "BMC" in uri:
            score = 320
        elif uri.startswith("/redfish/v1/Chassis/HMC_"):
            score = 300
        elif uri.startswith("/redfish/v1/Chassis/"):
            score = 440
        elif uri == "/redfish/v1":
            score = 250
        else:
            score = 200

        if signal == "manufacturer":
            score -= 40
        return score

    @staticmethod
    def _extract_redfish_success_payload(response: Any) -> Tuple[bool, Optional[Any]]:
        if not isinstance(response, tuple) or len(response) < 2:
            return False, None
        success = response[0]
        payload = response[1]
        return (success, payload) if isinstance(success, bool) else (False, None)

    @staticmethod
    def _mapping_specificity(mapping: Dict[str, Any], pattern: str, value: str) -> Tuple[int, int, int]:
        """Rank a matching mapping so the most-specific one wins a tie.

        Order, highest first:
          1. Baseboard name appears as a case-insensitive substring of the
             observed value (e.g. model "MGX-GH200 System" contains the
             baseboard name "MGX-GH200"). This is a strong signal the mapping
             is the intended target.
          2. Longer baseboard name (ties broken by name length).
          3. Longer matching pattern (a broad ".*GH200.*" loses to a more
             specific ".*GH200-NVL2.*").
        """
        baseboard_name = (mapping.get("baseboards") or [""])[0] or ""
        value_lower = (value or "").lower()
        name_lower = baseboard_name.lower()
        name_in_value = 1 if name_lower and name_lower in value_lower else 0
        return (name_in_value, len(baseboard_name), len(pattern or ""))

    async def try_manufacturer_matching(
        self, dut_id: str, manufacturer: str, info_dict: Dict[str, Any]
    ) -> bool:
        if not manufacturer:
            return False

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AutoDetection",
            f"Trying to match manufacturer: '{manufacturer}'",
        )

        exact_matches = []
        regex_matches = []
        for mapping in self.platform_mappings:
            patterns = mapping.get("manufacturer", []) or []
            for pattern in patterns:
                if not pattern:
                    continue
                if pattern == manufacturer:
                    exact_matches.append((mapping, pattern))
                else:
                    regex_matches.append((mapping, pattern))

        if exact_matches:
            best_mapping, best_pattern = max(
                exact_matches,
                key=lambda mp: self._mapping_specificity(mp[0], mp[1], manufacturer),
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "AutoDetection",
                f"EXACT MANUFACTURER MATCH FOUND! '{manufacturer}' matches '{best_pattern}'",
            )
            info_dict["platform"] = best_mapping["platform"]
            info_dict["node_type"] = best_mapping["node_type"]
            if best_mapping["baseboards"]:
                info_dict["baseboard"] = best_mapping["baseboards"][0]
            return True

        valid_regex_hits = []
        for mapping, pattern in regex_matches:
            try:
                if re.search(pattern, manufacturer, re.IGNORECASE):
                    valid_regex_hits.append((mapping, pattern))
            except re.error as e:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "AutoDetection",
                    f"Invalid manufacturer regex pattern '{pattern}' in platform mapping: {e}",
                )

        if not valid_regex_hits:
            return False

        best_mapping, best_pattern = max(
            valid_regex_hits,
            key=lambda mp: self._mapping_specificity(mp[0], mp[1], manufacturer),
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "AutoDetection",
            f"REGEX MANUFACTURER MATCH FOUND! Pattern '{best_pattern}' matches manufacturer '{manufacturer}' "
            f"(selected most specific of {len(valid_regex_hits)} candidate mapping(s))",
        )
        info_dict["platform"] = best_mapping["platform"]
        info_dict["node_type"] = best_mapping["node_type"]
        if best_mapping["baseboards"]:
            info_dict["baseboard"] = best_mapping["baseboards"][0]
        return True

    async def _evaluate_redfish_candidate(
        self, dut_id: str, uri: str, payload: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        model = self._extract_first_string_field(payload, "Model")
        manufacturer = self._extract_first_string_field(payload, "Manufacturer")
        part_number = self._extract_first_string_field(payload, "PartNumber")

        if uri.startswith("/redfish/v1/Chassis/PowerShelf") or (
            isinstance(manufacturer, str) and manufacturer.strip().lower() == "delta"
        ):
            return {
                "uri": uri,
                "signal": "heuristic",
                "score": self._candidate_score(uri, "model"),
                "platform": "PowerShelf",
                "baseboard": "PowerShelf",
                "node_type": "PowerShelf",
                "model": model,
                "manufacturer": manufacturer,
            }

        match_info: Dict[str, Optional[str]] = {
            "platform": None,
            "baseboard": None,
            "node_type": None,
        }
        signal = None

        if self._identity_is_present(model) and not self._model_is_generic(model):
            if await self.try_model_matching(dut_id, model, match_info):
                signal = "model"

        # PartNumber is more specific than Model when both are present: the FRU
        # PartNumber identifies the exact PCB SKU/stepping while Model often
        # collapses related products into a single marketing string (e.g.
        # GB200 NVL and GB200 NVL4 both publish Model="GB200 NVL"). If a
        # PartNumber pattern explicitly matches and resolves to a *different*
        # baseboard than model matching did, prefer the PartNumber result.
        # When model matching produced no result, PartNumber acts as the
        # primary signal.
        if self._identity_is_present(part_number):
            pn_match: Dict[str, Optional[str]] = {
                "platform": None,
                "baseboard": None,
                "node_type": None,
            }
            if await self.try_part_number_matching(dut_id, part_number, pn_match):
                if signal is None or (
                    pn_match.get("baseboard")
                    and pn_match["baseboard"] != match_info.get("baseboard")
                ):
                    if signal == "model":
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "AutoDetection",
                            f"PartNumber '{part_number}' overrides model-matched "
                            f"baseboard '{match_info.get('baseboard')}' with more specific "
                            f"'{pn_match['baseboard']}'",
                        )
                    match_info = pn_match
                    signal = "part_number"

        if signal is None and self._identity_is_present(manufacturer):
            if await self.try_manufacturer_matching(dut_id, manufacturer, match_info):
                signal = "manufacturer"

        if signal is None:
            return None

        return {
            "uri": uri,
            "signal": signal,
            "score": self._candidate_score(uri, signal),
            "platform": match_info["platform"],
            "baseboard": match_info["baseboard"],
            "node_type": match_info["node_type"],
            "model": model,
            "manufacturer": manufacturer,
            "part_number": part_number,
        }

    async def _select_best_redfish_candidate(
        self, dut_id: str
    ) -> Optional[Dict[str, Any]]:
        best_candidate: Optional[Dict[str, Any]] = None
        seen_uris = set()

        async def consider_uri(uri: str) -> None:
            nonlocal best_candidate
            if uri in seen_uris:
                return
            seen_uris.add(uri)

            success, payload = self._extract_redfish_success_payload(
                await self.dut_manager.execute_redfish_request(dut_id, "GET", uri)
            )
            if not success or not payload:
                return

            candidate = await self._evaluate_redfish_candidate(dut_id, uri, payload)
            if candidate and (
                best_candidate is None
                or candidate["score"] > best_candidate["score"]
            ):
                best_candidate = candidate

        primary_system_ids = ["HGX_Baseboard_0", "System_0", "DGX"]
        primary_chassis_ids = [
            "HGX_Chassis_0",
            "Chassis_0",
            "DGX",
            "HGX_BMC_0",
            "BMC_0",
            "HMC_0",
            "HGX",
            "MGX_NVSwitch_0",
            "MGX_NVSwitch_1",
            "MGX_BMC_0",
        ]
        primary_chassis_assembly_ids = ["HGX_Chassis_0", "Chassis_0", "DGX"]

        for system_id in primary_system_ids:
            await consider_uri(f"/redfish/v1/Systems/{system_id}")

        for chassis_id in primary_chassis_ids:
            await consider_uri(f"/redfish/v1/Chassis/{chassis_id}")

        for chassis_id in primary_chassis_assembly_ids:
            await consider_uri(f"/redfish/v1/Chassis/{chassis_id}/Assembly")

        success, systems_payload = self._extract_redfish_success_payload(
            await self.dut_manager.execute_redfish_request(
                dut_id, "GET", "/redfish/v1/Systems"
            )
        )
        if success and systems_payload:
            for member in systems_payload.get("Members", []):
                uri = member.get("@odata.id")
                if isinstance(uri, str) and uri.startswith("/redfish/v1/Systems/"):
                    await consider_uri(uri)

        success, chassis_payload = self._extract_redfish_success_payload(
            await self.dut_manager.execute_redfish_request(
                dut_id, "GET", "/redfish/v1/Chassis"
            )
        )
        if success and chassis_payload:
            for member in chassis_payload.get("Members", []):
                uri = member.get("@odata.id")
                if isinstance(uri, str) and uri.startswith("/redfish/v1/Chassis/"):
                    await consider_uri(uri)

        await consider_uri("/redfish/v1")
        return best_candidate

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
                    "part_numbers": platform_detection.get("part_numbers", []),
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

    async def _finalize_detection_with_confirmation(
        self,
        dut_id: str,
        info_dict: Dict[str, Any],
        non_interactive: bool,
    ) -> Tuple[bool, Dict[str, Any]]:
        try:
            detected_node_type = info_dict.get("node_type")
            confirmed_platform, confirmed_baseboard = (
                self.prompt_for_detection_confirmation(
                    info_dict["platform"],
                    info_dict.get("baseboard"),
                    info_dict.get("node_type"),
                    non_interactive,
                )
            )

            info_dict["platform"] = confirmed_platform
            info_dict["baseboard"] = confirmed_baseboard
            info_dict["node_type"] = None

            mapping_found = False
            for mapping in self.platform_mappings:
                if (
                    confirmed_platform == mapping["platform"]
                    and confirmed_baseboard in mapping.get("baseboards", [])
                ):
                    info_dict["node_type"] = mapping["node_type"]
                    mapping_found = True
                    break

            if not info_dict.get("node_type"):
                info_dict["node_type"] = detected_node_type or "unknown"
                warning_message = (
                    "No platform mapping found after confirmation - "
                    f"Platform: {confirmed_platform}, Baseboard: {confirmed_baseboard}"
                )
                if hasattr(self.logger, "warning"):
                    self.logger.warning(warning_message)
                else:
                    logging.warning(warning_message)

                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "AutoDetection",
                    warning_message,
                )

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "AutoDetection",
                f"User confirmed - Platform: {confirmed_platform}, Baseboard: {confirmed_baseboard}, NodeType: {info_dict.get('node_type')}",
            )

            self.console.print("[green]Auto-detection completed successfully![/green]")
            return True, info_dict
        except (KeyboardInterrupt, EOFError):
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "AutoDetection",
                "User cancelled auto-detection process",
            )
            info_dict["error"] = "User cancelled auto-detection process"
            return False, info_dict

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

        Phase 1 finds literal exact matches; Phase 2 finds regex matches.
        When multiple mappings match the same model, the most specific one
        wins via `_mapping_specificity` (prefers a mapping whose baseboard
        name is a substring of the model, then the longest baseboard name,
        then the longest matching pattern). This prevents broad regexes
        like ``.*GH200.*`` on a generically-named baseboard (e.g. "C2")
        from shadowing a more specific mapping (e.g. "MGX-GH200").

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

        exact_hits: List[Tuple[Dict[str, Any], str]] = []
        for mapping in self.platform_mappings:
            if mapping["node_type"] == "PowerShelf":
                continue
            if not mapping["models"]:
                continue
            for model_pattern in mapping["models"]:
                if not model_pattern:
                    continue
                if model_pattern == model:
                    exact_hits.append((mapping, model_pattern))

        if exact_hits:
            best_mapping, best_pattern = max(
                exact_hits,
                key=lambda mp: self._mapping_specificity(mp[0], mp[1], model),
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "AutoDetection",
                f"EXACT MATCH FOUND! Model '{model}' exactly matches pattern '{best_pattern}' "
                f"in mapping for platform: {best_mapping['platform']}, node_type: {best_mapping['node_type']} "
                f"(selected most specific of {len(exact_hits)} exact match(es))",
            )
            info_dict["platform"] = best_mapping["platform"]
            info_dict["node_type"] = best_mapping["node_type"]
            if best_mapping["baseboards"]:
                info_dict["baseboard"] = best_mapping["baseboards"][0]
            return True

        # Phase 2: Try regex patterns only if no exact match was found
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AutoDetection",
            "Phase 2: No exact matches found, trying regex patterns",
        )

        regex_hits: List[Tuple[Dict[str, Any], str]] = []
        for mapping in self.platform_mappings:
            if not mapping["models"]:
                continue

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AutoDetection",
                f"Checking mapping for platform: {mapping['platform']}, node_type: {mapping['node_type']}",
            )

            for model_pattern in mapping["models"]:
                if not model_pattern:
                    continue
                if model_pattern == model:
                    # already handled in Phase 1
                    continue

                try:
                    if re.search(model_pattern, model, re.IGNORECASE):
                        regex_hits.append((mapping, model_pattern))
                except re.error as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "AutoDetection",
                        f"Invalid regex pattern '{model_pattern}' in platform mapping: {e}",
                    )
                    continue

        if not regex_hits:
            return False

        best_mapping, best_pattern = max(
            regex_hits,
            key=lambda mp: self._mapping_specificity(mp[0], mp[1], model),
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "AutoDetection",
            f"REGEX MATCH FOUND! Pattern '{best_pattern}' matches model '{model}' "
            f"(selected most specific of {len(regex_hits)} candidate mapping(s))",
        )
        info_dict["platform"] = best_mapping["platform"]
        info_dict["node_type"] = best_mapping["node_type"]
        if best_mapping["baseboards"]:
            info_dict["baseboard"] = best_mapping["baseboards"][0]
        return True

    async def try_part_number_matching(
        self, dut_id: str, part_number: str, info_dict: Dict[str, Any]
    ) -> bool:
        """
        Try to match a Redfish PartNumber against the baseboard mapping's
        ``part_numbers`` list.

        Required when two baseboards publish the same Model string and can
        only be told apart by their FRU PartNumber (e.g. GB200 NVL vs
        GB200 NVL4 -- both publish ``Model="GB200 NVL"`` but their
        HGX_Baseboard_0 PartNumbers differ at the ``-1201-`` vs ``-0201-``
        infix). Like ``try_model_matching`` this runs Phase 1 (literal
        equality) then Phase 2 (regex search) and uses the same
        ``_mapping_specificity`` tie-break.

        Args:
            dut_id: The DUT identifier
            part_number: The PartNumber string to match
            info_dict: The info dictionary to update on a successful match
        """
        if not part_number:
            return False

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AutoDetection",
            f"Trying to match PartNumber: '{part_number}'",
        )

        exact_hits: List[Tuple[Dict[str, Any], str]] = []
        for mapping in self.platform_mappings:
            for pn_pattern in mapping.get("part_numbers") or []:
                if pn_pattern and pn_pattern == part_number:
                    exact_hits.append((mapping, pn_pattern))

        if exact_hits:
            best_mapping, best_pattern = max(
                exact_hits,
                key=lambda mp: self._mapping_specificity(mp[0], mp[1], part_number),
            )
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "AutoDetection",
                f"EXACT PART-NUMBER MATCH FOUND! '{part_number}' matches '{best_pattern}'",
            )
            info_dict["platform"] = best_mapping["platform"]
            info_dict["node_type"] = best_mapping["node_type"]
            if best_mapping["baseboards"]:
                info_dict["baseboard"] = best_mapping["baseboards"][0]
            return True

        regex_hits: List[Tuple[Dict[str, Any], str]] = []
        for mapping in self.platform_mappings:
            for pn_pattern in mapping.get("part_numbers") or []:
                if not pn_pattern or pn_pattern == part_number:
                    continue
                try:
                    if re.search(pn_pattern, part_number, re.IGNORECASE):
                        regex_hits.append((mapping, pn_pattern))
                except re.error as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "AutoDetection",
                        f"Invalid PartNumber regex pattern '{pn_pattern}' in platform mapping: {e}",
                    )

        if not regex_hits:
            return False

        best_mapping, best_pattern = max(
            regex_hits,
            key=lambda mp: self._mapping_specificity(mp[0], mp[1], part_number),
        )
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "AutoDetection",
            f"REGEX PART-NUMBER MATCH FOUND! Pattern '{best_pattern}' matches PartNumber '{part_number}' "
            f"(selected most specific of {len(regex_hits)} candidate mapping(s))",
        )
        info_dict["platform"] = best_mapping["platform"]
        info_dict["node_type"] = best_mapping["node_type"]
        if best_mapping["baseboards"]:
            info_dict["baseboard"] = best_mapping["baseboards"][0]
        return True

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
        redfish_preflight_status = preflight_results.get("redfish", {}).get("status")
        redfish_preflight_passed = redfish_preflight_status == "pass"

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

        _switch_detected = False
        switch_baseboard_fallback = None

        # Detection Strategy 1: BMC/Redfish detection
        if dut_config.get("BMC_IP"):
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AutoDetection",
                "BMC IP is present - attempting Redfish detection",
            )

            if redfish_preflight_status == "pass":
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "AutoDetection",
                    "Redfish preflight passed - attempting Redfish detection",
                )
                candidate = await self._select_best_redfish_candidate(dut_id)
                if candidate:
                    info_dict["platform"] = candidate["platform"]
                    info_dict["baseboard"] = candidate["baseboard"]
                    info_dict["node_type"] = candidate["node_type"]
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "AutoDetection",
                        "Selected Redfish detection candidate: "
                        f"uri={candidate['uri']}, signal={candidate['signal']}, "
                        f"model={candidate.get('model')}, manufacturer={candidate.get('manufacturer')}, "
                        f"baseboard={candidate['baseboard']}, platform={candidate['platform']}",
                    )
            elif redfish_preflight_status == "fail":
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "AutoDetection",
                    "Redfish preflight failed - skipping Redfish-based detection",
                )
            else:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "AutoDetection",
                    "No Redfish preflight results were provided - attempting Redfish detection as best-effort fallback",
                )
                candidate = await self._select_best_redfish_candidate(dut_id)
                if candidate:
                    info_dict["platform"] = candidate["platform"]
                    info_dict["baseboard"] = candidate["baseboard"]
                    info_dict["node_type"] = candidate["node_type"]
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "INFO",
                        "AutoDetection",
                        "Selected Redfish detection candidate: "
                        f"uri={candidate['uri']}, signal={candidate['signal']}, "
                        f"model={candidate.get('model')}, manufacturer={candidate.get('manufacturer')}, "
                        f"baseboard={candidate['baseboard']}, platform={candidate['platform']}",
                    )

        # Detection Strategy 2: Host-based fallback
        # Try host detection only if Redfish did not already determine the baseboard.
        if not (info_dict["platform"] and info_dict["baseboard"]):
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AutoDetection",
                "Attempting host-based fallback detection",
            )

            try:
                exit_code, output, stderr = await self.dut_manager.execute_host_command(
                    dut_id, "which nv"
                )
                if exit_code == 0 and output:
                    # Treat this as a provisional SwitchTray signal and keep going so
                    # Redfish can refine the exact tray baseboard.
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "AutoDetection",
                        "NVIDIA GPU detected via 'which nv' command - switch node detected, deferring exact baseboard selection to Redfish if available",
                    )

                    info_dict["node_type"] = "SwitchTray"
                    info_dict["platform"] = "NVSwitch"
                    _switch_detected = True

                    switch_mappings = [
                        mapping
                        for mapping in self.platform_mappings
                        if mapping["node_type"] == "SwitchTray"
                        and mapping["platform"] == "NVSwitch"
                    ]
                    if len(switch_mappings) == 1 and switch_mappings[0]["baseboards"]:
                        info_dict["baseboard"] = switch_mappings[0]["baseboards"][0]
                    elif switch_mappings and switch_mappings[0]["baseboards"]:
                        switch_baseboard_fallback = switch_mappings[0]["baseboards"][0]
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "DEBUG",
                            "AutoDetection",
                            "Multiple NVSwitch tray mappings are available - waiting for Redfish to disambiguate before choosing a baseboard",
                        )
            except Exception as e:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "AutoDetection",
                    f"Error checking for switch: {e}",
                )

            # If not a switch, it must be a compute node
            if not _switch_detected:
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
                                # Even if dmidecode fails, we still have a baseboard from mapping
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

        if _switch_detected and not info_dict.get("baseboard") and switch_baseboard_fallback:
            info_dict["baseboard"] = switch_baseboard_fallback
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "INFO",
                "AutoDetection",
                f"Redfish did not disambiguate switch tray baseboard, falling back to '{switch_baseboard_fallback}'",
            )

        # Check if detection was successful
        self.console.print("[green]Detection completed, processing results...[/green]")
        detection_successful = bool(
            info_dict["platform"]
            and (
                info_dict["baseboard"]
                or (_switch_detected and info_dict.get("node_type") == "SwitchTray")
            )
        )

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

        if (
            _switch_detected
            and info_dict.get("platform") == "NVSwitch"
            and info_dict.get("node_type") == "SwitchTray"
            and not info_dict.get("baseboard")
        ):
            self.console.print("[green]Auto-detection completed successfully![/green]")
            return True, info_dict

        # If detection was successful or failed, prompt user for confirmation (unless non-interactive)
        # This allows user to confirm detected values or manually select if detection failed
        try:
            return await self._finalize_detection_with_confirmation(
                dut_id, info_dict, non_interactive
            )
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
