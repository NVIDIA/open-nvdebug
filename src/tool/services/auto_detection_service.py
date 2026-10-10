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
from ..utils.platform_detection_profile import (
    remaining_probe_max_score,
    score_platform_detection_candidate,
)
from ..utils.redfish_limits import (
    MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS,
    bound_redfish_collection_members,
)
from ..utils.redfish_topology_profile import (
    RedfishTopologyProfileError,
    validate_redfish_uri_path,
)
from ..utils.sanitizer import neutralize_terminal_text

logger = logging.getLogger(__name__)


class AutoDetectionService:
    """
    Service for detecting platform and baseboard types from DUTs.

    Builds platform-baseboard mapping from spreadsheet configuration.
    """

    MAX_FOLLOWED_COLLECTION_MEMBERS = MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS

    def __init__(self, dut_manager, logger, sanitized_console=None):
        """
        Initialize the AutoDetectionService.

        The initializer records ``console``, ``dut_manager``, ``logger``,
        ``platform_detection_profile``, and ``platform_mappings`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            dut_manager: DUT manager consumed while the function attempts to
                initialize the AutoDetectionService.
            logger: Sanitized logger used for operator-visible diagnostics.
            sanitized_console: Optional sanitized console; ``None`` selects the
                function's default behavior.
        """
        self.dut_manager = dut_manager
        self.logger = logger
        self.console = (
            sanitized_console.console
            if sanitized_console
            else create_sanitized_console()
        )
        self.platform_mappings = []  # Will be populated in async_init
        self.platform_detection_profile: Optional[Dict[str, Any]] = None
        self.reserved_model_patterns: List[str] = []

    @staticmethod
    def _identity_is_present(value: Any) -> bool:
        """
        Return the identity is present.

        The implementation uses ``value`` to produce the identity is present.

        Args:
            value: Value object whose ``strip`` state is read while performing
                identity is present.

        Returns:
            Whether the identity is present operation succeeds.
        """
        if not isinstance(value, str):
            return False
        normalized = value.strip()
        return normalized not in ("", "$", "null", "NULL")

    @staticmethod
    def _model_is_generic(model: str) -> bool:
        """
        Return the model is generic.

        The implementation uses ``model`` to produce the model is generic.

        Args:
            model: Text supplied as model in the format accepted by this
                function.

        Returns:
            Whether the model is generic operation succeeds.
        """
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
        """
        Extract first string field.

        The implementation uses ``payload`` and ``field_name`` to extract first
        string field.

        Args:
            payload: Payload object whose ``get`` and ``values`` state is read
                while performing extract first string field.
            field_name: Field label included in validation failures for the
                selected input.

        Returns:
            The canonical first string field text, or ``None`` when the
            requested value is unavailable.
        """
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

    def _candidate_score(self, uri: str, signal: str) -> Optional[int]:
        """
        Return the candidate score.

        After applying local validation, the function forwards ``uri`` and
        ``signal`` to ``score_platform_detection_candidate`` and preserves its
        return and exception contract.

        Args:
            uri: Validated remote resource identifier used for URI.
            signal: Text supplied as signal in the format accepted by this
                function.

        Returns:
            The numeric candidate score value, or ``None`` when the requested
            value is unavailable.
        """
        return score_platform_detection_candidate(
            self.platform_detection_profile, uri, signal
        )

    @staticmethod
    def _extract_redfish_success_payload(
        response: Any,
    ) -> Tuple[bool, Optional[Any]]:
        """
        Extract Redfish success payload.

        The implementation uses ``response`` to extract Redfish success payload.

        Args:
            response: Transport response governed by the configured
                authentication and trust policy.

        Returns:
            A tuple containing ``success flag`` and ``absence sentinel`` in that
            order.
        """
        if not isinstance(response, tuple) or len(response) < 2:
            return False, None
        success = response[0]
        payload = response[1]
        return (success, payload) if isinstance(success, bool) else (False, None)

    @staticmethod
    def _mapping_specificity(
        mapping: Dict[str, Any], pattern: str, value: str
    ) -> Tuple[int, int]:
        """
        Rank evidence-backed specificity without using catalog order.

        Order, highest first:

        1. Baseboard name appears as a case-insensitive substring of the
           observed value (e.g. model "MGX-GH200 System" contains the baseboard
           name "MGX-GH200"). This is a strong signal the mapping is the
           intended target.
        2. Longer matching pattern (a broad ".*GH200.*" loses to a more specific
           ".*GH200-NVL2.*").

        Baseboard-name length is deliberately not a tie-breaker: shared board
        codes such as P2312 must remain ambiguous unless the observed identity
        itself distinguishes their owners.

        Args:
            mapping: Mapping supplying fields for rank evidence-backed
                specificity without using catalog order.
            pattern: Text supplied as pattern in the format accepted by this
                function.
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            A tuple containing ``name in value`` and ``len`` in that order.
        """
        baseboard_name = (mapping.get("baseboards") or [""])[0] or ""
        value_lower = (value or "").lower()
        name_lower = baseboard_name.lower()
        name_in_value = 1 if name_lower and name_lower in value_lower else 0
        return (name_in_value, len(pattern or ""))

    async def _select_unambiguous_mapping_hit(
        self,
        dut_id: str,
        identity_name: str,
        value: str,
        hits: List[Tuple[Dict[str, Any], str]],
    ) -> Optional[Tuple[Dict[str, Any], str]]:
        """
        Return the uniquely best mapping, or fail closed on an evidence tie.

        The implementation uses ``dut_id``, ``identity_name``, ``value``, and
        ``hits`` to produce the uniquely best mapping, or fail closed on an
        evidence tie. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            identity_name: Stable identity name used for lookup and
                operator-facing diagnostics.
            value: Text supplied as value in the format accepted by this
                function.
            hits: Mapping supplying fields for uniquely best mapping, or fail
                closed on an evidence tie.

        Returns:
            A tuple containing the fields that represent unambiguous mapping
            hit, or ``None`` when the requested value is unavailable.
        """

        if not hits:
            return None
        ranked = [
            (
                self._mapping_specificity(mapping, pattern, value),
                mapping,
                pattern,
            )
            for mapping, pattern in hits
        ]
        best_rank = max(rank for rank, _, _ in ranked)
        best_hits = [
            (mapping, pattern) for rank, mapping, pattern in ranked if rank == best_rank
        ]
        owners = {
            str((mapping.get("baseboards") or [""])[0]) for mapping, _ in best_hits
        }
        owners.discard("")
        if len(owners) != 1:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "AutoDetection",
                f"{identity_name} {value!r} matches equally specific catalog "
                "baseboards; refusing order-dependent auto-detection: "
                + ", ".join(sorted(owners or {"<unmapped>"})),
            )
            return None
        return sorted(best_hits, key=lambda item: item[1])[0]

    async def try_manufacturer_matching(
        self, dut_id: str, manufacturer: str, info_dict: Dict[str, Any]
    ) -> bool:
        """
        Return the try manufacturer matching.

        The implementation uses ``dut_id``, ``manufacturer``, and ``info_dict``
        to produce the try manufacturer matching. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            manufacturer: Text supplied as manufacturer in the format accepted
                by this function.
            info_dict: Mapping supplying fields for try manufacturer matching.

        Returns:
            Whether the try manufacturer matching operation succeeds.
        """
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
            selected = await self._select_unambiguous_mapping_hit(
                dut_id, "Manufacturer", manufacturer, exact_matches
            )
            if selected is None:
                return False
            best_mapping, best_pattern = selected
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

        selected = await self._select_unambiguous_mapping_hit(
            dut_id, "Manufacturer", manufacturer, valid_regex_hits
        )
        if selected is None:
            return False
        best_mapping, best_pattern = selected
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
        self,
        dut_id: str,
        uri: str,
        payload: Dict[str, Any],
        *,
        model_field: str = "Model",
        manufacturer_field: str = "Manufacturer",
        part_number_field: str = "PartNumber",
    ) -> Optional[Dict[str, Any]]:
        """
        Return the evaluate Redfish candidate.

        The implementation uses ``dut_id``, ``uri``, ``payload``,
        ``model_field``, and ``manufacturer_field`` to produce the evaluate
        Redfish candidate. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            uri: Validated remote resource identifier used for URI.
            payload: Mapping supplying fields for evaluate Redfish candidate.
            model_field: Text supplied as model field in the format accepted by
                this function.
            manufacturer_field: Text supplied as manufacturer field in the
                format accepted by this function.
            part_number_field: Text supplied as part number field in the format
                accepted by this function.

        Returns:
            A mapping containing the ``uri``, ``signal``, ``score``,
            ``platform``, and ``baseboard`` fields.
        """
        model = self._extract_first_string_field(payload, model_field)
        manufacturer = self._extract_first_string_field(payload, manufacturer_field)
        part_number = self._extract_first_string_field(payload, part_number_field)

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

        score = self._candidate_score(uri, signal)
        if score is None:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "AutoDetection",
                f"Catalog platform detection profile has no score for {uri}",
            )
            return None

        return {
            "uri": uri,
            "signal": signal,
            "score": score,
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
        """
        Select best Redfish candidate.

        The implementation uses ``dut_id`` to select best Redfish candidate.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``best_candidate``, or ``None`` when no value
            qualifies.
        """
        profile = self.platform_detection_profile
        if not profile:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "AutoDetection",
                "Catalog platform detection profile is unavailable; Redfish "
                "auto-detection is disabled",
            )
            return None

        best_candidate: Optional[Dict[str, Any]] = None
        equally_ranked_baseboards = set()
        seen_uris = set()

        async def consider_uri(uri: str, step: Dict[str, Any]) -> None:
            """
            Evaluate one Redfish URI as a platform-detection candidate.

            The implementation uses ``uri`` and ``step`` to evaluate one Redfish
            URI as a platform-detection candidate. Owned asynchronous work is
            awaited before return, so completion does not leave an unobserved
            task behind.

            Args:
                uri: Validated remote resource identifier used for URI.
                step: Mapping supplying fields for evaluate one Redfish URI as a
                    platform-detection candidate.
            """
            nonlocal best_candidate, equally_ranked_baseboards
            if uri in seen_uris:
                return
            seen_uris.add(uri)

            success, payload = self._extract_redfish_success_payload(
                await self.dut_manager.execute_redfish_request(
                    dut_id,
                    "GET",
                    uri,
                    expected_http_statuses=[404],
                )
            )
            if not success or not payload:
                return

            candidate = await self._evaluate_redfish_candidate(
                dut_id,
                uri,
                payload,
                model_field=step.get("model_field", "Model"),
                manufacturer_field=step.get("manufacturer_field", "Manufacturer"),
                part_number_field=step.get("part_number_field", "PartNumber"),
            )
            if candidate is None:
                return
            if best_candidate is None or candidate["score"] > best_candidate["score"]:
                best_candidate = candidate
                equally_ranked_baseboards = {candidate["baseboard"]}
            elif candidate["score"] == best_candidate["score"]:
                equally_ranked_baseboards.add(candidate["baseboard"])

        for index, step in enumerate(profile["probe_steps"]):
            if "uri" in step:
                await consider_uri(step["uri"], step)
            else:
                success, collection_payload = self._extract_redfish_success_payload(
                    await self.dut_manager.execute_redfish_request(
                        dut_id,
                        "GET",
                        step["collection_uri"],
                        expected_http_statuses=[404],
                    )
                )
                if success and isinstance(collection_payload, dict):
                    try:
                        members, source_member_count, members_truncated = (
                            bound_redfish_collection_members(
                                collection_payload.get("Members", []),
                                field_name="platform detection Members",
                                limit=self.MAX_FOLLOWED_COLLECTION_MEMBERS,
                            )
                        )
                    except ValueError:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "AutoDetection",
                            "Ignoring malformed Redfish platform-detection collection",
                        )
                        continue
                    if members_truncated:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "AutoDetection",
                            "Refusing order-dependent platform detection from a "
                            f"collection with {source_member_count} members; safe "
                            f"follow limit is {self.MAX_FOLLOWED_COLLECTION_MEMBERS}",
                        )
                        continue
                    for member in members:
                        uri = (
                            member.get("@odata.id")
                            if isinstance(member, dict)
                            else None
                        )
                        try:
                            uri = validate_redfish_uri_path(
                                uri,
                                context="platform detection member URI",
                                service_root=step["collection_uri"],
                            )
                        except (
                            RedfishTopologyProfileError,
                            TypeError,
                            ValueError,
                        ):
                            continue
                        if not uri.startswith(step["member_uri_prefix"]):
                            continue
                        member_id = uri[len(step["member_uri_prefix"]) :]
                        if not member_id or "/" in member_id:
                            continue
                        await consider_uri(uri, step)

            remaining_max = remaining_probe_max_score(profile, index)
            if (
                best_candidate is not None
                # An equally ranked later identity could expose a conflict. Stop
                # only when no remaining probe can equal or improve the winner.
                and best_candidate["score"] > remaining_max
            ):
                break

        if len(equally_ranked_baseboards) > 1:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "AutoDetection",
                "Equally ranked Redfish identities resolved to conflicting "
                "baseboards; refusing order-dependent auto-detection: "
                + ", ".join(sorted(str(item) for item in equally_ranked_baseboards)),
            )
            return None
        return best_candidate

    async def async_init(self):
        """
        Async initialization to build platform mappings.

        The implementation uses current instance state to async initialization
        to build platform mappings. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind. It
        updates ``platform_mappings`` on the instance as part of that state
        transition.
        """
        self.platform_mappings = await self._build_platform_mappings_from_spreadsheet()

    async def _build_platform_mappings_from_spreadsheet(
        self,
    ) -> List[Dict[str, Any]]:
        """
        Build platform mappings from spreadsheet.

        Get platform mappings from the baseboard manager (spreadsheet).

        Returns:
            The platform mappings from spreadsheet returned in operation-defined
            order.
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

            self.platform_detection_profile = getattr(
                baseboard_manager, "platform_detection_profile", None
            )
            if not self.platform_detection_profile:
                await self.logger.log_runtime(
                    "WARNING",
                    "AutoDetectionService",
                    "Catalog platform detection profile is unavailable; Redfish "
                    "auto-detection will fail closed",
                )

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

        The implementation uses ``baseboards`` to convert baseboard
        configurations to legacy mapping format. The source value keeps its
        ownership while the normalized representation is returned separately. It
        updates ``reserved_model_patterns`` on the instance as part of that
        state transition.

        Args:
            baseboards: Mapping supplying fields for baseboard configurations to
                legacy mapping format.

        Returns:
            The validated ``mappings``.
        """
        mappings = []
        self.reserved_model_patterns = []

        for baseboard_name, baseboard_config in baseboards.items():
            platform_detection = baseboard_config.get("platform_detection", {})
            if platform_detection:
                for pattern in (
                    platform_detection.get("reserved_model_patterns", []) or []
                ):
                    pattern_text = str(pattern).strip()
                    if (
                        pattern_text
                        and pattern_text not in self.reserved_model_patterns
                    ):
                        self.reserved_model_patterns.append(pattern_text)
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

        Sort by platform, then by baseboard for consistent display.

        Returns:
            The validated ``combinations``.
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

        The implementation uses current instance state to display manual
        selection prompt using Rich console. If the function cannot display
        manual selection prompt using Rich console, its exception reaches the
        caller instead of being converted into a successful result.

        Returns:
            A tuple containing ``selected platform`` and ``selected baseboard``
            in that order.

        Raises:
            ValueError: If no platform-baseboard combinations available.
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
                f"[bold]{neutralize_terminal_text(platform.upper())} PLATFORM:[/bold]",
                "",
                "",
                style="bold",
            )

            for baseboard, node_type in platform_groups[platform]:
                # table.add_row(f"  {option_number}", platform, baseboard, node_type)
                table.add_row(
                    f"  {option_number}",
                    neutralize_terminal_text(baseboard),
                    neutralize_terminal_text(node_type),
                )
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
                            Text.from_markup(
                                "[green]✓ Selected: "
                                f"{neutralize_terminal_text(selected_platform)} - "
                                f"{neutralize_terminal_text(selected_baseboard)}[/green]"
                            )
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
            detected_platform: Text supplied as detected platform in the format
                accepted by this function.
            detected_baseboard: Text supplied as detected baseboard in the
                format accepted by this function.
            detected_node_type: Text supplied as detected node type in the
                format accepted by this function.
            non_interactive: Whether non interactive is enabled or required for
                this operation.

        Returns:
            A tuple containing ``detected platform`` and ``detected baseboard``
            in that order.

        Raises:
            ValueError: If baseboard detection failed in non-interactive mode.
        """
        # Check if detection was successful (we primarily care about baseboard)
        detection_successful = detected_baseboard is not None

        if detection_successful:
            # Create detection results panel
            detection_text = Text()
            detection_text.append("Detection Results\n", style="bold")
            # detection_text.append(f"Platform:     {detected_platform}\n")
            detection_text.append_text(
                Text.from_markup(
                    f"Baseboard:    {neutralize_terminal_text(detected_baseboard)}\n"
                )
            )
            if detected_node_type:
                detection_text.append_text(
                    Text.from_markup(
                        f"Node Type:    {neutralize_terminal_text(detected_node_type)}"
                    )
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
                detection_text.append_text(
                    Text.from_markup(
                        "Partially detected baseboard: "
                        f"{neutralize_terminal_text(detected_baseboard)}\n"
                    )
                )
            else:
                detection_text.append("Baseboard detection failed\n")

            if detected_platform:
                detection_text.append_text(
                    Text.from_markup(
                        "Derived platform: "
                        f"{neutralize_terminal_text(detected_platform)}\n"
                    )
                )
            if detected_node_type:
                detection_text.append_text(
                    Text.from_markup(
                        "Derived node type: "
                        f"{neutralize_terminal_text(detected_node_type)}"
                    )
                )

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
        """
        Finalize detection with confirmation.

        The implementation uses ``dut_id``, ``info_dict``, and
        ``non_interactive`` to finalize detection with confirmation. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            info_dict: Mapping supplying fields for finalize detection with
                confirmation.
            non_interactive: Whether non interactive is enabled or required for
                this operation.

        Returns:
            A tuple containing ``success flag`` and ``info dict`` in that order.
        """
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
                if confirmed_platform == mapping[
                    "platform"
                ] and confirmed_baseboard in mapping.get("baseboards", []):
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

        The implementation uses ``dut_id``, ``platform``, ``baseboard``,
        ``node_type``, and ``manufacturer`` to validate against platform
        mappings. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path. Owned asynchronous work is awaited before return, so completion
        does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            platform: Optional platform; ``None`` selects the function's default
                behavior.
            baseboard: Optional baseboard; ``None`` selects the function's
                default behavior.
            node_type: Optional node type; ``None`` selects the function's
                default behavior.
            manufacturer: Optional manufacturer; ``None`` selects the function's
                default behavior.

        Returns:
            The uniquely applicable ``mapping``, or ``None`` when no mapping
            matches or the supplied evidence leaves multiple baseboards.
        """
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AutoDetection",
            f"Validating against mappings: platform={platform}, node_type={node_type}, manufacturer={manufacturer}",
        )
        matching_mappings: List[Dict[str, Any]] = []
        for mapping in self.platform_mappings:
            # Check if all provided values match the mapping
            if platform and mapping["platform"] != platform:
                continue
            if baseboard and baseboard not in mapping.get("baseboards", []):
                continue
            if node_type and mapping["node_type"] != node_type:
                continue
            if manufacturer and manufacturer not in mapping["manufacturer"]:
                continue
            matching_mappings.append(mapping)

        candidate_baseboards = {
            candidate
            for mapping in matching_mappings
            for candidate in mapping.get("baseboards", [])
            if candidate
        }
        if len(candidate_baseboards) > 1:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "AutoDetection",
                "Mapping criteria matched multiple baseboards; refusing to select "
                f"one by catalog order: {sorted(candidate_baseboards)}",
            )
            return None

        if matching_mappings:
            mapping = matching_mappings[0]
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "AutoDetection",
                f"Found unambiguous matching mapping: {mapping}",
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

        Phase 1 finds literal exact matches; Phase 2 finds regex matches. When
        multiple mappings match the same model, the most specific evidence wins.
        Equally specific mappings for different baseboards are rejected rather
        than being resolved by catalog order or name length.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            model: Text supplied as model in the format accepted by this
                function.
            info_dict: Mapping supplying fields for try to match a model against
                the platform mapping.

        Returns:
            Whether the try to match a model against the platform mapping
            operation succeeds.
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
            if not mapping["models"]:
                continue
            for model_pattern in mapping["models"]:
                if not model_pattern:
                    continue
                if model_pattern == model:
                    exact_hits.append((mapping, model_pattern))

        if exact_hits:
            selected = await self._select_unambiguous_mapping_hit(
                dut_id, "Model", model, exact_hits
            )
            if selected is None:
                return False
            best_mapping, best_pattern = selected
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

        for reserved_pattern in self.reserved_model_patterns:
            try:
                reserved_match = re.search(reserved_pattern, model, re.IGNORECASE)
            except re.error as error:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "AutoDetection",
                    f"Invalid reserved model regex {reserved_pattern!r}: {error}",
                )
                continue
            if reserved_match:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "AutoDetection",
                    f"Model {model!r} is reserved by catalog metadata and has no "
                    "exact enabled identity; refusing a broad regex match",
                )
                return False

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

        selected = await self._select_unambiguous_mapping_hit(
            dut_id, "Model", model, regex_hits
        )
        if selected is None:
            return False
        best_mapping, best_pattern = selected
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
        Return the try part number matching.

        The implementation uses ``dut_id``, ``part_number``, and ``info_dict``
        to produce the try part number matching. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            part_number: Text supplied as part number in the format accepted by
                this function.
            info_dict: Mapping supplying fields for try part number matching.

        Returns:
            Whether the try part number matching operation succeeds.
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
            selected = await self._select_unambiguous_mapping_hit(
                dut_id, "PartNumber", part_number, exact_hits
            )
            if selected is None:
                return False
            best_mapping, best_pattern = selected
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

        selected = await self._select_unambiguous_mapping_hit(
            dut_id, "PartNumber", part_number, regex_hits
        )
        if selected is None:
            return False
        best_mapping, best_pattern = selected
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

        The implementation uses ``dut_id``, ``preflight_results``, and
        ``non_interactive`` to detect platform and baseboard type from the DUT.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.
            non_interactive: Whether non interactive is enabled or required for
                this operation.

        Returns:
            A tuple containing ``success flag`` and ``info dict`` in that order.
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

        # Callers may provide either the service map directly or the complete
        # per-DUT preflight record returned by DUTManager. Normalize both forms
        # here so every auto-detection entry point follows the same transport
        # gating rules.
        preflight_was_provided = bool(preflight_results)
        preflight_results = preflight_results or {}
        nested_service_results = preflight_results.get("services")
        service_preflight_results = (
            nested_service_results
            if isinstance(nested_service_results, dict)
            else preflight_results
        )

        host_preflight_status = service_preflight_results.get("host", {}).get("status")
        host_preflight_passed = host_preflight_status == "pass"
        redfish_preflight_status = service_preflight_results.get("redfish", {}).get(
            "status"
        )
        redfish_preflight_passed = redfish_preflight_status == "pass"

        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "DEBUG",
            "AutoDetection",
            "Preflight status - "
            f"Host: {host_preflight_status or 'not assigned'}, "
            f"Redfish: {redfish_preflight_status or 'not assigned'}",
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
            host_fallback_allowed = not preflight_was_provided or host_preflight_passed
            if host_fallback_allowed:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "DEBUG",
                    "AutoDetection",
                    "Attempting host-based fallback detection",
                )
            else:
                host_reason = (
                    f"preflight status is '{host_preflight_status}'"
                    if host_preflight_status
                    else "no Host transport was assigned"
                )
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "INFO",
                    "AutoDetection",
                    "Skipping host-based fallback detection because " + host_reason,
                )

            try:
                if host_fallback_allowed:
                    exit_code, output, stderr = (
                        await self.dut_manager.execute_host_command(dut_id, "which nv")
                    )
                else:
                    exit_code, output, stderr = 1, "", ""
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
                    elif len(switch_mappings) > 1:
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
            if host_fallback_allowed and not _switch_detected:
                try:
                    exit_code, output, stderr = (
                        await self.dut_manager.execute_host_command(dut_id, "uname -m")
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
                            dut_id,
                            platform=info_dict["platform"],
                            node_type="Compute",
                        )
                        if mapping and mapping.get("baseboards"):
                            info_dict["baseboard"] = mapping["baseboards"][0]
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "DEBUG",
                                "AutoDetection",
                                "Set baseboard from unambiguous mapping: "
                                f"{info_dict['baseboard']}",
                            )

                        # Strong model evidence can resolve an architecture that
                        # maps to multiple baseboards, so always run the DMI probe.
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
                                                dut_id,
                                                detected_baseboard,
                                                info_dict,
                                            ):
                                                await self.logger.write_to_dut_runtime_log(
                                                    dut_id,
                                                    "INFO",
                                                    "AutoDetection",
                                                    f"Successfully matched model '{detected_baseboard}' to platform '{info_dict['platform']}' and baseboard '{info_dict['baseboard']}'",
                                                )
                                                # Don't return here - let it flow to confirmation prompt
                                            elif info_dict.get("baseboard"):
                                                await self.logger.write_to_dut_runtime_log(
                                                    dut_id,
                                                    "INFO",
                                                    "AutoDetection",
                                                    f"Model '{detected_baseboard}' didn't match specific patterns, but using unambiguous baseboard from platform mapping: '{info_dict['baseboard']}'",
                                                )
                                                # Don't return here - let it flow to confirmation prompt
                                            else:
                                                await self.logger.write_to_dut_runtime_log(
                                                    dut_id,
                                                    "WARNING",
                                                    "AutoDetection",
                                                    f"Model '{detected_baseboard}' did not match a specific pattern and architecture-only evidence is ambiguous",
                                                )
                        except Exception as e:
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "WARNING",
                                "AutoDetection",
                                f"Error detecting compute baseboard: {e}",
                            )
                            if info_dict.get("baseboard"):
                                await self.logger.write_to_dut_runtime_log(
                                    dut_id,
                                    "INFO",
                                    "AutoDetection",
                                    "Using unambiguous baseboard from platform mapping "
                                    f"despite dmidecode error: '{info_dict['baseboard']}'",
                                )
                                # Don't return here - let it flow to confirmation prompt
                except Exception as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "AutoDetection",
                        f"Error detecting CPU architecture: {e}",
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
