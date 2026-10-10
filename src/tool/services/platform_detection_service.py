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
Platform Detection Service for NVDebug Tool.

Handles gathering platform information including FRU data, system
identification, and hardware configuration from DUTs for platform and baseboard
detection.
"""

import asyncio
import logging
import re
from typing import Any, Dict, Optional, Tuple

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

logger = logging.getLogger(__name__)


class PlatformDetectionService:
    """
    Service for detecting platform information from DUTs.

    The type coordinates ``_extract_first_string_field``, ``_model_is_generic``,
    ``async_init``, ``_load_platform_mappings``, and
    ``_build_platform_mappings_from_baseboards`` and retains the state those
    operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    MAX_FOLLOWED_COLLECTION_MEMBERS = min(MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS, 64)
    MAX_REDFISH_DETECTION_REQUESTS = 128
    REDFISH_DETECTION_DEADLINE_SECONDS = 30.0
    REDFISH_REQUEST_TIMEOUT_SECONDS = 10.0

    def __init__(self, dut_manager, logger, baseboard_manager=None):
        """
        Initialize the Platform Detection Service.

        The initializer records ``baseboard_manager``, ``dut_manager``,
        ``logger``, ``platform_detection_profile``, and ``platform_mappings``
        for later operations and establishes the instance invariants before any
        public method runs.

        Args:
            dut_manager: DUT manager consumed while the function attempts to
                initialize the Platform Detection Service.
            logger: Sanitized logger used for operator-visible diagnostics.
            baseboard_manager: Optional baseboard manager; ``None`` selects the
                function's default behavior.
        """
        self.dut_manager = dut_manager
        self.logger = logger
        self.baseboard_manager = baseboard_manager
        self.platform_mappings = {}  # Will be loaded in async_init()
        self.platform_detection_profile = (
            getattr(baseboard_manager, "platform_detection_profile", None)
            if baseboard_manager
            else None
        )

    @staticmethod
    def _extract_first_string_field(payload: Any, field_name: str) -> Optional[str]:
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
                found = PlatformDetectionService._extract_first_string_field(
                    nested, field_name
                )
                if found:
                    return found
        elif isinstance(payload, list):
            for item in payload:
                found = PlatformDetectionService._extract_first_string_field(
                    item, field_name
                )
                if found:
                    return found
        return None

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
        } or normalized.startswith(("$", "unknownmodel"))

    async def async_init(self):
        """
        Async initialization - load platform mappings.

        The implementation uses current instance state to async initialization -
        load platform mappings. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind. It
        updates ``platform_mappings`` on the instance as part of that state
        transition.
        """
        self.platform_mappings = await self._load_platform_mappings()

    async def _load_platform_mappings(self) -> Dict[str, Any]:
        """
        Load platform mappings from spreadsheet configuration.

        Get platform mappings from the baseboard manager (spreadsheet).

        Returns:
            A mapping containing platform mappings.
        """
        try:
            # Get platform mappings from the baseboard manager (spreadsheet)
            if self.baseboard_manager and self.baseboard_manager.baseboards:
                self.platform_detection_profile = getattr(
                    self.baseboard_manager, "platform_detection_profile", None
                )
                return self._build_platform_mappings_from_baseboards(
                    self.baseboard_manager.baseboards
                )

            # Return empty mappings if no baseboard manager or no baseboards loaded
            if self.logger:
                await self.logger.log_runtime(
                    "WARNING",
                    "PlatformDetection",
                    "No baseboard manager or baseboards available - using empty platform mappings",
                )
            return {
                "redfish_chassis_mappings": {},
                "platform_model_mappings": [],
            }

        except Exception as e:
            if self.logger:
                await self.logger.log_runtime(
                    "WARNING",
                    "PlatformDetection",
                    f"Failed to load platform mappings: {e}",
                )
            # Return empty mappings instead of default - let the system work without platform mappings
            return {
                "redfish_chassis_mappings": {},
                "platform_model_mappings": [],
            }

    def _build_platform_mappings_from_baseboards(
        self, baseboards: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build platform mappings from baseboard configurations.

        Build platform model mappings from baseboard platform_detection
        sections.

        Args:
            baseboards: Mapping supplying fields for platform mappings from
                baseboard configurations.

        Returns:
            The validated ``platform_mappings``.
        """
        platform_mappings = {
            "redfish_chassis_mappings": {},
            "platform_model_mappings": [],
        }

        # Build platform model mappings from baseboard platform_detection sections
        for baseboard_name, baseboard_config in baseboards.items():
            platform_detection = baseboard_config.get("platform_detection", {})
            if platform_detection:
                # Resolve HMC IP reference
                hmc_ip_value = platform_detection.get("hmc_ip")
                if isinstance(hmc_ip_value, str) and hmc_ip_value in {
                    "HMC_IP",
                    "HMC_HOSTNAME",
                }:
                    hmc_ip_value = baseboard_config.get(hmc_ip_value, hmc_ip_value)

                # Add to platform model mappings
                platform_mappings["platform_model_mappings"].append(
                    {
                        "models": platform_detection.get("models", []),
                        "manufacturer": platform_detection.get("manufacturer", []),
                        "node_type": platform_detection.get("node_type", "Compute"),
                        "platform": baseboard_config.get("platform", "x86_64"),
                        "baseboards": [baseboard_name],
                        "HMC_IP": hmc_ip_value,
                        "product_family": platform_detection.get("product_family"),
                    }
                )

        # Retain the data-derived compatibility map for callers that inspect it.
        redfish_chassis_mappings = {}

        # Add baseboard-specific chassis mappings based on platform_detection
        for baseboard_name, baseboard_config in baseboards.items():
            platform_detection = baseboard_config.get("platform_detection", {})
            if platform_detection:
                # Map baseboard name to its models for chassis identification
                models = platform_detection.get("models", [])
                if models:
                    # Create chassis mapping for this baseboard
                    # Use the first model as the primary identifier
                    primary_model = models[0] if models else baseboard_name
                    redfish_chassis_mappings[baseboard_name] = primary_model

                    # Also map individual models to the baseboard
                    for model in models:
                        if model and model != baseboard_name:
                            redfish_chassis_mappings[model] = baseboard_name

        platform_mappings["redfish_chassis_mappings"] = redfish_chassis_mappings

        return platform_mappings

    async def gather_platform_info(
        self, dut_id: str, preflight_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """
        Gather platform information using multiple methods.

        Attempts to gather platform info in the following order:

        1. Redfish (if preflight passed).
        2. IPMI (if preflight passed).
        3. Host (if preflight passed).

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            preflight_results: Optional preflight results; ``None`` selects the
                function's default behavior.

        Returns:
            A mapping containing gather platform info.
        """
        await self.logger.write_to_dut_runtime_log(
            dut_id,
            "INFO",
            "PlatformDetection",
            "Starting platform detection service...",
        )
        try:
            # Get preflight results for this DUT if not provided
            if preflight_results is None:
                preflight_results = await self.dut_manager.get_preflight_results(dut_id)

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "PlatformDetection",
                f"Preflight results: {preflight_results}",
            )

            # 1) Attempt Redfish if Redfish preflight is OK
            if preflight_results.get("redfish", {}).get("status") == "pass":
                try:
                    status, chassis_dict = await self._get_system_info_via_redfish(
                        dut_id
                    )
                    if status and chassis_dict:
                        model = chassis_dict.get("Model", "N/A")
                        partnumber = chassis_dict.get("PartNumber", "N/A")
                        serialnumber = chassis_dict.get("SerialNumber", "N/A")
                        # If Redfish gave us some valid model
                        if isinstance(model, str) and not self._model_is_generic(model):
                            await self.logger.write_to_dut_runtime_log(
                                dut_id,
                                "INFO",
                                "PlatformDetection",
                                f"Platform info via Redfish: Model={model}, PartNo={partnumber}, SerialNo={serialnumber}",
                            )
                            return {
                                "model": model,
                                "partnumber": partnumber,
                                "serialnumber": serialnumber,
                            }
                except Exception as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "PlatformDetection",
                        f"Redfish platform info unavailable: {str(e)}",
                    )

            # 2) If IPMI preflight is OK, fallback to IPMI
            if preflight_results.get("ipmi", {}).get("status") == "pass":
                try:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "PlatformDetection",
                        "Attempting IPMI FRU detection...",
                    )
                    ipmi_info = await self._get_platform_info_via_ipmi(dut_id)
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "DEBUG",
                        "PlatformDetection",
                        f"IPMI FRU result: {ipmi_info}",
                    )
                    if not self._model_is_generic(ipmi_info.get("model", "")):
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "PlatformDetection",
                            f"Platform info via IPMI: Model={ipmi_info['model']}, PartNo={ipmi_info['partnumber']}, SerialNo={ipmi_info['serialnumber']}",
                        )
                        return ipmi_info
                    else:
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "WARNING",
                            "PlatformDetection",
                            "IPMI FRU detection returned no model information",
                        )
                except Exception as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "PlatformDetection",
                        f"IPMI platform info unavailable: {str(e)}",
                    )

            # 3) If Host preflight is OK, fallback to Host
            if preflight_results.get("host", {}).get("status") == "pass":
                try:
                    host_info = await self._get_platform_info_via_host(dut_id)
                    if not self._model_is_generic(host_info.get("model", "")):
                        await self.logger.write_to_dut_runtime_log(
                            dut_id,
                            "INFO",
                            "PlatformDetection",
                            f"Platform info via Host: Model={host_info['model']}, PartNo={host_info['partnumber']}, SerialNo={host_info['serialnumber']}",
                        )
                        return host_info
                except Exception as e:
                    await self.logger.write_to_dut_runtime_log(
                        dut_id,
                        "WARNING",
                        "PlatformDetection",
                        f"Host platform info unavailable: {str(e)}",
                    )

            # All methods failed, return default values
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "PlatformDetection",
                "All platform detection methods failed, using default values",
            )

            return {
                "model": "Unknown",
                "partnumber": "Unknown",
                "serialnumber": "Unknown",
            }

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "ERROR",
                "PlatformDetection",
                f"Failed to gather platform info: {str(e)}",
            )
            return {
                "model": "Unknown",
                "partnumber": "Unknown",
                "serialnumber": "Unknown",
            }

    async def _get_system_info_via_redfish(
        self, dut_id: str
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Get the highest-ranked platform identity from the catalog probe plan.

        The implementation uses ``dut_id`` to get the highest-ranked platform
        identity from the catalog probe plan. Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        Remote I/O uses the configured transport policy and returns only after
        its response or failure has been observed.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A tuple containing ``outcome flag`` and ``metadata mapping`` in that
            order.
        """
        try:
            profile = self.platform_detection_profile
            if not profile:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "PlatformDetection",
                    "Catalog platform detection profile is unavailable; Redfish "
                    "platform metadata detection is disabled",
                )
                return False, None

            best_payload: Optional[Dict[str, Any]] = None
            best_score: Optional[int] = None
            best_identities = set()
            seen_uris = set()
            request_count = 0
            terminal_reason: Optional[str] = None
            loop = asyncio.get_running_loop()
            deadline = loop.time() + self.REDFISH_DETECTION_DEADLINE_SECONDS

            def response_payload(response: Any) -> Tuple[bool, Optional[Any]]:
                """
                Return the response payload.

                The implementation uses ``response`` to produce the response
                payload.

                Args:
                    response: Transport response governed by the configured
                        authentication and trust policy.

                Returns:
                    A tuple containing ``status flag`` and ``returned value`` in
                    that order.
                """
                if not isinstance(response, tuple) or len(response) < 2:
                    return False, None
                return bool(response[0]), response[1]

            async def request_payload(uri: str) -> Tuple[bool, Optional[Any]]:
                """
                Return the request payload.

                The implementation uses ``uri`` to produce the request payload.
                Owned asynchronous work is awaited before return, so completion
                does not leave an unobserved task behind.

                Args:
                    uri: Validated remote resource identifier used for URI.

                Returns:
                    A tuple containing ``success flag`` and ``absence sentinel``
                    in that order.
                """
                nonlocal request_count, terminal_reason
                if terminal_reason is not None:
                    return False, None
                if request_count >= self.MAX_REDFISH_DETECTION_REQUESTS:
                    terminal_reason = (
                        "Redfish platform-detection request budget was exhausted "
                        f"({self.MAX_REDFISH_DETECTION_REQUESTS})"
                    )
                    return False, None
                remaining = deadline - loop.time()
                if remaining <= 0:
                    terminal_reason = (
                        "Redfish platform-detection deadline was exhausted"
                    )
                    return False, None

                request_count += 1
                request_timeout = min(self.REDFISH_REQUEST_TIMEOUT_SECONDS, remaining)
                try:
                    response = await asyncio.wait_for(
                        self.dut_manager.execute_redfish_request(
                            dut_id,
                            "GET",
                            uri,
                            timeout=request_timeout,
                            expected_http_statuses=[404],
                        ),
                        timeout=remaining,
                    )
                except TimeoutError:
                    terminal_reason = (
                        "Redfish platform-detection deadline was exhausted"
                    )
                    return False, None
                return response_payload(response)

            async def consider_uri(uri: str, step: Dict[str, Any]) -> None:
                """
                Evaluate one Redfish URI as a platform-detection candidate.

                The implementation uses ``uri`` and ``step`` to evaluate one
                Redfish URI as a platform-detection candidate. Owned
                asynchronous work is awaited before return, so completion does
                not leave an unobserved task behind.

                Args:
                    uri: Validated remote resource identifier used for URI.
                    step: Mapping supplying fields for evaluate one Redfish URI
                        as a platform-detection candidate.
                """
                nonlocal best_payload, best_score, best_identities
                if uri in seen_uris:
                    return
                seen_uris.add(uri)
                success, payload = await request_payload(uri)
                if not success or not isinstance(payload, dict):
                    return
                model = self._extract_first_string_field(
                    payload, step.get("model_field", "Model")
                )
                if not model or self._model_is_generic(model):
                    return
                score = score_platform_detection_candidate(profile, uri, "model")
                if score is None:
                    return
                normalized_payload = dict(payload)
                normalized_payload["Model"] = model
                part_number = self._extract_first_string_field(
                    payload, step.get("part_number_field", "PartNumber")
                )
                serial_number = self._extract_first_string_field(
                    payload, "SerialNumber"
                )
                if part_number:
                    normalized_payload["PartNumber"] = part_number
                if serial_number:
                    normalized_payload["SerialNumber"] = serial_number
                identity = (model, part_number or "", serial_number or "")

                if best_score is None or score > best_score:
                    best_score = score
                    best_payload = normalized_payload
                    best_identities = {identity}
                elif score == best_score:
                    best_identities.add(identity)

            for index, step in enumerate(profile["probe_steps"]):
                if terminal_reason is not None:
                    break
                if "uri" in step:
                    await consider_uri(step["uri"], step)
                else:
                    success, collection_payload = await request_payload(
                        step["collection_uri"]
                    )
                    if success and isinstance(collection_payload, dict):
                        next_link = collection_payload.get(
                            "Members@odata.nextLink"
                        ) or collection_payload.get("@odata.nextLink")
                        if next_link:
                            terminal_reason = (
                                "Redfish platform-detection collection is paginated; "
                                "the complete member set was not available"
                            )
                            break
                        try:
                            members, source_member_count, members_truncated = (
                                bound_redfish_collection_members(
                                    collection_payload.get("Members"),
                                    field_name="platform detection Members",
                                    limit=self.MAX_FOLLOWED_COLLECTION_MEMBERS,
                                )
                            )
                        except ValueError:
                            terminal_reason = (
                                "Redfish platform-detection collection returned a "
                                "malformed Members value"
                            )
                            break
                        advertised_count = collection_payload.get("Members@odata.count")
                        if advertised_count is not None and (
                            isinstance(advertised_count, bool)
                            or not isinstance(advertised_count, int)
                            or advertised_count < 0
                            or advertised_count != source_member_count
                        ):
                            terminal_reason = (
                                "Redfish platform-detection collection member list "
                                "does not match Members@odata.count"
                            )
                            break
                        if members_truncated:
                            terminal_reason = (
                                "Redfish platform-detection collection returned "
                                f"{source_member_count} members; safe follow limit is "
                                f"{self.MAX_FOLLOWED_COLLECTION_MEMBERS}"
                            )
                            break

                        collection_uris: list[str] = []
                        collection_seen: set[str] = set()
                        invalid_members = 0
                        for member in members:
                            raw_uri = (
                                member.get("@odata.id")
                                if isinstance(member, dict)
                                else None
                            )
                            try:
                                uri = validate_redfish_uri_path(
                                    raw_uri,
                                    context="platform detection member URI",
                                    service_root=step["collection_uri"],
                                )
                            except (
                                RedfishTopologyProfileError,
                                TypeError,
                                ValueError,
                            ):
                                invalid_members += 1
                                continue
                            if not uri.startswith(step["member_uri_prefix"]):
                                invalid_members += 1
                                continue
                            member_id = uri[len(step["member_uri_prefix"]) :]
                            if not member_id or "/" in member_id:
                                invalid_members += 1
                                continue
                            if uri in collection_seen:
                                continue
                            collection_seen.add(uri)
                            collection_uris.append(uri)

                        if invalid_members:
                            terminal_reason = (
                                "Redfish platform-detection collection contains "
                                f"{invalid_members} invalid member URI(s)"
                            )
                            break

                        unseen_uris = [
                            uri for uri in collection_uris if uri not in seen_uris
                        ]
                        if (
                            request_count + len(unseen_uris)
                            > self.MAX_REDFISH_DETECTION_REQUESTS
                        ):
                            terminal_reason = (
                                "Redfish platform-detection request budget would be "
                                f"exceeded ({self.MAX_REDFISH_DETECTION_REQUESTS})"
                            )
                            break
                        for uri in collection_uris:
                            await consider_uri(uri, step)
                            if terminal_reason is not None:
                                break

                if best_score is not None and best_score > remaining_probe_max_score(
                    profile, index
                ):
                    break

            if terminal_reason is not None:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "PlatformDetection",
                    f"{terminal_reason}; refusing incomplete Redfish identity",
                )
                return False, None
            if len(best_identities) > 1:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "PlatformDetection",
                    "Equally ranked Redfish resources reported conflicting "
                    "model/PartNumber/SerialNumber identities; refusing "
                    "order-dependent report metadata",
                )
                return False, None
            return (best_payload is not None), best_payload

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "PlatformDetection",
                f"Error getting Redfish system info for DUT {dut_id}: {e}",
            )
            return False, None

    async def _get_platform_info_via_ipmi(self, dut_id: str) -> Dict[str, str]:
        """
        Get platform information via IPMI FRU commands.

        The implementation uses ``dut_id`` to get platform information via IPMI
        FRU commands. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing the ``model``, ``partnumber``, and
            ``serialnumber`` fields.
        """
        try:
            # Get FRU information via IPMI
            exit_code, output, stderr = await self.dut_manager.execute_ipmi_command(
                dut_id, "fru print 0"
            )

            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "DEBUG",
                "PlatformDetection",
                f"IPMI FRU command result: exit_code={exit_code}, output_length={len(output) if output else 0}",
            )

            if exit_code != 0 or not output:
                await self.logger.write_to_dut_runtime_log(
                    dut_id,
                    "WARNING",
                    "PlatformDetection",
                    f"IPMI FRU command failed: exit_code={exit_code}, output={output}, stderr={stderr}",
                )
                return {"model": "", "partnumber": "", "serialnumber": ""}

            model = None
            partno = None
            serialno = None

            # Parse FRU output using regex (from legacy code)
            match_model = re.search(r"Product\s+Name\s*:[ \t]*(.+)", output)
            if match_model:
                model = match_model.group(1).strip()

            match_part = re.search(
                r"(?m)^[ \t]*(?:Product[ \t]+)?Part[ \t]+Number[ \t]*:[ \t]*(.*)$",
                output,
            )
            if match_part:
                partno = match_part.group(1).strip()

            match_serial = re.search(
                r"(?m)^[ \t]*(?:Product[ \t]+)?Serial(?:[ \t]+Number)?[ \t]*:[ \t]*(.*)$",
                output,
            )
            if match_serial:
                serialno = match_serial.group(1).strip()

            # Return results if we found a model
            if model:
                return {
                    "model": model,
                    "partnumber": partno or "N/A",
                    "serialnumber": serialno or "N/A",
                }

            return {"model": "", "partnumber": "", "serialnumber": ""}

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "PlatformDetection",
                f"Error getting IPMI platform info: {e}",
            )
            return {"model": "", "partnumber": "", "serialnumber": ""}

    async def _get_platform_info_via_host(self, dut_id: str) -> Dict[str, str]:
        """
        Get platform information via host dmidecode commands.

        The implementation uses ``dut_id`` to get platform information via host
        dmidecode commands. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            A mapping containing platform info via host.
        """
        try:
            result = {
                "model": "N/A",
                "partnumber": "N/A",
                "serialnumber": "N/A",
            }

            # Get system product name (model)
            exit_code, output, stderr = await self.dut_manager.execute_host_command(
                dut_id, "dmidecode -s system-product-name"
            )
            if exit_code == 0 and output:
                model = output.strip()
                # Ensure single line by replacing newlines with spaces
                model = model.replace("\n", " ").replace("\r", " ").strip()
                if (
                    model
                    and model != "To be filled by O.E.M."
                    and model != "Default string"
                ):
                    result["model"] = model

            # Get system serial number
            exit_code, output, stderr = await self.dut_manager.execute_host_command(
                dut_id, "dmidecode -s system-serial-number"
            )
            if exit_code == 0 and output:
                serial = output.strip()
                # Ensure single line by replacing newlines with spaces
                serial = serial.replace("\n", " ").replace("\r", " ").strip()
                if (
                    serial
                    and serial != "To be filled by O.E.M."
                    and serial != "Default string"
                ):
                    result["serialnumber"] = serial

            # Try to get part number from baseboard
            exit_code, output, stderr = await self.dut_manager.execute_host_command(
                dut_id, "dmidecode -s baseboard-product-name"
            )
            if exit_code == 0 and output:
                partnum = output.strip()
                # Ensure single line by replacing newlines with spaces
                partnum = partnum.replace("\n", " ").replace("\r", " ").strip()
                if (
                    partnum
                    and partnum != "To be filled by O.E.M."
                    and partnum != "Default string"
                ):
                    result["partnumber"] = partnum

            return result

        except Exception as e:
            await self.logger.write_to_dut_runtime_log(
                dut_id,
                "WARNING",
                "PlatformDetection",
                f"Error getting host platform info for DUT {dut_id}: {e}",
            )
            return {"model": "", "partnumber": "", "serialnumber": ""}
