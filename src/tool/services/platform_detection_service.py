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

Handles gathering platform information including FRU data, system identification,
and hardware configuration from DUTs for platform and baseboard detection.
"""

import logging
import os
import re
from typing import Any, Dict, Optional, Tuple

import yaml

from ..utils import get_tool_resource_content
from ..utils.resources import find_config_directory

logger = logging.getLogger(__name__)


class PlatformDetectionService:
    """
    Service for detecting platform information from DUTs.
    """

    def __init__(self, dut_manager, logger, baseboard_manager=None):
        """
        Initialize the Platform Detection Service.

        Args:
            dut_manager: DUT manager instance.
            logger: Logger instance.
            baseboard_manager: Baseboard manager instance.
        """
        self.dut_manager = dut_manager
        self.logger = logger
        self.baseboard_manager = baseboard_manager
        self.platform_mappings = {}  # Will be loaded in async_init()

    async def async_init(self):
        """
        Async initialization - load platform mappings.

        Args:
            None
        """
        self.platform_mappings = await self._load_platform_mappings()

    async def _load_platform_mappings(self) -> Dict[str, Any]:
        """
        Load platform mappings from spreadsheet configuration.

        Returns:
            Dictionary of platform mappings.
        """
        try:
            # Get platform mappings from the baseboard manager (spreadsheet)
            if self.baseboard_manager and self.baseboard_manager.baseboards:
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

        Args:
            baseboards: Dictionary of baseboard configurations.
        """
        platform_mappings = {
            "redfish_chassis_mappings": {},
            "platform_model_mappings": [],
        }

        # Extract constants (from baseboards sheet if available, otherwise use defaults)
        hmc_ip = "192.168.31.1"  # Default HMC IP
        hmc_hostname = "HMC_0"  # Default HMC hostname

        # Build platform model mappings from baseboard platform_detection sections
        for baseboard_name, baseboard_config in baseboards.items():
            platform_detection = baseboard_config.get("platform_detection", {})
            if platform_detection:
                # Resolve HMC IP reference
                hmc_ip_value = platform_detection.get("hmc_ip")
                if hmc_ip_value == "HMC_IP":
                    hmc_ip_value = hmc_ip
                elif hmc_ip_value == "HMC_HOSTNAME":
                    hmc_ip_value = hmc_hostname

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

        # Build redfish chassis mappings from baseboard platform_detection sections
        redfish_chassis_mappings = {}

        # Add common chassis mappings that are used across multiple baseboards
        common_chassis = [
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

        for chassis in common_chassis:
            redfish_chassis_mappings[chassis] = chassis

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
        1. Redfish (if preflight passed)
        2. IPMI (if preflight passed)
        3. Host (if preflight passed)

        Args:
            dut_id: The DUT identifier
            preflight_results: Optional preflight results for the DUT

        Returns:
            dict: Dictionary containing platform information with keys:
                - "model": Platform model name
                - "partnumber": Part number
                - "serialnumber": Serial number
                If all methods fail, returns default values with "Unknown" model.
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
                        if model and model != "N/A":
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
                    if ipmi_info.get("model"):
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
                    if host_info.get("model"):
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
        Get system information via Redfish API with dynamic discovery.

        Args:
            dut_id: The DUT identifier

        Returns:
            tuple: (success, chassis_data)
        """
        try:
            # Get platform mappings from configuration
            platform_dict = self.platform_mappings.get("redfish_chassis_mappings", {})

            # First try DGX chassis - use shorter timeout for platform detection
            success, response, _, _ = await self.dut_manager.execute_redfish_request(
                dut_id, "GET", "/redfish/v1/Chassis/DGX", timeout=10
            )

            if success and response:
                return True, response

            # If DGX fails, discover available chassis - use shorter timeout for platform detection
            success, chassis_list_response, _, _ = (
                await self.dut_manager.execute_redfish_request(
                    dut_id, "GET", "/redfish/v1/Chassis/", timeout=10
                )
            )

            if not success or not chassis_list_response:
                return False, None

            # Extract chassis names
            members = chassis_list_response.get("Members", [])
            chassis_list = []
            for member in members:
                odata_id = member.get("@odata.id", "")
                if odata_id:
                    chassis_name = odata_id.split("/")[-1]
                    chassis_list.append(chassis_name)

            # Try each known chassis
            for chassis in chassis_list:
                if chassis in platform_dict:
                    success, response, _, _ = (
                        await self.dut_manager.execute_redfish_request(
                            dut_id,
                            "GET",
                            f"/redfish/v1/Chassis/{chassis}",
                            timeout=10,
                        )
                    )
                    if success and response:
                        model = response.get("Model")
                        if model and not model.startswith("$"):
                            return True, response
                        elif model and model.startswith("$"):
                            # Use mapped platform name
                            response["Model"] = platform_dict[chassis]
                            return True, response

            # Fallback to BMC_0 - use shorter timeout for platform detection
            success, response, _, _ = await self.dut_manager.execute_redfish_request(
                dut_id, "GET", "/redfish/v1/Chassis/BMC_0", timeout=10
            )

            if success and response:
                model = response.get("Model")
                if model:
                    # Check if we can map it to a known platform
                    for platform, model_name in platform_dict.items():
                        platform_name = platform.partition("_Management_Board")[0]
                        if platform_name in model:
                            response["Model"] = model_name
                            break
                    return True, response

            return False, None

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

        Args:
            dut_id: The DUT identifier

        Returns:
            dict: Platform information
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

            # Parse FRU output using regex
            match_model = re.search(r"Product\s+Name\s*:\s*(.+)", output)
            if match_model:
                model = match_model.group(1).strip()

            match_part = re.search(r"Part\s+Number\s*:\s*(.+)", output)
            if match_part:
                partno = match_part.group(1).strip()

            match_serial = re.search(r"Serial\s+Number\s*:\s*(.+)", output)
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

        Args:
            dut_id: The DUT identifier

        Returns:
            dict: Platform information
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
