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
Health Check Service - Handles all Health Check-related collector operations.

Provides health monitoring and diagnostic checks for DUT systems including
system status, component health, and error detection.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from .base_service import BaseService

logger = logging.getLogger(__name__)


class HealthCheckService(BaseService):
    """
    Service for Health Check operations.

    Provides health monitoring and diagnostic checks for DUT systems including
    system status, component health, and error detection.
    """

    def __init__(self, service_name: str, orchestrator: Any) -> None:
        """
        Initialize the Health Check service.

        Args:
            service_name: Name of the service.
            orchestrator: Orchestrator instance.
        """
        super().__init__(service_name, orchestrator)

    async def validate_connection(self, dut_id: str) -> Tuple[bool, str]:
        """
        Validate health check connection (always returns True for health checks).

        Args:
            dut_id: DUT ID.
        """
        return True, "Health check validation passed"

    # Validation methods
    async def _validate_health_check_environment(
        self, dut_id: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Validate that health check environment is ready.

        Args:
            dut_id: DUT ID.
        """
        return await self._create_standardized_collector_result(
            successful_operations=1,
            total_operations=1,
            output_files=[],
            error_messages=[],
            operation_name="health_check_validation",
            additional_context={
                "reason": "Health check environment ready",
                "health_check_ready": True,
            },
        )

    async def _validate_health_check_ready(
        self, dut_id: str, **kwargs
    ) -> Dict[str, Any]:
        """
        Validate that health check is ready to run.

        Args:
            dut_id: DUT ID.
        """
        return await self._create_standardized_collector_result(
            successful_operations=1,
            total_operations=1,
            output_files=[],
            error_messages=[],
            operation_name="health_check_validation",
            additional_context={
                "reason": "Health check ready",
                "health_check_ready": True,
            },
        )

    # Execution methods
    async def run_health_check(self, dut_id: str, **kwargs) -> Dict[str, Any]:
        """
        Run comprehensive health check.

        Args:
            dut_id: DUT ID.
            **kwargs: Additional keyword arguments.
        """
        await self._log_runtime(
            "INFO", "HealthCheckService", "Starting comprehensive health check", dut_id
        )
        try:
            output_files = []
            health_results = {}

            # Check Redfish health
            redfish_health = await self._check_redfish_health(dut_id)
            health_results["redfish"] = redfish_health

            # Check IPMI health
            ipmi_health = await self._check_ipmi_health(dut_id)
            health_results["ipmi"] = ipmi_health

            # Check SSH health
            ssh_health = await self._check_ssh_health(dut_id)
            health_results["ssh"] = ssh_health

            # Check Host health
            host_health = await self._check_host_health(dut_id)
            health_results["host"] = host_health

            # Determine overall health
            overall_health = self._determine_overall_health(health_results)

            # Save health check results
            health_data = {
                "dut_id": dut_id,
                "timestamp": str(asyncio.get_event_loop().time()),
                "overall_health": overall_health,
                "service_health": health_results,
            }

            file_path = await self._save_data_with_common_pattern(
                dut_id,
                health_data,
                kwargs.get("function_tag", "health_check"),
                output_pattern=f"HealthCheck_C1_out_of_band_health_check.json",
                collector_id=kwargs.get("collector_id", "C1"),
            )
            if file_path:
                output_files.append(file_path)

            return await self._create_standardized_collector_result(
                successful_operations=1,
                total_operations=1,
                output_files=output_files,
                error_messages=[],
                operation_name="health_check",
                additional_context={
                    "overall_health": overall_health,
                    "services_checked": list(health_results.keys()),
                    "dut_id": dut_id,
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="health_check",
                additional_context={},
                dut_id=dut_id,
                collector_id="health_check",
            )

    async def _check_redfish_health(self, dut_id: str) -> Dict[str, Any]:
        """
        Check Redfish service health.

        Args:
            dut_id: DUT ID.
        """
        try:
            # Test Redfish connection
            success, message = await self.dut_manager.get_dut(
                dut_id
            ).test_redfish_connection()

            if not success:
                return {
                    "status": "unhealthy",
                    "reason": message,
                    "details": {"connection_failed": True},
                }

            # Test basic Redfish operations
            success, response, _, _ = await self.dut_manager.execute_redfish_request(
                dut_id, "GET", "/redfish/v1/"
            )

            if not success:
                return {
                    "status": "unhealthy",
                    "reason": f"Redfish root access failed: {response}",
                    "details": {"root_access_failed": True},
                }

            # Check for basic Redfish resources
            resources = ["Systems", "Managers", "Chassis"]
            available_resources = []

            for resource in resources:
                success, _, _, _ = await self.dut_manager.execute_redfish_request(
                    dut_id, "GET", f"/redfish/v1/{resource}"
                )
                if success:
                    available_resources.append(resource)

            return {
                "status": "healthy",
                "reason": "Redfish service operational",
                "details": {
                    "available_resources": available_resources,
                    "total_resources": len(resources),
                },
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "reason": str(e),
                "details": {"exception": True},
            }

    async def _check_ipmi_health(self, dut_id: str) -> Dict[str, Any]:
        """
        Check IPMI service health.

        Args:
            dut_id: DUT ID.
        """
        try:
            # Test IPMI connection
            success, message = await self.dut_manager.get_dut(
                dut_id
            ).test_ipmi_connection()

            if not success:
                return {
                    "status": "unhealthy",
                    "reason": message,
                    "details": {"connection_failed": True},
                }

            # Test basic IPMI command
            exit_code, stdout, stderr = await self.dut_manager.execute_ipmi_command(
                dut_id, "mc info"
            )

            if exit_code != 0:
                return {
                    "status": "unhealthy",
                    "reason": f"IPMI mc info failed: {stderr or stdout}",
                    "details": {"mc_info_failed": True},
                }

            return {
                "status": "healthy",
                "reason": "IPMI service operational",
                "details": {"mc_info_successful": True},
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "reason": str(e),
                "details": {"exception": True},
            }

    async def _check_ssh_health(self, dut_id: str) -> Dict[str, Any]:
        """
        Check SSH service health.

        Args:
            dut_id: DUT ID.
        """
        try:
            # Test SSH connection
            success, message = await self.dut_manager.get_dut(
                dut_id
            ).test_ssh_connection()

            if not success:
                return {
                    "status": "unhealthy",
                    "reason": message,
                    "details": {"connection_failed": True},
                }

            # Test basic SSH command
            exit_code, stdout, stderr = await self.dut_manager.execute_bmc_command(
                dut_id, "echo 'SSH test'"
            )

            if exit_code != 0:
                return {
                    "status": "unhealthy",
                    "reason": f"SSH echo test failed: {stderr or stdout}",
                    "details": {"echo_test_failed": True},
                }

            return {
                "status": "healthy",
                "reason": "SSH service operational",
                "details": {"echo_test_successful": True},
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "reason": str(e),
                "details": {"exception": True},
            }

    async def _check_host_health(self, dut_id: str) -> Dict[str, Any]:
        """
        Check Host service health.

        Args:
            dut_id: DUT ID.
        """
        try:
            # Test Host connection
            success, message = await self.dut_manager.get_dut(
                dut_id
            ).test_host_connection()

            if not success:
                return {
                    "status": "unhealthy",
                    "reason": message,
                    "details": {"connection_failed": True},
                }

            # Test basic host command
            exit_code, stdout, stderr = await self.dut_manager.execute_host_command(
                dut_id, "echo 'Host test'"
            )

            if exit_code != 0:
                return {
                    "status": "unhealthy",
                    "reason": f"Host echo test failed: {stderr or stdout}",
                    "details": {"echo_test_failed": True},
                }

            return {
                "status": "healthy",
                "reason": "Host service operational",
                "details": {"echo_test_successful": True},
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "reason": str(e),
                "details": {"exception": True},
            }

    async def _save_data_with_common_pattern(
        self,
        dut_id: str,
        data: Any,
        function_tag: str,
        output_pattern: str = None,
        substitutions: Dict[str, Any] = None,
        **kwargs,
    ) -> Optional[str]:
        """
        Common data saving function with pattern handling.

        Args:
            dut_id: DUT ID.
            data: Data to save.
            function_tag: Function tag.
            output_pattern: Output pattern.
            substitutions: Substitutions.
            **kwargs: Additional keyword arguments.
        """
        try:
            # Convert data to JSON if it's a dict/list
            if isinstance(data, (dict, list)):
                content = json.dumps(data, indent=2)
            else:
                content = str(data)

            # Use the output pattern if provided, otherwise use function_tag
            filename = output_pattern or f"{function_tag}_{dut_id}.json"

            file_path = await self.write_output_file(
                dut_id, kwargs.get("collector_id", ""), filename, content
            )
            return file_path
        except Exception as e:
            await self._log_runtime(
                "ERROR",
                "HealthCheckService",
                f"Failed to save data for {function_tag}: {str(e)}",
                dut_id,
            )
            return None

    def _determine_overall_health(self, health_results: Dict[str, Any]) -> str:
        """
        Determine overall health based on individual service health.

        Args:
            health_results: Dictionary of health results.
        """
        healthy_services = 0
        total_services = len(health_results)

        for service, result in health_results.items():
            if result.get("status") == "healthy":
                healthy_services += 1

        if healthy_services == total_services:
            return "excellent"
        elif healthy_services >= total_services * 0.75:
            return "good"
        elif healthy_services >= total_services * 0.5:
            return "fair"
        else:
            return "poor"

    async def run_targeted_health_check(
        self, dut_id: str, target_services: List[str], **kwargs
    ) -> Dict[str, Any]:
        """
        Run health check for specific services.

        Args:
            dut_id: DUT ID.
            target_services: List of services to check.
            **kwargs: Additional keyword arguments.
        """
        try:
            output_files = []
            health_results = {}

            service_checkers = {
                "redfish": self._check_redfish_health,
                "ipmi": self._check_ipmi_health,
                "ssh": self._check_ssh_health,
                "host": self._check_host_health,
            }

            for service in target_services:
                if service in service_checkers:
                    health_results[service] = await service_checkers[service](dut_id)

            # Determine overall health
            overall_health = self._determine_overall_health(health_results)

            # Save results
            health_data = {
                "dut_id": dut_id,
                "target_services": target_services,
                "timestamp": str(asyncio.get_event_loop().time()),
                "overall_health": overall_health,
                "service_health": health_results,
            }

            file_path = await self._save_data_with_common_pattern(
                dut_id,
                health_data,
                kwargs.get("function_tag", "targeted_health_check"),
                output_pattern=f"targeted_health_check_{dut_id}.json",
            )
            if file_path:
                output_files.append(file_path)

            return await self._create_standardized_collector_result(
                dut_id=dut_id,
                collector_id=kwargs.get("collector_id", "unknown"),
                successful_operations=1,
                total_operations=1,
                output_files=output_files,
                error_messages=[],
                operation_name="targeted_health_check",
                additional_context={
                    "overall_health": overall_health,
                    "target_services": target_services,
                    "services_checked": list(health_results.keys()),
                    "dut_id": dut_id,
                },
            )
        except Exception as e:
            return await self._create_standardized_collector_result(
                successful_operations=0,
                total_operations=1,
                output_files=[],
                error_messages=[str(e)],
                operation_name="health_check",
                additional_context={},
                dut_id=dut_id,
                collector_id="health_check",
            )
