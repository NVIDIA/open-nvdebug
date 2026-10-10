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
Enums for the NVDebug Tool.

This module defines enumerations used throughout the tool for type safety and
standardization of values.
"""

from enum import Enum


class DutExecutionMode(Enum):
    """
    DUT execution modes.

    Defines where the tool is executed relative to the DUT.
    """

    LOCAL = "Local"
    REMOTE_CLIENT = "RemoteClient"


class NetworkType(Enum):
    """
    Network types.

    Defines the IP protocol version.

    Its serialized members form a shared vocabulary for configuration, runtime
    state, logs, and reports. Renaming or renumbering a member is therefore a
    compatibility change.
    """

    IPV4 = "ipv4"
    IPV6 = "ipv6"


class CollectionLevel(Enum):
    """
    Collection levels.

    Defines the depth/completeness of log collection.
    """

    L0 = "L0"  # Special collectors - only run when explicitly specified
    L1 = "L1"  # Basic collection
    L2 = "L2"  # Standard collection
    L3 = "L3"  # Comprehensive collection


class ResourceType(Enum):
    """
    Enum for Redfish resource types.

    Defines standard Redfish resource categories and services.
    """

    # Core collections
    SYSTEMS = "Systems"
    CHASSIS = "Chassis"
    MANAGERS = "Managers"

    # Singleton services
    UPDATE_SERVICE = "UpdateService"
    TASK_SERVICE = "TaskService"
    EVENT_SERVICE = "EventService"
    SESSION_SERVICE = "SessionService"
    ACCOUNT_SERVICE = "AccountService"

    # UpdateService sub-resources
    FIRMWARE_INVENTORY = "FirmwareInventory"
    SOFTWARE_INVENTORY = "SoftwareInventory"

    # TaskService sub-resources
    TASKS = "Tasks"

    # EventService sub-resources
    SUBSCRIPTIONS = "Subscriptions"

    # SessionService sub-resources
    SESSIONS = "Sessions"

    # AccountService sub-resources
    ACCOUNTS = "Accounts"
    ROLES = "Roles"
    EXTERNAL_ACCOUNT_PROVIDERS = "ExternalAccountProviders"


# Constant mapping for extracting entity IDs from Redfish URIs
# Maps URI path segments to their corresponding placeholder variable names
# Used for output pattern substitution (e.g., {chassis_id}, {system_id}, {task_id})
# Note: Must be defined after ResourceType enum to reference its values
def _create_entity_uri_mapping():
    """
    Create the entity URI to placeholder mapping using ResourceType enum.

    The implementation uses current instance state to create the entity URI to
    placeholder mapping using ResourceType enum.

    Returns:
        A mapping from entity names to their canonical Redfish URI categories.
    """
    return {
        # Core collections
        f"/{ResourceType.CHASSIS.value}/": "chassis_id",
        f"/{ResourceType.SYSTEMS.value}/": "system_id",
        f"/{ResourceType.MANAGERS.value}/": "manager_id",
        # Task service
        f"/{ResourceType.TASKS.value}/": "task_id",
        # Event service
        f"/{ResourceType.SUBSCRIPTIONS.value}/": "subscription_id",
        # Session service
        f"/{ResourceType.SESSIONS.value}/": "session_id",
        # Account service
        f"/{ResourceType.ACCOUNTS.value}/": "account_id",
        f"/{ResourceType.ROLES.value}/": "role_id",
        # Update service
        f"/{ResourceType.FIRMWARE_INVENTORY.value}/": "firmware_id",
        f"/{ResourceType.SOFTWARE_INVENTORY.value}/": "software_id",
    }


ENTITY_URI_TO_PLACEHOLDER = _create_entity_uri_mapping()


class PreflightChecks(Enum):
    """
    Options supported for preflight check.

    Defines the available preflight checks for verifying system readiness.
    """

    HOST = "Host-OS"
    REDFISH = "Redfish-Service"
    IPMI = "IPMI-Service"
    # DCGM = "DCGM-Service"
    SSH = "BMC-SSH"
    # DCGM_PFW = "DCGM-Port-Forwarding"
    # FWTS = "FWTS-Installation"
    # NVIDIA_SMI = "NVIDIA-SMI-Service"
    HMC = "HMC-Service"


class CollectorServiceMapping(Enum):
    """
    Mapping from collector ID prefixes to service names.

    Provides utilities to map collector IDs and group names to service types.
    """

    REDFISH = "redfish"
    IPMI = "ipmi"
    SSH = "ssh"
    HOST = "host"
    HEALTH_CHECK = "health_check"

    @classmethod
    def get_service_from_collector_id(cls, collector_id: str) -> str:
        """
        Get service name from collector ID prefix.

        The implementation uses ``collector_id`` to get service name from
        collector ID prefix.

        Args:
            collector_id: Stable collector identifier used to correlate
                configuration, logs, and results.

        Returns:
            The canonical service from collector identifier text.
        """
        if not collector_id:
            return "unknown"

        prefix = collector_id[0].upper()
        mapping = {
            "R": cls.REDFISH.value,
            "I": cls.IPMI.value,
            "S": cls.SSH.value,
            "H": cls.HOST.value,
            "C": cls.HEALTH_CHECK.value,
        }
        return mapping.get(prefix, "unknown")

    @classmethod
    def get_service_from_group_name(cls, group_name: str) -> str:
        """
        Get service name from collector group name.

        The implementation uses ``group_name`` to get service name from
        collector group name.

        Args:
            group_name: Stable group name used for lookup and operator-facing
                diagnostics.

        Returns:
            The canonical service from group name.
        """
        if not group_name:
            return "unknown"

        group_lower = group_name.lower()
        mapping = {
            cls.REDFISH.value: cls.REDFISH.value,
            cls.IPMI.value: cls.IPMI.value,
            cls.SSH.value: cls.SSH.value,
            cls.HOST.value: cls.HOST.value,
            cls.HEALTH_CHECK.value: cls.HEALTH_CHECK.value,
            "healthcheck": cls.HEALTH_CHECK.value,  # Map HealthCheck group to health_check service
            "bmc_ssh": cls.SSH.value,  # Legacy mapping
        }
        return mapping.get(group_lower, "unknown")

    @classmethod
    def get_display_name_from_group_name(cls, group_name: str) -> str:
        """
        Get display name from collector group name.

        The implementation uses ``group_name`` to get display name from
        collector group name.

        Args:
            group_name: Stable group name used for lookup and operator-facing
                diagnostics.

        Returns:
            The canonical display name from group name.
        """
        if not group_name:
            return "Unknown"

        group_lower = group_name.lower()
        # Map enum values to display names
        mapping = {
            cls.REDFISH.value: "Redfish",
            cls.IPMI.value: "IPMI",
            cls.SSH.value: "SSH",
            cls.HOST.value: "Host",
            cls.HEALTH_CHECK.value: "HealthCheck",
            "bmc_ssh": "SSH",  # Legacy mapping
        }
        return mapping.get(group_lower, group_name.title())


def get_preflight_enum_from_service(service_name: str) -> PreflightChecks:
    """
    Get preflight check enum from service name.

    After applying local validation, the function forwards ``service_name`` to
    ``service_mapping.get`` and preserves its return and exception contract.

    Args:
        service_name: Stable service name used for lookup and operator-facing
            diagnostics.

    Returns:
        A ``PreflightChecks`` representing preflight enum from service.
    """
    service_mapping = {
        CollectorServiceMapping.REDFISH.value: PreflightChecks.REDFISH,
        CollectorServiceMapping.IPMI.value: PreflightChecks.IPMI,
        CollectorServiceMapping.SSH.value: PreflightChecks.SSH,
        CollectorServiceMapping.HOST.value: PreflightChecks.HOST,
        CollectorServiceMapping.HEALTH_CHECK.value: PreflightChecks.HOST,  # Health check uses HOST preflight
    }
    return service_mapping.get(service_name.lower(), PreflightChecks.HOST)


def get_main_preflight_names() -> list:
    """
    Get list of main preflight check names.

    The implementation uses current instance state to get list of main preflight
    check names.

    Returns:
        The main preflight names returned in operation-defined order.
    """
    return [
        PreflightChecks.HOST.name,
        PreflightChecks.REDFISH.name,
        PreflightChecks.IPMI.name,
        PreflightChecks.SSH.name,
    ]
