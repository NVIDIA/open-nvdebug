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

This module defines enumerations used throughout the tool for type safety
and standardization of values.
"""

from enum import Enum
from typing import Dict


class DutNodeType(Enum):
    """
    DUT node types.

    Defines the hardware node types that can be collected from.

    Attributes:
        COMPUTE: Compute node with GPUs.
        SWITCH_TRAY: Network switch tray.
        POWER_SHELF: Power distribution shelf.
    """

    COMPUTE = "Compute"
    SWITCH_TRAY = "SwitchTray"
    POWER_SHELF = "PowerShelf"


class DutExecutionMode(Enum):
    """
    DUT execution modes.

    Defines where the tool is executed relative to the DUT.

    Attributes:
        LOCAL: Tool runs locally on the DUT.
        REMOTE_CLIENT: Tool runs on remote client machine.
    """

    LOCAL = "Local"
    REMOTE_CLIENT = "RemoteClient"


class NetworkType(Enum):
    """
    Network types.

    Defines the IP protocol version.

    Attributes:
        IPV4: IPv4 addressing.
        IPV6: IPv6 addressing.
    """

    IPV4 = "ipv4"
    IPV6 = "ipv6"


class RedfishHmcAccess(Enum):
    """
    Redfish HMC access methods.

    Defines how BMC Redfish API is accessed through HMC.

    Attributes:
        PORTFORWARDING: TCP port forwarding through host.
        AGGREGATION: BMC aggregation through host.
        SSHACCESS: SSH tunneling through host.
        NOTAPPLICABLE: Direct BMC access (no HMC).
    """

    PORTFORWARDING = "HostBmcTcpPortForwarding"
    AGGREGATION = "HostBmcAggregation"
    SSHACCESS = "HostBmcSshAccess"
    NOTAPPLICABLE = "None"


class CollectionLevel(Enum):
    """
    Collection levels.

    Defines the depth/completeness of log collection.

    Attributes:
        L1: Basic collection - minimal essential logs.
        L2: Standard collection - typical debugging logs.
        L3: Comprehensive collection - complete system dump.
    """

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
    """Create the entity URI to placeholder mapping using ResourceType enum."""
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

    Attributes:
        HOST: Host OS accessibility check.
        REDFISH: Redfish service availability check.
        IPMI: IPMI service availability check.
        SSH: BMC SSH access check.
        HMC: HMC service availability check.
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

    Attributes:
        REDFISH: Redfish API service.
        IPMI: IPMI command service.
        SSH: SSH access service.
        HOST: Host system service.
        HEALTH_CHECK: Health check service.
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

        Args:
            collector_id (str): Collector ID string.

        Returns:
            str: Service name or 'unknown'.
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

        Args:
            group_name (str): Collector group name.

        Returns:
            str: Service name or 'unknown'.
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

        Args:
            group_name (str): Collector group name.

        Returns:
            str: Display name for the group.
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
    Get preflight check enum from service name

    Args:
        service_name: Service name (e.g., "redfish", "ipmi", "ssh", "host", "health_check")

    Returns:
        PreflightChecks enum value
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

    Returns:
        list: List of preflight check enum names.
    """
    return [
        PreflightChecks.HOST.name,
        PreflightChecks.REDFISH.name,
        PreflightChecks.IPMI.name,
        PreflightChecks.SSH.name,
    ]
