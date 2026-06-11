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
URI Configuration Manager.

Handles Redfish URI overrides at tool and DUT levels with support for
custom resource paths and system-specific configurations.
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional, Union

import yaml

from .enums import ResourceType

logger = logging.getLogger(__name__)

# Built-in default URI configuration
DEFAULT_URI_CONFIG = {
    "default_uris": {
        # Core collections
        "Systems": "/redfish/v1/Systems",
        "Chassis": "/redfish/v1/Chassis",
        "Managers": "/redfish/v1/Managers",
        # Singleton services
        "UpdateService": "/redfish/v1/UpdateService",
        "TaskService": "/redfish/v1/TaskService",
        "EventService": "/redfish/v1/EventService",
        "SessionService": "/redfish/v1/SessionService",
        "AccountService": "/redfish/v1/AccountService",
        # UpdateService sub-resources
        "FirmwareInventory": "/redfish/v1/UpdateService/FirmwareInventory",
        "SoftwareInventory": "/redfish/v1/UpdateService/SoftwareInventory",
        # TaskService sub-resources
        "Tasks": "/redfish/v1/TaskService/Tasks",
        # EventService sub-resources
        "Subscriptions": "/redfish/v1/EventService/Subscriptions",
        # SessionService sub-resources
        "Sessions": "/redfish/v1/SessionService/Sessions",
        # AccountService sub-resources
        "Accounts": "/redfish/v1/AccountService/Accounts",
        "Roles": "/redfish/v1/AccountService/Roles",
        "ExternalAccountProviders": "/redfish/v1/AccountService/ExternalAccountProviders",
    },
}


class URIConfigManager:
    """
    Manages Redfish URI configurations with support for tool-level and DUT-level overrides.

    Priority order:
    1. DUT-specific URI overrides (highest priority)
    2. Baseboard-specific URI overrides
    3. Platform-specific URI overrides
    4. Tool-level default URIs (lowest priority)
    """

    def __init__(self, tool_uri_config_path: Optional[str] = None):
        """
        Initialize the URI configuration manager.

        Args:
            tool_uri_config_path: Path to tool-level URI configuration file
        """
        self.tool_uri_config_path = tool_uri_config_path
        self.tool_uris: Dict[str, Any] = {}
        self.dut_uri_configs: Dict[str, Dict[str, Any]] = {}

        # Load tool-level URI configuration
        if tool_uri_config_path:
            self._load_tool_uri_config()
        else:
            # Use built-in default configuration if no config file is provided
            self.tool_uris = DEFAULT_URI_CONFIG.copy()

    def _load_tool_uri_config(self) -> None:
        """
        Load tool-level URI configuration from YAML file.

        Loads URI overrides from the tool-level configuration file.
        """
        try:
            if self.tool_uri_config_path and Path(self.tool_uri_config_path).exists():
                with open(self.tool_uri_config_path, "r") as f:
                    self.tool_uris = yaml.safe_load(f) or {}
                logger.info(
                    f"Loaded tool URI configuration from {self.tool_uri_config_path}"
                )
            else:
                logger.warning(
                    f"Tool URI configuration file not found: {self.tool_uri_config_path}"
                )
        except Exception as e:
            logger.error(f"Failed to load tool URI configuration: {e}")
            self.tool_uris = {}

    def load_dut_uri_config(self, dut_id: str, dut_config: Dict[str, Any]) -> None:
        """
        Load DUT-specific URI configuration.

        Args:
            dut_id: The DUT identifier
            dut_config: DUT configuration dictionary
        """
        try:
            # Check if DUT has a specific URI config file
            uri_config_file = dut_config.get("uri_config_file")
            if uri_config_file:
                config_path = Path(uri_config_file)
                if config_path.exists():
                    with open(config_path, "r") as f:
                        self.dut_uri_configs[dut_id] = yaml.safe_load(f) or {}
                    logger.info(
                        f"Loaded DUT URI configuration for {dut_id} from {uri_config_file}"
                    )
                else:
                    logger.warning(
                        f"DUT URI configuration file not found: {uri_config_file}"
                    )
                    self.dut_uri_configs[dut_id] = {}
            else:
                # Use inline URI overrides from DUT config
                uri_overrides = dut_config.get("uri_overrides", {})
                if uri_overrides:
                    self.dut_uri_configs[dut_id] = uri_overrides.copy()
                    logger.info(f"Loaded inline URI overrides for DUT {dut_id}")
                else:
                    self.dut_uri_configs[dut_id] = {}

                # Also store RF_DEFAULT_PREFIX if present (for conflict detection)
                rf_default_prefix = dut_config.get("RF_DEFAULT_PREFIX")
                if rf_default_prefix:
                    self.dut_uri_configs[dut_id][
                        "RF_DEFAULT_PREFIX"
                    ] = rf_default_prefix
                    logger.debug(
                        f"Stored RF_DEFAULT_PREFIX for DUT {dut_id}: {rf_default_prefix}"
                    )

                # Store RF_HMC_DEFAULT_PREFIX if present (HMC-specific prefix override)
                rf_hmc_default_prefix = dut_config.get("RF_HMC_DEFAULT_PREFIX")
                if rf_hmc_default_prefix:
                    self.dut_uri_configs[dut_id][
                        "RF_HMC_DEFAULT_PREFIX"
                    ] = rf_hmc_default_prefix
                    logger.debug(
                        f"Stored RF_HMC_DEFAULT_PREFIX for DUT {dut_id}: {rf_hmc_default_prefix}"
                    )

        except Exception as e:
            logger.error(f"Failed to load DUT URI configuration for {dut_id}: {e}")
            self.dut_uri_configs[dut_id] = {}

    def update_dut_rf_prefix(self, dut_id: str, rf_prefix: str) -> None:
        """
        Update the RF_DEFAULT_PREFIX for a specific DUT.

        This is called after DUT creation when RF_DEFAULT_PREFIX may have been
        modified by applying tool-level prefix_override.

        Args:
            dut_id: The DUT identifier
            rf_prefix: The new RF_DEFAULT_PREFIX value
        """
        if dut_id not in self.dut_uri_configs:
            self.dut_uri_configs[dut_id] = {}

        self.dut_uri_configs[dut_id]["RF_DEFAULT_PREFIX"] = rf_prefix
        logger.debug(f"Updated RF_DEFAULT_PREFIX for DUT {dut_id}: {rf_prefix}")

    def update_dut_hmc_prefix(self, dut_id: str, hmc_prefix: str) -> None:
        """
        Update the RF_HMC_DEFAULT_PREFIX for a specific DUT.

        This is called after DUT creation when RF_HMC_DEFAULT_PREFIX has been
        resolved (DUT-level or from tool-level hmc_prefix_override).

        Args:
            dut_id: The DUT identifier
            hmc_prefix: The new RF_HMC_DEFAULT_PREFIX value
        """
        if dut_id not in self.dut_uri_configs:
            self.dut_uri_configs[dut_id] = {}

        self.dut_uri_configs[dut_id]["RF_HMC_DEFAULT_PREFIX"] = hmc_prefix
        logger.debug(f"Updated RF_HMC_DEFAULT_PREFIX for DUT {dut_id}: {hmc_prefix}")

    def get_uri(
        self,
        dut_id: str,
        uri_key: Union[str, ResourceType],
        baseboard: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> str:
        """
        Get URI for a specific key with proper override resolution.

        Args:
            dut_id: The DUT identifier
            uri_key: The URI key to look up (string or ResourceType enum)
            baseboard: Optional baseboard name for baseboard-specific overrides
            platform: Optional platform name for platform-specific overrides

        Returns:
            str: The resolved URI
        """
        # Convert ResourceType enum to string if needed
        if isinstance(uri_key, ResourceType):
            uri_key = uri_key.value
        # Priority 1: DUT-specific URI overrides
        dut_uris = self.dut_uri_configs.get(dut_id, {})
        if uri_key in dut_uris:
            uri = dut_uris[uri_key]
            logger.debug(f"Using DUT-specific URI for {dut_id}.{uri_key}: {uri}")
            return self._apply_prefix_override(uri, dut_id)

        # Priority 2: Baseboard-specific URI overrides
        if baseboard and self.tool_uris:
            baseboard_overrides = self.tool_uris.get("baseboard_overrides", {})
            baseboard_uris = baseboard_overrides.get(baseboard, {})
            if uri_key in baseboard_uris:
                uri = baseboard_uris[uri_key]
                logger.debug(
                    f"Using baseboard-specific URI for {baseboard}.{uri_key}: {uri}"
                )
                return self._apply_prefix_override(uri, dut_id)

        # Priority 3: Platform-specific URI overrides
        if platform and self.tool_uris:
            platform_overrides = self.tool_uris.get("platform_overrides", {})
            platform_uris = platform_overrides.get(platform, {})
            if uri_key in platform_uris:
                uri = platform_uris[uri_key]
                logger.debug(
                    f"Using platform-specific URI for {platform}.{uri_key}: {uri}"
                )
                return self._apply_prefix_override(uri, dut_id)

        # Priority 4: Tool-level default URIs
        if self.tool_uris:
            default_uris = self.tool_uris.get("default_uris", {})
            if uri_key in default_uris:
                uri = default_uris[uri_key]
                logger.debug(f"Using tool-level default URI for {uri_key}: {uri}")
                return self._apply_prefix_override(uri, dut_id)

        # Fallback: Return a standard URI pattern
        fallback_uri = self._get_fallback_uri(uri_key, dut_id)
        logger.debug(
            f"No URI configuration found for {uri_key}, using fallback: {fallback_uri}"
        )
        return fallback_uri

    def _get_fallback_uri(self, uri_key: str, dut_id: Optional[str] = None) -> str:
        """
        Get fallback URI for a key when no configuration is found.

        Args:
            uri_key: The URI key
            dut_id: Optional DUT ID for prefix override logic

        Returns:
            str: Fallback URI
        """
        # First try to get from tool-level default URIs
        if self.tool_uris:
            default_uris = self.tool_uris.get("default_uris", {})
            if uri_key in default_uris:
                return default_uris[uri_key]

        # Use built-in default configuration as final fallback
        default_uris = DEFAULT_URI_CONFIG.get("default_uris", {})
        if uri_key in default_uris:
            return default_uris[uri_key]

        # Ultimate fallback - construct URI from key and apply prefix override
        fallback_uri = f"/redfish/v1/{uri_key}"
        return self._apply_prefix_override(fallback_uri, dut_id)

    def _is_hmc_uri(self, uri: str) -> bool:
        """
        Determine if a URI targets an HMC-owned resource on arm64 (Redfish aggregation).

        HMC resources are identified by the presence of an HGX_ resource segment in
        the URI path (e.g. /Systems/HGX_Baseboard_0/... or /Managers/HGX_BMC_0/...).
        The prefix used to identify HMC resources is configurable via
        ``uri_overrides.hmc_resource_prefix`` in tool_config.yaml (default: ``HGX_``).

        Args:
            uri: The Redfish URI to inspect

        Returns:
            bool: True if the URI targets an HMC resource, False otherwise
        """
        hmc_resource_prefix = (
            self.tool_uris.get("hmc_resource_prefix", "HGX_")
            if self.tool_uris
            else "HGX_"
        )
        return f"/{hmc_resource_prefix}" in uri

    def _apply_prefix_override(self, uri: str, dut_id: Optional[str] = None) -> str:
        """
        Apply prefix override if configured in the tool URIs.

        For URIs targeting HMC resources (containing an HGX_ path segment), the
        HMC-specific prefix is applied in this priority order:
          1. DUT-level ``RF_HMC_DEFAULT_PREFIX`` (dut_config.yaml)
          2. Tool-level ``uri_overrides.hmc_prefix_override`` (tool_config.yaml)

        For all other (BMC) URIs, the standard prefix logic applies:
          1. DUT-level ``RF_DEFAULT_PREFIX`` (if non-default, skips tool-level override)
          2. Tool-level ``uri_overrides.prefix_override``

        Args:
            uri: The URI to potentially modify
            dut_id: Optional DUT ID to check for DUT-specific prefix settings

        Returns:
            str: The URI with the appropriate prefix override applied
        """
        dut_uris = self.dut_uri_configs.get(dut_id, {}) if dut_id else {}

        # --- HMC URI path ---
        # HMC resources carry an HGX_ path segment and may live under a different
        # Redfish prefix than the Customer BMC (e.g. /hgx/redfish/v1 vs /redfish/v1).
        #
        # Priority when RF_HMC_DEFAULT_PREFIX / hmc_prefix_override IS set:
        #   Apply it and return immediately — it takes full precedence over any
        #   global prefix_override.
        #
        # When neither HMC-specific prefix is set:
        #   Fall through to the global prefix_override logic below so that a single
        #   global prefix applies to ALL collectors (BMC and HMC alike).
        if self._is_hmc_uri(uri):
            # Priority 1: DUT-level HMC prefix (no tool_uris required)
            hmc_prefix = dut_uris.get("RF_HMC_DEFAULT_PREFIX")
            # Priority 2: Tool-level HMC prefix override (requires tool_uris)
            if not hmc_prefix and self.tool_uris:
                hmc_prefix = self.tool_uris.get("hmc_prefix_override")

            if hmc_prefix:
                # An HMC-specific prefix is configured — apply it and stop here.
                if "/redfish/v1" in uri and not uri.startswith(hmc_prefix):
                    uri = uri.replace("/redfish/v1", hmc_prefix, 1)
                    logger.debug(f"Applied HMC prefix override '{hmc_prefix}' to URI: {uri}")
                return uri
            # No HMC-specific prefix configured — fall through to global prefix_override
            # so that a single global prefix covers both BMC and HMC collectors.

        # --- BMC URI path (also reached by HMC URIs when no HMC-specific prefix set) ---
        if not self.tool_uris:
            return uri

        # If DUT has a custom RF_DEFAULT_PREFIX (not the default), skip tool-level
        # prefix_override — the DUT's normalize_redfish_uri will handle it.
        dut_rf_prefix = dut_uris.get("RF_DEFAULT_PREFIX")
        if dut_rf_prefix and dut_rf_prefix != "/redfish/v1":
            logger.debug(
                f"Skipping tool-level prefix_override for DUT {dut_id} "
                f"(has custom RF_DEFAULT_PREFIX: {dut_rf_prefix})"
            )
            return uri

        prefix_override = self.tool_uris.get("prefix_override")
        if not prefix_override:
            return uri

        if "/redfish/v1" in uri and not uri.startswith(prefix_override):
            uri = uri.replace("/redfish/v1", prefix_override, 1)
            logger.debug(f"Applied prefix override '{prefix_override}' to URI: {uri}")

        return uri

    def get_uri_template(self, template_key: str, **kwargs) -> str:
        """
        Get URI template and substitute parameters.

        Args:
            template_key: The template key to look up
            **kwargs: Parameters to substitute in the template

        Returns:
            str: The resolved URI template
        """
        if not self.tool_uris:
            return self._get_fallback_uri(template_key)

        templates = self.tool_uris.get("uri_templates", {})
        template = templates.get(template_key)

        if not template:
            return self._get_fallback_uri(template_key)

        # Substitute parameters
        try:
            return template.format(**kwargs)
        except KeyError as e:
            logger.warning(f"Missing parameter {e} for template {template_key}")
            return template

    def validate_uri(self, uri: str, uri_type: str) -> bool:
        """
        Validate URI structure against configured patterns.

        Args:
            uri: The URI to validate
            uri_type: The type of URI (systems, chassis, managers, etc.)

        Returns:
            bool: True if URI is valid, False otherwise
        """
        if not self.tool_uris:
            return True  # Skip validation if no config loaded

        validation_patterns = self.tool_uris.get("validation_patterns", {})
        pattern = validation_patterns.get(uri_type)

        if not pattern:
            return True  # No validation pattern defined

        try:
            return bool(re.match(pattern, uri))
        except re.error:
            logger.warning(f"Invalid regex pattern for {uri_type}: {pattern}")
            return True

    def get_all_uris_for_dut(
        self,
        dut_id: str,
        baseboard: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Get all configured URIs for a DUT.

        Args:
            dut_id: The DUT identifier
            baseboard: Optional baseboard name
            platform: Optional platform name

        Returns:
            dict: Dictionary of URI keys to resolved URIs
        """
        # Use ResourceType enum values for consistency
        uri_keys = [resource_type.value for resource_type in ResourceType]

        uris = {}
        for key in uri_keys:
            uris[key] = self.get_uri(dut_id, key, baseboard, platform)

        return uris

    def clear_dut_config(self, dut_id: str) -> None:
        """
        Clear DUT-specific URI configuration.

        Args:
            dut_id: The DUT identifier
        """
        if dut_id in self.dut_uri_configs:
            del self.dut_uri_configs[dut_id]
            logger.debug(f"Cleared URI configuration for DUT {dut_id}")

    def get_config_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current URI configuration.

        Returns:
            dict: Configuration summary
        """
        return {
            "tool_uri_config_loaded": bool(self.tool_uris),
            "tool_uri_config_path": self.tool_uri_config_path,
            "configured_duts": list(self.dut_uri_configs.keys()),
            "available_uri_keys": (
                list(self.tool_uris.get("default_uris", {}).keys())
                if self.tool_uris
                else []
            ),
        }
