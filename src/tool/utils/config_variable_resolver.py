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
Configuration Variable Resolver for NVDebug Tool.

Resolves variables from multiple sources including baseboard config, general
config, runtime context, and environment variables with priority ordering.
"""

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

logger = logging.getLogger(__name__)


class ConfigurationVariableResolver:
    """
    Resolves configuration variables from multiple sources with fallback hierarchy.

    Resolution order:
    1. Runtime context (highest priority)
    2. Baseboard-specific configuration
    3. General configuration
    4. Environment variables (lowest priority)
    """

    def __init__(
        self,
        baseboard_config: Dict[str, Any] = None,
        general_config: Dict[str, Any] = None,
    ):
        """
        Initialize the ConfigurationVariableResolver.

        Args:
            baseboard_config: Baseboard-specific configuration from baseboards sheet
            general_config: General configuration from config files
        """
        self.baseboard_config = baseboard_config or {}
        self.general_config = general_config or {}

        # Variable mapping from collector definitions to config keys
        self.variable_mapping = {
            # I2C Configuration
            "vee_bus": "i2c_config.VIRTUAL_EEPROM_BUS",
            "vee_addr": "i2c_config.VIRTUAL_EEPROM_ADDR",
            "hmc_addr": "i2c_config.HMC_I2C_ADDRESS",
            "bus1": "i2c_config.HGX_I2C1_BUS_ADDRESS",
            "bus2": "i2c_config.HGX_I2C2_BUS_ADDRESS",
            # Network Configuration
            "BMC_IP": "platform_detection.hmc_ip",
            "addr": "platform_detection.hmc_ip",
            "hmc_addr": "platform_detection.hmc_ip",
            # Platform Configuration
            "temp_dir": "platform.temp_dir",
            "device": "platform.device",
            "device_index": "platform.device_index",
            "device_instance": "platform.device_instance",
            "interface_id": "platform.interface_id",
            # Command Configuration
            "command_type": "commands.type",
            "option": "commands.option",
            "options": "commands.options",
            "flags": "commands.flags",
            "data_value": "commands.data_value",
        }

        # Environment variable fallbacks
        self.env_fallbacks = {
            "temp_dir": "TMPDIR",
            "BMC_IP": "BMC_IP",
            "hmc_addr": "HMC_ADDR",
            "vee_bus": "VEE_BUS",
            "vee_addr": "VEE_ADDR",
        }

    def resolve_variable(
        self, variable_name: str, runtime_context: Dict[str, Any] = None
    ) -> Optional[str]:
        """
        Resolve a variable from the appropriate source.

        Args:
            variable_name: Name of the variable to resolve
            runtime_context: Runtime context (highest priority)

        Returns:
            Resolved value or None if not found
        """
        runtime_context = runtime_context or {}

        # 1. Check runtime context first (highest priority)
        if variable_name in runtime_context:
            value = runtime_context[variable_name]
            logger.debug(f"Resolved {variable_name} from runtime context: {value}")
            return str(value)

        # 2. Check baseboard configuration
        config_value = self._get_from_config(variable_name, self.baseboard_config)
        if config_value is not None:
            logger.debug(
                f"Resolved {variable_name} from baseboard config: {config_value}"
            )
            return str(config_value)

        # 3. Check general configuration
        config_value = self._get_from_config(variable_name, self.general_config)
        if config_value is not None:
            logger.debug(
                f"Resolved {variable_name} from general config: {config_value}"
            )
            return str(config_value)

        # 4. Check environment variables (lowest priority)
        env_value = self._get_from_environment(variable_name)
        if env_value is not None:
            logger.debug(f"Resolved {variable_name} from environment: {env_value}")
            return env_value

        logger.warning(
            f"Variable {variable_name} not found in any configuration source"
        )
        return None

    def _get_from_config(
        self, variable_name: str, config: Dict[str, Any]
    ) -> Optional[Any]:
        """
        Get variable value from configuration using dot notation.

        Args:
            variable_name (str): Name of the variable to resolve
            config (Dict[str, Any]): Configuration to search in

        Returns:
            Optional[Any]: Resolved value or None if not found
        """
        if not config:
            return None

        # Check direct mapping first
        if variable_name in config:
            return config[variable_name]

        # Check mapped configuration path
        config_path = self.variable_mapping.get(variable_name)
        if config_path:
            return self._get_nested_value(config, config_path)

        # Try to find in nested configuration
        return self._search_nested_config(config, variable_name)

    def _get_nested_value(self, config: Dict[str, Any], path: str) -> Optional[Any]:
        """
        Get value from nested configuration using dot notation.

        Args:
            config (Dict[str, Any]): Configuration to search in
            path (str): Path to the value to resolve

        Returns:
            Optional[Any]: Resolved value or None if not found
        """
        keys = path.split(".")
        current = config

        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None

        return current

    def _search_nested_config(
        self, config: Dict[str, Any], variable_name: str
    ) -> Optional[Any]:
        """
        Search for variable in nested configuration recursively.

        Args:
            config (Dict[str, Any]): Configuration to search in
            variable_name (str): Name of the variable to resolve

        Returns:
            Optional[Any]: Resolved value or None if not found
        """
        if isinstance(config, dict):
            # Check direct keys
            if variable_name in config:
                return config[variable_name]

            # Search nested dictionaries
            for key, value in config.items():
                if isinstance(value, dict):
                    result = self._search_nested_config(value, variable_name)
                    if result is not None:
                        return result
        elif isinstance(config, list):
            # Search in list items
            for item in config:
                if isinstance(item, dict):
                    result = self._search_nested_config(item, variable_name)
                    if result is not None:
                        return result

        return None

    def _get_from_environment(self, variable_name: str) -> Optional[str]:
        """
        Get variable value from environment variables.

        Args:
            variable_name (str): Name of the variable to resolve

        Returns:
            Optional[str]: Resolved value or None if not found
        """
        # Check direct environment variable
        env_var = os.environ.get(variable_name)
        if env_var:
            return env_var

        # Check mapped environment variable
        env_var_name = self.env_fallbacks.get(variable_name)
        if env_var_name:
            return os.environ.get(env_var_name)

        return None

    def resolve_variables_in_template(
        self, template: str, runtime_context: Dict[str, Any] = None
    ) -> str:
        """
        Resolve all variables in a template string.

        Args:
            template: Template string with {variable_name} placeholders
            runtime_context: Runtime context for variable resolution

        Returns:
            Template with variables resolved
        """
        if not template:
            return template

        runtime_context = runtime_context or {}
        result = template

        # Find all variable patterns
        variable_pattern = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
        variables = set()

        for match in variable_pattern.finditer(template):
            variables.add(match.group(1))

        # Resolve each variable
        for var_name in variables:
            resolved_value = self.resolve_variable(var_name, runtime_context)
            if resolved_value is not None:
                result = result.replace(f"{{{var_name}}}", resolved_value)
            else:
                logger.warning(
                    f"Could not resolve variable {var_name} in template: {template}"
                )

        return result

    def get_available_variables(self) -> Dict[str, List[str]]:
        """
        Get list of available variables from each source.

        Returns:
            Dict[str, List[str]]: Dictionary of available variables from each source
        """
        available = {
            "runtime_context": [],
            "baseboard_config": [],
            "general_config": [],
            "environment": [],
        }

        # Get baseboard config variables
        if self.baseboard_config:
            available["baseboard_config"] = self._get_config_variables(
                self.baseboard_config
            )

        # Get general config variables
        if self.general_config:
            available["general_config"] = self._get_config_variables(
                self.general_config
            )

        # Get environment variables
        available["environment"] = list(self.env_fallbacks.keys())

        return available

    def _get_config_variables(self, config: Dict[str, Any]) -> List[str]:
        """
        Extract all variable names from configuration.

        Args:
            config (Dict[str, Any]): Configuration to search in

        Returns:
            List[str]: List of variable names
        """
        variables = []

        def extract_vars(obj, prefix=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_key = f"{prefix}.{key}" if prefix else key
                    variables.append(current_key)
                    if isinstance(value, (dict, list)):
                        extract_vars(value, current_key)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_key = f"{prefix}[{i}]" if prefix else f"[{i}]"
                    if isinstance(item, (dict, list)):
                        extract_vars(item, current_key)

        extract_vars(config)
        return variables

    def update_baseboard_config(self, baseboard_config: Dict[str, Any]) -> None:
        """
        Update the baseboard configuration.

        Args:
            baseboard_config (Dict[str, Any]): Baseboard configuration to update
        """
        self.baseboard_config = baseboard_config
        logger.info("Updated baseboard configuration")

    def update_general_config(self, general_config: Dict[str, Any]) -> None:
        """
        Update the general configuration.

        Args:
            general_config (Dict[str, Any]): General configuration to update
        """
        self.general_config = general_config
        logger.info("Updated general configuration")

    def add_variable_mapping(self, variable_name: str, config_path: str) -> None:
        """
        Add a new variable mapping.

        Args:
            variable_name (str): Name of the variable to map
            config_path (str): Path to the value to map
        """
        self.variable_mapping[variable_name] = config_path
        logger.debug(f"Added variable mapping: {variable_name} -> {config_path}")

    def add_env_fallback(self, variable_name: str, env_var_name: str) -> None:
        """
        Add a new environment variable fallback.

        Args:
            variable_name (str): Name of the variable to fallback
            env_var_name (str): Name of the environment variable to fallback
        """
        self.env_fallbacks[variable_name] = env_var_name
        logger.debug(f"Added environment fallback: {variable_name} -> {env_var_name}")
