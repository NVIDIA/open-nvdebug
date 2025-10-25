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
Variable Substitution Service for NVDebug Tool.

Handles dynamic replacement of placeholders in action URIs, payloads, and
configurations with support for DUT-specific values and nested substitutions.
"""

import asyncio
import os
import re
import time
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Union

from .config_variable_resolver import ConfigurationVariableResolver


class VariableSubstitutionError(Exception):
    """
    Exception raised for variable substitution errors.

    Raised when variable substitution fails due to missing variables,
    type validation errors, or other substitution issues.
    """

    pass


class VariableSubstitutionService:
    """
    Service for variable substitution that dynamically replaces placeholders
    with runtime context values, with proper async logging support.
    """

    def __init__(self, logger=None, orchestrator=None):
        """
        Initialize the VariableSubstitutionService.

        Args:
            logger: AsyncSafeLogger instance for DUT-specific logging
            orchestrator: WorkflowOrchestrator instance for accessing configurations
        """
        self.logger = logger
        self.orchestrator = orchestrator

        # Initialize with default settings
        self.enable_caching = True
        self.cache_size = 128
        self.substitution_cache = {}
        self.cache_hits = 0
        self.cache_misses = 0
        self.config_resolver = None
        self.dut_object = None

        # Enhanced variable patterns:
        # {variable_name} - runtime context variables
        # {config.path.to.value} - configuration variables
        # {env.VARIABLE_NAME} - environment variables
        # {dut.attribute} - DUT-specific variables
        self.variable_pattern = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
        self.config_pattern = re.compile(r"\{config\.([a-zA-Z0-9_.]+)\}")
        self.env_pattern = re.compile(r"\{env\.([A-Z_][A-Z0-9_]*)\}")
        self.dut_pattern = re.compile(r"\{dut\.([a-zA-Z0-9_.]+)\}")

        # Supported variable types and their validation patterns
        self.variable_types = {
            "system_id": r"^[a-zA-Z0-9_-]+$",
            "manager_id": r"^[a-zA-Z0-9_-]+$",
            "chassis_id": r"^[a-zA-Z0-9_-]+$",
            "task_id": r"^[a-zA-Z0-9_-]+$",
            "device_id": r"^[a-zA-Z0-9_-]+$",
            "entry_id": r"^[a-zA-Z0-9_-]+$",
            "diagnostic_type": r"^[a-zA-Z0-9_-]+$",
            "command_name": r"^[a-zA-Z0-9_-]+$",
            "file_name": r"^[a-zA-Z0-9_.-]+$",
            "timestamp": r"^\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}$",
            "log_id": r"^[a-zA-Z0-9_-]+$",
            "report_id": r"^[a-zA-Z0-9_-]+$",
            "member_id": r"^[a-zA-Z0-9_-]+$",
            "index": r"^\d+$",
            "page": r"^\d+$",
            "total": r"^\d+$",
            "sma_id": r"^[a-zA-Z0-9_-]+$",
            "service_id": r"^[a-zA-Z0-9_-]+$",
            "group": r"^[a-zA-Z0-9_-]+$",
            "device_name": r"^[a-zA-Z0-9_-]+$",
            "log_type": r"^[a-zA-Z0-9_-]+$",
            # Additional variables found in collector definitions
            "addr": r"^[a-zA-Z0-9_.-]+$",
            "BMC_IP": r"^[a-zA-Z0-9_.-]+$",
            "bus1": r"^[a-zA-Z0-9_-]+$",
            "bus2": r"^[a-zA-Z0-9_-]+$",
            "command_type": r"^[a-zA-Z0-9_-]+$",
            "data_value": r"^[a-zA-Z0-9_.-]+$",
            "device": r"^[a-zA-Z0-9_-]+$",
            "device_index": r"^[a-zA-Z0-9_-]+$",
            "device_instance": r"^[a-zA-Z0-9_-]+$",
            "flags": r"^[a-zA-Z0-9_-]+$",
            "hmc_addr": r"^[a-zA-Z0-9_.-]+$",
            "interface_id": r"^[a-zA-Z0-9_-]+$",
            "option": r"^[a-zA-Z0-9_-]+$",
            "options": r"^[a-zA-Z0-9_-]+$",
            "temp_dir": r"^[a-zA-Z0-9_/.-]+$",
            "vee_addr": r"^[a-zA-Z0-9_.-]+$",
            "vee_bus": r"^[a-zA-Z0-9_-]+$",
            "collector_dir": r"^[a-zA-Z0-9_/.-]+$",
            "log_dir": r"^[a-zA-Z0-9_/.-]+$",
        }

        # Type validation patterns
        self.type_patterns = {
            "string": r".*",
            "integer": r"^\d+$",
            "float": r"^\d+\.?\d*$",
            "boolean": r"^(true|false|True|False|1|0)$",
        }

    @classmethod
    async def create(
        cls,
        logger=None,
        orchestrator=None,
        config_resolver=None,
        dut_object=None,
        cache_size=None,
    ):
        """
        Factory method to create and initialize VariableSubstitutionService asynchronously.

        Args:
            logger: AsyncSafeLogger instance for DUT-specific logging
            orchestrator: WorkflowOrchestrator instance for accessing configurations
            config_resolver: ConfigurationVariableResolver for config variables
            dut_object: DUT object for DUT-specific variables
            cache_size: Optional cache size override (default: 128)
        """
        instance = cls(logger, orchestrator)
        instance.config_resolver = config_resolver
        instance.dut_object = dut_object
        if cache_size is not None:
            instance.cache_size = cache_size
        await instance._initialize()
        return instance

    async def _initialize(self):
        """
        Async initialization method.

        Sets up logging helper and initializes internal state.
        """

        # Helper method for async logging
        async def log_message(level: str, message: str, dut_id: str = None):
            """
            Helper to log messages using async logger if available.

            Args:
                level: Log level.
                message: Log message.
                dut_id: Optional DUT ID for DUT-specific logging.
            """
            if self.logger and dut_id:
                # Use DUT-specific logging
                await self.logger.write_to_dut_runtime_log(
                    dut_id, level, "VariableSubstitution", message
                )
            elif self.logger:
                # Use system-level logging
                await self.logger.log_runtime(level, "VariableSubstitution", message)
            # Remove fallback print statement to avoid console spam

        self._log = log_message

    async def substitute_variables(
        self,
        template: str,
        context: Dict[str, Any],
        dut_id: str = None,
        validate_types: bool = True,
        allow_missing: bool = False,
    ) -> str:
        """
        Substitute variables in a template string with values from context.

        Args:
            template: String containing variable placeholders like {variable_name}, {config.path.to.value}, {env.VARIABLE_NAME}
            context: Dictionary containing variable values
            dut_id: DUT ID for DUT-specific logging
            validate_types: Whether to validate variable types
            allow_missing: Whether to allow missing variables (keep as-is)

        Returns:
            String with variables substituted

        Raises:
            VariableSubstitutionError: If substitution fails
        """
        if not template:
            return template

        # Check cache first if enabled
        cache_key = None
        if self.enable_caching:
            cache_key = self._generate_cache_key(template, context)
            if cache_key in self.substitution_cache:
                self.cache_hits += 1
                await self._log(
                    "DEBUG",
                    f"Cache hit for template: {template[:50]}...",
                    dut_id,
                )
                return self.substitution_cache[cache_key]
            else:
                self.cache_misses += 1
        else:
            # Count as cache miss when caching is disabled
            self.cache_misses += 1

        try:
            result = template

            # 1. Substitute configuration variables first: {config.path.to.value}
            result = await self._substitute_config_variables(
                result, context, dut_id, allow_missing
            )

            # 2. Substitute environment variables: {env.VARIABLE_NAME}
            result = await self._substitute_env_variables(result, dut_id, allow_missing)

            # 3. Substitute DUT variables: {dut.attribute}
            result = await self._substitute_dut_variables(result, dut_id, allow_missing)

            # 4. Substitute runtime context variables: {variable_name}
            result = await self._substitute_runtime_variables(
                result, context, dut_id, validate_types, allow_missing
            )

            # Handle nested variable substitution
            result = await self._handle_nested_substitution(
                result, context, dut_id, validate_types, allow_missing
            )

            # Cache result if enabled
            if self.enable_caching:
                self._cache_result(cache_key, result)

            await self._log(
                "DEBUG", f"Substitution completed: {result[:100]}...", dut_id
            )
            return result

        except Exception as e:
            await self._log("ERROR", f"Variable substitution failed: {e}", dut_id)
            raise VariableSubstitutionError(f"Substitution failed: {e}")

    async def _substitute_config_variables(
        self,
        template: str,
        context: Dict[str, Any],
        dut_id: str,
        allow_missing: bool,
    ) -> str:
        """
        Substitute configuration variables: {config.path.to.value}.

        Args:
            template: Template string.
            context: Variable context.
            dut_id: DUT ID.
            allow_missing: Whether to allow missing variables.

        Returns:
            Template with config variables substituted.
        """
        if not self.config_resolver:
            await self._log(
                "WARNING",
                "No config resolver available, skipping config variable substitution",
                dut_id,
            )
            return template

        result = template

        for match in self.config_pattern.finditer(template):
            config_path = match.group(1)
            full_pattern = match.group(0)

            try:
                # Try to resolve the full config path first
                config_value = self.config_resolver.resolve_variable(
                    config_path, context
                )

                # If that fails, try to extract a simple variable name from the path
                if config_value is None and "." in config_path:
                    # Extract the last part as a simple variable name
                    simple_var_name = config_path.split(".")[-1]
                    config_value = self.config_resolver.resolve_variable(
                        simple_var_name, context
                    )

                if config_value is not None:
                    result = result.replace(full_pattern, config_value)
                    await self._log(
                        "DEBUG",
                        f"Substituted {full_pattern} with {config_value}",
                        dut_id,
                    )
                else:
                    if not allow_missing:
                        raise VariableSubstitutionError(
                            f"Missing config variable: {config_path}"
                        )
                    else:
                        await self._log(
                            "WARNING",
                            f"Missing config variable {config_path}, keeping as-is",
                            dut_id,
                        )
            except Exception as e:
                if not allow_missing:
                    raise VariableSubstitutionError(
                        f"Error resolving config variable {config_path}: {e}"
                    )
                else:
                    await self._log(
                        "WARNING",
                        f"Error resolving config variable {config_path}: {e}",
                        dut_id,
                    )

        return result

    async def _substitute_env_variables(
        self, template: str, dut_id: str, allow_missing: bool
    ) -> str:
        """
        Substitute environment variables: {env.VARIABLE_NAME}.

        Args:
            template: Template string.
            dut_id: DUT ID.
            allow_missing: Whether to allow missing variables.

        Returns:
            Template with environment variables substituted.
        """
        result = template

        for match in self.env_pattern.finditer(template):
            env_var_name = match.group(1)
            full_pattern = match.group(0)

            env_value = os.environ.get(env_var_name)
            if env_value is not None:
                result = result.replace(full_pattern, env_value)
                await self._log(
                    "DEBUG",
                    f"Substituted {full_pattern} with {env_value}",
                    dut_id,
                )
            else:
                if not allow_missing:
                    raise VariableSubstitutionError(
                        f"Missing environment variable: {env_var_name}"
                    )
                else:
                    await self._log(
                        "WARNING",
                        f"Missing environment variable {env_var_name}, keeping as-is",
                        dut_id,
                    )

        return result

    async def _substitute_dut_variables(
        self, template: str, dut_id: str, allow_missing: bool
    ) -> str:
        """
        Substitute DUT-specific variables: {dut.attribute}.

        Args:
            template: Template string.
            dut_id: DUT ID.
            allow_missing: Whether to allow missing variables.

        Returns:
            Template with DUT variables substituted.
        """
        if not self.dut_object:
            await self._log(
                "WARNING",
                "No DUT object available, skipping DUT variable substitution",
                dut_id,
            )
            return template

        result = template

        for match in self.dut_pattern.finditer(template):
            dut_path = match.group(1)
            full_pattern = match.group(0)

            try:
                # Get value from DUT object using dot notation
                dut_value = self._get_dut_attribute(dut_path)
                if dut_value is not None:
                    result = result.replace(full_pattern, str(dut_value))
                    await self._log(
                        "DEBUG",
                        f"Substituted {full_pattern} with {dut_value}",
                        dut_id,
                    )
                else:
                    if not allow_missing:
                        raise VariableSubstitutionError(
                            f"Missing DUT variable: {dut_path}"
                        )
                    else:
                        await self._log(
                            "WARNING",
                            f"Missing DUT variable {dut_path}, keeping as-is",
                            dut_id,
                        )
            except Exception as e:
                if not allow_missing:
                    raise VariableSubstitutionError(
                        f"Error resolving DUT variable {dut_path}: {e}"
                    )
                else:
                    await self._log(
                        "WARNING",
                        f"Error resolving DUT variable {dut_path}: {e}",
                        dut_id,
                    )

        return result

    def _get_dut_attribute(self, path: str) -> Any:
        """
        Get DUT attribute using dot notation (e.g., 'config.i2c_bus').

        Args:
            path: Dot-separated attribute path.

        Returns:
            Attribute value or None if not found.
        """
        if not self.dut_object:
            return None

        try:
            current = self.dut_object
            for part in path.split("."):
                if hasattr(current, part):
                    current = getattr(current, part)
                elif isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None

            return current
        except Exception as e:
            # Log error but don't raise - let the calling method handle it
            return None

    async def _substitute_runtime_variables(
        self,
        template: str,
        context: Dict[str, Any],
        dut_id: str,
        validate_types: bool,
        allow_missing: bool,
    ) -> str:
        """
        Substitute runtime context variables: {variable_name}.

        Args:
            template: Template string.
            context: Variable context.
            dut_id: DUT ID.
            validate_types: Whether to validate types.
            allow_missing: Whether to allow missing variables.

        Returns:
            Template with runtime variables substituted.
        """
        # Find all runtime variables in the template
        variables = self._extract_variables(template)
        await self._log("DEBUG", f"Found runtime variables: {variables}", dut_id)

        # Validate variables if requested
        if validate_types:
            self._validate_variables(variables, context)

        result = template
        missing_vars = []

        for var_name in variables:
            if var_name in context:
                value = context[var_name]
                # Convert value to string and escape any special characters
                str_value = self._format_value(value)
                result = result.replace(f"{{{var_name}}}", str_value)
                await self._log(
                    "DEBUG",
                    f"Substituted {{{var_name}}} with {str_value}",
                    dut_id,
                )
            else:
                missing_vars.append(var_name)
                if not allow_missing:
                    raise VariableSubstitutionError(
                        f"Missing required variable: {var_name}"
                    )
                else:
                    await self._log(
                        "WARNING",
                        f"Missing variable {var_name}, keeping as-is",
                        dut_id,
                    )

        return result

    def _extract_variables(self, template: str) -> Set[str]:
        """
        Extract all variable names from a template string.

        Args:
            template: Template string to parse.

        Returns:
            Set of variable names found in the template.
        """
        variables = set()
        for match in self.variable_pattern.finditer(template):
            variables.add(match.group(1))
        return variables

    def _validate_variables(self, variables: Set[str], context: Dict[str, Any]) -> None:
        """
        Validate variable types and values.

        Args:
            variables: Set of variable names to validate
            context: Context containing variable values

        Raises:
            VariableSubstitutionError: If validation fails
        """
        for var_name in variables:
            if var_name in context:
                value = context[var_name]

                # Check if we have a type definition for this variable
                if var_name in self.variable_types:
                    pattern = self.variable_types[var_name]
                    str_value = str(value)
                    if not re.match(pattern, str_value):
                        raise VariableSubstitutionError(
                            f"Variable {var_name} value '{str_value}' does not match expected pattern: {pattern}"
                        )

                # Validate basic type if it's a known type
                if isinstance(value, (int, float, str, bool)):
                    # Basic type validation passed
                    pass
                elif value is None:
                    raise VariableSubstitutionError(
                        f"Variable {var_name} cannot be None"
                    )
                else:
                    # For complex types, try to convert to string
                    try:
                        str(value)
                    except Exception as e:
                        raise VariableSubstitutionError(
                            f"Variable {var_name} cannot be converted to string: {e}"
                        )

    def _format_value(self, value: Any) -> str:
        """
        Format a value for substitution, handling different types.

        Args:
            value: Value to format.

        Returns:
            Formatted string representation of the value.
        """
        if value is None:
            return ""
        elif isinstance(value, (int, float)):
            return str(value)
        elif isinstance(value, bool):
            return str(value).lower()
        elif isinstance(value, str):
            return value
        else:
            # For complex types, convert to string
            return str(value)

    async def _handle_nested_substitution(
        self,
        template: str,
        context: Dict[str, Any],
        dut_id: str,
        validate_types: bool,
        allow_missing: bool,
        max_depth: int = 10,
    ) -> str:
        """
        Handle nested variable substitution (variables within variables).

        Args:
            template: Template string to process
            context: Context dictionary
            dut_id: DUT ID for logging
            validate_types: Whether to validate variable types
            allow_missing: Whether to allow missing variables
            max_depth: Maximum nesting depth to prevent infinite loops

        Returns:
            String with nested variables resolved
        """
        result = template
        depth = 0
        previous_result = None

        while depth < max_depth:
            # Check if there are any remaining variables
            remaining_vars = self._extract_variables(result)
            if not remaining_vars:
                break

            # Store previous result to detect if anything changed
            previous_result = result

            # Perform one level of substitution by calling individual methods directly
            # to avoid infinite recursion
            result = await self._substitute_config_variables(
                result, context, dut_id, allow_missing
            )
            result = await self._substitute_env_variables(result, dut_id, allow_missing)
            result = await self._substitute_dut_variables(result, dut_id, allow_missing)
            result = await self._substitute_runtime_variables(
                result, context, dut_id, validate_types, allow_missing
            )

            depth += 1

            await self._log(
                "DEBUG",
                f"Nested substitution depth {depth}: {result[:100]}...",
                dut_id,
            )

            # If result hasn't changed, no more substitutions can be made
            if result == previous_result:
                break

        if depth >= max_depth:
            await self._log(
                "WARNING",
                f"Maximum nested substitution depth ({max_depth}) reached",
                dut_id,
            )

        return result

    def _generate_cache_key(self, template: str, context: Dict[str, Any]) -> str:
        """
        Generate a cache key for the template and context combination.

        Args:
            template: Template string.
            context: Variable context.

        Returns:
            Cache key string.
        """
        # Create a sorted string representation of the context
        context_str = str(sorted(context.items()))
        return f"{hash(template)}:{hash(context_str)}"

    def _cache_result(self, cache_key: str, result: str) -> None:
        """
        Cache a substitution result.

        Args:
            cache_key: Cache key.
            result: Result to cache.
        """
        if len(self.substitution_cache) >= self.cache_size:
            # Remove oldest entry (simple FIFO)
            oldest_key = next(iter(self.substitution_cache))
            del self.substitution_cache[oldest_key]

        self.substitution_cache[cache_key] = result

    async def get_cache_stats(self, dut_id: str = None) -> Dict[str, Any]:
        """
        Get cache statistics.

        Args:
            dut_id: Optional DUT ID for logging.

        Returns:
            Dictionary containing cache statistics.
        """
        stats = {
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_size": len(self.substitution_cache),
            "max_cache_size": self.cache_size,
            "hit_ratio": (
                self.cache_hits / (self.cache_hits + self.cache_misses)
                if (self.cache_hits + self.cache_misses) > 0
                else 0
            ),
        }
        await self._log("INFO", f"Cache stats: {stats}", dut_id)
        return stats

    async def clear_cache(self, dut_id: str = None) -> None:
        """
        Clear the substitution cache.

        Args:
            dut_id: Optional DUT ID for logging.
        """
        self.substitution_cache.clear()
        self.cache_hits = 0
        self.cache_misses = 0
        await self._log("INFO", "Variable substitution cache cleared", dut_id)

    async def add_variable_type(
        self, var_name: str, pattern: str, dut_id: str = None
    ) -> None:
        """
        Add a new variable type with validation pattern.

        Args:
            var_name: Name of the variable type
            pattern: Regex pattern for validation
            dut_id: DUT ID for logging
        """
        self.variable_types[var_name] = pattern
        await self._log(
            "DEBUG",
            f"Added variable type: {var_name} with pattern: {pattern}",
            dut_id,
        )

    def get_supported_variables(self) -> Set[str]:
        """
        Get the set of supported variable names.

        Returns:
            Set of supported variable names.
        """
        return set(self.variable_types.keys())

    async def validate_context(
        self, context: Dict[str, Any], dut_id: str = None
    ) -> Dict[str, List[str]]:
        """
        Validate a context dictionary against supported variables.

        Args:
            context: Context dictionary to validate
            dut_id: DUT ID for logging

        Returns:
            Dictionary with 'valid' and 'invalid' variable lists
        """
        valid_vars = []
        invalid_vars = []

        for var_name, value in context.items():
            if var_name in self.variable_types:
                pattern = self.variable_types[var_name]
                str_value = str(value)
                if re.match(pattern, str_value):
                    valid_vars.append(var_name)
                else:
                    invalid_vars.append(var_name)
            else:
                # Unknown variable type - consider it valid but log warning
                await self._log("WARNING", f"Unknown variable type: {var_name}", dut_id)
                valid_vars.append(var_name)

        return {"valid": valid_vars, "invalid": invalid_vars}


# Backward compatibility - keep the old class name for existing code
VariableSubstitutionEngine = VariableSubstitutionService
