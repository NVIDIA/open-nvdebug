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
Utils module for NVDebug Tool.

This module provides utility functions and classes for the NVDebug tool including:
    - Configuration variable resolution
    - Console output and sanitization
    - Constants and enumerations
    - Dependency checking
    - File and JSON utilities
    - Logging setup
    - Resource management
    - YAML processing and validation
    - Variable substitution
    - Timing management
    - URI configuration
"""

# Import all utility modules and their public functions/classes
from . import (
    config_variable_resolver,
    console_output,
    constants,
    dependency_checker,
    enums,
    exceptions,
    file_utils,
    json_utils,
    logging,
    resource_manager,
    resources,
    sanitizer,
    timing_manager,
    uri_config_manager,
    variable_substitution,
    yaml_manager,
    yaml_validator,
)

# Import specific functions and classes for easier access
from .config_variable_resolver import (
    ConfigurationVariableResolver as ConfigVariableResolver,
)
from .console_output import SanitizedConsole as ConsoleOutput
from .constants import *
from .dependency_checker import DependencyChecker
from .enums import (
    CollectionLevel,
    CollectorServiceMapping,
    DutExecutionMode,
    DutNodeType,
    NetworkType,
    PreflightChecks,
    RedfishHmcAccess,
    get_main_preflight_names,
    get_preflight_enum_from_service,
)
from .exceptions import *
from .file_utils import (
    cleanup_empty_directories,
    ensure_directory_exists,
    get_collector_group_from_id,
    is_directory_empty,
)
from .json_utils import process_value_for_json, safe_json_dump, safe_json_dumps
from .logging import setup_logging
from .resource_manager import (
    ResourceManager,
    get_platforms_resource,
    get_tool_resource,
    get_tool_resource_content,
)
from .sanitizer import LogSanitizer as Sanitizer
from .timing_manager import TimingManager
from .uri_config_manager import URIConfigManager as UriConfigManager
from .variable_substitution import VariableSubstitutionService as VariableSubstitution
from .yaml_manager import YAMLManager as YamlManager
from .yaml_validator import YAMLValidator as YamlValidator

__all__ = [
    # Modules
    "config_variable_resolver",
    "console_output",
    "constants",
    "dependency_checker",
    "enums",
    "exceptions",
    "file_utils",
    "json_utils",
    "logging",
    "resource_manager",
    "resources",
    "sanitizer",
    "timing_manager",
    "uri_config_manager",
    "variable_substitution",
    "yaml_manager",
    "yaml_validator",
    # Classes
    "ConfigVariableResolver",
    "ConsoleOutput",
    "DependencyChecker",
    "ResourceManager",
    "Sanitizer",
    "TimingManager",
    "UriConfigManager",
    "VariableSubstitution",
    "YamlManager",
    "YamlValidator",
    # Enums
    "CollectionLevel",
    "CollectorServiceMapping",
    "DutExecutionMode",
    "DutNodeType",
    "NetworkType",
    "PreflightChecks",
    "RedfishHmcAccess",
    # Functions
    "cleanup_empty_directories",
    "ensure_directory_exists",
    "get_collector_group_from_id",
    "get_main_preflight_names",
    "get_preflight_enum_from_service",
    "get_platforms_resource",
    "get_tool_resource",
    "get_tool_resource_content",
    "is_directory_empty",
    "process_value_for_json",
    "safe_json_dump",
    "safe_json_dumps",
    "setup_logging",
]
