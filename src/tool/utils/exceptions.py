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
Exception classes for NVDebug Tool.

This module defines custom exceptions used throughout the NVDebug tool
for error handling and reporting.
"""


class NVDebugError(Exception):
    """
    Base exception for NVDebug tool.

    All custom exceptions in the tool inherit from this class.
    """

    pass


class ConfigurationError(NVDebugError):
    """
    Configuration-related errors.

    Raised when configuration loading or validation fails.
    """

    pass


class ValidationError(NVDebugError):
    """
    Validation errors.

    Raised when input validation or data validation fails.
    """

    pass


class ExecutionError(NVDebugError):
    """
    Execution errors.

    Raised when command or operation execution fails.
    """

    pass


class ConnectionError(NVDebugError):
    """
    Connection-related errors.

    Raised when network connections or remote connections fail.
    """

    pass


class AuthenticationError(NVDebugError):
    """
    Authentication errors.

    Raised when authentication to remote systems fails.
    """

    pass


class CollectorError(NVDebugError):
    """
    Collector-related errors.

    Raised when log collection operations fail.
    """

    pass


class StateMachineError(NVDebugError):
    """
    State machine errors.

    Raised when state transitions or state management fails.
    """

    pass


class ParserError(NVDebugError):
    """
    Parser errors.

    Raised when parsing of logs or binary files fails.
    """

    pass


class OutputError(NVDebugError):
    """
    Output generation errors.

    Raised when output file generation or formatting fails.
    """

    pass


class TimeoutError(NVDebugError):
    """
    Timeout errors.

    Raised when operations exceed configured timeout limits.
    """

    pass


class DependencyError(NVDebugError):
    """
    Dependency errors.

    Raised when required dependencies are missing or invalid.
    """

    pass
