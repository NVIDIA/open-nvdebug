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
Console Output Utilities for NVDebug Tool.

Provides standardized sanitized console output functionality using Rich console
with automatic data sanitization.
"""

from typing import Optional

from rich.console import Console
from rich.text import Text

from .sanitizer import LogSanitizer


class SanitizedConsole:
    """
    Provides sanitized console output functionality.

    Wraps Rich Console to provide color-coded output with automatic
    sanitization of sensitive data.

    Attributes:
        console (Console): Rich console instance.
        sanitizer (Optional[LogSanitizer]): Sanitizer for output.
    """

    def __init__(self, sanitizer: Optional[LogSanitizer] = None):
        """
        Initialize sanitized console.

        Args:
            sanitizer (Optional[LogSanitizer]): Sanitizer instance.
        """
        self.console = Console()
        self.sanitizer = sanitizer

    def print(self, text: str, style: str = "") -> None:
        """
        Print sanitized text to console with optional styling.

        Args:
            text (str): Text to print.
            style (str): Rich style string.
        """
        if self.sanitizer:
            sanitized_text = self.sanitizer.sanitize(text)
            self.console.print(sanitized_text, style=style)
        else:
            self.console.print(text, style=style)

    def print_separator(
        self, char: str = "=", length: int = 80, style: str = "bold blue"
    ) -> None:
        """
        Print a separator line.

        Args:
            char (str): Character for separator.
            length (int): Length of separator.
            style (str): Rich style string.
        """
        separator = char * length
        self.print(separator, style)

    def print_header(self, text: str, style: str = "bold blue") -> None:
        """
        Print a header with consistent formatting.

        Args:
            text (str): Header text.
            style (str): Rich style string.
        """
        self.print(text, style)

    def print_success(self, text: str) -> None:
        """
        Print success message in green.

        Args:
            text (str): Success message.
        """
        self.print(text, "bold green")

    def print_warning(self, text: str) -> None:
        """
        Print warning message in yellow.

        Args:
            text (str): Warning message.
        """
        self.print(text, "bold yellow")

    def print_error(self, text: str) -> None:
        """
        Print error message in red.

        Args:
            text (str): Error message.
        """
        self.print(text, "bold red")

    def print_info(self, text: str) -> None:
        """
        Print info message in blue.

        Args:
            text (str): Info message.
        """
        self.print(text, "bold blue")

    def print_debug(self, text: str) -> None:
        """
        Print debug message in dim white.

        Args:
            text (str): Debug message.
        """
        self.print(text, "dim white")


def create_sanitized_console(
    sanitizer: Optional[LogSanitizer] = None,
) -> SanitizedConsole:
    """
    Factory function to create a sanitized console instance.

    Args:
        sanitizer (Optional[LogSanitizer]): Sanitizer instance.

    Returns:
        SanitizedConsole: New sanitized console instance.
    """
    return SanitizedConsole(sanitizer)
