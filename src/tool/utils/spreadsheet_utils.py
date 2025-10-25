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
Spreadsheet utility functions for the NVDebug tool.

Provides utilities for auto-detecting and working with collector definition
spreadsheets including the Telemetry Catalog.
"""

from pathlib import Path
from typing import Optional

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .console_output import create_sanitized_console


def auto_detect_spreadsheet(
    spreadsheet: Optional[Path], suppress_print: bool = False
) -> Optional[Path]:
    """
    Auto-detect the latest Telemetry Catalog spreadsheet in config directory.

    Uses version number parsing (e.g., v3.15.1 > v3.15) to find the highest version.

    Args:
        spreadsheet: Optional path to a spreadsheet
        suppress_print: Whether to suppress print statements
    """
    if spreadsheet:
        return spreadsheet

    # Try to find the latest spreadsheet in config directory
    config_dir = Path("config")
    if config_dir.exists():
        # Look for the latest Telemetry Catalog spreadsheet
        spreadsheet_files = list(config_dir.glob("Telemetry_Catalog_*.xlsx"))
        if spreadsheet_files:
            import re

            # Pattern to match: Telemetry_Catalog_v{major}.{minor}.{patch}.xlsx
            pattern = re.compile(r"Telemetry_Catalog_v(\d+)\.(\d+)\.(\d+)\.xlsx")

            versioned_files = []
            unversioned_files = []

            for file in spreadsheet_files:
                match = pattern.match(file.name)
                if match:
                    major, minor, patch = map(int, match.groups())
                    versioned_files.append((major, minor, patch, file))
                else:
                    # Try simpler pattern: v{major}.{minor}
                    simple_pattern = re.compile(
                        r"Telemetry_Catalog_v(\d+)\.(\d+)\.xlsx"
                    )
                    simple_match = simple_pattern.match(file.name)
                    if simple_match:
                        major, minor = map(int, simple_match.groups())
                        versioned_files.append((major, minor, 0, file))
                    else:
                        unversioned_files.append(file)

            # Use highest version if versioned files exist
            if versioned_files:
                versioned_files.sort(reverse=True)
                latest_spreadsheet = versioned_files[0][3]
                version = latest_spreadsheet.stem.replace("Telemetry_Catalog_", "")
            else:
                # Fallback to modification time for unversioned files
                latest_spreadsheet = max(
                    unversioned_files, key=lambda p: p.stat().st_mtime
                )
                version = latest_spreadsheet.stem.replace("Telemetry_Catalog_", "")

            if not suppress_print:
                sanitized_console = create_sanitized_console()
                sanitized_console.print_info(
                    f"Detected Telemetry Catalog {version} in config directory. Auto-loading..."
                )
            return latest_spreadsheet

    return None


def validate_spreadsheet_requirement(spreadsheet: Optional[Path]) -> None:
    """
    Validate that a valid spreadsheet is available (always required in spreadsheet-only mode).

    Args:
        spreadsheet: Optional path to a spreadsheet
    """
    if not spreadsheet or not spreadsheet.exists():
        show_spreadsheet_requirement_message()
        import sys

        sys.exit(1)


def show_spreadsheet_requirement_message() -> None:
    """
    Display a beautiful rich console message about spreadsheet requirements.

    Args:
        None
    """
    sanitized_console = create_sanitized_console()

    # Create the main message
    title = Text("📊 Telemetry Catalog Spreadsheet Required", style="bold blue")

    # Create detailed message
    message = Text()
    message.append(
        "The nvdebugtool requires a Telemetry Catalog spreadsheet to function.\n\n",
        style="white",
    )

    message.append("🔍 ", style="yellow")
    message.append("Auto-detection: ", style="bold")
    message.append(
        "The tool will automatically look for spreadsheets in the 'config' directory.\n",
        style="white",
    )

    message.append("📁 ", style="yellow")
    message.append("Expected location: ", style="bold")
    message.append("config/Telemetry_Catalog_*.xlsx\n", style="cyan")

    message.append("⚙️ ", style="yellow")
    message.append(" Manual specification: ", style="bold")
    message.append(
        "Use the --spreadsheet argument to specify a custom path.\n\n",
        style="white",
    )

    message.append("💡 ", style="green")
    message.append("Example usage:\n", style="bold")
    message.append(
        "  nvdebug collect --spreadsheet /path/to/Telemetry_Catalog_*.xlsx\n",
        style="cyan",
    )
    message.append(
        "  nvdebug list-collectors --spreadsheet config/Telemetry_Catalog_*.xlsx\n",
        style="cyan",
    )
    message.append(
        "  nvdebug list-baseboards --spreadsheet config/Telemetry_Catalog_*.xlsx\n\n",
        style="cyan",
    )

    message.append("❓ ", style="red")
    message.append(
        "If you don't have a Telemetry Catalog spreadsheet, please contact your system administrator.",
        style="white",
    )

    # Create a table with available commands
    table = Table(
        title="Commands that require --spreadsheet",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Command", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")
    table.add_column("Example", style="green")

    table.add_row(
        "collect",
        "Collect logs and debug information",
        "nvdebug collect --spreadsheet config/Telemetry_Catalog_*.xlsx",
    )
    table.add_row(
        "list-collectors",
        "List available collectors",
        "nvdebug list-collectors --spreadsheet config/Telemetry_Catalog_*.xlsx",
    )
    table.add_row(
        "list-baseboards",
        "List available baseboards",
        "nvdebug list-baseboards --spreadsheet config/Telemetry_Catalog_*.xlsx",
    )
    table.add_row(
        "default-collectors",
        "Show default collectors for a baseboard",
        "nvdebug default-collectors --baseboard 'GB200 NVL' --spreadsheet config/Telemetry_Catalog_*.xlsx",
    )
    table.add_row(
        "preflight",
        "Run preflight checks",
        "nvdebug preflight --spreadsheet config/Telemetry_Catalog_*.xlsx",
    )

    # Display the panel and table
    sanitized_console.print(
        Panel(message, title=title, border_style="blue", padding=(1, 2))
    )
    sanitized_console.print(table)
    sanitized_console.print("\n")
