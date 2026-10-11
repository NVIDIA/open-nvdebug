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
spreadsheets including the Telemetry Catalog. Frozen executables deliberately
retain the source workflow's relocatable catalog lookup instead of requiring a
catalog beside the binary.
"""

import base64
import gzip
import io
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .console_output import create_sanitized_console
from .frozen_path import get_base_path, is_frozen

_logger = logging.getLogger(__name__)

# Excel stores at most 32,767 characters per cell. Large collector fields
# (notably the Stages JSON for command-heavy collectors like S18) exceed this
# and get silently truncated on write, producing unparseable JSON. To keep the
# catalog self-sufficient — the generated YAML is NOT shipped to customers, so
# the spreadsheet must round-trip on its own — oversized cells are stored
# gzip+base64 encoded behind a sentinel prefix.
EXCEL_CELL_CHAR_LIMIT = 32767
_GZIP_CELL_PREFIX = "gzip+base64:"
MAX_DECODED_CELL_BYTES = 16 * 1024 * 1024


def encode_long_cell(text: str, limit: int = EXCEL_CELL_CHAR_LIMIT) -> str:
    """
    Encode long cell.

    A GZIP header normally embeds the current time. These values are stored
    inside the tracked XLSX catalog, so that timestamp made identical YAML
    inputs produce different workbook bytes on every build. GzipFile with an
    empty filename also emits the portable "unknown OS" byte (255), avoiding a
    second platform-dependent header field.

    Args:
        text: Text supplied as text in the format accepted by this function.
        limit: Numeric limit used while the operation performs bounded
            accounting.

    Returns:
        The canonical long cell text.

    Raises:
        ValueError: If cell content exceeds the ``MAX_DECODED_CELL_BYTES``-byte
            decode ceiling; or the supplied input cannot be used to encode long
            cell.
    """
    if not isinstance(text, str) or len(text) <= limit:
        return text
    raw_text = text.encode("utf-8")
    if len(raw_text) > MAX_DECODED_CELL_BYTES:
        raise ValueError(
            f"Cell content exceeds the {MAX_DECODED_CELL_BYTES}-byte decode ceiling"
        )
    # A GZIP header normally embeds the current time. These values are stored
    # inside the tracked XLSX catalog, so that timestamp made identical YAML
    # inputs produce different workbook bytes on every build. GzipFile with
    # an empty filename also emits the portable "unknown OS" byte (255),
    # avoiding a second platform-dependent header field.
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=compressed, mtime=0
    ) as gzip_stream:
        gzip_stream.write(raw_text)
    encoded = _GZIP_CELL_PREFIX + base64.b64encode(compressed.getvalue()).decode(
        "ascii"
    )
    if len(encoded) > limit:
        raise ValueError(
            f"Cell content is {len(text)} chars and {len(encoded)} chars even "
            f"after compression, exceeding Excel's {limit}-char cell limit. "
            "Split the collector definition into smaller pieces."
        )
    return encoded


def decode_long_cell(value: str) -> str:
    """
    Decode long cell.

    The implementation uses ``value`` to decode long cell. Parsing or I/O must
    finish before the validated representation is made available to the caller.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. If the function cannot decode long cell, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        The canonical long cell text.

    Raises:
        ValueError: If encoded catalog cell exceeds the Excel cell limit; or
            decoded catalog cell exceeds ``MAX_DECODED_CELL_BYTES`` bytes.
    """
    if isinstance(value, str) and value.startswith(_GZIP_CELL_PREFIX):
        encoded = value[len(_GZIP_CELL_PREFIX) :]
        if len(value) > EXCEL_CELL_CHAR_LIMIT:
            raise ValueError("Encoded catalog cell exceeds the Excel cell limit")
        raw = base64.b64decode(encoded, validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as stream:
            decoded = stream.read(MAX_DECODED_CELL_BYTES + 1)
        if len(decoded) > MAX_DECODED_CELL_BYTES:
            raise ValueError(
                f"Decoded catalog cell exceeds {MAX_DECODED_CELL_BYTES} bytes"
            )
        return decoded.decode("utf-8")
    return value


def _config_search_dirs() -> list[Path]:
    """
    Return candidate config directories, ordered by priority.

    Search order:

    1. CWD/config (original behaviour).
    2. Directory containing the binary + /config (frozen mode).
    3. get_base_path()/config (frozen extraction dir).
    4. The installed package's config directory when a non-frozen invocation
       has no working-directory catalog. Packaged data must not hide an operator's
       local catalog merely because the packaged version number is higher.

    Returns:
        The validated ``dirs``.
    """
    dirs = [Path("config")]
    if is_frozen():
        binary_dir = Path(sys.argv[0]).resolve().parent / "config"
        base_dir = get_base_path() / "config"
        if binary_dir not in dirs:
            dirs.append(binary_dir)
        if base_dir not in dirs:
            dirs.append(base_dir)
    elif not any(dirs[0].glob("Telemetry_Catalog_*.xlsx")):
        packaged = Path(__file__).resolve().parents[1] / "config"
        if packaged.is_dir():
            dirs.append(packaged)
    return dirs


def auto_detect_spreadsheet(
    spreadsheet: Optional[Path], suppress_print: bool = False
) -> Optional[Path]:
    """
    Select an explicit catalog or discover the latest catalog version.

    CLI and environment selections take precedence over version-based discovery.
    Both source and frozen runtimes accept renamed or locally edited catalogs
    without comparing their contents with a release manifest. Workbook validation
    belongs to the consumers of the selected path.

    Args:
        spreadsheet: Explicit catalog path, or ``None`` to consult the environment
            and then the standard configuration directories.
        suppress_print: Whether to suppress the automatic-discovery message.

    Returns:
        The selected catalog path, or ``None`` when discovery finds no catalog.
        Explicit paths are returned without checking their existence or contents.
    """
    if spreadsheet:
        return spreadsheet

    environment_spreadsheet = os.environ.get("NVDEBUG_SPREADSHEET", "").strip()
    if environment_spreadsheet:
        return Path(environment_spreadsheet).expanduser()

    try:
        import re

        pattern_3 = re.compile(r"Telemetry_Catalog_v(\d+)\.(\d+)\.(\d+)\.xlsx")
        pattern_2 = re.compile(r"Telemetry_Catalog_v(\d+)\.(\d+)\.xlsx")

        versioned_files: list[tuple[int, int, int, Path]] = []
        unversioned_files: list[Path] = []

        for config_dir in _config_search_dirs():
            if not config_dir.exists():
                continue
            for file in config_dir.glob("Telemetry_Catalog_*.xlsx"):
                try:
                    name = file.name
                except Exception:
                    continue

                match = pattern_3.match(name)
                if match:
                    major, minor, patch = map(int, match.groups())
                    versioned_files.append((major, minor, patch, file))
                    continue
                simple_match = pattern_2.match(name)
                if simple_match:
                    major, minor = map(int, simple_match.groups())
                    versioned_files.append((major, minor, 0, file))
                else:
                    unversioned_files.append(file)

        if versioned_files:
            versioned_files.sort(reverse=True)
            latest_spreadsheet = versioned_files[0][3]
            version = latest_spreadsheet.stem.replace("Telemetry_Catalog_", "")
        elif unversioned_files:
            try:
                latest_spreadsheet = max(
                    unversioned_files, key=lambda p: p.stat().st_mtime
                )
            except Exception:
                return None
            version = latest_spreadsheet.stem.replace("Telemetry_Catalog_", "")
        else:
            return None

        if not suppress_print:
            sanitized_console = create_sanitized_console()
            sanitized_console.print_info(
                f"Detected Telemetry Catalog {version} in config directory. Auto-loading..."
            )
        return latest_spreadsheet
    except Exception:
        _logger.debug("Failed to auto-detect spreadsheet", exc_info=True)
        return None


def validate_spreadsheet_requirement(
    spreadsheet: Optional[Path],
    *,
    json_output: bool = False,
) -> None:
    """
    Validate spreadsheet requirement.

    The implementation uses ``spreadsheet`` to validate spreadsheet requirement.
    Every required invariant is checked before a successful value is returned;
    invalid input follows the function's explicit exception path.

    Args:
        spreadsheet: filesystem location used as the spreadsheet for this
            operation.
        json_output: Whether stdout is reserved for machine-readable output.

    Raises:
        SystemExit: If the function cannot validate spreadsheet requirement
            safely.
    """
    if not spreadsheet or not spreadsheet.exists():
        if json_output:
            create_sanitized_console().print_error(
                "A Telemetry Catalog spreadsheet is required. Provide "
                "--spreadsheet or install one in the config directory."
            )
        else:
            show_spreadsheet_requirement_message()
        raise SystemExit(2)


def show_spreadsheet_requirement_message() -> None:
    """
    Display a beautiful rich console message about spreadsheet requirements.

    The implementation uses current instance state to display a beautiful rich
    console message about spreadsheet requirements.
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
