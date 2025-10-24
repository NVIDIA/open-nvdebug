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
YAML validation utility for NVDebug Tool.

Provides helpful error messages for common YAML syntax issues including
indentation problems, quote mismatches, and structural errors.
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .yaml_manager import YAMLManager


class YAMLValidator:
    """
    Validates YAML files and provides helpful error messages.

    Provides static methods for validating YAML syntax, structure, and
    DUT configuration specific validation.
    """

    @staticmethod
    def validate_file(file_path: str) -> Tuple[bool, str]:
        """
        Validate a YAML file and return (is_valid, message)

        Args:
            file_path: Path to the YAML file to validate

        Returns:
            Tuple of (is_valid, message)
        """
        try:
            # Use YAMLManager to load and validate
            data = YAMLManager.load_yaml(file_path, "YAML file")

            # Validate structure
            validation_msg = YAMLValidator._validate_structure(data, file_path)

            return True, f"✅ YAML file is valid!\n{validation_msg}"

        except ValueError as e:
            return False, f"❌ YAML validation error:\n{str(e)}"
        except Exception as e:
            return False, f"❌ Error reading file: {str(e)}"

    @staticmethod
    def _format_yaml_error(yaml_error) -> str:
        """
        Format YAML error messages to be more user-friendly.

        Args:
            yaml_error: YAML error to format.

        Returns:
            Formatted error message.

        Note:
            Deprecated - use YAMLManager._format_yaml_error instead.
        """
        # This method is now deprecated - use YAMLManager._format_yaml_error instead
        return YAMLManager._format_yaml_error(yaml_error)

    @staticmethod
    def _validate_structure(data: Any, file_path: str) -> str:
        """
        Validate YAML structure and return validation message.

        Args:
            data: Parsed YAML data.
            file_path: Path to YAML file.

        Returns:
            Validation message string.
        """
        if not isinstance(data, dict):
            return "⚠️  Warning: Root element is not a mapping (dictionary)"

        if not data:
            return "⚠️  Warning: YAML file is empty"

        # Check for DUT configuration specific structure
        if "DUT_Defaults" in data or any("DUT" in key for key in data.keys()):
            return YAMLValidator._validate_dut_config(data)

        return f"✅ Valid YAML structure. Found {len(data)} top-level keys."

    @staticmethod
    def _validate_dut_config(data: Dict[str, Any]) -> str:
        """
        Validate DUT configuration specific structure.

        Args:
            data: DUT configuration data.

        Returns:
            Validation message string.
        """
        messages = []

        # Use YAMLManager for validation
        is_valid, issues = YAMLManager.validate_dut_config(data)

        # Check for DUT_Defaults
        if YAMLManager.has_dut_defaults(data):
            messages.append("✅ DUT_Defaults section found")
        else:
            messages.append(
                "⚠️  No DUT_Defaults section found (optional but recommended)"
            )

        # Count DUTs
        dut_count = YAMLManager.get_dut_count(data)
        dut_names = YAMLManager.get_dut_names(data)
        if dut_count > 0:
            messages.append(
                f"✅ Found {dut_count} DUT(s): {', '.join(dut_names[:5])}{'...' if dut_count > 5 else ''}"
            )
        else:
            messages.append("❌ No DUT configurations found")

        # Report validation issues
        if issues:
            messages.append(
                f"⚠️  Issues found:\n" + "\n".join(f"  - {issue}" for issue in issues)
            )

        return "\n".join(messages)


def main():
    """
    Command-line interface for YAML validation.

    Usage:
        python yaml_validator.py <yaml_file>
    """
    if len(sys.argv) != 2:
        print("Usage: python yaml_validator.py <yaml_file>")
        print("Example: python yaml_validator.py logs/test_multi_dut_config.yaml")
        sys.exit(1)

    file_path = sys.argv[1]
    is_valid, message = YAMLValidator.validate_file(file_path)

    print(f"\nValidating: {file_path}")
    print("=" * 50)
    print(message)
    print("=" * 50)

    if not is_valid:
        sys.exit(1)


if __name__ == "__main__":
    main()
