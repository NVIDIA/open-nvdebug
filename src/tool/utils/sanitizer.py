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
Log Sanitizer for NVDebug Tool.

Handles sanitization of sensitive data in logs and console output including
IP addresses, MAC addresses, credentials, and custom patterns.
"""

import logging
import re
from enum import Enum
from typing import Any, Dict, List, Optional


class BuiltInSanitizers(Enum):
    """
    Built-in sanitizer patterns.

    Defines standard patterns for common sensitive data types.

    Attributes:
        IPV4: IPv4 address pattern.
        IPV6: IPv6 address pattern.
        MAC_ADDRESS: MAC address pattern.
        SERIAL_NUMBER: Serial number pattern.
        PART_NUMBER: Part number pattern.
        CREDENTIALS: Credential key-value pairs.
        API_KEYS: API key patterns.
        TOKENS: Bearer token patterns.
    """

    IPV4 = "ipv4_address"
    IPV6 = "ipv6_address"
    MAC_ADDRESS = "mac_address"
    SERIAL_NUMBER = "serial_number"
    PART_NUMBER = "part_number"
    CREDENTIALS = "credentials"
    API_KEYS = "api_keys"
    TOKENS = "tokens"


class LogSanitizer(logging.Formatter):
    """
    Comprehensive log sanitizer that removes sensitive information.

    Extends logging.Formatter to provide automatic sanitization of sensitive
    data in log messages using configurable patterns.

    Attributes:
        enabled (bool): Whether sanitization is enabled.
        replacement (str): Replacement string for sensitive data.
        compiled_regex: Compiled regex pattern for matching.
    """

    # Built-in regex patterns for common sensitive data
    builtin_regex = {
        BuiltInSanitizers.IPV4: r"\b((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b",
        BuiltInSanitizers.IPV6: r"\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b",
        BuiltInSanitizers.MAC_ADDRESS: r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b",
        BuiltInSanitizers.SERIAL_NUMBER: r"\b[A-Z0-9]{8,20}\b",  # Common serial number patterns
        BuiltInSanitizers.PART_NUMBER: r"\b[A-Z0-9\-]{8,25}\b(?!\s+(?:NVL|GPU|HGX|MGX|DC|PowerShelf))",  # Common part number patterns, but exclude baseboard names
        BuiltInSanitizers.CREDENTIALS: r"\b(password|passwd|pwd|secret|key|token|auth|credential)\s*[=:]\s*[^\s,;}\]\n]+\b",
        BuiltInSanitizers.API_KEYS: r"\b(api_key|apikey|access_key|secret_key)\s*[=:]\s*[A-Za-z0-9+/]{20,}\b",
        BuiltInSanitizers.TOKENS: r"\b(bearer|token)\s+[A-Za-z0-9\-._~+/]+=*\b",
    }

    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        style: str = "%",
        string_list: Optional[List[str]] = None,
        replacement_string: str = "XXXX",
        additional_regex: Optional[List[BuiltInSanitizers]] = None,
        enabled: bool = True,
    ):
        """
        Initialize the sanitizer

        Args:
            fmt: Log format string
            datefmt: Date format string
            style: Format style ('%', '{', or '$')
            string_list: List of specific strings to sanitize
            replacement_string: String to replace sensitive data
            additional_regex: List of built-in sanitizers to use
            enabled: Whether sanitization is enabled
        """
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)

        self.enabled = enabled
        self.replacement = replacement_string
        self.compiled_regex = None

        if not enabled:
            return

        # Build regex patterns
        patterns = []

        # Add specific strings to sanitize
        if string_list:
            for string in string_list:
                if string:
                    escaped = re.escape(string)
                    # Use word boundaries only if the string starts/ends with
                    # word characters; otherwise use the raw escaped pattern
                    # so passwords with special chars (@ ! # $) are matched.
                    start = r"\b" if re.match(r"\w", string) else ""
                    end = r"\b" if re.search(r"\w$", string) else ""
                    patterns.append(f"{start}{escaped}{end}")

        # Add built-in patterns
        if additional_regex:
            for sanitizer in additional_regex:
                if sanitizer in self.builtin_regex:
                    patterns.append(self.builtin_regex[sanitizer])

        # Compile the combined regex
        if patterns:
            self.compiled_regex = re.compile(
                "|".join(patterns), flags=re.IGNORECASE | re.MULTILINE
            )

    def sanitize(self, text: str) -> str:
        """
        Sanitize a string by replacing sensitive data

        Args:
            text: Text to sanitize

        Returns:
            Sanitized text
        """
        if not self.enabled or not self.compiled_regex or not text:
            return text

        return self.compiled_regex.sub(self.replacement, text)

    def format(self, record: logging.LogRecord) -> str:
        """
        Override format to sanitize log messages.

        Args:
            record (logging.LogRecord): Log record to format.

        Returns:
            str: Sanitized formatted log message.
        """
        if not self.enabled:
            return super().format(record)

        # Sanitize the message
        if hasattr(record, "msg") and record.msg:
            record.msg = self.sanitize(str(record.msg))

        # Sanitize the formatted string
        formatted = super().format(record)
        return self.sanitize(formatted)


class SanitizedPrinter:
    """
    Wrapper for print() that sanitizes output.

    Intercepts print calls and sanitizes arguments before outputting.

    Attributes:
        sanitizer (LogSanitizer): Sanitizer instance.
        original_print: Original print function.
    """

    def __init__(self, sanitizer: LogSanitizer):
        """
        Initialize sanitized printer.

        Args:
            sanitizer (LogSanitizer): Sanitizer to use for output.
        """
        self.sanitizer = sanitizer
        self.original_print = print

    def __call__(self, *args, **kwargs):
        """
        Sanitize and print arguments.

        Args:
            *args: Arguments to print.
            **kwargs: Keyword arguments for print function.
        """
        if not self.sanitizer.enabled:
            self.original_print(*args, **kwargs)
            return

        # Convert all arguments to strings and sanitize them
        sanitized_args = []
        for arg in args:
            sanitized_args.append(self.sanitizer.sanitize(str(arg)))

        self.original_print(*sanitized_args, **kwargs)


def extract_sensitive_fields_from_dut_config(
    dut_config: Dict[str, Any],
) -> List[str]:
    """
    Extract sensitive fields from DUT configuration

    Args:
        dut_config: DUT configuration dictionary

    Returns:
        List of sensitive values to sanitize
    """
    sensitive_fields = [
        "BMC_IP",
        "BMC_USERNAME",
        "BMC_PASSWORD",
        "HOST_IP",
        "HOST_USERNAME",
        "HOST_PASSWORD",
        "RF_User",
        "RF_Pass",
        "BMC_SSH_USERNAME",
        "BMC_SSH_PASSWORD",
        "HOST_SSH_USERNAME",
        "HOST_SSH_PASSWORD",
        "SSH_PROXY_USERNAME",
        "SSH_PROXY_PASSWORD",
        "HMC_IP",
        "HMC_USERNAME",
        "HMC_PASSWORD",
        "HMC_SSH_USERNAME",
        "HMC_SSH_PASSWORD",
        "hmc_user",
        "hmc_pass",
        "hmc_ssh_user",
        "hmc_ssh_pass",
        "hmc_username",
        "hmc_password",
        "hmc_ssh_username",
        "hmc_ssh_password",
        "SSH_PROXY_HOST",
        "ssh_proxy_host",
        "ssh_proxy_user",
        "ssh_proxy_pass",
        "ssh_proxy_username",
        "ssh_proxy_password",
        "serial_number",
        "part_number",
        # "baseboard",  # Removed - baseboard names are not sensitive
        "PlatformModel",
        "PartNumber",
        "SerialNumber",
    ]

    sensitive_values = []

    def extract_from_dict(data: Any, prefix: str = "") -> None:
        """
        Recursively extract sensitive values from nested dictionaries.

        Args:
            data: Data to extract from.
            prefix: Key prefix for nested paths.
        """
        if isinstance(data, dict):
            for key, value in data.items():
                current_key = f"{prefix}.{key}" if prefix else key

                # Check if this is a sensitive field
                if any(field.lower() in key.lower() for field in sensitive_fields):
                    if isinstance(value, (str, int)) and value:
                        sensitive_values.append(str(value))

                # Recursively check nested structures
                extract_from_dict(value, current_key)
        elif isinstance(data, list):
            for item in data:
                extract_from_dict(item, prefix)

    extract_from_dict(dut_config)
    return sensitive_values


def create_sanitizer_from_config(
    dut_config: Dict[str, Any],
    enabled: bool = True,
    additional_regex: Optional[List[BuiltInSanitizers]] = None,
    extra_strings: Optional[List[str]] = None,
) -> LogSanitizer:
    """
    Create a sanitizer configured for the given DUT configuration

    Args:
        dut_config: DUT configuration
        enabled: Whether sanitization is enabled
        additional_regex: Additional built-in sanitizers to use
        extra_strings: Extra strings to sanitize

    Returns:
        Configured LogSanitizer
    """
    if not enabled:
        return LogSanitizer(enabled=False)

    # Extract sensitive values from DUT config
    sensitive_values = extract_sensitive_fields_from_dut_config(dut_config)

    # Add extra strings
    if extra_strings:
        sensitive_values.extend(extra_strings)

    # Default built-in sanitizers
    if additional_regex is None:
        additional_regex = [
            BuiltInSanitizers.IPV4,
            BuiltInSanitizers.IPV6,
            BuiltInSanitizers.MAC_ADDRESS,
            BuiltInSanitizers.CREDENTIALS,
            BuiltInSanitizers.API_KEYS,
            BuiltInSanitizers.TOKENS,
        ]

    return LogSanitizer(
        string_list=sensitive_values,
        additional_regex=additional_regex,
        enabled=enabled,
    )


def patch_print_with_sanitizer(sanitizer: LogSanitizer) -> None:
    """
    Patch the global print function to use sanitization

    Args:
        sanitizer: Sanitizer to use
    """
    import builtins

    builtins.print = SanitizedPrinter(sanitizer)


# ----------------------------
# Config file sanitization
# ----------------------------
_CONFIG_CRED_KEY_RE = re.compile(
    # Match YAML/INI-ish "key: value" or "key = value" where key contains credential-ish tokens.
    # We intentionally do NOT require word boundaries so identifiers like "BMC_USERNAME" match.
    r"(?im)^(\s*[^#\n:=]*"
    r"(?:password|passwd|pwd|secret|token|auth|credential|api[_-]?key|access[_-]?key|secret[_-]?key|user|username)"
    r"[^#\n:=]*\s*[:=]\s*)([^\n#]+)"
)

_IPV4_RE = re.compile(LogSanitizer.builtin_regex[BuiltInSanitizers.IPV4])
_IPV6_RE = re.compile(LogSanitizer.builtin_regex[BuiltInSanitizers.IPV6])


def sanitize_config_text(text: str, replacement: str = "XXXX") -> str:
    """
    Sanitize config *text* while preserving structure.

    - Redacts values of any lines whose *key* contains user/password/token/etc (case-insensitive)
      while preserving the key portion.
    - Redacts IPv4/IPv6 addresses anywhere in the text.

    This is intended for archiving `dut_config.yaml` / `tool_config.yaml` into run directories.
    """
    if not text:
        return text

    # Redact credential-ish key/value lines but preserve the key
    text = _CONFIG_CRED_KEY_RE.sub(rf"\1{replacement}", text)

    # Redact IPs anywhere (including inside URLs)
    text = _IPV4_RE.sub(replacement, text)
    text = _IPV6_RE.sub(replacement, text)
    return text
