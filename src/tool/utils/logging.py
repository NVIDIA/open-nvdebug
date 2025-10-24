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
Logging utilities for NVDebug Tool.

This module provides logging configuration and sanitization utilities.
"""

import logging
import logging.handlers
import re
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional, Union


def create_timestamped_log_dir(base_folder: str) -> str:
    """
    Create a timestamped directory to store all results.

    Args:
        base_folder (str): Base directory where logs will be stored.

    Returns:
        str: Path to the created directory.

    Raises:
        IOError: If directory creation fails after multiple attempts.
    """
    try:
        now = datetime.now()
        dt_string = now.strftime("%d_%m_%Y_%H_%M_%S")
        base_folder_name = "/nvdebug_logs_" + dt_string
        base_new_dir = base_folder + base_folder_name
        new_dir = base_new_dir

        for retry in range(100):
            try:
                Path(new_dir).mkdir(parents=True, exist_ok=False)
                break
            except FileExistsError:
                new_dir = f"{base_new_dir}_{retry}"
        else:
            raise IOError("Could not create log folder")

        return new_dir
    except Exception as e:
        print(f"Error creating directory: {str(e)}")
        raise


def setup_logging(
    level: Union[str, int] = "INFO",
    log_file: Optional[Union[str, Path]] = None,
    format_string: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    max_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    verbose: bool = False,
    debug: bool = False,
) -> None:
    """
    Setup logging configuration.

    Args:
        level (Union[str, int]): Logging level.
        log_file (Optional[Union[str, Path]]): Path to log file.
        format_string (str): Log format string.
        max_size (int): Maximum log file size before rotation.
        backup_count (int): Number of backup log files to keep.
        verbose (bool): Enable verbose logging.
        debug (bool): Enable debug logging.
    """
    # Convert string level to logging level
    if isinstance(level, str):
        log_level = getattr(logging, level.upper(), logging.INFO)
    else:
        log_level = level

    # Create formatter
    formatter = logging.Formatter(format_string)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Clear existing handlers
    root_logger.handlers.clear()

    # Console handler - only show errors when verbose mode is enabled
    if verbose or debug:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(log_level)
        root_logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)

        # Use rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_size,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level)
        root_logger.addHandler(file_handler)

    # Suppress noisy loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name.

    Args:
        name (str): Name of the logger.

    Returns:
        logging.Logger: Logger with the specified name.
    """
    return logging.getLogger(name)


class LogSanitizer:
    """Log sanitizer for sensitive information.

    Args:
        patterns (Optional[List[str]]): List of patterns to sanitize.
    """

    def __init__(self, patterns: Optional[List[str]] = None) -> None:
        """Initialize sanitizer with patterns.

        Args:
            patterns (Optional[List[str]]): List of patterns to sanitize.
        """
        self.patterns = patterns or []
        self._compiled_patterns: List[re.Pattern] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile regex patterns for sanitization.

        Args:
            patterns (Optional[List[str]]): List of patterns to sanitize.
        """
        # Default patterns for sensitive information with capture groups
        default_patterns = [
            r'(password["\']?\s*[:=]\s*["\']?)([^"\s]+)(["\']?)',
            r'(passwd["\']?\s*[:=]\s*["\']?)([^"\s]+)(["\']?)',
            r'(secret["\']?\s*[:=]\s*["\']?)([^"\s]+)(["\']?)',
            r'(token["\']?\s*[:=]\s*["\']?)([^"\s]+)(["\']?)',
            r'(key["\']?\s*[:=]\s*["\']?)([^"\s]+)(["\']?)',
            r'(authorization["\']?\s*[:=]\s*["\']?)([^"\s]+)(["\']?)',
            r'(api_key["\']?\s*[:=]\s*["\']?)([^"\s]+)(["\']?)',
        ]

        all_patterns = default_patterns + self.patterns

        for pattern in all_patterns:
            try:
                self._compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                # Skip invalid patterns
                continue

    def sanitize(self, message: str) -> str:
        """Sanitize a message by replacing sensitive information.

        Args:
            message (str): Message to sanitize.

        Returns:
            str: Sanitized message.
        """
        if not message:
            return message

        sanitized = message

        for pattern in self._compiled_patterns:
            # Replace the captured sensitive value with REDACTED
            # Use a function to handle the replacement properly
            def replace_func(match):
                prefix = match.group(1)
                # Extract the actual sensitive value (group 2) and any trailing quote
                sensitive_value = match.group(2)
                # Check if the sensitive value ends with a quote
                if sensitive_value and sensitive_value[-1] in ['"', "'"]:
                    suffix = sensitive_value[-1]
                    sensitive_value = sensitive_value[:-1]
                else:
                    suffix = match.group(3) if match.group(3) else ""

                return f"{prefix}XXXX{suffix}"

            sanitized = pattern.sub(replace_func, sanitized)

        return sanitized


def create_sanitized_logger(
    name: str, sanitizer: Optional[LogSanitizer] = None
) -> logging.Logger:
    """Create a logger with sanitization capabilities.

    Args:
        name (str): Name of the logger.
        sanitizer (Optional[LogSanitizer]): Sanitizer to use.

    Returns:
        logging.Logger: Logger with sanitization capabilities.
    """
    logger = get_logger(name)

    if sanitizer:
        # Create a custom handler for this specific logger to avoid recursion
        class SanitizedHandler(logging.Handler):
            def __init__(self, sanitizer, original_handlers):
                super().__init__()
                self.sanitizer = sanitizer
                self.original_handlers = original_handlers

            def emit(self, record):
                # Sanitize the message
                record.msg = self.sanitizer.sanitize(str(record.msg))
                if hasattr(record, "args") and record.args:
                    record.args = tuple(
                        self.sanitizer.sanitize(str(arg)) for arg in record.args
                    )

                # Pass to original handlers
                for handler in self.original_handlers:
                    try:
                        handler.emit(record)
                    except Exception:
                        # If a handler fails, continue with others
                        continue

        # Get the root logger handlers
        root_logger = logging.getLogger()
        original_handlers = [
            h
            for h in root_logger.handlers
            if isinstance(
                h,
                (logging.StreamHandler, logging.handlers.RotatingFileHandler),
            )
        ]

        # Create and add our sanitized handler
        sanitized_handler = SanitizedHandler(sanitizer, original_handlers)
        logger.addHandler(sanitized_handler)

    return logger
