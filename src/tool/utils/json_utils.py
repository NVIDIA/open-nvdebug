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
JSON utilities for NVDebug Tool.

Handles JSON serialization and value processing with support for complex
types, circular references, and safe encoding.

This module provides:
    - process_value_for_json: Convert values to JSON-serializable format
    - safe_json_dumps: Safe JSON string serialization
    - safe_json_dump: Safe JSON file writing
"""

import json
import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


def process_value_for_json(value: Any) -> Any:
    """
    Process any value to ensure it can be JSON serialized.

    Args:
        value (Any): The value to process for JSON serialization

    Returns:
        Any: A JSON-serializable version of the input value

    Notes:
        - Handles circular references
        - Processes basic types, bytes, datetime objects
        - Handles lists, tuples, dictionaries, sets
        - Provides fallback string representation for unserializable objects
    """
    # Track objects to detect circular references
    seen = set()

    def _process_value(val, path=()):
        # Check for circular references
        if isinstance(val, (dict, list, tuple, set)):
            val_id = id(val)
            if val_id in seen:
                logger.warning("Detected circular reference in JSON processing")
                return "<circular reference to {type(val).__name__}>"
            seen.add(val_id)

        # Handle None
        if val is None:
            return None

        # Handle bytes
        if isinstance(val, bytes):
            try:
                # First try UTF-8 with replace
                return val.decode("utf-8", errors="replace")
            except Exception:
                try:
                    # Try latin1 as fallback - it can handle all byte values
                    return val.decode("latin1", errors="replace")
                except Exception:
                    # Last resort - hex representation
                    return f"hex:{val.hex()}"

        # Handle basic JSON-serializable types
        if isinstance(val, (str, int, float, bool)):
            return val

        # Handle datetime objects
        if isinstance(val, datetime):
            return val.isoformat() + "Z"

        # Handle lists and tuples
        if isinstance(val, (list, tuple)):
            try:
                return [_process_value(item, path + (i,)) for i, item in enumerate(val)]
            except Exception as e:
                logger.warning(f"Failed to process list/tuple: {str(e)}")
                return f"<error processing {type(val).__name__}>"

        # Handle dictionaries
        if isinstance(val, dict):
            try:
                return {str(k): _process_value(v, path + (k,)) for k, v in val.items()}
            except Exception as e:
                logger.warning(f"Failed to process dict: {str(e)}")
                return f"<error processing {type(val).__name__}>"

        # Handle sets
        if isinstance(val, set):
            try:
                return [_process_value(item, path + (i,)) for i, item in enumerate(val)]
            except Exception as e:
                logger.warning(f"Failed to process set: {str(e)}")
                return f"<error processing {type(val).__name__}>"

        # Try to JSON serialize directly
        try:
            json.dumps(val)
            return val
        except (TypeError, ValueError, json.JSONDecodeError):
            # For custom objects, try to get their dict representation
            try:
                if hasattr(val, "__dict__"):
                    return _process_value(val.__dict__, path + ("__dict__",))
                elif hasattr(val, "__slots__"):
                    return _process_value(
                        {slot: getattr(val, slot) for slot in val.__slots__},
                        path + ("__slots__",),
                    )
            except Exception as e:
                logger.warning(f"Failed to process custom object: {str(e)}")

            # If all else fails, convert to string
            try:
                return str(val)
            except Exception:
                logger.warning("Unprintable object in JSON processing")
                return f"<unprintable {type(val).__name__} object>"

    try:
        return _process_value(value)
    except Exception as e:
        logger.warning(f"JSON conversion failed: {str(e)}")
        return f"<error during JSON conversion>"


def safe_json_dumps(obj: Any, **kwargs) -> str:
    """
    Safely serialize an object to JSON string.

    Args:
        obj: Object to serialize
        **kwargs: Additional arguments for json.dumps

    Returns:
        str: JSON string representation
    """
    processed_obj = process_value_for_json(obj)
    return json.dumps(processed_obj, **kwargs)


def safe_json_dump(obj: Any, fp, **kwargs) -> None:
    """
    Safely serialize an object to JSON and write to file.

    Args:
        obj: Object to serialize
        fp: File-like object to write to
        **kwargs: Additional arguments for json.dump
    """
    processed_obj = process_value_for_json(obj)
    json.dump(processed_obj, fp, **kwargs)
