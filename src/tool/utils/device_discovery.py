#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
Shared bounds and identity guards for device-derived collector work.

Host and BMC discovery paths use these helpers to enforce one device-count
ceiling and one collision-resistant artifact component grammar.
"""

import re
from typing import Any, List

MAX_DEVICE_DISCOVERY_MATCHES = 256
_SAFE_REMOTE_OUTPUT_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")


def bounded_device_matches(pattern_text: Any, output: Any) -> List[str]:
    """
    Return bounded scalar device identifiers from endpoint-controlled output.

    Only the first capture group is used when the authored expression contains
    groups, preventing tuple-valued ``findall`` results from reaching command
    and filename templates. The existing 256-device ceiling is shared by Host
    and BMC collectors and rejects excess work as one per-collector error.

    Args:
        pattern_text: Authored regular expression used for device discovery.
        output: Endpoint-controlled detection transcript.

    Returns:
        Device identifiers in transcript order.

    Raises:
        ValueError: If the expression is missing, oversized, invalid, or the
            transcript contains more than the shared device ceiling.
    """
    if not isinstance(pattern_text, str) or not pattern_text:
        raise ValueError("device_detection.device_pattern is required")
    if len(pattern_text) > 512:
        raise ValueError("device_detection.device_pattern exceeds 512 characters")
    try:
        pattern = re.compile(pattern_text, re.MULTILINE)
    except re.error as exc:
        raise ValueError("device_detection.device_pattern is invalid") from exc

    matches: List[str] = []
    for match in pattern.finditer(str(output or "")):
        if len(matches) >= MAX_DEVICE_DISCOVERY_MATCHES:
            raise ValueError(
                f"device detection exceeded {MAX_DEVICE_DISCOVERY_MATCHES} matches"
            )
        value = match.group(1) if match.lastindex else match.group(0)
        if value is not None:
            matches.append(str(value))
    return matches


def safe_remote_output_component(value: Any) -> str:
    """
    Return a device-derived value safe for one artifact filename component.

    The guard deliberately accepts only a compact ASCII identity vocabulary;
    endpoint text that does not qualify is recorded against that device and
    never normalized into a potentially colliding artifact name.

    Args:
        value: Device-derived identifier or rendered filename component.

    Returns:
        The unchanged validated component.

    Raises:
        ValueError: If the value is empty, special, non-ASCII, or otherwise
            outside the shared artifact-identity grammar.
    """
    component = str(value)
    if component in {".", ".."} or not _SAFE_REMOTE_OUTPUT_COMPONENT.fullmatch(
        component
    ):
        raise ValueError("device-derived output name is not a safe filename component")
    return component
