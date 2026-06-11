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
NVDebug Tool package.

This tool collects system logs and debug information from NVIDIA platforms.

This package exports:
    - Config: Configuration management
    - load_config: Load tool configuration
    - load_dut_config: Load DUT configuration
    - get_available_baseboards: Get available baseboard platforms
    - validate_baseboard: Validate baseboard name
    - __version__: Version string
    - __build_hash__: Build hash
"""

from .config import (
    Config,
    get_available_baseboards,
    load_config,
    load_dut_config,
    validate_baseboard,
)
from .version import __build_hash__, __version__

__all__ = [
    "__version__",
    "__build_hash__",
    "Config",
    "load_config",
    "load_dut_config",
    "get_available_baseboards",
    "validate_baseboard",
]
