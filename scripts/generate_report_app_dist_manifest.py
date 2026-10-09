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
Generate the build-recorded integrity manifest for report-app assets.

The build invokes this script only after Vite has emitted the complete
distribution. It validates source provenance and writes the manifest
atomically so packaging cannot consume a partial integrity record.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, os.fspath(PROJECT_ROOT / "src"))

from tool.utils.report_app_assets import (  # noqa: E402
    REPORT_APP_DIST_MANIFEST_NAME,
    build_report_app_dist_manifest,
)


def main() -> int:
    """
    Write a deterministic manifest after validating generated report-app bytes.

    Command-line paths identify the authored source and completed distribution.
    Validation failures propagate as a non-zero process exit before packaging.

    Returns:
        Process exit status; zero indicates that the manifest was written.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_root", type=Path)
    parser.add_argument("dist_root", type=Path)
    arguments = parser.parse_args()

    document = build_report_app_dist_manifest(
        arguments.source_root,
        arguments.dist_root,
    )
    destination = arguments.dist_root / REPORT_APP_DIST_MANIFEST_NAME
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        payload = (
            json.dumps(document, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
