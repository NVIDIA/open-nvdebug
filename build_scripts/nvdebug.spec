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
Freeze the public collection application and its explicitly selected resources.

Build through scripts/build_binary.py in an exported source checkout. Python
modules must resolve to that checkout, and data inputs must be regular files.
"""

from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent
TOOL = ROOT / "src/tool"
REPORT = TOOL / "report_app_dist"
CATALOGS = sorted((ROOT / "config").glob("Telemetry_Catalog_v*.xlsx"))
if len(CATALOGS) != 1:
    raise SystemExit("Build requires exactly one exported Telemetry Catalog")

datas = [(str(CATALOGS[0]), "config")]
for name in ("tool_config.yaml", "dut_config.yaml"):
    datas.append((str(ROOT / "default_config" / name), "."))
for asset in sorted(REPORT.rglob("*")):
    if asset.is_symlink():
        raise SystemExit("Report assets must not contain symbolic links")
    if asset.is_file():
        datas.append((str(asset), str(Path("tool/report_app_dist") / asset.relative_to(REPORT).parent)))
for source, destination in datas:
    path = Path(source)
    if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(ROOT):
        raise SystemExit("Build resources must be regular files inside the checkout")

analysis = Analysis(
    [str(ROOT / "build_scripts/main_wrapper.py")],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=["aiofiles", "aiofiles.os", "bcrypt", "zstandard"],
    hookspath=[],
    runtime_hooks=[],
    excludes=["nvdebug_internal_extensions", "src.external", "tool.parsers",
              "boto3", "botocore", "s3transfer", "azure", "multistorageclient",
              "serial", "pandas", "numpy", "matplotlib", "pytest", "IPython", "tkinter"],
    noarchive=False,
)
for name, source, kind in analysis.pure:
    if name == "tool" or name.startswith("tool."):
        if not source or not Path(source).resolve().is_relative_to(TOOL):
            raise SystemExit("Application module resolved outside the public checkout: " + name)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz, analysis.scripts, analysis.binaries, analysis.datas, [],
    name="nvdebug", debug=False, bootloader_ignore_signals=False,
    strip=False, upx=False, console=True,
)
