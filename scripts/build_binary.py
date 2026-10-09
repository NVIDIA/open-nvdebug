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
Build and smoke-test a native Linux executable from a public source checkout.

Report assets must already have been built with the owning report script. Build
work stays in a private temporary directory; a new output directory is published
only after the executable starts successfully outside the source checkout.
"""

from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def source_version(root: Path) -> str:
    """
    Read the product version without executing source or accepting unsafe names.

    Only a literal semantic version assignment can supply the archive stem, so
    version metadata cannot execute application code or introduce path separators.

    Args:
        root: Public checkout containing the canonical version module.

    Returns:
        The semantic version used in the output archive name.

    Raises:
        ValueError: If the module has no supported literal version assignment.
        OSError: If the version module cannot be read.
    """
    tree = ast.parse((root / "src/tool/version.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in node.targets
        ):
            version = ast.literal_eval(node.value)
            if isinstance(version, str) and re.fullmatch(
                r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version
            ):
                return version
    raise ValueError("version.py must declare a literal semantic version")


def validate_inputs(root: Path) -> None:
    """
    Require an exported checkout and report assets matching its authored sources.

    Validate through the selected checkout's own application package. An export
    marker alone does not establish that generated report assets are current.

    Args:
        root: Public checkout selected by this script's own location.

    Raises:
        ValueError: If the export marker or package import origin is wrong.
        ReportAppAssetError: If report assets are missing, stale, or invalid.

    Side Effects:
        Adds the selected source directory to this build process's import path.
    """
    if not (root / "PUBLIC_SOURCE_SHA256SUMS").is_file():
        raise ValueError("Build from an exported public source checkout")
    sys.path.insert(0, str(root / "src"))
    import tool
    from tool.utils.report_app_assets import validate_report_app_index

    if Path(tool.__file__).resolve() != root / "src/tool/__init__.py":
        raise ValueError("Application import resolved outside the public checkout")
    validate_report_app_index(root / "src/tool/report_app_dist/index.html")


def smoke_binary(binary: Path, environment: dict[str, str], work: Path) -> None:
    """
    Check startup, command help, and the embedded catalog without target access.

    Each command must start from an empty directory with the sanitized environment.
    Catalog listings exercise resource loading beyond the eager version option.

    Args:
        binary: Finished executable with an absolute path.
        environment: Sanitized process environment with no operator settings.
        work: Empty working directory outside the source checkout.

    Raises:
        RuntimeError: If a command fails or produces no output.
        subprocess.TimeoutExpired: If a command exceeds its startup deadline.
    """
    for arguments in (
        ("--version",),
        ("--help",),
        ("collect", "--help"),
        ("list-baseboards",),
        ("list-collectors",),
    ):
        result = subprocess.run(
            [str(binary), *arguments],
            cwd=work,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if result.returncode or not result.stdout.strip():
            raise RuntimeError(
                f"Binary smoke check failed: {arguments!r}\n{result.stderr or result.stdout}"
            )


def package_binary(root: Path, binary: Path, output: Path, name: str) -> None:
    """
    Stage the complete public distribution and archive those same resource bytes.

    Copy only the exported catalog, authored default configuration, and selected
    documentation. Operator settings in the checkout root are never included.
    Defaults sit beside the executable so binary configuration discovery can
    find editable copies. The executable retains its embedded fallback resources.

    Args:
        root: Public source checkout containing the catalog, notices, and defaults.
        binary: Smoke-tested executable to package.
        output: New staging directory owned by the caller.
        name: Validated archive stem derived from version and native architecture.

    Raises:
        ValueError: If the catalog is missing or ambiguous, or a selected input is
            not a regular file within its expected source boundary.
        OSError: If packaging or checksum output fails.

    Side Effects:
        Writes the distribution files, compressed archive, and SHA256SUMS covering
        every loose file and the archive in output.
    """
    catalogs = sorted((root / "config").glob("Telemetry_Catalog_v*.xlsx"))
    if len(catalogs) != 1:
        raise ValueError("Package requires exactly one exported Telemetry Catalog")
    selected = {"nvdebug": binary}
    for relative in (
        "README.md",
        "CONTRIBUTING.md",
        "License.txt",
        "Third-party-licenses.md",
        "release-notes.txt",
    ):
        selected[relative] = root / relative
    for filename in ("dut_config.yaml", "tool_config.yaml"):
        selected[filename] = root / "default_config" / filename
    selected[f"config/{catalogs[0].name}"] = catalogs[0]
    for relative, path in selected.items():
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Package input must be a regular file: {path.name}")
        if relative != "nvdebug" and (
            not path.resolve().is_relative_to(root.resolve())
            or any(
                (root / parent).is_symlink()
                for parent in path.relative_to(root).parents
            )
        ):
            raise ValueError(
                f"Package input must stay inside the checkout: {path.name}"
            )
    output.mkdir()
    for relative, source in selected.items():
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o755 if relative == "nvdebug" else 0o644)
    archive = output / f"{name}.tar.gz"
    with (
        archive.open("xb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed,
    ):
        with tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
        ) as bundle:
            for relative in sorted(selected):
                path = output / relative
                metadata = bundle.gettarinfo(str(path), arcname=f"{name}/{relative}")
                metadata.uid = metadata.gid = metadata.mtime = 0
                metadata.uname = metadata.gname = ""
                metadata.mode = 0o755 if relative == "nvdebug" else 0o644
                with path.open("rb") as stream:
                    bundle.addfile(metadata, stream)
    hashes = []
    for relative in sorted([*selected, archive.name]):
        path = output / relative
        with path.open("rb") as stream:
            hashes.append(
                f"{hashlib.file_digest(stream, 'sha256').hexdigest()}  {relative}\n"
            )
    (output / "SHA256SUMS").write_text("".join(hashes), encoding="utf-8")


def main() -> int:
    """
    Build a native executable and publish a complete new output directory.

    Keep intermediate products private until compilation, standalone startup,
    resource staging, and checksums all succeed. Existing output is preserved.

    Returns:
        Zero after build, report validation, CLI smoke checks, and packaging pass.

    Raises:
        SystemExit: For unsupported hosts, invalid arguments, or existing output.
        subprocess.CalledProcessError: If PyInstaller fails.
        OSError: If staging or final publication fails.

    Side Effects:
        Runs a local PyInstaller build and executable smoke checks, writes build
        products, and removes temporary build files on success or failure.
    """
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, help="Output directory (default: dist/<arch>)"
    )
    args = parser.parse_args()
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if (
        platform.system() != "Linux"
        or architecture is None
        or sys.version_info[:2] != (3, 12)
    ):
        parser.error("Build requires native Linux amd64/arm64 and Python 3.12")
    output = Path(os.path.abspath(args.output or root / "dist" / architecture))
    if os.path.lexists(output):
        parser.error("Output already exists; select a new directory with --output")
    version = source_version(root)
    validate_inputs(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".nvdebug-build-", dir=output.parent
    ) as temporary:
        work = Path(temporary)
        home = work / "home"
        home.mkdir(mode=0o700)
        environment = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(home),
            "LANG": "C.UTF-8",
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": "0",
            "XDG_CACHE_HOME": str(work / "cache"),
        }
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "PyInstaller",
                "--noconfirm",
                "--distpath",
                str(work / "frozen"),
                "--workpath",
                str(work / "pyinstaller"),
                str(root / "build_scripts/nvdebug.spec"),
            ],
            cwd=work,
            env=environment,
            check=True,
            timeout=1800,
        )
        binary = work / "frozen/nvdebug"
        smoke_binary(binary, environment, home)
        stage = work / "package"
        package_binary(root, binary, stage, f"nvdebug-{version}-linux-{architecture}")
        if os.path.lexists(output):
            raise FileExistsError(f"Output appeared during build: {output}")
        stage.rename(output)
    print(f"Built and smoke-tested: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
