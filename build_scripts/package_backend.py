# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Build installable public packages with their complete runtime resources.

PEP 517 hooks delegate metadata and archive creation to setuptools in an isolated
staging directory. Only paths selected by the public source inventory and assets
accepted by the report validator enter that directory. Building never invokes npm,
contacts a target, or copies operator configuration from the checkout root.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import shutil
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Iterator

from setuptools import build_meta

_MANIFEST = "PUBLIC_SOURCE_SHA256SUMS"


def _source_files(root: Path) -> list[str]:
    """
    Read the exported path inventory without admitting traversal or duplicate paths.

    Digests remain provenance for the export; tracked local edits can still be
    built. Unlisted operator files and stale build products are never selected.

    Args:
        root: Public checkout or unpacked source distribution.

    Returns:
        Validated source paths, including the inventory itself.

    Raises:
        ValueError: If an inventory entry is malformed, unsafe, or duplicated.
        OSError: If the inventory is unavailable.
    """
    manifest = _regular_input(root, _MANIFEST)
    if manifest.stat().st_size > 1024 * 1024:
        raise ValueError("Public source inventory is too large")
    paths = [_MANIFEST]
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"[0-9a-f]{64}  100(?:644|755)  (.+)", line)
        if match is None:
            raise ValueError("Invalid public source inventory entry")
        relative = match.group(1)
        _regular_input(root, relative)
        if relative in paths:
            raise ValueError("Duplicate public source inventory path")
        paths.append(relative)
    if len(paths) < 2:
        raise ValueError("Public source inventory is empty")
    return paths


def _regular_input(root: Path, relative: str) -> Path:
    """
    Resolve a regular input without following a symbolic link inside the checkout.

    Validate the visible path and every parent before copying, so a selected
    resource cannot be redirected to operator data elsewhere on the host.

    Args:
        root: Owning source directory.
        relative: Canonical forward-slash path below that directory.

    Returns:
        The checked input path.

    Raises:
        ValueError: If the path is unsafe, absent, or redirected.
    """
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or path.as_posix() != relative
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise ValueError("Invalid public package input path")
    candidate = root / path
    if (
        not candidate.is_file()
        or candidate.is_symlink()
        or any((root / parent).is_symlink() for parent in path.parents)
        or not candidate.resolve().is_relative_to(root.resolve())
    ):
        raise ValueError(f"Package input must be a regular checkout file: {relative}")
    return candidate


def _report_files(root: Path) -> list[str]:
    """
    Validate generated assets using the runtime's report integrity implementation.

    The private namespace loads only validation modules, so an isolated build
    needs no installed application dependencies and never initializes the CLI.
    All temporary module registrations are removed even if validation fails.

    Args:
        root: Source tree containing authored and generated report inputs.

    Returns:
        Validated report asset paths relative to the source root.

    Raises:
        ValueError: If report assets are missing, changed, or stale.
        OSError: If a report input cannot be read safely.
    """
    namespace = "_nvdebug_package_validation"
    if any(
        name == namespace or name.startswith(namespace + ".") for name in sys.modules
    ):
        raise ValueError("Report validation namespace is already in use")
    try:
        for name, directory in (
            (namespace, root / "src/tool"),
            (namespace + ".utils", root / "src/tool/utils"),
        ):
            package = ModuleType(name)
            package.__path__ = [str(directory)]
            sys.modules[name] = package
        validator = importlib.import_module(namespace + ".utils.report_app_assets")
        dist = root / "src/tool/report_app_dist"
        expected = validator.build_report_app_dist_manifest(
            root / "src/report-app", dist
        )
        recorded = json.loads(
            _regular_input(
                root, "src/tool/report_app_dist/report-app-dist.json"
            ).read_text(encoding="utf-8")
        )
        if recorded != expected:
            raise ValueError("Report asset manifest does not match validated inputs")
        return [
            "src/tool/report_app_dist/" + relative
            for relative in [*expected["files"], "report-app-dist.json"]
        ]
    except (OSError, RuntimeError, ValueError) as error:
        raise ValueError(
            "Build validated report assets first: make build-report-app"
        ) from error
    finally:
        for name in list(sys.modules):
            if name == namespace or name.startswith(namespace + "."):
                del sys.modules[name]


@contextmanager
def _staged_source(*, resources: bool) -> Iterator[Path]:
    """
    Stage declared public files and optional runtime data for one backend call.

    A fresh staging tree prevents setuptools from reusing stale package files or
    cached source lists. The original checkout and its operator files stay intact.

    Args:
        resources: Require generated report assets and package runtime data when
            producing a wheel or source archive; metadata discovery omits them.

    Yields:
        A private source tree used as the current directory until the hook returns.

    Raises:
        ValueError: If source or resource selection is incomplete or unsafe.
        OSError: If selected files cannot be staged.

    Side Effects:
        Temporarily changes the process working directory and removes its private
        staging tree on exit, including failed builds.
    """
    root = Path(__file__).resolve().parents[1]
    paths = _source_files(root)
    selected = {relative: relative for relative in paths}
    if resources:
        catalogs = [
            path
            for path in paths
            if PurePosixPath(path).parent == PurePosixPath("config")
            and re.fullmatch(
                r"Telemetry_Catalog_v[0-9.]+\.xlsx", PurePosixPath(path).name
            )
        ]
        if len(catalogs) != 1:
            raise ValueError("Package requires exactly one exported Telemetry Catalog")
        selected["src/tool/" + catalogs[0]] = catalogs[0]
        for filename in ("dut_config.yaml", "tool_config.yaml"):
            relative = "default_config/" + filename
            if relative not in paths:
                raise ValueError(f"Missing exported default configuration: {filename}")
            selected["src/tool/" + relative] = relative
        selected.update({relative: relative for relative in _report_files(root)})
    with tempfile.TemporaryDirectory(prefix="nvdebug-package-") as temporary:
        stage = Path(temporary)
        for destination, relative in sorted(selected.items()):
            source = _regular_input(root, relative)
            target = stage / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
        # The staging tree contains only explicitly selected inputs.
        (stage / "MANIFEST.in").write_text(
            "graft .\nglobal-exclude *.py[cod]\n", encoding="utf-8"
        )
        previous = Path.cwd()
        os.chdir(stage)
        try:
            yield stage
        finally:
            os.chdir(previous)


def prepare_metadata_for_build_wheel(
    metadata_directory: str, config_settings: dict | None = None
) -> str:
    """
    Resolve package metadata before report assets or runtime dependencies exist.

    Metadata discovery reads the literal version and dependency declarations in
    isolation; it does not initialize the application's CLI or resource loaders.

    Args:
        metadata_directory: Frontend-owned output directory for dist-info metadata.
        config_settings: Standard setuptools options supplied by the frontend.

    Returns:
        The generated dist-info directory name.

    Side Effects:
        Writes metadata to the selected output directory.
    """
    destination = str(Path(metadata_directory).resolve())
    with _staged_source(resources=False):
        return build_meta.prepare_metadata_for_build_wheel(destination, config_settings)


def build_wheel(
    wheel_directory: str,
    config_settings: dict | None = None,
    metadata_directory: str | None = None,
) -> str:
    """
    Build a wheel containing the collection CLI and validated runtime resources.

    Resource validation completes before setuptools sees the staged tree. Output
    paths are resolved before changing directories to honor frontend ownership.

    Args:
        wheel_directory: Frontend-owned output directory for the wheel.
        config_settings: Standard setuptools options supplied by the frontend.
        metadata_directory: Previously prepared metadata, when supplied by pip.

    Returns:
        The completed wheel filename.

    Raises:
        ValueError: If required public inputs or report assets fail validation.

    Side Effects:
        Writes the wheel to the selected output directory.
    """
    destination = str(Path(wheel_directory).resolve())
    metadata = str(Path(metadata_directory).resolve()) if metadata_directory else None
    with _staged_source(resources=True):
        return build_meta.build_wheel(destination, config_settings, metadata)


def build_sdist(sdist_directory: str, config_settings: dict | None = None) -> str:
    """
    Build a source archive that can produce its wheel without npm or network access.

    Include authored report inputs alongside their validated generated assets so
    a downstream wheel build can check provenance without rebuilding the frontend.

    Args:
        sdist_directory: Frontend-owned output directory for the source archive.
        config_settings: Standard setuptools options supplied by the frontend.

    Returns:
        The completed source archive filename.

    Raises:
        ValueError: If required public inputs or report assets fail validation.

    Side Effects:
        Writes the source archive to the selected output directory.
    """
    destination = str(Path(sdist_directory).resolve())
    with _staged_source(resources=True):
        return build_meta.build_sdist(destination, config_settings)
