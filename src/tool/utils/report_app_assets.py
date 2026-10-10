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
Bind generated report-app bytes to the authored source that produced them.

This module owns the report app assets boundary and exposes
``ReportAppAssetError``, ``_same_file``, ``_read_stable_regular_file``,
``_relative_input_path``, and ``_input_path``. Keeping those contracts together
gives importers one source of truth for their validation, lifecycle, and
compatibility behavior.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any

from .archive_member_policy import (
    MemberNamePolicyError,
    validate_distributable_member_name,
)
from .bounded_archive import STANDARD_ARCHIVE_LIMITS

REPORT_APP_SOURCE_META_NAME = "nvdebug-report-app-source-sha256"
REPORT_APP_INPUT_MANIFEST_NAME = "report-app-inputs.json"
REPORT_APP_DIST_MANIFEST_NAME = "report-app-dist.json"
REPORT_APP_DIST_SCHEMA_VERSION = 1

_DIGEST_DOMAIN = b"nvdebug-report-app-source-v1\n"
_MAX_INPUT_MANIFEST_BYTES = 64 * 1024
_MAX_SOURCE_INPUT_FILES = 4096
_MAX_SOURCE_INPUT_BYTES = 64 * 1024 * 1024
_MAX_REPORT_APP_INDEX_BYTES = 128 * 1024 * 1024
_STABLE_FILE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)
_SHA256_HEX_LENGTH = 64


class ReportAppAssetError(RuntimeError):
    """
    A generated report-app distribution is missing or stale.

    Callers receive this exception when the report app asset error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """

    def __init__(self, code: str, *, source_checkout: bool):
        """
        Initialize a ``ReportAppAssetError`` instance.

        The initializer records ``code`` and ``source_checkout`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            code: Text supplied as code in the format accepted by this function.
            source_checkout: Whether source checkout is enabled or required for
                this operation.
        """
        super().__init__(code)
        self.code = code
        self.source_checkout = source_checkout


def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
    """
    Return the same file.

    After applying local validation, the function forwards ``first`` and
    ``second`` to ``all`` and preserves its return and exception contract.

    Args:
        first: First consumed while the function attempts to produce the same
            file.
        second: Second consumed while the function attempts to produce the same
            file.

    Returns:
        Whether the same file operation succeeds.
    """
    return all(
        getattr(first, field) == getattr(second, field) for field in _STABLE_FILE_FIELDS
    )


def _read_stable_regular_file(path: Path, maximum_bytes: int) -> bytes:
    """
    Read stable regular file.

    After applying local validation, the function forwards ``path`` and
    ``maximum_bytes`` to ``join`` and preserves its return and exception
    contract. Parsing or I/O must finish before the validated representation is
    made available to the caller. Cleanup in the ``finally`` path runs for
    successful, failed, and cancelled execution.

    Args:
        path: filesystem location used as the path for this operation.
        maximum_bytes: Upper bound enforced for bytes; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The bounded stable regular file bytes.

    Raises:
        OSError: If report-app input is not a bounded regular file; report-app
            input changed before it was opened; report-app input exceeds its
            byte bound; or report-app input changed while it was read.
    """
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
        raise OSError("report-app input is not a bounded regular file")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if not _same_file(before, opened):
            raise OSError("report-app input changed before it was opened")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, maximum_bytes + 1 - observed),
            )
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum_bytes:
                raise OSError("report-app input exceeds its byte bound")
        after = os.fstat(descriptor)
        path_after = path.lstat()
        if (
            observed != before.st_size
            or not _same_file(before, after)
            or not _same_file(before, path_after)
        ):
            raise OSError("report-app input changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _relative_input_path(value: Any, label: str) -> str:
    """
    Validate one manifest entry as a canonical relative source path.

    The manifest is an authored input, so the string must already be canonical:
    the round-trip identity check refuses ``./name`` and any other spelling that
    ``PurePosixPath`` would silently rewrite. Containment is then decided by the
    shared ``utils.archive_member_policy`` component rules rather than by
    testing for a leading ``../``, which admitted an embedded ``..`` that the
    lexical containment check in ``_input_path`` could not see.

    Args:
        value: Candidate manifest entry. Anything other than a ``str`` is
            refused rather than coerced.
        label: Entry kind used in the operator-facing message, such as ``file``
            or ``directory``.

    Returns:
        The validated ``normalized`` path, identical to ``value``.

    Raises:
        ValueError: If invalid report-app ``label``.
        UnicodeEncodeError: If the entry cannot be encoded as UTF-8.
    """
    if type(value) is not str:
        raise ValueError(f"invalid report-app {label}")
    value.encode("utf-8")
    normalized = PurePosixPath(value).as_posix()
    if normalized != value:
        raise ValueError(f"invalid report-app {label}")
    try:
        validate_distributable_member_name(
            normalized,
            max_path_depth=STANDARD_ARCHIVE_LIMITS.max_path_depth,
        )
    except MemberNamePolicyError as error:
        raise ValueError(f"invalid report-app {label}") from error
    return normalized


def _input_path(root: Path, relative: str) -> Path:
    """
    Return the input path.

    The implementation uses ``root`` and ``relative`` to produce the input path.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. If the function cannot produce the input path,
    its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        root: filesystem location used as the root for this operation.
        relative: Text supplied as relative in the format accepted by this
            function.

    The prefix is checked before containment so a symbolic link in the path is
    always reported as the ``OSError`` its callers expect, rather than as a
    containment failure. Containment is then decided on the resolved parent
    directory instead of lexically, which closes the case where ``root`` itself
    is reached through a link. The leaf is deliberately left unresolved: a
    symlinked leaf stays the caller's decision, made with ``O_NOFOLLOW`` on the
    exact path returned here.

    Returns:
        The validated ``candidate``, unresolved and rooted at ``root``.

    Raises:
        ValueError: If report-app input escaped its source root.
        OSError: If report-app input parent is a symbolic link; or report-app
            input parent is not a regular directory.
    """
    components = relative.split("/")
    candidate = root.joinpath(*components)
    parent = root
    for component in components[:-1]:
        parent /= component
        metadata = parent.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise OSError("report-app input parent is a symbolic link")
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError("report-app input parent is not a regular directory")
    try:
        candidate.parent.resolve(strict=False).relative_to(root.resolve(strict=False))
    except (OSError, RuntimeError, ValueError) as error:
        raise ValueError("report-app input escaped its source root") from error
    return candidate


def _load_input_manifest(root: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """
    Load input manifest.

    The implementation uses ``root`` to load input manifest. Parsing or I/O must
    finish before the validated representation is made available to the caller.
    If the function cannot load input manifest, its exception reaches the caller
    instead of being converted into a successful result.

    Args:
        root: filesystem location used as the root for this operation.

    Returns:
        A tuple containing ``files`` and ``directories`` in that order.

    Raises:
        ValueError: If report-app input manifest is malformed; or report-app
            input manifest contains duplicates.
    """
    raw = _read_stable_regular_file(
        root / REPORT_APP_INPUT_MANIFEST_NAME,
        _MAX_INPUT_MANIFEST_BYTES,
    )
    document = json.loads(raw.decode("utf-8"))
    if (
        type(document) is not dict
        or set(document) != {"schema_version", "files", "directories"}
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or type(document["files"]) is not list
        or type(document["directories"]) is not list
    ):
        raise ValueError("report-app input manifest is malformed")
    files = tuple(
        _relative_input_path(value, "file input") for value in document["files"]
    )
    directories = tuple(
        _relative_input_path(value, "directory input")
        for value in document["directories"]
    )
    if len(files) != len(set(files)) or len(directories) != len(set(directories)):
        raise ValueError("report-app input manifest contains duplicates")
    return files, directories


def _collect_directory_inputs(
    root: Path,
    relative_directory: str,
    inputs: set[str],
) -> None:
    """
    Collect directory inputs.

    The implementation uses ``root``, ``relative_directory``, and ``inputs`` to
    collect directory inputs. Terminal status is emitted only after directory
    inputs and its owned cleanup have completed. The operation mutates
    ``inputs`` in place; ownership of those objects remains with the caller.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle. If the function cannot collect directory inputs,
    its exception reaches the caller instead of being converted into a
    successful result.

    Args:
        root: filesystem location used as the root for this operation.
        relative_directory: filesystem location used as the relative directory
            for this operation.
        inputs: Entries supplied as ``inputs`` without transferring container
            ownership.

    Raises:
        OSError: If report-app source input is not a regular directory; the
            report-app source inputs are not regular files; or report-app source
            directory changed during inventory.
        ValueError: If report-app input manifest contains overlaps; or
            report-app source input inventory exceeds its entry bound.
    """
    directory = _input_path(root, relative_directory)
    before = directory.lstat()
    if not stat.S_ISDIR(before.st_mode):
        raise OSError("report-app source input is not a regular directory")
    with os.scandir(directory) as iterator:
        entries = sorted(
            (
                entry.name,
                entry.stat(follow_symlinks=False),
            )
            for entry in iterator
        )
    for name, metadata in entries:
        relative = PurePosixPath(relative_directory, name).as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            _collect_directory_inputs(root, relative, inputs)
        elif stat.S_ISREG(metadata.st_mode):
            if relative in inputs:
                raise ValueError("report-app input manifest contains overlaps")
            inputs.add(relative)
            if len(inputs) > _MAX_SOURCE_INPUT_FILES:
                raise ValueError(
                    "report-app source input inventory exceeds its entry bound"
                )
        else:
            raise OSError("report-app source inputs must be regular files")
    after = directory.lstat()
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_mode != after.st_mode
    ):
        raise OSError("report-app source directory changed during inventory")


def compute_report_app_source_digest(report_app_root: Path) -> str:
    """
    Return the deterministic digest embedded by the Vite build.

    After applying local validation, the function forwards ``report_app_root``
    to ``aggregate.hexdigest`` and preserves its return and exception contract.
    Filesystem effects remain confined to the caller-selected paths and the
    owning resource lifecycle.

    Args:
        report_app_root: filesystem location used as the report app root for
            this operation.

    Returns:
        The canonical report app source digest.

    Raises:
        OSError: If report-app source root is not a regular directory.
        ValueError: If report-app source input inventory exceeds its entry
            bound; or report-app source inputs exceed their byte bound.
    """

    root = Path(os.path.abspath(os.fspath(report_app_root)))
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise OSError("report-app source root is not a regular directory")
    files, directories = _load_input_manifest(root)
    inputs = set(files)
    if len(inputs) > _MAX_SOURCE_INPUT_FILES:
        raise ValueError("report-app source input inventory exceeds its entry bound")
    for relative_directory in directories:
        _collect_directory_inputs(root, relative_directory, inputs)

    aggregate = hashlib.sha256(_DIGEST_DOMAIN)
    total_bytes = 0
    for relative in sorted(inputs, key=lambda value: value.encode("utf-8")):
        payload = _read_stable_regular_file(
            _input_path(root, relative),
            _MAX_SOURCE_INPUT_BYTES,
        )
        total_bytes += len(payload)
        if total_bytes > _MAX_SOURCE_INPUT_BYTES:
            raise ValueError("report-app source inputs exceed their byte bound")
        relative_bytes = relative.encode("utf-8")
        leaf_digest = hashlib.sha256(payload).hexdigest()
        aggregate.update(
            b"%d:%s:%d:%s\n"
            % (
                len(relative_bytes),
                relative_bytes,
                len(payload),
                leaf_digest.encode("ascii"),
            )
        )
    return aggregate.hexdigest()


def report_app_source_root() -> Path | None:
    """
    Return the authored source root when running from a source checkout.

    Once the checkout is authoritative, return the expected source path even
    when it is missing or malformed so validation fails closed as a source build
    instead of silently downgrading to package-only marker checks.

    Returns:
        The validated report app source root filesystem path, or ``None`` when
        the requested value is unavailable.
    """

    module_path = Path(__file__).resolve()
    try:
        project_root = module_path.parents[3]
    except IndexError:
        return None
    expected_module = project_root / "src" / "tool" / "utils" / "report_app_assets.py"
    if module_path != expected_module:
        return None
    try:
        project_marker = (project_root / "pyproject.toml").lstat()
    except OSError:
        return None
    if not stat.S_ISREG(project_marker.st_mode):
        return None
    # Once the checkout is authoritative, return the expected source path even
    # when it is missing or malformed so validation fails closed as a source
    # build instead of silently downgrading to package-only marker checks.
    return project_root / "src" / "report-app"


class _SourceDigestParser(HTMLParser):
    """
    Extract provenance from actual meta elements, not comments or scripts.

    The type coordinates ``handle_starttag`` and retains the state those
    operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    def __init__(self) -> None:
        """
        Initialize a ``_SourceDigestParser`` instance.

        The initializer records ``matches`` for later operations and establishes
        the instance invariants before any public method runs.
        """
        super().__init__(convert_charrefs=True)
        self.matches: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        """
        Handle starttag.

        The implementation uses ``tag`` and ``attrs`` to handle starttag.
        Terminal status is emitted only after starttag and its owned cleanup
        have completed. If the function cannot handle starttag, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            tag: Text supplied as tag in the format accepted by this function.
            attrs: Optional attrs; ``None`` selects the function's default
                behavior.

        Raises:
            ValueError: If report-app source provenance marker is malformed.
        """
        if tag.casefold() != "meta":
            return
        names = [value for name, value in attrs if name.casefold() == "name"]
        if not any(
            value is not None and value.casefold() == REPORT_APP_SOURCE_META_NAME
            for value in names
        ):
            return
        contents = [value for name, value in attrs if name.casefold() == "content"]
        if (
            len(names) != 1
            or names[0] is None
            or len(contents) != 1
            or contents[0] is None
            or len(contents[0]) != 64
            or any(character not in "0123456789abcdef" for character in contents[0])
        ):
            raise ValueError("report-app source provenance marker is malformed")
        self.matches.append(contents[0])


def _embedded_source_digest(index_document: bytes) -> str:
    """
    Return the embedded source digest.

    The implementation uses ``index_document`` to produce the embedded source
    digest. If the function cannot produce the embedded source digest, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        index_document: Bounded byte sequence supplied as index document.

    Returns:
        The canonical embedded source digest.

    Raises:
        ValueError: If report-app source provenance marker is not unique.
    """
    parser = _SourceDigestParser()
    parser.feed(index_document.decode("utf-8"))
    parser.close()
    if len(parser.matches) != 1:
        raise ValueError("report-app source provenance marker is not unique")
    return parser.matches[0]


def _report_app_dist_files(root: Path) -> tuple[str, ...]:
    """
    Return the bounded regular-file inventory for a report-app distribution.

    Directory entries are inspected without following symbolic links. The
    build manifest itself is excluded because a file cannot bind its own
    digest; every other emitted file must appear in the returned inventory.

    Args:
        root: Distribution root whose regular files are inventoried.

    Returns:
        Canonical POSIX relative paths for every emitted distribution file.

    Raises:
        OSError: If the distribution contains a symbolic link, special file,
            or non-directory traversal component.
        ValueError: If the distribution exceeds its file-count bound.
    """
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise OSError("report-app distribution root is not a regular directory")

    files: list[str] = []
    pending: list[tuple[Path, PurePosixPath]] = [(root, PurePosixPath())]
    while pending:
        directory, relative_directory = pending.pop()
        before = directory.lstat()
        if not stat.S_ISDIR(before.st_mode):
            raise OSError("report-app distribution contains a non-directory path")
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
        for entry in reversed(entries):
            metadata = entry.stat(follow_symlinks=False)
            relative = relative_directory / entry.name
            relative_text = relative.as_posix()
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                if relative_text != REPORT_APP_DIST_MANIFEST_NAME:
                    files.append(_relative_input_path(relative_text, "dist asset"))
                    if len(files) > _MAX_SOURCE_INPUT_FILES:
                        raise ValueError(
                            "report-app distribution exceeds its file-count bound"
                        )
            else:
                raise OSError("report-app distribution assets must be regular files")
        after = directory.lstat()
        if not _same_file(before, after):
            raise OSError("report-app distribution changed during inventory")
    return tuple(sorted(files, key=lambda value: value.encode("utf-8")))


def build_report_app_dist_manifest(
    report_app_root: Path,
    dist_root: Path,
) -> dict[str, Any]:
    """
    Build the out-of-band integrity manifest for generated report-app assets.

    The authored source digest is recomputed from the reviewed source manifest,
    checked against the marker in the generated index, and paired with a digest
    for every emitted distribution file except this manifest itself.

    Args:
        report_app_root: Authored report-app source root.
        dist_root: Generated distribution root.

    Returns:
        JSON-serializable manifest content for ``report-app-dist.json``.

    Raises:
        OSError: If an input is not a stable regular file or directory.
        ValueError: If generated assets do not match their authored source.
    """
    source_sha256 = compute_report_app_source_digest(report_app_root)
    files: dict[str, str] = {}
    for relative in _report_app_dist_files(dist_root):
        payload = _read_stable_regular_file(
            _input_path(dist_root, relative),
            _MAX_REPORT_APP_INDEX_BYTES,
        )
        files[relative] = hashlib.sha256(payload).hexdigest()

    index_payload = _read_stable_regular_file(
        _input_path(dist_root, "index.html"),
        _MAX_REPORT_APP_INDEX_BYTES,
    )
    if not hmac.compare_digest(_embedded_source_digest(index_payload), source_sha256):
        raise ValueError("report-app distribution is stale")
    return {
        "schema_version": REPORT_APP_DIST_SCHEMA_VERSION,
        "source_sha256": source_sha256,
        "files": files,
    }


def _load_report_app_dist_manifest(dist_root: Path) -> tuple[str, dict[str, str]]:
    """
    Load and strictly validate a packaged report-app integrity manifest.

    The manifest has an exact schema, refuses duplicate keys, and must enumerate
    the same regular-file inventory observed beside it before any digest is
    trusted.

    Args:
        dist_root: Generated distribution root containing the manifest.

    Returns:
        The source digest and exact relative-file digest mapping.

    Raises:
        OSError: If the manifest is missing or is not a stable regular file.
        ValueError: If the manifest shape, paths, digests, or inventory is
            malformed.
    """
    raw = _read_stable_regular_file(
        dist_root / REPORT_APP_DIST_MANIFEST_NAME,
        _MAX_INPUT_MANIFEST_BYTES,
    )

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """
        Build one JSON object while refusing a repeated member name.

        JSON's ordinary object construction keeps the last repeated value. This
        hook rejects that ambiguous representation before schema validation.

        Args:
            pairs: Ordered key/value pairs supplied by ``json.loads``.

        Returns:
            A mapping containing every unique pair.

        Raises:
            ValueError: If the JSON object repeats a key.
        """
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("report-app dist manifest contains duplicate keys")
            result[key] = value
        return result

    document = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=reject_duplicate_keys,
    )
    if (
        type(document) is not dict
        or set(document) != {"schema_version", "source_sha256", "files"}
        or type(document["schema_version"]) is not int
        or document["schema_version"] != REPORT_APP_DIST_SCHEMA_VERSION
        or type(document["source_sha256"]) is not str
        or len(document["source_sha256"]) != _SHA256_HEX_LENGTH
        or any(
            character not in "0123456789abcdef"
            for character in document["source_sha256"]
        )
        or type(document["files"]) is not dict
        or not document["files"]
        or len(document["files"]) > _MAX_SOURCE_INPUT_FILES
    ):
        raise ValueError("report-app dist manifest is malformed")

    files: dict[str, str] = {}
    for raw_relative, raw_digest in document["files"].items():
        relative = _relative_input_path(raw_relative, "dist asset")
        if relative == REPORT_APP_DIST_MANIFEST_NAME:
            raise ValueError("report-app dist manifest cannot bind itself")
        if (
            type(raw_digest) is not str
            or len(raw_digest) != _SHA256_HEX_LENGTH
            or any(character not in "0123456789abcdef" for character in raw_digest)
        ):
            raise ValueError("report-app dist asset digest is malformed")
        files[relative] = raw_digest

    if set(files) != set(_report_app_dist_files(dist_root)):
        raise ValueError("report-app dist manifest inventory does not match assets")
    return document["source_sha256"], files


def _validate_packaged_report_app(
    dist_root: Path,
    embedded_digest: str,
) -> None:
    """
    Validate packaged report-app bytes against their build-emitted manifest.

    Validation binds the embedded source marker and every generated asset to a
    record produced outside those assets by the build workflow.

    Args:
        dist_root: Generated distribution root containing all packaged assets.
        embedded_digest: Authored source digest embedded in ``index.html``.

    Raises:
        OSError: If an asset is not a stable regular file.
        ValueError: If source or asset digests do not match the manifest.
    """
    source_sha256, files = _load_report_app_dist_manifest(dist_root)
    if not hmac.compare_digest(embedded_digest, source_sha256):
        raise ValueError("report-app source marker does not match build manifest")
    for relative, expected_digest in files.items():
        payload = _read_stable_regular_file(
            _input_path(dist_root, relative),
            _MAX_REPORT_APP_INDEX_BYTES,
        )
        if not hmac.compare_digest(
            hashlib.sha256(payload).hexdigest(), expected_digest
        ):
            raise ValueError(f"report-app dist asset digest mismatch: {relative}")


def validate_report_app_index(
    index_path: Path,
    *,
    trusted_source_digest: str | None = None,
) -> str:
    """
    Reject a generated SPA that does not match available authored sources.

    The implementation uses ``index_path`` to reject a generated SPA that does
    not match available authored sources. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        index_path: filesystem location used as the index path for this
            operation.
        trusted_source_digest: Digest obtained from a separately validated
            pristine source distribution. Supplying it permits intentional
            runtime manifest embedding while preventing the generated page
            from authenticating a rewritten provenance marker itself.

    Returns:
        The validated ``embedded_digest``.

    Raises:
        ValueError: If report-app distribution is stale.
        ReportAppAssetError: If the function cannot reject a generated SPA that
            does not match available authored sources safely.
    """

    source_root = report_app_source_root()
    source_checkout = source_root is not None
    try:
        document = _read_stable_regular_file(
            Path(index_path),
            _MAX_REPORT_APP_INDEX_BYTES,
        )
        embedded_digest = _embedded_source_digest(document)
        if trusted_source_digest is not None:
            if (
                type(trusted_source_digest) is not str
                or len(trusted_source_digest) != _SHA256_HEX_LENGTH
                or any(
                    character not in "0123456789abcdef"
                    for character in trusted_source_digest
                )
                or not hmac.compare_digest(
                    embedded_digest,
                    trusted_source_digest,
                )
            ):
                raise ValueError(
                    "report-app marker does not match the trusted source digest"
                )
        elif source_root is not None:
            expected_digest = compute_report_app_source_digest(source_root)
            if not hmac.compare_digest(embedded_digest, expected_digest):
                raise ValueError("report-app distribution is stale")
        else:
            _validate_packaged_report_app(Path(index_path).parent, embedded_digest)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ReportAppAssetError(
            "stale_source_assets" if source_checkout else "invalid_package_assets",
            source_checkout=source_checkout,
        ) from error
    return embedded_digest


__all__ = [
    "REPORT_APP_SOURCE_META_NAME",
    "REPORT_APP_DIST_MANIFEST_NAME",
    "ReportAppAssetError",
    "build_report_app_dist_manifest",
    "compute_report_app_source_digest",
    "report_app_source_root",
    "validate_report_app_index",
]
