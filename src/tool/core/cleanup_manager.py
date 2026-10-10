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
Cleanup Manager for NVDebug Tool.

Handles directory cleanup, empty directory removal, and zip archive creation for
collected logs with support for split archives.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Mapping, Optional, Sequence


@contextmanager
def _bundle_sanitization_progress(
    orchestrator: object,
) -> Iterator[Optional[Callable[[int, int], None]]]:
    """
    Yield a progress callback for bundle sanitization, or None.

    Sanitizing a large nested-archive bundle is a multi-minute silent phase. A
    determinate bar makes it legible. Everything here is best-effort: if rich is
    unavailable, no console is wired up, or the display raises, the caller still
    sanitizes exactly as before.

    Args:
        orchestrator: Orchestrator consumed while the function attempts to yield
            a progress callback for bundle sanitization, or None.

    Yields:
        Each bundle sanitization progress admitted by the operation, in
        deterministic iteration order.
    """

    console = getattr(orchestrator, "console", None)
    if console is None:
        yield None
        return
    try:
        from rich.progress import (
            BarColumn,
            Progress,
            SpinnerColumn,
            TaskProgressColumn,
            TextColumn,
        )
    except Exception:
        yield None
        return

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            task_id: list[object] = [None]

            def _on_progress(done: int, total: int) -> None:
                """
                Forward one bundle-sanitization progress update.

                The implementation uses ``done`` and ``total`` to forward one
                bundle-sanitization progress update.

                Args:
                    done: Numeric done used while the operation performs bounded
                        accounting.
                    total: Numeric total used while the operation performs
                        bounded accounting.
                """
                if task_id[0] is None:
                    task_id[0] = progress.add_task(
                        "Sanitizing collected bundle...", total=total
                    )
                progress.update(task_id[0], completed=done, total=total)

            yield _on_progress
    except Exception:
        # Never let a display failure interfere with the security control.
        yield None


from ..utils.bounded_archive import archive_creation_limits_from_runtime_boundaries
from ..utils.bundle_sanitizer import (
    BundleSanitizationReport,
    resolve_live_bundle_sanitization_limits,
    sanitize_distributable_bundle,
)
from ..utils.file_utils import cleanup_empty_directories
from ..utils.operation_progress import SanitizedOperationProgress
from ..utils.runtime_boundary_profile import resolve_run_finalization_boundaries
from ..utils.status_snapshot import validate_terminal_snapshot_tree
from ..utils.zip_utils import (
    ArchiveArtifactDigest,
    ArchiveFinalizationError,
    ArchiveMemberDigest,
    create_zip,
    create_zip_split,
    issue_archive_artifact_digests,
    should_skip_zip_creation,
    validate_archive_artifact_digests,
)
from .finalization_receipt import (
    FinalizationReceipt,
    select_authoritative_exception,
    validate_consumable_finalization_receipt,
)

logger = logging.getLogger(__name__)

MAX_ARCHIVE_FAILURE_EVIDENCE_BYTES = 16 * 1024


def _fsync_evidence_directory(path: Path) -> None:
    """
    Synchronize the directory that owns finalization evidence.

    The implementation uses ``path`` to synchronize the directory that owns
    finalization evidence. Filesystem effects remain confined to the
    caller-selected paths and the owning resource lifecycle. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        path: filesystem location used as the path for this operation.
    """
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _canonical_failure_evidence(payload: dict[str, object]) -> bytes:
    """
    Return the canonical failure evidence.

    The implementation uses ``payload`` to produce the canonical failure
    evidence. If the function cannot produce the canonical failure evidence, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        payload: Mapping supplying fields for canonical failure evidence.

    Returns:
        The validated ``encoded``.

    Raises:
        ValueError: If archive failure evidence is too large.
    """
    encoded = (
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_ARCHIVE_FAILURE_EVIDENCE_BYTES:
        raise ValueError("Archive failure evidence is too large")
    return encoded


def _read_exact_private_evidence(path: Path) -> bytes:
    """
    Read exact private evidence.

    The implementation uses ``path`` to read exact private evidence. Parsing or
    I/O must finish before the validated representation is made available to the
    caller. If the function cannot read exact private evidence, its exception
    reaches the caller instead of being converted into a successful result.
    Cleanup in the ``finally`` path runs for successful, failed, and cancelled
    execution.

    Args:
        path: filesystem location used as the path for this operation.

    Returns:
        The validated ``data``.

    Raises:
        RuntimeError: If archive evidence lacks no-follow access.
        ValueError: If archive failure evidence is not a private stable file; or
            archive failure evidence changed while read.
    """
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise RuntimeError("Archive evidence requires no-follow access")
    descriptor = os.open(
        path,
        os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        visible = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o077
            or (before.st_dev, before.st_ino, before.st_size)
            != (visible.st_dev, visible.st_ino, visible.st_size)
            or before.st_size > MAX_ARCHIVE_FAILURE_EVIDENCE_BYTES
        ):
            raise ValueError("Archive failure evidence is not a private stable file")
        data = b""
        while len(data) <= MAX_ARCHIVE_FAILURE_EVIDENCE_BYTES:
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            data += chunk
        after = os.fstat(descriptor)
        visible_after = path.lstat()
        if (
            len(data) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (after.st_dev, after.st_ino, after.st_size)
            != (visible_after.st_dev, visible_after.st_ino, visible_after.st_size)
        ):
            raise ValueError("Archive failure evidence changed while read")
        return data
    finally:
        os.close(descriptor)


def _publish_failure_evidence_no_clobber(
    target: Path, payload: dict[str, object]
) -> None:
    """
    Publish canonical private evidence, or accept an exact durable replay.

    The implementation uses ``target`` and ``payload`` to publish canonical
    private evidence, or accept an exact durable replay. Success is reported
    only after the owning output boundary has completed its required write or
    publication step. If the function cannot publish canonical private evidence,
    or accept an exact durable replay, its exception reaches the caller instead
    of being converted into a successful result. Cleanup in the ``finally`` path
    runs for successful, failed, and cancelled execution.

    Args:
        target: filesystem location used as the target for this operation.
        payload: Mapping supplying fields for canonical private evidence, or
            accept an exact durable replay.

    Raises:
        FileExistsError: If conflicting archive failure evidence: ``target``.
        ValueError: If archive failure evidence replay changed; or durable
            archive failure evidence changed.
    """

    encoded = _canonical_failure_evidence(payload)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = _read_exact_private_evidence(target)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if existing != encoded:
            raise FileExistsError(f"Conflicting archive failure evidence: {target}")
        _fsync_evidence_directory(target.parent)
        if _read_exact_private_evidence(target) != encoded:
            raise ValueError("Archive failure evidence replay changed")
        return

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.stage-",
        dir=target.parent,
    )
    temporary = Path(temporary_name)
    linked = False
    committed = False
    temporary_identity: tuple[int, int] | None = None
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
            metadata = os.fstat(stream.fileno())
            temporary_identity = (metadata.st_dev, metadata.st_ino)
        try:
            os.link(temporary, target, follow_symlinks=False)
            linked = True
        except FileExistsError:
            if _read_exact_private_evidence(target) != encoded:
                raise
            _fsync_evidence_directory(target.parent)
            return
        _fsync_evidence_directory(target.parent)
        temporary.unlink()
        _fsync_evidence_directory(target.parent)
        committed = True
        if _read_exact_private_evidence(target) != encoded:
            raise ValueError("Durable archive failure evidence changed")
    except BaseException:
        if linked and not committed and temporary_identity is not None:
            try:
                visible = target.lstat()
                if (visible.st_dev, visible.st_ino) == temporary_identity:
                    target.unlink()
                    _fsync_evidence_directory(target.parent)
            except BaseException:
                pass
        raise
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            temporary_metadata = temporary.lstat()
            if (
                temporary_identity is None
                or (
                    temporary_metadata.st_dev,
                    temporary_metadata.st_ino,
                )
                == temporary_identity
            ):
                temporary.unlink()
        except FileNotFoundError:
            pass


class CleanupManager:
    """
    Manages cleanup operations and resource finalization.

    Handles post-collection cleanup including empty directory removal and
    archive creation for collected logs.
    """

    def __init__(self, logger):
        """
        Initialize cleanup manager.

        The initializer records ``archive_artifact_digests``,
        ``bundle_sanitization_report``, and ``logger`` for later operations and
        establishes the instance invariants before any public method runs.

        Args:
            logger: Sanitized logger used for operator-visible diagnostics.
        """
        self.logger = logger
        self.bundle_sanitization_report: Optional[BundleSanitizationReport] = None
        self.archive_artifact_digests: tuple[ArchiveArtifactDigest, ...] = ()

    def _finalization_runtime_boundaries(self) -> Mapping[str, int]:
        """
        Return run-wide catalog limits with a safe offline fallback.

        The orchestrator owns cross-DUT selection. Compatibility callers that
        have no orchestrator receive the finite code-owned defaults.

        Returns:
            The resolved finalization boundary mapping for this run.
        """

        orchestrator = getattr(self.logger, "orchestrator", None)
        resolver = getattr(orchestrator, "get_finalization_runtime_boundaries", None)
        if callable(resolver):
            try:
                boundaries = resolver()
                if isinstance(boundaries, Mapping):
                    return boundaries
            except Exception:
                logger.warning("Failed to resolve catalog finalization boundaries")
        return resolve_run_finalization_boundaries(())

    async def cleanup_empty_directories(
        self, log_dir: Path, dut_ids: list[str] | None = None
    ) -> None:
        """
        Clean up empty directories in the log directory.

        Clean up empty directories (scoped to known DUT IDs if provided).

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            dut_ids: Optional DUT identifiers; ``None`` selects the function's
                default behavior.
        """
        try:
            await self.logger.log_runtime(
                "INFO", "CleanupManager", "Cleaning up empty directories..."
            )

            # Clean up empty directories (scoped to known DUT IDs if provided)
            removed = []
            try:
                if (
                    dut_ids is None
                    and hasattr(self.logger, "orchestrator")
                    and self.logger.orchestrator
                    and getattr(self.logger.orchestrator, "dut_manager", None)
                ):
                    dut_ids = self.logger.orchestrator.dut_manager.get_all_dut_ids()
                    await self.logger.log_runtime(
                        "DEBUG",
                        "CleanupManager",
                        f"Retrieved DUT IDs from manager: {dut_ids}",
                    )
            except Exception as e:
                await self.logger.log_runtime(
                    "WARN",
                    "CleanupManager",
                    f"Failed to get DUT IDs from manager: {e}",
                )
                dut_ids = []

            # If we still don't have DUT IDs, try to discover them from the log directory
            if not dut_ids:
                try:
                    discovered_dut_ids = []
                    with os.scandir(str(log_dir)) as entries:
                        for entry in entries:
                            if entry.name.startswith("."):
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                discovered_dut_ids.append(entry.name)
                    dut_ids = discovered_dut_ids
                    await self.logger.log_runtime(
                        "DEBUG",
                        "CleanupManager",
                        f"Discovered DUT IDs from log directory: {dut_ids}",
                    )
                except Exception as e:
                    await self.logger.log_runtime(
                        "WARN",
                        "CleanupManager",
                        f"Failed to discover DUT IDs from log directory: {e}",
                    )

            if dut_ids:
                dut_ids = sorted(dut_ids)

            await self.logger.log_runtime(
                "DEBUG",
                "CleanupManager",
                f"Final DUT IDs for cleanup: {dut_ids}",
            )

            removed = cleanup_empty_directories(str(log_dir), dut_ids or [])

            await self.logger.log_runtime(
                "INFO",
                "CleanupManager",
                f"Empty directory cleanup completed; removed {len(removed)} directories: {removed}",
            )

        except Exception as e:
            await self.logger.log_runtime(
                "ERROR",
                "CleanupManager",
                f"Failed to cleanup empty directories: {e}",
            )

    def _persist_verified_archive_failure(
        self, log_dir: Path, error: BaseException
    ) -> None:
        """
        Record a post-verification failure beside immutable archive bytes.

        A source tree may be only partially present after an interrupted rmtree.
        Once verified archive paths exist, never advertise that residue as a
        second authoritative loose representation.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            error: Exception or failure detail associated with the operation.
        """

        verified_paths = tuple(getattr(error, "verified_archive_paths", ()) or ())[
            :4096
        ]
        if not verified_paths:
            return

        message = str(error)[:4096]
        sanitizer = getattr(self.logger, "sanitizer", None)
        sanitize = getattr(sanitizer, "sanitize", None)
        if callable(sanitize):
            try:
                message = str(sanitize(message))[:4096]
            except Exception:
                message = "[archive failure sanitization failed]"

        # A source tree may be only partially present after an interrupted
        # rmtree. Once verified archive paths exist, never advertise that
        # residue as a second authoritative loose representation.
        loose_bundle_retained = False
        payload = {
            "state": "failed",
            "operation": "archive_creation",
            "phase": str(getattr(error, "phase", "archive_creation"))[:128]
            or "archive_creation",
            "loose_bundle_retained": loose_bundle_retained,
            "verified_archive_retained": True,
            "verified_archive_files": [Path(path).name for path in verified_paths],
            "representation": (
                "verified_archive_and_recoverable_loose"
                if loose_bundle_retained
                else "verified_archive"
            ),
            "error": message,
        }

        target = log_dir.parent / f"{log_dir.name}.archive_failure.json"
        _publish_failure_evidence_no_clobber(target, payload)

    def _run_archive_factory(
        self,
        log_dir: Path,
        archive_factory,
        *args,
        **kwargs,
    ):
        """
        Run an archive transaction and bind any verified retained output.

        After applying local validation, the function forwards ``log_dir``,
        ``archive_factory``, ``args``, and ``kwargs`` to ``archive_factory`` and
        preserves its return and exception contract. Terminal status is emitted
        only after archive transaction and bind any verified retained output and
        its owned cleanup have completed. It updates
        ``archive_artifact_digests`` on the instance as part of that state
        transition.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            archive_factory: Callable invoked at the archive factory boundary.
            args: Additional positional values forwarded in caller-provided
                order.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The archive-factory result after any verified retained artifact is
            bound.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to run an archive transaction and bind any verified
                retained output.
        """

        try:
            return archive_factory(*args, **kwargs)
        except BaseException as error:
            observed_errors: list[BaseException] = [error]
            verified_paths = tuple(getattr(error, "verified_archive_paths", ()) or ())
            if verified_paths:
                try:
                    self.archive_artifact_digests = issue_archive_artifact_digests(
                        verified_paths
                    )
                except BaseException as evidence_error:
                    observed_errors.append(evidence_error)
                    try:
                        error.add_note(
                            "Verified archive evidence could not be retained: "
                            f"{type(evidence_error).__name__}"
                        )
                    except BaseException:
                        pass
            try:
                self._persist_verified_archive_failure(log_dir, error)
            except BaseException as persistence_error:
                observed_errors.append(persistence_error)
                logger.error(
                    "Failed to prepare verified archive evidence (%s)",
                    type(persistence_error).__name__,
                )
            authoritative = select_authoritative_exception(observed_errors)
            if authoritative is not error:
                try:
                    setattr(
                        authoritative,
                        "phase",
                        getattr(error, "phase", "archive_creation"),
                    )
                    setattr(
                        authoritative,
                        "verified_archive_paths",
                        tuple(verified_paths),
                    )
                    setattr(
                        authoritative,
                        "loose_bundle_retained",
                        getattr(error, "loose_bundle_retained", False),
                    )
                except BaseException:
                    pass
            raise authoritative

    async def create_zip_archive(
        self,
        log_dir: Path,
        skip_zip: bool = False,
        skip_zip_split: bool = False,
        zip_split_threshold: float = 200.0,
        *,
        expected_snapshot_leaf_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
        required_member_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
        archive_member_mode: Optional[int] = None,
    ) -> Optional[str]:
        """
        Create zip archive of the log directory.

        The implementation uses ``log_dir``, ``skip_zip``, ``skip_zip_split``,
        ``zip_split_threshold``, and ``expected_snapshot_leaf_digests`` to
        create zip archive of the log directory. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. It updates ``archive_artifact_digests`` on the instance as part
        of that state transition.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            skip_zip: Whether skip ZIP is enabled or required for this
                operation.
            skip_zip_split: Whether skip ZIP split is enabled or required for
                this operation.
            zip_split_threshold: Numeric ZIP split threshold used while the
                operation performs bounded accounting.
            expected_snapshot_leaf_digests: Optional expected snapshot leaf
                digests; ``None`` selects the function's default behavior.
            required_member_digests: Optional required member digests; ``None``
                selects the function's default behavior.
            archive_member_mode: Optional exact permission mode recorded for
                every regular ZIP member.

        Returns:
            The canonical ZIP archive text, or ``None`` when the requested value
            is unavailable.

        Raises:
            RuntimeError: If the managed-publication delivery validator returns
                a value instead of completing normally.
            BaseException: If control flow is requested or verified archive
                evidence requires the original archive failure to propagate.
        """
        self.archive_artifact_digests = ()
        receipt_bound = bool(
            expected_snapshot_leaf_digests is not None
            or required_member_digests is not None
        )
        orchestrator = getattr(self.logger, "orchestrator", None)
        archive_progress = SanitizedOperationProgress(
            getattr(orchestrator, "sanitized_console", None),
            "Creating ZIP archive",
        )

        def retain_archive_evidence(
            evidence: tuple[ArchiveArtifactDigest, ...],
        ) -> None:
            """
            Retain bounded failure evidence for an archive attempt.

            The implementation uses ``evidence`` to retain bounded failure
            evidence for an archive attempt. It updates
            ``archive_artifact_digests`` on the instance as part of that state
            transition.

            Args:
                evidence: Entries supplied as ``evidence`` without transferring
                    container ownership.
            """
            self.archive_artifact_digests = validate_archive_artifact_digests(evidence)

        def validate_result_evidence(result: str | list[str]) -> None:
            """
            Validate result evidence.

            The implementation uses ``result`` to validate result evidence.
            Every required invariant is checked before a successful value is
            returned; invalid input follows the function's explicit exception
            path.

            Args:
                result: Entries supplied as ``result`` without transferring
                    container ownership.
            """
            paths = tuple(result) if isinstance(result, list) else (result,)
            if receipt_bound or self.archive_artifact_digests:
                validate_archive_artifact_digests(
                    self.archive_artifact_digests,
                    paths,
                )

        try:
            # Check if zip creation should be skipped
            if should_skip_zip_creation(skip_zip, skip_zip_split):
                await self.logger.log_runtime(
                    "INFO",
                    "CleanupManager",
                    "Zip creation skipped by configuration",
                )
                return None

            if not log_dir.exists():
                await self.logger.log_runtime(
                    "WARNING",
                    "CleanupManager",
                    f"Log directory {log_dir} does not exist, skipping zip creation",
                )
                return None

            delivery_validator = getattr(
                type(self.logger),
                "validate_managed_publication_exclusions_for_delivery",
                None,
            )
            if callable(delivery_validator):
                validation_result = delivery_validator(self.logger)
                if validation_result is not None:
                    raise RuntimeError(
                        "Managed publication delivery validator returned a value"
                    )

            await self.logger.log_runtime(
                "INFO", "CleanupManager", "Creating zip archive..."
            )
            archive_progress.start()

            # Get the base name for the zip file
            zip_name = log_dir.name
            archive_digest_kwargs = {}
            exclusion_provider = getattr(
                type(self.logger),
                "managed_publication_delivery_exclusion_paths",
                None,
            )
            if callable(exclusion_provider):
                excluded_source_paths = exclusion_provider(self.logger)
                if excluded_source_paths:
                    archive_digest_kwargs["excluded_source_paths"] = (
                        excluded_source_paths
                    )
            if expected_snapshot_leaf_digests is not None:
                archive_digest_kwargs["expected_snapshot_leaf_digests"] = (
                    expected_snapshot_leaf_digests
                )
            if required_member_digests is not None:
                archive_digest_kwargs["required_member_digests"] = (
                    required_member_digests
                )
            if archive_member_mode is not None:
                archive_digest_kwargs["archive_member_mode"] = archive_member_mode
            archive_digest_kwargs["archive_evidence_sink"] = retain_archive_evidence
            archive_digest_kwargs["archive_limits"] = (
                archive_creation_limits_from_runtime_boundaries(
                    self._finalization_runtime_boundaries()
                )
            )
            if archive_progress.enabled:
                archive_digest_kwargs["progress_callback"] = archive_progress.update

            if skip_zip_split:
                # Create regular zip without splitting
                zip_path = self._run_archive_factory(
                    log_dir,
                    create_zip,
                    str(log_dir),
                    zip_name,
                    **archive_digest_kwargs,
                )
                validate_result_evidence(zip_path)
                # The loose source has been removed. Do not introduce an await
                # or provider-owned failure between the verified archive commit
                # and returning its receipt evidence to the orchestrator.
                try:
                    logger.info("Zip archive created: %s", zip_path)
                except BaseException:
                    pass
                return zip_path
            else:
                # Create zip with potential splitting
                zip_result = self._run_archive_factory(
                    log_dir,
                    create_zip_split,
                    str(log_dir),
                    zip_name,
                    split=True,
                    max_size_mb=zip_split_threshold,
                    **archive_digest_kwargs,
                )

                # Handle both single file and split files cases
                if isinstance(zip_result, list):
                    validate_result_evidence(zip_result)
                    # Files were split - return the list of all files
                    try:
                        logger.info(
                            "Split archive created with %d files",
                            len(zip_result),
                        )
                    except BaseException:
                        pass
                    return zip_result
                else:
                    validate_result_evidence(zip_result)
                    # Single file - return the path
                    try:
                        logger.info(
                            "Zip archive created (with splitting): %s", zip_result
                        )
                    except BaseException:
                        pass
                    return zip_result

        except BaseException as e:
            verified_paths = tuple(getattr(e, "verified_archive_paths", ()) or ())
            if not verified_paths:
                self.archive_artifact_digests = ()
            try:
                await self.logger.log_runtime(
                    "ERROR", "CleanupManager", f"Failed to create zip archive: {e}"
                )
            except BaseException as logging_error:
                try:
                    e.add_note(
                        "Archive failure logging also failed: "
                        f"{type(logging_error).__name__}"
                    )
                except BaseException:
                    pass
            # The callee preserves the authoritative sibling sidecar when it
            # exists, and writes a retained-bundle fallback only if sibling
            # persistence failed or the archive was never verified.
            try:
                self._persist_loose_archive_failure(log_dir, e)
            except BaseException:
                logger.error("Failed to prepare archive failure evidence")
            if (
                not isinstance(e, Exception)
                or verified_paths
                or isinstance(e, ArchiveFinalizationError)
            ):
                raise
            # Preserve compatibility with third-party archive factories which
            # historically report an ordinary exception as an empty result.
            # Project-owned transactional errors propagate after their retained
            # evidence is durable so terminal reporting keeps the exact phase.
            return None
        finally:
            archive_progress.stop()

    def _persist_loose_archive_failure(
        self, log_dir: Path, error: BaseException
    ) -> None:
        """
        Record why an archive request retained its loose source bundle.

        Preserve the historical single-sidecar contract for third-party archive
        factories. Transactional finalization errors additionally retain an
        in-bundle copy only after source validation completed. A preflight
        rejection cannot authorize traversal of the unvalidated tree, so its
        private record remains beside the loose root under the output parent.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            error: Exception or failure detail associated with the operation.
        """

        if (
            getattr(error, "loose_bundle_retained", False) is not True
            or not log_dir.is_dir()
            or log_dir.is_symlink()
        ):
            return
        sibling_sidecar = log_dir.parent / f"{log_dir.name}.archive_failure.json"
        if (
            getattr(error, "verified_archive_paths", None)
            and sibling_sidecar.is_file()
            and not isinstance(error, ArchiveFinalizationError)
        ):
            # Preserve the historical single-sidecar contract for third-party
            # archive factories. Transactional finalization errors additionally
            # retain an in-bundle copy so either recoverable representation
            # carries the same failure evidence.
            return
        message = str(error)[:4096]
        sanitizer = getattr(self.logger, "sanitizer", None)
        sanitize = getattr(sanitizer, "sanitize", None)
        if callable(sanitize):
            try:
                message = str(sanitize(message))[:4096]
            except Exception:
                message = "[archive failure sanitization failed]"

        verified_paths = tuple(getattr(error, "verified_archive_paths", ()) or ())[
            :4096
        ]
        verified_files = [Path(path).name for path in verified_paths]
        verified_archive_retained = bool(verified_files)
        source_validation_complete = (
            getattr(error, "archive_source_validation_complete", None) is not False
        )
        payload = {
            "state": "failed",
            "operation": "archive_creation",
            "phase": str(getattr(error, "phase", "archive_creation"))[:128]
            or "archive_creation",
            "loose_bundle_retained": True,
            "verified_archive_retained": verified_archive_retained,
            "verified_archive_files": verified_files,
            "representation": (
                "verified_archive_and_recoverable_loose"
                if verified_archive_retained
                else "loose"
            ),
            "error": message,
        }

        target = (
            log_dir / ".metadata" / "archive_failure.json"
            if source_validation_complete
            else sibling_sidecar
        )
        _publish_failure_evidence_no_clobber(target, payload)

    async def cleanup(self, log_dir: Path) -> None:
        """
        Perform comprehensive cleanup operations.

        The implementation uses ``log_dir`` to perform comprehensive cleanup
        operations. Owned asynchronous work is awaited before return, so
        completion does not leave an unobserved task behind.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
        """
        try:
            await self.logger.log_runtime(
                "INFO", "CleanupManager", "Starting cleanup operations..."
            )

            # Clean up empty directories
            await self.cleanup_empty_directories(log_dir)

            # Clean up DUT manager resources (including Redfish sessions)
            if (
                hasattr(self.logger, "orchestrator")
                and self.logger.orchestrator
                and getattr(self.logger.orchestrator, "dut_manager", None)
            ):
                await self.logger.log_runtime(
                    "INFO",
                    "CleanupManager",
                    "Cleaning up DUT manager resources...",
                )
                await self.logger.orchestrator.dut_manager.cleanup()

            # Create metadata files (but don't finalize logger yet)
            await self.logger._create_root_metadata_aggregator()
            await self.logger._create_all_group_files()

            await self.logger.log_runtime(
                "INFO",
                "CleanupManager",
                "Cleanup operations completed successfully",
            )

        except Exception as e:
            await self.logger.log_runtime(
                "ERROR", "CleanupManager", f"Cleanup failed: {e}"
            )
            raise

    async def finalize_logger(self) -> None:
        """
        Finalize the logger (call this after HTML generation).

        The implementation uses current instance state to finalize the logger
        (call this after HTML generation). Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.
        """
        try:
            await self.logger.log_runtime(
                "INFO", "CleanupManager", "Finalizing logger..."
            )
            await self.logger.finalize()
        except Exception as e:
            await self.logger.log_runtime(
                "ERROR", "CleanupManager", f"Failed to finalize logger: {e}"
            )
            raise

    async def sanitize_distributable_bundle(
        self,
        log_dir: Path,
        *,
        status_receipt: FinalizationReceipt | None = None,
    ) -> BundleSanitizationReport:
        """
        Sanitize every distributable artifact after logger finalization.

        Mandatory resource/session/logger teardown has completed before this
        terminal boundary, so no useful event-loop work remains to overlap.
        Running the filesystem transaction directly also avoids making
        publication authorization depend on an executor completion wakeup after
        the loop has become otherwise idle.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            status_receipt: Optional status receipt; ``None`` selects the
                function's default behavior.

        Returns:
            The validated ``report``.
        """
        validated_status_leaf_digests = None
        receipt_validation_failed = False
        if status_receipt is not None:
            try:
                generation, roster = validate_consumable_finalization_receipt(
                    status_receipt
                )
                validate_terminal_snapshot_tree(
                    Path(log_dir),
                    roster,
                    expected_generation=generation,
                    expected_leaf_digests=status_receipt.snapshot_leaf_digests,
                    allow_pending_run_result=True,
                )
                validated_status_leaf_digests = status_receipt.snapshot_leaf_digests
            except Exception:
                # Receipt authority is optional for privacy inspection.  A bad
                # receipt must revoke generated-status exemptions and block
                # publication without skipping the mandatory backstop scan.
                receipt_validation_failed = True

        # Sanitizing a large nested-archive bundle can run for minutes. Without
        # any output the tool looks hung, so surface determinate progress when a
        # console is available. The callback is best-effort: sanitization is a
        # fail-closed security control and must not depend on the display.
        try:
            with _bundle_sanitization_progress(
                getattr(self.logger, "orchestrator", None)
            ) as on_progress:
                report = sanitize_distributable_bundle(
                    log_dir,
                    getattr(self.logger, "sanitizer", None),
                    limits=resolve_live_bundle_sanitization_limits(
                        self._finalization_runtime_boundaries()
                    ),
                    validated_status_leaf_digests=validated_status_leaf_digests,
                    progress_callback=on_progress,
                )
        except BaseException as error:
            self.bundle_sanitization_report = BundleSanitizationReport(
                errors=[
                    "post-collection sanitization aborted: " f"{type(error).__name__}"
                ]
            )
            raise
        if receipt_validation_failed:
            report.errors.append("terminal status receipt validation failed")
        self.bundle_sanitization_report = report
        if report.errors:
            logger.warning(
                "Bundle sanitization could not inspect %d artifact(s): %s",
                len(report.errors),
                "; ".join(report.errors),
            )
        else:
            logger.info(
                "Bundle sanitization complete: %d files scanned, %d rewritten, "
                "%d nested archives inspected",
                report.scanned_files,
                report.sanitized_files,
                report.scanned_archives,
            )
        return report

    async def create_final_zip_archive(
        self,
        log_dir: Path,
        *,
        expected_snapshot_leaf_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
        required_member_digests: Optional[Sequence[ArchiveMemberDigest]] = None,
    ) -> Optional[str]:
        """
        Create zip archive after logger finalization (all files are closed).

        Sanitized bundles record completed files and parent directories as
        0755 so a separate report-server account can traverse an extracted copy,
        regardless of whether the output path was explicit. Owner-private
        selection evidence stays 0600. Unsanitized archives retain source modes.
        The implementation uses ``log_dir``, ``expected_snapshot_leaf_digests``,
        and ``required_member_digests`` to create zip archive after logger
        finalization (all files are closed). Owned asynchronous work is awaited
        before return, so completion does not leave an unobserved task behind.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            expected_snapshot_leaf_digests: Optional expected snapshot leaf
                digests; ``None`` selects the function's default behavior.
            required_member_digests: Optional required member digests; ``None``
                selects the function's default behavior.

        Returns:
            The validated ``zip_path``, or ``None`` when no value qualifies.
        """
        try:
            # Get tool config for zip settings
            if hasattr(self.logger, "orchestrator") and self.logger.orchestrator:
                # For cleanup operations, we use the global tool config since this affects the entire run
                # DUT-specific tool config overrides would not apply to cleanup operations
                tool_config = self.logger.orchestrator.config_manager.get_tool_config()

                # Check both possible key names for skip_zip - check both top level and output section
                output_config = tool_config.get("output", {})
                skip_zip = output_config.get(
                    "skip_zip", tool_config.get("skip_zip", False)
                ) or output_config.get("skipzip", tool_config.get("skipzip", False))

                skip_zip_split = output_config.get(
                    "skip_zip_split", tool_config.get("skip_zip_split", False)
                ) or output_config.get(
                    "skipzipsplit", tool_config.get("skipzipsplit", False)
                )
                zip_split_threshold = output_config.get(
                    "zip_split_threshold", tool_config.get("zip_split_threshold", 200.0)
                )

                # Use existing console if available and debug mode is enabled
                # debug_message = f"Zip settings - skip_zip: {skip_zip}, skip_zip_split: {skip_zip_split}, zip_split_threshold: {zip_split_threshold}"
                # if hasattr(self.logger, "orchestrator") and self.logger.orchestrator:
                #     if hasattr(self.logger.orchestrator, "sanitized_console"):
                #         self.logger.orchestrator.sanitized_console.print_debug(
                #             debug_message
                #         )
                #     elif hasattr(self.logger.orchestrator, "console"):
                #         self.logger.orchestrator.console.print(
                #             f"[DEBUG] CleanupManager: {debug_message}"
                #         )
                #     else:
                #         print(f"[DEBUG] CleanupManager: {debug_message}")
                # else:
                #     print(f"[DEBUG] CleanupManager: {debug_message}")

                if not skip_zip:
                    # Create zip archive (all files are now closed and flushed)
                    archive_digest_kwargs = {}
                    if expected_snapshot_leaf_digests is not None:
                        archive_digest_kwargs["expected_snapshot_leaf_digests"] = (
                            expected_snapshot_leaf_digests
                        )
                    if required_member_digests is not None:
                        archive_digest_kwargs["required_member_digests"] = (
                            required_member_digests
                        )
                    if not bool(tool_config.get("skip_sanitization", False)):
                        archive_digest_kwargs["archive_member_mode"] = 0o755
                    zip_path = await self.create_zip_archive(
                        log_dir,
                        skip_zip=skip_zip,
                        skip_zip_split=skip_zip_split,
                        zip_split_threshold=zip_split_threshold,
                        **archive_digest_kwargs,
                    )
                    return zip_path
            return None
        except BaseException as e:
            if (
                not isinstance(e, Exception)
                or getattr(e, "verified_archive_paths", None)
                or isinstance(e, ArchiveFinalizationError)
            ):
                raise
            # Log error but don't raise - zip creation failure shouldn't stop the process
            print(f"Warning: Failed to create final zip archive: {e}")
            return None
