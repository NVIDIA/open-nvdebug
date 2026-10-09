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
Durable post-collection outcome publication.

This module owns the post collection outcome boundary and exposes
``PostCollectionOutcomePublisher``. Keeping those contracts together gives
importers one source of truth for their validation, lifecycle, and compatibility
behavior.
"""

from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.delivery_evidence import write_terminal_outcome_override_evidence
from ..core.finalization_receipt import (
    FinalizationFailure,
    FinalizationOutcomeHint,
    FinalizationReceipt,
    sanitize_finalization_message,
    validate_structural_finalization_receipt,
)
from ..core.run_result import RunResult
from .run_limits import is_printable_identity
from .zip_utils import issue_archive_artifact_digests


class PostCollectionOutcomePublisher:
    """
    Publish late failures to the surviving collection representation.

    The type coordinates ``publish_post_collection_outcome`` and
    ``_write_archive_terminal_outcome`` and retains the state those operations
    share between calls. Resource ownership remains inside the instance until
    the matching close, exit, or cleanup operation completes.
    """

    async def publish_post_collection_outcome(
        self,
        *,
        status: str,
        reason: str,
        failure_type: Optional[str] = None,
    ) -> None:
        """
        Publish a post-collection failure to mutable or archived evidence.

        The implementation uses ``status``, ``reason``, and ``failure_type`` to
        publish a post-collection failure to mutable or archived evidence.
        Success is reported only after the owning output boundary has completed
        its required write or publication step. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. It updates ``terminal_override_receipt`` and
        ``terminal_override_run_result`` on the instance as part of that state
        transition. If the function cannot publish a post-collection failure to
        mutable or archived evidence, its exception reaches the caller instead
        of being converted into a successful result.

        Args:
            status: Text supplied as status in the format accepted by this
                function.
            reason: Text supplied as reason in the format accepted by this
                function.
            failure_type: Optional failure type; ``None`` selects the function's
                default behavior.

        Raises:
            ValueError: If unsupported post-collection outcome: ``status``.
            RuntimeError: If invalid terminal failure type; canonical
                finalization receipt is unavailable for archive override; or
                orchestrator cannot record a run outcome.
        """

        orchestrator = getattr(self, "orchestrator", None)
        if orchestrator is None:
            return
        if status not in {"runtime_failed", "interrupted"}:
            raise ValueError(f"unsupported post-collection outcome: {status!r}")

        raw_log_dir = getattr(orchestrator, "log_dir", None)
        if raw_log_dir is None:
            return

        dut_manager = getattr(orchestrator, "dut_manager", None)
        affected_duts = (
            list(dut_manager.get_all_dut_ids()) if dut_manager is not None else []
        )
        log_dir = Path(raw_log_dir)
        if not log_dir.is_dir():
            raw_archives = getattr(orchestrator, "zip_archive_path", None)
            if not raw_archives:
                return
            archive_paths = (
                [Path(path) for path in raw_archives]
                if isinstance(raw_archives, list)
                else [Path(raw_archives)]
            )
            sanitizer = (
                getattr(self, "sanitizer", None)
                or getattr(orchestrator, "sanitizer", None)
                or getattr(getattr(orchestrator, "logger", None), "sanitizer", None)
            )
            sanitizer_callable = (
                getattr(sanitizer, "sanitize", None) if sanitizer is not None else None
            )
            rendered_reason = sanitize_finalization_message(
                reason,
                sanitizer=sanitizer_callable,
            )
            canonical_failure = str(failure_type or "upload_failure")
            if status == "runtime_failed" and not is_printable_identity(
                canonical_failure,
                maximum_bytes=256,
            ):
                raise RuntimeError("invalid terminal failure type")

            base_receipt = getattr(self, "finalization_receipt", None)
            if type(base_receipt) is not FinalizationReceipt:
                base_receipt = getattr(orchestrator, "finalization_receipt", None)
            if type(base_receipt) is not FinalizationReceipt:
                raise RuntimeError(
                    "Canonical finalization receipt is unavailable for archive override"
                )
            validate_structural_finalization_receipt(base_receipt)

            if not base_receipt.archive_artifact_digests:
                cleanup_manager = getattr(orchestrator, "cleanup_manager", None)
                archive_digests = getattr(
                    cleanup_manager,
                    "archive_artifact_digests",
                    (),
                )
                if not archive_digests:
                    archive_digests = issue_archive_artifact_digests(
                        tuple(archive_paths)
                    )
                base_receipt = base_receipt.with_archive_evidence(
                    tuple(archive_digests),
                    archive_duration_seconds=0.0,
                )

            affected = tuple(
                dut_id
                for dut_id in dict.fromkeys(affected_duts)
                if dut_id in base_receipt.dut_roster
            )
            if not affected:
                affected = tuple(base_receipt.dut_roster)
            prior_hint = base_receipt.outcome_hint
            if prior_hint.status == "domain_failed":
                late_receipt = base_receipt.with_cleanup_evidence(
                    completed_teardown_phases=base_receipt.completed_teardown_phases,
                    failures=(
                        *base_receipt.failures,
                        FinalizationFailure(
                            phase="post_collection",
                            error_type=(
                                canonical_failure
                                if status == "runtime_failed"
                                else "interrupted"
                            ),
                            message=rendered_reason,
                        ),
                    ),
                )
            else:
                late_receipt = replace(
                    base_receipt,
                    outcome_hint=FinalizationOutcomeHint(
                        status=status,
                        failure_type=(
                            canonical_failure if status == "runtime_failed" else ""
                        ),
                        reason=rendered_reason,
                        affected_duts=affected,
                    ),
                )
            if status == "interrupted":
                late_receipt = late_receipt.with_interruption()
            late_result = RunResult.from_finalization_receipt(late_receipt)
            self._write_archive_terminal_outcome(
                log_dir,
                archive_paths,
                receipt=late_receipt,
                run_result=late_result,
            )
            self.terminal_override_receipt = late_receipt
            self.terminal_override_run_result = late_result
            return

        recorder = getattr(orchestrator, "record_run_outcome", None)
        if not callable(recorder):
            raise RuntimeError("orchestrator cannot record a run outcome")

        if status == "interrupted":
            await recorder(
                "interrupted",
                reason=reason,
                affected_duts=affected_duts,
            )
            return
        await recorder(
            "runtime_failed",
            failure_type=failure_type or "upload_failure",
            reason=reason,
            affected_duts=affected_duts,
        )

    @staticmethod
    def _write_archive_terminal_outcome(
        log_dir: Path,
        archive_paths: List[Path],
        outcome: Dict[str, Any] | None = None,
        *,
        receipt: FinalizationReceipt | None = None,
        run_result: RunResult | None = None,
    ) -> None:
        """
        Write only receipt-derived canonical archive override evidence.

        The implementation uses ``log_dir``, ``archive_paths``, ``outcome``,
        ``receipt``, and ``run_result`` to write only receipt-derived canonical
        archive override evidence. Success is reported only after the owning
        output boundary has completed its required write or publication step. If
        the function cannot write only receipt-derived canonical archive
        override evidence, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            log_dir: filesystem location used as the log dir for this operation.
            archive_paths: filesystem location used as the archive paths for
                this operation.
            outcome: Optional outcome; ``None`` selects the function's default
                behavior.
            receipt: Optional receipt; ``None`` selects the function's default
                behavior.
            run_result: Optional run result; ``None`` selects the function's
                default behavior.

        Raises:
            RuntimeError: If canonical receipt and RunResult are required for an
                archive override.
        """

        del outcome  # Legacy mutable outcomes are never an authority.
        if (
            type(receipt) is not FinalizationReceipt
            or type(run_result) is not RunResult
        ):
            raise RuntimeError(
                "Canonical receipt and RunResult are required for an archive override"
            )
        write_terminal_outcome_override_evidence(
            receipt=receipt,
            run_result=run_result,
            run_directory=Path(log_dir),
            archive_paths=tuple(Path(path) for path in archive_paths),
        )
