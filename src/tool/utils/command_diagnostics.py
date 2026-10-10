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
Capture command transcripts at the shared transport return boundary.

These sanitized diagnostic artifacts complement the content-free execution
ledger. Capture happens before service-specific parsers can discard streams or
replace a process exit code with a collector status.
"""

import inspect
import time
from contextvars import ContextVar
from functools import wraps
from typing import Any, Callable

_active_streams: ContextVar[dict[str, list[Any]] | None] = ContextVar(
    "command_diagnostic_streams", default=None
)


class CommandDiagnosticPublicationError(RuntimeError):
    """
    Report a local diagnostic failure without requesting transport recovery.

    A completed command must not be replayed just because saving its transcript
    failed. Keeping publication failures distinct from OSError prevents shared
    SSH batches from mistaking a local disk failure for a broken connection.
    """


def retain_command_stream(stream_name: str, chunks: list[Any]) -> None:
    """
    Borrow an already bounded pipe buffer until its command owner completes.

    The SSH and subprocess readers continue to own byte-limit enforcement and
    task cleanup. Sharing their existing lists avoids a second raw-output buffer
    and preserves bytes read before cancellation or a transport exception.

    Args:
        stream_name: Standard output or standard error label from the reader.
        chunks: Reader-owned list, populated only after its byte-budget checks.
    """

    streams = _active_streams.get()
    if streams is not None and stream_name in {"stdout", "stderr"}:
        streams[stream_name] = chunks


def capture_command_diagnostics(transport: str) -> Callable:
    """
    Decorate a DUT command method while preserving its return and cancellation.

    Only the command and result are recorded; credentials, environment values,
    stdin, and managed protocol bytes never enter a transcript. Concrete logger
    implementations own attribution, sanitization, limits, and publication.

    Args:
        transport: Stable transport name recorded with each result.

    Returns:
        A decorator for asynchronous methods returning exit code, stdout, stderr.
    """

    def decorate(method: Callable) -> Callable:
        """
        Bind the command signature once and preserve its public metadata.

        Signature binding accepts both positional and keyword invocation without
        inspecting credentials or serializing the method's full argument mapping.

        Args:
            method: DUT manager command coroutine to wrap.

        Returns:
            A coroutine with the same call signature and result contract.
        """

        signature = inspect.signature(method)

        @wraps(method)
        async def execute(self: Any, *args: Any, **kwargs: Any) -> Any:
            """
            Await the command and publish its result before returning to a parser.

            Publication is awaited by the command owner. An original transport
            exception remains primary if writing its diagnostic also fails.

            Args:
                self: DUT manager owning the logger and transport.
                args: Positional arguments passed unchanged to the command.
                kwargs: Named arguments passed unchanged to the command.

            Returns:
                The original command result without stream or exit-code changes.

            Raises:
                BaseException: The original command exception or cancellation;
                    a publication failure propagates after an otherwise completed
                    command, without replaying that command.
            """

            logger = getattr(self, "logger", None)
            # A missing recorder is supported for lightweight embedders and
            # transport unit-test doubles. Never invoke a dynamically fabricated
            # Mock attribute as though it were a production logging boundary.
            recorder = getattr(type(logger), "record_command_diagnostic", None)
            if recorder is None:
                return await method(self, *args, **kwargs)
            bound = signature.bind(self, *args, **kwargs)
            bound.apply_defaults()
            values = bound.arguments
            dut_id = values.get("dut_id") or getattr(values.get("dut"), "dut_id", None)
            started = time.monotonic()
            result = None
            error = None
            redacted = values.get("redact_command") is True
            streams: dict[str, list[Any]] = {}
            stream_token = _active_streams.set(None if redacted else streams)
            try:
                result = await method(self, *args, **kwargs)
                return result
            except BaseException as exc:
                error = exc
                raise
            finally:
                try:
                    exit_code, stdout, stderr = (
                        result if result is not None else (None, "", "")
                    )
                    if streams and (error is not None or exit_code == -1):
                        partial = {}
                        for name, chunks in streams.items():
                            partial[name] = (
                                b"".join(chunks)
                                if chunks and isinstance(chunks[0], bytes)
                                else "".join(chunks)
                            )
                        await recorder(
                            logger,
                            dut_id,
                            transport=transport,
                            command=values.get("command", ""),
                            exit_code=None,
                            stdout=partial.get("stdout", ""),
                            stderr=partial.get("stderr", ""),
                            timeout=values.get("timeout"),
                            duration_seconds=time.monotonic() - started,
                            operation=method.__name__ + "_partial_streams",
                            target="hmc" if values.get("hmc") else transport,
                            outcome="transport_incomplete",
                            error=error,
                        )
                    await recorder(
                        logger,
                        dut_id,
                        transport=transport,
                        command=values.get("command", ""),
                        exit_code=exit_code,
                        stdout="" if redacted else stdout,
                        stderr=stderr,
                        timeout=values.get("timeout"),
                        duration_seconds=time.monotonic() - started,
                        operation=method.__name__,
                        target="hmc" if values.get("hmc") else transport,
                        error=error,
                        redacted=redacted,
                    )
                except BaseException as capture_error:
                    if not isinstance(capture_error, Exception):
                        raise
                    if error is None:
                        raise CommandDiagnosticPublicationError(
                            "Command diagnostic publication failed"
                        ) from capture_error
                    # Preserve the transport exception or cancellation as the
                    # primary failure, with a non-secret note about lost evidence.
                    error.add_note("Command diagnostic publication also failed")
                finally:
                    _active_streams.reset(stream_token)

        return execute

    return decorate
