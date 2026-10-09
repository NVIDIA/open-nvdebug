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
Validated finite memory ceilings for Redfish responses and evidence.

This module owns the redfish limits boundary and exposes
``bound_redfish_collection_members``, ``validate_redfish_limit_integer``,
``clamp_redfish_attachment_limit``, ``parse_redfish_limit_environment``, and
``RedfishResponseLimits``. Keeping those contracts together gives importers one
source of truth for their validation, lifecycle, and compatibility behavior.
"""

from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_SIGNED_64_BIT_INTEGER = (1 << 63) - 1
MEBIBYTE = 1024 * 1024

DEFAULT_REDFISH_STRUCTURED_RESPONSE_MAX_BYTES = 64 * MEBIBYTE
DEFAULT_REDFISH_ATTACHMENT_MAX_BYTES = 2 * 1024 * MEBIBYTE
DEFAULT_REDFISH_ERROR_RESPONSE_MAX_BYTES = MEBIBYTE
DEFAULT_REDFISH_ERROR_EVIDENCE_MAX_BYTES = 256 * 1024
DEFAULT_REDFISH_ERROR_EVIDENCE_AGGREGATE_MAX_BYTES = MEBIBYTE
DEFAULT_REDFISH_ERROR_EVIDENCE_MAX_RESPONSES = 4
DEFAULT_REDFISH_PREFLIGHT_RESPONSE_MAX_BYTES = MEBIBYTE
DEFAULT_REDFISH_CACHE_MAX_BYTES = 32 * MEBIBYTE
DEFAULT_REDFISH_CACHE_ENTRY_MAX_BYTES = 4 * MEBIBYTE
DEFAULT_REDFISH_PROBE_RESPONSE_MAX_BYTES = 16 * MEBIBYTE
DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_RECORD_BYTES = 256 * MEBIBYTE
DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_ARTIFACT_BYTES = 2 * 1024 * MEBIBYTE
DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_SPOOL_BYTES = 8 * 1024 * MEBIBYTE
DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_OBJECTS = 256
DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_READERS = 64
DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_FILE_DESCRIPTORS = 257
DEFAULT_REDFISH_REQUEST_CAPTURE_WORKER_COUNT = 16
MAX_REDFISH_REQUEST_CAPTURE_WORKER_COUNT = 64
DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_RECORDS = 100_000
DEFAULT_REDFISH_REQUEST_CAPTURE_MIN_FREE_SPACE_RESERVE_BYTES = 512 * MEBIBYTE
# A Redfish collection is controlled by the remote BMC. Dereferencing every
# advertised member turns one response into one authenticated request per item,
# so all collection-walk callers share this finite amplification ceiling.
MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS = 1024
# AdditionalDataURI-heavy event logs can advertise thousands of independent
# authenticated downloads.  Preserve every EventLog row, but cap the secondary
# request amplification at the reviewed R1/R21 safety boundary and publish an
# omission disposition for every attachment beyond it.
MAX_FOLLOWED_REDFISH_ADDITIONAL_DATA_ATTACHMENTS = 1000
# Inline collection rows have already crossed the structured-response byte
# boundary and do not inherently create another request. Keep their iteration
# finite without discarding ordinary large event-log pages at the smaller
# request-amplification ceiling.
MAX_RETAINED_REDFISH_COLLECTION_MEMBERS = 100_000


def bound_redfish_collection_members(
    members: Any,
    *,
    field_name: str = "Members",
    limit: int = MAX_FOLLOWED_REDFISH_COLLECTION_MEMBERS,
) -> Tuple[List[Any], int, bool]:
    """
    Validate and bound one BMC-controlled Redfish member collection.

    Returns ``(bounded_members, source_count, truncated)``. Callers must expose
    ``truncated`` as a partial/error condition; the helper deliberately does not
    make a collector-specific status decision.

    Args:
        members: Member values received from the source collection in their
            existing order.
        field_name: Field label included in validation failures for the selected
            input.
        limit: Numeric limit used while the operation performs bounded
            accounting.

    Returns:
        A tuple containing the bounded member list, original source count, and
        truncation flag, in that order.

    Raises:
        ValueError: If the ``field_name`` is not a list; or the redfish
            collection member limit is not a positive integer.
    """

    if not isinstance(members, list):
        raise ValueError(f"{field_name} must be a list")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("Redfish collection member limit must be a positive integer")
    source_count = len(members)
    truncated = source_count > limit
    bounded_members = members[:limit] if truncated else members
    return bounded_members, source_count, truncated


def validate_redfish_limit_integer(value: Any, *, field_name: str) -> int:
    """
    Validate a positive signed-64-bit byte ceiling without coercion.

    Booleans, coercible strings, nonpositive values, and integers above the
    signed 64-bit ceiling are rejected. Successful validation returns the
    original integer without widening or coercing it.

    Args:
        value: Value evaluated while performing positive signed-64-bit byte
            ceiling without coercion.
        field_name: Field label included in validation failures for the selected
            input.

    Returns:
        The validated ``value``.

    Raises:
        ValueError: If the ``field_name`` is not an integer number of bytes; or
            the ``field_name`` is not between 1 and
            ``MAX_SIGNED_64_BIT_INTEGER`` bytes.
    """

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer number of bytes")
    if value <= 0 or value > MAX_SIGNED_64_BIT_INTEGER:
        raise ValueError(
            f"{field_name} must be between 1 and {MAX_SIGNED_64_BIT_INTEGER} bytes"
        )
    return value


def clamp_redfish_attachment_limit(
    requested_limit: Optional[int],
    *,
    operator_limit: int,
    field_name: str,
) -> int:
    """
    Clamp a request-specific attachment limit to the operator ceiling.

    Collector and workflow limits may narrow the configured session policy, but
    they must never raise it. Validate both values without coercion so an
    invalid override fails closed instead of silently selecting a wider limit.

    Args:
        requested_limit: Optional request ceiling; ``None`` selects the operator
            limit.
        operator_limit: Configured upper ceiling that a request-specific limit
            cannot exceed.
        field_name: Field label included in validation failures for the selected
            input.

    Returns:
        The numeric clamp Redfish attachment limit.
    """

    resolved_operator_limit = validate_redfish_limit_integer(
        operator_limit,
        field_name="attachment_max_bytes",
    )
    if requested_limit is None:
        return resolved_operator_limit
    resolved_requested_limit = validate_redfish_limit_integer(
        requested_limit,
        field_name=field_name,
    )
    return min(resolved_requested_limit, resolved_operator_limit)


def parse_redfish_limit_environment(value: str, *, field_name: str) -> int:
    """
    Parse one environment value, rejecting empty or non-decimal text.

    The text must contain a base-10 integer and then satisfy the same positive
    signed 64-bit bounds as configured limits. Invalid or empty environment
    values fail instead of selecting an implicit default.

    Args:
        value: Text supplied as value in the format accepted by this function.
        field_name: Field label included in validation failures for the selected
            input.

    Returns:
        The numeric Redfish limit environment value.

    Raises:
        ValueError: If the ``field_name`` is not a base-10 integer number of
            bytes.
    """

    try:
        parsed = int(value, 10)
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"{field_name} must be a base-10 integer number of bytes"
        ) from error
    return validate_redfish_limit_integer(parsed, field_name=field_name)


class RedfishResponseLimits(BaseModel):
    """
    One immutable response, evidence, and cache limit profile.

    Byte fields and the retained-response count use strict integer validation.
    Booleans, floats, quoted YAML values, and misspellings fail closed instead
    of silently falling back to a less restrictive policy.

    Attributes:
        structured_response_max_bytes: Byte count recorded for structured
            response max.
        attachment_max_bytes: Byte count recorded for attachment max.
        error_response_max_bytes: Byte count recorded for error response max.
        error_evidence_max_bytes: Byte count recorded for error evidence max.
        error_evidence_aggregate_max_bytes: Byte count recorded for error
            evidence aggregate max.
        error_evidence_max_responses: Number of error evidence max responses
            represented by this record.
        preflight_response_max_bytes: Byte count recorded for preflight response
            max.
        cache_max_bytes: Byte count recorded for cache max.
        cache_entry_max_bytes: Byte count recorded for cache entry max.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    structured_response_max_bytes: int = Field(
        default=DEFAULT_REDFISH_STRUCTURED_RESPONSE_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    attachment_max_bytes: int = Field(
        default=DEFAULT_REDFISH_ATTACHMENT_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    error_response_max_bytes: int = Field(
        default=DEFAULT_REDFISH_ERROR_RESPONSE_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    error_evidence_max_bytes: int = Field(
        default=DEFAULT_REDFISH_ERROR_EVIDENCE_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    error_evidence_aggregate_max_bytes: int = Field(
        default=DEFAULT_REDFISH_ERROR_EVIDENCE_AGGREGATE_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    error_evidence_max_responses: int = Field(
        default=DEFAULT_REDFISH_ERROR_EVIDENCE_MAX_RESPONSES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    preflight_response_max_bytes: int = Field(
        default=DEFAULT_REDFISH_PREFLIGHT_RESPONSE_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    cache_max_bytes: int = Field(
        default=DEFAULT_REDFISH_CACHE_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    cache_entry_max_bytes: int = Field(
        default=DEFAULT_REDFISH_CACHE_ENTRY_MAX_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )

    @model_validator(mode="after")
    def validate_limit_relationships(self) -> "RedfishResponseLimits":
        """
        Validate limit relationships.

        The implementation uses current instance state to validate limit
        relationships. Every required invariant is checked before a successful
        value is returned; invalid input follows the function's explicit
        exception path.

        Returns:
            The validated ``self``.

        Raises:
            ValueError: If cache_entry_max_bytes cannot exceed cache_max_bytes;
                error_evidence_max_bytes cannot exceed
                error_evidence_aggregate_max_bytes; or error_evidence_max_bytes
                cannot exceed error_response_max_bytes.
        """
        if self.cache_entry_max_bytes > self.cache_max_bytes:
            raise ValueError("cache_entry_max_bytes cannot exceed cache_max_bytes")
        if self.error_evidence_max_bytes > self.error_evidence_aggregate_max_bytes:
            raise ValueError(
                "error_evidence_max_bytes cannot exceed "
                "error_evidence_aggregate_max_bytes"
            )
        if self.error_evidence_max_bytes > self.error_response_max_bytes:
            raise ValueError(
                "error_evidence_max_bytes cannot exceed error_response_max_bytes"
            )
        return self

    @classmethod
    def from_session_config(cls, config: Any) -> "RedfishResponseLimits":
        """
        Read only recognized limit fields from a session configuration.

        After applying local validation, the function forwards ``config`` to
        ``cls.model_validate`` and preserves its return and exception contract.
        Parsing or I/O must finish before the validated representation is made
        available to the caller.

        Args:
            config: Config governing only recognized limit fields from a session
                configuration.

        Returns:
            A ``RedfishResponseLimits`` initialized from session config.

        Raises:
            ValueError: If the supplied input cannot be used to read only
                recognized limit fields from a session configuration.
        """

        if isinstance(config, BaseModel):
            values = {
                field_name: getattr(config, field_name)
                for field_name in cls.model_fields
                if hasattr(config, field_name)
            }
        elif isinstance(config, dict):
            values = config
        else:
            values = {}
        known_limit_stems = tuple(
            f"{field_name.rsplit('_max_', 1)[0]}_max"
            for field_name in cls.model_fields
            if "_max_" in field_name
        )
        unknown_limit_fields = sorted(
            field_name
            for field_name in values
            if isinstance(field_name, str)
            and field_name not in cls.model_fields
            and (
                field_name.endswith(
                    (
                        "_max_byte",
                        "_max_bytes",
                        "_max_response",
                        "_max_responses",
                    )
                )
                or field_name.startswith(known_limit_stems)
            )
        )
        if unknown_limit_fields:
            raise ValueError(
                "Unknown Redfish response-limit field(s): "
                + ", ".join(unknown_limit_fields)
            )
        return cls.model_validate(
            {
                field_name: values[field_name]
                for field_name in cls.model_fields
                if field_name in values
            }
        )

    def as_dict(self) -> Dict[str, int]:
        """
        Return a plain mapping suitable for non-sensitive diagnostics.

        After applying local validation, the function forwards current instance
        state to ``self.model_dump`` and preserves its return and exception
        contract.

        Returns:
            A mapping containing as dictionary.
        """

        return self.model_dump()


class RedfishRequestCaptureLimits(BaseModel):
    """
    Validated run-wide limits for generic and Redfish request capture.

    The concurrent byte limit accounts for live private JSONL spools, anonymous
    staged records, verified copies, and publication staging. Reservations
    survive until each private owner is discarded, including for zero-byte
    objects. A published artifact retains its byte/object reservation until
    durable collector status acknowledges it or exact rollback completes.

    Attributes:
        enabled: Whether enabled applies to this record.
        max_record_bytes: Maximum record bytes admitted by this record.
        max_artifact_bytes: Maximum artifact bytes admitted by this record.
        max_concurrent_private_spool_bytes: Maximum concurrent private spool
            bytes admitted by this record.
        max_concurrent_private_objects: Maximum concurrent private objects
            admitted by this record.
        max_concurrent_private_readers: Maximum concurrent private readers
            admitted by this record.
        max_concurrent_private_file_descriptors: Maximum concurrent private file
            descriptors admitted by this record.
        worker_count: Maximum blocking capture operations executed concurrently
            by the run-owned worker pool.
        max_records: Maximum records admitted by this record.
        min_free_space_reserve_bytes: Byte count recorded for min free space
            reserve.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = Field(default=True, strict=True)

    max_record_bytes: int = Field(
        default=DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_RECORD_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    max_artifact_bytes: int = Field(
        default=DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_ARTIFACT_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    max_concurrent_private_spool_bytes: int = Field(
        default=DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_SPOOL_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    max_concurrent_private_objects: int = Field(
        default=DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_OBJECTS,
        strict=True,
        ge=2,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    max_concurrent_private_readers: int = Field(
        default=DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_READERS,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    max_concurrent_private_file_descriptors: int = Field(
        default=(
            DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_CONCURRENT_PRIVATE_FILE_DESCRIPTORS
        ),
        strict=True,
        # Boundary root + output root + verified input + publication parent
        # + publication staging file can all be live at the atomic rename.
        ge=5,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    worker_count: int = Field(
        default=DEFAULT_REDFISH_REQUEST_CAPTURE_WORKER_COUNT,
        strict=True,
        gt=0,
        le=MAX_REDFISH_REQUEST_CAPTURE_WORKER_COUNT,
    )
    max_records: int = Field(
        default=DEFAULT_REDFISH_REQUEST_CAPTURE_MAX_RECORDS,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )
    min_free_space_reserve_bytes: int = Field(
        default=DEFAULT_REDFISH_REQUEST_CAPTURE_MIN_FREE_SPACE_RESERVE_BYTES,
        strict=True,
        gt=0,
        le=MAX_SIGNED_64_BIT_INTEGER,
    )

    @model_validator(mode="after")
    def validate_limit_relationships(self) -> "RedfishRequestCaptureLimits":
        """
        Validate limit relationships.

        The implementation uses current instance state to validate limit
        relationships. Every required invariant is checked before a successful
        value is returned; invalid input follows the function's explicit
        exception path.

        Returns:
            The validated ``self``.

        Raises:
            ValueError: If max_record_bytes cannot exceed max_artifact_bytes; or
                the max_concurrent_private_spool_bytes are not at least twice
                max_artifact_bytes.
        """
        if self.max_record_bytes > self.max_artifact_bytes:
            raise ValueError("max_record_bytes cannot exceed max_artifact_bytes")
        if 2 * self.max_artifact_bytes > self.max_concurrent_private_spool_bytes:
            raise ValueError(
                "max_concurrent_private_spool_bytes must be at least twice "
                "max_artifact_bytes"
            )
        return self

    @classmethod
    def from_tool_config(cls, tool_config: Any) -> "RedfishRequestCaptureLimits":
        """
        Resolve the canonical nested mapping from a runtime tool config.

        After applying local validation, the function forwards ``tool_config``
        to ``cls.model_validate`` and preserves its return and exception
        contract.

        Args:
            tool_config: Tool config governing canonical nested mapping from a
                runtime tool config.

        Returns:
            A ``RedfishRequestCaptureLimits`` initialized from tool config.
        """

        missing = object()
        if isinstance(tool_config, dict):
            values = tool_config.get("redfish_request_capture", missing)
        elif hasattr(tool_config, "__dict__") and "redfish_request_capture" not in vars(
            tool_config
        ):
            values = missing
        else:
            values = getattr(tool_config, "redfish_request_capture", missing)
        if values is missing:
            values = {}
        if isinstance(values, BaseModel):
            values = values.model_dump()
        return cls.model_validate(values)

    def as_dict(self) -> Dict[str, bool | int]:
        """
        Return the validated runtime representation.

        After applying local validation, the function forwards current instance
        state to ``self.model_dump`` and preserves its return and exception
        contract.

        Returns:
            A mapping containing as dictionary.
        """

        return self.model_dump()


REDFISH_RESPONSE_LIMIT_ENVIRONMENT = {
    field_name: (f"REDFISH_SESSION_CONFIG__{field_name.upper()}")
    for field_name in RedfishResponseLimits.model_fields
}
