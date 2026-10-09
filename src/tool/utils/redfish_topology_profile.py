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
Strict schema and helpers for catalog-owned Redfish topology policy.

This module owns the redfish topology profile boundary and exposes
``RedfishTopologyProfileError``, ``_require_exact_keys``, ``_require_string``,
``validate_redfish_uri_path``, ``validate_redfish_request_uri``,
``validate_redfish_uri_segment``, ``redfish_uri_targets_collection``, and
``redfish_uri_is_collection_member``. Keeping those contracts together gives
importers one source of truth for their validation, lifecycle, and
compatibility behavior.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping, Sequence
from typing import Any, Dict, List
from urllib.parse import unquote, urlsplit

REDFISH_TOPOLOGY_PROFILE_KEY = "redfish_topology_profile"
REDFISH_TOPOLOGY_PROFILE_VERSION = 1
SERVICE_ROOT_CANDIDATE = "ServiceRoot"

# These names form the runtime topology contract. The catalog owns their URI
# values and order; the schema only requires that every runtime-consumed name
# has an authored value. Additional identifier-shaped resources are allowed so
# a newer catalog can extend the topology without another default URI table.
REQUIRED_REDFISH_RESOURCE_NAMES = (
    "Systems",
    "Chassis",
    "Managers",
    "UpdateService",
    "TaskService",
    "EventService",
    "SessionService",
    "AccountService",
    "FirmwareInventory",
    "SoftwareInventory",
    "Tasks",
    "Subscriptions",
    "Sessions",
    "Accounts",
    "Roles",
    "ExternalAccountProviders",
)

CREDENTIAL_SELECTOR_FIELDS = (
    "baseboards",
    "baseboard_types",
    "platforms",
    "node_types",
)
CANONICAL_REDFISH_NODE_TYPES = ("SwitchTray", "Compute", "PowerShelf")
FIRMWARE_INVENTORY_RESOURCE_NAMES = (
    "FirmwareInventory",
    "SoftwareInventory",
)

_RESOURCE_NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_URI_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9._~!$&'()*+,;=:@%\-]+$")
_INVALID_PERCENT_ESCAPE_PATTERN = re.compile(r"%(?![0-9A-Fa-f]{2})")
_PERCENT_ESCAPE_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")
_MAX_URI_LENGTH = 2048
_MAX_URI_SEGMENT_LENGTH = 255
_MAX_RESOURCE_NAME_LENGTH = 128
_MAX_RESOURCES = 256
_MAX_CANDIDATES = 64
_MAX_RULES = 128
_MAX_SELECTOR_VALUES = 256


class RedfishTopologyProfileError(ValueError):
    """
    Raised when catalog-owned Redfish topology policy is invalid.

    Callers receive this exception when the Redfish topology profile error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


def _require_exact_keys(
    value: Mapping[str, Any],
    *,
    required: set[str],
    context: str,
) -> None:
    """
    Require exact keys.

    The implementation uses ``value``, ``required``, and ``context`` to require
    exact keys. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        value: Mapping supplying fields for exact keys.
        required: Entries supplied as ``required`` without transferring
            container ownership.
        context: Runtime context carrying state shared across this operation.

    Raises:
        RedfishTopologyProfileError: If the function cannot require exact keys
            safely.
    """
    observed = set(value)
    missing = required - observed
    unsupported = observed - required
    if missing:
        raise RedfishTopologyProfileError(
            f"{context} is missing required keys: "
            + ", ".join(sorted(str(key) for key in missing))
        )
    if unsupported:
        raise RedfishTopologyProfileError(
            f"{context} has unsupported keys: "
            + ", ".join(sorted(str(key) for key in unsupported))
        )


def _require_string(value: Any, *, context: str, max_length: int = 256) -> str:
    """
    Require string.

    The implementation uses ``value``, ``context``, and ``max_length`` to
    require string. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path.

    Args:
        value: Value object whose ``strip`` state is read while performing
            string.
        context: Runtime context carrying state shared across this operation.
        max_length: Upper bound enforced for max length; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The validated ``value``.

    Raises:
        RedfishTopologyProfileError: If the ``context`` is not a non-empty
            string.
    """
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_length
    ):
        raise RedfishTopologyProfileError(f"{context} must be a non-empty string")
    return value


def validate_redfish_uri_path(
    value: Any,
    *,
    context: str = "Redfish URI",
    service_root: str | None = None,
) -> str:
    """
    Validate one absolute, query-free Redfish URI path without coercion.

    When ``service_root`` is supplied, ``value`` must be a child of that root.
    The root itself is not accepted as a resource path. This helper is public so
    runtime override handling can apply exactly the catalog's URI grammar.

    Args:
        value: Value evaluated while performing one absolute, query-free Redfish
            URI path without coercion.
        context: Runtime context carrying state shared across this operation.
        service_root: Optional filesystem location used as the service root for
            this operation.

    Returns:
        The validated ``uri``.

    Raises:
        RedfishTopologyProfileError: If the ``context`` is not an absolute URI
            path; ``context`` must not end with '/'; the ``context`` is not a
            normalized query-free URI path; or ``context`` contains an invalid
            escape; or another input invariant is violated.
    """

    uri = _require_string(value, context=context, max_length=_MAX_URI_LENGTH)
    if not uri.startswith("/"):
        raise RedfishTopologyProfileError(f"{context} must be an absolute URI path")
    if uri != "/" and uri.endswith("/"):
        raise RedfishTopologyProfileError(f"{context} must not end with '/'")
    if "//" in uri or "\\" in uri or "?" in uri or "#" in uri:
        raise RedfishTopologyProfileError(
            f"{context} must be a normalized query-free URI path"
        )
    if any(character.isspace() or ord(character) < 32 for character in uri):
        raise RedfishTopologyProfileError(
            f"{context} must be a normalized query-free URI path"
        )
    if _INVALID_PERCENT_ESCAPE_PATTERN.search(uri):
        raise RedfishTopologyProfileError(f"{context} contains an invalid escape")

    segments = [] if uri == "/" else uri.split("/")[1:]
    if any(
        segment in {"", ".", ".."} or not _URI_SEGMENT_PATTERN.fullmatch(segment)
        for segment in segments
    ):
        raise RedfishTopologyProfileError(
            f"{context} must be a normalized absolute URI path"
        )

    try:
        decoded_uri = unquote(uri, errors="strict")
    except UnicodeDecodeError as error:
        raise RedfishTopologyProfileError(
            f"{context} contains an invalid UTF-8 escape"
        ) from error
    decoded_segments = [] if decoded_uri == "/" else decoded_uri.split("/")[1:]
    if (
        decoded_uri.count("/") != uri.count("/")
        or "\\" in decoded_uri
        or "?" in decoded_uri
        or "#" in decoded_uri
        or (decoded_uri != "/" and decoded_uri.endswith("/"))
        or any(character.isspace() or ord(character) < 32 for character in decoded_uri)
        or any(
            segment in {"", ".", ".."} or not _URI_SEGMENT_PATTERN.fullmatch(segment)
            for segment in decoded_segments
        )
        or _INVALID_PERCENT_ESCAPE_PATTERN.search(decoded_uri)
        or _PERCENT_ESCAPE_PATTERN.search(decoded_uri)
    ):
        raise RedfishTopologyProfileError(
            f"{context} contains an unsafe or ambiguous encoded path"
        )

    if service_root is not None:
        root = validate_redfish_uri_path(service_root, context="service_root")
        if root == "/":
            is_child = uri != "/"
        else:
            is_child = uri.startswith(f"{root}/")
        if not is_child:
            raise RedfishTopologyProfileError(
                f"{context} must be beneath service_root {root!r}"
            )
    return uri


def validate_redfish_request_uri(
    value: Any,
    *,
    context: str = "Redfish request URI",
    service_root: str | None = None,
) -> str:
    """
    Validate a path-only Redfish request target, preserving a safe query.

    Catalog requests and pagination links may legitimately contain query
    parameters, but an authority, scheme, fragment, ambiguous path, or control
    character must never reach the host/port concatenation in the transport.

    When ``service_root`` is supplied the validated path must be beneath that
    root, so a response-derived link cannot leave the collection it was
    advertised by while still satisfying the request grammar.

    Args:
        value: Value evaluated while performing path-only Redfish request
            target, preserving a safe query.
        context: Runtime context carrying state shared across this operation.
        service_root: Optional collection path the validated request URI must
            be beneath; ``None`` applies no anchoring.

    Returns:
        The canonical Redfish request URI text.

    Raises:
        RedfishTopologyProfileError: If ``context`` is not a valid URI;
            ``context`` must not contain a scheme, authority, or fragment; the
            ``context`` is not a path-only URI; or ``context`` contains an
            unsafe or ambiguous query; or another input invariant is violated.
    """

    uri = _require_string(value, context=context, max_length=_MAX_URI_LENGTH)
    try:
        parsed = urlsplit(uri)
    except ValueError as error:
        raise RedfishTopologyProfileError(f"{context} is not a valid URI") from error
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise RedfishTopologyProfileError(
            f"{context} must not contain a scheme, authority, or fragment"
        )
    if parsed.path + (f"?{parsed.query}" if parsed.query else "") != uri:
        raise RedfishTopologyProfileError(f"{context} must be a path-only URI")
    path = validate_redfish_uri_path(
        parsed.path,
        context=f"{context} path",
        service_root=service_root,
    )
    query = parsed.query
    if query:
        if (
            "\\" in query
            or _INVALID_PERCENT_ESCAPE_PATTERN.search(query)
            or any(
                character.isspace() or ord(character) < 32 or ord(character) == 127
                for character in query
            )
        ):
            raise RedfishTopologyProfileError(
                f"{context} contains an unsafe or ambiguous query"
            )
        try:
            decoded_query = unquote(query, errors="strict")
        except UnicodeDecodeError as error:
            raise RedfishTopologyProfileError(
                f"{context} contains an invalid UTF-8 query escape"
            ) from error
        if "\\" in decoded_query or any(
            ord(character) < 32
            or ord(character) == 127
            or (character.isspace() and character != " ")
            for character in decoded_query
        ):
            raise RedfishTopologyProfileError(
                f"{context} contains an unsafe or ambiguous encoded query"
            )
    return path + (f"?{query}" if query else "")


def rebase_redfish_uri(uri: str, catalog_root: str, target_root: str) -> str:
    """
    Resolve a Redfish request path beneath its configured service root.

    Rewrite only a complete catalog-root prefix. Already-rebased paths and
    unrelated absolute resource overrides retain their identity. Relative paths
    are joined once, including when the target is ``/``. HTTP response links
    contribute only their path and query; the transport owns the destination.

    Args:
        uri: Relative resource, absolute path, or HTTP response link.
        catalog_root: Validated service root authored in the catalog.
        target_root: Effective BMC or HMC service root from configuration.

    Returns:
        A validated path-only request target with its original safe query.

    Raises:
        RedfishTopologyProfileError: If a root or URI is malformed, contains
            credentials or a fragment, or violates the request path policy.
    """

    catalog_root = validate_redfish_uri_path(catalog_root, context="catalog root")
    target_root = validate_redfish_uri_path(target_root, context="target root")
    uri = _require_string(uri, context="Redfish URI", max_length=_MAX_URI_LENGTH)
    if any(character.isspace() or ord(character) < 32 for character in uri):
        raise RedfishTopologyProfileError("Redfish URI contains whitespace")
    try:
        parsed = urlsplit(uri)
        if parsed.scheme or parsed.netloc:
            if (
                parsed.scheme.casefold() not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("invalid HTTP response link")
        if "#" in uri:
            raise ValueError("fragment in request URI")
    except ValueError as error:
        raise RedfishTopologyProfileError("Invalid Redfish response URI") from error

    path = parsed.path
    if not path.startswith("/"):
        path = f"{target_root.rstrip('/')}/{path}"
    else:
        already_rebased = (
            target_root != "/"
            and (path == target_root or path.startswith(f"{target_root}/"))
            and not catalog_root.startswith(f"{target_root}/")
        )
        if not already_rebased:
            if path == catalog_root:
                path = target_root
            elif catalog_root == "/" or path.startswith(f"{catalog_root}/"):
                suffix = path if catalog_root == "/" else path[len(catalog_root) :]
                path = f"{target_root.rstrip('/')}/{suffix.lstrip('/')}"
    return validate_redfish_request_uri(
        path + (f"?{parsed.query}" if parsed.query else "")
    )


def validate_redfish_uri_segment(
    value: Any,
    *,
    context: str = "Redfish URI segment",
) -> str:
    """
    Validate one device-supplied value as exactly one Redfish path segment.

    Identifiers taken from a response body (``Id``, a task identifier, a member
    identifier) are substituted into catalog-authored URI templates. Accepting
    only a single RFC 3986 ``pchar`` segment keeps such a value from adding a
    path separator, a query, or a fragment and thereby re-targeting the
    catalog-authored template. The percent-decoded form is checked as well, so
    an encoded separator cannot survive one round of decoding.

    Args:
        value: Device-supplied value validated as a single path segment.
        context: Runtime context carrying state shared across this operation.

    Returns:
        The validated segment exactly as supplied.

    Raises:
        RedfishTopologyProfileError: If ``value`` is not a bounded non-empty
            string, is not one Redfish path segment, is a relative segment,
            contains an invalid escape, or decodes to an unsafe or ambiguous
            segment.
    """

    segment = _require_string(
        value,
        context=context,
        max_length=_MAX_URI_SEGMENT_LENGTH,
    )
    if segment in {".", ".."} or not _URI_SEGMENT_PATTERN.fullmatch(segment):
        raise RedfishTopologyProfileError(
            f"{context} must be exactly one Redfish path segment"
        )
    if _INVALID_PERCENT_ESCAPE_PATTERN.search(segment):
        raise RedfishTopologyProfileError(f"{context} contains an invalid escape")
    try:
        decoded_segment = unquote(segment, errors="strict")
    except UnicodeDecodeError as error:
        raise RedfishTopologyProfileError(
            f"{context} contains an invalid UTF-8 escape"
        ) from error
    if (
        decoded_segment in {"", ".", ".."}
        or not _URI_SEGMENT_PATTERN.fullmatch(decoded_segment)
        or _PERCENT_ESCAPE_PATTERN.search(decoded_segment)
        or any(
            character.isspace() or ord(character) < 32 for character in decoded_segment
        )
    ):
        raise RedfishTopologyProfileError(
            f"{context} contains an unsafe or ambiguous encoded segment"
        )
    return segment


def _decoded_request_uri_path(value: Any, *, context: str) -> str:
    """
    Return the validated, percent-decoded path component of a request URI.

    Anchoring comparisons run on the decoded path so two spellings of the same
    resource cannot be treated as different collections. The request-URI
    grammar runs first, so only already-unambiguous encodings reach the
    comparison.

    Args:
        value: Request URI whose path component is validated and decoded.
        context: Runtime context carrying state shared across this operation.

    Returns:
        The percent-decoded path of the validated request URI.

    Raises:
        RedfishTopologyProfileError: If ``value`` is not a valid path-only
            Redfish request URI.
        ValueError: If the validated path carries an invalid percent escape.
    """

    request_uri = validate_redfish_request_uri(value, context=context)
    return unquote(urlsplit(request_uri).path, errors="strict")


def redfish_uri_targets_collection(value: Any, collection_uri: Any) -> bool:
    """
    Report whether a response-derived URI still addresses its own collection.

    A pagination link may change only its query, never its resource path. The
    predicate therefore compares percent-decoded paths after both values have
    passed the request-URI grammar, which is the rule the dynamic discovery
    walk already applies to ``Members@odata.nextLink``.

    Args:
        value: Response-derived URI to test, such as an advertised next link.
        collection_uri: URI of the collection the value was returned from.

    Returns:
        ``True`` when both URIs are valid and address the same resource path,
        ``False`` for any invalid input or any path divergence.
    """

    try:
        candidate_path = _decoded_request_uri_path(
            value,
            context="Redfish response URI",
        )
        collection_path = _decoded_request_uri_path(
            collection_uri,
            context="Redfish collection URI",
        )
    except (RedfishTopologyProfileError, TypeError, ValueError):
        return False
    return candidate_path == collection_path


def redfish_uri_is_collection_member(value: Any, collection_uri: Any) -> bool:
    """
    Report whether a response-derived member URI is beneath its collection.

    Member dereferences follow ``@odata.id`` values chosen by the controller.
    Anchoring each one to the collection that advertised it keeps a member of
    one collection from selecting an unrelated resource while still satisfying
    the Redfish path grammar.

    Args:
        value: Response-derived member URI to test.
        collection_uri: URI of the collection that advertised the member.

    Returns:
        ``True`` when the member URI is a valid path beneath the collection,
        ``False`` for any invalid input or any URI outside the collection.
    """

    try:
        collection_path = urlsplit(
            validate_redfish_request_uri(
                collection_uri,
                context="Redfish collection URI",
            )
        ).path
        validate_redfish_uri_path(
            value,
            context="Redfish member URI",
            service_root=collection_path,
        )
    except (RedfishTopologyProfileError, TypeError, ValueError):
        return False
    return True


def _require_resource_name(value: Any, *, context: str) -> str:
    """
    Require resource name.

    The implementation uses ``value`` and ``context`` to require resource name.
    Every required invariant is checked before a successful value is returned;
    invalid input follows the function's explicit exception path.

    Args:
        value: Value evaluated while performing resource name.
        context: Runtime context carrying state shared across this operation.

    Returns:
        The validated ``name``.

    Raises:
        RedfishTopologyProfileError: If the ``context`` is not a Redfish
            resource identifier; or ``context`` uses the reserved candidate
            ``SERVICE_ROOT_CANDIDATE``.
    """
    name = _require_string(
        value,
        context=context,
        max_length=_MAX_RESOURCE_NAME_LENGTH,
    )
    if not _RESOURCE_NAME_PATTERN.fullmatch(name):
        raise RedfishTopologyProfileError(
            f"{context} must be a Redfish resource identifier"
        )
    if name == SERVICE_ROOT_CANDIDATE:
        raise RedfishTopologyProfileError(
            f"{context} uses the reserved candidate {SERVICE_ROOT_CANDIDATE!r}"
        )
    return name


def _require_unique_string_list(
    value: Any,
    *,
    context: str,
    allow_empty: bool,
    limit: int,
) -> List[str]:
    """
    Require unique string list.

    The implementation uses ``value``, ``context``, ``allow_empty``, and
    ``limit`` to require unique string list. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        value: Entries supplied as ``value`` and processed in caller-provided
            order.
        context: Runtime context carrying state shared across this operation.
        allow_empty: Whether allow empty is enabled or required for this
            operation.
        limit: Numeric limit used while the operation performs bounded
            accounting.

    Returns:
        The validated ``normalized``.

    Raises:
        RedfishTopologyProfileError: If the ``context`` is not a ``qualifier``;
            or ``context`` contains a duplicate value.
    """
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or len(value) > limit
    ):
        qualifier = "bounded list" if allow_empty else "non-empty bounded list"
        raise RedfishTopologyProfileError(f"{context} must be a {qualifier}")
    normalized: List[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        normalized_item = _require_string(item, context=f"{context}[{index}]")
        if normalized_item in seen:
            raise RedfishTopologyProfileError(f"{context} contains a duplicate value")
        seen.add(normalized_item)
        normalized.append(normalized_item)
    return normalized


def _validate_candidates(
    value: Any,
    *,
    context: str,
    resource_names: Collection[str],
    allow_empty: bool = False,
) -> List[str]:
    """
    Validate candidates.

    Credential validation must prove access to an authenticated resource.
    ServiceRoot is deliberately reserved and can never be a probe candidate.

    Args:
        value: Value evaluated while performing candidates.
        context: Runtime context carrying state shared across this operation.
        resource_names: Text supplied as resource names in the format accepted
            by this function.
        allow_empty: Whether allow empty is enabled or required for this
            operation.

    Returns:
        The validated ``candidates``.

    Raises:
        RedfishTopologyProfileError: If the function cannot validate candidates
            safely.
    """
    candidates = _require_unique_string_list(
        value,
        context=context,
        allow_empty=allow_empty,
        limit=_MAX_CANDIDATES,
    )
    # Credential validation must prove access to an authenticated resource.
    # ServiceRoot is deliberately reserved and can never be a probe candidate.
    supported = set(resource_names)
    unknown = [candidate for candidate in candidates if candidate not in supported]
    if unknown:
        raise RedfishTopologyProfileError(
            f"{context} references unknown resources: " + ", ".join(unknown)
        )
    return candidates


def _validate_selector_values(
    value: Any,
    *,
    context: str,
    allowed_values: Collection[str] | None,
) -> List[str]:
    """
    Validate selector values.

    The implementation uses ``value``, ``context``, and ``allowed_values`` to
    validate selector values. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        value: Value evaluated while performing selector values.
        context: Runtime context carrying state shared across this operation.
        allowed_values: Optional allowed values; ``None`` selects the function's
            default behavior.

    Returns:
        The validated ``values``.

    Raises:
        RedfishTopologyProfileError: If the function cannot validate selector
            values safely.
    """
    values = _require_unique_string_list(
        value,
        context=context,
        allow_empty=True,
        limit=_MAX_SELECTOR_VALUES,
    )
    if allowed_values is not None:
        allowed = set(allowed_values)
        unknown = [item for item in values if item not in allowed]
        if unknown:
            raise RedfishTopologyProfileError(
                f"{context} references unknown values: " + ", ".join(unknown)
            )
    return values


def validate_redfish_topology_profile(
    value: Any,
    *,
    allowed_baseboards: Collection[str] | None = None,
    allowed_baseboard_types: Collection[str] | None = None,
    allowed_platforms: Collection[str] | None = None,
    allowed_node_types: Collection[str] | None = CANONICAL_REDFISH_NODE_TYPES,
) -> Dict[str, Any]:
    """
    Validate and normalize the versioned Redfish topology profile.

    The implementation uses ``value``, ``allowed_baseboards``,
    ``allowed_baseboard_types``, ``allowed_platforms``, and
    ``allowed_node_types`` to validate and normalize the versioned Redfish
    topology profile. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path.

    Args:
        value: Mapping supplying fields for and normalize the versioned Redfish
            topology profile.
        allowed_baseboards: Optional allowed baseboards; ``None`` selects the
            function's default behavior.
        allowed_baseboard_types: Optional allowed baseboard types; ``None``
            selects the function's default behavior.
        allowed_platforms: Optional allowed platforms; ``None`` selects the
            function's default behavior.
        allowed_node_types: Optional allowed node types; ``None`` selects the
            function's default behavior.

    Returns:
        A mapping containing the ``version``, ``service_root``,
        ``resource_uris``, ``discovery``, and ``credential_validation`` fields.

    Raises:
        RedfishTopologyProfileError: If the ``context`` is not a mapping;
            ``context`` has an unsupported version; ``context``.service_root
            must identify a non-root Redfish path; or the
            ``context``.resource_uris are not a non-empty bounded list; or
            another input invariant is violated.
    """

    context = REDFISH_TOPOLOGY_PROFILE_KEY
    if not isinstance(value, Mapping):
        raise RedfishTopologyProfileError(f"{context} must be a mapping")
    _require_exact_keys(
        value,
        required={
            "version",
            "service_root",
            "resource_uris",
            "discovery",
            "credential_validation",
        },
        context=context,
    )
    version = value["version"]
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != REDFISH_TOPOLOGY_PROFILE_VERSION
    ):
        raise RedfishTopologyProfileError(f"{context} has an unsupported version")

    service_root = validate_redfish_uri_path(
        value["service_root"], context=f"{context}.service_root"
    )
    if service_root == "/":
        raise RedfishTopologyProfileError(
            f"{context}.service_root must identify a non-root Redfish path"
        )
    raw_resources = value["resource_uris"]
    if (
        not isinstance(raw_resources, list)
        or not raw_resources
        or len(raw_resources) > _MAX_RESOURCES
    ):
        raise RedfishTopologyProfileError(
            f"{context}.resource_uris must be a non-empty bounded list"
        )

    resources: List[Dict[str, str]] = []
    resource_names: set[str] = set()
    resource_paths: set[str] = set()
    for index, raw_resource in enumerate(raw_resources):
        resource_context = f"{context}.resource_uris[{index}]"
        if not isinstance(raw_resource, Mapping):
            raise RedfishTopologyProfileError(f"{resource_context} must be a mapping")
        _require_exact_keys(
            raw_resource,
            required={"name", "uri"},
            context=resource_context,
        )
        name = _require_resource_name(
            raw_resource["name"], context=f"{resource_context}.name"
        )
        uri = validate_redfish_uri_path(
            raw_resource["uri"],
            context=f"{resource_context}.uri",
            service_root=service_root,
        )
        if name in resource_names:
            raise RedfishTopologyProfileError(
                f"{context}.resource_uris contains duplicate resource {name!r}"
            )
        canonical_uri = unquote(uri, errors="strict")
        if canonical_uri in resource_paths:
            raise RedfishTopologyProfileError(
                f"{context}.resource_uris contains duplicate URI {uri!r}"
            )
        resource_names.add(name)
        resource_paths.add(canonical_uri)
        resources.append({"name": name, "uri": uri})

    missing_resources = set(REQUIRED_REDFISH_RESOURCE_NAMES) - resource_names
    if missing_resources:
        raise RedfishTopologyProfileError(
            f"{context}.resource_uris is missing required resources: "
            + ", ".join(sorted(missing_resources))
        )

    raw_discovery = value["discovery"]
    if not isinstance(raw_discovery, Mapping):
        raise RedfishTopologyProfileError(f"{context}.discovery must be a mapping")
    _require_exact_keys(
        raw_discovery,
        required={"core", "optional", "firmware_inventory_candidates"},
        context=f"{context}.discovery",
    )
    discovery: Dict[str, List[str]] = {}
    seen_discovery: set[str] = set()
    for group in ("core", "optional"):
        candidates = _validate_candidates(
            raw_discovery[group],
            context=f"{context}.discovery.{group}",
            resource_names=resource_names,
            allow_empty=group == "optional",
        )
        if SERVICE_ROOT_CANDIDATE in candidates:
            raise RedfishTopologyProfileError(
                f"{context}.discovery.{group} cannot reference "
                f"{SERVICE_ROOT_CANDIDATE!r}"
            )
        unsupported_discovery = [
            candidate
            for candidate in candidates
            if candidate not in REQUIRED_REDFISH_RESOURCE_NAMES
        ]
        if unsupported_discovery:
            raise RedfishTopologyProfileError(
                f"{context}.discovery.{group} references resources unsupported "
                "by runtime discovery: " + ", ".join(unsupported_discovery)
            )
        overlap = seen_discovery.intersection(candidates)
        if overlap:
            raise RedfishTopologyProfileError(
                f"{context}.discovery repeats resources across ordered groups: "
                + ", ".join(sorted(overlap))
            )
        seen_discovery.update(candidates)
        discovery[group] = candidates

    firmware_inventory_candidates = _validate_candidates(
        raw_discovery["firmware_inventory_candidates"],
        context=f"{context}.discovery.firmware_inventory_candidates",
        resource_names=resource_names,
    )
    unsupported_firmware_candidates = [
        candidate
        for candidate in firmware_inventory_candidates
        if candidate not in FIRMWARE_INVENTORY_RESOURCE_NAMES
    ]
    if unsupported_firmware_candidates:
        raise RedfishTopologyProfileError(
            f"{context}.discovery.firmware_inventory_candidates references "
            "resources unsupported for firmware inventory: "
            + ", ".join(unsupported_firmware_candidates)
        )
    discovery["firmware_inventory_candidates"] = firmware_inventory_candidates

    raw_validation = value["credential_validation"]
    if not isinstance(raw_validation, Mapping):
        raise RedfishTopologyProfileError(
            f"{context}.credential_validation must be a mapping"
        )
    _require_exact_keys(
        raw_validation,
        required={
            "default_candidates",
            "custom_prefix_candidates",
            "rules",
        },
        context=f"{context}.credential_validation",
    )
    default_candidates = _validate_candidates(
        raw_validation["default_candidates"],
        context=f"{context}.credential_validation.default_candidates",
        resource_names=resource_names,
    )
    custom_prefix_candidates = _validate_candidates(
        raw_validation["custom_prefix_candidates"],
        context=f"{context}.credential_validation.custom_prefix_candidates",
        resource_names=resource_names,
    )

    raw_rules = raw_validation["rules"]
    if not isinstance(raw_rules, list) or len(raw_rules) > _MAX_RULES:
        raise RedfishTopologyProfileError(
            f"{context}.credential_validation.rules must be a bounded list"
        )
    allowed_selectors = {
        "baseboards": allowed_baseboards,
        "baseboard_types": allowed_baseboard_types,
        "platforms": allowed_platforms,
        "node_types": allowed_node_types,
    }
    rules: List[Dict[str, List[str]]] = []
    seen_rule_selectors: set[tuple[tuple[str, ...], ...]] = set()
    for index, raw_rule in enumerate(raw_rules):
        rule_context = f"{context}.credential_validation.rules[{index}]"
        if not isinstance(raw_rule, Mapping):
            raise RedfishTopologyProfileError(f"{rule_context} must be a mapping")
        _require_exact_keys(
            raw_rule,
            required={*CREDENTIAL_SELECTOR_FIELDS, "candidates"},
            context=rule_context,
        )
        rule: Dict[str, List[str]] = {}
        for selector in CREDENTIAL_SELECTOR_FIELDS:
            rule[selector] = _validate_selector_values(
                raw_rule[selector],
                context=f"{rule_context}.{selector}",
                allowed_values=allowed_selectors[selector],
            )
        if not any(rule[selector] for selector in CREDENTIAL_SELECTOR_FIELDS):
            raise RedfishTopologyProfileError(
                f"{rule_context} must define at least one selector"
            )
        selector_identity = tuple(
            tuple(rule[selector]) for selector in CREDENTIAL_SELECTOR_FIELDS
        )
        if selector_identity in seen_rule_selectors:
            raise RedfishTopologyProfileError(
                f"{context}.credential_validation.rules contains duplicate selectors"
            )
        seen_rule_selectors.add(selector_identity)
        rule["candidates"] = _validate_candidates(
            raw_rule["candidates"],
            context=f"{rule_context}.candidates",
            resource_names=resource_names,
        )
        rules.append(rule)

    return {
        "version": version,
        "service_root": service_root,
        "resource_uris": resources,
        "discovery": discovery,
        "credential_validation": {
            "default_candidates": default_candidates,
            "custom_prefix_candidates": custom_prefix_candidates,
            "rules": rules,
        },
    }


def build_redfish_resource_uri_lookup(value: Any) -> Dict[str, str]:
    """
    Return the validated resource-to-URI map in authored order.

    The implementation uses ``value`` to produce the validated resource-to-URI
    map in authored order.

    Args:
        value: Value evaluated while performing validated resource-to-URI map in
            authored order.

    Returns:
        A mapping containing Redfish resource URI lookup.
    """

    profile = validate_redfish_topology_profile(value)
    return {resource["name"]: resource["uri"] for resource in profile["resource_uris"]}


def select_redfish_credential_candidates(
    value: Any,
    *,
    baseboard: str | None = None,
    baseboard_type: str | None = None,
    platform: str | None = None,
    node_type: str | None = None,
    custom_prefix: bool = False,
) -> List[str]:
    """
    Select ordered credential-probe resource names for one DUT.

    Rules use first-match ordering. A rule matches when any non-empty identity
    supplied by the caller appears in its corresponding selector list. This lets
    a PowerShelf identity remain effective whether discovery supplied its
    concrete baseboard, type, platform, or node type.

    Args:
        value: Value evaluated while performing ordered credential-probe
            resource names for one DUT.
        baseboard: Optional baseboard; ``None`` selects the function's default
            behavior.
        baseboard_type: Optional baseboard type; ``None`` selects the function's
            default behavior.
        platform: Optional platform; ``None`` selects the function's default
            behavior.
        node_type: Optional node type; ``None`` selects the function's default
            behavior.
        custom_prefix: Whether custom prefix is enabled or required for this
            operation.

    Returns:
        The Redfish credential candidates returned in operation-defined order.
    """

    profile = validate_redfish_topology_profile(value)
    identities = {
        "baseboards": baseboard,
        "baseboard_types": baseboard_type,
        "platforms": platform,
        "node_types": node_type,
    }
    validation = profile["credential_validation"]
    for rule in validation["rules"]:
        if any(
            isinstance(identity, str)
            and identity.strip()
            and identity.strip().casefold()
            in {candidate.casefold() for candidate in rule[selector]}
            for selector, identity in identities.items()
        ):
            return list(rule["candidates"])
    key = "custom_prefix_candidates" if custom_prefix else "default_candidates"
    return list(validation[key])


def resolve_redfish_candidate_uris(
    value: Any,
    candidates: Sequence[str],
) -> List[str]:
    """
    Resolve validated credential candidate resource names to URIs.

    The implementation uses ``value`` and ``candidates`` to resolve validated
    credential candidate resource names to URIs.

    Args:
        value: Value evaluated while performing validated credential candidate
            resource names to URIs.
        candidates: Entries supplied as ``candidates`` without transferring
            container ownership.

    Returns:
        The Redfish candidate URIs returned in operation-defined order.
    """

    profile = validate_redfish_topology_profile(value)
    resource_uris = {
        resource["name"]: resource["uri"] for resource in profile["resource_uris"]
    }
    normalized_candidates = _validate_candidates(
        list(candidates),
        context="credential candidates",
        resource_names=resource_uris,
    )
    return [resource_uris[candidate] for candidate in normalized_candidates]


def filter_redfish_topology_profile_for_release(
    value: Any,
    *,
    allowed_baseboards: Collection[str],
    allowed_baseboard_types: Collection[str],
    allowed_platforms: Collection[str],
    allowed_node_types: Collection[str] = CANONICAL_REDFISH_NODE_TYPES,
) -> Dict[str, Any]:
    """
    Remove selector identities unavailable in a release and revalidate.

    After applying local validation, the function forwards ``value``,
    ``allowed_baseboards``, ``allowed_baseboard_types``, ``allowed_platforms``,
    and ``allowed_node_types`` to ``validate_redfish_topology_profile`` and
    preserves its return and exception contract.

    Args:
        value: Value evaluated while performing remove selector identities
            unavailable in a release and revalidate.
        allowed_baseboards: Text supplied as allowed baseboards in the format
            accepted by this function.
        allowed_baseboard_types: Text supplied as allowed baseboard types in the
            format accepted by this function.
        allowed_platforms: Text supplied as allowed platforms in the format
            accepted by this function.
        allowed_node_types: Text supplied as allowed node types in the format
            accepted by this function.

    Returns:
        A mapping containing filter Redfish topology profile for release.
    """

    profile = validate_redfish_topology_profile(value)
    allowed = {
        "baseboards": set(allowed_baseboards),
        "baseboard_types": set(allowed_baseboard_types),
        "platforms": set(allowed_platforms),
        "node_types": set(allowed_node_types),
    }
    projected_rules: List[Dict[str, List[str]]] = []
    for rule in profile["credential_validation"]["rules"]:
        projected_rule = {
            selector: [item for item in rule[selector] if item in allowed[selector]]
            for selector in CREDENTIAL_SELECTOR_FIELDS
        }
        if not any(projected_rule[selector] for selector in CREDENTIAL_SELECTOR_FIELDS):
            continue
        projected_rule["candidates"] = list(rule["candidates"])
        projected_rules.append(projected_rule)

    profile["credential_validation"]["rules"] = projected_rules
    return validate_redfish_topology_profile(
        profile,
        allowed_baseboards=allowed["baseboards"],
        allowed_baseboard_types=allowed["baseboard_types"],
        allowed_platforms=allowed["platforms"],
        allowed_node_types=allowed["node_types"],
    )
