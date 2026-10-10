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
One canonical name policy for distributable archive members.

Producers and consumers of archives previously carried five independent
member-name validators that drifted apart: the bounded extractor, the read-only
TAR scanner, the ZIP producer, the host ``archive_targets`` gate, and the
default-off bundle sanitizer each rejected a different set of names. A name that
one boundary admitted could only ever fail at the next, which turned a single
device-chosen filename into whole-archive loss.

This module owns that decision for every boundary. It exposes
``MemberNamePolicyError``, ``validate_distributable_member_name``,
``member_name_parts_or_none``, and ``is_unsafe_portable_component``, and it
deliberately imports nothing from ``bounded_archive`` so the archive limits
module can depend on it. The depth ceiling is never owned here: callers pass
``max_path_depth`` from the ``ArchiveLimits`` profile already in force, so the
bound stays operator-configurable and no new constant is invented.

The policy has two tiers. The core tier is the character and shape decision that
every boundary applies, because a name that violates it cannot survive a
round-trip through the extractor. The portability tier
(``is_unsafe_portable_component``) additionally rejects names that are ambiguous
on Windows; it stays opt-in and is applied only by the sanitizer that produces
operator-facing bundles, because those rules would reject legitimate POSIX
members inside untrusted device archives.
"""

from __future__ import annotations

import re
from typing import Optional

UNSAFE_MEMBER_PATH_REASON = "unsafe_member_path"
PATH_DEPTH_LIMIT_REASON = "path_depth_limit"

_DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:")
_WINDOWS_RESERVED_COMPONENT_RE = re.compile(
    r"(?i)^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])" r"(?:\..*)?$"
)
_WINDOWS_ILLEGAL_COMPONENT_CHARS = frozenset('<>:"|?*')
_RESERVED_COMPONENTS = frozenset({"", ".", ".."})


class MemberNamePolicyError(ValueError):
    """
    One archive member name violated the shared name policy.

    The exception carries a stable ``reason`` code so each boundary can map the
    rejection onto its own error type without parsing a message: the bounded
    extractor re-raises it as ``ArchivePolicyError(reason)``, the read-only
    scanner converts it into its ``None`` sentinel, and the host producer
    surfaces it as a per-target ``ValueError``. Deriving from ``ValueError``
    keeps existing ``except (TypeError, ValueError)`` call sites correct.

    Attributes:
        reason: Stable policy reason code, either ``unsafe_member_path`` or
            ``path_depth_limit``. Callers and telemetry match on this value, so
            it must not be reworded.
        member_name: The rejected name exactly as supplied, retained for
            operator-facing diagnostics. It is untrusted device input and must
            be rendered through the console sanitizer before display.
    """

    def __init__(self, reason: str, member_name: str) -> None:
        """
        Initialize a ``MemberNamePolicyError`` instance.

        The message repeats only the stable reason code, never the untrusted
        name, so a hostile member name cannot reach a log line through ``str``
        on this exception. The name stays available on ``member_name`` for
        callers that sanitize it themselves.

        Args:
            reason: Stable policy reason code recorded on the instance.
            member_name: Rejected member name retained for diagnostics.
        """
        super().__init__(reason)
        self.reason = reason
        self.member_name = member_name


def is_unsafe_portable_component(component: str) -> bool:
    """
    Return whether one non-dot path component is ambiguous on Windows.

    This is the portability tier of the shared policy and is intentionally not
    applied to untrusted device archives: a POSIX member named ``aux.log`` is
    legitimate on the extraction host and rejecting it would discard otherwise
    valid collected data. Bundles that are handed to operators apply it so the
    published artifact can be unpacked on any supported platform.

    The component is expected to be a meaningful path component; ``""``, ``.``,
    and ``..`` are decided by the core tier before this predicate runs.

    Args:
        component: One already-split path component to classify.

    Returns:
        ``True`` when the component has a trailing dot or space, exceeds the
        255-unit per-component ceiling in either UTF-8 bytes or UTF-16 code
        units, contains a C0 control character, contains a character Windows
        forbids in a file name, or matches a reserved device name such as
        ``con`` or ``com1`` with any extension. ``False`` when the component is
        portable.
    """
    return (
        component != component.rstrip(" .")
        or len(component.encode("utf-8", errors="surrogateescape")) > 255
        or len(component.encode("utf-16-le", errors="surrogatepass")) // 2 > 255
        or any(ord(char) < 32 for char in component)
        or any(char in _WINDOWS_ILLEGAL_COMPONENT_CHARS for char in component)
        or _WINDOWS_RESERVED_COMPONENT_RE.fullmatch(component) is not None
    )


def has_unsafe_member_characters(name: str) -> bool:
    """
    Return whether a member name carries characters no boundary may distribute.

    The predicate is the character half of the core tier and is shared so the
    producer and the consumer cannot drift. It rejects C0 control characters and
    DEL, which would otherwise reach operator terminals and log files verbatim;
    any character that is not printable, which covers bidirectional overrides
    and other format characters used to disguise an extension; and the literal
    backslash, which a Windows consumer would interpret as a path separator the
    POSIX validator never inspected.

    Args:
        name: Candidate member name, or one component of one.

    Returns:
        ``True`` when the name must be refused, ``False`` when its characters
        are admissible.
    """
    return (
        "\\" in name
        or not name.isprintable()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)
    )


def validate_distributable_member_name(
    name: str,
    *,
    max_path_depth: int,
    directory: bool = False,
    require_portable: bool = False,
) -> tuple[str, ...]:
    """
    Validate one archive member name and return its safe components.

    This is the single admission decision for archive member names. It rejects,
    never rewrites: a caller that needs producer-prefix normalization (a leading
    ``/`` or ``./`` from ``tar``, or redundant separators in an operator-supplied
    source path) performs that normalization first and passes the result here,
    so the validated value is exactly the name that will be written into or read
    out of the archive.

    The depth ceiling is checked twice on purpose. The separator precheck runs
    before the name is split so a name with millions of components cannot force
    the allocation of a component list first; it is strictly conservative,
    because empty and dot components are rejected immediately afterwards, so a
    name with ``max_path_depth`` separators can only ever yield more than
    ``max_path_depth`` components.

    Args:
        name: Candidate member name. Untrusted device or operator input.
        max_path_depth: Maximum admitted component count, supplied by the
            caller from the ``ArchiveLimits`` profile in force so the bound
            stays operator-configurable.
        directory: Whether the member is a directory entry, in which case a
            single trailing ``/`` is the archive's directory spelling and is
            stripped before validation rather than treated as an empty
            component.
        require_portable: Whether to additionally apply the Windows portability
            tier. Producers of operator-facing bundles set this; consumers of
            untrusted device archives must not, or legitimate POSIX members are
            discarded.

    Returns:
        The validated path components in order. The tuple is never empty and
        contains no empty, ``.``, or ``..`` component, so joining it with ``/``
        reproduces the canonical member name.

    Raises:
        MemberNamePolicyError: With reason ``path_depth_limit`` when the name
            exceeds ``max_path_depth`` components, and with reason
            ``unsafe_member_path`` for every other violation: a non-string or
            empty name, a forbidden character, an absolute path, a drive-letter
            prefix, an empty or dot component, or a non-portable component when
            ``require_portable`` is set.
    """
    if not isinstance(name, str) or not name or has_unsafe_member_characters(name):
        raise MemberNamePolicyError(UNSAFE_MEMBER_PATH_REASON, str(name))
    normalized = name[:-1] if directory and name.endswith("/") else name
    if (
        not normalized
        or normalized.startswith("/")
        or _DRIVE_PREFIX_RE.match(normalized) is not None
    ):
        raise MemberNamePolicyError(UNSAFE_MEMBER_PATH_REASON, name)
    # Bound allocation before splitting.  A PAX name can carry millions of tiny
    # components while its encoded header stays under the metadata ceiling, and
    # the split below would materialize every one of them.
    if normalized.count("/") >= max_path_depth:
        raise MemberNamePolicyError(PATH_DEPTH_LIMIT_REASON, name)
    parts = tuple(normalized.split("/"))
    if any(part in _RESERVED_COMPONENTS for part in parts):
        raise MemberNamePolicyError(UNSAFE_MEMBER_PATH_REASON, name)
    if len(parts) > max_path_depth:
        raise MemberNamePolicyError(PATH_DEPTH_LIMIT_REASON, name)
    if require_portable and any(is_unsafe_portable_component(part) for part in parts):
        raise MemberNamePolicyError(UNSAFE_MEMBER_PATH_REASON, name)
    return parts


def member_name_parts_or_none(
    name: str,
    *,
    max_path_depth: int,
    directory: bool = False,
    require_portable: bool = False,
) -> Optional[tuple[str, ...]]:
    """
    Validate one member name and return ``None`` instead of raising.

    Read-only scanners count a refused member and continue rather than aborting
    the archive, so they need the policy decision as a sentinel rather than an
    exception. The admitted names are identical to
    ``validate_distributable_member_name``; only the failure shape differs.

    Args:
        name: Candidate member name. Untrusted device input.
        max_path_depth: Maximum admitted component count, supplied from the
            ``ArchiveLimits`` profile in force.
        directory: Whether a single trailing ``/`` is the directory spelling.
        require_portable: Whether to apply the Windows portability tier.

    Returns:
        The validated components in order, or ``None`` when the name violates
        the policy for any reason. The sentinel intentionally discards the
        distinction between an unsafe name and an over-deep one, because the
        scanner records both as one rejected member.
    """
    try:
        return validate_distributable_member_name(
            name,
            max_path_depth=max_path_depth,
            directory=directory,
            require_portable=require_portable,
        )
    except MemberNamePolicyError:
        return None
