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
Log Sanitizer for NVDebug Tool.

Handles sanitization of sensitive data in logs and console output including IP
addresses, MAC addresses, credentials, and custom patterns.
"""

import json
import logging
import os
import re
from collections import OrderedDict
from enum import Enum
from functools import lru_cache
from threading import current_thread, main_thread
from time import monotonic, sleep
from typing import Any, Dict, Iterable, List, Optional

import yaml
from rich.markup import escape as escape_markup

from .secret_env import (
    extract_url_userinfo_secrets,
    is_secret_environment_name,
)
from .trusted_extensions import sanitize_optional_config_text

_TERMINAL_CONTROL_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b[@-_]"
    r"|[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]"
)
_UNICODE_LINE_SEPARATOR_RE = re.compile(r"[\x85\u2028\u2029]")
_MULTILINE_THREAD_YIELD_MATCHES = 2
_MULTILINE_THREAD_YIELD_INTERVAL_SECONDS = 0.0001


def neutralize_text_controls(text: str, *, replacement: str = "") -> str:
    """
    Remove display controls while preserving ordinary whitespace.

    After applying local validation, the function forwards ``text`` and
    ``replacement`` to ``_TERMINAL_CONTROL_RE.sub`` and preserves its return and
    exception contract.

    Args:
        text: Text supplied as text in the format accepted by this function.
        replacement: Text supplied as replacement in the format accepted by this
            function.

    Returns:
        The canonical neutralize text controls text.
    """

    visible_separators = _UNICODE_LINE_SEPARATOR_RE.sub(r"\\n", str(text))
    return _TERMINAL_CONTROL_RE.sub(replacement, visible_separators)


def neutralize_terminal_text(text: str) -> str:
    """
    Remove display controls and neutralize Rich markup in untrusted text.

    After applying local validation, the function forwards ``text`` to
    ``escape_markup`` and preserves its return and exception contract.

    Args:
        text: Text supplied as text in the format accepted by this function.

    Returns:
        The canonical neutralize terminal text.
    """

    return escape_markup(neutralize_text_controls(text))


_AUTHORIZATION_FIELD_NAME_PATTERN = (
    r"(?:(?:proxy[_-]?)?authorization(?:[_-]?header)?|auth(?:[_-]?header))"
)
_CREDENTIAL_KEY_NAME_PATTERN = (
    r"(?:"
    rf"{_AUTHORIZATION_FIELD_NAME_PATTERN}"
    r"|(?:[A-Za-z0-9]+[_-])*(?:password|passwd|pwd|passphrase|pass|secret|token|auth|"
    r"authorization|credential)"
    r"|(?:[A-Za-z0-9]+[_-])*(?:user|username)"
    # Allow an optional '_'/'-' inside api-key/access-key/etc so the hyphenated
    # header spelling (e.g. flat-text ``x-api-key:``) matches, not only the
    # snake_case/concatenated forms.
    r"|(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key)"
    # ``sshpass`` is the non-standard shell-wrapper spelling; list it explicitly
    # so a free-text ``sshpass=`` line redacts (the separator-anchored ``pass``
    # alternatives above never reach the concatenated ``sshpass`` token).
    r"|[A-Za-z0-9]*(?:password|passwd|pwd|passphrase|secret|token|jwt|auth|"
    r"authorization|credential|credentials|apikey|accesskey|secretkey|privatekey|sshpass)"
    r"|clientSecret|refreshToken|accessToken|apiKey"
    r"|key"
    r")"
)
_API_KEY_NAME_PATTERN = (
    r"(?:"
    r"(?:[A-Za-z0-9]+[_-])*(?:api_key|apikey|access_key|secret_key)"
    r"|[A-Za-z0-9]*(?:apikey|accesskey|secretkey)"
    r")"
)
_QUOTED_CREDENTIAL_VALUE_PATTERN = (
    r"""(?:"(?:\\[^\r\n]|[^"\\\r\n])*"|"""
    r"'(?:\\[^\r\n]|''|[^'\\\r\n])*')"
    r"(?![A-Za-z0-9_])"
)
_UNTERMINATED_QUOTED_VALUE_PATTERN = (
    r"""(?:"(?:\\[^\r\n]|[^"\\\r\n])*$|""" r"'(?:\\[^\r\n]|''|[^'\\\r\n])*$)"
)
_UNQUOTED_EQUALS_VALUE_PATTERN = r"""(?!["'])[^\s}\]\r\n]+"""
# YAML block indicators introduce indentation-owned bodies, not scalar values
# on this line. This matcher deliberately avoids replacing only the header;
# callers handling structured YAML must redact the complete block.
_UNQUOTED_COLON_VALUE_PATTERN = r"""(?!["'|>])[^\s}\]\r\n]+"""
# Every scheme, not just Basic. Recognising only `basic` here let the generic
# credential-pair matcher claim `Authorization: Bearer` instead -- its unquoted
# value stops at whitespace -- which consumed the `bearer` anchor the TOKENS
# pattern needed, leaving the actual token in the output. This alternative is
# tried first in _CREDENTIAL_PATTERN, so it claims the whole header.
# The credential charset covers base64 as well as JWT and opaque token forms.
_AUTHORIZATION_SCHEME_PATTERN = r"(?:basic|bearer|digest|token|apikey|negotiate|ntlm)"
_AUTHORIZATION_HEADER_PATTERN = (
    rf"""(?<![A-Za-z0-9_-])["']?{_AUTHORIZATION_FIELD_NAME_PATTERN}"""
    r"""(?![A-Za-z0-9_-])["']?[ \t]*[:=][ \t]*["']?"""
    rf"""{_AUTHORIZATION_SCHEME_PATTERN}[ \t]+"""
    r"""[A-Za-z0-9+/._~-]+={0,2}["']?(?![A-Za-z0-9_])"""
)


def _credential_pair_pattern(key_pattern: str) -> str:
    """
    Build a single-line word-key credential matcher with bounded quoting.

    A necessary field-shape lookahead rejects ordinary journal words before
    trying the credential-name alternatives. Both governed key policies contain
    only letters, digits, underscores, and hyphens; Python's case-insensitive
    Unicode equivalents are admitted by the same character class. The gate
    allows a superset of the existing quote, bracket, and whitespace syntax.
    The original expression still decides the match and replacement boundaries.

    Args:
        key_pattern: Governed credential-key expression whose matches contain
            only ASCII word-key characters or their Unicode case equivalents.

    Returns:
        The canonical credential pair pattern text.
    """

    field = (
        r"""(?<![A-Za-z0-9_-])(?=["']?[A-Za-z0-9_-]+["'\] \t]*[:=])"""
        rf"""["']?{key_pattern}"""
        r"""(?![A-Za-z0-9_-])["']?(?:[ \t]*\])*"""
    )
    return (
        rf"{field}[ \t]*(?:"
        rf"=[ \t]*(?:{_QUOTED_CREDENTIAL_VALUE_PATTERN}|"
        rf"{_UNTERMINATED_QUOTED_VALUE_PATTERN}|"
        rf"{_UNQUOTED_EQUALS_VALUE_PATTERN})"
        rf"|:[ \t]*(?:{_QUOTED_CREDENTIAL_VALUE_PATTERN}|"
        rf"{_UNTERMINATED_QUOTED_VALUE_PATTERN}|"
        rf"{_UNQUOTED_COLON_VALUE_PATTERN})"
        r")"
    )


_CREDENTIAL_PAIR_PATTERN = _credential_pair_pattern(_CREDENTIAL_KEY_NAME_PATTERN)
_API_KEY_PAIR_PATTERN = _credential_pair_pattern(_API_KEY_NAME_PATTERN)
# Escaped JSON in free-form logs may have multiple serialization layers. Once
# a credential key is recognized, redact the rest of that physical line so an
# escaped quote inside its value cannot leave a credential suffix visible.
_ESCAPED_CREDENTIAL_PAIR_PATTERN = (
    rf'\\+"{_CREDENTIAL_KEY_NAME_PATTERN}\\+"[ \t]*[:=][ \t]*[^\r\n]*'
)
_COMMAND_CREDENTIAL_PATTERN = (
    r"(?<![A-Za-z0-9_-])(?:"
    r"ipmitool\b[^\r\n]{0,1024}?[ \t]-P[ \t]+|"
    r"curl\b[^\r\n]{0,1024}?[ \t](?:-u|--user)[ \t]+|"
    r"sshpass[ \t]+-p[ \t]+)"
    rf"(?:{_QUOTED_CREDENTIAL_VALUE_PATTERN}|"
    rf"{_UNTERMINATED_QUOTED_VALUE_PATTERN}|[^\s\r\n]+)"
)
_CREDENTIAL_PATTERN = (
    rf"(?:{_AUTHORIZATION_HEADER_PATTERN}|{_ESCAPED_CREDENTIAL_PAIR_PATTERN}|"
    rf"{_COMMAND_CREDENTIAL_PATTERN}|{_CREDENTIAL_PAIR_PATTERN})"
)

# Standalone URL-userinfo credential alternative, placed before configured
# canaries in the single combined substitution. The ordinary
# ``CREDENTIAL_URIS`` builtin is lookbehind-anchored on ``://`` yet configured
# canaries used to precede it; a canary username (for example ``admin``) could
# therefore consume just the username and strand the password after the regex
# engine advanced beyond the anchor. Giving this group-free alternative first
# priority removes the whole authority without running a second substitution
# over transformed text. Its ``user:pass`` branch also accepts an empty
# username, which safely covers malformed-but-observed ``scheme://:pass@host``
# output.
_CREDENTIAL_URI_STANDALONE_PATTERN = (
    r"""(?<=://)(?:[^/\s:@?#]*:[^\s?#]*|[^/\s:@?#]+)"""
    r"""(?=@[^\s@/?#"',;)\]}]+(?:[/?#"',;)\]}\s]|$))"""
)

_CAMEL_CASE_KEY_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ACRONYM_KEY_BOUNDARY_RE = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_NON_KEY_CHARACTER_RE = re.compile(r"[^A-Za-z0-9]+")
_STRUCTURED_CREDENTIAL_SUFFIXES = (
    ("password",),
    ("passwd",),
    ("pwd",),
    ("passphrase",),
    ("pass",),
    ("secret",),
    ("token",),
    ("auth",),
    ("authorization",),
    ("auth", "header"),
    ("authorization", "header"),
    ("credential",),
    ("user",),
    ("username",),
    ("api", "key"),
    ("apikey",),
    ("access", "key"),
    ("secret", "key"),
    ("private", "key"),
)
_STRUCTURED_API_KEY_SUFFIXES = (
    ("api", "key"),
    ("apikey",),
    ("access", "key"),
    ("secret", "key"),
)
_STRUCTURED_COOKIE_SUFFIXES = (
    ("cookie",),
    ("sessionid",),
    ("session", "id"),
    ("auth", "session"),
    ("session", "token"),
    ("sid",),
)
_STRUCTURED_CREDENTIAL_NEAR_MISSES = frozenset(
    {
        ("password", "policy"),
        ("public", "key"),
        # Redfish ManagerDiagnosticData uses this numeric processor telemetry
        # field.  Its leading ``User`` token denotes CPU time, not an account
        # identity, so replacing the value would corrupt the response type.
        ("user", "percent"),
    }
)


def _normalized_structured_key_parts(key: str) -> tuple[str, ...]:
    """
    Return the normalized structured key parts.

    After applying local validation, the function forwards ``key`` to ``tuple``
    and preserves its return and exception contract.

    Args:
        key: Stable key used for lookup and operator-facing diagnostics.

    Returns:
        The normalized structured key parts returned in operation-defined order.
    """
    separated = _ACRONYM_KEY_BOUNDARY_RE.sub("_", str(key))
    separated = _CAMEL_CASE_KEY_BOUNDARY_RE.sub("_", separated)
    normalized = _NON_KEY_CHARACTER_RE.sub("_", separated).strip("_").casefold()
    return tuple(part for part in normalized.split("_") if part)


def _structured_key_has_suffix(
    parts: tuple[str, ...], suffixes: tuple[tuple[str, ...], ...]
) -> bool:
    """
    Return whether a sensitive token sequence occurs in structured key parts.

    After applying local validation, the function forwards ``parts`` and
    ``suffixes`` to ``any`` and preserves its return and exception contract.

    Args:
        parts: Entries supplied as ``parts`` without transferring container
            ownership.
        suffixes: Entries supplied as ``suffixes`` without transferring
            container ownership.

    Returns:
        Whether the structured key has suffix operation succeeds.
    """
    if parts in _STRUCTURED_CREDENTIAL_NEAR_MISSES:
        return False
    return any(
        suffix
        and any(
            parts[index : index + len(suffix)] == suffix
            for index in range(len(parts) - len(suffix) + 1)
        )
        for suffix in suffixes
    )


def _is_sensitive_structured_key(key: str) -> bool:
    """
    Return whether a mapping key denotes a credential-bearing value.

    Structured documents separate keys from values before sanitization, so the
    text matcher cannot see the delimiter it deliberately requires. Normalize
    snake/kebab/camel-case names here while retaining the matcher's important
    near-miss behavior: suffixes such as ``password_policy`` and generic names
    such as ``public_key`` are not treated as credentials.

    Args:
        key: Stable key used for lookup and operator-facing diagnostics.

    Returns:
        Whether a mapping key denotes a credential-bearing value.
    """

    parts = _normalized_structured_key_parts(key)
    # Redfish action identifiers are schema names, and URI/URL-suffixed fields
    # contain locators rather than the credential named by an earlier token.
    # Their values still pass through ordinary recursive text sanitization, so
    # userinfo and query credentials remain covered without erasing the public
    # response shape.
    if str(key).lstrip().startswith("#") or parts[-1:] in {("uri",), ("url",)}:
        return False
    if parts == ("key",):
        return True
    return _structured_key_has_suffix(parts, _STRUCTURED_CREDENTIAL_SUFFIXES)


class BuiltInSanitizers(Enum):
    """
    Built-in sanitizer patterns.

    Defines standard patterns for common sensitive data types.
    """

    IPV4 = "ipv4_address"
    IPV6 = "ipv6_address"
    MAC_ADDRESS = "mac_address"
    SERIAL_NUMBER = "serial_number"
    PART_NUMBER = "part_number"
    CREDENTIALS = "credentials"
    API_KEYS = "api_keys"
    TOKENS = "tokens"
    PRIVATE_KEYS = "private_keys"
    CREDENTIAL_URIS = "credential_uris"
    COOKIES = "cookies"
    AWS_ACCESS_KEY_IDS = "aws_access_key_ids"


def _classify_structured_key(
    key: str, enabled_builtins: frozenset[BuiltInSanitizers]
) -> bool:
    """
    Classify a field using only the supplied built-in redaction policy.

    Exact secret values and replacement text do not affect field classification.
    Keeping this decision separate lets repeated schema keys share a bounded
    cache without retaining a sanitizer instance or caching payload values.

    Args:
        key: Original structured field name before text sanitization.
        enabled_builtins: Immutable set of enabled built-in sanitizers.

    Returns:
        Whether the field's entire value must be redacted under this policy.
    """

    if (
        BuiltInSanitizers.CREDENTIALS in enabled_builtins
        and _is_sensitive_structured_key(key)
    ):
        return True
    parts = _normalized_structured_key_parts(key)
    if BuiltInSanitizers.API_KEYS in enabled_builtins and _structured_key_has_suffix(
        parts, _STRUCTURED_API_KEY_SUFFIXES
    ):
        return True
    return BuiltInSanitizers.COOKIES in enabled_builtins and _structured_key_has_suffix(
        parts, _STRUCTURED_COOKIE_SUFFIXES
    )


# Bound both cardinality and retained key length; untrusted mapping keys may be
# arbitrarily large. functools keeps cache bookkeeping safe across capture and
# publication workers. The policy is part of the key, so independent runs with
# different enabled matchers cannot reuse one another's classification.
_STRUCTURED_KEY_CACHE_MAX_CHARS = 256
_cached_structured_key_classification = lru_cache(maxsize=1024)(
    _classify_structured_key
)


def _configured_identity_pattern(identity: str) -> str:
    """
    Return a regex that redacts an account name only in identity contexts.

    Usernames can legitimately equal public product vocabulary. Treating those
    values as unanchored secret canaries corrupts commands and diagnostic
    payloads such as vendor tool names. The returned expression still covers
    assignments, login prose, home-directory paths, and SSH-style userinfo.

    Args:
        identity: Configured username admitted as a contextual privacy value.

    Returns:
        A case-insensitive-compatible regular expression for identity use sites.
    """

    escaped = re.escape(identity)
    quoted = rf"[\"']?{escaped}[\"']?"
    return (
        rf"(?:(?<![A-Za-z0-9_-])(?:user(?:name)?|password|passwd|pwd|"
        rf"passphrase|pass|secret|token|login(?:[ \t]+as)?|"
        rf"login[^\r\n]{{0,128}}?[ \t]+as|"
        rf"logged[ \t]+in[ \t]+as|running[ \t]+as[ \t]+user)"
        rf"[ \t]*(?:[:=][ \t]*)?{quoted}(?![A-Za-z0-9_.-])"
        rf"|(?<=/home/){escaped}(?=/|$)"
        rf"|(?<=/Users/){escaped}(?=/|$)"
        rf"|(?<=\\Users\\){escaped}(?=\\|$)"
        rf"|(?<=~){escaped}(?=/|$)"
        rf"|(?<![A-Za-z0-9_.-]){escaped}(?=@[A-Za-z0-9_.-]+(?:[:/]|$)))"
    )


class LogSanitizer(logging.Formatter):
    """
    Comprehensive log sanitizer that removes sensitive information.

    Extends logging.Formatter to provide automatic sanitization of sensitive
    data in log messages using configurable patterns.
    """

    # Built-in regex patterns for common sensitive data
    builtin_regex = {
        BuiltInSanitizers.IPV4: r"\b((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b",
        BuiltInSanitizers.IPV6: r"\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b",
        BuiltInSanitizers.MAC_ADDRESS: r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b",
        BuiltInSanitizers.SERIAL_NUMBER: r"\b[A-Z0-9]{8,20}\b",  # Common serial number patterns
        BuiltInSanitizers.PART_NUMBER: r"\b[A-Z0-9\-]{8,25}\b(?!\s+(?:NVL|GPU|HGX|MGX|DC|PowerShelf))",  # Common part number patterns, but exclude baseboard names
        # Structured quoting is confined to one line. Unquoted values retain
        # the existing punctuation support and stop at the first whitespace so
        # surrounding diagnostic text remains available.
        BuiltInSanitizers.CREDENTIALS: _CREDENTIAL_PATTERN,
        BuiltInSanitizers.API_KEYS: _API_KEY_PAIR_PATTERN,
        BuiltInSanitizers.TOKENS: r"\b(bearer|token)\s+[^\s}\]\r\n]+",
        # Interval tempered so it cannot run past a following BEGIN header, and
        # length-bounded. ``[\s\S]*?`` re-scanned to end-of-input for every
        # BEGIN with no matching END, which is quadratic on repeated headers.
        BuiltInSanitizers.PRIVATE_KEYS: r"-{4,5}BEGIN [^-\r\n]*PRIVATE KEY-{4,5}(?:(?:(?!-{4,5}BEGIN)[\s\S]){0,65536}?-{4,5}END [^-\r\n]*PRIVATE KEY-{4,5}|[\s\S]*)",
        # The password alternative permits '/' because device and tool output
        # can contain unescaped userinfo even though producers should encode it.
        # The broad password alternative requires username ':' password, while
        # the username-only alternative excludes '/', avoiding path '@' false
        # positives.
        BuiltInSanitizers.CREDENTIAL_URIS: _CREDENTIAL_URI_STANDALONE_PATTERN,
        BuiltInSanitizers.COOKIES: r"\b(?:set-cookie|cookie)\s*:\s*[^\r\n]+|\b(?:sessionid|session_id|auth_session|session_token|sid)\s*=\s*[^;\s,]+",
        # Access-key IDs are exactly 20 uppercase ASCII alphanumerics. AKIA is
        # the long-lived form and ASIA is the temporary STS form. Keep this
        # alternative case-sensitive despite the combined expression's
        # IGNORECASE flag, and require non-alphanumeric boundaries so a prefix
        # of a longer identifier is never rewritten.
        BuiltInSanitizers.AWS_ACCESS_KEY_IDS: r"(?-i:(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9]))",
    }

    _CREDENTIAL_MARKERS = (
        "ipmitool",
        "curl",
        "sshpass",
        "password",
        "passwd",
        "pwd",
        "pass",
        "secret",
        "key",
        "token",
        "jwt",
        "auth",
        "credential",
        "user",
        "username",
    )
    _API_KEY_MARKERS = (
        "api_key",
        "apikey",
        "access_key",
        "accesskey",
        "secret_key",
        "secretkey",
    )
    _TOKEN_MARKERS = ("bearer", "token")
    _COOKIE_MARKERS = (
        "cookie",
        "sessionid",
        "session_id",
        "auth_session",
        "session_token",
        "sid",
    )
    # Every successful match contains at least one of these literal fragments.
    # Broad serial/part patterns and future policies have no proven literal gate
    # and therefore keep the full expression. This checks only whether a match
    # is possible; the ordered master expression still decides what to redact.
    _BUILTIN_LITERAL_MARKERS = {
        BuiltInSanitizers.IPV4: (".",),
        BuiltInSanitizers.IPV6: (":",),
        BuiltInSanitizers.MAC_ADDRESS: (":", "-"),
        BuiltInSanitizers.CREDENTIALS: _CREDENTIAL_MARKERS,
        BuiltInSanitizers.API_KEYS: _API_KEY_MARKERS,
        BuiltInSanitizers.TOKENS: _TOKEN_MARKERS,
        BuiltInSanitizers.PRIVATE_KEYS: ("BEGIN ",),
        BuiltInSanitizers.CREDENTIAL_URIS: ("@",),
        BuiltInSanitizers.COOKIES: _COOKIE_MARKERS,
        BuiltInSanitizers.AWS_ACCESS_KEY_IDS: ("AKIA", "ASIA"),
    }

    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        style: str = "%",
        string_list: Optional[List[str]] = None,
        contextual_identity_list: Optional[List[str]] = None,
        replacement_string: str = "XXXX",
        additional_regex: Optional[List[BuiltInSanitizers]] = None,
        enabled: bool = True,
    ):
        """
        Initialize the sanitizer.

        The initializer records ``_ascii_subset_cache``, ``_builtin_patterns``,
        ``_exact_patterns``, ``compiled_regex``, and ``enabled`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            fmt: Optional fmt; ``None`` selects the function's default behavior.
            datefmt: Optional datefmt; ``None`` selects the function's default
                behavior.
            style: Text supplied as style in the format accepted by this
                function.
            string_list: Optional string list; ``None`` selects the function's
                default behavior.
            contextual_identity_list: Optional configured usernames redacted
                only where surrounding syntax identifies an account value.
            replacement_string: Text supplied as replacement string in the
                format accepted by this function.
            additional_regex: Optional additional regex; ``None`` selects the
                function's default behavior.
            enabled: Whether enabled is enabled or required for this operation.
        """
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)

        self.enabled = enabled
        self.replacement = replacement_string
        self.compiled_regex = None
        self._exact_patterns: tuple[str, ...] = ()
        self._exact_pattern_markers: tuple[str, ...] = ()
        self._builtin_patterns: tuple[tuple[BuiltInSanitizers, str], ...] = ()
        self._enabled_builtins: frozenset[BuiltInSanitizers] = frozenset()
        self._ascii_subset_cache: OrderedDict[
            tuple[tuple[bool, ...], tuple[bool, ...]], re.Pattern[str] | None
        ] = OrderedDict()
        self._literal_match_prefilter: re.Pattern[str] | None = None
        self._literal_match_prefilter_uses_ascii_fold = False

        if not enabled:
            return

        # Build regex patterns
        exact_patterns: list[str] = []
        exact_pattern_markers: list[str] = []
        builtin_patterns: list[tuple[BuiltInSanitizers, str]] = []
        literal_markers: set[str] = set()
        can_prefilter = True

        # Add specific strings to sanitize
        if string_list:
            ordered_strings = sorted(
                dict.fromkeys(string_list),
                key=lambda value: (-len(value), value.casefold(), value),
            )
            for string in ordered_strings:
                if string:
                    # Configured canaries are exact secret values, not lexical
                    # words. Match the escaped literal wherever it occurs so a
                    # controller cannot preserve it by adjoining identifier
                    # characters. Longest-first ordering handles overlaps.
                    pattern = re.escape(string)
                    exact_patterns.append(pattern)
                    exact_pattern_markers.append(string)
                    literal_markers.add(string)

        # Configured account names are privacy identifiers, not opaque secret
        # values. Contextual matching preserves public command/vendor tokens
        # while still redacting assignments, login prose, and user paths.
        if contextual_identity_list:
            ordered_identities = sorted(
                dict.fromkeys(contextual_identity_list),
                key=lambda value: (-len(value), value.casefold(), value),
            )
            for identity in ordered_identities:
                if identity:
                    pattern = _configured_identity_pattern(identity)
                    exact_patterns.append(pattern)
                    exact_pattern_markers.append(identity)
                    literal_markers.add(identity)

        # Add built-in patterns
        if additional_regex:
            for sanitizer in additional_regex:
                if sanitizer in self.builtin_regex:
                    pattern = self.builtin_regex[sanitizer]
                    builtin_patterns.append((sanitizer, pattern))
                    markers = self._BUILTIN_LITERAL_MARKERS.get(sanitizer)
                    if markers is None:
                        can_prefilter = False
                    else:
                        literal_markers.update(markers)

        self._exact_patterns = tuple(exact_patterns)
        self._exact_pattern_markers = tuple(exact_pattern_markers)
        self._builtin_patterns = tuple(builtin_patterns)
        self._enabled_builtins = frozenset(
            sanitizer for sanitizer, _pattern in builtin_patterns
        )

        # URL userinfo must win at the same starting position as a configured
        # username canary. Keep the original builtin in the expression as well:
        # it preserves the established pattern inventory while this
        # group-free priority alternative closes the overlap in one pass.
        patterns: list[str] = []
        if any(
            sanitizer is BuiltInSanitizers.CREDENTIAL_URIS
            for sanitizer, _pattern in builtin_patterns
        ):
            patterns.append(_CREDENTIAL_URI_STANDALONE_PATTERN)
        patterns.extend(exact_patterns)
        patterns.extend(pattern for _sanitizer, pattern in builtin_patterns)

        # Compile the combined regex
        if patterns:
            self.compiled_regex = re.compile(
                "|".join(patterns), flags=re.IGNORECASE | re.MULTILINE
            )
            if can_prefilter and literal_markers:
                prefilter_flags = re.IGNORECASE | re.MULTILINE
                if all(str.isascii(marker) for marker in literal_markers):
                    # This gate only sees ASCII inputs. Lowercase both copies
                    # so the regex engine can use its case-sensitive literal
                    # search instead of Unicode case comparisons at every
                    # input position. Actual redaction still uses the original
                    # complete input and its unchanged policy expression.
                    literal_markers = {str.lower(marker) for marker in literal_markers}
                    prefilter_flags = re.MULTILINE
                    self._literal_match_prefilter_uses_ascii_fold = True
                self._literal_match_prefilter = re.compile(
                    "|".join(re.escape(marker) for marker in sorted(literal_markers)),
                    flags=prefilter_flags,
                )

    def is_sensitive_structured_key(self, key: str) -> bool:
        """
        Return whether this sanitizer must redact a structured field.

        Key-aware redaction is enabled only when the sanitizer was configured
        with a credential-key matcher. Exact-string-only sanitizers therefore
        retain their existing semantics in JSON/YAML artifacts. Repeated short
        field names reuse a bounded, policy-specific classification cache;
        payload values still pass through the active text sanitizer on every
        write. Oversized names are classified without retaining them.

        Args:
            key: Stable key used for lookup and operator-facing diagnostics.

        Returns:
            Whether this sanitizer must redact a structured field.
        """

        if not self.enabled:
            return False
        if type(key) is str and len(key) <= _STRUCTURED_KEY_CACHE_MAX_CHARS:
            return _cached_structured_key_classification(key, self._enabled_builtins)
        return _classify_structured_key(key, self._enabled_builtins)

    @classmethod
    def _builtin_can_match_ascii(
        cls,
        sanitizer: BuiltInSanitizers,
        text: str,
        lowered: str,
    ) -> bool:
        """
        Test necessary ASCII markers without changing Unicode matching semantics.

        These checks deliberately use necessary, not sufficient, conditions.
        False positives merely retain a regex alternative; a false negative
        would weaken sanitization. For Unicode inputs, the caller maps the four
        additional Unicode equivalents of ASCII letters before lowercasing the
        marker-search copy. Delimiters and case-sensitive AWS prefixes are
        checked against the original text. Matching still uses the original
        input with Python's full Unicode ``IGNORECASE`` behavior.

        Args:
            sanitizer: Built-in policy whose necessary markers are checked.
            text: Original text used for exact delimiter and prefix checks.
            lowered: Lowercase marker-search copy with Unicode equivalents of
                ASCII letters mapped before lowercasing.

        Returns:
            Whether the built-in remains eligible to match the complete input.
            Policies without a proven necessary marker always remain eligible.
        """

        if sanitizer is BuiltInSanitizers.IPV4:
            return "." in text
        if sanitizer is BuiltInSanitizers.IPV6:
            return ":" in text
        if sanitizer is BuiltInSanitizers.MAC_ADDRESS:
            return ":" in text or "-" in text
        if sanitizer in {
            BuiltInSanitizers.SERIAL_NUMBER,
            BuiltInSanitizers.PART_NUMBER,
        }:
            # These broad patterns have no cheap delimiter which every match
            # must contain, so they must remain active.
            return True
        if sanitizer is BuiltInSanitizers.CREDENTIALS:
            return any(tool in lowered for tool in ("ipmitool", "curl", "sshpass")) or (
                ("=" in text or ":" in text)
                and any(marker in lowered for marker in cls._CREDENTIAL_MARKERS)
            )
        if sanitizer is BuiltInSanitizers.API_KEYS:
            return ("=" in text or ":" in text) and any(
                marker in lowered for marker in cls._API_KEY_MARKERS
            )
        if sanitizer is BuiltInSanitizers.TOKENS:
            return any(marker in lowered for marker in cls._TOKEN_MARKERS)
        if sanitizer is BuiltInSanitizers.PRIVATE_KEYS:
            return all(marker in lowered for marker in ("begin ", "private key"))
        if sanitizer is BuiltInSanitizers.CREDENTIAL_URIS:
            return "://" in text and "@" in text
        if sanitizer is BuiltInSanitizers.COOKIES:
            return (":" in text or "=" in text) and any(
                marker in lowered for marker in cls._COOKIE_MARKERS
            )
        if sanitizer is BuiltInSanitizers.AWS_ACCESS_KEY_IDS:
            # The pattern is deliberately case-sensitive, so lowercase
            # prefixes are not a necessary condition for an ASCII match.
            return "AKIA" in text or "ASIA" in text
        # Future built-ins remain enabled until they have a proven-safe gate.
        return True

    def _compiled_regex_for_text(self, text: str) -> re.Pattern[str] | None:
        """
        Select a semantics-equivalent regex for one input string.

        Short fields use the complete expression directly. Evaluating every
        built-in predicate for each small JSON key or value costs more than
        matching the expression; large strings still benefit from the
        reduced set of alternatives.

        Large artifacts also omit configured ASCII literal and identity patterns
        whose necessary literal is absent from the complete input. The literal
        gate maps Python's four additional Unicode equivalents of ASCII letters
        before lowercasing; the actual matcher still receives the original text.
        The same mapping preserves built-in ASCII keyword gates. Non-ASCII
        configured markers and built-ins without proven gates stay active.
        The bounded cache retains policy-selection bits and compiled expressions;
        it never retains artifact text or redacted payloads.

        The master expression remains the fallback for short Unicode fields and
        replacement templates containing escapes/backreferences. Removing an impossible
        alternative changes capture-group numbering, so escaped replacement
        templates must retain the original expression even when the skipped
        groups could not have matched.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical compiled regex for text, or ``None`` when the
            requested value is unavailable.
        """

        if (
            len(text) < 128
            or not isinstance(self.replacement, str)
            or "\\" in self.replacement
        ):
            return self.compiled_regex

        ascii_text = text.isascii()
        if not ascii_text and len(text) < 64 * 1024:
            return self.compiled_regex

        literal_input = text
        if not ascii_text:
            # Python re.IGNORECASE equates these four non-ASCII characters
            # with ASCII letters. Replace them before lowercasing, since dotted
            # capital I otherwise expands to an i followed by a combining dot.
            # No normalized text is ever used as the redaction input.
            for character, equivalent in (
                ("\u0130", "i"),
                ("\u0131", "i"),
                ("\u017f", "s"),
                ("\u212a", "k"),
            ):
                literal_input = literal_input.replace(character, equivalent)
        lowered = literal_input.lower()
        active = tuple(
            self._builtin_can_match_ascii(sanitizer, text, lowered)
            for sanitizer, _ in self._builtin_patterns
        )
        active_exact = tuple(
            len(text) < 64 * 1024 or not marker.isascii() or marker.lower() in lowered
            for marker in self._exact_pattern_markers
        )
        if all(active) and all(active_exact):
            return self.compiled_regex
        cache_key = (active_exact, active)
        try:
            return self._ascii_subset_cache[cache_key]
        except KeyError:
            pass

        enabled_builtins = tuple(
            (sanitizer, pattern)
            for enabled, (sanitizer, pattern) in zip(active, self._builtin_patterns)
            if enabled
        )
        patterns: list[str] = []
        if any(
            sanitizer is BuiltInSanitizers.CREDENTIAL_URIS
            for sanitizer, _pattern in enabled_builtins
        ):
            patterns.append(_CREDENTIAL_URI_STANDALONE_PATTERN)
        patterns.extend(
            pattern
            for enabled, pattern in zip(active_exact, self._exact_patterns)
            if enabled
        )
        patterns.extend(pattern for _sanitizer, pattern in enabled_builtins)
        compiled = (
            re.compile("|".join(patterns), flags=re.IGNORECASE | re.MULTILINE)
            if patterns
            else None
        )
        self._ascii_subset_cache[cache_key] = compiled
        while len(self._ascii_subset_cache) > 128:
            # Remove the oldest entry in one operation. Holding a live dict
            # iterator across calls lets concurrent publication workers change
            # its size before next() and fail an otherwise valid redaction.
            try:
                self._ascii_subset_cache.popitem(last=False)
            except KeyError:
                break
        return compiled

    def sanitize(self, text: str) -> str:
        """
        Sanitize a string by replacing sensitive data.

        A compiled literal gate can prove that an ASCII field cannot match any
        configured secret, identity, or enabled built-in pattern. Such fields
        avoid the more expensive substitution without caching payload values.
        Possible matches retain the existing expression order and replacement
        behavior. Unicode input and escaped or non-string replacements bypass
        this gate to preserve case folding and replacement validation.

        An all-ASCII marker policy uses a lowercase search copy to avoid costly
        Unicode case comparisons in the prefilter. Non-ASCII configured markers
        retain the original case-insensitive gate, including their possible
        ASCII equivalents. Built-in string operations inspect actual string
        contents even when a caller supplies a string subclass.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical result text.
        """
        if not self.enabled or not self.compiled_regex or not text:
            return text

        if (
            self._literal_match_prefilter is not None
            and len(text) < 64 * 1024
            and isinstance(self.replacement, str)
            and "\\" not in self.replacement
            and str.isascii(text)
            and self._literal_match_prefilter.search(
                str.lower(text)
                if self._literal_match_prefilter_uses_ascii_fold
                else text
            )
            is None
        ):
            return text

        compiled_regex = self._compiled_regex_for_text(text)
        if compiled_regex is None:
            return text
        if (
            len(text) >= 64 * 1024
            and "\n" in text
            and isinstance(self.replacement, str)
            and "\\" not in self.replacement
        ):
            return self._sanitize_multiline_text(text, compiled_regex)
        return compiled_regex.sub(self.replacement, text)

    def _sanitize_multiline_text(
        self, text: str, compiled_regex: re.Pattern[str]
    ) -> str:
        """
        Preserve complete-string redaction while yielding between unmatched lines.

        Python's regex substitution can hold the interpreter lock throughout a
        large journal, even in a worker thread. A final newline alternative lets
        match iteration return to Python at line boundaries. The original ordered
        expression has priority and sees the entire original string, so matches
        spanning newlines and lookaround context remain unchanged. Checkpoint
        matches are copied verbatim and never become redactions.

        Background callers explicitly release the interpreter lock after the
        first small batch, then after short elapsed-time budgets. Returning to
        Python alone leaves I/O callbacks waiting behind CPU workers when socket,
        crypto, or filesystem calls release and reacquire that lock. A zero-delay
        thread yield lets those callbacks proceed without changing process-wide
        scheduling settings.
        Checking time at the same small match intervals avoids a system call for
        every pair of cheap newline checkpoints while retaining later handoffs.
        Main-thread callers retain the synchronous API without clock reads or
        added yields.

        This does not bound work inside one physical line or regex match. Callers
        still offload large text preparation to owned workers. Escaped replacement
        templates retain the canonical substitution path in ``sanitize``.

        Args:
            text: Complete diagnostic text requiring redaction.
            compiled_regex: The existing policy expression selected for this text.

        Returns:
            Exactly the canonical substitution result for the literal replacement.
        """

        # Keep global inline flags at the beginning and terminate a possible
        # trailing verbose-mode comment before appending the final alternative.
        separator = "\n" if compiled_regex.flags & re.VERBOSE else ""
        checkpoint_regex = re.compile(
            f"{compiled_regex.pattern}{separator}|(\\n)", flags=compiled_regex.flags
        )
        checkpoint_group = compiled_regex.groups + 1
        pieces: list[str] = []
        position = 0
        yield_worker = current_thread() is not main_thread()
        matches_since_yield = 0
        yield_deadline: Optional[float] = None
        for match in checkpoint_regex.finditer(text):
            if yield_worker:
                matches_since_yield += 1
                if matches_since_yield >= _MULTILINE_THREAD_YIELD_MATCHES:
                    matches_since_yield = 0
                    if yield_deadline is None or monotonic() >= yield_deadline:
                        sleep(0)
                        yield_deadline = (
                            monotonic() + _MULTILINE_THREAD_YIELD_INTERVAL_SECONDS
                        )
            if match.group(checkpoint_group) is not None:
                continue
            pieces.extend((text[position : match.start()], self.replacement))
            position = match.end()
        if not pieces:
            return text
        pieces.append(text[position:])
        return "".join(pieces)

    def format(self, record: logging.LogRecord) -> str:
        """
        Override format to sanitize log messages.

        The implementation uses ``record`` to override format to sanitize log
        messages.

        Args:
            record: Record object whose ``msg`` state is read while performing
                override format to sanitize log messages.

        Returns:
            The canonical result text.
        """
        if not self.enabled:
            return super().format(record)

        # Sanitize the message
        if hasattr(record, "msg") and record.msg:
            record.msg = self.sanitize(str(record.msg))

        # Sanitize the formatted string
        formatted = super().format(record)
        return self.sanitize(formatted)


class SanitizedPrinter:
    """
    Wrapper for print() that sanitizes output.

    Intercepts print calls and sanitizes arguments before outputting.
    """

    def __init__(self, sanitizer: LogSanitizer):
        """
        Initialize sanitized printer.

        The initializer records ``original_print`` and ``sanitizer`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            sanitizer: Sanitizer applied before untrusted or sensitive text
                leaves its boundary.
        """
        self.sanitizer = sanitizer
        self.original_print = print

    def __call__(self, *args, **kwargs):
        """
        Sanitize and print arguments.

        Convert all arguments to strings and sanitize them.

        Args:
            args: Additional positional values forwarded in caller-provided
                order.
            kwargs: Additional named values forwarded without changing their
                keys.
        """
        if not self.sanitizer.enabled:
            self.original_print(*args, **kwargs)
            return

        # Convert all arguments to strings and sanitize them
        sanitized_args = []
        for arg in args:
            sanitized_args.append(
                neutralize_terminal_text(self.sanitizer.sanitize(str(arg)))
            )

        self.original_print(*sanitized_args, **kwargs)


_DUT_IDENTITY_FIELDS = frozenset(
    {
        "user",
        "username",
        "bmc_user",
        "bmc_username",
        "bmc_ssh_user",
        "bmc_ssh_username",
        "bmc_rf_user",
        "rf_user",
        "host_user",
        "host_username",
        "host_ssh_user",
        "host_ssh_username",
        "hmc_user",
        "hmc_username",
        "hmc_ssh_user",
        "hmc_ssh_username",
        "ssh_proxy_user",
        "ssh_proxy_username",
    }
)
_DUT_EXACT_SENSITIVE_FIELDS = frozenset(
    {
        "pass",
        "password",
        "bmc_ip",
        "bmc_pass",
        "bmc_password",
        "bmc_ssh_pass",
        "bmc_ssh_password",
        "bmc_ssh_key_path",
        "bmc_rf_pass",
        "rf_pass",
        "host_ip",
        "host_pass",
        "host_password",
        "host_sudo_password",
        "host_ssh_pass",
        "host_ssh_password",
        "host_ssh_key_path",
        "hmc_ip",
        "hmc_pass",
        "hmc_password",
        "hmc_ssh_pass",
        "hmc_ssh_password",
        "hmc_ssh_key_path",
        "ssh_proxy_host",
        "ssh_proxy_pass",
        "ssh_proxy_password",
        "ssh_proxy_key_path",
        "serial_number",
        "part_number",
        "platform_model",
        "platformmodel",
        "partnumber",
        "serialnumber",
    }
)
_DUT_SENSITIVE_FIELDS = _DUT_IDENTITY_FIELDS | _DUT_EXACT_SENSITIVE_FIELDS


def _extract_dut_config_field_values(
    dut_config: Dict[str, Any], field_names: frozenset[str]
) -> List[str]:
    """
    Return scalar values below an exact set of accepted DUT field names.

    Canonical Pydantic names and legacy YAML spellings normalize through
    case-folding. Exact field membership keeps similarly named boolean controls
    from becoming destructive canaries.

    Args:
        dut_config: Nested DUT configuration mapping to inspect recursively.
        field_names: Case-folded field names whose scalar values are retained.

    Returns:
        Matching nonempty string and integer values in traversal order.
    """

    values: List[str] = []

    def visit(data: Any) -> None:
        """
        Visit nested mappings and lists without retaining container ownership.

        Recursion deliberately continues below matched fields so nested DUT
        records are handled consistently regardless of their container shape.

        Args:
            data: Current nested configuration value being inspected.

        Side Effects:
            Appends admitted scalar values to the enclosing ``values`` list.
        """

        if isinstance(data, dict):
            for key, value in data.items():
                if (
                    key.casefold() in field_names
                    and not isinstance(value, bool)
                    and isinstance(value, (str, int))
                    and value
                ):
                    values.append(str(value))
                visit(value)
        elif isinstance(data, list):
            for item in data:
                visit(item)

    visit(dut_config)
    return values


def extract_sensitive_fields_from_dut_config(
    dut_config: Dict[str, Any],
) -> List[str]:
    """
    Extract credential and privacy fields from DUT configuration.

    This inventory API retains usernames alongside opaque credentials for
    compatibility. Sanitizer construction separately assigns contextual
    matching to usernames so public product vocabulary remains intact.

    Args:
        dut_config: Nested DUT configuration mapping to inspect recursively.

    Returns:
        Matching credential, endpoint, hardware-identity, and username values.
    """

    return _extract_dut_config_field_values(dut_config, _DUT_SENSITIVE_FIELDS)


_COMMON_SENSITIVE_CANARY_VALUES = frozenset({"true", "false", "none", "null"})


def normalize_sensitive_canary_values(values: Iterable[Any]) -> List[str]:
    """
    Return safe, deterministic exact-value sanitizer canaries.

    Tiny and common values are too destructive as unanchored sanitizer patterns.
    Longer overlapping values must precede their prefixes so the combined
    regular expression cannot expose a secret suffix.

    Args:
        values: Entries supplied as ``values`` without transferring container
            ownership.

    Returns:
        The sensitive canary values returned in operation-defined order.
    """

    unique_values = {
        str(value)
        for value in values
        if value is not None and not isinstance(value, bool)
    }
    filtered_values = [
        value
        for value in unique_values
        if value.strip()
        and len(value.encode("utf-8")) >= 4
        and value.strip().casefold() not in _COMMON_SENSITIVE_CANARY_VALUES
    ]
    return sorted(
        filtered_values,
        key=lambda value: (-len(value), value.casefold(), value),
    )


def extract_sensitive_fields_from_environment(
    environment: Optional[Dict[str, str]] = None,
) -> List[str]:
    """
    Return credential-like environment values that must not enter a bundle.

    Environment is the lowest supported configuration source, but its secrets
    still need the same exact-value canaries as DUT YAML credentials. Boolean
    controls and very short/common values are excluded to avoid rewriting
    ordinary prose throughout reports.

    Args:
        environment: Optional environment; ``None`` selects the function's
            default behavior.

    Returns:
        The sensitive fields from environment returned in operation-defined
        order.
    """

    values: List[str] = []
    source = os.environ if environment is None else environment
    for key, raw_value in source.items():
        if is_secret_environment_name(key):
            values.append(str(raw_value))
        else:
            values.extend(extract_url_userinfo_secrets(str(raw_value)))
    return normalize_sensitive_canary_values(values)


def create_sanitizer_from_config(
    dut_config: Dict[str, Any],
    enabled: bool = True,
    additional_regex: Optional[List[BuiltInSanitizers]] = None,
    extra_strings: Optional[List[str]] = None,
    username_strings: Optional[List[str]] = None,
) -> LogSanitizer:
    """
    Create a sanitizer configured for the given DUT configuration.

    Usernames are matched only in account contexts so common public product
    vocabulary remains intact. Opaque credentials, configured endpoints, and
    explicit extra strings retain exact substring redaction.

    Args:
        dut_config: DUT config governing sanitizer configured for the given DUT
            configuration.
        enabled: Whether enabled is enabled or required for this operation.
        additional_regex: Optional additional regex; ``None`` selects the
            function's default behavior.
        extra_strings: Optional extra strings; ``None`` selects the function's
            default behavior.
        username_strings: Optional additional account identities; ``None``
            selects the function's default behavior.

    Returns:
        A ``LogSanitizer`` representing sanitizer from config.
    """
    if not enabled:
        return LogSanitizer(enabled=False)

    # Opaque credentials and device identifiers remain exact canaries.
    # Usernames use contextual matching because field deployments commonly use
    # public vendor/tool words as account names.
    sensitive_values = _extract_dut_config_field_values(
        dut_config, _DUT_EXACT_SENSITIVE_FIELDS
    )
    identity_values = _extract_dut_config_field_values(dut_config, _DUT_IDENTITY_FIELDS)

    # Add extra strings
    if extra_strings:
        sensitive_values.extend(extra_strings)
    if username_strings:
        identity_values.extend(username_strings)

    identity_values = normalize_sensitive_canary_values(identity_values)
    identity_value_keys = {value.casefold() for value in identity_values}
    sensitive_values = normalize_sensitive_canary_values(
        value
        for value in sensitive_values
        if str(value).casefold() not in identity_value_keys
    )

    # Default built-in sanitizers.
    #
    # Generic IPV4/IPV6/MAC_ADDRESS matching is deliberately NOT enabled here.
    # This tool exists to diagnose network-attached BMCs, and blanket address
    # redaction destroyed the evidence it collects: every address became the
    # same replacement token, so distinct hosts were indistinguishable and a
    # request could not be followed across hops. It was also what failed a
    # whole bundle when a collector legitimately keyed a mapping by interface
    # address.
    #
    # The DUT's own configured addresses remain redacted -- bmc_ip, host_ip and
    # hmc_ip are registered as exact-match canaries by
    # extract_sensitive_fields_from_dut_config -- so this widens only incidental
    # addresses appearing in collected output. Deployments that need blanket
    # matching can still request these patterns via additional_regex.
    if additional_regex is None:
        additional_regex = [
            BuiltInSanitizers.CREDENTIALS,
            BuiltInSanitizers.API_KEYS,
            BuiltInSanitizers.TOKENS,
            BuiltInSanitizers.PRIVATE_KEYS,
            BuiltInSanitizers.CREDENTIAL_URIS,
            BuiltInSanitizers.COOKIES,
            BuiltInSanitizers.AWS_ACCESS_KEY_IDS,
        ]

    return LogSanitizer(
        string_list=sensitive_values,
        contextual_identity_list=identity_values,
        additional_regex=additional_regex,
        enabled=enabled,
    )


def patch_print_with_sanitizer(sanitizer: LogSanitizer) -> None:
    """
    Patch the global print function to use sanitization.

    The implementation uses ``sanitizer`` to patch the global print function to
    use sanitization.

    Args:
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.
    """
    import builtins

    builtins.print = SanitizedPrinter(sanitizer)


# ----------------------------
# Config file sanitization
# ----------------------------
_CONFIG_CRED_KEY_RE = re.compile(
    # Capture one bounded YAML/INI-ish key/value line. Sensitivity is decided
    # by the same structured-key classifier used for JSON/YAML artifacts,
    # eliminating drift between delimited and camel/concatenated key names.
    r"(?im)^(?P<prefix>[ \t]*(?P<key>[^#\n:=]+?)[ \t]*[:=][ \t]*)"
    r"(?P<value>[^\n]+)"
)

_IPV4_RE = re.compile(LogSanitizer.builtin_regex[BuiltInSanitizers.IPV4])
_IPV6_RE = re.compile(LogSanitizer.builtin_regex[BuiltInSanitizers.IPV6])
_EXTENSION_CONFIG_BLOCK_RE = re.compile(
    r"^(?P<indent>[ \t]*)[\"']?COLLECTOR_EXTENSION_CONFIG[\"']?\s*:\s*(?:#.*)?(?:\r?\n)?$",
    re.IGNORECASE,
)
_EXTENSION_FILE_REFERENCE_RE = re.compile(
    r"^(?P<prefix>[ \t]*(?:-[ \t]*)?[\"']?(?:path|file|source|[A-Za-z0-9_-]+_(?:path|file|source))[\"']?[ \t]*:[ \t]*)"
    r"(?P<value>[^#\r\n]*?)(?P<comment>[ \t]*#.*)?(?P<newline>\r?\n)?$",
    re.IGNORECASE,
)
_EXTENSION_INLINE_FILE_REFERENCE_RE = re.compile(
    r"(?P<prefix>[\"']?(?:path|file|source|[A-Za-z0-9_-]+_(?:path|file|source))[\"']?[ \t]*:[ \t]*)"
    r"(?P<value>[^,}\]\r\n#]+)",
    re.IGNORECASE,
)
_EXTENSION_FILE_REFERENCE_KEY_RE = re.compile(
    r"(?:path|file|source|[A-Za-z0-9_-]+_(?:path|file|source))",
    re.IGNORECASE,
)
_YAML_VALUE_PREFIX_RE = re.compile(r"^(?:(?:&|!)[^ \t\r\n]+[ \t]+)*")
_YAML_NODE_PROPERTY_PREFIX_RE = re.compile(
    r"^(?P<prefix>(?:(?:&|!)[^ \t\r\n]+(?:[ \t\r\n]+))*)"
)
_YAML_PLAIN_REPLACEMENT_RE = re.compile(r"[A-Za-z0-9_.-]+")
_YAML_NON_STRING_PLAIN_SCALARS = frozenset(
    {"", "~", "null", "true", "false", "yes", "no", "on", "off"}
)
_MAX_CONFIG_YAML_CHARACTERS = 16 * 1024 * 1024
_MAX_CONFIG_YAML_DOCUMENTS = 64
_MAX_CONFIG_YAML_NODES = 100_000
_MAX_CONFIG_YAML_ALIASES = 10_000
_MAX_CONFIG_YAML_DEPTH = 128
_CONFIG_STRUCTURED_CONTAINER_NAMESPACES = frozenset({("debug", "token")})
_EXTENSION_CONFIG_NAMESPACE = ("collector", "extension", "config")


def _yaml_replacement_scalar(replacement: str) -> str:
    """
    Return the YAML replacement scalar.

    JSON strings are also valid YAML double-quoted scalars and keep arbitrary
    operator-selected replacement text on one syntactic line.

    Args:
        replacement: Text supplied as replacement in the format accepted by this
            function.

    Returns:
        The canonical YAML replacement scalar text.
    """
    if (
        _YAML_PLAIN_REPLACEMENT_RE.fullmatch(replacement)
        and replacement.casefold() not in _YAML_NON_STRING_PLAIN_SCALARS
    ):
        return replacement
    # JSON strings are also valid YAML double-quoted scalars and keep arbitrary
    # operator-selected replacement text on one syntactic line.
    return json.dumps(replacement, ensure_ascii=False)


class _BoundedConfigYamlLoader(yaml.SafeLoader):
    """
    Compose YAML nodes without permitting unbounded aliases or depth.

    The type coordinates ``compose_node`` and retains the state those operations
    share between calls. Resource ownership remains inside the instance until
    the matching close, exit, or cleanup operation completes.
    """

    def __init__(self, stream: str) -> None:
        """
        Initialize a ``_BoundedConfigYamlLoader`` instance.

        The initializer records ``_alias_count``, ``_compose_depth``, and
        ``_node_count`` for later operations and establishes the instance
        invariants before any public method runs.

        Args:
            stream: Text supplied as stream in the format accepted by this
                function.
        """
        super().__init__(stream)
        self._node_count = 0
        self._alias_count = 0
        self._compose_depth = 0

    def compose_node(self, parent: Any, index: Any) -> yaml.Node:
        """
        Compose node.

        The implementation uses ``parent`` and ``index`` to compose node. It
        updates ``_alias_count``, ``_compose_depth``, and ``_node_count`` on the
        instance as part of that state transition. If the function cannot
        compose node, its exception reaches the caller instead of being
        converted into a successful result. Cleanup in the ``finally`` path runs
        for successful, failed, and cancelled execution.

        Args:
            parent: Parent consumed while the function attempts to compose node.
            index: Zero-based position within the containing sequence.

        Returns:
            A ``Node`` representing compose node.

        Raises:
            ValueError: If config YAML alias count exceeds sanitization limit;
                config YAML node count exceeds sanitization limit; or config
                YAML nesting depth exceeds sanitization limit.
        """
        if self.check_event(yaml.events.AliasEvent):
            self._alias_count += 1
            if self._alias_count > _MAX_CONFIG_YAML_ALIASES:
                raise ValueError("config YAML alias count exceeds sanitization limit")
            return super().compose_node(parent, index)

        self._node_count += 1
        if self._node_count > _MAX_CONFIG_YAML_NODES:
            raise ValueError("config YAML node count exceeds sanitization limit")
        self._compose_depth += 1
        if self._compose_depth > _MAX_CONFIG_YAML_DEPTH:
            self._compose_depth -= 1
            raise ValueError("config YAML nesting depth exceeds sanitization limit")
        try:
            return super().compose_node(parent, index)
        finally:
            self._compose_depth -= 1


def _compose_config_yaml_bounded(text: str) -> list[yaml.Node | None]:
    """
    Compose config YAML bounded.

    The implementation uses ``text`` to compose config YAML bounded. If the
    function cannot compose config YAML bounded, its exception reaches the
    caller instead of being converted into a successful result. Cleanup in the
    ``finally`` path runs for successful, failed, and cancelled execution.

    Args:
        text: Text supplied as text in the format accepted by this function.

    Returns:
        The validated ``roots``, or ``None`` when no value qualifies.

    Raises:
        ValueError: If config YAML size exceeds sanitization limit; or config
            YAML document count exceeds sanitization limit.
    """
    if len(text) > _MAX_CONFIG_YAML_CHARACTERS:
        raise ValueError("config YAML size exceeds sanitization limit")

    loader = _BoundedConfigYamlLoader(text)
    roots: list[yaml.Node | None] = []
    try:
        while loader.check_node():
            if len(roots) >= _MAX_CONFIG_YAML_DOCUMENTS:
                raise ValueError(
                    "config YAML document count exceeds sanitization limit"
                )
            roots.append(loader.get_node())
    finally:
        loader.dispose()
    return roots


def _sanitize_yaml_credential_values(text: str, replacement: str) -> tuple[str, bool]:
    """
    Redact credential values by bounded YAML node spans.

    Composed nodes retain source spans and alias identity without constructing
    arbitrary Python objects. Replacing those spans covers block and flow
    mappings as well as aliases while retaining anchors used elsewhere in the
    document. Invalid/non-structured input is returned for the legacy text
    matcher; resource-limit violations fail closed instead of silently falling
    back to a weaker redaction mode.

    Args:
        text: Text supplied as text in the format accepted by this function.
        replacement: Text supplied as replacement in the format accepted by this
            function.

    Returns:
        A tuple containing ``text`` and ``status flag`` in that order.
    """

    try:
        roots = _compose_config_yaml_bounded(text)
    except yaml.YAMLError:
        return text, False
    if not roots:
        return text, False

    spans: set[tuple[int, int]] = set()
    # Alias targets can be reached once outside and once inside the extension
    # namespace. Keep traversal identity contextual so an earlier benign alias
    # cannot suppress path redaction at its sensitive use site.
    visited: set[tuple[int, bool]] = set()
    saw_mapping = False

    def collect(node: yaml.Node, *, in_extension_config: bool = False) -> None:
        """
        Collect the configured diagnostic data.

        The implementation uses ``node`` and ``in_extension_config`` to collect
        the configured diagnostic data. Terminal status is emitted only after
        configured diagnostic data and its owned cleanup have completed.

        Args:
            node: Node object whose ``value`` state is read while performing
                configured diagnostic data.
            in_extension_config: Whether in extension config is enabled or
                required for this operation.
        """
        nonlocal saw_mapping
        identity = (id(node), in_extension_config)
        if identity in visited:
            return
        visited.add(identity)

        if isinstance(node, yaml.MappingNode):
            saw_mapping = True
            for key_node, value_node in node.value:
                key_text = (
                    key_node.value
                    if isinstance(key_node, yaml.ScalarNode)
                    and isinstance(key_node.value, str)
                    else None
                )
                key_parts = (
                    _normalized_structured_key_parts(key_text)
                    if key_text is not None
                    else ()
                )
                child_in_extension_config = (
                    in_extension_config or key_parts == _EXTENSION_CONFIG_NAMESPACE
                )
                extension_file_reference = (
                    in_extension_config
                    and key_text is not None
                    and _EXTENSION_FILE_REFERENCE_KEY_RE.fullmatch(key_text) is not None
                )
                sensitive_key = key_text is not None and _is_sensitive_structured_key(
                    key_text
                )
                structured_namespace = (
                    sensitive_key
                    and not isinstance(value_node, yaml.ScalarNode)
                    and key_parts in _CONFIG_STRUCTURED_CONTAINER_NAMESPACES
                )
                sensitive_value = sensitive_key and not structured_namespace
                if sensitive_value or extension_file_reference:
                    spans.add(
                        (
                            value_node.start_mark.index,
                            value_node.end_mark.index,
                        )
                    )
                else:
                    collect(
                        value_node,
                        in_extension_config=child_in_extension_config,
                    )
                collect(key_node)
            return

        if isinstance(node, yaml.SequenceNode):
            for child in node.value:
                collect(child, in_extension_config=in_extension_config)

    for root in roots:
        if root is not None:
            collect(root)

    # Alias references reuse the anchored node's source span. A sensitive
    # alias can therefore introduce a span that contains one already found in
    # the anchor body. Keep only outermost intervals before editing offsets.
    selected_spans: list[tuple[int, int]] = []
    covered_until = -1
    for start, end in sorted(spans, key=lambda span: (span[0], -span[1])):
        if end <= covered_until:
            continue
        selected_spans.append((start, end))
        covered_until = end

    scalar = _yaml_replacement_scalar(replacement)
    for start, end in reversed(selected_spans):
        original_value = text[start:end]
        if original_value.endswith("\r\n"):
            line_break = "\r\n"
        elif original_value.endswith("\n"):
            line_break = "\n"
        else:
            line_break = ""

        prefix_match = _YAML_NODE_PROPERTY_PREFIX_RE.match(original_value)
        raw_prefix = prefix_match.group("prefix") if prefix_match else ""
        anchors = [token for token in raw_prefix.split() if token.startswith("&")]
        prefix = f"{' '.join(anchors)} " if anchors else ""
        text = f"{text[:start]}{prefix}{scalar}{line_break}{text[end:]}"
    return text, saw_mapping


def _sanitize_extension_file_references(text: str, replacement: str) -> str:
    """
    Redact local file references below the generic extension namespace.

    After applying local validation, the function forwards ``text`` and
    ``replacement`` to ``join`` and preserves its return and exception contract.

    Args:
        text: Text supplied as text in the format accepted by this function.
        replacement: Text supplied as replacement in the format accepted by this
            function.

    Returns:
        The canonical extension file references text.
    """
    output: List[str] = []
    extension_indent: Optional[int] = None
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        indentation = len(line) - len(line.lstrip(" \t"))

        block_match = _EXTENSION_CONFIG_BLOCK_RE.match(line)
        if block_match:
            extension_indent = len(block_match.group("indent"))
            output.append(line)
            continue

        if extension_indent is not None:
            if (
                stripped
                and not stripped.startswith("#")
                and indentation <= extension_indent
            ):
                extension_indent = None
            else:
                path_match = _EXTENSION_FILE_REFERENCE_RE.match(line)
                if path_match:
                    output.append(
                        f"{path_match.group('prefix')}{replacement}"
                        f"{path_match.group('comment') or ''}"
                        f"{path_match.group('newline') or ''}"
                    )
                    continue
                line = _EXTENSION_INLINE_FILE_REFERENCE_RE.sub(
                    lambda match: f"{match.group('prefix')}{replacement}", line
                )

        output.append(line)
    return "".join(output)


def redact_config_file_references(text: str, replacement: str = "XXXX") -> str:
    """
    Redact extension-owned file references without general config sanitization.

    Explicit sanitization opt-out preserves ordinary configuration values, but
    trusted extension and debug-token file references remain outside the bundle
    disclosure contract. This helper applies only that unconditional boundary
    while preserving the source YAML text and structure otherwise.

    Args:
        text: Configuration text whose extension file references are redacted.
        replacement: Text written in place of protected file references.

    Returns:
        Configuration text with only governed extension references redacted.
    """
    if not text:
        return text

    text = _sanitize_extension_file_references(text, replacement)
    return sanitize_optional_config_text(text, replacement)


def sanitize_config_text(text: str, replacement: str = "XXXX") -> str:
    """
    Sanitize config *text* while preserving structure.

    - Redacts values of any lines whose *key* contains user/password/token/etc
    (case-insensitive) while preserving the key portion. - Redacts IPv4/IPv6
    addresses anywhere in the text.

    This is intended for archiving `dut_config.yaml` / `tool_config.yaml` into
    run directories.

    Args:
        text: Text supplied as text in the format accepted by this function.
        replacement: Text supplied as replacement in the format accepted by this
            function.

    Returns:
        The canonical config text.
    """
    if not text:
        return text

    # Extension-owned local files use intentionally generic keys. Redact the
    # canonical namespace and let an installed trusted package handle bounded
    # legacy aliases before the general credential pass.
    text = redact_config_file_references(text, replacement)

    # Own credential values through a bounded YAML composition pass. This
    # covers block scalars, flow mappings, anchors, and aliases without
    # constructing arbitrary objects or expanding alias graphs.
    text, _structured_yaml = _sanitize_yaml_credential_values(text, replacement)

    # Redact credential-ish key/value lines but preserve the key. A YAML block
    # scalar already reduced above may retain an anchor/tag needed by aliases;
    # do not strip that safe prefix on the second pass.
    safe_yaml_scalar = _yaml_replacement_scalar(replacement)

    def redact_credential_match(match: re.Match[str]) -> str:
        """
        Return the redact credential match.

        The implementation uses ``match`` to produce the redact credential
        match.

        Args:
            match: Text supplied as match in the format accepted by this
                function.

        Returns:
            The canonical redact credential match text.
        """
        if not _is_sensitive_structured_key(match.group("key")):
            return match.group(0)
        value = match.group("value").strip()
        value_without_yaml_prefix = _YAML_VALUE_PREFIX_RE.sub("", value)
        if value_without_yaml_prefix in {replacement, safe_yaml_scalar}:
            return match.group(0)
        return f"{match.group('prefix')}{replacement}"

    text = _CONFIG_CRED_KEY_RE.sub(redact_credential_match, text)

    # Redact IPs anywhere (including inside URLs)
    text = _IPV4_RE.sub(replacement, text)
    text = _IPV6_RE.sub(replacement, text)
    return text
