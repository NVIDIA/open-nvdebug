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
Validation and scoring for catalog-defined Redfish platform discovery.

This module owns the platform detection profile boundary and exposes
``PlatformDetectionProfileError``, ``_literal_regex_prefix``,
``_collection_rule_scores``, ``_require_nonempty_string``, and
``_require_score``. Keeping those contracts together gives importers one source
of truth for their validation, lifecycle, and compatibility behavior.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

PLATFORM_DETECTION_PROFILE_KEY = "platform_detection_profile"
PLATFORM_DETECTION_PROFILE_VERSION = 1
_SUPPORTED_SIGNALS = {"model", "manufacturer", "part_number"}


class PlatformDetectionProfileError(ValueError):
    """
    Raised when catalog platform-detection metadata is unsafe or ambiguous.

    Callers receive this exception when the platform detection profile error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


def _literal_regex_prefix(pattern: str) -> str:
    """
    Return the literal prefix before the first regex operator.

    After applying local validation, the function forwards ``pattern`` to
    ``join`` and preserves its return and exception contract.

    Args:
        pattern: Text supplied as pattern in the format accepted by this
            function.

    Returns:
        The canonical literal regex prefix text.
    """

    literal = []
    escaped = False
    for character in pattern[1:]:
        if escaped:
            literal.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character in ".^$*+?{}[]|()":
            break
        else:
            literal.append(character)
    return "".join(literal)


def _collection_rule_scores(
    rules: List[Dict[str, Any]], member_uri_prefix: str
) -> List[int]:
    """
    Return a conservative score bound for direct members below a prefix.

    The implementation uses ``rules`` and ``member_uri_prefix`` to produce a
    conservative score bound for direct members below a prefix.

    Args:
        rules: Mapping supplying fields for conservative score bound for direct
            members below a prefix.
        member_uri_prefix: Validated remote resource identifier used for member
            URI prefix.

    Returns:
        The validated ``scores``.
    """

    scores = []
    for rule in rules:
        literal_prefix = _literal_regex_prefix(rule["pattern"])
        if member_uri_prefix.startswith(literal_prefix) or literal_prefix.startswith(
            member_uri_prefix
        ):
            scores.append(rule["score"])
    return scores


def _require_nonempty_string(value: Any, field: str) -> str:
    """
    Require nonempty string.

    The implementation uses ``value`` and ``field`` to require nonempty string.
    Every required invariant is checked before a successful value is returned;
    invalid input follows the function's explicit exception path.

    Args:
        value: Value object whose ``strip`` state is read while performing
            nonempty string.
        field: Text supplied as field in the format accepted by this function.

    Returns:
        The validated ``value``.

    Raises:
        PlatformDetectionProfileError: If the
            ``platform_detection_profile_key``.``field`` is not a non-empty
            string without outer whitespace.
    """
    if not isinstance(value, str) or not value or value != value.strip():
        raise PlatformDetectionProfileError(
            f"{PLATFORM_DETECTION_PROFILE_KEY}.{field} must be a non-empty "
            "string without outer whitespace"
        )
    return value


def _require_score(value: Any, field: str) -> int:
    """
    Require score.

    The implementation uses ``value`` and ``field`` to require score. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        value: Value evaluated while performing score.
        field: Text supplied as field in the format accepted by this function.

    Returns:
        The validated ``value``.

    Raises:
        PlatformDetectionProfileError: If the
            ``platform_detection_profile_key``.``field`` is not a non-negative
            integer.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PlatformDetectionProfileError(
            f"{PLATFORM_DETECTION_PROFILE_KEY}.{field} must be a non-negative integer"
        )
    return value


def _require_shared_regex(pattern: str, field: str) -> None:
    """
    Require the conservative regex subset shared by Python and POSIX ERE.

    The implementation uses ``pattern`` and ``field`` to require the
    conservative regex subset shared by Python and POSIX ERE. Every required
    invariant is checked before a successful value is returned; invalid input
    follows the function's explicit exception path.

    Args:
        pattern: Text supplied as pattern in the format accepted by this
            function.
        field: Text supplied as field in the format accepted by this function.

    Raises:
        PlatformDetectionProfileError: If the
            ``platform_detection_profile_key``.``field`` is not anchored with ^
            and $; or ``PLATFORM_DETECTION_PROFILE_KEY``.``field`` uses regex
            syntax that is not portable between Python and POSIX ERE.
    """

    if not pattern.startswith("^") or not pattern.endswith("$"):
        raise PlatformDetectionProfileError(
            f"{PLATFORM_DETECTION_PROFILE_KEY}.{field} must be anchored with ^ and $"
        )
    if re.search(r"\(\?|\[\[:|\\(?:[1-9AbBdDsSwWZ])", pattern):
        raise PlatformDetectionProfileError(
            f"{PLATFORM_DETECTION_PROFILE_KEY}.{field} uses regex syntax that "
            "is not portable between Python and POSIX ERE"
        )


def _is_redfish_path(value: str) -> bool:
    """
    Return whether ``value`` is Redfish path.

    After applying local validation, the function forwards ``value`` to ``bool``
    and preserves its return and exception contract.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        Whether ``value`` is Redfish path.
    """
    return bool(re.fullmatch(r"/redfish/v1(?:/[A-Za-z0-9._~-]+)*", value))


def validate_platform_detection_profile(value: Any) -> Dict[str, Any]:
    """
    Validate and copy the catalog's ordered platform-detection profile.

    The implementation uses ``value`` to validate and copy the catalog's ordered
    platform-detection profile. Every required invariant is checked before a
    successful value is returned; invalid input follows the function's explicit
    exception path.

    Args:
        value: Value object whose ``get`` state is read while performing and
            copy the catalog's ordered platform-detection profile.

    Returns:
        The validated ``profile``.

    Raises:
        PlatformDetectionProfileError: If the ``platform_detection_profile_key``
            is not a JSON object; the function cannot validate and copy the
            catalog's ordered platform-detection profile safely; the
            ``platform_detection_profile_key``.version is not
            ``PLATFORM_DETECTION_PROFILE_VERSION``; or the
            ``platform_detection_profile_key``.signal_score_adjustments are not
            an object; or another input invariant is violated.
    """

    if not isinstance(value, dict):
        raise PlatformDetectionProfileError(
            f"{PLATFORM_DETECTION_PROFILE_KEY} must be a JSON object"
        )
    allowed_keys = {
        "version",
        "conclusive_score",
        "signal_score_adjustments",
        "uri_score_rules",
        "probe_steps",
    }
    unknown_keys = set(value) - allowed_keys
    if unknown_keys:
        raise PlatformDetectionProfileError(
            f"{PLATFORM_DETECTION_PROFILE_KEY} has unsupported keys: "
            + ", ".join(sorted(str(key) for key in unknown_keys))
        )
    if value.get("version") != PLATFORM_DETECTION_PROFILE_VERSION:
        raise PlatformDetectionProfileError(
            f"{PLATFORM_DETECTION_PROFILE_KEY}.version must be "
            f"{PLATFORM_DETECTION_PROFILE_VERSION}"
        )

    conclusive_score = value.get("conclusive_score")
    if conclusive_score is not None:
        conclusive_score = _require_score(conclusive_score, "conclusive_score")

    raw_adjustments = value.get("signal_score_adjustments", {})
    if not isinstance(raw_adjustments, dict):
        raise PlatformDetectionProfileError(
            f"{PLATFORM_DETECTION_PROFILE_KEY}.signal_score_adjustments must be an object"
        )
    adjustments: Dict[str, int] = {}
    for signal, adjustment in raw_adjustments.items():
        signal_name = _require_nonempty_string(
            signal, "signal_score_adjustments signal"
        )
        if signal_name not in _SUPPORTED_SIGNALS:
            raise PlatformDetectionProfileError(
                f"{PLATFORM_DETECTION_PROFILE_KEY}.signal_score_adjustments "
                f"has unsupported signal {signal_name!r}"
            )
        if isinstance(adjustment, bool) or not isinstance(adjustment, int):
            raise PlatformDetectionProfileError(
                f"{PLATFORM_DETECTION_PROFILE_KEY}.signal_score_adjustments"
                f"[{signal_name!r}] must be an integer"
            )
        adjustments[signal_name] = adjustment

    raw_rules = value.get("uri_score_rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise PlatformDetectionProfileError(
            f"{PLATFORM_DETECTION_PROFILE_KEY}.uri_score_rules must be a non-empty list"
        )
    rules: List[Dict[str, Any]] = []
    seen_patterns = set()
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict) or set(raw_rule) != {
            "pattern",
            "score",
        }:
            raise PlatformDetectionProfileError(
                f"{PLATFORM_DETECTION_PROFILE_KEY}.uri_score_rules[{index}] must "
                "contain only pattern and score"
            )
        pattern = _require_nonempty_string(
            raw_rule.get("pattern"), f"uri_score_rules[{index}].pattern"
        )
        if pattern in seen_patterns:
            raise PlatformDetectionProfileError(
                f"{PLATFORM_DETECTION_PROFILE_KEY}.uri_score_rules contains "
                f"duplicate pattern {pattern!r}"
            )
        try:
            re.compile(pattern)
        except re.error as error:
            raise PlatformDetectionProfileError(
                f"{PLATFORM_DETECTION_PROFILE_KEY}.uri_score_rules[{index}] "
                f"contains invalid regex: {error}"
            ) from error
        _require_shared_regex(pattern, f"uri_score_rules[{index}].pattern")
        seen_patterns.add(pattern)
        rules.append(
            {
                "pattern": pattern,
                "score": _require_score(
                    raw_rule.get("score"), f"uri_score_rules[{index}].score"
                ),
            }
        )

    raw_steps = value.get("probe_steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise PlatformDetectionProfileError(
            f"{PLATFORM_DETECTION_PROFILE_KEY}.probe_steps must be a non-empty list"
        )
    steps: List[Dict[str, Any]] = []
    for index, raw_step in enumerate(raw_steps):
        if not isinstance(raw_step, dict):
            raise PlatformDetectionProfileError(
                f"{PLATFORM_DETECTION_PROFILE_KEY}.probe_steps[{index}] must be an object"
            )
        is_direct = "uri" in raw_step
        is_collection = "collection_uri" in raw_step
        if is_direct == is_collection:
            raise PlatformDetectionProfileError(
                f"{PLATFORM_DETECTION_PROFILE_KEY}.probe_steps[{index}] must define "
                "exactly one of uri or collection_uri"
            )
        common_keys = {
            "max_score",
            "model_field",
            "manufacturer_field",
            "part_number_field",
        }
        expected_keys = (
            common_keys | {"uri"}
            if is_direct
            else common_keys | {"collection_uri", "member_uri_prefix"}
        )
        unknown_step_keys = set(raw_step) - expected_keys
        if unknown_step_keys:
            raise PlatformDetectionProfileError(
                f"{PLATFORM_DETECTION_PROFILE_KEY}.probe_steps[{index}] has "
                "unsupported keys: "
                + ", ".join(sorted(str(key) for key in unknown_step_keys))
            )

        step: Dict[str, Any] = {
            "max_score": _require_score(
                raw_step.get("max_score"), f"probe_steps[{index}].max_score"
            ),
            "model_field": _require_nonempty_string(
                raw_step.get("model_field", "Model"),
                f"probe_steps[{index}].model_field",
            ),
            "manufacturer_field": _require_nonempty_string(
                raw_step.get("manufacturer_field", "Manufacturer"),
                f"probe_steps[{index}].manufacturer_field",
            ),
            "part_number_field": _require_nonempty_string(
                raw_step.get("part_number_field", "PartNumber"),
                f"probe_steps[{index}].part_number_field",
            ),
        }
        if is_direct:
            uri = _require_nonempty_string(
                raw_step.get("uri"), f"probe_steps[{index}].uri"
            )
            if not _is_redfish_path(uri):
                raise PlatformDetectionProfileError(
                    f"{PLATFORM_DETECTION_PROFILE_KEY}.probe_steps[{index}].uri "
                    "must stay below /redfish/v1"
                )
            step["uri"] = uri
        else:
            collection_uri = _require_nonempty_string(
                raw_step.get("collection_uri"),
                f"probe_steps[{index}].collection_uri",
            )
            member_uri_prefix = _require_nonempty_string(
                raw_step.get("member_uri_prefix"),
                f"probe_steps[{index}].member_uri_prefix",
            )
            if (
                not _is_redfish_path(collection_uri)
                or member_uri_prefix != collection_uri.rstrip("/") + "/"
            ):
                raise PlatformDetectionProfileError(
                    f"{PLATFORM_DETECTION_PROFILE_KEY}.probe_steps[{index}] "
                    "collection paths must stay below /redfish/v1 and use its "
                    "direct-child prefix"
                )
            step["collection_uri"] = collection_uri
            step["member_uri_prefix"] = member_uri_prefix
        steps.append(step)

    profile = {
        "version": PLATFORM_DETECTION_PROFILE_VERSION,
        "signal_score_adjustments": adjustments,
        "uri_score_rules": rules,
        "probe_steps": steps,
    }
    if conclusive_score is not None:
        profile["conclusive_score"] = conclusive_score
        highest_possible_score = max(rule["score"] for rule in rules) + max(
            [0, *adjustments.values()]
        )
        if conclusive_score > highest_possible_score:
            raise PlatformDetectionProfileError(
                f"{PLATFORM_DETECTION_PROFILE_KEY}.conclusive_score cannot exceed "
                f"the highest possible score ({highest_possible_score})"
            )
    signals = ["model", *adjustments]
    for index, step in enumerate(steps):
        uri = step.get("uri")
        if uri:
            possible_scores = [
                score_platform_detection_candidate(profile, uri, signal)
                for signal in signals
            ]
            possible_scores = [score for score in possible_scores if score is not None]
            if not possible_scores:
                raise PlatformDetectionProfileError(
                    f"{PLATFORM_DETECTION_PROFILE_KEY}.probe_steps[{index}].uri "
                    "does not match any uri_score_rules pattern"
                )
            required_max = max(possible_scores)
            target_description = uri
        else:
            member_uri_prefix = step["member_uri_prefix"]
            reachable_scores = _collection_rule_scores(rules, member_uri_prefix)
            if not reachable_scores:
                raise PlatformDetectionProfileError(
                    f"{PLATFORM_DETECTION_PROFILE_KEY}.probe_steps[{index}] "
                    "collection members do not match any uri_score_rules pattern"
                )
            required_max = max(
                0,
                max(reachable_scores) + max([0, *adjustments.values()]),
            )
            target_description = member_uri_prefix + "<member>"
        if step["max_score"] < required_max:
            raise PlatformDetectionProfileError(
                f"{PLATFORM_DETECTION_PROFILE_KEY}.probe_steps[{index}].max_score "
                f"must be at least {required_max} for {target_description}"
            )

    return profile


def score_platform_detection_candidate(
    profile: Optional[Dict[str, Any]], uri: str, signal: str
) -> Optional[int]:
    """
    Return the first ordered URI-rule score plus its signal adjustment.

    After applying local validation, the function forwards ``profile``, ``uri``,
    and ``signal`` to ``max`` and preserves its return and exception contract.

    Args:
        profile: Mapping supplying fields for first ordered URI-rule score plus
            its signal adjustment.
        uri: Validated remote resource identifier used for URI.
        signal: Text supplied as signal in the format accepted by this function.

    Returns:
        The numeric score platform detection candidate value, or ``None`` when
        the requested value is unavailable.
    """

    if not profile:
        return None
    for rule in profile["uri_score_rules"]:
        if re.fullmatch(rule["pattern"], uri):
            return max(
                0,
                rule["score"] + profile["signal_score_adjustments"].get(signal, 0),
            )
    return None


def remaining_probe_max_score(profile: Dict[str, Any], completed_index: int) -> int:
    """
    Return the largest possible score after the completed probe step.

    After applying local validation, the function forwards ``profile`` and
    ``completed_index`` to ``max`` and preserves its return and exception
    contract.

    Args:
        profile: Mapping supplying fields for largest possible score after the
            completed probe step.
        completed_index: Numeric completed index used by the operation's bounded
            accounting.

    Returns:
        The numeric remaining probe max score value.
    """

    return max(
        (step["max_score"] for step in profile["probe_steps"][completed_index + 1 :]),
        default=-1,
    )
