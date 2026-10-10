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
Strict, config-driven descriptors for diagnostic debug-capture targets.

This module deliberately has no RedfishService dependency. It defines the schema
and extraction semantics that a later runtime slice can consume without changing
the existing integer-ID discovery path in the meantime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from string import Formatter
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence, TypeAlias, cast

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ASCII_DECIMAL_RE = re.compile(r"^[0-9]+$")
_MAX_IDENTIFIER_LENGTH = 1024
_MAX_PATTERN_LENGTH = 2048
_MAX_RULES = 256

_DESCRIPTOR_FIELDS = frozenset(
    {
        "identifier",
        "device_id",
        "family",
        "source",
        "system_hints",
        "routing_hints",
    }
)
_RULE_FIELDS = frozenset(
    {
        "match",
        "identifier_template",
        "family",
        "system_hints",
        "routing_hints",
    }
)

RoutingHintValue: TypeAlias = str | tuple[str, ...]
LegacyDeviceId: TypeAlias = int


class DeviceDescriptorError(ValueError):
    """
    Base class for fail-closed descriptor validation errors.

    Callers receive this exception when the device descriptor error invariant
    prevents the requested operation from completing. The distinct type lets
    them handle that boundary without parsing an error message.
    """


class DeviceDescriptorSchemaError(DeviceDescriptorError):
    """
    Raised when descriptor configuration does not match the strict schema.

    Callers receive this exception when the device descriptor schema error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


class DeviceDescriptorSemanticError(DeviceDescriptorError):
    """
    Raised when valid-looking rules produce an ambiguous target identity.

    Callers receive this exception when the device descriptor semantic error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """


def _validate_text(value: Any, *, field_name: str, max_length: int) -> str:
    """
    Validate text.

    After applying local validation, the function forwards ``value``,
    ``field_name``, and ``max_length`` to ``cast`` and preserves its return and
    exception contract. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path.

    Args:
        value: Value evaluated while performing text.
        field_name: Field label included in validation failures for the selected
            input.
        max_length: Upper bound enforced for max length; the consuming boundary
            rejects or truncates values that exceed it.

    Returns:
        The canonical text.

    Raises:
        DeviceDescriptorSchemaError: If the ``field_name`` is not a non-empty
            string; ``field_name`` exceeds the ``max_length``-character limit;
            or ``field_name`` must not contain control characters.
    """
    if not isinstance(value, str) or not value:
        raise DeviceDescriptorSchemaError(f"{field_name} must be a non-empty string")
    if len(value) > max_length:
        raise DeviceDescriptorSchemaError(
            f"{field_name} exceeds the {max_length}-character limit"
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise DeviceDescriptorSchemaError(
            f"{field_name} must not contain control characters"
        )
    return cast(str, value)


def _validate_name(value: Any, *, field_name: str) -> str:
    """
    Validate name.

    The implementation uses ``value`` and ``field_name`` to validate name. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        value: Value evaluated while performing name.
        field_name: Field label included in validation failures for the selected
            input.

    Returns:
        The validated ``value``.

    Raises:
        DeviceDescriptorSchemaError: If the ``field_name`` is not a lowercase
            identifier.
    """
    value = _validate_text(value, field_name=field_name, max_length=64)
    if not _NAME_RE.fullmatch(value):
        raise DeviceDescriptorSchemaError(
            f"{field_name} must be a lowercase identifier"
        )
    return value


def _validate_exact_fields(
    raw: Mapping[str, Any],
    *,
    field_name: str,
    allowed: frozenset[str],
    required: frozenset[str],
) -> None:
    """
    Validate exact fields.

    The implementation uses ``raw``, ``field_name``, ``allowed``, and
    ``required`` to validate exact fields. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        raw: Mapping supplying fields for exact fields.
        field_name: Field label included in validation failures for the selected
            input.
        allowed: Entries supplied as ``allowed`` without transferring container
            ownership.
        required: Entries supplied as ``required`` without transferring
            container ownership.

    Raises:
        DeviceDescriptorSchemaError: If input or state violates constraints
            required to validate exact fields.
    """
    unknown = sorted((key for key in raw if key not in allowed), key=repr)
    missing = sorted(required - set(raw))
    if unknown:
        raise DeviceDescriptorSchemaError(
            f"{field_name} has unsupported field(s): "
            + ", ".join(repr(key) for key in unknown)
        )
    if missing:
        raise DeviceDescriptorSchemaError(
            f"{field_name} is missing required field(s): {', '.join(missing)}"
        )


def _validate_string_sequence(
    value: Any,
    *,
    field_name: str,
) -> tuple[str, ...]:
    """
    Validate string sequence.

    The implementation uses ``value`` and ``field_name`` to validate string
    sequence. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        value: Entries supplied as ``value`` and processed in caller-provided
            order.
        field_name: Field label included in validation failures for the selected
            input.

    Returns:
        The string sequence returned in operation-defined order.

    Raises:
        DeviceDescriptorSchemaError: If the ``field_name`` is not a list of
            strings; or ``field_name`` must not contain duplicates.
    """
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise DeviceDescriptorSchemaError(f"{field_name} must be a list of strings")
    normalized: list[str] = []
    for index, item in enumerate(value):
        normalized.append(
            _validate_text(
                item,
                field_name=f"{field_name}[{index}]",
                max_length=256,
            )
        )
    if len(set(normalized)) != len(normalized):
        raise DeviceDescriptorSchemaError(f"{field_name} must not contain duplicates")
    return tuple(normalized)


def _validate_routing_hints(
    value: Any,
    *,
    field_name: str,
) -> Mapping[str, RoutingHintValue]:
    """
    Validate routing hints.

    The implementation uses ``value`` and ``field_name`` to validate routing
    hints. Every required invariant is checked before a successful value is
    returned; invalid input follows the function's explicit exception path.

    Args:
        value: Value object whose ``items`` state is read while performing
            routing hints.
        field_name: Field label included in validation failures for the selected
            input.

    Returns:
        A mapping containing routing hints.

    Raises:
        DeviceDescriptorSchemaError: If the ``field_name`` is not a mapping; or
            ``field_name``.``key`` must not be empty.
    """
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, Mapping):
        raise DeviceDescriptorSchemaError(f"{field_name} must be a mapping")

    normalized: dict[str, RoutingHintValue] = {}
    for raw_key, raw_value in value.items():
        key = _validate_name(raw_key, field_name=f"{field_name} key")
        if isinstance(raw_value, str):
            normalized[key] = _validate_text(
                raw_value,
                field_name=f"{field_name}.{key}",
                max_length=256,
            )
            continue
        normalized[key] = _validate_string_sequence(
            raw_value,
            field_name=f"{field_name}.{key}",
        )
        if not normalized[key]:
            raise DeviceDescriptorSchemaError(f"{field_name}.{key} must not be empty")
    return MappingProxyType(normalized)


def _copy_routing_hints(
    value: Mapping[str, RoutingHintValue],
) -> dict[str, str | list[str]]:
    """
    Copy routing hints.

    The implementation uses ``value`` to copy routing hints.

    Args:
        value: Mapping supplying fields for copy routing hints.

    Returns:
        A mapping containing copy routing hints.
    """
    return {
        key: list(item) if isinstance(item, tuple) else item
        for key, item in value.items()
    }


@dataclass(frozen=True, slots=True)
class DeviceDescriptor:
    """
    One stable, identity-preserving diagnostic capture target.

    The immutable record keeps ``identifier``, ``device_id``, ``family``,
    ``source``, and ``system_hints`` together so consumers observe one device
    descriptor state. Construction validates cross-field invariants before the
    instance is exposed.

    Attributes:
        identifier: Canonical text used as identifier.
        device_id: Canonical text used as device identifier.
        family: Canonical text used as family.
        source: Canonical text used as source.
        system_hints: Collection of system hints entries retained by this
            record.
        routing_hints: Mapping that retains the routing hints fields for this
            record.
    """

    identifier: str
    device_id: int | str
    family: str
    source: str
    system_hints: Sequence[str] = ()
    routing_hints: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized DeviceDescriptor state.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Raises:
            DeviceDescriptorSchemaError: If the descriptor.device_id is not an
                integer or non-empty string.
        """
        object.__setattr__(
            self,
            "identifier",
            _validate_text(
                self.identifier,
                field_name="descriptor.identifier",
                max_length=_MAX_IDENTIFIER_LENGTH,
            ),
        )
        if isinstance(self.device_id, bool) or not isinstance(
            self.device_id, (int, str)
        ):
            raise DeviceDescriptorSchemaError(
                "descriptor.device_id must be an integer or non-empty string"
            )
        if isinstance(self.device_id, str):
            object.__setattr__(
                self,
                "device_id",
                _validate_text(
                    self.device_id,
                    field_name="descriptor.device_id",
                    max_length=_MAX_IDENTIFIER_LENGTH,
                ),
            )
        object.__setattr__(
            self,
            "family",
            _validate_name(self.family, field_name="descriptor.family"),
        )
        object.__setattr__(
            self,
            "source",
            _validate_name(self.source, field_name="descriptor.source"),
        )
        object.__setattr__(
            self,
            "system_hints",
            _validate_string_sequence(
                self.system_hints,
                field_name="descriptor.system_hints",
            ),
        )
        object.__setattr__(
            self,
            "routing_hints",
            _validate_routing_hints(
                self.routing_hints,
                field_name="descriptor.routing_hints",
            ),
        )

    @classmethod
    def from_mapping(cls, raw: Any) -> "DeviceDescriptor":
        """
        Build a DeviceDescriptor from mapping.

        After applying local validation, the function forwards ``raw`` to
        ``cls`` and preserves its return and exception contract.

        Args:
            raw: Raw consumed while the function attempts to build a
                DeviceDescriptor from mapping.

        Returns:
            A ``DeviceDescriptor`` initialized from mapping.

        Raises:
            DeviceDescriptorSchemaError: If the descriptor is not a mapping.
        """
        if not isinstance(raw, Mapping):
            raise DeviceDescriptorSchemaError("descriptor must be a mapping")
        _validate_exact_fields(
            raw,
            field_name="descriptor",
            allowed=_DESCRIPTOR_FIELDS,
            required=_DESCRIPTOR_FIELDS,
        )
        return cls(**dict(raw))

    def as_dict(self) -> dict[str, Any]:
        """
        Return the exact plain mapping expected by collector context.

        The implementation uses current instance state to produce the exact
        plain mapping expected by collector context.

        Returns:
            A mapping containing the ``identifier``, ``device_id``, ``family``,
            ``source``, and ``system_hints`` fields.
        """

        return {
            "identifier": self.identifier,
            "device_id": self.device_id,
            "family": self.family,
            "source": self.source,
            "system_hints": list(self.system_hints),
            "routing_hints": _copy_routing_hints(self.routing_hints),
        }


DeviceTarget: TypeAlias = LegacyDeviceId | DeviceDescriptor


@dataclass(frozen=True, slots=True)
class DeviceDescriptorRule:
    """
    One compiled, config-defined descriptor extraction rule.

    The immutable record keeps ``match``, ``family``, ``identifier_template``,
    ``system_hints``, and ``routing_hints`` together so consumers observe one
    device descriptor rule state. Construction validates cross-field invariants
    before the instance is exposed.

    Attributes:
        match: Canonical text used as match.
        family: Canonical text used as family.
        identifier_template: Canonical text used as identifier template.
        system_hints: Collection of system hints entries retained by this
            record.
        routing_hints: Mapping that retains the routing hints fields for this
            record.
    """

    match: str
    family: str
    identifier_template: str = "{source_identifier}"
    system_hints: Sequence[str] = ()
    routing_hints: Mapping[str, Any] = field(default_factory=dict)
    _pattern: re.Pattern[str] = field(init=False, repr=False, compare=False)
    _template_fields: frozenset[str] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        """
        Validate and finalize the initialized DeviceDescriptorRule state.

        The hook checks cross-field invariants after generated initialization
        and rejects inconsistent state before the instance becomes visible to
        callers. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Raises:
            DeviceDescriptorSchemaError: If descriptor rule match is not valid
                regex: ``error``; descriptor rule identifier_template is
                invalid: ``error``; descriptor rule identifier_template has
                unsupported field ``field_name``; or descriptor rule
                identifier_template does not allow formatting or conversion.
        """
        match = _validate_text(
            self.match,
            field_name="descriptor rule match",
            max_length=_MAX_PATTERN_LENGTH,
        )
        try:
            pattern = re.compile(match)
        except re.error as error:
            raise DeviceDescriptorSchemaError(
                f"descriptor rule match is not valid regex: {error}"
            ) from error

        template = _validate_text(
            self.identifier_template,
            field_name="descriptor rule identifier_template",
            max_length=_MAX_IDENTIFIER_LENGTH,
        )
        allowed_fields = {
            "device_id",
            "device_type",
            "family",
            "source",
            "source_identifier",
            *(f"group{number}" for number in range(1, pattern.groups + 1)),
        }
        template_fields: set[str] = set()
        try:
            parsed_template = tuple(Formatter().parse(template))
        except ValueError as error:
            raise DeviceDescriptorSchemaError(
                f"descriptor rule identifier_template is invalid: {error}"
            ) from error
        for _, field_name, format_spec, conversion in parsed_template:
            if field_name is None:
                continue
            if not field_name or field_name not in allowed_fields:
                raise DeviceDescriptorSchemaError(
                    "descriptor rule identifier_template has unsupported field "
                    f"{field_name!r}"
                )
            if format_spec or conversion:
                raise DeviceDescriptorSchemaError(
                    "descriptor rule identifier_template does not allow formatting "
                    "or conversion"
                )
            template_fields.add(field_name)

        object.__setattr__(self, "match", match)
        object.__setattr__(
            self,
            "family",
            _validate_name(self.family, field_name="descriptor rule family"),
        )
        object.__setattr__(self, "identifier_template", template)
        object.__setattr__(
            self,
            "system_hints",
            _validate_string_sequence(
                self.system_hints,
                field_name="descriptor rule system_hints",
            ),
        )
        object.__setattr__(
            self,
            "routing_hints",
            _validate_routing_hints(
                self.routing_hints,
                field_name="descriptor rule routing_hints",
            ),
        )
        object.__setattr__(self, "_pattern", pattern)
        object.__setattr__(self, "_template_fields", frozenset(template_fields))

    @classmethod
    def from_mapping(cls, raw: Any, *, index: int) -> "DeviceDescriptorRule":
        """
        Build a DeviceDescriptorRule from mapping.

        After applying local validation, the function forwards ``raw`` and
        ``index`` to ``cls`` and preserves its return and exception contract.

        Args:
            raw: Raw consumed while the function attempts to build a
                DeviceDescriptorRule from mapping.
            index: Zero-based position within the containing sequence.

        Returns:
            A ``DeviceDescriptorRule`` initialized from mapping.

        Raises:
            DeviceDescriptorSchemaError: If the ``field_name`` is not a mapping.
        """
        field_name = f"descriptor rule {index}"
        if not isinstance(raw, Mapping):
            raise DeviceDescriptorSchemaError(f"{field_name} must be a mapping")
        _validate_exact_fields(
            raw,
            field_name=field_name,
            allowed=_RULE_FIELDS,
            required=frozenset({"match", "family"}),
        )
        return cls(**dict(raw))

    def match_source(self, source_identifier: str) -> re.Match[str] | None:
        """
        Match one complete source identifier, never a coincidental prefix.

        After applying local validation, the function forwards
        ``source_identifier`` to ``self._pattern.fullmatch`` and preserves its
        return and exception contract.

        Args:
            source_identifier: Stable source identifier used to correlate
                configuration, logs, and results.

        Returns:
            The canonical match source text, or ``None`` when the requested
            value is unavailable.
        """

        return self._pattern.fullmatch(source_identifier)

    def describe(
        self,
        match: re.Match[str],
        *,
        device_type: str,
        source: str,
        source_identifier: str,
    ) -> DeviceDescriptor:
        """
        Return the describe.

        After applying local validation, the function forwards ``match``,
        ``device_type``, ``source``, and ``source_identifier`` to
        ``DeviceDescriptor`` and preserves its return and exception contract.

        Args:
            match: Text supplied as match in the format accepted by this
                function.
            device_type: Text supplied as device type in the format accepted by
                this function.
            source: Text supplied as source in the format accepted by this
                function.
            source_identifier: Stable source identifier used to correlate
                configuration, logs, and results.

        Returns:
            A ``DeviceDescriptor`` representing describe.

        Raises:
            DeviceDescriptorSemanticError: If ``source_identifier`` has an
                unmatched first capture group; or the function cannot produce
                the describe safely.
        """
        raw_device_id = match.group(1) if match.groups() else source_identifier
        if raw_device_id is None:
            raise DeviceDescriptorSemanticError(
                f"{source_identifier!r} has an unmatched first capture group"
            )
        device_id: int | str = (
            int(raw_device_id)
            if _ASCII_DECIMAL_RE.fullmatch(raw_device_id)
            else raw_device_id
        )
        groups = {
            f"group{number}": value for number, value in enumerate(match.groups(), 1)
        }
        missing_groups = sorted(
            field_name
            for field_name in self._template_fields
            if field_name.startswith("group") and groups[field_name] is None
        )
        if missing_groups:
            raise DeviceDescriptorSemanticError(
                f"{source_identifier!r} does not populate template field(s): "
                + ", ".join(missing_groups)
            )
        identifier = self.identifier_template.format_map(
            {
                "device_id": device_id,
                "device_type": device_type,
                "family": self.family,
                "source": source,
                "source_identifier": source_identifier,
                **groups,
            }
        )
        return DeviceDescriptor(
            identifier=identifier,
            device_id=device_id,
            family=self.family,
            source=source,
            system_hints=self.system_hints,
            routing_hints=self.routing_hints,
        )


class DeviceDescriptorRegistry:
    """
    Validated rules for one logical device type such as ``sma``.

    The type coordinates ``from_config``, ``extract``, and ``extract_mappings``
    and retains the state those operations share between calls. Resource
    ownership remains inside the instance until the matching close, exit, or
    cleanup operation completes.
    """

    def __init__(
        self,
        *,
        device_type: str,
        rules: Sequence[DeviceDescriptorRule],
    ) -> None:
        """
        Initialize a ``DeviceDescriptorRegistry`` instance.

        The initializer records ``device_type`` and ``rules`` for later
        operations and establishes the instance invariants before any public
        method runs. If the function cannot initialize a
        ``DeviceDescriptorRegistry`` instance, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            device_type: Text supplied as device type in the format accepted by
                this function.
            rules: Entries supplied as ``rules`` without transferring container
                ownership.

        Raises:
            DeviceDescriptorSchemaError: If the descriptor registry rules are
                not a non-empty list; descriptor registry cannot exceed
                ``_MAX_RULES`` rules; descriptor registry rules must contain
                DeviceDescriptorRule values; or input or state violates
                constraints required to initialize a
                ``DeviceDescriptorRegistry`` instance.
        """
        self.device_type = _validate_name(
            device_type,
            field_name="descriptor registry device_type",
        )
        if not isinstance(rules, (list, tuple)) or not rules:
            raise DeviceDescriptorSchemaError(
                "descriptor registry rules must be a non-empty list"
            )
        if len(rules) > _MAX_RULES:
            raise DeviceDescriptorSchemaError(
                f"descriptor registry cannot exceed {_MAX_RULES} rules"
            )
        if not all(isinstance(rule, DeviceDescriptorRule) for rule in rules):
            raise DeviceDescriptorSchemaError(
                "descriptor registry rules must contain DeviceDescriptorRule values"
            )
        duplicate_matches = sorted(
            pattern
            for pattern in {rule.match for rule in rules}
            if sum(rule.match == pattern for rule in rules) > 1
        )
        if duplicate_matches:
            raise DeviceDescriptorSchemaError(
                "descriptor registry has duplicate match rule(s): "
                + ", ".join(duplicate_matches)
            )
        self.rules = tuple(rules)

    @classmethod
    def from_config(
        cls,
        *,
        device_type: str,
        config: Any,
    ) -> "DeviceDescriptorRegistry":
        """
        Build a DeviceDescriptorRegistry from config.

        After applying local validation, the function forwards ``device_type``
        and ``config`` to ``cls`` and preserves its return and exception
        contract.

        Args:
            device_type: Text supplied as device type in the format accepted by
                this function.
            config: Config governing deviceDescriptorRegistry from config.

        Returns:
            The canonical from config text.

        Raises:
            DeviceDescriptorSchemaError: If the descriptor registry config is
                not a mapping; or the descriptor registry descriptors are not a
                list.
        """
        if not isinstance(config, Mapping):
            raise DeviceDescriptorSchemaError(
                "descriptor registry config must be a mapping"
            )
        _validate_exact_fields(
            config,
            field_name="descriptor registry config",
            allowed=frozenset({"descriptors"}),
            required=frozenset({"descriptors"}),
        )
        raw_rules = config["descriptors"]
        if not isinstance(raw_rules, list):
            raise DeviceDescriptorSchemaError(
                "descriptor registry descriptors must be a list"
            )
        return cls(
            device_type=device_type,
            rules=[
                DeviceDescriptorRule.from_mapping(raw, index=index)
                for index, raw in enumerate(raw_rules)
            ],
        )

    def extract(
        self,
        source_identifiers: Iterable[str],
        *,
        source: str,
    ) -> tuple[DeviceDescriptor, ...]:
        """
        Extract descriptors deterministically and reject ambiguous identity.

        After applying local validation, the function forwards
        ``source_identifiers`` and ``source`` to ``tuple`` and preserves its
        return and exception contract.

        Args:
            source_identifiers: Entries supplied as ``source_identifiers``
                without transferring container ownership.
            source: Text supplied as source in the format accepted by this
                function.

        Returns:
            Descriptors matched to unique source identities, in deterministic
            source order.

        Raises:
            DeviceDescriptorSchemaError: If the descriptor source identifiers
                are not an iterable of strings.
            DeviceDescriptorSemanticError: If the function cannot extract
                descriptors deterministically and reject ambiguous identity
                safely; or ``previous_source`` and ``source_identifier`` both
                map to descriptor identity ``identity``.
        """

        source = _validate_name(source, field_name="descriptor source")
        if isinstance(source_identifiers, (str, bytes, Mapping)):
            raise DeviceDescriptorSchemaError(
                "descriptor source identifiers must be an iterable of strings"
            )
        try:
            source_iterator = iter(source_identifiers)
        except TypeError as error:
            raise DeviceDescriptorSchemaError(
                "descriptor source identifiers must be an iterable of strings"
            ) from error

        descriptors: list[DeviceDescriptor] = []
        identity_sources: dict[tuple[str, str], str] = {}
        seen_sources: set[str] = set()
        for raw_identifier in source_iterator:
            source_identifier = _validate_text(
                raw_identifier,
                field_name="descriptor source identifier",
                max_length=_MAX_IDENTIFIER_LENGTH,
            )
            if source_identifier in seen_sources:
                continue
            seen_sources.add(source_identifier)

            matches = [
                (index, rule, match)
                for index, rule in enumerate(self.rules)
                if (match := rule.match_source(source_identifier)) is not None
            ]
            if len(matches) > 1:
                raise DeviceDescriptorSemanticError(
                    f"{source_identifier!r} matches multiple descriptor rules: "
                    + ", ".join(str(index) for index, _, _ in matches)
                )
            if not matches:
                continue

            _, rule, match = matches[0]
            descriptor = rule.describe(
                match,
                device_type=self.device_type,
                source=source,
                source_identifier=source_identifier,
            )
            identity = (descriptor.identifier, descriptor.family)
            previous_source = identity_sources.get(identity)
            if previous_source is not None and previous_source != source_identifier:
                raise DeviceDescriptorSemanticError(
                    f"{previous_source!r} and {source_identifier!r} both map to "
                    f"descriptor identity {identity!r}"
                )
            if previous_source is None:
                descriptors.append(descriptor)
                identity_sources[identity] = source_identifier

        descriptors.sort(
            key=lambda descriptor: (
                descriptor.identifier,
                descriptor.family,
                descriptor.source,
            )
        )
        return tuple(descriptors)

    def extract_mappings(
        self,
        source_identifiers: Iterable[str],
        *,
        source: str,
    ) -> list[dict[str, Any]]:
        """
        Extract plain context mappings for a future runtime integration.

        The implementation uses ``source_identifiers`` and ``source`` to extract
        plain context mappings for a future runtime integration.

        Args:
            source_identifiers: Entries supplied as ``source_identifiers``
                without transferring container ownership.
            source: Text supplied as source in the format accepted by this
                function.

        Returns:
            The mappings returned in operation-defined order.
        """

        return [
            descriptor.as_dict()
            for descriptor in self.extract(source_identifiers, source=source)
        ]


def validate_device_targets(raw_targets: Any) -> tuple[DeviceTarget, ...]:
    """
    Validate one logical target list without breaking legacy integer IDs.

    A target list is either the unchanged legacy integer form or the strict
    descriptor form. Mixing both representations is rejected because it would
    make downstream routing and result accounting ambiguous.

    Args:
        raw_targets: Entries supplied as ``raw_targets`` and processed in
            caller-provided order.

    Returns:
        The device targets returned in operation-defined order.

    Raises:
        DeviceDescriptorSchemaError: If the device targets are not a list; or
            the device target ``index`` is not a legacy integer or descriptor
            mapping.
        DeviceDescriptorSemanticError: If device targets must not mix legacy
            integers and descriptors.
    """

    if not isinstance(raw_targets, (list, tuple)):
        raise DeviceDescriptorSchemaError("device targets must be a list")
    targets: list[DeviceTarget] = []
    modes: set[str] = set()
    for index, raw_target in enumerate(raw_targets):
        if isinstance(raw_target, int) and not isinstance(raw_target, bool):
            targets.append(raw_target)
            modes.add("legacy")
            continue
        if isinstance(raw_target, DeviceDescriptor):
            targets.append(raw_target)
            modes.add("descriptor")
            continue
        if isinstance(raw_target, Mapping):
            targets.append(DeviceDescriptor.from_mapping(raw_target))
            modes.add("descriptor")
            continue
        raise DeviceDescriptorSchemaError(
            f"device target {index} must be a legacy integer or descriptor mapping"
        )
    if len(modes) > 1:
        raise DeviceDescriptorSemanticError(
            "device targets must not mix legacy integers and descriptors"
        )
    return tuple(targets)


def merge_device_descriptor_groups(
    *groups: Iterable[DeviceDescriptor | Mapping[str, Any]],
) -> tuple[DeviceDescriptor, ...]:
    """
    Merge preferred-first discovery sources without losing identity.

    The first occurrence supplies provenance. A later occurrence with the same
    identifier/family is accepted only when every source-independent field
    agrees; otherwise discovery is ambiguous and fails closed.

    Args:
        groups: Additional positional values forwarded in caller-provided order.

    Returns:
        The merge device descriptor groups returned in operation-defined order.

    Raises:
        DeviceDescriptorSchemaError: If the descriptor group ``group_index`` is
            not an iterable of descriptors.
        DeviceDescriptorSemanticError: If descriptor identity ``identity`` has
            conflicting metadata between ``source`` and ``source``.
    """

    merged: dict[tuple[str, str], DeviceDescriptor] = {}
    for group_index, group in enumerate(groups):
        if isinstance(group, (str, bytes, Mapping)):
            raise DeviceDescriptorSchemaError(
                f"descriptor group {group_index} must be an iterable of descriptors"
            )
        try:
            iterator = iter(group)
        except TypeError as error:
            raise DeviceDescriptorSchemaError(
                f"descriptor group {group_index} must be an iterable of descriptors"
            ) from error
        for raw_descriptor in iterator:
            descriptor = (
                raw_descriptor
                if isinstance(raw_descriptor, DeviceDescriptor)
                else DeviceDescriptor.from_mapping(raw_descriptor)
            )
            identity = (descriptor.identifier, descriptor.family)
            previous = merged.get(identity)
            if previous is None:
                merged[identity] = descriptor
                continue
            if (
                previous.device_id != descriptor.device_id
                or previous.system_hints != descriptor.system_hints
                or previous.routing_hints != descriptor.routing_hints
            ):
                raise DeviceDescriptorSemanticError(
                    f"descriptor identity {identity!r} has conflicting metadata "
                    f"between {previous.source!r} and {descriptor.source!r}"
                )
    return tuple(
        sorted(
            merged.values(),
            key=lambda descriptor: (
                descriptor.identifier,
                descriptor.family,
                descriptor.source,
            ),
        )
    )


__all__ = [
    "DeviceDescriptor",
    "DeviceDescriptorError",
    "DeviceDescriptorRegistry",
    "DeviceDescriptorRule",
    "DeviceDescriptorSchemaError",
    "DeviceDescriptorSemanticError",
    "DeviceTarget",
    "LegacyDeviceId",
    "merge_device_descriptor_groups",
    "validate_device_targets",
]
