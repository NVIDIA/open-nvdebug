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
URI Configuration Manager.

Handles Redfish URI overrides at tool and DUT levels with support for custom
resource paths and system-specific configurations.
"""

import logging
import re
from collections.abc import Mapping
from pathlib import Path
from string import Formatter
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlsplit

from .enums import ResourceType
from .redfish_topology_profile import (
    REDFISH_TOPOLOGY_PROFILE_KEY,
    build_redfish_resource_uri_lookup,
    rebase_redfish_uri,
    select_redfish_credential_candidates,
    validate_redfish_topology_profile,
    validate_redfish_uri_path,
)

logger = logging.getLogger(__name__)

_TOOL_OVERRIDE_KEYS = {
    "prefix_override",
    "hmc_prefix_override",
    "hmc_resource_prefix",
    "default_uris",
    "baseboard_overrides",
    "platform_overrides",
    # Retained for compatibility with explicitly supplied URI configuration.
    # They are not a source of built-in routing policy.
    "uri_templates",
    "validation_patterns",
}
_DUT_PREFIX_KEYS = {"RF_DEFAULT_PREFIX", "RF_HMC_DEFAULT_PREFIX"}
_TEMPLATE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _load_uri_override_yaml(config_file) -> Any:
    """
    Load an override document with the project's duplicate-key guard.

    The implementation uses ``config_file`` to load an override document with
    the project's duplicate-key guard. Parsing or I/O must finish before the
    validated representation is made available to the caller.

    Args:
        config_file: filesystem location used as the config file for this
            operation.

    Returns:
        The URI override YAML value selected by the operation.
    """

    # Import lazily: tool.config imports the utils package during startup.
    from ..config import load_yaml_strict

    loaded = load_yaml_strict(config_file)
    return {} if loaded is None else loaded


def _validate_uri_template(value: Any, *, context: str) -> str:
    """
    Validate a URI template while retaining identifier placeholders.

    The implementation uses ``value`` and ``context`` to validate a URI template
    while retaining identifier placeholders. Every required invariant is checked
    before a successful value is returned; invalid input follows the function's
    explicit exception path.

    Args:
        value: Value evaluated while performing URI template while retaining
            identifier placeholders.
        context: Runtime context carrying state shared across this operation.

    Returns:
        The validated ``value``.

    Raises:
        ValueError: If the ``context`` is not a string; ``context`` contains
            malformed placeholders; or the ``context`` placeholders are not
            plain Python identifiers.
    """

    if not isinstance(value, str):
        raise ValueError(f"{context} must be a string")
    rendered_parts: List[str] = []
    try:
        parsed_parts = list(Formatter().parse(value))
    except ValueError as error:
        raise ValueError(f"{context} contains malformed placeholders") from error
    for literal, field_name, format_spec, conversion in parsed_parts:
        rendered_parts.append(literal)
        if field_name is None:
            continue
        if (
            not field_name
            or not _TEMPLATE_IDENTIFIER_PATTERN.fullmatch(field_name)
            or format_spec
            or conversion
        ):
            raise ValueError(f"{context} placeholders must be plain Python identifiers")
        rendered_parts.append("placeholder")
    validate_redfish_uri_path("".join(rendered_parts), context=context)
    return value


class URIConfigManager:
    """
    Manage URI config manager operations for the NVDebug runtime.

    The type coordinates ``_load_catalog_topology_profile``,
    ``_load_tool_uri_config``, ``_validate_resource_overrides``,
    ``_validate_scoped_overrides``, and ``_configure_tool_overrides`` and
    retains the state those operations share between calls. Resource ownership
    remains inside the instance until the matching close, exit, or cleanup
    operation completes.
    """

    def __init__(
        self,
        tool_uri_config_path: Optional[str] = None,
        *,
        topology_profile: Optional[Dict[str, Any]] = None,
        tool_uri_overrides: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize the URI configuration manager.

        Prefix values need separate source provenance. An explicit DUT value
        remains authoritative even when it equals the built-in default or is an
        empty/null clear; value-only checks cannot represent that.

        Args:
            tool_uri_config_path: Optional filesystem location used as the tool
                URI config path for this operation.
            topology_profile: Optional topology profile; ``None`` selects the
                function's default behavior.
            tool_uri_overrides: Validated remote resource identifier used for
                tool URI overrides.

        Raises:
            ValueError: If configure either a tool URI config file or inline
                overrides, not both.
        """
        self.tool_uri_config_path = tool_uri_config_path
        self.dut_uri_configs: Dict[str, Dict[str, Any]] = {}
        # Prefix values need separate source provenance. An explicit DUT value
        # remains authoritative even when it equals the built-in default or is
        # an empty/null clear; value-only checks cannot represent that.
        self.dut_explicit_prefixes: Dict[str, set[str]] = {}

        if topology_profile is None:
            topology_profile = self._load_catalog_topology_profile()
        self.topology_profile = validate_redfish_topology_profile(topology_profile)
        self.service_root = self.topology_profile["service_root"]
        self.catalog_uris = build_redfish_resource_uri_lookup(self.topology_profile)
        self.tool_uris: Dict[str, Any] = {
            "default_uris": dict(self.catalog_uris),
        }

        tool_config_file_supplied = tool_uri_config_path not in (None, "")
        tool_overrides_supplied = tool_uri_overrides is not None
        if tool_config_file_supplied and tool_overrides_supplied:
            raise ValueError(
                "Configure either a tool URI config file or inline overrides, not both"
            )
        if tool_config_file_supplied:
            self._load_tool_uri_config()
        elif tool_overrides_supplied:
            self._configure_tool_overrides(tool_uri_overrides)

    @staticmethod
    def _load_catalog_topology_profile() -> Dict[str, Any]:
        """
        Load the packaged catalog when a lightweight caller omits a profile.

        The implementation uses current instance state to load the packaged
        catalog when a lightweight caller omits a profile. Parsing or I/O must
        finish before the validated representation is made available to the
        caller. If the function cannot load the packaged catalog when a
        lightweight caller omits a profile, its exception reaches the caller
        instead of being converted into a successful result.

        Returns:
            The validated ``profile``.

        Raises:
            ValueError: If unable to initialize URI policy: no catalog contains
                ``REDFISH_TOPOLOGY_PROFILE_KEY``; or catalog is missing
                ``REDFISH_TOPOLOGY_PROFILE_KEY``.
        """

        from .catalog_global_profile import load_catalog_global_profile
        from .spreadsheet_utils import auto_detect_spreadsheet

        spreadsheet = auto_detect_spreadsheet(None, suppress_print=True)
        if not spreadsheet:
            raise ValueError(
                f"Unable to initialize URI policy: no catalog contains "
                f"{REDFISH_TOPOLOGY_PROFILE_KEY}"
            )
        profile = load_catalog_global_profile(
            spreadsheet,
            REDFISH_TOPOLOGY_PROFILE_KEY,
            validate_redfish_topology_profile,
        )
        if profile is None:  # Required loader; keeps the type checker honest.
            raise ValueError(f"Catalog is missing {REDFISH_TOPOLOGY_PROFILE_KEY}")
        return profile

    def _load_tool_uri_config(self) -> None:
        """
        Load tool-level URI configuration from YAML file.

        Loads URI overrides from the tool-level configuration file.

        Raises:
            ValueError: If the tool uri configuration path is not a path string;
                or failed to load tool URI configuration '``config_path``':
                ``error``.
            FileNotFoundError: If tool URI configuration file not found:
                ``config_path``.
        """
        if not isinstance(self.tool_uri_config_path, (str, Path)):
            raise ValueError("Tool URI configuration path must be a path string")
        config_path = Path(self.tool_uri_config_path)
        if not config_path.exists():
            raise FileNotFoundError(
                f"Tool URI configuration file not found: {config_path}"
            )
        try:
            with open(config_path, "r", encoding="utf-8") as config_file:
                raw_config = _load_uri_override_yaml(config_file)
        except Exception as error:
            raise ValueError(
                f"Failed to load tool URI configuration '{config_path}': {error}"
            ) from error
        self._configure_tool_overrides(raw_config)
        logger.info("Loaded tool URI configuration from %s", config_path)

    def _validate_resource_overrides(
        self, value: Any, *, context: str
    ) -> Dict[str, str]:
        """
        Validate resource overrides.

        The implementation uses ``value`` and ``context`` to validate resource
        overrides. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Args:
            value: Value object whose ``items`` state is read while performing
                resource overrides.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            The validated ``normalized``.

        Raises:
            ValueError: If the ``context`` is not a mapping; or ``context``
                contains unknown resource ``raw_key``.
        """
        if not isinstance(value, Mapping):
            raise ValueError(f"{context} must be a mapping")
        normalized: Dict[str, str] = {}
        for raw_key, raw_uri in value.items():
            if not isinstance(raw_key, str) or raw_key not in self.catalog_uris:
                raise ValueError(f"{context} contains unknown resource {raw_key!r}")
            normalized[raw_key] = validate_redfish_uri_path(
                raw_uri, context=f"{context}.{raw_key}"
            )
        return normalized

    def _validate_scoped_overrides(
        self, value: Any, *, context: str
    ) -> Dict[str, Dict[str, str]]:
        """
        Validate scoped overrides.

        The implementation uses ``value`` and ``context`` to validate scoped
        overrides. Every required invariant is checked before a successful value
        is returned; invalid input follows the function's explicit exception
        path.

        Args:
            value: Value object whose ``items`` state is read while performing
                scoped overrides.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            The validated ``normalized``.

        Raises:
            ValueError: If the ``context`` is not a mapping; or ``context``
                contains an invalid selector.
        """
        if not isinstance(value, Mapping):
            raise ValueError(f"{context} must be a mapping")
        normalized: Dict[str, Dict[str, str]] = {}
        for raw_scope, raw_overrides in value.items():
            if (
                not isinstance(raw_scope, str)
                or not raw_scope
                or raw_scope != raw_scope.strip()
            ):
                raise ValueError(f"{context} contains an invalid selector")
            normalized[raw_scope] = self._validate_resource_overrides(
                raw_overrides, context=f"{context}.{raw_scope}"
            )
        return normalized

    def _configure_tool_overrides(self, value: Any) -> None:
        """
        Configure tool overrides.

        The implementation uses ``value`` to configure tool overrides. It
        updates ``tool_uris`` on the instance as part of that state transition.
        If the function cannot configure tool overrides, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            value: Mapping supplying fields for configure tool overrides.

        Raises:
            ValueError: If the tool uri overrides are not a mapping; the
                supplied input cannot be used to configure tool overrides; the
                uri_overrides.hmc_resource_prefix is not one path-segment
                prefix; or the uri_overrides.uri_templates are not a mapping; or
                another input invariant is violated.
        """
        if not isinstance(value, Mapping):
            raise ValueError("Tool URI overrides must be a mapping")
        unsupported = set(value) - _TOOL_OVERRIDE_KEYS
        if unsupported:
            raise ValueError(
                "Tool URI overrides contain unsupported keys: "
                + ", ".join(sorted(str(key) for key in unsupported))
            )

        normalized: Dict[str, Any] = {"default_uris": dict(self.catalog_uris)}
        for prefix_key in ("prefix_override", "hmc_prefix_override"):
            if prefix_key in value and value[prefix_key] not in (None, ""):
                normalized[prefix_key] = validate_redfish_uri_path(
                    value[prefix_key], context=f"uri_overrides.{prefix_key}"
                )
        if "hmc_resource_prefix" in value and value["hmc_resource_prefix"] not in (
            None,
            "",
        ):
            hmc_resource_prefix = value["hmc_resource_prefix"]
            if (
                not isinstance(hmc_resource_prefix, str)
                or hmc_resource_prefix != hmc_resource_prefix.strip()
                or len(hmc_resource_prefix) > 128
                or not re.fullmatch(r"[A-Za-z0-9_~-]+", hmc_resource_prefix)
                or hmc_resource_prefix in {".", ".."}
            ):
                raise ValueError(
                    "uri_overrides.hmc_resource_prefix must be one path-segment prefix"
                )
            normalized["hmc_resource_prefix"] = hmc_resource_prefix

        if "default_uris" in value:
            normalized["default_uris"].update(
                self._validate_resource_overrides(
                    value["default_uris"], context="uri_overrides.default_uris"
                )
            )
        for scoped_key in ("baseboard_overrides", "platform_overrides"):
            if scoped_key in value:
                normalized[scoped_key] = self._validate_scoped_overrides(
                    value[scoped_key], context=f"uri_overrides.{scoped_key}"
                )

        if "uri_templates" in value:
            templates = value["uri_templates"]
            if not isinstance(templates, Mapping):
                raise ValueError("uri_overrides.uri_templates must be a mapping")
            normalized_templates: Dict[str, str] = {}
            for key, template in templates.items():
                if (
                    not isinstance(key, str)
                    or not _TEMPLATE_IDENTIFIER_PATTERN.fullmatch(key)
                    or len(key) > 128
                ):
                    raise ValueError(
                        "uri_overrides.uri_templates contains an invalid name"
                    )
                normalized_templates[key] = _validate_uri_template(
                    template, context=f"uri_overrides.uri_templates.{key}"
                )
            normalized["uri_templates"] = normalized_templates
        if "validation_patterns" in value:
            patterns = value["validation_patterns"]
            if not isinstance(patterns, Mapping):
                raise ValueError("uri_overrides.validation_patterns must be a mapping")
            normalized_patterns: Dict[str, str] = {}
            for key, pattern in patterns.items():
                if (
                    not isinstance(key, str)
                    or not _TEMPLATE_IDENTIFIER_PATTERN.fullmatch(key)
                    or not isinstance(pattern, str)
                    or not pattern
                    or len(pattern) > 4096
                ):
                    raise ValueError(
                        "uri_overrides.validation_patterns must map strings to strings"
                    )
                try:
                    re.compile(pattern)
                except re.error as error:
                    raise ValueError(
                        f"uri_overrides.validation_patterns.{key} is invalid: {error}"
                    ) from error
                normalized_patterns[key] = pattern
            normalized["validation_patterns"] = normalized_patterns
        self.tool_uris = normalized

    def load_dut_uri_config(self, dut_id: str, dut_config: Dict[str, Any]) -> None:
        """
        Load DUT-specific URI configuration.

        The implementation uses ``dut_id`` and ``dut_config`` to load
        DUT-specific URI configuration. Parsing or I/O must finish before the
        validated representation is made available to the caller. Filesystem
        effects remain confined to the caller-selected paths and the owning
        resource lifecycle. If the function cannot load DUT-specific URI
        configuration, its exception reaches the caller instead of being
        converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            dut_config: DUT config governing DUT-specific URI configuration.

        Raises:
            ValueError: If the dut uri configuration for ``dut_id`` is not a
                mapping; DUT ``dut_id`` configures both uri_config_file and
                uri_overrides; the dut uri configuration path for ``dut_id`` is
                not a path string; or failed to load DUT URI configuration for
                ``dut_id``: ``error``; or another input invariant is violated.
            FileNotFoundError: If DUT URI configuration file not found:
                ``config_path``.
        """
        if not isinstance(dut_config, Mapping):
            raise ValueError(f"DUT URI configuration for {dut_id} must be a mapping")

        uri_config_file = dut_config.get("uri_config_file")
        inline_overrides = dut_config.get("uri_overrides")
        config_file_supplied = uri_config_file not in (None, "")
        inline_overrides_supplied = (
            "uri_overrides" in dut_config and inline_overrides is not None
        )
        if config_file_supplied and inline_overrides_supplied:
            raise ValueError(
                f"DUT {dut_id} configures both uri_config_file and uri_overrides"
            )
        if config_file_supplied:
            if not isinstance(uri_config_file, (str, Path)):
                raise ValueError(
                    f"DUT URI configuration path for {dut_id} must be a path string"
                )
            config_path = Path(uri_config_file)
            if not config_path.exists():
                raise FileNotFoundError(
                    f"DUT URI configuration file not found: {config_path}"
                )
            try:
                with open(config_path, "r", encoding="utf-8") as config_file:
                    raw_overrides = _load_uri_override_yaml(config_file)
            except Exception as error:
                raise ValueError(
                    f"Failed to load DUT URI configuration for {dut_id}: {error}"
                ) from error
            logger.info(
                "Loaded DUT URI configuration for %s from %s", dut_id, config_path
            )
        else:
            raw_overrides = {} if inline_overrides is None else inline_overrides
            if inline_overrides_supplied:
                logger.info("Loaded inline URI overrides for DUT %s", dut_id)

        if not isinstance(raw_overrides, Mapping):
            raise ValueError(f"DUT URI overrides for {dut_id} must be a mapping")
        unsupported = set(raw_overrides) - set(self.catalog_uris) - _DUT_PREFIX_KEYS
        if unsupported:
            raise ValueError(
                f"DUT URI overrides for {dut_id} contain unknown keys: "
                + ", ".join(sorted(str(key) for key in unsupported))
            )
        normalized_overrides = self._validate_resource_overrides(
            {
                key: value
                for key, value in raw_overrides.items()
                if key not in _DUT_PREFIX_KEYS
            },
            context=f"DUT URI overrides for {dut_id}",
        )
        for prefix_key in _DUT_PREFIX_KEYS:
            if prefix_key in raw_overrides:
                prefix_value = raw_overrides[prefix_key]
                normalized_overrides[prefix_key] = (
                    validate_redfish_uri_path(
                        prefix_value,
                        context=f"DUT URI overrides for {dut_id}.{prefix_key}",
                    )
                    if prefix_value not in (None, "")
                    else prefix_value
                )
        raw_explicit = dut_config.get("__explicit_fields")
        if isinstance(raw_explicit, dict):
            explicit_fields = {key for key, present in raw_explicit.items() if present}
        elif isinstance(raw_explicit, (list, tuple, set)):
            explicit_fields = set(raw_explicit)
        elif raw_explicit is None:
            explicit_fields = set(dut_config)
        else:
            explicit_fields = set()

        explicit_prefixes = {
            prefix_key for prefix_key in _DUT_PREFIX_KEYS if prefix_key in raw_overrides
        }
        for prefix_key in _DUT_PREFIX_KEYS:
            if prefix_key not in dut_config:
                continue
            if prefix_key in raw_overrides:
                if prefix_key in explicit_fields:
                    raise ValueError(
                        f"DUT {dut_id} configures {prefix_key} both at the top level "
                        "and in its URI overrides"
                    )
                # A model-populated top-level compatibility default must not
                # overwrite a prefix explicitly authored in an override file.
                continue
            prefix_value = dut_config[prefix_key]
            normalized_overrides[prefix_key] = (
                validate_redfish_uri_path(
                    prefix_value, context=f"DUT configuration {dut_id}.{prefix_key}"
                )
                if prefix_value not in (None, "")
                else prefix_value
            )
            if prefix_key in explicit_fields:
                explicit_prefixes.add(prefix_key)
            logger.debug(
                "Stored %s for DUT %s: %r (explicit=%s)",
                prefix_key,
                dut_id,
                dut_config[prefix_key],
                prefix_key in explicit_fields,
            )

        # Commit only after every field validates. A failed reload leaves the
        # previously valid DUT policy and its provenance internally consistent.
        self.dut_uri_configs[dut_id] = normalized_overrides
        if explicit_prefixes:
            self.dut_explicit_prefixes[dut_id] = explicit_prefixes
        else:
            self.dut_explicit_prefixes.pop(dut_id, None)

    def set_dut_prefix_explicit(
        self, dut_id: str, prefix_key: str, explicit: bool
    ) -> None:
        """
        Record whether a resolved prefix came from a DUT-scoped source.

        The implementation uses ``dut_id``, ``prefix_key``, and ``explicit`` to
        record whether a resolved prefix came from a DUT-scoped source. If the
        function cannot record whether a resolved prefix came from a DUT-scoped
        source, its exception reaches the caller instead of being converted into
        a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            prefix_key: Stable prefix key used for lookup and operator-facing
                diagnostics.
            explicit: Whether explicit is enabled or required for this
                operation.

        Raises:
            ValueError: If unsupported Redfish prefix key: ``prefix_key``.
        """
        if prefix_key not in {"RF_DEFAULT_PREFIX", "RF_HMC_DEFAULT_PREFIX"}:
            raise ValueError(f"Unsupported Redfish prefix key: {prefix_key}")
        explicit_prefixes = self.dut_explicit_prefixes.setdefault(dut_id, set())
        if explicit:
            explicit_prefixes.add(prefix_key)
        else:
            explicit_prefixes.discard(prefix_key)

    def _dut_prefix_is_explicit(self, dut_id: Optional[str], prefix_key: str) -> bool:
        """
        Return the DUT prefix is explicit.

        After applying local validation, the function forwards ``dut_id`` and
        ``prefix_key`` to ``bool`` and preserves its return and exception
        contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            prefix_key: Stable prefix key used for lookup and operator-facing
                diagnostics.

        Returns:
            Whether the DUT prefix is explicit operation succeeds.
        """
        return bool(
            dut_id and prefix_key in self.dut_explicit_prefixes.get(dut_id, set())
        )

    def is_dut_service_root_explicit(
        self, dut_id: Optional[str], *, hmc: bool = False
    ) -> bool:
        """
        Return whether the effective service root came from DUT-owned policy.

        After applying local validation, the function forwards ``dut_id`` and
        ``hmc`` to ``self._dut_prefix_is_explicit`` and preserves its return and
        exception contract.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether HMC is enabled or required for this operation.

        Returns:
            Whether the effective service root came from DUT-owned policy.
        """

        prefix_key = "RF_HMC_DEFAULT_PREFIX" if hmc else "RF_DEFAULT_PREFIX"
        return self._dut_prefix_is_explicit(dut_id, prefix_key)

    def get_service_root_provenance(
        self, dut_id: Optional[str] = None, *, hmc: bool = False
    ) -> str:
        """
        Return the authoritative source of the effective service root.

        The implementation uses ``dut_id`` and ``hmc`` to produce the
        authoritative source of the effective service root.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether HMC is enabled or required for this operation.

        Returns:
            The canonical service root provenance text.
        """

        if hmc:
            if self._dut_prefix_is_explicit(dut_id, "RF_HMC_DEFAULT_PREFIX"):
                return "dut_hmc"
            if self.tool_uris.get("hmc_prefix_override"):
                return "tool_hmc"
        if self._dut_prefix_is_explicit(dut_id, "RF_DEFAULT_PREFIX"):
            return "dut"
        if self.tool_uris.get("prefix_override"):
            return "tool"
        return "catalog"

    def get_explicit_dut_prefix_value(
        self, dut_id: Optional[str], *, hmc: bool = False
    ) -> Any:
        """
        Return the authored DUT prefix value, including an explicit clear.

        Callers must first confirm ``get_service_root_provenance`` reports the
        matching DUT source. Returning the raw value is necessary for HMC, where
        null/empty explicitly clears a lower tool-level HMC prefix.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether HMC is enabled or required for this operation.

        Returns:
            The authored DUT prefix value, including an explicit clear.

        Raises:
            ValueError: If DUT ``dut_id`` has no explicit ``prefix_key``.
        """

        prefix_key = "RF_HMC_DEFAULT_PREFIX" if hmc else "RF_DEFAULT_PREFIX"
        if not self._dut_prefix_is_explicit(dut_id, prefix_key):
            raise ValueError(f"DUT {dut_id!r} has no explicit {prefix_key}")
        return self.dut_uri_configs.get(dut_id, {}).get(prefix_key)

    def update_dut_rf_prefix(self, dut_id: str, rf_prefix: str) -> None:
        """
        Update the RF_DEFAULT_PREFIX for a specific DUT.

        This is called after DUT creation when RF_DEFAULT_PREFIX may have been
        modified by applying tool-level prefix_override.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            rf_prefix: Text supplied as Redfish prefix in the format accepted by
                this function.
        """
        if dut_id not in self.dut_uri_configs:
            self.dut_uri_configs[dut_id] = {}

        self.dut_uri_configs[dut_id]["RF_DEFAULT_PREFIX"] = validate_redfish_uri_path(
            rf_prefix, context=f"DUT configuration {dut_id}.RF_DEFAULT_PREFIX"
        )
        # Direct callers historically use this method for a DUT-owned value.
        # DUTManager corrects this marker to false when the value came from a
        # lower tool override.
        self.set_dut_prefix_explicit(dut_id, "RF_DEFAULT_PREFIX", True)
        logger.debug(f"Updated RF_DEFAULT_PREFIX for DUT {dut_id}: {rf_prefix}")

    def update_dut_hmc_prefix(self, dut_id: str, hmc_prefix: Optional[str]) -> None:
        """
        Update the RF_HMC_DEFAULT_PREFIX for a specific DUT.

        This is called after DUT creation when RF_HMC_DEFAULT_PREFIX has been
        resolved (DUT-level or from tool-level hmc_prefix_override).

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc_prefix: Text supplied as HMC prefix in the format accepted by
                this function.
        """
        if dut_id not in self.dut_uri_configs:
            self.dut_uri_configs[dut_id] = {}

        self.dut_uri_configs[dut_id]["RF_HMC_DEFAULT_PREFIX"] = (
            validate_redfish_uri_path(
                hmc_prefix,
                context=f"DUT configuration {dut_id}.RF_HMC_DEFAULT_PREFIX",
            )
            if hmc_prefix not in (None, "")
            else hmc_prefix
        )
        self.set_dut_prefix_explicit(dut_id, "RF_HMC_DEFAULT_PREFIX", True)
        logger.debug(f"Updated RF_HMC_DEFAULT_PREFIX for DUT {dut_id}: {hmc_prefix}")

    def get_uri(
        self,
        dut_id: str,
        uri_key: Union[str, ResourceType],
        baseboard: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> str:
        """
        Get URI for a specific key with proper override resolution.

        The implementation uses ``dut_id``, ``uri_key``, ``baseboard``, and
        ``platform`` to get URI for a specific key with proper override
        resolution. If the function cannot get URI for a specific key with
        proper override resolution, its exception reaches the caller instead of
        being converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            uri_key: Validated remote resource identifier used for URI key.
            baseboard: Optional baseboard; ``None`` selects the function's
                default behavior.
            platform: Optional platform; ``None`` selects the function's default
                behavior.

        Returns:
            The canonical URI text.

        Raises:
            KeyError: If unknown Redfish URI resource key: ``uri_key``.
        """
        # Convert ResourceType enum to string if needed
        if isinstance(uri_key, ResourceType):
            uri_key = uri_key.value
        # Priority 1: DUT-specific URI overrides
        dut_uris = self.dut_uri_configs.get(dut_id, {})
        if uri_key in dut_uris:
            uri = dut_uris[uri_key]
            logger.debug(f"Using DUT-specific URI for {dut_id}.{uri_key}: {uri}")
            return self._apply_prefix_override(uri, dut_id)

        # Priority 2: Baseboard-specific URI overrides
        if baseboard and self.tool_uris:
            baseboard_overrides = self.tool_uris.get("baseboard_overrides", {})
            baseboard_uris = baseboard_overrides.get(baseboard, {})
            if uri_key in baseboard_uris:
                uri = baseboard_uris[uri_key]
                logger.debug(
                    f"Using baseboard-specific URI for {baseboard}.{uri_key}: {uri}"
                )
                return self._apply_prefix_override(uri, dut_id)

        # Priority 3: Platform-specific URI overrides
        if platform and self.tool_uris:
            platform_overrides = self.tool_uris.get("platform_overrides", {})
            platform_uris = platform_overrides.get(platform, {})
            if uri_key in platform_uris:
                uri = platform_uris[uri_key]
                logger.debug(
                    f"Using platform-specific URI for {platform}.{uri_key}: {uri}"
                )
                return self._apply_prefix_override(uri, dut_id)

        # Priority 4: Tool-level default URIs
        if self.tool_uris:
            default_uris = self.tool_uris.get("default_uris", {})
            if uri_key in default_uris:
                uri = default_uris[uri_key]
                logger.debug(f"Using tool-level default URI for {uri_key}: {uri}")
                return self._apply_prefix_override(uri, dut_id)

        raise KeyError(f"Unknown Redfish URI resource key: {uri_key}")

    def normalize_response_uri(
        self, dut_id: str, uri: str, *, hmc: Optional[bool] = None
    ) -> str:
        """
        Resolve a concrete response URI using the DUT's effective root policy.

        Collection validators use this before applying their existing resource
        ancestry checks. HMC links advertised through the BMC namespace are
        translated to the independent HMC root when one is configured. An explicit
        BMC namespace also translates HMC members back for collection ancestry
        comparisons. The longest matching configured root identifies the source
        namespace, preserving nested roots before catalog rebasing. Templates
        must be expanded before this request boundary.

        Args:
            dut_id: DUT whose explicit or inherited URI policy is selected.
            uri: Concrete resource path or response link to normalize.
            hmc: Optional explicit namespace; otherwise infer it from the path.

        Returns:
            A validated request path and safe query under the effective root.

        Raises:
            ValueError: If the URI or configured roots violate request policy.
        """

        is_hmc = self._is_hmc_uri(uri, dut_id) if hmc is None else hmc
        target_root = self.get_service_root(dut_id, hmc=is_hmc)
        source_root = self.service_root
        path = urlsplit(uri).path
        roots = {
            self.service_root,
            self.get_service_root(dut_id),
            self.get_service_root(dut_id, hmc=True),
        }
        for root in sorted(roots, key=len, reverse=True):
            if path == root or path.startswith(f"{root.rstrip('/')}/"):
                source_root = root
                break
        return rebase_redfish_uri(uri, source_root, target_root)

    def _get_fallback_uri(self, uri_key: str, dut_id: Optional[str] = None) -> str:
        """
        Get fallback URI for a key when no configuration is found.

        The implementation uses ``uri_key`` and ``dut_id`` to get fallback URI
        for a key when no configuration is found. If the function cannot get
        fallback URI for a key when no configuration is found, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            uri_key: Validated remote resource identifier used for URI key.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The canonical fallback URI text.

        Raises:
            KeyError: If unknown Redfish URI resource key: ``uri_key``.
        """
        # Resolve only named resources. Inventing a path for a typo can send a
        # credential or collection request to an unintended endpoint.
        if self.tool_uris:
            default_uris = self.tool_uris.get("default_uris", {})
            if uri_key in default_uris:
                return self._apply_prefix_override(default_uris[uri_key], dut_id)
        if uri_key in self.catalog_uris:
            return self._apply_prefix_override(self.catalog_uris[uri_key], dut_id)
        raise KeyError(f"Unknown Redfish URI resource key: {uri_key}")

    def get_service_root(
        self, dut_id: Optional[str] = None, *, hmc: bool = False
    ) -> str:
        """
        Return the catalog service root after explicit prefix precedence.

        The implementation uses ``dut_id`` and ``hmc`` to produce the catalog
        service root after explicit prefix precedence.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            hmc: Whether HMC is enabled or required for this operation.

        Returns:
            The canonical service root text.
        """

        dut_uris = self.dut_uri_configs.get(dut_id, {}) if dut_id else {}
        if hmc:
            if self._dut_prefix_is_explicit(dut_id, "RF_HMC_DEFAULT_PREFIX"):
                return dut_uris.get("RF_HMC_DEFAULT_PREFIX") or self.service_root
            hmc_prefix = self.tool_uris.get("hmc_prefix_override")
            if hmc_prefix:
                return hmc_prefix

        if self._dut_prefix_is_explicit(dut_id, "RF_DEFAULT_PREFIX"):
            return dut_uris.get("RF_DEFAULT_PREFIX") or self.service_root
        return self.tool_uris.get("prefix_override") or self.service_root

    def get_discovery_resource_types(self, category: str) -> List[ResourceType]:
        """
        Return one catalog-owned ordered dynamic-discovery category.

        The implementation uses ``category`` to produce one catalog-owned
        ordered dynamic-discovery category. If the function cannot produce one
        catalog-owned ordered dynamic-discovery category, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            category: Text supplied as category in the format accepted by this
                function.

        Returns:
            The discovery resource types returned in operation-defined order.

        Raises:
            ValueError: If unknown Redfish discovery category: ``category``.
        """

        if category not in {
            "core",
            "optional",
            "firmware_inventory_candidates",
        }:
            raise ValueError(f"Unknown Redfish discovery category: {category}")
        return [
            ResourceType(resource_name)
            for resource_name in self.topology_profile["discovery"][category]
        ]

    def _credential_candidate_names(
        self,
        *,
        baseboard: Optional[str],
        baseboard_type: Optional[str],
        platform: Optional[str],
        node_type: Optional[str],
        custom_prefix: bool,
    ) -> List[str]:
        """
        Return the credential candidate names.

        After applying local validation, the function forwards ``baseboard``,
        ``baseboard_type``, ``platform``, ``node_type``, and ``custom_prefix``
        to ``select_redfish_credential_candidates`` and preserves its return and
        exception contract.

        Args:
            baseboard: Text supplied as baseboard in the format accepted by this
                function.
            baseboard_type: Text supplied as baseboard type in the format
                accepted by this function.
            platform: Text supplied as platform in the format accepted by this
                function.
            node_type: Text supplied as node type in the format accepted by this
                function.
            custom_prefix: Whether custom prefix is enabled or required for this
                operation.

        Returns:
            The credential candidate names returned in operation-defined order.
        """
        return select_redfish_credential_candidates(
            self.topology_profile,
            baseboard=baseboard,
            baseboard_type=baseboard_type,
            platform=platform,
            node_type=node_type,
            custom_prefix=custom_prefix,
        )

    def get_credential_validation_uris(
        self,
        dut_id: str,
        *,
        baseboard: Optional[str] = None,
        baseboard_type: Optional[str] = None,
        platform: Optional[str] = None,
        node_type: Optional[str] = None,
        configured_uri: Any = None,
    ) -> List[str]:
        """
        Resolve ordered credential probes from explicit or catalog policy.

        The implementation uses ``dut_id``, ``baseboard``, ``baseboard_type``,
        ``platform``, and ``node_type`` to resolve ordered credential probes
        from explicit or catalog policy. If the function cannot resolve ordered
        credential probes from explicit or catalog policy, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            baseboard: Optional baseboard; ``None`` selects the function's
                default behavior.
            baseboard_type: Optional baseboard type; ``None`` selects the
                function's default behavior.
            platform: Optional platform; ``None`` selects the function's default
                behavior.
            node_type: Optional node type; ``None`` selects the function's
                default behavior.
            configured_uri: Validated remote resource identifier used for
                configured URI.

        Returns:
            The validated ``unique_candidates``.

        Raises:
            ValueError: If credential_validation_uri must not be empty; or
                ``context`` must identify a resource beneath the catalog or
                effective Redfish service root.
        """

        if configured_uri is not None:
            raw_candidates = (
                list(configured_uri)
                if isinstance(configured_uri, (list, tuple))
                else [configured_uri]
            )
            if not raw_candidates:
                raise ValueError("credential_validation_uri must not be empty")
            effective_root = self.get_service_root(dut_id)
            allowed_roots = list(dict.fromkeys((self.service_root, effective_root)))
            candidates = []
            for index, candidate in enumerate(raw_candidates):
                context = f"credential_validation_uri[{index}]"
                normalized_candidate = validate_redfish_uri_path(
                    candidate,
                    context=context,
                )
                for allowed_root in allowed_roots:
                    try:
                        validate_redfish_uri_path(
                            normalized_candidate,
                            context=context,
                            service_root=allowed_root,
                        )
                        break
                    except ValueError:
                        continue
                else:
                    raise ValueError(
                        f"{context} must identify a resource beneath the catalog "
                        "or effective Redfish service root"
                    )
                candidates.append(
                    self._credential_uri_under_effective_root(
                        normalized_candidate,
                        effective_root=effective_root,
                        context=context,
                    )
                )
        else:
            service_root = self.get_service_root(dut_id)
            candidate_names = self._credential_candidate_names(
                baseboard=baseboard,
                baseboard_type=baseboard_type,
                platform=platform,
                node_type=node_type,
                custom_prefix=service_root != self.service_root,
            )
            candidates = [
                self._credential_uri_under_effective_root(
                    self.get_uri(dut_id, candidate, baseboard, platform),
                    effective_root=service_root,
                    context=f"credential candidate {candidate}",
                )
                for candidate in candidate_names
            ]

        unique_candidates: List[str] = []
        for candidate in candidates:
            if candidate not in unique_candidates:
                unique_candidates.append(candidate)
        return unique_candidates

    def _credential_uri_under_effective_root(
        self, uri: str, *, effective_root: str, context: str
    ) -> str:
        """
        Rebase a catalog collection and require it beneath the effective root.

        After applying local validation, the function forwards ``uri``,
        ``effective_root``, and ``context`` to ``validate_redfish_uri_path`` and
        preserves its return and exception contract.

        Args:
            uri: Validated remote resource identifier used for URI.
            effective_root: filesystem location used as the effective root for
                this operation.
            context: Runtime context carrying state shared across this
                operation.

        Returns:
            The canonical credential URI under effective root text.

        Raises:
            ValueError: If ``context`` must identify a collection beneath the
                effective Redfish service root.
        """

        normalized_uri = validate_redfish_uri_path(uri, context=context)
        effective_root = validate_redfish_uri_path(
            effective_root, context="effective service root"
        )
        if normalized_uri in {self.service_root, effective_root}:
            raise ValueError(
                f"{context} must identify a collection beneath the effective "
                "Redfish service root"
            )
        already_effective = effective_root != "/" and normalized_uri.startswith(
            f"{effective_root}/"
        )
        if not already_effective:
            normalized_uri = self._replace_service_root(normalized_uri, effective_root)
        return validate_redfish_uri_path(
            normalized_uri,
            context=context,
            service_root=effective_root,
        )

    def _is_hmc_uri(self, uri: str, dut_id: Optional[str] = None) -> bool:
        """
        Classify HMC resources by configured identity prefix or URI namespace.

        Preserve legacy identity routing for links advertised through the BMC.
        Otherwise, an independent HMC root identifies non-prefixed resources.
        Match complete path boundaries and prefer the most specific root; a
        shared BMC or catalog namespace and relative links remain ambiguous and
        require the identity prefix. Query values never select the namespace.

        Args:
            uri: Resource path, template, or response URL to classify.
            dut_id: DUT selecting explicit roots, or ``None`` for tool defaults.

        Returns:
            Whether configuration identifies the resource as belonging to HMC.

        Raises:
            ValueError: If URL parsing rejects a malformed authority.
        """
        hmc_resource_prefix = (
            self.tool_uris.get("hmc_resource_prefix", "HGX_")
            if self.tool_uris
            else "HGX_"
        )
        path = urlsplit(uri).path
        if f"/{hmc_resource_prefix}" in f"/{path.lstrip('/')}":
            return True
        if not path.startswith("/"):
            return False
        bmc_root = self.get_service_root(dut_id)
        hmc_root = self.get_service_root(dut_id, hmc=True)
        roots = {self.service_root, bmc_root, hmc_root}
        for root in sorted(roots, key=len, reverse=True):
            if path == root or path.startswith(f"{root.rstrip('/')}/"):
                return root == hmc_root and root not in {bmc_root, self.service_root}
        return False

    def _replace_service_root(self, uri: str, replacement: str) -> str:
        """
        Replace the catalog service-root prefix without touching lookalikes.

        Keep already-rebased templates intact, including roots nested beneath
        the catalog root. When the replacement is an ancestor of the catalog
        root, a complete catalog prefix still needs translation. Templates may
        contain placeholders, so concrete request validation happens after
        expansion at the transport boundary.

        Args:
            uri: Catalog resource path or validated URI template.
            replacement: Effective service-root path from configuration.

        Returns:
            The resource or template under the selected service root.
        """

        if (
            replacement != "/"
            and (uri == replacement or uri.startswith(f"{replacement}/"))
            and not self.service_root.startswith(f"{replacement}/")
        ):
            return uri
        if self.service_root == "/":
            if replacement == "/":
                return uri
            return f"{replacement.rstrip('/')}/{uri.lstrip('/')}"
        if uri == self.service_root:
            return replacement
        service_prefix = f"{self.service_root}/"
        if uri.startswith(service_prefix):
            suffix = uri[len(self.service_root) :]
            return suffix if replacement == "/" else f"{replacement}{suffix}"
        return uri

    def _apply_prefix_override(self, uri: str, dut_id: Optional[str] = None) -> str:
        """
        Apply prefix override if configured in the tool URIs.

        For URIs targeting a configured HMC identity prefix or namespace, the
        HMC-specific prefix is applied in this priority order:

        1. DUT-level ``RF_HMC_DEFAULT_PREFIX`` (dut_config.yaml).
        2. Tool-level ``uri_overrides.hmc_prefix_override`` (tool_config.yaml).

        For all other (BMC) URIs, the standard prefix logic applies:

        1. Explicit DUT-level ``RF_DEFAULT_PREFIX``, including an explicit clear.
        2. Tool-level ``uri_overrides.prefix_override``.

        Args:
            uri: Validated remote resource identifier used for URI.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The canonical prefix override text.
        """
        dut_uris = self.dut_uri_configs.get(dut_id, {}) if dut_id else {}

        # --- HMC URI path ---
        # HMC resources may use a distinct identity prefix, namespace, or both.
        #
        # Priority when RF_HMC_DEFAULT_PREFIX / hmc_prefix_override IS set:
        #   Apply it and return immediately — it takes full precedence over any
        #   global prefix_override.
        #
        # When neither HMC-specific prefix is set:
        #   Fall through to the global prefix_override logic below so that a single
        #   global prefix applies to ALL collectors (BMC and HMC alike).
        if self._is_hmc_uri(uri, dut_id):
            if self._dut_prefix_is_explicit(dut_id, "RF_HMC_DEFAULT_PREFIX"):
                # A DUT-scoped value wins by presence. Empty/null deliberately
                # clears the lower tool HMC prefix; a populated value is applied.
                hmc_prefix = dut_uris.get("RF_HMC_DEFAULT_PREFIX")
                if hmc_prefix:
                    uri = self._replace_service_root(uri, hmc_prefix)
                    logger.debug(
                        f"Applied explicit DUT HMC prefix '{hmc_prefix}' to URI: {uri}"
                    )
                return uri

            # A non-explicit model/default value is not DUT policy. The tool
            # override is therefore the next authoritative HMC prefix.
            hmc_prefix = self.tool_uris.get("hmc_prefix_override")

            if hmc_prefix:
                # An HMC-specific prefix is configured — apply it and stop here.
                uri = self._replace_service_root(uri, hmc_prefix)
                logger.debug(
                    f"Applied HMC prefix override '{hmc_prefix}' to URI: {uri}"
                )
                return uri
            # No HMC-specific prefix configured — fall through to global prefix_override
            # so that a single global prefix covers both BMC and HMC collectors.

        # --- BMC URI path (also reached by HMC URIs when no HMC-specific prefix set) ---
        if not self.tool_uris:
            return uri

        # Resolve DUT policy before discovery validates response links against
        # the collection URI. Deferring this until transport would leave those
        # validators anchored to the catalog root instead of the requested root.
        if self._dut_prefix_is_explicit(dut_id, "RF_DEFAULT_PREFIX"):
            dut_prefix = self.get_service_root(dut_id)
            return self._replace_service_root(uri, dut_prefix)

        prefix_override = self.tool_uris.get("prefix_override")
        if not prefix_override:
            return uri

        uri = self._replace_service_root(uri, prefix_override)
        logger.debug(f"Applied prefix override '{prefix_override}' to URI: {uri}")

        return uri

    def get_uri_template(self, template_key: str, **kwargs) -> str:
        """
        Get URI template and substitute parameters.

        The implementation uses ``template_key`` and ``kwargs`` to get URI
        template and substitute parameters. If the function cannot get URI
        template and substitute parameters, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            template_key: Stable template key used for lookup and
                operator-facing diagnostics.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The canonical URI template text.

        Raises:
            ValueError: If the supplied input cannot be used to get URI template
                and substitute parameters; or the uri template
                ``template_key``.``field_name`` is not a non-empty path segment.
        """
        if not self.tool_uris:
            return self._get_fallback_uri(template_key)

        templates = self.tool_uris.get("uri_templates", {})
        template = templates.get(template_key)

        if not template:
            return self._get_fallback_uri(template_key)

        fields = {
            field_name
            for _, field_name, _, _ in Formatter().parse(template)
            if field_name is not None
        }
        missing = fields - set(kwargs)
        unexpected = set(kwargs) - fields
        if missing:
            raise ValueError(
                f"URI template {template_key} is missing parameters: "
                + ", ".join(sorted(missing))
            )
        if unexpected:
            raise ValueError(
                f"URI template {template_key} has unexpected parameters: "
                + ", ".join(sorted(unexpected))
            )
        for field_name, field_value in kwargs.items():
            if (
                not isinstance(field_value, str)
                or not field_value
                or "/" in field_value
                or "\\" in field_value
            ):
                raise ValueError(
                    f"URI template {template_key}.{field_name} must be a non-empty "
                    "path segment"
                )
            validate_redfish_uri_path(
                f"/{field_value}",
                context=f"URI template {template_key}.{field_name}",
            )
        return validate_redfish_uri_path(
            template.format(**kwargs),
            context=f"URI template {template_key}",
        )

    def validate_uri(self, uri: str, uri_type: str) -> bool:
        """
        Validate URI structure against configured patterns.

        The implementation uses ``uri`` and ``uri_type`` to validate URI
        structure against configured patterns. Every required invariant is
        checked before a successful value is returned; invalid input follows the
        function's explicit exception path.

        Args:
            uri: Validated remote resource identifier used for URI.
            uri_type: Validated remote resource identifier used for URI type.

        Returns:
            Whether the URI structure against configured patterns operation
            succeeds.

        Raises:
            ValueError: If invalid regex pattern for ``uri_type``: ``pattern``.
        """
        try:
            validate_redfish_uri_path(uri, context=f"Redfish URI {uri_type}")
        except ValueError:
            return False

        if not self.tool_uris:
            return True

        validation_patterns = self.tool_uris.get("validation_patterns", {})
        pattern = validation_patterns.get(uri_type)

        if not pattern:
            return True  # No validation pattern defined

        try:
            return bool(re.match(pattern, uri))
        except re.error as error:
            raise ValueError(
                f"Invalid regex pattern for {uri_type}: {pattern}"
            ) from error

    def get_all_uris_for_dut(
        self,
        dut_id: str,
        baseboard: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Get all configured URIs for a DUT.

        The implementation uses ``dut_id``, ``baseboard``, and ``platform`` to
        get all configured URIs for a DUT.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            baseboard: Optional baseboard; ``None`` selects the function's
                default behavior.
            platform: Optional platform; ``None`` selects the function's default
                behavior.

        Returns:
            The validated ``uris``.
        """
        uri_keys = list(self.catalog_uris)

        uris = {}
        for key in uri_keys:
            uris[key] = self.get_uri(dut_id, key, baseboard, platform)

        return uris

    def clear_dut_config(self, dut_id: str) -> None:
        """
        Clear DUT-specific URI configuration.

        The implementation uses ``dut_id`` to clear DUT-specific URI
        configuration.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        had_config = dut_id in self.dut_uri_configs
        self.dut_uri_configs.pop(dut_id, None)
        self.dut_explicit_prefixes.pop(dut_id, None)
        if had_config:
            logger.debug(f"Cleared URI configuration for DUT {dut_id}")

    def get_config_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current URI configuration.

        The implementation uses current instance state to get a summary of the
        current URI configuration.

        Returns:
            A mapping containing the ``tool_uri_config_loaded``,
            ``tool_uri_config_path``, ``configured_duts``, and
            ``available_uri_keys`` fields.
        """
        return {
            "tool_uri_config_loaded": bool(self.tool_uris),
            "tool_uri_config_path": self.tool_uri_config_path,
            "configured_duts": list(self.dut_uri_configs.keys()),
            "available_uri_keys": (
                list(self.tool_uris.get("default_uris", {}).keys())
                if self.tool_uris
                else []
            ),
        }
