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
Variable Substitution Service for NVDebug Tool.

Handles dynamic replacement of placeholders in action URIs, payloads, and
configurations with support for DUT-specific values and nested substitutions.

Only placeholders authored in the input template are evaluated. Resolved values
are opaque data. Intentional nesting must be supplied separately through the
``trusted_templates`` argument so lower-trust runtime or device values cannot
cross into configuration, environment, DUT, or other runtime namespaces.
"""

import os
import re
from collections.abc import Iterable
from typing import Any, Dict, Set

_ENVIRONMENT_ALLOWLIST_MAX_ENTRIES = 64
_ENVIRONMENT_NAME_MAX_LENGTH = 128
_ENVIRONMENT_VALUE_MAX_CHARS = 64 * 1024
_ENVIRONMENT_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_SENSITIVE_ENVIRONMENT_NAME_COMPONENTS = frozenset(
    {
        "ACCESS",
        "AUTH",
        "AUTHORIZATION",
        "COOKIE",
        "CREDS",
        "CREDENTIAL",
        "CREDENTIALS",
        "CSRF",
        "DIR",
        "DIRECTORY",
        "DSN",
        "FILE",
        "HOME",
        "JWT",
        "KEY",
        "NONCE",
        "OTP",
        "PASS",
        "PASSPHRASE",
        "PASSWD",
        "PASSWORD",
        "PATH",
        "PAT",
        "PRIVATE",
        "PWD",
        "SECRET",
        "SESSION",
        "SIGNATURE",
        "TOKEN",
        "URI",
        "URL",
        "XSRF",
    }
)
_SENSITIVE_ENVIRONMENT_COMPACT_MARKERS = (
    "ACCESSKEY",
    "APIKEY",
    "AUTHKEY",
    "AUTHTOKEN",
    "CLIENTSECRET",
    "COOKIE",
    "CREDENTIAL",
    "PASSWD",
    "PASSWORD",
    "PASSPHRASE",
    "PRIVATEKEY",
    "REFRESHTOKEN",
    "SECRET",
    "SESSIONTOKEN",
    "TOKEN",
)
_SENSITIVE_ENVIRONMENT_NAMES = frozenset(
    {
        "BASH_ENV",
        "CLOUDSDK_CONFIG",
        "DOCKER_CONFIG",
        "ENV",
        "GIT_ASKPASS",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "KUBECONFIG",
        "NETRC",
        "PERL5LIB",
        "PERL5OPT",
        "PYTHONHOME",
        "PYTHONPATH",
        "RUBYOPT",
        "SHELL",
        "SSLKEYLOGFILE",
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "SSH_AUTH_SOCK",
        "SUDO_ASKPASS",
        "TEMP",
        "TMP",
        "TMPDIR",
    }
)


class VariableSubstitutionError(Exception):
    """
    Exception raised for variable substitution errors.

    Raised when variable substitution fails due to missing variables, type
    validation errors, or other substitution issues.
    """

    pass


class EnvironmentVariablePolicyError(VariableSubstitutionError):
    """
    Environment substitution was rejected by the explicit trust policy.

    Callers receive this exception when the environment variable policy error
    invariant prevents the requested operation from completing. The distinct
    type lets them handle that boundary without parsing an error message.
    """

    pass


class VariableSubstitutionService:
    """
    Manage variable substitution service operations for the NVDebug runtime.

    The type coordinates ``create``, ``_initialize``, ``substitute_variables``,
    ``_resolve_approved_template``, and ``_is_cache_safe`` and retains the state
    those operations share between calls. Resource ownership remains inside the
    instance until the matching close, exit, or cleanup operation completes.
    """

    def __init__(
        self,
        logger=None,
        orchestrator=None,
        *,
        environment_allowlist: Iterable[str] | None = None,
    ):
        """
        Initialize the VariableSubstitutionService.

        The initializer records ``cache_hits``, ``cache_misses``,
        ``cache_size``, ``config_pattern``, and ``config_resolver`` for later
        operations and establishes the instance invariants before any public
        method runs.

        Args:
            logger: Sanitized logger used for operator-visible diagnostics.
            orchestrator: Optional orchestrator; ``None`` selects the function's
                default behavior.
            environment_allowlist: Optional environment allowlist; ``None``
                selects the function's default behavior.
        """
        self.logger = logger
        self.orchestrator = orchestrator
        self.environment_allowlist = self._validate_environment_allowlist(
            environment_allowlist
        )

        # Initialize with default settings
        self.enable_caching = True
        self.cache_size = 128
        self.substitution_cache = {}
        self.cache_hits = 0
        self.cache_misses = 0
        self.config_resolver = None
        self.dut_object = None

        # Enhanced variable patterns:
        # {variable_name} - runtime context variables
        # {config.path.to.value} - configuration variables
        # {env.VARIABLE_NAME} - environment variables
        # {dut.attribute} - DUT-specific variables
        self.variable_pattern = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
        self.config_pattern = re.compile(r"\{config\.([a-zA-Z0-9_.]+)\}")
        self.env_pattern = re.compile(r"\{env\.([A-Z_][A-Z0-9_]*)\}")
        self.dut_pattern = re.compile(r"\{dut\.([a-zA-Z0-9_.]+)\}")
        # Match every supported placeholder in source order.  Public substitution
        # walks the approved template once with this pattern so values returned by
        # one resolver never become input to another resolver.
        self.placeholder_pattern = re.compile(
            r"\{(?:(?:config\.(?P<config>[a-zA-Z0-9_.]+))|"
            r"(?:env\.(?P<env>[A-Z_][A-Z0-9_]*))|"
            r"(?:dut\.(?P<dut>[a-zA-Z0-9_.]+))|"
            r"(?P<runtime>[a-zA-Z_][a-zA-Z0-9_]*))\}"
        )

        # Supported variable types and their validation patterns
        self.variable_types = {
            "system_id": r"^[a-zA-Z0-9_-]+$",
            "manager_id": r"^[a-zA-Z0-9_-]+$",
            "chassis_id": r"^[a-zA-Z0-9_-]+$",
            "task_id": r"^[a-zA-Z0-9_-]+$",
            "device_id": r"^[a-zA-Z0-9_-]+$",
            "entry_id": r"^[a-zA-Z0-9_-]+$",
            "diagnostic_type": r"^[a-zA-Z0-9_-]+$",
            "command_name": r"^[a-zA-Z0-9_-]+$",
            "file_name": r"^[a-zA-Z0-9_.-]+$",
            "timestamp": r"^\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}$",
            "log_id": r"^[a-zA-Z0-9_-]+$",
            "report_id": r"^[a-zA-Z0-9_-]+$",
            "member_id": r"^[a-zA-Z0-9_-]+$",
            "index": r"^\d+$",
            "page": r"^\d+$",
            "total": r"^\d+$",
            "sma_id": r"^[a-zA-Z0-9_-]+$",
            "service_id": r"^[a-zA-Z0-9_-]+$",
            "group": r"^[a-zA-Z0-9_-]+$",
            "device_name": r"^[a-zA-Z0-9_-]+$",
            "log_type": r"^[a-zA-Z0-9_-]+$",
            # Additional variables found in collector definitions
            "addr": r"^[a-zA-Z0-9_.-]+$",
            "BMC_IP": r"^[a-zA-Z0-9_.-]+$",
            "bus1": r"^[a-zA-Z0-9_-]+$",
            "bus2": r"^[a-zA-Z0-9_-]+$",
            "command_type": r"^[a-zA-Z0-9_-]+$",
            "data_value": r"^[a-zA-Z0-9_.-]+$",
            "device": r"^[a-zA-Z0-9_-]+$",
            "device_index": r"^[a-zA-Z0-9_-]+$",
            "device_instance": r"^[a-zA-Z0-9_-]+$",
            "flags": r"^[a-zA-Z0-9_-]+$",
            "hmc_addr": r"^[a-zA-Z0-9_.-]+$",
            "interface_id": r"^[a-zA-Z0-9_-]+$",
            "option": r"^[a-zA-Z0-9_-]+$",
            "options": r"^[a-zA-Z0-9_-]+$",
            "temp_dir": r"^[a-zA-Z0-9_/.-]+$",
            "vee_addr": r"^[a-zA-Z0-9_.-]+$",
            "vee_bus": r"^[a-zA-Z0-9_-]+$",
            "collector_dir": r"^[a-zA-Z0-9_/.-]+$",
            "log_dir": r"^[a-zA-Z0-9_/.-]+$",
        }

        # Type validation patterns
        self.type_patterns = {
            "string": r".*",
            "integer": r"^\d+$",
            "float": r"^\d+\.?\d*$",
            "boolean": r"^(true|false|True|False|1|0)$",
        }

    @classmethod
    async def create(
        cls,
        logger=None,
        orchestrator=None,
        config_resolver=None,
        dut_object=None,
        cache_size=None,
        environment_allowlist: Iterable[str] | None = None,
    ):
        """
        Create the configured resource.

        The implementation uses ``logger``, ``orchestrator``,
        ``config_resolver``, ``dut_object``, and ``cache_size`` to create the
        configured resource. Owned asynchronous work is awaited before return,
        so completion does not leave an unobserved task behind.

        Args:
            logger: Sanitized logger used for operator-visible diagnostics.
            orchestrator: Optional orchestrator; ``None`` selects the function's
                default behavior.
            config_resolver: Optional Config resolver governing configured
                resource.
            dut_object: Optional DUT object; ``None`` selects the function's
                default behavior.
            cache_size: Numeric cache size used by the operation's bounded
                accounting.
            environment_allowlist: Optional environment allowlist; ``None``
                selects the function's default behavior.

        Returns:
            The validated ``instance``.
        """
        instance = cls(
            logger,
            orchestrator,
            environment_allowlist=environment_allowlist,
        )
        instance.config_resolver = config_resolver
        instance.dut_object = dut_object
        if cache_size is not None:
            instance.cache_size = cache_size
        await instance._initialize()
        return instance

    async def _initialize(self):
        """
        Async initialization method.

        Sets up logging helper and initializes internal state.
        """

        # Helper method for async logging
        async def log_message(level: str, message: str, dut_id: str = None):
            """
            Helper to log messages using async logger if available.

            The implementation uses ``level``, ``message``, and ``dut_id`` to
            helper to log messages using async logger if available. Owned
            asynchronous work is awaited before return, so completion does not
            leave an unobserved task behind.

            Args:
                level: Text supplied as level in the format accepted by this
                    function.
                message: Operator-facing text carried by the reported event or
                    failure.
                dut_id: Stable DUT identifier used to correlate configuration,
                    logs, and results.
            """
            if self.logger and dut_id:
                # Use DUT-specific logging
                await self.logger.write_to_dut_runtime_log(
                    dut_id, level, "VariableSubstitution", message
                )
            elif self.logger:
                # Use system-level logging
                await self.logger.log_runtime(level, "VariableSubstitution", message)
            # Remove fallback print statement to avoid console spam

        self._log = log_message

    async def substitute_variables(
        self,
        template: str,
        context: Dict[str, Any],
        dut_id: str = None,
        validate_types: bool = True,
        allow_missing: bool = False,
        trusted_templates: Dict[str, str] = None,
        max_depth: int = 10,
    ) -> str:
        """
        Substitute variables in a template string with values from context.

        The implementation uses ``template``, ``context``, ``dut_id``,
        ``validate_types``, and ``allow_missing`` to substitute variables in a
        template string with values from context. Owned asynchronous work is
        awaited before return, so completion does not leave an unobserved task
        behind. It updates ``cache_hits`` and ``cache_misses`` on the instance
        as part of that state transition. If the function cannot substitute
        variables in a template string with values from context, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            template: Text supplied as template in the format accepted by this
                function.
            context: Runtime context carrying state shared across this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            validate_types: Whether validate types is enabled or required for
                this operation.
            allow_missing: Whether allow missing is enabled or required for this
                operation.
            trusted_templates: Optional trusted templates; ``None`` selects the
                function's default behavior.
            max_depth: Upper bound enforced for max depth; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            The canonical substitute variables text.

        Raises:
            VariableSubstitutionError: If max_depth cannot be negative; or
                substitution failed: ``e``.
        """
        if not template:
            return template

        if max_depth < 0:
            raise VariableSubstitutionError("max_depth cannot be negative")

        approved_templates = dict(trusted_templates or {})

        # Check cache first if enabled
        cache_key = None
        cache_allowed = self.enable_caching and self._is_cache_safe(
            template, approved_templates
        )
        if cache_allowed:
            cache_key = self._generate_cache_key(
                template,
                context,
                trusted_templates=approved_templates,
                validate_types=validate_types,
                allow_missing=allow_missing,
                max_depth=max_depth,
            )
            if cache_key in self.substitution_cache:
                self.cache_hits += 1
                await self._log(
                    "DEBUG",
                    "Variable substitution cache hit",
                    dut_id,
                )
                return self.substitution_cache[cache_key]
            else:
                self.cache_misses += 1
        else:
            # Count as cache miss when caching is disabled
            self.cache_misses += 1

        try:
            result = await self._resolve_approved_template(
                template,
                context,
                dut_id,
                validate_types,
                allow_missing,
                approved_templates,
                max_depth=max_depth,
            )

            # Cache result if enabled
            if cache_allowed:
                self._cache_result(cache_key, result)

            await self._log("DEBUG", "Variable substitution completed", dut_id)
            return result

        except EnvironmentVariablePolicyError:
            await self._log(
                "ERROR",
                "Environment variable substitution denied by policy",
                dut_id,
            )
            raise
        except VariableSubstitutionError as e:
            await self._log("ERROR", f"Variable substitution failed: {e}", dut_id)
            raise
        except Exception as e:
            await self._log("ERROR", f"Variable substitution failed: {e}", dut_id)
            raise VariableSubstitutionError(f"Substitution failed: {e}")

    async def _resolve_approved_template(
        self,
        template: str,
        context: Dict[str, Any],
        dut_id: str,
        validate_types: bool,
        allow_missing: bool,
        trusted_templates: Dict[str, str],
        max_depth: int,
        depth: int = 0,
        resolution_stack: tuple[str, ...] = (),
    ) -> str:
        """
        Resolve placeholders present in an approved template.

        Resolver values are appended as opaque data. Only fragments supplied via
        ``trusted_templates`` are parsed recursively, which prevents device
        data, environment values, configuration values, or DUT attributes from
        creating a new placeholder at a more trusted source.

        Args:
            template: Text supplied as template in the format accepted by this
                function.
            context: Runtime context carrying state shared across this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            validate_types: Whether validate types is enabled or required for
                this operation.
            allow_missing: Whether allow missing is enabled or required for this
                operation.
            trusted_templates: Mapping supplying fields for placeholders present
                in an approved template.
            max_depth: Upper bound enforced for max depth; the consuming
                boundary rejects or truncates values that exceed it.
            depth: Numeric depth used while the operation performs bounded
                accounting.
            resolution_stack: Entries supplied as ``resolution_stack`` without
                transferring container ownership.

        Returns:
            The canonical approved template text.
        """
        parts = []
        cursor = 0

        for match in self.placeholder_pattern.finditer(template):
            parts.append(template[cursor : match.start()])
            full_pattern = match.group(0)

            if match.group("config") is not None:
                replacement = await self._substitute_config_variables(
                    full_pattern, context, dut_id, allow_missing
                )
            elif match.group("env") is not None:
                replacement = await self._substitute_env_variables(
                    full_pattern, dut_id, allow_missing
                )
            elif match.group("dut") is not None:
                replacement = await self._substitute_dut_variables(
                    full_pattern, dut_id, allow_missing
                )
            else:
                variable_name = match.group("runtime")
                if variable_name in trusted_templates:
                    if variable_name in resolution_stack:
                        cycle = " -> ".join((*resolution_stack, variable_name))
                        await self._log(
                            "WARNING",
                            f"Trusted template cycle detected: {cycle}",
                            dut_id,
                        )
                        replacement = full_pattern
                    elif depth >= max_depth:
                        await self._log(
                            "WARNING",
                            f"Maximum nested substitution depth ({max_depth}) reached",
                            dut_id,
                        )
                        replacement = full_pattern
                    else:
                        nested_template = self._format_value(
                            trusted_templates[variable_name]
                        )
                        replacement = await self._resolve_approved_template(
                            nested_template,
                            context,
                            dut_id,
                            validate_types,
                            allow_missing,
                            trusted_templates,
                            max_depth,
                            depth + 1,
                            (*resolution_stack, variable_name),
                        )
                else:
                    replacement = await self._substitute_runtime_variables(
                        full_pattern,
                        context,
                        dut_id,
                        validate_types,
                        allow_missing,
                    )

            parts.append(replacement)
            cursor = match.end()

        parts.append(template[cursor:])
        return "".join(parts)

    def _is_cache_safe(self, template: str, trusted_templates: Dict[str, str]) -> bool:
        """
        Return whether a result depends only on explicit method arguments.

        The implementation uses ``template`` and ``trusted_templates`` to
        determine whether a result depends only on explicit method arguments.

        Args:
            template: Text supplied as template in the format accepted by this
                function.
            trusted_templates: Mapping supplying fields for result depends only
                on explicit method arguments.

        Returns:
            Whether a result depends only on explicit method arguments.
        """
        external_patterns = (self.config_pattern, self.env_pattern, self.dut_pattern)
        approved_fragments = (template, *map(str, trusted_templates.values()))
        return not any(
            pattern.search(fragment)
            for fragment in approved_fragments
            for pattern in external_patterns
        )

    async def _substitute_config_variables(
        self,
        template: str,
        context: Dict[str, Any],
        dut_id: str,
        allow_missing: bool,
    ) -> str:
        """
        Substitute configuration variables: {config.path.to.value}.

        The implementation uses ``template``, ``context``, ``dut_id``, and
        ``allow_missing`` to substitute configuration variables:
        {config.path.to.value}. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle. If the function cannot substitute
        configuration variables: {config.path.to.value}, its exception reaches
        the caller instead of being converted into a successful result.

        Args:
            template: Text supplied as template in the format accepted by this
                function.
            context: Runtime context carrying state shared across this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            allow_missing: Whether allow missing is enabled or required for this
                operation.

        Returns:
            The canonical substitute config variables text.

        Raises:
            VariableSubstitutionError: If missing config variable:
                ``config_path``; or error resolving config variable
                ``config_path``: ``e``.
        """
        has_config_placeholders = bool(self.config_pattern.search(template))

        if not self.config_resolver:
            if has_config_placeholders:
                await self._log(
                    "WARNING",
                    "No config resolver available, skipping config variable substitution",
                    dut_id,
                )
            return template

        result = template

        for match in self.config_pattern.finditer(template):
            config_path = match.group(1)
            full_pattern = match.group(0)

            try:
                # Try to resolve the full config path first
                config_value = self.config_resolver.resolve_variable(
                    config_path, context
                )

                # If that fails, try to extract a simple variable name from the path
                if config_value is None and "." in config_path:
                    # Extract the last part as a simple variable name
                    simple_var_name = config_path.split(".")[-1]
                    config_value = self.config_resolver.resolve_variable(
                        simple_var_name, context
                    )

                if config_value is not None:
                    result = result.replace(full_pattern, config_value)
                    await self._log(
                        "DEBUG",
                        f"Substituted {full_pattern} from configuration",
                        dut_id,
                    )
                else:
                    if not allow_missing:
                        raise VariableSubstitutionError(
                            f"Missing config variable: {config_path}"
                        )
                    else:
                        await self._log(
                            "WARNING",
                            f"Missing config variable {config_path}, keeping as-is",
                            dut_id,
                        )
            except Exception as e:
                if not allow_missing:
                    raise VariableSubstitutionError(
                        f"Error resolving config variable {config_path}: {e}"
                    )
                else:
                    await self._log(
                        "WARNING",
                        f"Error resolving config variable {config_path}: {e}",
                        dut_id,
                    )

        return result

    async def _substitute_env_variables(
        self, template: str, dut_id: str, allow_missing: bool
    ) -> str:
        """
        Substitute environment variables: {env.VARIABLE_NAME}.

        The implementation uses ``template``, ``dut_id``, and ``allow_missing``
        to substitute environment variables: {env.VARIABLE_NAME}. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. If the function
        cannot substitute environment variables: {env.VARIABLE_NAME}, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            template: Text supplied as template in the format accepted by this
                function.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            allow_missing: Whether allow missing is enabled or required for this
                operation.

        Returns:
            The validated ``result``.

        Raises:
            EnvironmentVariablePolicyError: If environment variable substitution
                denied by policy.
            VariableSubstitutionError: If missing environment variable:
                ``env_var_name``.
        """
        result = template

        for match in self.env_pattern.finditer(template):
            env_var_name = match.group(1)
            full_pattern = match.group(0)

            self._require_environment_variable_allowed(env_var_name)

            env_value = os.environ.get(env_var_name)
            if env_value is not None:
                if len(env_value) > _ENVIRONMENT_VALUE_MAX_CHARS:
                    raise EnvironmentVariablePolicyError(
                        "Environment variable substitution denied by policy"
                    )
                result = result.replace(full_pattern, env_value)
                await self._log(
                    "DEBUG",
                    f"Substituted {full_pattern} from environment",
                    dut_id,
                )
            else:
                if not allow_missing:
                    raise VariableSubstitutionError(
                        f"Missing environment variable: {env_var_name}"
                    )
                else:
                    await self._log(
                        "WARNING",
                        f"Missing environment variable {env_var_name}, keeping as-is",
                        dut_id,
                    )

        return result

    @staticmethod
    def _is_sensitive_environment_name(name: str) -> bool:
        """
        Return whether an environment name can expose secrets or host paths.

        The implementation uses ``name`` to determine whether an environment
        name can expose secrets or host paths.

        Args:
            name: Stable name used for lookup and operator-facing diagnostics.

        Returns:
            Whether an environment name can expose secrets or host paths.
        """
        if name in _SENSITIVE_ENVIRONMENT_NAMES:
            return True
        components = frozenset(name.split("_"))
        if components & _SENSITIVE_ENVIRONMENT_NAME_COMPONENTS:
            return True
        if any(
            marker in component
            for component in components
            for marker in _SENSITIVE_ENVIRONMENT_COMPACT_MARKERS
        ):
            return True
        return any(
            component.endswith(("DIR", "FILE", "HOME", "PATH"))
            for component in components
        )

    @classmethod
    def _validate_environment_allowlist(
        cls, environment_allowlist: Iterable[str] | None
    ) -> frozenset[str]:
        """
        Validate and freeze the bounded, code-supplied environment allowlist.

        The implementation uses ``environment_allowlist`` to validate and freeze
        the bounded, code-supplied environment allowlist. Every required
        invariant is checked before a successful value is returned; invalid
        input follows the function's explicit exception path.

        Args:
            environment_allowlist: Optional environment allowlist; ``None``
                selects the function's default behavior.

        Returns:
            The unique environment allowlist returned by the operation.

        Raises:
            EnvironmentVariablePolicyError: If environment variable allowlist is
                invalid; environment variable allowlist exceeds policy limits;
                or environment variable allowlist contains a prohibited name.
        """
        if environment_allowlist is None:
            return frozenset()
        if isinstance(environment_allowlist, (str, bytes)):
            raise EnvironmentVariablePolicyError(
                "Environment variable allowlist is invalid"
            )

        approved = set()
        try:
            iterator = iter(environment_allowlist)
        except TypeError as error:
            raise EnvironmentVariablePolicyError(
                "Environment variable allowlist is invalid"
            ) from error

        for index, name in enumerate(iterator):
            if index >= _ENVIRONMENT_ALLOWLIST_MAX_ENTRIES:
                raise EnvironmentVariablePolicyError(
                    "Environment variable allowlist exceeds policy limits"
                )
            if (
                not isinstance(name, str)
                or not name
                or len(name) > _ENVIRONMENT_NAME_MAX_LENGTH
                or _ENVIRONMENT_NAME_RE.fullmatch(name) is None
                or cls._is_sensitive_environment_name(name)
            ):
                raise EnvironmentVariablePolicyError(
                    "Environment variable allowlist contains a prohibited name"
                )
            approved.add(name)

        return frozenset(approved)

    def _require_environment_variable_allowed(self, name: str) -> None:
        """
        Fail closed before consulting ambient process state.

        The implementation uses ``name`` to fail closed before consulting
        ambient process state. If the function cannot fail closed before
        consulting ambient process state, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            name: Stable name used for lookup and operator-facing diagnostics.

        Raises:
            EnvironmentVariablePolicyError: If environment variable substitution
                denied by policy.
        """
        if (
            name not in self.environment_allowlist
            or self._is_sensitive_environment_name(name)
        ):
            raise EnvironmentVariablePolicyError(
                "Environment variable substitution denied by policy"
            )

    async def _substitute_dut_variables(
        self, template: str, dut_id: str, allow_missing: bool
    ) -> str:
        """
        Substitute DUT-specific variables: {dut.attribute}.

        The implementation uses ``template``, ``dut_id``, and ``allow_missing``
        to substitute DUT-specific variables: {dut.attribute}. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind. Filesystem effects remain confined to the
        caller-selected paths and the owning resource lifecycle. If the function
        cannot substitute DUT-specific variables: {dut.attribute}, its exception
        reaches the caller instead of being converted into a successful result.

        Args:
            template: Text supplied as template in the format accepted by this
                function.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            allow_missing: Whether allow missing is enabled or required for this
                operation.

        Returns:
            The canonical substitute DUT variables text.

        Raises:
            VariableSubstitutionError: If missing DUT variable: ``dut_path``; or
                error resolving DUT variable ``dut_path``: ``e``.
        """
        if not self.dut_object:
            await self._log(
                "WARNING",
                "No DUT object available, skipping DUT variable substitution",
                dut_id,
            )
            return template

        result = template

        for match in self.dut_pattern.finditer(template):
            dut_path = match.group(1)
            full_pattern = match.group(0)

            try:
                # Get value from DUT object using dot notation
                dut_value = self._get_dut_attribute(dut_path)
                if dut_value is not None:
                    result = result.replace(full_pattern, str(dut_value))
                    await self._log(
                        "DEBUG",
                        f"Substituted {full_pattern} from DUT context",
                        dut_id,
                    )
                else:
                    if not allow_missing:
                        raise VariableSubstitutionError(
                            f"Missing DUT variable: {dut_path}"
                        )
                    else:
                        await self._log(
                            "WARNING",
                            f"Missing DUT variable {dut_path}, keeping as-is",
                            dut_id,
                        )
            except Exception as e:
                if not allow_missing:
                    raise VariableSubstitutionError(
                        f"Error resolving DUT variable {dut_path}: {e}"
                    )
                else:
                    await self._log(
                        "WARNING",
                        f"Error resolving DUT variable {dut_path}: {e}",
                        dut_id,
                    )

        return result

    def _get_dut_attribute(self, path: str) -> Any:
        """
        Get DUT attribute using dot notation (e.g., 'config.i2c_bus').

        DUT templates expose operational attributes only. Private object
        internals and credential-bearing fields must never become
        catalog-substituted URI, command, or log content.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The validated ``current``.
        """
        if not self.dut_object:
            return None

        try:
            current = self.dut_object
            parts = path.split(".")
            if len(parts) > 8:
                return None
            for part in parts:
                normalized_part = part.casefold()
                if (
                    part.startswith("_")
                    or normalized_part == "credentials"
                    or any(
                        marker in normalized_part
                        for marker in ("password", "passwd", "secret", "token")
                    )
                ):
                    # DUT templates expose operational attributes only. Private
                    # object internals and credential-bearing fields must never
                    # become catalog-substituted URI, command, or log content.
                    return None
                if hasattr(current, part):
                    current = getattr(current, part)
                elif isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None

            return current
        except Exception:
            # Log error but don't raise - let the calling method handle it
            return None

    async def _substitute_runtime_variables(
        self,
        template: str,
        context: Dict[str, Any],
        dut_id: str,
        validate_types: bool,
        allow_missing: bool,
    ) -> str:
        """
        Substitute runtime context variables: {variable_name}.

        The implementation uses ``template``, ``context``, ``dut_id``,
        ``validate_types``, and ``allow_missing`` to substitute runtime context
        variables: {variable_name}. Owned asynchronous work is awaited before
        return, so completion does not leave an unobserved task behind.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle. If the function cannot substitute runtime
        context variables: {variable_name}, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            template: Text supplied as template in the format accepted by this
                function.
            context: Runtime context carrying state shared across this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            validate_types: Whether validate types is enabled or required for
                this operation.
            allow_missing: Whether allow missing is enabled or required for this
                operation.

        Returns:
            The validated ``result``.

        Raises:
            VariableSubstitutionError: If missing required variable:
                ``var_name``.
        """
        # Find all runtime variables in the template
        variables = self._extract_variables(template)
        await self._log("DEBUG", f"Found runtime variables: {variables}", dut_id)

        # Validate variables if requested
        if validate_types:
            self._validate_variables(variables, context)

        result = template
        missing_vars = []

        for var_name in variables:
            if var_name in context:
                value = context[var_name]
                # Convert to text only. Values are not escaped here: each sink
                # must apply its own context-specific encoding or validation.
                str_value = self._format_value(value)
                result = result.replace(f"{{{var_name}}}", str_value)
                await self._log(
                    "DEBUG",
                    f"Substituted {{{var_name}}} from runtime context",
                    dut_id,
                )
            else:
                missing_vars.append(var_name)
                if not allow_missing:
                    raise VariableSubstitutionError(
                        f"Missing required variable: {var_name}"
                    )
                else:
                    await self._log(
                        "WARNING",
                        f"Missing variable {var_name}, keeping as-is",
                        dut_id,
                    )

        return result

    def _extract_variables(self, template: str) -> Set[str]:
        """
        Extract all variable names from a template string.

        The implementation uses ``template`` to extract all variable names from
        a template string.

        Args:
            template: Text supplied as template in the format accepted by this
                function.

        Returns:
            The validated ``variables``.
        """
        variables = set()
        for match in self.variable_pattern.finditer(template):
            variables.add(match.group(1))
        return variables

    def _validate_variables(self, variables: Set[str], context: Dict[str, Any]) -> None:
        """
        Validate variable types and values.

        Check if we have a type definition for this variable.

        Args:
            variables: Entries supplied as ``variables`` without transferring
                container ownership.
            context: Runtime context carrying state shared across this
                operation.

        Raises:
            VariableSubstitutionError: If variable ``var_name`` value
                '``str_value``' does not match expected pattern: ``pattern``;
                variable ``var_name`` cannot be None; or variable ``var_name``
                cannot be converted to string: ``e``.
        """
        for var_name in variables:
            if var_name in context:
                value = context[var_name]

                # Check if we have a type definition for this variable
                if var_name in self.variable_types:
                    pattern = self.variable_types[var_name]
                    str_value = str(value)
                    if not re.match(pattern, str_value):
                        raise VariableSubstitutionError(
                            f"Variable {var_name} value '{str_value}' does not match expected pattern: {pattern}"
                        )

                # Validate basic type if it's a known type
                if isinstance(value, (int, float, str, bool)):
                    # Basic type validation passed
                    pass
                elif value is None:
                    raise VariableSubstitutionError(
                        f"Variable {var_name} cannot be None"
                    )
                else:
                    # For complex types, try to convert to string
                    try:
                        str(value)
                    except Exception as e:
                        raise VariableSubstitutionError(
                            f"Variable {var_name} cannot be converted to string: {e}"
                        )

    def _format_value(self, value: Any) -> str:
        """
        Format a value for substitution, handling different types.

        The implementation uses ``value`` to format a value for substitution,
        handling different types. The source value keeps its ownership while the
        normalized representation is returned separately.

        Args:
            value: Value evaluated while performing value for substitution,
                handling different types.

        Returns:
            The canonical value.
        """
        if value is None:
            return ""
        elif isinstance(value, bool):
            return str(value).lower()
        elif isinstance(value, (int, float)):
            return str(value)
        elif isinstance(value, str):
            return value
        else:
            # For complex types, convert to string
            return str(value)

    async def _handle_nested_substitution(
        self,
        template: str,
        context: Dict[str, Any],
        dut_id: str,
        validate_types: bool,
        allow_missing: bool,
        max_depth: int = 10,
        trusted_templates: Dict[str, str] = None,
    ) -> str:
        """
        Resolve a template with explicit, trusted nested template fragments.

        This compatibility helper no longer reparses arbitrary resolver output.
        Callers that intentionally use nested, operator-authored fragments must
        provide them separately via ``trusted_templates``.

        Args:
            template: Text supplied as template in the format accepted by this
                function.
            context: Runtime context carrying state shared across this
                operation.
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
            validate_types: Whether validate types is enabled or required for
                this operation.
            allow_missing: Whether allow missing is enabled or required for this
                operation.
            max_depth: Upper bound enforced for max depth; the consuming
                boundary rejects or truncates values that exceed it.
            trusted_templates: Optional trusted templates; ``None`` selects the
                function's default behavior.

        Returns:
            The canonical handle nested substitution text.

        Raises:
            VariableSubstitutionError: If max_depth cannot be negative.
        """
        if max_depth < 0:
            raise VariableSubstitutionError("max_depth cannot be negative")

        return await self._resolve_approved_template(
            template,
            context,
            dut_id,
            validate_types,
            allow_missing,
            dict(trusted_templates or {}),
            max_depth,
        )

    def _generate_cache_key(
        self,
        template: str,
        context: Dict[str, Any],
        *,
        trusted_templates: Dict[str, str] = None,
        validate_types: bool = True,
        allow_missing: bool = False,
        max_depth: int = 10,
    ) -> str:
        """
        Generate a cache key for the template and context combination.

        The implementation uses ``template``, ``context``,
        ``trusted_templates``, ``validate_types``, and ``allow_missing`` to
        generate a cache key for the template and context combination.

        Args:
            template: Text supplied as template in the format accepted by this
                function.
            context: Runtime context carrying state shared across this
                operation.
            trusted_templates: Optional trusted templates; ``None`` selects the
                function's default behavior.
            validate_types: Whether validate types is enabled or required for
                this operation.
            allow_missing: Whether allow missing is enabled or required for this
                operation.
            max_depth: Upper bound enforced for max depth; the consuming
                boundary rejects or truncates values that exceed it.

        Returns:
            The canonical generate cache key text.
        """
        # Include behavior-affecting options so a permissive/missing result cannot
        # be reused by a stricter call with the same template and context.
        context_str = str(sorted(context.items()))
        trusted_template_str = str(sorted((trusted_templates or {}).items()))
        options = (validate_types, allow_missing, max_depth)
        return (
            f"{hash(template)}:{hash(context_str)}:"
            f"{hash(trusted_template_str)}:{hash(options)}"
        )

    def _cache_result(self, cache_key: str, result: str) -> None:
        """
        Cache a substitution result.

        The implementation uses ``cache_key`` and ``result`` to cache a
        substitution result.

        Args:
            cache_key: Stable cache key used for lookup and operator-facing
                diagnostics.
            result: Text supplied as result in the format accepted by this
                function.
        """
        if len(self.substitution_cache) >= self.cache_size:
            # Remove oldest entry (simple FIFO)
            oldest_key = next(iter(self.substitution_cache))
            del self.substitution_cache[oldest_key]

        self.substitution_cache[cache_key] = result

    async def get_cache_stats(self, dut_id: str = None) -> Dict[str, Any]:
        """
        Get cache statistics.

        The implementation uses ``dut_id`` to get cache statistics. Owned
        asynchronous work is awaited before return, so completion does not leave
        an unobserved task behind.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.

        Returns:
            The validated ``stats``.
        """
        stats = {
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_size": len(self.substitution_cache),
            "max_cache_size": self.cache_size,
            "hit_ratio": (
                self.cache_hits / (self.cache_hits + self.cache_misses)
                if (self.cache_hits + self.cache_misses) > 0
                else 0
            ),
        }
        await self._log("INFO", f"Cache stats: {stats}", dut_id)
        return stats

    async def clear_cache(self, dut_id: str = None) -> None:
        """
        Clear the substitution cache.

        The implementation uses ``dut_id`` to clear the substitution cache.
        Owned asynchronous work is awaited before return, so completion does not
        leave an unobserved task behind. It updates ``cache_hits`` and
        ``cache_misses`` on the instance as part of that state transition.

        Args:
            dut_id: Stable DUT identifier used to correlate configuration, logs,
                and results.
        """
        self.substitution_cache.clear()
        self.cache_hits = 0
        self.cache_misses = 0
        await self._log("INFO", "Variable substitution cache cleared", dut_id)


# Backward compatibility - keep the old class name for existing code
VariableSubstitutionEngine = VariableSubstitutionService
