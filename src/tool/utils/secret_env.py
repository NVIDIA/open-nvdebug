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
Utilities for preventing CLI-bound secrets from leaking to child processes.

This module owns the secret env boundary and exposes
``is_secret_environment_name``, ``_is_secret_environment_name``,
``scrub_secret_environment``, ``scrubbed_child_environment``, and
``scrubbed_subprocess_environment``. Keeping those contracts together gives
importers one source of truth for their validation, lifecycle, and compatibility
behavior.
"""

import os
import re
from collections.abc import Mapping, MutableMapping
from typing import Dict, Iterable, Optional
from urllib.parse import unquote, urlsplit, urlunsplit

SECRET_ENVIRONMENT_VARIABLES = frozenset(
    {
        "NVDEBUG_BMC_PASSWORD",
        "NVDEBUG_BMC_SSH_PASSWORD",
        "NVDEBUG_BMC_REDFISH_PASSWORD",
        "NVDEBUG_HOST_PASSWORD",
        "NVDEBUG_HMC_PASSWORD",
        "NVDEBUG_HMC_SSH_PASSWORD",
        "NVDEBUG_SSH_PROXY_PASSWORD",
    }
)


_SECRET_ENVIRONMENT_NAME_RE = re.compile(
    r"(?:^|_)(?:password|passwd|pass|pwd|passphrase|secret|token|jwt|key|api_key|access_key|"
    r"private_key|authorization|cookie|credential|credentials)(?:$|_)",
    re.IGNORECASE,
)
_AUTH_KEY_NAME_RE = re.compile(
    r"(?:^|_)(?:nv)?auth_(?:key|token|config)(?:$|_)", re.IGNORECASE
)
_CONCATENATED_SECRET_ENVIRONMENT_NAME_RE = re.compile(
    r"(?:password|passwd|pwd|passphrase|secret|token|jwt|apikey|accesskey|"
    r"secretkey|privatekey|authorization|cookie|credential|credentials|"
    r"authkey|authtoken|authconfig)$",
    re.IGNORECASE,
)
_CONCATENATED_SECRET_ENVIRONMENT_NAMES = frozenset(
    {
        "DBPASS",
        "MYSQL_PWD",
        "PGPASSFILE",
        "PGPASSWORD",
        "REDISCLI_AUTH",
        "SSHPASS",
    }
)
_UNSAFE_CHILD_ENVIRONMENT_VARIABLES = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "GCONV_PATH",
        "GIT_ASKPASS",
        "IFS",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "PERL5LIB",
        "PERL5OPT",
        "PYTHONHOME",
        "PYTHONPATH",
        "RUBYOPT",
        "SSLKEYLOGFILE",
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "SUDO_ASKPASS",
    }
)
# Loader/interpreter control families whose namespace is open-ended, so a fixed
# name set cannot enumerate them. Mirroring the existing ``PYTHON`` prefix rule,
# any variable whose upper-cased name begins with one of these is a dynamic
# loader (``LD_*`` such as LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT/LD_PROFILE) or an
# exported shell function (``BASH_FUNC_*``) that must not be inherited by a
# spawned child even when a poisoned operator environment sets it.
_UNSAFE_CHILD_ENVIRONMENT_NAME_PREFIXES = (
    "PYTHON",
    "LD_",
    "BASH_FUNC_",
)


def _is_unsafe_child_environment_name(name: str) -> bool:
    """
    Return whether a name is a loader/exec control unsafe to inherit.

    The predicate centralizes the defense-in-depth denylist for the non-sudo
    child environment: an exact match against the fixed unsafe-name set or a
    case-insensitive match against the open-ended loader/interpreter prefix
    families (``PYTHON*``, ``LD_*``, ``BASH_FUNC_*``). The privileged (sudo)
    spawn path is separately protected by sudo ``env_reset`` and is unaffected.

    Args:
        name: Environment variable name proposed for the child environment.

    Returns:
        Whether the name denotes a dynamic-loader, interpreter, or exported
        shell-function control that must be removed from the child environment.
    """

    upper_name = str(name).upper()
    return bool(
        upper_name in _UNSAFE_CHILD_ENVIRONMENT_VARIABLES
        or upper_name.startswith(_UNSAFE_CHILD_ENVIRONMENT_NAME_PREFIXES)
    )


def is_secret_environment_name(name: str) -> bool:
    """
    Return whether an environment name conventionally carries a secret.

    After applying local validation, the function forwards ``name`` to ``bool``
    and preserves its return and exception contract.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.

    Returns:
        Whether an environment name conventionally carries a secret.
    """

    normalized = str(name)
    return bool(
        normalized.upper() in _CONCATENATED_SECRET_ENVIRONMENT_NAMES
        or _SECRET_ENVIRONMENT_NAME_RE.search(normalized)
        or _AUTH_KEY_NAME_RE.search(normalized)
        or _CONCATENATED_SECRET_ENVIRONMENT_NAME_RE.search(normalized)
    )


def _is_secret_environment_name(name: str) -> bool:
    """
    Compatibility alias for callers that imported the private helper.

    After applying local validation, the function forwards ``name`` to
    ``is_secret_environment_name`` and preserves its return and exception
    contract.

    Args:
        name: Stable name used for lookup and operator-facing diagnostics.

    Returns:
        Whether the compatibility alias for callers that imported the private
        helper operation succeeds.
    """

    return is_secret_environment_name(name)


def strip_url_userinfo(value: str) -> str:
    """
    Remove URL userinfo while preserving the destination and other components.

    Malformed or non-hierarchical values are returned unchanged so environment
    scrubbing remains total and cannot break process creation by raising.

    Args:
        value: Environment value which may contain a proxy-style URL.

    Returns:
        The URL without username/password userinfo, or the original value when
        it has no safely parseable authority.
    """
    try:
        parsed = urlsplit(str(value))
    except ValueError:
        return value
    if not parsed.scheme or not parsed.netloc or "@" not in parsed.netloc:
        return value
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc.rsplit("@", 1)[1],
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def extract_url_userinfo_secrets(value: str) -> tuple[str, ...]:
    """
    Return raw and decoded passwords carried in a URL authority.

    The helper intentionally returns no username-only values because usernames
    are identifiers rather than authentication secrets. Malformed URL values
    produce an empty result instead of affecting the caller's lifecycle.

    Args:
        value: Environment value which may contain URL userinfo.

    Returns:
        Distinct nonempty password spellings in deterministic order.
    """
    try:
        parsed = urlsplit(str(value))
        password = parsed.password
    except (UnicodeError, ValueError):
        return ()
    if not password:
        return ()
    decoded = unquote(password)
    return tuple(
        dict.fromkeys(candidate for candidate in (password, decoded) if candidate)
    )


def scrub_secret_environment(
    environment: Optional[MutableMapping[str, str]] = None,
    *,
    additional_variables: Iterable[str] = (),
) -> None:
    """
    Remove recognized secret inputs after the CLI has bound their values.

    The implementation uses ``environment`` and ``additional_variables`` to
    remove recognized secret inputs after the CLI has bound their values.

    Args:
        environment: Optional environment; ``None`` selects the function's
            default behavior.
        additional_variables: Entries supplied as ``additional_variables``
            without transferring container ownership.
    """
    target = os.environ if environment is None else environment
    for variable in (
        *SECRET_ENVIRONMENT_VARIABLES,
        *additional_variables,
    ):
        target.pop(variable, None)
    for variable in tuple(target):
        if _is_unsafe_child_environment_name(variable) or is_secret_environment_name(
            variable
        ):
            target.pop(variable, None)
        else:
            # Credentials can be embedded in any URL-valued setting (for
            # example DATABASE_URL, SENTRY_DSN, or a vendor endpoint), not
            # only the conventional proxy variables. The helper is a no-op
            # for ordinary or malformed values, so applying it uniformly
            # retains every non-userinfo environment value.
            target[variable] = strip_url_userinfo(target[variable])


def scrubbed_child_environment(
    overrides: Optional[Mapping[str, str]] = None,
    *,
    additional_variables: Iterable[str] = (),
) -> Dict[str, str]:
    """
    Return a child environment without inherited CLI-bound secrets.

    Explicit overrides are deliberately applied after scrubbing. Callers use
    them to grant one child process the minimum credentials it needs without
    leaving those credentials in the parent's ambient environment.

    Args:
        overrides: Optional overrides; ``None`` selects the function's default
            behavior.
        additional_variables: Entries supplied as ``additional_variables``
            without transferring container ownership.

    Returns:
        The validated ``environment``.
    """
    environment = dict(os.environ)
    scrub_secret_environment(
        environment,
        additional_variables=additional_variables,
    )
    if overrides:
        environment.update({str(key): str(value) for key, value in overrides.items()})
    return environment


def scrubbed_subprocess_environment(
    environment: Optional[Mapping[str, str]] = None,
    *,
    additional_variables: Iterable[str] = (),
) -> Dict[str, str]:
    """
    Scrub either an explicit subprocess environment or ambient state.

    Unlike ``scrubbed_child_environment(overrides)``, an explicitly supplied
    mapping is treated as inherited state, not as an authorization to grant
    secrets to the child.

    Args:
        environment: Optional environment; ``None`` selects the function's
            default behavior.
        additional_variables: Entries supplied as ``additional_variables``
            without transferring container ownership.

    Returns:
        The validated ``child_environment``.
    """
    child_environment = dict(os.environ if environment is None else environment)
    scrub_secret_environment(
        child_environment,
        additional_variables=additional_variables,
    )
    return child_environment
