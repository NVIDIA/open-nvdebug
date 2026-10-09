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
Shared SSH host-key verification policy helpers.

This module owns the ssh security boundary and exposes
``InsecureSSHHostKeyWarning``, ``normalize_ssh_tunnel_prefix``,
``_parse_legacy_ssh_host_key_controls``, ``infer_legacy_ssh_host_key_policy``,
and ``infer_legacy_ssh_known_hosts_file``. Keeping those contracts together
gives importers one source of truth for their validation, lifecycle, and
compatibility behavior.
"""

import re
import shlex
import warnings
from typing import Any, Dict, Optional

SSH_HOST_KEY_POLICIES = frozenset({"strict", "insecure"})
SSH_HOST_KEY_CONTROL_OPTIONS = frozenset(
    {"stricthostkeychecking", "userknownhostsfile"}
)
DEFAULT_SSH_TUNNEL_OPERATION_OPTIONS = "-4 -o LogLevel=ERROR -fNT"
DEFAULT_SSH_TUNNEL_PREFIX = "sshpass -d 0"
_LEGACY_SSH_TUNNEL_PREFIX = ("sshpass", "-p")
_DESCRIPTOR_SAFE_SSH_TUNNEL_PREFIX = ("sshpass", "-d", "0")
INSECURE_SSH_HOST_KEY_WARNING_MESSAGE = (
    "SECURITY WARNING: SSH host-key verification is disabled for all SSH routes "
    "on the affected DUT (BMC, HMC, Host, proxy/jump host, SFTP, and OpenSSH "
    "tunnels); connections are vulnerable to man-in-the-middle attacks"
)


class InsecureSSHHostKeyWarning(UserWarning):
    """
    Raised when SSH server identity verification is explicitly disabled.

    The type gives the insecure SSH host key warning responsibility a stable
    runtime boundary. Callers use the declared Python protocol instead of
    depending on its representation.
    """


def normalize_ssh_tunnel_prefix(value: Any) -> str:
    """
    Canonicalize the one legacy password prefix without accepting argv data.

    ``sshpass -p`` historically meant that the service would append a password
    to the command line. It is retained only as an exact migration alias and is
    rewritten to descriptor-zero mode. Any other prefix fails closed rather than
    becoming an operator-controlled command prefix.

    Args:
        value: Value evaluated while performing one legacy password prefix
            without accepting argv data.

    Returns:
        The validated ``DEFAULT_SSH_TUNNEL_PREFIX``.

    Raises:
        ValueError: If SSH_TUNNEL_PREFIX must use the documented descriptor-safe
            auth mode; SSH_TUNNEL_PREFIX contains invalid quoting; or
            SSH_TUNNEL_PREFIX is unsupported; use the documented descriptor-safe
            auth mode.
    """

    if not isinstance(value, str):
        raise ValueError(
            "SSH_TUNNEL_PREFIX must use the documented descriptor-safe auth mode"
        )
    try:
        tokens = tuple(shlex.split(value))
    except ValueError:
        raise ValueError("SSH_TUNNEL_PREFIX contains invalid quoting") from None
    if tokens in {
        _LEGACY_SSH_TUNNEL_PREFIX,
        _DESCRIPTOR_SAFE_SSH_TUNNEL_PREFIX,
    }:
        return DEFAULT_SSH_TUNNEL_PREFIX
    raise ValueError(
        "SSH_TUNNEL_PREFIX is unsupported; use the documented descriptor-safe auth mode"
    )


def _parse_legacy_ssh_host_key_controls(
    custom_options: Optional[str],
) -> Optional[Dict[str, Optional[str]]]:
    """
    Parse unique legacy host-key controls and reject malformed quoting.

    The implementation uses ``custom_options`` to parse unique legacy host-key
    controls and reject malformed quoting. Parsing or I/O must finish
    before the validated representation is made available to the caller. If the
    function cannot parse unique legacy host-key controls, its exception reaches
    the caller instead of being converted into a successful result.

    Args:
        custom_options: Text supplied as custom options in the format accepted
            by this function.

    Returns:
        A mapping containing legacy SSH host key controls, or ``None`` when the
        requested value is unavailable.

    Raises:
        ValueError: If SSH_TUNNEL_OPTIONS contains malformed quoting or duplicate
            host-key controls.
    """

    if not custom_options:
        return {}
    try:
        tokens = shlex.split(str(custom_options))
    except ValueError:
        raise ValueError("SSH_TUNNEL_OPTIONS contains invalid quoting") from None

    controlled: Dict[str, Optional[str]] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        option = None
        if token == "-o" and index + 1 < len(tokens):
            option = tokens[index + 1]
            index += 2
        elif token.startswith("-o") and len(token) > 2:
            option = token[2:].removeprefix("=")
            index += 1
        else:
            index += 1
            continue

        name_and_value = re.split(r"\s*=\s*|\s+", option.strip(), maxsplit=1)
        name = name_and_value[0].lower()
        if name not in SSH_HOST_KEY_CONTROL_OPTIONS:
            continue
        if name in controlled:
            raise ValueError(
                "SSH_TUNNEL_OPTIONS cannot contain duplicate host-key controls"
            )
        controlled[name] = name_and_value[1] if len(name_and_value) == 2 else None
    return controlled


def infer_legacy_ssh_host_key_policy(
    custom_options: Optional[str],
) -> Optional[str]:
    """
    Recognize an unambiguous legacy tunnel host-key policy.

    Older configurations expressed host-key policy only through
    ``SSH_TUNNEL_OPTIONS``. Preserve explicit strict or insecure intent while
    rejecting ambiguous trust sources and duplicate controls instead of silently
    reinterpreting them.

    Args:
        custom_options: Text supplied as custom options in the format accepted
            by this function.

    Returns:
        The canonical infer legacy SSH host key policy text, or ``None`` when
        the requested value is unavailable.

    Raises:
        ValueError: If legacy SSH_TUNNEL_OPTIONS sets UserKnownHostsFile without
            StrictHostKeyChecking; this cannot be safely mapped to nvdebug's
            strict/insecure policy. Remove the legacy host-key control and set
            ssh_host_key_policy='strict' with ssh_known_hosts_file, or set
            ssh_host_key_policy='insecure' explicitly; legacy SSH_TUNNEL_OPTIONS
            uses StrictHostKeyChecking=``normalized_strict_value``, which cannot
            be safely mapped to nvdebug's strict/insecure policy; remove that
            legacy control and set ssh_host_key_policy='strict' or
            ssh_host_key_policy='insecure' explicitly; legacy ssh_tunnel_options
            stricthostkeychecking lacks one of yes, true, no, false, or off;
            remove the legacy control and set ssh_host_key_policy='strict' or
            ssh_host_key_policy='insecure' explicitly; or
            stricthostkeychecking=yes/true lacks a valid known-hosts trust
            source; or another input invariant is violated.
    """

    controlled = _parse_legacy_ssh_host_key_controls(custom_options)
    if controlled is None:
        return None

    strict_present = "stricthostkeychecking" in controlled
    strict_value = controlled.get("stricthostkeychecking")
    normalized_strict_value = (
        strict_value.strip().lower() if isinstance(strict_value, str) else None
    )
    known_hosts_present = "userknownhostsfile" in controlled
    known_hosts_value = controlled.get("userknownhostsfile")
    normalized_known_hosts_value = (
        known_hosts_value.strip().lower()
        if isinstance(known_hosts_value, str)
        else None
    )

    if not strict_present:
        if known_hosts_present:
            raise ValueError(
                "Legacy SSH_TUNNEL_OPTIONS sets UserKnownHostsFile without "
                "StrictHostKeyChecking; this cannot be safely mapped to "
                "nvdebug's strict/insecure policy. Remove the legacy host-key "
                "control and set ssh_host_key_policy='strict' with "
                "ssh_known_hosts_file, or set ssh_host_key_policy='insecure' "
                "explicitly"
            )
        return None
    if normalized_strict_value in {"accept-new", "ask"}:
        raise ValueError(
            "Legacy SSH_TUNNEL_OPTIONS uses "
            f"StrictHostKeyChecking={normalized_strict_value}, which cannot be "
            "safely mapped to nvdebug's strict/insecure policy; remove that "
            "legacy control and set ssh_host_key_policy='strict' or "
            "ssh_host_key_policy='insecure' explicitly"
        )
    if normalized_strict_value not in {"yes", "true", "no", "false", "off"}:
        raise ValueError(
            "Legacy SSH_TUNNEL_OPTIONS StrictHostKeyChecking requires one of "
            "yes, true, no, false, or off; remove the legacy control and set "
            "ssh_host_key_policy='strict' or ssh_host_key_policy='insecure' "
            "explicitly"
        )
    known_hosts_is_trust_source = (
        isinstance(known_hosts_value, str)
        and bool(known_hosts_value.strip())
        and normalized_known_hosts_value not in {"none", "/dev/null"}
    )
    strict_enabled = normalized_strict_value in {"yes", "true"}
    if strict_enabled and known_hosts_present and not known_hosts_is_trust_source:
        raise ValueError(
            "StrictHostKeyChecking=yes/true requires a valid known-hosts trust source"
        )
    if strict_enabled:
        return "strict"
    if known_hosts_present and normalized_known_hosts_value not in {
        "none",
        "/dev/null",
    }:
        raise ValueError(
            "Legacy SSH_TUNNEL_OPTIONS combines an insecure "
            "StrictHostKeyChecking value with UserKnownHostsFile; this cannot "
            "be safely mapped to nvdebug's strict/insecure policy. Remove the "
            "legacy host-key controls and set ssh_host_key_policy='strict' "
            "with ssh_known_hosts_file, or set ssh_host_key_policy='insecure' "
            "explicitly"
        )
    # An explicit legacy StrictHostKeyChecking=no/false/off setting remains a
    # supported insecure setting. Omission of host-key controls retains the
    # accepted password-only compatibility default.
    return "insecure"


def infer_legacy_ssh_known_hosts_file(
    custom_options: Optional[str],
) -> Optional[str]:
    """
    Return a unique usable legacy ``UserKnownHostsFile`` value.

    The caller decides the effective dedicated policy. Separating path
    extraction from policy inference preserves explicit strict configurations
    which historically supplied only ``UserKnownHostsFile`` in the legacy option
    string; the strict resolver adds ``StrictHostKeyChecking=yes``.

    Args:
        custom_options: Text supplied as custom options in the format accepted
            by this function.

    Returns:
        The validated ``known_hosts_file``, or ``None`` when no value qualifies.
    """

    controlled = _parse_legacy_ssh_host_key_controls(custom_options)
    if controlled is None:
        return None
    known_hosts_value = controlled.get("userknownhostsfile")
    if not isinstance(known_hosts_value, str):
        return None
    known_hosts_file = known_hosts_value.strip()
    if known_hosts_file and known_hosts_file.lower() not in {
        "none",
        "/dev/null",
    }:
        return known_hosts_file
    return None


def canonical_openssh_host_key_alias(host: str, port: int = 22) -> str:
    """
    Return the exact known_hosts identity for a logical SSH endpoint.

    OpenSSH uses ``HostKeyAlias`` verbatim. A non-default logical port must
    therefore be encoded in the alias instead of inheriting a temporary local
    forwarding port.

    Args:
        host: Text supplied as host in the format accepted by this function.
        port: Numeric port used while the operation performs bounded accounting.

    Returns:
        The canonical openssh host key alias text.

    Raises:
        ValueError: If ssh host-key alias lacks a non-empty logical host; or the
            ssh host-key alias port is not between 1 and 65535.
    """

    normalized_host = str(host or "").strip()
    if not normalized_host:
        raise ValueError("SSH host-key alias requires a non-empty logical host")
    if normalized_host.startswith("[") and normalized_host.endswith("]"):
        normalized_host = normalized_host[1:-1]
    normalized_port = int(port)
    if not 1 <= normalized_port <= 65535:
        raise ValueError("SSH host-key alias port must be between 1 and 65535")
    if normalized_port == 22:
        return normalized_host
    return f"[{normalized_host}]:{normalized_port}"


def canonical_asyncssh_host_key_alias(host: str) -> str:
    """
    Return the bare logical host identity expected by AsyncSSH.

    AsyncSSH receives the connection port separately and applies OpenSSH
    ``known_hosts`` port formatting itself. Supplying an OpenSSH-style
    ``[host]:port`` alias here can also break host-certificate principal
    validation, where the alias is used verbatim.

    Args:
        host: Text supplied as host in the format accepted by this function.

    Returns:
        The validated ``normalized_host``.

    Raises:
        ValueError: If ssh host-key alias lacks a non-empty logical host.
    """

    normalized_host = str(host or "").strip()
    if not normalized_host:
        raise ValueError("SSH host-key alias requires a non-empty logical host")
    if normalized_host.startswith("[") and normalized_host.endswith("]"):
        normalized_host = normalized_host[1:-1]
    return normalized_host


def normalize_ssh_host_key_policy(policy: str) -> str:
    """
    Validate and normalize an SSH host-key verification policy.

    The implementation uses ``policy`` to validate and normalize an SSH host-key
    verification policy. Every required invariant is checked before a successful
    value is returned; invalid input follows the function's explicit exception
    path.

    Args:
        policy: Policy governing and normalize an SSH host-key verification
            policy.

    Returns:
        The validated ``normalized``.

    Raises:
        ValueError: If the ssh_host_key_policy is not either 'strict' or
            'insecure'.
    """

    # Wrapper APIs own their documented defaults. Once a value reaches this
    # validator, omission/empty text is a caller bug and must not silently pick
    # a second, contradictory default.
    normalized = str(policy).strip().lower()
    if normalized not in SSH_HOST_KEY_POLICIES:
        raise ValueError("ssh_host_key_policy must be either 'strict' or 'insecure'")
    if normalized == "insecure":
        warnings.warn(
            INSECURE_SSH_HOST_KEY_WARNING_MESSAGE,
            InsecureSSHHostKeyWarning,
            stacklevel=2,
        )
    return normalized


def asyncssh_host_key_options(
    policy: str = "insecure",
    known_hosts_file: Optional[str] = None,
    host_key_alias: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Return AsyncSSH keyword arguments for the selected trust policy.

    Omitting ``known_hosts`` is intentional for strict mode: AsyncSSH then uses
    its normal OpenSSH-compatible known-hosts lookup. Supplying ``None`` is
    reserved for the explicit insecure override.

    Args:
        policy: Policy governing asyncSSH keyword arguments for the selected
            trust policy.
        known_hosts_file: Optional filesystem location used as the known hosts
            file for this operation.
        host_key_alias: Optional host key alias; ``None`` selects the function's
            default behavior.

    Returns:
        A mapping containing asyncssh host key options.
    """

    normalized = normalize_ssh_host_key_policy(policy)
    options: Dict[str, Any] = {}
    if host_key_alias:
        options["host_key_alias"] = str(host_key_alias)
    if normalized == "insecure":
        options["known_hosts"] = None
        return options
    if known_hosts_file:
        options["known_hosts"] = str(known_hosts_file)
    return options


def openssh_host_key_options(
    policy: str = "insecure",
    known_hosts_file: Optional[str] = None,
) -> str:
    """
    Return shell-safe OpenSSH options for the selected trust policy.

    After applying local validation, the function forwards ``policy`` and
    ``known_hosts_file`` to ``_openssh_host_key_options`` and preserves its
    return and exception contract.

    Args:
        policy: Policy governing shell-safe OpenSSH options for the selected
            trust policy.
        known_hosts_file: Optional filesystem location used as the known hosts
            file for this operation.

    Returns:
        The canonical openssh host key options text.
    """

    normalized = normalize_ssh_host_key_policy(policy)
    return _openssh_host_key_options(normalized, known_hosts_file)


def _openssh_host_key_options(
    normalized_policy: str,
    known_hosts_file: Optional[str],
) -> str:
    """
    Build OpenSSH options for an already validated policy.

    The implementation uses ``normalized_policy`` and ``known_hosts_file`` to
    build OpenSSH options for an already validated policy.

    Args:
        normalized_policy: Normalized policy governing openSSH options for an
            already validated policy.
        known_hosts_file: filesystem location used as the known hosts file for
            this operation.

    Returns:
        The canonical openssh host key options text.
    """

    if normalized_policy == "insecure":
        return "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

    options = "-o StrictHostKeyChecking=yes"
    if known_hosts_file:
        options += f" -o UserKnownHostsFile={shlex.quote(str(known_hosts_file))}"
    return options


def default_ssh_tunnel_options(
    policy: str = "insecure",
    known_hosts_file: Optional[str] = None,
    *,
    force_ipv4: bool = True,
) -> str:
    """
    Build the standard SSH tunnel options with authenticated host keys.

    The implementation uses ``policy``, ``known_hosts_file``, and ``force_ipv4``
    to build the standard SSH tunnel options with authenticated host keys.

    Args:
        policy: Policy governing standard SSH tunnel options with authenticated
            host keys.
        known_hosts_file: Optional filesystem location used as the known hosts
            file for this operation.
        force_ipv4: Whether force ipv4 is enabled or required for this
            operation.

    Returns:
        The canonical default SSH tunnel options text.
    """

    host_key_options = openssh_host_key_options(policy, known_hosts_file)
    operation_options = (
        DEFAULT_SSH_TUNNEL_OPERATION_OPTIONS
        if force_ipv4
        else DEFAULT_SSH_TUNNEL_OPERATION_OPTIONS.removeprefix("-4 ").strip()
    )
    return f"{operation_options} {host_key_options}"


def resolve_ssh_tunnel_options(
    custom_options: Optional[str],
    policy: str = "insecure",
    known_hosts_file: Optional[str] = None,
    *,
    force_ipv4: bool = True,
) -> str:
    """
    Apply the policy to custom tunnel options without allowing bypasses.

    The resolver may be reached by both the proxy and port-forwarding layers, so
    applying it to its own output must be a fixpoint.

    Args:
        custom_options: Text supplied as custom options in the format accepted
            by this function.
        policy: Policy governing apply the policy to custom tunnel options
            without allowing bypasses.
        known_hosts_file: Optional filesystem location used as the known hosts
            file for this operation.
        force_ipv4: Whether force ipv4 is enabled or required for this
            operation.

    Returns:
        The canonical SSH tunnel options text.

    Raises:
        ValueError: If SSH_TUNNEL_OPTIONS cannot contain duplicate host-key
            controls; use the dedicated SSH host-key policy fields; or
            SSH_TUNNEL_OPTIONS cannot weaken the strict host-key policy; keep
            StrictHostKeyChecking=yes/true and configure a valid known-hosts
            trust source.
    """

    normalized_policy = normalize_ssh_host_key_policy(policy)
    if not custom_options:
        custom_options = (
            DEFAULT_SSH_TUNNEL_OPERATION_OPTIONS
            if force_ipv4
            else DEFAULT_SSH_TUNNEL_OPERATION_OPTIONS.removeprefix("-4 ").strip()
        )

    tokens = shlex.split(str(custom_options))
    controlled: Dict[str, Optional[str]] = {}
    filtered_tokens = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        option = None
        if token == "-o" and index + 1 < len(tokens):
            option = tokens[index + 1]
        elif token.startswith("-o") and len(token) > 2:
            # OpenSSH accepts both ``-oName=value`` and ``-o=Name=value``.
            # Normalize the optional separator before identifying controls.
            option = token[2:].removeprefix("=")
        if option:
            name_and_value = re.split(r"\s*=\s*|\s+", option.strip(), maxsplit=1)
            name = name_and_value[0].lower()
            value = name_and_value[1] if len(name_and_value) == 2 else None
            if name in SSH_HOST_KEY_CONTROL_OPTIONS and name in controlled:
                raise ValueError(
                    "SSH_TUNNEL_OPTIONS cannot contain duplicate host-key "
                    "controls; use the dedicated SSH host-key policy fields"
                )
            controlled[name] = value
            if normalized_policy == "insecure" and name in SSH_HOST_KEY_CONTROL_OPTIONS:
                index += 2 if token == "-o" else 1
                continue
        filtered_tokens.append(token)
        index += 1

    controlled_names = set(controlled).intersection(SSH_HOST_KEY_CONTROL_OPTIONS)
    if normalized_policy == "insecure":
        custom_prefix = shlex.join(filtered_tokens)
        insecure_controls = _openssh_host_key_options("insecure", None)
        return (
            f"{custom_prefix} {insecure_controls}"
            if custom_prefix
            else insecure_controls
        )

    if controlled_names:
        strict_present = "stricthostkeychecking" in controlled
        strict_value = controlled.get("stricthostkeychecking")
        known_hosts_present = "userknownhostsfile" in controlled
        known_hosts_value = controlled.get("userknownhostsfile")
        known_hosts_is_trust_source = (
            isinstance(known_hosts_value, str)
            and bool(known_hosts_value.strip())
            and known_hosts_value.strip().lower() not in {"none", "/dev/null"}
        )
        known_hosts_matches = (
            not known_hosts_present
            or (known_hosts_file is None and known_hosts_is_trust_source)
            or (
                known_hosts_file is not None
                and known_hosts_value == str(known_hosts_file)
            )
        )
        strict_value_is_enabled = isinstance(
            strict_value, str
        ) and strict_value.strip().lower() in {"yes", "true"}
        if (strict_present and not strict_value_is_enabled) or not known_hosts_matches:
            raise ValueError(
                "SSH_TUNNEL_OPTIONS cannot weaken the strict host-key policy; "
                "keep StrictHostKeyChecking=yes/true and configure a valid "
                "known-hosts trust source"
            )

    missing_controls = []
    if "stricthostkeychecking" not in controlled:
        missing_controls.append("-o StrictHostKeyChecking=yes")
    if known_hosts_file is not None and "userknownhostsfile" not in controlled:
        missing_controls.append(
            "-o UserKnownHostsFile=" f"{shlex.quote(str(known_hosts_file))}"
        )
    if not missing_controls:
        return str(custom_options)
    return f"{custom_options} {' '.join(missing_controls)}"
