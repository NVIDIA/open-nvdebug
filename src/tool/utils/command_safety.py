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
Safe command construction utilities for open-nvdebugtool.

Prevents shell command injection by providing:

- quote_arg(): Shell-safe argument quoting via shlex.quote.
- build_remote_cmd(): Build quoted commands for SSH remote execution.
- build_local_cmd(): Build argument lists for subprocess (no shell).
- safe_subprocess_run(): subprocess.run wrapper that forbids shell=True.
"""

import ipaddress
import os
import re
import shlex
import subprocess
from collections.abc import Sequence
from typing import Any, List, Optional, Tuple, Union

from .secret_env import scrubbed_subprocess_environment

# Output signatures a BMC shell emits when a command produced no usable data
# even though it may have exited 0. Known modes on these platforms:
#   * restricted shell cannot deliver stdout ("Duplicated file pointer is NULL
#     / stdout redirection error"), and
#   * the SSH session cap is hit ("...can't establish more than N active
#     sessions / please close any one of the active session"), and
#   * the SOLSSH command service is disabled, or opens a SOL-agent serial port
#     instead of running the command, while the transport still returns exit
#     code 0.
# This is a best-effort diagnostic denylist over endpoint-controlled text. It
# recognises only the modes listed above: other failure wording is not detected,
# and a valid payload containing one of these phrases can be a false positive.
# Callers must use positive parsing or expected-output contracts when validity
# matters; a signature match is routed only as diagnostic evidence.
BMC_COMMAND_FAILURE_SIGNATURES = (
    "duplicated file pointer is null",
    "stdout redirection error",
    "establish more than",
    "close any one of the active session",
    "solssh service is disabled",
    "open sol serial port by sol agent",
)
_PURE_LOCAL_SUBSTITUTION = re.compile(r"^\{[A-Za-z_][A-Za-z0-9_]*\}$")
_PING_HOSTNAME = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?\Z")
_SHELL_TEMPLATE_PLACEHOLDER = re.compile(
    r"(?<![$\\{])\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}"
)

TRUSTED_PRIVILEGED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
TRUSTED_REMOTE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
TRUSTED_SUDO_PATH = "/usr/bin/sudo"
TRUSTED_ENV_PATH = "/usr/bin/env"
TRUSTED_POSIX_SHELL_PATH = "/bin/sh"
TRUSTED_IPMITOOL_PATHS = (
    "/usr/bin/ipmitool",
    "/usr/local/bin/ipmitool",
)
# Compatibility alias for callers which need the preferred path as a stable
# constant. Execution paths must resolve or select from the full allowlist.
TRUSTED_IPMITOOL_PATH = TRUSTED_IPMITOOL_PATHS[0]
TRUSTED_IPMITOOL_NOT_FOUND_MESSAGE = (
    "No trusted ipmitool executable found; checked: "
    + ", ".join(TRUSTED_IPMITOOL_PATHS)
)

_SUPPORTED_SUDO_EXECUTABLES = frozenset({"sudo", TRUSTED_SUDO_PATH})
_SUDO_PASSWORD_MODE = "password"  # pragma: allowlist secret
_SUDO_NONINTERACTIVE_MODE = "noninteractive"


def resolve_trusted_ipmitool_path() -> Optional[str]:
    """
    Resolve the first executable ipmitool path from the reviewed allowlist.

    The fixed candidate order preserves the conventional system location while
    supporting appliances which install ipmitool under ``/usr/local``. The
    process ``PATH`` is deliberately ignored so an untrusted executable cannot
    enter a privileged or credential-bearing command.

    Returns:
        The first approved absolute path which names an executable regular
        file, or ``None`` when no approved candidate is available.
    """

    for candidate in TRUSTED_IPMITOOL_PATHS:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def build_trusted_ipmitool_selection_script() -> str:
    """
    Build a POSIX-shell fragment which selects an approved ipmitool binary.

    Candidate paths and the failure diagnostic come only from project-owned
    constants. The fragment stores the selected absolute path in
    ``nvdebug_ipmitool_path`` and never consults ``PATH`` or ``command -v``.

    Returns:
        A shell fragment which selects an executable approved candidate or
        exits with status 127 and a deterministic diagnostic.
    """

    candidates = " ".join(shlex.quote(path) for path in TRUSTED_IPMITOOL_PATHS)
    diagnostic = shlex.quote(TRUSTED_IPMITOOL_NOT_FOUND_MESSAGE)
    return (
        'nvdebug_ipmitool_path=""\n'
        f"for nvdebug_ipmitool_candidate in {candidates}; do\n"
        '    if [ -x "$nvdebug_ipmitool_candidate" ]; then\n'
        "        nvdebug_ipmitool_path=$nvdebug_ipmitool_candidate\n"
        "        break\n"
        "    fi\n"
        "done\n"
        'if [ -z "$nvdebug_ipmitool_path" ]; then\n'
        f"    printf '%s\\n' {diagnostic} >&2\n"
        "    exit 127\n"
        "fi"
    )


def build_trusted_ipmitool_remote_command(arguments: Sequence[Any]) -> str:
    """
    Build a remote command using only an allowlisted ipmitool executable.

    The remote shell receives caller values as positional parameters rather
    than interpolated program text. A fixed ``PATH`` is exported for supporting
    utilities, while ipmitool itself is selected only from reviewed absolute
    paths.

    Args:
        arguments: Command arguments forwarded to ipmitool in their original
            order. Values are rendered as text and must not contain NUL.

    Returns:
        A shell-quoted command suitable for an SSH command channel.

    Raises:
        TypeError: If ``arguments`` is a string or bytes object instead of a
            sequence of argument values.
        ValueError: If a rendered argument contains a NUL character.
    """

    if isinstance(arguments, (str, bytes)):
        raise TypeError("ipmitool arguments must be a sequence of values")
    normalized_arguments = []
    for argument in arguments:
        rendered_argument = str(argument)
        if "\x00" in rendered_argument:
            raise ValueError("ipmitool arguments cannot contain NUL characters")
        normalized_arguments.append(rendered_argument)

    script = (
        "set -eu\n"
        f"PATH={TRUSTED_PRIVILEGED_PATH}\n"
        "export PATH\n"
        f"{build_trusted_ipmitool_selection_script()}\n"
        'exec "$nvdebug_ipmitool_path" "$@"'
    )
    return shlex.join(
        [
            TRUSTED_POSIX_SHELL_PATH,
            "-c",
            script,
            "nvdebug-ipmitool",
            *normalized_arguments,
        ]
    )


# Read the credential in the shell rather than allowing the elevated payload to
# share sudo's stdin.  The validation-only sudo receives a dedicated pipe, so a
# cached or NOPASSWD policy cannot leave the password for the payload to read.
# Keep both sudo processes as children of this shell so process-scoped sudo
# timestamps established by ``-v`` are available to the noninteractive launch.
# Capturing the final status prevents shells such as Bash from replacing
# themselves with the last sudo process and thereby changing its parent ID.
_SUDO_PASSWORD_GATE_SCRIPT = (
    "IFS= read -r nvdebug_sudo_password || exit 1\n"
    "if ! printf '%s\\n' \"$nvdebug_sudo_password\" | "
    f"{TRUSTED_SUDO_PATH} -S -p '' -v >/dev/null\n"
    "then\n"
    "    unset nvdebug_sudo_password\n"
    "    exit 1\n"
    "fi\n"
    "unset nvdebug_sudo_password\n"
    f'{TRUSTED_SUDO_PATH} -n -- "$@"\n'
    "nvdebug_sudo_status=$?\n"
    'exit "$nvdebug_sudo_status"'
)


def validate_password_stdin_line(
    password: Optional[str], *, credential_name: str
) -> None:
    """
    Reject credentials which cannot be isolated to one receiver input line.

    The implementation uses ``password`` and ``credential_name`` to reject
    credentials which cannot be isolated to one receiver input line. Every
    required invariant is checked before a successful value is returned; invalid
    input follows the function's explicit exception path.

    Args:
        password: Sensitive value supplied through the approved input boundary
            and never logged.
        credential_name: Sensitive value supplied through the approved input
            boundary and never logged.

    Raises:
        TypeError: If the ``credential_name`` is not a string.
        ValueError: If ``credential_name`` cannot contain CR, LF, or NUL
            characters.
    """

    if password is None:
        return
    if not isinstance(password, str):
        raise TypeError(f"{credential_name} must be a string")
    if any(delimiter in password for delimiter in ("\r", "\n", "\x00")):
        raise ValueError(f"{credential_name} cannot contain CR, LF, or NUL characters")


def _pop_unquoted_shell_token(value: str) -> Tuple[str, str]:
    """
    Pop one option-like token without interpreting the remaining shell body.

    The implementation uses ``value`` to pop one option-like token without
    interpreting the remaining shell body.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        A tuple containing the leading unquoted token and the remaining shell
        body, with empty strings when no token can be parsed.
    """

    match = re.match(r"\A(\S+)(?:\s+(.*))?\Z", value, flags=re.DOTALL)
    if match is None:
        return "", ""
    return match.group(1), match.group(2) or ""


def _is_sudo_executable(value: str) -> bool:
    """
    Return whether ``value`` is sudo executable.

    The implementation uses ``value`` to determine whether ``value`` is sudo
    executable.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        Whether ``value`` is sudo executable.
    """
    return value == "sudo" or value.endswith("/sudo")


def _reject_obscured_leading_sudo(command: str) -> None:
    """
    Reject quoted or escaped sudo spellings the strict parser will not strip.

    The implementation uses ``command`` to reject quoted or escaped sudo
    spellings the strict parser will not strip. Every required invariant is
    checked before a successful value is returned; invalid input follows the
    function's explicit exception path.

    Args:
        command: Text supplied as command in the format accepted by this
            function.

    Raises:
        ValueError: If privileged command contains invalid shell quoting; or
            leading sudo executable must not be quoted or escaped.
    """

    try:
        parsed = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValueError("privileged command contains invalid shell quoting") from exc
    if not parsed or not _is_sudo_executable(parsed[0]):
        return
    raw_executable, _remainder = _pop_unquoted_shell_token(command)
    if raw_executable != parsed[0]:
        raise ValueError("leading sudo executable must not be quoted or escaped")


def _strip_supported_sudo_shell_prefix(command: str) -> Tuple[str, Optional[str]]:
    """
    Remove a supported leading sudo form while retaining the exact shell body.

    The implementation uses ``command`` to remove a supported leading sudo form
    while retaining the exact shell body. If the function cannot remove a
    supported leading sudo form while retaining the exact shell body, its
    exception reaches the caller instead of being converted into a successful
    result.

    Args:
        command: Text supplied as command in the format accepted by this
            function.

    Returns:
        A tuple containing the shell body with an accepted sudo prefix removed
        and its password mode, or the original command and ``None`` when no
        sudo prefix is present.

    Raises:
        TypeError: If the privileged shell command is not a string.
        ValueError: If privileged command cannot be empty; unsupported sudo
            executable ``executable``; expected ``TRUSTED_SUDO_PATH``; sudo
            command is missing its executable; or unsupported pre-supplied sudo
            option: ``token``.
    """

    if not isinstance(command, str):
        raise TypeError("privileged shell command must be a string")
    stripped = command.lstrip()
    if not stripped:
        raise ValueError("privileged command cannot be empty")
    _reject_obscured_leading_sudo(stripped)

    executable, remainder = _pop_unquoted_shell_token(stripped)
    if executable not in _SUPPORTED_SUDO_EXECUTABLES:
        if _is_sudo_executable(executable):
            raise ValueError(
                f"unsupported sudo executable {executable!r}; "
                f"expected {TRUSTED_SUDO_PATH}"
            )
        return command, None

    if not remainder:
        raise ValueError("sudo command is missing its executable")

    mode: Optional[str] = None
    token, tail = _pop_unquoted_shell_token(remainder)
    if token in {"-S", "-n"}:
        mode = _SUDO_PASSWORD_MODE if token == "-S" else _SUDO_NONINTERACTIVE_MODE
        remainder = tail
        if not remainder:
            raise ValueError("sudo command is missing its executable")
        token, tail = _pop_unquoted_shell_token(remainder)

    if token == "--":
        remainder = tail
    elif token.startswith("-"):
        raise ValueError(f"unsupported pre-supplied sudo option: {token}")

    if not remainder:
        raise ValueError("sudo command is missing its executable")
    return remainder, mode


def _strip_supported_sudo_argv_prefix(
    command: Sequence[str],
) -> Tuple[List[str], Optional[str]]:
    """
    Remove a supported leading sudo argv form without losing arguments.

    The implementation uses ``command`` to remove a supported leading sudo argv
    form without losing arguments. If the function cannot remove a supported
    leading sudo argv form without losing arguments, its exception reaches the
    caller instead of being converted into a successful result.

    Args:
        command: Entries supplied as ``command`` without transferring container
            ownership.

    Returns:
        A tuple containing ``arguments`` and ``status or message text`` in that
        order.

    Raises:
        TypeError: If the privileged argv command is not a sequence of strings.
        ValueError: If privileged argv command must contain nonempty strings;
            unsupported sudo executable ``executable``; expected
            ``TRUSTED_SUDO_PATH``; sudo command is missing its executable; or
            the supplied input cannot be used to remove a supported leading sudo
            argv form without losing arguments.
    """

    if isinstance(command, (str, bytes)) or not isinstance(command, Sequence):
        raise TypeError("privileged argv command must be a sequence of strings")
    if not command or any(not isinstance(value, str) or not value for value in command):
        raise ValueError("privileged argv command must contain nonempty strings")

    arguments = list(command)
    executable = arguments[0]
    if executable not in _SUPPORTED_SUDO_EXECUTABLES:
        if _is_sudo_executable(executable):
            raise ValueError(
                f"unsupported sudo executable {executable!r}; "
                f"expected {TRUSTED_SUDO_PATH}"
            )
        return arguments, None

    arguments.pop(0)
    if not arguments:
        raise ValueError("sudo command is missing its executable")

    mode: Optional[str] = None
    if arguments[0] in {"-S", "-n"}:
        option = arguments.pop(0)
        mode = _SUDO_PASSWORD_MODE if option == "-S" else _SUDO_NONINTERACTIVE_MODE
    if arguments and arguments[0] == "--":
        arguments.pop(0)
    elif arguments and arguments[0].startswith("-"):
        raise ValueError(f"unsupported pre-supplied sudo option: {arguments[0]}")
    if not arguments:
        raise ValueError("sudo command is missing its executable")
    return arguments, mode


def build_privileged_command_argv(
    command: Union[str, Sequence[str]],
    *,
    password_available: bool,
    use_shell: bool,
    already_root: bool = False,
) -> Tuple[List[str], bool]:
    """
    Build privileged command argument vector.

    The implementation uses ``command``, ``password_available``, ``use_shell``,
    and ``already_root`` to build privileged command argument vector. If the
    function cannot build privileged command argument vector, its exception
    reaches the caller instead of being converted into a successful result.

    Args:
        command: Entries supplied as ``command`` without transferring container
            ownership.
        password_available: Sensitive value supplied through the approved input
            boundary and never logged.
        use_shell: Whether use shell is enabled or required for this operation.
        already_root: filesystem location used as the already root for this
            operation.

    Returns:
        A tuple containing ``selected entries`` and ``status flag`` in that
        order.

    Raises:
        ValueError: If privileged command cannot be empty.
    """

    if isinstance(command, str):
        body, requested_mode = _strip_supported_sudo_shell_prefix(command)
        if use_shell:
            payload = [TRUSTED_POSIX_SHELL_PATH, "-c", body]
        else:
            payload = shlex.split(body)
    else:
        body_argv, requested_mode = _strip_supported_sudo_argv_prefix(command)
        payload = (
            [TRUSTED_POSIX_SHELL_PATH, "-c", shlex.join(body_argv)]
            if use_shell
            else body_argv
        )

    if not payload or (not use_shell and not payload[0]):
        raise ValueError("privileged command cannot be empty")

    trusted_payload = [
        TRUSTED_ENV_PATH,
        f"PATH={TRUSTED_PRIVILEGED_PATH}",
        *payload,
    ]
    if already_root:
        return trusted_payload, False

    password_stdin = bool(password_available) and (
        requested_mode != _SUDO_NONINTERACTIVE_MODE
    )
    if password_stdin:
        return [
            TRUSTED_POSIX_SHELL_PATH,
            "-c",
            _SUDO_PASSWORD_GATE_SCRIPT,
            "nvdebug-sudo-gate",
            *trusted_payload,
        ], True
    return [TRUSTED_SUDO_PATH, "-n", "--", *trusted_payload], False


def validate_ping_target(value: Any) -> str:
    """
    Return a host-only ping operand or reject ambiguous/option-like input.

    Accept plain IPv4, IPv6, and conservative DNS-style hostnames. Endpoint
    candidates may include a decimal port (``host:22`` or ``[IPv6]:22``); the
    port is validated and removed because ``ping`` accepts only a host.

    Args:
        value: Value object whose ``strip`` state is read while performing
            host-only ping operand or reject ambiguous/option-like input.

    Returns:
        The validated ``host``.

    Raises:
        TypeError: If the ping target is not a string.
        ValueError: If ping target is empty, padded, or option-like; ping target
            contains control characters; ping target has an invalid bracketed
            host; or ping target has invalid text after its host; or another
            input invariant is violated.
    """

    if not isinstance(value, str):
        raise TypeError("ping target must be a string")
    candidate = value.strip()
    if not candidate or candidate != value or candidate.startswith("-"):
        raise ValueError("ping target is empty, padded, or option-like")
    if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
        raise ValueError("ping target contains control characters")

    host = candidate
    port: Optional[str] = None
    if candidate.startswith("["):
        closing_bracket = candidate.find("]")
        if closing_bracket <= 1:
            raise ValueError("ping target has an invalid bracketed host")
        host = candidate[1:closing_bracket]
        suffix = candidate[closing_bracket + 1 :]
        if suffix:
            if not suffix.startswith(":"):
                raise ValueError("ping target has invalid text after its host")
            port = suffix[1:]
    else:
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            if candidate.count(":") == 1:
                host, port = candidate.rsplit(":", 1)
            elif ":" in candidate:
                raise ValueError("ping target has an invalid IPv6 address")

    if port is not None:
        if not port.isascii() or not port.isdecimal():
            raise ValueError("ping target port must be decimal")
        port_number = int(port)
        if not 1 <= port_number <= 65535:
            raise ValueError("ping target port is out of range")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        if (
            len(host) > 253
            or not _PING_HOSTNAME.fullmatch(host)
            or ".." in host
            or any(
                label.startswith("-") or label.endswith("-")
                for label in host.split(".")
            )
        ):
            raise ValueError("ping target host is invalid")
    return host


def is_bmc_command_failure_output(
    stdout: Optional[str], stderr: Optional[str] = None
) -> bool:
    """
    Return whether ``stdout`` is BMC command failure output.

    After applying local validation, the function forwards ``stdout`` and
    ``stderr`` to ``any`` and preserves its return and exception contract.

    Args:
        stdout: Text supplied as stdout in the format accepted by this function.
        stderr: Optional stderr; ``None`` selects the function's default
            behavior.

    Returns:
        Whether ``stdout`` is BMC command failure output.
    """
    combined = f"{stdout or ''}\n{stderr or ''}".lower()
    return any(sig in combined for sig in BMC_COMMAND_FAILURE_SIGNATURES)


def quote_arg(value: str) -> str:
    """
    Quote a single argument for safe shell interpolation.

    Uses shlex.quote which wraps the value in single quotes.

    Args:
        value: Text supplied as value in the format accepted by this function.

    Returns:
        The canonical quote arg text.

    Raises:
        TypeError: If quote_arg lacks a string, got ``__name__``.
    """
    if not isinstance(value, str):
        raise TypeError(f"quote_arg requires a string, got {type(value).__name__}")
    return shlex.quote(value)


def inspect_shell_template_placeholder_contexts(
    template: str,
) -> List[Tuple[re.Match[str], Optional[str], Optional[str]]]:
    """
    Inspect simple format fields without evaluating the shell template.

    The scanner tracks top-level single and double quotes, comments, and shell
    constructs that start a nested evaluation language. Once a nested language
    is encountered, later fields remain unsupported because proving its end
    requires a complete shell parser. Escaped braces, doubled braces, and shell
    parameter expansions are not treated as simple format fields.

    Args:
        template: Shell command template whose simple named fields are
            inspected.

    Returns:
        Tuples containing each field match, its quote context, and the first
        unsupported nested context preceding it. A ``None`` quote and nested
        context means the field is top-level and can accept ``shlex.quote``
        output safely.

    Raises:
        TypeError: If ``template`` is not a string.
    """
    if not isinstance(template, str):
        raise TypeError("shell command template must be a string")

    contexts: List[Tuple[re.Match[str], Optional[str], Optional[str]]] = []
    cursor = 0
    quote_context: Optional[str] = None
    unsupported_context: Optional[str] = None

    def advance_shell_context(segment: str) -> None:
        """
        Advance the conservative shell lexer over one literal segment.

        The lexer updates the enclosing function's quote and unsupported-state
        markers without evaluating or normalizing any command text.

        Args:
            segment: Literal template text preceding a simple format field.
        """
        nonlocal quote_context, unsupported_context
        if unsupported_context is not None:
            return

        index = 0
        while index < len(segment):
            character = segment[index]
            if quote_context == "comment":
                if character == "\n":
                    quote_context = None
                index += 1
                continue
            if quote_context == "single":
                if character == "'":
                    quote_context = None
                index += 1
                continue
            if quote_context == "double":
                if character == "\\":
                    index += 2
                    continue
                if character == '"':
                    quote_context = None
                    index += 1
                    continue
                if segment.startswith("$((", index):
                    unsupported_context = "arithmetic expansion"
                    return
                if segment.startswith("$(", index):
                    unsupported_context = "command substitution"
                    return
                if segment.startswith("${", index):
                    unsupported_context = "parameter expansion"
                    return
                if character == "`":
                    unsupported_context = "backtick command substitution"
                    return
                index += 1
                continue

            if character == "\\":
                index += 2
                continue
            if segment.startswith("$((", index):
                unsupported_context = "arithmetic expansion"
                return
            if segment.startswith("$(", index):
                unsupported_context = "command substitution"
                return
            if segment.startswith("${", index):
                unsupported_context = "parameter expansion"
                return
            if segment.startswith("$[", index):
                unsupported_context = "legacy arithmetic expansion"
                return
            if segment.startswith("$'", index):
                unsupported_context = "ANSI-C quoted string"
                return
            if segment.startswith('$"', index):
                unsupported_context = "locale-translated quoted string"
                return
            if character == "`":
                unsupported_context = "backtick command substitution"
                return
            if segment.startswith("<<<", index):
                index += 3
                continue
            if segment.startswith("<<", index):
                unsupported_context = "here-document"
                return
            if segment.startswith("((", index):
                unsupported_context = "arithmetic command"
                return
            if segment.startswith("<(", index) or segment.startswith(">(", index):
                unsupported_context = "process substitution"
                return
            if character == "'":
                quote_context = "single"
            elif character == '"':
                quote_context = "double"
            elif character == "#":
                quote_context = "comment"
            index += 1

    for match in _SHELL_TEMPLATE_PLACEHOLDER.finditer(template):
        advance_shell_context(template[cursor : match.start()])
        contexts.append((match, quote_context, unsupported_context))
        cursor = match.end()
    return contexts


def build_remote_cmd(template: str, **kwargs: str) -> str:
    """
    Build remote cmd.

    After applying local validation, the function forwards ``template`` and
    ``kwargs`` to ``template.format`` and preserves its return and exception
    contract.

    Args:
        template: Text supplied as template in the format accepted by this
            function.
        kwargs: Additional named values forwarded without changing their keys.

    Example:
        >>> build_remote_cmd("cat {path}", path="/var/log/syslog")
        "cat '/var/log/syslog'"

    Returns:
        The canonical remote cmd text.

    Raises:
        TypeError: If ``template`` is not a string.
        ValueError: If a substituted field occurs in a quoted, comment, or
            nested shell-evaluation context where top-level quoting cannot make
            its value data.
    """
    for (
        match,
        quote_context,
        unsupported_context,
    ) in inspect_shell_template_placeholder_contexts(template):
        if unsupported_context is not None or quote_context is not None:
            context = unsupported_context or f"{quote_context}-quoted context"
            raise ValueError(
                f"remote command placeholder {match.group('name')!r} must be "
                f"top-level and unquoted, not in {context}"
            )
    quoted_kwargs = {k: quote_arg(str(v)) for k, v in kwargs.items()}
    return template.format(**quoted_kwargs)


def build_trusted_remote_command(command: str) -> str:
    """
    Execute an authored remote shell program with a fixed system search path.

    Remote login accounts can receive a restricted ``PATH`` which omits
    standard system directories. The complete authored command remains one
    argument to the trusted POSIX shell, preserving its pipes and redirections
    while preventing the caller's login environment from selecting executable
    locations. An empty command remains empty so connection-only SSH probes do
    not start a remote process.

    Args:
        command: Authored remote shell program to execute.

    Returns:
        The shell-quoted command which installs ``TRUSTED_REMOTE_PATH`` before
        executing the authored program, or an empty string for an empty input.

    Raises:
        TypeError: If ``command`` is not text.
    """

    if not isinstance(command, str):
        raise TypeError("remote command must be a string")
    if not command:
        return command
    # Minimal BMC images do not necessarily provide /usr/bin/env.  Install the
    # governed path inside the POSIX shell which is already the required remote
    # execution boundary, so every collector receives the same lookup policy
    # without adding a second executable dependency.
    trusted_script = f"PATH={TRUSTED_REMOTE_PATH}\nexport PATH\n{command}"
    return shlex.join([TRUSTED_POSIX_SHELL_PATH, "-c", trusted_script])


def build_trusted_remote_executable_probe(
    command: str, *, local_privileged: bool = False
) -> str:
    """
    Build a shell-safe probe for a bare executable in trusted remote directories.

    The probe checks fixed absolute candidates instead of inheriting the login
    account's ``PATH`` or depending on a remote ``which`` utility. Candidate
    paths are passed as positional arguments to a fixed shell program, so the
    dependency name cannot add shell syntax. Exit status ``126`` means a
    candidate exists but is not executable, while ``127`` means no candidate
    exists in the governed search path.

    Args:
        command: Bare executable name declared by collector configuration.
        local_privileged: Select the narrower PATH used by privileged local
            Host execution instead of the trusted remote Host PATH.

    Returns:
        A shell-quoted remote command which prints the first executable absolute
        path and exits successfully, or emits a bounded diagnostic and exits
        with ``126`` or ``127``.

    Raises:
        TypeError: If ``command`` is not text.
        ValueError: If ``command`` is empty, contains NUL, or contains a path
            separator instead of being a bare executable name.
    """

    if not isinstance(command, str):
        raise TypeError("remote executable name must be a string")
    if not command or "\x00" in command or "/" in command:
        raise ValueError(
            "remote executable name must be nonempty, NUL-free, and contain no '/'"
        )

    probe_script = (
        'nvdebug_non_executable=""\n'
        'for nvdebug_candidate in "$@"; do\n'
        '    if [ -x "$nvdebug_candidate" ] && [ ! -d "$nvdebug_candidate" ]; then\n'
        "        printf '%s\\n' \"$nvdebug_candidate\"\n"
        "        exit 0\n"
        "    fi\n"
        '    if [ -e "$nvdebug_candidate" ]; then\n'
        "        nvdebug_non_executable=1\n"
        "    fi\n"
        "done\n"
        'if [ -n "$nvdebug_non_executable" ]; then\n'
        "    printf '%s\\n' "
        "'Command exists in the trusted remote search path but is not executable' >&2\n"
        "    exit 126\n"
        "fi\n"
        "printf '%s\\n' "
        "'Command was not found in the trusted remote search path' >&2\n"
        "exit 127"
    )
    search_path = TRUSTED_PRIVILEGED_PATH if local_privileged else TRUSTED_REMOTE_PATH
    candidates = [f"{directory}/{command}" for directory in search_path.split(":")]
    return shlex.join(
        [
            TRUSTED_POSIX_SHELL_PATH,
            "-c",
            probe_script,
            "nvdebug-command-probe",
            *candidates,
        ]
    )


def build_local_cmd(template_args: List[str], **kwargs: str) -> List[str]:
    """
    Build a command argument list for local subprocess execution.

    ``shell=False`` makes metacharacters literal, but does not prevent a
    substituted operand beginning with ``-`` from becoming a program option.
    Pure substituted operands are therefore rejected until an explicit ``--``
    end-of-options marker has appeared.

    Args:
        template_args: Entries supplied as ``template_args`` without
            transferring container ownership.
        kwargs: Additional named values forwarded without changing their keys.

    Example:
        >>> build_local_cmd(["xxd", "-g", "1", "{file}"], file="/tmp/dump.bin")
        ["xxd", "-g", "1", "/tmp/dump.bin"]

    Returns:
        The validated ``rendered``.

    Raises:
        ValueError: If build_local_cmd operand resolved to an option-like value;
            place untrusted operands after '--' or validate them upstream.
    """
    rendered = [arg.format(**kwargs) for arg in template_args]
    options_terminated = False
    for template, value in zip(template_args, rendered):
        if template == "--":
            options_terminated = True
            continue
        if (
            not options_terminated
            and _PURE_LOCAL_SUBSTITUTION.fullmatch(template)
            and value.startswith("-")
        ):
            raise ValueError(
                "build_local_cmd operand resolved to an option-like value; "
                "place untrusted operands after '--' or validate them upstream"
            )
    return rendered


def safe_subprocess_run(
    cmd: List[str],
    timeout: Optional[int] = 120,
    capture_output: bool = True,
    text: bool = True,
    check: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """
    Safe wrapper around subprocess.run that forbids shell=True.

    After applying local validation, the function forwards ``cmd``, ``timeout``,
    ``capture_output``, ``text``, and ``check`` to ``subprocess.run`` and
    preserves its return and exception contract. The operation mutates
    ``kwargs`` in place; ownership of those objects remains with the caller.

    Args:
        cmd: Entries supplied as ``cmd`` without transferring container
            ownership.
        timeout: Maximum duration allowed before the operation is cancelled or
            fails.
        capture_output: Whether capture output is enabled or required for this
            operation.
        text: Whether text is enabled or required for this operation.
        check: Whether check is enabled or required for this operation.
        kwargs: Additional named values forwarded without changing their keys.

    Returns:
        A ``CompletedProcess`` representing safe subprocess run.

    Raises:
        TypeError: If the cmd is not a list of arguments, got ``__name__``. Use
            build_local_cmd() to construct the argument list.
        ValueError: If shell=True is not allowed. Use build_local_cmd() to
            construct a safe argument list for subprocess.run(shell=False).
    """
    if not isinstance(cmd, list):
        raise TypeError(
            f"cmd must be a list of arguments, got {type(cmd).__name__}. "
            "Use build_local_cmd() to construct the argument list."
        )
    if kwargs.get("shell", False):
        raise ValueError(
            "shell=True is not allowed. Use build_local_cmd() to construct "
            "a safe argument list for subprocess.run(shell=False)."
        )
    kwargs.pop("shell", None)
    kwargs["env"] = scrubbed_subprocess_environment(kwargs.get("env"))
    return subprocess.run(
        cmd,
        timeout=timeout,
        capture_output=capture_output,
        text=text,
        check=check,
        **kwargs,
    )
