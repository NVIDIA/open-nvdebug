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
Normalize supported legacy command lines before Click dispatches a command.

The modern CLI keeps explicit subcommands and canonical option ownership. This
module contains the compatibility boundary for retained root utility modes and
legacy variadic collector/group selectors after an explicit ``collect`` command.
It never reads configuration, opens output, contacts a target, or records argument
values, which keeps sensitive credentials under Click's existing option and
sanitization policies.
"""

from __future__ import annotations

import inspect
from collections.abc import Collection, Sequence

import click
from typer.core import TyperGroup

from .help import format_cli_help

_LEGACY_COLLECTOR_SELECTORS = frozenset({"-S", "--cid", "--cids"})
_COLLECTOR_SELECTORS = _LEGACY_COLLECTOR_SELECTORS | {"--collector-id"}
_GROUP_SELECTORS = frozenset({"-g", "--collector-group", "--loggroup"})
_PLATFORM_HINTS = frozenset({"-t", "--platform"})
_ROOT_HELP = frozenset({"-h", "--help"})
_PLATFORM_HINT_ERROR = (
    "Legacy option -t/--platform is no longer supported because it has no "
    "effect. Remove it; platform is derived from the selected baseboard and "
    "catalog."
)


def _split_bound_option(token: str) -> tuple[str, str | None]:
    """
    Split a long option token from an equals-bound value.

    Short options and ordinary values are returned unchanged. Only the first
    equals sign is structural so values containing additional equals signs retain
    their exact bytes.

    Args:
        token: One argument token from the process command line.

    Returns:
        A pair containing the option spelling and its bound value, or ``None``
        when the token does not use long-option equals syntax.
    """

    if token.startswith("--") and "=" in token:
        option, value = token.split("=", 1)
        return option, value
    return token, None


def _looks_like_option(token: str) -> bool:
    """
    Report whether a token begins another command-line option.

    A lone hyphen remains a value. Selector values are collector IDs or group
    names and therefore do not require negative-number special handling.

    Args:
        token: One argument token from the process command line.

    Returns:
        ``True`` when the token has an option prefix and is not a lone hyphen.
    """

    return token.startswith("-") and token != "-"


def _reject_platform_hints(arguments: Sequence[str]) -> None:
    """
    Reject legacy platform hints that no longer affect runtime behavior.

    The current data-driven runtime derives architecture and node type from the
    selected or detected baseboard catalog entry. Accepting ``-t`` or
    ``--platform`` would therefore create a false-success invocation in which an
    operator-provided value is silently discarded. Detection uses only option
    spellings before Click's ``--`` end-of-options marker and never retains or
    emits an adjacent value.

    Args:
        arguments: Command arguments inspected before compatibility routing.

    Raises:
        click.UsageError: If either unsupported platform option spelling is
            present, including equals-bound long-option syntax.
    """

    for token in arguments:
        if token == "--":
            break
        option, _ = _split_bound_option(token)
        if option in _PLATFORM_HINTS:
            raise click.UsageError(_PLATFORM_HINT_ERROR)


def normalize_legacy_command_args(
    command: str,
    arguments: Sequence[str],
) -> list[str]:
    """
    Normalize legacy selector cardinality for one modern command.

    Legacy collection accepted ``-S R1 R2`` and ``-g Redfish IPMI`` while the
    modern Click surface accepts a scalar collector expression and repeatable
    group options. When a legacy collector spelling occurs, this function joins
    every collector occurrence into one scalar; canonical-only repetition keeps
    Click's established last-wins behavior. Every group value expands into a
    repeatable canonical option. Legacy platform hints fail at this boundary
    because silently consuming a no-effect value would misrepresent the
    invocation. Other tokens, including credential values, remain in their
    original order and are never logged.

    Args:
        command: Modern subcommand selected for dispatch.
        arguments: Command arguments excluding the executable and subcommand.

    Returns:
        A fresh argument list suitable for the modern Click command parser.

    Raises:
        click.UsageError: If the invocation contains ``-t`` or ``--platform``.
    """

    _reject_platform_hints(arguments)
    if command != "collect":
        return list(arguments)

    legacy_collector_cardinality = any(
        _split_bound_option(token)[0] in _LEGACY_COLLECTOR_SELECTORS
        for token in arguments
    )
    active_collector_selectors = (
        _COLLECTOR_SELECTORS if legacy_collector_cardinality else frozenset()
    )
    normalized: list[str] = []
    collector_values: list[str] = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        option, bound_value = _split_bound_option(token)
        if option not in active_collector_selectors | _GROUP_SELECTORS:
            normalized.append(token)
            index += 1
            continue

        values: list[str] = []
        if bound_value is not None:
            values.append(bound_value)
            index += 1
        else:
            index += 1
            while index < len(arguments) and not _looks_like_option(arguments[index]):
                values.append(arguments[index])
                index += 1

        if not values:
            normalized.append(option)
            continue
        if option in active_collector_selectors:
            collector_values.extend(values)
            continue
        for value in values:
            normalized.extend(("--collector-group", value))

    if collector_values:
        normalized.extend(("--collector-id", " ".join(collector_values)))
    return normalized


def _extract_legacy_mode(
    arguments: Sequence[str],
    spellings: Collection[str],
) -> tuple[list[str], str | None]:
    """
    Remove one legacy mode option and capture its optional adjacent value.

    Legacy list, default-collector, and parse modes were options on the root
    command. Their optional value is consumed only when it is adjacent and does
    not begin another option; all remaining arguments preserve their order.

    Args:
        arguments: Root arguments excluding the executable name.
        spellings: Equivalent option names selecting the legacy mode.

    Returns:
        A pair containing the remaining arguments and the optional mode value.
        When no requested spelling occurs, the returned value is ``None`` and a
        fresh copy of the original arguments is returned.
    """

    remaining = list(arguments)
    for index, token in enumerate(remaining):
        option, bound_value = _split_bound_option(token)
        if option not in spellings:
            continue
        del remaining[index]
        if bound_value is not None:
            return remaining, bound_value
        if index < len(remaining) and not _looks_like_option(remaining[index]):
            return remaining[:index] + remaining[index + 1 :], remaining[index]
        return remaining, None
    return remaining, None


def _rewrite_utility_output_aliases(arguments: Sequence[str]) -> list[str]:
    """
    Canonicalize legacy output aliases accepted by root utility modes.

    Utility commands use the same destination meaning but expose the modern
    ``--output`` name. Equals-bound values remain bound so Click retains their
    original single-token parsing behavior.

    Args:
        arguments: Utility-command arguments after removal of the root mode flag.

    Returns:
        A fresh list with ``--outdir`` rewritten to the utility command's
        canonical ``--output`` spelling.
    """

    normalized: list[str] = []
    for token in arguments:
        option, bound_value = _split_bound_option(token)
        if option != "--outdir":
            normalized.append(token)
        elif bound_value is None:
            normalized.append("--output")
        else:
            normalized.append(f"--output={bound_value}")
    return normalized


def normalize_legacy_root_args(
    arguments: Sequence[str],
    command_names: Collection[str],
) -> list[str]:
    """
    Route a supported root-level utility mode to a modern subcommand.

    Existing subcommands, empty invocations, root help, version, and unknown
    positional commands retain native Click behavior. Collection options at the
    root also remain untouched so Click rejects them as unknown; ``collect`` is a
    required command boundary. Legacy list, default-collector, preflight, and
    explicit parse modes are routed to their corresponding modern commands. This
    boundary changes utility dispatch only and does not alter the selected
    command's exit policy.

    Args:
        arguments: Root arguments excluding the executable name.
        command_names: Registered modern subcommand names that must remain
            untouched.

    Returns:
        A fresh root argument list with a modern subcommand when compatibility
        routing applies.

    Raises:
        click.UsageError: If the invocation contains ``-t`` or ``--platform``.
    """

    original = list(arguments)
    _reject_platform_hints(original)
    if not original or original[0] in command_names:
        return original
    if len(original) == 1 and original[0] in _ROOT_HELP:
        return original
    if any(_split_bound_option(token)[0] == "--version" for token in original):
        return ["--version"]
    if not _looks_like_option(original[0]):
        return original

    option_names = {_split_bound_option(token)[0] for token in original}
    if option_names & {"-l", "--list"}:
        remaining, group = _extract_legacy_mode(original, {"-l", "--list"})
        remaining = _rewrite_utility_output_aliases(remaining)
        if group:
            remaining.extend(("--group", group))
        return ["list-collectors", *remaining]

    if option_names & {"-D", "--default_collectors"}:
        remaining, group = _extract_legacy_mode(
            original, {"-D", "--default_collectors"}
        )
        remaining = _rewrite_utility_output_aliases(remaining)
        if group:
            # No modern default-collector group filter exists. Preserve the
            # value as an unexpected argument so Click fails visibly instead of
            # silently broadening the requested result.
            remaining.append(group)
        return ["default-collectors", *remaining]

    if "--preflight" in option_names:
        remaining, _ = _extract_legacy_mode(original, {"--preflight"})
        return ["preflight", *remaining]

    if "--parse" in option_names:
        remaining, input_path = _extract_legacy_mode(original, {"--parse"})
        routed = ["parse"]
        if input_path and input_path != "auto":
            routed.append(input_path)
        routed.extend(remaining)
        return routed

    return original


class LegacyCompatibleTyperGroup(TyperGroup):
    """
    Apply the reviewed legacy argv adapter before normal Click parsing.

    The group stores only a boolean marker in Click metadata when normalization
    occurs. Raw arguments and credential values are neither retained nor emitted.
    Registered command callbacks and their lifecycle/exit semantics remain owned
    by the ordinary Typer command tree.
    """

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """
        Use the same complete terminal and redirected help policy as commands.

        Routing the root through the shared formatter keeps command summaries
        and global options readable under the same width and capture rules as
        individual subcommands.

        Args:
            ctx: Root context supplying terminal dimensions and color policy.
            formatter: Click-owned buffer receiving the help document.

        Side Effects:
            Appends help without invoking any registered command callback.
        """

        format_cli_help(self, ctx, formatter)

    def format_commands(
        self, ctx: click.Context, formatter: click.HelpFormatter
    ) -> None:
        """
        Preserve each visible command's complete introductory description.

        Match the former Rich root menu's first-paragraph summaries without
        Click's width-dependent abbreviation. Hidden commands stay hidden.

        Args:
            ctx: Root context used to resolve the registered commands.
            formatter: Plain or Rich formatter receiving command help records.

        Side Effects:
            Appends a Commands section when visible subcommands exist.
        """

        rows = []
        for name in self.list_commands(ctx):
            command = self.get_command(ctx, name)
            if command is None or command.hidden:
                continue
            description = inspect.cleandoc(command.short_help or command.help or "")
            description = description.partition("\f")[0].split("\n\n")[0]
            if command.deprecated:
                notice = (
                    f"DEPRECATED: {command.deprecated}"
                    if isinstance(command.deprecated, str)
                    else "DEPRECATED"
                )
                description = f"{description} ({notice})"
            rows.append((name, description))
        if rows:
            with formatter.section("Commands"):
                formatter.write_dl(rows)

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        """
        Normalize root dispatch and legacy selector cardinality.

        Normalization finishes before Typer chooses a subcommand. Retained root
        utility modes route to their modern commands, while collection argument
        normalization occurs only after an explicit ``collect`` command.

        Args:
            ctx: Click-owned root context receiving parser metadata.
            args: Mutable root argument list supplied by Click.

        Returns:
            The unconsumed arguments returned by Typer's standard group parser.

        Raises:
            click.UsageError: If the normalized invocation violates the selected
                modern command's syntax.

        Side Effects:
            Records a value-free compatibility marker in ``ctx.meta`` when the
            input shape changes, then delegates command parsing and dispatch.
        """

        original = list(args)
        normalized = normalize_legacy_root_args(original, self.commands)
        if normalized and normalized[0] in {"collect", "preflight"}:
            normalized = [
                normalized[0],
                *normalize_legacy_command_args(normalized[0], normalized[1:]),
            ]
        if normalized != original:
            ctx.meta["nvdebug_legacy_argv_compatibility"] = True
        return super().parse_args(ctx, normalized)


__all__ = [
    "LegacyCompatibleTyperGroup",
    "normalize_legacy_command_args",
    "normalize_legacy_root_args",
]
