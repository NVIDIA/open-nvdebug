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
Console Output Utilities for NVDebug Tool.

Provides standardized sanitized console output functionality using Rich console
with automatic data sanitization.
"""

from typing import Any, Optional, Sequence

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .sanitizer import (
    BuiltInSanitizers,
    LogSanitizer,
    neutralize_terminal_text,
    neutralize_text_controls,
)

_NON_TERMINAL_GLYPH_REPLACEMENTS = str.maketrans(
    {
        "🚫": "ERROR",
        "🔧": "",
        "📖": "",
        "💡": "",
        "📝": "",
        "🏠": "",
        "🔑": "",
        "•": "-",
        "→": "->",
        "✓": "OK",
        "✗": "X",
        "○": "o",
        "─": "-",
        "━": "-",
        "│": "|",
        "┃": "|",
        "╭": "+",
        "╮": "+",
        "╰": "+",
        "╯": "+",
        "┌": "+",
        "┐": "+",
        "└": "+",
        "┘": "+",
        "├": "+",
        "┤": "+",
        "┬": "+",
        "┴": "+",
        "┼": "+",
        "┏": "+",
        "┓": "+",
        "┗": "+",
        "┛": "+",
        "┣": "+",
        "┫": "+",
        "┳": "+",
        "┻": "+",
        "╋": "+",
    }
)


def _console_supports_rich_glyphs(console: Any) -> bool:
    """
    Return whether one output sink is an interactive terminal.

    Captured subprocess output crosses an unknown decoder boundary after Rich
    writes it. Restrict decorative Unicode to interactive terminals so CI and
    QA wrappers receive an ASCII transcript even when their locale metadata
    incorrectly claims UTF-8 support.

    Args:
        console: Rich console, sanitized-console wrapper, or injected test sink.

    Returns:
        ``True`` only for an explicitly interactive Rich console.
    """

    output_console = getattr(console, "console", console)
    return getattr(output_console, "is_terminal", False) is True


def _adapt_console_glyphs(text: str, console: Any) -> str:
    """
    Replace decorative Unicode when output is captured by another process.

    The replacement set is deliberately limited to project-owned UI glyphs and
    Rich box borders. User-supplied Unicode remains unchanged unless it is one
    of those presentation characters.

    Args:
        text: Sanitized, terminal-control-free text ready for rendering.
        console: Output sink whose interactive state selects the layout.

    Returns:
        Original text for a terminal, otherwise its ASCII-safe UI equivalent.
    """

    if _console_supports_rich_glyphs(console):
        return text
    return text.translate(_NON_TERMINAL_GLYPH_REPLACEMENTS)


def _default_console_sanitizer() -> LogSanitizer:
    """
    Return the credential-pattern baseline available before config load.

    After applying local validation, the function forwards current instance
    state to ``LogSanitizer`` and preserves its return and exception contract.

    Returns:
        A ``LogSanitizer`` representing default console sanitizer.
    """

    return LogSanitizer(
        additional_regex=[
            BuiltInSanitizers.CREDENTIALS,
            BuiltInSanitizers.API_KEYS,
            BuiltInSanitizers.TOKENS,
            BuiltInSanitizers.PRIVATE_KEYS,
            BuiltInSanitizers.CREDENTIAL_URIS,
            BuiltInSanitizers.COOKIES,
            BuiltInSanitizers.AWS_ACCESS_KEY_IDS,
        ]
    )


class SanitizedConsole:
    """
    Provides sanitized console output functionality.

    Wraps Rich Console to provide color-coded output with automatic sanitization
    of sensitive data.
    """

    def __init__(self, sanitizer: Optional[LogSanitizer] = None):
        """
        Initialize sanitized console.

        Normal messages use stdout while errors use stderr. Both sinks apply
        the same sanitizer before rendering. The public ``console`` setter
        deliberately replaces both sinks so callers can continue injecting one
        recording console for tests or redirected output.

        Args:
            sanitizer: Sanitizer applied before untrusted or sensitive text
                leaves its boundary.
        """
        self._console = Console()
        self._error_console = Console(stderr=True)
        self.sanitizer = sanitizer or _default_console_sanitizer()

    @property
    def console(self) -> Console:
        """
        Replace the output console for dependency injection and tests.

        Each access computes the value from ``_console`` on the current
        instance; the derived view is not stored as independent state.

        Returns:
            A ``Console`` representing console.
        """

        return self._console

    @console.setter
    def console(self, value: Console) -> None:
        """
        Replace the output console for dependency injection and tests.

        The injected console becomes both the normal and error sink. This
        preserves the historical single-console injection contract while
        default instances keep stdout and stderr separate.

        Args:
            value: Value evaluated while performing replace the output console
                for dependency injection and tests.
        """

        self._console = value
        self._error_console = value

    def print_renderable(self, renderable: Any) -> None:
        """
        Print a Rich renderable whose dynamic cells were already neutralized.

        The implementation uses ``renderable`` to print a Rich renderable whose
        dynamic cells were already neutralized.

        Args:
            renderable: Renderable consumed while the function attempts to print
                a Rich renderable whose dynamic cells were already neutralized.
        """

        self._console.print(renderable)

    def print(
        self, text: Any = "", style: str = "", *, soft_wrap: bool = False
    ) -> None:
        """
        Print sanitized text to console with optional styling.

        Rich renderables can embed rejected configuration values. Render them
        first rather than passing a Panel/Text object into a string-only
        sanitizer.

        Args:
            text: Text consumed while the function attempts to print sanitized
                text to console with optional styling.
            style: Text supplied as style in the format accepted by this
                function.
            soft_wrap: Whether Rich should preserve the sanitized message as
                one logical line instead of inserting width-based line breaks.
        """
        if isinstance(text, str):
            rendered_text = text
        else:
            # Rich renderables can embed rejected configuration values. Render
            # them first rather than passing a Panel/Text object into a
            # string-only sanitizer.
            with self._console.capture() as capture:
                self._console.print(text)
            rendered_text = capture.get()
        sanitized_text = self.sanitizer.sanitize(rendered_text)
        display_text = _adapt_console_glyphs(
            neutralize_terminal_text(sanitized_text), self._console
        )
        self._console.print(
            display_text,
            style=style,
            soft_wrap=soft_wrap,
        )

    def print_separator(
        self, char: str = "=", length: int = 80, style: str = "bold blue"
    ) -> None:
        """
        Print a separator line.

        The implementation uses ``char``, ``length``, and ``style`` to print a
        separator line.

        Args:
            char: Text supplied as char in the format accepted by this function.
            length: Numeric length used while the operation performs bounded
                accounting.
            style: Text supplied as style in the format accepted by this
                function.
        """
        separator = char * length
        self.print(separator, style)

    def print_header(self, text: str, style: str = "bold blue") -> None:
        """
        Print a header with consistent formatting.

        The implementation uses ``text`` and ``style`` to print a header with
        consistent formatting.

        Args:
            text: Text supplied as text in the format accepted by this function.
            style: Text supplied as style in the format accepted by this
                function.
        """
        self.print(text, style)

    def print_success(self, text: str) -> None:
        """
        Print success message in green.

        The implementation uses ``text`` to print success message in green.

        Args:
            text: Text supplied as text in the format accepted by this function.
        """
        self.print(text, "bold green")

    def print_warning(self, text: str) -> None:
        """
        Print warning message in yellow.

        The implementation uses ``text`` to print warning message in yellow.

        Args:
            text: Text supplied as text in the format accepted by this function.
        """
        self.print(text, "bold yellow")

    def print_error(self, text: str) -> None:
        """
        Print a sanitized error message in red on the error sink.

        Default instances render through stderr. Injected consoles still
        receive the message through the object assigned with ``console``.

        Args:
            text: Text supplied as text in the format accepted by this function.
        """
        sanitized_text = self.sanitizer.sanitize(text)
        display_text = _adapt_console_glyphs(
            neutralize_terminal_text(sanitized_text), self._error_console
        )
        self._error_console.print(
            display_text,
            style="bold red",
        )

    def print_failure(
        self,
        text: str,
        *,
        title: str = "Command Failed",
        suggestions: Sequence[str] = (),
    ) -> None:
        """
        Render one fatal human-facing diagnostic as a sanitized Rich panel.

        Fatal panels use the normal human-output sink so subprocess wrappers
        that retain the command's progress transcript also retain the terminal
        reason. Machine-readable command modes must keep stdout pristine and
        therefore continue to use ``print_error`` or an explicit stderr path.
        Dynamic text is sanitized and terminal-control neutralized before it
        enters a Rich renderable, preventing rejected input from injecting
        markup or terminal actions.

        Args:
            text: Operator-facing reason the command cannot continue.
            title: Stable failure category displayed in the panel heading.
            suggestions: Ordered recovery actions displayed below the reason.

        Side Effects:
            Writes one Rich panel to the normal console output sink.
        """

        unicode_layout = _console_supports_rich_glyphs(self._console)

        def safe_text(value: Any) -> str:
            """
            Sanitize and neutralize one value before Rich renders it.

            Rich ``Text`` treats the returned value as literal content. The
            sanitizer still runs first so rejected configuration values cannot
            bypass the same redaction boundary used by ordinary console output.

            Args:
                value: Dynamic value destined for the fatal diagnostic.

            Returns:
                Plain display-safe text with sensitive values and terminal
                controls removed.
            """

            sanitized = self.sanitizer.sanitize(str(value))
            return _adapt_console_glyphs(
                neutralize_text_controls(sanitized), self._console
            )

        body = Text()
        body.append("Reason\n", style="bold red")
        body.append(safe_text(text), style="red")
        if suggestions:
            body.append("\n\nNext steps\n", style="bold yellow")
            for index, suggestion in enumerate(suggestions, 1):
                body.append(f"{index}. ", style="bold cyan")
                body.append(safe_text(suggestion))
                if index != len(suggestions):
                    body.append("\n")

        panel = Panel(
            body,
            title=Text(
                f"{'🚫 ' if unicode_layout else 'ERROR: '}{safe_text(title)}",
                style="bold red",
            ),
            subtitle=Text("The command stopped before continuing", style="dim"),
            border_style="red",
            box=box.ROUNDED if unicode_layout else box.ASCII,
            padding=(1, 2),
            title_align="center",
        )
        self._console.print(panel)

    def print_info(self, text: str, *, soft_wrap: bool = False) -> None:
        """
        Print info message in blue.

        The implementation uses ``text`` to print info message in blue.

        Args:
            text: Text supplied as text in the format accepted by this function.
            soft_wrap: Whether to preserve the sanitized informational message
                as one logical line regardless of terminal width.
        """
        self.print(text, "bold blue", soft_wrap=soft_wrap)

    def print_debug(self, text: str) -> None:
        """
        Print debug message in dim white.

        The implementation uses ``text`` to print debug message in dim white.

        Args:
            text: Text supplied as text in the format accepted by this function.
        """
        self.print(text, "dim white")


def create_sanitized_console(
    sanitizer: Optional[LogSanitizer] = None,
) -> SanitizedConsole:
    """
    Factory function to create a sanitized console instance.

    After applying local validation, the function forwards ``sanitizer`` to
    ``SanitizedConsole`` and preserves its return and exception contract.

    Args:
        sanitizer: Sanitizer applied before untrusted or sensitive text leaves
            its boundary.

    Returns:
        A ``SanitizedConsole`` representing sanitized console.
    """
    return SanitizedConsole(sanitizer)
