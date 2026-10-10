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
Render the canonical Click help records with lossless terminal wrapping.

Rich supplies panels and styles for interactive terminals; Click continues to
own usage, argument and option records, defaults, environment hints, and epilogs.
Captured output stays plain. Rendering returns through Click's formatter instead
of writing directly to stdout, preserving the caller's output-stream ownership.
"""

from collections.abc import Iterator, Sequence
from contextlib import contextmanager

import click
from click import get_text_stream
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..utils.sanitizer import neutralize_text_controls


def _help_text(value: str, style: str = "") -> Text:
    """
    Build literal help text that wraps without dropping characters.

    Rich markup in descriptions and defaults remains visible text, and terminal
    controls cannot escape the help layout. Folding preserves long flag names
    and environment identifiers even when they exceed the available line width.

    Args:
        value: Help content supplied by the command's canonical formatter.
        style: Trusted Rich style applied to the complete text.

    Returns:
        A styled text renderable with character-preserving overflow behavior.
    """

    return Text(neutralize_text_controls(value), style=style, overflow="fold")


class _RichHelpFormatter(click.HelpFormatter):
    """
    Adapt Click's help-writing protocol to captured Rich renderables.

    Sections become panels and definition lists become responsive tables. Narrow
    terminals stack each term above its description, leaving enough room for long
    option aliases and environment hints. No rendering mutates command metadata.
    """

    def __init__(self, console: Console) -> None:
        """
        Bind the formatter to one terminal's dimensions and color policy.

        The console remains caller-owned. This formatter holds only the
        renderables for one help document and captures output when requested.

        Args:
            console: Console used only under capture when returning the document.
        """

        super().__init__(width=console.width)
        self._console = console
        self._renderables: list[RenderableType] = []

    def write_usage(self, prog: str, args: str = "", prefix: str | None = None) -> None:
        """
        Preserve the complete command path and usage syntax above the panels.

        Usage stays outside the option table so long argument metavars can use
        the full width instead of being cropped to an option-name column.

        Args:
            prog: Executable and parent command names supplied by Click.
            args: Canonical argument and option usage syntax.
            prefix: Optional localized usage label; defaults to ``Usage:``.

        Side Effects:
            Appends a styled usage paragraph to the current help document.
        """

        usage = _help_text(prefix if prefix is not None else "Usage: ", "bold yellow")
        usage.append(_help_text(prog, "bold"))
        if args:
            usage.append(_help_text(f" {args}"))
        self._renderables.extend((usage, Text()))

    def write_text(self, text: str) -> None:
        """
        Retain descriptive paragraphs, examples, and epilog text.

        Click's paragraph handling preserves explicitly preformatted examples
        and removes formatting markers. Rich then wraps at the actual terminal
        width, including the space consumed by any surrounding panel.

        Args:
            text: Complete prose passed by Click's command help methods.

        Side Effects:
            Appends literal prose and paragraph spacing to the current document.
        """

        prose = click.wrap_text(text, width=max(len(text), 1), preserve_paragraphs=True)
        self._renderables.extend((_help_text(prose), Text()))

    @contextmanager
    def section(self, name: str) -> Iterator[None]:
        """
        Capture a Click help section inside a labeled Rich panel.

        Nested sections restore their parent's renderables on exit, including
        when the command formatter raises an exception.

        Args:
            name: Section heading supplied by the command, such as ``Options``.

        Yields:
            Control while the caller writes the section's help records.

        Side Effects:
            Appends the completed panel to the enclosing help document.
        """

        parent = self._renderables
        self._renderables = []
        try:
            yield
        finally:
            contents = self._renderables
            self._renderables = parent
            self._renderables.extend(
                (
                    Panel(
                        Group(*contents),
                        title=_help_text(name, "bold"),
                        title_align="left",
                        border_style="dim",
                        padding=(0, 1),
                    ),
                    Text(),
                )
            )

    def write_dl(
        self,
        rows: Sequence[tuple[str, str]],
        col_max: int = 30,
        col_spacing: int = 2,
    ) -> None:
        """
        Render complete option, argument, or command records without ellipses.

        Use two columns only when every term fits intact in the first column.
        Otherwise stack the records, giving long aliases and choice lists the
        full terminal width. Both layouts render the same canonical records.

        Args:
            rows: Pairs of public spellings and their complete descriptions.
            col_max: Click protocol parameter; Rich ratios govern column widths.
            col_spacing: Click protocol parameter; Rich padding governs spacing.

        Side Effects:
            Appends one definition table to the current section.
        """

        table = Table(
            show_header=False, box=None, padding=(0, 1), leading=1, expand=True
        )
        term_width = max((_help_text(term).cell_len for term, _ in rows), default=0)
        if (
            self._console.width >= 100
            and term_width <= (self._console.width - 8) * 2 // 5
        ):
            table.add_column(ratio=2, overflow="fold")
            table.add_column(ratio=3, overflow="fold")
            for term, description in rows:
                table.add_row(_help_text(term, "bold cyan"), _help_text(description))
        else:
            table.add_column(overflow="fold")
            for term, description in rows:
                table.add_row(
                    Group(
                        _help_text(term, "bold cyan"), _help_text(description), Text()
                    )
                )
        self._renderables.append(table)

    def getvalue(self) -> str:
        """
        Capture the complete document without writing to the terminal.

        Rich owns wrapping and styling inside a temporary capture. The caller
        receives the resulting string and retains control of output routing.

        Returns:
            Terminal-formatted help, including styles only when colors are
            enabled. The owning Click caller decides where to emit it.
        """

        with self._console.capture() as capture:
            self._console.print(Group(*self._renderables), crop=False)
        return capture.get()


def format_cli_help(
    command: click.Command, ctx: click.Context, formatter: click.HelpFormatter
) -> None:
    """
    Style interactive help while preserving complete plain redirected output.

    The canonical Click/Typer help methods supply every record in either mode.
    Rich renders only to a capture buffer so ``ctx.get_help()`` remains free of
    stdout side effects. Dumb terminals and redirected streams retain Click's
    plain format regardless of color-forcing environment variables.

    Args:
        command: Registered command or group whose existing help is rendered.
        ctx: Click context supplying terminal width and explicit color policy.
        formatter: Caller-owned buffer receiving the complete help document.

    Side Effects:
        Appends help to ``formatter`` without invoking command callbacks,
        reading configuration, or emitting directly to either output stream.
    """

    stream = get_text_stream("stdout")
    console = Console(
        file=stream,
        width=ctx.terminal_width,
        color_system=None if ctx.color is False else "auto",
        markup=False,
        highlight=False,
    )
    if not stream.isatty() or console.is_dumb_terminal:
        click.Command.format_help(command, ctx, formatter)
        return
    rich_formatter = _RichHelpFormatter(console)
    click.Command.format_help(command, ctx, rich_formatter)
    formatter.write(rich_formatter.getvalue())
