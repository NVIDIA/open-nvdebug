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
Pure rendering policy for legacy HTML reports.

The report service owns data loading, async orchestration, and publication. This
module owns deterministic HTML construction from immutable snapshots so
rendering can be tested without filesystem, logger, or orchestrator state.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html import escape
from typing import Any, Sequence
from urllib.parse import quote, urlsplit

__all__ = [
    "BackButtonRenderModel",
    "HTMLPageRenderModel",
    "HTMLReportRenderer",
    "RenderedLinkList",
    "SystemDetailsRenderModel",
]


@dataclass(frozen=True, slots=True)
class BackButtonRenderModel:
    """
    Immutable navigation inputs for a rendered page header.

    The immutable record keeps ``url`` and ``text`` together so consumers
    observe one back button render model state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        url: URL retained as part of the record's public state.
        text: Text retained as part of the record's public state.
    """

    url: Any = "index.html"
    text: Any = "← Back"


@dataclass(frozen=True, slots=True)
class HTMLPageRenderModel:
    """
    Immutable inputs for one complete legacy HTML document.

    The immutable record keeps ``template``, ``navbar``, ``page_title``,
    ``content``, and ``page_icon`` together so consumers observe one HTML page
    render model state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        template: Canonical text used as template.
        navbar: Canonical text used as navbar.
        page_title: Page title retained as part of the record's public state.
        content: Canonical text used as content.
        page_icon: Canonical text used as page icon.
        back_button: Back button retained as part of the record's public state.
        subtitle: Subtitle retained as part of the record's public state.
    """

    template: str
    navbar: str
    page_title: Any
    content: str
    page_icon: str | None = None
    back_button: BackButtonRenderModel | None = None
    subtitle: Any | None = None


@dataclass(frozen=True, slots=True)
class RenderedLinkList:
    """
    A rendered link-list fragment and its optional detached modal.

    The immutable record keeps ``html`` and ``modal_html`` together so consumers
    observe one rendered link list state. Consumers receive the fields as one
    unit instead of assembling partial state.

    Attributes:
        html: Canonical text used as HTML.
        modal_html: Canonical text used as modal HTML.
    """

    html: str
    modal_html: str | None = None


@dataclass(frozen=True, slots=True)
class SystemDetailsRenderModel:
    """
    Immutable system-detail values used by node and group pages.

    The immutable record keeps ``model``, ``part_number``, and ``serial_number``
    together so consumers observe one system details render model state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        model: Model retained as part of the record's public state.
        part_number: Part number retained as part of the record's public state.
        serial_number: Serial number retained as part of the record's public
            state.
    """

    model: Any = "Unknown"
    part_number: Any = "Unknown"
    serial_number: Any = "Unknown"


@dataclass(frozen=True, slots=True)
class HTMLReportRenderer:
    """
    Deterministic, side-effect-free legacy report renderer.

    The type coordinates ``json_for_script``, ``has_unsafe_html_control``,
    ``escape_html_text``, ``safe_external_url``, and
    ``encoded_relative_report_link`` and retains the state those operations
    share between calls. Resource ownership remains inside the instance until
    the matching close, exit, or cleanup operation completes.
    """

    @staticmethod
    def json_for_script(value: Any, **kwargs: Any) -> str:
        """
        Serialize JSON safely for direct embedding inside script tags.

        After applying local validation, the function forwards ``value`` and
        ``kwargs`` to ``replace`` and preserves its return and exception
        contract. Filesystem effects remain confined to the caller-selected
        paths and the owning resource lifecycle.

        Args:
            value: Value evaluated while performing serialize JSON safely for
                direct embedding inside script tags.
            kwargs: Additional named values forwarded without changing their
                keys.

        Returns:
            The canonical JSON for script text.
        """

        return (
            json.dumps(value, **kwargs)
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029")
        )

    @staticmethod
    def has_unsafe_html_control(value: str) -> bool:
        """
        Return whether text contains a control forbidden in HTML contexts.

        After applying local validation, the function forwards ``value`` to
        ``any`` and preserves its return and exception contract.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            Whether text contains a control forbidden in HTML contexts.
        """

        return any(
            (ord(character) < 0x20 and character not in "\t\n\r")
            or ord(character) == 0x7F
            for character in value
        )

    @classmethod
    def escape_html_text(cls, value: Any) -> str:
        """
        Escape untrusted text and replace controls forbidden by HTML.

        After applying local validation, the function forwards ``value`` to
        ``escape`` and preserves its return and exception contract.

        Args:
            value: Value evaluated while performing escape untrusted text and
                replace controls forbidden by HTML.

        Returns:
            The canonical escape HTML text.
        """

        normalized = "".join(
            character if not cls.has_unsafe_html_control(character) else "\ufffd"
            for character in str(value)
        )
        return escape(normalized, quote=True)

    @classmethod
    def safe_external_url(cls, value: str) -> str | None:
        """
        Return an absolute HTTP(S) URL only when it is safe for navigation.

        The implementation uses ``value`` to produce an absolute HTTP(S) URL
        only when it is safe for navigation.

        Args:
            value: Text supplied as value in the format accepted by this
                function.

        Returns:
            The validated ``value``, or ``None`` when no value qualifies.
        """

        if cls.has_unsafe_html_control(value):
            return None
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
        except ValueError:
            return None
        if parsed.scheme.lower() not in {"http", "https"} or not hostname:
            return None
        return value

    @classmethod
    def encoded_relative_report_link(
        cls, node_name: str, relative_link: str
    ) -> str | None:
        """
        Encode a report-local link without permitting path reinterpretation.

        The implementation uses ``node_name`` and ``relative_link`` to encode a
        report-local link without permitting path reinterpretation.

        Args:
            node_name: Stable node name used for lookup and operator-facing
                diagnostics.
            relative_link: Text supplied as relative link in the format accepted
                by this function.

        Returns:
            The canonical encoded relative report link text, or ``None`` when
            the requested value is unavailable.
        """

        node_name = str(node_name)
        relative_link = str(relative_link)
        if (
            not node_name
            or not relative_link
            or cls.has_unsafe_html_control(node_name)
            or cls.has_unsafe_html_control(relative_link)
            or relative_link.startswith(("/", "\\"))
        ):
            return None

        segments = relative_link.split("/")
        if node_name in {".", ".."} or any(
            not segment or segment in {".", ".."} for segment in segments
        ):
            return None

        encoded_node = quote(node_name, safe="-._~")
        encoded_path = "/".join(quote(segment, safe="-._~") for segment in segments)
        return f"{encoded_node}/{encoded_path}"

    @classmethod
    def encoded_report_relative_path(cls, relative_link: str) -> str | None:
        """
        Percent-encode a report-relative path without changing its hierarchy.

        The path is rejected when a browser could reinterpret it as absolute,
        when it contains unsafe controls, or when any raw segment is empty or a
        dot traversal component. Each admitted segment is encoded independently
        so scheme-like filenames and fragment/query characters remain data.

        Args:
            relative_link: Report-relative path supplied by an artifact view.

        Returns:
            The encoded relative path, or ``None`` when it is unsafe.
        """
        relative_link = str(relative_link)
        if (
            not relative_link
            or cls.has_unsafe_html_control(relative_link)
            or relative_link.startswith(("/", "\\"))
        ):
            return None
        segments = relative_link.replace("\\", "/").split("/")
        if any(not segment or segment in {".", ".."} for segment in segments):
            return None
        return "/".join(quote(segment, safe="-._~") for segment in segments)

    @classmethod
    def make_links_clickable(cls, text: str) -> str:
        """
        Convert safe absolute HTTP(S) URLs in text to escaped links.

        After applying local validation, the function forwards ``text`` to
        ``join`` and preserves its return and exception contract. The source
        value keeps its ownership while the normalized representation is
        returned separately.

        Args:
            text: Text supplied as text in the format accepted by this function.

        Returns:
            The canonical make links clickable text.
        """

        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        output: list[str] = []
        cursor = 0
        for match in re.finditer(url_pattern, text):
            output.append(cls.escape_html_text(text[cursor : match.start()]))
            url = match.group(0)
            safe_url = cls.safe_external_url(url)
            if safe_url is None:
                output.append(cls.escape_html_text(url))
            else:
                escaped_url = cls.escape_html_text(safe_url)
                output.append(
                    f'<a href="{escaped_url}" target="_blank" '
                    f'rel="noopener noreferrer">{cls.escape_html_text(safe_url)}</a>'
                )
            cursor = match.end()
        output.append(cls.escape_html_text(text[cursor:]))
        return "".join(output)

    @staticmethod
    def format_bytes(size: float) -> str:
        """
        Convert a byte count into the legacy human-readable representation.

        The implementation uses ``size`` to convert a byte count into the legacy
        human-readable representation. The source value keeps its ownership
        while the normalized representation is returned separately.

        Args:
            size: Numeric size used by the operation's bounded accounting.

        Returns:
            The canonical bytes text.
        """

        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"

    @classmethod
    def build_system_details(cls, model: SystemDetailsRenderModel) -> str:
        """
        Render the system details card fragment from an immutable snapshot.

        The implementation uses ``model`` to render the system details card
        fragment from an immutable snapshot. The source value keeps its
        ownership while the normalized representation is returned separately.

        Args:
            model: Model object whose ``model``, ``part_number``, and
                ``serial_number`` state is read while performing system details
                card fragment from an immutable snapshot.

        Returns:
            The canonical system details text.
        """

        return f"""
        <h5>System Details</h5>
        <ul>
            <li><strong>Model:</strong> {cls.escape_html_text(model.model)}</li>
            <li><strong>Partno:</strong> {cls.escape_html_text(model.part_number)}</li>
            <li><strong>Serialno:</strong> {cls.escape_html_text(model.serial_number)}</li>
        </ul>
        """

    @classmethod
    def build_modal(cls, modal_id: str, modal_title: str, body_content: str) -> str:
        """
        Render one Bootstrap modal, treating only body content as trusted HTML.

        The implementation uses ``modal_id``, ``modal_title``, and
        ``body_content`` to render one Bootstrap modal, treating only body
        content as trusted HTML. The source value keeps its ownership while the
        normalized representation is returned separately.

        Args:
            modal_id: Stable modal identifier used to correlate configuration,
                logs, and results.
            modal_title: Text supplied as modal title in the format accepted by
                this function.
            body_content: Text supplied as body content in the format accepted
                by this function.

        Returns:
            The canonical modal text.
        """

        escaped_modal_id = cls.escape_html_text(modal_id)
        return f"""
        <div class="modal fade" id="{escaped_modal_id}" tabindex="-1" aria-labelledby="{escaped_modal_id}Label" aria-hidden="true">
            <div class="modal-dialog modal-xl">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="{escaped_modal_id}Label">{cls.escape_html_text(modal_title)}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        {body_content}
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
        """

    @classmethod
    def render_link_list_with_modal(
        cls,
        link_objects: Sequence[str],
        threshold: int,
        modal_id: str,
        modal_title: str,
    ) -> RenderedLinkList:
        """
        Render a deduplicated link list and return any modal separately.

        The implementation uses ``link_objects``, ``threshold``, ``modal_id``,
        and ``modal_title`` to render a deduplicated link list and return any
        modal separately. The source value keeps its ownership while the
        normalized representation is returned separately.

        Args:
            link_objects: Entries supplied as ``link_objects`` without
                transferring container ownership.
            threshold: Numeric threshold used while the operation performs
                bounded accounting.
            modal_id: Stable modal identifier used to correlate configuration,
                logs, and results.
            modal_title: Text supplied as modal title in the format accepted by
                this function.

        Returns:
            A ``RenderedLinkList`` representing link list with modal.
        """

        links = sorted(dict.fromkeys(link_objects))
        total_links = len(links)
        if total_links <= threshold:
            return RenderedLinkList("<br>".join(links) if links else "N/A")

        displayed_links = "<br>".join(links[:threshold])
        modal_body = "<br>".join(links[threshold:])
        modal_html = cls.build_modal(modal_id, modal_title, modal_body)
        html = (
            f"{displayed_links}"
            f'<br><a href="#" class="btn btn-secondary" data-bs-toggle="modal" '
            f'data-bs-target="#{cls.escape_html_text(modal_id)}">'
            f"Show remaining {total_links - threshold} file(s)</a>"
        )
        return RenderedLinkList(html=html, modal_html=modal_html)

    @classmethod
    def build_breadcrumbs(
        cls, links: Sequence[tuple[str, str]], active_text: str
    ) -> str:
        """
        Render breadcrumb navigation with escaped labels and destinations.

        After applying local validation, the function forwards ``links`` and
        ``active_text`` to ``join`` and preserves its return and exception
        contract. The source value keeps its ownership while the normalized
        representation is returned separately.

        Args:
            links: Entries supplied as ``links`` without transferring container
                ownership.
            active_text: Text supplied as active text in the format accepted by
                this function.

        Returns:
            The canonical breadcrumbs text.
        """

        output = ['<nav aria-label="breadcrumb"><ol class="breadcrumb">']
        for link_text, link_href in links:
            encoded_href = cls.encoded_report_relative_path(str(link_href))
            if encoded_href is None:
                output.append(
                    '<li class="breadcrumb-item">'
                    f"{cls.escape_html_text(link_text)}</li>"
                )
            else:
                output.append(
                    '<li class="breadcrumb-item">'
                    f'<a href="{cls.escape_html_text(encoded_href)}">'
                    f"{cls.escape_html_text(link_text)}</a></li>"
                )
        output.append(
            '<li class="breadcrumb-item active" aria-current="page">'
            f"{cls.escape_html_text(active_text)}</li>"
        )
        output.append("</ol></nav>")
        return "".join(output)

    @classmethod
    def render_page(cls, model: HTMLPageRenderModel) -> str:
        """
        Render one complete document without performing publication I/O.

        After applying local validation, the function forwards ``model`` to
        ``model.template.format`` and preserves its return and exception
        contract. The source value keeps its ownership while the normalized
        representation is returned separately.

        Args:
            model: Model object whose ``back_button``, ``content``, ``format``,
                ``navbar``, and ``page_icon`` state is read while performing one
                complete document without performing publication I/O.

        Returns:
            The canonical page text.
        """

        safe_page_title = cls.escape_html_text(model.page_title)
        page_header = ""

        if model.back_button is not None:
            page_header = (
                '<div class="d-flex justify-content-between align-items-center mb-4">'
            )
            page_header += "<div>"

        page_header += "<h1>"
        if model.page_icon:
            page_header += model.page_icon
        page_header += safe_page_title
        page_header += "</h1>"

        if model.subtitle:
            page_header += (
                f'<p class="text-muted mb-0">{cls.escape_html_text(model.subtitle)}</p>'
            )

        if model.back_button is not None:
            page_header += "</div>"
            page_header += (
                f'<a href="{cls.escape_html_text(model.back_button.url)}" '
                'class="btn btn-outline-primary">'
                f"{cls.escape_html_text(model.back_button.text)}</a>"
            )
            page_header += "</div>"

        return model.template.format(
            title=safe_page_title,
            navbar=model.navbar,
            content=page_header + model.content,
        )

    @classmethod
    def json_tree_html(cls, data: Any, max_depth: int = 64) -> str:
        """
        Render a colorized, collapsible JSON tree.

        The implementation uses ``data`` to render a colorized, collapsible JSON
        tree. The source value keeps its ownership while the normalized
        representation is returned separately.

        Args:
            data: Data consumed while the function attempts to render a
                colorized, collapsible JSON tree.
            max_depth: Maximum nested container depth rendered inline.

        Returns:
            The canonical JSON tree HTML text.

        Raises:
            ValueError: If ``max_depth`` is not a positive integer.
        """

        if type(max_depth) is not int or max_depth < 1:
            raise ValueError("max_depth must be a positive integer")

        def render_json(obj: Any, depth: int = 0) -> str:
            """
            Render JSON.

            The implementation uses ``obj`` to render JSON. The source value
            keeps its ownership while the normalized representation is returned
            separately.

            Args:
                obj: Object whose ``items`` state is read while
                    performing JSON.
                depth: Current nested container depth.

            Returns:
                The canonical JSON text.
            """
            if isinstance(obj, (dict, list)) and depth > max_depth:
                return (
                    '<span class="json-depth-limit">nesting depth exceeded; '
                    "download the artifact to inspect</span>"
                )
            if isinstance(obj, dict):
                if not obj:
                    return '<span class="json-brace">{}</span>'
                html = ['<span class="json-brace">{</span>']
                html.append('<div class="json-block" style="display: block;">')
                items = list(obj.items())
                for index, (key, value) in enumerate(items):
                    html.append('<div class="json-item">')
                    html.append(
                        '<span class="json-key">"'
                        f"{cls.escape_html_text(key)}"
                        '"</span>'
                    )
                    html.append('<span class="json-colon">: </span>')
                    html.append('<span class="json-value">')
                    html.append(render_json(value, depth + 1))
                    html.append("</span>")
                    if index < len(items) - 1:
                        html.append('<span class="json-comma">,</span>')
                    html.append("</div>")
                html.append("</div>")
                html.append('<span class="json-brace">}</span>')
                return "".join(html)

            if isinstance(obj, list):
                if not obj:
                    return '<span class="json-bracket">[]</span>'
                html = ['<span class="json-bracket">[</span>']
                html.append('<div class="json-block" style="display: block;">')
                for index, value in enumerate(obj):
                    html.append('<div class="json-item">')
                    html.append(render_json(value, depth + 1))
                    if index < len(obj) - 1:
                        html.append('<span class="json-comma">,</span>')
                    html.append("</div>")
                html.append("</div>")
                html.append('<span class="json-bracket">]</span>')
                return "".join(html)

            return render_scalar(obj)

        def render_scalar(value: Any) -> str:
            """
            Render scalar.

            The implementation uses ``value`` to render scalar. The source value
            keeps its ownership while the normalized representation is returned
            separately.

            Args:
                value: Value evaluated while performing scalar.

            Returns:
                The canonical scalar text.
            """
            if value is None:
                return '<span class="json-literal json-null">null</span>'
            if isinstance(value, bool):
                return f'<span class="json-literal json-boolean">{"true" if value else "false"}</span>'
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return (
                    '<span class="json-literal json-number">'
                    f"{cls.escape_html_text(value)}</span>"
                )
            return (
                '<span class="json-string">"'
                f"{cls.escape_html_text(value)}"
                '"</span>'
            )

        tree_html = render_json(data)
        return f"""
        <div class="json-container">
            {tree_html}
        </div>
        <script>
        // Collapsing/expanding logic:
        // We'll let users click on the brace/bracket to toggle the block that follows it.
        document.addEventListener('DOMContentLoaded', function() {{
            const braces = document.querySelectorAll('.json-brace, .json-bracket');
            braces.forEach(function(braceEl) {{
                braceEl.style.cursor = 'pointer';
                braceEl.addEventListener('click', function(e) {{
                    e.stopPropagation();
                    // The ".json-block" that immediately follows
                    const sibling = braceEl.nextElementSibling;
                    if(sibling && sibling.classList.contains('json-block')) {{
                        if(sibling.style.display === 'none') {{
                            sibling.style.display = 'block';
                        }} else {{
                            sibling.style.display = 'none';
                        }}
                    }}
                }});
            }});
        }});
        </script>
        <style>
        .json-container {{
            font-family: monospace;
            line-height: 1.4em;
            font-size: 14px;
            color: #333;
        }}
        .json-block {{
            margin-left: 1.5em;
            border-left: 1px dotted #ccc;
            padding-left: 1em;
        }}
        .json-item {{
            margin: 2px 0;
        }}
        .json-key {{
            color: #92278f;  /* purple-ish for keys */
        }}
        .json-literal.json-boolean {{
            color: #1a01cc;  /* bluish for booleans */
        }}
        .json-literal.json-null {{
            color: #777;     /* gray for null */
        }}
        .json-literal.json-number {{
            color: #0086b3;  /* teal-like for numbers */
        }}
        .json-string {{
            color: #c41a16;  /* dark red for strings */
        }}
        .json-colon {{
            color: #555;
        }}
        .json-comma {{
            color: #555;
            margin-left: 1px;
        }}
        .json-brace, .json-bracket {{
            color: #4b6eaf;
            font-weight: bold;
            margin-right: 3px;
        }}
        </style>
        """
