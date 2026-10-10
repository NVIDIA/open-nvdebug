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
Synchronous file reading and rendering for HTML report file views.

The report service owns async orchestration and logging. This module owns the
bounded filesystem read plus the deterministic JSON, text, and download page
rendering boundary so it can run outside the event-loop thread.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .html_report_renderer import HTMLReportRenderer

escape = HTMLReportRenderer.escape_html_text

__all__ = ["HTMLReportFileView", "PreparedTextView", "TextViewResult"]


def _encoded_download_href(relative_file: str) -> str | None:
    """
    Percent-encode a download target without letting it reconstitute a scheme.

    ``relative_file`` is the ``os.path.relpath`` result pointing from a generated
    download page back to its source artifact, so it legitimately begins with one
    or more ``..``/``.`` traversal segments. Those leading traversal segments are
    kept verbatim (a browser never reads a ``../`` prefix as a URL scheme), while
    the remaining report-relative tail is routed through the report renderer's
    ``encoded_report_relative_path`` URL-safety encoder used at every sibling
    href. Each admitted tail segment is percent-encoded, so a device-controlled
    basename such as ``javascript:alert(1)`` becomes ``javascript%3Aalert%281%29``
    and can never be reinterpreted as an executable scheme, regardless of the
    surrounding directory layout. The whole-path encoder cannot be used directly
    because it rejects the leading ``..`` segments this link requires.

    Args:
        relative_file: Slash-or-backslash separated relative path from the
            download page to the source artifact.

    Returns:
        The percent-encoded relative href, or ``None`` when the report-relative
        tail is unsafe (empty, absolute, or containing an unsafe control or an
        interior traversal component); the caller renders a disabled control in
        that case.
    """

    segments = str(relative_file).replace("\\", "/").split("/")
    prefix_length = 0
    for segment in segments:
        if segment in {".", ".."}:
            prefix_length += 1
        else:
            break
    traversal_prefix = segments[:prefix_length]
    tail = "/".join(segments[prefix_length:])
    encoded_tail = HTMLReportRenderer.encoded_report_relative_path(tail)
    if encoded_tail is None:
        return None
    return "/".join([*traversal_prefix, encoded_tail])


@dataclass(frozen=True, slots=True)
class PreparedTextView:
    """
    Bounded text-read result awaiting rendering or already download-only.

    The immutable record keeps ``display_name``, ``text_data``, ``link``, and
    ``read_error`` together so consumers observe one prepared text view state.
    Consumers receive the fields as one unit instead of assembling partial
    state.

    Attributes:
        display_name: Canonical text used as display name.
        text_data: Canonical text used as text data.
        link: Canonical text used as link.
        read_error: Read error retained as part of the record's public state.
    """

    display_name: str
    text_data: str | None = None
    link: str | None = None
    read_error: Exception | None = None


@dataclass(frozen=True, slots=True)
class TextViewResult:
    """
    Rendered text-view link and an optional read error for async logging.

    The immutable record keeps ``link`` and ``read_error`` together so consumers
    observe one text view state. Consumers receive the fields as one unit
    instead of assembling partial state.

    Attributes:
        link: Canonical text used as link.
        read_error: Read error retained as part of the record's public state.
    """

    link: str
    read_error: Exception | None = None


@dataclass(frozen=True, slots=True)
class HTMLReportFileView:
    """
    Render file-view pages using service-owned paths and page templates.

    The immutable record keeps ``root_dir``, ``report_dir``,
    ``max_parseable_file_size``, ``log_files_with_viewer``, and ``format_bytes``
    together so consumers observe one HTML report file view state. Consumers
    receive the fields as one unit instead of assembling partial state.

    Attributes:
        root_dir: Root dir retained as part of the record's public state.
        report_dir: Report dir retained as part of the record's public state.
        max_parseable_file_size: Maximum parseable file size admitted by this
            record.
        log_files_with_viewer: Canonical text used as log files with viewer.
        format_bytes: Byte count recorded for format.
        logical_relative_path: Map an authorized input to its bundle-relative
            logical path.
        get_html_output_path: Validated filesystem location associated with get
            HTML output path.
        get_html_output_path_for_file: Get HTML output path for file retained as
            part of the record's public state.
        write_html_report: Canonical text used as write HTML report.
        json_tree_html: Canonical text used as JSON tree HTML.
        generate_log_viewer: Canonical text used as generate log viewer.
        inspect_input: Inspect input retained as part of the record's public
            state.
        read_json: Read JSON retained as part of the record's public state.
        read_text: Canonical text used as read text.
        fail_closed_exceptions: Collection of fail closed exceptions entries
            retained by this record.
    """

    root_dir: Path
    report_dir: Path
    max_parseable_file_size: int
    log_files_with_viewer: Collection[str]
    format_bytes: Callable[[float], str]
    logical_relative_path: Callable[[Path], Path]
    get_html_output_path: Callable[[Path, str], Path]
    get_html_output_path_for_file: Callable[[Path], Path]
    write_html_report: Callable[[Path, str, str], str]
    json_tree_html: Callable[[Any], str]
    generate_log_viewer: Callable[[str, str], str]
    inspect_input: Callable[[Path], Any]
    read_json: Callable[[Path], Any]
    read_text: Callable[[Path], str]
    fail_closed_exceptions: tuple[type[BaseException], ...]

    def __post_init__(self) -> None:
        """
        Reject construction without every hardened filesystem safety seam.

        The file-view boundary must never fall back to path-following standard
        library reads. Callers therefore provide no-follow inspection, bounded
        JSON/text readers, and at least one exception type that remains
        fail-closed across view-level fallback handling.

        Raises:
            ValueError: If the fail-closed exception set is empty.
        """
        if not self.fail_closed_exceptions:
            raise ValueError("fail_closed_exceptions must not be empty")

    def generate_download_view(
        self,
        file_path: Path,
        display_name: str | None = None,
        message: str | None = None,
    ) -> str:
        """
        Generate a page offering a direct download link for a file.

        After applying local validation, the function forwards ``file_path``,
        ``display_name``, and ``message`` to ``self._relative_report_link`` and
        preserves its return and exception contract. Filesystem effects remain
        confined to the caller-selected paths and the owning resource lifecycle.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            display_name: Stable display name used for lookup and
                operator-facing diagnostics.
            message: Operator-facing text carried by the reported event or
                failure.

        Returns:
            The canonical generate download view text.
        """

        display_name = display_name or file_path.name
        if message is None:
            message = "Unable to parse this file. Please download to view."

        download_html_name = f"{file_path.name}_download.html"
        html_file_path = self.get_html_output_path(file_path.parent, download_html_name)
        logical_file_path = self.root_dir / self.logical_relative_path(file_path)
        relative_file = os.path.relpath(
            logical_file_path, os.path.dirname(html_file_path)
        ).replace("\\", "/")

        # Route the href through the report's URL-safety encoder (as every
        # sibling href does) so a device-controlled filename cannot reconstitute
        # a URL scheme such as "javascript:". Fall back to a disabled control
        # when the report-relative path is not a safe link.
        safe_href = _encoded_download_href(relative_file)
        if safe_href is None:
            download_control = (
                '<p><span class="text-muted">'
                f"Download unavailable for {escape(display_name)}</span></p>"
            )
        else:
            download_control = (
                f'<p><a href="{escape(safe_href)}" download '
                'class="btn btn-primary btn-lg">'
                '<i class="bi bi-download"></i> '
                f"Download {escape(display_name)}</a></p>"
            )

        try:
            file_size = self._input_size(file_path)
            file_size_str = self.format_bytes(file_size)
        except Exception as error:
            self._raise_if_fail_closed(error)
            file_size_str = "Unknown size"

        content = f"""
        <div class="card">
            <div class="card-body">
                <h2>File: {escape(display_name)}</h2>
                <div class="alert alert-info" role="alert">
                    <i class="bi bi-info-circle"></i> {escape(message)}
                </div>
                <p><strong>File Size:</strong> {file_size_str}</p>
                {download_control}
            </div>
        </div>
        """
        rel_html_path = self.write_html_report(
            html_file_path, f"Download: {display_name}", content
        )
        return self._relative_report_link(file_path, rel_html_path)

    def download_view_if_too_large(
        self, file_path: Path, display_name: str
    ) -> str | None:
        """
        Return a download-only view when the file's current size exceeds the cap.

        Preserve the legacy best-effort size check: a failed stat or download
        attempt falls through to the bounded parse attempt.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            display_name: Stable display name used for lookup and
                operator-facing diagnostics.

        Returns:
            The canonical download view if too large text, or ``None`` when the
            requested value is unavailable.
        """

        try:
            file_size = self._input_size(file_path)
            if file_size > self.max_parseable_file_size:
                return self._generate_too_large_download(
                    file_path, display_name, file_size
                )
        except Exception as error:
            self._raise_if_fail_closed(error)
            # Preserve the legacy best-effort size check: a failed stat or download
            # attempt falls through to the bounded parse attempt.
            pass
        return None

    def generate_json_view(
        self, file_path: Path, display_name: str | None = None
    ) -> str:
        """
        Generate a collapsible JSON view or a download fallback.

        The implementation uses ``file_path`` and ``display_name`` to generate a
        collapsible JSON view or a download fallback.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            display_name: Stable display name used for lookup and
                operator-facing diagnostics.

        Returns:
            The canonical generate JSON view text.
        """

        display_name = display_name or file_path.name
        maybe = self.download_view_if_too_large(file_path, display_name)
        if maybe:
            return maybe

        try:
            data = self.read_json(file_path)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self.generate_download_view(file_path, display_name)
        except Exception as error:
            self._raise_if_fail_closed(error)
            data = {"error": f"Error reading file: {error}"}

        try:
            tree_html = self.json_tree_html(data)
        except RecursionError:
            return self.generate_download_view(
                file_path,
                display_name,
                "JSON nesting exceeded the report renderer; download the artifact "
                "to inspect.",
            )
        content = f"""
        <div class="card">
            <div class="card-body">
                <h2>File: {escape(display_name)}</h2>
                <div id="jsonTree" class="json-tree">{tree_html}</div>
            </div>
        </div>
        """
        content += """
        <script>
        function toggleChildren(event) {
          event.stopPropagation();
          var next = this.nextElementSibling;
          if (next) {
             if (next.style.display === "none") {
                 next.style.display = "block";
             } else {
                 next.style.display = "none";
             }
          }
        }
        document.addEventListener("DOMContentLoaded", function() {
          var toggles = document.getElementsByClassName("json-toggle");
          for (var i = 0; i < toggles.length; i++) {
             toggles[i].addEventListener("click", toggleChildren);
          }
        });
        function jsonGlobalSearch(query) {
          var tree = document.getElementById("jsonTree");
          if(!tree) return;
          var spans = tree.getElementsByTagName("span");
          for (var i = 0; i < spans.length; i++) {
             spans[i].style.backgroundColor = "";
          }
          if(query === "") return;
          query = query.toLowerCase();
          for (var i = 0; i < spans.length; i++) {
             var txt = spans[i].innerText || spans[i].textContent;
             if(txt.toLowerCase().indexOf(query) > -1) {
                spans[i].style.backgroundColor = "yellow";
                var li = spans[i].closest("li");
                if(li) li.style.display = "";
             }
          }
        }
        </script>
        <style>
        .json-tree ul { list-style-type: none; margin-left: 20px; padding-left: 10px; border-left: 1px solid #ccc; }
        .json-toggle { cursor: pointer; font-weight: bold; }
        .json-value { color: #555; }
        </style>
        """
        html_file_path = self.get_html_output_path_for_file(file_path)
        rel_html_path = self.write_html_report(
            html_file_path, f"View: {display_name}", content
        )
        return self._relative_report_link(file_path, rel_html_path)

    def generate_text_view(
        self, file_path: Path, display_name: str | None = None
    ) -> TextViewResult:
        """
        Synchronously prepare and render a text/log view.

        After applying local validation, the function forwards ``file_path`` and
        ``display_name`` to ``self.render_text_view`` and preserves its return
        and exception contract.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            display_name: Stable display name used for lookup and
                operator-facing diagnostics.

        Returns:
            A ``TextViewResult`` representing generate text view.
        """

        prepared = self.prepare_text_view(file_path, display_name)
        return self.render_text_view(file_path, prepared)

    def prepare_text_view(
        self, file_path: Path, display_name: str | None = None
    ) -> PreparedTextView:
        """
        Read text within the byte cap, returning any error for async logging.

        The implementation uses ``file_path`` and ``display_name`` to read text
        within the byte cap, returning any error for async logging. Parsing or
        I/O must finish before the validated representation is made available to
        the caller.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            display_name: Stable display name used for lookup and
                operator-facing diagnostics.

        Returns:
            A ``PreparedTextView`` representing prepare text view.
        """

        display_name = display_name or file_path.name
        maybe = self.download_view_if_too_large(file_path, display_name)
        if maybe:
            return PreparedTextView(display_name=display_name, link=maybe)

        read_error: Exception | None = None
        try:
            text_data = self.read_text(file_path)
        except UnicodeDecodeError:
            return PreparedTextView(
                display_name=display_name,
                link=self.generate_download_view(file_path, display_name),
            )
        except Exception as error:
            self._raise_if_fail_closed(error)
            text_data = f"Error reading file: {error}"
            read_error = error

        return PreparedTextView(
            display_name=display_name,
            text_data=text_data,
            read_error=read_error,
        )

    def render_text_view(
        self, file_path: Path, prepared: PreparedTextView
    ) -> TextViewResult:
        """
        Render prepared text, preserving the legacy interactive-viewer routing.

        The implementation uses ``file_path`` and ``prepared`` to render
        prepared text, preserving the legacy interactive-viewer routing. The
        source value keeps its ownership while the normalized representation is
        returned separately.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            prepared: Prepared object whose ``display_name``, ``link``,
                ``read_error``, and ``text_data`` state is read while performing
                prepared text, preserving the legacy interactive-viewer routing.

        Returns:
            A ``TextViewResult`` representing text view.
        """

        if prepared.link is not None:
            return TextViewResult(prepared.link, prepared.read_error)
        assert prepared.text_data is not None

        if file_path.name in self.log_files_with_viewer or file_path.name.endswith(
            "_stdout.log"
        ):
            content = self.generate_log_viewer(
                prepared.text_data, prepared.display_name
            )
        else:
            content = f"""
            <div class="card">
                <div class="card-body">
                    <h2>File: {escape(prepared.display_name)}</h2>
                    <div class="file-view"><pre id="textView"><code class="language-json">{escape(prepared.text_data)}</code></pre></div>
                </div>
            </div>
            """
            content += """
            <script>
            var textViewOriginalContent = null;
            function textGlobalSearch(query) {
               var pre = document.getElementById("textView");
               if(!pre) return;
               if(textViewOriginalContent === null) {
                  textViewOriginalContent = pre.textContent || "";
               }

               pre.replaceChildren();
               if(query === "") {
                  pre.textContent = textViewOriginalContent;
                  return;
               }

               var sourceText = textViewOriginalContent;
               var searchText = String(query);
               var normalizedSource = sourceText.toLowerCase();
               var normalizedSearch = searchText.toLowerCase();
               var cursor = 0;
               var matchIndex = normalizedSource.indexOf(normalizedSearch, cursor);

               while(matchIndex !== -1) {
                  if(matchIndex > cursor) {
                     pre.appendChild(document.createTextNode(
                        sourceText.slice(cursor, matchIndex)
                     ));
                  }
                  var mark = document.createElement("mark");
                  mark.textContent = sourceText.slice(
                     matchIndex,
                     matchIndex + searchText.length
                  );
                  pre.appendChild(mark);
                  cursor = matchIndex + searchText.length;
                  matchIndex = normalizedSource.indexOf(normalizedSearch, cursor);
               }

               if(cursor < sourceText.length) {
                  pre.appendChild(document.createTextNode(sourceText.slice(cursor)));
               }
            }
            </script>
            """

        html_file_path = self.get_html_output_path_for_file(file_path)
        rel_html_path = self.write_html_report(
            html_file_path, f"View: {prepared.display_name}", content
        )
        return TextViewResult(
            self._relative_report_link(file_path, rel_html_path), prepared.read_error
        )

    def _input_size(self, file_path: Path) -> int:
        """
        Return size through the service's no-follow inspection seam when bound.

        The implementation uses ``file_path`` to produce size through the
        service's no-follow inspection seam when bound. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle. If the function cannot produce size through the service's
        no-follow inspection seam when bound, its exception reaches the caller
        instead of being converted into a successful result.

        Args:
            file_path: filesystem location used as the file path for this
                operation.

        Returns:
            The numeric input size.

        Raises:
            FileNotFoundError: If the function cannot produce size through the
                service's no-follow inspection seam when bound safely.
        """

        entry = self.inspect_input(file_path)
        if entry is None or not entry.is_file:
            raise FileNotFoundError(file_path)
        return entry.metadata.st_size

    def _raise_if_fail_closed(self, error: BaseException) -> None:
        """
        Preserve service-owned safety failures across the extracted boundary.

        The implementation uses ``error`` to preserve service-owned safety
        failures across the extracted boundary. If the function cannot preserve
        service-owned safety failures across the extracted boundary, its
        exception reaches the caller instead of being converted into a
        successful result.

        Args:
            error: Exception or failure detail associated with the operation.

        Raises:
            BaseException: If a delegated failure occurs while the function
                attempts to preserve service-owned safety failures across the
                extracted boundary.
        """

        if self.fail_closed_exceptions and isinstance(
            error, self.fail_closed_exceptions
        ):
            raise error

    def _generate_too_large_download(
        self, file_path: Path, display_name: str, file_size: int
    ) -> str:
        """
        Generate too large download.

        After applying local validation, the function forwards ``file_path``,
        ``display_name``, and ``file_size`` to ``self.generate_download_view``
        and preserves its return and exception contract.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            display_name: Stable display name used for lookup and
                operator-facing diagnostics.
            file_size: Numeric file size used by the operation's bounded
                accounting.

        Returns:
            The canonical generate too large download text.
        """
        file_size_mb = file_size / (1024 * 1024)
        message = (
            f"This file is too large ({file_size_mb:.1f} MB) to parse and display in the browser. "
            f"Files larger than {self.max_parseable_file_size / (1024 * 1024):.0f} MB are download-only for performance. "
            f"Please download the file to view it locally."
        )
        return self.generate_download_view(file_path, display_name, message)

    def _relative_report_link(self, file_path: Path, rel_html_path: str) -> str:
        """
        Return the relative report link.

        After applying local validation, the function forwards ``file_path`` and
        ``rel_html_path`` to ``replace`` and preserves its return and exception
        contract. Filesystem effects remain confined to the caller-selected
        paths and the owning resource lifecycle.

        Args:
            file_path: filesystem location used as the file path for this
                operation.
            rel_html_path: filesystem location used as the rel HTML path for
                this operation.

        Returns:
            The canonical relative report link text.

        Raises:
            ValueError: If the mapped input has no logical node component.
        """
        logical_path = self.logical_relative_path(file_path)
        if not logical_path.parts:
            raise ValueError("file view input has no logical node component")
        node_name = logical_path.parts[0]
        base_dir = self.report_dir / node_name
        return os.path.relpath(self.report_dir / rel_html_path, base_dir).replace(
            "\\", "/"
        )
