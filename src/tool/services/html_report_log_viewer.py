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
Immutable browser projection for the legacy runtime-log viewer.

This module owns the html report log viewer boundary and exposes
``LogViewerRenderModel`` and ``HTMLReportLogViewer``. Keeping those contracts
together gives importers one source of truth for their validation, lifecycle,
and compatibility behavior.
"""

from __future__ import annotations

from dataclasses import dataclass

from .html_report_renderer import HTMLReportRenderer

escape = HTMLReportRenderer.escape_html_text

__all__ = ["HTMLReportLogViewer", "LogViewerRenderModel"]


@dataclass(frozen=True, slots=True)
class LogViewerRenderModel:
    """
    Complete precomputed inputs for one runtime-log browser projection.

    The immutable record keeps ``text_data``, ``display_name``,
    ``parser_metadata_json``, ``levels``, and ``components`` together so
    consumers observe one log viewer render model state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        text_data: Canonical text used as text data.
        display_name: Canonical text used as display name.
        parser_metadata_json: Canonical text used as parser metadata JSON.
        levels: Collection of levels entries retained by this record.
        components: Collection of components entries retained by this record.
    """

    text_data: str
    display_name: str
    parser_metadata_json: str
    levels: tuple[str, ...] = ()
    components: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class HTMLReportLogViewer:
    """
    Render the legacy runtime-log browser without parsing or performing I/O.

    The type coordinates ``render`` and retains the state those operations share
    between calls. Resource ownership remains inside the instance until the
    matching close, exit, or cleanup operation completes.
    """

    @staticmethod
    def render(model: LogViewerRenderModel) -> str:
        """
        Return the exact legacy HTML/CSS/JavaScript browser projection.

        The implementation uses ``model`` to produce the exact legacy
        HTML/CSS/JavaScript browser projection.

        Args:
            model: Model object whose ``components``, ``display_name``,
                ``levels``, ``parser_metadata_json``, and ``text_data`` state is
                read while performing exact legacy HTML/CSS/JavaScript browser
                projection.

        Returns:
            The validated ``content``.
        """

        text_data = model.text_data
        display_name = model.display_name
        parser_metadata_json = model.parser_metadata_json
        levels = model.levels
        components = model.components

        level_filter_disabled = "" if levels else " disabled"
        component_filter_disabled = "" if components else " disabled"
        level_default = "All Levels" if levels else "No levels detected"
        component_default = "All Components" if components else "No components detected"
        content = f"""
        <div class="card mb-3">
            <div class="card-body">
                <h2>Runtime Log Viewer: {escape(display_name)}</h2>
                <p class="text-muted">Interactive log viewer with filtering and syntax highlighting</p>

                <!-- Filter Controls -->
                <div class="row mb-3">
                    <div class="col-md-4">
                        <label class="form-label fw-bold">Search</label>
                        <input type="text" id="logSearch" class="form-control" placeholder="Search logs...">
                    </div>
                    <div class="col-md-4">
                        <label class="form-label fw-bold">Log Level</label>
                        <select id="levelFilter" class="form-select"{level_filter_disabled}>
                            <option value="">{level_default}</option>
                            {''.join(f'<option value="{escape(level)}">{escape(level)}</option>' for level in levels)}
                        </select>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label fw-bold">Component</label>
                        <select id="componentFilter" class="form-select"{component_filter_disabled}>
                            <option value="">{component_default}</option>
                            {''.join(f'<option value="{escape(comp)}">{escape(comp)}</option>' for comp in components)}
                        </select>
                    </div>
                </div>

                <!-- Stats -->
                <div class="d-flex gap-3 mb-3">
                    <span class="badge bg-secondary">Total: <span id="totalLines">0</span> lines</span>
                    <span class="badge bg-primary">Visible: <span id="visibleLines">0</span> lines</span>
                    <button class="btn btn-sm btn-outline-secondary" onclick="copyLog()">
                        <i class="bi bi-clipboard"></i> Copy Filtered
                    </button>
                    <button class="btn btn-sm btn-outline-secondary" onclick="downloadLog()">
                        <i class="bi bi-download"></i> Download Filtered
                    </button>
                    <button class="btn btn-sm btn-outline-secondary" onclick="toggleWrap()">
                        <i class="bi bi-text-wrap"></i> Toggle Wrap
                    </button>
                </div>

                <!-- Log Content -->
                <div id="logContainer" class="border rounded" style="background: #1e1e1e !important; max-height: 600px; overflow: auto;">
                    <pre id="logView" style="margin: 0; padding: 15px; color: #f0f0f0 !important; background: #1e1e1e !important; font-family: 'Consolas', 'Monaco', 'Courier New', monospace; font-size: 13px; line-height: 1.5; text-shadow: none !important; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;"><code class="language-nvdebug" style="background: #1e1e1e !important; color: #f0f0f0 !important; text-shadow: none !important;">{escape(text_data)}</code></pre>
                </div>
            </div>
        </div>

        <style>
        /* Log viewer custom styles - Force dark theme and crisp rendering */
        /* Override Prism.js default styles completely */
        #logContainer *,
        #logContainer,
        #logContainer pre,
        #logContainer code,
        #logContainer pre[class*="language-"],
        #logContainer code[class*="language-"],
        #logContainer .token,
        #logContainer span {{
            background: #1e1e1e !important;
            color: #f0f0f0 !important;
            text-shadow: none !important;
            -webkit-font-smoothing: antialiased !important;
            -moz-osx-font-smoothing: grayscale !important;
            text-rendering: optimizeLegibility !important;
        }}
        .log-line {{
            display: block;
            border-left: 3px solid transparent;
            padding-left: 8px;
            margin: 2px 0;
        }}
        .log-line.log-ERROR,
        .log-line.log-CRITICAL {{
            background-color: rgba(249, 117, 131, 0.1);
            border-left-color: #f97583;
        }}
        .log-line.log-WARNING,
        .log-line.log-WARN {{
            background-color: rgba(255, 171, 112, 0.1);
            border-left-color: #ffab70;
        }}
        .log-line.log-INFO {{
            background-color: rgba(86, 182, 194, 0.05);
            border-left-color: #56b6c2;
        }}
        .log-line.log-DEBUG {{
            background-color: rgba(158, 158, 158, 0.05);
            border-left-color: #9e9e9e;
        }}
        .log-line.hidden {{
            display: none !important;
        }}
        #logContainer .log-timestamp {{
            color: #999999 !important;
            text-shadow: none !important;
        }}
        .log-level {{
            font-weight: bold;
            padding: 2px 6px;
            border-radius: 3px;
            text-shadow: none !important;
        }}
        #logContainer .log-level-INFO {{
            color: #56b6c2 !important;
            text-shadow: none !important;
        }}
        #logContainer .log-level-DEBUG {{
            color: #9e9e9e !important;
            text-shadow: none !important;
        }}
        #logContainer .log-level-ERROR,
        #logContainer .log-level-CRITICAL {{
            color: #f97583 !important;
            text-shadow: none !important;
        }}
        #logContainer .log-level-WARNING,
        #logContainer .log-level-WARN {{
            color: #ffab70 !important;
            text-shadow: none !important;
        }}
        #logContainer .log-component {{
            color: #4db8a8 !important;
            font-weight: 600;
            text-shadow: none !important;
        }}
        #logContainer .log-message {{
            color: #f0f0f0 !important;
            text-shadow: none !important;
        }}
        #logContainer .log-separator {{
            color: #888888 !important;
            opacity: 0.5;
            border-top: 1px solid #555;
            margin: 10px 0;
            text-shadow: none !important;
        }}
        #logContainer mark {{
            background-color: #ffeb3b !important;
            color: #000 !important;
            padding: 2px 4px;
            border-radius: 2px;
            text-shadow: none !important;
        }}
        </style>

        <script>
        // Define custom Prism language for nvdebug logs
        Prism.languages.nvdebug = {{
            'timestamp': /\\[\\d{{4}}-\\d{{2}}-\\d{{2}}\\s+\\d{{2}}:\\d{{2}}:\\d{{2}}\\.\\d{{3}}\\]/,
            'level-error': /\\[ERROR\\]/,
            'level-warning': /\\[WARNING\\]/,
            'level-info': /\\[INFO\\]/,
            'level-debug': /\\[DEBUG\\]/,
            'component': /\\]\\s+\\[([^\\]]+)\\]/,
            'separator': /^[=+\\-]{{2,}}.*$/m,
            'string': /"(?:\\\\.|[^"\\\\])*"/
        }};

        // Keep the potentially large log body only in the code element above.
        // This compact metadata uses the same parser contract as Python.
        const logParserMetadata = {parser_metadata_json};
        const logParsers = logParserMetadata.parsers.map(parser => ({{
            ...parser,
            regex: new RegExp(parser.pattern)
        }}));

        // Parse and render logs with structure
        document.addEventListener('DOMContentLoaded', function() {{
            parseAndRenderLogs();

            document.getElementById('logSearch').addEventListener('input', filterLogs);
            document.getElementById('levelFilter').addEventListener('change', filterLogs);
            document.getElementById('componentFilter').addEventListener('change', filterLogs);

        }});

        let logLines = [];
        let wrapEnabled = false;

        function groupValue(match, groupIndex, trimValue) {{
            if (!groupIndex) {{
                return null;
            }}
            const value = match[groupIndex];
            if (value === undefined || value === null) {{
                return null;
            }}
            return trimValue ? value.trim() : value;
        }}

        function parseLogLine(line) {{
            let best = null;
            let bestScore = -1;

            for (const parser of logParsers) {{
                const match = parser.regex.exec(line);
                if (!match) {{
                    continue;
                }}

                const timestamp = groupValue(
                    match, parser.groups.timestamp, true
                );
                const level = groupValue(match, parser.groups.level, true);
                const component = groupValue(
                    match, parser.groups.component, true
                );
                const parsedMessage = groupValue(
                    match, parser.groups.message, false
                );
                let parts = parser.tokens.map(token => {{
                    if (Object.prototype.hasOwnProperty.call(token, 'text')) {{
                        return {{ role: 'literal', text: token.text }};
                    }}
                    return {{
                        role: token.role,
                        text: match[token.group] || ''
                    }};
                }});
                if (parts.map(part => part.text).join('') !== line) {{
                    parts = [{{ role: 'plain', text: line }}];
                }}

                const score = [timestamp, level, component].filter(Boolean).length;
                if (score > bestScore) {{
                    best = {{
                        raw: line,
                        timestamp: timestamp,
                        level: level,
                        component: component,
                        message: parsedMessage === null ? line : parsedMessage,
                        parts: parts,
                        parsed: true,
                        visible: true
                    }};
                    bestScore = score;
                }}
            }}

            return best || {{
                raw: line,
                timestamp: null,
                level: null,
                component: null,
                message: line,
                parts: [{{ role: 'plain', text: line }}],
                parsed: false,
                visible: true
            }};
        }}

        function parseAndRenderLogs() {{
            const logView = document.getElementById('logView');
            const code = logView.querySelector('code');
            const text = code.textContent;
            const lines = text.split('\\n');

            // Show loading indicator for large logs
            if (lines.length > 5000) {{
                code.innerHTML = '<span style="color: #0dcaf0;">Parsing ' + lines.length + ' log lines...</span>';
            }}

            // Parse in chunks to avoid blocking UI
            const chunkSize = 1000;
            let chunkIndex = 0;

            function parseChunk() {{
                const start = chunkIndex * chunkSize;
                const end = Math.min(start + chunkSize, lines.length);

                for (let i = start; i < end; i++) {{
                    logLines.push(parseLogLine(lines[i]));
                }}

                chunkIndex++;

                if (end < lines.length) {{
                    // Continue parsing in next frame
                    setTimeout(parseChunk, 0);
                }} else {{
                    // Done parsing, now render
                    updateStats();
                    renderLogs();
                }}
            }}

            parseChunk();
        }}

        function filterLogs() {{
            const search = document.getElementById('logSearch').value.toLowerCase();
            const levelFilter = document.getElementById('levelFilter').value;
            const componentFilter = document.getElementById('componentFilter').value;

            logLines.forEach(log => {{
                let visible = true;

                // Apply search filter
                if (search && !log.raw.toLowerCase().includes(search)) {{
                    visible = false;
                }}

                // Apply level filter
                if (levelFilter && log.level !== levelFilter) {{
                    visible = false;
                }}

                // Apply component filter
                if (componentFilter && log.component !== componentFilter) {{
                    visible = false;
                }}

                log.visible = visible;
            }});

            renderLogs();
            updateStats();
        }}

        function escapeLogText(value) {{
            return String(value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }}

        function renderText(value, search) {{
            const text = String(value);
            if (!search) {{
                return escapeLogText(text);
            }}

            const loweredText = text.toLowerCase();
            const loweredSearch = search.toLowerCase();
            const pieces = [];
            let cursor = 0;
            let matchIndex = loweredText.indexOf(loweredSearch, cursor);
            while (matchIndex !== -1) {{
                pieces.push(escapeLogText(text.slice(cursor, matchIndex)));
                pieces.push(
                    '<mark>' +
                    escapeLogText(
                        text.slice(matchIndex, matchIndex + search.length)
                    ) +
                    '</mark>'
                );
                cursor = matchIndex + search.length;
                matchIndex = loweredText.indexOf(loweredSearch, cursor);
            }}
            pieces.push(escapeLogText(text.slice(cursor)));
            return pieces.join('');
        }}

        const severityClasses = Object.freeze({{
            DEBUG: 'DEBUG',
            INFO: 'INFO',
            WARN: 'WARNING',
            WARNING: 'WARNING',
            ERROR: 'ERROR',
            CRITICAL: 'ERROR'
        }});

        function renderLog(log, search) {{
            if (!log.parsed && /^[=+\\-]{{2,}}/.test(log.raw)) {{
                return '<span class="log-separator">' +
                    renderText(log.raw, search) + '</span>';
            }}

            const severity = severityClasses[
                String(log.level || '').toUpperCase()
            ];
            return log.parts.map(part => {{
                const rendered = renderText(part.text, search);
                if (part.role === 'timestamp') {{
                    return '<span class="log-timestamp">' + rendered + '</span>';
                }}
                if (part.role === 'level') {{
                    const levelClass = severity ? ' log-level-' + severity : '';
                    return '<span class="log-level' + levelClass + '">' +
                        rendered + '</span>';
                }}
                if (part.role === 'component') {{
                    return '<span class="log-component">' + rendered + '</span>';
                }}
                if (part.role === 'message') {{
                    return '<span class="log-message">' + rendered + '</span>';
                }}
                return rendered;
            }}).join('');
        }}

        function renderLogs() {{
            const logView = document.getElementById('logView');
            const code = logView.querySelector('code');
            const search = document.getElementById('logSearch').value;

            // Filter visible logs
            const visibleLogs = logLines.filter(log => log.visible);

            // For large logs (>2000 lines), render in chunks
            if (visibleLogs.length > 2000) {{
                code.innerHTML = '<span style="color: #0dcaf0;">Rendering ' + visibleLogs.length + ' log lines...</span>';

                // Render in chunks to avoid UI freeze
                let rendered = [];
                let chunkIdx = 0;
                const chunkSize = 500;

                function renderChunk() {{
                    const start = chunkIdx * chunkSize;
                    const end = Math.min(start + chunkSize, visibleLogs.length);

                    for (let i = start; i < end; i++) {{
                        rendered.push(renderLog(visibleLogs[i], search));
                    }}

                    chunkIdx++;

                    if (end < visibleLogs.length) {{
                        // Update progress and continue
                        const progress = Math.round((end / visibleLogs.length) * 100);
                        code.innerHTML = `<span style="color: #0dcaf0;">Rendering ${{progress}}%...</span>`;
                        setTimeout(renderChunk, 0);
                    }} else {{
                        // Done rendering
                        code.innerHTML = rendered.join('\\n');
                    }}
                }}

                renderChunk();
            }} else {{
                // Small log, render immediately
                const html = visibleLogs.map(
                    log => renderLog(log, search)
                ).join('\\n');

                code.innerHTML = html;
            }}
        }}

        function updateStats() {{
            const total = logLines.length;
            const visible = logLines.filter(l => l.visible).length;
            document.getElementById('totalLines').textContent = total;
            document.getElementById('visibleLines').textContent = visible;
        }}

        function copyLog() {{
            const filtered = logLines.filter(l => l.visible).map(l => l.raw).join('\\n');
            navigator.clipboard.writeText(filtered).then(() => {{
                alert('Filtered log copied to clipboard!');
            }});
        }}

        function downloadLog() {{
            const filtered = logLines.filter(l => l.visible).map(l => l.raw).join('\\n');
            const blob = new Blob([filtered], {{ type: 'text/plain' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'filtered_log.txt';
            a.click();
            URL.revokeObjectURL(url);
        }}

        function toggleWrap() {{
            const pre = document.getElementById('logView');
            wrapEnabled = !wrapEnabled;
            pre.style.whiteSpace = wrapEnabled ? 'pre-wrap' : 'pre';
        }}
        </script>
        """

        return content
