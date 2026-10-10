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
Immutable shared assets for legacy HTML report pages.

This module owns the html report page assets boundary and exposes
``NavbarRenderModel`` and ``HTMLReportPageAssets``. Keeping those contracts
together gives importers one source of truth for their validation, lifecycle,
and compatibility behavior.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..core.run_result import RunResult

_LEGACY_HTML_HEADER = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self' data: https://cdn.jsdelivr.net; img-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
            <meta name="referrer" content="no-referrer">
            <title>{title}</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous"> <!-- pragma: allowlist secret -->
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet" integrity="sha384-XGjxtQfXaH2tnPFa9x+ruJTuLE3Aa6LhHSWRr1XeTyhezb4abCG4ccI5AkVDxqC+" crossorigin="anonymous"> <!-- pragma: allowlist secret -->
            <style>
                /* Base styles with modern polish */
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                    margin: 0;
                    padding: 0 1rem;
                    padding-top: 80px;
                    background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                    min-height: 100vh;
                }}

                /* Container with card style */
                .container {{
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
                    padding: 2rem;
                    margin-top: 1rem !important;
                    margin-bottom: 2rem !important;
                    margin-left: auto !important;
                    margin-right: auto !important;
                }}

                .navbar-fixed-top {{
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    z-index: 1030;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}

                /* Enhanced table styling */
                table {{
                    border-collapse: collapse;
                    width: 100%;
                    margin-bottom: 20px;
                    background: white;
                }}
                th, td {{
                    border: 1px solid #e0e0e0;
                    padding: 12px;
                    text-align: left;
                }}
                th {{
                    font-weight: 600;
                }}
                thead:not(.table-dark) th {{
                    background: linear-gradient(180deg, #f8f9fa 0%, #e9ecef 100%);
                    color: #495057;
                }}
                thead.table-dark th {{
                    background: linear-gradient(180deg, #343a40 0%, #23272b 100%) !important;
                    color: #fff !important;
                    border-color: #454d55 !important;
                }}
                .table-dark tbody tr {{
                    background-color: transparent;
                }}
                .table-striped.table-dark tbody tr:nth-of-type(odd) {{
                    background-color: rgba(255, 255, 255, 0.05);
                }}
                tbody tr:hover {{ background-color: #f8f9fa; }}
                .table-dark tbody tr:hover {{ background-color: rgba(255, 255, 255, 0.075); }}
                a {{
                    text-decoration: none;
                    color: #0066cc;
                    transition: color 0.2s ease;
                }}
                a:hover {{ color: #0052a3; }}

                /* Status badges with modern colors */
                .status-complete {{ background-color: #d4edda !important; color: #155724 !important; }}
                .status-error {{ background-color: #f8d7da !important; color: #721c24 !important; }}
                .status-degraded {{ background-color: #ffe8a1 !important; color: #7a4e00 !important; }}
                .status-partial {{ background-color: #fff3cd !important; color: #856404 !important; }}
                .status-skipped {{ background-color: #ffc107 !important; color: #212529 !important; }}
                .status-na {{ background-color: #e9ecef !important; color: #6c757d !important; }}
                .status-notran {{ background-color: #e9ecef !important; color: #6c757d !important; }}

                /* Cards and sections */
                .card {{
                    border: none;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.08);
                    transition: transform 0.2s ease, box-shadow 0.2s ease;
                }}
                .card:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 8px rgba(0,0,0,0.12);
                }}
                /* Only gradient cards should be equal height */
                .card.bg-primary, .card.bg-success, .card.bg-danger, .card.bg-info, .card.bg-warning {{
                    height: 100%;
                }}
                .card.bg-primary .card-body,
                .card.bg-success .card-body,
                .card.bg-danger .card-body,
                .card.bg-info .card-body,
                .card.bg-warning .card-body {{
                    display: flex;
                    flex-direction: column;
                    height: 100%;
                }}

                .section {{
                    background: white;
                    border-radius: 8px;
                    padding: 1.5rem;
                    margin-bottom: 1.5rem;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.06);
                }}

                /* Enhanced buttons */
                .btn {{
                    border-radius: 6px;
                    font-weight: 500;
                    transition: all 0.2s ease;
                }}
                .btn:hover {{
                    transform: translateY(-1px);
                    box-shadow: 0 4px 8px rgba(0,0,0,0.15);
                }}

                /* Breadcrumb */
                .breadcrumb {{
                    background: #f8f9fa;
                    padding: 0.75rem;
                    border-radius: 6px;
                    margin-bottom: 1rem;
                }}

                /* Accordion */
                .accordion {{
                    background-color: #f8f9fa;
                    cursor: pointer;
                    padding: 12px;
                    width: 100%;
                    border: none;
                    border-radius: 6px;
                    text-align: left;
                    outline: none;
                    transition: all 0.3s ease;
                    font-weight: 500;
                }}
                .accordion.active, .accordion:hover {{
                    background-color: #e9ecef;
                }}
                .panel {{
                    padding: 0 15px;
                    display: none;
                    background-color: white;
                    overflow: auto;
                    max-height: 600px;
                    border-radius: 0 0 6px 6px;
                }}

                /* Tree view */
                ul {{ list-style-type: none; }}
                li.folder > span {{
                    font-weight: bold;
                    cursor: pointer;
                    color: #0066cc;
                }}
                #treeview ul {{ margin-left: 20px; }}

                .highlight {{
                    background-color: #fff3cd;
                    padding: 2px 4px;
                    border-radius: 3px;
                }}

                .nv-logo {{
                    display: inline-flex;
                    height: 25px;
                    padding-right: 20px;
                }}

                .table-shadow {{
                    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
                    border-radius: 8px;
                    overflow: hidden;
                }}

                /* Progress bars */
                .progress {{
                    border-radius: 8px;
                    overflow: hidden;
                }}

                /* Headings */
                h1, h2, h3, h4, h5, h6 {{
                    color: #2c3e50;
                    font-weight: 600;
                }}

                /* Badge improvements */
                .badge {{
                    padding: 0.35em 0.65em;
                    border-radius: 6px;
                    font-weight: 500;
                }}

                /* Service color scheme - consistent across all reports */
                .service-redfish,
                span.badge.service-redfish,
                span.badge.service-badge.service-redfish {{
                    background-color: #f8d7da !important;
                    color: #721c24 !important;
                    border: 1px solid #f5c2c7 !important;
                }}
                .service-ssh,
                span.badge.service-ssh,
                span.badge.service-badge.service-ssh {{
                    background-color: #fff3cd !important;
                    color: #856404 !important;
                    border: 1px solid #ffecb5 !important;
                }}
                .service-ipmi,
                span.badge.service-ipmi,
                span.badge.service-badge.service-ipmi {{
                    background-color: #d4edda !important;
                    color: #155724 !important;
                    border: 1px solid #c3e6cb !important;
                }}
                .service-host,
                span.badge.service-host,
                span.badge.service-badge.service-host {{
                    background-color: #cfe2ff !important;
                    color: #084298 !important;
                    border: 1px solid #b6d4fe !important;
                }}
                .service-health_check,
                span.badge.service-health_check,
                span.badge.service-badge.service-health_check {{
                    background-color: #e2d9f3 !important;
                    color: #4a148c !important;
                    border: 1px solid #d4c4e8 !important;
                }}
                .service-preflight,
                span.badge.service-preflight,
                span.badge.service-badge.service-preflight {{
                    background-color: #e9ecef !important;
                    color: #495057 !important;
                    border: 1px solid #dee2e6 !important;
                }}

                /* Service badges (inline display) */
                .service-badge {{
                    display: inline-block !important;
                    padding: 6px 12px !important;
                    border-radius: 12px !important;
                    font-size: 0.8rem !important;
                    font-weight: 600 !important;
                    margin-right: 8px !important;
                }}

                /* Gradient cards for summary boxes */
                .card.bg-primary {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
                }}
                .card.bg-success {{
                    background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%) !important;
                }}
                .card.bg-danger {{
                    background: linear-gradient(135deg, #ee0979 0%, #ff6a00 100%) !important;
                }}
                .card.bg-info {{
                    background: linear-gradient(135deg, #3a7bd5 0%, #00d2ff 100%) !important;
                }}
                .card.bg-warning {{
                    background: linear-gradient(135deg, #f2994a 0%, #f2c94c 100%) !important;
                }}

                /* Chart containers */
                .chart-container {{
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: none !important;
                    margin-bottom: 20px;
                }}

                /* Sortable table headers */
                th.sortable {{
                    cursor: pointer;
                    user-select: none;
                    position: relative;
                }}
                thead:not(.table-dark) th.sortable:hover {{
                    background: linear-gradient(180deg, #e9ecef 0%, #d3d7da 100%) !important;
                }}
                thead.table-dark th.sortable:hover {{
                    background: linear-gradient(180deg, #454d55 0%, #343a40 100%) !important;
                }}
                th.sortable:after {{
                    content: '⇅';
                    position: absolute;
                    right: 8px;
                    opacity: 0.5;
                }}
                #logView {{
                    background: #1e1e1e !important;
                }}
            </style>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/themes/prism.min.css" rel="stylesheet" integrity="sha384-rCCjoCPCsizaAAYVoz1Q0CmCTvnctK0JkfCSjx7IIxexTBg+uCKtFYycedUjMyA2" crossorigin="anonymous" /> <!-- pragma: allowlist secret -->
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script> <!-- pragma: allowlist secret -->
            <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/prism.min.js" integrity="sha384-JKnirmMqCcCIzVxhkUuD57FTnoVYoa4eESxqE5dO6qD7UdfzNat+vGyFn50rKsRE" crossorigin="anonymous"></script> <!-- pragma: allowlist secret -->
            <script src="https://cdn.jsdelivr.net/npm/chart.js@4.5.1/dist/chart.umd.min.js" integrity="sha384-jb8JQMbMoBUzgWatfe6COACi2ljcDdZQ2OxczGA3bGNeWe+6DChMTBJemed7ZnvJ" crossorigin="anonymous"></script> <!-- pragma: allowlist secret -->
            <script>
                // Initialize all modals when the document is ready
                document.addEventListener('DOMContentLoaded', function() {{
                    // Initialize all modals
                    var modalElements = document.querySelectorAll('.modal');
                    modalElements.forEach(function(modalElement) {{
                        new bootstrap.Modal(modalElement);
                    }});

                    // Initialize all tooltips
                    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
                    tooltipTriggerList.map(function (tooltipTriggerEl) {{
                        return new bootstrap.Tooltip(tooltipTriggerEl);
                    }});

                    // Initialize all popovers
                    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
                    popoverTriggerList.map(function (popoverTriggerEl) {{
                        return new bootstrap.Popover(popoverTriggerEl);
                    }});
                }});

                // Function to open a modal by ID
                function openModal(modalId) {{
                    var modalElement = document.getElementById(modalId);
                    if (modalElement) {{
                        var modal = bootstrap.Modal.getInstance(modalElement) || new bootstrap.Modal(modalElement);
                        modal.show();
                    }}
                }}

                function filterTable(query) {{
                    query = query.toLowerCase();
                    var tables = document.getElementsByTagName('table');
                    for (var t = 0; t < tables.length; t++) {{
                        var rows = tables[t].getElementsByTagName('tr');
                        for (var i = 1; i < rows.length; i++) {{
                            var cells = rows[i].getElementsByTagName('td');
                            var match = false;
                            for (var c = 0; c < cells.length; c++) {{
                                var cellText = cells[c].innerText.toLowerCase();
                                if (cellText.indexOf(query) > -1) {{
                                    match = true;
                                    break;
                                }}
                            }}
                            rows[i].style.display = (match || query === '') ? '' : 'none';
                        }}
                    }}
                }}

                function clearSearch() {{
                    var input = document.getElementById("globalSearchBox");
                    if (input) {{
                        input.value = '';
                        globalSearchHandler('');
                    }}
                }}

                function globalSearchHandler(value) {{
                    var tables = document.getElementsByTagName('table');
                    if (tables.length > 0) {{
                        filterTable(value);
                    }} else if (document.getElementById("jsonTree")) {{
                        jsonGlobalSearch(value);
                    }} else if (document.getElementById("textView")) {{
                        textGlobalSearch(value);
                    }} else if (document.getElementById("stdoutView")) {{
                        stdoutGlobalSearch(value);
                    }}
                }}

                // Universal table sorting with unique state per table
                var tableSortStates = {{}};

                function makeTableSortable(tableId) {{
                    var table = document.getElementById(tableId);
                    if (!table) return;

                    // Initialize sort state for this table
                    tableSortStates[tableId] = {{}};

                    var headers = table.getElementsByTagName('th');

                    for (var i = 0; i < headers.length; i++) {{
                        (function(index, tId) {{
                            headers[index].classList.add('sortable');
                            headers[index].addEventListener('click', function() {{
                                sortTableByColumn(tId, index);
                            }});
                        }})(i, tableId);
                    }}
                }}

                function sortTableByColumn(tableId, columnIndex) {{
                    var table = document.getElementById(tableId);
                    if (!table) return;

                    var tbody = table.getElementsByTagName('tbody')[0];
                    if (!tbody) return;

                    var rows = Array.from(tbody.getElementsByTagName('tr'));
                    if (rows.length === 0) return;

                    // Toggle sort direction
                    var sortStates = tableSortStates[tableId];
                    sortStates[columnIndex] = !sortStates[columnIndex];
                    var isAscending = sortStates[columnIndex];

                    rows.sort(function(a, b) {{
                        var aCell = a.getElementsByTagName('td')[columnIndex];
                        var bCell = b.getElementsByTagName('td')[columnIndex];
                        if (!aCell || !bCell) return 0;

                        var aValue = aCell.textContent.trim();
                        var bValue = bCell.textContent.trim();

                        // Prefer data-sort attribute for unit-aware numeric sorting
                        var aNum = aCell.hasAttribute('data-sort') ? parseFloat(aCell.getAttribute('data-sort')) : parseFloat(aValue.replace(/[^0-9.-]/g, ''));
                        var bNum = bCell.hasAttribute('data-sort') ? parseFloat(bCell.getAttribute('data-sort')) : parseFloat(bValue.replace(/[^0-9.-]/g, ''));
                        if (!isNaN(aNum) && !isNaN(bNum)) {{
                            return isAscending ? aNum - bNum : bNum - aNum;
                        }}

                        // Fall back to string comparison
                        if (aValue < bValue) return isAscending ? -1 : 1;
                        if (aValue > bValue) return isAscending ? 1 : -1;
                        return 0;
                    }});

                    tbody.innerHTML = '';
                    rows.forEach(function(row) {{ tbody.appendChild(row); }});
                }}

                document.addEventListener('DOMContentLoaded', function() {{
                    // Initialize all modals
                    const modalElements = document.querySelectorAll('.modal');
                    modalElements.forEach(function(modalElement) {{
                        new bootstrap.Modal(modalElement);
                    }});

                    // Make all tables with class 'table' sortable
                    const allTables = document.querySelectorAll('table.table');
                    allTables.forEach(function(table) {{
                        if (table.id) {{
                            makeTableSortable(table.id);
                        }} else {{
                            // Assign an ID if it doesn't have one
                            table.id = 'table_' + Math.random().toString(36).substr(2, 9);
                            makeTableSortable(table.id);
                        }}
                    }});

                    /*/
                    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                        document.documentElement.setAttribute('data-bs-theme', prefersDark ? 'dark' : 'light');
                        themeToggle.checked = prefersDark;
                        themeToggle.addEventListener('change', function() {{
                            document.documentElement.setAttribute('data-bs-theme', this.checked ? 'dark' : 'light');
                    }});
                    /**/

                    var acc = document.getElementsByClassName("accordion");
                    for (var i = 0; i < acc.length; i++) {{
                        acc[i].addEventListener("click", function() {{
                            this.classList.toggle("active");
                            var panel = this.nextElementSibling;
                            if (panel.style.display === "block") {{
                                panel.style.display = "none";
                            }} else {{
                                panel.style.display = "block";
                            }}
                        }});
                    }}
                }});
            </script>
        </head>
        <body>
        {navbar}
        {content}
        </body>
        </html>
        """


@dataclass(frozen=True, slots=True)
class NavbarRenderModel:
    """
    Immutable trusted fragments used to render the shared navbar.

    The immutable record keeps ``theme_toggle`` and ``identity_html`` together
    so consumers observe one navbar render model state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        theme_toggle: Whether theme toggle applies to this record.
        identity_html: Canonical text used as identity HTML.
    """

    theme_toggle: bool
    identity_html: str


@dataclass(frozen=True, slots=True)
class HTMLReportPageAssets:
    """
    Side-effect-free provider for shared legacy page assets.

    The immutable record keeps ``html_header_template`` together so consumers
    observe one HTML report page assets state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        html_header_template: Canonical text used as HTML header template.
    """

    html_header_template: str = field(
        default=_LEGACY_HTML_HEADER,
        init=False,
        repr=False,
    )

    @staticmethod
    def render_run_identity_navbar(
        run_result: RunResult | None,
        *,
        escape_html_text: Callable[[Any], str],
    ) -> str:
        """
        Render canonical identity facts without consulting another authority.

        The implementation uses ``run_result`` and ``escape_html_text`` to
        render canonical identity facts without consulting another authority.
        The source value keeps its ownership while the normalized representation
        is returned separately.

        Args:
            run_result: Optional run result; ``None`` selects the function's
                default behavior.
            escape_html_text: Text supplied as escape HTML text in the format
                accepted by this function.

        Returns:
            The canonical run identity navbar text.
        """

        identity = run_result.run_identity if run_result is not None else None
        if identity is None:
            return ""

        version = escape_html_text(identity.tool_version)
        level = escape_html_text(identity.resolved_level)
        profile = escape_html_text(identity.resolved_profile)
        full_hash = escape_html_text(identity.identity_sha256)
        short_hash = escape_html_text(identity.identity_sha256[:12])
        return f"""
                    <div class="nv-run-identity small text-muted ms-3 d-flex align-items-center gap-2" aria-label="Canonical run identity" title="Run identity {full_hash}">
                        <span>v{version}</span>
                        <span>{level} / {profile}</span>
                        <span>Identity <code>{short_hash}</code></span>
                    </div>"""

    @staticmethod
    def render_common_navbar(model: NavbarRenderModel) -> str:
        """
        Render the shared logo, identity, theme, and search navigation.

        The implementation uses ``model`` to render the shared logo, identity,
        theme, and search navigation. The source value keeps its ownership while
        the normalized representation is returned separately.

        Args:
            model: Model object whose ``identity_html`` and ``theme_toggle``
                state is read while performing shared logo, identity, theme, and
                search navigation.

        Returns:
            The canonical common navbar text.
        """

        theme_toggle_html = (
            """
        <div class="form-check form-switch">
            <input class="form-check-input" type="checkbox" id="themeToggle">
            <label class="form-check-label" for="themeToggle">Dark Mode</label>
        </div>"""
            if model.theme_toggle
            else ""
        )
        identity_html = model.identity_html

        return f"""
        <header class="py-3 mb-3 border-bottom navbar-fixed-top bg-white">
            <div class="container-fluid d-grid gap-3 align-items-center" style="grid-template-columns: 1fr 2fr;">
                <div class="d-flex">
                    <div class="nv-logo">
                        <svg viewBox="0 0 164 30"><defs><path id="a" d="M157.725 29.99H.01V.048h157.715z"></path></defs><g fill="none" fill-rule="evenodd"><path d="M160.352 24.069v-.449h.288c.157 0 .371.012.371.204 0 .208-.11.245-.296.245h-.363m0 .315h.192l.447.784h.49l-.494-.816c.255-.019.465-.14.465-.484 0-.427-.295-.565-.793-.565h-.721v1.865h.414v-.784m2.098-.146c0-1.095-.851-1.73-1.8-1.73-.955 0-1.805.635-1.805 1.73s.85 1.733 1.805 1.733c.948 0 1.8-.638 1.8-1.733m-.52 0c0 .798-.587 1.334-1.28 1.334v-.006c-.713.006-1.289-.53-1.289-1.328 0-.797.577-1.331 1.289-1.331.694 0 1.28.534 1.28 1.331" fill="#1A1919"></path><mask id="b" fill="#fff"><use href="#a"></use></mask><path d="m96.374 5.707.002 19.66h5.552V5.707h-5.554zm-43.677-.026v19.686H58.3V10.086l4.37.014c1.437 0 2.43.345 3.123 1.084.879.936 1.237 2.444 1.237 5.205v8.978h5.427V14.49c0-7.763-4.948-8.81-9.789-8.81h-9.97zm52.617.027v19.659h9.006c4.798 0 6.364-.798 8.057-2.587 1.198-1.256 1.971-4.014 1.971-7.027 0-2.763-.655-5.228-1.797-6.763-2.057-2.745-5.02-3.282-9.445-3.282h-7.792zm5.508 4.28h2.387c3.463 0 5.703 1.556 5.703 5.591 0 4.037-2.24 5.592-5.703 5.592h-2.387V9.989zm-22.453-4.28-4.634 15.58-4.44-15.579-5.993-.001 6.34 19.659h8.003l6.391-19.659H88.37zm38.563 19.659h5.553V5.709l-5.555-.001.002 19.659zm15.564-19.652-7.753 19.645h5.475l1.227-3.472h9.175l1.161 3.472h5.944l-7.812-19.646-7.417.001zM146.1 9.3l3.364 9.204h-6.833l3.47-9.204z" fill="#000" mask="url(#b)"></path><path d="M16.889 8.985V6.28c.262-.02.528-.033.798-.042 7.4-.232 12.255 6.359 12.255 6.359s-5.244 7.282-10.866 7.282a6.82 6.82 0 0 1-2.187-.35v-8.204c2.88.348 3.46 1.62 5.192 4.508l3.852-3.248s-2.812-3.688-7.552-3.688c-.515 0-1.008.036-1.492.088zm0-8.938V4.09c.265-.021.531-.038.798-.048 10.29-.346 16.995 8.44 16.995 8.44s-7.7 9.364-15.723 9.364c-.735 0-1.424-.068-2.07-.183v2.498c.553.07 1.126.112 1.724.112 7.465 0 12.864-3.812 18.092-8.325.867.694 4.416 2.383 5.145 3.123-4.971 4.16-16.555 7.515-23.123 7.515a18.89 18.89 0 0 1-1.838-.096V30h28.375V.047H16.89zm0 19.482v2.133c-6.905-1.23-8.822-8.408-8.822-8.408s3.316-3.674 8.822-4.269v2.34l-.011-.001c-2.89-.347-5.147 2.353-5.147 2.353s1.265 4.544 5.158 5.852zM4.625 12.943s4.092-6.04 12.264-6.663V4.088C7.838 4.815 0 12.48 0 12.48s4.439 12.833 16.889 14.008V24.16C7.753 23.011 4.625 12.943 4.625 12.943z" fill="#76B900" mask="url(#b)"></path></g></svg>
                    </div>
                    <a class="navbar-brand" href="#">NVDebug Reports</a>{identity_html}
                    {theme_toggle_html}
                </div>
                <div class="d-flex justify-content-end">
                    <form class="row me-3" role="search" onsubmit="return false;">
                        <div class="col-auto">
                            <input id="globalSearchBox" type="search" class="form-control" placeholder="Search..." aria-label="Search" onkeyup="globalSearchHandler(this.value)">
                        </div>
                        <div class="col-auto">
                            <button class="btn btn-outline-success my-2 my-sm-0" type="button" onclick="clearSearch()">Clear</button>
                        </div>
                    </form>
                </div>
            </div>
        </header>
        """


HTML_REPORT_PAGE_ASSETS = HTMLReportPageAssets()


__all__ = [
    "HTML_REPORT_PAGE_ASSETS",
    "HTMLReportPageAssets",
    "NavbarRenderModel",
]
