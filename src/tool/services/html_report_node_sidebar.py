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
Immutable inventory and rendering boundary for legacy node sidebars.

The report service owns filesystem discovery, async child-page generation, and
publication. This module classifies an already discovered path snapshot and
renders an immutable sidebar model without performing filesystem or async I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from .html_report_renderer import HTMLReportRenderer

escape = HTMLReportRenderer.escape_html_text

__all__ = [
    "HTMLReportNodeSidebar",
    "NodeSidebarFileInventory",
    "NodeSidebarLink",
    "NodeSidebarLinkGroup",
    "NodeSidebarRenderModel",
]


@dataclass(frozen=True, slots=True)
class NodeSidebarFileInventory:
    """
    Classified paths from one bounded node-directory snapshot.

    The immutable record keeps ``metadata_files``, ``config_files``,
    ``runtime_logs``, ``error_logs``, and ``misc_files`` together so consumers
    observe one node sidebar file inventory state. Consumers receive the fields
    as one unit instead of assembling partial state.

    Attributes:
        metadata_files: Collection of metadata files entries retained by this
            record.
        config_files: Collection of config files entries retained by this
            record.
        runtime_logs: Collection of runtime logs entries retained by this
            record.
        error_logs: Collection of error logs entries retained by this record.
        misc_files: Collection of misc files entries retained by this record.
    """

    metadata_files: tuple[Path, ...] = ()
    config_files: tuple[Path, ...] = ()
    runtime_logs: tuple[Path, ...] = ()
    error_logs: tuple[Path, ...] = ()
    misc_files: tuple[Path, ...] = ()


@dataclass(frozen=True, slots=True)
class NodeSidebarLink:
    """
    One escaped-at-render navigation item.

    The immutable record keeps ``href``, ``display_text``, and ``icon`` together
    so consumers observe one node sidebar link state. Consumers receive the
    fields as one unit instead of assembling partial state.

    Attributes:
        href: Href retained as part of the record's public state.
        display_text: Display text retained as part of the record's public
            state.
        icon: Canonical text used as icon.
    """

    href: Any
    display_text: Any
    icon: str


@dataclass(frozen=True, slots=True)
class NodeSidebarLinkGroup:
    """
    Named group of sidebar links.

    The immutable record keeps ``name`` and ``links`` together so consumers
    observe one node sidebar link group state. Consumers receive the fields as
    one unit instead of assembling partial state.

    Attributes:
        name: Name retained as part of the record's public state.
        links: Collection of links entries retained by this record.
    """

    name: Any
    links: tuple[NodeSidebarLink, ...]


@dataclass(frozen=True, slots=True)
class NodeSidebarRenderModel:
    """
    Complete immutable inputs for a legacy node sidebar.

    The immutable record keeps ``node_name``, ``log_collection_time``,
    ``node_execution_seconds``, ``system_details_html``, and
    ``show_collector_groups`` together so consumers observe one node sidebar
    render model state. Consumers receive the fields as one unit instead of
    assembling partial state.

    Attributes:
        node_name: Node name retained as part of the record's public state.
        log_collection_time: Log collection time retained as part of the
            record's public state.
        node_execution_seconds: Number of node execution seconds represented by
            this record.
        system_details_html: Canonical text used as system details HTML.
        show_collector_groups: Whether show collector groups applies to this
            record.
        collector_groups: Collection of collector groups entries retained by
            this record.
        metadata_groups: Collection of metadata groups entries retained by this
            record.
        standalone_metadata: Collection of standalone metadata entries retained
            by this record.
        config_files: Collection of config files entries retained by this
            record.
        runtime_logs: Collection of runtime logs entries retained by this
            record.
        error_logs: Collection of error logs entries retained by this record.
        misc_files: Collection of misc files entries retained by this record.
    """

    node_name: Any
    log_collection_time: Any
    node_execution_seconds: float | None
    system_details_html: str
    show_collector_groups: bool = False
    collector_groups: tuple[NodeSidebarLink, ...] = ()
    metadata_groups: tuple[NodeSidebarLinkGroup, ...] = ()
    standalone_metadata: tuple[NodeSidebarLink, ...] = ()
    config_files: tuple[NodeSidebarLink, ...] = ()
    runtime_logs: tuple[NodeSidebarLink, ...] = ()
    error_logs: tuple[NodeSidebarLink, ...] = ()
    misc_files: tuple[NodeSidebarLink, ...] = ()


@dataclass(frozen=True, slots=True)
class HTMLReportNodeSidebar:
    """
    Pure classification and rendering policy for node sidebars.

    The type coordinates ``classify_files``, ``metadata_display_path``,
    ``metadata_group_name``, ``error_log_sort_key``, and ``_render_links`` and
    retains the state those operations share between calls. Resource ownership
    remains inside the instance until the matching close, exit, or cleanup
    operation completes.
    """

    @staticmethod
    def classify_files(
        *,
        node_path: Path,
        files: Iterable[Path],
        collector_group_names: frozenset[str],
        node_config_names: frozenset[str],
        runtime_log_names: frozenset[str],
    ) -> NodeSidebarFileInventory:
        """
        Classify a caller-owned path snapshot using the legacy precedence.

        After applying local validation, the function forwards ``node_path``,
        ``files``, ``collector_group_names``, ``node_config_names``, and
        ``runtime_log_names`` to ``NodeSidebarFileInventory`` and preserves its
        return and exception contract.

        Args:
            node_path: filesystem location used as the node path for this
                operation.
            files: filesystem location used as the files for this operation.
            collector_group_names: Entries supplied as ``collector_group_names``
                without transferring container ownership.
            node_config_names: Node config names governing classify a
                caller-owned path snapshot using the legacy precedence.
            runtime_log_names: Entries supplied as ``runtime_log_names`` without
                transferring container ownership.

        Returns:
            A ``NodeSidebarFileInventory`` representing classify files.
        """

        metadata_files: list[Path] = []
        config_files: list[Path] = []
        runtime_logs: list[Path] = []
        error_logs: list[Path] = []
        misc_files: list[Path] = []

        for path in files:
            relative_parts = path.relative_to(node_path).parts
            if len(relative_parts) > 1:
                parent_name = relative_parts[0]
                if parent_name in {"metadata", ".metadata"}:
                    metadata_files.append(path)
                    continue
                if parent_name in {"error-logs", "error_logs"}:
                    error_logs.append(path)
                    continue
                if (
                    parent_name in collector_group_names
                    and path.name not in node_config_names
                    and path.name not in runtime_log_names
                ):
                    continue

            if path.name in node_config_names:
                config_files.append(path)
            elif path.name in runtime_log_names:
                runtime_logs.append(path)
            elif len(relative_parts) == 1:
                misc_files.append(path)

        return NodeSidebarFileInventory(
            metadata_files=tuple(metadata_files),
            config_files=tuple(config_files),
            runtime_logs=tuple(runtime_logs),
            error_logs=tuple(error_logs),
            misc_files=tuple(misc_files),
        )

    @staticmethod
    def metadata_display_path(node_path: Path, path: Path) -> str:
        """
        Return the legacy user-facing path for a metadata file.

        After applying local validation, the function forwards ``node_path`` and
        ``path`` to ``replace`` and preserves its return and exception contract.
        Filesystem effects remain confined to the caller-selected paths and the
        owning resource lifecycle.

        Args:
            node_path: filesystem location used as the node path for this
                operation.
            path: filesystem location used as the path for this operation.

        Returns:
            The canonical metadata display path.
        """

        return str(path.relative_to(node_path)).replace(".metadata", "metadata")

    @staticmethod
    def metadata_group_name(node_path: Path, path: Path) -> str | None:
        """
        Return the first metadata subdirectory when one is present.

        The implementation uses ``node_path`` and ``path`` to produce the first
        metadata subdirectory when one is present.

        Args:
            node_path: filesystem location used as the node path for this
                operation.
            path: filesystem location used as the path for this operation.

        Returns:
            The canonical metadata group name, or ``None`` when the requested
            value is unavailable.
        """

        relative_parts = path.relative_to(node_path).parts
        return relative_parts[1] if len(relative_parts) > 2 else None

    @staticmethod
    def error_log_sort_key(path: Path) -> list[int | str]:
        """
        Return the legacy alphanumeric filename ordering key.

        The implementation uses ``path`` to produce the legacy alphanumeric
        filename ordering key.

        Args:
            path: filesystem location used as the path for this operation.

        Returns:
            The error log sort key returned in operation-defined order.
        """

        import re

        return [
            int(part) if part.isdigit() else part
            for part in re.split(r"(\d+)", path.name)
        ]

    @staticmethod
    def _render_links(links: Sequence[NodeSidebarLink]) -> str:
        """
        Render links.

        After applying local validation, the function forwards ``links`` to
        ``join`` and preserves its return and exception contract. The source
        value keeps its ownership while the normalized representation is
        returned separately.

        Args:
            links: Entries supplied as ``links`` without transferring container
                ownership.

        Returns:
            The canonical links text.
        """
        rendered: list[str] = []
        for link in links:
            encoded_href = HTMLReportRenderer.encoded_report_relative_path(link.href)
            label = (
                f'<i class="bi {escape(link.icon)}"></i> '
                f"{escape(link.display_text)}"
            )
            if encoded_href is None:
                rendered.append(f'<li><span class="d-block py-1">{label}</span></li>')
            else:
                rendered.append(
                    f'<li><a href="{escape(encoded_href)}" class="d-block py-1">'
                    f"{label}</a></li>"
                )
        return "".join(rendered)

    @classmethod
    def render(cls, model: NodeSidebarRenderModel) -> str:
        """
        Render exact legacy sidebar bytes from an immutable model.

        The implementation uses ``model`` to render exact legacy sidebar bytes
        from an immutable model. The source value keeps its ownership while the
        normalized representation is returned separately. Filesystem effects
        remain confined to the caller-selected paths and the owning resource
        lifecycle.

        Args:
            model: Model object whose ``collector_groups``, ``config_files``,
                ``error_logs``, ``log_collection_time``, and ``metadata_groups``
                state is read while performing exact legacy sidebar bytes from
                an immutable model.

        Returns:
            The validated ``rendered``.
        """

        rendered = f"""
        <div class="card mb-3">
            <div class="card-body">
                <h4>Node: {escape(model.node_name)}</h4>
        """

        if (
            model.node_execution_seconds is not None
            and model.node_execution_seconds > 0
        ):
            rendered += (
                "<p><strong>Total execution time: "
                f"{model.node_execution_seconds:.3f}s</strong></p>"
            )
        elif model.log_collection_time:
            rendered += f"<p><strong>{escape(model.log_collection_time)}</strong></p>"

        rendered += model.system_details_html
        rendered += """
            </div>
        </div>
        """

        if model.show_collector_groups:
            rendered += """
            <div class="card mb-3">
                <div class="card-body">
                    <h5>Collector Groups</h5>
                    <ul class="list-unstyled">
            """
            rendered += cls._render_links(model.collector_groups)
            rendered += """
                    </ul>
                </div>
            </div>
            """

        if model.metadata_groups or model.standalone_metadata:
            rendered += """
            <div class="card mb-3">
                <div class="card-body">
                    <h5>Node Metadata Files</h5>
            """
            for group in model.metadata_groups:
                readable_name = str(group.name).replace("_", " ").title()
                rendered += (
                    f"<h6>{escape(readable_name)}</h6><ul class='list-unstyled'>"
                )
                rendered += cls._render_links(group.links)
                rendered += "</ul>"
            if model.standalone_metadata:
                rendered += "<h6>General Metadata</h6><ul class='list-unstyled'>"
                rendered += cls._render_links(model.standalone_metadata)
                rendered += "</ul>"
            rendered += """
                </div>
            </div>
            """

        sections = (
            ("Node Config", model.config_files, "<ul class='list-unstyled'>"),
            ("Runtime Logs", model.runtime_logs, "<ul class='list-unstyled'>"),
            ("Error Logs", model.error_logs, "<ul class='list-unstyled'>"),
            ("Misc Files", model.misc_files, "<ul class='list-unstyled'>"),
        )
        for title, links, list_open in sections:
            if not links:
                continue
            rendered += f"""
            <div class="card mb-3">
                <div class="card-body">
                    <h5>{title}</h5>
                    {list_open}
            """
            rendered += cls._render_links(links)
            rendered += """
                    </ul>
                </div>
            </div>
            """

        return rendered
