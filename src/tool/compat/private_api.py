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
Declare private Python callables retained for 2.1 compatibility.

These names are a compatibility inventory, not a dynamic dispatch table and
not an extension of the collector-catalog hook allowlist. New product code
should use the maintained owner boundaries documented in the MR !1586
compatibility audit. Keeping the inventory in shipping source makes retention
intentional and lets tests prevent an unrelated coverage cleanup from silently
deleting established programmatic seams.
"""

from __future__ import annotations

LEGACY_PRIVATE_CALLABLE_NAMES: frozenset[str] = frozenset(
    {
        "_await_workflow_child_with_timeout",
        "_build_group_dependency_table",
        "_build_group_preflight_table",
        "_build_sudo_command",
        "_cleanup_owned_extraction_root",
        "_concurrent_entity_processing",
        "_create_available_extraction_root",
        "_create_owned_extraction_root",
        "_create_redfish_sessions_with_progress",
        "_deduplicate_log_paths",
        "_delete_archive_source",
        "_diagnostic_uri_keyed_mapping",
        "_diagnostic_uri_list_evidence",
        "_embed_manifest",
        "_execute_service_groups_with_parallel_progress",
        "_extract_error_details",
        "_find_chunked_archive_parts",
        "_find_pattern_matches",
        "_force_noninteractive_sudo",
        "_format_supported_baseboards",
        "_get_baseboard_groups",
        "_get_collector_id_from_path",
        "_get_collector_name",
        "_get_collector_timeout",
        "_get_command_version",
        "_get_diagnostic_data_action_info",
        "_handle_collector_completion",
        "_handle_emergency_cleanup_failure",
        "_infer_group",
        "_load_metadata",
        "_log_redfish_request",
        "_log_redfish_response",
        "_matches_filter",
        "_parse_from_collection_name",
        "_process_entities_common",
        "_process_entities_with_common_logic",
        "_process_entity",
        "_publish_post_collection_outcome",
        "_restore_prior_root_marker",
        "_save_collection_summary_json",
        "_save_collection_summary_text",
        "_strip_leading_sudo",
        "_summarize_host_command_stream",
        "_to_dut_relative_path",
        "_validate_and_auto_detect_page",
        "_validate_and_suggest_parsing_mode",
        "_validate_by_baseboard",
        "_validate_specific_entities",
        "create_session_for_dut",
        "search_recursive",
    }
)

__all__ = ["LEGACY_PRIVATE_CALLABLE_NAMES"]
