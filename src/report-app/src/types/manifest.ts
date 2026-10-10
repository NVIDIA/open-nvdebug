// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

export const SUPPORTED_SCHEMA_VERSIONS = ['1.0', '2.0']

export type AccessPath = 'redfish' | 'host_ssh' | 'bmc_ssh' | 'ipmi' | 'composite' | 'unknown'

export interface PlatformIdentity {
  baseboard: string
  node_type: string
  model: string | null
  part_number: string | null
  serial_number: string | null
}

export interface SecurityModeMetadata {
  status: 'reported' | 'unknown'
  value: string | boolean | number | null
  source: string | null
}

export interface Manifest {
  schema_version?: string
  version: string
  generated_at: string
  tool_version: string
  tool_config: {
    collection_level: string
    collection_profile?: string
    execution_mode: string
    baseboard: string
    [key: string]: unknown
  }
  duts: DUT[]
  collector_catalog: CollectorDef[]
  timing: TimingData
  file_index: FileEntry[]
  errors: ErrorEntry[]
  preflight: PreflightData
  dependency_check?: DependencyCheckData
  extensions?: ExtensionData
  openbmc_coredumps?: OpenBMCCoreDumpManifest
  run_identity?: RunIdentity
  run_result: RunResult | null
  collection_summary: CollectionSummary
}

export interface ExtensionCapability {
  kind?: string
  name?: string
  verified?: boolean
  [key: string]: unknown
}

/**
 * Metadata-only handoff for OpenBMC core dump analysis.
 *
 * Core files are never uploaded by the report application. This contract only
 * describes artifacts already present in the NVDebug collection archive.
 */
export interface OpenBMCCoreDumpManifest {
  schema_version: string
  generated_at: string
  analyzer: {
    name: string
    url: string | null
    integration_mode: 'manual_handoff'
    automatic_upload: false
  }
  privacy: {
    classification: string
    notice: string
  }
  summary: {
    core_dump_count: number
    analyzer_ready_count: number
    needs_metadata_count: number
  }
  scan_warnings: string[]
  archive_scan: {
    complete: boolean
    archives_inspected: number
    compressed_bytes_inspected: number
    decompressed_bytes_consumed: number
    members_inspected: number
    uninspected_archive_count: number
    uninspected_archive_details_omitted: number
    uninspected_archives: Array<{
      artifact_path: string
      size_bytes: number
      status: string
      reason: string
    }>
  }
  core_dumps: OpenBMCCoreDumpRecord[]
}

export interface OpenBMCCoreDumpRecord {
  artifact_path: string
  archive_member_path: string | null
  filename: string
  size_bytes: number
  outer_archive_size_bytes: number | null
  source_dut: string
  collector: {
    id: string
    name: string
    group: string
    path: string
  }
  openbmc_commit: string | null
  machine: string | null
  baseboard: string | null
  service: string | null
  pid: number | null
  timestamp: string | null
  compression: string
  validation: string
  metadata_sources: Record<string, string | null>
  ready_for_analyzer: boolean
  missing_required_metadata: string[]
  warnings: string[]
  preparation_required: string[]
  handoff: {
    action: 'manual_upload'
    analyzer_url: string | null
    upload_performed: false
  }
}

export interface LifecycleExtensionResult {
  schema_version: string
  namespace: string
  dut_id: string
  phase: string
  outcome: string
  started_at?: string
  updated_at?: string
  duration_seconds?: number
  capabilities: ExtensionCapability[]
  cleanup?: Record<string, unknown>
  errors: Array<Record<string, unknown>>
  warnings: Array<Record<string, unknown>>
  [key: string]: unknown
}

export interface ExtensionData {
  per_dut: LifecycleExtensionResult[]
}

export interface DependencyCheckData {
  per_dut: Array<{
    dut_id: string
    collectors: DependencyCollector[]
  }>
}

export interface DependencyEntry {
  name: string
  type: string
  status: string
  message: string
  required: boolean
}

export interface DependencyCollector {
  collector_id: string
  name: string
  dependencies: (DependencyEntry | string)[]
}

export interface DUT {
  id: string
  baseboard: string
  node_type: string
  bmc_ip: string
  platform_identity?: PlatformIdentity
  security_mode?: SecurityModeMetadata
  collector_groups: CollectorGroup[]
  status_summary: {
    success: number
    error: number
    degraded?: number
    partial: number
    skipped: number
    not_ran: number
    cancelled?: number
    running?: number
    pending?: number
  }
  overall_status: 'success' | 'degraded' | 'error' | 'partial' | 'skipped' | 'interrupted' | 'incomplete' | 'unknown'
  execution_time: number
  log_size: number
  system_info: {
    model: string | null
    part_number: string | null
    serial_number: string | null
    firmware: FirmwareEntry[]
    system_view?: SystemViewInfo
  }
  extensions?: LifecycleExtensionResult[]
}

export interface FirmwareEntry {
  id: string
  name: string
  version: string
  component?: string
  date?: string | null
}

export interface SystemViewInfo {
  bmc?: {
    version?: string | null
    os?: string | null
    kernel?: string | null
    uptime?: string | null
    utilization?: UtilizationInfo
  }
  host?: {
    os?: string | null
    kernel?: string | null
    uptime?: string | null
    utilization?: UtilizationInfo
  }
  software?: {
    host_os?: string | null
    kernel_version?: string | null
    bmc_version?: string | null
    sbios?: string | null
    rm_driver_version?: string | null
    cuda_driver_version?: string | null
    dcgm_version?: string | null
  }
}

export interface UtilizationInfo {
  cpu?: string | null
  memory?: string | null
  disk?: string | null
}

export interface CollectorGroup {
  name: string
  service_type: string
  access_path?: AccessPath
  component_labels?: string[]
  collectors: CollectorResult[]
  total_execution_time: number
}

export type CollectorFailureCategory =
  | 'timeout'
  | 'dependency-missing'
  | 'auth-failure'
  | 'transport-failure'
  | 'parser-failure'
  | 'data-quality'
  | 'internal-error'

export type CollectorOutcomeAttribute =
  | string
  | number
  | boolean
  | null
  | Array<string | number | boolean | null>

export interface CollectorOutcomeDetails {
  schema_version: '1.0'
  category: CollectorFailureCategory
  condition: string
  messages: string[]
  attributes: Record<string, CollectorOutcomeAttribute>
}

export interface CollectorResult {
  id: string
  name: string
  report_role?: string | string[]
  component_label?: string
  access_path?: AccessPath
  status: 'success' | 'degraded' | 'error' | 'partial' | 'skipped' | 'cancelled' | 'not_ran' | 'running' | 'pending'
  execution_time: number
  start_time: string | null
  end_time: string | null
  reason: string
  failure_category?: CollectorFailureCategory
  outcome_details?: CollectorOutcomeDetails
  dependencies: string[]
  collection_level: string
  files: FileRef[]
  timing?: GranularCollectorTiming
  timing_ref?: TimingReference
  stage_timing: {
    validation: number | null
    discovery: number | null
    execution: number | null
    post_processing: number | null
  }
}

export interface TimingReference {
  schema_version: '2.0'
  scope: 'dut'
  source: string
  collector_id: string
  size_bytes: number
  sha256: string
  snapshot_generation: string
}

export interface FileRef {
  path: string
  size: number
  type: 'json' | 'text' | 'log' | 'binary' | 'xml' | 'yaml'
  collector_id: string
  component_label?: string
  access_path?: AccessPath
  viewer_hint?: 'log-viewer' | 'json-tree' | 'monaco' | 'download'
  produced_by_operation_id?: string | null
  measurement?: string | null
  measurement_quality?: 'measured' | 'measured_duration_only' | 'estimated' | 'unavailable' | null
  measurement_scope?: 'artifact' | 'shared_operation' | 'shared_requests' | 'none' | null
  shared_operation_artifact_count?: number | null
  shared_request_operation_count?: number | null
  started_at?: string | null
  ended_at?: string | null
  duration_seconds?: number | null
  status?: string | null
}

export interface GranularTimingOperation {
  operation_id: string
  parent_id: string | null
  operation_type: string
  name: string
  stage: string | null
  hook: string | null
  started_at: string | null
  ended_at: string | null
  duration_seconds: number | null
  status: string
  artifact_paths: string[]
  size_bytes: number | null
  contributes_to_active_time: boolean
  metadata: Record<string, unknown>
  error?: string
}

export interface GranularCollectorTiming {
  collector_started_at: string
  collector_ended_at: string
  wall_clock_duration_seconds: number
  wall_clock_is_authoritative: true
  cumulative_operation_time_seconds: number
  operation_aggregation: 'top_level_contributing_spans'
  nested_operation_time_excluded_seconds: number
  active_operation_union_seconds: number
  overlapped_operation_time_seconds: number
  unattributed_wall_time_seconds: number
  operation_sum_equals_wall_clock: false
  operations: GranularTimingOperation[]
  artifact_timings: Array<{
    path: string
    operation_id: string | null
    measurement: string
    measurement_quality: 'measured' | 'measured_duration_only' | 'estimated' | 'unavailable'
    measurement_scope: 'artifact' | 'shared_operation' | 'shared_requests' | 'none'
    shared_operation_artifact_count: number
    shared_request_operation_count?: number
    started_at: string | null
    ended_at: string | null
    duration_seconds: number | null
    size_bytes: number | null
    status: string
  }>
}

export interface FileEntry extends FileRef {
  dut_id: string
  collector_group: string
  collector_name: string
}

export interface ErrorEntry {
  dut_id: string
  collector_id: string
  collector_name: string
  collector_group: string
  message: string
  timestamp: string | null
}

export interface PreflightData {
  per_dut: Array<{
    dut_id: string
    checks: PreflightCheck[]
  }>
}

export interface PreflightCheck {
  name: string
  group: string
  status: 'pass' | 'fail' | 'warning' | 'skip' | 'na'
  details: string
}

export interface TimingData {
  total_duration: number
  component_timing: {
    tool_init: number | null
    config_load: number | null
    dut_init: number | null
    preflight: number | null
    collection: number | null
    report_generation: number | null
    metadata_write: number | null
    cleanup: number | null
  }
  per_dut: Array<{
    dut_id: string
    duration: number
    collectors: Array<{
      id: string
      name: string
      group: string
      duration: number
      start_time: string | null
      end_time: string | null
      status: string
      timing_ref?: TimingReference
      stage_timing: {
        validation: number | null
        discovery: number | null
        execution: number | null
        post_processing: number | null
      }
    }>
  }>
  per_service: Array<{
    service: string
    total_collectors: number
    total_duration: number
  }>
}

export interface CollectionSummary {
  total_duts: number
  total_collectors_executed: number
  total_collectors_in_catalog: number
  total_collectors_filtered_out: number
  total_collectors_not_applicable?: number
  total_collectors_running?: number
  total_collectors_pending?: number
  total_log_size: number
  total_runtime: number
  overall_collection_pct: number
  overall_status?: 'Passed' | 'Degraded' | 'Failed' | 'Partial' | 'Interrupted' | 'Incomplete'
  runtime_status: RunResult['runtime_status'] | null
  collection_status: RunResult['collection_status'] | null
  collector_counts: CanonicalCollectorCounts | Record<string, never> | null
  run_identity?: RunIdentity
  run_result: RunResult | null
  domain_failure?: boolean
  domain_failure_type?: string
  domain_failure_reason?: string
  domain_failure_evidence?: string
  run_outcome_status?: RunOutcome['status']
  run_outcome_failure_type?: string
  run_outcome_reason?: string
  run_outcome?: RunOutcome
  underlying_outcome?: RunOutcome
  status_counts: {
    success: number
    error: number
    degraded?: number
    partial: number
    skipped: number
    cancelled?: number
    running?: number
    pending?: number
    not_ran?: number
  }
}

export interface RunOutcome {
  status: 'success' | 'domain_failed' | 'runtime_failed' | 'interrupted'
  reason: string
  affected_duts: string[]
  failure_type?: string
  evidence?: string
  underlying_outcome?: RunOutcome
}

export interface CanonicalCollectorCounts {
  total_collectors: number
  pending_collectors: number
  running_collectors: number
  completed_collectors: number
  degraded_collectors: number
  partial_collectors: number
  failed_collectors: number
  skipped_collectors: number
  cancelled_collectors: number
  baseboard_excluded: number
  capability_excluded: number
  config_excluded: number
}

export interface RunPathIdentity {
  path_sha256: string | null
  version_alignment: 'aligned' | 'conflict' | 'not_declared'
  level_alignment: 'aligned' | 'conflict' | 'not_declared'
  profile_alignment: 'aligned' | 'conflict' | 'not_declared'
}

export interface RunIdentity {
  schema_version: '1.1'
  tool: {
    version: string
    build_hash: string
    source_mode: 'frozen' | 'source' | 'unknown'
    source_revision: string
    build_timestamp_utc: string
  }
  catalog: {
    name: string
    version: string
    sha256: string
    size_bytes: number
    binding: 'manifest_bound' | 'operator_supplied' | 'discovered'
  }
  effective_config_sha256: string
  invocation: {
    resolved_level: 'L1' | 'L2' | 'L3' | 'unknown'
    resolved_profile: 'custom' | 'level' | 'planning' | 'streaming' | 'unknown'
    resolved_plan_sha256: string
    invocation_sha256: string
  }
  output: {
    mode: 'configured_generated' | 'caller_based_generated' | 'caller_supplied_append'
    caller_relation: 'absent' | 'same' | 'descendant'
    caller_path: RunPathIdentity
    resolved_path: RunPathIdentity
    generated_path: RunPathIdentity
  }
  identity_sha256: string
}

interface RunResultBase {
  mode: 'collection' | 'planning'
  runtime_status: 'success' | 'failed' | 'interrupted'
  collection_status: 'success' | 'partial' | 'failed' | 'interrupted' | 'incomplete'
  collector_counts: CanonicalCollectorCounts | Record<string, never>
  terminal_snapshot_committed: boolean
  explicit_domain_failure: boolean
  dut_roster: string[]
  affected_duts: string[]
  reasons: string[]
  exit_code?: 0 | 1 | 3 | 130
}

export type RunResult = RunResultBase & (
  | { schema_version: '1.0'; run_identity?: never }
  | { schema_version: '1.1'; run_identity: RunIdentity }
)

export interface CollectorDef {
  id: string
  name: string
  group: string
  description: string
  collection_level: string
  dependencies: string[]
  applicable_baseboards: string[]
  report_role?: string | string[]
}
