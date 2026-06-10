export const SUPPORTED_SCHEMA_VERSIONS = ['1.0', '2.0']

export interface Manifest {
  schema_version?: string
  version: string
  generated_at: string
  tool_version: string
  tool_config: {
    collection_level: string
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
  collection_summary: CollectionSummary
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
  collector_groups: CollectorGroup[]
  status_summary: {
    success: number
    error: number
    partial: number
    skipped: number
    not_ran: number
  }
  overall_status: 'success' | 'error' | 'partial' | 'skipped' | 'unknown'
  execution_time: number
  log_size: number
  system_info: {
    model: string | null
    part_number: string | null
    serial_number: string | null
    firmware: FirmwareEntry[]
    system_view?: SystemViewInfo
  }
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
  collectors: CollectorResult[]
  total_execution_time: number
}

export interface CollectorResult {
  id: string
  name: string
  status: 'success' | 'error' | 'partial' | 'skipped' | 'not_ran'
  execution_time: number
  start_time: string | null
  end_time: string | null
  reason: string
  dependencies: string[]
  collection_level: string
  files: FileRef[]
  stage_timing: {
    validation: number | null
    discovery: number | null
    execution: number | null
    post_processing: number | null
  }
}

export interface FileRef {
  path: string
  size: number
  type: 'json' | 'text' | 'log' | 'binary' | 'xml' | 'yaml'
  collector_id: string
  viewer_hint?: 'log-viewer' | 'json-tree' | 'monaco' | 'download'
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
  total_log_size: number
  total_runtime: number
  overall_collection_pct: number
  status_counts: {
    success: number
    error: number
    partial: number
    skipped: number
    not_ran: number
  }
}

export interface CollectorDef {
  id: string
  name: string
  group: string
  description: string
  collection_level: string
  dependencies: string[]
  applicable_baseboards: string[]
}
