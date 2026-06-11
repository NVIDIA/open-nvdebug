import { describe, it, expect } from 'vitest'
import { generateReportSummary } from '@/composables/useReportSummary'
import type { Manifest } from '@/types/manifest'

function makeManifest(): Manifest {
  return {
    schema_version: '2.0',
    version: '1.0',
    generated_at: '2026-03-19T12:00:00Z',
    tool_version: '2.5.0',
    tool_config: { collection_level: 'L2', execution_mode: 'parallel', baseboard: 'GB200' },
    duts: [{
      id: 'DUT_1',
      baseboard: 'GB200',
      node_type: 'compute',
      bmc_ip: '10.0.0.1',
      collector_groups: [{
        name: 'redfish',
        service_type: 'redfish',
        total_execution_time: 60,
        collectors: [
          { id: 'R001', name: 'BMC Info', status: 'success', execution_time: 30, start_time: null, end_time: null, reason: '', dependencies: [], collection_level: 'L2', files: [], stage_timing: { validation: null, discovery: null, execution: null, post_processing: null } },
          { id: 'R002', name: 'Sensors', status: 'error', execution_time: 30, start_time: null, end_time: null, reason: 'timeout', dependencies: [], collection_level: 'L2', files: [], stage_timing: { validation: null, discovery: null, execution: null, post_processing: null } },
        ],
      }],
      status_summary: { success: 1, error: 1, partial: 0, skipped: 0, not_ran: 0 },
      overall_status: 'partial',
      execution_time: 60,
      log_size: 1024 * 500,
      system_info: { model: 'GB200', part_number: 'P001', serial_number: 'S001', firmware: [] },
    }],
    collector_catalog: [],
    timing: { total_duration: 60, component_timing: {} as any, per_dut: [], per_service: [] },
    file_index: [],
    errors: [{
      dut_id: 'DUT_1',
      collector_id: 'R002',
      collector_name: 'Sensors',
      collector_group: 'redfish',
      message: 'Request timed out after 30s',
      timestamp: null,
    }],
    preflight: { per_dut: [] },
    collection_summary: {
      total_duts: 1,
      total_collectors_executed: 2,
      total_collectors_in_catalog: 10,
      total_collectors_filtered_out: 0,
      total_log_size: 1024 * 500,
      total_runtime: 60,
      overall_collection_pct: 50,
      status_counts: { success: 1, error: 1, partial: 0, skipped: 0, not_ran: 0 },
    },
  }
}

describe('useReportSummary', () => {
  it('generates a non-empty summary', () => {
    const summary = generateReportSummary(makeManifest())
    expect(summary.length).toBeGreaterThan(0)
  })

  it('includes collection date', () => {
    const summary = generateReportSummary(makeManifest())
    expect(summary).toContain('2026-03-19')
  })

  it('includes DUT count', () => {
    const summary = generateReportSummary(makeManifest())
    expect(summary).toContain('1 DUT')
  })

  it('includes error information', () => {
    const summary = generateReportSummary(makeManifest())
    expect(summary).toContain('Issues found')
    expect(summary).toContain('DUT_1')
  })

  it('includes pass rate percentage', () => {
    const summary = generateReportSummary(makeManifest())
    expect(summary).toContain('50%')
  })
})
