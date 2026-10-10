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

  it('reports the selected 63 collectors without including 56 filtered catalog entries', () => {
    const manifest = makeManifest()
    manifest.errors = []
    manifest.collection_summary.total_collectors_executed = 63
    manifest.collection_summary.total_collectors_in_catalog = 119
    manifest.collection_summary.total_collectors_filtered_out = 56
    manifest.collection_summary.status_counts = {
      success: 63, error: 0, partial: 0, skipped: 0, not_ran: 56,
    }

    const summary = generateReportSummary(manifest)

    expect(summary).toContain('63/63 collectors passed (100%)')
    expect(summary).not.toContain('63/119')
  })

  it('excludes active records and counts cancelled as a non-pass', () => {
    const manifest = makeManifest()
    manifest.collection_summary.status_counts = {
      success: 1,
      error: 0,
      partial: 0,
      skipped: 0,
      cancelled: 1,
      running: 20,
      pending: 30,
    }

    const summary = generateReportSummary(manifest)

    expect(summary).toContain('1/2 collectors passed (50%)')
    expect(summary).toContain('1 cancelled')
    expect(summary).toContain('20 running, 30 pending')
  })

  it('reports degraded collectors as a distinct non-pass terminal state', () => {
    const manifest = makeManifest()
    manifest.collection_summary.status_counts = {
      success: 1,
      degraded: 1,
      error: 0,
      partial: 0,
      skipped: 0,
    }

    const summary = generateReportSummary(manifest)

    expect(summary).toContain('1/2 collectors passed (50%)')
    expect(summary).toContain('1 degraded, 0 failed')
  })

  it('labels active-only reports as in progress', () => {
    const manifest = makeManifest()
    manifest.collection_summary.status_counts = {
      success: 0,
      error: 0,
      partial: 0,
      skipped: 0,
      running: 2,
      pending: 3,
    }

    const summary = generateReportSummary(manifest)

    expect(summary).toContain('Overall: In progress.')
    expect(summary).toContain('2 running, 3 pending')
    expect(summary).not.toContain('(0%)')
  })
})
