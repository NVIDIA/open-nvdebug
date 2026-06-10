import { describe, it, expect } from 'vitest'
import { detectAnomalies, getAnomalySummary } from '@/composables/useAnomalyDetection'
import type { Manifest } from '@/types/manifest'

function makeManifest(overrides: Partial<Manifest> = {}): Manifest {
  return {
    schema_version: '2.0',
    version: '1.0',
    generated_at: '2026-03-19T00:00:00Z',
    tool_version: '1.0.0',
    tool_config: { collection_level: 'L2', execution_mode: 'parallel', baseboard: 'GB200' },
    duts: [],
    collector_catalog: [],
    timing: { total_duration: 120, component_timing: {} as any, per_dut: [], per_service: [] },
    file_index: [],
    errors: [],
    preflight: { per_dut: [] },
    collection_summary: {
      total_duts: 0,
      total_collectors_executed: 0,
      total_collectors_in_catalog: 0,
      total_collectors_filtered_out: 0,
      total_log_size: 0,
      total_runtime: 120,
      overall_collection_pct: 100,
      status_counts: { success: 0, error: 0, partial: 0, skipped: 0, not_ran: 0 },
    },
    ...overrides,
  }
}

function makeDut(
  id: string,
  collectors: Array<{ id: string; time: number; status: string; files?: number; group?: string }>,
  logSize = 1024 * 1024,
) {
  const statusCounts = { success: 0, error: 0, partial: 0, skipped: 0, not_ran: 0 }
  for (const c of collectors) {
    const key = c.status as keyof typeof statusCounts
    if (key in statusCounts) statusCounts[key]++
  }

  const grouped = new Map<string, typeof collectors>()
  for (const c of collectors) {
    const g = c.group ?? 'redfish'
    if (!grouped.has(g)) grouped.set(g, [])
    grouped.get(g)!.push(c)
  }

  return {
    id,
    baseboard: 'GB200',
    node_type: 'compute',
    bmc_ip: '10.0.0.1',
    collector_groups: [...grouped.entries()].map(([name, cols]) => ({
      name,
      service_type: name,
      total_execution_time: cols.reduce((s, c) => s + c.time, 0),
      collectors: cols.map(c => ({
        id: c.id,
        name: c.id,
        status: c.status as any,
        execution_time: c.time,
        start_time: null,
        end_time: null,
        reason: '',
        dependencies: [],
        collection_level: 'L2',
        files: Array.from({ length: c.files ?? 1 }, (_, i) => ({
          path: `${id}/${c.id}/file${i}.json`,
          size: 1024,
          type: 'json' as const,
          collector_id: c.id,
        })),
        stage_timing: { validation: null, discovery: null, execution: null, post_processing: null },
      })),
    })),
    status_summary: statusCounts,
    overall_status: 'success' as const,
    execution_time: collectors.reduce((s, c) => s + c.time, 0),
    log_size: logSize,
    system_info: { model: null, part_number: null, serial_number: null, firmware: [] },
  }
}

describe('useAnomalyDetection', () => {
  it('returns empty for manifest with no data', () => {
    const anomalies = detectAnomalies(makeManifest())
    expect(anomalies).toEqual([])
  })

  it('detects per-collector-ID slow across DUTs', () => {
    const duts = []
    for (let i = 0; i < 10; i++) {
      duts.push(makeDut(`DUT_${i}`, [
        { id: 'R10', time: 1.5, status: 'success' },
        { id: 'R20', time: 3.0, status: 'success' },
      ]))
    }
    // One DUT where R10 is massively slow
    duts.push(makeDut('DUT_SLOW', [
      { id: 'R10', time: 60, status: 'success' },
      { id: 'R20', time: 3.0, status: 'success' },
    ]))

    const manifest = makeManifest({ duts })
    const anomalies = detectAnomalies(manifest)
    const crossSlow = anomalies.filter(a => a.type === 'cross_dut_slow')
    expect(crossSlow.length).toBeGreaterThanOrEqual(1)
    expect(crossSlow.some(a => a.dutId === 'DUT_SLOW' && a.collectorId === 'R10')).toBe(true)
    // R20 should NOT be flagged (consistent across all DUTs)
    expect(crossSlow.some(a => a.collectorId === 'R20')).toBe(false)
  })

  it('detects locally slow collector within a single DUT', () => {
    const normalCollectors = Array.from({ length: 20 }, (_, i) => ({
      id: `R${String(i + 1).padStart(3, '0')}`,
      time: 2 + Math.random(),
      status: 'success',
    }))
    normalCollectors.push({ id: 'R_SLOW', time: 200, status: 'success' })
    const dut = makeDut('DUT_1', normalCollectors)
    const manifest = makeManifest({ duts: [dut] })
    const anomalies = detectAnomalies(manifest)
    const slow = anomalies.filter(a => a.type === 'slow_collector')
    expect(slow.length).toBeGreaterThanOrEqual(1)
    expect(slow[0].collectorId).toBe('R_SLOW')
  })

  it('detects high failure rate', () => {
    const dut = makeDut('DUT_1', [
      { id: 'R001', time: 5, status: 'error' },
      { id: 'R002', time: 5, status: 'error' },
      { id: 'R003', time: 5, status: 'error' },
      { id: 'R004', time: 5, status: 'success' },
    ])
    const manifest = makeManifest({ duts: [dut] })
    const anomalies = detectAnomalies(manifest)
    const highFail = anomalies.filter(a => a.type === 'high_failure_rate')
    expect(highFail.length).toBe(1)
  })

  it('detects missing files on success', () => {
    const dut = makeDut('DUT_1', [
      { id: 'R001', time: 5, status: 'success', files: 0 },
    ])
    const manifest = makeManifest({ duts: [dut] })
    const anomalies = detectAnomalies(manifest)
    const missing = anomalies.filter(a => a.type === 'missing_files')
    expect(missing.length).toBe(1)
  })

  it('detects cross-DUT status inconsistency', () => {
    const duts = [
      makeDut('DUT_A', [{ id: 'R10', time: 2, status: 'success' }]),
      makeDut('DUT_B', [{ id: 'R10', time: 2, status: 'success' }]),
      makeDut('DUT_C', [{ id: 'R10', time: 2, status: 'error' }]),
    ]
    const manifest = makeManifest({ duts })
    const anomalies = detectAnomalies(manifest)
    const inconsistent = anomalies.filter(a => a.type === 'cross_dut_inconsistency')
    expect(inconsistent.length).toBe(1)
    expect(inconsistent[0].dutId).toBe('DUT_C')
    expect(inconsistent[0].collectorId).toBe('R10')
  })

  it('detects abnormal log size', () => {
    const duts = [
      makeDut('DUT_A', [{ id: 'R10', time: 2, status: 'success' }], 1024 * 1024),
      makeDut('DUT_B', [{ id: 'R10', time: 2, status: 'success' }], 1024 * 1024),
      makeDut('DUT_C', [{ id: 'R10', time: 2, status: 'success' }], 1024 * 1024),
      makeDut('DUT_BIG', [{ id: 'R10', time: 2, status: 'success' }], 500 * 1024 * 1024),
    ]
    const manifest = makeManifest({ duts })
    const anomalies = detectAnomalies(manifest)
    const logSize = anomalies.filter(a => a.type === 'abnormal_log_size')
    expect(logSize.length).toBeGreaterThanOrEqual(1)
    expect(logSize.some(a => a.dutId === 'DUT_BIG')).toBe(true)
  })

  it('getAnomalySummary counts correctly', () => {
    const normalCollectors = Array.from({ length: 10 }, (_, i) => ({
      id: `R${String(i + 1).padStart(3, '0')}`,
      time: 2,
      status: 'success',
    }))
    normalCollectors.push({ id: 'R_SLOW', time: 200, status: 'success' })
    normalCollectors.push({ id: 'R_EMPTY', time: 2, status: 'success' })
    const dut = makeDut('DUT_1', normalCollectors)
    // Make the EMPTY one have 0 files
    dut.collector_groups[0].collectors.find(c => c.id === 'R_EMPTY')!.files = []
    const manifest = makeManifest({ duts: [dut] })
    const anomalies = detectAnomalies(manifest)
    const summary = getAnomalySummary(anomalies)
    expect(summary.critical + summary.warning + summary.info).toBe(anomalies.length)
  })
})
