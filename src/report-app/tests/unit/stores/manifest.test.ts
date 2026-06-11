import { setActivePinia, createPinia } from 'pinia'
import { describe, it, expect, beforeEach } from 'vitest'
import { useManifestStore } from '@/stores/manifest'
import type { Manifest } from '@/types/manifest'

const SAMPLE_MANIFEST: Manifest = {
  version: '1.0',
  generated_at: '2026-03-18T14:30:00Z',
  tool_version: '2.1.0',
  tool_config: { collection_level: 'L2', execution_mode: 'RemoteClient', baseboard: 'HGX_H100' },
  duts: [
    {
      id: 'DUT_1',
      baseboard: 'HGX_H100',
      node_type: 'Compute',
      bmc_ip: '10.0.0.1',
      collector_groups: [],
      status_summary: { success: 10, error: 2, partial: 1, skipped: 0, not_ran: 0 },
      overall_status: 'error',
      execution_time: 120.5,
      log_size: 52428800,
      system_info: { model: 'DGXH100', part_number: '123-456', serial_number: 'ABC789', firmware: [] },
    },
  ],
  collector_catalog: [],
  timing: { total_duration: 120.5, component_timing: { tool_init: null, config_load: null, dut_init: null, preflight: null, collection: null, report_generation: null, metadata_write: null, cleanup: null }, per_dut: [], per_service: [] },
  file_index: [
    { path: 'DUT_1/redfish/Systems.json', size: 1024, type: 'json', collector_id: 'R1', dut_id: 'DUT_1', collector_group: 'redfish', collector_name: 'Systems' },
    { path: 'DUT_1/host/dmesg.log', size: 5242880, type: 'log', collector_id: 'H1', dut_id: 'DUT_1', collector_group: 'host', collector_name: 'dmesg' },
  ],
  errors: [
    { dut_id: 'DUT_1', collector_id: 'R5', collector_name: 'Thermal', collector_group: 'redfish', message: 'Connection timeout', timestamp: null },
  ],
  preflight: { per_dut: [] },
  collection_summary: {
    total_duts: 1,
    total_collectors_executed: 13,
    total_collectors_in_catalog: 50,
    total_collectors_filtered_out: 37,
    total_log_size: 52428800,
    total_runtime: 120.5,
    overall_collection_pct: 76.9,
    status_counts: { success: 10, error: 2, partial: 1, skipped: 0, not_ran: 0 },
  },
}

describe('manifest store', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('starts with null manifest', () => {
    const store = useManifestStore()
    expect(store.manifest).toBeNull()
    expect(store.loaded).toBe(false)
  })

  it('loads from JSON', () => {
    const store = useManifestStore()
    store.loadFromJson(SAMPLE_MANIFEST)
    expect(store.loaded).toBe(true)
    expect(store.manifest?.version).toBe('1.0')
  })

  it('returns duts', () => {
    const store = useManifestStore()
    store.loadFromJson(SAMPLE_MANIFEST)
    expect(store.duts).toHaveLength(1)
    expect(store.duts[0].id).toBe('DUT_1')
  })

  it('finds DUT by id', () => {
    const store = useManifestStore()
    store.loadFromJson(SAMPLE_MANIFEST)
    expect(store.dutById('DUT_1')?.baseboard).toBe('HGX_H100')
    expect(store.dutById('NONEXISTENT')).toBeUndefined()
  })

  it('filters files by DUT', () => {
    const store = useManifestStore()
    store.loadFromJson(SAMPLE_MANIFEST)
    expect(store.filesByDut('DUT_1')).toHaveLength(2)
    expect(store.filesByDut('DUT_2')).toHaveLength(0)
  })

  it('returns global status counts', () => {
    const store = useManifestStore()
    store.loadFromJson(SAMPLE_MANIFEST)
    expect(store.globalStatusCounts.success).toBe(10)
    expect(store.globalStatusCounts.error).toBe(2)
  })

  it('returns errors', () => {
    const store = useManifestStore()
    store.loadFromJson(SAMPLE_MANIFEST)
    expect(store.errors).toHaveLength(1)
    expect(store.errors[0].message).toBe('Connection timeout')
  })
})
