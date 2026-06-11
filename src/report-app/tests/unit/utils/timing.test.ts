import { describe, expect, it } from 'vitest'
import { buildDurationBuckets, hasTimingValues, normalizeCollectorId, topSlowCollectors } from '@/utils/timing'

describe('timing utilities', () => {
  it('groups collector durations into readable operator buckets', () => {
    const buckets = buildDurationBuckets([0.4, 3, 11, 75, 420])

    expect(buckets.map(b => ({ label: b.label, count: b.count }))).toEqual([
      { label: '< 1s', count: 1 },
      { label: '1-10s', count: 1 },
      { label: '10-60s', count: 1 },
      { label: '1-5m', count: 1 },
      { label: '> 5m', count: 1 },
    ])
    expect(buckets.every(b => b.percent === 20)).toBe(true)
  })

  it('returns the slowest collectors with useful rank metadata', () => {
    const slowest = topSlowCollectors([
      { id: 'R1', name: 'Inventory', group: 'redfish', dutId: 'DUT_A', duration: 8 },
      { id: 'R37', name: 'GPU Debug Dump', group: 'redfish', dutId: 'DUT_A', duration: 240 },
      { id: 'H2', name: 'Host Logs', group: 'host', dutId: 'DUT_B', duration: 40 },
    ])

    expect(slowest).toEqual([
      { id: 'R37', name: 'GPU Debug Dump', group: 'redfish', dutId: 'DUT_A', duration: 240 },
      { id: 'H2', name: 'Host Logs', group: 'host', dutId: 'DUT_B', duration: 40 },
      { id: 'R1', name: 'Inventory', group: 'redfish', dutId: 'DUT_A', duration: 8 },
    ])
  })

  it('detects when component timing has no useful data', () => {
    expect(hasTimingValues({ tool_init: null, config_load: 0, collection: null })).toBe(false)
    expect(hasTimingValues({ tool_init: null, collection: 12.5 })).toBe(true)
  })

  it('normalizes collector IDs for matching timing and file metadata', () => {
    expect(normalizeCollectorId('R37')).toBe('r37')
    expect(normalizeCollectorId(' h8 ')).toBe('h8')
  })
})
