import { describe, it, expect } from 'vitest'
import { clusterErrors } from '@/composables/useErrorClustering'
import type { ErrorEntry } from '@/types/manifest'

function makeError(msg: string, dutId = 'DUT_1', collectorId = 'C001'): ErrorEntry {
  return {
    dut_id: dutId,
    collector_id: collectorId,
    collector_name: 'Test',
    collector_group: 'test',
    message: msg,
    timestamp: null,
  }
}

describe('useErrorClustering', () => {
  it('returns empty for empty input', () => {
    expect(clusterErrors([])).toEqual([])
  })

  it('clusters identical messages', () => {
    const errors = [
      makeError('Connection refused'),
      makeError('Connection refused', 'DUT_2'),
      makeError('Connection refused', 'DUT_3'),
    ]
    const clusters = clusterErrors(errors)
    expect(clusters).toHaveLength(1)
    expect(clusters[0].count).toBe(3)
    expect(clusters[0].dutIds).toEqual(['DUT_1', 'DUT_2', 'DUT_3'])
  })

  it('clusters similar messages with different IPs', () => {
    const errors = [
      makeError('Connection refused to 192.168.1.1:443'),
      makeError('Connection refused to 10.0.0.5:443'),
    ]
    const clusters = clusterErrors(errors)
    expect(clusters).toHaveLength(1)
    expect(clusters[0].count).toBe(2)
  })

  it('separates unrelated messages', () => {
    const errors = [
      makeError('Connection refused'),
      makeError('Authentication failed: invalid credentials'),
    ]
    const clusters = clusterErrors(errors)
    expect(clusters.length).toBeGreaterThanOrEqual(2)
  })

  it('detects known issues', () => {
    const errors = [makeError('Connection refused')]
    const clusters = clusterErrors(errors)
    expect(clusters[0].knownIssue).not.toBeNull()
    expect(clusters[0].knownIssue?.title).toBe('Connection Refused')
  })

  it('classifies severity based on count and DUTs', () => {
    const errors = Array.from({ length: 15 }, (_, i) =>
      makeError('Timeout error', `DUT_${i}`)
    )
    const clusters = clusterErrors(errors)
    expect(clusters[0].severity).toBe('critical')
  })

  it('sorts clusters by severity then count', () => {
    const errors = [
      ...Array.from({ length: 10 }, () => makeError('Critical mass error')),
      makeError('Minor glitch'),
    ]
    const clusters = clusterErrors(errors)
    expect(clusters[0].count).toBeGreaterThan(clusters[clusters.length - 1].count)
  })
})
