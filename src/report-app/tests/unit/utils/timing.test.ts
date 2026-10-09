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

import { describe, expect, it } from 'vitest'
import {
  buildDurationBuckets,
  hasTimingValues,
  normalizeCollectorId,
  resolveStageTiming,
  stageTimingFromOperations,
  selectPreferredArtifactTimings,
  topSlowCollectors,
} from '@/utils/timing'
import type { GranularCollectorTiming } from '@/types/manifest'

describe('timing utilities', () => {
  it('fills missing summary stages without inventing zeroes or replacing measured values', () => {
    expect(resolveStageTiming(
      { execution: 0, validation: null, discovery: Number.NaN, post_processing: -1 },
      { execution: 9, validation: { total_time: 0.5 }, discovery: {}, post_processing: { duration_seconds: 2 } },
    )).toEqual({ execution: 0, validation: 0.5, discovery: null, post_processing: 2 })
  })

  it('uses only stage scopes and excludes their nested work from stage totals', () => {
    const operations = [
      { operation_id: 'stage', operation_type: 'stage', name: 'execution', duration_seconds: 2.5 },
      { operation_id: 'request', operation_type: 'request', name: 'execution', duration_seconds: 2 },
      { operation_id: 'nested', parent_id: 'stage', operation_type: 'stage', name: 'execution', duration_seconds: 2 },
      { operation_id: 'retry', operation_type: 'stage', name: 'execution', duration_seconds: 1 },
    ] as GranularCollectorTiming['operations']
    expect(stageTimingFromOperations({ operations } as GranularCollectorTiming)).toEqual({
      execution: 3.5, validation: null, discovery: null, post_processing: null,
    })
  })
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

  it('keeps Redfish acquisition timing when persistence targets the same artifact', () => {
    const path = 'dut-1/redfish/Redfish_R1/events.json'
    const common = {
      path,
      measurement_quality: 'measured' as const,
      shared_operation_artifact_count: 1,
      started_at: '2026-08-20T00:00:00Z',
      ended_at: '2026-08-20T00:00:01Z',
      size_bytes: 2,
      status: 'success',
    }
    const selected = selectPreferredArtifactTimings([
      {
        ...common,
        operation_id: 'request-1',
        measurement: 'redfish_request',
        measurement_scope: 'shared_requests',
        shared_request_operation_count: 2,
        duration_seconds: null,
      },
      {
        ...common,
        operation_id: 'persist-1',
        measurement: 'artifact_persistence',
        measurement_scope: 'artifact',
        duration_seconds: 0.01,
      },
    ])

    expect(selected.get(path)).toMatchObject({
      operation_id: 'request-1',
      measurement: 'redfish_request',
      measurement_scope: 'shared_requests',
      shared_request_operation_count: 2,
      duration_seconds: null,
    })
  })
})
