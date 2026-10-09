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
  analyzeCoFailures,
  MAX_CO_FAILURE_PAIR_OBSERVATIONS,
} from '@/composables/useCoFailureAnalysis'
import { validateAndNormalize } from '@/stores/manifest'
import type { Manifest } from '@/types/manifest'

function manifestWithFailures(failuresByDut: string[][]): Manifest {
  return {
    duts: failuresByDut.map((collectorIds, index) => ({
      id: `dut-${index}`,
      collector_groups: [{
        name: 'redfish',
        service_type: 'redfish',
        collectors: collectorIds.map(id => ({
          id,
          status: 'error',
          dependencies: [],
        })),
      }],
    })),
  } as unknown as Manifest
}

describe('co-failure analysis resource bounds', () => {
  it('preserves correlations for ordinary manifests', () => {
    const result = analyzeCoFailures(
      manifestWithFailures([
        ['R1', 'R2'],
        ['R1', 'R2'],
      ]),
    )

    expect(result.limited).toBe(false)
    expect(result.pairs).toEqual([{
      a: 'R1',
      b: 'R2',
      coCount: 2,
      jaccard: 1,
      dutIds: ['dut-0', 'dut-1'],
    }])
    expect(result.clusters).toHaveLength(1)
    expect(result.clusters[0].coOccurrences).toBe(2)
  })

  it('does not enumerate pairs that cannot meet the two-DUT threshold', () => {
    const collectorIds = Array.from(
      { length: 20_000 },
      (_, index) => `R${index}`,
    )

    const result = analyzeCoFailures(manifestWithFailures([collectorIds]))

    expect(result).toEqual({
      pairs: [],
      clusters: [],
      limited: false,
      limitReason: null,
    })
  })

  it('fails closed before pair enumeration exceeds the safety budget', () => {
    const collectorCount = 448
    const collectorIds = Array.from(
      { length: collectorCount },
      (_, index) => `R${index}`,
    )
    expect(collectorCount * (collectorCount - 1) / 2).toBeGreaterThan(
      MAX_CO_FAILURE_PAIR_OBSERVATIONS,
    )

    const result = analyzeCoFailures(
      manifestWithFailures([collectorIds, collectorIds]),
    )

    expect(result.limited).toBe(true)
    expect(result.pairs).toEqual([])
    expect(result.clusters).toEqual([])
    expect(result.limitReason).toContain('safety limit')
  })

  it('rejects manifests whose actual collector arrays exceed the record cap', () => {
    const collectors = new Array(100_001).fill(null)

    expect(() => validateAndNormalize({
      duts: [{
        id: 'dut-0',
        collector_groups: [{ collectors }],
      }],
    })).toThrow('Manifest collector records exceed the 100000-entry safety limit')
  })
})
