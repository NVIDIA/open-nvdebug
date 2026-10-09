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
import {
  clusterErrors,
  clusterErrorsWithStats,
  ERROR_CLUSTER_COMPARISON_LIMIT,
  ERROR_CLUSTER_INPUT_LIMIT,
  ERROR_CLUSTER_MESSAGE_LIMIT,
} from '@/composables/useErrorClustering'
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

  it('bounds attacker-controlled inputs and fuzzy comparisons', () => {
    const alphabet = 'ghjklmnpqrstuvwxyz'
    const uniqueSuffix = (index: number) => {
      let value = index
      let result = ''
      do {
        result = alphabet[value % alphabet.length] + result
        value = Math.floor(value / alphabet.length)
      } while (value > 0)
      return result
    }
    const errors = Array.from(
      { length: ERROR_CLUSTER_INPUT_LIMIT + 2_000 },
      (_, index) => makeError(`unique-${uniqueSuffix(index)}-${'x'.repeat(180)}`),
    )

    const result = clusterErrorsWithStats(errors)

    expect(result.processedErrors).toBe(ERROR_CLUSTER_INPUT_LIMIT)
    expect(result.omittedErrors).toBe(2_000)
    expect(result.comparisons).toBeLessThanOrEqual(ERROR_CLUSTER_COMPARISON_LIMIT)
    expect(result.clusters.reduce((total, cluster) => total + cluster.count, 0)).toBe(
      ERROR_CLUSTER_INPUT_LIMIT,
    )
  })

  it('normalizes only the bounded message prefix', () => {
    const longPrefix = 'connection refused: bounded-message-'.padEnd(200, 'x')
    const result = clusterErrorsWithStats([
      makeError(`${longPrefix}${'a'.repeat(100_000)}`),
      makeError(`${longPrefix}${'z'.repeat(100_000)}`),
    ])

    expect(result.clusters).toHaveLength(1)
    expect(result.clusters[0].count).toBe(2)
    expect(result.clusters[0].representative).toHaveLength(200)
    expect(result.clusters[0].knownIssue?.title).toBe('Connection Refused')
    expect(result.comparisons).toBe(0)
  })

  it('does not coerce malformed structured messages', () => {
    const hostileObject = {
      toString: () => {
        throw new Error('must not coerce attacker object')
      },
    }
    const hostileArray: unknown[] = []
    hostileArray.join = () => {
      throw new Error('must not join attacker array')
    }
    const objectError = makeError('')
    const arrayError = makeError('')
    objectError.message = hostileObject as unknown as string
    arrayError.message = hostileArray as unknown as string

    const result = clusterErrorsWithStats([objectError, arrayError])

    expect(result.clusters).toHaveLength(1)
    expect(result.clusters[0].representative).toBe('')
    expect(result.clusters[0].count).toBe(2)
  })

  it('drops malformed entries without invoking accessors or proxy traps', () => {
    const getterEntry = {
      ...makeError('getter'),
      get message() {
        throw new Error('must not invoke attacker getter')
      },
    }
    const proxyEntry = new Proxy(makeError('proxy'), {
      getOwnPropertyDescriptor() {
        throw new Error('must contain attacker proxy failure')
      },
    })
    const valid = makeError('Connection refused', 'DUT_VALID', 'C_VALID')

    const result = clusterErrorsWithStats([
      null,
      undefined,
      7,
      true,
      'error',
      [],
      getterEntry,
      proxyEntry,
      valid,
    ])

    expect(result.processedErrors).toBe(1)
    expect(result.omittedErrors).toBe(0)
    expect(result.clusters).toHaveLength(1)
    expect(result.clusters[0]).toMatchObject({
      representative: 'Connection refused',
      count: 1,
      dutIds: ['DUT_VALID'],
      collectorIds: ['C_VALID'],
    })
  })

  it('preserves valid results while bounding every retained text field', () => {
    const suffix = 'x'.repeat(ERROR_CLUSTER_MESSAGE_LIMIT + 20)
    const valid = makeError(`Timeout ${suffix}`, `DUT_${suffix}`, `C_${suffix}`)
    valid.collector_name = `name_${suffix}`
    valid.collector_group = `group_${suffix}`
    valid.timestamp = `2026-08-09T00:00:00Z_${suffix}`

    const result = clusterErrorsWithStats([valid])
    const entry = result.clusters[0].entries[0]

    expect(result.processedErrors).toBe(1)
    expect(result.clusters[0].representative).toBe(valid.message.slice(0, 200))
    expect(entry).toEqual({
      dut_id: valid.dut_id.slice(0, 200),
      collector_id: valid.collector_id.slice(0, 200),
      collector_name: valid.collector_name.slice(0, 200),
      collector_group: valid.collector_group.slice(0, 200),
      message: valid.message.slice(0, 200),
      timestamp: valid.timestamp.slice(0, 200),
    })
  })

  it('inspects only bounded entries and required fields', () => {
    let indexReads = 0
    const sparseErrors = new Proxy([], {
      get(target, property, receiver) {
        if (property === 'length') return Number.MAX_SAFE_INTEGER
        if (typeof property === 'string' && /^\d+$/u.test(property)) indexReads++
        return Reflect.get(target, property, receiver)
      },
    })

    const sparseResult = clusterErrorsWithStats(sparseErrors)
    expect(sparseResult.processedErrors).toBe(0)
    expect(indexReads).toBe(ERROR_CLUSTER_INPUT_LIMIT)

    const valid = makeError('Connection refused')
    let descriptorReads = 0
    const extraFields = new Proxy({ ...valid, unused: 'ignored' }, {
      ownKeys() {
        throw new Error('must not enumerate unused attacker fields')
      },
      getOwnPropertyDescriptor(target, property) {
        descriptorReads++
        return Reflect.getOwnPropertyDescriptor(target, property)
      },
    })

    const extraFieldResult = clusterErrorsWithStats([extraFields])
    expect(extraFieldResult.clusters[0].entries).toEqual([valid])
    expect(descriptorReads).toBe(6)
  })
})
