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

import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  categoryFromCollectorId,
  categoryFromGroupName,
  correlateFiles,
  parseLevel,
  parseTimestamp,
} from '@/composables/useLogCorrelation'

describe('log correlation parsing', () => {
  afterEach(() => vi.useRealTimers())

  it.each([
    ['R17', 'redfish'],
    ['s2', 'ssh'],
    ['I4', 'ipmi'],
    ['H1', 'host'],
    ['B9', 'bmc'],
    ['C3', 'health_check'],
    ['X1', 'general'],
    [undefined, 'general'],
  ] as const)('maps collector %s to %s', (collectorId, expected) => {
    expect(categoryFromCollectorId(collectorId)).toBe(expected)
  })

  it.each([
    ['Redfish', 'redfish'],
    ['SSH', 'ssh'],
    ['bmc_ssh', 'ssh'],
    ['IPMI', 'ipmi'],
    ['host', 'host'],
    ['bmc', 'bmc'],
    ['health_check', 'health_check'],
    ['custom', 'general'],
    [undefined, 'general'],
  ] as const)('maps group %s to %s', (group, expected) => {
    expect(categoryFromGroupName(group)).toBe(expected)
  })

  it('recognizes ISO, bracketed, monotonic, and syslog timestamp formats', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-08-19T12:00:00Z'))

    expect(parseTimestamp('2026-08-19T01:02:03.004Z start'))
      .toBe(Date.parse('2026-08-19T01:02:03.004Z'))
    expect(parseTimestamp('[2026-08-19 01:02:03.004] start')).not.toBeNull()
    expect(parseTimestamp('[ 1.250] kernel event')).toBe(1250)
    expect(parseTimestamp('Jan 2 03:04:05 host daemon: ready')).not.toBeNull()
    expect(parseTimestamp('not a timestamp')).toBeNull()
    expect(parseTimestamp('2026-99-99T99:99:99Z invalid')).toBeNull()
  })

  it('normalizes supported levels and leaves unmarked text alone', () => {
    expect(parseLevel('[warning] threshold reached')).toBe('WARNING')
    expect(parseLevel('[CRITICAL] device failed')).toBe('CRITICAL')
    expect(parseLevel('ERROR without structural brackets')).toBeUndefined()
  })

  it('interleaves timestamped lines and preserves bounded source metadata', () => {
    const longMessage = `2026-08-19T01:02:05Z [INFO] ${'x'.repeat(400)}`

    const events = correlateFiles([
      {
        path: 'dut-a/redfish.log',
        index: 7,
        category: 'redfish',
        content: `${longMessage}\n\nplain text without a timestamp`,
      },
      {
        path: 'dut-a/host.log',
        index: 3,
        category: 'host',
        content: '2026-08-19T01:02:03Z [ERROR] earlier',
      },
      {
        path: 'dut-a/general.log',
        index: 9,
        content: '2026-08-19T01:02:04Z middle',
      },
    ])

    expect(events).toHaveLength(3)
    expect(events.map(event => event.sourceIndex)).toEqual([3, 9, 7])
    expect(events[0]).toMatchObject({
      source: 'dut-a/host.log',
      lineNumber: 1,
      level: 'ERROR',
      category: 'host',
    })
    expect(events[1].category).toBe('general')
    expect(events[2].line).toHaveLength(300)
    expect(events[2].level).toBe('INFO')
  })
})
