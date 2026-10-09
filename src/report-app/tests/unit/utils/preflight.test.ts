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
import type { PreflightCheck } from '@/types/manifest'
import {
  formatPreflightStatusCounts,
  normalizePreflightStatus,
  summarizePreflightChecks,
} from '@/utils/preflight'

function check(status: string): PreflightCheck {
  return {
    name: `Check ${status}`,
    group: 'test',
    status: status as PreflightCheck['status'],
    details: '',
  }
}

describe('preflight status utilities', () => {
  it('preserves canonical status semantics when summarizing checks', () => {
    const summary = summarizePreflightChecks([
      check('pass'),
      check('fail'),
      check('warning'),
      check('skip'),
      check('na'),
    ])

    expect(summary).toEqual({
      pass: 1,
      fail: 1,
      warning: 1,
      skip: 1,
      na: 1,
      total: 5,
    })
    expect(formatPreflightStatusCounts(summary)).toBe(
      '1 passed, 1 failed, 1 warning, 1 skipped, 1 not applicable',
    )
  })

  it.each([
    ['passed', 'pass'],
    ['success', 'pass'],
    ['failed', 'fail'],
    ['error', 'fail'],
    ['warn', 'warning'],
    ['skipped', 'skip'],
    ['not_ran', 'skip'],
    ['N/A', 'na'],
    ['', 'na'],
  ])('normalizes legacy status %j to %j', (input, expected) => {
    expect(normalizePreflightStatus(input)).toBe(expected)
  })

  it('reports missing checks as no preflight data', () => {
    const summary = summarizePreflightChecks(undefined)

    expect(summary.total).toBe(0)
    expect(formatPreflightStatusCounts(summary)).toBe('No preflight data')
  })
})
