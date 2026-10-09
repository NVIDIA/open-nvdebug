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
  ACTIVE_COLLECTOR_STATUSES,
  TERMINAL_COLLECTOR_STATUSES,
  formatCollectorPassRate,
  isActiveCollectorStatus,
  isTerminalCollectorStatus,
  normalizeCollectorLifecycleCounts,
  normalizeCollectorStatus,
  summarizeCollectorLifecycleCounts,
  summarizeCollectorStatuses,
} from '@/utils/collectorLifecycle'

describe('collector lifecycle policy', () => {
  it('defines the audited terminal and active sets once', () => {
    expect(TERMINAL_COLLECTOR_STATUSES).toEqual([
      'success',
      'degraded',
      'error',
      'partial',
      'skipped',
      'cancelled',
    ])
    expect(ACTIVE_COLLECTOR_STATUSES).toEqual(['running', 'pending'])

    for (const status of TERMINAL_COLLECTOR_STATUSES) {
      expect(isTerminalCollectorStatus(status)).toBe(true)
      expect(isActiveCollectorStatus(status)).toBe(false)
    }
    for (const status of ACTIVE_COLLECTOR_STATUSES) {
      expect(isTerminalCollectorStatus(status)).toBe(false)
      expect(isActiveCollectorStatus(status)).toBe(true)
    }
  })

  it('keeps active records out of completed and pass-rate denominators', () => {
    const summary = summarizeCollectorLifecycleCounts({
      success: 1,
      error: 1,
      partial: 1,
      skipped: 1,
      cancelled: 1,
      running: 20,
      pending: 30,
    })

    expect(summary.completedCount).toBe(5)
    expect(summary.activeCount).toBe(50)
    expect(summary.passRate).toBe(20)
    expect(formatCollectorPassRate(summary)).toBe('20%')
  })

  it('counts cancelled as completed but never as a pass', () => {
    const cancelledOnly = summarizeCollectorStatuses(['cancelled'])

    expect(cancelledOnly.completedCount).toBe(1)
    expect(cancelledOnly.counts.success).toBe(0)
    expect(cancelledOnly.passRate).toBe(0)
    expect(formatCollectorPassRate(cancelledOnly)).toBe('0%')
  })

  it('labels active-only collections as in progress', () => {
    const summary = summarizeCollectorStatuses(['running', 'pending', 'not_ran'])

    expect(summary.completedCount).toBe(0)
    expect(summary.activeCount).toBe(2)
    expect(summary.passRate).toBeNull()
    expect(summary.state).toBe('in_progress')
    expect(formatCollectorPassRate(summary)).toBe('In progress')
  })

  it('distinguishes no data from an active collection', () => {
    const summary = summarizeCollectorStatuses(['not_ran', 'unknown'])

    expect(summary.state).toBe('no_data')
    expect(summary.passRate).toBeNull()
    expect(formatCollectorPassRate(summary)).toBe('\u2014')
  })

  it('normalizes the legacy US spelling without double counting it', () => {
    expect(normalizeCollectorStatus(' CANCELED ')).toBe('cancelled')
    expect(
      normalizeCollectorLifecycleCounts({ cancelled: 2, canceled: 7 }),
    ).toMatchObject({ cancelled: 2 })
    expect(
      normalizeCollectorLifecycleCounts({ canceled: 7 }),
    ).toMatchObject({ cancelled: 7 })
  })

  it('fails closed on invalid, negative, or nonnumeric counts', () => {
    expect(
      normalizeCollectorLifecycleCounts({
        success: Number.NaN,
        error: -1,
        partial: 1.5,
        skipped: Number.POSITIVE_INFINITY,
      }),
    ).toMatchObject({ success: 0, error: 0, partial: 0, skipped: 0 })
  })
})
