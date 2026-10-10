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

export const TERMINAL_COLLECTOR_STATUSES = [
  'success',
  'degraded',
  'error',
  'partial',
  'skipped',
  'cancelled',
] as const

export const ACTIVE_COLLECTOR_STATUSES = ['running', 'pending'] as const

export type TerminalCollectorStatus =
  (typeof TERMINAL_COLLECTOR_STATUSES)[number]
export type ActiveCollectorStatus =
  (typeof ACTIVE_COLLECTOR_STATUSES)[number]
export type CollectorLifecycleStatus =
  | TerminalCollectorStatus
  | ActiveCollectorStatus
  | 'not_ran'
  | 'unknown'

export interface CollectorLifecycleCounts {
  success: number
  degraded: number
  error: number
  partial: number
  skipped: number
  cancelled: number
  running: number
  pending: number
}

export interface CollectorLifecycleSummary {
  counts: CollectorLifecycleCounts
  completedCount: number
  activeCount: number
  passRate: number | null
  state: 'complete' | 'in_progress' | 'no_data'
}

type CollectorLifecycleCountInput = Partial<CollectorLifecycleCounts> & {
  canceled?: unknown
}

const TERMINAL_STATUS_SET = new Set<string>(TERMINAL_COLLECTOR_STATUSES)
const ACTIVE_STATUS_SET = new Set<string>(ACTIVE_COLLECTOR_STATUSES)

function safeCount(value: unknown): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
    ? value
    : 0
}

export function normalizeCollectorStatus(
  value: unknown,
): CollectorLifecycleStatus {
  if (typeof value !== 'string') return 'unknown'
  const normalized = value.trim().toLowerCase().replace(/[\s-]+/g, '_')
  if (normalized === 'canceled') return 'cancelled'
  if (
    TERMINAL_STATUS_SET.has(normalized) ||
    ACTIVE_STATUS_SET.has(normalized) ||
    normalized === 'not_ran'
  ) {
    return normalized as CollectorLifecycleStatus
  }
  return 'unknown'
}

export function isTerminalCollectorStatus(value: unknown): boolean {
  return TERMINAL_STATUS_SET.has(normalizeCollectorStatus(value))
}

export function isActiveCollectorStatus(value: unknown): boolean {
  return ACTIVE_STATUS_SET.has(normalizeCollectorStatus(value))
}

export function normalizeCollectorLifecycleCounts(
  value: CollectorLifecycleCountInput | null | undefined,
): CollectorLifecycleCounts {
  const source = value ?? {}
  return {
    success: safeCount(source.success),
    degraded: safeCount(source.degraded),
    error: safeCount(source.error),
    partial: safeCount(source.partial),
    skipped: safeCount(source.skipped),
    cancelled:
      source.cancelled === undefined
        ? safeCount(source.canceled)
        : safeCount(source.cancelled),
    running: safeCount(source.running),
    pending: safeCount(source.pending),
  }
}

export function summarizeCollectorLifecycleCounts(
  value: CollectorLifecycleCountInput | null | undefined,
): CollectorLifecycleSummary {
  const counts = normalizeCollectorLifecycleCounts(value)
  const completedCount = TERMINAL_COLLECTOR_STATUSES.reduce(
    (total, status) => total + counts[status],
    0,
  )
  const activeCount = ACTIVE_COLLECTOR_STATUSES.reduce(
    (total, status) => total + counts[status],
    0,
  )

  return {
    counts,
    completedCount,
    activeCount,
    passRate:
      completedCount > 0 ? (counts.success / completedCount) * 100 : null,
    state:
      completedCount > 0
        ? 'complete'
        : activeCount > 0
          ? 'in_progress'
          : 'no_data',
  }
}

export function summarizeCollectorStatuses(
  statuses: Iterable<unknown>,
): CollectorLifecycleSummary {
  const counts = normalizeCollectorLifecycleCounts(null)
  for (const value of statuses) {
    const status = normalizeCollectorStatus(value)
    if (status in counts) {
      counts[status as keyof CollectorLifecycleCounts] += 1
    }
  }
  return summarizeCollectorLifecycleCounts(counts)
}

export function formatCollectorPassRate(
  summary: CollectorLifecycleSummary,
  fractionDigits = 0,
): string {
  if (summary.state === 'in_progress') return 'In progress'
  if (summary.passRate === null) return '\u2014'
  return `${summary.passRate.toFixed(fractionDigits)}%`
}
