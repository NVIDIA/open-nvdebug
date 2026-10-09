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

import type { PreflightCheck } from '@/types/manifest'

export interface PreflightStatusCounts {
  pass: number
  fail: number
  warning: number
  skip: number
  na: number
  total: number
}

type PreflightStatus = keyof Omit<PreflightStatusCounts, 'total'>

const STATUS_ALIASES: Record<string, PreflightStatus> = {
  pass: 'pass',
  passed: 'pass',
  success: 'pass',
  fail: 'fail',
  failed: 'fail',
  error: 'fail',
  warning: 'warning',
  warn: 'warning',
  skip: 'skip',
  skipped: 'skip',
  not_ran: 'skip',
  notran: 'skip',
  na: 'na',
  'n/a': 'na',
}

export function normalizePreflightStatus(status: unknown): PreflightStatus {
  if (typeof status !== 'string') return 'na'
  return STATUS_ALIASES[status.trim().toLowerCase()] ?? 'na'
}

export function summarizePreflightChecks(
  checks: readonly PreflightCheck[] | undefined,
): PreflightStatusCounts {
  const counts: PreflightStatusCounts = {
    pass: 0,
    fail: 0,
    warning: 0,
    skip: 0,
    na: 0,
    total: checks?.length ?? 0,
  }

  for (const check of checks ?? []) {
    counts[normalizePreflightStatus(check.status)]++
  }

  return counts
}

export function formatPreflightStatusCounts(counts: PreflightStatusCounts): string {
  if (counts.total === 0) return 'No preflight data'

  const parts: string[] = []
  if (counts.pass > 0) parts.push(`${counts.pass} passed`)
  if (counts.fail > 0) parts.push(`${counts.fail} failed`)
  if (counts.warning > 0) {
    parts.push(`${counts.warning} ${counts.warning === 1 ? 'warning' : 'warnings'}`)
  }
  if (counts.skip > 0) parts.push(`${counts.skip} skipped`)
  if (counts.na > 0) parts.push(`${counts.na} not applicable`)
  return parts.join(', ')
}
