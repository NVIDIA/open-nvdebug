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

import type { CollectorResult, GranularCollectorTiming } from '@/types/manifest'

type StageTiming = CollectorResult['stage_timing']
const STAGES = ['validation', 'discovery', 'execution', 'post_processing'] as const

/** Fill missing stage values from measured sources, preserving explicit zeroes. */
export function resolveStageTiming(...sources: unknown[]): StageTiming {
  const result: StageTiming = { validation: null, discovery: null, execution: null, post_processing: null }
  for (const source of sources) {
    if (!source || typeof source !== 'object') continue
    for (const stage of STAGES) {
      let value = (source as Record<string, unknown>)[stage]
      if (value && typeof value === 'object') {
        const record = value as Record<string, unknown>
        value = record.total_time ?? record.duration ?? record.duration_seconds
      }
      if (result[stage] === null && typeof value === 'number' && Number.isFinite(value) && value >= 0) {
        result[stage] = value
      }
    }
  }
  return result
}

/** Use recorded stage spans, never the sum of their nested requests or hooks. */
export function stageTimingFromOperations(timing: GranularCollectorTiming | null | undefined): StageTiming {
  const result = resolveStageTiming()
  const operations = Array.isArray(timing?.operations) ? timing.operations : []
  const stageIds = new Set(operations.filter(operation => operation?.operation_type === 'stage').map(operation => operation.operation_id))
  for (const operation of operations) {
    if (operation?.operation_type !== 'stage' || (operation.parent_id && stageIds.has(operation.parent_id))) continue
    const stage = operation.name as keyof StageTiming
    const duration = operation.duration_seconds
    if (!STAGES.includes(stage) || typeof duration !== 'number' || !Number.isFinite(duration) || duration < 0) continue
    result[stage] = (result[stage] ?? 0) + duration
  }
  return resolveStageTiming(result)
}

export interface DurationBucket {
  label: string
  min: number
  max: number
  count: number
  percent: number
}

export interface SlowCollector {
  id: string
  name: string
  group: string
  dutId: string
  duration: number
}

const BUCKETS: Array<Omit<DurationBucket, 'count' | 'percent'>> = [
  { label: '< 1s', min: 0, max: 1 },
  { label: '1-10s', min: 1, max: 10 },
  { label: '10-60s', min: 10, max: 60 },
  { label: '1-5m', min: 60, max: 300 },
  { label: '> 5m', min: 300, max: Number.POSITIVE_INFINITY },
]

type ArtifactTiming = GranularCollectorTiming['artifact_timings'][number]

const ARTIFACT_TIMING_PRIORITY: Record<string, number> = {
  not_instrumented: 0,
  artifact_persistence: 1,
  hook_acquisition: 2,
  host_command_acquisition: 2,
  host_command: 2,
  bmc_ssh_command: 2,
  ipmi_command: 2,
  host_file_acquisition: 2,
  bmc_file_acquisition: 2,
  redfish_file_acquisition: 2,
  redfish_request: 2,
  bmc_ssh_command_duration: 3,
  bmc_ssh_command_duration_estimated: 3,
}

function artifactTimingPriority(timing: ArtifactTiming): number {
  return ARTIFACT_TIMING_PRIORITY[timing.measurement] ?? 1
}

export function selectPreferredArtifactTimings(
  timings: readonly ArtifactTiming[],
): Map<string, ArtifactTiming> {
  const selected = new Map<string, ArtifactTiming>()
  for (const timing of timings) {
    const existing = selected.get(timing.path)
    if (!existing || artifactTimingPriority(timing) >= artifactTimingPriority(existing)) {
      selected.set(timing.path, timing)
    }
  }
  return selected
}

export function buildDurationBuckets(durations: number[]): DurationBucket[] {
  const positiveDurations = durations.filter(duration => duration > 0)
  if (positiveDurations.length === 0) return []

  const counts = new Array(BUCKETS.length).fill(0) as number[]
  for (const duration of positiveDurations) {
    const index = BUCKETS.findIndex(bucket => duration >= bucket.min && duration < bucket.max)
    counts[index >= 0 ? index : counts.length - 1]++
  }

  return BUCKETS.map((bucket, index) => ({
    ...bucket,
    count: counts[index],
    percent: Math.round((counts[index] / positiveDurations.length) * 100),
  }))
}

export function topSlowCollectors(collectors: SlowCollector[], limit = 5): SlowCollector[] {
  return [...collectors]
    .filter(collector => collector.duration > 0)
    .sort((a, b) => b.duration - a.duration)
    .slice(0, limit)
}

export function hasTimingValues(timing: Record<string, number | null | undefined>): boolean {
  return Object.values(timing).some(value => typeof value === 'number' && value > 0)
}

export function normalizeCollectorId(id: string): string {
  return id.trim().toLowerCase()
}
