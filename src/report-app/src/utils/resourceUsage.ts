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

import type {
  AnalyzeResourceUsageOptions,
  RequestCaptureAnalysis,
  ResourceDataHealth,
  ResourceLoadDiagnostics,
  ResourceMetricDefinition,
  ResourceRunSignals,
  ResourceSamplePoint,
  ResourceScopeDiagnostic,
  ResourceUsageAnalysis,
  SchedulerDiagnostic,
} from '@/types/resourceUsage'

type JsonRecord = Record<string, unknown>

const DEFAULT_TIMELINE_POINTS = 900
const MAX_RENDERED_SCOPES = 64
const SUPPORTED_RESOURCE_SCHEMA_VERSION = 1
const MEMORY_ACCUMULATION_MIN_BYTES = 64 * 1024 * 1024
const MEMORY_ACCUMULATION_MIN_SECONDS = 10 * 60
const IMPORTANT_TIMELINE_KEYS: Array<keyof ResourceSamplePoint> = [
  'rssBytes',
  'cgroupMemoryBytes',
  'processSwapBytes',
  'cgroupSwapBytes',
  'cpuCores',
  'cgroupCpuCores',
  'physicalReadBytesPerSecond',
  'physicalWriteBytesPerSecond',
  'logicalReadBytesPerSecond',
  'logicalWriteBytesPerSecond',
  'cpuPressureSomeAvg10',
  'cpuPressureFullAvg10',
  'memoryPressureSomeAvg10',
  'memoryPressureFullAvg10',
  'pidsCurrent',
  'pidsLimit',
  'threads',
  'openFds',
  'majorPageFaults',
  'captureActiveWorkers',
  'captureQueuedCalls',
  'captureWorkerCompletions',
  'captureQueueWaitSecondsTotal',
  'captureUtilizationWhileQueuedPercent',
  'captureSaturationWhileQueuedPercent',
]

function asRecord(value: unknown): JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as JsonRecord
    : {}
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function at(value: unknown, ...path: string[]): unknown {
  let current = value
  for (const part of path) {
    const record = asRecord(current)
    if (!(part in record)) return undefined
    current = record[part]
  }
  return current
}

function finiteNumber(value: unknown): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value)
    return Number.isFinite(parsed) ? parsed : null
  }
  return null
}

function nonNegativeNumber(value: unknown): number | null {
  const parsed = finiteNumber(value)
  return parsed !== null && parsed >= 0 ? parsed : null
}

function boundedRatio(value: unknown): number | null {
  const parsed = finiteNumber(value)
  return parsed !== null && parsed >= 0 && parsed <= 1 ? parsed : null
}

function ratioPercent(value: unknown): number | null {
  const ratio = boundedRatio(value)
  return ratio === null ? null : ratio * 100
}

function textValue(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback
}

function boundedText(value: unknown, fallback = '', maximum = 512): string {
  const text = textValue(value, fallback)
  return text.length <= maximum ? text : `${text.slice(0, maximum - 1)}…`
}

function booleanValue(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null
}

function sumPresent(values: Array<number | null>): number | null {
  const available = values.filter((value): value is number => value !== null)
  return available.length > 0 ? available.reduce((sum, value) => sum + value, 0) : null
}

function maxPresent(values: Array<number | null>): number | null {
  const available = values.filter((value): value is number => value !== null)
  return available.length > 0
    ? available.reduce((maximum, value) => Math.max(maximum, value), Number.NEGATIVE_INFINITY)
    : null
}

function minPresent(values: Array<number | null>): number | null {
  const available = values.filter((value): value is number => value !== null)
  return available.length > 0
    ? available.reduce((minimum, value) => Math.min(minimum, value), Number.POSITIVE_INFINITY)
    : null
}

function parseTimestamp(value: unknown): number | null {
  if (typeof value !== 'string' || value.length === 0) return null
  const parsed = Date.parse(value)
  return Number.isFinite(parsed) ? parsed : null
}

function scopeId(scope: JsonRecord): string {
  return `${textValue(scope.controller, 'unknown')}:${textValue(scope.path, '/')}`
}

function maxScopeMetric(scopes: JsonRecord[], path: string[]): number | null {
  return maxPresent(scopes.map(scope => nonNegativeNumber(at(scope, ...path))))
}

function minScopeMetric(scopes: JsonRecord[], path: string[]): number | null {
  return minPresent(scopes.map(scope => nonNegativeNumber(at(scope, ...path))))
}

function pressureMetric(scopes: JsonRecord[], domain: 'cpu' | 'memory', kind: 'some' | 'full'): number | null {
  return maxScopeMetric(scopes, [domain, 'pressure', kind, 'avg10'])
}

function scopeRole(
  scopes: JsonRecord[],
  scope: JsonRecord,
  index: number,
): ResourceScopeDiagnostic['role'] {
  const explicitRoles = scopes.some(candidate => candidate.role === 'current' || candidate.role === 'ancestor')
  if (explicitRoles) {
    return scope.role === 'current' || scope.role === 'ancestor' ? scope.role : 'unknown'
  }

  // Schema-v1 artifacts produced before scope roles were added always place
  // the process's own scope first for each controller, followed by any limited
  // ancestors. Preserve that contract without folding ancestor usage into the
  // process-facing timelines and signals.
  const controller = textValue(scope.controller, 'unknown')
  const firstForController = scopes.findIndex(candidate =>
    textValue(candidate.controller, 'unknown') === controller,
  )
  return firstForController === index ? 'current' : 'ancestor'
}

function currentScopes(scopes: JsonRecord[]): JsonRecord[] {
  return scopes.filter((scope, index) => scopeRole(scopes, scope, index) === 'current')
}

function cgroupSwapBytes(scopes: JsonRecord[], field: 'current' | 'peak'): number | null {
  return maxPresent(scopes.map(scope => {
    const direct = nonNegativeNumber(at(scope, 'memory', `swap_${field}_bytes`))
    if (direct !== null) return direct
    if (field === 'peak') return null
    const memory = nonNegativeNumber(at(scope, 'memory', 'current_bytes'))
    const memoryAndSwap = nonNegativeNumber(at(scope, 'memory', 'memory_and_swap_current_bytes'))
    if (memory === null || memoryAndSwap === null) return null
    return Math.max(0, memoryAndSwap - memory)
  }))
}

function cgroupCpuUsageSeconds(scopes: JsonRecord[]): number | null {
  const values = currentScopes(scopes).map(scope => {
    const usageUsec = nonNegativeNumber(at(scope, 'cpu', 'stat', 'usage_usec'))
    if (usageUsec !== null) return usageUsec / 1_000_000
    const usageNanoseconds = nonNegativeNumber(at(scope, 'cpu', 'usage_nanoseconds'))
    return usageNanoseconds === null ? null : usageNanoseconds / 1_000_000_000
  })
  return maxPresent(values)
}

function cgroupThrottledSeconds(scopes: JsonRecord[]): number | null {
  const values = scopes.map(scope => {
    const throttledUsec = nonNegativeNumber(at(scope, 'cpu', 'stat', 'throttled_usec'))
    if (throttledUsec !== null) return throttledUsec / 1_000_000
    const throttledNanoseconds = nonNegativeNumber(at(scope, 'cpu', 'stat', 'throttled_time'))
    return throttledNanoseconds === null ? null : throttledNanoseconds / 1_000_000_000
  })
  return maxPresent(values)
}

function cgroupMemoryEvent(scopes: JsonRecord[], key: string): number | null {
  return maxPresent(scopes.flatMap(scope => [
    nonNegativeNumber(at(scope, 'memory', 'events', key)),
    nonNegativeNumber(at(scope, 'memory', 'events_local', key)),
  ]))
}

function cgroupSwapEvents(scopes: JsonRecord[]): number | null {
  return maxPresent(scopes.map(scope => {
    const memory = asRecord(scope.memory)
    const events = asRecord(memory.swap_events)
    return sumPresent([
      ...Object.values(events).map(nonNegativeNumber),
      nonNegativeNumber(memory.memory_and_swap_fail_count),
    ])
  }))
}

export function normalizeResourceSample(value: unknown): ResourceSamplePoint | null {
  const sample = asRecord(value)
  if (Object.keys(sample).length === 0) return null
  const process = asRecord(sample.process)
  const io = asRecord(process.io)
  const cgroup = asRecord(sample.cgroup)
  const requestCapture = asRecord(at(sample, 'components', 'request_capture'))
  const requestCaptureCalls = asRecord(requestCapture.calls)
  const requestCapturePool = asRecord(requestCapture.pool)
  const requestCaptureQueue = asRecord(requestCapture.queue)
  const scopes = asArray(cgroup.scopes).map(asRecord).filter(scope => Object.keys(scope).length > 0)
  const leafScopes = currentScopes(scopes)
  const timestamp = typeof sample.timestamp === 'string' ? boundedText(sample.timestamp, '', 128) : null
  const elapsedSeconds = nonNegativeNumber(sample.elapsed_seconds)
  if (elapsedSeconds === null && parseTimestamp(timestamp) === null) return null
  const cpuTotalSeconds = sumPresent([
    nonNegativeNumber(process.user_cpu_seconds),
    nonNegativeNumber(process.system_cpu_seconds),
    nonNegativeNumber(process.completed_children_user_cpu_seconds),
    nonNegativeNumber(process.completed_children_system_cpu_seconds),
  ])

  return {
    timestamp,
    elapsedSeconds,
    reason: boundedText(sample.reason, 'sample', 128),
    rssBytes: nonNegativeNumber(process.rss_bytes),
    processPeakRssBytes: nonNegativeNumber(process.peak_rss_bytes),
    processSwapBytes: nonNegativeNumber(process.swap_bytes),
    cgroupMemoryBytes: maxScopeMetric(leafScopes, ['memory', 'current_bytes']),
    cgroupPeakMemoryBytes: maxScopeMetric(leafScopes, ['memory', 'peak_bytes']),
    cgroupSwapBytes: cgroupSwapBytes(leafScopes, 'current'),
    swapEvents: cgroupSwapEvents(leafScopes),
    cpuTotalSeconds,
    cgroupCpuUsageSeconds: cgroupCpuUsageSeconds(leafScopes),
    cpuCores: null,
    cgroupCpuCores: null,
    availableCpus: null,
    quotaPercent: null,
    cgroupQuotaPercent: null,
    physicalReadBytes: nonNegativeNumber(io.read_bytes),
    physicalWriteBytes: nonNegativeNumber(io.write_bytes),
    logicalReadBytes: nonNegativeNumber(io.rchar),
    logicalWriteBytes: nonNegativeNumber(io.wchar),
    physicalReadBytesPerSecond: null,
    physicalWriteBytesPerSecond: null,
    logicalReadBytesPerSecond: null,
    logicalWriteBytesPerSecond: null,
    throttledSeconds: cgroupThrottledSeconds(leafScopes),
    throttleEvents: maxScopeMetric(leafScopes, ['cpu', 'stat', 'nr_throttled']),
    oomEvents: cgroupMemoryEvent(leafScopes, 'oom'),
    oomKillEvents: cgroupMemoryEvent(leafScopes, 'oom_kill'),
    memoryHighEvents: cgroupMemoryEvent(leafScopes, 'high'),
    cpuPressureSomeAvg10: pressureMetric(leafScopes, 'cpu', 'some'),
    cpuPressureFullAvg10: pressureMetric(leafScopes, 'cpu', 'full'),
    memoryPressureSomeAvg10: pressureMetric(leafScopes, 'memory', 'some'),
    memoryPressureFullAvg10: pressureMetric(leafScopes, 'memory', 'full'),
    pidsCurrent: maxScopeMetric(leafScopes, ['pids', 'current']),
    pidsLimit: minScopeMetric(leafScopes, ['pids', 'limit', 'value']),
    threads: nonNegativeNumber(process.threads),
    openFds: nonNegativeNumber(process.open_fds),
    voluntaryContextSwitches: nonNegativeNumber(process.voluntary_context_switches),
    involuntaryContextSwitches: nonNegativeNumber(process.involuntary_context_switches),
    majorPageFaults: nonNegativeNumber(process.major_page_faults),
    captureWorkerCount: nonNegativeNumber(requestCapture.worker_count),
    captureActiveWorkers: nonNegativeNumber(requestCapturePool.active_workers),
    captureQueuedCalls: nonNegativeNumber(requestCapturePool.queued_calls),
    captureWorkerCompletions: nonNegativeNumber(requestCaptureCalls.worker_completions),
    captureWorkerFailures: nonNegativeNumber(requestCaptureCalls.worker_failures),
    captureQueueWaitSecondsTotal: nonNegativeNumber(requestCaptureQueue.wait_seconds_total),
    captureUtilizationWhileQueuedPercent: ratioPercent(requestCaptureQueue.utilization_while_queued_ratio),
    captureSaturationWhileQueuedPercent: ratioPercent(requestCaptureQueue.saturation_while_queued_ratio),
  }
}

function resolveAvailableCpus(artifact: JsonRecord): { value: number | null; source: string } {
  const candidates: Array<[unknown, string]> = [
    [at(artifact, 'scheduler', 'effective_cpus'), 'scheduler effective CPU budget'],
    [at(artifact, 'system', 'cgroup', 'effective_quota_cpus'), 'effective cgroup quota'],
    [at(artifact, 'system', 'affinity', 'cpu_count'), 'process CPU affinity'],
    [at(artifact, 'system', 'host_cpu_count'), 'host CPU count'],
  ]
  for (const [raw, source] of candidates) {
    const value = finiteNumber(raw)
    if (value !== null && value > 0) return { value, source }
  }
  return { value: null, source: 'unavailable' }
}

function counterRate(current: number | null, previous: number | null, seconds: number): { value: number | null; reset: boolean } {
  if (current === null || previous === null || seconds <= 0) return { value: null, reset: false }
  const delta = current - previous
  if (delta < 0) return { value: null, reset: true }
  return { value: delta / seconds, reset: false }
}

function syntheticGapPoint(previous: ResourceSamplePoint, current: ResourceSamplePoint): ResourceSamplePoint {
  const midpoint = previous.elapsedSeconds !== null && current.elapsedSeconds !== null
    ? (previous.elapsedSeconds + current.elapsedSeconds) / 2
    : null
  const blank = normalizeResourceSample({ elapsed_seconds: midpoint, reason: 'sampling_gap' })!
  blank.syntheticGap = true
  return blank
}

function annotateTimeline(
  sourceSamples: ResourceSamplePoint[],
  availableCpus: number | null,
  expectedInterval: number | null,
  startedAt: string | null,
): { samples: ResourceSamplePoint[]; gaps: number; estimatedMissing: number; counterResets: number } {
  const startedEpoch = parseTimestamp(startedAt)
  const normalized = sourceSamples.map(sample => ({ ...sample }))
  for (const sample of normalized) {
    if (sample.elapsedSeconds === null && sample.timestamp && startedEpoch !== null) {
      const timestamp = parseTimestamp(sample.timestamp)
      if (timestamp !== null) sample.elapsedSeconds = Math.max(0, (timestamp - startedEpoch) / 1000)
    }
    sample.availableCpus = availableCpus
  }
  normalized.sort((left, right) => {
    const leftElapsed = left.elapsedSeconds ?? Number.POSITIVE_INFINITY
    const rightElapsed = right.elapsedSeconds ?? Number.POSITIVE_INFINITY
    return leftElapsed - rightElapsed
  })

  const result: ResourceSamplePoint[] = []
  let previous: ResourceSamplePoint | null = null
  let gaps = 0
  let estimatedMissing = 0
  let counterResets = 0
  for (const sample of normalized) {
    if (previous?.elapsedSeconds !== null && previous?.elapsedSeconds !== undefined && sample.elapsedSeconds !== null) {
      const elapsedDelta = sample.elapsedSeconds - previous.elapsedSeconds
      if (elapsedDelta > 0) {
        const cpu = counterRate(sample.cpuTotalSeconds, previous.cpuTotalSeconds, elapsedDelta)
        const cgroupCpu = counterRate(sample.cgroupCpuUsageSeconds, previous.cgroupCpuUsageSeconds, elapsedDelta)
        const physicalRead = counterRate(sample.physicalReadBytes, previous.physicalReadBytes, elapsedDelta)
        const physicalWrite = counterRate(sample.physicalWriteBytes, previous.physicalWriteBytes, elapsedDelta)
        const logicalRead = counterRate(sample.logicalReadBytes, previous.logicalReadBytes, elapsedDelta)
        const logicalWrite = counterRate(sample.logicalWriteBytes, previous.logicalWriteBytes, elapsedDelta)
        sample.cpuCores = cpu.value
        sample.quotaPercent = cpu.value !== null && availableCpus !== null
          ? (cpu.value / availableCpus) * 100
          : null
        sample.cgroupCpuCores = cgroupCpu.value
        // A current cgroup can include sibling processes, while ancestors can
        // include an entire pod or host subtree. Neither is comparable to this
        // process's scheduler budget, so only process CPU gets a quota ratio.
        sample.cgroupQuotaPercent = null
        sample.physicalReadBytesPerSecond = physicalRead.value
        sample.physicalWriteBytesPerSecond = physicalWrite.value
        sample.logicalReadBytesPerSecond = logicalRead.value
        sample.logicalWriteBytesPerSecond = logicalWrite.value
        counterResets += [cpu, cgroupCpu, physicalRead, physicalWrite, logicalRead, logicalWrite]
          .filter(metric => metric.reset).length

        if (expectedInterval !== null && elapsedDelta > expectedInterval * 1.5) {
          gaps++
          estimatedMissing += Math.max(1, Math.round(elapsedDelta / expectedInterval) - 1)
          result.push(syntheticGapPoint(previous, sample))
        }
      }
    }
    result.push(sample)
    previous = sample
  }
  return { samples: result, gaps, estimatedMissing, counterResets }
}

export function downsampleResourceTimeline(points: ResourceSamplePoint[], maximum = DEFAULT_TIMELINE_POINTS): ResourceSamplePoint[] {
  const limit = Math.max(3, Math.floor(maximum))
  if (points.length <= limit) return points
  const selected = new Set<number>([0, points.length - 1])
  const gapIndexes = points
    .map((point, index) => point.syntheticGap ? index : -1)
    .filter(index => index >= 0)
  const gapBudget = Math.min(
    Math.max(0, limit - selected.size),
    Math.max(1, Math.floor(limit * 0.1)),
  )
  const gapStep = Math.max(1, Math.ceil(gapIndexes.length / Math.max(1, gapBudget)))
  for (let index = 0; index < gapIndexes.length && selected.size < limit; index += gapStep) {
    selected.add(gapIndexes[index])
  }

  // Uniform sampling alone can erase the exact spike that explains a long
  // run. Preserve one maximum for every primary metric before filling the
  // remaining display budget.
  for (const key of IMPORTANT_TIMELINE_KEYS) {
    if (selected.size >= limit) break
    let maximumIndex = -1
    let maximumValue = Number.NEGATIVE_INFINITY
    for (let index = 0; index < points.length; index++) {
      const value = points[index][key]
      if (typeof value === 'number' && Number.isFinite(value) && value > maximumValue) {
        maximumValue = value
        maximumIndex = index
      }
    }
    if (maximumIndex >= 0) selected.add(maximumIndex)
  }
  const remaining = limit - selected.size
  if (remaining > 0) {
    const step = (points.length - 1) / (remaining + 1)
    for (let index = 1; index <= remaining; index++) selected.add(Math.round(index * step))
  }
  while (selected.size < limit) {
    const ordered = [...selected].sort((left, right) => left - right)
    let widestStart = -1
    let widestDistance = 0
    for (let index = 1; index < ordered.length; index++) {
      const distance = ordered[index] - ordered[index - 1]
      if (distance > widestDistance) {
        widestDistance = distance
        widestStart = ordered[index - 1]
      }
    }
    if (widestDistance <= 1) break
    selected.add(widestStart + Math.floor(widestDistance / 2))
  }
  return [...selected]
    .sort((left, right) => left - right)
    .slice(0, limit)
    .map(index => points[index])
}

function deltaFromSummary(artifact: JsonRecord, path: string[]): number | null {
  return nonNegativeNumber(at(artifact, 'summary', 'deltas', ...path))
}

function endpointDelta(samples: ResourceSamplePoint[], key: keyof ResourceSamplePoint): number | null {
  const actual = samples.filter(sample => !sample.syntheticGap && typeof sample[key] === 'number')
  if (actual.length < 2) return null
  const first = actual[0][key] as number
  const last = actual[actual.length - 1][key] as number
  return last >= first ? last - first : null
}

function durationSeconds(artifact: JsonRecord, samples: ResourceSamplePoint[]): number | null {
  const summaryDuration = nonNegativeNumber(at(artifact, 'summary', 'duration_seconds'))
  if (summaryDuration !== null) return summaryDuration
  const elapsed = samples.map(sample => sample.elapsedSeconds).filter((value): value is number => value !== null)
  return elapsed.length > 0 ? Math.max(...elapsed) : null
}

function averageCpuCores(artifact: JsonRecord, samples: ResourceSamplePoint[], duration: number | null): number | null {
  if (duration === null || duration <= 0) return null
  const summaryCpu = sumPresent([
    deltaFromSummary(artifact, ['process', 'user_cpu_seconds']),
    deltaFromSummary(artifact, ['process', 'system_cpu_seconds']),
    deltaFromSummary(artifact, ['process', 'completed_children_user_cpu_seconds']),
    deltaFromSummary(artifact, ['process', 'completed_children_system_cpu_seconds']),
  ])
  if (summaryCpu !== null) return summaryCpu / duration
  const cpuDelta = endpointDelta(samples, 'cpuTotalSeconds')
  return cpuDelta === null ? null : cpuDelta / duration
}

function buildHealth(
  artifact: JsonRecord,
  diagnostics: ResourceLoadDiagnostics,
  loadedSamples: number,
  gaps: number,
  estimatedMissing: number,
  counterResets: number,
  scopeRowsIgnored: number,
): ResourceDataHealth {
  const samplesReported = nonNegativeNumber(at(artifact, 'summary', 'samples_total'))
  const samplesRetained = nonNegativeNumber(at(artifact, 'summary', 'samples_retained'))
    ?? nonNegativeNumber(at(artifact, 'sample_history', 'samples_retained'))
  const samplesDropped = nonNegativeNumber(at(artifact, 'summary', 'samples_dropped'))
  const samplesRotatedOut = nonNegativeNumber(at(artifact, 'summary', 'samples_rotated_out'))
  const sampleWriteFailures = nonNegativeNumber(at(artifact, 'summary', 'sample_history_write_failures'))
  const rotations = nonNegativeNumber(at(artifact, 'sample_history', 'rotations'))
  const expectedIntervalSeconds = finiteNumber(at(artifact, 'monitor', 'sample_interval_seconds'))
  const artifactWriteSucceeded = booleanValue(at(artifact, 'summary', 'artifact_write_succeeded'))
  const schemaVersion = finiteNumber(artifact.schema_version)
  const schemaSupported = schemaVersion === SUPPORTED_RESOURCE_SCHEMA_VERSION
  const status = boundedText(artifact.status, 'unknown', 64)
  const producerErrors = asArray(artifact.errors).length
  const scheduledPeriodicSamples = nonNegativeNumber(at(artifact, 'summary', 'sampling_schedule', 'periodic_samples'))
    ?? nonNegativeNumber(at(artifact, 'monitor', 'sampling_schedule', 'periodic_samples'))
  const missedScheduledIntervals = nonNegativeNumber(at(artifact, 'summary', 'sampling_schedule', 'missed_intervals'))
    ?? nonNegativeNumber(at(artifact, 'monitor', 'sampling_schedule', 'missed_intervals'))
  const maxSamplingJitterSeconds = nonNegativeNumber(at(artifact, 'summary', 'sampling_schedule', 'max_start_jitter_seconds'))
    ?? nonNegativeNumber(at(artifact, 'monitor', 'sampling_schedule', 'max_start_jitter_seconds'))
  const historySamplesLoaded = diagnostics.historySamplesLoaded ?? loadedSamples
  const retainedFileCoveragePercent = samplesRetained !== null && samplesRetained > 0
    ? Math.min(100, (historySamplesLoaded / samplesRetained) * 100)
    : null
  const scheduledTotal = scheduledPeriodicSamples !== null && missedScheduledIntervals !== null
    ? scheduledPeriodicSamples + missedScheduledIntervals
    : null
  const cadenceCoveragePercent = scheduledTotal !== null && scheduledTotal > 0
    ? Math.min(100, (scheduledPeriodicSamples! / scheduledTotal) * 100)
    : null
  const declaredCoverageIncomplete = samplesRetained !== null && samplesRetained > historySamplesLoaded
  const warnings: string[] = []
  if (diagnostics.missingFiles.length > 0) warnings.push(`Missing history file(s): ${diagnostics.missingFiles.join(', ')}`)
  if (diagnostics.malformedLines > 0) warnings.push(`${diagnostics.malformedLines} malformed JSONL sample(s) were skipped.`)
  if (diagnostics.oversizedLines > 0) warnings.push(`${diagnostics.oversizedLines} oversized JSONL line(s) were skipped.`)
  if (diagnostics.byteLimitReached) warnings.push('History byte limit reached; the displayed timeline is partial.')
  if (diagnostics.sampleLimitReached) warnings.push('History sample limit reached; additional samples were not loaded.')
  if (diagnostics.historySegmentsIgnored > 0) warnings.push(`${diagnostics.historySegmentsIgnored} unsupported or duplicate history segment declaration(s) were ignored.`)
  if (gaps > 0) warnings.push(`${gaps} sampling gap(s) indicate about ${estimatedMissing} missing interval(s).`)
  if ((samplesRotatedOut ?? 0) > 0) warnings.push(`${samplesRotatedOut} older sample(s) were intentionally rotated out by the producer.`)
  if ((sampleWriteFailures ?? 0) > 0) warnings.push(`${sampleWriteFailures} sample history write(s) failed.`)
  if (artifactWriteSucceeded === false) warnings.push('The producer reported that its final atomic summary write failed.')
  if (counterResets > 0) warnings.push(`${counterResets} cumulative counter reset(s) prevented interval-rate calculation.`)
  if (!schemaSupported) warnings.push(`Resource schema ${schemaVersion ?? 'unknown'} is not supported; known fields are shown conservatively.`)
  if (scopeRowsIgnored > 0) warnings.push(`${scopeRowsIgnored} cgroup scope row(s) exceeded the bounded display limit and were omitted.`)
  if (declaredCoverageIncomplete) warnings.push(`${Math.ceil(samplesRetained! - historySamplesLoaded)} retained sample(s) declared by the producer were not available to the dashboard.`)
  if ((missedScheduledIntervals ?? 0) > 0) warnings.push(`${missedScheduledIntervals} periodic sampling deadline(s) were missed by the producer.`)
  if (producerErrors > 0) warnings.push(`The resource monitor reported ${producerErrors} internal error(s).`)
  if (status !== 'completed') warnings.push(`The resource monitor ended with status "${status}" rather than "completed".`)

  let state: ResourceDataHealth['state'] = 'healthy'
  if (loadedSamples === 0) state = 'unavailable'
  else if (
    diagnostics.malformedLines > 0
    || diagnostics.oversizedLines > 0
    || (sampleWriteFailures ?? 0) > 0
    || gaps > 0
    || artifactWriteSucceeded === false
    || counterResets > 0
    || (missedScheduledIntervals ?? 0) > 0
    || producerErrors > 0
    || status !== 'completed'
  ) state = 'degraded'
  else if (
    diagnostics.byteLimitReached
    || diagnostics.sampleLimitReached
    || diagnostics.missingFiles.length > 0
    || (samplesRotatedOut ?? 0) > 0
    || diagnostics.historySegmentsIgnored > 0
    || !schemaSupported
    || scopeRowsIgnored > 0
    || declaredCoverageIncomplete
  ) state = 'limited'

  return {
    state,
    status,
    samplesReported,
    samplesRetained,
    samplesLoaded: loadedSamples,
    samplesDropped,
    samplesRotatedOut,
    sampleWriteFailures,
    malformedLines: diagnostics.malformedLines,
    oversizedLines: diagnostics.oversizedLines,
    historySegmentsIgnored: diagnostics.historySegmentsIgnored,
    gapCount: gaps,
    estimatedMissingSamples: estimatedMissing,
    counterResets,
    rotations,
    expectedIntervalSeconds,
    retainedFileCoveragePercent,
    cadenceCoveragePercent,
    scheduledPeriodicSamples,
    missedScheduledIntervals,
    maxSamplingJitterSeconds,
    artifactWriteSucceeded,
    byteLimitReached: diagnostics.byteLimitReached,
    sampleLimitReached: diagnostics.sampleLimitReached,
    warnings,
  }
}

function limitMetric(value: unknown): { value: number | null; state: ResourceScopeDiagnostic['memoryLimitState'] } {
  const limit = asRecord(value)
  const numeric = nonNegativeNumber(limit.value)
  if (numeric !== null) return { value: numeric, state: 'limited' }
  if (limit.unlimited === true || limit.raw === 'max') return { value: null, state: 'unlimited' }
  return { value: null, state: 'unavailable' }
}

function maximumEvent(primary: JsonRecord, local: JsonRecord, key: string): number | null {
  return maxPresent([
    nonNegativeNumber(primary[key]),
    nonNegativeNumber(local[key]),
  ])
}

function scopeDiagnostics(artifact: JsonRecord): { rows: ResourceScopeDiagnostic[]; ignored: number } {
  const latestScopes = asArray(at(artifact, 'latest', 'cgroup', 'scopes')).map(asRecord)
  const deltas = asRecord(at(artifact, 'summary', 'deltas', 'cgroup_scopes'))
  const observedPeaks = asRecord(at(artifact, 'summary', 'peaks', 'cgroup_scopes'))
  const rows = latestScopes.slice(0, MAX_RENDERED_SCOPES).map((scope, index) => {
    const id = scopeId(scope)
    const delta = asRecord(deltas[id])
    const observedPeak = asRecord(observedPeaks[id])
    const cpuStat = asRecord(delta.cpu_stat)
    const memoryEvents = asRecord(delta.memory_events)
    const memoryEventsLocal = asRecord(delta.memory_events_local)
    const swapEvents = asRecord(delta.swap_events)
    const pidsEvents = asRecord(delta.pids_events)
    const throttledUsec = nonNegativeNumber(cpuStat.throttled_usec)
    const throttledNanoseconds = nonNegativeNumber(cpuStat.throttled_time)
    const usageUsec = nonNegativeNumber(cpuStat.usage_usec)
    const usageNanoseconds = nonNegativeNumber(delta.usage_nanoseconds)
    const memory = asRecord(scope.memory)
    const memoryLimit = limitMetric(memory.limit)
    const swapLimit = limitMetric(memory.swap_limit)
    const memoryAndSwapLimit = limitMetric(memory.memory_and_swap_limit)
    const pids = asRecord(scope.pids)
    const pidsLimit = limitMetric(pids.limit)
    const directSwap = nonNegativeNumber(memory.swap_current_bytes)
    const memoryCurrent = nonNegativeNumber(memory.current_bytes)
    const memoryAndSwap = nonNegativeNumber(memory.memory_and_swap_current_bytes)
    const derivedV1Swap = memoryCurrent !== null && memoryAndSwap !== null
      ? Math.max(0, memoryAndSwap - memoryCurrent)
      : null
    const swapCurrent = directSwap ?? derivedV1Swap
    const role = scopeRole(latestScopes, scope, index)
    const swapCurrentSemantics: ResourceScopeDiagnostic['swapCurrentSemantics'] = directSwap !== null
      ? 'direct'
      : derivedV1Swap !== null
        ? 'derived_memsw'
        : 'unavailable'
    return {
      id,
      controller: boundedText(scope.controller, 'unknown', 64),
      path: boundedText(scope.path, '/', 512),
      role,
      memoryCurrentBytes: memoryCurrent,
      memoryPeakBytes: maxPresent([
        nonNegativeNumber(observedPeak.memory_current_bytes),
        memoryCurrent,
      ]),
      memoryLifetimePeakBytes: nonNegativeNumber(memory.peak_bytes),
      memoryLimitBytes: memoryLimit.value,
      memoryLimitState: memoryLimit.state,
      swapCurrentBytes: swapCurrent,
      swapObservedPeakBytes: maxPresent([
        nonNegativeNumber(observedPeak.swap_current_bytes),
        swapCurrent,
      ]),
      swapLifetimeHighWaterBytes: maxPresent([
        nonNegativeNumber(observedPeak.swap_peak_bytes),
        nonNegativeNumber(memory.swap_peak_bytes),
      ]),
      swapLimitBytes: swapLimit.value,
      swapLimitState: swapLimit.state,
      swapCurrentSemantics,
      memoryAndSwapCurrentBytes: memoryAndSwap,
      memoryAndSwapLimitBytes: memoryAndSwapLimit.value,
      memoryAndSwapLimitState: memoryAndSwapLimit.state,
      swapEvents: sumPresent([
        ...Object.values(swapEvents).map(nonNegativeNumber),
        nonNegativeNumber(delta.memory_and_swap_fail_count),
      ]),
      cpuUsageSeconds: usageUsec !== null ? usageUsec / 1_000_000 : usageNanoseconds !== null ? usageNanoseconds / 1_000_000_000 : null,
      throttleEvents: nonNegativeNumber(cpuStat.nr_throttled),
      throttledSeconds: throttledUsec !== null ? throttledUsec / 1_000_000 : throttledNanoseconds !== null ? throttledNanoseconds / 1_000_000_000 : null,
      oomEvents: maximumEvent(memoryEvents, memoryEventsLocal, 'oom'),
      oomKillEvents: maximumEvent(memoryEvents, memoryEventsLocal, 'oom_kill'),
      memoryHighEvents: maximumEvent(memoryEvents, memoryEventsLocal, 'high'),
      cpuPressureSomeAvg10: nonNegativeNumber(at(scope, 'cpu', 'pressure', 'some', 'avg10')),
      cpuPressureFullAvg10: nonNegativeNumber(at(scope, 'cpu', 'pressure', 'full', 'avg10')),
      memoryPressureSomeAvg10: nonNegativeNumber(at(scope, 'memory', 'pressure', 'some', 'avg10')),
      memoryPressureFullAvg10: nonNegativeNumber(at(scope, 'memory', 'pressure', 'full', 'avg10')),
      pidsCurrent: nonNegativeNumber(pids.current),
      pidsLimit: pidsLimit.value,
      pidsLimitState: pidsLimit.state,
      pidsMaxEvents: nonNegativeNumber(pidsEvents.max),
    }
  })
  return { rows, ignored: Math.max(0, latestScopes.length - rows.length) }
}

function schedulerDiagnostics(artifact: JsonRecord, availableCpus: { value: number | null; source: string }): SchedulerDiagnostic[] {
  const scheduler = asRecord(artifact.scheduler)
  const system = asRecord(artifact.system)
  const cgroup = asRecord(system.cgroup)
  const affinity = asRecord(system.affinity)
  const v1Cpu = asRecord(at(cgroup, 'controllers', 'cpu'))
  const quotaCandidates = [
    ...asArray(cgroup.cpu_quota_candidates),
    ...asArray(v1Cpu.quota_candidates),
  ].map(asRecord)
  const effectiveQuota = nonNegativeNumber(cgroup.effective_quota_cpus)
  const cgroupQuotaDisplay: unknown = effectiveQuota
    ?? (quotaCandidates.some(candidate => candidate.state === 'unlimited')
      && !quotaCandidates.some(candidate => candidate.state === 'limited')
      ? 'Unlimited'
      : null)
  const bindingSources = Array.isArray(scheduler.binding_sources)
    ? scheduler.binding_sources.slice(0, 32).map(source => boundedText(source, 'unknown', 128)).join(', ')
    : scheduler.binding_sources
  const entries: Array<[string, unknown]> = [
    ['Available CPU budget', availableCpus.value],
    ['CPU budget source', availableCpus.source],
    ['Host logical CPUs', system.host_cpu_count],
    ['Affinity CPUs', affinity.cpu_count],
    ['Affinity mask', affinity.cpus_compact],
    ['cgroup version', cgroup.version],
    ['Effective cgroup quota (CPUs)', cgroupQuotaDisplay],
    ['Effective cpuset', cgroup.cpuset_cpus_effective],
    ['Oversubscription factor', scheduler.oversubscription_factor],
    ['Collector operation cap', scheduler.installed_collector_operation_limit ?? scheduler.collector_operation_limit],
    ['DUT concurrency cap', scheduler.max_concurrent_duts],
    ['Binding sources', bindingSources],
  ]
  return entries.map(([label, raw]) => {
    const unavailable = raw === null || raw === undefined || raw === ''
    return {
      label,
      value: unavailable ? 'Unavailable' : boundedText(String(raw), 'Unavailable', 512),
      state: unavailable ? 'unavailable' : 'available',
    }
  })
}

function requestCaptureAnalysis(artifact: JsonRecord): RequestCaptureAnalysis | null {
  const capture = asRecord(at(artifact, 'components', 'request_capture'))
  if (Object.keys(capture).length === 0) return null
  const calls = asRecord(capture.calls)
  const pool = asRecord(capture.pool)
  const queue = asRecord(capture.queue)
  const workers = asRecord(capture.workers)
  return {
    schemaVersion: finiteNumber(capture.schema_version)
      ?? (boundedText(capture.schema_version, '', 64) || null),
    status: boundedText(capture.status, 'unknown', 64),
    workerCount: nonNegativeNumber(capture.worker_count),
    observationSeconds: nonNegativeNumber(capture.observation_seconds),
    callsEnqueued: nonNegativeNumber(calls.enqueued),
    callsCompleted: nonNegativeNumber(calls.worker_completions),
    workerFailures: nonNegativeNumber(calls.worker_failures),
    abandonedBeforeSubmission: nonNegativeNumber(calls.abandoned_before_submission),
    peakActiveWorkers: nonNegativeNumber(pool.peak_active_workers),
    peakQueuedCalls: nonNegativeNumber(pool.peak_queued_calls),
    queueWaitSecondsTotal: nonNegativeNumber(queue.wait_seconds_total),
    queueWaitSecondsAverage: nonNegativeNumber(queue.wait_seconds_average),
    queueWaitSecondsMax: nonNegativeNumber(queue.wait_seconds_max),
    queuedWallSeconds: nonNegativeNumber(queue.queued_wall_seconds),
    queuedCapacityWorkerSeconds: nonNegativeNumber(queue.queued_capacity_worker_seconds),
    queuedActiveWorkerSeconds: nonNegativeNumber(queue.queued_active_worker_seconds),
    saturatedWhileQueuedSeconds: nonNegativeNumber(queue.saturated_while_queued_seconds),
    runnableGapWorkerSeconds: nonNegativeNumber(queue.runnable_gap_worker_seconds),
    utilizationWhileQueuedRatio: boundedRatio(queue.utilization_while_queued_ratio),
    saturationWhileQueuedRatio: boundedRatio(queue.saturation_while_queued_ratio),
    workerSecondsTotal: nonNegativeNumber(workers.seconds_total),
    workerUtilizationRatio: boundedRatio(workers.utilization_ratio),
  }
}

function maximumCgroupDelta(artifact: JsonRecord, path: string[]): number | null {
  const deltas = asRecord(at(artifact, 'summary', 'deltas', 'cgroup_scopes'))
  const latestScopes = asArray(at(artifact, 'latest', 'cgroup', 'scopes')).map(asRecord)
  const currentIds = new Set(
    currentScopes(latestScopes).map(scopeId),
  )
  return maxPresent(Object.entries(deltas)
    .filter(([id]) => currentIds.has(id))
    .map(([, scope]) => nonNegativeNumber(at(scope, ...path))))
}

function maximumCgroupDeltaSum(artifact: JsonRecord, paths: string[][]): number | null {
  const deltas = asRecord(at(artifact, 'summary', 'deltas', 'cgroup_scopes'))
  const latestScopes = asArray(at(artifact, 'latest', 'cgroup', 'scopes')).map(asRecord)
  const currentIds = new Set(
    currentScopes(latestScopes).map(scopeId),
  )
  return maxPresent(Object.entries(deltas)
    .filter(([id]) => currentIds.has(id))
    .map(([, scope]) => sumPresent(paths.map(path => nonNegativeNumber(at(scope, ...path))))))
}

function buildRunSignals(
  artifact: JsonRecord,
  samples: ResourceSamplePoint[],
  scopes: ResourceScopeDiagnostic[],
  duration: number | null,
  finalRss: number | null,
  peakRss: number | null,
): ResourceRunSignals {
  const currentScopeRows = scopes.filter(scope => scope.role === 'current')
  const currentScopeIds = new Set(currentScopeRows.map(scope => scope.id))
  const baselineRss = nonNegativeNumber(at(artifact, 'baseline', 'process', 'rss_bytes'))
    ?? samples.find(sample => sample.rssBytes !== null)?.rssBytes
    ?? null
  const rssGrowthBytes = baselineRss !== null && finalRss !== null ? finalRss - baselineRss : null
  const rssGrowthBytesPerHour = rssGrowthBytes !== null && duration !== null && duration > 0
    ? rssGrowthBytes / (duration / 3600)
    : null
  const peakRssRetainedPercent = finalRss !== null && peakRss !== null && peakRss > 0
    ? (finalRss / peakRss) * 100
    : null
  let memoryAccumulationState: ResourceRunSignals['memoryAccumulationState'] = 'unavailable'
  if (rssGrowthBytes !== null && baselineRss !== null && duration !== null && duration >= MEMORY_ACCUMULATION_MIN_SECONDS) {
    memoryAccumulationState = rssGrowthBytes > Math.max(MEMORY_ACCUMULATION_MIN_BYTES, baselineRss * 0.2)
      ? 'observed'
      : 'clear'
  }

  const peakCpuBudgetPercent = maxPresent(samples.map(sample => sample.quotaPercent))
  const throttleEvents = maximumCgroupDelta(artifact, ['cpu_stat', 'nr_throttled'])
    ?? endpointDelta(samples, 'throttleEvents')
  const throttledSecondsUsec = maximumCgroupDelta(artifact, ['cpu_stat', 'throttled_usec'])
  const throttledSecondsNsec = maximumCgroupDelta(artifact, ['cpu_stat', 'throttled_time'])
  const throttledSeconds = throttledSecondsUsec !== null
    ? throttledSecondsUsec / 1_000_000
    : throttledSecondsNsec !== null
      ? throttledSecondsNsec / 1_000_000_000
      : endpointDelta(samples, 'throttledSeconds')
  const peakCpuPressureSomeAvg10 = maxPresent(samples.map(sample => sample.cpuPressureSomeAvg10))
  const cpuSignalAvailable = [peakCpuBudgetPercent, throttleEvents, throttledSeconds, peakCpuPressureSomeAvg10]
    .some(value => value !== null)
  const cpuPressureState: ResourceRunSignals['cpuPressureState'] = !cpuSignalAvailable
    ? 'unavailable'
    : (throttleEvents ?? 0) > 0
      || (throttledSeconds ?? 0) > 0
      || (peakCpuBudgetPercent ?? 0) >= 100
      || (peakCpuPressureSomeAvg10 ?? 0) >= 10
      ? 'observed'
      : 'clear'

  const memoryHighEvents = maxPresent([
    maximumCgroupDelta(artifact, ['memory_events', 'high']),
    maximumCgroupDelta(artifact, ['memory_events_local', 'high']),
  ]) ?? endpointDelta(samples, 'memoryHighEvents')
  const oomEvents = maxPresent([
    maximumCgroupDelta(artifact, ['memory_events', 'oom']),
    maximumCgroupDelta(artifact, ['memory_events_local', 'oom']),
  ]) ?? endpointDelta(samples, 'oomEvents')
  const oomKillEvents = maxPresent([
    maximumCgroupDelta(artifact, ['memory_events', 'oom_kill']),
    maximumCgroupDelta(artifact, ['memory_events_local', 'oom_kill']),
  ]) ?? endpointDelta(samples, 'oomKillEvents')
  const peakMemoryPressureSomeAvg10 = maxPresent(samples.map(sample => sample.memoryPressureSomeAvg10))
  const peakMemoryLimitPercent = maxPresent(currentScopeRows.map(scope =>
    (scope.memoryPeakBytes ?? scope.memoryCurrentBytes) !== null && scope.memoryLimitBytes !== null && scope.memoryLimitBytes > 0
      ? ((scope.memoryPeakBytes ?? scope.memoryCurrentBytes)! / scope.memoryLimitBytes) * 100
      : null,
  ))
  const memorySignalAvailable = [
    memoryHighEvents,
    oomEvents,
    oomKillEvents,
    peakMemoryPressureSomeAvg10,
    peakMemoryLimitPercent,
  ].some(value => value !== null)
  const memoryPressureState: ResourceRunSignals['memoryPressureState'] = !memorySignalAvailable
    ? 'unavailable'
    : (oomKillEvents ?? 0) > 0
      ? 'critical'
      : (oomEvents ?? 0) > 0
        || (memoryHighEvents ?? 0) > 0
        || (peakMemoryLimitPercent ?? 0) >= 90
        || (peakMemoryPressureSomeAvg10 ?? 0) >= 10
        ? 'observed'
        : 'clear'

  const processObservedPeakSwapBytes = maxPresent([
    nonNegativeNumber(at(artifact, 'summary', 'peaks', 'process', 'swap_bytes')),
    ...samples.map(sample => sample.processSwapBytes),
    nonNegativeNumber(at(artifact, 'latest', 'process', 'swap_bytes')),
  ])
  const cgroupObservedPeakSwapBytes = maxPresent([
    ...Object.entries(asRecord(at(artifact, 'summary', 'peaks', 'cgroup_scopes')))
      .filter(([id]) => currentScopeIds.has(id))
      .map(([, peak]) => nonNegativeNumber(asRecord(peak).swap_current_bytes)),
    ...samples.map(sample => sample.cgroupSwapBytes),
    ...currentScopeRows.map(scope => scope.swapObservedPeakBytes),
  ])
  const swapEvents = maximumCgroupDeltaSum(artifact, [
    ['swap_events', 'high'],
    ['swap_events', 'max'],
    ['swap_events', 'fail'],
    ['memory_and_swap_fail_count'],
  ]) ?? endpointDelta(samples, 'swapEvents')
  const swapState: ResourceRunSignals['swapState'] = processObservedPeakSwapBytes === null && cgroupObservedPeakSwapBytes === null && swapEvents === null
    ? 'unavailable'
    : (processObservedPeakSwapBytes ?? 0) > 0 || (cgroupObservedPeakSwapBytes ?? 0) > 0 || (swapEvents ?? 0) > 0
      ? 'observed'
      : 'clear'

  return {
    memoryAccumulationState,
    baselineRssBytes: baselineRss,
    rssGrowthBytes,
    rssGrowthBytesPerHour,
    peakRssRetainedPercent,
    cpuPressureState,
    peakCpuBudgetPercent,
    throttleEvents,
    throttledSeconds,
    peakCpuPressureSomeAvg10,
    memoryPressureState,
    peakMemoryLimitPercent,
    memoryHighEvents,
    oomEvents,
    oomKillEvents,
    peakMemoryPressureSomeAvg10,
    swapState,
    processObservedPeakSwapBytes,
    cgroupObservedPeakSwapBytes,
    swapEvents,
  }
}

const METRIC_DEFINITIONS: ResourceMetricDefinition[] = [
  { metric: 'Peak RSS', definition: 'Highest resident-set size sampled while resource monitoring was active. This is physical memory resident for the process, not total host or pod memory.', source: 'summary.peaks.process.rss_bytes (fallback: sampled process RSS)' },
  { metric: 'Process lifetime HWM', definition: 'Kernel VmHWM for the process lifetime. It can include activity before resource monitoring started and is therefore shown separately from the monitored peak.', source: '/proc/self/status VmHWM via summary.peaks.process.peak_rss_bytes' },
  { metric: 'Final RSS', definition: 'Resident-set size in the latest persisted resource sample.', source: 'latest.process.rss_bytes' },
  { metric: 'Average CPU cores', definition: 'Process plus completed-child user and system CPU seconds divided by monitored wall-clock seconds. A value of 1.0 means one core continuously busy.', source: 'summary.deltas.process CPU counters / summary.duration_seconds' },
  { metric: 'Interval CPU', definition: 'Shows process plus completed-child counter rates and the producer-marked current cgroup rate separately. Completed-child usage can arrive at process exit, and cgroup accounting can include sibling tasks.', source: 'sampled process counters and current-role cgroup cumulative CPU counters' },
  { metric: 'CPU quota utilization', definition: 'Average CPU cores divided by the effective CPU budget selected by the producer. This is unavailable when no trustworthy CPU budget was recorded.', source: 'scheduler/system CPU budget and average CPU cores' },
  { metric: 'Physical I/O', definition: 'Bytes actually submitted to storage by Linux for this process. It excludes reads served from page cache and may include writes performed by the monitor itself.', source: '/proc/self/io read_bytes and write_bytes deltas' },
  { metric: 'Logical I/O', definition: 'Bytes returned by read-like syscalls or passed to write-like syscalls, including page-cache traffic.', source: '/proc/self/io rchar and wchar deltas' },
  { metric: 'RSS accumulation signal', definition: 'Flags a descriptive growth signal only when a run lasts at least ten minutes and final RSS exceeds baseline RSS by both 64 MiB and 20%. Growth does not prove a memory leak.', source: 'baseline/latest process RSS and monitored duration' },
  { metric: 'Swap signal', definition: 'Reports the highest sampled current process and cgroup swap while monitoring was active. On cgroup v1, current swap is derived from memory.memsw.usage_in_bytes minus memory.usage_in_bytes; memsw limits and peaks remain combined memory-plus-swap values and are never presented as swap-only limits or peaks.', source: '/proc/self/status VmSwap, cgroup v2 swap counters, and cgroup v1 memory/memsw counters' },
  { metric: 'cgroup pressure/events', definition: 'Kernel counters and PSI averages from the producer-marked current scope drive run signals. Ancestor rows remain visible for diagnosis but are not divided by the process CPU budget.', source: 'current-role cgroup cpu.stat, memory.events, pressure, and pids files' },
  { metric: 'cgroup memory peaks', definition: 'Observed peak is the highest sampled current usage while monitoring was active. Kernel memory.peak is shown separately because it can predate the run or include other tasks in an ancestor scope.', source: 'summary.peaks.cgroup_scopes.memory_current_bytes and cgroup memory.peak' },
  { metric: 'Sample health', definition: 'Retained-file coverage reports how much declared retained history the browser loaded. Cadence coverage separately reports producer-started periodic samples versus missed monotonic deadlines. Rotation, malformed, oversized, capped, and inferred-gap counts remain explicit.', source: 'monitor sampling_schedule, sample_history, summary, and bounded browser-loader diagnostics' },
  { metric: 'Producer scope', definition: 'The producer records which collection lifecycle interval the resource artifact covers. The dashboard uses that value conservatively and does not infer coverage for report generation, archive creation, upload, or extraction.', source: 'monitor.scope' },
  { metric: 'Request capture pool', definition: 'Shows local blocking capture workers, callers waiting for a worker, exact event-driven queue totals, and periodic pool snapshots. Capture workers sanitize, verify, and publish responses; they do not admit additional requests to a DUT.', source: 'components.request_capture in resource_usage.json and resource sample history' },
]

const PUBLIC_MONITOR_ERROR_CODES = new Set([
  'monitor_loop',
  'sample',
  'resource_sample_history_init',
  'resource_sample_history_rotation',
  'resource_sample_history_write',
  'resource_usage_write',
  'request_capture_component',
  'proc_self_cgroup',
  'proc_self_status',
])

function monitorErrors(artifact: JsonRecord): ResourceUsageAnalysis['monitorErrors'] {
  return asArray(artifact.errors).slice(0, 100).map(error => {
    const record = asRecord(error)
    const rawTimestamp = textValue(record.timestamp)
    const parsedTimestamp = parseTimestamp(rawTimestamp)
    const rawSource = textValue(record.source)
    return {
      timestamp: parsedTimestamp === null ? null : new Date(parsedTimestamp).toISOString(),
      code: PUBLIC_MONITOR_ERROR_CODES.has(rawSource) ? rawSource : 'resource_monitor',
    }
  })
}

export function analyzeResourceUsage(options: AnalyzeResourceUsageOptions): ResourceUsageAnalysis {
  const artifact = asRecord(options.artifact)
  const startedAt = typeof artifact.started_at === 'string' ? boundedText(artifact.started_at, '', 128) : null
  const completedAt = typeof artifact.completed_at === 'string' ? boundedText(artifact.completed_at, '', 128) : null
  const rawExpectedInterval = finiteNumber(at(artifact, 'monitor', 'sample_interval_seconds'))
  const expectedInterval = rawExpectedInterval !== null && rawExpectedInterval > 0 ? rawExpectedInterval : null
  const availableCpus = resolveAvailableCpus(artifact)
  const annotated = annotateTimeline(options.samples, availableCpus.value, expectedInterval, startedAt)
  const actualSamples = annotated.samples.filter(sample => !sample.syntheticGap)
  const duration = durationSeconds(artifact, actualSamples)
  const averageCpu = averageCpuCores(artifact, actualSamples, duration)
  const peakFromSummary = nonNegativeNumber(at(artifact, 'summary', 'peaks', 'process', 'rss_bytes'))
  const samplePeak = maxPresent(actualSamples.map(sample => sample.rssBytes))
  const latestRss = nonNegativeNumber(at(artifact, 'latest', 'process', 'rss_bytes'))
    ?? [...actualSamples].reverse().find(sample => sample.rssBytes !== null)?.rssBytes
    ?? null
  const processLifetimeHighWater = maxPresent([
    nonNegativeNumber(at(artifact, 'summary', 'peaks', 'process', 'peak_rss_bytes')),
    nonNegativeNumber(at(artifact, 'latest', 'process', 'peak_rss_bytes')),
    maxPresent(actualSamples.map(sample => sample.processPeakRssBytes)),
  ])
  const physicalRead = deltaFromSummary(artifact, ['process', 'io', 'read_bytes'])
    ?? endpointDelta(actualSamples, 'physicalReadBytes')
  const physicalWrite = deltaFromSummary(artifact, ['process', 'io', 'write_bytes'])
    ?? endpointDelta(actualSamples, 'physicalWriteBytes')
  const logicalRead = deltaFromSummary(artifact, ['process', 'io', 'rchar'])
    ?? endpointDelta(actualSamples, 'logicalReadBytes')
  const logicalWrite = deltaFromSummary(artifact, ['process', 'io', 'wchar'])
    ?? endpointDelta(actualSamples, 'logicalWriteBytes')
  const scopes = scopeDiagnostics(artifact)
  const health = buildHealth(
    artifact,
    options.diagnostics,
    actualSamples.length,
    annotated.gaps,
    annotated.estimatedMissing,
    annotated.counterResets,
    scopes.ignored,
  )
  const producerScope = boundedText(at(artifact, 'monitor', 'scope'), 'unknown', 256)
  const peakRss = maxPresent([peakFromSummary, samplePeak, latestRss])
  const signals = buildRunSignals(artifact, actualSamples, scopes.rows, duration, latestRss, peakRss)

  return {
    schemaVersion: finiteNumber(artifact.schema_version) ?? (boundedText(artifact.schema_version, '', 64) || null),
    status: boundedText(artifact.status, 'unknown', 64),
    startedAt,
    completedAt,
    producerScope,
    kpis: {
      peakRssBytes: peakRss,
      processLifetimeHighWaterBytes: processLifetimeHighWater,
      finalRssBytes: latestRss,
      averageCpuCores: averageCpu,
      availableCpus: availableCpus.value,
      cpuQuotaPercent: averageCpu !== null && availableCpus.value !== null ? (averageCpu / availableCpus.value) * 100 : null,
      physicalReadBytes: physicalRead,
      physicalWriteBytes: physicalWrite,
      logicalReadBytes: logicalRead,
      logicalWriteBytes: logicalWrite,
      durationSeconds: duration,
    },
    signals,
    health,
    samples: downsampleResourceTimeline(annotated.samples, options.maxTimelinePoints ?? DEFAULT_TIMELINE_POINTS),
    scopes: scopes.rows,
    scheduler: schedulerDiagnostics(artifact, availableCpus),
    requestCapture: requestCaptureAnalysis(artifact),
    metricDefinitions: METRIC_DEFINITIONS,
    monitorErrors: monitorErrors(artifact),
  }
}

export function emptyResourceDiagnostics(): ResourceLoadDiagnostics {
  return {
    filesAttempted: [],
    filesLoaded: [],
    missingFiles: [],
    historySamplesLoaded: null,
    malformedLines: 0,
    oversizedLines: 0,
    bytesRead: 0,
    byteLimitReached: false,
    sampleLimitReached: false,
    mainArtifactTruncated: false,
    historySegmentsIgnored: 0,
  }
}
