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
  ConcurrencyCountMetric,
  ConcurrencyDecisionAction,
  ConcurrencyDecisionPoint,
  ConcurrencyDecisionProgress,
  ConcurrencyMode,
  ConcurrencyPressureSignals,
  ConcurrencySchedulerAnalysis,
  ConcurrencySchedulerStatus,
  ConcurrencyServiceMetric,
} from '@/types/concurrencyScheduler'

type JsonRecord = Record<string, unknown>

const MAX_DECISIONS = 10_000
const MAX_RENDERED_DECISIONS = 500
const MAX_LABELS = 128
const MAX_SAFE_COUNT = 1_000_000_000
const SAFE_LABEL = /^[a-z0-9][a-z0-9_.:-]{0,63}$/
const GOVERNED_SERVICE = /^(?:redfish|ssh|host|ipmi|hmc|unknown)$/
const GOVERNED_REMOTE_EVENT = /^(?:redfish_resource_in_use|http_429|http_503|ssh_channel_failure|ssh_reset|ipmi_timeout|transport_reset)$/
const GOVERNED_REASON = /^(?:mode_(?:conservative|fixed|adaptive)|periodic_observation|healthy_window_[0-9]+|consecutive_healthy_windows|cooldown|no_queued_demand|insufficient_healthy_signals|completed|interrupted|event_loop_lag|cgroup_oom_event|memory_headroom|file_descriptor_pressure|pid_pressure|cgroup_throttling|cpu_utilization|remote_throttling|sampler_error_[a-z0-9_]+)$/

function asRecord(value: unknown): JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as JsonRecord
    : {}
}

function finiteNumber(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= minimum && value <= maximum
    ? value
    : null
}

function count(value: unknown): number {
  const parsed = finiteNumber(value, 0, MAX_SAFE_COUNT)
  return parsed === null ? 0 : Math.floor(parsed)
}

function optionalCount(value: unknown): number | null {
  const parsed = finiteNumber(value, 0, MAX_SAFE_COUNT)
  return parsed === null ? null : Math.floor(parsed)
}

function positiveLimit(value: unknown, fallback: number): number {
  const parsed = finiteNumber(value, 1, 4096)
  return parsed === null ? fallback : Math.floor(parsed)
}

function timestamp(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 64 || !Number.isFinite(Date.parse(value))) return null
  return value
}

function label(value: unknown, fallback = 'unknown'): string {
  if (typeof value !== 'string') return fallback
  const normalized = value.trim().toLowerCase()
  return SAFE_LABEL.test(normalized) ? normalized : fallback
}

function ratio(value: unknown): number | null {
  return finiteNumber(value, 0, 100)
}

function mode(value: unknown): ConcurrencyMode {
  const normalized = label(value)
  return normalized === 'conservative' || normalized === 'fixed' || normalized === 'adaptive'
    ? normalized
    : 'unknown'
}

function status(value: unknown): ConcurrencySchedulerStatus {
  const normalized = label(value)
  return ['not_started', 'running', 'completed', 'interrupted'].includes(normalized)
    ? normalized as ConcurrencySchedulerStatus
    : 'unknown'
}

function action(value: unknown): ConcurrencyDecisionAction {
  const normalized = label(value)
  return ['start', 'hold', 'increase', 'decrease', 'stop'].includes(normalized)
    ? normalized as ConcurrencyDecisionAction
    : 'unknown'
}

function reasonLabels(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.slice(0, 32)
    .map(item => label(item))
    .filter(item => GOVERNED_REASON.test(item))
}

function countMap(
  value: unknown,
  allowLabel: (value: string) => boolean = () => true,
): Record<string, number> {
  return Object.fromEntries(
    Object.entries(asRecord(value))
      .slice(0, MAX_LABELS)
      .flatMap(([rawLabel, rawCount]) => {
        const safeLabel = label(rawLabel)
        return safeLabel === 'unknown' || !allowLabel(safeLabel)
          ? []
          : [[safeLabel, count(rawCount)]]
      }),
  )
}

function remoteEventLabel(value: string): boolean {
  const parts = value.split(':')
  if (parts.length === 1) return GOVERNED_REMOTE_EVENT.test(parts[0])
  return parts.length === 2 && GOVERNED_SERVICE.test(parts[0]) && GOVERNED_REMOTE_EVENT.test(parts[1])
}

function pressureSignals(value: unknown): ConcurrencyPressureSignals | null {
  if (value === null || value === undefined) return null
  const raw = asRecord(value)
  if (Object.keys(raw).length === 0) return null
  return {
    eventLoopLagSeconds: finiteNumber(raw.event_loop_lag_seconds, 0, 3600),
    cpuUtilization: ratio(raw.cpu_utilization),
    cgroupThrottlingRatio: ratio(raw.cgroup_throttling_ratio),
    memoryHeadroomRatio: ratio(raw.memory_headroom_ratio),
    fileDescriptorUtilization: ratio(raw.file_descriptor_utilization),
    pidUtilization: ratio(raw.pid_utilization),
    cgroupOomEvents: count(raw.cgroup_oom_events),
    completedOperations: finiteNumber(raw.completed_operations, 0, MAX_SAFE_COUNT),
    remoteEvents: countMap(raw.remote_events, remoteEventLabel),
    transportLatencyP95Seconds: finiteNumber(raw.transport_latency_p95_seconds, 0, 86_400),
  }
}

function decisionProgress(value: unknown): ConcurrencyDecisionProgress | null {
  const raw = asRecord(value)
  if (Object.keys(raw).length === 0) return null
  const limiter = asRecord(raw.limiter)
  const admissions = finiteNumber(raw.admissions, 0, MAX_SAFE_COUNT)
  const completedOperations = finiteNumber(raw.completed_operations, 0, MAX_SAFE_COUNT)
  const activeOperations = finiteNumber(limiter.active_operations, 0, MAX_SAFE_COUNT)
  const activeWeight = finiteNumber(limiter.active_weight, 0, MAX_SAFE_COUNT)
  const queuedOperations = finiteNumber(limiter.queued_operations, 0, MAX_SAFE_COUNT)
  if (
    admissions === null
    || completedOperations === null
    || activeOperations === null
    || activeWeight === null
    || queuedOperations === null
  ) return null
  return {
    admissions: Math.floor(admissions),
    completedOperations: Math.floor(completedOperations),
    activeOperations: Math.floor(activeOperations),
    activeWeight: Math.floor(activeWeight),
    queuedOperations: Math.floor(queuedOperations),
  }
}

function downsample<T>(values: T[], maximum: number): T[] {
  if (values.length <= maximum) return values
  const selected: T[] = []
  const last = values.length - 1
  for (let index = 0; index < maximum; index++) {
    selected.push(values[Math.round(index * last / (maximum - 1))])
  }
  return selected
}

function decisions(value: unknown, terminalCompleted: number): ConcurrencyDecisionPoint[] {
  const rawDecisions = Array.isArray(value) ? value.slice(0, MAX_DECISIONS) : []
  let cumulative = 0
  const normalized = rawDecisions.flatMap((item): ConcurrencyDecisionPoint[] => {
    const raw = asRecord(item)
    const elapsed = finiteNumber(raw.elapsed_seconds, 0, 10 * 365 * 24 * 3600)
    const previousLimit = finiteNumber(raw.previous_limit, 1, 4096)
    const newLimit = finiteNumber(raw.new_limit, 1, 4096)
    if (elapsed === null || previousLimit === null || newLimit === null) return []
    const signals = pressureSignals(raw.signals)
    const progress = decisionProgress(raw.progress)
    cumulative = progress?.completedOperations
      ?? cumulative + Math.floor(signals?.completedOperations ?? 0)
    return [{
      timestamp: timestamp(raw.timestamp),
      elapsedSeconds: elapsed,
      action: action(raw.action),
      previousLimit: Math.floor(previousLimit),
      newLimit: Math.floor(newLimit),
      reasons: reasonLabels(raw.reasons),
      signals,
      progress,
      cumulativeCompletedOperations: cumulative,
    }]
  })
  const last = normalized[normalized.length - 1]
  if (last?.action === 'stop' && terminalCompleted > last.cumulativeCompletedOperations) {
    last.cumulativeCompletedOperations = terminalCompleted
  }
  return downsample(normalized, MAX_RENDERED_DECISIONS)
}

function countMetrics(value: unknown): ConcurrencyCountMetric[] {
  return Object.entries(countMap(value, remoteEventLabel)).map(([safeLabel, safeCount]) => ({
    label: safeLabel,
    count: safeCount,
  }))
}

function serviceMetrics(operationMetrics: JsonRecord): ConcurrencyServiceMetric[] {
  const active = asRecord(operationMetrics.active_time_by_service)
  const peak = countMap(
    operationMetrics.peak_active_operations_by_service,
    value => GOVERNED_SERVICE.test(value),
  )
  return Object.entries(active).slice(0, MAX_LABELS).flatMap(([rawService, rawMetrics]) => {
    const service = label(rawService)
    if (!GOVERNED_SERVICE.test(service)) return []
    const metrics = asRecord(rawMetrics)
    return [{
      service,
      completedOperations: count(metrics.completed_operations),
      activeSecondsTotal: finiteNumber(metrics.active_seconds_total, 0, 1e12) ?? 0,
      activeSecondsAverage: finiteNumber(metrics.active_seconds_average, 0, 1e9) ?? 0,
      peakActiveOperations: peak[service] ?? 0,
    }]
  })
}

export function analyzeConcurrencyScheduler(value: unknown): ConcurrencySchedulerAnalysis {
  const root = asRecord(value)
  const settings = asRecord(root.settings)
  const plan = asRecord(root.plan_summary)
  const limits = asRecord(plan.limits)
  const operationMetrics = asRecord(root.operation_metrics)
  const limiter = asRecord(operationMetrics.limiter)
  const decisionAccounting = asRecord(root.decision_accounting)

  const initialLimit = positiveLimit(settings.initial_limit, 1)
  const minimumLimit = positiveLimit(settings.minimum_limit, 1)
  const maximumLimit = positiveLimit(settings.maximum_limit, initialLimit)
  const finalLimit = positiveLimit(root.final_limit, initialLimit)
  const plannedOperations = count(plan.runnable_collector_operations)
  const completedOperations = count(operationMetrics.completed_operations)
  const decisionPoints = decisions(root.decisions, completedOperations)
  const decisionTotal = count(decisionAccounting.total)
  const decisionRetained = count(decisionAccounting.retained)
  const decisionDropped = count(decisionAccounting.dropped)
  const warnings: string[] = []
  if (decisionDropped > 0) warnings.push(`${decisionDropped.toLocaleString()} older scheduler decisions were dropped by the producer's evidence bound.`)
  if (Array.isArray(root.decisions) && root.decisions.length > MAX_RENDERED_DECISIONS) warnings.push(`The browser downsampled scheduler decisions to ${MAX_RENDERED_DECISIONS.toLocaleString()} points.`)
  const schedulerStatus = status(root.status)
  if (schedulerStatus === 'running') warnings.push('This artifact is an in-progress atomic snapshot; reload the report to see newer decisions.')
  if (schedulerStatus === 'interrupted') warnings.push('Collection ended while the scheduler was interrupted; terminal progress may be incomplete.')

  return {
    schemaVersion: typeof root.schema_version === 'string' || typeof root.schema_version === 'number' ? root.schema_version : null,
    status: schedulerStatus,
    mode: mode(settings.mode),
    startedAt: timestamp(root.started_at),
    completedAt: timestamp(root.completed_at),
    initialLimit,
    minimumLimit,
    maximumLimit,
    finalLimit,
    sampleIntervalSeconds: finiteNumber(settings.sample_interval_seconds, 0.001, 3600),
    healthyWindowsRequired: finiteNumber(settings.healthy_windows_required, 1, 1000),
    increaseStep: finiteNumber(settings.increase_step, 1, 4096),
    decreaseRatio: ratio(settings.decrease_ratio),
    hardDecreaseRatio: ratio(settings.hard_decrease_ratio),
    cooldownSeconds: finiteNumber(settings.cooldown_seconds, 0, 86_400),
    endpointCooldownSeconds: finiteNumber(settings.endpoint_cooldown_seconds, 0, 86_400),
    plannedOperations,
    skippedOperations: count(plan.skipped_collector_operations),
    weightedDemand: count(plan.weighted_demand),
    dutCount: count(plan.dut_count),
    serviceLaneCount: count(plan.runnable_service_lanes),
    perDutRedfishLimit: finiteNumber(limits.redfish_per_dut, 1, 4096),
    admissions: count(operationMetrics.admissions),
    completedOperations,
    completionPercent: plannedOperations > 0 ? Math.min(100, completedOperations / plannedOperations * 100) : null,
    queueWaitSecondsTotal: finiteNumber(operationMetrics.queue_wait_seconds_total, 0, 1e12) ?? 0,
    queueWaitSecondsAverage: finiteNumber(operationMetrics.queue_wait_seconds_average, 0, 1e9) ?? 0,
    queueWaitSecondsMax: finiteNumber(operationMetrics.queue_wait_seconds_max, 0, 1e9) ?? 0,
    activeSecondsTotal: finiteNumber(operationMetrics.active_seconds_total, 0, 1e12) ?? 0,
    activeSecondsAverage: finiteNumber(operationMetrics.active_seconds_average, 0, 1e9) ?? 0,
    activeSecondsMax: finiteNumber(operationMetrics.active_seconds_max, 0, 1e9) ?? 0,
    peakActiveOperations: count(limiter.peak_active_operations),
    peakActiveWeight: count(limiter.peak_active_weight),
    currentQueuedOperations: count(limiter.queued_operations),
    peakQueuedOperations: optionalCount(limiter.peak_queued_operations),
    backfilledOperations: optionalCount(limiter.backfilled_operations),
    queuedWallSeconds: finiteNumber(limiter.queued_wall_seconds, 0, 1e12),
    saturatedWhileQueuedSeconds: finiteNumber(limiter.saturated_while_queued_seconds, 0, 1e12),
    runnableGapWeightSeconds: finiteNumber(limiter.runnable_gap_weight_seconds, 0, 1e12),
    fragmentationWeightSeconds: finiteNumber(limiter.fragmentation_weight_seconds, 0, 1e12),
    utilizationWhileQueuedRatio: finiteNumber(limiter.utilization_while_queued_ratio, 0, 1),
    saturationWhileQueuedRatio: finiteNumber(limiter.saturation_while_queued_ratio, 0, 1),
    decisionTotal,
    decisionRetained,
    decisionDropped,
    decisions: decisionPoints,
    serviceMetrics: serviceMetrics(operationMetrics),
    remotePressureEvents: countMetrics(root.remote_pressure_events),
    endpointCooldowns: countMetrics(root.endpoint_cooldowns),
    warnings,
  }
}
