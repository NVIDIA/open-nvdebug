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
import { analyzeConcurrencyScheduler } from '@/utils/concurrencyScheduler'

function schedulerArtifact() {
  return {
    schema_version: '1.2',
    status: 'completed',
    started_at: '2026-08-14T00:00:00Z',
    completed_at: '2026-08-14T00:02:00Z',
    settings: {
      mode: 'adaptive',
      initial_limit: 5,
      minimum_limit: 4,
      maximum_limit: 64,
      sample_interval_seconds: 20,
      healthy_windows_required: 3,
      increase_step: 8,
      decrease_ratio: 0.75,
      hard_decrease_ratio: 0.5,
      cooldown_seconds: 60,
      endpoint_cooldown_seconds: 30,
    },
    plan_summary: {
      runnable_collector_operations: 324,
      skipped_collector_operations: 36,
      weighted_demand: 324,
      dut_count: 45,
      runnable_service_lanes: 45,
      limits: { redfish_per_dut: 1 },
    },
    decisions: [
      {
        timestamp: '2026-08-14T00:00:00Z',
        elapsed_seconds: 0,
        action: 'start',
        previous_limit: 5,
        new_limit: 5,
        reasons: ['mode_adaptive'],
        signals: null,
        progress: {
          admissions: 0,
          completed_operations: 0,
          limiter: { active_operations: 0, active_weight: 0, queued_operations: 0 },
        },
      },
      {
        timestamp: '2026-08-14T00:01:00Z',
        elapsed_seconds: 60,
        action: 'increase',
        previous_limit: 5,
        new_limit: 6,
        reasons: ['consecutive_healthy_windows'],
        signals: {
          event_loop_lag_seconds: 0.001,
          cpu_utilization: 0.1,
          cgroup_throttling_ratio: 0,
          memory_headroom_ratio: 0.8,
          file_descriptor_utilization: 0.02,
          pid_utilization: 0.03,
          cgroup_oom_events: 0,
          completed_operations: 100,
          remote_events: {},
          transport_latency_p95_seconds: 2.5,
        },
        progress: {
          admissions: 160,
          completed_operations: 155,
          limiter: { active_operations: 5, active_weight: 5, queued_operations: 20 },
        },
      },
    ],
    decision_accounting: { total: 2, retained: 2, dropped: 0 },
    operation_metrics: {
      admissions: 324,
      completed_operations: 324,
      queue_wait_seconds_total: 120,
      queue_wait_seconds_average: 0.37,
      queue_wait_seconds_max: 5,
      active_seconds_total: 600,
      active_seconds_average: 1.85,
      active_seconds_max: 30,
      active_time_by_service: {
        redfish: { completed_operations: 324, active_seconds_total: 600, active_seconds_average: 1.85 },
      },
      peak_active_operations_by_service: { redfish: 6 },
      limiter: {
        queued_operations: 0,
        peak_active_operations: 6,
        peak_active_weight: 6,
        peak_queued_operations: 20,
        backfilled_operations: 3,
        queued_wall_seconds: 100,
        saturated_while_queued_seconds: 96,
        runnable_gap_weight_seconds: 0.02,
        fragmentation_weight_seconds: 4,
        utilization_while_queued_ratio: 0.9958,
        saturation_while_queued_ratio: 0.96,
      },
    },
    remote_pressure_events: {},
    endpoint_cooldowns: {},
    final_limit: 6,
  }
}

describe('concurrency scheduler analysis', () => {
  it('normalizes bounded policy, progress, signals, and service metrics', () => {
    const analysis = analyzeConcurrencyScheduler(schedulerArtifact())

    expect(analysis).toMatchObject({
      schemaVersion: '1.2',
      status: 'completed',
      mode: 'adaptive',
      initialLimit: 5,
      finalLimit: 6,
      plannedOperations: 324,
      completedOperations: 324,
      completionPercent: 100,
      dutCount: 45,
      serviceLaneCount: 45,
      peakActiveOperations: 6,
      peakQueuedOperations: 20,
      backfilledOperations: 3,
      utilizationWhileQueuedRatio: 0.9958,
      saturationWhileQueuedRatio: 0.96,
      runnableGapWeightSeconds: 0.02,
      fragmentationWeightSeconds: 4,
    })
    expect(analysis.decisions[1]).toMatchObject({
      action: 'increase',
      cumulativeCompletedOperations: 155,
      progress: {
        admissions: 160,
        completedOperations: 155,
        activeOperations: 5,
        activeWeight: 5,
        queuedOperations: 20,
      },
      signals: { cpuUtilization: 0.1, completedOperations: 100 },
    })
    expect(analysis.serviceMetrics).toEqual([{
      service: 'redfish',
      completedOperations: 324,
      activeSecondsTotal: 600,
      activeSecondsAverage: 1.85,
      peakActiveOperations: 6,
    }])
  })

  it('filters arbitrary labels and never carries endpoint-like map keys', () => {
    const artifact = schedulerArtifact()
    artifact.decisions[1].reasons = ['../../private endpoint', 'healthy_window_1']
    artifact.remote_pressure_events = {
      'redfish:http_429': 2,
      '10.23.45.67': 100,
    }

    const analysis = analyzeConcurrencyScheduler(artifact)

    expect(analysis.decisions[1].reasons).toEqual(['healthy_window_1'])
    expect(analysis.remotePressureEvents).toEqual([{ label: 'redfish:http_429', count: 2 }])
    expect(JSON.stringify(analysis)).not.toContain('10.23.45.67')
    expect(JSON.stringify(analysis)).not.toContain('private endpoint')
  })

  it('bounds browser-rendered decisions and reports the downsampling', () => {
    const artifact = schedulerArtifact()
    artifact.decisions = Array.from({ length: 600 }, (_, index) => ({
      elapsed_seconds: index,
      action: 'hold',
      previous_limit: 5,
      new_limit: 5,
      reasons: ['healthy_window_1'],
      signals: { completed_operations: 1, remote_events: {} },
      progress: {
        admissions: index + 1,
        completed_operations: index + 1,
        limiter: { active_operations: 5, active_weight: 5, queued_operations: 10 },
      },
    }))
    artifact.decision_accounting = { total: 600, retained: 600, dropped: 0 }

    const analysis = analyzeConcurrencyScheduler(artifact)

    expect(analysis.decisions).toHaveLength(500)
    expect(analysis.decisions[0].elapsedSeconds).toBe(0)
    expect(analysis.decisions[analysis.decisions.length - 1]?.elapsedSeconds).toBe(599)
    expect(analysis.warnings.join(' ')).toContain('downsampled')
  })

  it('reconstructs cumulative progress from schema 1.0 decision windows', () => {
    const artifact = schedulerArtifact()
    artifact.schema_version = '1.0'
    artifact.decisions = [
      {
        elapsed_seconds: 20,
        action: 'hold',
        previous_limit: 5,
        new_limit: 5,
        reasons: ['healthy_window_1'],
        signals: { completed_operations: 12, remote_events: {} },
      },
      {
        elapsed_seconds: 40,
        action: 'stop',
        previous_limit: 5,
        new_limit: 5,
        reasons: ['completed'],
        signals: { completed_operations: 8, remote_events: {} },
      },
    ]
    artifact.decision_accounting = { total: 2, retained: 2, dropped: 0 }

    const analysis = analyzeConcurrencyScheduler(artifact)

    expect(analysis.decisions[0].cumulativeCompletedOperations).toBe(12)
    expect(analysis.decisions[1].cumulativeCompletedOperations).toBe(324)
    expect(analysis.decisions.every(decision => decision.progress === null)).toBe(true)
  })
})
