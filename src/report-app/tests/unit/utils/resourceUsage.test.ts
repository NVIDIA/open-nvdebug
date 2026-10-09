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
import resourceArtifact from '../../fixtures/resource_usage.json'
import previousSamples from '../../fixtures/resource_usage_samples.previous.jsonl?raw'
import currentSamples from '../../fixtures/resource_usage_samples.jsonl?raw'
import type { ResourceLoadDiagnostics, ResourceSamplePoint } from '@/types/resourceUsage'
import {
  analyzeResourceUsage,
  downsampleResourceTimeline,
  emptyResourceDiagnostics,
  normalizeResourceSample,
} from '@/utils/resourceUsage'

function fixtureSamples(): ResourceSamplePoint[] {
  return `${previousSamples}\n${currentSamples}`
    .trim()
    .split('\n')
    .filter(line => line.trim())
    .map(line => normalizeResourceSample(JSON.parse(line)))
    .filter((sample): sample is ResourceSamplePoint => sample !== null)
}

function requestCaptureSnapshot() {
  return {
    schema_version: '1.0',
    status: 'closed',
    worker_count: 16,
    observation_seconds: 50,
    calls: {
      enqueued: 3000,
      worker_completions: 2999,
      worker_failures: 1,
      abandoned_before_submission: 0,
    },
    pool: {
      active_workers: 7,
      queued_calls: 3,
      peak_active_workers: 16,
      peak_queued_calls: 45,
    },
    queue: {
      wait_seconds_total: 600,
      wait_seconds_average: 0.2,
      wait_seconds_max: 1.9,
      queued_wall_seconds: 40,
      queued_capacity_worker_seconds: 640,
      queued_active_worker_seconds: 320,
      saturated_while_queued_seconds: 4,
      runnable_gap_worker_seconds: 320,
      utilization_while_queued_ratio: 0.5,
      saturation_while_queued_ratio: 0.1,
    },
    workers: {
      seconds_total: 350,
      utilization_ratio: 0.4375,
    },
  }
}

describe('resource telemetry analysis', () => {
  it('derives KPI, quota, I/O, cgroup, and sample-health values from schema v1 fixtures', () => {
    const analysis = analyzeResourceUsage({
      artifact: resourceArtifact,
      samples: fixtureSamples(),
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(analysis.kpis).toMatchObject({
      peakRssBytes: 188743680,
      processLifetimeHighWaterBytes: 188743680,
      finalRssBytes: 157286400,
      averageCpuCores: 1,
      availableCpus: 2,
      cpuQuotaPercent: 50,
      physicalReadBytes: 1048576,
      physicalWriteBytes: 2097152,
      logicalReadBytes: 4194304,
      logicalWriteBytes: 8388608,
    })
    expect(analysis.health).toMatchObject({
      state: 'healthy',
      samplesLoaded: 4,
      retainedFileCoveragePercent: 100,
      cadenceCoveragePercent: 100,
      malformedLines: 0,
      gapCount: 0,
    })
    expect(analysis.scopes[0]).toMatchObject({
      controller: 'unified',
      role: 'current',
      memoryLimitState: 'limited',
      swapLimitState: 'unavailable',
      throttleEvents: 2,
      oomEvents: 0,
      oomKillEvents: 0,
      pidsCurrent: 10,
    })
    expect(analysis.samples[1].cpuCores).toBeCloseTo(0.9)
    expect(analysis.samples[1].physicalReadBytesPerSecond).toBeCloseTo(13107.2)
    expect(analysis.signals).toMatchObject({
      memoryAccumulationState: 'unavailable',
      cpuPressureState: 'observed',
      memoryPressureState: 'observed',
      swapState: 'unavailable',
    })
    expect(analysis.requestCapture).toBeNull()
  })

  it('normalizes aggregate and sampled request-capture scaling evidence', () => {
    const capture = requestCaptureSnapshot()
    const sample = normalizeResourceSample({
      elapsed_seconds: 10,
      components: { request_capture: capture },
    })!
    const analysis = analyzeResourceUsage({
      artifact: { components: { request_capture: capture } },
      samples: [sample],
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(sample).toMatchObject({
      captureWorkerCount: 16,
      captureActiveWorkers: 7,
      captureQueuedCalls: 3,
      captureWorkerCompletions: 2999,
      captureWorkerFailures: 1,
      captureQueueWaitSecondsTotal: 600,
      captureUtilizationWhileQueuedPercent: 50,
      captureSaturationWhileQueuedPercent: 10,
    })
    expect(analysis.requestCapture).toMatchObject({
      schemaVersion: 1,
      status: 'closed',
      workerCount: 16,
      callsEnqueued: 3000,
      callsCompleted: 2999,
      workerFailures: 1,
      peakActiveWorkers: 16,
      peakQueuedCalls: 45,
      queueWaitSecondsTotal: 600,
      utilizationWhileQueuedRatio: 0.5,
      workerUtilizationRatio: 0.4375,
    })
  })

  it('keeps explicitly recorded zero separate from unavailable fields', () => {
    const sampleA = normalizeResourceSample({
      elapsed_seconds: 0,
      process: { user_cpu_seconds: 0, system_cpu_seconds: 0, io: { read_bytes: 0, write_bytes: 0 } },
    })!
    const sampleB = normalizeResourceSample({
      elapsed_seconds: 10,
      process: { user_cpu_seconds: 0, system_cpu_seconds: 0, io: { read_bytes: 0, write_bytes: 0 } },
    })!
    const analysis = analyzeResourceUsage({
      artifact: { summary: { duration_seconds: 10, deltas: { process: { user_cpu_seconds: 0, system_cpu_seconds: 0, io: { read_bytes: 0, write_bytes: 0 } } } } },
      samples: [sampleA, sampleB],
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(analysis.kpis.averageCpuCores).toBe(0)
    expect(analysis.kpis.physicalReadBytes).toBe(0)
    expect(analysis.kpis.physicalWriteBytes).toBe(0)
    expect(analysis.kpis.availableCpus).toBeNull()
    expect(analysis.kpis.cpuQuotaPercent).toBeNull()
    expect(analysis.kpis.finalRssBytes).toBeNull()
  })

  it('keeps sampled RSS separate from the process-lifetime high-water mark', () => {
    const samples = [
      normalizeResourceSample({ elapsed_seconds: 0, process: { rss_bytes: 100, peak_rss_bytes: 700 } })!,
      normalizeResourceSample({ elapsed_seconds: 10, process: { rss_bytes: 180, peak_rss_bytes: 900 } })!,
    ]
    const analysis = analyzeResourceUsage({
      artifact: {
        schema_version: 1,
        status: 'completed',
        latest: { process: { rss_bytes: 170, peak_rss_bytes: 850 } },
        summary: {
          duration_seconds: 10,
          artifact_write_succeeded: true,
          peaks: { process: { rss_bytes: 150, peak_rss_bytes: 800 } },
        },
      },
      samples,
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(analysis.kpis.peakRssBytes).toBe(180)
    expect(analysis.kpis.processLifetimeHighWaterBytes).toBe(900)
  })

  it('degrades gracefully for malformed fields, sampling gaps, and counter resets', () => {
    const first = normalizeResourceSample({
      timestamp: '2026-08-04T00:00:00Z', elapsed_seconds: 0,
      process: { rss_bytes: 'bad', user_cpu_seconds: 10, io: { read_bytes: 20, write_bytes: 20, rchar: 20, wchar: 20 } },
    })!
    const last = normalizeResourceSample({
      timestamp: '2026-08-04T00:00:40Z', elapsed_seconds: 40,
      process: { user_cpu_seconds: 1, io: { read_bytes: 1, write_bytes: 1, rchar: 1, wchar: 1 } },
    })!
    const diagnostics: ResourceLoadDiagnostics = {
      ...emptyResourceDiagnostics(),
      malformedLines: 2,
    }
    const analysis = analyzeResourceUsage({
      artifact: { monitor: { sample_interval_seconds: 10 } },
      samples: [first, last],
      diagnostics,
    })

    expect(analysis.health.state).toBe('degraded')
    expect(analysis.health.gapCount).toBe(1)
    expect(analysis.health.estimatedMissingSamples).toBe(3)
    expect(analysis.health.counterResets).toBe(5)
    expect(analysis.samples.some(sample => sample.syntheticGap)).toBe(true)
    expect(analysis.kpis.peakRssBytes).toBeNull()
  })

  it('bounds rendered points while preserving endpoints and a gap marker', () => {
    const points = Array.from({ length: 100 }, (_, index) => ({
      ...normalizeResourceSample({ elapsed_seconds: index, process: { rss_bytes: index } })!,
      syntheticGap: index === 50,
    }))
    const reduced = downsampleResourceTimeline(points, 10)

    expect(reduced).toHaveLength(10)
    expect(reduced[0].elapsedSeconds).toBe(0)
    expect(reduced.at(-1)?.elapsedSeconds).toBe(99)
    expect(reduced.some(point => point.syntheticGap)).toBe(true)
  })

  it('preserves a rare resource peak when downsampling a long timeline', () => {
    const points = Array.from({ length: 1_000 }, (_, index) =>
      normalizeResourceSample({
        elapsed_seconds: index,
        process: { rss_bytes: index === 437 ? 10_000_000 : index },
      })!,
    )

    const reduced = downsampleResourceTimeline(points, 20)

    expect(reduced.some(point => point.rssBytes === 10_000_000)).toBe(true)
  })

  it('retains PSI, PID, thread, and descriptor peaks during downsampling', () => {
    const points = Array.from({ length: 1_000 }, (_, index) => normalizeResourceSample({
      elapsed_seconds: index,
      process: {
        threads: index === 111 ? 10_001 : 1,
        open_fds: index === 222 ? 10_002 : 2,
      },
      cgroup: { scopes: [{
        controller: 'unified', path: '/run', role: 'current',
        cpu: { pressure: {
          some: { avg10: index === 333 ? 91 : 0 },
          full: { avg10: index === 444 ? 92 : 0 },
        } },
        memory: { pressure: {
          some: { avg10: index === 555 ? 93 : 0 },
          full: { avg10: index === 666 ? 94 : 0 },
        } },
        pids: {
          current: index === 777 ? 10_003 : 3,
          limit: { value: index === 888 ? 10_004 : 4 },
        },
      }] },
    })!)

    const reduced = downsampleResourceTimeline(points, 30)

    expect(reduced.some(point => point.threads === 10_001)).toBe(true)
    expect(reduced.some(point => point.openFds === 10_002)).toBe(true)
    expect(reduced.some(point => point.cpuPressureSomeAvg10 === 91)).toBe(true)
    expect(reduced.some(point => point.cpuPressureFullAvg10 === 92)).toBe(true)
    expect(reduced.some(point => point.memoryPressureSomeAvg10 === 93)).toBe(true)
    expect(reduced.some(point => point.memoryPressureFullAvg10 === 94)).toBe(true)
    expect(reduced.some(point => point.pidsCurrent === 10_003)).toBe(true)
    expect(reduced.some(point => point.pidsLimit === 10_004)).toBe(true)
  })

  it('derives conservative accumulation and explicit zero-swap signals', () => {
    const samples = [
      normalizeResourceSample({ elapsed_seconds: 0, process: { rss_bytes: 100 * 1024 * 1024, swap_bytes: 0 } })!,
      normalizeResourceSample({ elapsed_seconds: 3600, process: { rss_bytes: 500 * 1024 * 1024, swap_bytes: 0 } })!,
    ]
    const analysis = analyzeResourceUsage({
      artifact: {
        schema_version: 1,
        status: 'completed',
        baseline: { process: { rss_bytes: 100 * 1024 * 1024 } },
        latest: { process: { rss_bytes: 500 * 1024 * 1024 } },
        summary: {
          duration_seconds: 3600,
          artifact_write_succeeded: true,
          peaks: { process: { rss_bytes: 550 * 1024 * 1024 } },
        },
      },
      samples,
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(analysis.signals.memoryAccumulationState).toBe('observed')
    expect(analysis.signals.rssGrowthBytes).toBe(400 * 1024 * 1024)
    expect(analysis.signals.swapState).toBe('clear')
    expect(analysis.signals.processObservedPeakSwapBytes).toBe(0)
  })

  it('surfaces new producer swap usage and limit events', () => {
    const samples = [0, 1].map((fail, index) => normalizeResourceSample({
      elapsed_seconds: index * 10,
      process: { swap_bytes: 0 },
      cgroup: { scopes: [{
        controller: 'unified', path: '/run', role: 'current',
        memory: {
          swap_current_bytes: index * 4096,
          swap_peak_bytes: index * 4096,
          swap_limit: { value: 8192 },
          swap_events: { high: index * 2, max: index * 3, fail },
        },
      }] },
    })!)
    const analysis = analyzeResourceUsage({
      artifact: {
        schema_version: 1, status: 'completed',
        latest: { cgroup: { scopes: [{
          controller: 'unified', path: '/run', role: 'current',
          memory: { swap_current_bytes: 4096, swap_peak_bytes: 4096, swap_limit: { value: 8192 } },
        }] } },
        summary: {
          artifact_write_succeeded: true,
          deltas: { cgroup_scopes: { 'unified:/run': { swap_events: { high: 2, max: 3, fail: 1 } } } },
        },
      },
      samples,
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(analysis.signals).toMatchObject({ swapState: 'observed', cgroupObservedPeakSwapBytes: 4096, swapEvents: 6 })
    expect(analysis.scopes[0]).toMatchObject({ swapCurrentBytes: 4096, swapLimitState: 'limited', swapEvents: 6 })
  })

  it('preserves run-observed swap peaks after earlier samples rotate out', () => {
    const samples = [normalizeResourceSample({
      elapsed_seconds: 100,
      process: { swap_bytes: 0 },
      cgroup: { scopes: [{
        controller: 'unified',
        path: '/run',
        role: 'current',
        memory: { swap_current_bytes: 0 },
      }] },
    })!]
    const analysis = analyzeResourceUsage({
      artifact: {
        schema_version: 1,
        status: 'completed',
        latest: {
          process: { swap_bytes: 0 },
          cgroup: { scopes: [{
            controller: 'unified',
            path: '/run',
            role: 'current',
            memory: { swap_current_bytes: 0, swap_peak_bytes: 16384 },
          }] },
        },
        summary: {
          artifact_write_succeeded: true,
          peaks: {
            process: { swap_bytes: 4096 },
            cgroup_scopes: {
              'unified:/run': { swap_current_bytes: 8192, swap_peak_bytes: 16384 },
            },
          },
        },
      },
      samples,
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(analysis.signals).toMatchObject({
      swapState: 'observed',
      processObservedPeakSwapBytes: 4096,
      cgroupObservedPeakSwapBytes: 8192,
    })
    expect(analysis.scopes[0]).toMatchObject({
      swapCurrentBytes: 0,
      swapObservedPeakBytes: 8192,
      swapLifetimeHighWaterBytes: 16384,
    })
  })

  it('sums current-scope swap categories without double-counting an ancestor', () => {
    const sample = normalizeResourceSample({
      elapsed_seconds: 10,
      cgroup: {
        scopes: [
          { role: 'current', memory: { swap_events: { high: 2, max: 3, fail: 1 } } },
          { role: 'ancestor', memory: { swap_events: { high: 4, max: 5, fail: 1 } } },
        ],
      },
    })

    expect(sample?.swapEvents).toBe(6)
  })

  it('keeps explicit unlimited cgroup limits separate from unavailable values', () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.latest.cgroup.scopes[0].memory.limit = { raw: 'max', value: null, unlimited: true }
    artifact.latest.cgroup.scopes[0].pids.limit = { raw: 'max', value: null, unlimited: true }
    artifact.system.cgroup.effective_quota_cpus = null
    artifact.system.cgroup.cpu_quota_candidates = [{ raw: 'max 100000', state: 'unlimited' }]

    const analysis = analyzeResourceUsage({ artifact, samples: fixtureSamples(), diagnostics: emptyResourceDiagnostics() })

    expect(analysis.scopes[0].memoryLimitState).toBe('unlimited')
    expect(analysis.scopes[0].pidsLimitState).toBe('unlimited')
    expect(analysis.scheduler.find(entry => entry.label === 'Effective cgroup quota (CPUs)')?.value).toBe('Unlimited')
  })

  it('separates observed cgroup memory from the kernel scope-lifetime peak', () => {
    const sample = normalizeResourceSample({
      elapsed_seconds: 10,
      cgroup: { scopes: [{ controller: 'unified', path: '/run', role: 'current', memory: { current_bytes: 300 } }] },
    })!
    const artifact = {
      schema_version: 1,
      status: 'completed',
      latest: {
        cgroup: {
          scopes: [{
            controller: 'unified',
            path: '/run',
            role: 'current',
            memory: { current_bytes: 300, peak_bytes: 900, limit: { value: 1000 } },
          }],
        },
      },
      summary: {
        artifact_write_succeeded: true,
        peaks: { cgroup_scopes: { 'unified:/run': { memory_current_bytes: 500 } } },
      },
    }

    const analysis = analyzeResourceUsage({ artifact, samples: [sample], diagnostics: emptyResourceDiagnostics() })

    expect(analysis.scopes[0]).toMatchObject({
      memoryCurrentBytes: 300,
      memoryPeakBytes: 500,
      memoryLifetimePeakBytes: 900,
    })
    expect(analysis.signals.peakMemoryLimitPercent).toBe(50)

    delete (artifact.summary.peaks as any).cgroup_scopes
    const legacy = analyzeResourceUsage({ artifact, samples: [sample], diagnostics: emptyResourceDiagnostics() })
    expect(legacy.scopes[0].memoryPeakBytes).toBe(300)
    expect(legacy.signals.peakMemoryLimitPercent).toBe(30)
  })

  it('bounds cgroup rows from a hostile summary and reports the limitation', () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.latest.cgroup.scopes = Array.from({ length: 100 }, (_, index) => ({
      controller: 'unified', path: `/scope-${index}`, memory: { current_bytes: index },
    }))

    const analysis = analyzeResourceUsage({ artifact, samples: fixtureSamples(), diagnostics: emptyResourceDiagnostics() })

    expect(analysis.scopes).toHaveLength(64)
    expect(analysis.health.state).toBe('limited')
    expect(analysis.health.warnings.some(warning => warning.includes('36 cgroup scope'))).toBe(true)
  })

  it('limits health when declared retained samples are absent from the loaded history', () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.summary.samples_total = 10
    artifact.summary.samples_retained = 10

    const analysis = analyzeResourceUsage({
      artifact,
      samples: fixtureSamples(),
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(analysis.health.state).toBe('limited')
    expect(analysis.health.retainedFileCoveragePercent).toBe(40)
    expect(analysis.health.warnings).toContain(
      '6 retained sample(s) declared by the producer were not available to the dashboard.',
    )
  })

  it('does not mislabel total reported samples as retained-file coverage', () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.summary.samples_total = 10
    delete artifact.summary.samples_retained
    delete artifact.sample_history.samples_retained

    const analysis = analyzeResourceUsage({
      artifact,
      samples: fixtureSamples(),
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(analysis.health.retainedFileCoveragePercent).toBeNull()
    expect(analysis.health.warnings.some(warning => warning.includes('not available to the dashboard'))).toBe(false)
  })

  it('does not count summary fallback points as retained history files', () => {
    const diagnostics = { ...emptyResourceDiagnostics(), historySamplesLoaded: 0 }
    const analysis = analyzeResourceUsage({
      artifact: resourceArtifact,
      samples: fixtureSamples().slice(0, 2),
      diagnostics,
    })

    expect(analysis.health.retainedFileCoveragePercent).toBe(0)
    expect(analysis.health.warnings).toContain(
      '4 retained sample(s) declared by the producer were not available to the dashboard.',
    )
  })

  it('uses retained coverage when older reported samples were intentionally rotated', () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.summary.samples_total = 10
    artifact.summary.samples_retained = 4
    artifact.summary.samples_rotated_out = 6

    const analysis = analyzeResourceUsage({
      artifact,
      samples: fixtureSamples(),
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(analysis.health.retainedFileCoveragePercent).toBe(100)
    expect(analysis.health.warnings.some(warning => warning.includes('not available to the dashboard'))).toBe(false)
    expect(analysis.health.warnings).toContain('6 older sample(s) were intentionally rotated out by the producer.')
  })

  it('separates retained-file coverage from missed monotonic cadence', () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.summary.sampling_schedule = {
      periodic_samples: 8,
      missed_intervals: 2,
      max_start_jitter_seconds: 4.25,
    }

    const analysis = analyzeResourceUsage({ artifact, samples: fixtureSamples(), diagnostics: emptyResourceDiagnostics() })

    expect(analysis.health.retainedFileCoveragePercent).toBe(100)
    expect(analysis.health.cadenceCoveragePercent).toBe(80)
    expect(analysis.health.maxSamplingJitterSeconds).toBe(4.25)
    expect(analysis.health.state).toBe('degraded')
  })

  it('never divides ancestor cgroup CPU counters by the process budget', () => {
    const samples = [0, 10].map((elapsed, index) => normalizeResourceSample({
      elapsed_seconds: elapsed,
      process: { user_cpu_seconds: index * 5 },
      cgroup: { scopes: [
        { controller: 'unified', path: '/pod/process', role: 'current', cpu: { stat: { usage_usec: index * 6_000_000 } } },
        { controller: 'unified', path: '/pod', role: 'ancestor', cpu: { stat: { usage_usec: index * 500_000_000 } } },
      ] },
    })!)
    const analysis = analyzeResourceUsage({
      artifact: { scheduler: { effective_cpus: 1 }, summary: { duration_seconds: 10 } },
      samples,
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(analysis.samples[1].cpuCores).toBe(0.5)
    expect(analysis.samples[1].quotaPercent).toBe(50)
    expect(analysis.samples[1].cgroupCpuCores).toBe(0.6)
    expect(analysis.samples[1].cgroupQuotaPercent).toBeNull()
    expect(analysis.signals.peakCpuBudgetPercent).toBe(50)
  })

  it('uses only producer-marked current cgroup counters for timelines and signals', () => {
    const scopes = [
      {
        controller: 'unified', path: '/pod/process', role: 'current',
        cpu: {
          stat: { usage_usec: 1_000_000, nr_throttled: 1, throttled_usec: 1_000 },
          pressure: { some: { avg10: 3 }, full: { avg10: 2 } },
        },
        memory: {
          current_bytes: 100, peak_bytes: 120, limit: { value: 200 },
          swap_current_bytes: 10, swap_events: { high: 1 },
          events: { high: 1, oom: 0, oom_kill: 0 },
          pressure: { some: { avg10: 4 }, full: { avg10: 1 } },
        },
        pids: { current: 4, limit: { value: 10 } },
      },
      {
        controller: 'unified', path: '/pod', role: 'ancestor',
        cpu: {
          stat: { usage_usec: 999_000_000, nr_throttled: 999, throttled_usec: 999_000_000 },
          pressure: { some: { avg10: 99 }, full: { avg10: 99 } },
        },
        memory: {
          current_bytes: 9_000, peak_bytes: 9_999, limit: { value: 10_000 },
          swap_current_bytes: 9_000, swap_events: { high: 999 },
          events: { high: 999, oom: 999, oom_kill: 999 },
          pressure: { some: { avg10: 99 }, full: { avg10: 99 } },
        },
        pids: { current: 999, limit: { value: 1 } },
      },
    ]
    const sample = normalizeResourceSample({ elapsed_seconds: 0, cgroup: { scopes } })!

    expect(sample).toMatchObject({
      cgroupMemoryBytes: 100,
      cgroupPeakMemoryBytes: 120,
      cgroupSwapBytes: 10,
      swapEvents: 1,
      cgroupCpuUsageSeconds: 1,
      throttleEvents: 1,
      throttledSeconds: 0.001,
      oomEvents: 0,
      oomKillEvents: 0,
      memoryHighEvents: 1,
      cpuPressureSomeAvg10: 3,
      cpuPressureFullAvg10: 2,
      memoryPressureSomeAvg10: 4,
      memoryPressureFullAvg10: 1,
      pidsCurrent: 4,
      pidsLimit: 10,
    })

    const analysis = analyzeResourceUsage({
      artifact: {
        schema_version: 1,
        status: 'completed',
        latest: { cgroup: { scopes } },
        summary: {
          duration_seconds: 1,
          artifact_write_succeeded: true,
          peaks: { cgroup_scopes: {
            'unified:/pod/process': { memory_current_bytes: 120, swap_current_bytes: 10 },
            'unified:/pod': { memory_current_bytes: 9_999, swap_current_bytes: 9_000 },
          } },
          deltas: { cgroup_scopes: {
            'unified:/pod/process': {
              cpu_stat: { nr_throttled: 1, throttled_usec: 1_000 },
              memory_events: { high: 1, oom: 0, oom_kill: 0 },
              swap_events: { high: 1 },
            },
            'unified:/pod': {
              cpu_stat: { nr_throttled: 999, throttled_usec: 999_000_000 },
              memory_events: { high: 999, oom: 999, oom_kill: 999 },
              swap_events: { high: 999 },
            },
          } },
        },
      },
      samples: [sample],
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(analysis.signals).toMatchObject({
      peakMemoryLimitPercent: 60,
      memoryHighEvents: 1,
      oomEvents: 0,
      oomKillEvents: 0,
      throttleEvents: 1,
      cgroupObservedPeakSwapBytes: 10,
      swapEvents: 1,
    })
  })

  it('infers the first roleless schema-v1 scope per controller without folding in ancestors', () => {
    const scopes = [
      {
        controller: 'unified',
        path: '/pod/process',
        cpu: { stat: { usage_usec: 1_000_000, nr_throttled: 1 } },
        memory: {
          current_bytes: 100,
          limit: { value: 200 },
          events: { high: 1, oom: 0, oom_kill: 0 },
        },
        pids: { current: 4, limit: { value: 10 } },
      },
      {
        controller: 'unified',
        path: '/pod',
        cpu: { stat: { usage_usec: 999_000_000, nr_throttled: 999 } },
        memory: {
          current_bytes: 9_000,
          limit: { value: 10_000 },
          events: { high: 999, oom: 999, oom_kill: 999 },
        },
        pids: { current: 999, limit: { value: 1 } },
      },
    ]
    const sample = normalizeResourceSample({
      elapsed_seconds: 0,
      cgroup: { version: 2, scopes },
    })!
    const analysis = analyzeResourceUsage({
      artifact: {
        schema_version: 1,
        status: 'completed',
        monitor: { scope: 'collection_and_pre_packaging_cleanup' },
        latest: { cgroup: { version: 2, scopes } },
        summary: {
          duration_seconds: 1,
          artifact_write_succeeded: true,
          deltas: {
            cgroup_scopes: {
              'unified:/pod/process': {
                cpu_stat: { nr_throttled: 1 },
                memory_events: { high: 1, oom: 0, oom_kill: 0 },
              },
              'unified:/pod': {
                cpu_stat: { nr_throttled: 999 },
                memory_events: { high: 999, oom: 999, oom_kill: 999 },
              },
            },
          },
        },
      },
      samples: [sample],
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(sample).toMatchObject({
      cgroupMemoryBytes: 100,
      cgroupCpuUsageSeconds: 1,
      throttleEvents: 1,
      memoryHighEvents: 1,
      oomEvents: 0,
      pidsCurrent: 4,
      pidsLimit: 10,
    })
    expect(analysis.scopes.map(scope => scope.role)).toEqual(['current', 'ancestor'])
    expect(analysis.signals).toMatchObject({
      peakMemoryLimitPercent: 50,
      memoryHighEvents: 1,
      oomEvents: 0,
      oomKillEvents: 0,
      throttleEvents: 1,
    })
    expect(analysis.producerScope).toBe('collection_and_pre_packaging_cleanup')
  })

  it('only preserves producer-defined public monitor error codes', () => {
    const analysis = analyzeResourceUsage({
      artifact: {
        errors: [
          {
            timestamp: '2026-08-04T00:00:00Z',
            source: 'resource_sample_history_write',
            error: 'safe producer code with a private message',
          },
          {
            timestamp: '2026-08-04T00:00:01Z',
            source: 'InternalCase123',
            error: 'credential=do-not-render',
          },
        ],
      },
      samples: [],
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(analysis.monitorErrors).toEqual([
      {
        timestamp: '2026-08-04T00:00:00.000Z',
        code: 'resource_sample_history_write',
      },
      {
        timestamp: '2026-08-04T00:00:01.000Z',
        code: 'resource_monitor',
      },
    ])
    expect(JSON.stringify(analysis.monitorErrors)).not.toContain('do-not-render')
    expect(JSON.stringify(analysis.monitorErrors)).not.toContain('InternalCase123')
    expect(analysis.producerScope).toBe('unknown')
  })

  it('labels cgroup v1 memsw as combined accounting, not a swap-only limit or peak', () => {
    const sample = normalizeResourceSample({
      elapsed_seconds: 0,
      cgroup: { scopes: [{
        controller: 'memory', path: '/run', role: 'current',
        memory: { current_bytes: 400, memory_and_swap_current_bytes: 650 },
      }] },
    })!
    const analysis = analyzeResourceUsage({
      artifact: {
        latest: { cgroup: { scopes: [{
          controller: 'memory', path: '/run', role: 'current',
          memory: {
            current_bytes: 400,
            peak_bytes: 900,
            memory_and_swap_current_bytes: 650,
            memory_and_swap_peak_bytes: 1200,
            memory_and_swap_limit: { value: 2000 },
          },
        }] } },
      },
      samples: [sample],
      diagnostics: emptyResourceDiagnostics(),
    })

    expect(analysis.scopes[0]).toMatchObject({
      swapCurrentBytes: 250,
      swapCurrentSemantics: 'derived_memsw',
      swapLimitState: 'unavailable',
      swapLifetimeHighWaterBytes: null,
      memoryAndSwapCurrentBytes: 650,
      memoryAndSwapLimitBytes: 2000,
      memoryAndSwapLimitState: 'limited',
    })
  })

  it('analyzes and bounds a maximum-sized synthetic run responsively', () => {
    const samples = Array.from({ length: 20_000 }, (_, index) => normalizeResourceSample({
      elapsed_seconds: index * 30,
      process: {
        rss_bytes: index,
        threads: index === 7_777 ? 50_000 : 10,
        open_fds: index === 8_888 ? 60_000 : 20,
      },
      cgroup: { scopes: [{
        controller: 'unified', path: '/run', role: 'current',
        cpu: { pressure: { some: { avg10: index === 9_999 ? 99 : 0 } } },
        pids: { current: index === 10_001 ? 70_000 : 30 },
      }] },
    })!)
    const started = performance.now()
    const analysis = analyzeResourceUsage({ artifact: {}, samples, diagnostics: emptyResourceDiagnostics() })
    const elapsed = performance.now() - started

    expect(analysis.samples.length).toBeLessThanOrEqual(900)
    expect(analysis.samples.some(sample => sample.threads === 50_000)).toBe(true)
    expect(analysis.samples.some(sample => sample.openFds === 60_000)).toBe(true)
    expect(analysis.samples.some(sample => sample.cpuPressureSomeAvg10 === 99)).toBe(true)
    expect(analysis.samples.some(sample => sample.pidsCurrent === 70_000)).toBe(true)
    expect(elapsed).toBeLessThan(3_000)
  })
})
