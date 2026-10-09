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

import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, shallowMount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import resourceArtifact from '../../fixtures/resource_usage.json'
import previousSamples from '../../fixtures/resource_usage_samples.previous.jsonl?raw'
import currentSamples from '../../fixtures/resource_usage_samples.jsonl?raw'
import ResourcesView from '@/views/ResourcesView.vue'
import { useFileSystemStore } from '@/stores/fileSystem'
import { emptyResourceDiagnostics, normalizeResourceSample } from '@/utils/resourceUsage'
import type { ResourceSamplePoint } from '@/types/resourceUsage'
import { ResourceArtifactMissingError } from '@/services/resourceUsageLoader'
import { ConcurrencySchedulerArtifactMissingError } from '@/services/concurrencySchedulerLoader'

const loadMock = vi.hoisted(() => vi.fn())
const concurrencyLoadMock = vi.hoisted(() => vi.fn())

vi.mock('@/services/resourceUsageLoader', async importOriginal => ({
  ...await importOriginal<typeof import('@/services/resourceUsageLoader')>(),
  loadResourceUsageArtifacts: loadMock,
}))

vi.mock('@/services/concurrencySchedulerLoader', async importOriginal => ({
  ...await importOriginal<typeof import('@/services/concurrencySchedulerLoader')>(),
  loadConcurrencySchedulerArtifact: concurrencyLoadMock,
}))

function samples(): ResourceSamplePoint[] {
  return `${previousSamples}\n${currentSamples}`.trim().split('\n')
    .filter(line => line.trim())
    .map(line => normalizeResourceSample(JSON.parse(line))!)
}

const stubs = {
  AnalysisNav: { template: '<nav />' },
  Breadcrumbs: { template: '<div />' },
  PageLoader: { props: ['message'], template: '<div>{{ message }}</div>' },
  EmptyState: { props: ['title', 'description'], template: '<div><strong>{{ title }}</strong><span>{{ description }}</span></div>' },
  NvCallout: { props: ['title'], template: '<div><strong>{{ title }}</strong><slot /></div>' },
  NvCollapsibleSection: { props: ['title'], template: '<div>{{ title }}<slot /></div>' },
  ConcurrencyTimelineChart: {
    name: 'ConcurrencyTimelineChart',
    props: ['points', 'plannedOperations'],
    template: '<div class="concurrency-chart-stub" />',
  },
  ResourceTimelineChart: {
    name: 'ResourceTimelineChart',
    props: ['series', 'yAxisTitle', 'accessibilityLabel'],
    template: '<div class="resource-chart-stub" />',
  },
  StatCard: { name: 'StatCard', props: ['label', 'value', 'subtitle'], template: '<div>{{ label }}={{ value }} {{ subtitle }}</div>' },
}

function mountView() {
  return shallowMount(ResourcesView, { global: { stubs } })
}

describe('ResourcesView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    const fileStore = useFileSystemStore()
    fileStore.mode = 'file'
    fileStore.directoryLoaded = true
    loadMock.mockReset()
    concurrencyLoadMock.mockReset()
    concurrencyLoadMock.mockRejectedValue(new ConcurrencySchedulerArtifactMissingError())
  })

  it('renders resource KPIs, honest scope, health, and detailed diagnostic sections', async () => {
    loadMock.mockResolvedValue({
      artifact: resourceArtifact,
      samples: samples(),
      diagnostics: emptyResourceDiagnostics(),
    })
    const wrapper = mountView()
    await flushPromises()

    const cards = wrapper.findAllComponents({ name: 'StatCard' })
    const values = Object.fromEntries(cards.map(card => [card.props('label'), card.props('value')]))
    expect(values).toMatchObject({
      'Peak RSS': '180.0 MiB',
      'Process HWM': '180.0 MiB',
      'Final RSS': '150.0 MiB',
      'Average CPU': '1.00 cores',
      'CPU budget used': '50.0%',
      'Physical reads': '1.0 MiB',
      'Physical writes': '2.0 MiB',
    })
    expect(wrapper.text()).toContain('after runtime logging is available')
    expect(wrapper.text()).toContain('interactive report generation, archive creation, upload, and extraction are outside')
    expect(wrapper.text()).toContain('Missing metrics are shown as Unavailable, never as zero')
    expect(wrapper.text()).toContain('cgroup diagnostics')
    expect(wrapper.text()).toContain('Scheduler and CPU budget')
    expect(wrapper.text()).not.toContain('Collector-stage correlations')
    expect(wrapper.text()).toContain('Run signals')
    expect(wrapper.text()).toContain('RSS accumulation')
    expect(wrapper.text()).toContain('Swap activity')
    expect(wrapper.text()).toContain('run-observed peak')
    expect(wrapper.text()).toContain('kernel lifetime HWM')
    expect(wrapper.text()).toContain('Retained-file coverage')
    expect(wrapper.text()).toContain('Cadence coverage')
    expect(wrapper.findAll('th[scope="col"]').length).toBeGreaterThan(0)
    expect(wrapper.findAll('caption').length).toBeGreaterThan(0)
    expect(wrapper.text()).not.toContain('/nvdebug')
    const charts = wrapper.findAllComponents({ name: 'ResourceTimelineChart' })
    expect(charts).toHaveLength(7)
    const eventChart = charts.find(chart => chart.props('accessibilityLabel').includes('event count'))!
    const throttledTimeChart = charts.find(chart => chart.props('accessibilityLabel').includes('throttled-time'))!
    expect(eventChart.props('series').map((series: { key: string }) => series.key)).toEqual([
      'throttleEvents',
      'memoryHighEvents',
      'oomEvents',
      'oomKillEvents',
      'swapEvents',
    ])
    expect(throttledTimeChart.props('series').map((series: { key: string }) => series.key)).toEqual([
      'throttledSeconds',
    ])
  })

  it('renders request-capture pool aggregates and sampled concurrency', async () => {
    const capture = {
      schema_version: '1.0', status: 'closed', worker_count: 16, observation_seconds: 50,
      calls: { enqueued: 3000, worker_completions: 3000, worker_failures: 0, abandoned_before_submission: 0 },
      pool: { peak_active_workers: 16, peak_queued_calls: 45 },
      queue: {
        wait_seconds_total: 600, wait_seconds_average: 0.2, wait_seconds_max: 1.9,
        queued_wall_seconds: 40, queued_capacity_worker_seconds: 640,
        queued_active_worker_seconds: 320, saturated_while_queued_seconds: 4,
        runnable_gap_worker_seconds: 320, utilization_while_queued_ratio: 0.5,
        saturation_while_queued_ratio: 0.1,
      },
      workers: { seconds_total: 350, utilization_ratio: 0.4375 },
    }
    const captureSamples = samples().map((sample, index) => ({
      ...sample,
      captureWorkerCount: 16,
      captureActiveWorkers: index * 4,
      captureQueuedCalls: index === 1 ? 20 : 0,
      captureUtilizationWhileQueuedPercent: 40 + index * 5,
      captureSaturationWhileQueuedPercent: 10 + index,
    }))
    loadMock.mockResolvedValue({
      artifact: { ...resourceArtifact, components: { request_capture: capture } },
      samples: captureSamples,
      diagnostics: emptyResourceDiagnostics(),
    })
    const wrapper = mountView()
    await flushPromises()

    const cards = Object.fromEntries(wrapper.findAllComponents({ name: 'StatCard' })
      .map(card => [card.props('label'), card.props('value')]))
    expect(cards).toMatchObject({
      'Capture workers': '16',
      'Capture calls': '3,000 / 3,000',
      'Peak active workers': '16',
      'Maximum queue wait': '1.90s',
      'Queued utilization': '50.0%',
      'Overall pool utilization': '43.8%',
      'Capture failures': '0',
    })
    expect(wrapper.text()).toContain('Request capture pool')
    expect(wrapper.text()).toContain('they do not admit more requests to a DUT')
    const chart = wrapper.findAllComponents({ name: 'ResourceTimelineChart' })
      .find(candidate => candidate.props('accessibilityLabel').includes('Request capture'))!
    expect(chart.props('series').map((series: { key: string }) => series.key)).toEqual([
      'captureWorkerCount',
      'captureActiveWorkers',
      'captureQueuedCalls',
    ])
    const efficiencyChart = wrapper.findAllComponents({ name: 'ResourceTimelineChart' })
      .find(candidate => candidate.props('accessibilityLabel').includes('queued utilization'))!
    expect(efficiencyChart.props('series').map((series: { key: string }) => series.key)).toEqual([
      'captureUtilizationWhileQueuedPercent',
      'captureSaturationWhileQueuedPercent',
    ])
  })

  it('shows explicit zero and unavailable values without conflating them', async () => {
    loadMock.mockResolvedValue({
      artifact: {
        summary: {
          duration_seconds: 10,
          deltas: { process: { user_cpu_seconds: 0, system_cpu_seconds: 0, io: { read_bytes: 0, write_bytes: 0 } } },
        },
      },
      samples: [
        normalizeResourceSample({ elapsed_seconds: 0, process: { user_cpu_seconds: 0, system_cpu_seconds: 0, io: { read_bytes: 0, write_bytes: 0 } } })!,
        normalizeResourceSample({ elapsed_seconds: 10, process: { user_cpu_seconds: 0, system_cpu_seconds: 0, io: { read_bytes: 0, write_bytes: 0 } } })!,
      ],
      diagnostics: emptyResourceDiagnostics(),
    })
    const wrapper = mountView()
    await flushPromises()

    const values = Object.fromEntries(wrapper.findAllComponents({ name: 'StatCard' })
      .map(card => [card.props('label'), card.props('value')]))
    expect(values['Peak RSS']).toBe('Unavailable')
    expect(values['Process HWM']).toBe('Unavailable')
    expect(values['Average CPU']).toBe('0.0 cores')
    expect(values['CPU budget used']).toBe('Unavailable')
    expect(values['Physical reads']).toBe('0 B')
  })

  it('renders bounded adaptive concurrency progress and decision evidence', async () => {
    loadMock.mockResolvedValue({
      artifact: resourceArtifact,
      samples: samples(),
      diagnostics: emptyResourceDiagnostics(),
    })
    concurrencyLoadMock.mockResolvedValue({
      schema_version: '1.2',
      status: 'completed',
      settings: {
        mode: 'adaptive', initial_limit: 5, minimum_limit: 4, maximum_limit: 64,
        sample_interval_seconds: 20, healthy_windows_required: 3, increase_step: 8,
      },
      plan_summary: {
        runnable_collector_operations: 324, skipped_collector_operations: 36,
        weighted_demand: 324, dut_count: 45, runnable_service_lanes: 45,
        limits: { redfish_per_dut: 1 },
      },
      decisions: [{
        elapsed_seconds: 60, action: 'increase', previous_limit: 5, new_limit: 6,
        reasons: ['consecutive_healthy_windows'],
        signals: { completed_operations: 100, cpu_utilization: 0.1, memory_headroom_ratio: 0.8, remote_events: {} },
        progress: {
          admissions: 160, completed_operations: 155,
          limiter: { active_operations: 5, active_weight: 5, queued_operations: 20 },
        },
      }],
      decision_accounting: { total: 1, retained: 1, dropped: 0 },
      operation_metrics: {
        admissions: 324, completed_operations: 324,
        queue_wait_seconds_average: 0.2, queue_wait_seconds_max: 2,
        active_time_by_service: { redfish: { completed_operations: 324, active_seconds_total: 600, active_seconds_average: 1.85 } },
        peak_active_operations_by_service: { redfish: 6 },
        limiter: {
          peak_active_operations: 6, peak_active_weight: 6, queued_operations: 0,
          peak_queued_operations: 20, backfilled_operations: 3,
          queued_wall_seconds: 100, saturated_while_queued_seconds: 96,
          runnable_gap_weight_seconds: 0.02, fragmentation_weight_seconds: 4,
          utilization_while_queued_ratio: 0.9958, saturation_while_queued_ratio: 0.96,
        },
      },
      remote_pressure_events: {}, endpoint_cooldowns: {}, final_limit: 6,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('Concurrency scheduler')
    expect(wrapper.text()).toContain('Collector operations')
    expect(wrapper.text()).toContain('324 / 324')
    expect(wrapper.text()).toContain('Queued utilization')
    expect(wrapper.text()).toContain('99.6%')
    expect(wrapper.text()).toContain('Opportunistic backfill')
    expect(wrapper.text()).toContain('consecutive healthy windows')
    expect(wrapper.text()).toContain('redfish')
    expect(wrapper.text()).not.toContain('10.23.45.67')
    const chart = wrapper.getComponent({ name: 'ConcurrencyTimelineChart' })
    expect(chart.props('plannedOperations')).toBe(324)
    expect(chart.props('points')).toHaveLength(1)
  })

  it('degrades cleanly when the resource artifact is absent in a legacy run', async () => {
    loadMock.mockRejectedValue(new ResourceArtifactMissingError())
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('Resource telemetry unavailable')
    expect(wrapper.text()).toContain('may predate resource telemetry')
    expect(wrapper.findAllComponents({ name: 'StatCard' })).toHaveLength(0)
  })

  it('scrolls within the resource route without replacing the hash route', async () => {
    loadMock.mockResolvedValue({
      artifact: resourceArtifact,
      samples: samples(),
      diagnostics: emptyResourceDiagnostics(),
    })
    const scrollIntoView = vi.fn()
    const target = document.createElement('section')
    target.id = 'overview'
    target.scrollIntoView = scrollIntoView
    document.body.appendChild(target)
    const wrapper = mountView()
    await flushPromises()
    const link = wrapper.get('a[href="#overview"]')
    const event = new MouseEvent('click', { bubbles: true, cancelable: true })

    link.element.dispatchEvent(event)

    expect(event.defaultPrevented).toBe(true)
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: 'smooth', block: 'start' })
    wrapper.unmount()
    target.remove()
  })

  it('aborts an obsolete HTTP load before reloading from local files', async () => {
    const fileStore = useFileSystemStore()
    fileStore.mode = 'http'
    let firstSignal: AbortSignal | undefined
    loadMock
      .mockImplementationOnce((access) => {
        firstSignal = access.signal
        return new Promise((_resolve, reject) => {
          access.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
        })
      })
      .mockResolvedValueOnce({
        artifact: resourceArtifact,
        samples: samples(),
        diagnostics: emptyResourceDiagnostics(),
      })
    const wrapper = mountView()
    await flushPromises()

    fileStore.mode = 'file'
    await flushPromises()

    expect(firstSignal?.aborted).toBe(true)
    expect(loadMock.mock.calls[1][0].signal).toBeInstanceOf(AbortSignal)
    expect(wrapper.text()).not.toContain('Resource telemetry could not be loaded')
    wrapper.unmount()
  })

  it('uses conservative artifact-driven wording for legacy and unknown scope values', async () => {
    const legacyArtifact = JSON.parse(JSON.stringify(resourceArtifact))
    legacyArtifact.monitor.scope = 'collection_and_pre_packaging_cleanup'
    loadMock.mockResolvedValueOnce({
      artifact: legacyArtifact,
      samples: samples(),
      diagnostics: emptyResourceDiagnostics(),
    })
    const legacyWrapper = mountView()
    await flushPromises()

    expect(legacyWrapper.text()).toContain('collection workflow and cleanup before report packaging')
    expect(legacyWrapper.text()).not.toContain('after runtime logging is available')
    legacyWrapper.unmount()

    const unknownArtifact = JSON.parse(JSON.stringify(resourceArtifact))
    unknownArtifact.monitor.scope = 'private_pipeline_phase'
    loadMock.mockResolvedValueOnce({
      artifact: unknownArtifact,
      samples: samples(),
      diagnostics: emptyResourceDiagnostics(),
    })
    const unknownWrapper = mountView()
    await flushPromises()

    expect(unknownWrapper.text()).toContain('Exact lifecycle boundaries are unavailable')
    expect(unknownWrapper.text()).not.toContain('private_pipeline_phase')
    unknownWrapper.unmount()
  })

  it('does not display raw monitor errors, sources, or cgroup paths', async () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.errors = [{
      timestamp: '2026-08-04T00:00:00Z',
      source: '../../sensitive/resource',
      error: 'credential=do-not-render',
    }]
    artifact.latest.cgroup.scopes[0].path = '/private/pod/container'
    loadMock.mockResolvedValue({
      artifact,
      samples: samples(),
      diagnostics: emptyResourceDiagnostics(),
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('Resource monitor diagnostic')
    expect(wrapper.text()).toContain('resource_monitor')
    expect(wrapper.text()).not.toContain('sensitive/resource')
    expect(wrapper.text()).not.toContain('credential=do-not-render')
    expect(wrapper.text()).not.toContain('/private/pod/container')
    wrapper.unmount()
  })

  it('aborts an active HTTP load when the view unmounts', async () => {
    useFileSystemStore().mode = 'http'
    let signal: AbortSignal | undefined
    loadMock.mockImplementationOnce((access) => {
      signal = access.signal
      return new Promise((_resolve, reject) => {
        access.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
      })
    })
    const wrapper = mountView()
    await flushPromises()

    wrapper.unmount()

    expect(signal?.aborted).toBe(true)
  })

  it('aborts an active local-file load when the view unmounts', async () => {
    let signal: AbortSignal | undefined
    loadMock.mockImplementationOnce((access) => {
      signal = access.signal
      return new Promise((_resolve, reject) => {
        access.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
      })
    })
    const wrapper = mountView()
    await flushPromises()

    wrapper.unmount()

    expect(signal?.aborted).toBe(true)
  })
})
