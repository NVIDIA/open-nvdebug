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
import { mount, shallowMount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import StatusPieChart from '@/components/charts/StatusPieChart.vue'
import EmptyState from '@/components/common/EmptyState.vue'
import PageLoader from '@/components/common/PageLoader.vue'
import ProgressBar from '@/components/dashboard/ProgressBar.vue'
import DataTable from '@/components/common/DataTable.vue'
import StatCard from '@/components/dashboard/StatCard.vue'
import { useManifestStore } from '@/stores/manifest'
import CoverageMatrixView from '@/views/CoverageMatrixView.vue'
import DashboardView from '@/views/DashboardView.vue'
import ServiceHealthView from '@/views/ServiceHealthView.vue'
import StatusDetailView from '@/views/StatusDetailView.vue'
import TimingView from '@/views/TimingView.vue'
import { formatDutForTicket } from '@/composables/useCopyForTicket'

const mockRoute = vi.hoisted(() => ({
  params: { statusType: 'cancelled' },
}))

vi.mock('vue-router', () => ({
  useRoute: () => mockRoute,
  useRouter: () => ({ push: vi.fn() }),
}))

vi.mock('vue-chartjs', () => ({
  Doughnut: {
    name: 'Doughnut',
    props: ['data', 'options'],
    template: '<div class="doughnut-stub" />',
  },
  Bar: {
    name: 'Bar',
    props: ['data', 'options'],
    template: '<div class="bar-stub" />',
  },
}))

function loadSummary(statusCounts: Record<string, number>) {
  const store = useManifestStore()
  store.loadFromJson({
    collection_summary: { status_counts: statusCounts },
  })
  return store
}

function dashboardMetric(wrapper: ReturnType<typeof shallowMount>, label: string) {
  return wrapper
    .findAll('.exec-summary__metric')
    .find(metric => metric.find('.exec-summary__metric-label').text() === label)
}

function dashboardMetricValue(wrapper: ReturnType<typeof shallowMount>, label: string) {
  return dashboardMetric(wrapper, label)?.find('.exec-summary__metric-value').text()
}

describe('shared lifecycle policy views', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    mockRoute.params.statusType = 'cancelled'
  })

  it('renders terminal and active lifecycle states distinctly', () => {
    const counts = { degraded: 4, canceled: 1, running: 2, pending: 3 }
    const progress = mount(ProgressBar, {
      props: { counts, excludeNotRan: true },
    })

    expect(progress.find('.nv-progress__segment--cancelled').exists()).toBe(true)
    expect(progress.find('.nv-progress__segment--warning').exists()).toBe(true)
    expect(progress.find('.nv-progress__segment--running').exists()).toBe(true)
    expect(progress.find('.nv-progress__segment--pending').exists()).toBe(true)

    const chart = shallowMount(StatusPieChart, { props: { counts } })
    const chartData = chart.findComponent({ name: 'Doughnut' }).props('data') as {
      labels: string[]
      datasets: Array<{ data: number[] }>
    }
    expect(chartData.labels).toEqual(['Degraded', 'Cancelled', 'Running', 'Pending'])
    expect(chartData.datasets[0].data).toEqual([4, 1, 2, 3])
  })

  it('includes degraded counts in copied DUT evidence', () => {
    const text = formatDutForTicket({
      id: 'dut-1',
      baseboard: 'GB200',
      overall_status: 'degraded',
      status_summary: {
        success: 2,
        degraded: 1,
        error: 0,
        partial: 0,
        skipped: 0,
        not_ran: 0,
      },
      execution_time: 3,
      log_size: 1024,
      system_info: null,
    } as any)

    expect(text).toContain('2 passed, 1 degraded, 0 failed')
  })

  it('keeps degraded timing entries in the status accumulator', () => {
    vi.stubGlobal('IntersectionObserver', class {
      observe() {}
      disconnect() {}
    })
    const store = useManifestStore()
    store.loadFromJson({
      timing: {
        total_duration: 10,
        component_timing: {},
        per_service: [],
        per_dut: [{
          dut_id: 'dut-1',
          duration: 10,
          collectors: [{
            id: 'R1',
            name: 'Usable Payload',
            group: 'redfish',
            duration: 10,
            start_time: null,
            end_time: null,
            status: 'degraded',
            stage_timing: {
              validation: null,
              discovery: null,
              execution: null,
              post_processing: null,
            },
          }],
        }],
      },
    })

    const wrapper = shallowMount(TimingView, {
      global: { stubs: { RouterLink: true } },
    })
    const degraded = wrapper.findAllComponents(StatCard)
      .find(card => card.props('label') === 'Degraded Collectors')

    expect(degraded?.props('value')).toBe(1)
    vi.unstubAllGlobals()
  })

  it('uses only terminal outcomes for the dashboard pass rate', () => {
    loadSummary({ success: 1, cancelled: 1, running: 20, pending: 30 })

    const wrapper = shallowMount(DashboardView, {
      global: { stubs: { RouterLink: true } },
    })
    const passRate = dashboardMetric(wrapper, 'Pass Rate')

    expect(passRate?.find('.exec-summary__metric-value').text()).toBe('50%')
    expect(passRate?.attributes('title')).toContain('1 passed / 2 completed')
    expect(wrapper.text()).toContain('Cancelled: 1')
    expect(wrapper.text()).toContain('Running: 20')
    expect(wrapper.text()).toContain('Pending: 30')
  })

  it('shows a terminal dashboard error instead of an endless loader', () => {
    const store = useManifestStore()
    store.loadError = 'Failed to load manifest: canonical status mismatch'

    const wrapper = shallowMount(DashboardView, {
      global: { stubs: { RouterLink: true } },
    })

    expect(wrapper.findComponent(PageLoader).exists()).toBe(false)
    expect(wrapper.findComponent(EmptyState).props()).toMatchObject({
      icon: 'error',
      title: 'Dashboard unavailable',
      description: store.loadError,
    })
  })

  it('labels an active-only dashboard as in progress', () => {
    loadSummary({ running: 2, pending: 3 })

    const wrapper = shallowMount(DashboardView, {
      global: { stubs: { RouterLink: true } },
    })
    const passRate = dashboardMetric(wrapper, 'Pass Rate')

    expect(passRate?.find('.exec-summary__metric-value').text()).toBe('In progress')
    expect(passRate?.attributes('title')).toContain('0 passed / 0 completed')
  })

  it('projects degraded collectors as a first-class dashboard status', () => {
    loadSummary({ success: 1, degraded: 2 })

    const wrapper = shallowMount(DashboardView, {
      global: { stubs: { RouterLink: true } },
    })

    expect(dashboardMetricValue(wrapper, 'Degraded')).toBe('2')
    expect(dashboardMetricValue(wrapper, 'Pass Rate')).toBe('33%')
  })

  it('uses the same policy for active-only service health', () => {
    const store = useManifestStore()
    store.loadFromJson({
      duts: [
        {
          id: 'dut-1',
          collector_groups: [
            {
              name: 'Redfish',
              service_type: 'redfish',
              collectors: [
                { status: 'running', execution_time: 10 },
                { status: 'pending', execution_time: 0 },
              ],
            },
          ],
        },
      ],
    })

    const wrapper = shallowMount(ServiceHealthView, {
      global: { stubs: { RouterLink: true } },
    })

    expect(wrapper.text()).toContain('In progress')
    expect(wrapper.text()).toContain('0 completed')
    expect(wrapper.text()).toContain('1 running')
    expect(wrapper.text()).toContain('1 pending')
  })

  it('shows degraded service health as a distinct terminal count', () => {
    const store = useManifestStore()
    store.loadFromJson({
      duts: [
        {
          id: 'dut-1',
          collector_groups: [
            {
              name: 'Redfish',
              service_type: 'redfish',
              collectors: [
                { status: 'success', execution_time: 5 },
                { status: 'degraded', execution_time: 5 },
              ],
            },
          ],
        },
      ],
    })

    const wrapper = shallowMount(ServiceHealthView, {
      global: { stubs: { RouterLink: true } },
    })

    expect(wrapper.text()).toContain('1 degraded')
    expect(wrapper.find('.sh-card__bar-fill--degraded').exists()).toBe(true)
    expect(wrapper.text()).toContain('50%')
  })

  it('shows canonical lifecycle states in the coverage matrix', () => {
    const store = useManifestStore()
    store.loadFromJson({
      duts: [
        {
          id: 'dut-1',
          collector_groups: [
            {
              name: 'Redfish',
              collectors: [
                {
                  id: 'collector-1',
                  status: 'canceled',
                  execution_time: 0,
                  reason: 'collection stopped',
                },
                {
                  id: 'collector-2',
                  status: 'degraded',
                  execution_time: 1,
                  reason: 'usable primary evidence with optional failures',
                },
              ],
            },
          ],
        },
      ],
    })

    const wrapper = shallowMount(CoverageMatrixView)

    expect(wrapper.find('.cm-cell--cancelled').exists()).toBe(true)
    expect(wrapper.find('.cm-cell--degraded').exists()).toBe(true)
    expect(wrapper.text()).toContain('Degraded')
    expect(wrapper.text()).toContain('Cancelled')
    expect(wrapper.text()).toContain('Running')
    expect(wrapper.text()).toContain('Pending')
  })

  it('includes legacy cancellation records in the canonical status view', () => {
    const store = useManifestStore()
    store.loadFromJson({
      duts: [
        {
          id: 'dut-1',
          collector_groups: [
            {
              name: 'Redfish',
              collectors: [
                {
                  id: 'collector-1',
                  name: 'Collector 1',
                  status: 'canceled',
                  execution_time: 0,
                  reason: 'collection stopped',
                },
              ],
            },
          ],
        },
      ],
    })

    const wrapper = shallowMount(StatusDetailView)
    const rows = wrapper.findComponent(DataTable).props('data') as Array<{
      status: string
    }>

    expect(rows).toHaveLength(1)
    expect(rows[0].status).toBe('cancelled')
  })
})
