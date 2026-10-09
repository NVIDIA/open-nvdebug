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

import { shallowMount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import ConcurrencyTimelineChart from '@/components/charts/ConcurrencyTimelineChart.vue'
import type { ConcurrencyDecisionPoint } from '@/types/concurrencyScheduler'

vi.mock('vue-chartjs', () => ({
  Line: { name: 'Line', props: ['data', 'options'], template: '<div class="line-chart" />' },
}))

const points: ConcurrencyDecisionPoint[] = [
  {
    timestamp: null,
    elapsedSeconds: 0,
    action: 'start',
    previousLimit: 5,
    newLimit: 5,
    reasons: ['mode_adaptive'],
    signals: null,
    progress: { admissions: 0, completedOperations: 0, activeOperations: 0, activeWeight: 0, queuedOperations: 0 },
    cumulativeCompletedOperations: 0,
  },
  {
    timestamp: null,
    elapsedSeconds: 60,
    action: 'increase',
    previousLimit: 5,
    newLimit: 6,
    reasons: ['consecutive_healthy_windows'],
    signals: null,
    progress: { admissions: 160, completedOperations: 155, activeOperations: 5, activeWeight: 5, queuedOperations: 20 },
    cumulativeCompletedOperations: 155,
  },
]

describe('ConcurrencyTimelineChart', () => {
  it('plots capacity, active, queued, and completion history on bounded axes', () => {
    const wrapper = shallowMount(ConcurrencyTimelineChart, {
      props: { points, plannedOperations: 324 },
    })
    const chart = wrapper.findComponent({ name: 'Line' })
    const data = chart.props('data') as any

    expect(data.datasets.map((dataset: { label: string }) => dataset.label)).toEqual([
      'Weighted capacity',
      'Active operations',
      'Queued operations',
      'Completed operations',
    ])
    expect(data.datasets[1].data).toEqual([{ x: 0, y: 0 }, { x: 60, y: 5 }])
    expect(data.datasets[2].data).toEqual([{ x: 0, y: 0 }, { x: 60, y: 20 }])
    expect(wrapper.get('.concurrency-chart').attributes('aria-label')).toContain('155 of 324')
    expect(wrapper.get('figcaption').text()).toContain('20 queued')
  })

  it('renders an explicit unavailable state without decision points', () => {
    const wrapper = shallowMount(ConcurrencyTimelineChart, {
      props: { points: [], plannedOperations: 0 },
    })

    expect(wrapper.findComponent({ name: 'Line' }).exists()).toBe(false)
    expect(wrapper.findComponent({ name: 'EmptyState' }).props('title')).toBe('Decision timeline unavailable')
  })

  it('does not render absent legacy progress snapshots as zero activity', () => {
    const wrapper = shallowMount(ConcurrencyTimelineChart, {
      props: {
        points: points.map(point => ({ ...point, progress: null })),
        plannedOperations: 324,
      },
    })

    expect(wrapper.get('.concurrency-chart').attributes('aria-label')).toContain(
      'Active and queued operation snapshots are unavailable',
    )
    expect(wrapper.get('.concurrency-chart').attributes('aria-label')).not.toContain('with 0 active')
  })
})
