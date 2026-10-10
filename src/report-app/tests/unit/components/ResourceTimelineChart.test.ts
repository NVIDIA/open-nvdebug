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
import ResourceTimelineChart from '@/components/charts/ResourceTimelineChart.vue'
import { normalizeResourceSample } from '@/utils/resourceUsage'

vi.mock('vue-chartjs', () => ({
  Line: { name: 'Line', props: ['data', 'options'], template: '<div class="line-chart" />' },
}))

describe('ResourceTimelineChart', () => {
  it('keeps unavailable values null and divides recorded values for display', () => {
    const points = [
      normalizeResourceSample({ elapsed_seconds: 0, process: { rss_bytes: 1048576 } })!,
      normalizeResourceSample({ elapsed_seconds: 10, process: {} })!,
    ]
    const wrapper = shallowMount(ResourceTimelineChart, {
      props: {
        points,
        series: [{ key: 'rssBytes', label: 'RSS', color: '#76b900' }],
        yAxisTitle: 'MiB',
        divisor: 1048576,
        accessibilityLabel: 'Memory timeline',
      },
    })
    const data = wrapper.findComponent({ name: 'Line' }).props('data') as any

    expect(data.datasets[0].data).toEqual([{ x: 0, y: 1 }, { x: 10, y: null }])
    expect(data.datasets[0].spanGaps).toBe(false)
    expect(wrapper.get('.resource-chart').attributes('role')).toBe('img')
    expect(wrapper.get('.resource-chart').attributes('aria-label')).toContain('Elapsed range 0.0s to 10s')
    expect(wrapper.get('figcaption').text()).toContain('RSS: minimum 1.00, maximum 1.00')
    expect((wrapper.findComponent({ name: 'Line' }).props('options') as any).scales.x.type).toBe('linear')
  })

  it('renders the explicit unavailable state when every point lacks the metric', () => {
    const wrapper = shallowMount(ResourceTimelineChart, {
      props: {
        points: [normalizeResourceSample({ elapsed_seconds: 0, process: {} })!],
        series: [{ key: 'rssBytes', label: 'RSS', color: '#76b900' }],
        yAxisTitle: 'MiB',
        accessibilityLabel: 'Memory timeline',
      },
    })

    expect(wrapper.findComponent({ name: 'Line' }).exists()).toBe(false)
    expect(wrapper.findComponent({ name: 'EmptyState' }).props('title')).toBe('Metric unavailable')
  })
})
