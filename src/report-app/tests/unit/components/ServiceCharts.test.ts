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
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import ServiceDistributionChart from '@/components/charts/ServiceDistributionChart.vue'
import ServiceTimeChart from '@/components/charts/ServiceTimeChart.vue'

vi.mock('vue-chartjs', () => ({
  Doughnut: {
    name: 'Doughnut',
    props: ['data', 'options'],
    template: '<div />',
  },
  Bar: {
    name: 'Bar',
    props: ['data', 'options'],
    template: '<div />',
  },
}))

const chartStubs = {
  EmptyState: {
    name: 'EmptyState',
    template: '<div />',
  },
}

describe('service charts', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('color-codes collector distribution slices by service', () => {
    const wrapper = shallowMount(ServiceDistributionChart, {
      props: {
        services: [
          { service: 'redfish', total_collectors: 4 },
          { service: 'ssh', total_collectors: 2 },
          { service: 'ipmi', total_collectors: 1 },
        ],
      },
      global: { stubs: chartStubs },
    })

    const data = wrapper.findComponent({ name: 'Doughnut' }).props('data') as any
    expect(data.datasets[0].backgroundColor).toEqual(['#dc6976b3', '#ffc107b3', '#0dcaf0b3'])
    expect(data.datasets[0].hoverBackgroundColor).toEqual(['#dc6976', '#ffc107', '#0dcaf0'])
  })

  it('color-codes execution time bars by service', () => {
    const wrapper = shallowMount(ServiceTimeChart, {
      props: {
        services: [
          { service: 'Redfish', total_duration: 10 },
          { service: 'health-check', total_duration: 5 },
          { service: 'host', total_duration: 3 },
        ],
      },
      global: { stubs: chartStubs },
    })

    const data = wrapper.findComponent({ name: 'Bar' }).props('data') as any
    expect(data.datasets[0].backgroundColor).toEqual(['#dc6976b3', '#6f42c1b3', '#28a745b3'])
    expect(data.datasets[0].borderColor).toEqual(['#dc6976', '#6f42c1', '#28a745'])
  })
})
