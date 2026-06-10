import { shallowMount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
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
