import { shallowMount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import CollectorMetricTrendCard from '@/components/charts/CollectorMetricTrendCard.vue'

vi.mock('vue-chartjs', () => ({
  Line: {
    name: 'Line',
    props: ['data', 'options'],
    template: '<div />',
  },
}))

const items = [
  {
    index: 1,
    id: 'R1',
    name: 'Inventory',
    group: 'Redfish',
    dutId: 'DUT_A',
    value: 3,
  },
  {
    index: 2,
    id: 'H6',
    name: 'Bug Report',
    group: 'Host',
    dutId: 'DUT_A',
    value: 120,
  },
  {
    index: 3,
    id: 'R37',
    name: 'Debug Dump',
    group: 'Redfish',
    dutId: 'DUT_B',
    value: 40,
  },
]

const manyItems = Array.from({ length: 20 }, (_, i) => ({
  index: i + 1,
  id: `C${i + 1}`,
  name: `Collector ${i + 1}`,
  group: i % 2 === 0 ? 'Redfish' : 'Host',
  dutId: 'DUT_A',
  value: i + 1,
}))

describe('CollectorMetricTrendCard', () => {
  it('renders a collector-order line chart with highlighted top values', () => {
    const wrapper = shallowMount(CollectorMetricTrendCard, {
      props: {
        title: 'Collector Timing',
        yAxisTitle: 'Time',
        topTitle: 'Slowest Collectors',
        unitLabel: 'seconds',
        items,
        topLimit: 1,
        formatValue: (value: number) => `${value}s`,
      },
    })

    const data = wrapper.findComponent({ name: 'Line' }).props('data') as any
    expect(data.labels).toEqual(['1', '2', '3'])
    expect(data.datasets[0].data).toEqual([3, 120, 40])
    expect(data.datasets[0].pointBackgroundColor[1]).toBe('#76b900')
    expect(data.datasets[0].pointBackgroundColor[0]).not.toBe('#76b900')
  })

  it('shows top collectors in descending value order', () => {
    const wrapper = shallowMount(CollectorMetricTrendCard, {
      props: {
        title: 'Collector Size',
        yAxisTitle: 'Size',
        topTitle: 'Largest Collectors',
        unitLabel: 'bytes',
        items,
        formatValue: (value: number) => `${value} B`,
      },
    })

    const text = wrapper.text()
    expect(text.indexOf('2. Host / Bug Report')).toBeLessThan(text.indexOf('3. Redfish / Debug Dump'))
    expect(text).toContain('120 B')
  })

  it('zooms the chart around a clicked top-list row and can reset', async () => {
    const wrapper = shallowMount(CollectorMetricTrendCard, {
      props: {
        title: 'Collector Timing',
        yAxisTitle: 'Time',
        topTitle: 'Slowest Collectors',
        unitLabel: 'seconds',
        items: manyItems,
        topLimit: 1,
        formatValue: (value: number) => `${value}s`,
      },
    })

    expect((wrapper.findComponent({ name: 'Line' }).props('data') as any).labels).toHaveLength(20)

    await wrapper.find('button.collector-metric__item').trigger('click')
    const zoomedData = wrapper.findComponent({ name: 'Line' }).props('data') as any
    expect(zoomedData.labels).toEqual(['14', '15', '16', '17', '18', '19', '20'])
    expect(wrapper.text()).toContain('Zoomed to 20')

    await wrapper.find('button.collector-metric__reset').trigger('click')
    expect((wrapper.findComponent({ name: 'Line' }).props('data') as any).labels).toHaveLength(20)
  })
})
