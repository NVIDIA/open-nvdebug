import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import VerticalExecutionTimeline from '@/components/charts/VerticalExecutionTimeline.vue'

vi.mock('vue-router', () => ({
  useRouter: () => ({
    push: vi.fn(),
  }),
}))

const stageTiming = {
  validation: 1,
  discovery: 2,
  execution: 3,
  post_processing: 4,
}

const perDut = [
  {
    dut_id: 'DUT_A',
    duration: 125,
    collectors: [
      {
        id: 'R1',
        name: 'System Inventory',
        group: 'redfish',
        duration: 10,
        start_time: '2026-05-13T20:00:00Z',
        end_time: '2026-05-13T20:00:10Z',
        status: 'success',
        stage_timing: stageTiming,
      },
      {
        id: 'R37',
        name: 'GPU Debug Dump',
        group: 'redfish',
        duration: 90,
        start_time: '2026-05-13T20:00:20Z',
        end_time: '2026-05-13T20:01:50Z',
        status: 'partial',
        stage_timing: {
          validation: 1,
          discovery: 1,
          execution: 84,
          post_processing: 4,
        },
      },
    ],
  },
  {
    dut_id: 'DUT_B',
    duration: 25,
    collectors: [
      {
        id: 'H1',
        name: 'Host Logs',
        group: 'host',
        duration: 25,
        start_time: '2026-05-13T20:02:00Z',
        end_time: '2026-05-13T20:02:25Z',
        status: 'success',
        stage_timing: stageTiming,
      },
    ],
  },
]

describe('VerticalExecutionTimeline', () => {
  it('defaults to one DUT and explains the collector timeline', () => {
    const wrapper = mount(VerticalExecutionTimeline, {
      props: {
        perDut,
        totalDuration: 160,
      },
    })

    expect((wrapper.find('select[title="Filter by DUT"]').element as HTMLSelectElement).value).toBe('DUT_A')
    expect(wrapper.text()).toContain('Collector Run Timeline')
    expect(wrapper.text()).toContain('2 collectors')
    expect(wrapper.text()).toContain('1 DUT')
    expect(wrapper.text()).toContain('Active Collector Time')
    expect(wrapper.text()).toContain('Longest Collector')
    expect(wrapper.text()).toContain('R37')
  })

  it('calls out idle gaps and runtime hotspots for the selected DUT', () => {
    const wrapper = mount(VerticalExecutionTimeline, {
      props: {
        perDut,
        totalDuration: 160,
      },
    })

    expect(wrapper.text()).toContain('Idle Gap')
    expect(wrapper.text()).toContain('Runtime Hotspot')
    expect(wrapper.text()).toContain('Slowest')
  })

  it('makes run position map dots navigate to collector cards', async () => {
    const scrollIntoView = vi.fn()
    const originalGetElementById = document.getElementById.bind(document)
    const getElementById = vi.spyOn(document, 'getElementById').mockImplementation((id: string) => {
      if (id === 'timeline-event-DUT_A-R37-1778702420000') {
        return { scrollIntoView } as unknown as HTMLElement
      }
      return originalGetElementById(id)
    })

    const wrapper = mount(VerticalExecutionTimeline, {
      props: {
        perDut,
        totalDuration: 160,
      },
    })

    const dots = wrapper.findAll('button.vexec__dot')
    expect(dots).toHaveLength(2)
    await dots[1].trigger('click')

    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: 'smooth', block: 'center' })
    getElementById.mockRestore()
  })
})
