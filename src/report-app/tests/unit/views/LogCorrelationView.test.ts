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

import { flushPromises, shallowMount } from '@vue/test-utils'
import { nextTick } from 'vue'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import LogCorrelationView from '@/views/LogCorrelationView.vue'

const state = vi.hoisted(() => ({
  router: { push: vi.fn() },
  manifest: {
    duts: [{ id: 'dut-a' }, { id: 'dut-b' }],
    fileIndex: [
      {
        path: 'dut-a/nvdebug_runtime.log',
        collector_id: 'R1',
        dut_id: 'dut-a',
        size: 900,
        type: 'log',
      },
      {
        path: 'dut-a/system.log',
        collector_id: 'H1',
        dut_id: 'dut-a',
        size: 2_048,
        type: 'text',
      },
      {
        path: 'dut-b/nvdebug_output.txt',
        collector_id: 'S1',
        dut_id: 'dut-b',
        size: 2_000_000,
        type: 'text',
      },
      {
        path: 'dut-b/archive.bin',
        collector_id: 'H2',
        dut_id: 'dut-b',
        size: 10,
        type: 'binary',
      },
      {
        path: 'dut-b/too-large.log',
        collector_id: 'H3',
        dut_id: 'dut-b',
        size: 50_000_001,
        type: 'log',
      },
    ],
  },
  fileSystem: {
    mode: 'http',
    directoryLoaded: false,
    fileMap: new Map(),
  },
  loadFile: vi.fn(),
  setFileMap: vi.fn(),
}))

vi.mock('vue-router', () => ({ useRouter: () => state.router }))
vi.mock('@/stores/manifest', () => ({ useManifestStore: () => state.manifest }))
vi.mock('@/stores/fileSystem', () => ({ useFileSystemStore: () => state.fileSystem }))
vi.mock('@/services/dataLoader', () => ({
  DataLoader: class {
    loadFile = state.loadFile
    setFileMap = state.setFileMap
  },
}))

class ResizeObserverStub {
  observe = vi.fn()
  disconnect = vi.fn()
}

async function mountCorrelator() {
  vi.stubGlobal('ResizeObserver', ResizeObserverStub)
  const wrapper = shallowMount(LogCorrelationView, {
    global: {
      stubs: {
        Teleport: true,
        Transition: false,
      },
    },
  })
  await nextTick()
  await nextTick()
  await flushPromises()
  await nextTick()
  return wrapper
}

describe('LogCorrelationView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    state.manifest.duts = [{ id: 'dut-a' }, { id: 'dut-b' }]
    state.fileSystem.mode = 'http'
    state.fileSystem.directoryLoaded = false
    state.loadFile.mockImplementation(async (file: { path: string }) => {
      if (file.path.includes('dut-a')) {
        return [
          '2026-08-19T01:02:03Z [ERROR] redfish failed',
          '2026-08-19T01:02:05Z [INFO] redfish recovered',
        ].join('\n')
      }
      return '2026-08-19T01:02:04Z [WARNING] ssh delayed'
    })
  })

  it('auto-correlates runtime logs and supports event filtering and navigation', async () => {
    const wrapper = await mountCorrelator()

    expect(state.loadFile).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('3 events correlated')
    expect(wrapper.text()).toContain('2 files')
    expect(wrapper.text()).toContain('Redfish')
    expect(wrapper.text()).toContain('SSH / BMC')
    expect(wrapper.text()).not.toContain('archive.bin')
    expect(wrapper.text()).not.toContain('too-large.log')

    const search = wrapper.find('input[placeholder="Search events..."]')
    await search.setValue('recovered')
    expect(wrapper.text()).toContain('1 events')

    await search.setValue('')
    const errorLevel = wrapper.findAll('.corr-lvl-pill')[0]
    await errorLevel.trigger('click')
    expect(wrapper.text()).not.toContain('redfish failed')
    await errorLevel.trigger('click')

    const category = wrapper.findAll('.corr-cat-chip')[0]
    await category.trigger('click')
    expect(wrapper.findAll('.corr-list__row').length).toBeGreaterThan(0)

    const row = wrapper.find('.corr-list__row')
    await row.trigger('click')
    expect(wrapper.text()).toContain('Event Detail')
    await row.trigger('dblclick')
    expect(state.router.push).toHaveBeenCalledWith(
      expect.stringMatching(/^\/file\/dut-[ab]%2F/),
    )
  })

  it('re-scopes files and uses a caller-selected directory map', async () => {
    state.fileSystem.mode = 'file'
    state.fileSystem.directoryLoaded = true
    const wrapper = await mountCorrelator()

    expect(state.setFileMap).toHaveBeenCalledWith(state.fileSystem.fileMap)
    const scope = wrapper.find('select')
    await scope.setValue('dut-a')
    await nextTick()
    await nextTick()
    await flushPromises()

    expect(wrapper.text()).toContain('dut-a')
    expect(wrapper.text()).not.toContain('dut-b/nvdebug_output.txt')
    wrapper.unmount()
  })

  it('reports no timestamped events while tolerating one unreadable file', async () => {
    state.loadFile.mockRejectedValueOnce(new Error('unreadable'))
    state.loadFile.mockResolvedValue('plain text without timestamp')

    const wrapper = await mountCorrelator()
    await wrapper.find('.corr-controls__actions button').trigger('click')
    await flushPromises()
    await nextTick()

    expect(wrapper.find('empty-state-stub').attributes('title'))
      .toBe('No timestamped events found')
    expect(wrapper.text()).not.toContain('Processing Logs')
    wrapper.unmount()
  })

  it('limits an initial wide fleet scope to the first DUT', async () => {
    state.manifest.duts = [
      { id: 'dut-a' },
      { id: 'dut-b' },
      { id: 'dut-c' },
      { id: 'dut-d' },
    ]

    const wrapper = await mountCorrelator()

    expect((wrapper.find('select').element as HTMLSelectElement).value).toBe('dut-a')
    expect(state.loadFile).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })
})
