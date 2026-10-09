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

import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import CollectorFileTable from '@/components/collector/CollectorFileTable.vue'
import { useFileSystemStore } from '@/stores/fileSystem'
import type { FileRef } from '@/types/manifest'

const wrappers: Array<ReturnType<typeof mount>> = []
const artifact: FileRef = {
  path: 'DUT_1/redfish/inventory #1?.json', size: 200_000_000, type: 'json', collector_id: 'R1',
}

beforeEach(() => {
  setActivePinia(createPinia())
  vi.useFakeTimers()
  vi.stubGlobal('ResizeObserver', class {
    observe() {}
    unobserve() {}
    disconnect() {}
  })
})
afterEach(() => {
  for (const wrapper of wrappers.splice(0)) wrapper.unmount()
  vi.runOnlyPendingTimers()
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

async function render(file: FileRef = artifact) {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:path(.*)', component: { template: '<div />' } }] })
  await router.push('/dut/DUT_1/redfish/R1')
  const wrapper = mount(CollectorFileTable, {
    props: { files: [file], stateKey: 'artifacts' },
    global: { plugins: [router], stubs: { DirectoryPicker: true } },
  })
  wrappers.push(wrapper)
  return wrapper
}

describe('collector artifact actions', () => {
  it('provides explicit viewer and encoded same-origin download links without fetching the artifact', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    const wrapper = await render()
    const open = wrapper.get('a[aria-label="Open inventory #1?.json"]')
    expect(open.attributes('href')).toBe('/file/DUT_1%2Fredfish%2Finventory%20%231%3F.json')
    const download = wrapper.get('a[download]')
    expect(download.attributes('href')).toMatch(/\/DUT_1\/redfish\/inventory%20%231%3F\.json$/)
    expect(new URL(download.attributes('href')).origin).toBe(window.location.origin)
    expect(download.attributes('download')).toBe('inventory #1?.json')
    expect(fetchMock).not.toHaveBeenCalled()
    expect(wrapper.get('tbody').text()).toContain('Not recorded')
    expect(wrapper.find('button[aria-label^="Timing details"]').exists()).toBe(false)
  })

  it.each(['../secret', '/outside', 'https://example.invalid/file', 'DUT_1/../secret', 'DUT_1\\secret', 'DUT_1/\u0000secret'])(
    'does not offer a download outside the report for invalid path %j', async path => {
      const wrapper = await render({ ...artifact, path })
      expect(wrapper.find('a[download]').exists()).toBe(false)
      expect(wrapper.get('button[aria-label^="Download "]').attributes('disabled')).toBeDefined()
    },
  )

  it('shows shared timing attribution in the row without inventing a file duration', async () => {
    const wrapper = await render({
      ...artifact, measurement: 'redfish_request', measurement_quality: 'measured',
      measurement_scope: 'shared_requests', shared_request_operation_count: 2, duration_seconds: null,
    })
    const row = wrapper.get('tbody tr')
    expect(row.text()).toContain('Shared requests (2 requests)')
    expect(row.text()).toContain('Shared timing')
    expect(row.text()).not.toContain('Not recorded')
    expect(row.get('button[aria-label^="Timing details"]').text()).toBe('Timing details')
  })

  it('allows reopening after Escape before the previous native close event arrives', async () => {
    const wrapper = await render({ ...artifact, duration_seconds: 1.5, measurement: 'file_transfer' })
    const dialog = document.querySelector('dialog')!
    // jsdom does not implement the native dialog methods or queued close event.
    dialog.showModal = () => { dialog.open = true }
    dialog.close = () => {
      dialog.open = false
      setTimeout(() => dialog.dispatchEvent(new Event('close')), 0)
    }
    const button = wrapper.get('button[aria-label^="Timing details"]')
    await button.trigger('click')
    await wrapper.vm.$nextTick()
    expect(dialog.open).toBe(true)

    const escape = new Event('cancel', { cancelable: true })
    dialog.dispatchEvent(escape)
    expect(escape.defaultPrevented).toBe(true)
    expect(dialog.open).toBe(false)
    await wrapper.vm.$nextTick()
    await button.trigger('click')
    await wrapper.vm.$nextTick()
    expect(dialog.open).toBe(true)

    vi.runOnlyPendingTimers()
    await wrapper.vm.$nextTick()
    expect(dialog.open).toBe(true)
    expect(dialog.textContent).toContain('inventory #1?.json')
  })

  it('waits for the selected folder, then downloads original binary File bytes and revokes the URL', async () => {
    const store = useFileSystemStore()
    store.mode = 'file'
    const wrapper = await render()
    const download = wrapper.get('button[aria-label^="Download "]')
    expect(download.attributes('disabled')).toBeDefined()
    expect(download.attributes('title')).toContain('Select the report folder')
    const file = new File([new Uint8Array([0, 255, 128])], 'inventory #1?.json')
    store.fileMap.set(artifact.path, file)
    store.directoryLoaded = true
    await wrapper.vm.$nextTick()
    const createUrl = vi.fn().mockReturnValue('blob:synthetic-download')
    const revokeUrl = vi.fn()
    vi.stubGlobal('URL', class extends URL {
      static createObjectURL = createUrl
      static revokeObjectURL = revokeUrl
    })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    expect(download.attributes('disabled')).toBeUndefined()
    await download.trigger('click')
    expect(createUrl).toHaveBeenCalledWith(file)
    expect(click).toHaveBeenCalledOnce()
    expect(click.mock.instances[0].download).toBe('inventory #1?.json')
    expect(revokeUrl).not.toHaveBeenCalled()
    vi.advanceTimersByTime(1000)
    expect(revokeUrl).toHaveBeenCalledWith('blob:synthetic-download')
  })

  it('explains when a file is missing from the selected offline folder', async () => {
    const store = useFileSystemStore()
    store.mode = 'file'
    store.directoryLoaded = true
    const wrapper = await render()
    expect(wrapper.text()).toContain('Missing from selected folder')
    expect(wrapper.get('button[aria-label^="Download "]').attributes('disabled')).toBeDefined()
  })
})
