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

import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import CollectorRuntimeLogs from '@/components/collector/CollectorRuntimeLogs.vue'
import LogViewer from '@/components/viewers/LogViewer.vue'
import { loadCollectorRuntimeLogs, type CollectorLogPreview } from '@/services/collectorRuntimeLogs'
import { useManifestStore } from '@/stores/manifest'
import { useFileSystemStore } from '@/stores/fileSystem'
import fixture from '../../fixtures/sample_manifest.json'

vi.mock('@/services/collectorRuntimeLogs', () => ({ loadCollectorRuntimeLogs: vi.fn() }))

const path = 'DUT_1/nvdebug_runtime_output.txt'
const result = (content = '[time] [ERROR] [CID:R1] [redfish] request failed'): CollectorLogPreview => ({
  content, lineCount: content ? 1 : 0, bytesRead: 100,
  scanLimited: false, previewLimited: false, longLinesTruncated: false,
})
const wrappers: Array<ReturnType<typeof mount>> = []

beforeEach(() => {
  setActivePinia(createPinia())
  vi.mocked(loadCollectorRuntimeLogs).mockReset().mockResolvedValue(result())
})
afterEach(() => {
  for (const wrapper of wrappers.splice(0)) wrapper.unmount()
})

async function render(paths = [path]) {
  const manifest = JSON.parse(JSON.stringify(fixture))
  manifest.file_index = paths.map(filePath => ({
    path: filePath, size: 100, type: 'text', dut_id: filePath.split('/')[0], collector_id: '',
  }))
  useManifestStore().loadFromJson(manifest)
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:path(.*)', component: { template: '<div />' } }] })
  await router.push('/')
  const wrapper = mount(CollectorRuntimeLogs, {
    props: { dutId: 'DUT_1', collectorId: 'R1' },
    global: { plugins: [router] },
  })
  wrappers.push(wrapper)
  await flushPromises()
  return wrapper
}

describe('collector runtime log panel', () => {
  it('loads only the current DUT log and provides inline filters and a full-log link', async () => {
    const wrapper = await render(['nvdebug_runtime_output.txt', 'DUT_2/nvdebug_runtime_output.txt', path])
    expect(loadCollectorRuntimeLogs).toHaveBeenCalledTimes(1)
    expect(loadCollectorRuntimeLogs).toHaveBeenCalledWith(path, 'R1', expect.objectContaining({ mode: 'http' }))
    expect(wrapper.findComponent(LogViewer).props('height')).toBe('360px')
    expect(wrapper.get('a').attributes('href')).toBe('/file/DUT_1%2Fnvdebug_runtime_output.txt')
    expect(wrapper.get('input[aria-label="Search logs"]').exists()).toBe(true)
    expect(wrapper.get('.nv-log__content').text()).toContain('request failed')
  })

  it('distinguishes missing artifacts from logs without matching tags', async () => {
    const missing = await render(['DUT_2/nvdebug_runtime_output.txt'])
    expect(missing.text()).toContain('does not include a runtime log for this node')
    expect(loadCollectorRuntimeLogs).not.toHaveBeenCalled()
    missing.unmount()
    vi.mocked(loadCollectorRuntimeLogs).mockResolvedValue(result(''))
    const empty = await render()
    expect(empty.text()).toContain('No entries tagged for R1 were found')
    expect(empty.text()).toContain('cannot be attributed to this collector')
  })

  it('allows retry after a read failure', async () => {
    vi.mocked(loadCollectorRuntimeLogs).mockRejectedValueOnce(new Error('The runtime log could not be loaded (HTTP 404).'))
    const wrapper = await render()
    expect(wrapper.get('[role="alert"]').text()).toContain('HTTP 404')
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(loadCollectorRuntimeLogs).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
    expect(wrapper.get('.nv-log__content').text()).toContain('request failed')
  })

  it('waits for offline folder selection and then loads in place', async () => {
    const files = useFileSystemStore()
    files.mode = 'file'
    const wrapper = await render()
    expect(wrapper.text()).toContain('Select the report folder')
    expect(wrapper.find('input[webkitdirectory]').exists()).toBe(true)
    expect(loadCollectorRuntimeLogs).not.toHaveBeenCalled()
    files.directoryLoaded = true
    await flushPromises()
    expect(loadCollectorRuntimeLogs).toHaveBeenCalledWith(path, 'R1', expect.objectContaining({ mode: 'file' }))
    expect(wrapper.get('.nv-log__content').text()).toContain('request failed')
  })

  it('aborts prior requests and rejects stale results when switching collectors or leaving', async () => {
    let completeFirst!: (value: CollectorLogPreview) => void
    let completeSecond!: (value: CollectorLogPreview) => void
    vi.mocked(loadCollectorRuntimeLogs)
      .mockImplementationOnce(() => new Promise(resolve => { completeFirst = resolve }))
      .mockImplementationOnce(() => new Promise(resolve => { completeSecond = resolve }))
    const wrapper = await render()
    expect(wrapper.get('[role="status"]').text()).toContain('Loading collector runtime logs')
    await wrapper.setProps({ collectorId: 'R2' })
    const calls = vi.mocked(loadCollectorRuntimeLogs).mock.calls
    expect(calls[0][2].signal.aborted).toBe(true)
    completeFirst(result('STALE R1 LOGS'))
    await flushPromises()
    expect(wrapper.text()).not.toContain('STALE R1 LOGS')
    expect(wrapper.findComponent(LogViewer).exists()).toBe(false)
    wrapper.unmount()
    expect(calls[1][2].signal.aborted).toBe(true)
    completeSecond(result('R2 LOGS'))
    await flushPromises()
  })

  it('marks capped scans as partial instead of claiming no logs exist', async () => {
    vi.mocked(loadCollectorRuntimeLogs).mockResolvedValue({ ...result(''), scanLimited: true })
    const wrapper = await render()
    expect(wrapper.get('[role="status"]').text()).toContain('partial log preview')
    expect(wrapper.text()).toContain('No entries tagged for R1 were found in the scanned portion')
  })
})
