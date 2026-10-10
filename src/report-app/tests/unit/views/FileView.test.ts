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
import FileView from '@/views/FileView.vue'
import { wordWrap } from '@/composables/useViewerPrefs'

vi.mock('@/components/viewers/MonacoViewer.vue', () => ({
  default: {
    name: 'MonacoViewer',
    template: '<div class="monaco-viewer-mock" />',
  },
}))

const state = vi.hoisted(() => ({
  route: {
    params: { encodedPath: 'dut-a%2Fhost%2Fone.json' } as Record<string, string | string[]>,
  },
  router: { push: vi.fn() },
  manifest: {
    fileIndex: [
      {
        path: 'dut-a/host/one.json',
        size: 10_000,
        type: 'json',
        dut_id: 'dut-a',
        collector_group: 'host',
        collector_id: 'H1',
        collector_name: 'Host inventory',
      },
      {
        path: 'dut-a/host/two.json',
        size: 20,
        type: 'json',
        dut_id: 'dut-a',
        collector_group: 'host',
        collector_id: 'H1',
        collector_name: 'Host inventory',
      },
      {
        path: 'dut-a/host/raw.log',
        size: 20,
        type: 'log',
        dut_id: 'dut-a',
        collector_group: 'host',
        collector_id: 'H2',
      },
      {
        path: 'dut-a/archive.zip',
        size: 50,
        type: 'binary',
        dut_id: 'dut-a',
        collector_group: 'host',
        collector_id: 'H3',
      },
    ],
  },
  fileSystem: {
    mode: 'http',
    directoryLoaded: false,
    needsDirectoryPicker: false,
    fileMap: new Map(),
  },
  loadFile: vi.fn(),
  setFileMap: vi.fn(),
  copyToClipboard: vi.fn(),
  showToast: vi.fn(),
}))

vi.mock('vue-router', () => ({
  useRoute: () => state.route,
  useRouter: () => state.router,
}))
vi.mock('@/stores/manifest', () => ({ useManifestStore: () => state.manifest }))
vi.mock('@/stores/fileSystem', () => ({ useFileSystemStore: () => state.fileSystem }))
vi.mock('@/services/dataLoader', () => ({
  DataLoader: class {
    loadFile = state.loadFile
    setFileMap = state.setFileMap
  },
}))
vi.mock('@/utils/clipboard', () => ({
  copyToClipboard: state.copyToClipboard,
}))
vi.mock('@/composables/useToast', () => ({ showToast: state.showToast }))

async function mountFileView() {
  const wrapper = shallowMount(FileView, {
    global: {
      stubs: {
        Teleport: true,
        Transition: false,
        ErrorBoundary: { template: '<div class="error-boundary"><slot /></div>' },
        RouterLink: { template: '<a><slot /></a>' },
      },
    },
  })
  await flushPromises()
  await nextTick()
  return wrapper
}

describe('FileView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useRealTimers()
    state.route.params = { encodedPath: 'dut-a%2Fhost%2Fone.json' }
    state.fileSystem.mode = 'http'
    state.fileSystem.directoryLoaded = false
    state.fileSystem.needsDirectoryPicker = false
    state.loadFile.mockResolvedValue('{"healthy":true}')
    state.copyToClipboard.mockResolvedValue(undefined)
    wordWrap.value = true
  })

  it('loads JSON and exposes metadata, copy, navigation, and display actions', async () => {
    const createObjectURL = vi.fn(() => 'blob:file-download')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', { ...URL, createObjectURL, revokeObjectURL })
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
    const wrapper = await mountFileView()

    expect(state.loadFile).toHaveBeenCalledWith(state.manifest.fileIndex[0])
    expect(wrapper.find('json-tree-viewer-stub').exists()).toBe(true)
    expect(wrapper.text()).toContain('File appears truncated')
    expect(wrapper.text()).toContain('9.8 KB')

    await wrapper.find('button[aria-label="File metadata"]').trigger('click')
    expect(wrapper.text()).toContain('dut-a/host/one.json')
    expect(wrapper.text()).toContain('Host inventory')

    await wrapper.find('button[aria-label="Toggle word wrap"]').trigger('click')
    expect(wordWrap.value).toBe(false)
    expect(state.showToast).toHaveBeenCalledWith('Word wrap off', 'info')

    await wrapper.find('button[aria-label="Next file"]').trigger('click')
    expect(state.router.push).toHaveBeenCalledWith(
      '/file/dut-a%2Fhost%2Ftwo.json',
    )

    await wrapper.find('button[aria-label="Copy file contents"]').trigger('click')
    await wrapper.find('button[aria-label="Copy shareable link"]').trigger('click')
    await flushPromises()
    expect(state.copyToClipboard).toHaveBeenCalledWith('{"healthy":true}')
    expect(state.copyToClipboard).toHaveBeenCalledWith(
      expect.stringContaining('#/file/dut-a%2Fhost%2Fone.json'),
    )

    vi.useFakeTimers()
    await wrapper.find('button[aria-label="Download file"]').trigger('click')
    expect(createObjectURL).toHaveBeenCalledOnce()
    expect(click).toHaveBeenCalledOnce()
    vi.advanceTimersByTime(500)
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:file-download')

    click.mockRestore()
    wrapper.unmount()
    vi.unstubAllGlobals()
  })

  it('falls back from invalid JSON and binary log content to safe viewers', async () => {
    state.loadFile.mockResolvedValueOnce('{invalid json')
    const invalidJson = await mountFileView()
    expect(invalidJson.text()).toContain('Invalid JSON — showing raw content')
    expect(invalidJson.find('monaco-viewer-stub').exists()).toBe(true)
    invalidJson.unmount()

    state.route.params = { encodedPath: 'dut-a%2Fhost%2Fraw.log' }
    state.loadFile.mockResolvedValueOnce('\uFFFD'.repeat(10) + 'binary')
    const binary = await mountFileView()
    expect(binary.text()).toContain('Binary content detected')
    expect(binary.find('hex-viewer-stub').exists()).toBe(true)
    binary.unmount()
  })

  it('reports typed and non-Error load failures and bounds retry controls', async () => {
    state.loadFile.mockRejectedValueOnce(new Error('read failed'))
    const wrapper = await mountFileView()
    expect(wrapper.text()).toContain('Failed to load file')
    expect(wrapper.text()).toContain('read failed')
    expect(wrapper.find('a[download]').exists()).toBe(true)

    state.loadFile.mockRejectedValueOnce('second failure')
    await wrapper.find('button').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('second failure')

    expect(wrapper.find('button').exists()).toBe(false)
    wrapper.unmount()
  })

  it('gates file-scheme reads and renders archive downloads without loading', async () => {
    state.fileSystem.mode = 'file'
    state.fileSystem.needsDirectoryPicker = true
    const gated = await mountFileView()
    expect(gated.text()).toContain('Select the report folder to view files')
    expect(state.loadFile).not.toHaveBeenCalled()
    gated.unmount()

    vi.clearAllMocks()
    state.fileSystem.mode = 'http'
    state.fileSystem.needsDirectoryPicker = false
    state.route.params = { encodedPath: 'dut-a%2Farchive.zip' }
    const archive = await mountFileView()
    expect(archive.find('download-card-stub').exists()).toBe(true)
    expect(state.loadFile).not.toHaveBeenCalled()
    expect(archive.text()).not.toContain('Copy file contents')
    archive.unmount()
  })

  it('owns keyboard shortcuts and removes document listeners on unmount', async () => {
    const wrapper = await mountFileView()

    document.dispatchEvent(new KeyboardEvent('keydown', { key: '?' }))
    await nextTick()
    expect(wrapper.text()).toContain('Keyboard Shortcuts')

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'F' }))
    await nextTick()
    expect(wrapper.classes()).toContain('fv-fullscreen')

    wrapper.unmount()
    state.showToast.mockClear()
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'W' }))
    expect(state.showToast).not.toHaveBeenCalled()
  })
})
