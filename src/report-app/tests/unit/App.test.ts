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
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from '@/App.vue'

const state = vi.hoisted(() => ({
  route: {
    name: 'file' as string,
    params: { encodedPath: 'dut-a%2Fsystem.log' } as Record<string, string>,
  },
  router: {
    push: vi.fn(),
    back: vi.fn(),
    isReady: vi.fn(async () => undefined),
  },
  theme: {
    theme: 'dark',
    init: vi.fn(),
    toggle: vi.fn(),
  },
  manifest: {
    loaded: true,
    loadError: null as string | null,
    generatedAt: '2026-08-19T00:00:00Z',
    toolVersion: '2.2.0',
    fileIndex: [{ path: 'dut-a/system.log' }],
    manifest: { duts: [{ id: 'dut-a' }] },
    loadInitial: vi.fn(async () => undefined),
  },
  fileSystem: {
    mode: 'http',
    integrityOk: true,
    integrityStatus: null as null | {
      missing: string[]
      checked: number
      total: number
    },
    checkHttpIntegrity: vi.fn(async () => undefined),
    cancelHttpIntegrityCheck: vi.fn(),
  },
  search: { grepPanelOpen: false },
  annotations: { init: vi.fn() },
  startup: {
    reportProgress: vi.fn(async () => undefined),
    finish: vi.fn(),
    fail: vi.fn(),
  },
}))

vi.mock('vue-router', () => ({
  useRoute: () => state.route,
  useRouter: () => state.router,
}))
vi.mock('@/stores/theme', () => ({ useThemeStore: () => state.theme }))
vi.mock('@/stores/manifest', () => ({ useManifestStore: () => state.manifest }))
vi.mock('@/stores/fileSystem', () => ({ useFileSystemStore: () => state.fileSystem }))
vi.mock('@/stores/search', () => ({ useSearchStore: () => state.search }))
vi.mock('@/stores/annotations', () => ({
  useAnnotationsStore: () => state.annotations,
}))
vi.mock('@/services/reportStartup', () => ({
  createReportLoadReporter: () => state.startup.reportProgress,
  finishReportStartup: () => state.startup.finish(),
  failReportStartup: () => state.startup.fail(),
  yieldForPaint: async () => undefined,
}))

async function mountReadyApp() {
  const wrapper = shallowMount(App, {
    global: {
      stubs: {
        RouterView: { template: '<div class="route-content" />' },
      },
    },
  })
  await flushPromises()
  return wrapper
}

describe('App bootstrap and shortcuts', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    state.route.name = 'file'
    state.route.params = { encodedPath: 'dut-a%2Fsystem.log' }
    state.theme.theme = 'dark'
    state.manifest.loaded = true
    state.manifest.loadError = null
    state.manifest.loadInitial.mockResolvedValue(undefined)
    state.manifest.generatedAt = '2026-08-19T00:00:00Z'
    state.fileSystem.mode = 'http'
    state.fileSystem.integrityOk = true
    state.fileSystem.integrityStatus = null
    state.fileSystem.checkHttpIntegrity.mockResolvedValue(undefined)
    state.search.grepPanelOpen = false
  })

  it('initializes stores, checks HTTP integrity, and removes ownership on unmount', async () => {
    const wrapper = await mountReadyApp()

    expect(wrapper.find('#app').exists()).toBe(true)
    expect(wrapper.find('#app').attributes('data-theme')).toBe('dark')
    expect(state.theme.init).toHaveBeenCalledOnce()
    expect(state.manifest.loadInitial).toHaveBeenCalledOnce()
    expect(state.manifest.loadInitial).toHaveBeenCalledWith(state.startup.reportProgress)
    expect(state.startup.reportProgress).toHaveBeenCalledWith({ stage: 'rendering' })
    expect(state.startup.finish).toHaveBeenCalledOnce()
    expect(state.fileSystem.checkHttpIntegrity).toHaveBeenCalledWith(
      state.manifest.fileIndex,
    )
    expect(state.annotations.init).toHaveBeenCalledWith(
      '2026-08-19T00:00:00Z',
    )
    expect(wrapper.text()).toContain('NVDebug v2.2.0')
    expect(wrapper.text()).toContain('1 DUTs')

    wrapper.unmount()
    expect(state.fileSystem.cancelHttpIntegrityCheck).toHaveBeenCalledOnce()
  })

  it('retains the startup screen while the manifest is pending', async () => {
    let resolveLoad!: () => void
    state.manifest.loadInitial.mockReturnValueOnce(new Promise(resolve => { resolveLoad = resolve }))
    const wrapper = await mountReadyApp()

    expect(wrapper.find('#app').exists()).toBe(false)
    expect(state.startup.finish).not.toHaveBeenCalled()
    resolveLoad()
    await flushPromises()

    expect(wrapper.find('.route-content').exists()).toBe(true)
    expect(state.startup.finish).toHaveBeenCalledOnce()
    wrapper.unmount()
  })

  it('shows a recovery state if initialization unexpectedly fails', async () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    state.manifest.loadInitial.mockRejectedValueOnce(new Error('startup failed'))
    const wrapper = await mountReadyApp()

    expect(state.startup.fail).toHaveBeenCalledOnce()
    expect(state.startup.finish).not.toHaveBeenCalled()
    wrapper.unmount()
    consoleError.mockRestore()
  })

  it('does not finish startup or attach shortcuts after unmounting a pending load', async () => {
    let resolveLoad!: () => void
    state.manifest.loadInitial.mockReturnValueOnce(new Promise(resolve => { resolveLoad = resolve }))
    const wrapper = await mountReadyApp()
    wrapper.unmount()
    resolveLoad()
    await flushPromises()

    expect(state.startup.finish).not.toHaveBeenCalled()
    expect(state.fileSystem.checkHttpIntegrity).not.toHaveBeenCalled()
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 't' }))
    expect(state.theme.toggle).not.toHaveBeenCalled()
  })

  it('routes global shortcuts while ignoring editable targets', async () => {
    const wrapper = await mountReadyApp()

    window.dispatchEvent(new KeyboardEvent('keydown', {
      key: 'F', ctrlKey: true, shiftKey: true,
    }))
    expect(state.search.grepPanelOpen).toBe(true)

    window.dispatchEvent(new KeyboardEvent('keydown', { key: 't' }))
    expect(state.theme.toggle).toHaveBeenCalledOnce()

    const split = new KeyboardEvent('keydown', {
      key: '\\', ctrlKey: true, cancelable: true,
    })
    window.dispatchEvent(split)
    expect(split.defaultPrevented).toBe(true)
    expect(state.router.push).toHaveBeenCalledWith({
      name: 'split-file',
      query: { left: 'dut-a%2Fsystem.log' },
    })

    state.route.name = 'split-file'
    window.dispatchEvent(new KeyboardEvent('keydown', { key: '\\', ctrlKey: true }))
    expect(state.router.back).toHaveBeenCalledOnce()

    const input = document.createElement('input')
    wrapper.element.appendChild(input)
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 't', bubbles: true }))
    expect(state.theme.toggle).toHaveBeenCalledOnce()
    wrapper.unmount()
  })

  it('does not warn about a bounded scan when no missing file was detected', async () => {
    state.fileSystem.integrityOk = false
    state.fileSystem.integrityStatus = {
      missing: [],
      checked: 256,
      total: 18087,
    }

    const wrapper = await mountReadyApp()

    expect(wrapper.find('.nv-banner--warning').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('Archive integrity could not be fully verified')
    expect(state.fileSystem.integrityOk).toBe(false)
    expect(state.fileSystem.checkHttpIntegrity).toHaveBeenCalledWith(
      state.manifest.fileIndex,
    )
    wrapper.unmount()
  })

  it('preserves manifest-load and missing-file warnings during a bounded scan', async () => {
    state.manifest.loadError = 'Manifest unavailable; using fallback data'
    state.fileSystem.integrityOk = false
    state.fileSystem.integrityStatus = {
      missing: ['dut-a/missing.log'],
      checked: 1,
      total: 3,
    }

    const wrapper = await mountReadyApp()

    expect(wrapper.text()).toContain('Manifest unavailable; using fallback data')
    expect(wrapper.text()).toContain('1 of 3 files not found')
    expect(wrapper.text()).not.toContain('Integrity check incomplete')
    expect(wrapper.text()).not.toContain('Archive integrity could not be fully verified')
    wrapper.unmount()
  })

  it('preserves missing-file warnings after a complete directory check', async () => {
    state.fileSystem.mode = 'file'
    state.fileSystem.integrityOk = false
    state.fileSystem.integrityStatus = {
      missing: ['dut-a/missing.log'],
      checked: 3,
      total: 3,
    }

    const wrapper = await mountReadyApp()

    expect(wrapper.text()).toContain('1 of 3 files not found')
    expect(state.fileSystem.checkHttpIntegrity).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('logs a failed background integrity check without blocking readiness', async () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    state.fileSystem.checkHttpIntegrity.mockRejectedValueOnce(new Error('probe failed'))

    const wrapper = await mountReadyApp()

    expect(wrapper.find('#app').exists()).toBe(true)
    expect(consoleError).toHaveBeenCalledWith(
      '[FileSystemStore] HTTP integrity check failed',
    )
    wrapper.unmount()
    consoleError.mockRestore()
  })
})
