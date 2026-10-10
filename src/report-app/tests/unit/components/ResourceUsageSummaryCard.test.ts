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

import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount, shallowMount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createMemoryHistory, createRouter } from 'vue-router'
import resourceArtifact from '../../fixtures/resource_usage.json'
import sampleManifest from '../../fixtures/sample_manifest.json'
import ResourceUsageSummaryCard from '@/components/dashboard/ResourceUsageSummaryCard.vue'
import {
  RESOURCE_USAGE_PATH,
  ResourceArtifactMissingError,
} from '@/services/resourceUsageLoader'
import { useFileSystemStore } from '@/stores/fileSystem'
import { useManifestStore } from '@/stores/manifest'
import { emptyResourceDiagnostics, normalizeResourceSample } from '@/utils/resourceUsage'
import DashboardView from '@/views/DashboardView.vue'

const { loadSummaryMock, fullLoadMock } = vi.hoisted(() => ({
  loadSummaryMock: vi.fn(),
  fullLoadMock: vi.fn(),
}))

vi.mock('@/services/resourceUsageLoader', async importOriginal => ({
  ...await importOriginal<typeof import('@/services/resourceUsageLoader')>(),
  loadResourceUsageSummary: loadSummaryMock,
  loadResourceUsageArtifacts: fullLoadMock,
}))

const StatCardStub = {
  name: 'StatCard',
  props: ['label', 'value', 'subtitle', 'color'],
  template: '<div class="stat-card"><strong>{{ label }}</strong><span>{{ value }}</span><small>{{ subtitle }}</small></div>',
}

let pinia: ReturnType<typeof createPinia>

function loadedSummary(artifact: unknown = resourceArtifact) {
  const record = artifact !== null && typeof artifact === 'object'
    ? artifact as Record<string, unknown>
    : {}
  return {
    artifact,
    samples: [record.baseline, record.latest]
      .map(normalizeResourceSample)
      .filter(sample => sample !== null),
    diagnostics: emptyResourceDiagnostics(),
  }
}

function directoryFiles(summary: File): FileList {
  Object.defineProperty(summary, 'webkitRelativePath', {
    configurable: true,
    value: `selected-run/${RESOURCE_USAGE_PATH}`,
  })
  return { 0: summary, length: 1, item: (index: number) => index === 0 ? summary : null } as unknown as FileList
}

async function mountCard() {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', name: 'dashboard', component: { template: '<div />' } },
      { path: '/resources', name: 'resources', component: { template: '<div />' } },
    ],
  })
  await router.push('/')
  await router.isReady()
  const wrapper = mount(ResourceUsageSummaryCard, {
    global: {
      plugins: [pinia, router],
      stubs: { StatCard: StatCardStub },
    },
  })
  return { router, wrapper }
}

describe('ResourceUsageSummaryCard', () => {
  beforeEach(() => {
    pinia = createPinia()
    setActivePinia(pinia)
    const fileStore = useFileSystemStore()
    fileStore.mode = 'file'
    fileStore.directoryLoaded = true
    fileStore.fileMap.set('.metadata/resource_usage.json', new File([], 'resource_usage.json'))
    loadSummaryMock.mockReset()
    fullLoadMock.mockReset()
  })

  it('is mounted after DUT reports on the main dashboard', async () => {
    useManifestStore().loadFromJson(sampleManifest)
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/', name: 'dashboard', component: { template: '<div />' } }],
    })
    await router.push('/')
    await router.isReady()

    const wrapper = shallowMount(DashboardView, {
      global: { plugins: [pinia, router] },
    })

    const resourceCard = wrapper.findComponent(ResourceUsageSummaryCard)
    const dutReports = wrapper.findAll('h3').find(
      heading => heading.text() === 'DUT Reports',
    )

    expect(resourceCard.exists()).toBe(true)
    expect(dutReports).toBeDefined()
    expect(
      dutReports!.element.compareDocumentPosition(resourceCard.element)
      & Node.DOCUMENT_POSITION_FOLLOWING,
    ).not.toBe(0)
  })

  it('shows summary-only KPIs and links to the existing detailed analysis route', async () => {
    loadSummaryMock.mockResolvedValue(loadedSummary())

    const { wrapper } = await mountCard()
    await flushPromises()

    const cards = Object.fromEntries(wrapper.findAllComponents({ name: 'StatCard' })
      .map(card => [card.props('label'), card.props()]))
    expect(cards['Peak RSS'].value).toBe('150.0 MiB')
    expect(cards['Average CPU'].value).toBe('1.00 cores')
    expect(cards['Physical I/O'].value).toBe('R 1.0 MiB / W 2.0 MiB')
    expect(cards['Sampling health'].value).toBe('Complete')
    expect(cards['Pressure signals'].value).toBe('Observed')
    expect(wrapper.get('a').attributes('href')).toBe('/resources')
    expect(loadSummaryMock).toHaveBeenCalledWith(expect.objectContaining({
      mode: 'file',
      signal: expect.any(AbortSignal),
    }))
    expect(fullLoadMock).not.toHaveBeenCalled()
  })

  it('renders no dashboard section when telemetry is unavailable', async () => {
    loadSummaryMock.mockRejectedValue(new ResourceArtifactMissingError('restricted-location/run'))

    const { wrapper } = await mountCard()
    await flushPromises()

    expect(wrapper.find('[data-testid="resource-usage-summary"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('restricted-location/run')
  })

  it('shows missing legacy metrics as unavailable instead of guessed zeroes', async () => {
    loadSummaryMock.mockResolvedValue(loadedSummary({ schema_version: 1, status: 'completed' }))

    const { wrapper } = await mountCard()
    await flushPromises()

    const cards = Object.fromEntries(wrapper.findAllComponents({ name: 'StatCard' })
      .map(card => [card.props('label'), card.props('value')]))
    expect(cards['Peak RSS']).toBe('Unavailable')
    expect(cards['Average CPU']).toBe('Unavailable')
    expect(cards['Physical I/O']).toBe('Unavailable')
    expect(cards['Sampling health']).toBe('Unavailable')
    expect(cards['Pressure signals']).toBe('Unavailable')
    expect(wrapper.text()).not.toContain('0 B')
    expect(wrapper.text()).not.toContain('0.00 cores')
  })

  it('uses bounded baseline and latest summary samples for pressure signals', async () => {
    const artifact = {
      schema_version: 1,
      status: 'completed',
      summary: { samples_total: 2, samples_retained: 2 },
      baseline: {
        elapsed_seconds: 0,
        cgroup: { scopes: [{ controller: 'unified', path: '/run', cpu: { pressure: { some: { avg10: 0 } } } }] },
      },
      latest: {
        elapsed_seconds: 10,
        cgroup: { scopes: [{ controller: 'unified', path: '/run', cpu: { pressure: { some: { avg10: 12 } } } }] },
      },
    }
    loadSummaryMock.mockResolvedValue(loadedSummary(artifact))

    const { wrapper } = await mountCard()
    await flushPromises()

    const pressure = wrapper.findAllComponents({ name: 'StatCard' })
      .find(card => card.props('label') === 'Pressure signals')!
    expect(pressure.props('value')).toBe('Observed')
    expect(fullLoadMock).not.toHaveBeenCalled()
  })

  it('never renders raw producer errors, paths, or internal identifiers', async () => {
    const artifact = JSON.parse(JSON.stringify(resourceArtifact))
    artifact.status = 'failed at restricted-location/run'
    artifact.errors = [{
      source: 'restricted-location/collector.py',
      message: 'opaque-error-detail',
      issue: 'private-issue-marker',
    }]
    loadSummaryMock.mockResolvedValue(loadedSummary(artifact))

    const { wrapper } = await mountCard()
    await flushPromises()

    expect(wrapper.text()).toContain('Review')
    expect(wrapper.text()).not.toContain('restricted-location')
    expect(wrapper.text()).not.toContain('opaque-error-detail')
    expect(wrapper.text()).not.toContain('private-issue-marker')
    expect(wrapper.text()).not.toContain('failed at')
  })

  it('waits for the existing directory selection before loading local summary data', async () => {
    const fileStore = useFileSystemStore()
    fileStore.directoryLoaded = false
    loadSummaryMock.mockResolvedValue(loadedSummary())
    const { wrapper } = await mountCard()
    await flushPromises()

    expect(loadSummaryMock).not.toHaveBeenCalled()
    expect(wrapper.find('[data-testid="resource-usage-summary"]').exists()).toBe(false)

    fileStore.directoryLoaded = true
    await flushPromises()

    expect(loadSummaryMock).toHaveBeenCalledOnce()
    expect(wrapper.find('[data-testid="resource-usage-summary"]').exists()).toBe(true)
  })

  it('aborts and supersedes a stale load when a directory is reselected without changing mode', async () => {
    const fileStore = useFileSystemStore()
    const oldFile = new File(['old'], 'resource_usage.json')
    const newFile = new File(['new'], 'resource_usage.json')
    fileStore.fileMap.set(RESOURCE_USAGE_PATH, oldFile)
    let firstSignal: AbortSignal | undefined
    let resolveFirst!: (value: ReturnType<typeof loadedSummary>) => void
    const firstArtifact = {
      status: 'completed',
      summary: { samples_total: 1, peaks: { process: { rss_bytes: 1024 } } },
    }
    const secondArtifact = {
      status: 'completed',
      summary: { samples_total: 1, peaks: { process: { rss_bytes: 2048 } } },
    }
    loadSummaryMock
      .mockImplementationOnce(access => {
        firstSignal = access.signal
        return new Promise(resolve => { resolveFirst = resolve })
      })
      .mockResolvedValueOnce(loadedSummary(secondArtifact))
    const { wrapper } = await mountCard()
    await flushPromises()

    fileStore.loadDirectory(directoryFiles(newFile))
    await flushPromises()

    expect(fileStore.directoryLoaded).toBe(true)
    expect(fileStore.fileMap.get(RESOURCE_USAGE_PATH)).toBe(newFile)
    expect(firstSignal?.aborted).toBe(true)
    expect(loadSummaryMock).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('2.0 KiB')

    resolveFirst(loadedSummary(firstArtifact))
    await flushPromises()

    expect(wrapper.text()).toContain('2.0 KiB')
    expect(wrapper.text()).not.toContain('1.0 KiB')
  })

  it('aborts an obsolete load when the report access mode changes', async () => {
    const fileStore = useFileSystemStore()
    fileStore.mode = 'http'
    let firstSignal: AbortSignal | undefined
    loadSummaryMock
      .mockImplementationOnce(access => {
        firstSignal = access.signal
        return new Promise((_resolve, reject) => {
          access.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
        })
      })
      .mockResolvedValueOnce(loadedSummary())
    const { wrapper } = await mountCard()
    await flushPromises()

    fileStore.mode = 'file'
    await flushPromises()

    expect(firstSignal?.aborted).toBe(true)
    expect(loadSummaryMock).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[data-testid="resource-usage-summary"]').exists()).toBe(true)
    expect(fullLoadMock).not.toHaveBeenCalled()
  })
})
