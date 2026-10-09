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
import { shallowMount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import DataTable from '@/components/common/DataTable.vue'
import { useManifestStore } from '@/stores/manifest'
import CollectorGroupView from '@/views/CollectorGroupView.vue'
import DutProfileView from '@/views/DutProfileView.vue'
import FileMapView from '@/views/FileMapView.vue'
import metadataManifest from '../../fixtures/report_metadata_manifest.json'

const mockRoute = vi.hoisted(() => ({
  params: { dutId: 'DUT_METADATA', group: 'redfish' },
  query: {} as Record<string, string>,
}))

vi.mock('vue-router', () => ({
  useRoute: () => mockRoute,
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}))

function cloneFixture(): any {
  return JSON.parse(JSON.stringify(metadataManifest))
}

function loadFixture(document = cloneFixture()) {
  const store = useManifestStore()
  store.loadFromJson(document)
  return store
}

function columnLabels(wrapper: ReturnType<typeof shallowMount>): string[] {
  return (wrapper.findComponent(DataTable).props('columns') as Array<{ label: string }>)
    .map(column => column.label)
}

describe('report metadata views', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    mockRoute.params.dutId = 'DUT_METADATA'
    mockRoute.params.group = 'redfish'
    mockRoute.query = {}
  })

  it('renders contract platform identity and explicit security-mode provenance', () => {
    loadFixture()

    const wrapper = shallowMount(DutProfileView)
    const text = wrapper.text()

    expect(text).toContain('VR-NVL72')
    expect(text).toContain('compute')
    expect(text).toContain('DGX GB300')
    expect(text).toContain('699-2G530-0200-000')
    expect(text).toContain('metadata-serial-001')
    expect(text).not.toContain('Legacy model')
    expect(wrapper.get('[data-testid="security-mode-section"]').text()).toContain('Reported')
    expect(text).toContain('production')
    expect(text).toContain('dut_config.security_mode')
  })

  it('renders unknown security mode without deriving a value or source', () => {
    const document = cloneFixture()
    document.duts[0].security_mode = {
      status: 'unknown',
      value: null,
      source: null,
    }
    loadFixture(document)

    const section = shallowMount(DutProfileView).get('[data-testid="security-mode-section"]')

    expect(section.text()).toContain('Unknown')
    expect(section.text()).toContain('Not reported')
    expect(section.text()).toContain('No explicit source')
    expect(section.text()).not.toContain('production')
  })

  it('shows explicit group, collector, and file component/access metadata', () => {
    loadFixture()

    const groupView = shallowMount(CollectorGroupView)
    expect(groupView.get('[data-testid="collector-group-metadata"]').text()).toContain('Access path: Redfish')
    expect(groupView.get('[data-testid="collector-group-metadata"]').text()).toContain('BMC')
    expect(columnLabels(groupView)).toEqual([
      'ID',
      'Name',
      'Component',
      'Access Path',
      'Status',
      'Exec Time',
      'Reason',
      'Files',
    ])
    expect(groupView.findComponent(DataTable).props('data')).toEqual([
      expect.objectContaining({ component_label: 'BMC', access_path: 'Redfish' }),
    ])
    expect(groupView.findComponent(DataTable).props('fillViewport')).toBe(false)

    const fileMap = shallowMount(FileMapView)
    expect(columnLabels(fileMap)).toEqual([
      'DUT',
      'Group',
      'Collector',
      'Component',
      'Access Path',
      'File Path',
      'Type',
      'Size',
    ])
    expect(fileMap.findComponent(DataTable).props('data')).toEqual([
      expect.objectContaining({ component_label: 'BMC', access_path: 'Redfish' }),
    ])
  })

  it('warning-styles degraded collectors in the group sidebar', () => {
    const document = cloneFixture()
    document.duts[0].collector_groups[0].collectors[0].status = 'degraded'
    loadFixture(document)

    const wrapper = shallowMount(CollectorGroupView)
    const statusDot = wrapper.findAll('span').find(span =>
      span.attributes('style')?.includes('font-size: 8px')
    )

    expect(statusDot?.attributes('style')).toContain('color: var(--nv-warning)')
  })

  it('keeps historical manifests on the legacy rendering surface', () => {
    const document = cloneFixture()
    const dut = document.duts[0]
    delete dut.platform_identity
    delete dut.security_mode
    delete dut.collector_groups[0].access_path
    delete dut.collector_groups[0].component_labels
    delete dut.collector_groups[0].collectors[0].component_label
    delete dut.collector_groups[0].collectors[0].access_path
    delete document.file_index[0].component_label
    delete document.file_index[0].access_path
    loadFixture(document)

    const profile = shallowMount(DutProfileView)
    expect(profile.text()).toContain('legacy-board')
    expect(profile.text()).toContain('Legacy model')
    expect(profile.find('[data-testid="security-mode-section"]').exists()).toBe(false)

    const groupView = shallowMount(CollectorGroupView)
    expect(groupView.find('[data-testid="collector-group-metadata"]').exists()).toBe(false)
    expect(columnLabels(groupView)).toEqual([
      'ID',
      'Name',
      'Status',
      'Exec Time',
      'Reason',
      'Files',
    ])

    const fileMap = shallowMount(FileMapView)
    expect(columnLabels(fileMap)).toEqual([
      'DUT',
      'Group',
      'Collector',
      'File Path',
      'Type',
      'Size',
    ])
  })
})
