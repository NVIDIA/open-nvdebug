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
import { mount, shallowMount } from '@vue/test-utils'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import DataTable from '@/components/common/DataTable.vue'
import FileMapView from '@/views/FileMapView.vue'
import { useManifestStore } from '@/stores/manifest'

const downloadCsvMock = vi.hoisted(() => vi.fn())
const replaceMock = vi.hoisted(() => vi.fn())

vi.mock('@/services/exportService', () => ({
  downloadCsv: downloadCsvMock,
}))

vi.mock('vue-router', async (importOriginal) => ({
  ...await importOriginal<typeof import('vue-router')>(),
  useRoute: () => ({ query: {} }),
  useRouter: () => ({ push: vi.fn(), replace: replaceMock }),
}))

describe('CSV export call sites', () => {
  beforeAll(() => {
    vi.stubGlobal('ResizeObserver', class {
      observe = vi.fn()
      disconnect = vi.fn()
    })
  })

  afterAll(() => {
    vi.unstubAllGlobals()
  })

  beforeEach(() => {
    setActivePinia(createPinia())
    downloadCsvMock.mockReset()
    replaceMock.mockReset()
    sessionStorage.clear()
  })

  it('routes DataTable headers and formatted cells through the shared exporter', async () => {
    const wrapper = mount(DataTable, {
      props: {
        columns: [
          { key: 'name', label: '=untrusted heading' },
          { key: 'details', label: 'Details', formatter: (value: unknown) => ` ${value}` },
        ],
        data: [{ name: '=HYPERLINK("https://attacker.invalid")', details: '@SUM(1,2)' }],
      },
    })

    await wrapper.get('button[title="Download as CSV"]').trigger('click')

    expect(downloadCsvMock).toHaveBeenCalledOnce()
    expect(downloadCsvMock).toHaveBeenCalledWith([
      ['=untrusted heading', 'Details'],
      ['=HYPERLINK("https://attacker.invalid")', ' @SUM(1,2)'],
    ])
  })

  it('routes attacker-controlled file-map fields through the shared exporter', async () => {
    useManifestStore().loadFromJson({
      file_index: [{
        dut_id: '=DUT',
        collector_group: '+group',
        collector_id: 'R1',
        collector_name: '@collector',
        path: '\t=HYPERLINK("https://attacker.invalid", "open")',
        type: 'text,log',
        size: 7,
      }],
    })
    const wrapper = shallowMount(FileMapView)

    await wrapper.get('button[title="Export filtered file list as CSV"]').trigger('click')

    expect(downloadCsvMock).toHaveBeenCalledOnce()
    expect(downloadCsvMock).toHaveBeenCalledWith(
      [
        ['DUT', 'Group', 'Collector', 'File Path', 'Type', 'Size'],
        [
          '=DUT',
          '+group',
          'R1 @collector',
          '\t=HYPERLINK("https://attacker.invalid", "open")',
          'text,log',
          7,
        ],
      ],
      expect.stringMatching(/^nvdebug-files-\d{4}-\d{2}-\d{2}\.csv$/),
    )
  })
})
