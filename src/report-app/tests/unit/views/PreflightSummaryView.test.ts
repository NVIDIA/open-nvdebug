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
import PreflightSummaryView from '@/views/PreflightSummaryView.vue'
import metadataManifest from '../../fixtures/report_metadata_manifest.json'

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}))

function renderStatuses(statuses: string[]) {
  const document = JSON.parse(JSON.stringify(metadataManifest))
  document.preflight = {
    per_dut: [{
      dut_id: 'DUT_METADATA',
      checks: statuses.map((status, index) => ({
        name: `check-${index}`,
        group: 'host',
        status,
        details: `result-${index}`,
      })),
    }],
  }
  useManifestStore().loadFromJson(document)
  return shallowMount(PreflightSummaryView)
}

describe('preflight summary status normalization', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('counts producer passed/failed results and preserves failure details', async () => {
    const wrapper = renderStatuses(['passed', 'passed', 'failed', 'failed'])

    expect(wrapper.get('.ps-health__score').text()).toBe('50%')
    expect(wrapper.get('.ps-health').text()).toContain('2 passed · 2 failed')
    expect(wrapper.text()).not.toContain('All Checks Skipped')
    expect(wrapper.findComponent(DataTable).props('data')).toEqual([
      { dutId: 'DUT_METADATA', pass: 2, fail: 2, warn: 0, skip: 0, total: 4, passRate: '50.0' },
    ])
    const failedCheck = wrapper.findAll('.ps-check').find(check => check.text().includes('check-2'))!
    expect(failedCheck.get('.ps-check__rate').text()).toBe('0/1')
    await failedCheck.trigger('click')
    expect(failedCheck.get('.ps-check__detail').text()).toContain('DUT_METADATA')
    expect(failedCheck.get('.ps-check__detail').text()).toContain('result-2')
  })

  it('keeps all views consistent for aliases, warnings, and skipped checks', () => {
    const wrapper = renderStatuses([' SUCCESS ', 'error', 'WARN', 'not_ran', 'n/a'])

    expect(wrapper.get('.ps-health__score').text()).toBe('33%')
    expect(wrapper.findComponent(DataTable).props('data')).toEqual([
      { dutId: 'DUT_METADATA', pass: 1, fail: 1, warn: 1, skip: 2, total: 3, passRate: '33.3' },
    ])
    expect(wrapper.findAll('.ps-check__rate').map(check => check.text()).filter(text => text === 'N/A')).toHaveLength(2)
  })

  it('retains the all-skipped state for runs without applicable checks', () => {
    const wrapper = renderStatuses(['skipped', 'na', 'unrecognized'])

    expect(wrapper.get('.ps-health').text()).toContain('All Checks Skipped / N/A')
    expect(wrapper.get('.ps-health').text()).toContain('3 skipped')
  })
})
