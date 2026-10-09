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

import { shallowMount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { describe, expect, it, vi } from 'vitest'
import DataTable from '@/components/common/DataTable.vue'
import DutView from '@/views/DutView.vue'
import { useManifestStore } from '@/stores/manifest'

vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { dutId: 'DUT_1' } }),
  useRouter: () => ({ push: vi.fn() }),
}))

vi.mock('@/composables/usePdfExport', () => ({
  usePdfExport: () => ({ exportToPdf: vi.fn(), isExporting: false }),
}))

function mountDutView() {
  const pinia = createPinia()
  setActivePinia(pinia)
  useManifestStore().loadFromJson({
    version: '1.0',
    generated_at: '2026-08-04T00:00:00Z',
    tool_version: '2.1.0',
    tool_config: { collection_level: 'L2', execution_mode: 'RemoteClient', baseboard: 'Vera Rubin NVL72' },
    duts: [{
      id: 'DUT_1',
      baseboard: 'Vera Rubin NVL72',
      node_type: 'Compute',
      bmc_ip: '192.0.2.10',
      collector_groups: [],
      status_summary: { success: 0, error: 0, partial: 0, skipped: 0, not_ran: 0 },
      overall_status: 'success',
      execution_time: 1,
      log_size: 0,
      system_info: { model: null, part_number: null, serial_number: null, firmware: [] },
      extensions: [{
        schema_version: '1.0',
        namespace: 'evidence_planner',
        dut_id: 'DUT_1',
        phase: 'completed',
        outcome: 'partial',
        capabilities: [
          {
            kind: 'capture_evidence',
            name: 'System event evidence',
            status: 'completed',
            reason: 'The catalog collector completed',
            unrendered_path: '/sensitive/value.bin',
            unrendered_payload: 'redacted-value',
          },
          {
            kind: 'capture_evidence',
            name: 'GPU DrMOS temperature',
            status: 'missing_prerequisite',
            reason: 'Owner capability selector unavailable',
          },
        ],
        errors: [],
        warnings: [],
      }],
    }],
    collector_catalog: [],
    timing: {},
    file_index: [],
    errors: [],
    preflight: { per_dut: [] },
    dependency_check: { per_dut: [] },
    collection_summary: {},
  })

  return shallowMount(DutView, {
    global: {
      plugins: [pinia],
      stubs: { RouterLink: true },
    },
  })
}

describe('DutView lifecycle capability evidence', () => {
  it('lets the page own vertical scrolling for the execution summary', () => {
    const table = mountDutView().findComponent(DataTable)

    expect(table.props('fillViewport')).toBe(false)
  })

  it('shows safe capture names, outcomes, and reasons without rendering private fields', () => {
    const wrapper = mountDutView()
    const capabilities = wrapper.findAll('.extension-capability')

    expect(capabilities).toHaveLength(2)
    expect(capabilities[0].text()).toContain('System event evidence · completed')
    expect(capabilities[0].classes()).toContain('nv-badge--success')
    expect(capabilities[0].attributes('title')).toBe('The catalog collector completed')
    expect(capabilities[1].text()).toContain('GPU DrMOS temperature · missing_prerequisite')
    expect(capabilities[1].classes()).toContain('nv-badge--warning')
    expect(wrapper.text()).not.toContain('/sensitive/value.bin')
    expect(wrapper.text()).not.toContain('redacted-value')
  })
})
