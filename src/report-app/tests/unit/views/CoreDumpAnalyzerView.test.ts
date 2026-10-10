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
import { nextTick } from 'vue'
import { describe, expect, it, vi } from 'vitest'
import CoreDumpAnalyzerView from '@/views/CoreDumpAnalyzerView.vue'
import { useManifestStore } from '@/stores/manifest'
import type { Manifest } from '@/types/manifest'

function manifestWithMembers(members: string[]): Manifest {
  return {
    version: '1.0',
    generated_at: '2026-07-30T12:00:00Z',
    file_index: [
      {
        path: 'dut-1/redfish/Redfish_R2_existing_dump_15.tar.xz',
        size: 1024,
        type: 'archive',
        dut_id: 'dut-1',
        collector_id: 'R2',
        collector_group: 'redfish',
        collector_name: 'Manager existing log dump',
      },
    ],
    openbmc_coredumps: {
      core_dumps: members.map(member => ({
        artifact_path:
          'dut-1/redfish/Redfish_R2_existing_dump_15.tar.xz',
        archive_member_path: member,
        source_dut: 'dut-1',
        openbmc_commit: 'deadbeef',
        machine: 'test-machine',
        service: 'example',
        size_bytes: 512,
        validation: 'compressed_archive_member_not_inspected',
        ready_for_analyzer: false,
        preparation_required: ['Extract a copy of the archive member.'],
      })),
    },
  } as Manifest
}

describe('CoreDumpAnalyzerView', () => {
  it('keeps multiple core members from one archive as distinct rows', async () => {
    setActivePinia(createPinia())
    const store = useManifestStore()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const members = ['dump/core.first.1.zst', 'dump/core.second.2.zst']
    store.loadFromJson(manifestWithMembers(members))

    const wrapper = mount(CoreDumpAnalyzerView, {
      global: {
        stubs: {
          RouterLink: { template: '<a><slot /></a>' },
        },
      },
    })

    store.loadFromJson(manifestWithMembers([...members].reverse()))
    await nextTick()

    expect(wrapper.findAll('.core-card')).toHaveLength(2)
    expect(wrapper.find('a.nv-btn--primary').exists()).toBe(false)
    expect(wrapper.text()).toContain('Analysis destination not configured')
    expect(wrapper.text()).toContain(members[0])
    expect(wrapper.text()).toContain(members[1])
    expect(
      warn.mock.calls.some(args =>
        args.some(value => String(value).includes('Duplicate keys')),
      ),
    ).toBe(false)

    warn.mockRestore()
  })

  it('reports bounded archive totals and omitted detail counts', () => {
    setActivePinia(createPinia())
    const store = useManifestStore()
    const manifest = manifestWithMembers([])
    manifest.openbmc_coredumps = {
      ...manifest.openbmc_coredumps,
      archive_scan: {
        complete: false,
        archives_inspected: 256,
        compressed_bytes_inspected: 1024,
        decompressed_bytes_consumed: 4096,
        members_inspected: 65536,
        uninspected_archive_count: 300,
        uninspected_archive_details_omitted: 44,
        uninspected_archives: [],
      },
      scan_warnings: ['The archive detail list was bounded.'],
    } as Manifest['openbmc_coredumps']
    store.loadFromJson(manifest)

    const wrapper = mount(CoreDumpAnalyzerView, {
      global: {
        stubs: {
          RouterLink: { template: '<a><slot /></a>' },
        },
      },
    })

    expect(wrapper.text()).toContain('300 controller archive(s)')
    expect(wrapper.text()).toContain('44 additional archive detail(s)')
  })
})
