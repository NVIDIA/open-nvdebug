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

import { createHash } from 'node:crypto'
import { flushPromises, shallowMount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import CollectorDetailView from '@/views/CollectorDetailView.vue'
import DataTable from '@/components/common/DataTable.vue'
import CollectorFileTable from '@/components/collector/CollectorFileTable.vue'
import { useManifestStore } from '@/stores/manifest'
import type { GranularCollectorTiming, TimingReference } from '@/types/manifest'
import fixture from '../../fixtures/sample_manifest.json'

function timing(
  operations: GranularCollectorTiming['operations'],
  artifactTimings: GranularCollectorTiming['artifact_timings'] = [],
): GranularCollectorTiming {
  return {
    collector_started_at: '2026-08-07T00:00:00Z',
    collector_ended_at: '2026-08-07T00:00:01Z',
    wall_clock_duration_seconds: 1,
    wall_clock_is_authoritative: true,
    cumulative_operation_time_seconds: 1,
    operation_aggregation: 'top_level_contributing_spans',
    nested_operation_time_excluded_seconds: 0,
    active_operation_union_seconds: 1,
    overlapped_operation_time_seconds: 0,
    unattributed_wall_time_seconds: 0,
    operation_sum_equals_wall_clock: false,
    operations,
    artifact_timings: artifactTimings,
  }
}

describe('collector detailed timing lifecycle', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('detaches the prior collector graph when route navigation changes collector', async () => {
    const document = {
      snapshot_generation: 'a'.repeat(32),
      collectors: {
        R1: {
          timing: timing([{
            operation_id: 'stage-1',
            parent_id: null,
            operation_type: 'stage',
            name: 'execution',
            stage: 'execution',
            hook: null,
            started_at: null,
            ended_at: null,
            duration_seconds: 1,
            status: 'success',
            artifact_paths: [],
            size_bytes: null,
            contributes_to_active_time: false,
            metadata: {},
          }, {
            operation_id: 'op-1',
            parent_id: null,
            operation_type: 'request',
            name: 'ONLY_R1_GRAPH_SENTINEL',
            stage: null,
            hook: null,
            started_at: null,
            ended_at: null,
            duration_seconds: 1,
            status: 'success',
            artifact_paths: [],
            size_bytes: null,
            contributes_to_active_time: true,
            metadata: {},
          }]),
        },
        R2: { timing: timing([]) },
      },
    }
    const bytes = new TextEncoder().encode(JSON.stringify(document))
    const digest = createHash('sha256').update(bytes).digest('hex')
    const reference = (collectorId: string): TimingReference => ({
      schema_version: '2.0',
      scope: 'dut',
      source: 'DUT_1/.metadata/timing.json',
      collector_id: collectorId,
      size_bytes: bytes.byteLength,
      sha256: digest,
      snapshot_generation: 'a'.repeat(32),
    })
    const collector = (id: string) => ({
      id,
      name: id,
      status: 'success',
      execution_time: 1,
      start_time: null,
      end_time: null,
      reason: '',
      dependencies: [],
      collection_level: 'L1',
      files: [],
      timing_ref: reference(id),
      stage_timing: {
        validation: null,
        discovery: null,
        execution: null,
        post_processing: null,
      },
    })
    const manifest = {
      schema_version: '2.0',
      version: '1.0',
      generated_at: '2026-08-07T00:00:00Z',
      tool_version: '2.2.0',
      tool_config: {
        collection_level: 'L1',
        execution_mode: 'RemoteClient',
        baseboard: 'synthetic',
      },
      duts: [{
        id: 'DUT_1',
        baseboard: 'synthetic',
        node_type: 'Compute',
        bmc_ip: '',
        collector_groups: [{
          name: 'redfish',
          service_type: 'redfish',
          collectors: [collector('R1'), collector('R2')],
          total_execution_time: 2,
        }],
        status_summary: { success: 2, error: 0, partial: 0, skipped: 0, not_ran: 0 },
        overall_status: 'success',
        execution_time: 2,
        log_size: 0,
        system_info: { model: null, part_number: null, serial_number: null, firmware: [] },
      }],
      collector_catalog: [],
      timing: { total_duration: 2, component_timing: {}, per_dut: [], per_service: [] },
      file_index: [],
      errors: [],
      preflight: { per_dut: [] },
      collection_summary: { status_counts: {} },
      run_result: null,
    }

    const pinia = createPinia()
    setActivePinia(pinia)
    useManifestStore().loadFromJson(manifest)
    const fetchMock = vi.fn().mockResolvedValue(new Response(bytes, { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{
        path: '/dut/:dutId/:group/:collectorId',
        component: CollectorDetailView,
      }],
    })
    await router.push('/dut/DUT_1/redfish/R1')
    await router.isReady()
    const wrapper = shallowMount(CollectorDetailView, {
      global: { plugins: [pinia, router] },
    })
    await flushPromises()

    const operationTable = () => wrapper.findAllComponents(DataTable).find(table =>
      (table.props('columns') as Array<{ key: string }> | undefined)
        ?.some(column => column.key === 'operation_type'),
    )
    await vi.waitFor(() => expect(operationTable()).toBeDefined())
    expect(wrapper.get('.cd-stage-legend').text()).toContain('Execution')
    expect(wrapper.get('.cd-stage-legend').text()).toContain('1.00s')
    expect(operationTable()?.props('data')).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: 'ONLY_R1_GRAPH_SENTINEL' })]),
    )

    await router.push('/dut/DUT_1/redfish/R2')
    await flushPromises()

    await vi.waitFor(() => expect(wrapper.find('.cd-header__id').text()).toBe('R2'))
    expect(wrapper.find('.cd-stage-legend').exists()).toBe(false)
    expect(
      wrapper.findAllComponents(DataTable).flatMap(table => {
        const data = table.props('data')
        return Array.isArray(data) ? data : []
      }),
    ).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'ONLY_R1_GRAPH_SENTINEL' }),
      ]),
    )
    expect(JSON.stringify(useManifestStore().manifest)).not.toContain('ONLY_R1_GRAPH_SENTINEL')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })

  it.each(['loading', 'error'])('clears stale %s state when the next collector has no timing reference', async state => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const manifest = JSON.parse(JSON.stringify(fixture))
    const collectors = manifest.duts[0].collector_groups[0].collectors
    for (const [index, collector] of collectors.entries()) {
      collector.id = `R${index + 1}`
      collector.stage_timing = { validation: null, discovery: null, execution: null, post_processing: null }
    }
    collectors[0].timing_ref = {
      schema_version: '2.0', scope: 'dut', source: 'DUT_1/.metadata/timing.json',
      collector_id: 'R1', size_bytes: 100, sha256: 'a'.repeat(64), snapshot_generation: 'b'.repeat(32),
    }
    const store = useManifestStore()
    store.loadFromJson(manifest)
    let rejectTiming!: (reason: Error) => void
    vi.spyOn(store, 'loadCollectorTiming').mockReturnValue(new Promise<GranularCollectorTiming>((_, reject) => {
      rejectTiming = reject
    }))
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/dut/:dutId/:group/:collectorId', component: CollectorDetailView }],
    })
    await router.push('/dut/DUT_1/redfish/R1')
    const wrapper = shallowMount(CollectorDetailView, { global: { plugins: [pinia, router] } })
    if (state === 'error') {
      rejectTiming(new Error('Synthetic timing read failed'))
      await flushPromises()
      expect(wrapper.text()).toContain('Stage timing could not be loaded')
    } else {
      expect(wrapper.text()).toContain('Loading stage timing')
    }
    await router.push('/dut/DUT_1/redfish/R2')
    if (state === 'loading') rejectTiming(new Error('Late synthetic read failure'))
    await flushPromises()
    expect(wrapper.text()).toContain('No stage measurements were recorded in this report')
    expect(wrapper.text()).not.toContain('Loading stage timing')
    expect(wrapper.text()).not.toContain('Stage timing could not be loaded')
    wrapper.unmount()
  })

  it('renders the normalized failure category beside the terminal reason', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    useManifestStore().loadFromJson({
      schema_version: '2.0',
      version: '1.0',
      generated_at: '2026-08-10T00:00:00Z',
      tool_version: '2.2.0',
      tool_config: {
        collection_level: 'L1',
        execution_mode: 'RemoteClient',
        baseboard: 'synthetic',
      },
      duts: [{
        id: 'DUT_1',
        baseboard: 'synthetic',
        node_type: 'Compute',
        bmc_ip: '',
        collector_groups: [{
          name: 'redfish',
          service_type: 'redfish',
          collectors: [{
            id: 'R1',
            name: 'Synthetic degraded result',
            status: 'degraded',
            execution_time: 1,
            start_time: null,
            end_time: null,
            reason: 'request timed out',
            failure_category: 'transport-failure',
            dependencies: [],
            collection_level: 'L1',
            files: [],
            stage_timing: {
              validation: null,
              discovery: null,
              execution: 1,
              post_processing: null,
            },
          }],
          total_execution_time: 1,
        }],
        status_summary: {
          success: 0,
          degraded: 1,
          error: 0,
          partial: 0,
          skipped: 0,
          not_ran: 0,
        },
        overall_status: 'degraded',
        execution_time: 1,
        log_size: 0,
        system_info: {
          model: null,
          part_number: null,
          serial_number: null,
          firmware: [],
        },
      }],
      collector_catalog: [],
      timing: {
        total_duration: 1,
        component_timing: {},
        per_dut: [],
        per_service: [],
      },
      file_index: [],
      errors: [],
      preflight: { per_dut: [] },
      collection_summary: { status_counts: {} },
      run_result: null,
    })
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{
        path: '/dut/:dutId/:group/:collectorId',
        component: CollectorDetailView,
      }],
    })
    await router.push('/dut/DUT_1/redfish/R1')
    await router.isReady()

    const wrapper = shallowMount(CollectorDetailView, {
      global: { plugins: [pinia, router], stubs: { StatusBadge: false } },
    })

    expect(wrapper.get('[data-testid="failure-category"]').text())
      .toBe('transport failure')
    expect(wrapper.text()).toContain('Failure Category')
    expect(wrapper.text()).toContain('transport failure')
    expect(wrapper.text()).toContain('Degraded')
  })

  it('shows Redfish request attribution instead of later persistence timing', async () => {
    const path = 'DUT_1/redfish/Redfish_R1_system_event_log/events.json'
    const collectorTiming = timing([], [
      {
        path,
        operation_id: 'request-1',
        measurement: 'redfish_request',
        measurement_quality: 'measured',
        measurement_scope: 'shared_requests',
        shared_operation_artifact_count: 1,
        shared_request_operation_count: 2,
        started_at: '2026-08-20T00:00:00Z',
        ended_at: '2026-08-20T00:00:01Z',
        duration_seconds: null,
        size_bytes: 2,
        status: 'success',
      },
      {
        path,
        operation_id: 'persist-1',
        measurement: 'artifact_persistence',
        measurement_quality: 'measured',
        measurement_scope: 'artifact',
        shared_operation_artifact_count: 1,
        started_at: '2026-08-20T00:00:01Z',
        ended_at: '2026-08-20T00:00:01.01Z',
        duration_seconds: 0.01,
        size_bytes: 2,
        status: 'success',
      },
    ])
    const pinia = createPinia()
    setActivePinia(pinia)
    useManifestStore().loadFromJson({
      schema_version: '2.0',
      version: '1.0',
      generated_at: '2026-08-20T00:00:00Z',
      tool_version: '2.2.0',
      tool_config: {
        collection_level: 'L1',
        execution_mode: 'RemoteClient',
        baseboard: 'synthetic',
      },
      duts: [{
        id: 'DUT_1',
        baseboard: 'synthetic',
        node_type: 'Compute',
        bmc_ip: '',
        collector_groups: [{
          name: 'redfish',
          service_type: 'redfish',
          collectors: [{
            id: 'R1',
            name: 'system event log',
            status: 'success',
            execution_time: 1,
            start_time: null,
            end_time: null,
            reason: '',
            dependencies: [],
            collection_level: 'L1',
            files: [{ path, size: 2, type: 'json', collector_id: 'R1' }],
            timing: collectorTiming,
            stage_timing: {
              validation: null,
              discovery: null,
              execution: 1,
              post_processing: null,
            },
          }],
          total_execution_time: 1,
        }],
        status_summary: { success: 1, error: 0, partial: 0, skipped: 0, not_ran: 0 },
        overall_status: 'success',
        execution_time: 1,
        log_size: 2,
        system_info: { model: null, part_number: null, serial_number: null, firmware: [] },
      }],
      collector_catalog: [],
      timing: { total_duration: 1, component_timing: {}, per_dut: [], per_service: [] },
      file_index: [],
      errors: [],
      preflight: { per_dut: [] },
      collection_summary: { status_counts: {} },
      run_result: null,
    })
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{
        path: '/dut/:dutId/:group/:collectorId',
        component: CollectorDetailView,
      }],
    })
    await router.push('/dut/DUT_1/redfish/R1')
    await router.isReady()
    const wrapper = shallowMount(CollectorDetailView, {
      global: { plugins: [pinia, router] },
    })

    const fileTable = wrapper.findAllComponents(CollectorFileTable).find(table => {
      return table.props('files').some(file => file.path === path)
    })
    expect(fileTable?.props('files')).toEqual([
      expect.objectContaining({
        measurement: 'redfish_request',
        measurement_scope: 'shared_requests',
        shared_request_operation_count: 2,
        duration_seconds: null,
      }),
    ])
    wrapper.unmount()
  })
})
